#!/usr/bin/env python3
"""
KRB_Handler - Kerberos/KDC environment profile manager for AD pentesting.

Point your machine at a target domain in one command: detect the realm, DC FQDN
and KDC clock through unauthenticated SMB2/NTLM probing, then write
/etc/krb5.conf, update /etc/hosts and sync the clock. Each environment
(HTB, OSCP, GOAD, client labs) is saved as a profile, so switching targets does
not require rewriting files by hand.

Usage:
  krb-handler                      # no argument: show this help
  krb-handler set <target>         # detect and apply everything
  krb-handler add <target>         # add another domain to the active profile
  krb-handler use <profile>        # switch to a saved profile
  krb-handler list                 # list profiles and mark the active one
  krb-handler show [profile]       # print the generated krb5.conf
  krb-handler status               # active realm, DCs, hosts, clock skew
  krb-handler check [target]       # diagnostics: ports, DNS, skew, consistency
  krb-handler clock <target>       # only sync the clock with the KDC
  krb-handler hosts <ip> <fqdn>    # only update /etc/hosts
  krb-handler del <profile>        # delete a saved profile
  krb-handler rename <a> <b>       # rename a profile
  krb-handler restore              # restore krb5.conf, /etc/hosts and NTP

Options for 'set' / 'add':
  --realm <REALM>    force the realm and skip detection
  --dc <fqdn>        force the DC FQDN
  --profile <name>   profile name; default is the detected domain
  --desc "<text>"    profile description
  --no-clock         do not change the clock
  --no-hosts         do not touch /etc/hosts
  --faketime         create a faketime wrapper instead of changing the clock
  --weak             enable legacy RC4 compatibility for old lab domains
  --dry-run          print the generated configuration without changing anything

The script auto-elevates with sudo for commands that write /etc/krb5.conf,
/etc/hosts or the system clock. Profiles are stored in ~/.krb-profiles/.
Standard library only, no external dependencies.

Avocado / Caramelo Storm
"""

import ipaddress
import json
import os
import pwd
import re
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager, nullcontext
from datetime import datetime, timezone
from pathlib import Path

# ------------------------------------------------------------------ defaults
KRB5_CONF   = Path("/etc/krb5.conf")
HOSTS_FILE  = Path("/etc/hosts")
HOSTS_BEGIN = "# >>> KRB_Handler"
HOSTS_END   = "# <<< KRB_Handler"
SKEW_LIMIT = 120                  # AD Kerberos rejects tickets above this skew
PROBE_TO = 4                      # socket timeout for probes
MAX_SMB_FRAME = 1024 * 1024       # probe responses should not need more than 1 MiB
MIN_CLOCK_EPOCH = 946_684_800      # 2000-01-01 UTC
MAX_CLOCK_EPOCH = 4_102_444_800    # 2100-01-01 UTC
VERSION = "0.2.0"

PROFILE_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
DNS_LABEL_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z")

# Honor NO_COLOR and avoid escape sequences in pipes and logs.
if sys.stdout.isatty() and "NO_COLOR" not in os.environ:
    R, B = "\033[0m", "\033[1m"
    RED, GRN, YLW, CYN = "\033[1;31m", "\033[1;32m", "\033[1;33m", "\033[1;36m"
else:
    R = B = RED = GRN = YLW = CYN = ""


def info(msg): print(f"{GRN}[*]{R} {msg}")
def warn(msg): print(f"{YLW}[!]{R} {msg}")
def err(msg):  print(f"{RED}[x]{R} {msg}", file=sys.stderr)
def ok(msg):   print(f"{GRN}[+]{R} {msg}")


# ---------------------------------------------------------------- utilities
def out(cmd):
    """Run a bounded subprocess and return stdout, or an empty string on error."""
    try:
        p = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, timeout=10, check=False,
        )
        return p.stdout.strip()
    except (OSError, subprocess.SubprocessError, subprocess.TimeoutExpired):
        return ""


def real_user():
    """Return the account that invoked sudo without trusting a username variable."""
    if os.geteuid() == 0:
        sudo_uid = os.environ.get("SUDO_UID")
        if sudo_uid:
            try:
                return pwd.getpwuid(int(sudo_uid)).pw_name
            except (KeyError, ValueError):
                pass
    try:
        return pwd.getpwuid(os.getuid()).pw_name
    except KeyError:
        return "root"


def filetime_to_epoch(ft):
    """Convert Windows FILETIME (100 ns since 1601-01-01) to Unix time."""
    return ft / 10_000_000.0 - 11_644_473_600.0


def valid_clock_epoch(value):
    return isinstance(value, (int, float)) and MIN_CLOCK_EPOCH <= value <= MAX_CLOCK_EPOCH


def fmt_skew(delta):
    s = abs(int(delta))
    sign = "ahead" if delta < 0 else "behind"
    if s < 60:
        return f"{s}s ({sign})"
    return f"{s // 3600}h{(s % 3600) // 60:02d}m{s % 60:02d}s ({sign})"


def is_ip(s):
    try:
        ipaddress.ip_address(s)
        return True
    except (ValueError, TypeError):
        return False


def valid_dns_name(value, require_dot=False):
    """Validate host/domain names without accepting control chars or injection."""
    if not isinstance(value, str) or not value or len(value) > 253:
        return False
    value = value.rstrip(".")
    if not value or (require_dot and "." not in value):
        return False
    labels = value.split(".")
    return all(DNS_LABEL_RE.fullmatch(label) for label in labels)


def valid_endpoint(value):
    return is_ip(value) or valid_dns_name(value)


def valid_description(value):
    return (
        isinstance(value, str)
        and len(value) <= 512
        and all(ord(char) >= 32 or char == "\t" for char in value)
    )


def looks_like_domain(s):
    """Filter noisy reverse-DNS values such as raw IPs and single labels."""
    if not valid_dns_name(s, require_dot=True) or is_ip(s):
        return False
    labels = s.rstrip(".").split(".")
    return any(c.isalpha() for c in labels[-1])


# ======================================================================
#  PROBING: detect domain, DC and clock without credentials
# ======================================================================
#
# One SMB2 handshake on port 445 gives what krb5.conf needs:
#   - NEGOTIATE returns SystemTime -> KDC clock skew
#   - anonymous NTLMSSP SESSION_SETUP returns a CHALLENGE whose AV_PAIRs contain
#     NetBIOS, host FQDN, DNS domain and forest.
# Nothing is authenticated; the probe stops at STATUS_MORE_PROCESSING_REQUIRED.

SMB2_HDR = b"\xfeSMB"
NTLM_SIG = b"NTLMSSP\x00"

AV_NB_COMPUTER = 1
AV_NB_DOMAIN   = 2
AV_DNS_COMPUTER = 3
AV_DNS_DOMAIN  = 4
AV_DNS_TREE    = 5
AV_TIMESTAMP   = 7


def _smb2_header(command, message_id):
    return (
        SMB2_HDR
        + struct.pack("<HH", 64, 0)          # StructureSize, CreditCharge
        + struct.pack("<I", 0)               # Status / ChannelSequence
        + struct.pack("<HH", command, 1)     # Command, CreditRequest
        + struct.pack("<I", 0)               # Flags
        + struct.pack("<I", 0)               # NextCommand
        + struct.pack("<Q", message_id)      # MessageId
        + struct.pack("<I", 0)               # Reserved / PID
        + struct.pack("<I", 0)               # TreeId
        + struct.pack("<Q", 0)               # SessionId
        + b"\x00" * 16                       # Signature
    )


def _smb_send(sock, payload):
    sock.sendall(struct.pack(">I", len(payload)) + payload)


def _smb_recv(sock):
    head = _recv_exact(sock, 4)
    if not head:
        return b""
    size = struct.unpack(">I", head)[0] & 0x00FFFFFF
    if size <= 0 or size > MAX_SMB_FRAME:
        return b""
    return _recv_exact(sock, size)


def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return b""
        buf += chunk
    return buf


def _ntlm_negotiate():
    """Raw NTLMSSP type 1 message without SPNEGO; Windows accepts it."""
    flags = 0xA2088205  # UNICODE|REQUEST_TARGET|NTLM|ALWAYS_SIGN|EXT_SEC|VERSION|128|56
    return (
        NTLM_SIG
        + struct.pack("<I", 1)
        + struct.pack("<I", flags)
        + struct.pack("<HHI", 0, 0, 32)      # Empty DomainName
        + struct.pack("<HHI", 0, 0, 32)      # Empty Workstation
        + b"\x06\x01\xb1\x1d\x00\x00\x00\x0f"  # Version
    )


def _parse_av_pairs(blob):
    """Extract AV_PAIRs from an NTLMSSP CHALLENGE (type 2)."""
    start = blob.find(NTLM_SIG + struct.pack("<I", 2))
    if start < 0 or len(blob) < start + 48:
        return {}
    ti_len, _, ti_off = struct.unpack("<HHI", blob[start + 40:start + 48])
    data = blob[start + ti_off:start + ti_off + ti_len]
    found, i = {}, 0
    while i + 4 <= len(data):
        av_id, av_len = struct.unpack("<HH", data[i:i + 4])
        if i + 4 + av_len > len(data):
            break
        val = data[i + 4:i + 4 + av_len]
        if av_id == 0:
            break
        if av_id == AV_TIMESTAMP and av_len == 8:
            found[av_id] = struct.unpack("<Q", val)[0]
        else:
            found[av_id] = val.decode("utf-16-le", "ignore")
        i += 4 + av_len
    return found


def probe_smb(host, port=445):
    """Return domain/DC/clock data, or {} when the target does not answer SMB2."""
    res = {}
    try:
        sock = socket.create_connection((host, port), PROBE_TO)
    except OSError:
        return res
    try:
        sock.settimeout(PROBE_TO)
        # --- NEGOTIATE (dialects 2.0.2 through 3.0.2; avoids 3.1.1 contexts)
        dialects = [0x0202, 0x0210, 0x0300, 0x0302]
        body = (
            struct.pack("<HHHH", 36, len(dialects), 1, 0)
            + struct.pack("<I", 0)
            + b"\x00" * 16                    # ClientGuid
            + struct.pack("<Q", 0)            # ClientStartTime
            + b"".join(struct.pack("<H", d) for d in dialects)
        )
        _smb_send(sock, _smb2_header(0x0000, 1) + body)
        resp = _smb_recv(sock)
        if not resp.startswith(SMB2_HDR) or len(resp) < 112:
            return res
        # SystemTime is at offset 40 of the response body (64 = header)
        server_time = filetime_to_epoch(struct.unpack("<Q", resp[104:112])[0])
        if valid_clock_epoch(server_time):
            res["time"] = server_time

        # --- SESSION_SETUP with anonymous NTLMSSP type 1, stopping at the challenge
        token = _ntlm_negotiate()
        body = (
            struct.pack("<HBB", 25, 0, 1)     # StructureSize, Flags, SecurityMode
            + struct.pack("<I", 0)            # Capabilities
            + struct.pack("<I", 0)            # Channel
            + struct.pack("<HH", 64 + 24, len(token))  # SecurityBufferOffset/Length
            + struct.pack("<Q", 0)            # PreviousSessionId
            + token
        )
        _smb_send(sock, _smb2_header(0x0001, 2) + body)
        resp = _smb_recv(sock)
        av = _parse_av_pairs(resp)
        if av.get(AV_DNS_DOMAIN):
            res["domain"] = av[AV_DNS_DOMAIN].lower().rstrip(".")
        if av.get(AV_DNS_COMPUTER):
            res["fqdn"] = av[AV_DNS_COMPUTER].lower().rstrip(".")
        if av.get(AV_NB_DOMAIN):
            res["netbios_domain"] = av[AV_NB_DOMAIN].upper()
        if av.get(AV_NB_COMPUTER):
            res["netbios_host"] = av[AV_NB_COMPUTER].upper()
        if av.get(AV_DNS_TREE):
            res["forest"] = av[AV_DNS_TREE].lower().rstrip(".")
        if av.get(AV_TIMESTAMP):
            server_time = filetime_to_epoch(av[AV_TIMESTAMP])
            if valid_clock_epoch(server_time):
                res["time"] = server_time
        res["via"] = "SMB2/NTLM"
    except (OSError, struct.error):
        pass
    finally:
        sock.close()
    return res


def _ber_len(data, i):
    """Read a short or long BER length. Return (value, new_index)."""
    if i >= len(data):
        raise ValueError("missing BER length")
    n = data[i]
    i += 1
    if n & 0x80:
        cnt = n & 0x7F
        if cnt == 0 or cnt > 4 or i + cnt > len(data):
            raise ValueError("invalid BER length")
        n = int.from_bytes(data[i:i + cnt], "big")
        i += cnt
    return n, i


def _ber_children(data):
    """Iterate TLVs from a BER buffer as (tag, value) pairs."""
    i = 0
    while i + 1 < len(data):
        tag = data[i]
        try:
            ln, i = _ber_len(data, i + 1)
        except ValueError:
            return
        if i + ln > len(data):
            return
        yield tag, data[i:i + ln]
        i += ln


def _parse_rootdse(data):
    """Extract {attribute: value} from an LDAP SearchResultEntry.

    Decode BER properly: scanning printable strings looks fine until a framing
    byte lands in the ASCII range and appends garbage to the name.
    """
    attrs = {}
    for tag, msg in _ber_children(data):              # LDAPMessage
        if tag != 0x30:
            continue
        for tag2, entry in _ber_children(msg):        # messageID + protocolOp
            if tag2 != 0x64:                          # 0x64 = SearchResultEntry
                continue
            kids = list(_ber_children(entry))         # objectName + attrs
            for tag3, attr_list in kids:
                if tag3 != 0x30:
                    continue
                for tag4, attr in _ber_children(attr_list):
                    if tag4 != 0x30:
                        continue
                    parts = list(_ber_children(attr))  # type + SET OF values
                    if len(parts) < 2 or parts[0][0] != 0x04:
                        continue
                    name = parts[0][1].decode("utf-8", "ignore").lower()
                    vals = [v.decode("utf-8", "ignore")
                            for t, v in _ber_children(parts[1][1]) if t == 0x04]
                    if vals:
                        attrs[name] = vals[0]
    return attrs


def probe_ldap(host, port=389):
    """Query anonymous LDAP rootDSE for dnsHostName and defaultNamingContext."""
    # Minimal raw-BER searchRequest: baseObject scope and objectClass presence.
    attrs = [b"defaultNamingContext", b"dnsHostName"]
    attr_seq = b"".join(b"\x04" + bytes([len(a)]) + a for a in attrs)
    body = (
        b"\x04\x00"                                   # baseObject: ""
        b"\x0a\x01\x00"                               # scope: baseObject
        b"\x0a\x01\x00"                               # derefAliases: never
        b"\x02\x01\x00"                               # sizeLimit
        b"\x02\x01\x05"                               # timeLimit
        b"\x01\x01\x00"                               # typesOnly: false
        b"\x87\x0bobjectClass"                        # filter: present
        + b"\x30" + bytes([len(attr_seq)]) + attr_seq
    )
    req = b"\x63" + bytes([len(body)]) + body
    msg = b"\x02\x01\x01" + req
    pkt = b"\x30" + bytes([len(msg)]) + msg

    res, data = {}, b""
    try:
        sock = socket.create_connection((host, port), PROBE_TO)
    except OSError:
        return res
    try:
        sock.settimeout(PROBE_TO)
        sock.sendall(pkt)
        while len(data) < 65536:
            chunk = sock.recv(8192)
            if not chunk:
                break
            data += chunk
            if _parse_rootdse(data):      # enough data to parse the entry
                break
    except OSError:
        pass
    finally:
        sock.close()

    attrs = _parse_rootdse(data)
    dn = attrs.get("defaultnamingcontext", "")
    labels = [p.strip()[3:] for p in dn.split(",") if p.strip().upper().startswith("DC=")]
    if len(labels) >= 2:
        res["domain"] = ".".join(labels).lower()
    host_attr = attrs.get("dnshostname", "")
    if looks_like_domain(host_attr):
        res["fqdn"] = host_attr.lower().rstrip(".")
    if res:
        res["via"] = "LDAP rootDSE"
    return res


def probe_ntp(host):
    """Clock through NTP (UDP 123), used as skew fallback when SMB does not answer."""
    pkt = b"\x1b" + 47 * b"\0"
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(PROBE_TO)
            sock.sendto(pkt, (host, 123))
            data, _ = sock.recvfrom(96)
    except OSError:
        return None
    return _parse_ntp_time(data)


def _parse_ntp_time(data, now=None):
    """Validate an NTP server response and return an era-aware Unix timestamp."""
    if len(data) < 48 or data[0] & 0x07 != 4 or not 1 <= data[1] <= 15:
        return None
    seconds, fraction = struct.unpack("!II", data[40:48])
    if not seconds:
        return None
    epoch = seconds + fraction / 2**32 - 2_208_988_800
    reference = time.time() if now is None else now
    if epoch < reference - 2**31:
        epoch += 2**32
    elif epoch > reference + 2**31:
        epoch -= 2**32
    return epoch if valid_clock_epoch(epoch) else None


def probe(host, want_time=True):
    """Full probe with fallbacks. Returns a possibly incomplete dict."""
    ip = host
    if not is_ip(host):
        try:
            ip = socket.gethostbyname(host)
        except OSError:
            ip = host

    res = probe_smb(ip)
    if not res.get("domain"):
        ldap_res = probe_ldap(ip)
        for k, v in ldap_res.items():
            res.setdefault(k, v)
    if want_time and "time" not in res:
        t = probe_ntp(ip)
        if t:
            res["time"] = float(t)
            res.setdefault("via", "NTP")
    if not res.get("fqdn"):
        try:
            name = socket.gethostbyaddr(ip)[0].lower().rstrip(".")
            if looks_like_domain(name):
                res["fqdn"] = name
                res.setdefault("via", "reverse DNS")
        except OSError:
            pass
    if not res.get("domain") and looks_like_domain(res.get("fqdn", "")):
        candidate = res["fqdn"].split(".", 1)[1]
        if looks_like_domain(candidate):
            res["domain"] = candidate
    res["ip"] = ip
    return res


# ======================================================================
#  PROFILES
# ======================================================================
BASE = PROF_DIR = ACTIVE_F = BACKUP_DIR = STATE_F = None
SYSTEM_BASE = Path("/var/lib/krb-handler")


@contextmanager
def real_user_access():
    """Access profile files as the user that invoked sudo."""
    if os.geteuid() != 0:
        yield
        return
    try:
        account = pwd.getpwnam(real_user())
    except KeyError:
        raise RuntimeError("real user not found") from None
    if account.pw_uid == 0:
        yield
        return

    old_groups = os.getgroups()
    old_egid = os.getegid()
    try:
        os.setgroups(os.getgrouplist(account.pw_name, account.pw_gid))
        os.setegid(account.pw_gid)
        os.seteuid(account.pw_uid)
        yield
    finally:
        os.seteuid(0)
        os.setegid(old_egid)
        os.setgroups(old_groups)


def atomic_write(path, content, mode=0o600, owner_back=False):
    """Write state atomically on the destination filesystem."""
    access = real_user_access() if owner_back else nullcontext()
    with access:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
        tmp = Path(tmp_name)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            tmp.chmod(mode)
            os.replace(tmp, path)
        finally:
            try:
                tmp.unlink()
            except FileNotFoundError:
                pass


def ensure_system_storage():
    """Create privileged state outside user-writable directories."""
    if os.geteuid() != 0:
        return
    for path, mode in ((SYSTEM_BASE, 0o755), (BACKUP_DIR, 0o700)):
        if path.exists():
            st = path.lstat()
            if path.is_symlink() or not path.is_dir() or st.st_uid != 0:
                raise RuntimeError(f"insecure storage: {path} must be a root-owned directory")
        else:
            path.mkdir(parents=True, mode=mode)
        path.chmod(mode)


def init_paths(create=True):
    global BASE, PROF_DIR, ACTIVE_F, BACKUP_DIR, STATE_F
    ru = real_user()
    try:
        home = Path(pwd.getpwnam(ru).pw_dir)
    except KeyError:
        home = Path.home()
    BASE       = home / ".krb-profiles"
    PROF_DIR   = BASE / "profiles"
    ACTIVE_F   = BASE / "active"
    BACKUP_DIR = SYSTEM_BASE / "backup"
    STATE_F    = SYSTEM_BASE / "state.json"
    if create:
        with real_user_access():
            PROF_DIR.mkdir(parents=True, exist_ok=True)
        ensure_system_storage()


def valid_name(name):
    return isinstance(name, str) and bool(PROFILE_NAME_RE.fullmatch(name))


def profile_path(name):
    if not valid_name(name):
        raise ValueError(f"invalid profile name: {name!r}")
    return PROF_DIR / f"{name}.json"


def list_profiles():
    with real_user_access():
        return sorted(p.stem for p in PROF_DIR.glob("*.json") if valid_name(p.stem))


def active_profile():
    try:
        with real_user_access():
            if ACTIVE_F.exists():
                name = ACTIVE_F.read_text(encoding="utf-8").strip()
                return name if valid_name(name) else None
    except OSError:
        pass
    return None


def set_active(name):
    if not valid_name(name):
        raise ValueError(f"invalid profile name: {name!r}")
    atomic_write(ACTIVE_F, name + "\n", owner_back=True)


def validate_profile(prof):
    """Validate and normalize a profile before using it in a root context."""
    if not isinstance(prof, dict):
        raise TypeError("profile must be a JSON object")
    name = prof.get("name")
    if not valid_name(name):
        raise ValueError("invalid profile name")
    description = prof.get("description", "")
    if not valid_description(description):
        raise ValueError("description contains invalid characters or is too long")

    raw_realms = prof.get("realms")
    if not isinstance(raw_realms, dict) or len(raw_realms) > 64:
        raise ValueError("invalid realm list")
    realms = {}
    for raw_realm, raw_entry in raw_realms.items():
        if not valid_dns_name(raw_realm) or not isinstance(raw_entry, dict):
            raise ValueError(f"invalid realm: {raw_realm!r}")
        realm = raw_realm.rstrip(".").upper()
        if realm in realms:
            raise ValueError(f"duplicate realm: {realm}")
        raw_kdcs = raw_entry.get("kdc", [])
        if not isinstance(raw_kdcs, list) or not raw_kdcs or len(raw_kdcs) > 64:
            raise ValueError(f"invalid KDC list in realm {realm}")
        kdcs = []
        for raw_kdc in raw_kdcs:
            if not isinstance(raw_kdc, str) or not valid_endpoint(raw_kdc):
                raise ValueError(f"invalid KDC in realm {realm}")
            kdc = raw_kdc.rstrip(".").lower() if not is_ip(raw_kdc) else raw_kdc
            if kdc not in kdcs:
                kdcs.append(kdc)
        raw_ip = raw_entry.get("ip", "")
        if raw_ip and (not isinstance(raw_ip, str) or not valid_endpoint(raw_ip)):
            raise ValueError(f"invalid endpoint in realm {realm}")
        netbios = raw_entry.get("netbios", "")
        if netbios and (not isinstance(netbios, str) or not DNS_LABEL_RE.fullmatch(netbios)):
            raise ValueError(f"invalid NetBIOS name in realm {realm}")
        forest = raw_entry.get("forest", "")
        if forest and (not isinstance(forest, str) or not valid_dns_name(forest)):
            raise ValueError(f"invalid forest in realm {realm}")
        realms[realm] = {
            "kdc": kdcs,
            "ip": raw_ip.rstrip(".").lower() if raw_ip and not is_ip(raw_ip) else raw_ip,
            "netbios": netbios.upper(),
            "forest": forest.rstrip(".").lower(),
        }

    default_realm = prof.get("default_realm", "")
    if default_realm:
        if not isinstance(default_realm, str) or not valid_dns_name(default_realm):
            raise ValueError("invalid default_realm")
        default_realm = default_realm.rstrip(".").upper()
        if default_realm not in realms:
            raise ValueError("default_realm is not present in realms")

    raw_hosts = prof.get("hosts", [])
    if not isinstance(raw_hosts, list) or len(raw_hosts) > 256:
        raise ValueError("invalid hosts list")
    hosts = []
    for raw_host in raw_hosts:
        if not isinstance(raw_host, dict):
            raise TypeError("invalid host entry")
        ip = raw_host.get("ip")
        fqdn = raw_host.get("fqdn")
        aliases = raw_host.get("aliases", [])
        if not isinstance(ip, str) or not is_ip(ip):
            raise ValueError("invalid IP in hosts")
        if not isinstance(fqdn, str) or not valid_dns_name(fqdn):
            raise ValueError("invalid FQDN in hosts")
        if not isinstance(aliases, list) or len(aliases) > 32:
            raise ValueError("invalid aliases in hosts")
        clean_aliases = []
        for alias in aliases:
            if not isinstance(alias, str) or not valid_dns_name(alias):
                raise ValueError("invalid host alias")
            alias = alias.rstrip(".").lower()
            if alias not in clean_aliases:
                clean_aliases.append(alias)
        hosts.append({"ip": ip, "fqdn": fqdn.rstrip(".").lower(), "aliases": clean_aliases})

    options = prof.get("options", {})
    if not isinstance(options, dict):
        raise TypeError("invalid options")
    if not isinstance(options.get("weak_crypto", False), bool):
        raise TypeError("invalid options")
    created = prof.get("created", "")
    if not isinstance(created, str) or len(created) > 64:
        raise ValueError("invalid creation timestamp")
    return {
        "name": name,
        "description": description,
        "created": created,
        "default_realm": default_realm,
        "realms": realms,
        "hosts": hosts,
        "options": {"weak_crypto": options.get("weak_crypto", False)},
    }


def load_profile(name):
    p = profile_path(name)
    try:
        with real_user_access():
            content = p.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise RuntimeError(f"could not read profile '{name}': {exc}") from exc
    try:
        return validate_profile(json.loads(content))
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ValueError(f"profile '{name}' is invalid: {exc}") from exc


def unlink_user_file(path, missing_ok=False):
    with real_user_access():
        path.unlink(missing_ok=missing_ok)


def user_file_exists(path):
    with real_user_access():
        return path.exists()


def save_profile(prof):
    clean = validate_profile(prof)
    p = profile_path(clean["name"])
    atomic_write(p, json.dumps(clean, indent=2) + "\n", owner_back=True)
    return clean


def new_profile(name, desc=""):
    return {
        "name": name,
        "description": desc,
        "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "default_realm": "",
        "realms": {},      # REALM -> {kdc:[], ip:"", netbios:"", forest:""}
        "hosts": [],       # [{ip, fqdn, aliases:[]}]
        "options": {"weak_crypto": False},
    }


def merge_target(prof, data, make_default=True):
    """Add a probed target to the profile idempotently."""
    if not valid_dns_name(data.get("realm", "")):
        raise ValueError("invalid target realm")
    if data.get("fqdn") and not valid_endpoint(data["fqdn"]):
        raise ValueError("invalid target FQDN")
    if data.get("ip") and not valid_endpoint(data["ip"]):
        raise ValueError("invalid target IP/endpoint")
    realm = data["realm"]
    entry = prof["realms"].setdefault(realm, {"kdc": [], "ip": "", "netbios": "", "forest": ""})
    # FQDN first because it matches the SPN; IP remains a fallback.
    if data.get("fqdn") and data["fqdn"] not in entry["kdc"]:
        entry["kdc"].insert(0, data["fqdn"])
    if data.get("ip") and data["ip"] not in entry["kdc"]:
        entry["kdc"].append(data["ip"])
    entry["ip"] = data.get("ip", entry["ip"])
    entry["netbios"] = data.get("netbios_domain", entry["netbios"])
    entry["forest"] = data.get("forest", entry["forest"])

    if is_ip(data.get("ip")) and data.get("fqdn") and valid_dns_name(data["fqdn"]):
        aliases = [data["domain"]]
        short = data["fqdn"].split(".")[0]
        if short and short != data["domain"]:
            aliases.append(short)
        prof["hosts"] = [h for h in prof["hosts"] if h["fqdn"] != data["fqdn"]]
        prof["hosts"].append({"ip": data["ip"], "fqdn": data["fqdn"], "aliases": aliases})

    if make_default or not prof["default_realm"]:
        prof["default_realm"] = realm
    return prof


def profile_clock_host(prof):
    """Return the preferred clock source from the profile's default realm."""
    prof = validate_profile(prof)
    entry = prof["realms"].get(prof["default_realm"], {})
    return entry.get("ip") or next(iter(entry.get("kdc", [])), None)


# ======================================================================
#  RENDER: krb5.conf and /etc/hosts
# ======================================================================
def render_krb5(prof):
    prof = validate_profile(prof)
    o = prof.get("options", {})
    lines = [
        "# Generated by KRB_Handler (Avocado / Caramelo Storm) - do not edit by hand.",
        f"# profile: {prof['name']}   {datetime.now(timezone.utc).isoformat(timespec='seconds')}",
        "",
        "[libdefaults]",
        f"    default_realm = {prof['default_realm']}",
        "    dns_lookup_realm = false",
        "    dns_lookup_kdc = false",
        "    rdns = false",
        "    dns_canonicalize_hostname = false",
        "    ticket_lifetime = 24h",
        "    renew_lifetime = 7d",
        "    forwardable = true",
        "    noaddresses = true",
        "    udp_preference_limit = 1",   # Force TCP because large PACs exceed UDP.
        f"    clockskew = {SKEW_LIMIT}",
    ]
    if o.get("weak_crypto"):
        lines += [
            "    allow_weak_crypto = true",
            "    default_tgs_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96 rc4-hmac",
            "    default_tkt_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96 rc4-hmac",
            "    permitted_enctypes  = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96 rc4-hmac",
        ]
    lines += ["", "[realms]"]
    for realm in sorted(prof["realms"]):
        e = prof["realms"][realm]
        lines.append(f"    {realm} = {{")
        for kdc in e.get("kdc") or []:
            lines.append(f"        kdc = {kdc}")
        if e.get("kdc"):
            lines.append(f"        admin_server = {e['kdc'][0]}")
            lines.append(f"        kpasswd_server = {e['kdc'][0]}")
        lines.append(f"        default_domain = {realm.lower()}")
        lines.append("    }")
    lines += ["", "[domain_realm]"]
    for realm in sorted(prof["realms"]):
        dom = realm.lower()
        lines.append(f"    {dom} = {realm}")
        lines.append(f"    .{dom} = {realm}")
    # Each host maps to the longest matching realm suffix. Without this, a child
    # domain host may also match the parent suffix and the client will query the
    # wrong KDC, causing "KDC reply did not match expectations".
    for h in prof["hosts"]:
        best = best_realm_for(h["fqdn"], prof["realms"])
        if best:
            lines.append(f"    {h['fqdn']} = {best}")
    lines.append("")
    return "\n".join(lines)


def best_realm_for(fqdn, realms):
    """Return the realm whose domain is the most specific FQDN suffix."""
    match = ""
    for realm in realms:
        dom = realm.lower()
        if (fqdn == dom or fqdn.endswith("." + dom)) and len(dom) > len(match):
            match = dom
    return match.upper() if match else ""


def render_hosts_block(prof):
    prof = validate_profile(prof)
    lines = [f"{HOSTS_BEGIN}: {prof['name']} (generated; use krb-handler)"]
    for h in prof["hosts"]:
        names = " ".join([h["fqdn"], *h.get("aliases", [])])
        lines.append(f"{h['ip']}\t{names}")
    lines.append(HOSTS_END)
    return "\n".join(lines) + "\n"


def backup_once(path):
    """Save one copy of the original file."""
    ensure_system_storage()
    dst = BACKUP_DIR / (path.name + ".orig")
    if not dst.exists() and path.exists():
        shutil.copy2(path, dst)
        dst.chmod(0o600)
        info(f"Original backup saved to {dst}")


def write_system_text(path, content, mode=0o644):
    """Write a system file atomically with predictable permissions."""
    if path.exists():
        st = path.lstat()
        if path.is_symlink() or not path.is_file() or st.st_uid != 0:
            raise RuntimeError(f"insecure system file: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        tmp.chmod(mode)
        if os.geteuid() == 0:
            os.chown(tmp, 0, 0)
        os.replace(tmp, path)
        path.chmod(mode)
        if os.geteuid() == 0:
            os.chown(path, 0, 0)
        try:
            dir_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except OSError:
            pass
    finally:
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass


def write_krb5(prof):
    prof = validate_profile(prof)
    backup_once(KRB5_CONF)
    write_system_text(KRB5_CONF, render_krb5(prof), mode=0o644)
    ok(f"/etc/krb5.conf written  (default_realm = {CYN}{prof['default_realm']}{R})")


def write_hosts(prof):
    prof = validate_profile(prof)
    backup_once(HOSTS_FILE)
    current = HOSTS_FILE.read_text(encoding="utf-8") if HOSTS_FILE.exists() else ""
    body = remove_hosts_block(current).rstrip("\n") + "\n"
    if prof["hosts"]:
        body += "\n" + render_hosts_block(prof)
    write_system_text(HOSTS_FILE, body, mode=0o644)
    if prof["hosts"]:
        ok(f"/etc/hosts updated ({len(prof['hosts'])} profile entries)")


def remove_hosts_block(content):
    """Remove one complete managed block and reject ambiguous marker layouts."""
    lines = content.splitlines(keepends=True)
    begins = [i for i, line in enumerate(lines) if line.startswith(HOSTS_BEGIN)]
    ends = [i for i, line in enumerate(lines) if line.startswith(HOSTS_END)]
    if not begins and not ends:
        return content
    if len(begins) != 1 or len(ends) != 1 or begins[0] >= ends[0]:
        raise RuntimeError(
            f"refusing to modify {HOSTS_FILE}: malformed KRB_Handler marker block"
        )
    return "".join(lines[:begins[0]] + lines[ends[0] + 1:])


def clear_hosts_block():
    if not HOSTS_FILE.exists():
        return
    prof = new_profile("restore")
    write_hosts(prof)


# ======================================================================
#  CLOCK MANAGEMENT
# ======================================================================
def read_state():
    if STATE_F and STATE_F.exists():
        try:
            return json.loads(STATE_F.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            pass
    return {}


def write_state(st):
    ensure_system_storage()
    atomic_write(STATE_F, json.dumps(st, indent=2) + "\n", mode=0o600)


def ntp_enabled():
    return "yes" in out(["timedatectl", "show", "-p", "NTP", "--value"]).lower()


def set_ntp(enabled):
    """Enable or disable automatic NTP and report whether the operation succeeded."""
    try:
        result = subprocess.run(
            ["timedatectl", "set-ntp", "true" if enabled else "false"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        err(f"Failed to {'enable' if enabled else 'disable'} automatic NTP: {exc}")
        return False
    if result.returncode != 0:
        detail = result.stderr.strip() or f"exit status {result.returncode}"
        err(f"Failed to {'enable' if enabled else 'disable'} automatic NTP: {detail}")
        return False
    return True


def sync_clock(target_epoch, host, faketime=False):
    """Align the local clock to the KDC or generate a faketime wrapper."""
    if not valid_clock_epoch(target_epoch):
        err(f"Refusing invalid KDC timestamp from {host}: {target_epoch!r}")
        return False
    skew = target_epoch - time.time()
    if abs(skew) < 5:
        ok(f"Clock already aligned with {host} (delta {int(skew)}s)")
        return True
    print(f"    local clock is {YLW}{fmt_skew(skew)}{R} compared to the KDC")

    if faketime:
        if not shutil.which("faketime"):
            err("faketime is not installed")
            return False
        offset = f"{'+' if skew >= 0 else '-'}{abs(int(skew))}s"
        script = BASE / "faketime.sh"
        atomic_write(
            script,
            "#!/bin/sh\n"
            f"# generated by KRB_Handler for {host}\n"
            f"exec faketime -f '{offset}' \"$@\"\n",
            mode=0o700,
            owner_back=True,
        )
        ok(f"Wrapper created: {script}   (usage: {script} <your-tool> ...)")
        return True

    if abs(skew) < SKEW_LIMIT:
        info(f"{int(abs(skew))}s skew is within the limit ({SKEW_LIMIT}s) - syncing anyway")

    st = read_state()
    ntp_was_on = ntp_enabled()
    if ntp_was_on:
        st["ntp_was_on"] = True
        write_state(st)
        if not set_ntp(False):
            st.pop("ntp_was_on", None)
            write_state(st)
            return False
        info("Automatic NTP disabled so it does not undo the adjustment")
    else:
        write_state(st)

    stamp = datetime.fromtimestamp(target_epoch, timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    try:
        r = subprocess.run(
            ["date", "-u", "-s", stamp],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        r = None
        failure = str(exc)
    if r is not None and r.returncode == 0:
        ok(f"Clock synced with the KDC ({stamp} UTC)")
        return True
    else:
        failure = failure if r is None else (r.stderr.strip() or f"exit status {r.returncode}")
        err(f"Failed to adjust the clock: {failure}")
        if ntp_was_on and set_ntp(True):
            st.pop("ntp_was_on", None)
            write_state(st)
            warn("Automatic NTP was re-enabled after the failed clock adjustment")
        return False


def restore_clock():
    st = read_state()
    if st.get("ntp_was_on"):
        if not set_ntp(True):
            return False
        st.pop("ntp_was_on", None)
        ok("Automatic NTP re-enabled")
    write_state(st)
    return True


# ======================================================================
#  ARGUMENT PARSING
# ======================================================================
SET_BOOL_FLAGS = {"--no-clock", "--no-hosts", "--faketime", "--weak", "--dry-run"}
SET_VALUE_FLAGS = {"--realm", "--dc", "--profile", "--desc"}
USE_BOOL_FLAGS = {"--no-clock", "--no-hosts", "--faketime", "--dry-run"}


def parse_args(argv, bool_flags=(), value_flags=()):
    """Parse a small, command-specific option set, including --name=value."""
    bool_flags = set(bool_flags)
    value_flags = set(value_flags)
    pos, opts = [], {}
    i = 0
    while i < len(argv):
        a = argv[i]
        flag, separator, inline_value = a.partition("=")
        if flag in bool_flags:
            if separator:
                err(f"{flag} does not accept a value")
                sys.exit(1)
            opts[flag.lstrip("-")] = True
        elif flag in value_flags:
            if separator:
                if not inline_value:
                    err(f"{flag} requires a value")
                    sys.exit(1)
                value = inline_value
            else:
                if i + 1 >= len(argv):
                    err(f"{flag} requires a value")
                    sys.exit(1)
                value = argv[i + 1]
                i += 1
            opts[flag.lstrip("-")] = value
        elif a.startswith("--"):
            err(f"unknown option: {a}")
            sys.exit(1)
        else:
            pos.append(a)
        i += 1
    return pos, opts


def require_positionals(pos, minimum, maximum, usage):
    """Reject missing or silently ignored positional arguments."""
    if len(pos) < minimum or (maximum is not None and len(pos) > maximum):
        err(f"usage: {usage}")
        sys.exit(1)


# ======================================================================
#  COMMANDS
# ======================================================================
def resolve_target(target, opts):
    """Probe the target and build the data dict, honoring --realm/--dc."""
    if not valid_endpoint(target):
        err(f"invalid target: {target!r}")
        sys.exit(1)
    info(f"Probing {CYN}{target}{R} ...")
    data = probe(target)

    forced = []
    if opts.get("realm"):
        realm = opts["realm"].rstrip(".")
        if not valid_dns_name(realm):
            err(f"invalid realm: {opts['realm']!r}")
            sys.exit(1)
        data["domain"] = realm.lower()
        forced.append("--realm")
    if opts.get("dc"):
        dc = opts["dc"].rstrip(".")
        if not valid_endpoint(dc):
            err(f"invalid DC: {opts['dc']!r}")
            sys.exit(1)
        data["fqdn"] = dc.lower()
        forced.append("--dc")
        if not data.get("domain") and data["fqdn"].count(".") >= 1:
            data["domain"] = data["fqdn"].split(".", 1)[1]
    if forced:
        detected = data.get("via")
        data["via"] = f"manual ({', '.join(forced)})" + (f" + {detected}" if detected else "")

    if not data.get("domain") or not valid_dns_name(data["domain"]):
        err("Could not detect the domain.")
        warn("Did the target answer? Try passing the values manually:")
        warn(f"  krb-handler set {target} --realm CORP.LOCAL --dc dc01.corp.local")
        sys.exit(1)

    data["domain"] = data["domain"].rstrip(".").lower()
    data["realm"] = data["domain"].upper()
    if data.get("fqdn") and not valid_endpoint(data["fqdn"]):
        warn("Detected FQDN was invalid - ignoring it")
        data.pop("fqdn", None)
    if data.get("forest") and not valid_dns_name(data["forest"]):
        data.pop("forest", None)
    for key in ("netbios_domain", "netbios_host"):
        if data.get(key) and not DNS_LABEL_RE.fullmatch(data[key]):
            data.pop(key, None)
    if not data.get("fqdn"):
        warn("DC FQDN was not detected - using the target itself as KDC")
        data["fqdn"] = data.get("ip", target)

    print(f"    domain   : {CYN}{data['domain']}{R}   (realm {data['realm']})")
    print(f"    DC       : {data['fqdn']}  [{data.get('ip','?')}]")
    if data.get("netbios_domain"):
        print(f"    NetBIOS  : {data['netbios_domain']}\\{data.get('netbios_host','?')}")
    if data.get("forest") and data["forest"] != data["domain"]:
        print(f"    forest   : {data['forest']}")
    print(f"    via      : {data.get('via', '?')}")
    return data


def apply_profile(prof, opts, clock_host=None, clock_epoch=None):
    prof = validate_profile(prof)
    if opts.get("dry-run"):
        print(f"\n{B}--- /etc/krb5.conf (preview) ---{R}")
        print(render_krb5(prof), end="")
        if not opts.get("no-hosts"):
            print(f"\n{B}--- managed /etc/hosts block (preview) ---{R}")
            print(render_hosts_block(prof), end="")
        if not opts.get("no-clock") and clock_epoch:
            print(f"\nClock adjustment: {fmt_skew(clock_epoch - time.time())} compared to {clock_host}")
        info("Dry run complete; no files, profiles, or clock settings were changed")
        return False
    write_krb5(prof)
    if not opts.get("no-hosts"):
        write_hosts(prof)
    if not opts.get("no-clock") and clock_epoch:
        sync_clock(clock_epoch, clock_host, faketime=bool(opts.get("faketime")))
    elif not opts.get("no-clock"):
        warn("KDC clock was not obtained - skipped sync (run: krb-handler clock <target>)")
    save_profile(prof)
    set_active(prof["name"])
    return True


def cmd_set(argv, add=False):
    command = "add" if add else "set"
    pos, opts = parse_args(argv, SET_BOOL_FLAGS, SET_VALUE_FLAGS)
    require_positionals(pos, 1, 1, f"krb-handler {command} <DC-ip-or-fqdn> [options]")
    data = resolve_target(pos[0], opts)

    if opts.get("desc") is not None and not valid_description(opts["desc"]):
        err("invalid description: use at most 512 characters without line breaks")
        sys.exit(1)

    if add:
        name = opts.get("profile") or active_profile()
        if not name or not valid_name(name):
            err("No active profile. Use 'set' first or pass --profile <name>.")
            sys.exit(1)
        prof = load_profile(name) or new_profile(name, opts.get("desc", ""))
    else:
        name = opts.get("profile") or data["domain"].split(".")[0]
        if not valid_name(name):
            err(f"invalid profile name: {name}")
            sys.exit(1)
        prof = load_profile(name) or new_profile(name, opts.get("desc", ""))
        if opts.get("desc"):
            prof["description"] = opts["desc"]

    if opts.get("weak"):
        prof.setdefault("options", {})["weak_crypto"] = True

    merge_target(prof, data, make_default=not add)
    print()
    changed = apply_profile(prof, opts, data.get("fqdn"), data.get("time"))
    print()
    if changed:
        ok(f"Profile {CYN}{prof['name']}{R} active with {len(prof['realms'])} realm(s). "
           f"You can use your tools with -k / Kerberos.")


def cmd_use(argv):
    pos, opts = parse_args(argv, USE_BOOL_FLAGS)
    require_positionals(pos, 1, 1, "krb-handler use <profile> [options]")
    prof = load_profile(pos[0])
    if not prof:
        err(f"Profile '{pos[0]}' does not exist. See:  krb-handler list")
        sys.exit(1)
    apply_opts = dict(opts)
    apply_opts["no-clock"] = True
    changed = apply_profile(prof, apply_opts, None, None)
    if not changed:
        return
    ok(f"Profile {CYN}{prof['name']}{R} applied.")
    if not opts.get("no-clock"):
        host = profile_clock_host(prof)
        if host:
            info(f"Checking the clock against {host} ...")
            data = probe(host)
            if data.get("time"):
                sync_clock(data["time"], host, faketime=bool(opts.get("faketime")))
            else:
                warn("KDC did not answer - clock was not verified")


def cmd_list(argv):
    pos, _ = parse_args(argv)
    require_positionals(pos, 0, 0, "krb-handler list")
    act = active_profile()
    names = list_profiles()
    if not names:
        info("No profiles yet. Create one with:  krb-handler set <DC-ip>")
        return
    print(f"\n{B}Kerberos Profiles{R}   (* = active)\n")
    print(f"   {'NAME':<16}{'DEFAULT REALM':<30}{'REALMS':>7}  DESCRIPTION")
    print(f"   {'-'*14:<16}{'-'*28:<30}{'-'*6:>7}  {'-'*18}")
    for n in names:
        p = load_profile(n) or {}
        mark = f"{GRN}*{R}" if n == act else " "
        print(f" {mark} {n:<16}{p.get('default_realm','?'):<30}"
              f"{len(p.get('realms', {})):>7}  {p.get('description','')}")
    print()


def cmd_show(argv):
    pos, _ = parse_args(argv)
    require_positionals(pos, 0, 1, "krb-handler show [profile]")
    name = pos[0] if pos else active_profile()
    if not name:
        err("No active profile. usage: krb-handler show <profile>")
        sys.exit(1)
    prof = load_profile(name)
    if not prof:
        err(f"Profile '{name}' does not exist.")
        sys.exit(1)
    print(render_krb5(prof))
    if prof["hosts"]:
        print(render_hosts_block(prof))


def cmd_status(argv):
    pos, _ = parse_args(argv)
    require_positionals(pos, 0, 0, "krb-handler status")
    act = active_profile()
    print(f"\n{B}Kerberos Status{R}")
    print(f"  Active profile: {CYN}{act}{R}" if act else f"  Active profile: {YLW}(none){R}")

    realm, realms = "(not set)", []
    if KRB5_CONF.exists():
        for line in KRB5_CONF.read_text(encoding="utf-8").splitlines():
            s = line.strip()
            if s.startswith("default_realm"):
                realm = s.split("=", 1)[1].strip()
            elif "=" in s and s.endswith("{"):
                realms.append(s.split("=")[0].strip())
    print(f"  krb5.conf    : {KRB5_CONF} {'(exists)' if KRB5_CONF.exists() else RED + '(missing)' + R}")
    print(f"  default_realm: {CYN}{realm}{R}")
    print(f"  realms       : {', '.join(realms) if realms else '-'}")

    managed = []
    if HOSTS_FILE.exists():
        inside = False
        for line in HOSTS_FILE.read_text(encoding="utf-8").splitlines():
            if line.startswith(HOSTS_BEGIN):
                inside = True
                continue
            if line.startswith(HOSTS_END):
                inside = False
                continue
            if inside and line.strip():
                managed.append(line.strip())
    print(f"  /etc/hosts   : {len(managed)} managed entries")
    for m in managed:
        print(f"                 {m}")

    if ntp_enabled():
        ntp_txt = "enabled"
    elif read_state().get("ntp_was_on"):
        ntp_txt = f"{YLW}disabled by KRB_Handler{R} ('restore' re-enables it)"
    else:
        ntp_txt = "disabled (already disabled)"
    print(f"  Auto NTP     : {ntp_txt}")
    local_time = datetime.now(timezone.utc).astimezone()
    print(f"  Local time   : {local_time.strftime('%Y-%m-%d %H:%M:%S %Z')}")

    prof = load_profile(act) if act else None
    if prof:
        host = profile_clock_host(prof)
        if host:
            data = probe(host)
            if data.get("time"):
                skew = data["time"] - time.time()
                color = GRN if abs(skew) < SKEW_LIMIT else RED
                print(f"  Skew vs KDC  : {color}{fmt_skew(skew)}{R}  (limit {SKEW_LIMIT}s)")
            else:
                print(f"  Skew vs KDC  : {YLW}KDC {host} did not answer{R}")
    print(f"  Profiles in  : {BASE}\n")


def cmd_check(argv):
    pos, _ = parse_args(argv)
    require_positionals(pos, 0, 1, "krb-handler check [target]")
    if pos and not valid_endpoint(pos[0]):
        err(f"invalid target: {pos[0]!r}")
        sys.exit(1)
    prof = load_profile(active_profile()) if active_profile() else None
    targets = []
    if pos:
        targets = [(None, pos[0])]           # ad-hoc target; realm is not known yet
    elif prof:
        for realm, e in prof["realms"].items():
            kdcs = e.get("kdc") or []
            if kdcs:
                targets.append((realm, kdcs[0]))
    if not targets:
        err("Nothing to check. usage: krb-handler check <target>")
        sys.exit(1)

    print(f"\n{B}Kerberos Diagnostics{R}\n")
    for realm, host in targets:
        print(f"  {CYN}{realm or host}{R}" + (f"  ->  {host}" if realm else ""))
        ip = host
        if not is_ip(host):
            try:
                ip = socket.gethostbyname(host)
                print(f"    [{GRN}ok{R}]   DNS/hosts: {host} -> {ip}")
            except OSError:
                print(f"    [{RED}x{R} ]   DNS/hosts: {host} does not resolve  "
                      f"-> missing /etc/hosts entry")
                continue
        for port, label in ((88, "kerberos"), (445, "smb"), (389, "ldap"), (464, "kpasswd")):
            try:
                s = socket.create_connection((ip, port), 3)
                s.close()
                print(f"    [{GRN}ok{R}]   {port}/tcp {label}")
            except OSError:
                mark = RED + "x" + R if port == 88 else YLW + "!" + R
                print(f"    [{mark} ]   {port}/tcp {label} closed")
        data = probe(ip)
        if data.get("time"):
            skew = data["time"] - time.time()
            good = abs(skew) < SKEW_LIMIT
            print(f"    [{GRN + 'ok' + R if good else RED + 'x ' + R}]   skew {fmt_skew(skew)}"
                  f"{'' if good else '  -> KRB_AP_ERR_SKEW; run: krb-handler clock ' + host}")
        if data.get("domain"):
            if realm and data["domain"].upper() != realm.upper():
                print(f"    [{YLW}!{R} ]   host reports {data['domain'].upper()}, "
                      f"not {realm}  -> outdated profile?")
            elif not realm:
                print(f"    [{GRN}ok{R}]   host realm: {data['domain'].upper()}"
                      f"  ({data.get('fqdn','?')})")
    print()


def cmd_clock(argv):
    pos, opts = parse_args(argv, {"--faketime", "--dry-run"})
    require_positionals(pos, 0, 1, "krb-handler clock [target] [--faketime|--dry-run]")
    host = pos[0] if pos else None
    if not host:
        prof = load_profile(active_profile()) if active_profile() else None
        if prof:
            host = profile_clock_host(prof)
    if not host:
        err("usage: krb-handler clock <target>")
        sys.exit(1)
    info(f"Reading clock from {CYN}{host}{R} ...")
    data = probe(host)
    if not data.get("time"):
        err(f"{host} did not return a timestamp (SMB 445 / NTP 123 closed?)")
        sys.exit(1)
    if opts.get("dry-run"):
        print(f"Clock adjustment: {fmt_skew(data['time'] - time.time())} compared to {host}")
        info("Dry run complete; the system clock was not changed")
        return
    sync_clock(data["time"], host, faketime=bool(opts.get("faketime")))


def cmd_hosts(argv):
    pos, opts = parse_args(argv, {"--dry-run"})
    if len(pos) < 2:
        err("usage: krb-handler hosts <ip> <fqdn> [alias ...]")
        sys.exit(1)
    name = active_profile() or "manual"
    prof = load_profile(name) or new_profile(name)
    ip, fqdn, aliases = pos[0], pos[1].lower(), [a.lower() for a in pos[2:]]
    if not is_ip(ip):
        err(f"invalid IP: {ip!r}")
        sys.exit(1)
    if not valid_dns_name(fqdn):
        err(f"invalid FQDN: {fqdn!r}")
        sys.exit(1)
    if any(not valid_dns_name(alias) for alias in aliases):
        err("invalid alias")
        sys.exit(1)
    if not aliases and fqdn.count(".") >= 1:
        aliases = [fqdn.split(".")[0]]
    prof["hosts"] = [h for h in prof["hosts"] if h["fqdn"] != fqdn]
    prof["hosts"].append({"ip": ip, "fqdn": fqdn, "aliases": aliases})
    if opts.get("dry-run"):
        print(render_hosts_block(prof), end="")
        info("Dry run complete; the profile and /etc/hosts were not changed")
        return
    save_profile(prof)
    set_active(name)
    write_hosts(prof)


def cmd_del(argv):
    pos, _ = parse_args(argv)
    require_positionals(pos, 1, 1, "krb-handler del <profile>")
    name = pos[0]
    if not valid_name(name):
        err(f"invalid profile name: {name!r}")
        sys.exit(1)
    if not user_file_exists(profile_path(name)):
        err(f"Profile '{name}' does not exist.")
        sys.exit(1)
    unlink_user_file(profile_path(name))
    if active_profile() == name:
        unlink_user_file(ACTIVE_F, missing_ok=True)
        warn("It was the active profile - /etc/krb5.conf was left as-is. "
             "Use 'use <other>' or 'restore'.")
    info(f"Profile '{name}' deleted.")


def cmd_rename(argv):
    pos, _ = parse_args(argv)
    require_positionals(pos, 2, 2, "krb-handler rename <old> <new>")
    if not valid_name(pos[0]) or not valid_name(pos[1]):
        err("usage: krb-handler rename <old> <new>")
        sys.exit(1)
    old, new = pos
    if not user_file_exists(profile_path(old)):
        err(f"Profile '{old}' does not exist.")
        sys.exit(1)
    if user_file_exists(profile_path(new)):
        err(f"Profile '{new}' already exists.")
        sys.exit(1)
    prof = load_profile(old)
    prof["name"] = new
    save_profile(prof)
    unlink_user_file(profile_path(old))
    if active_profile() == old:
        set_active(new)
    info(f"'{old}' -> '{new}'")


def cmd_restore(argv):
    pos, _ = parse_args(argv)
    require_positionals(pos, 0, 0, "krb-handler restore")
    orig = BACKUP_DIR / "krb5.conf.orig"
    if orig.exists():
        write_system_text(KRB5_CONF, orig.read_text(encoding="utf-8"), mode=0o644)
        ok(f"/etc/krb5.conf restored from backup ({orig})")
    else:
        warn("No krb5.conf backup found - leaving it as-is.")
    clear_hosts_block()
    ok("/etc/hosts: KRB_Handler block removed")
    restore_clock()
    unlink_user_file(ACTIVE_F, missing_ok=True)
    info("No active profile now. Saved profiles are still on disk.")


def cmd_help(argv):
    if not argv:
        print(__doc__)
        return
    topic = HELP_ALIASES.get(argv[0], argv[0])
    detail = COMMAND_HELP.get(topic)
    if not detail:
        err(f"unknown help topic: {argv[0]}")
        sys.exit(1)
    print(detail)


COMMAND_HELP = {
    "set": """usage: krb-handler set <target> [options]

Create or update a profile from an IP address or hostname, then apply it.

Options:
  --realm REALM      override domain discovery
  --dc FQDN          override DC hostname discovery
  --profile NAME     choose the profile name
  --desc TEXT        set a profile description
  --no-clock         do not adjust the system clock
  --no-hosts         do not update /etc/hosts
  --faketime         create a faketime wrapper instead of changing the clock
  --weak             enable legacy RC4 compatibility
  --dry-run          preview all generated configuration without changing state""",
    "add": """usage: krb-handler add <target> [options]

Add another realm or trusted domain to the active profile. The options are the
same as for 'set'. Use --profile NAME to update a non-active profile.""",
    "use": """usage: krb-handler use <profile> [options]

Apply a saved profile. Options: --no-clock, --no-hosts, --faketime, --dry-run.""",
    "list": "usage: krb-handler list\n\nList saved profiles and mark the active profile.",
    "show": "usage: krb-handler show [profile]\n\nPrint the generated krb5.conf and managed hosts block.",
    "status": "usage: krb-handler status\n\nShow the active configuration, managed hosts, NTP state, and KDC skew.",
    "check": "usage: krb-handler check [target]\n\nCheck DNS, Kerberos-related ports, realm identity, and clock skew.",
    "clock": """usage: krb-handler clock [target] [--faketime|--dry-run]

Synchronize with a KDC, or use the active profile when target is omitted.""",
    "hosts": """usage: krb-handler hosts <ip> <fqdn> [alias ...] [--dry-run]

Add or replace one managed hosts entry in the active profile.""",
    "del": "usage: krb-handler del <profile>\n\nDelete a saved profile without changing system files.",
    "rename": "usage: krb-handler rename <old> <new>\n\nRename a saved profile.",
    "restore": "usage: krb-handler restore\n\nRestore original system files and automatic NTP state.",
}

HELP_ALIASES = {
    "target": "set", "switch": "use", "ls": "list", "cat": "show",
    "st": "status", "doctor": "check", "time": "clock", "sync": "clock",
    "rm": "del", "delete": "del", "mv": "rename", "revert": "restore",
}


COMMANDS = {
    "set": cmd_set, "target": cmd_set,
    "add": lambda a: cmd_set(a, add=True),
    "use": cmd_use, "switch": cmd_use,
    "list": cmd_list, "ls": cmd_list,
    "show": cmd_show, "cat": cmd_show,
    "status": cmd_status, "st": cmd_status,
    "check": cmd_check, "doctor": cmd_check,
    "clock": cmd_clock, "time": cmd_clock, "sync": cmd_clock,
    "hosts": cmd_hosts,
    "del": cmd_del, "rm": cmd_del, "delete": cmd_del,
    "rename": cmd_rename, "mv": cmd_rename,
    "restore": cmd_restore, "revert": cmd_restore,
    "help": cmd_help, "-h": cmd_help, "--help": cmd_help,
}

# Commands that write to /etc or change the clock need root.
NEEDS_ROOT = {"set", "target", "add", "use", "switch", "hosts",
              "clock", "time", "sync", "restore", "revert"}
DRY_RUN_COMMANDS = {"set", "target", "add", "use", "switch", "hosts",
                    "clock", "time", "sync"}


def main():
    argv = sys.argv[1:]

    if not argv:
        cmd_help([])
        return
    if argv[0] in ("help", "-h", "--help"):
        cmd_help(argv[1:])
        return
    if argv[0] in ("version", "--version"):
        if len(argv) != 1:
            err("usage: krb-handler --version")
            sys.exit(1)
        print(f"krb-handler {VERSION}")
        return

    cmd = argv[0]
    handler = COMMANDS.get(cmd)
    if not handler:
        err(f"unknown command: {cmd}\n")
        cmd_help([])
        sys.exit(1)
    if len(argv) > 1 and argv[1] in ("help", "-h", "--help"):
        cmd_help([cmd])
        return
    dry_run = cmd in DRY_RUN_COMMANDS and "--dry-run" in argv[1:]
    if cmd in NEEDS_ROOT and not dry_run and os.geteuid() != 0:
        sudo = shutil.which("sudo")
        if not sudo:
            err("sudo not found; this command needs root")
            sys.exit(1)
        os.execv(sudo, [sudo, "--", sys.executable, os.path.abspath(__file__), *argv])

    try:
        init_paths(create=cmd in NEEDS_ROOT and not dry_run)
        handler(argv[1:])
    except KeyboardInterrupt:
        print()
        warn("interrupted")
        sys.exit(130)
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        err(str(exc))
        sys.exit(1)


if __name__ == "__main__":
    main()
