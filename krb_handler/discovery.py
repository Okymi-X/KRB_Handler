"""
Credential-free discovery of domain, DC, and clock.

One SMB2 handshake on port 445 gives what krb5.conf needs:
  - NEGOTIATE returns SystemTime -> KDC clock skew
  - anonymous NTLMSSP SESSION_SETUP returns a CHALLENGE whose AV_PAIRs contain
    NetBIOS, host FQDN, DNS domain and forest.
Nothing is authenticated; the probe stops at STATUS_MORE_PROCESSING_REQUIRED.
LDAP rootDSE, NTP, and reverse DNS act as fallbacks.
"""

import socket
import struct
import time

from .constants import MAX_SMB_FRAME, PROBE_TO
from .utils import filetime_to_epoch, is_ip, looks_like_domain, valid_clock_epoch

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
