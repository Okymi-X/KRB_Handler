#!/usr/bin/env python3
"""
KRB_Handler - configurador de ambiente Kerberos (KDC) para pentest de AD.

Aponta a sua Kali para o dominio alvo em UM comando: descobre o realm, o FQDN do
DC e o relogio do KDC sondando o alvo (SMB2/NTLM anonimo, sem credencial), e entao
escreve /etc/krb5.conf, ajusta /etc/hosts e sincroniza o relogio. Cada ambiente
(HTB, OSCP, GOAD, cliente) vira um PERFIL salvo, entao trocar de alvo e um
comando - sem reescrever arquivo na mao e sem quebrar o que ja estava ali.

Uso:
  KRB_Handler.py                      # sem argumento: mostra esta ajuda
  KRB_Handler.py set <alvo>           # DETECTA e APLICA tudo (o comando principal)
  KRB_Handler.py add <alvo>           # soma outro dominio ao perfil (trust/filho)
  KRB_Handler.py use <perfil>         # troca para um perfil salvo
  KRB_Handler.py list                 # lista os perfis (marca o ativo)
  KRB_Handler.py show [perfil]        # mostra o krb5.conf gerado
  KRB_Handler.py status               # realm ativo, DCs, hosts, skew do relogio
  KRB_Handler.py check [alvo]         # diagnostico (portas, DNS, skew, coerencia)
  KRB_Handler.py clock <alvo>         # so o relogio (sincroniza com o KDC)
  KRB_Handler.py hosts <ip> <fqdn>    # so o /etc/hosts
  KRB_Handler.py del <perfil>         # remove um perfil salvo
  KRB_Handler.py rename <a> <b>       # renomeia um perfil
  KRB_Handler.py restore              # devolve krb5.conf, /etc/hosts e NTP ao original

Opcoes de 'set' / 'add':
  --realm <REALM>    forca o realm (pula a deteccao)
  --dc <fqdn>        forca o FQDN do DC
  --profile <nome>   nome do perfil (default: o dominio detectado)
  --desc "<texto>"   descricao do perfil
  --no-clock         nao mexe no relogio
  --no-hosts         nao mexe no /etc/hosts
  --faketime         em vez de mudar o relogio, gera um wrapper faketime
  --weak             habilita RC4/DES (labs e dominios antigos)

O script se auto-eleva com sudo nos comandos que escrevem (/etc/krb5.conf,
/etc/hosts, relogio). Perfis ficam em ~/.krb-profiles/ do seu usuario.
Somente biblioteca padrao - sem dependencias externas.

Avocado / Caramelo Storm
"""

import json
import os
import pwd
import shutil
import socket
import struct
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# ------------------------------------------------------------------ defaults
KRB5_CONF   = Path("/etc/krb5.conf")
HOSTS_FILE  = Path("/etc/hosts")
HOSTS_BEGIN = "# >>> KRB_Handler"
HOSTS_END   = "# <<< KRB_Handler"
SKEW_LIMIT  = 120                 # segundos: acima disso o Kerberos do AD recusa
PROBE_TO    = 4                    # timeout de socket nas sondagens

# cores
R, B   = "\033[0m", "\033[1m"
RED    = "\033[1;31m"
GRN    = "\033[1;32m"
YLW    = "\033[1;33m"
CYN    = "\033[1;36m"


def info(msg): print(f"{GRN}[*]{R} {msg}")
def warn(msg): print(f"{YLW}[!]{R} {msg}")
def err(msg):  print(f"{RED}[x]{R} {msg}", file=sys.stderr)
def ok(msg):   print(f"{GRN}[+]{R} {msg}")


# --------------------------------------------------------------- utilitarios
def out(cmd):
    """Roda e devolve stdout (str), engolindo erros."""
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        return p.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return ""


def real_user():
    return os.environ.get("SUDO_USER") or os.environ.get("USER") or "root"


def filetime_to_epoch(ft):
    """FILETIME do Windows (100ns desde 1601-01-01) -> epoch unix (float)."""
    return ft / 10_000_000.0 - 11_644_473_600.0


def fmt_skew(delta):
    s = abs(int(delta))
    sign = "adiantada" if delta < 0 else "atrasada"
    if s < 60:
        return f"{s}s ({sign})"
    return f"{s // 3600}h{(s % 3600) // 60:02d}m{s % 60:02d}s ({sign})"


def is_ip(s):
    try:
        socket.inet_aton(s)
        return s.count(".") == 3
    except OSError:
        return False


def looks_like_domain(s):
    """Filtra lixo de DNS reverso (IP cru, nome sem ponto, rotulo so numerico)."""
    if not s or "." not in s or is_ip(s):
        return False
    labels = s.split(".")
    if any(not lb for lb in labels):
        return False
    return any(c.isalpha() for c in labels[-1])


# ======================================================================
#  SONDAGEM: descobre dominio, DC e relogio sem precisar de credencial
# ======================================================================
#
# Um unico handshake SMB2 (porta 445) entrega tudo o que o krb5.conf precisa:
#   - NEGOTIATE responde com SystemTime  -> o relogio do KDC (skew)
#   - SESSION_SETUP com NTLMSSP anonimo  -> o servidor devolve um CHALLENGE cujos
#     AV_PAIRs trazem NetBIOS, FQDN do host, dominio DNS e a floresta.
# Nao autentica nada: para no CHALLENGE (STATUS_MORE_PROCESSING_REQUIRED).

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
    return _recv_exact(sock, struct.unpack(">I", head)[0] & 0x00FFFFFF)


def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return b""
        buf += chunk
    return buf


def _ntlm_negotiate():
    """Mensagem NTLMSSP tipo 1 (crua, sem SPNEGO - o Windows aceita)."""
    flags = 0xA2088205  # UNICODE|REQUEST_TARGET|NTLM|ALWAYS_SIGN|EXT_SEC|VERSION|128|56
    return (
        NTLM_SIG
        + struct.pack("<I", 1)
        + struct.pack("<I", flags)
        + struct.pack("<HHI", 0, 0, 32)      # DomainName (vazio)
        + struct.pack("<HHI", 0, 0, 32)      # Workstation (vazio)
        + b"\x06\x01\xb1\x1d\x00\x00\x00\x0f"  # Version
    )


def _parse_av_pairs(blob):
    """Extrai os AV_PAIRs do NTLMSSP CHALLENGE (tipo 2)."""
    start = blob.find(NTLM_SIG + struct.pack("<I", 2))
    if start < 0 or len(blob) < start + 48:
        return {}
    ti_len, _, ti_off = struct.unpack("<HHI", blob[start + 40:start + 48])
    data = blob[start + ti_off:start + ti_off + ti_len]
    found, i = {}, 0
    while i + 4 <= len(data):
        av_id, av_len = struct.unpack("<HH", data[i:i + 4])
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
    """Devolve dict com dominio/DC/relogio, ou {} se o alvo nao responder SMB2."""
    res = {}
    try:
        sock = socket.create_connection((host, port), PROBE_TO)
    except OSError:
        return res
    try:
        sock.settimeout(PROBE_TO)
        # --- NEGOTIATE (dialetos 2.0.2 a 3.0.2; evita 3.1.1 p/ nao lidar com contexts)
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
        # SystemTime fica no offset 40 do corpo da resposta (64 = header)
        res["time"] = filetime_to_epoch(struct.unpack("<Q", resp[104:112])[0])

        # --- SESSION_SETUP com NTLMSSP tipo 1 (anonimo, para no challenge)
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
            res["time"] = filetime_to_epoch(av[AV_TIMESTAMP])
        res["via"] = "SMB2/NTLM"
    except (OSError, struct.error):
        pass
    finally:
        sock.close()
    return res


def _ber_len(data, i):
    """Le um comprimento BER (curto ou longo). Devolve (valor, novo_indice)."""
    n = data[i]
    i += 1
    if n & 0x80:
        cnt = n & 0x7F
        n = int.from_bytes(data[i:i + cnt], "big")
        i += cnt
    return n, i


def _ber_children(data):
    """Itera os TLVs de um buffer BER como pares (tag, valor)."""
    i = 0
    while i + 1 < len(data):
        tag = data[i]
        ln, i = _ber_len(data, i + 1)
        if i + ln > len(data):
            return
        yield tag, data[i:i + ln]
        i += ln


def _parse_rootdse(data):
    """Extrai {atributo: valor} de um SearchResultEntry LDAP.

    Decodifica o BER de verdade: varrer strings imprimiveis parece funcionar
    ate um byte de enquadramento cair na faixa ASCII e colar lixo no nome.
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
    """Fallback: rootDSE anonimo. Le dnsHostName e defaultNamingContext."""
    # searchRequest minimo (baseObject, filtro presente objectClass) em BER cru.
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
            if _parse_rootdse(data):      # ja deu para ler a entrada
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
    """Relogio via NTP (UDP 123). Fallback de skew quando SMB nao responde."""
    pkt = b"\x1b" + 47 * b"\0"
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(PROBE_TO)
        sock.sendto(pkt, (host, 123))
        data, _ = sock.recvfrom(96)
        sock.close()
    except OSError:
        return None
    if len(data) < 48:
        return None
    secs = struct.unpack("!I", data[40:44])[0]
    return secs - 2_208_988_800  # epoch NTP (1900) -> unix (1970)


def probe(host, want_time=True):
    """Sondagem completa com fallbacks. Devolve dict (pode vir incompleto)."""
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
                res.setdefault("via", "DNS reverso")
        except OSError:
            pass
    if not res.get("domain") and looks_like_domain(res.get("fqdn", "")):
        candidate = res["fqdn"].split(".", 1)[1]
        if looks_like_domain(candidate):
            res["domain"] = candidate
    res["ip"] = ip
    return res


# ======================================================================
#  PERFIS
# ======================================================================
BASE = PROF_DIR = ACTIVE_F = BACKUP_DIR = STATE_F = None


def init_paths():
    global BASE, PROF_DIR, ACTIVE_F, BACKUP_DIR, STATE_F
    ru = real_user()
    try:
        home = Path(pwd.getpwnam(ru).pw_dir)
    except KeyError:
        home = Path.home()
    BASE       = home / ".krb-profiles"
    PROF_DIR   = BASE / "profiles"
    ACTIVE_F   = BASE / "active"
    BACKUP_DIR = BASE / "backup"
    STATE_F    = BASE / "state.json"
    PROF_DIR.mkdir(parents=True, exist_ok=True)
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    chown_back(BASE, PROF_DIR, BACKUP_DIR)


def chown_back(*paths):
    """Devolve a posse ao usuario real (criamos os arquivos como root)."""
    try:
        pw = pwd.getpwnam(real_user())
    except KeyError:
        return
    for p in paths:
        try:
            os.chown(p, pw.pw_uid, pw.pw_gid)
        except (OSError, PermissionError):
            pass


def valid_name(name):
    return bool(name) and "/" not in name and not name.startswith(".")


def profile_path(name):
    return PROF_DIR / f"{name}.json"


def list_profiles():
    return sorted(p.stem for p in PROF_DIR.glob("*.json"))


def active_profile():
    if ACTIVE_F.exists():
        return ACTIVE_F.read_text().strip() or None
    return None


def set_active(name):
    ACTIVE_F.write_text(name + "\n")
    chown_back(ACTIVE_F)


def load_profile(name):
    p = profile_path(name)
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text())
    except (json.JSONDecodeError, OSError):
        return None


def save_profile(prof):
    p = profile_path(prof["name"])
    p.write_text(json.dumps(prof, indent=2) + "\n")
    chown_back(p)


def new_profile(name, desc=""):
    return {
        "name": name,
        "description": desc,
        "created": datetime.now().isoformat(timespec="seconds"),
        "default_realm": "",
        "realms": {},      # REALM -> {kdc:[], ip:"", netbios:"", forest:""}
        "hosts": [],       # [{ip, fqdn, aliases:[]}]
        "options": {"weak_crypto": False},
    }


def merge_target(prof, data, make_default=True):
    """Soma um alvo sondado ao perfil (idempotente)."""
    realm = data["realm"]
    entry = prof["realms"].setdefault(realm, {"kdc": [], "ip": "", "netbios": "", "forest": ""})
    # FQDN primeiro (casa com o SPN), IP depois como rede de seguranca.
    if data.get("fqdn") and data["fqdn"] not in entry["kdc"]:
        entry["kdc"].insert(0, data["fqdn"])
    if data.get("ip") and data["ip"] not in entry["kdc"]:
        entry["kdc"].append(data["ip"])
    entry["ip"] = data.get("ip", entry["ip"])
    entry["netbios"] = data.get("netbios_domain", entry["netbios"])
    entry["forest"] = data.get("forest", entry["forest"])

    if data.get("ip") and data.get("fqdn"):
        aliases = [data["domain"]]
        short = data["fqdn"].split(".")[0]
        if short and short != data["domain"]:
            aliases.append(short)
        prof["hosts"] = [h for h in prof["hosts"] if h["fqdn"] != data["fqdn"]]
        prof["hosts"].append({"ip": data["ip"], "fqdn": data["fqdn"], "aliases": aliases})

    if make_default or not prof["default_realm"]:
        prof["default_realm"] = realm
    return prof


# ======================================================================
#  RENDER: krb5.conf e /etc/hosts
# ======================================================================
def render_krb5(prof):
    o = prof.get("options", {})
    lines = [
        "# Gerado por KRB_Handler (Avocado / Caramelo Storm) - nao edite na mao.",
        f"# perfil: {prof['name']}   {datetime.now().isoformat(timespec='seconds')}",
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
        "    udp_preference_limit = 1",   # forca TCP: PAC grande estoura o UDP
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
    # Cada host vai para o realm de sufixo MAIS LONGO. Sem isso, num dominio
    # filho o host casa tambem com o sufixo do pai e o cliente procura o KDC
    # errado - o classico "KDC reply did not match expectations".
    for h in prof["hosts"]:
        best = best_realm_for(h["fqdn"], prof["realms"])
        if best:
            lines.append(f"    {h['fqdn']} = {best}")
    lines.append("")
    return "\n".join(lines)


def best_realm_for(fqdn, realms):
    """Realm cujo dominio e o sufixo mais especifico do FQDN."""
    match = ""
    for realm in realms:
        dom = realm.lower()
        if fqdn == dom or fqdn.endswith("." + dom):
            if len(dom) > len(match):
                match = dom
    return match.upper() if match else ""


def render_hosts_block(prof):
    lines = [f"{HOSTS_BEGIN}: {prof['name']} (gerado; use KRB_Handler.py)"]
    for h in prof["hosts"]:
        names = " ".join([h["fqdn"], *h.get("aliases", [])])
        lines.append(f"{h['ip']}\t{names}")
    lines.append(HOSTS_END)
    return "\n".join(lines) + "\n"


def backup_once(path):
    """Guarda uma copia do arquivo original (so na primeira vez)."""
    dst = BACKUP_DIR / (path.name + ".orig")
    if not dst.exists() and path.exists():
        shutil.copy2(path, dst)
        chown_back(dst)
        info(f"Backup do original em {dst}")


def write_krb5(prof):
    backup_once(KRB5_CONF)
    KRB5_CONF.write_text(render_krb5(prof))
    ok(f"/etc/krb5.conf escrito  (default_realm = {CYN}{prof['default_realm']}{R})")


def write_hosts(prof):
    backup_once(HOSTS_FILE)
    current = HOSTS_FILE.read_text().splitlines(keepends=True) if HOSTS_FILE.exists() else []
    kept, skipping = [], False
    for line in current:
        if line.startswith(HOSTS_BEGIN):
            skipping = True
            continue
        if line.startswith(HOSTS_END):
            skipping = False
            continue
        if not skipping:
            kept.append(line)
    while kept and not kept[-1].strip():
        kept.pop()
    body = "".join(kept).rstrip("\n") + "\n"
    if prof["hosts"]:
        body += "\n" + render_hosts_block(prof)
    HOSTS_FILE.write_text(body)
    if prof["hosts"]:
        ok(f"/etc/hosts atualizado ({len(prof['hosts'])} entrada(s) do perfil)")


def clear_hosts_block():
    if not HOSTS_FILE.exists():
        return
    prof = {"name": "-", "hosts": []}
    write_hosts(prof)


# ======================================================================
#  RELOGIO
# ======================================================================
def read_state():
    if STATE_F and STATE_F.exists():
        try:
            return json.loads(STATE_F.read_text())
        except (json.JSONDecodeError, OSError):
            pass
    return {}


def write_state(st):
    STATE_F.write_text(json.dumps(st, indent=2) + "\n")
    chown_back(STATE_F)


def ntp_enabled():
    return "yes" in out(["timedatectl", "show", "-p", "NTP", "--value"]).lower()


def sync_clock(target_epoch, host, faketime=False):
    """Alinha o relogio local ao do KDC (ou gera um wrapper faketime)."""
    skew = target_epoch - time.time()
    if abs(skew) < 5:
        ok(f"Relogio ja alinhado com {host} (delta {int(skew)}s)")
        return
    print(f"    relogio local esta {YLW}{fmt_skew(skew)}{R} em relacao ao KDC")

    if faketime:
        if not shutil.which("faketime"):
            err("faketime nao instalado:  sudo apt install faketime")
            return
        offset = f"{'+' if skew >= 0 else '-'}{abs(int(skew))}s"
        script = BASE / "faketime.sh"
        script.write_text(
            "#!/bin/sh\n"
            f"# gerado por KRB_Handler para {host}\n"
            f"exec faketime -f '{offset}' \"$@\"\n"
        )
        script.chmod(0o755)
        chown_back(script)
        ok(f"Wrapper criado: {script}   (uso: {script} <sua-ferramenta> ...)")
        return

    if abs(skew) < SKEW_LIMIT:
        info(f"Skew de {int(abs(skew))}s esta dentro do limite ({SKEW_LIMIT}s) - sincronizando mesmo assim")

    st = read_state()
    if ntp_enabled():
        st["ntp_was_on"] = True
        subprocess.run(["timedatectl", "set-ntp", "false"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        info("NTP automatico desligado (senao ele desfaz o ajuste)")
    write_state(st)

    stamp = datetime.fromtimestamp(target_epoch, timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    r = subprocess.run(["date", "-u", "-s", stamp],
                       stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    if r.returncode == 0:
        ok(f"Relogio sincronizado com o KDC ({stamp} UTC)")
    else:
        err(f"Falha ao ajustar o relogio: {r.stderr.strip()}")


def restore_clock():
    st = read_state()
    if st.pop("ntp_was_on", False):
        subprocess.run(["timedatectl", "set-ntp", "true"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        ok("NTP automatico religado (relogio volta sozinho ao horario real)")
    write_state(st)


# ======================================================================
#  PARSER DE ARGUMENTOS
# ======================================================================
FLAGS_BOOL = ("--no-clock", "--no-hosts", "--faketime", "--weak")
FLAGS_VAL  = ("--realm", "--dc", "--profile", "--desc")


def parse_args(argv):
    pos, opts = [], {}
    i = 0
    while i < len(argv):
        a = argv[i]
        if a in FLAGS_BOOL:
            opts[a.lstrip("-")] = True
        elif a in FLAGS_VAL:
            if i + 1 >= len(argv):
                err(f"{a} exige um valor")
                sys.exit(1)
            opts[a.lstrip("-")] = argv[i + 1]
            i += 1
        elif a.startswith("--"):
            err(f"opcao desconhecida: {a}")
            sys.exit(1)
        else:
            pos.append(a)
        i += 1
    return pos, opts


# ======================================================================
#  COMANDOS
# ======================================================================
def resolve_target(target, opts):
    """Sonda o alvo e monta o dict de dados, respeitando --realm/--dc."""
    info(f"Sondando {CYN}{target}{R} ...")
    data = probe(target)

    forced = []
    if opts.get("realm"):
        data["domain"] = opts["realm"].lower()
        forced.append("--realm")
    if opts.get("dc"):
        data["fqdn"] = opts["dc"].lower()
        forced.append("--dc")
        if not data.get("domain") and data["fqdn"].count(".") >= 1:
            data["domain"] = data["fqdn"].split(".", 1)[1]
    if forced:
        detected = data.get("via")
        data["via"] = f"manual ({', '.join(forced)})" + (f" + {detected}" if detected else "")

    if not data.get("domain"):
        err("Nao consegui descobrir o dominio.")
        warn("O alvo respondeu? Tente com os valores na mao:")
        warn(f"  KRB_Handler.py set {target} --realm CORP.LOCAL --dc dc01.corp.local")
        sys.exit(1)

    data["realm"] = data["domain"].upper()
    if not data.get("fqdn"):
        warn("FQDN do DC nao detectado - usando o proprio alvo como KDC")
        data["fqdn"] = data.get("ip", target)

    print(f"    dominio  : {CYN}{data['domain']}{R}   (realm {data['realm']})")
    print(f"    DC       : {data['fqdn']}  [{data.get('ip','?')}]")
    if data.get("netbios_domain"):
        print(f"    NetBIOS  : {data['netbios_domain']}\\{data.get('netbios_host','?')}")
    if data.get("forest") and data["forest"] != data["domain"]:
        print(f"    floresta : {data['forest']}")
    print(f"    via      : {data.get('via', '?')}")
    return data


def apply_profile(prof, opts, clock_host=None, clock_epoch=None):
    write_krb5(prof)
    if not opts.get("no-hosts"):
        write_hosts(prof)
    if not opts.get("no-clock") and clock_epoch:
        sync_clock(clock_epoch, clock_host, faketime=bool(opts.get("faketime")))
    elif not opts.get("no-clock"):
        warn("Relogio do KDC nao obtido - pulei o sync (rode: KRB_Handler.py clock <alvo>)")
    save_profile(prof)
    set_active(prof["name"])


def cmd_set(argv, add=False):
    pos, opts = parse_args(argv)
    if not pos:
        err(f"uso: KRB_Handler.py {'add' if add else 'set'} <ip-ou-fqdn-do-DC> [opcoes]")
        sys.exit(1)
    data = resolve_target(pos[0], opts)

    if add:
        name = opts.get("profile") or active_profile()
        if not name:
            err("Nenhum perfil ativo. Use 'set' primeiro ou passe --profile <nome>.")
            sys.exit(1)
        prof = load_profile(name) or new_profile(name, opts.get("desc", ""))
    else:
        name = opts.get("profile") or data["domain"].split(".")[0]
        if not valid_name(name):
            err(f"nome de perfil invalido: {name}")
            sys.exit(1)
        prof = load_profile(name) or new_profile(name, opts.get("desc", ""))
        if opts.get("desc"):
            prof["description"] = opts["desc"]

    if opts.get("weak"):
        prof.setdefault("options", {})["weak_crypto"] = True

    merge_target(prof, data, make_default=not add)
    print()
    apply_profile(prof, opts, data.get("fqdn"), data.get("time"))
    print()
    ok(f"Perfil {CYN}{prof['name']}{R} ativo com {len(prof['realms'])} realm(s). "
       f"Pode usar suas ferramentas com -k / Kerberos.")


def cmd_use(argv):
    pos, opts = parse_args(argv)
    if not pos:
        err("uso: KRB_Handler.py use <perfil>")
        sys.exit(1)
    prof = load_profile(pos[0])
    if not prof:
        err(f"Perfil '{pos[0]}' nao existe. Veja:  KRB_Handler.py list")
        sys.exit(1)
    apply_profile(prof, opts, None, None)
    ok(f"Perfil {CYN}{prof['name']}{R} aplicado.")
    if not opts.get("no-clock"):
        first = next(iter(prof["realms"].values()), {})
        host = first.get("ip") or (first.get("kdc") or [None])[0]
        if host:
            info(f"Checando o relogio contra {host} ...")
            data = probe(host)
            if data.get("time"):
                sync_clock(data["time"], host, faketime=bool(opts.get("faketime")))
            else:
                warn("KDC nao respondeu - relogio nao verificado")


def cmd_list(argv):
    act = active_profile()
    names = list_profiles()
    if not names:
        info("Nenhum perfil ainda. Crie com:  KRB_Handler.py set <ip-do-DC>")
        return
    print(f"\n{B}Perfis Kerberos{R}   (* = ativo)\n")
    print(f"   {'NOME':<16}{'REALM PADRAO':<30}{'REALMS':>7}  DESCRICAO")
    print(f"   {'-'*14:<16}{'-'*28:<30}{'-'*6:>7}  {'-'*18}")
    for n in names:
        p = load_profile(n) or {}
        mark = f"{GRN}*{R}" if n == act else " "
        print(f" {mark} {n:<16}{p.get('default_realm','?'):<30}"
              f"{len(p.get('realms', {})):>7}  {p.get('description','')}")
    print()


def cmd_show(argv):
    pos, _ = parse_args(argv)
    name = pos[0] if pos else active_profile()
    if not name:
        err("Nenhum perfil ativo. uso: KRB_Handler.py show <perfil>")
        sys.exit(1)
    prof = load_profile(name)
    if not prof:
        err(f"Perfil '{name}' nao existe.")
        sys.exit(1)
    print(render_krb5(prof))
    if prof["hosts"]:
        print(render_hosts_block(prof))


def cmd_status(argv):
    act = active_profile()
    print(f"\n{B}Status Kerberos{R}")
    print(f"  Perfil ativo : {CYN}{act}{R}" if act else f"  Perfil ativo : {YLW}(nenhum){R}")

    realm, realms = "(nao definido)", []
    if KRB5_CONF.exists():
        for line in KRB5_CONF.read_text().splitlines():
            s = line.strip()
            if s.startswith("default_realm"):
                realm = s.split("=", 1)[1].strip()
            elif "=" in s and s.endswith("{"):
                realms.append(s.split("=")[0].strip())
    print(f"  krb5.conf    : {KRB5_CONF} {'(existe)' if KRB5_CONF.exists() else RED + '(ausente)' + R}")
    print(f"  default_realm: {CYN}{realm}{R}")
    print(f"  realms       : {', '.join(realms) if realms else '-'}")

    managed = []
    if HOSTS_FILE.exists():
        inside = False
        for line in HOSTS_FILE.read_text().splitlines():
            if line.startswith(HOSTS_BEGIN):
                inside = True
                continue
            if line.startswith(HOSTS_END):
                inside = False
                continue
            if inside and line.strip():
                managed.append(line.strip())
    print(f"  /etc/hosts   : {len(managed)} entrada(s) gerenciada(s)")
    for m in managed:
        print(f"                 {m}")

    if ntp_enabled():
        ntp_txt = "ligado"
    elif read_state().get("ntp_was_on"):
        ntp_txt = f"{YLW}desligado pelo KRB_Handler{R} ('restore' religa)"
    else:
        ntp_txt = "desligado (ja estava assim)"
    print(f"  NTP auto     : {ntp_txt}")
    print(f"  Hora local   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S %Z')}")

    prof = load_profile(act) if act else None
    if prof:
        first = next(iter(prof["realms"].values()), {})
        host = first.get("ip") or (first.get("kdc") or [None])[0]
        if host:
            data = probe(host)
            if data.get("time"):
                skew = data["time"] - time.time()
                color = GRN if abs(skew) < SKEW_LIMIT else RED
                print(f"  Skew vs KDC  : {color}{fmt_skew(skew)}{R}  (limite {SKEW_LIMIT}s)")
            else:
                print(f"  Skew vs KDC  : {YLW}KDC {host} nao respondeu{R}")
    print(f"  Perfis em    : {BASE}\n")


def cmd_check(argv):
    pos, _ = parse_args(argv)
    prof = load_profile(active_profile()) if active_profile() else None
    targets = []
    if pos:
        targets = [(None, pos[0])]           # alvo avulso: realm ainda desconhecido
    elif prof:
        for realm, e in prof["realms"].items():
            targets.append((realm, e.get("kdc", [e.get("ip")])[0]))
    if not targets:
        err("Nada para checar. uso: KRB_Handler.py check <alvo>")
        sys.exit(1)

    print(f"\n{B}Diagnostico Kerberos{R}\n")
    for realm, host in targets:
        print(f"  {CYN}{realm or host}{R}" + (f"  ->  {host}" if realm else ""))
        ip = host
        if not is_ip(host):
            try:
                ip = socket.gethostbyname(host)
                print(f"    [{GRN}ok{R}]   DNS/hosts: {host} -> {ip}")
            except OSError:
                print(f"    [{RED}x{R} ]   DNS/hosts: {host} NAO resolve  "
                      f"-> falta entrada no /etc/hosts")
                continue
        for port, label in ((88, "kerberos"), (445, "smb"), (389, "ldap"), (464, "kpasswd")):
            try:
                s = socket.create_connection((ip, port), 3)
                s.close()
                print(f"    [{GRN}ok{R}]   {port}/tcp {label}")
            except OSError:
                mark = RED + "x" + R if port == 88 else YLW + "!" + R
                print(f"    [{mark} ]   {port}/tcp {label} fechado")
        data = probe(ip)
        if data.get("time"):
            skew = data["time"] - time.time()
            good = abs(skew) < SKEW_LIMIT
            print(f"    [{GRN + 'ok' + R if good else RED + 'x ' + R}]   skew {fmt_skew(skew)}"
                  f"{'' if good else '  -> KRB_AP_ERR_SKEW; rode: KRB_Handler.py clock ' + host}")
        if data.get("domain"):
            if realm and data["domain"].upper() != realm.upper():
                print(f"    [{YLW}!{R} ]   o host diz ser de {data['domain'].upper()}, "
                      f"nao de {realm}  -> perfil desatualizado?")
            elif not realm:
                print(f"    [{GRN}ok{R}]   realm do host: {data['domain'].upper()}"
                      f"  ({data.get('fqdn','?')})")
    print()


def cmd_clock(argv):
    pos, opts = parse_args(argv)
    host = pos[0] if pos else None
    if not host:
        prof = load_profile(active_profile()) if active_profile() else None
        if prof:
            first = next(iter(prof["realms"].values()), {})
            host = first.get("ip") or (first.get("kdc") or [None])[0]
    if not host:
        err("uso: KRB_Handler.py clock <alvo>")
        sys.exit(1)
    info(f"Lendo o relogio de {CYN}{host}{R} ...")
    data = probe(host)
    if not data.get("time"):
        err(f"{host} nao devolveu horario (SMB 445 / NTP 123 fechados?)")
        sys.exit(1)
    sync_clock(data["time"], host, faketime=bool(opts.get("faketime")))


def cmd_hosts(argv):
    pos, _ = parse_args(argv)
    if len(pos) < 2:
        err("uso: KRB_Handler.py hosts <ip> <fqdn> [alias ...]")
        sys.exit(1)
    name = active_profile() or "manual"
    prof = load_profile(name) or new_profile(name)
    ip, fqdn, aliases = pos[0], pos[1].lower(), [a.lower() for a in pos[2:]]
    if not aliases and fqdn.count(".") >= 1:
        aliases = [fqdn.split(".")[0]]
    prof["hosts"] = [h for h in prof["hosts"] if h["fqdn"] != fqdn]
    prof["hosts"].append({"ip": ip, "fqdn": fqdn, "aliases": aliases})
    save_profile(prof)
    set_active(name)
    write_hosts(prof)


def cmd_del(argv):
    pos, _ = parse_args(argv)
    if not pos:
        err("uso: KRB_Handler.py del <perfil>")
        sys.exit(1)
    name = pos[0]
    if not profile_path(name).exists():
        err(f"Perfil '{name}' nao existe.")
        sys.exit(1)
    profile_path(name).unlink()
    if active_profile() == name:
        ACTIVE_F.unlink(missing_ok=True)
        warn("Era o perfil ativo - /etc/krb5.conf continua como esta. "
             "Use 'use <outro>' ou 'restore'.")
    info(f"Perfil '{name}' removido.")


def cmd_rename(argv):
    pos, _ = parse_args(argv)
    if len(pos) < 2 or not valid_name(pos[1]):
        err("uso: KRB_Handler.py rename <antigo> <novo>")
        sys.exit(1)
    old, new = pos
    if not profile_path(old).exists():
        err(f"Perfil '{old}' nao existe.")
        sys.exit(1)
    if profile_path(new).exists():
        err(f"Perfil '{new}' ja existe.")
        sys.exit(1)
    prof = load_profile(old)
    prof["name"] = new
    save_profile(prof)
    profile_path(old).unlink()
    if active_profile() == old:
        set_active(new)
    info(f"'{old}' -> '{new}'")


def cmd_restore(argv):
    orig = BACKUP_DIR / "krb5.conf.orig"
    if orig.exists():
        shutil.copy2(orig, KRB5_CONF)
        ok(f"/etc/krb5.conf restaurado do backup ({orig})")
    else:
        warn("Sem backup de krb5.conf - deixando como esta.")
    clear_hosts_block()
    ok("/etc/hosts: bloco do KRB_Handler removido")
    restore_clock()
    ACTIVE_F.unlink(missing_ok=True)
    info("Nenhum perfil ativo agora. Os perfis salvos continuam em disco.")


def cmd_help(argv):
    print(__doc__)


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

# Comandos que escrevem em /etc ou mexem no relogio precisam de root.
NEEDS_ROOT = {"set", "target", "add", "use", "switch", "hosts",
              "clock", "time", "sync", "restore", "revert"}


def main():
    argv = sys.argv[1:]

    if not argv or argv[0] in ("help", "-h", "--help"):
        cmd_help([])
        return

    cmd = argv[0]
    if cmd in NEEDS_ROOT and os.geteuid() != 0:
        os.execvp("sudo", ["sudo", "-E", sys.executable, os.path.abspath(__file__), *argv])

    init_paths()

    handler = COMMANDS.get(cmd)
    if not handler:
        err(f"comando desconhecido: {cmd}\n")
        cmd_help([])
        sys.exit(1)
    try:
        handler(argv[1:])
    except KeyboardInterrupt:
        print()
        warn("interrompido")
        sys.exit(130)


if __name__ == "__main__":
    main()
