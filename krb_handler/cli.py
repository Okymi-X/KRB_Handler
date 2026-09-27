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

import os
import shutil
import socket
import sys
import time
from datetime import datetime, timezone

from . import clock, discovery, paths, profiles, render, system
from .constants import (
    DNS_LABEL_RE,
    HOSTS_BEGIN,
    HOSTS_END,
    HOSTS_FILE,
    KRB5_CONF,
    SKEW_LIMIT,
    VERSION,
)
from .ui import CYN, GRN, RED, YLW, B, R, err, info, ok, warn
from .utils import (
    fmt_skew,
    is_ip,
    valid_description,
    valid_dns_name,
    valid_endpoint,
)

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
    data = discovery.probe(target)

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
    prof = profiles.validate_profile(prof)
    if opts.get("dry-run"):
        print(f"\n{B}--- /etc/krb5.conf (preview) ---{R}")
        print(render.render_krb5(prof), end="")
        if not opts.get("no-hosts"):
            print(f"\n{B}--- managed /etc/hosts block (preview) ---{R}")
            print(render.render_hosts_block(prof), end="")
        if not opts.get("no-clock") and clock_epoch:
            print(f"\nClock adjustment: {fmt_skew(clock_epoch - time.time())} compared to {clock_host}")
        info("Dry run complete; no files, profiles, or clock settings were changed")
        return False
    system.write_krb5(prof)
    if not opts.get("no-hosts"):
        system.write_hosts(prof)
    if not opts.get("no-clock") and clock_epoch:
        clock.sync_clock(clock_epoch, clock_host, faketime=bool(opts.get("faketime")))
    elif not opts.get("no-clock"):
        warn("KDC clock was not obtained - skipped sync (run: krb-handler clock <target>)")
    profiles.save_profile(prof)
    profiles.set_active(prof["name"])
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
        name = opts.get("profile") or profiles.active_profile()
        if not name or not profiles.valid_name(name):
            err("No active profile. Use 'set' first or pass --profile <name>.")
            sys.exit(1)
        prof = profiles.load_profile(name) or profiles.new_profile(name, opts.get("desc", ""))
    else:
        name = opts.get("profile") or data["domain"].split(".")[0]
        if not profiles.valid_name(name):
            err(f"invalid profile name: {name}")
            sys.exit(1)
        prof = profiles.load_profile(name) or profiles.new_profile(name, opts.get("desc", ""))
        if opts.get("desc"):
            prof["description"] = opts["desc"]

    if opts.get("weak"):
        prof.setdefault("options", {})["weak_crypto"] = True

    profiles.merge_target(prof, data, make_default=not add)
    print()
    changed = apply_profile(prof, opts, data.get("fqdn"), data.get("time"))
    print()
    if changed:
        ok(f"Profile {CYN}{prof['name']}{R} active with {len(prof['realms'])} realm(s). "
           f"You can use your tools with -k / Kerberos.")


def cmd_use(argv):
    pos, opts = parse_args(argv, USE_BOOL_FLAGS)
    require_positionals(pos, 1, 1, "krb-handler use <profile> [options]")
    prof = profiles.load_profile(pos[0])
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
        host = profiles.profile_clock_host(prof)
        if host:
            info(f"Checking the clock against {host} ...")
            data = discovery.probe(host)
            if data.get("time"):
                clock.sync_clock(data["time"], host, faketime=bool(opts.get("faketime")))
            else:
                warn("KDC did not answer - clock was not verified")


def cmd_list(argv):
    pos, _ = parse_args(argv)
    require_positionals(pos, 0, 0, "krb-handler list")
    act = profiles.active_profile()
    names = profiles.list_profiles()
    if not names:
        info("No profiles yet. Create one with:  krb-handler set <DC-ip>")
        return
    print(f"\n{B}Kerberos Profiles{R}   (* = active)\n")
    print(f"   {'NAME':<16}{'DEFAULT REALM':<30}{'REALMS':>7}  DESCRIPTION")
    print(f"   {'-'*14:<16}{'-'*28:<30}{'-'*6:>7}  {'-'*18}")
    for n in names:
        p = profiles.load_profile(n) or {}
        mark = f"{GRN}*{R}" if n == act else " "
        print(f" {mark} {n:<16}{p.get('default_realm','?'):<30}"
              f"{len(p.get('realms', {})):>7}  {p.get('description','')}")
    print()


def cmd_show(argv):
    pos, _ = parse_args(argv)
    require_positionals(pos, 0, 1, "krb-handler show [profile]")
    name = pos[0] if pos else profiles.active_profile()
    if not name:
        err("No active profile. usage: krb-handler show <profile>")
        sys.exit(1)
    prof = profiles.load_profile(name)
    if not prof:
        err(f"Profile '{name}' does not exist.")
        sys.exit(1)
    print(render.render_krb5(prof))
    if prof["hosts"]:
        print(render.render_hosts_block(prof))


def cmd_status(argv):
    pos, _ = parse_args(argv)
    require_positionals(pos, 0, 0, "krb-handler status")
    act = profiles.active_profile()
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

    if clock.ntp_enabled():
        ntp_txt = "enabled"
    elif clock.read_state().get("ntp_was_on"):
        ntp_txt = f"{YLW}disabled by KRB_Handler{R} ('restore' re-enables it)"
    else:
        ntp_txt = "disabled (already disabled)"
    print(f"  Auto NTP     : {ntp_txt}")
    local_time = datetime.now(timezone.utc).astimezone()
    print(f"  Local time   : {local_time.strftime('%Y-%m-%d %H:%M:%S %Z')}")

    prof = profiles.load_profile(act) if act else None
    if prof:
        host = profiles.profile_clock_host(prof)
        if host:
            data = discovery.probe(host)
            if data.get("time"):
                skew = data["time"] - time.time()
                color = GRN if abs(skew) < SKEW_LIMIT else RED
                print(f"  Skew vs KDC  : {color}{fmt_skew(skew)}{R}  (limit {SKEW_LIMIT}s)")
            else:
                print(f"  Skew vs KDC  : {YLW}KDC {host} did not answer{R}")
    print(f"  Profiles in  : {paths.BASE}\n")


def cmd_check(argv):
    pos, _ = parse_args(argv)
    require_positionals(pos, 0, 1, "krb-handler check [target]")
    if pos and not valid_endpoint(pos[0]):
        err(f"invalid target: {pos[0]!r}")
        sys.exit(1)
    prof = profiles.load_profile(profiles.active_profile()) if profiles.active_profile() else None
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
        data = discovery.probe(ip)
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
        prof = profiles.load_profile(profiles.active_profile()) if profiles.active_profile() else None
        if prof:
            host = profiles.profile_clock_host(prof)
    if not host:
        err("usage: krb-handler clock <target>")
        sys.exit(1)
    info(f"Reading clock from {CYN}{host}{R} ...")
    data = discovery.probe(host)
    if not data.get("time"):
        err(f"{host} did not return a timestamp (SMB 445 / NTP 123 closed?)")
        sys.exit(1)
    if opts.get("dry-run"):
        print(f"Clock adjustment: {fmt_skew(data['time'] - time.time())} compared to {host}")
        info("Dry run complete; the system clock was not changed")
        return
    clock.sync_clock(data["time"], host, faketime=bool(opts.get("faketime")))


def cmd_hosts(argv):
    pos, opts = parse_args(argv, {"--dry-run"})
    if len(pos) < 2:
        err("usage: krb-handler hosts <ip> <fqdn> [alias ...]")
        sys.exit(1)
    name = profiles.active_profile() or "manual"
    prof = profiles.load_profile(name) or profiles.new_profile(name)
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
        print(render.render_hosts_block(prof), end="")
        info("Dry run complete; the profile and /etc/hosts were not changed")
        return
    profiles.save_profile(prof)
    profiles.set_active(name)
    system.write_hosts(prof)


def cmd_del(argv):
    pos, _ = parse_args(argv)
    require_positionals(pos, 1, 1, "krb-handler del <profile>")
    name = pos[0]
    if not profiles.valid_name(name):
        err(f"invalid profile name: {name!r}")
        sys.exit(1)
    if not profiles.user_file_exists(profiles.profile_path(name)):
        err(f"Profile '{name}' does not exist.")
        sys.exit(1)
    profiles.unlink_user_file(profiles.profile_path(name))
    if profiles.active_profile() == name:
        profiles.unlink_user_file(paths.ACTIVE_F, missing_ok=True)
        warn("It was the active profile - /etc/krb5.conf was left as-is. "
             "Use 'use <other>' or 'restore'.")
    info(f"Profile '{name}' deleted.")


def cmd_rename(argv):
    pos, _ = parse_args(argv)
    require_positionals(pos, 2, 2, "krb-handler rename <old> <new>")
    if not profiles.valid_name(pos[0]) or not profiles.valid_name(pos[1]):
        err("usage: krb-handler rename <old> <new>")
        sys.exit(1)
    old, new = pos
    if not profiles.user_file_exists(profiles.profile_path(old)):
        err(f"Profile '{old}' does not exist.")
        sys.exit(1)
    if profiles.user_file_exists(profiles.profile_path(new)):
        err(f"Profile '{new}' already exists.")
        sys.exit(1)
    prof = profiles.load_profile(old)
    prof["name"] = new
    profiles.save_profile(prof)
    profiles.unlink_user_file(profiles.profile_path(old))
    if profiles.active_profile() == old:
        profiles.set_active(new)
    info(f"'{old}' -> '{new}'")


def cmd_restore(argv):
    pos, _ = parse_args(argv)
    require_positionals(pos, 0, 0, "krb-handler restore")
    orig = paths.BACKUP_DIR / "krb5.conf.orig"
    if orig.exists():
        system.write_system_text(KRB5_CONF, orig.read_text(encoding="utf-8"), mode=0o644)
        ok(f"/etc/krb5.conf restored from backup ({orig})")
    else:
        warn("No krb5.conf backup found - leaving it as-is.")
    system.clear_hosts_block()
    ok("/etc/hosts: KRB_Handler block removed")
    clock.restore_clock()
    profiles.unlink_user_file(paths.ACTIVE_F, missing_ok=True)
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
        os.execv(sudo, [sudo, "--", sys.executable, "-m", "krb_handler", *argv])

    try:
        paths.init_paths(create=cmd in NEEDS_ROOT and not dry_run)
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
