"""Profile model: naming, validation, on-disk storage, and target merging."""

import json
from datetime import datetime, timezone

from . import paths
from .constants import DNS_LABEL_RE, PROFILE_NAME_RE
from .utils import is_ip, valid_description, valid_dns_name, valid_endpoint


def valid_name(name):
    return isinstance(name, str) and bool(PROFILE_NAME_RE.fullmatch(name))


def profile_path(name):
    if not valid_name(name):
        raise ValueError(f"invalid profile name: {name!r}")
    return paths.PROF_DIR / f"{name}.json"


def list_profiles():
    with paths.real_user_access():
        return sorted(p.stem for p in paths.PROF_DIR.glob("*.json") if valid_name(p.stem))


def active_profile():
    try:
        with paths.real_user_access():
            if paths.ACTIVE_F.exists():
                name = paths.ACTIVE_F.read_text(encoding="utf-8").strip()
                return name if valid_name(name) else None
    except OSError:
        pass
    return None


def set_active(name):
    if not valid_name(name):
        raise ValueError(f"invalid profile name: {name!r}")
    paths.atomic_write(paths.ACTIVE_F, name + "\n", owner_back=True)


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
        with paths.real_user_access():
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
    with paths.real_user_access():
        path.unlink(missing_ok=missing_ok)


def user_file_exists(path):
    with paths.real_user_access():
        return path.exists()


def save_profile(prof):
    clean = validate_profile(prof)
    p = profile_path(clean["name"])
    paths.atomic_write(p, json.dumps(clean, indent=2) + "\n", owner_back=True)
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
