"""Small, dependency-free helpers: subprocess, identity, time, and validation."""

import ipaddress
import os
import pwd
import subprocess

from .constants import DNS_LABEL_RE, MAX_CLOCK_EPOCH, MIN_CLOCK_EPOCH


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
