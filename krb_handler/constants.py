"""Shared constants: file locations, limits, and validation patterns."""

import re
from pathlib import Path

KRB5_CONF   = Path("/etc/krb5.conf")
HOSTS_FILE  = Path("/etc/hosts")
HOSTS_BEGIN = "# >>> KRB_Handler"
HOSTS_END   = "# <<< KRB_Handler"
SKEW_LIMIT = 120                  # AD Kerberos rejects tickets above this skew
PROBE_TO = 4                      # socket timeout for probes
MAX_SMB_FRAME = 1024 * 1024       # probe responses should not need more than 1 MiB
MIN_CLOCK_EPOCH = 946_684_800      # 2000-01-01 UTC
MAX_CLOCK_EPOCH = 4_102_444_800    # 2100-01-01 UTC
VERSION = "0.3.0"

# Privileged state lives outside user-writable directories.
SYSTEM_BASE = Path("/var/lib/krb-handler")

PROFILE_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
DNS_LABEL_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z")
