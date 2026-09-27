"""Terminal output helpers with NO_COLOR support."""

import os
import sys

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
