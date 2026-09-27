#!/usr/bin/env python3
"""Backward-compatible launcher for the :mod:`krb_handler` package.

The tool was originally a single script. It is now a package under
``krb_handler/``; this file remains so that ``python3 KRB_Handler.py ...`` keeps
working from a source checkout. The installed ``krb-handler`` command and
``python -m krb_handler`` are the preferred entry points.
"""

import os
import sys

# Make the package importable when run as a loose script from the repo root.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from krb_handler.cli import main

if __name__ == "__main__":
    main()
