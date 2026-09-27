# Changelog

All notable changes to KRB_Handler are documented here.

## 0.3.0

- Restructured the single `KRB_Handler.py` script into a `krb_handler` package
  with focused modules (`constants`, `ui`, `utils`, `discovery`, `paths`,
  `profiles`, `render`, `system`, `clock`, `cli`). No behavior changes.
- Added `python -m krb_handler` as an entry point; privilege re-elevation now
  re-executes the module instead of a file path.
- Kept `KRB_Handler.py` as a thin backward-compatible launcher so
  `python3 KRB_Handler.py` still works from a source checkout.
- Updated the test suite to exercise the new module layout (23 tests).

## 0.2.0

- Rewrote the user documentation and command help in English.
- Added command-specific help and strict positional argument validation.
- Added `--dry-run` previews that do not elevate privileges or create state.
- Added support for `--option=value` syntax.
- Reject malformed managed blocks instead of risking unrelated `/etc/hosts` data.
- Report invalid profile files instead of silently treating them as missing.
- Use the default realm, rather than insertion order, as the clock source.
- Validate SMB and NTP timestamps before attempting a clock change.
- Validate NTP response mode and stratum and handle the NTP era rollover.
- Re-enable automatic NTP when a clock adjustment fails.
- Store privileged state with mode `0600`.
- Derive the invoking sudo account from its numeric UID.
- Use the Python module as the single source of truth for the package version.
- Expanded regression coverage from 10 to 23 tests.

## 0.1.0

- Initial packaged release with pipx installation support.
- Added profile validation, atomic writes, and root-owned system backups.
