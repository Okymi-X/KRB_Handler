"""KRB_Handler - Kerberos environment profile manager for authorized AD assessments.

The package is split into focused modules:

- ``constants``  - file locations, limits, and validation patterns
- ``ui``         - colored terminal output helpers
- ``utils``      - small validation and process helpers
- ``discovery``  - credential-free SMB2/LDAP/NTP probing
- ``paths``      - storage locations and safe/atomic file access
- ``profiles``   - profile model, validation, and on-disk storage
- ``render``     - krb5.conf and /etc/hosts generation
- ``system``     - writing and restoring managed system files
- ``clock``      - KDC clock synchronization and NTP bookkeeping
- ``cli``        - argument parsing, commands, and the ``main`` entry point
"""

from .constants import VERSION

__version__ = VERSION
__all__ = ["VERSION", "__version__"]
