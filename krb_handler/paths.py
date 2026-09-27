"""
Storage locations and safe file access.

User-owned profile data lives under ``~/.krb-profiles``; privileged state and
original backups are root-owned under ``/var/lib/krb-handler``. The module-level
path globals are populated by :func:`init_paths` and are read by other modules
through ``paths.<NAME>`` so they stay overridable (including in tests).
"""

import os
import pwd
import tempfile
from contextlib import contextmanager, nullcontext
from pathlib import Path

from .constants import SYSTEM_BASE
from .utils import real_user

BASE = PROF_DIR = ACTIVE_F = BACKUP_DIR = STATE_F = None


@contextmanager
def real_user_access():
    """Access profile files as the user that invoked sudo."""
    if os.geteuid() != 0:
        yield
        return
    try:
        account = pwd.getpwnam(real_user())
    except KeyError:
        raise RuntimeError("real user not found") from None
    if account.pw_uid == 0:
        yield
        return

    old_groups = os.getgroups()
    old_egid = os.getegid()
    try:
        os.setgroups(os.getgrouplist(account.pw_name, account.pw_gid))
        os.setegid(account.pw_gid)
        os.seteuid(account.pw_uid)
        yield
    finally:
        os.seteuid(0)
        os.setegid(old_egid)
        os.setgroups(old_groups)


def atomic_write(path, content, mode=0o600, owner_back=False):
    """Write state atomically on the destination filesystem."""
    access = real_user_access() if owner_back else nullcontext()
    with access:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
        tmp = Path(tmp_name)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            tmp.chmod(mode)
            os.replace(tmp, path)
        finally:
            try:
                tmp.unlink()
            except FileNotFoundError:
                pass


def ensure_system_storage():
    """Create privileged state outside user-writable directories."""
    if os.geteuid() != 0:
        return
    for path, mode in ((SYSTEM_BASE, 0o755), (BACKUP_DIR, 0o700)):
        if path.exists():
            st = path.lstat()
            if path.is_symlink() or not path.is_dir() or st.st_uid != 0:
                raise RuntimeError(f"insecure storage: {path} must be a root-owned directory")
        else:
            path.mkdir(parents=True, mode=mode)
        path.chmod(mode)


def init_paths(create=True):
    global BASE, PROF_DIR, ACTIVE_F, BACKUP_DIR, STATE_F
    ru = real_user()
    try:
        home = Path(pwd.getpwnam(ru).pw_dir)
    except KeyError:
        home = Path.home()
    BASE       = home / ".krb-profiles"
    PROF_DIR   = BASE / "profiles"
    ACTIVE_F   = BASE / "active"
    BACKUP_DIR = SYSTEM_BASE / "backup"
    STATE_F    = SYSTEM_BASE / "state.json"
    if create:
        with real_user_access():
            PROF_DIR.mkdir(parents=True, exist_ok=True)
        ensure_system_storage()
