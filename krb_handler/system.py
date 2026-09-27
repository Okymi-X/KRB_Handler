"""Write and restore the system files the tool manages: krb5.conf and /etc/hosts."""

import os
import shutil
import tempfile
from pathlib import Path

from . import paths, render
from .constants import HOSTS_BEGIN, HOSTS_END, HOSTS_FILE, KRB5_CONF
from .profiles import new_profile, validate_profile
from .ui import CYN, R, info, ok


def backup_once(path):
    """Save one copy of the original file."""
    paths.ensure_system_storage()
    dst = paths.BACKUP_DIR / (path.name + ".orig")
    if not dst.exists() and path.exists():
        shutil.copy2(path, dst)
        dst.chmod(0o600)
        info(f"Original backup saved to {dst}")


def write_system_text(path, content, mode=0o644):
    """Write a system file atomically with predictable permissions."""
    if path.exists():
        st = path.lstat()
        if path.is_symlink() or not path.is_file() or st.st_uid != 0:
            raise RuntimeError(f"insecure system file: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        tmp.chmod(mode)
        if os.geteuid() == 0:
            os.chown(tmp, 0, 0)
        os.replace(tmp, path)
        path.chmod(mode)
        if os.geteuid() == 0:
            os.chown(path, 0, 0)
        try:
            dir_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except OSError:
            pass
    finally:
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass


def write_krb5(prof):
    prof = validate_profile(prof)
    backup_once(KRB5_CONF)
    write_system_text(KRB5_CONF, render.render_krb5(prof), mode=0o644)
    ok(f"/etc/krb5.conf written  (default_realm = {CYN}{prof['default_realm']}{R})")


def write_hosts(prof):
    prof = validate_profile(prof)
    backup_once(HOSTS_FILE)
    current = HOSTS_FILE.read_text(encoding="utf-8") if HOSTS_FILE.exists() else ""
    body = remove_hosts_block(current).rstrip("\n") + "\n"
    if prof["hosts"]:
        body += "\n" + render.render_hosts_block(prof)
    write_system_text(HOSTS_FILE, body, mode=0o644)
    if prof["hosts"]:
        ok(f"/etc/hosts updated ({len(prof['hosts'])} profile entries)")


def remove_hosts_block(content):
    """Remove one complete managed block and reject ambiguous marker layouts."""
    lines = content.splitlines(keepends=True)
    begins = [i for i, line in enumerate(lines) if line.startswith(HOSTS_BEGIN)]
    ends = [i for i, line in enumerate(lines) if line.startswith(HOSTS_END)]
    if not begins and not ends:
        return content
    if len(begins) != 1 or len(ends) != 1 or begins[0] >= ends[0]:
        raise RuntimeError(
            f"refusing to modify {HOSTS_FILE}: malformed KRB_Handler marker block"
        )
    return "".join(lines[:begins[0]] + lines[ends[0] + 1:])


def clear_hosts_block():
    if not HOSTS_FILE.exists():
        return
    prof = new_profile("restore")
    write_hosts(prof)
