"""Prevent multiple local CDSS servers from sharing port 5000."""

from pathlib import Path
import os


class AlreadyRunningError(RuntimeError):
    pass


_LOCK_HANDLE = None


def acquire_server_lock():
    global _LOCK_HANDLE
    lock_path = Path(__file__).resolve().parents[1] / "data" / "server.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    handle = lock_path.open("a+b")
    if lock_path.stat().st_size == 0:
        handle.write(b"0")
        handle.flush()
    handle.seek(0)
    try:
        if os.name == "nt":
            import msvcrt
            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as error:
        handle.close()
        raise AlreadyRunningError(
            "CDSS is already running. Stop the existing port 5000 instance before restarting."
        ) from error
    _LOCK_HANDLE = handle
    return handle
