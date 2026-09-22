# SPDX-License-Identifier: 0BSD
"""Raw ctypes bindings for add_key(2), request_key(2) and keyctl(2).

glibc has no wrappers for these syscalls on most architectures, so all
three are invoked through libc's syscall(2). The numbers differ per
architecture; the table covers the common ones and everything else gets
UnsupportedError.
"""

import ctypes
import ctypes.util
import errno
import os
import platform
import sys
from typing import NoReturn

from .errors import KeyctlError, UnsupportedError
from .flags import KeyctlOp

_libc: ctypes.CDLL | None = None
_numbers: tuple[int, int, int] | None = None


def _get_libc() -> ctypes.CDLL:
    global _libc
    if _libc is None:
        if sys.platform != "linux":
            raise UnsupportedError("keyctl2 is only available on Linux")
        name = ctypes.util.find_library("c")
        _libc = ctypes.CDLL(name or None, use_errno=True)
        _libc.syscall.restype = ctypes.c_long
    return _libc


def _syscall_numbers() -> tuple[int, int, int]:
    """Return the (add_key, request_key, keyctl) numbers for this arch."""
    global _numbers
    if _numbers is not None:
        return _numbers
    machine = platform.machine().lower()
    if machine in ("x86_64", "amd64"):
        _numbers = (248, 249, 250)
    elif machine in ("aarch64", "arm64", "riscv64", "loongarch64"):
        # asm-generic syscall table
        _numbers = (217, 218, 219)
    elif machine in ("i386", "i486", "i586", "i686", "x86"):
        _numbers = (286, 287, 288)
    else:
        raise UnsupportedError(
            f"no add_key/request_key/keyctl numbers for architecture {machine}"
        )
    return _numbers


def _raise_errno(err: int) -> NoReturn:
    if err in (errno.ENOSYS, errno.EOPNOTSUPP):
        raise UnsupportedError(err, os.strerror(err))
    raise KeyctlError(err, os.strerror(err))


def _call(nr: int, *args: object) -> int:
    ret = int(_get_libc().syscall(nr, *args))
    if ret == -1:
        _raise_errno(ctypes.get_errno())
    return ret


def _keyctl(op: int, *args: object) -> int:
    return _call(_syscall_numbers()[2], op, *args)


def _u32(value: int) -> ctypes.c_uint32:
    # unsigned 32-bit argument, so -1 style sentinels marshal correctly
    return ctypes.c_uint32(value & 0xFFFFFFFF)


def add_key(
    type_: bytes,
    description: bytes | None,
    payload: bytes | None,
    ringid: int,
) -> int:
    """add_key(2): create or update a key in ringid, return its serial."""
    plen = 0 if payload is None else len(payload)
    return _call(_syscall_numbers()[0], type_, description, payload, plen, ringid)


def request_key(
    type_: bytes,
    description: bytes,
    callout_info: bytes | None,
    ringid: int,
) -> int:
    """request_key(2): find or conjure a key, return its serial."""
    return _call(_syscall_numbers()[1], type_, description, callout_info, ringid)


def get_keyring_id(ringid: int, create: bool) -> int:
    """KEYCTL_GET_KEYRING_ID: resolve a key or special ID to a serial."""
    return _keyctl(KeyctlOp.GET_KEYRING_ID, ringid, int(create))


def join_session_keyring(name: bytes | None) -> int:
    """KEYCTL_JOIN_SESSION_KEYRING: return the joined ring's serial."""
    return _keyctl(KeyctlOp.JOIN_SESSION_KEYRING, name)


def update(serial: int, payload: bytes | None) -> None:
    """KEYCTL_UPDATE: replace a key's payload."""
    plen = 0 if payload is None else len(payload)
    _keyctl(KeyctlOp.UPDATE, serial, payload, plen)


def revoke(serial: int) -> None:
    """KEYCTL_REVOKE: revoke a key."""
    _keyctl(KeyctlOp.REVOKE, serial)


def chown(serial: int, uid: int, gid: int) -> None:
    """KEYCTL_CHOWN: set ownership; -1 leaves a field unchanged."""
    _keyctl(KeyctlOp.CHOWN, serial, _u32(uid), _u32(gid))


def setperm(serial: int, perm: int) -> None:
    """KEYCTL_SETPERM: set a key's permission mask."""
    _keyctl(KeyctlOp.SETPERM, serial, _u32(perm))


def describe(serial: int) -> bytes:
    """KEYCTL_DESCRIBE: return the type;uid;gid;perm;description string."""
    size = _keyctl(KeyctlOp.DESCRIBE, serial, None, 0)
    buf = ctypes.create_string_buffer(size)
    _keyctl(KeyctlOp.DESCRIBE, serial, buf, size)
    return bytes(buf.value)


def clear(ringid: int) -> None:
    """KEYCTL_CLEAR: remove all links from a keyring."""
    _keyctl(KeyctlOp.CLEAR, ringid)


def link(serial: int, ringid: int) -> None:
    """KEYCTL_LINK: link a key into a keyring."""
    _keyctl(KeyctlOp.LINK, serial, ringid)


def unlink(serial: int, ringid: int) -> None:
    """KEYCTL_UNLINK: remove a key's link from a keyring."""
    _keyctl(KeyctlOp.UNLINK, serial, ringid)


def search(ringid: int, type_: bytes, description: bytes, destringid: int) -> int:
    """KEYCTL_SEARCH: find a key in a ring, return its serial."""
    return _keyctl(KeyctlOp.SEARCH, ringid, type_, description, destringid)


def read(serial: int) -> bytes:
    """KEYCTL_READ: return a key's payload or a keyring's serial list."""
    size = _keyctl(KeyctlOp.READ, serial, None, 0)
    if size == 0:
        return b""
    buf = ctypes.create_string_buffer(size)
    got = _keyctl(KeyctlOp.READ, serial, buf, size)
    return buf.raw[:got]


def set_reqkey_keyring(default: int) -> int:
    """KEYCTL_SET_REQKEY_KEYRING: set the request_key(2) default ring."""
    return _keyctl(KeyctlOp.SET_REQKEY_KEYRING, default)


def set_timeout(serial: int, timeout: int) -> None:
    """KEYCTL_SET_TIMEOUT: expire a key after timeout seconds."""
    _keyctl(KeyctlOp.SET_TIMEOUT, serial, _u32(timeout))


def session_to_parent() -> None:
    """KEYCTL_SESSION_TO_PARENT: install our session keyring on the parent."""
    _keyctl(KeyctlOp.SESSION_TO_PARENT)


def invalidate(serial: int) -> None:
    """KEYCTL_INVALIDATE: mark a key invalid."""
    _keyctl(KeyctlOp.INVALIDATE, serial)


def get_persistent(uid: int, ringid: int) -> int:
    """KEYCTL_GET_PERSISTENT: return a user's persistent keyring serial."""
    return _keyctl(KeyctlOp.GET_PERSISTENT, _u32(uid), ringid)


def restrict_keyring(
    ringid: int, type_: bytes | None, restriction: bytes | None
) -> None:
    """KEYCTL_RESTRICT_KEYRING: limit which keys may link to a ring."""
    _keyctl(KeyctlOp.RESTRICT_KEYRING, ringid, type_, restriction)


def move(serial: int, from_ringid: int, to_ringid: int, flags: int) -> None:
    """KEYCTL_MOVE: move a key's link between keyrings."""
    _keyctl(KeyctlOp.MOVE, serial, from_ringid, to_ringid, _u32(flags))


def capabilities() -> bytes:
    """KEYCTL_CAPABILITIES: return the subsystem capability bits."""
    buf = ctypes.create_string_buffer(8)
    got = _keyctl(KeyctlOp.CAPABILITIES, buf, len(buf))
    return buf.raw[:got]
