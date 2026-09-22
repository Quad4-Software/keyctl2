# SPDX-License-Identifier: 0BSD
"""High-level interface to the kernel key retention service.

Serials returned by add_key() and friends are plain ints. Wrap one in a
Key to describe, read, update, link or revoke it. Keyring arguments
accept a serial, a KeySpec member or a short name like "session".

Kernel references: keyctl(2), add_key(2), request_key(2), keyrings(7).
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from . import _syscall
from .flags import KeyPerm, KeySpec, KeyType, MoveFlag, ReqKeyDefault

__all__ = [
    "Key",
    "KeyDescription",
    "add_key",
    "capabilities",
    "clear",
    "get_keyring_id",
    "get_persistent",
    "join_session_keyring",
    "keyring",
    "request_key",
    "restrict",
    "search",
    "session_to_parent",
    "set_reqkey_keyring",
]

_KeyringLike = int | KeySpec | str
_KeyTypeLike = str | KeyType


def _ring(ring: _KeyringLike) -> int:
    if isinstance(ring, str):
        return int(KeySpec.from_name(ring))
    return int(ring)


def _type(type_: _KeyTypeLike) -> bytes:
    if isinstance(type_, KeyType):
        type_ = type_.value
    return os.fsencode(type_)


def _desc(description: str) -> bytes:
    data = os.fsencode(description)
    if b"\x00" in data:
        raise ValueError("description must not contain NUL")
    return data


def add_key(
    type_: _KeyTypeLike,
    description: str,
    payload: bytes | None = None,
    keyring: _KeyringLike = KeySpec.SESSION_KEYRING,
) -> int:
    """Create a key in the given keyring and return its serial.

    If a matching key already exists in the keyring its payload is
    updated instead. EDQUOT means the caller's key quota is exhausted.
    """
    return _syscall.add_key(_type(type_), _desc(description), payload, _ring(keyring))


def request_key(
    type_: _KeyTypeLike,
    description: str,
    keyring: _KeyringLike = KeySpec.SESSION_KEYRING,
    callout_info: str | None = None,
) -> int:
    """Search the caller's keyrings for a key, return its serial.

    If the key is not found and callout_info is given, the kernel asks
    /sbin/request-key to instantiate it, passing callout_info along.
    With callout_info=None a miss raises ENOKEY.
    """
    info = None if callout_info is None else os.fsencode(callout_info)
    return _syscall.request_key(_type(type_), _desc(description), info, _ring(keyring))


def join_session_keyring(name: str | None = None) -> int:
    """Join or create a session keyring, return its serial.

    This replaces the calling process's session keyring. name=None
    joins a fresh anonymous keyring.
    """
    return _syscall.join_session_keyring(None if name is None else os.fsencode(name))


def get_keyring_id(ring: _KeyringLike, create: bool = False) -> int:
    """Resolve a key or special keyring ID to a real serial.

    With create=True, special keyring IDs are created on demand.
    """
    return _syscall.get_keyring_id(_ring(ring), create)


def keyring(ring: _KeyringLike) -> Key:
    """Wrap a keyring serial, KeySpec member or name in a Key."""
    return Key(_ring(ring))


def clear(ring: _KeyringLike) -> None:
    """Remove all links from a keyring."""
    _syscall.clear(_ring(ring))


def search(
    ring: _KeyringLike,
    type_: _KeyTypeLike,
    description: str,
    dest: _KeyringLike = 0,
) -> int:
    """Search a keyring tree for a key, return its serial.

    If dest is nonzero the found key is also linked into that keyring.
    ENOKEY means no matching key was found or it was not searchable.
    """
    return _syscall.search(_ring(ring), _type(type_), _desc(description), _ring(dest))


def restrict(
    ring: _KeyringLike,
    type_: _KeyTypeLike | None = None,
    restriction: str | None = None,
) -> None:
    """Restrict which keys may be linked into a keyring.

    With type=None and restriction=None the ring rejects all further
    links. A type may only be named if it implements a restriction
    scheme, like "asymmetric" does. The restriction string then selects
    the scheme, for example "builtin_trusted". Restriction is permanent.
    """
    _syscall.restrict_keyring(
        _ring(ring),
        None if type_ is None else _type(type_),
        None if restriction is None else os.fsencode(restriction),
    )


def session_to_parent() -> None:
    """Install this process's session keyring on the parent process."""
    _syscall.session_to_parent()


def get_persistent(uid: int, ring: _KeyringLike) -> int:
    """Return a user's persistent keyring, linked into ring.

    The persistent keyring survives logout for a kernel-configured
    grace period. EOPNOTSUPP means the kernel lacks persistent ring
    support.
    """
    return _syscall.get_persistent(uid, _ring(ring))


def set_reqkey_keyring(default: ReqKeyDefault) -> None:
    """Set the default destination ring for request_key(2) calls."""
    _syscall.set_reqkey_keyring(int(default))


def capabilities() -> bytes:
    """Return the keyrings subsystem capability bits."""
    return _syscall.capabilities()


@dataclass(frozen=True)
class KeyDescription:
    """Parsed result of KEYCTL_DESCRIBE."""

    type: str
    uid: int
    gid: int
    perm: KeyPerm
    description: str

    @classmethod
    def parse(cls, text: bytes) -> KeyDescription:
        """Parse a type;uid;gid;perm;description string.

        The description itself may contain semicolons, so at most four
        fields are split off the front.
        """
        parts = text.split(b";", 4)
        if len(parts) != 5:
            raise ValueError(f"malformed describe string: {text!r}")
        return cls(
            type=parts[0].decode("ascii"),
            uid=int(parts[1]),
            gid=int(parts[2]),
            perm=KeyPerm(int(parts[3], 16)),
            description=os.fsdecode(parts[4]),
        )


class Key:
    """A key or keyring, referenced by serial or KeySpec member."""

    __slots__ = ("_serial",)

    def __init__(self, serial: int | KeySpec) -> None:
        self._serial = int(serial)

    @property
    def serial(self) -> int:
        """The key serial number, possibly a negative KeySpec value."""
        return self._serial

    def describe(self) -> KeyDescription:
        """Fetch the key's attributes."""
        return KeyDescription.parse(_syscall.describe(self._serial))

    def read(self) -> bytes:
        """Read the key's payload, or a keyring's serial list.

        EKEYREVOKED, EKEYEXPIRED or EACCES mean the key can no longer be
        read by this caller.
        """
        return _syscall.read(self._serial)

    def update(self, payload: bytes | None) -> None:
        """Replace the key's payload."""
        _syscall.update(self._serial, payload)

    def set_timeout(self, seconds: int) -> None:
        """Make the key expire after the given number of seconds."""
        if seconds < 0:
            raise ValueError(f"timeout out of range: {seconds}")
        _syscall.set_timeout(self._serial, seconds)

    def set_perm(self, perm: KeyPerm) -> None:
        """Set the key's permission mask."""
        _syscall.setperm(self._serial, int(perm))

    def link(self, ring: _KeyringLike) -> None:
        """Link the key into a keyring."""
        _syscall.link(self._serial, _ring(ring))

    def unlink(self, ring: _KeyringLike) -> None:
        """Remove the key's link from a keyring."""
        _syscall.unlink(self._serial, _ring(ring))

    def move(
        self,
        from_ring: _KeyringLike,
        to_ring: _KeyringLike,
        flags: MoveFlag = MoveFlag.NONE,
    ) -> None:
        """Atomically move the key's link between two keyrings.

        With MoveFlag.EXCL, a matching key already in to_ring is kept
        and the call fails with EEXIST instead of displacing it.
        """
        _syscall.move(self._serial, _ring(from_ring), _ring(to_ring), int(flags))

    def revoke(self) -> None:
        """Revoke the key, making it unusable."""
        _syscall.revoke(self._serial)

    def invalidate(self) -> None:
        """Mark the key invalid, making it vanish promptly."""
        _syscall.invalidate(self._serial)

    def chown(self, uid: int = -1, gid: int = -1) -> None:
        """Set the key's owner. -1 leaves a field unchanged."""
        _syscall.chown(self._serial, uid, gid)

    def search(
        self,
        type_: _KeyTypeLike,
        description: str,
        dest: _KeyringLike = 0,
    ) -> int:
        """Search this keyring for a key, return its serial."""
        return search(self._serial, type_, description, dest)

    def __int__(self) -> int:
        return self._serial

    def __repr__(self) -> str:
        return f"{type(self).__name__}({self._serial})"

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Key):
            return self._serial == other._serial
        return NotImplemented

    def __hash__(self) -> int:
        return hash(self._serial)
