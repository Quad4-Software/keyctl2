# SPDX-License-Identifier: 0BSD
"""Constants for the kernel key retention service.

Values are from linux/keyctl.h and keyutils.h. See keyctl(2), keyrings(7)
and the kernel documentation under Documentation/security/keys/.
"""

from enum import Enum, IntEnum, IntFlag

__all__ = [
    "KeyPerm",
    "KeySpec",
    "KeyType",
    "KeyctlOp",
    "MoveFlag",
    "ReqKeyDefault",
]


class KeySpec(IntEnum):
    """Special keyring IDs, resolved by the kernel per caller.

    The negative values are passed to the kernel verbatim; they are not
    real key serials.
    """

    THREAD_KEYRING = -1
    PROCESS_KEYRING = -2
    SESSION_KEYRING = -3
    USER_KEYRING = -4
    USER_SESSION_KEYRING = -5
    GROUP_KEYRING = -6
    REQKEY_AUTH_KEY = -7
    REQUESTOR_KEYRING = -8

    @classmethod
    def from_name(cls, name: str) -> "KeySpec":
        """Resolve a short name like "session" or "user" to a KeySpec."""
        table = {
            "thread": cls.THREAD_KEYRING,
            "process": cls.PROCESS_KEYRING,
            "session": cls.SESSION_KEYRING,
            "user": cls.USER_KEYRING,
            "user_session": cls.USER_SESSION_KEYRING,
            "group": cls.GROUP_KEYRING,
            "reqkey_auth": cls.REQKEY_AUTH_KEY,
            "requestor": cls.REQUESTOR_KEYRING,
        }
        try:
            return table[name]
        except KeyError:
            raise ValueError(f"unknown keyring name: {name!r}") from None


class KeyPerm(IntFlag):
    """Key permission bits, one hex digit per class.

    Each of the possessor, user, group and other classes holds the same
    six bits: VIEW, READ, WRITE, SEARCH, LINK and SETATTR. The ALL masks
    cover a whole class; KeyPerm.ALL covers everything.
    """

    NONE = 0
    POS_VIEW = 0x01000000
    POS_READ = 0x02000000
    POS_WRITE = 0x04000000
    POS_SEARCH = 0x08000000
    POS_LINK = 0x10000000
    POS_SETATTR = 0x20000000
    POS_ALL = 0x3F000000
    USR_VIEW = 0x00010000
    USR_READ = 0x00020000
    USR_WRITE = 0x00040000
    USR_SEARCH = 0x00080000
    USR_LINK = 0x00100000
    USR_SETATTR = 0x00200000
    USR_ALL = 0x003F0000
    GRP_VIEW = 0x00000100
    GRP_READ = 0x00000200
    GRP_WRITE = 0x00000400
    GRP_SEARCH = 0x00000800
    GRP_LINK = 0x00001000
    GRP_SETATTR = 0x00002000
    GRP_ALL = 0x00003F00
    OTH_VIEW = 0x00000001
    OTH_READ = 0x00000002
    OTH_WRITE = 0x00000004
    OTH_SEARCH = 0x00000008
    OTH_LINK = 0x00000010
    OTH_SETATTR = 0x00000020
    OTH_ALL = 0x0000003F
    ALL = 0x3F3F3F3F


class KeyType(str, Enum):
    """Common kernel key types.

    Plain strings are accepted everywhere a KeyType is, so types not
    listed here can still be used.
    """

    USER = "user"
    LOGON = "logon"
    KEYRING = "keyring"
    BIG_KEY = "big_key"
    ASYMMETRIC = "asymmetric"


class KeyctlOp(IntEnum):
    """Operation codes for the keyctl(2) syscall."""

    GET_KEYRING_ID = 0
    JOIN_SESSION_KEYRING = 1
    UPDATE = 2
    REVOKE = 3
    CHOWN = 4
    SETPERM = 5
    DESCRIBE = 6
    CLEAR = 7
    LINK = 8
    UNLINK = 9
    SEARCH = 10
    READ = 11
    SET_REQKEY_KEYRING = 14
    SET_TIMEOUT = 15
    SESSION_TO_PARENT = 18
    INVALIDATE = 21
    GET_PERSISTENT = 22
    RESTRICT_KEYRING = 29
    MOVE = 30
    CAPABILITIES = 31


class MoveFlag(IntFlag):
    """Flags for KEYCTL_MOVE."""

    NONE = 0
    EXCL = 0x00000001  # KEYCTL_MOVE_EXCL, do not displace a matching key


class ReqKeyDefault(IntEnum):
    """Default destination keyring for request_key(2), KEY_REQKEY_DEFL_*."""

    NO_CHANGE = -1
    DEFAULT = 0
    THREAD_KEYRING = 1
    PROCESS_KEYRING = 2
    SESSION_KEYRING = 3
    USER_KEYRING = 4
    USER_SESSION_KEYRING = 5
    GROUP_KEYRING = 6
    REQUESTOR_KEYRING = 7
