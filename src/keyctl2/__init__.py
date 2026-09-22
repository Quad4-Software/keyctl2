# SPDX-License-Identifier: 0BSD
"""Python bindings for the Linux kernel key retention service.

Create and search keys and keyrings through add_key(2), request_key(2)
and keyctl(2) via ctypes; there are no runtime dependencies.

Kernel references: keyctl(2), add_key(2), request_key(2), keyrings(7).
"""

from .errors import KeyctlError, UnsupportedError
from .flags import (
    KeyctlOp,
    KeyPerm,
    KeySpec,
    KeyType,
    MoveFlag,
    ReqKeyDefault,
)
from .keys import (
    Key,
    KeyDescription,
    add_key,
    capabilities,
    clear,
    get_keyring_id,
    get_persistent,
    join_session_keyring,
    keyring,
    request_key,
    restrict,
    search,
    session_to_parent,
    set_reqkey_keyring,
)

__version__ = "0.1.0"

__all__ = [
    "Key",
    "KeyDescription",
    "KeyPerm",
    "KeySpec",
    "KeyType",
    "KeyctlError",
    "KeyctlOp",
    "MoveFlag",
    "ReqKeyDefault",
    "UnsupportedError",
    "__version__",
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
