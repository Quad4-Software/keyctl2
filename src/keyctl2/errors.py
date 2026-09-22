# SPDX-License-Identifier: 0BSD
"""Exception types raised by keyctl2."""


class KeyctlError(OSError):
    """A key management syscall failed.

    The errno attribute carries the kernel error. Common values are
    ENOKEY for a missing or non-searchable key, EACCES for a revoked,
    expired or inaccessible key, EDQUOT for an exceeded key quota and
    EKEYEXPIRED or EKEYREVOKED for keys in those states.
    """


class UnsupportedError(KeyctlError):
    """The running kernel or architecture does not support the operation."""
