# SPDX-License-Identifier: 0BSD

import os
import sys

import pytest

from keyctl2 import KeyctlError, join_session_keyring

requires_linux = pytest.mark.skipif(sys.platform != "linux", reason="Linux only")


def _probe() -> int:
    """Fork a child that joins a session keyring; return its exit code.

    The probe runs in a child so the test process's own keyrings are
    never touched.
    """
    pid = os.fork()
    if pid == 0:
        code = 0
        try:
            join_session_keyring(f"keyctl2-probe-{os.getpid()}")
        except KeyctlError as exc:
            code = exc.errno or 1
        except BaseException:  # noqa: BLE001 - probe must not reach pytest
            code = 1
        os._exit(code)
    _, status = os.waitpid(pid, 0)
    return os.waitstatus_to_exitcode(status)


_PROBE_CODE: int | None = None


def keys_available() -> bool:
    """Whether the keyrings syscalls work on this kernel."""
    global _PROBE_CODE
    if _PROBE_CODE is None:
        _PROBE_CODE = _probe()
    return _PROBE_CODE == 0


requires_keys = pytest.mark.skipif(
    not keys_available(),
    reason="kernel keyrings unavailable (ENOSYS or EACCES)",
)
