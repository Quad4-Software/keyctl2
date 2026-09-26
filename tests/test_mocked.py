# SPDX-License-Identifier: 0BSD
"""Error-path and edge-case tests with libc stubbed out.

A fake libc.syscall returns a fixed result and errno, so marshalling,
error mapping and the buffer retry logic are covered in-process
without touching the kernel.
"""

import ctypes
import errno
import platform
import sys
from collections.abc import Callable
from typing import Any

import pytest

import keyctl2._syscall as _syscall
from keyctl2 import (
    Key,
    KeyctlError,
    KeyctlOp,
    KeyPerm,
    KeySpec,
    KeyType,
    MoveFlag,
    ReqKeyDefault,
    UnsupportedError,
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

from .conftest import requires_linux


class _FakeLibc:
    """Stand-in for a ctypes.CDLL, exposing only syscall()."""

    def __init__(self, ret: int, err: int = 0) -> None:
        self.ret = ret
        self.err = err
        self.calls: list[tuple[int, tuple[object, ...]]] = []

    def syscall(self, nr: int, *args: object) -> int:
        self.calls.append((nr, args))
        if self.ret == -1:
            ctypes.set_errno(self.err)
        return self.ret


def _install_libc(
    monkeypatch: pytest.MonkeyPatch, ret: int = 0, err: int = 0
) -> _FakeLibc:
    fake = _FakeLibc(ret, err)
    monkeypatch.setattr(_syscall, "_libc", fake)
    return fake


def test_call_returns_syscall_result(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _install_libc(monkeypatch, ret=42)
    assert _syscall._call(250, 1, b"x") == 42
    assert fake.calls == [(250, (1, b"x"))]


def test_call_raises_keyctl_error_with_errno(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_libc(monkeypatch, ret=-1, err=errno.EACCES)
    with pytest.raises(KeyctlError) as excinfo:
        _syscall._call(250)
    assert excinfo.value.errno == errno.EACCES


@pytest.mark.parametrize("err", [errno.ENOSYS, errno.EOPNOTSUPP])
def test_call_maps_unsupported_errno(monkeypatch: pytest.MonkeyPatch, err: int) -> None:
    _install_libc(monkeypatch, ret=-1, err=err)
    with pytest.raises(UnsupportedError) as excinfo:
        _syscall._call(250)
    assert excinfo.value.errno == err


@pytest.mark.parametrize("bad", [2**31, -(2**31) - 1, 10**30])
def test_call_rejects_out_of_range_ints(
    monkeypatch: pytest.MonkeyPatch, bad: int
) -> None:
    fake = _install_libc(monkeypatch)
    with pytest.raises(ValueError, match="int32"):
        _syscall._call(250, bad)
    assert fake.calls == []


def test_call_rejects_out_of_range_syscall_number(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _install_libc(monkeypatch)
    with pytest.raises(ValueError, match="int32"):
        _syscall._call(2**31)
    assert fake.calls == []


@pytest.mark.parametrize(
    ("machine", "expected"),
    [
        ("x86_64", (248, 249, 250)),
        ("amd64", (248, 249, 250)),
        ("i386", (286, 287, 288)),
        ("i686", (286, 287, 288)),
        ("aarch64", (217, 218, 219)),
        ("arm64", (217, 218, 219)),
        ("riscv32", (217, 218, 219)),
        ("riscv64", (217, 218, 219)),
        ("loongarch64", (217, 218, 219)),
        ("armv6l", (309, 310, 311)),
        ("armv7l", (309, 310, 311)),
        ("ppc", (269, 270, 271)),
        ("ppc64", (269, 270, 271)),
        ("ppc64le", (269, 270, 271)),
        ("s390", (278, 279, 280)),
        ("s390x", (278, 279, 280)),
        ("sparc64", (281, 282, 283)),
    ],
)
def test_syscall_numbers_per_arch(
    monkeypatch: pytest.MonkeyPatch, machine: str, expected: tuple[int, int, int]
) -> None:
    monkeypatch.setattr(_syscall, "_numbers", None)
    monkeypatch.setattr(platform, "machine", lambda: machine)
    assert _syscall._syscall_numbers() == expected


def test_syscall_numbers_unknown_arch(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_syscall, "_numbers", None)
    monkeypatch.setattr(platform, "machine", lambda: "mips64")
    with pytest.raises(UnsupportedError, match="mips64"):
        _syscall._syscall_numbers()


def test_get_libc_rejects_non_linux(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(_syscall, "_libc", None)
    with pytest.raises(UnsupportedError, match="only available on Linux"):
        _syscall._get_libc()


@requires_linux
def test_get_libc_loads_real_libc(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_syscall, "_libc", None)
    libc = _syscall._get_libc()
    assert libc.syscall.restype is ctypes.c_long


def test_add_key_marshals_payload_length(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _install_libc(monkeypatch, ret=99)
    assert _syscall.add_key(b"user", b"desc", b"payload", -3) == 99
    nr, args = fake.calls[0]
    assert nr == _syscall._syscall_numbers()[0]
    assert args == (b"user", b"desc", b"payload", 7, -3)


def test_add_key_none_payload(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _install_libc(monkeypatch, ret=99)
    _syscall.add_key(b"user", b"desc", None, -3)
    assert fake.calls[0][1] == (b"user", b"desc", None, 0, -3)


def test_request_key_argument_order(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _install_libc(monkeypatch, ret=5)
    assert _syscall.request_key(b"user", b"desc", b"info", -3) == 5
    nr, args = fake.calls[0]
    assert nr == _syscall._syscall_numbers()[1]
    assert args == (b"user", b"desc", b"info", -3)


@pytest.mark.parametrize("bad", [-2, -(2**31), 2**32, 10**20])
def test_u32_rejects_out_of_range(bad: int) -> None:
    with pytest.raises(ValueError, match="test out of range"):
        _syscall._u32(bad, "test")


@pytest.mark.parametrize(
    ("value", "expected"),
    [(-1, 0xFFFFFFFF), (0, 0), (0xFFFFFFFF, 0xFFFFFFFF)],
)
def test_u32_marshals(value: int, expected: int) -> None:
    assert _syscall._u32(value).value == expected


def _describer(blobs: list[bytes]) -> Callable[..., int]:
    """Fake KEYCTL_DESCRIBE cycling through blobs, one per call."""

    calls = 0

    def fake(
        op: int, serial: int, buf: ctypes.Array[ctypes.c_char] | None, buflen: int
    ) -> int:
        nonlocal calls
        blob = blobs[min(calls, len(blobs) - 1)] + b"\x00"
        calls += 1
        if buf is None:
            return len(blob)
        n = min(buflen, len(blob))
        ctypes.memmove(buf, blob, n)
        return len(blob)

    return fake


def test_describe_returns_bounded_string(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_syscall, "_keyctl", _describer([b"user;0;0;3f3f3f3f;hello"]))
    assert _syscall.describe(7) == b"user;0;0;3f3f3f3f;hello"


def test_describe_retries_when_description_grows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    long_desc = b"t;0;0;1;a much longer description"
    fake = _describer([b"t;0;0;1;a", long_desc])
    monkeypatch.setattr(_syscall, "_keyctl", fake)
    assert _syscall.describe(7) == long_desc


def test_describe_stays_bounded_under_constant_growth(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake(
        op: int, serial: int, buf: ctypes.Array[ctypes.c_char] | None, buflen: int
    ) -> int:
        if buf is None:
            return 8
        ctypes.memmove(buf, b"y" * buflen, buflen)
        return buflen + 64

    monkeypatch.setattr(_syscall, "_keyctl", fake)
    # four fetch attempts at sizes 8, 72, 136, 200, then a bounded return
    assert _syscall.describe(7) == b"y" * 200


def test_read_returns_payload(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake(
        op: int, serial: int, buf: ctypes.Array[ctypes.c_char] | None, buflen: int
    ) -> int:
        data = b"key payload"
        if buf is None:
            return len(data)
        ctypes.memmove(buf, data, len(data))
        return len(data)

    monkeypatch.setattr(_syscall, "_keyctl", fake)
    assert _syscall.read(7) == b"key payload"


def test_read_empty_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_syscall, "_keyctl", lambda *args: 0)
    assert _syscall.read(7) == b""


def test_read_retries_when_payload_grows(monkeypatch: pytest.MonkeyPatch) -> None:
    blobs = [b"small", b"a payload that outgrew the first buffer"]
    calls = 0

    def fake(
        op: int, serial: int, buf: ctypes.Array[ctypes.c_char] | None, buflen: int
    ) -> int:
        nonlocal calls
        blob = blobs[min(calls, 1)]
        calls += 1
        if buf is None:
            return len(blob)
        n = min(buflen, len(blob))
        ctypes.memmove(buf, blob, n)
        return len(blob)

    monkeypatch.setattr(_syscall, "_keyctl", fake)
    assert _syscall.read(7) == blobs[1]
    assert calls == 3


def test_read_stays_bounded_under_constant_growth(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake(
        op: int, serial: int, buf: ctypes.Array[ctypes.c_char] | None, buflen: int
    ) -> int:
        if buf is None:
            return 4
        ctypes.memmove(buf, b"z" * buflen, buflen)
        return buflen + 32

    monkeypatch.setattr(_syscall, "_keyctl", fake)
    # four fetch attempts at sizes 4, 36, 68, 100, then a bounded return
    assert _syscall.read(7) == b"z" * 100


def test_keyctl_wrappers_reach_libc(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _install_libc(monkeypatch, ret=1)
    _syscall.get_keyring_id(-3, True)
    _syscall.join_session_keyring(b"ring")
    _syscall.join_session_keyring(None)
    _syscall.update(1, b"payload")
    _syscall.update(1, None)
    _syscall.revoke(1)
    _syscall.chown(1, 0, 0)
    _syscall.setperm(1, 0x3F3F3F3F)
    _syscall.clear(2)
    _syscall.link(1, 2)
    _syscall.unlink(1, 2)
    _syscall.search(2, b"user", b"d", 0)
    _syscall.set_reqkey_keyring(0)
    _syscall.set_timeout(1, 30)
    _syscall.session_to_parent()
    _syscall.invalidate(1)
    _syscall.get_persistent(-1, -3)
    _syscall.restrict_keyring(2, b"asymmetric", b"builtin_trusted")
    _syscall.restrict_keyring(2, None, None)
    _syscall.move(1, 2, 3, 1)
    _syscall.describe(1)
    _syscall.read(1)
    assert _syscall.capabilities() == b"\x00"

    keyctl_nr = _syscall._syscall_numbers()[2]
    assert all(nr == keyctl_nr for nr, _ in fake.calls)
    ops = {args[0] for _, args in fake.calls}
    assert ops >= set(KeyctlOp)
    # GET_KEYRING_ID passes the ring id and the create flag verbatim
    assert fake.calls[0][1] == (KeyctlOp.GET_KEYRING_ID, -3, 1)


@pytest.mark.parametrize(
    "call",
    [
        lambda: add_key("us\x00er", "d", b"p"),
        lambda: add_key("user", "d\x00d"),
        lambda: request_key("user", "d", callout_info="x\x00y"),
        lambda: join_session_keyring("r\x00ing"),
        lambda: search("session", "u\x00ser", "d"),
        lambda: restrict(0, "asymmetric", "bad\x00scheme"),
    ],
    ids=["type", "description", "callout", "name", "search type", "restriction"],
)
def test_public_api_rejects_nul(call: Callable[[], object]) -> None:
    with pytest.raises(ValueError, match="must not contain NUL"):
        call()


@pytest.mark.parametrize("seconds", [-1, 2**32, 10**20])
def test_set_timeout_out_of_range(seconds: int) -> None:
    with pytest.raises(ValueError, match="timeout out of range"):
        Key(1).set_timeout(seconds)


@pytest.mark.parametrize(
    ("uid", "gid", "match"),
    [
        (-2, -1, "uid out of range"),
        (2**32, -1, "uid out of range"),
        (-1, -2, "gid out of range"),
        (-1, 2**32, "gid out of range"),
    ],
)
def test_chown_out_of_range(uid: int, gid: int, match: str) -> None:
    with pytest.raises(ValueError, match=match):
        Key(1).chown(uid, gid)


def test_get_persistent_uid_out_of_range() -> None:
    with pytest.raises(ValueError, match="uid out of range"):
        get_persistent(2**32, "session")


def test_move_flags_out_of_range() -> None:
    with pytest.raises(ValueError, match="flags out of range"):
        Key(1).move(1, 2, MoveFlag(2**32))


def test_set_perm_out_of_range() -> None:
    with pytest.raises(ValueError, match="perm out of range"):
        Key(1).set_perm(KeyPerm(2**32))


def test_key_equality_hash_repr() -> None:
    a, b = Key(5), Key(5)
    assert a == b
    assert a != Key(6)
    assert a != "5"
    assert hash(a) == hash(b)
    assert int(a) == 5
    assert repr(a) == "Key(5)"


def test_key_wraps_spec_members() -> None:
    assert Key(KeySpec.SESSION_KEYRING).serial == -3
    assert keyring("session") == Key(-3)


def test_keyring_wrapper_accepts_serials_and_specs() -> None:
    assert keyring(1234).serial == 1234
    assert keyring(KeySpec.USER_KEYRING).serial == -4


def test_keyring_rejects_unknown_name() -> None:
    with pytest.raises(ValueError, match="unknown keyring name"):
        keyring("bogus")


def test_public_wrappers_delegate(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, tuple[Any, ...]] = {}

    def rec(name: str, result: object = 123) -> Callable[..., object]:
        def fn(*args: object) -> object:
            seen[name] = args
            return result

        return fn

    for name in (
        "add_key",
        "request_key",
        "join_session_keyring",
        "get_keyring_id",
        "clear",
        "search",
        "restrict_keyring",
        "session_to_parent",
        "get_persistent",
        "set_reqkey_keyring",
        "capabilities",
        "update",
        "revoke",
        "chown",
        "setperm",
        "link",
        "unlink",
        "move",
        "invalidate",
        "set_timeout",
        "read",
    ):
        monkeypatch.setattr(_syscall, name, rec(name))
    # describe feeds into KeyDescription.parse, so it needs a real blob
    monkeypatch.setattr(_syscall, "describe", rec("describe", b"user;0;0;3f3f3f3f;x"))

    session = int(KeySpec.SESSION_KEYRING)
    assert add_key(KeyType.USER, "d", b"p") == 123
    assert seen["add_key"] == (b"user", b"d", b"p", session)
    assert request_key("user", "d", "session", "info") == 123
    assert seen["request_key"] == (b"user", b"d", b"info", session)
    assert join_session_keyring("name") == 123
    got = seen["join_session_keyring"]
    assert got == (b"name",)
    assert join_session_keyring() == 123
    got = seen["join_session_keyring"]
    assert got == (None,)
    assert get_keyring_id("user", create=True) == 123
    assert seen["get_keyring_id"] == (-4, True)
    clear("process")
    assert seen["clear"] == (-2,)
    assert search("session", "logon", "d", dest=5) == 123
    assert seen["search"] == (-3, b"logon", b"d", 5)
    restrict(9)
    got = seen["restrict_keyring"]
    assert got == (9, None, None)
    restrict(9, "asymmetric", "builtin_trusted")
    got = seen["restrict_keyring"]
    assert got == (9, b"asymmetric", b"builtin_trusted")
    session_to_parent()
    assert seen["session_to_parent"] == ()
    assert get_persistent(0, "session") == 123
    assert seen["get_persistent"] == (0, -3)
    set_reqkey_keyring(ReqKeyDefault.THREAD_KEYRING)
    assert seen["set_reqkey_keyring"] == (1,)
    capabilities()
    assert seen["capabilities"] == ()

    k = Key(7)
    k.describe()
    assert seen["describe"] == (7,)
    k.read()
    assert seen["read"] == (7,)
    k.update(b"x")
    got = seen["update"]
    assert got == (7, b"x")
    k.update(None)
    got = seen["update"]
    assert got == (7, None)
    k.set_timeout(9)
    assert seen["set_timeout"] == (7, 9)
    k.set_perm(KeyPerm.POS_ALL | KeyPerm.USR_ALL)
    assert seen["setperm"] == (7, int(KeyPerm.POS_ALL | KeyPerm.USR_ALL))
    k.link("session")
    assert seen["link"] == (7, -3)
    k.unlink("session")
    assert seen["unlink"] == (7, -3)
    k.move(1, 2, MoveFlag.EXCL)
    assert seen["move"] == (7, 1, 2, 1)
    k.revoke()
    assert seen["revoke"] == (7,)
    k.invalidate()
    assert seen["invalidate"] == (7,)
    k.chown(1000, 100)
    assert seen["chown"] == (7, 1000, 100)
    assert k.search("user", "d") == 123
    assert seen["search"] == (7, b"user", b"d", 0)
