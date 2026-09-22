# SPDX-License-Identifier: 0BSD
"""Tests against the running kernel.

Keyrings are per-process state and join_session_keyring() mutates the
caller's session keyring, so every scenario runs in a forked child.
Children that need a session keyring join a fresh, uniquely named one
first, which also keeps them out of the pytest process's own rings.
"""

import errno
import os
import struct
import time
import traceback
from collections.abc import Callable

import pytest

from keyctl2 import (
    Key,
    KeyctlError,
    KeyPerm,
    KeySpec,
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

from .conftest import requires_keys, requires_linux


class _SkipError(Exception):
    """Raised inside a child to turn into a pytest skip."""


def run_child(fn: Callable[[], None]) -> None:
    """Run fn in a forked child and report its result to pytest."""
    pid = os.fork()
    if pid == 0:
        code = 0
        try:
            fn()
        except _SkipError:
            code = 2
        # pytest failures like Failed are BaseException subclasses; any
        # escape would let the child keep running the pytest session
        except BaseException:  # noqa: BLE001
            traceback.print_exc()
            code = 1
        os._exit(code)
    _, status = os.waitpid(pid, 0)
    code = os.waitstatus_to_exitcode(status)
    if code == 2:
        pytest.skip("skipped in child process")
    assert code == 0


def fresh_ring(tag: str) -> int:
    """Join a fresh session keyring unique to this child, in the child."""
    return join_session_keyring(f"keyctl2-{tag}-{os.getpid()}")


@requires_linux
@requires_keys
def test_add_describe_read_search_update() -> None:
    def scenario() -> None:
        fresh_ring("basic")
        serial = add_key("user", "keyctl2-basic", b"secret")
        assert serial > 0
        key = Key(serial)
        desc = key.describe()
        assert desc.type == "user"
        assert desc.description == "keyctl2-basic"
        assert desc.uid == os.getuid()
        assert desc.perm & KeyPerm.POS_READ
        assert desc.perm & KeyPerm.USR_VIEW
        assert key.read() == b"secret"
        assert search("session", "user", "keyctl2-basic") == serial
        assert keyring("session").search("user", "keyctl2-basic") == serial
        with pytest.raises(KeyctlError) as excinfo:
            key.search("user", "keyctl2-basic")  # not a keyring
        assert excinfo.value.errno == errno.ENOTDIR
        key.update(b"new-secret")
        assert key.read() == b"new-secret"

    run_child(scenario)


@requires_linux
@requires_keys
def test_request_key_finds_existing() -> None:
    def scenario() -> None:
        fresh_ring("rk")
        serial = add_key("user", "keyctl2-rk", b"data")
        assert request_key("user", "keyctl2-rk") == serial
        with pytest.raises(KeyctlError) as excinfo:
            request_key("user", "keyctl2-missing")
        assert excinfo.value.errno == errno.ENOKEY

    run_child(scenario)


def _ring_serials(ring: int) -> set[int]:
    """Serials directly linked into a keyring, from KEYCTL_READ."""
    data = Key(ring).read()
    return set(struct.unpack(f"{len(data) // 4}i", data))


@requires_linux
@requires_keys
def test_link_unlink() -> None:
    def scenario() -> None:
        ring = fresh_ring("link")
        hold = add_key("keyring", "keyctl2-hold", None, ring)
        serial = add_key("user", "keyctl2-link", b"x", ring)
        Key(serial).link(hold)  # second link keeps the key alive
        Key(serial).unlink(ring)
        assert serial not in _ring_serials(ring)
        assert serial in _ring_serials(hold)
        Key(serial).link(ring)
        assert serial in _ring_serials(ring)

    run_child(scenario)


@requires_linux
@requires_keys
def test_set_timeout_expires() -> None:
    def scenario() -> None:
        fresh_ring("timeout")
        key = Key(add_key("user", "keyctl2-ttl", b"x"))
        key.set_timeout(1)
        assert key.read() == b"x"
        time.sleep(1.2)
        with pytest.raises(KeyctlError) as excinfo:
            key.read()
        assert excinfo.value.errno in (
            errno.EKEYEXPIRED,
            errno.ENOKEY,
            errno.EACCES,
        )

    run_child(scenario)


@requires_linux
@requires_keys
def test_revoke_blocks_read() -> None:
    def scenario() -> None:
        fresh_ring("revoke")
        key = Key(add_key("user", "keyctl2-rev", b"x"))
        key.revoke()
        with pytest.raises(KeyctlError) as excinfo:
            key.read()
        assert excinfo.value.errno in (
            errno.EKEYREVOKED,
            errno.ENOKEY,
            errno.EACCES,
        )

    run_child(scenario)


@requires_linux
@requires_keys
def test_invalidate_removes_key() -> None:
    def scenario() -> None:
        fresh_ring("inval")
        key = Key(add_key("user", "keyctl2-inv", b"x"))
        try:
            key.invalidate()
        except KeyctlError as exc:
            if exc.errno in (errno.EOPNOTSUPP, errno.ENOSYS):
                raise _SkipError from exc
            raise
        with pytest.raises(KeyctlError) as excinfo:
            key.describe()
        assert excinfo.value.errno in (
            errno.ENOKEY,
            errno.EKEYREVOKED,
            errno.EACCES,
        )

    run_child(scenario)


@requires_linux
@requires_keys
def test_set_perm_denies_read() -> None:
    def scenario() -> None:
        fresh_ring("perm")
        key = Key(add_key("user", "keyctl2-perm", b"x"))
        key.set_perm(KeyPerm.POS_ALL | KeyPerm.USR_ALL)
        assert key.describe().perm == KeyPerm.POS_ALL | KeyPerm.USR_ALL
        key.set_perm(KeyPerm.POS_VIEW | KeyPerm.USR_VIEW)
        assert key.describe().perm == KeyPerm.POS_VIEW | KeyPerm.USR_VIEW
        with pytest.raises(KeyctlError) as excinfo:
            key.read()
        assert excinfo.value.errno == errno.EACCES

    run_child(scenario)


@requires_linux
@requires_keys
def test_chown_self() -> None:
    def scenario() -> None:
        fresh_ring("chown")
        key = Key(add_key("user", "keyctl2-chown", b"x"))
        key.chown()
        key.chown(os.getuid(), -1)
        assert key.describe().uid == os.getuid()

    run_child(scenario)


@requires_linux
@requires_keys
def test_clear_keyring() -> None:
    def scenario() -> None:
        fresh_ring("clear")
        ring = add_key("keyring", "keyctl2-ring", None)
        add_key("user", "keyctl2-clr", b"x", ring)
        assert search(ring, "user", "keyctl2-clr") > 0
        clear(ring)
        with pytest.raises(KeyctlError) as excinfo:
            search(ring, "user", "keyctl2-clr")
        assert excinfo.value.errno == errno.ENOKEY

    run_child(scenario)


@requires_linux
@requires_keys
def test_move_between_keyrings() -> None:
    def scenario() -> None:
        fresh_ring("move")
        ring_a = add_key("keyring", "keyctl2-ring-a", None)
        ring_b = add_key("keyring", "keyctl2-ring-b", None)
        serial = add_key("user", "keyctl2-mv", b"x", ring_a)
        Key(serial).move(ring_a, ring_b)
        assert search(ring_b, "user", "keyctl2-mv") == serial
        with pytest.raises(KeyctlError):
            search(ring_a, "user", "keyctl2-mv")

        serial2 = add_key("user", "keyctl2-mv2", b"x", ring_a)
        serial3 = add_key("user", "keyctl2-mv2", b"y", ring_b)
        with pytest.raises(KeyctlError) as excinfo:
            Key(serial2).move(ring_a, ring_b, MoveFlag.EXCL)
        if excinfo.value.errno in (errno.EOPNOTSUPP, errno.ENOSYS):
            raise _SkipError
        assert excinfo.value.errno in (errno.EEXIST, errno.ENOKEY)
        assert search(ring_b, "user", "keyctl2-mv2") == serial3

    run_child(scenario)


@requires_linux
@requires_keys
def test_restrict_keyring() -> None:
    def scenario() -> None:
        fresh_ring("restrict")
        sealed = add_key("keyring", "keyctl2-sealed", None)
        try:
            restrict(sealed)
        except KeyctlError as exc:
            if exc.errno in (errno.EOPNOTSUPP, errno.ENOSYS):
                raise _SkipError from exc
            raise
        with pytest.raises(KeyctlError):
            add_key("user", "keyctl2-nope", b"x", sealed)

        # Only key types that implement a restriction scheme, such as
        # asymmetric, can be named; "user" has none and gives EINVAL.
        typed = add_key("keyring", "keyctl2-typed", None)
        try:
            restrict(typed, "asymmetric", "builtin_trusted")
        except KeyctlError as exc:
            if exc.errno in (errno.EOPNOTSUPP, errno.ENOSYS, errno.EINVAL):
                raise _SkipError from exc
            raise
        with pytest.raises(KeyctlError):
            add_key("user", "keyctl2-nope2", b"x", typed)

    run_child(scenario)


@requires_linux
@requires_keys
def test_get_persistent() -> None:
    def scenario() -> None:
        fresh_ring("persist")
        try:
            serial = get_persistent(os.getuid(), "session")
        except KeyctlError as exc:
            if exc.errno in (errno.EOPNOTSUPP, errno.ENOSYS):
                raise _SkipError from exc
            raise
        assert serial > 0
        assert Key(serial).describe().type == "keyring"

    run_child(scenario)


@requires_linux
@requires_keys
def test_get_keyring_id_and_describe() -> None:
    def scenario() -> None:
        name = f"keyctl2-gki-{os.getpid()}"
        serial = join_session_keyring(name)
        assert get_keyring_id("session") == serial
        desc = keyring(KeySpec.SESSION_KEYRING).describe()
        assert desc.type == "keyring"
        assert desc.description == name

    run_child(scenario)


@requires_linux
@requires_keys
def test_session_keyring_isolation() -> None:
    """A child's new session keyring must not leak into its parent."""

    def joiner() -> None:
        join_session_keyring("keyctl2-iso")
        add_key("user", "keyctl2-iso-key", b"x")

    run_child(joiner)

    def checker() -> None:
        try:
            desc = keyring("session").describe()
        except KeyctlError as exc:
            if exc.errno == errno.ENOKEY:
                return  # pytest process has no session ring at all
            raise
        assert desc.description != "keyctl2-iso"

    run_child(checker)


@requires_linux
@requires_keys
def test_session_to_parent() -> None:
    def scenario() -> None:
        pid = os.fork()
        if pid == 0:
            code = 0
            try:
                join_session_keyring("keyctl2-stp")
                session_to_parent()
            except KeyctlError as exc:
                code = 2 if exc.errno in (errno.EOPNOTSUPP, errno.EPERM) else 1
            os._exit(code)
        _, status = os.waitpid(pid, 0)
        code = os.waitstatus_to_exitcode(status)
        if code == 2:
            raise _SkipError
        assert code == 0
        assert keyring("session").describe().description == "keyctl2-stp"

    run_child(scenario)


@requires_linux
@requires_keys
def test_set_reqkey_keyring() -> None:
    def scenario() -> None:
        fresh_ring("reqkey")
        set_reqkey_keyring(ReqKeyDefault.NO_CHANGE)
        set_reqkey_keyring(ReqKeyDefault.SESSION_KEYRING)

    run_child(scenario)


@requires_linux
@requires_keys
def test_capabilities() -> None:
    try:
        caps = capabilities()
    except UnsupportedError:
        pytest.skip("KEYCTL_CAPABILITIES unsupported")
    else:
        assert len(caps) >= 1
