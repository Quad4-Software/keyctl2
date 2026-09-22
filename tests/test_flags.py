# SPDX-License-Identifier: 0BSD
"""Constant values, checked against linux/keyctl.h and keyutils.h."""

import pytest

from keyctl2 import (
    KeyctlOp,
    KeyPerm,
    KeySpec,
    KeyType,
    MoveFlag,
    ReqKeyDefault,
)


def test_key_spec_values() -> None:
    assert KeySpec.THREAD_KEYRING.value == -1
    assert KeySpec.PROCESS_KEYRING.value == -2
    assert KeySpec.SESSION_KEYRING.value == -3
    assert KeySpec.USER_KEYRING.value == -4
    assert KeySpec.USER_SESSION_KEYRING.value == -5
    assert KeySpec.GROUP_KEYRING.value == -6
    assert KeySpec.REQKEY_AUTH_KEY.value == -7
    assert KeySpec.REQUESTOR_KEYRING.value == -8


def test_key_spec_from_name() -> None:
    assert KeySpec.from_name("thread") is KeySpec.THREAD_KEYRING
    assert KeySpec.from_name("process") is KeySpec.PROCESS_KEYRING
    assert KeySpec.from_name("session") is KeySpec.SESSION_KEYRING
    assert KeySpec.from_name("user") is KeySpec.USER_KEYRING
    assert KeySpec.from_name("user_session") is KeySpec.USER_SESSION_KEYRING
    assert KeySpec.from_name("group") is KeySpec.GROUP_KEYRING
    assert KeySpec.from_name("requestor") is KeySpec.REQUESTOR_KEYRING
    with pytest.raises(ValueError, match="unknown keyring name"):
        KeySpec.from_name("bogus")


def test_key_perm_bits() -> None:
    assert KeyPerm.POS_VIEW.value == 0x01000000
    assert KeyPerm.POS_READ.value == 0x02000000
    assert KeyPerm.POS_WRITE.value == 0x04000000
    assert KeyPerm.POS_SEARCH.value == 0x08000000
    assert KeyPerm.POS_LINK.value == 0x10000000
    assert KeyPerm.POS_SETATTR.value == 0x20000000
    assert KeyPerm.USR_VIEW.value == 0x00010000
    assert KeyPerm.USR_READ.value == 0x00020000
    assert KeyPerm.USR_WRITE.value == 0x00040000
    assert KeyPerm.USR_SEARCH.value == 0x00080000
    assert KeyPerm.USR_LINK.value == 0x00100000
    assert KeyPerm.USR_SETATTR.value == 0x00200000
    assert KeyPerm.GRP_VIEW.value == 0x00000100
    assert KeyPerm.GRP_READ.value == 0x00000200
    assert KeyPerm.GRP_WRITE.value == 0x00000400
    assert KeyPerm.GRP_SEARCH.value == 0x00000800
    assert KeyPerm.GRP_LINK.value == 0x00001000
    assert KeyPerm.GRP_SETATTR.value == 0x00002000
    assert KeyPerm.OTH_VIEW.value == 0x00000001
    assert KeyPerm.OTH_READ.value == 0x00000002
    assert KeyPerm.OTH_WRITE.value == 0x00000004
    assert KeyPerm.OTH_SEARCH.value == 0x00000008
    assert KeyPerm.OTH_LINK.value == 0x00000010
    assert KeyPerm.OTH_SETATTR.value == 0x00000020


def test_key_perm_class_masks() -> None:
    assert KeyPerm.POS_ALL.value == 0x3F000000
    assert KeyPerm.USR_ALL.value == 0x003F0000
    assert KeyPerm.GRP_ALL.value == 0x00003F00
    assert KeyPerm.OTH_ALL.value == 0x0000003F
    assert KeyPerm.ALL.value == 0x3F3F3F3F
    perms = (
        KeyPerm.POS_VIEW
        | KeyPerm.POS_READ
        | KeyPerm.POS_WRITE
        | KeyPerm.POS_SEARCH
        | KeyPerm.POS_LINK
        | KeyPerm.POS_SETATTR
    )
    assert perms == KeyPerm.POS_ALL


def test_keyctl_op_values() -> None:
    assert KeyctlOp.GET_KEYRING_ID.value == 0
    assert KeyctlOp.JOIN_SESSION_KEYRING.value == 1
    assert KeyctlOp.UPDATE.value == 2
    assert KeyctlOp.REVOKE.value == 3
    assert KeyctlOp.CHOWN.value == 4
    assert KeyctlOp.SETPERM.value == 5
    assert KeyctlOp.DESCRIBE.value == 6
    assert KeyctlOp.CLEAR.value == 7
    assert KeyctlOp.LINK.value == 8
    assert KeyctlOp.UNLINK.value == 9
    assert KeyctlOp.SEARCH.value == 10
    assert KeyctlOp.READ.value == 11
    assert KeyctlOp.SET_REQKEY_KEYRING.value == 14
    assert KeyctlOp.SET_TIMEOUT.value == 15
    assert KeyctlOp.SESSION_TO_PARENT.value == 18
    assert KeyctlOp.INVALIDATE.value == 21
    assert KeyctlOp.GET_PERSISTENT.value == 22
    assert KeyctlOp.RESTRICT_KEYRING.value == 29
    assert KeyctlOp.MOVE.value == 30
    assert KeyctlOp.CAPABILITIES.value == 31


def test_move_flag_values() -> None:
    assert MoveFlag.NONE.value == 0
    assert MoveFlag.EXCL.value == 0x00000001


def test_reqkey_default_values() -> None:
    assert ReqKeyDefault.NO_CHANGE.value == -1
    assert ReqKeyDefault.DEFAULT.value == 0
    assert ReqKeyDefault.THREAD_KEYRING.value == 1
    assert ReqKeyDefault.PROCESS_KEYRING.value == 2
    assert ReqKeyDefault.SESSION_KEYRING.value == 3
    assert ReqKeyDefault.USER_KEYRING.value == 4
    assert ReqKeyDefault.USER_SESSION_KEYRING.value == 5
    assert ReqKeyDefault.GROUP_KEYRING.value == 6
    assert ReqKeyDefault.REQUESTOR_KEYRING.value == 7


def test_key_type_values() -> None:
    assert KeyType.USER.value == "user"
    assert KeyType.LOGON.value == "logon"
    assert KeyType.KEYRING.value == "keyring"
