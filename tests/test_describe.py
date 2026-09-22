# SPDX-License-Identifier: 0BSD
"""Unit tests for KEYCTL_DESCRIBE string parsing, using fixtures."""

import pytest

from keyctl2 import KeyDescription, KeyPerm


def test_parse_typical() -> None:
    desc = KeyDescription.parse(b"user;1000;1000;3f3f0000;my secret")
    assert desc.type == "user"
    assert desc.uid == 1000
    assert desc.gid == 1000
    assert desc.perm == KeyPerm.POS_ALL | KeyPerm.USR_ALL
    assert desc.description == "my secret"


def test_parse_keyring() -> None:
    desc = KeyDescription.parse(b"keyring;0;0;3f3f0000;_ses")
    assert desc.type == "keyring"
    assert desc.uid == 0
    assert desc.description == "_ses"


def test_parse_description_with_semicolons() -> None:
    desc = KeyDescription.parse(b"user;100;200;3f010000;a;b;c")
    assert desc.description == "a;b;c"
    assert desc.perm == KeyPerm.POS_ALL | KeyPerm.USR_VIEW


def test_parse_partial_perms() -> None:
    desc = KeyDescription.parse(b"logon;1000;100;3f010000;note")
    assert desc.perm & KeyPerm.USR_READ == 0
    assert desc.perm & KeyPerm.POS_READ


@pytest.mark.parametrize(
    "blob",
    [
        b"",
        b"user",
        b"user;1000;1000;3f3f0000",
        b"user;1000;1000;nothex;desc",
    ],
)
def test_parse_malformed(blob: bytes) -> None:
    with pytest.raises(ValueError, match=r"malformed describe|invalid literal"):
        KeyDescription.parse(blob)
