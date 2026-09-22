# SPDX-License-Identifier: 0BSD

import keyctl2


def test_all_exports_resolve() -> None:
    for name in keyctl2.__all__:
        assert getattr(keyctl2, name) is not None, name


def test_version_is_exposed() -> None:
    parts = keyctl2.__version__.split(".")
    assert len(parts) == 3
    assert all(part.isdigit() for part in parts)
