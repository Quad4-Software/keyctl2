# SPDX-License-Identifier: 0BSD

import keyctl2


def test_version_format() -> None:
    major, minor, patch = keyctl2.__version__.split(".")
    assert int(major) >= 0
    assert int(minor) >= 0
    assert int(patch) >= 0
