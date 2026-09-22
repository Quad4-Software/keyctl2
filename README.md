# keyctl2

[![CI](https://github.com/Quad4-Software/keyctl2/actions/workflows/ci.yml/badge.svg)](https://github.com/Quad4-Software/keyctl2/actions/workflows/ci.yml)
[![CodeQL](https://github.com/Quad4-Software/keyctl2/actions/workflows/codeql.yml/badge.svg)](https://github.com/Quad4-Software/keyctl2/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/Quad4-Software/keyctl2/badge)](https://securityscorecards.dev/viewer/?uri=github.com/Quad4-Software/keyctl2)
[![PyPI](https://img.shields.io/pypi/v/keyctl2.svg)](https://pypi.org/project/keyctl2/)
[![License: 0BSD](https://img.shields.io/badge/license-0BSD-blue)](LICENSE)

Dependency-free Python bindings for the Linux kernel keyring: add,
search, read, describe, link and unlink keys in session and process
keyrings, without shelling out to keyctl(1).

Requires Python 3.10+ and Linux. No runtime dependencies: the bindings
call add_key(2), request_key(2) and keyctl(2) through ctypes.

## Install

    pip install keyctl2

## Example

    import keyctl2

    # Add a user key to the session keyring and read it back.
    serial = keyctl2.add_key("user", "my-secret", b"hunter2")
    key = keyctl2.Key(serial)
    assert key.read() == b"hunter2"

    # Search the session keyring for it later.
    assert keyctl2.search("session", "user", "my-secret") == serial

    # Inspect it and clean up.
    print(key.describe())   # KeyDescription(type='user', ...)
    key.unlink("session")

## Development

    uv sync --group dev
    make check

License: 0BSD. Quad4 Software, https://quad4.io
