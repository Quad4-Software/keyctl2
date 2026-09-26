# Changelog

## [0.1.0] - Unreleased

Initial release.

- Python bindings for add_key(2), request_key(2) and keyctl(2) via ctypes, with no runtime dependencies
- Key and KeyDescription wrappers for describing, reading, updating, linking and revoking keys
- Constants for special keyring IDs, permission bits, key types and keyctl operations
- Syscall numbers for x86-64, i386, aarch64, riscv, loongarch64, 32-bit ARM, powerpc, s390x and sparc
- Test suite covering the live kernel in forked children plus mocked error paths
