# Changelog

## [0.2.0] - 2026-09-26

### Added

- Syscall numbers for 32-bit ARM, powerpc, s390x, sparc and riscv32
- Mocked error-path tests covering marshalling, errno mapping and buffer retries, lifting coverage to 100 percent
- Wheel smoke test in the CI matrix

### Fixed

- describe() no longer reads past its buffer when a key description grows between the size probe and the fetch
- read() retries instead of silently truncating a payload that grows between calls
- Arguments outside the int32 and u32 ranges now raise ValueError instead of OverflowError or silently wrapping
- Key type, callout info, keyring name and restriction strings reject NUL bytes instead of silently truncating
- Test collection skips cleanly on platforms without os.fork

## [0.1.0] - 2026-09-22

Initial release.

- Python bindings for add_key(2), request_key(2) and keyctl(2) via ctypes, with no runtime dependencies
- Key and KeyDescription wrappers for describing, reading, updating, linking and revoking keys
- Constants for special keyring IDs, permission bits, key types and keyctl operations
- Syscall numbers for x86-64, i386 and the asm-generic architectures aarch64, riscv64 and loongarch64
- Test suite exercising the live kernel in forked children
