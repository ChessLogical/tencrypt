# Changes

## 1.0.1 — 2026-10-03

Correct the Windows atomic rename request that caused native Windows tests to
fail with `ERROR_INVALID_PARAMETER` (Win32 error 87).

The `SetFileInformationByHandle(FileRenameInfoEx)` request now supplies the full
absolute destination path and a null `RootDirectory`. The previous relative
name plus directory handle can be transformed incorrectly by the Win32 wrapper
before it reaches the native rename operation. The byte-length field excludes
the terminating UTF-16 NUL, and the request retains an aligned variable-length
buffer.

Replacement still uses one handle-based rename with the original locking,
sharing, authentication, source validation, and private staging behavior.
There is no delete-then-rename or `ReplaceFileW` fallback.

The ten embedded keys and encrypted file format are unchanged from 1.0.0.
See `docs/VALIDATION.md` for completed checks and the remaining native Windows
retest. Existing source directories with customized keys should retain their
own `src/embedded_keys.rs` when updating.

## 1.0.0 — 2026-10-03

Initial Rust 1.99.0 / edition 2024 source release with ten authenticated suites,
compile-time embedded keys, and separate Windows/Linux binaries.
