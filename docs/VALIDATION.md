# Validation record

Prepared on **2026-10-03**. This file records checks performed on the supplied
source, and distinguishes compilation from native execution.

## Windows correction in version 1.0.1

A native Windows run of version 1.0.0 reported **16 of 17 unit tests passing**.
The remaining test, `native_transaction_replaces_and_keeps_old_handle_valid`,
failed at the rename with Win32 error 87 (`ERROR_INVALID_PARAMETER`). The CLI
integration tests had not yet run because Cargo stopped after the library
test failure.

Version 1.0.1 changes the Win32 `FileRenameInfoEx` request to an absolute
extended-length destination path with `RootDirectory = NULL`. It retains
the existing open source/staging handles, source locking and revalidation,
private staging, and single-operation replacement. The key source and file
format are byte-for-byte unchanged from the original source archive.

This correction addresses the same invalid-parameter behavior reproduced and
debugged in this [Microsoft Q&A report](https://learn.microsoft.com/ja-jp/answers/questions/6015074/setfileinformationbyhandle-filerenameinfo-rootdire).
That report is a community reproduction, not an official API guarantee. Rust's
own [Windows filesystem implementation](https://github.com/rust-lang/rust/blob/1.99.0/library/std/src/sys/fs/windows.rs)
also uses the full destination name and a null root for this Win32 call.

The corrected Windows configuration includes 18 unit tests and nine CLI
integration tests. The added unit test commits to an absolute Unicode path
outside the current working directory. The original old-handle test that
reported error 87 remains enabled.

**A successful native Windows run of the corrected code is still pending.**
Cross-target compilation cannot establish whether this particular native
filesystem operation succeeds on the user's Windows installation.

First rerun the previously failing test:

```powershell
cargo +1.99.0 test --locked --target x86_64-pc-windows-msvc --features windows-bin --lib native_transaction_replaces_and_keeps_old_handle_valid -- --no-capture
```

Then run the full Windows suite:

```powershell
cargo +1.99.0 test --locked --target x86_64-pc-windows-msvc --no-default-features --features windows-bin --all-targets
```

## Environment

```text
rustc 1.99.0 (b940084d7 2026-09-28)
cargo 1.99.0 (5f94df478 2026-08-27)
Rust edition: 2024
LLVM: 23.1.1
Execution host: x86_64-unknown-linux-gnu
Linux kernel: 6.18.44
Workspace filesystem: OverlayFS
Windows standard-library target installed: x86_64-pc-windows-msvc
```

## Completed checks

For version 1.0.1, formatting, the Linux all-target compilation check and full
native test suite, and the Windows all-target compilation and Clippy checks
were rerun successfully. Archive validation was also repeated. The release
build, release-process experiments, Linux Clippy, script/workflow checks, and
dependency review below were completed for version 1.0.0; those implementation
and dependency files are unchanged by this Windows correction.

| Check | Result |
|---|---|
| `cargo fmt --all -- --check` | Passed |
| `cargo clippy --locked --features linux-bin --all-targets -- -D warnings` | Passed |
| `cargo test --locked --features linux-bin --all-targets` | **18 unit tests and 10 CLI integration tests passed**, no failures |
| `bash scripts/build-linux.sh` | Passed; produced optimized `dist/linux/tencrypt-linux` |
| Release executable, all 10 suites | Encrypt/decrypt round trips passed using only the executable and input file, launched from a different working directory |
| Forced termination during encryption | Killed the release process after same-directory staging appeared; the original 64 MiB file retained its inode and SHA-256 digest |
| `cargo check --locked --target x86_64-pc-windows-msvc --features windows-bin --all-targets` | Passed, including Windows source and test compilation checks |
| `cargo clippy --locked --target x86_64-pc-windows-msvc --features windows-bin --all-targets -- -D warnings` | Passed |
| Linux build script | Shell syntax and help checked; the complete build was executed |
| Windows build script | Reviewed; PowerShell execution was not available |
| CI workflow | YAML parsed; separate Linux and Windows native jobs are configured |
| Optional key-regeneration script | Python syntax checked; verified that its default invocation refuses replacement and leaves existing embedded keys unchanged |
| Source archive | ZIP integrity and required project files checked before delivery |

The ZIP is a **source distribution**. Build outputs and dependency caches are
not included. No Windows executable was linked or run in this Linux session.

## What the tests cover

Cryptographic tests exercise every suite with empty, partial-block, and full
1 MiB records. They check authentication failures for altered ciphertext and
AAD, wrong keys, salts and indices, truncation and extension, key lengths,
record size limits, and key separation. Every empty record requires a valid
tag.

Six complete-record expected outputs were independently computed using
libsodium for XChaCha20-Poly1305 and Python cryptography/OpenSSL for
AES-GCM-SIV, ChaCha20-Poly1305, AES-GCM, AES-SIV, and Camellia CTR/HMAC. Two
official Threefish-1024 vectors test both zero and nonzero key/tweak/input
values. The reference vectors are available from the
[Threefish authors' page](https://www.schneier.com/academic/skein/threefish/)
and its [public-domain reference ZIP](https://www.schneier.com/wp-content/uploads/2015/01/skein.zip).
The test source records the reference-file location and byte encoding.

Framing and CLI tests check the fixed header and exact output sizes, valid
Unicode and space-containing filenames, all ten empty/binary round trips,
randomized repeated encryption, executable-directory path resolution,
portability between copied binaries, wrong suite selection, malformed
headers, corruption, truncation, appended bytes, repeat-encryption refusal,
multi-record files, record swaps, and failure in the last record. Failure
checks confirm original bytes remain and ordinary staging cleanup completes.

Linux transaction tests check exact private permissions, open-original-handle
behavior after replacement, source edits or namespace replacement during an
operation, symlink/hard-link rejection, and competing transaction rejection.
The parallel CLI harness coordinates executable copying with process spawning
to avoid Linux's transient `ETXTBSY` copy/fork race before the program starts.

## Dependency advisory comparison

All locked package names were compared with the official
[RustSec advisory database](https://github.com/RustSec/advisory-db), snapshot
`ef6173c` dated 2026-10-03. Nine matching advisory entries were examined; each
locked version meets its corresponding patched range:

| Locked package | Advisory | Patched range |
|---|---|---|
| anyhow 1.0.104 | [RUSTSEC-2026-0190](https://rustsec.org/advisories/RUSTSEC-2026-0190.html) | `>=1.0.103` |
| aes-gcm 0.10.3 | [RUSTSEC-2023-0096](https://rustsec.org/advisories/RUSTSEC-2023-0096.html) | `>=0.10.3` |
| zeroize_derive 1.5.0 | [RUSTSEC-2021-0115](https://rustsec.org/advisories/RUSTSEC-2021-0115.html) | `>=1.1.1` |
| sha2 0.10.9 | [RUSTSEC-2021-0100](https://rustsec.org/advisories/RUSTSEC-2021-0100.html) | `>=0.9.8` |
| generic-array 0.14.7 | [RUSTSEC-2020-0146](https://rustsec.org/advisories/RUSTSEC-2020-0146.html) | `>=0.13.3` |
| rand_core 0.6.4 | [RUSTSEC-2021-0023](https://rustsec.org/advisories/RUSTSEC-2021-0023.html) | `>=0.6.2` |
| rand_core 0.6.4 | [RUSTSEC-2019-0035](https://rustsec.org/advisories/RUSTSEC-2019-0035.html) | `>=0.4.2` |
| chacha20 0.9.1 | [RUSTSEC-2019-0029](https://rustsec.org/advisories/RUSTSEC-2019-0029.html) | `>=0.2.3` |
| once_cell 1.21.4 | [RUSTSEC-2019-0017](https://rustsec.org/advisories/RUSTSEC-2019-0017.html) | `>=1.0.1` |

This was a direct database comparison, **not a `cargo audit` invocation**.
The lockfile and minimum `anyhow` requirement retain the reviewed patched
version. Database checks are a dated check of known issues, not a security
audit of this application or a guarantee against unknown vulnerabilities.

## Remaining practical limits

Native Windows rename, DACL, lock, and alternate-stream behavior was not
executed here. Four Windows transaction tests and nine Windows CLI integration
tests are included for native Windows runs. The supplied CI workflow is a
configuration for those future runs, not evidence of a completed CI run.

Power-loss behavior, device failures, all supported filesystem implementations,
and CPU architectures other than the x86-64 targets above were not tested.
No throughput benchmark or external cryptographic audit was performed. See
[SECURITY.md](SECURITY.md) for the supported operating model and handling of
embedded keys, metadata, temporary plaintext, and post-commit warnings.
