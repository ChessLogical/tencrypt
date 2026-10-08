# Tencrypt


This has hard coded keys. If you want external keys see https://github.com/ChessLogical/fenc






**Version 1.0.1** corrects a Windows atomic rename failure reported as Win32
error 87. It preserves the original embedded keys and encrypted file format.
See [CHANGELOG.md](CHANGELOG.md) for the correction and
[docs/VALIDATION.md](docs/VALIDATION.md) for its validation status.

A single-file encryption CLI in **Rust 1.99.0, edition 2024**, with separate Linux and Windows binaries. Choose one of ten authenticated encryption suites, choose `E` or `D`, supply a filename, and the process exits after that operation.

```text
tencrypt-linux       <1..10> <E|D> <filename>
tencrypt-windows.exe <1..10> <E|D> <filename>
```

Lowercase `e` and `d` also work. The target file must be in the directory containing the **resolved executable**, regardless of the shell's current directory. Supply a filename only, such as `report.pdf` or `"quarterly report.pdf"`. Each algorithm's key is hardcoded into the application at compile time, so no key file or password is needed at runtime.

## Build

Install [Rust through rustup](https://rust-lang.github.io/rustup/installation/), a native C/C++ linker, and the requested toolchain:

```text
rustup toolchain install 1.99.0 --profile minimal --component rustfmt
```

Run the matching script from the source directory:

| Platform | Build command | Output |
|---|---|---|
| Linux, x86-64 GNU | `bash scripts/build-linux.sh` | `dist/linux/tencrypt-linux` |
| Windows, x86-64 MSVC | `.\scripts\build-windows.ps1` | `dist/windows/tencrypt-windows.exe` |

Windows builds require the Visual Studio C++ build tools and Windows SDK. Linux builds require a working C compiler/linker and development libraries for the selected target. These are native builds: run the Linux script on Linux and the Windows script on Windows.

The scripts use release optimization and the committed `Cargo.lock`. Add `--native` on Linux or `-Native` on Windows to allow instructions specific to the build computer's CPU. Such a binary should only be used on CPUs supporting those instructions. The default does not add this CPU restriction. Target overrides and direct Cargo commands are in [docs/BUILDING.md](docs/BUILDING.md).

See [docs/VALIDATION.md](docs/VALIDATION.md) for the compiler versions, checks actually run, and remaining validation limits. The included CI workflow is a configuration for future runs, not evidence that those runs have occurred.

## First use

Put the binary in a private, writable directory and put the file to process beside it. The ten distinct keys are already present as raw byte arrays in `src/embedded_keys.rs`; building embeds them into the executable. The scripts never regenerate keys automatically.

Linux:

```bash
cd dist/linux
# Place example.txt in this directory before running the next command.
./tencrypt-linux 1 E example.txt
./tencrypt-linux 1 D example.txt
```

Windows PowerShell:

```powershell
Set-Location .\dist\windows
# Place example.txt in this directory before running the next command.
.\tencrypt-windows.exe 2 E example.txt
.\tencrypt-windows.exe 2 D example.txt
```

**The source ZIP and both executables contain usable decryption keys. Anyone who has either can decrypt files encrypted with those keys.** Protect the source and binaries accordingly, and retain a protected backup before encrypting important files. Replacing embedded keys and rebuilding does not make old ciphertext decryptable with the new keys; keep the old keys or old executable if old ciphertext must remain recoverable.

An optional key-regeneration script is included for deliberately starting a new key set; see [Changing embedded keys](docs/BUILDING.md#changing-embedded-keys). Ordinary builds and file operations do not require running it.

For help and the built-in algorithm list:

```text
<binary> --help
<binary> --list
<binary> --version
```

## Algorithm numbers and embedded keys

| ID | Authenticated suite | Embedded key bytes |
|---:|---|---:|
| 1 | XChaCha20-Poly1305 | 32 |
| 2 | AES-256-GCM-SIV | 32 |
| 3 | Serpent-256-CTR + HMAC-SHA-256 | 32 |
| 4 | Threefish-1024-CTR + HMAC-SHA-256 | 128 |
| 5 | ChaCha20-Poly1305 | 32 |
| 6 | AES-256-GCM | 32 |
| 7 | AES-256-SIV | 64 |
| 8 | Twofish-256-CTR + HMAC-SHA-256 | 32 |
| 9 | Camellia-256-CTR + HMAC-SHA-256 | 32 |
| 10 | AES-256-EAX | 32 |

Each row selects its own compile-time key. AES-256-SIV uses a 64-byte master key because the construction needs two 256-bit keys. Threefish-1024 uses a 128-byte key. The block-cipher suites use authenticated encrypt-then-MAC constructions.

Use the same algorithm number to decrypt, with a build containing the original embedded keys. The file header also identifies the algorithm, and the application rejects a different selection. Linux and Windows binaries built from the same project share the same keys and encrypted file format, so their outputs can be exchanged.

## What “atomically in place” means here

The application streams the complete result to a private temporary file in the executable directory, flushes it, and replaces the original directory entry in one operating-system rename operation. The original filename remains the same; no extension is appended. Decryption verifies every record before committing the result. Empty files are authenticated too.

An error **before replacement succeeds** leaves the original file's contents unchanged. If a synchronization step fails after replacement, the command reports a durability warning and exits successfully because the new contents are already installed. Atomic replacement does not protect against hardware failures or all filesystem/power-loss behavior.

Requirements and deliberate behavior:

- Use a trusted directory that other users cannot modify. Do not edit, replace, move, or delete the target or its directory while an operation is running.
- The file must be a regular file with one hard link. Paths, symbolic links, Windows reparse points, and the executable itself are rejected. Windows alternate data streams are rejected.
- The directory must have enough free space for a complete second copy, including encryption overhead. Processing uses bounded memory and 1 MiB records.
- Linux uses a same-directory rename and directory synchronization. It accepts local ext2/3/4, XFS, Btrfs, F2FS, tmpfs/ramfs, and OverlayFS with local backing; unrecognized filesystem types are rejected. Windows uses a rename through the temporary file's open handle and requires Windows 10/11 with a local NTFS volume. Network shares are not supported. Memory filesystems do not retain data after reboot.
- Successful output has private permissions: mode `0600` on Linux, and an owner-only DACL on Windows. The file's bytes and name are retained as applicable; timestamps, original permissions/ACLs, extended attributes, and other metadata are not preserved.
- A crash or forced termination can leave a temporary file. During decryption, this can contain plaintext. The program does not promise secure erasure of previous data or temporary data on storage media.

The encrypted format is specific to Tencrypt. Existing files from other tools are not accepted, and no compatibility with older Tencrypt formats is promised. The format and key derivation are documented in [docs/FORMAT.md](docs/FORMAT.md).

## Source and security notes

Cryptographic primitives come from RustCrypto crates. The file format, chunk handling, counter-mode compositions, and filesystem transaction code are application code. This project has not received an independent cryptographic or security audit. Review [docs/SECURITY.md](docs/SECURITY.md) and the actual validation record before relying on it for valuable data.

Primary implementation references:

- [RustCrypto authenticated encryption crates](https://github.com/RustCrypto/AEADs)
- [RustCrypto block ciphers](https://github.com/RustCrypto/block-ciphers)
- [RustCrypto message authentication codes](https://github.com/RustCrypto/MACs)
- [HKDF specification, RFC 5869](https://www.rfc-editor.org/rfc/rfc5869)
- [Cargo build options](https://doc.rust-lang.org/cargo/commands/cargo-build.html)

Licensed under the [MIT License](LICENSE).
