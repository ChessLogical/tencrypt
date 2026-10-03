# Building Tencrypt

The project targets **Rust 1.99.0** and **edition 2024**. The toolchain file and package metadata express that requirement. `Cargo.lock` pins dependency resolution. Build scripts use `--locked`, which fails if the lockfile would need to change.

The build produces two separately named native programs from shared application and cryptographic code. OS-specific modules implement file opening, permissions, locking, replacement, and durability handling. Both binaries embed the same ten keys from `src/embedded_keys.rs`. Build scripts do not regenerate or change those keys.

## Prerequisites

Install [rustup](https://rust-lang.github.io/rustup/installation/), then:

```text
rustup toolchain install 1.99.0 --profile minimal --component rustfmt
```

Use a native linker for the requested target. On Windows, install Visual Studio Build Tools with the **Desktop development with C++** workload and a Windows SDK. On Linux, install the distribution's C/C++ build tools and required libc development files. The scripts install the Rust standard library for the selected target via `rustup target add`; they do not install system linkers or SDKs.

## Linux

From the source root:

```bash
bash scripts/build-linux.sh
# Optional: require this build computer's CPU instruction set.
bash scripts/build-linux.sh --native
```

The default target is `x86_64-unknown-linux-gnu`. To build for another supported Linux target with its native or cross-linker already configured:

```bash
bash scripts/build-linux.sh --target aarch64-unknown-linux-gnu
```

Output: `dist/linux/tencrypt-linux`.

Equivalent direct build for the default target:

```bash
rustup target add --toolchain 1.99.0 x86_64-unknown-linux-gnu
cargo +1.99.0 build --locked --release --target x86_64-unknown-linux-gnu --no-default-features --features linux-bin --bin tencrypt-linux
```

The direct command leaves its output under `target/x86_64-unknown-linux-gnu/release/` instead of copying it into `dist/`.

## Windows

From the source root in PowerShell:

```powershell
.\scripts\build-windows.ps1
# Optional: require this build computer's CPU instruction set.
.\scripts\build-windows.ps1 -Native
```

The default target is `x86_64-pc-windows-msvc`. For another Windows MSVC target, install its C++ toolchain support and select it explicitly:

```powershell
.\scripts\build-windows.ps1 -Target aarch64-pc-windows-msvc
```

Output: `dist/windows/tencrypt-windows.exe`.

Equivalent direct build for the default target:

```powershell
rustup target add --toolchain 1.99.0 x86_64-pc-windows-msvc
cargo +1.99.0 build --locked --release --target x86_64-pc-windows-msvc --no-default-features --features windows-bin --bin tencrypt-windows
```

The direct command leaves its output under `target/x86_64-pc-windows-msvc/release/`.

## CPU-specific builds

`--native` / `-Native` adds `-C target-cpu=native` to `RUSTFLAGS`. The scripts allow this only when the selected target exactly matches the compiler's host target. It can prevent the resulting program from running on a different CPU. Use a default build when distributing the binary to other computers.

Existing environment settings such as `RUSTFLAGS` and Cargo configuration still apply. Release optimization is configured in `Cargo.toml`; the scripts do not claim measured performance superiority for a platform or algorithm.

## Changing embedded keys

The source archive already contains the ten working keys. No key-generation step is needed to build or use the program.

To deliberately start using a different key set, first save a protected copy of the old `src/embedded_keys.rs` or old executable. With Python 3 installed, run the matching command once from the source root:

```bash
# Linux
python3 scripts/regenerate_keys.py --replace
```

```powershell
# Windows, with the Python launcher installed
py -3 scripts/regenerate_keys.py --replace
```

Then rebuild both platform executables from that same updated source. The script generates fresh random bytes for all ten keys and replaces `src/embedded_keys.rs`. It refuses to replace an existing file without `--replace`. It is not called by the build scripts or CI. Python is only required for this optional operation.

Files encrypted under the old keys still need those old keys to decrypt. Keeping a ciphertext file does not preserve its key, and a new build with changed keys cannot decrypt it.

## Local checks and CI

On Linux:

```bash
cargo +1.99.0 fmt --all -- --check
cargo +1.99.0 test --locked --no-default-features --features linux-bin --all-targets
```

On Windows:

```powershell
cargo +1.99.0 fmt --all -- --check
cargo +1.99.0 test --locked --no-default-features --features windows-bin --all-targets
```

The included workflow runs these checks on native Linux and Windows runners, builds the matching release executable, and uploads each executable as a separate artifact. **Those artifacts contain the embedded keys**, as does the source repository. Restrict repository, workflow-log, and artifact access accordingly. Check [VALIDATION.md](VALIDATION.md) for checks actually completed while preparing this source archive.

References: [Cargo build](https://doc.rust-lang.org/cargo/commands/cargo-build.html), [Cargo features](https://doc.rust-lang.org/cargo/reference/features.html), [rustup toolchains](https://rust-lang.github.io/rustup/concepts/toolchains.html), and [rustc target CPU options](https://doc.rust-lang.org/rustc/codegen-options/index.html#target-cpu).
