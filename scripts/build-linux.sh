#!/usr/bin/env bash
# Native Linux release build. Requires rustup and the requested linker.
set -euo pipefail

TOOLCHAIN="1.99.0"
BUILD_TARGET="x86_64-unknown-linux-gnu"
NATIVE_CPU=false
PROJECT_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"

usage() {
    cat <<'USAGE'
Usage: bash scripts/build-linux.sh [--native] [--target TARGET]

Builds dist/linux/tencrypt-linux with Rust 1.99.0.
Default target: x86_64-unknown-linux-gnu
--native adds -C target-cpu=native and requires target = compiler host.
USAGE
}

while (($# > 0)); do
    case "$1" in
        --native)
            NATIVE_CPU=true
            shift
            ;;
        --target)
            if (($# < 2)) || [[ -z "$2" ]]; then
                printf '%s\n' 'error: --target requires a target triple' >&2
                exit 2
            fi
            BUILD_TARGET="$2"
            shift 2
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *)
            printf 'error: unknown option: %s\n' "$1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

if [[ "$(uname -s)" != Linux ]]; then
    printf '%s\n' 'error: run this script on Linux; use build-windows.ps1 on Windows' >&2
    exit 2
fi

case "$BUILD_TARGET" in
    *-unknown-linux-*) ;;
    *)
        printf 'error: expected a Linux target, received: %s\n' "$BUILD_TARGET" >&2
        exit 2
        ;;
esac

for REQUIRED_TOOL in rustup rustc cargo; do
    if ! command -v "$REQUIRED_TOOL" >/dev/null 2>&1; then
        printf 'error: %s is missing; install Rust through rustup first\n' "$REQUIRED_TOOL" >&2
        exit 2
    fi
done

cd -- "$PROJECT_ROOT"

if ! COMPILER_INFO="$(rustc "+$TOOLCHAIN" -vV)"; then
    printf 'error: install the required toolchain with: rustup toolchain install %s --profile minimal --component rustfmt\n' "$TOOLCHAIN" >&2
    exit 2
fi

if [[ "$NATIVE_CPU" == true ]]; then
    COMPILER_HOST=""
    while IFS= read -r INFO_LINE; do
        case "$INFO_LINE" in
            'host: '*) COMPILER_HOST="${INFO_LINE#host: }" ;;
        esac
    done <<< "$COMPILER_INFO"
    if [[ -z "$COMPILER_HOST" || "$BUILD_TARGET" != "$COMPILER_HOST" ]]; then
        printf 'error: --native requires target %s to match compiler host %s\n' "$BUILD_TARGET" "$COMPILER_HOST" >&2
        exit 2
    fi
    export RUSTFLAGS="${RUSTFLAGS:+$RUSTFLAGS }-C target-cpu=native"
fi

rustup target add --toolchain "$TOOLCHAIN" "$BUILD_TARGET"
cargo "+$TOOLCHAIN" build --locked --release \
    --target "$BUILD_TARGET" \
    --target-dir "$PROJECT_ROOT/target" \
    --no-default-features --features linux-bin --bin tencrypt-linux

mkdir -p -- "$PROJECT_ROOT/dist/linux"
install -m 0755 -- \
    "$PROJECT_ROOT/target/$BUILD_TARGET/release/tencrypt-linux" \
    "$PROJECT_ROOT/dist/linux/tencrypt-linux"
printf 'Built %s\n' "$PROJECT_ROOT/dist/linux/tencrypt-linux"
