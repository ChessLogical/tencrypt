#!/usr/bin/env python3
"""Generate the ten master keys that Rust embeds at compile time.

Run once when making a NEW key set. Never run as part of a normal build.
Keep the old source/binary to retain access to files encrypted with old keys.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import secrets
import tempfile

SUITES = (
    ("XChaCha20Poly1305", 32),
    ("Aes256GcmSiv", 32),
    ("Serpent256", 32),
    ("Threefish1024", 128),
    ("ChaCha20Poly1305", 32),
    ("Aes256Gcm", 32),
    ("Aes256Siv", 64),
    ("Twofish256", 32),
    ("Camellia256", 32),
    ("Aes256Eax", 32),
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--replace",
        action="store_true",
        help="replace the embedded key set; preserve the old source/binary first",
    )
    args = parser.parse_args()
    destination = Path(__file__).resolve().parents[1] / "src" / "embedded_keys.rs"
    if destination.exists() and not args.replace:
        parser.error(
            "embedded keys already exist. Ordinary builds reuse them. "
            "To create different keys, preserve the old source/binary, then use --replace."
        )

    lines = [
        "//! SECRET: these master keys are compiled into both platform binaries.",
        "//! Possession of this source or either binary permits decryption.",
        "//! Generated with Python secrets.token_bytes (operating system randomness).",
        "//! Normal builds MUST reuse this file to preserve access to encrypted data.",
        "//! To intentionally replace keys: python3 scripts/regenerate_keys.py --replace",
        "",
        "use crate::crypto::Algorithm;",
        "",
    ]
    for index, (_name, length) in enumerate(SUITES, 1):
        key = secrets.token_bytes(length)
        lines.extend(["#[rustfmt::skip]", f"static KEY_{index:02d}: [u8; {length}] = ["])
        for offset in range(0, length, 16):
            lines.append("    " + ", ".join(f"0x{byte:02x}" for byte in key[offset:offset + 16]) + ",")
        lines.extend(["];", ""])
    lines.extend([
        "pub(crate) fn key(algorithm: Algorithm) -> &'static [u8] {",
        "    match algorithm {",
    ])
    for index, (name, _length) in enumerate(SUITES, 1):
        lines.append(f"        Algorithm::{name} => &KEY_{index:02d},")
    lines.extend(["    }", "}", ""])
    payload = "\n".join(lines)
    destination.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(prefix=".embedded-keys-", suffix=".rs", dir=destination.parent)
    try:
        with os.fdopen(handle, "w", encoding="utf-8", newline="\n") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, destination)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    print("Wrote src/embedded_keys.rs with 10 new independent keys. Rebuild both platform binaries.")


if __name__ == "__main__":
    main()
