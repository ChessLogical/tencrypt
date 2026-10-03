# Tencrypt file format, version 1

This is the complete byte format for the supplied implementation. The Windows
and Linux binaries use identical framing and cryptography. They interoperate
when built with the same `src/embedded_keys.rs`. No compatibility with any other
encryption program or earlier file format is implied.

## Keys and algorithm IDs

Each ID selects one distinct master key embedded at compile time. The master
key and derived keys are never written into an encrypted file. The master keys
are present in the source and executable; possession of either permits
decryption. New builds reuse the checked-in keys unless they are deliberately
regenerated.

| ID | Suite | Master / encryption key bytes | Record tag bytes | Record representation |
|---:|---|---:|---:|---|
| 1 | XChaCha20-Poly1305 | 32 | 16 | ciphertext, tag |
| 2 | AES-256-GCM-SIV | 32 | 16 | ciphertext, tag |
| 3 | Serpent-256-CTR + HMAC-SHA256 | 32 | 32 | ciphertext, tag |
| 4 | Threefish-1024-CTR + HMAC-SHA256 | 128 | 32 | ciphertext, tag |
| 5 | ChaCha20-Poly1305 | 32 | 16 | ciphertext, tag |
| 6 | AES-256-GCM | 32 | 16 | ciphertext, tag |
| 7 | AES-256-SIV | 64 | 16 | tag, ciphertext |
| 8 | Twofish-256-CTR + HMAC-SHA256 | 32 | 32 | ciphertext, tag |
| 9 | Camellia-256-CTR + HMAC-SHA256 | 32 | 32 | ciphertext, tag |
| 10 | AES-256-EAX | 32 | 16 | ciphertext, tag |

AES-256-SIV uses two 256-bit AES keys and the RFC 5297 SIV prefix layout.
Threefish-1024 uses an actual 1024-bit key and 1024-bit block, with a zero
128-bit tweak. HKDF-SHA256 limits the derived key entropy to at most 256 bits;
the 1024-bit name does not claim 1024-bit end-to-end security.

## Header

The first 64 bytes are unencrypted, fixed size, and authenticated by **every**
record. Integers in the header use little endian.

| Offset | Bytes | Field | Required value |
|---:|---:|---|---|
| 0 | 8 | Magic | ASCII `TENCRYPT` |
| 8 | 1 | Version | `1` |
| 9 | 1 | Algorithm ID | `1` through `10` |
| 10 | 2 | Flags | All zero |
| 12 | 4 | Plaintext chunk size, u32 LE | `1048576` (1 MiB) |
| 16 | 8 | Total plaintext length, u64 LE | `0` through `2^52` bytes |
| 24 | 32 | File salt | Fresh OS random bytes for each encryption |
| 56 | 8 | Reserved | All zero |

Unknown versions, IDs, flags, chunk sizes, and nonzero reserved bytes are
rejected. The user-selected ID must match the header ID.

The plaintext length and chosen suite are public metadata. The filename is
neither stored nor authenticated, so an encrypted file may be renamed before
decryption. An older valid ciphertext may be replayed; there is no external
revision database or rollback protection.

## Record boundaries and authenticated data

The header is followed immediately by fixed-position records. There are no
record length fields or delimiters in the stored body.

Let `L` be the header plaintext length, `S = 1048576`, and `T` the selected
suite's tag size:

```text
N = max(1, ceil(L / S))
plaintext_record_length(i) = min(S, L - i*S), for 0 <= i < N
stored_record_length(i) = plaintext_record_length(i) + T
total_encrypted_length = 64 + L + N*T
```

For an empty file, record zero has zero plaintext bytes and a full tag. The
implementation limits the record count to `2^32` and each plaintext record to
1 MiB. It rejects an input whose actual encrypted size differs from the size
computed above before allocating any record buffer. It also verifies EOF
after processing the final record.

Every record receives exactly this 77-byte additional authenticated data (AAD):

```text
header[64] || index:u64le || plaintext_record_length:u32le || final:u8
```

`index` starts at zero. `final` is `1` for record `N-1`, otherwise `0`. These
fields bind each record to this file, its position, its length, and the end of
the file. Authentication is mandatory even for empty files.

## Key derivation

Concatenation is written `||`. All strings below are ASCII and end in one NUL
byte where shown. Indices in the key derivation and counter/MAC construction
are **big endian**, independently of the little-endian framing fields above.

```text
PRK = HKDF-Extract-SHA256(salt = header.file_salt, IKM = embedded_master_key)

K_enc(i) = HKDF-Expand-SHA256(
  PRK,
  info = b"tencrypt/v1/record/encryption\0" || algorithm_id:u8 || i:u64be,
  length = suite_encryption_key_bytes
)

K_mac(i) = HKDF-Expand-SHA256(
  PRK,
  info = b"tencrypt/v1/record/authentication\0" || algorithm_id:u8 || i:u64be,
  length = 32
)  # CTR + HMAC suites only
```

Each record therefore uses independent encryption and authentication keys.
Salts must be fresh for every encryption. Encryption fails if OS randomness
cannot be obtained; it does not fall back to a clock, counter, or fixed salt.

## Native AEAD records: IDs 1, 2, 5, 6, 7, 10

The nonce consists of zero bytes followed by `index:u64be`. Its total length
is 24 bytes for ID 1, 12 bytes for IDs 2/5/6, and 16 bytes for IDs 7/10.

The implementation calls the RustCrypto AEAD with the derived encryption key,
that nonce, the 77-byte AAD, and this record's plaintext. IDs 1/2/5/6/10 append
the tag. ID 7 uses the `aes-siv` crate's `Aes256SivAead` representation, which
prepends its 16-byte synthetic IV. AES-SIV supplies the associated data vector
`[AAD, nonce]` to S2V, in that order, before the plaintext component.

## CTR plus encrypt-then-MAC records: IDs 3, 4, 8, 9

Each primitive encrypts full counter blocks. The counter block is exactly one
cipher block long:

```text
index:u64be || zero_padding || block_number:u64be
```

`block_number` starts at zero for each record. A 16-byte block has no padding;
Threefish's 128-byte block has 112 zero bytes between the two counters. XOR
the encrypted counter bytes with the plaintext; a partial final block uses
the required prefix of the encrypted counter. There is no plaintext padding.
The counter cannot wrap within a 1 MiB record.

Append the full 32-byte HMAC-SHA256 of the following transcript, using
`K_mac(i)`:

```text
b"tencrypt/v1/ctr-hmac-sha256\0" || algorithm_id:u8 || index:u64be ||
aad_length:u64be || AAD || ciphertext_length:u64be || ciphertext
```

MAC verification uses the dependency's constant-time tag comparison and
completes before any CTR decryption. The cipher primitives themselves come
from RustCrypto; the container and composition in this project are custom
application code, not a standardized interoperable file format.

## Publication and failures

Records are processed in bounded memory into a private staging file beside
the source. No unauthenticated record is written as plaintext. If a later
record fails, previously authenticated plaintext can already be present in
staging, but the transaction is aborted and its staging name is removed.

The visible source filename changes only after all records succeed, EOF is
verified, the source identity is rechecked, and the completed staging file is
flushed. The platform transaction then performs one filesystem replacement.
See `SECURITY.md` for crash, permission, metadata, and filesystem limits.

## Reference specifications

- [HKDF, RFC 5869](https://www.rfc-editor.org/rfc/rfc5869)
- [ChaCha20-Poly1305, RFC 8439](https://www.rfc-editor.org/rfc/rfc8439)
- [AES-GCM-SIV, RFC 8452](https://www.rfc-editor.org/rfc/rfc8452)
- [AES-SIV, RFC 5297](https://www.rfc-editor.org/rfc/rfc5297)
- [RustCrypto AEAD implementations](https://github.com/RustCrypto/AEADs)
- [RustCrypto block cipher implementations](https://github.com/RustCrypto/block-ciphers)
- [Threefish/Skein design and reference implementation](https://www.schneier.com/academic/skein/)
