# Security scope

Tencrypt is an encryption application with a new file format and application-specific filesystem transaction code. It is **not independently audited**. Unit and integration tests provide evidence for the cases exercised; they do not establish that cryptographic, memory-handling, or filesystem code is free of vulnerabilities.

## Keys and authenticated encryption

Each algorithm has a distinct, fixed key hardcoded as a raw byte array in `src/embedded_keys.rs`. The distributed source archive contains these working keys, and both compiled executables contain them. No external key files or passwords are used at runtime. Anyone who obtains a matching executable or its source can decrypt ciphertext produced with its embedded keys. Protect these artifacts as key material; compilation and executable optimization do not conceal the keys.

The initial key arrays are generated from the operating system's cryptographic random source when preparing the project. Normal builds preserve them. Keep a protected backup of the original keys or executable before relying on encrypted data. Regenerating or editing the keys changes which files a new build can decrypt; old files still need their original keys. Linux and Windows builds from the same unmodified project share the keys.

Encryption uses a fresh random 32-byte file salt and domain-separated HKDF derivation of record keys. The file header, algorithm choice, record index, length, and final-record marker are authenticated. Native AEAD suites use their authentication tags. The Serpent, Threefish, Twofish, and Camellia suites use counter mode with separate HMAC-SHA-256 keys and encrypt-then-MAC authentication. These compositions are application code built from RustCrypto primitives, not independently standardized Tencrypt cipher suites. See [FORMAT.md](FORMAT.md) for the exact encoding and derivation.

Authentication detects a wrong key, corruption, changes to authenticated fields, and record truncation, reordering, or insertion. It does not tell you whether a complete valid encrypted file is the most recent version, or whether someone substituted another complete valid file encrypted with the same key. There is no external freshness or file-identity registry.

## Local operating environment

Use a directory writable only by the account doing the work. The application runs with that account's privileges. An attacker who can copy the executable, read its source, or inspect the running process can recover the keys and decrypt files.

The program rejects nonregular files, symbolic links/reparse points, multiply linked targets, and the running executable. Windows also rejects alternate data streams. Platform locking and precommit source checks reduce accidental concurrent changes; Linux locks are cooperative. This is not a hostile-directory race defense. Other processes must not modify or replace the target, executable directory, or their path components during an operation.

The supported Windows environment is Windows 10/11 on local NTFS. Linux permits ext2/3/4, XFS, Btrfs, F2FS, tmpfs/ramfs, and OverlayFS and rejects other filesystem types before processing. OverlayFS must have local backing; its reported type alone cannot establish that property. Memory filesystems do not survive reboot. Network filesystems, unusual filesystem drivers, untrusted mount changes, and malicious kernel or administrator interference are outside the supported operating model.

## Replacement, crashes, and stored plaintext

The input stays open while output is written to a private staging file in the same directory. A complete, flushed result replaces the input pathname in one rename. Decryption authenticates the complete stream before this commit. Before commit, processing or authentication failure leaves the original file contents in place.

Once a replacement succeeds, a subsequent durability failure is reported as a warning with exit code zero: the new contents have been installed. Do not repeat encryption on the assumption that nothing happened. Atomic naming behavior and durable recovery after power loss are different guarantees, and depend on operating system, filesystem, device, and storage configuration.

A crash, kill, or hardware failure may leave a temporary file. Decryption staging files contain plaintext. Normal error cleanup is not secure erasure; deleted plaintext or earlier versions may remain recoverable through filesystem snapshots, backups, storage caches, journal behavior, SSD wear leveling, or other storage mechanisms. The application does not securely erase the original plaintext after encryption and does not promise to remove all copies of key material from memory or storage.

Successful replacement preserves file content and the filename as appropriate, but does not preserve source ACLs, timestamps, extended attributes, sparse-file layout, or other metadata. New results are private to the current account under the platform's normal permission model. This is intentional; account administrators and sufficiently privileged processes may still access them.

Keep an independent backup while evaluating the program. Atomic replacement prevents readers from seeing a partly rewritten file at the target path; it is not a substitute for backup, independent review, or appropriate key custody.

## References

- [RustCrypto AEADs](https://github.com/RustCrypto/AEADs)
- [RustCrypto block ciphers](https://github.com/RustCrypto/block-ciphers)
- [RustCrypto MACs](https://github.com/RustCrypto/MACs)
- [HKDF, RFC 5869](https://www.rfc-editor.org/rfc/rfc5869)
- [Microsoft FILE_RENAME_INFO](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_rename_info)
- [Microsoft SetFileInformationByHandle](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-setfileinformationbyhandle)
