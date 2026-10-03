//! Versioned, bounded-memory, authenticated file framing.
//!
//! Every record authenticates the complete header, its index, its plaintext
//! length, and whether it is the final record. Empty files have one tagged
//! record. See docs/FORMAT.md for the byte-level specification.

use std::io::{self, Read, Write};

use anyhow::{Context, Result, anyhow, bail, ensure};
use zeroize::Zeroizing;

use crate::crypto::{Algorithm, RecordCipher};

pub(crate) const MAGIC: &[u8; 8] = b"TENCRYPT";
pub(crate) const HEADER_LEN: usize = 64;
pub(crate) const CHUNK_SIZE: usize = 1_048_576;
const VERSION: u8 = 1;
const MAX_RECORDS: u64 = 1_u64 << 32;
const MAX_PLAINTEXT_LEN: u64 = MAX_RECORDS * CHUNK_SIZE as u64;

struct Header {
    raw: [u8; HEADER_LEN],
    plaintext_len: u64,
    salt: [u8; 32],
}

impl Header {
    fn new(algorithm: Algorithm, plaintext_len: u64) -> Result<Self> {
        record_count(plaintext_len)?;
        let mut salt = [0; 32];
        getrandom::fill(&mut salt)
            .map_err(|error| anyhow!("the operating system random generator failed: {error}"))?;
        let mut raw = [0; HEADER_LEN];
        raw[..8].copy_from_slice(MAGIC);
        raw[8] = VERSION;
        raw[9] = algorithm.id();
        raw[12..16].copy_from_slice(&(CHUNK_SIZE as u32).to_le_bytes());
        raw[16..24].copy_from_slice(&plaintext_len.to_le_bytes());
        raw[24..56].copy_from_slice(&salt);
        Ok(Self {
            raw,
            plaintext_len,
            salt,
        })
    }

    fn parse(raw: [u8; HEADER_LEN], selected: Algorithm) -> Result<Self> {
        ensure!(&raw[..8] == MAGIC, "this is not a Tencrypt encrypted file");
        ensure!(
            raw[8] == VERSION,
            "unsupported Tencrypt file version {}",
            raw[8]
        );
        let stored = Algorithm::from_id(raw[9]).context("invalid algorithm in file header")?;
        ensure!(
            stored.id() == selected.id(),
            "file uses algorithm {} ({}); select that algorithm to decrypt",
            stored.id(),
            stored.name()
        );
        ensure!(
            raw[10..12] == [0; 2] && raw[56..64] == [0; 8],
            "unsupported flags or reserved fields in file header"
        );
        let chunk_size = u32::from_le_bytes(raw[12..16].try_into()?);
        ensure!(
            chunk_size as usize == CHUNK_SIZE,
            "invalid chunk size in file header"
        );
        let plaintext_len = u64::from_le_bytes(raw[16..24].try_into()?);
        record_count(plaintext_len)?;
        let salt = raw[24..56].try_into()?;
        Ok(Self {
            raw,
            plaintext_len,
            salt,
        })
    }

    fn aad(&self, index: u64, len: usize, last: bool) -> [u8; HEADER_LEN + 13] {
        let mut aad = [0; HEADER_LEN + 13];
        aad[..HEADER_LEN].copy_from_slice(&self.raw);
        aad[HEADER_LEN..HEADER_LEN + 8].copy_from_slice(&index.to_le_bytes());
        aad[HEADER_LEN + 8..HEADER_LEN + 12].copy_from_slice(&(len as u32).to_le_bytes());
        aad[HEADER_LEN + 12] = u8::from(last);
        aad
    }
}

fn record_count(plaintext_len: u64) -> Result<u64> {
    ensure!(
        plaintext_len <= MAX_PLAINTEXT_LEN,
        "file exceeds the format limit of 4 PiB"
    );
    Ok(plaintext_len.div_ceil(CHUNK_SIZE as u64).max(1))
}

fn ciphertext_len(plaintext_len: u64, tag_len: usize) -> Result<u64> {
    let overhead = record_count(plaintext_len)?
        .checked_mul(tag_len as u64)
        .and_then(|value| value.checked_add(HEADER_LEN as u64))
        .context("encrypted file length overflow")?;
    plaintext_len
        .checked_add(overhead)
        .context("encrypted file length overflow")
}

fn record_plaintext_len(total: u64, index: u64) -> usize {
    total
        .saturating_sub(index * CHUNK_SIZE as u64)
        .min(CHUNK_SIZE as u64) as usize
}

fn ensure_eof(reader: &mut impl Read) -> Result<()> {
    let mut byte = [0];
    loop {
        match reader.read(&mut byte) {
            Ok(0) => return Ok(()),
            Ok(_) => bail!("unexpected trailing bytes, or source changed while being read"),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error).context("could not check the end of the source file"),
        }
    }
}

/// The caller owns the filesystem transaction and only commits after success.
pub(crate) fn encrypt(
    algorithm: Algorithm,
    master_key: &[u8],
    plaintext_len: u64,
    reader: &mut impl Read,
    writer: &mut impl Write,
) -> Result<u64> {
    let header = Header::new(algorithm, plaintext_len)?;
    let count = record_count(plaintext_len)?;
    let cipher = RecordCipher::new(algorithm, master_key, &header.salt)?;
    writer
        .write_all(&header.raw)
        .context("could not write encrypted header")?;
    for index in 0..count {
        let len = record_plaintext_len(plaintext_len, index);
        let mut plaintext = Zeroizing::new(vec![0; len]);
        reader
            .read_exact(&mut plaintext)
            .context("could not read source record")?;
        let aad = header.aad(index, len, index + 1 == count);
        let encrypted = cipher.encrypt(index, &aad, &plaintext)?;
        ensure!(
            encrypted.len() == len + algorithm.tag_len(),
            "unexpected cipher output length"
        );
        writer
            .write_all(&encrypted)
            .context("could not write encrypted record")?;
    }
    ensure_eof(reader)?;
    ciphertext_len(plaintext_len, algorithm.tag_len())
}

/// No unauthenticated record is written. Later errors abort the transaction.
pub(crate) fn decrypt(
    algorithm: Algorithm,
    master_key: &[u8],
    encrypted_len: u64,
    reader: &mut impl Read,
    writer: &mut impl Write,
) -> Result<u64> {
    ensure!(
        encrypted_len >= HEADER_LEN as u64,
        "file is too short to contain a Tencrypt header"
    );
    let mut raw = [0; HEADER_LEN];
    reader
        .read_exact(&mut raw)
        .context("could not read encrypted header")?;
    let header = Header::parse(raw, algorithm)?;
    ensure!(
        ciphertext_len(header.plaintext_len, algorithm.tag_len())? == encrypted_len,
        "encrypted file length does not match its header (truncated, appended, or damaged file)"
    );
    let count = record_count(header.plaintext_len)?;
    let cipher = RecordCipher::new(algorithm, master_key, &header.salt)?;
    for index in 0..count {
        let len = record_plaintext_len(header.plaintext_len, index);
        let mut encrypted = vec![0; len + algorithm.tag_len()];
        reader
            .read_exact(&mut encrypted)
            .context("could not read encrypted record")?;
        let aad = header.aad(index, len, index + 1 == count);
        let plaintext = Zeroizing::new(
            cipher
                .decrypt(index, &aad, &encrypted)
                .context("authentication failed: wrong key or damaged/modified encrypted file")?,
        );
        ensure!(plaintext.len() == len, "unexpected cipher output length");
        writer
            .write_all(&plaintext)
            .context("could not write decrypted record")?;
    }
    ensure_eof(reader)?;
    Ok(header.plaintext_len)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn frame_lengths_and_limits() {
        assert_eq!(record_count(0).unwrap(), 1);
        assert_eq!(record_count(CHUNK_SIZE as u64).unwrap(), 1);
        assert_eq!(record_count(CHUNK_SIZE as u64 + 1).unwrap(), 2);
        assert_eq!(record_count(MAX_PLAINTEXT_LEN).unwrap(), MAX_RECORDS);
        assert!(record_count(MAX_PLAINTEXT_LEN + 1).is_err());
        assert_eq!(ciphertext_len(0, 16).unwrap(), 80);
        assert_eq!(
            ciphertext_len(CHUNK_SIZE as u64 + 1, 32).unwrap(),
            CHUNK_SIZE as u64 + 129
        );
    }

    #[test]
    fn rejects_unbounded_and_noncanonical_headers() {
        let algorithm = Algorithm::from_id(1).unwrap();
        let valid = Header::new(algorithm, 0).unwrap().raw;
        for offset in [0, 8, 9, 10, 11, 12, 56, 63] {
            let mut changed = valid;
            changed[offset] ^= 0x80;
            assert!(
                Header::parse(changed, algorithm).is_err(),
                "offset {offset}"
            );
        }
        let mut giant = valid;
        giant[16..24].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(Header::parse(giant, algorithm).is_err());
    }

    #[test]
    fn a_corrupt_first_record_writes_no_plaintext() {
        let algorithm = Algorithm::from_id(1).unwrap();
        let key = [0x41; 32];
        let plaintext = b"file framing tamper test";
        let mut encrypted = Vec::new();
        encrypt(
            algorithm,
            &key,
            plaintext.len() as u64,
            &mut &plaintext[..],
            &mut encrypted,
        )
        .unwrap();
        encrypted[HEADER_LEN] ^= 1;
        let mut recovered = Vec::new();
        assert!(
            decrypt(
                algorithm,
                &key,
                encrypted.len() as u64,
                &mut Cursor::new(encrypted),
                &mut recovered
            )
            .is_err()
        );
        assert!(recovered.is_empty());
    }

    #[test]
    fn refuses_source_growth_and_short_reads() {
        let algorithm = Algorithm::from_id(1).unwrap();
        let key = [7; 32];
        assert!(encrypt(algorithm, &key, 1, &mut &b"ab"[..], &mut Vec::new()).is_err());
        assert!(encrypt(algorithm, &key, 3, &mut &b"ab"[..], &mut Vec::new()).is_err());
    }
}
