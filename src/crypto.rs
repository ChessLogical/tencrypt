//! The ten authenticated record ciphers used by the version-1 file container.
//!
//! Key derivation (all labels are exact, including the final NUL byte):
//!   PRK = HKDF-Extract-SHA256(file_salt[32], master_key)
//!   encryption_key = HKDF-Expand-SHA256(PRK,
//!       b"tencrypt/v1/record/encryption\0" || suite_id:u8 || index:u64be,
//!       suite_key_length)
//!   authentication_key = HKDF-Expand-SHA256(PRK,
//!       b"tencrypt/v1/record/authentication\0" || suite_id:u8 || index:u64be,
//!       32) // CTR suites only
//!
//! Each record therefore has an independent encryption key, including when two
//! records happen to contain the same bytes. Native AEAD nonces have the record
//! index in their final eight bytes (big endian), with preceding bytes zero.
//! Their lengths are 24 bytes for XChaCha20-Poly1305, 12 for ChaCha20-Poly1305,
//! AES-GCM and AES-GCM-SIV, and 16 for AES-SIV and AES-EAX.
//!
//! The four block-cipher suites use counter mode plus encrypt-then-MAC HMAC-
//! SHA256. A counter block is index:u64be || zero_padding || block_number:u64be,
//! exactly one block long, starting at block_number=0. Threefish uses the
//! standard all-zero 128-bit tweak. The MAC covers an unambiguous transcript:
//! b"tencrypt/v1/ctr-hmac-sha256\0" || suite_id:u8 || index:u64be ||
//! aad_length:u64be || aad || ciphertext_length:u64be || ciphertext.
//! The full 32-byte tag is appended. It is verified before any CTR decryption.
//!
//! Derived keys, the stored PRK, and scratch plaintext/keystream buffers are
//! zeroized on drop where practical. The compile-time master keys remain in
//! the executable by design. Dependency internals, compiler copies, registers
//! and swap are outside this module's zeroization guarantee.

use aead::{AeadInPlace, KeyInit, Nonce};
use anyhow::{Result, anyhow, bail, ensure};
use cipher::{Block, BlockEncrypt};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

pub const MAX_RECORD_SIZE: usize = 1024 * 1024;
const MAX_RECORD_COUNT: u64 = 1_u64 << 32;
const ENC_LABEL: &[u8] = b"tencrypt/v1/record/encryption\0";
const MAC_LABEL: &[u8] = b"tencrypt/v1/record/authentication\0";
const MAC_TRANSCRIPT_LABEL: &[u8] = b"tencrypt/v1/ctr-hmac-sha256\0";

type HmacSha256 = Hmac<Sha256>;
type Aes256Eax = eax::Eax<aes::Aes256>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Algorithm {
    XChaCha20Poly1305 = 1,
    Aes256GcmSiv = 2,
    Serpent256 = 3,
    Threefish1024 = 4,
    ChaCha20Poly1305 = 5,
    Aes256Gcm = 6,
    Aes256Siv = 7,
    Twofish256 = 8,
    Camellia256 = 9,
    Aes256Eax = 10,
}

impl Algorithm {
    pub const ALL: [Self; 10] = [
        Self::XChaCha20Poly1305,
        Self::Aes256GcmSiv,
        Self::Serpent256,
        Self::Threefish1024,
        Self::ChaCha20Poly1305,
        Self::Aes256Gcm,
        Self::Aes256Siv,
        Self::Twofish256,
        Self::Camellia256,
        Self::Aes256Eax,
    ];

    pub fn from_id(id: u8) -> Result<Self> {
        Self::ALL
            .get(usize::from(id).wrapping_sub(1))
            .copied()
            .ok_or_else(|| anyhow!("algorithm must be a number from 1 to 10"))
    }

    pub const fn id(self) -> u8 {
        self as u8
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::XChaCha20Poly1305 => "XChaCha20-Poly1305",
            Self::Aes256GcmSiv => "AES-256-GCM-SIV",
            Self::Serpent256 => "Serpent-256-CTR + HMAC-SHA256",
            Self::Threefish1024 => "Threefish-1024-CTR + HMAC-SHA256",
            Self::ChaCha20Poly1305 => "ChaCha20-Poly1305",
            Self::Aes256Gcm => "AES-256-GCM",
            Self::Aes256Siv => "AES-256-SIV",
            Self::Twofish256 => "Twofish-256-CTR + HMAC-SHA256",
            Self::Camellia256 => "Camellia-256-CTR + HMAC-SHA256",
            Self::Aes256Eax => "AES-256-EAX",
        }
    }

    /// Exact number of raw bytes in this suite's embedded master key.
    /// AES-256-SIV needs two 256-bit AES keys; Threefish-1024 needs 1024 bits.
    pub const fn key_len(self) -> usize {
        match self {
            Self::Threefish1024 => 128,
            Self::Aes256Siv => 64,
            _ => 32,
        }
    }

    pub const fn tag_len(self) -> usize {
        if self.is_ctr() { 32 } else { 16 }
    }

    const fn is_ctr(self) -> bool {
        matches!(
            self,
            Self::Serpent256 | Self::Threefish1024 | Self::Twofish256 | Self::Camellia256
        )
    }
}

/// Per-file key derivation state. Deliberately has no `Debug` implementation.
pub struct RecordCipher {
    algorithm: Algorithm,
    prk: Zeroizing<[u8; 32]>,
}

impl RecordCipher {
    pub fn new(algorithm: Algorithm, master_key: &[u8], salt: &[u8; 32]) -> Result<Self> {
        ensure!(
            master_key.len() == algorithm.key_len(),
            "{} requires an embedded key containing exactly {} raw bytes",
            algorithm.name(),
            algorithm.key_len()
        );
        let (mut extracted, _hkdf) = Hkdf::<Sha256>::extract(Some(salt), master_key);
        let mut prk = Zeroizing::new([0_u8; 32]);
        prk.copy_from_slice(extracted.as_slice());
        extracted.as_mut_slice().zeroize();
        Ok(Self { algorithm, prk })
    }

    fn derive_key(&self, label: &[u8], index: u64, length: usize) -> Result<Zeroizing<Vec<u8>>> {
        let hkdf = Hkdf::<Sha256>::from_prk(self.prk.as_ref())
            .map_err(|_| anyhow!("invalid internal HKDF key"))?;
        let mut info = Vec::with_capacity(label.len() + 9);
        info.extend_from_slice(label);
        info.push(self.algorithm.id());
        info.extend_from_slice(&index.to_be_bytes());
        let mut key = Zeroizing::new(vec![0_u8; length]);
        hkdf.expand(&info, &mut key)
            .map_err(|_| anyhow!("invalid internal HKDF output length"))?;
        Ok(key)
    }

    pub fn encrypt(&self, index: u64, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        validate_record(index, plaintext.len())?;
        let key = self.derive_key(ENC_LABEL, index, self.algorithm.key_len())?;
        let result = match self.algorithm {
            Algorithm::XChaCha20Poly1305 => {
                encrypt_aead::<chacha20poly1305::XChaCha20Poly1305>(&key, index, aad, plaintext)
            }
            Algorithm::Aes256GcmSiv => {
                encrypt_aead::<aes_gcm_siv::Aes256GcmSiv>(&key, index, aad, plaintext)
            }
            Algorithm::ChaCha20Poly1305 => {
                encrypt_aead::<chacha20poly1305::ChaCha20Poly1305>(&key, index, aad, plaintext)
            }
            Algorithm::Aes256Gcm => encrypt_aead::<aes_gcm::Aes256Gcm>(&key, index, aad, plaintext),
            Algorithm::Aes256Siv => {
                encrypt_aead::<aes_siv::Aes256SivAead>(&key, index, aad, plaintext)
            }
            Algorithm::Aes256Eax => encrypt_aead::<Aes256Eax>(&key, index, aad, plaintext),
            _ => {
                let mac_key = self.derive_key(MAC_LABEL, index, 32)?;
                let mut output = Zeroizing::new(plaintext.to_vec());
                self.apply_ctr(&key, index, &mut output)?;
                let tag = record_mac(&mac_key, self.algorithm, index, aad, &output)?
                    .finalize()
                    .into_bytes();
                output.extend_from_slice(&tag);
                Ok(std::mem::take(&mut *output))
            }
        }?;
        ensure!(
            result.len() == plaintext.len() + self.algorithm.tag_len(),
            "internal encryption length error"
        );
        Ok(result)
    }

    /// Returned plaintext belongs to the caller and should be zeroized after use.
    /// Authentication failure always returns `Err` with no plaintext result.
    pub fn decrypt(&self, index: u64, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        let Some(plaintext_len) = ciphertext.len().checked_sub(self.algorithm.tag_len()) else {
            bail!("authentication failed: encrypted record is too short");
        };
        validate_record(index, plaintext_len)?;
        let key = self.derive_key(ENC_LABEL, index, self.algorithm.key_len())?;
        let result = match self.algorithm {
            Algorithm::XChaCha20Poly1305 => {
                decrypt_aead::<chacha20poly1305::XChaCha20Poly1305>(&key, index, aad, ciphertext)
            }
            Algorithm::Aes256GcmSiv => {
                decrypt_aead::<aes_gcm_siv::Aes256GcmSiv>(&key, index, aad, ciphertext)
            }
            Algorithm::ChaCha20Poly1305 => {
                decrypt_aead::<chacha20poly1305::ChaCha20Poly1305>(&key, index, aad, ciphertext)
            }
            Algorithm::Aes256Gcm => {
                decrypt_aead::<aes_gcm::Aes256Gcm>(&key, index, aad, ciphertext)
            }
            Algorithm::Aes256Siv => {
                decrypt_aead::<aes_siv::Aes256SivAead>(&key, index, aad, ciphertext)
            }
            Algorithm::Aes256Eax => decrypt_aead::<Aes256Eax>(&key, index, aad, ciphertext),
            _ => {
                let mac_key = self.derive_key(MAC_LABEL, index, 32)?;
                let (encrypted, tag) = ciphertext.split_at(plaintext_len);
                record_mac(&mac_key, self.algorithm, index, aad, encrypted)?
                    .verify_slice(tag)
                    .map_err(|_| anyhow!("authentication failed: wrong key or modified file"))?;
                // No plaintext is computed until the full tag has been verified.
                let mut output = Zeroizing::new(encrypted.to_vec());
                self.apply_ctr(&key, index, &mut output)?;
                Ok(std::mem::take(&mut *output))
            }
        }?;
        ensure!(
            result.len() == plaintext_len,
            "internal decryption length error"
        );
        Ok(result)
    }

    fn apply_ctr(&self, key: &[u8], index: u64, buffer: &mut [u8]) -> Result<()> {
        match self.algorithm {
            Algorithm::Serpent256 => apply_ctr::<serpent::Serpent>(key, index, buffer),
            Algorithm::Threefish1024 => apply_ctr::<threefish::Threefish1024>(key, index, buffer),
            Algorithm::Twofish256 => apply_ctr::<twofish::Twofish>(key, index, buffer),
            Algorithm::Camellia256 => apply_ctr::<camellia::Camellia256>(key, index, buffer),
            _ => bail!("internal error: requested CTR for a native AEAD suite"),
        }
    }
}

fn validate_record(index: u64, plaintext_len: usize) -> Result<()> {
    ensure!(index < MAX_RECORD_COUNT, "too many encrypted records");
    ensure!(
        plaintext_len <= MAX_RECORD_SIZE,
        "encrypted record exceeds 1 MiB"
    );
    Ok(())
}

fn nonce<C: AeadInPlace>(index: u64) -> Nonce<C> {
    let mut nonce = Nonce::<C>::default();
    let offset = nonce.len() - 8;
    nonce[offset..].copy_from_slice(&index.to_be_bytes());
    nonce
}

fn encrypt_aead<C: AeadInPlace + KeyInit>(
    key: &[u8],
    index: u64,
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let cipher = C::new_from_slice(key).map_err(|_| anyhow!("invalid internal cipher key"))?;
    let mut output = Zeroizing::new(Vec::with_capacity(plaintext.len() + 16));
    output.extend_from_slice(plaintext);
    cipher
        .encrypt_in_place(&nonce::<C>(index), aad, &mut *output)
        .map_err(|_| anyhow!("record encryption failed"))?;
    Ok(std::mem::take(&mut *output))
}

fn decrypt_aead<C: AeadInPlace + KeyInit>(
    key: &[u8],
    index: u64,
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let cipher = C::new_from_slice(key).map_err(|_| anyhow!("invalid internal cipher key"))?;
    let mut output = Zeroizing::new(ciphertext.to_vec());
    cipher
        .decrypt_in_place(&nonce::<C>(index), aad, &mut *output)
        .map_err(|_| anyhow!("authentication failed: wrong key or modified file"))?;
    Ok(std::mem::take(&mut *output))
}

fn record_mac(
    key: &[u8],
    algorithm: Algorithm,
    index: u64,
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<HmacSha256> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key)
        .map_err(|_| anyhow!("invalid internal authentication key"))?;
    mac.update(MAC_TRANSCRIPT_LABEL);
    mac.update(&[algorithm.id()]);
    mac.update(&index.to_be_bytes());
    mac.update(&(aad.len() as u64).to_be_bytes());
    mac.update(aad);
    mac.update(&(ciphertext.len() as u64).to_be_bytes());
    mac.update(ciphertext);
    Ok(mac)
}

/// Standard counter-mode XOR using the underlying RustCrypto block primitive.
/// One record is limited to 1 MiB, so the 64-bit block counter cannot wrap.
fn apply_ctr<C: BlockEncrypt + KeyInit>(key: &[u8], index: u64, buffer: &mut [u8]) -> Result<()> {
    let cipher = C::new_from_slice(key).map_err(|_| anyhow!("invalid internal cipher key"))?;
    let mut counter = Block::<C>::default();
    let block_size = counter.len();
    ensure!(block_size >= 16, "internal error: block size is too small");
    for (block_number, block) in buffer.chunks_mut(block_size).enumerate() {
        counter.fill(0);
        counter[..8].copy_from_slice(&index.to_be_bytes());
        counter[block_size - 8..].copy_from_slice(&(block_number as u64).to_be_bytes());
        cipher.encrypt_block(&mut counter);
        for (byte, mask) in block.iter_mut().zip(counter.iter()) {
            *byte ^= mask;
        }
    }
    counter.as_mut_slice().zeroize();
    Ok(())
}

#[cfg(test)]
#[path = "crypto_tests.rs"]
mod tests;
