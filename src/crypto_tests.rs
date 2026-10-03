use super::*;

fn decode_hex(text: &str) -> Vec<u8> {
    let text: String = text.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    assert_eq!(text.len() % 2, 0);
    text.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let hex = std::str::from_utf8(pair).expect("ASCII test vector");
            u8::from_str_radix(hex, 16).expect("hexadecimal test vector")
        })
        .collect()
}

fn fixture_key(algorithm: Algorithm) -> Vec<u8> {
    (0..algorithm.key_len()).map(|i| i as u8).collect()
}

#[test]
fn all_suites_round_trip_empty_partial_and_full_records() {
    for algorithm in Algorithm::ALL {
        let cipher = RecordCipher::new(algorithm, &fixture_key(algorithm), &[0x5a; 32]).unwrap();
        for length in [0, 1, 15, 16, 17, 127, 128, 129, 4097, MAX_RECORD_SIZE] {
            let plaintext: Vec<u8> = (0..length)
                .map(|i| (i.wrapping_mul(37) % 251) as u8)
                .collect();
            let aad = b"header including record length and final flag";
            let encrypted = cipher.encrypt(7, aad, &plaintext).unwrap();
            assert_eq!(encrypted.len(), plaintext.len() + algorithm.tag_len());
            let recovered = cipher.decrypt(7, aad, &encrypted).unwrap();
            assert_eq!(recovered, plaintext, "{} length {length}", algorithm.name());
        }
    }
}

#[test]
fn all_suites_authenticate_ciphertext_aad_index_salt_and_key() {
    for algorithm in Algorithm::ALL {
        let key = fixture_key(algorithm);
        let salt = [0x42; 32];
        let cipher = RecordCipher::new(algorithm, &key, &salt).unwrap();
        let aad = b"authenticated header and record metadata";
        let plaintext = b"authenticated plaintext with a partial final block";
        let encrypted = cipher.encrypt(0, aad, plaintext).unwrap();

        // Every byte is covered, including the entire tag and partial last block.
        for offset in 0..encrypted.len() {
            let mut modified = encrypted.clone();
            modified[offset] ^= 0x80;
            assert!(
                cipher.decrypt(0, aad, &modified).is_err(),
                "{} failed to reject changed ciphertext byte {offset}",
                algorithm.name()
            );
        }
        for offset in 0..aad.len() {
            let mut modified = aad.to_vec();
            modified[offset] ^= 0x01;
            assert!(cipher.decrypt(0, &modified, &encrypted).is_err());
        }
        assert!(cipher.decrypt(1, aad, &encrypted).is_err());

        let mut wrong_key = key.clone();
        *wrong_key.last_mut().unwrap() ^= 1;
        let wrong_cipher = RecordCipher::new(algorithm, &wrong_key, &salt).unwrap();
        assert!(wrong_cipher.decrypt(0, aad, &encrypted).is_err());

        let mut wrong_salt = salt;
        wrong_salt[31] ^= 1;
        let wrong_cipher = RecordCipher::new(algorithm, &key, &wrong_salt).unwrap();
        assert!(wrong_cipher.decrypt(0, aad, &encrypted).is_err());

        assert!(
            cipher
                .decrypt(0, aad, &encrypted[..encrypted.len() - 1])
                .is_err()
        );
        let mut extended = encrypted.clone();
        extended.push(0);
        assert!(cipher.decrypt(0, aad, &extended).is_err());
    }
}

#[test]
fn empty_records_still_require_authentication() {
    for algorithm in Algorithm::ALL {
        let cipher = RecordCipher::new(algorithm, &fixture_key(algorithm), &[3; 32]).unwrap();
        let tag = cipher.encrypt(0, b"empty-file header", b"").unwrap();
        assert_eq!(tag.len(), algorithm.tag_len());
        assert!(
            cipher
                .decrypt(0, b"empty-file header", &tag)
                .unwrap()
                .is_empty()
        );
        assert!(cipher.decrypt(0, b"modified header", &tag).is_err());
        for length in 0..algorithm.tag_len() {
            assert!(
                cipher
                    .decrypt(0, b"empty-file header", &tag[..length])
                    .is_err()
            );
        }
    }
}

#[test]
fn record_and_key_limits_are_enforced() {
    assert!(Algorithm::from_id(0).is_err());
    assert!(Algorithm::from_id(11).is_err());
    assert!(Algorithm::from_id(255).is_err());
    for algorithm in Algorithm::ALL {
        assert_eq!(Algorithm::from_id(algorithm.id()).unwrap(), algorithm);
        let key = fixture_key(algorithm);
        assert!(RecordCipher::new(algorithm, &key[..key.len() - 1], &[1; 32]).is_err());
        let cipher = RecordCipher::new(algorithm, &key, &[1; 32]).unwrap();
        assert!(cipher.encrypt(1_u64 << 32, b"", b"").is_err());
        assert!(cipher.encrypt(u64::MAX, b"", b"").is_err());
        assert!(
            cipher
                .encrypt(0, b"", &vec![0; MAX_RECORD_SIZE + 1])
                .is_err()
        );
        assert!(
            cipher
                .decrypt(0, b"", &vec![0; MAX_RECORD_SIZE + algorithm.tag_len() + 1])
                .is_err()
        );

        let last = u64::from(u32::MAX);
        let encrypted = cipher.encrypt(last, b"last legal record", b"x").unwrap();
        assert_eq!(
            cipher
                .decrypt(last, b"last legal record", &encrypted)
                .unwrap(),
            b"x"
        );
    }
}

#[test]
fn key_derivation_separates_record_index_salt_and_algorithm() {
    let mut records = Vec::new();
    for algorithm in Algorithm::ALL {
        let key = fixture_key(algorithm);
        let a = RecordCipher::new(algorithm, &key, &[0x11; 32]).unwrap();
        let b = RecordCipher::new(algorithm, &key, &[0x12; 32]).unwrap();
        let first = a.encrypt(0, b"same metadata", b"same plaintext").unwrap();
        assert_ne!(
            first,
            a.encrypt(1, b"same metadata", b"same plaintext").unwrap()
        );
        assert_ne!(
            first,
            b.encrypt(0, b"same metadata", b"same plaintext").unwrap()
        );
        assert!(records.iter().all(|previous| previous != &first));
        records.push(first);
    }
}

#[test]
fn independent_complete_record_known_answers() {
    // Generated independently of this Rust implementation with Python's
    // cryptography/OpenSSL HKDF, AESGCMSIV, ChaCha20Poly1305, AESGCM, AESSIV,
    // and Camellia-ECB; XChaCha20-Poly1305 was evaluated with libsodium.
    // These fixtures test the exact HKDF labels, ID/index byte order, nonce,
    // AAD and MAC transcript, not merely an encrypt/decrypt round trip.
    // Fixture inputs: key bytes 00..1f (00..3f for AES-256-SIV), salt 20..3f,
    // plaintext 00..24, index 0x01020304, and the ASCII AAD below.
    let fixtures = [
        (
            Algorithm::XChaCha20Poly1305,
            "014d1cf81cdfd29eabceb98920be8b7740c67807082155b67ff7286759107cb105d0be5d1a31cd2e4436f8143a9db2590072bd0d8f",
        ),
        (
            Algorithm::Aes256GcmSiv,
            "7d1fec91659c268ac501a3dc0742a57b5c221487beb85fc20fc5d6d9dc67fc71f2acbd6566ceaeb6cab3ea6cdef30b96af81eda3b5",
        ),
        (
            Algorithm::ChaCha20Poly1305,
            "e9a981c87028146251589a8fd329df49a28055a8dd50fb62099c7c891103b2100e38a1375b926f6a3021aafbf78829871d26017692",
        ),
        (
            Algorithm::Aes256Gcm,
            "7ba8aae0d3e42eb19a0dc32f4694c80cca67d24c073f7ad64c841ee56bbe9fec0653d3cd265a0733fcd8ed412420f5eb6bd6b1912d",
        ),
        (
            Algorithm::Aes256Siv,
            "eb9c4c627627bd82dbb232af18046cd99d8bca0e9dd11f259bd2f0351e78250987b75f90190adff40f5673dcf67701b62970d3a2f7",
        ),
        (
            Algorithm::Camellia256,
            "bd80935d4b4c5be039dbea2c554cb02ad817d46f93e221e1f5106c1860ccfa85b3ef4033008269f9913ee22ccdc5f08049931bf89dc0a2107a84258b4db4709f3f46e28c07",
        ),
    ];
    let salt: [u8; 32] = std::array::from_fn(|i| (i + 32) as u8);
    let plaintext: Vec<u8> = (0..37).collect();
    let aad = b"TenCrypt independent record fixture";
    for (algorithm, expected) in fixtures {
        let cipher = RecordCipher::new(algorithm, &fixture_key(algorithm), &salt).unwrap();
        let expected = decode_hex(expected);
        assert_eq!(
            cipher.encrypt(0x0102_0304, aad, &plaintext).unwrap(),
            expected,
            "{} independent known answer",
            algorithm.name()
        );
        assert_eq!(
            cipher.decrypt(0x0102_0304, aad, &expected).unwrap(),
            plaintext
        );
    }
}

#[test]
fn threefish1024_zero_counter_matches_official_known_answer() {
    // Official Skein 1.3 reference distribution (public domain):
    // https://www.schneier.com/wp-content/uploads/2015/01/skein.zip
    // NIST/CD/KAT_MCT/skein_golden_kat_internals.txt,
    // first Threefish-1024 vector, state after key injection #20.
    // The reference displays little-endian u64 words; this is their byte form.
    let expected = decode_hex(
        "f05c3d0a3d05b304f785ddc7d1e03601
         5c8aa76e2f217b06c6e1544c0bc1a90d
         f0accb9473c24e0fd54fea68057f4332
         9cb454761d6df5cf7b2e9b3614fbd5a2
         0b2e4760b40603540d82eabc5482c171
         c832afbe68406bc39500367a592943fa
         9a5b4a43286ca3c4cf46104b443143d5
         60a4b230488311df4feef7e1dfe8391e",
    );
    let mut output = [0_u8; 128];
    apply_ctr::<threefish::Threefish1024>(&[0; 128], 0, &mut output).unwrap();
    assert_eq!(output.as_slice(), expected);
}

#[test]
fn threefish1024_nonzero_key_and_tweak_match_official_known_answer() {
    // Same official distribution, second Threefish-1024 vector, before the
    // Skein plaintext feedforward. This catches key/input/tweak byte-order errors.
    let key = std::array::from_fn(|i| (i + 16) as u8);
    let tweak = std::array::from_fn(|i| i as u8);
    let cipher = threefish::Threefish1024::new_with_tweak(&key, &tweak);
    let mut block = Block::<threefish::Threefish1024>::default();
    for (index, byte) in block.iter_mut().enumerate() {
        *byte = 255 - index as u8;
    }
    cipher.encrypt_block(&mut block);
    let expected = decode_hex(
        "a6654ddbd73cc3b05dd777105aa849bc
         e49372eaaffc5568d254771bab85531c
         94f780e7ffaae430d5d8af8c70eebbe1
         760f3b42b737a89cb363490d670314bd
         8aa41ee63c2e1f45fbd477922f8360b3
         88d6125ea6c7af0ad7056d01796e90c8
         3313f4150a5716b30ed5f569288ae974
         ce2b4347926fce57de44512177dd7cde",
    );
    assert_eq!(block.as_slice(), expected);
}
