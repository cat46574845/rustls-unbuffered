use alloc::boxed::Box;

use aws_lc_rs::hkdf::KeyType;
use aws_lc_rs::{aead, hkdf, hmac};

use crate::crypto;
use crate::crypto::cipher::{
    AeadKey, InboundOpaqueMessage, InboundOpaqueMessageImmut, Iv, MessageDecrypter,
    MessageEncrypter, Nonce, Tls13AeadAlgorithm, UnsupportedOperationError, make_tls13_aad,
};
use crate::crypto::tls13::{Hkdf, HkdfExpander, OkmBlock, OutputLengthError};
use crate::enums::{CipherSuite, ContentType, ProtocolVersion};
use crate::error::Error;
use crate::msgs::message::{
    InboundPlainMessage, OutboundOpaqueMessage, OutboundPlainMessage, PrefixedPayload,
};
use crate::suites::{CipherSuiteCommon, ConnectionTrafficSecrets, SupportedCipherSuite};
use crate::tls13::Tls13CipherSuite;

/// The TLS1.3 ciphersuite TLS_CHACHA20_POLY1305_SHA256
pub static TLS13_CHACHA20_POLY1305_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(TLS13_CHACHA20_POLY1305_SHA256_INTERNAL);

pub(crate) static TLS13_CHACHA20_POLY1305_SHA256_INTERNAL: &Tls13CipherSuite = &Tls13CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
        hash_provider: &super::hash::SHA256,
        // ref: <https://www.ietf.org/archive/id/draft-irtf-cfrg-aead-limits-08.html#section-5.2.1>
        confidentiality_limit: u64::MAX,
    },
    hkdf_provider: &AwsLcHkdf(hkdf::HKDF_SHA256, hmac::HMAC_SHA256),
    aead_alg: &Chacha20Poly1305Aead(AeadAlgorithm(&aead::CHACHA20_POLY1305)),
    quic: Some(&super::quic::KeyBuilder {
        packet_alg: &aead::CHACHA20_POLY1305,
        header_alg: &aead::quic::CHACHA20,
        // ref: <https://datatracker.ietf.org/doc/html/rfc9001#section-6.6>
        confidentiality_limit: u64::MAX,
        // ref: <https://datatracker.ietf.org/doc/html/rfc9001#section-6.6>
        integrity_limit: 1 << 36,
    }),
};

/// The TLS1.3 ciphersuite TLS_AES_256_GCM_SHA384
pub static TLS13_AES_256_GCM_SHA384: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&Tls13CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS13_AES_256_GCM_SHA384,
            hash_provider: &super::hash::SHA384,
            confidentiality_limit: 1 << 24,
        },
        hkdf_provider: &AwsLcHkdf(hkdf::HKDF_SHA384, hmac::HMAC_SHA384),
        aead_alg: &Aes256GcmAead(AeadAlgorithm(&aead::AES_256_GCM)),
        quic: Some(&super::quic::KeyBuilder {
            packet_alg: &aead::AES_256_GCM,
            header_alg: &aead::quic::AES_256,
            // ref: <https://datatracker.ietf.org/doc/html/rfc9001#section-b.1.1>
            confidentiality_limit: 1 << 23,
            // ref: <https://datatracker.ietf.org/doc/html/rfc9001#section-b.1.2>
            integrity_limit: 1 << 52,
        }),
    });

/// The TLS1.3 ciphersuite TLS_AES_128_GCM_SHA256
pub static TLS13_AES_128_GCM_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(TLS13_AES_128_GCM_SHA256_INTERNAL);

pub(crate) static TLS13_AES_128_GCM_SHA256_INTERNAL: &Tls13CipherSuite = &Tls13CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS13_AES_128_GCM_SHA256,
        hash_provider: &super::hash::SHA256,
        confidentiality_limit: 1 << 24,
    },
    hkdf_provider: &AwsLcHkdf(hkdf::HKDF_SHA256, hmac::HMAC_SHA256),
    aead_alg: &Aes128GcmAead(AeadAlgorithm(&aead::AES_128_GCM)),
    quic: Some(&super::quic::KeyBuilder {
        packet_alg: &aead::AES_128_GCM,
        header_alg: &aead::quic::AES_128,
        // ref: <https://datatracker.ietf.org/doc/html/rfc9001#section-b.1.1>
        confidentiality_limit: 1 << 23,
        // ref: <https://datatracker.ietf.org/doc/html/rfc9001#section-b.1.2>
        integrity_limit: 1 << 52,
    }),
};

struct Chacha20Poly1305Aead(AeadAlgorithm);

impl Tls13AeadAlgorithm for Chacha20Poly1305Aead {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        // safety: the caller arranges that `key` is `key_len()` in bytes, so this unwrap is safe.
        Box::new(AeadMessageEncrypter {
            enc_key: aead::LessSafeKey::new(aead::UnboundKey::new(self.0.0, key.as_ref()).unwrap()),
            iv,
        })
    }

    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        // safety: the caller arranges that `key` is `key_len()` in bytes, so this unwrap is safe.
        Box::new(AeadMessageDecrypter {
            dec_key: aead::LessSafeKey::new(aead::UnboundKey::new(self.0.0, key.as_ref()).unwrap()),
            iv,
        })
    }

    fn key_len(&self) -> usize {
        self.0.key_len()
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok(ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv })
    }

    fn fips(&self) -> bool {
        false // not FIPS approved
    }
}

struct Aes256GcmAead(AeadAlgorithm);

impl Tls13AeadAlgorithm for Aes256GcmAead {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        self.0.encrypter(key, iv)
    }

    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        self.0.decrypter(key, iv)
    }

    fn key_len(&self) -> usize {
        self.0.key_len()
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok(ConnectionTrafficSecrets::Aes256Gcm { key, iv })
    }

    fn fips(&self) -> bool {
        super::fips()
    }
}

struct Aes128GcmAead(AeadAlgorithm);

impl Tls13AeadAlgorithm for Aes128GcmAead {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        self.0.encrypter(key, iv)
    }

    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        self.0.decrypter(key, iv)
    }

    fn key_len(&self) -> usize {
        self.0.key_len()
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok(ConnectionTrafficSecrets::Aes128Gcm { key, iv })
    }

    fn fips(&self) -> bool {
        super::fips()
    }
}

// common encrypter/decrypter/key_len items for above Tls13AeadAlgorithm impls
struct AeadAlgorithm(&'static aead::Algorithm);

impl AeadAlgorithm {
    // using aead::TlsRecordSealingKey
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        // safety:
        // - the caller arranges that `key` is `key_len()` in bytes, so this unwrap is safe.
        // - this function should only be used for `Algorithm::AES_128_GCM` or `Algorithm::AES_256_GCM`
        Box::new(GcmMessageEncrypter {
            enc_key: aead::TlsRecordSealingKey::new(
                self.0,
                aead::TlsProtocolId::TLS13,
                key.as_ref(),
            )
            .unwrap(),
            iv,
        })
    }

    // using aead::TlsRecordOpeningKey
    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        // safety:
        // - the caller arranges that `key` is `key_len()` in bytes, so this unwrap is safe.
        // - this function should only be used for `Algorithm::AES_128_GCM` or `Algorithm::AES_256_GCM`
        Box::new(GcmMessageDecrypter {
            dec_key: aead::TlsRecordOpeningKey::new(
                self.0,
                aead::TlsProtocolId::TLS13,
                key.as_ref(),
            )
            .unwrap(),
            iv,
        })
    }

    fn key_len(&self) -> usize {
        self.0.key_len()
    }
}

struct AeadMessageEncrypter {
    enc_key: aead::LessSafeKey,
    iv: Iv,
}

struct AeadMessageDecrypter {
    dec_key: aead::LessSafeKey,
    iv: Iv,
}

impl MessageEncrypter for AeadMessageEncrypter {
    fn encrypt(
        &mut self,
        msg: OutboundPlainMessage<'_>,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, Error> {
        let total_len = self.encrypted_payload_len(msg.payload.len());
        let mut payload = PrefixedPayload::with_capacity(total_len);

        let nonce = aead::Nonce::assume_unique_for_key(Nonce::new(&self.iv, seq).0);
        let aad = aead::Aad::from(make_tls13_aad(total_len));
        payload.extend_from_chunks(&msg.payload);
        payload.extend_from_slice(&msg.typ.to_array());

        self.enc_key
            .seal_in_place_append_tag(nonce, aad, &mut payload)
            .map_err(|_| Error::EncryptError)?;

        Ok(OutboundOpaqueMessage::new(
            ContentType::ApplicationData,
            // Note: all TLS 1.3 application data records use TLSv1_2 (0x0303) as the legacy record
            // protocol version, see https://www.rfc-editor.org/rfc/rfc8446#section-5.1
            ProtocolVersion::TLSv1_2,
            payload,
        ))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + 1 + self.enc_key.algorithm().tag_len()
    }
}

impl MessageDecrypter for AeadMessageDecrypter {
    fn decrypt<'a>(
        &mut self,
        mut msg: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, Error> {
        let payload = &mut msg.payload;
        if payload.len() < self.dec_key.algorithm().tag_len() {
            return Err(Error::DecryptError);
        }

        let nonce = aead::Nonce::assume_unique_for_key(Nonce::new(&self.iv, seq).0);
        let aad = aead::Aad::from(make_tls13_aad(payload.len()));
        let plain_len = self
            .dec_key
            .open_in_place(nonce, aad, payload)
            .map_err(|_| Error::DecryptError)?
            .len();

        payload.truncate(plain_len);
        msg.into_tls13_unpadded_message()
    }

    fn decrypt_to<'a>(
        &mut self,
        msg: &InboundOpaqueMessageImmut<'_>,
        seq: u64,
        out: &'a mut [u8],
    ) -> Result<InboundPlainMessage<'a>, Error> {
        let tag_len = self.dec_key.algorithm().tag_len();
        if msg.payload.len() < tag_len {
            return Err(Error::DecryptError);
        }

        // Split ciphertext and tag (no copy yet)
        let ciphertext_len = msg.payload.len() - tag_len;
        let (ciphertext, tag) = msg.payload.split_at(ciphertext_len);

        if out.len() < ciphertext_len {
            return Err(Error::General("output buffer too small".into()));
        }

        let nonce = aead::Nonce::assume_unique_for_key(Nonce::new(&self.iv, seq).0);
        let aad = aead::Aad::from(make_tls13_aad(msg.payload.len()));

        // Zero-copy: decrypt directly from input ciphertext to output buffer
        self.dec_key
            .open_separate_gather(nonce, aad, ciphertext, tag, &mut out[..ciphertext_len])
            .map_err(|_| Error::DecryptError)?;

        let plain_len = ciphertext_len;

        // TLS 1.3: remove padding and extract content type from end
        // Find the real content type (last non-zero byte)
        let mut content_type_byte = 0u8;
        let mut actual_len = plain_len;
        for i in (0..plain_len).rev() {
            if out[i] != 0 {
                content_type_byte = out[i];
                actual_len = i;
                break;
            }
        }

        let typ = ContentType::from(content_type_byte);
        if typ == ContentType::Unknown(0) {
            return Err(Error::DecryptError);
        }

        Ok(InboundPlainMessage {
            typ,
            // TLS 1.3: must set version to TLSv1_3 for correct handshake parsing
            version: ProtocolVersion::TLSv1_3,
            payload: &out[..actual_len],
        })
    }
}

struct GcmMessageEncrypter {
    enc_key: aead::TlsRecordSealingKey,
    iv: Iv,
}

impl MessageEncrypter for GcmMessageEncrypter {
    fn encrypt(
        &mut self,
        msg: OutboundPlainMessage<'_>,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, Error> {
        let total_len = self.encrypted_payload_len(msg.payload.len());
        let mut payload = PrefixedPayload::with_capacity(total_len);

        let nonce = aead::Nonce::assume_unique_for_key(Nonce::new(&self.iv, seq).0);
        let aad = aead::Aad::from(make_tls13_aad(total_len));
        payload.extend_from_chunks(&msg.payload);
        payload.extend_from_slice(&msg.typ.to_array());

        self.enc_key
            .seal_in_place_append_tag(nonce, aad, &mut payload)
            .map_err(|_| Error::EncryptError)?;

        Ok(OutboundOpaqueMessage::new(
            ContentType::ApplicationData,
            ProtocolVersion::TLSv1_2,
            payload,
        ))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + 1 + self.enc_key.algorithm().tag_len()
    }
}

struct GcmMessageDecrypter {
    dec_key: aead::TlsRecordOpeningKey,
    iv: Iv,
}

impl MessageDecrypter for GcmMessageDecrypter {
    fn decrypt<'a>(
        &mut self,
        mut msg: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, Error> {
        let payload = &mut msg.payload;
        if payload.len() < self.dec_key.algorithm().tag_len() {
            return Err(Error::DecryptError);
        }

        let nonce = aead::Nonce::assume_unique_for_key(Nonce::new(&self.iv, seq).0);
        let aad = aead::Aad::from(make_tls13_aad(payload.len()));
        let plain_len = self
            .dec_key
            .open_in_place(nonce, aad, payload)
            .map_err(|_| Error::DecryptError)?
            .len();

        payload.truncate(plain_len);
        msg.into_tls13_unpadded_message()
    }

    fn decrypt_to<'a>(
        &mut self,
        msg: &InboundOpaqueMessageImmut<'_>,
        seq: u64,
        out: &'a mut [u8],
    ) -> Result<InboundPlainMessage<'a>, Error> {
        let tag_len = self.dec_key.algorithm().tag_len();
        if msg.payload.len() < tag_len {
            return Err(Error::DecryptError);
        }

        // Split ciphertext and tag (no copy yet)
        let ciphertext_len = msg.payload.len() - tag_len;
        let (ciphertext, tag) = msg.payload.split_at(ciphertext_len);

        if out.len() < ciphertext_len {
            return Err(Error::General("output buffer too small".into()));
        }

        let nonce = aead::Nonce::assume_unique_for_key(Nonce::new(&self.iv, seq).0);
        let aad = aead::Aad::from(make_tls13_aad(msg.payload.len()));

        // Zero-copy: decrypt directly from input ciphertext to output buffer
        self.dec_key
            .open_separate_gather(nonce, aad, ciphertext, tag, &mut out[..ciphertext_len])
            .map_err(|_| Error::DecryptError)?;

        let plain_len = ciphertext_len;

        // TLS 1.3: remove padding and extract content type from end
        let mut content_type_byte = 0u8;
        let mut actual_len = plain_len;
        for i in (0..plain_len).rev() {
            if out[i] != 0 {
                content_type_byte = out[i];
                actual_len = i;
                break;
            }
        }

        let typ = ContentType::from(content_type_byte);
        if typ == ContentType::Unknown(0) {
            return Err(Error::DecryptError);
        }

        Ok(InboundPlainMessage {
            typ,
            // TLS 1.3: must set version to TLSv1_3 for correct handshake parsing
            version: ProtocolVersion::TLSv1_3,
            payload: &out[..actual_len],
        })
    }
}

struct AwsLcHkdf(hkdf::Algorithm, hmac::Algorithm);

impl Hkdf for AwsLcHkdf {
    fn extract_from_zero_ikm(&self, salt: Option<&[u8]>) -> Box<dyn HkdfExpander> {
        let zeroes = [0u8; OkmBlock::MAX_LEN];
        let salt = match salt {
            Some(salt) => salt,
            None => &zeroes[..self.0.len()],
        };
        Box::new(AwsLcHkdfExpander {
            alg: self.0,
            prk: hkdf::Salt::new(self.0, salt).extract(&zeroes[..self.0.len()]),
        })
    }

    fn extract_from_secret(&self, salt: Option<&[u8]>, secret: &[u8]) -> Box<dyn HkdfExpander> {
        let zeroes = [0u8; OkmBlock::MAX_LEN];
        let salt = match salt {
            Some(salt) => salt,
            None => &zeroes[..self.0.len()],
        };
        Box::new(AwsLcHkdfExpander {
            alg: self.0,
            prk: hkdf::Salt::new(self.0, salt).extract(secret),
        })
    }

    fn expander_for_okm(&self, okm: &OkmBlock) -> Box<dyn HkdfExpander> {
        Box::new(AwsLcHkdfExpander {
            alg: self.0,
            prk: hkdf::Prk::new_less_safe(self.0, okm.as_ref()),
        })
    }

    fn hmac_sign(&self, key: &OkmBlock, message: &[u8]) -> crypto::hmac::Tag {
        crypto::hmac::Tag::new(hmac::sign(&hmac::Key::new(self.1, key.as_ref()), message).as_ref())
    }

    fn fips(&self) -> bool {
        super::fips()
    }
}

struct AwsLcHkdfExpander {
    alg: hkdf::Algorithm,
    prk: hkdf::Prk,
}

impl HkdfExpander for AwsLcHkdfExpander {
    fn expand_slice(&self, info: &[&[u8]], output: &mut [u8]) -> Result<(), OutputLengthError> {
        self.prk
            .expand(info, Len(output.len()))
            .and_then(|okm| okm.fill(output))
            .map_err(|_| OutputLengthError)
    }

    fn expand_block(&self, info: &[&[u8]]) -> OkmBlock {
        let mut buf = [0u8; OkmBlock::MAX_LEN];
        let output = &mut buf[..self.hash_len()];
        self.prk
            .expand(info, Len(output.len()))
            .and_then(|okm| okm.fill(output))
            .unwrap();
        OkmBlock::new(output)
    }

    fn hash_len(&self) -> usize {
        self.alg.len()
    }
}

struct Len(usize);

impl KeyType for Len {
    fn len(&self) -> usize {
        self.0
    }
}

/// 測試 TLS 1.3 的 decrypt_to 實現
///
/// 這些測試直接驗證 `AeadMessageDecrypter` 和 `GcmMessageDecrypter` 的
/// `decrypt_to` 方法，確保零拷貝解密路徑正確運作。
#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::cipher::MessageDecrypter;
    use crate::msgs::message::InboundOpaqueMessageImmut;
    use crate::msgs::message::OutboundChunks;
    use alloc::format;

    /// 測試 ChaCha20-Poly1305 的 decrypt_to 基本功能
    ///
    /// 驗證：
    /// - 加密後的數據可以正確解密到輸出緩衝區
    /// - 解密後的 payload 內容正確
    /// - content type 正確恢復為 ApplicationData
    #[test]
    fn test_aead_chacha20_decrypt_to() {
        // 創建加密器和解密器使用相同的密鑰
        let key_bytes = [0x42u8; 32]; // ChaCha20 需要 32 字節密鑰
        let iv = Iv::new([0x01u8; 12]);

        // 使用 ChaCha20-Poly1305 - AeadMessageEncrypter 使用 LessSafeKey
        let enc_key = aead::LessSafeKey::new(
            aead::UnboundKey::new(&aead::CHACHA20_POLY1305, &key_bytes).unwrap(),
        );
        let dec_key = aead::LessSafeKey::new(
            aead::UnboundKey::new(&aead::CHACHA20_POLY1305, &key_bytes).unwrap(),
        );

        let mut encrypter = AeadMessageEncrypter {
            enc_key,
            iv: Iv::new([0x01u8; 12]),
        };
        let mut decrypter = AeadMessageDecrypter { dec_key, iv };

        // 加密測試數據
        let plaintext = b"Hello, zero-copy TLS 1.3!";
        let msg = OutboundPlainMessage {
            typ: ContentType::ApplicationData,
            version: ProtocolVersion::TLSv1_3,
            payload: OutboundChunks::Single(plaintext),
        };

        let encrypted = encrypter.encrypt(msg, 0).unwrap();

        // 使用 decrypt_to 解密
        let encrypted_payload = encrypted.payload.as_ref();
        let opaque = InboundOpaqueMessageImmut::new(
            encrypted.typ,
            ProtocolVersion::TLSv1_2, // TLS 1.3 在線路上顯示為 1.2
            encrypted_payload,
        );

        let mut out_buf = [0u8; 16384 + 256];
        let result = decrypter
            .decrypt_to(&opaque, 0, &mut out_buf)
            .unwrap();

        // 驗證解密結果
        assert_eq!(result.typ, ContentType::ApplicationData);
        assert_eq!(result.version, ProtocolVersion::TLSv1_3);
        assert_eq!(result.payload, plaintext);
    }

    /// 測試 AES-128-GCM 的 decrypt_to 基本功能
    #[test]
    fn test_gcm_aes128_decrypt_to() {
        let key_bytes = [0x42u8; 16]; // AES-128 需要 16 字節密鑰
        let iv = Iv::new([0x01u8; 12]);

        let enc_key = aead::TlsRecordSealingKey::new(
            &aead::AES_128_GCM,
            aead::TlsProtocolId::TLS13,
            &key_bytes,
        )
        .unwrap();

        let dec_key = aead::TlsRecordOpeningKey::new(
            &aead::AES_128_GCM,
            aead::TlsProtocolId::TLS13,
            &key_bytes,
        )
        .unwrap();

        let mut encrypter = GcmMessageEncrypter {
            enc_key,
            iv: Iv::new([0x01u8; 12]),
        };
        let mut decrypter = GcmMessageDecrypter { dec_key, iv };

        // 加密測試數據
        let plaintext = b"AES-GCM zero-copy test";
        let msg = OutboundPlainMessage {
            typ: ContentType::ApplicationData,
            version: ProtocolVersion::TLSv1_3,
            payload: OutboundChunks::Single(plaintext),
        };

        let encrypted = encrypter.encrypt(msg, 0).unwrap();

        // 使用 decrypt_to 解密
        let encrypted_payload = encrypted.payload.as_ref();
        let opaque = InboundOpaqueMessageImmut::new(
            encrypted.typ,
            ProtocolVersion::TLSv1_2,
            encrypted_payload,
        );

        let mut out_buf = [0u8; 16384 + 256];
        let result = decrypter
            .decrypt_to(&opaque, 0, &mut out_buf)
            .unwrap();

        assert_eq!(result.typ, ContentType::ApplicationData);
        assert_eq!(result.version, ProtocolVersion::TLSv1_3);
        assert_eq!(result.payload, plaintext);
    }

    /// 測試 AES-256-GCM 的 decrypt_to
    #[test]
    fn test_gcm_aes256_decrypt_to() {
        let key_bytes = [0x42u8; 32]; // AES-256 需要 32 字節密鑰
        let iv = Iv::new([0x01u8; 12]);

        let enc_key = aead::TlsRecordSealingKey::new(
            &aead::AES_256_GCM,
            aead::TlsProtocolId::TLS13,
            &key_bytes,
        )
        .unwrap();

        let dec_key = aead::TlsRecordOpeningKey::new(
            &aead::AES_256_GCM,
            aead::TlsProtocolId::TLS13,
            &key_bytes,
        )
        .unwrap();

        let mut encrypter = GcmMessageEncrypter {
            enc_key,
            iv: Iv::new([0x01u8; 12]),
        };
        let mut decrypter = GcmMessageDecrypter { dec_key, iv };

        let plaintext = b"AES-256-GCM zero-copy test";
        let msg = OutboundPlainMessage {
            typ: ContentType::ApplicationData,
            version: ProtocolVersion::TLSv1_3,
            payload: OutboundChunks::Single(plaintext),
        };

        let encrypted = encrypter.encrypt(msg, 0).unwrap();

        let encrypted_payload = encrypted.payload.as_ref();
        let opaque = InboundOpaqueMessageImmut::new(
            encrypted.typ,
            ProtocolVersion::TLSv1_2,
            encrypted_payload,
        );

        let mut out_buf = [0u8; 16384 + 256];
        let result = decrypter
            .decrypt_to(&opaque, 0, &mut out_buf)
            .unwrap();

        assert_eq!(result.typ, ContentType::ApplicationData);
        assert_eq!(result.payload, plaintext);
    }

    /// 測試 decrypt_to 與 decrypt 的結果一致性
    ///
    /// 這是關鍵的等價性測試，確保零拷貝路徑與原始路徑
    /// 產生完全相同的結果。
    #[test]
    fn test_decrypt_to_matches_decrypt() {
        let key_bytes = [0x42u8; 32];
        let iv = Iv::new([0x01u8; 12]);

        // 創建兩個相同的解密器 - 使用 LessSafeKey
        let dec_key1 = aead::LessSafeKey::new(
            aead::UnboundKey::new(&aead::CHACHA20_POLY1305, &key_bytes).unwrap(),
        );
        let dec_key2 = aead::LessSafeKey::new(
            aead::UnboundKey::new(&aead::CHACHA20_POLY1305, &key_bytes).unwrap(),
        );

        let mut decrypter1 = AeadMessageDecrypter {
            dec_key: dec_key1,
            iv: Iv::new([0x01u8; 12]),
        };
        let mut decrypter2 = AeadMessageDecrypter {
            dec_key: dec_key2,
            iv: Iv::new([0x01u8; 12]),
        };

        // 創建加密器 - 使用 LessSafeKey
        let enc_key = aead::LessSafeKey::new(
            aead::UnboundKey::new(&aead::CHACHA20_POLY1305, &key_bytes).unwrap(),
        );
        let mut encrypter = AeadMessageEncrypter { enc_key, iv };

        let plaintext = b"Consistency test between decrypt and decrypt_to";
        let msg = OutboundPlainMessage {
            typ: ContentType::ApplicationData,
            version: ProtocolVersion::TLSv1_3,
            payload: OutboundChunks::Single(plaintext),
        };

        let encrypted = encrypter.encrypt(msg, 0).unwrap();
        let encrypted_payload = encrypted.payload.as_ref();

        // 使用 decrypt（需要擁有權，需要可變引用）
        let mut payload_vec = encrypted_payload.to_vec();
        let opaque1 =
            InboundOpaqueMessage::new(encrypted.typ, ProtocolVersion::TLSv1_2, &mut payload_vec);
        let result1 = decrypter1.decrypt(opaque1, 0).unwrap();

        // 使用 decrypt_to（零拷貝）
        let opaque2 = InboundOpaqueMessageImmut::new(
            encrypted.typ,
            ProtocolVersion::TLSv1_2,
            encrypted_payload,
        );
        let mut out_buf = [0u8; 16384 + 256];
        let result2 = decrypter2
            .decrypt_to(&opaque2, 0, &mut out_buf)
            .unwrap();

        // 驗證兩者結果一致
        assert_eq!(result1.typ, result2.typ, "content type 應該一致");
        assert_eq!(result1.version, result2.version, "version 應該一致");
        assert_eq!(result1.payload, result2.payload, "payload 應該一致");
    }

    /// 測試 decrypt_to 的序列號遞增
    ///
    /// 驗證使用不同序列號加密的消息可以正確解密
    #[test]
    fn test_decrypt_to_sequence_numbers() {
        let key_bytes = [0x42u8; 32];
        let iv = Iv::new([0x01u8; 12]);

        let enc_key = aead::LessSafeKey::new(
            aead::UnboundKey::new(&aead::CHACHA20_POLY1305, &key_bytes).unwrap(),
        );
        let dec_key = aead::LessSafeKey::new(
            aead::UnboundKey::new(&aead::CHACHA20_POLY1305, &key_bytes).unwrap(),
        );

        let mut encrypter = AeadMessageEncrypter {
            enc_key,
            iv: Iv::new([0x01u8; 12]),
        };
        let mut decrypter = AeadMessageDecrypter { dec_key, iv };

        // 使用不同序列號加密多條消息
        for seq in 0..5u64 {
            let plaintext = format!("Message with seq {}", seq);
            let msg = OutboundPlainMessage {
                typ: ContentType::ApplicationData,
                version: ProtocolVersion::TLSv1_3,
                payload: OutboundChunks::Single(plaintext.as_bytes()),
            };

            let encrypted = encrypter.encrypt(msg, seq).unwrap();
            let encrypted_payload = encrypted.payload.as_ref();

            let opaque = InboundOpaqueMessageImmut::new(
                encrypted.typ,
                ProtocolVersion::TLSv1_2,
                encrypted_payload,
            );

            let mut out_buf = [0u8; 16384 + 256];
            let result = decrypter
                .decrypt_to(&opaque, seq, &mut out_buf)
                .unwrap();

            assert_eq!(result.payload, plaintext.as_bytes());
        }
    }

    /// 測試 decrypt_to 的錯誤處理 - 損壞的密文
    #[test]
    fn test_decrypt_to_corrupted_ciphertext() {
        let key_bytes = [0x42u8; 32];
        let iv = Iv::new([0x01u8; 12]);

        let enc_key = aead::LessSafeKey::new(
            aead::UnboundKey::new(&aead::CHACHA20_POLY1305, &key_bytes).unwrap(),
        );
        let dec_key = aead::LessSafeKey::new(
            aead::UnboundKey::new(&aead::CHACHA20_POLY1305, &key_bytes).unwrap(),
        );

        let mut encrypter = AeadMessageEncrypter {
            enc_key,
            iv: Iv::new([0x01u8; 12]),
        };
        let mut decrypter = AeadMessageDecrypter { dec_key, iv };

        let plaintext = b"Test message";
        let msg = OutboundPlainMessage {
            typ: ContentType::ApplicationData,
            version: ProtocolVersion::TLSv1_3,
            payload: OutboundChunks::Single(plaintext),
        };

        let encrypted = encrypter.encrypt(msg, 0).unwrap();
        let mut corrupted = encrypted.payload.as_ref().to_vec();
        corrupted[0] ^= 0xFF; // 修改第一個字節

        let opaque =
            InboundOpaqueMessageImmut::new(encrypted.typ, ProtocolVersion::TLSv1_2, &corrupted);

        let mut out_buf = [0u8; 16384 + 256];
        let result = decrypter.decrypt_to(&opaque, 0, &mut out_buf);

        assert!(result.is_err(), "損壞的密文應該導致解密失敗");
        assert!(matches!(result, Err(Error::DecryptError)));
    }

    /// 測試 decrypt_to 的錯誤處理 - 錯誤的序列號
    #[test]
    fn test_decrypt_to_wrong_sequence_number() {
        let key_bytes = [0x42u8; 32];
        let iv = Iv::new([0x01u8; 12]);

        let enc_key = aead::LessSafeKey::new(
            aead::UnboundKey::new(&aead::CHACHA20_POLY1305, &key_bytes).unwrap(),
        );
        let dec_key = aead::LessSafeKey::new(
            aead::UnboundKey::new(&aead::CHACHA20_POLY1305, &key_bytes).unwrap(),
        );

        let mut encrypter = AeadMessageEncrypter {
            enc_key,
            iv: Iv::new([0x01u8; 12]),
        };
        let mut decrypter = AeadMessageDecrypter { dec_key, iv };

        let plaintext = b"Test message";
        let msg = OutboundPlainMessage {
            typ: ContentType::ApplicationData,
            version: ProtocolVersion::TLSv1_3,
            payload: OutboundChunks::Single(plaintext),
        };

        // 使用序列號 0 加密
        let encrypted = encrypter.encrypt(msg, 0).unwrap();
        let encrypted_payload = encrypted.payload.as_ref();

        let opaque = InboundOpaqueMessageImmut::new(
            encrypted.typ,
            ProtocolVersion::TLSv1_2,
            encrypted_payload,
        );

        // 使用序列號 1 解密（錯誤）
        let mut out_buf = [0u8; 16384 + 256];
        let result = decrypter.decrypt_to(&opaque, 1, &mut out_buf);

        assert!(result.is_err(), "錯誤的序列號應該導致解密失敗");
    }

    /// 測試 Handshake content type 的 decrypt_to
    #[test]
    fn test_decrypt_to_handshake_content_type() {
        let key_bytes = [0x42u8; 32];
        let iv = Iv::new([0x01u8; 12]);

        let enc_key = aead::LessSafeKey::new(
            aead::UnboundKey::new(&aead::CHACHA20_POLY1305, &key_bytes).unwrap(),
        );
        let dec_key = aead::LessSafeKey::new(
            aead::UnboundKey::new(&aead::CHACHA20_POLY1305, &key_bytes).unwrap(),
        );

        let mut encrypter = AeadMessageEncrypter {
            enc_key,
            iv: Iv::new([0x01u8; 12]),
        };
        let mut decrypter = AeadMessageDecrypter { dec_key, iv };

        let plaintext = b"Handshake message content";
        let msg = OutboundPlainMessage {
            typ: ContentType::Handshake,
            version: ProtocolVersion::TLSv1_3,
            payload: OutboundChunks::Single(plaintext),
        };

        let encrypted = encrypter.encrypt(msg, 0).unwrap();
        let encrypted_payload = encrypted.payload.as_ref();

        let opaque = InboundOpaqueMessageImmut::new(
            encrypted.typ,
            ProtocolVersion::TLSv1_2,
            encrypted_payload,
        );

        let mut out_buf = [0u8; 16384 + 256];
        let result = decrypter
            .decrypt_to(&opaque, 0, &mut out_buf)
            .unwrap();

        // 驗證 content type 正確恢復為 Handshake
        assert_eq!(result.typ, ContentType::Handshake);
        assert_eq!(result.payload, plaintext);
    }
}
