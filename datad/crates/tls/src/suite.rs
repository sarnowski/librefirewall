use alloc::boxed::Box;

use lfw_crypto::{ChaCha20Poly1305, DIGEST_LEN, KEY_LEN, MAC_LEN, NONCE_LEN, TAG_LEN};
use rustls::{
    CipherSuite, ConnectionTrafficSecrets, SupportedCipherSuite, Tls13CipherSuite,
    crypto::{
        CipherSuiteCommon,
        cipher::{
            AeadKey, InboundOpaqueMessage, InboundPlainMessage, Iv, MessageDecrypter,
            MessageEncrypter, Nonce, OutboundOpaqueMessage, OutboundPlainMessage, PrefixedPayload,
            Tls13AeadAlgorithm, UnsupportedOperationError, make_tls13_aad,
        },
        hash, hmac,
        tls13::HkdfUsingHmac,
    },
    {ContentType, Error, ProtocolVersion},
};

/// The one cipher suite the management channel negotiates.
///
/// One and not a list, deliberately: both ends of this connection are ours, so
/// there is nothing to negotiate down to and every additional suite is another
/// code path an adversary can steer into. ChaCha20-Poly1305 rather than
/// AES-GCM because this appliance's baseline guarantees AES-NI but the peer's
/// does not, and a stream cipher designed for scalar execution is the one that
/// is fast everywhere.
pub static TLS13_CHACHA20_POLY1305_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&Tls13CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
            // The construction's confidentiality bound is not reached by any
            // record count a 64-bit sequence number can express, which is what
            // the specification's own analysis says of it.
            confidentiality_limit: u64::MAX,
            hash_provider: &Sha256,
        },
        hkdf_provider: &HkdfUsingHmac(&HmacSha256),
        aead_alg: &ChaCha20Poly1305Aead,
        // QUIC is not spoken here and a key builder for it would be a second
        // key schedule to prove.
        quic: None,
    });

/// SHA-256 in the shape the TLS library takes a hash in.
#[derive(Debug)]
struct Sha256;

impl hash::Hash for Sha256 {
    fn start(&self) -> Box<dyn hash::Context> {
        Box::new(Sha256Context(lfw_crypto::Sha256::new()))
    }

    fn hash(&self, data: &[u8]) -> hash::Output {
        hash::Output::new(&lfw_crypto::sha256(data))
    }

    fn output_len(&self) -> usize {
        DIGEST_LEN
    }

    fn algorithm(&self) -> hash::HashAlgorithm {
        hash::HashAlgorithm::SHA256
    }
}

/// A transcript hash in progress.
///
/// It is cloned rather than forked in place because a TLS 1.3 handshake takes
/// the digest of the transcript so far several times while still appending to
/// it — so the state has to be duplicable, which is what `fork` means here.
struct Sha256Context(lfw_crypto::Sha256);

impl hash::Context for Sha256Context {
    fn fork_finish(&self) -> hash::Output {
        hash::Output::new(&self.0.clone().finish())
    }

    fn fork(&self) -> Box<dyn hash::Context> {
        Box::new(Self(self.0.clone()))
    }

    fn finish(self: Box<Self>) -> hash::Output {
        hash::Output::new(&self.0.finish())
    }

    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }
}

/// HMAC-SHA-256, which is also the whole of the key schedule: the library
/// builds HKDF out of an HMAC rather than taking one, so this is the only
/// thing the schedule needs from here.
#[derive(Debug)]
struct HmacSha256;

impl hmac::Hmac for HmacSha256 {
    fn with_key(&self, key: &[u8]) -> Box<dyn hmac::Key> {
        Box::new(HmacSha256Key(lfw_crypto::HmacKey::new(key)))
    }

    fn hash_output_len(&self) -> usize {
        MAC_LEN
    }
}

struct HmacSha256Key(lfw_crypto::HmacKey);

impl hmac::Key for HmacSha256Key {
    fn sign_concat(&self, first: &[u8], middle: &[&[u8]], last: &[u8]) -> hmac::Tag {
        let mut mac = self.0.start();
        mac.update(first);
        for chunk in middle {
            mac.update(chunk);
        }
        mac.update(last);
        hmac::Tag::new(&mac.finish())
    }

    fn tag_len(&self) -> usize {
        MAC_LEN
    }
}

/// The record-layer AEAD.
#[derive(Debug)]
struct ChaCha20Poly1305Aead;

impl Tls13AeadAlgorithm for ChaCha20Poly1305Aead {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        Box::new(Encrypter {
            cipher: cipher(&key),
            iv,
        })
    }

    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        Box::new(Decrypter {
            cipher: cipher(&key),
            iv,
        })
    }

    fn key_len(&self) -> usize {
        KEY_LEN
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok(ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv })
    }
}

/// The library sizes the key from [`Tls13AeadAlgorithm::key_len`] and hands
/// back exactly that many bytes, so the fallback below is unreachable — and it
/// is a zero key rather than a panic because a panicking cipher construction
/// on a path a peer drives is the shape this codebase does not carry. A zero
/// key produces records the peer cannot read, which fails the connection
/// visibly.
fn cipher(key: &AeadKey) -> ChaCha20Poly1305 {
    let mut bytes = [0_u8; KEY_LEN];
    if key.as_ref().len() == KEY_LEN {
        bytes.copy_from_slice(key.as_ref());
    }
    ChaCha20Poly1305::new(&bytes)
}

struct Encrypter {
    cipher: ChaCha20Poly1305,
    iv: Iv,
}

impl MessageEncrypter for Encrypter {
    fn encrypt(
        &mut self,
        message: OutboundPlainMessage<'_>,
        sequence: u64,
    ) -> Result<OutboundOpaqueMessage, Error> {
        let total = self.encrypted_payload_len(message.payload.len());
        let mut payload = PrefixedPayload::with_capacity(total);
        payload.extend_from_chunks(&message.payload);
        // TLS 1.3 puts the real content type at the end of the plaintext and
        // sends every record as application data; the byte appended here is
        // that type and is part of what the tag covers.
        payload.extend_from_slice(&message.typ.to_array());
        let nonce = Nonce::new(&self.iv, sequence).0;
        let aad = make_tls13_aad(total);
        let tag = self
            .cipher
            .seal(&nonce, &aad, payload.as_mut())
            .map_err(|_| Error::EncryptError)?;
        payload.extend_from_slice(&tag);
        Ok(OutboundOpaqueMessage::new(
            ContentType::ApplicationData,
            // Every TLS 1.3 record carries the 1.2 version on the wire, which
            // is what middleboxes were taught to expect before 1.3 existed.
            ProtocolVersion::TLSv1_2,
            payload,
        ))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len.saturating_add(1).saturating_add(TAG_LEN)
    }
}

struct Decrypter {
    cipher: ChaCha20Poly1305,
    iv: Iv,
}

impl MessageDecrypter for Decrypter {
    fn decrypt<'a>(
        &mut self,
        mut message: InboundOpaqueMessage<'a>,
        sequence: u64,
    ) -> Result<InboundPlainMessage<'a>, Error> {
        let payload = &mut message.payload;
        let total = payload.len();
        let Some(body) = total.checked_sub(TAG_LEN) else {
            return Err(Error::DecryptError);
        };
        let mut tag = [0_u8; TAG_LEN];
        let Some(carried) = payload.get(body..total) else {
            return Err(Error::DecryptError);
        };
        tag.copy_from_slice(carried);
        let nonce = Nonce::new(&self.iv, sequence).0;
        let aad = make_tls13_aad(total);
        let Some(ciphertext) = payload.get_mut(..body) else {
            return Err(Error::DecryptError);
        };
        self.cipher
            .open(&nonce, &aad, ciphertext, &tag)
            .map_err(|_| Error::DecryptError)?;
        payload.truncate(body);
        message.into_tls13_unpadded_message()
    }
}

/// The nonce this record layer builds is the AEAD's own width, which the
/// library's `Nonce` type and this crate's constant have to agree on for the
/// call above to be the right one.
const _: () = assert!(NONCE_LEN == 12);
