use sha2::Digest as _;

/// Bytes a SHA-256 digest occupies.
pub const DIGEST_LEN: usize = 32;

/// The digest of one contiguous message.
#[must_use]
pub fn sha256(message: &[u8]) -> [u8; DIGEST_LEN] {
    sha2::Sha256::digest(message).into()
}

/// A digest computed over a message the caller supplies in pieces, for the
/// callers that never hold one contiguously — a frame walked chunk by chunk,
/// a document read a region at a time.
///
/// `finish` consumes the hasher, so a digest cannot be taken twice from one
/// state and a caller cannot keep updating a hasher it has already read.
///
/// `Clone` because a TLS transcript is hashed repeatedly while it is still
/// being appended to: the digest of everything so far is taken from a copy,
/// and the original keeps growing.
#[derive(Clone)]
pub struct Sha256(sha2::Sha256);

impl Sha256 {
    #[must_use]
    pub fn new() -> Self {
        Self(sha2::Sha256::new())
    }

    pub fn update(&mut self, chunk: &[u8]) {
        self.0.update(chunk);
    }

    #[must_use]
    pub fn finish(self) -> [u8; DIGEST_LEN] {
        self.0.finalize().into()
    }
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}
