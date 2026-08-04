use alloc::{boxed::Box, vec::Vec};

use lfw_crypto::{
    Entropy, ML_KEM_768_CIPHERTEXT_LEN, ML_KEM_768_ENCAPSULATION_KEY_LEN, MlKem768DecapsulationKey,
    MlKem768EncapsulationKey, X25519_LEN, X25519Secret,
};
use rustls::{
    Error, NamedGroup, PeerMisbehaved, ProtocolVersion,
    crypto::{ActiveKeyExchange, CompletedKeyExchange, SharedSecret, SupportedKxGroup},
    ffdhe_groups::FfdheGroup,
};

/// The one answer every malformed share gets. A peer learns that its share was
/// not usable and nothing about which half of the hybrid rejected it.
const INVALID_SHARE: Error = Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare);

/// The one key exchange the management channel offers: X25519 and ML-KEM-768,
/// both, with the secret being the concatenation of theirs.
///
/// Hybrid and not a choice between the two. The classical half is what holds
/// if the lattice assumption turns out weak; the post-quantum half is what
/// holds against an adversary recording the channel today to decrypt when a
/// quantum computer exists — and this channel carries a customer's network
/// history, which is exactly the traffic worth recording for later.
pub struct X25519MlKem768 {
    entropy: &'static dyn Entropy,
}

impl X25519MlKem768 {
    #[must_use]
    pub const fn new(entropy: &'static dyn Entropy) -> Self {
        Self { entropy }
    }
}

impl core::fmt::Debug for X25519MlKem768 {
    /// Names the group and nothing else: the only field is the node's
    /// randomness, which has no rendering.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("X25519MLKEM768")
    }
}

/// The layout the draft fixes for this group, stated once.
///
/// The post-quantum share comes first here and second in the sibling group
/// over P-256, which is a wart of the specification rather than a choice — so
/// it is written down as a constant rather than inferred at each use.
const CLASSICAL_LEN: usize = X25519_LEN;
const POST_QUANTUM_CLIENT_LEN: usize = ML_KEM_768_ENCAPSULATION_KEY_LEN;
const POST_QUANTUM_SERVER_LEN: usize = ML_KEM_768_CIPHERTEXT_LEN;

impl SupportedKxGroup for X25519MlKem768 {
    /// The client's half: an ML-KEM encapsulation key and an X25519 public
    /// value, in that order.
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let classical = X25519Secret::generate(self.entropy);
        let post_quantum = MlKem768DecapsulationKey::generate(self.entropy);
        let mut share = Vec::with_capacity(POST_QUANTUM_CLIENT_LEN + CLASSICAL_LEN);
        share.extend_from_slice(&post_quantum.encapsulation_key());
        share.extend_from_slice(&classical.public_key());
        Ok(Box::new(Active {
            classical,
            post_quantum,
            share,
        }))
    }

    /// The server's half, which cannot be split into a start and a complete:
    /// the ciphertext it publishes is a function of the client's
    /// encapsulation key, so there is nothing to send before the client's
    /// share has arrived.
    fn start_and_complete(&self, client_share: &[u8]) -> Result<CompletedKeyExchange, Error> {
        let (encapsulation_key, peer_classical) = split(client_share, POST_QUANTUM_CLIENT_LEN)?;
        let peer =
            MlKem768EncapsulationKey::from_bytes(encapsulation_key).map_err(|_| INVALID_SHARE)?;
        let (ciphertext, post_quantum_secret) =
            peer.encapsulate(self.entropy).map_err(|_| INVALID_SHARE)?;
        let classical = X25519Secret::generate(self.entropy);
        let classical_secret = classical
            .agree(&fixed(peer_classical)?)
            .map_err(|_| INVALID_SHARE)?;

        let mut share = Vec::with_capacity(POST_QUANTUM_SERVER_LEN + CLASSICAL_LEN);
        share.extend_from_slice(&ciphertext);
        share.extend_from_slice(&classical.public_key());
        let mut secret = Vec::with_capacity(post_quantum_secret.len() + classical_secret.len());
        secret.extend_from_slice(&post_quantum_secret);
        secret.extend_from_slice(&classical_secret);
        Ok(CompletedKeyExchange {
            group: NamedGroup::X25519MLKEM768,
            pub_key: share,
            secret: SharedSecret::from(&secret[..]),
        })
    }

    /// Not a finite-field group, and the default implementation of this
    /// answer walks a table of every named group to say so.
    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        None
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::X25519MLKEM768
    }

    /// TLS 1.2 has no key schedule this group's secret could feed, and this
    /// build negotiates no version but 1.3 in any case.
    fn usable_for_version(&self, version: ProtocolVersion) -> bool {
        version == ProtocolVersion::TLSv1_3
    }
}

/// The client's exchange between publishing its share and receiving the
/// server's.
struct Active {
    classical: X25519Secret,
    post_quantum: MlKem768DecapsulationKey,
    share: Vec<u8>,
}

impl ActiveKeyExchange for Active {
    fn complete(self: Box<Self>, peer_share: &[u8]) -> Result<SharedSecret, Error> {
        let (ciphertext, peer_classical) = split(peer_share, POST_QUANTUM_SERVER_LEN)?;
        let post_quantum_secret = self
            .post_quantum
            .decapsulate(ciphertext)
            .map_err(|_| INVALID_SHARE)?;
        let classical_secret = self
            .classical
            .agree(&fixed(peer_classical)?)
            .map_err(|_| INVALID_SHARE)?;
        let mut secret = Vec::with_capacity(post_quantum_secret.len() + classical_secret.len());
        secret.extend_from_slice(&post_quantum_secret);
        secret.extend_from_slice(&classical_secret);
        Ok(SharedSecret::from(&secret[..]))
    }

    fn pub_key(&self) -> &[u8] {
        &self.share
    }

    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        None
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::X25519MLKEM768
    }
}

/// A share's two halves, refused unless the whole is exactly the two lengths
/// together. A share of any other length is a peer's, so it is a typed refusal
/// and not a slice.
fn split(share: &[u8], post_quantum_len: usize) -> Result<(&[u8], &[u8]), Error> {
    if share.len() != post_quantum_len.saturating_add(CLASSICAL_LEN) {
        return Err(INVALID_SHARE);
    }
    share
        .split_at_checked(post_quantum_len)
        .ok_or(INVALID_SHARE)
}

/// The classical half at its own width. Unreachable as a refusal after
/// [`split`], which is what fixed the length — and answered rather than
/// asserted, because the value on this path is a peer's.
fn fixed(classical: &[u8]) -> Result<[u8; X25519_LEN], Error> {
    classical.try_into().map_err(|_| INVALID_SHARE)
}
