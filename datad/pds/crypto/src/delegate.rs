//! Signing under a key this domain does not hold: the requesting end of the
//! delegation, in the shape the TLS stack resolves a certificate's key to.
//!
//! This is the second implementation of `lfw_tls::SignOperation`, and the whole
//! reason that trait exists. The first holds a `P256SecretKey` beside its caller.
//! This one holds no key at all — it writes a request into a shared region, wakes
//! the domain that owns the medium the key is written on, and copies back the
//! bytes that domain published. Nothing above it changes: the TLS stack asks for
//! something that signs and cannot tell where the scalar is, and the provider's
//! `KeyProvider` already refuses to load one from an encoding, which is what
//! keeps this a substitution rather than a rewrite.
//!
//! Four things are asked over that channel and only one of them is the trait's:
//! a signature, the public point and name the holder signs under, **the
//! appliance's own certificate over that point**, and **the trust anchor a
//! management plane delivered**. The certificate is fetched rather than issued
//! here because the holder is the identity domain — it minted that certificate
//! and made it durable — and a certificate written in this domain would be a
//! second statement over one key, with no domain able to say which one a peer was
//! shown. It is a public artifact either way: what crosses is what every peer of
//! this appliance is handed.
//!
//! The anchor is fetched for the sharper version of the same reason. It arrived
//! inside an onboarding package, the holder judged that package and made the
//! anchor durable, and it is one field of the very record the other three answers
//! come out of. **This is the domain that will validate a management server's
//! certificate**, so the anchor has to reach here — and a copy kept anywhere else
//! would be a second answer to the question of whom this appliance trusts. It is
//! public too: the peer this appliance dials issues under it and therefore holds
//! it already.
//!
//! It lives in this protection domain and not in `wire` for one reason: this is
//! the only place that sees both the TLS trait and the channel ABI, and `wire`
//! carries zero `unsafe` — a count worth keeping.
//!
//! # Adversary
//!
//! The **byzantine neighbour protection domain** that answers, one indirection
//! behind it a **block device** and a **physical attacker who wrote the medium**:
//! what comes back is what the key holder said, which is what its own medium
//! said. Nothing here believes any of it. `wire::signing` refuses a reply that is
//! not this request's, one whose status or operation is outside its set, one
//! answering a different question, and one claiming more bytes than the region
//! holds; what survives that is a byte string handed to a verifier or to the TLS
//! library, both of which judge it against a public key.
//!
//! A holder that never answers is the other case, and it is bounded rather than
//! trusted: [`POLL_BUDGET`] reads and then a refusal. That is what keeps a
//! handshake deep inside the protocol from becoming a domain that never returns.
//!
//! # Why a spin and not a block
//!
//! `sign` is called synchronously from inside the TLS library, at the point a
//! server produces its `CertificateVerify`. There is no continuation to hand a
//! notification to, and no way to return "not yet" to a caller that has none. So
//! the request is issued, the holder is woken, and the reply is read.
//!
//! **What makes that terminate on the first read is a scheduling fact, and it is
//! the reason the store domain sits above this one.** A notification to a
//! higher-priority domain blocked in the event loop preempts immediately: the
//! holder runs, answers, and blocks again before this domain's next instruction.
//! The budget below is therefore not the expected path — it is what happens when
//! the holder is compromised, faulted, or never established an identity to sign
//! with, and it turns each of those into a refusal rather than a hang.

use core::{
    cell::UnsafeCell,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
};

use lfw_tls::{SignOperation as TlsSignOperation, SignRefused};
use sel4_microkit::Channel;
use wire::{
    DEVICE_ID_LEN, DeviceIdentity, MAX_CERTIFICATE_LEN, MAX_SIGNATURE_LEN, PUBLIC_KEY_LEN,
    PendingSignature, SignAnswerBuffer, SignOperation, SignPoll, SignReply, SignRequest,
    SignRequester, StagedUpload,
};

/// Reads of the reply region one request is given before it is refused.
///
/// A first-party constant and a liveness bound, not a protocol one. A holder
/// keeping to the protocol has answered before the first read — see this module's
/// header on why — so any value above one is slack for a system under load and
/// none of it is on the expected path. 1024 rather than a handful because the
/// cost of being wrong in the two directions is not symmetric: too many reads
/// spends microseconds in a domain that is about to fail its handshake anyway,
/// and too few turns a scheduling hiccup into a management channel that refuses
/// connections.
const POLL_BUDGET: u32 = 1024;

// The two crates' names for the longest signature this profile produces, held
// equal where both are visible. `wire::signing` declines to depend on the
// cryptography for an integer and names the protection domain that sees both;
// this is that domain, on the store side and on this one.
const _: () = assert!(MAX_SIGNATURE_LEN == lfw_crypto::P256_MAX_SIGNATURE_LEN);
const _: () = assert!(PUBLIC_KEY_LEN == lfw_crypto::P256_PUBLIC_LEN);

/// What the holder answered a `Certificate` request with: the appliance's own
/// certificate over the key it signs under, and how many bytes of the array are
/// certificate.
///
/// Owned rather than a borrow of the region, on [`Answer`]'s terms — what a caller
/// holds must not be a view into memory a peer may still be writing. **Public
/// throughout**: this is the artifact the appliance shows every party it talks to,
/// so nothing about holding it is a secret to keep, and there is no `Debug`ging of
/// it only because 768 bytes of DER on a record is noise and not because it is
/// sensitive.
#[derive(Clone, Copy)]
pub struct HeldCertificate {
    bytes: [u8; MAX_CERTIFICATE_LEN],
    len: usize,
}

impl HeldCertificate {
    /// The certificate, bounded by what the holder published rather than by the
    /// array behind it.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.get(..self.len).unwrap_or(&[])
    }
}

/// What the holder answered an `Anchor` request with: the trust anchor a
/// management plane delivered, and how many bytes of the array are anchor.
///
/// Owned rather than a borrow of the region, on [`HeldCertificate`]'s terms
/// exactly, and its own type rather than a second use of that one because the two
/// are statements about different keys — one binds this appliance's key, the
/// other is the authority that will sign a peer's. A single type would let a
/// caller hand the wrong one to a verifier and be told only that validation
/// failed.
///
/// **Public throughout**, and for a reason of its own beyond the certificate's:
/// this is the authority the party at the other end of the channel issues under,
/// so it holds these bytes already.
#[derive(Clone, Copy)]
pub struct HeldAnchor {
    bytes: [u8; MAX_CERTIFICATE_LEN],
    len: usize,
}

impl HeldAnchor {
    /// The anchor, bounded by what the holder published rather than by the array
    /// behind it. Never empty: a holder with none refuses by name, so a value of
    /// this type is one somebody really delivered.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.get(..self.len).unwrap_or(&[])
    }
}

/// What the holder answered a `PublicKey` request with, and what it has done
/// since it started.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeldKey {
    /// The uncompressed SEC1 point the holder signs under. A public value, and
    /// the only thing a certificate needs from the other domain.
    pub public_key: [u8; PUBLIC_KEY_LEN],
    /// The appliance's 128-bit name, as the number the console renders.
    pub device: u128,
    /// Whether the record that key came out of says this appliance already has
    /// an owner.
    ///
    /// It arrives with the key rather than being asked for separately because it
    /// is a fact about the same record, read on the same boot by the same
    /// domain — and because what it decides is whether this domain serves
    /// onboarding at all, which has to be settled before a peer connects.
    pub owned: bool,
}

/// Why a request to the key holder produced nothing usable.
///
/// One variant per thing an operator would look at differently, and no variant
/// carrying a byte of the reply: a cause token for a remote domain's internals is
/// as far as this goes, because the caller above is on a path that faces the
/// network.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DelegationError {
    /// The budget ran out with no reply carrying this request's sequence. A
    /// holder that is not running, not scheduled, or answering something else.
    Unanswered,
    /// The holder answered and produced nothing, saying why.
    Refused,
    /// The holder answered and the reply could not be believed.
    Faulted,
}

impl DelegationError {
    /// The console cause token for this refusal.
    #[must_use]
    pub const fn cause(self) -> &'static str {
        match self {
            Self::Unanswered => "delegated-key-unanswered",
            Self::Refused => "delegated-key-refused",
            Self::Faulted => "delegated-reply-faulted",
        }
    }
}

/// The asking end of the delegation, shared the way the TLS library needs a
/// signing capability shared.
///
/// `Sync` is a requirement of the library rather than a property of this domain,
/// and the guarantor is the flag below rather than the execution model — the same
/// arrangement, for the same reason, that `lfw_crypto::NodeEntropy` records: an
/// appliance whose soundness argument was "there is only one thread" would be one
/// edit away from being wrong.
pub struct Delegated {
    /// Held rather than borrowed, because the trait hands out a shared reference
    /// and issuing a request advances the requester's private sequence.
    requester: UnsafeCell<SignRequester<'static>>,
    /// What makes the sharing sound rather than merely single-threaded.
    taken: AtomicBool,
    /// The channel the holder is woken on. This domain holds the send capability
    /// and the holder holds none back: it answers by publishing, and this domain
    /// reads rather than waits.
    holder: Channel,
    /// The holder's own signature tally, as of the last reply that carried one.
    /// Read back so a record can say the delegation is working without a
    /// signature reaching a surface.
    ///
    /// The one thing worth carrying across calls. A count of replies this side
    /// refused is deliberately *not* here: every one of them already ends the
    /// exchange with a typed [`DelegationError`] that reaches the console as its
    /// own cause token, so a tally beside it would be a second surface for a fact
    /// the first already carries — and nothing would read it.
    signatures: AtomicU64,
}

impl Delegated {
    /// Take the asking side of the channel — once per domain; a second would
    /// restart at sequence zero and reuse numbers the first has outstanding
    /// (`wire::SignRequest::requester`).
    #[must_use]
    pub const fn attach(
        request: &'static SignRequest,
        reply: &'static SignReply,
        holder: Channel,
    ) -> Self {
        Self {
            requester: UnsafeCell::new(request.requester(reply)),
            taken: AtomicBool::new(false),
            holder,
            signatures: AtomicU64::new(0),
        }
    }

    /// Ask the holder which key it holds.
    ///
    /// # Errors
    /// [`DelegationError`], naming which way the exchange failed.
    pub fn held_key(&self) -> Result<HeldKey, DelegationError> {
        match self.exchange(Ask::Message(SignOperation::PublicKey, &[]), None)? {
            Answer::Identity(DeviceIdentity {
                public_key,
                device_id,
                owned,
            }) => Ok(HeldKey {
                public_key,
                device: device_word(device_id),
                owned,
            }),
            // The channel refuses a reply answering a different operation before
            // it reaches here, so these arms are unreachable. Answered as a fault
            // rather than asserted: nothing on a path the TLS library calls into
            // may panic.
            Answer::Signature { .. }
            | Answer::Certificate { .. }
            | Answer::Anchor { .. }
            | Answer::Installed => Err(DelegationError::Faulted),
        }
    }

    /// Ask the holder to install the archive staged in the region this domain
    /// wrote.
    ///
    /// It takes the token the cursor minted, so the length the request states is
    /// the length that was really written. That is a convenience of this side and
    /// not a defence: the holder ranges the stated length against its own region
    /// and re-reads every rule of the package, because the domain that writes the
    /// medium is the one that has to have read what it writes.
    ///
    /// A refusal comes back as [`DelegationError::Refused`] and carries nothing.
    /// **Which** rule refused it is on the holder's own console, in the package
    /// contract's vocabulary and beside the numbers that place it — a word here
    /// spelling the same catalogue would be a second copy of it crossing a
    /// region.
    ///
    /// # Errors
    /// [`DelegationError`], naming which way the exchange failed.
    pub fn install(&self, staged: StagedUpload) -> Result<(), DelegationError> {
        match self.exchange(Ask::Install(staged), None)? {
            Answer::Installed => Ok(()),
            // Unreachable for [`Self::held_key`]'s reason, and a fault for it.
            Answer::Signature { .. }
            | Answer::Identity(_)
            | Answer::Certificate { .. }
            | Answer::Anchor { .. } => Err(DelegationError::Faulted),
        }
    }

    /// Ask the holder for the appliance's certificate over the key it holds.
    ///
    /// The certificate is fetched rather than written here because the holder is
    /// the identity domain: it minted this certificate, made it durable, and is
    /// the only domain that can say what a later boot will present. A certificate
    /// this domain issued for itself would be a second statement over one key.
    ///
    /// Nothing here judges the bytes. What comes back is a byte string the holder
    /// chose, bounded by the region; whether it is a certificate over the key the
    /// same channel named is a question for the caller, which has that key.
    ///
    /// # Errors
    /// [`DelegationError`], naming which way the exchange failed.
    pub fn held_certificate(&self) -> Result<HeldCertificate, DelegationError> {
        // The destination is this frame's, handed down rather than returned up:
        // [`Answer`] says why.
        let mut bytes = [0_u8; MAX_CERTIFICATE_LEN];
        match self.exchange(
            Ask::Message(SignOperation::Certificate, &[]),
            Some(&mut bytes),
        )? {
            Answer::Certificate { len } => Ok(HeldCertificate { bytes, len }),
            // Unreachable for [`Self::held_key`]'s reason, and a fault for it.
            Answer::Signature { .. }
            | Answer::Identity(_)
            | Answer::Anchor { .. }
            | Answer::Installed => Err(DelegationError::Faulted),
        }
    }

    /// Ask the holder for the trust anchor a management plane delivered.
    ///
    /// The anchor is fetched rather than kept here because the holder is the
    /// domain that took delivery of it: it read the package that carried it,
    /// judged it, and made it durable. A copy in this domain would be a second
    /// answer to whom this appliance trusts, and a session validated against the
    /// stale one would be a session no domain could account for.
    ///
    /// Nothing here judges the bytes, on [`Self::held_certificate`]'s terms. What
    /// comes back is a byte string the holder chose, bounded by the region;
    /// whether it is a certificate at all is a question for the TLS stack that
    /// will build a verifier out of it, which is where a second X.509 reader in
    /// this domain would otherwise have to go.
    ///
    /// **A holder with no anchor is a refusal and not an empty answer.** An
    /// appliance nobody has taken has none, so the caller must be able to tell
    /// that from a holder that answered badly — which is why the channel spells
    /// it [`wire::SignRefusal::NoAnchor`] and why nothing here turns a refusal
    /// into zero bytes.
    ///
    /// # Errors
    /// [`DelegationError`], naming which way the exchange failed.
    pub fn held_anchor(&self) -> Result<HeldAnchor, DelegationError> {
        // The destination is this frame's, handed down rather than returned up,
        // on the certificate's terms: [`Answer`] says why.
        let mut bytes = [0_u8; MAX_CERTIFICATE_LEN];
        match self.exchange(Ask::Message(SignOperation::Anchor, &[]), Some(&mut bytes))? {
            Answer::Anchor { len } => Ok(HeldAnchor { bytes, len }),
            // Unreachable for [`Self::held_key`]'s reason, and a fault for it.
            Answer::Signature { .. }
            | Answer::Identity(_)
            | Answer::Certificate { .. }
            | Answer::Installed => Err(DelegationError::Faulted),
        }
    }

    /// The holder's signature tally as of the last reply that carried one.
    ///
    /// The *holder's* number and not a count of calls made here, which is the
    /// point: a number this domain incremented itself would say only that it
    /// asked.
    #[must_use]
    pub fn signatures(&self) -> u64 {
        self.signatures.load(Ordering::Relaxed)
    }

    /// Issue one request, wake the holder, and read the reply.
    ///
    /// The flag is held across the whole exchange rather than around each half:
    /// the protocol admits one outstanding request, so two callers interleaving a
    /// request and a poll would have each claiming the other's reply.
    fn exchange(
        &self,
        ask: Ask<'_>,
        into: Option<&mut [u8; MAX_CERTIFICATE_LEN]>,
    ) -> Result<Answer, DelegationError> {
        while self
            .taken
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        let outcome = self.issue(ask, into);
        self.taken.store(false, Ordering::Release);
        outcome
    }

    /// The exchange itself, with the flag held.
    /// `into` is the caller's destination for whichever of the two
    /// certificate-shaped answers it asked for. One parameter for both, because
    /// the exchange admits one request at a time and the answering arm knows
    /// which question it is: two would be two ways to pass the same buffer and a
    /// third state where neither was supplied.
    fn issue(
        &self,
        ask: Ask<'_>,
        mut into: Option<&mut [u8; MAX_CERTIFICATE_LEN]>,
    ) -> Result<Answer, DelegationError> {
        // SAFETY: the flag is held by the caller, so this is the only live
        // reference to the requester for the duration of the call, and the
        // reference does not escape this function.
        let requester = unsafe { &mut *self.requester.get() };
        let mut pending: PendingSignature = match ask {
            Ask::Message(operation, message) => requester.request(operation, message),
            // The archive is not in this pair of regions at all: the request
            // states how many bytes of the staging region hold it, and the
            // sequence's own release store is what makes those bytes visible to
            // the holder before the demand that names them is.
            Ask::Install(staged) => requester.install(staged),
        };
        // After the request is published and not before: the notification is what
        // makes the holder look, and a signal ahead of the sequence would be a
        // wakeup for a request that is not there yet.
        self.holder.notify();
        // Zeroed once and reborrowed per read rather than built per read: the
        // reply's borrow of it still ends with the iteration that took it, and the
        // widest answer this channel carries is a certificate — so a buffer rebuilt
        // inside the loop would zero it again on every read of the budget, in
        // exactly the byzantine case the budget exists for. What leaves this
        // function is a copy either way, which is what keeps the shared region out
        // of every caller above.
        let mut window = SignAnswerBuffer::zero();
        for _ in 0..POLL_BUDGET {
            match requester.poll(pending, &mut window) {
                SignPoll::Outstanding(outstanding) => {
                    pending = outstanding;
                    core::hint::spin_loop();
                }
                SignPoll::Signed { signature, signed } => {
                    self.signatures.store(signed, Ordering::Relaxed);
                    let mut bytes = [0_u8; MAX_SIGNATURE_LEN];
                    let mut len = 0_usize;
                    for (slot, byte) in bytes.iter_mut().zip(signature) {
                        *slot = *byte;
                        len += 1;
                    }
                    return Ok(Answer::Signature { bytes, len });
                }
                SignPoll::Identity(identity) => return Ok(Answer::Identity(identity)),
                SignPoll::Certificate {
                    certificate: published,
                } => {
                    // Into the caller's destination where there is one. `zip` walks
                    // the shorter of the two and the ABI has already bounded the
                    // slice by the region, so the two lengths agree and no index is
                    // taken.
                    if let Some(destination) = into.as_mut() {
                        for (slot, byte) in destination.iter_mut().zip(published) {
                            *slot = *byte;
                        }
                    }
                    return Ok(Answer::Certificate {
                        len: published.len(),
                    });
                }
                SignPoll::Anchor { anchor } => {
                    // Into the caller's destination on the certificate's terms:
                    // the two answers share this one parameter because they are
                    // the same shape and only one is ever outstanding, the
                    // exchange admitting one request at a time.
                    if let Some(destination) = into.as_mut() {
                        for (slot, byte) in destination.iter_mut().zip(anchor) {
                            *slot = *byte;
                        }
                    }
                    return Ok(Answer::Anchor { len: anchor.len() });
                }
                SignPoll::Refused(_) => return Err(DelegationError::Refused),
                SignPoll::Installed => return Ok(Answer::Installed),
                SignPoll::Faulted(_) => return Err(DelegationError::Faulted),
            }
        }
        // The handle is dropped rather than kept, which frees the one slot: a
        // reply landing afterwards answers a sequence no request is held against,
        // and `wire::signing` reads that as no answer at all.
        Err(DelegationError::Unanswered)
    }
}

// SAFETY: `Sync` requires that concurrent shared access be sound. The guarantor
// is `taken` rather than the execution model: `exchange` acquires it before it
// touches the requester and releases it after, so at most one caller holds the
// `&mut` at a time whatever the caller count. A Microkit protection domain runs
// one thread and so never contends, but the claim does not rest on that. The
// other two fields are an atomic and a capability index, both sound to share on
// their own.
unsafe impl Sync for Delegated {}

/// What one exchange came back with: the three shapes a reply can be, already held
/// to the operation that was asked for by `wire::signing`.
///
/// Owned rather than a borrow of the region, which is what lets the poll loop
/// above declare its window per iteration — and what means no caller here holds a
/// view into a region a peer may still be writing.
///
/// **The two certificate-shaped answers are the exception and carry only their
/// length.** Each is ten times the size of everything else this channel moves, so
/// a variant holding one would make every exchange return a certificate's worth
/// of stack — including the signature exchange that runs inside a handshake,
/// which is the one path here that is not a once-per-boot call. The caller that
/// asks says where the bytes go instead, and only that caller carries the buffer.
enum Answer {
    Signature {
        bytes: [u8; MAX_SIGNATURE_LEN],
        len: usize,
    },
    Identity(DeviceIdentity),
    Certificate {
        len: usize,
    },
    /// The trust anchor a management plane delivered, carrying only its length
    /// for the certificate's reason and into the same caller-supplied
    /// destination.
    Anchor {
        len: usize,
    },
    /// The package staged in the region was installed. It carries nothing, which
    /// is the whole shape of the answer: the facts about what was installed reach
    /// an operator on the holder's console, where they were decided and made
    /// durable.
    Installed,
}

/// What one exchange asks for.
///
/// Its own value rather than an operation and a message, because the fourth
/// operation's subject is not a message at all: an install names bytes in a
/// region this pair of regions cannot see, and a call taking `(operation,
/// message)` would have to be handed an empty slice and a length carried
/// alongside — which is exactly the pairing `StagedUpload` exists to prevent.
enum Ask<'a> {
    Message(SignOperation, &'a [u8]),
    Install(StagedUpload),
}

impl TlsSignOperation for Delegated {
    /// Sign `message` in the domain that holds the key, and copy the DER encoding
    /// back.
    ///
    /// Every failure is the trait's single unit error, which is the right shape
    /// here for the reason the trait states: the handshake fails either way, and a
    /// richer error would be a description of another domain's internals arriving
    /// on a path that faces the network. What an operator gets instead is the
    /// tally and the fault count this type exposes, on this domain's own records.
    fn sign(&self, message: &[u8], out: &mut [u8]) -> Result<usize, SignRefused> {
        let Ok(Answer::Signature { bytes, len }) =
            self.exchange(Ask::Message(SignOperation::Sign, message), None)
        else {
            return Err(SignRefused);
        };
        // `zip` walks the shorter of the two, so no index is taken.
        let mut written = 0_usize;
        for (slot, byte) in out.iter_mut().zip(bytes.get(..len).unwrap_or_default()) {
            *slot = *byte;
            written += 1;
        }
        if written < len {
            // A truncated signature is not a signature, and answering one would
            // hand the library bytes no verifier accepts under a success.
            return Err(SignRefused);
        }
        Ok(written)
    }
}

/// A device identifier as the one number a console record carries it in.
///
/// Most significant byte first, which is the order the rendering prints them in —
/// so this domain's record and the holder's own are two renderings of one value
/// rather than two values. Total over the array: sixteen bytes shifted into a
/// 128-bit word is exactly its width.
fn device_word(bytes: [u8; DEVICE_ID_LEN]) -> u128 {
    let mut word = 0_u128;
    for byte in bytes {
        word = (word << 8) | u128::from(byte);
    }
    word
}
