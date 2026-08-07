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
//! Three things are asked over that channel and only one of them is the trait's:
//! a signature, the public point and name the holder signs under, and **the
//! appliance's own certificate over that point**. The certificate is fetched
//! rather than issued here because the holder is the identity domain — it minted
//! that certificate and made it durable — and a certificate written in this domain
//! would be a second statement over one key, with no domain able to say which one
//! a peer was shown. It is a public artifact either way: what crosses is what
//! every peer of this appliance is handed.
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
    SignRequester,
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

/// What the holder answered a `PublicKey` request with, and what it has done
/// since it started.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeldKey {
    /// The uncompressed SEC1 point the holder signs under. A public value, and
    /// the only thing a certificate needs from the other domain.
    pub public_key: [u8; PUBLIC_KEY_LEN],
    /// The appliance's 128-bit name, as the number the console renders.
    pub device: u128,
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
        match self.exchange(SignOperation::PublicKey, &[], None)? {
            Answer::Identity(DeviceIdentity {
                public_key,
                device_id,
            }) => Ok(HeldKey {
                public_key,
                device: device_word(device_id),
            }),
            // The channel refuses a reply answering a different operation before
            // it reaches here, so these arms are unreachable. Answered as a fault
            // rather than asserted: nothing on a path the TLS library calls into
            // may panic.
            Answer::Signature { .. } | Answer::Certificate { .. } => Err(DelegationError::Faulted),
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
        match self.exchange(SignOperation::Certificate, &[], Some(&mut bytes))? {
            Answer::Certificate { len } => Ok(HeldCertificate { bytes, len }),
            // Unreachable for [`Self::held_key`]'s reason, and a fault for it.
            Answer::Signature { .. } | Answer::Identity(_) => Err(DelegationError::Faulted),
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
        operation: SignOperation,
        message: &[u8],
        certificate: Option<&mut [u8; MAX_CERTIFICATE_LEN]>,
    ) -> Result<Answer, DelegationError> {
        while self
            .taken
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        let outcome = self.issue(operation, message, certificate);
        self.taken.store(false, Ordering::Release);
        outcome
    }

    /// The exchange itself, with the flag held.
    fn issue(
        &self,
        operation: SignOperation,
        message: &[u8],
        mut certificate: Option<&mut [u8; MAX_CERTIFICATE_LEN]>,
    ) -> Result<Answer, DelegationError> {
        // SAFETY: the flag is held by the caller, so this is the only live
        // reference to the requester for the duration of the call, and the
        // reference does not escape this function.
        let requester = unsafe { &mut *self.requester.get() };
        let mut pending: PendingSignature = requester.request(operation, message);
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
                    if let Some(into) = certificate.as_mut() {
                        for (slot, byte) in into.iter_mut().zip(published) {
                            *slot = *byte;
                        }
                    }
                    return Ok(Answer::Certificate {
                        len: published.len(),
                    });
                }
                SignPoll::Refused(_) => return Err(DelegationError::Refused),
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
/// **The certificate is the exception and carries only its length.** It is ten
/// times the size of everything else this channel moves, so a variant holding it
/// would make every exchange return a certificate's worth of stack — including the
/// signature exchange that runs inside a handshake, which is the one path here that
/// is not a once-per-boot call. The caller that asks for a certificate says where it
/// goes instead, and only that caller carries the buffer.
enum Answer {
    Signature {
        bytes: [u8; MAX_SIGNATURE_LEN],
        len: usize,
    },
    Identity(DeviceIdentity),
    Certificate {
        len: usize,
    },
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
            self.exchange(SignOperation::Sign, message, None)
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
