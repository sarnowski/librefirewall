//! Where a package upload's body goes, as the one thing this crate asks of its
//! caller.
//!
//! # Adversary
//!
//! The **unauthenticated management-plane attacker**, at one remove: every byte
//! offered to an [`Upload`] came off the onboarding port. Nothing here reads
//! one — this module is the shape of the handover and not a reader of what
//! crosses it.
//!
//! # Why the body does not stay in this crate
//!
//! Everything else this surface holds is small enough to be an array in a
//! protection domain's own memory: a request head is two kibibytes and the two
//! resources it serves are fixed. A package is a hundred and twenty-eight, and
//! it has somewhere to be that is not here — the region the domain that holds
//! the device key reads it out of. A surface that accumulated one first would
//! be a second copy of the largest object this appliance handles, held in the
//! one crate with no reason to hold it.
//!
//! So the body is handed on as it arrives and this crate keeps none of it. What
//! that costs is a trait; what it buys is that the bytes an administrator
//! uploads are written once, into the place they are judged from.
//!
//! # Three steps, because the caller can refuse at two of them
//!
//! [`Upload::open`] is where a caller reserves whatever an upload costs it, and
//! it is separate from the first [`Upload::take`] precisely so that the reserve
//! can be refused **before** any byte is placed: a caller that discovered
//! half-way through that it had nowhere to put the rest would have to abandon an
//! upload it had already begun answering for. [`Upload::install`] is the other
//! refusal, and it is the package's own.
//!
//! # Neither refusal carries a reason, and that is deliberate
//!
//! Why a package was refused is the vocabulary of the contract that judged it,
//! and it reaches an operator on the console of the domain that did the judging,
//! beside the facts that place it. A reason travelling back here would be a
//! second copy of that vocabulary in a crate with no way to keep it in step —
//! and the surface would then be composing an answer out of it, which is a byte
//! string about another domain's internals on a path that faces the network.

/// The caller would not, or could not, go on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UploadRefused;

/// Where an upload's body goes, and who judges it once it is whole.
///
/// Implemented by the protection domain that terminates the session; the tests
/// implement it over a vector, which is what makes every path through the
/// surface reachable on a host.
pub trait Upload {
    /// Reserve room for an upload of `declared` bytes, or refuse it.
    ///
    /// Called once, when a whole head has asked for the upload route and every
    /// other rule about the request has passed. `declared` is the length the
    /// peer stated and the request parser has already held to the widest
    /// package this appliance looks at — so it is bounded, and it is still a
    /// peer's claim about how much it intends to send rather than a promise.
    ///
    /// # Errors
    /// [`UploadRefused`] where the caller has nowhere to put an upload of this
    /// size. The peer is told the surface is unavailable, which is what it is.
    fn open(&mut self, declared: usize) -> Result<(), UploadRefused>;

    /// Take the next `segment` of the body, answering how many of its bytes
    /// were kept.
    ///
    /// A count rather than a refusal, because the caller's storage is what
    /// bounds it and a short answer is a fact about that storage; the surface
    /// compares the count against what it offered and refuses the request when
    /// they differ. Segments arrive in the pieces the network chose and are
    /// placed end to end.
    fn take(&mut self, segment: &[u8]) -> usize;

    /// The body is whole: judge it and install it, or refuse it.
    ///
    /// # Errors
    /// [`UploadRefused`] for every way the answer is no, with the reason on the
    /// console of whichever domain arrived at it.
    fn install(&mut self) -> Result<(), UploadRefused>;
}
