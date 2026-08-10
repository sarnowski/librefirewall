#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

//! The management channel's framing: the ten frames that cross the one
//! persistent connection between this appliance and its management server, and
//! the codec that writes and reads them.
//!
//! # Where it sits
//!
//! Above a TLS session and below a session state machine, touching neither.
//! Plaintext the record layer produced comes in, plaintext it should send goes
//! out, and what is underneath — a socket, a relay, a protection domain — is
//! somebody else's. Nothing here dials, retries, times anything, or decides
//! *when* a frame is sent: this crate says what a frame **is** and refuses one
//! that is not.
//!
//! That split is what makes the whole protocol host-testable against composed
//! bytes, and it is deliberate on a second count as well: the frames come in
//! both directions, so the encoder is the whole protocol's and not one end's.
//! An appliance encodes the appliance's frames and decodes the server's; a
//! server does the reverse; the same [`Side`] parameter picks which, and each
//! side's decoder refuses a frame the other end had no business sending.
//!
//! # Adversary
//!
//! A **management-plane attacker up to and including a compromised management
//! server**. Every byte the decoder reads was chosen by the peer: the lengths,
//! the type bytes, the reserved bytes, the ring selectors, the cursors, the
//! pacing of the arrivals, and how a frame is cut across them. That the peer is
//! *authenticated* by the session below is not a reason to model it as
//! well-behaved — a compromised server holds a valid certificate, and what
//! bounds it is the arithmetic here.
//!
//! So: every length is bounded by a constant of this crate before it is
//! believed, nothing is indexed without a bound, no arithmetic on a peer's
//! number can overflow, and there is no panicking construct on any path a byte
//! reaches. A peer that breaks a rule gets a [`Violation`] naming which rule,
//! and the connection is over — which is the whole of what a violation does.
//!
//! # One value per broken rule, because the console is the only place to look
//!
//! [`Violation`] has one variant per cause and no variant standing for several.
//! A deployed appliance is diagnosed from its console alone, so a token that
//! meant "the peer sent something wrong" would name nothing an operator could
//! act on: a header of a protocol this is not, a frame the peer's own end may
//! not send, a document past its bound and a range answer that contradicts
//! itself are four different things to go and look at. Nothing here maps a
//! violation to a console record — that mapping belongs with the protection
//! domain that emits one, and this crate emits nothing.
//!
//! # Where a partial frame is held, and what bounds it
//!
//! A frame carries up to [`MAX_PAYLOAD_LEN`] and arrives in whatever pieces the
//! record layer under it produces, which are tens of kibibytes at most. So the
//! reassembly happens **here**, above that layer rather than through it, and
//! [`FrameDecoder`] holds the frame in progress in a fixed
//! `[u8; MAX_FRAME_LEN]` of its own — one frame's worth and never two, because
//! [`FrameDecoder::absorb`] takes no byte past the end of the frame it is
//! assembling. A completed frame is handed out borrowed from that array and the
//! array is empty again the moment it is dropped, so nothing is ever copied
//! down it.
//!
//! The array is why a decoder is a megabyte-sized value that belongs in a
//! protection domain's own static storage, and [`FrameDecoder::new`] is `const`
//! so it can go there. This crate owns no allocator and asks for none: the
//! buffer is a fixed array sized by a named constant, so how much memory the
//! framing needs is a compile-time fact rather than something a peer's lengths
//! decide.

mod codec;
mod frame;

#[cfg(test)]
mod tests;

pub use codec::{Decoded, EncodeRefusal, FrameDecoder, encode, encoded_len};
pub use frame::{Frame, FrameType, Hello, RangeStatus, Ring, Side, Violation};

// The bound on a staged configuration document, named where it is enforced:
// the same region size the configuration reader's storage has, so a document
// this framing accepts is one that stage can hold.
pub use wire::MAX_DOCUMENT_BYTES;

/// Bytes of header in front of every frame's payload.
///
/// Four of payload length, one of frame type, three reserved and zero.
pub const HEADER_LEN: usize = 8;

/// Bytes of payload one frame may carry.
///
/// 1 MiB, matching a recording segment, and the whole reason a decoder is the
/// size it is. A **receiving** bound rather than a size anything emits: set at
/// the segment so the framing never decides how a ring is shipped, while an
/// upstream frame is bounded far below it, by its session's room for one.
pub const MAX_PAYLOAD_LEN: usize = 1 << 20;

/// Bytes of one whole frame, header and maximal payload.
///
/// The size of a decoder's reassembly buffer, and the most a caller ever needs
/// to offer an encoder.
pub const MAX_FRAME_LEN: usize = HEADER_LEN + MAX_PAYLOAD_LEN;

/// The protocol version this end speaks, and the only one it does.
///
/// A receiver that reads any other in a peer's greeting closes the connection.
/// There is no downgrade: both ends of this protocol ship from one project, so a
/// mismatch means one of them is due an update and negotiating around it would
/// hide that.
pub const VERSION: u16 = 1;

/// Bytes of a greeting the appliance sends: the version and nothing else, its
/// identity being the certificate the session below authenticated it by.
pub const APPLIANCE_HELLO_LEN: usize = 2;

/// Bytes of a greeting the server sends: the version and the two cursors up to
/// which it has durably ingested the two rings.
pub const SERVER_HELLO_LEN: usize = 2 + 8 + 8;

// The layout every frame in this protocol is written and read against, pinned so
// a change to one of these numbers is a compile error here rather than a frame
// the two ends disagree about.
const _: () = {
    assert!(HEADER_LEN == 8);
    assert!(MAX_PAYLOAD_LEN == 1_048_576);
    assert!(MAX_FRAME_LEN == 1_048_584);
    assert!(VERSION == 1);
    // The stated length is a `u32`, so the bound has to be one a `u32` can
    // reach — otherwise a frame at the bound could not be described by its own
    // header.
    assert!(MAX_PAYLOAD_LEN <= u32::MAX as usize);
    // Every fixed-shape payload fits inside the bound, so no frame this codec
    // can compose is one it would then refuse.
    assert!(SERVER_HELLO_LEN <= MAX_PAYLOAD_LEN);
    assert!(APPLIANCE_HELLO_LEN < SERVER_HELLO_LEN);
    // A staged document is a payload, so its own bound must sit under the frame
    // bound. Were it ever raised past this, a document the configuration stage
    // accepts could not be delivered at all.
    assert!(MAX_DOCUMENT_BYTES <= MAX_PAYLOAD_LEN);
};
