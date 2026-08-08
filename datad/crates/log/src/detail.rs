//! What a domain lifecycle point carries beyond its own name.
//!
//! A record of only `domain=` and `state=` would have cost the console three
//! payloads: the feature bitmap a driver and its device settled on, how many
//! receive descriptors were primed before the poll loop, and the whole reason a
//! start-up was refused. Each is a field of the record rather than text a call
//! site formats around it, so an exporter still sees attributes.
//!
//! # Two forms of one cause token
//!
//! A refusal names itself with text, and that text reaches this crate from two
//! directions that cannot be given one type. A call site mints a literal, which
//! is `&'static str` and is the whole reason a byte an adversary chose cannot
//! reach the field. A console domain reconstructs one from a shared
//! region, where the bytes are a peer's and there is no allocator to own them,
//! so it is [`Cause`]. The type parameter on [`Refusal`] is that seam, and its
//! default keeps every minting call site writing what it wrote before.
//!
//! Both forms print through [`fmt::Display`], which is what lets the renderer
//! stay one function: a line an operator reads cannot depend on which side of a
//! shared region the event was assembled on.

use core::{fmt, num::NonZeroU64};

use lfw_clock::UtcNanos;

use net_headers::Ipv4Address;

use crate::event::{
    DialOutcome, NextHopVia, OnboardEnd, OnboardOutcome, OnboardRefusal, OnboardRoute, Primitive,
    TlsIncompatible, TlsRefusal,
};

/// The longest `cause` token [`MAX_LINE_LEN`](crate::MAX_LINE_LEN) is derived
/// against, and the whole of a [`Cause`]'s storage.
pub const MAX_CAUSE_LEN: usize = 40;

/// Code points of one kind a record carries out of a client's offer.
///
/// A client lists as many as it likes and the domain that reads them keeps the
/// first few with the number really listed beside them, so a record that
/// dropped some says so rather than reading as the whole offer. Eight, which is
/// two operand words exactly — the record's storage is what decides this, so it
/// is stated here where that storage is, and the domain that fills it holds its
/// own bound equal to this one.
pub const MAX_OFFERED_POINTS: usize = 8;

/// Why a byte string is not a [`Cause`]. Names the position, never the byte:
/// an adversary-chosen byte must not reach an operator surface.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CauseError {
    TooLong { len: usize },
    NotInAlphabet { offset: usize },
}

impl fmt::Display for CauseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLong { len } => {
                write!(f, "{len} bytes exceeds the {MAX_CAUSE_LEN}-byte limit")
            }
            Self::NotInAlphabet { offset } => write!(f, "byte {offset} is outside [a-z0-9-]"),
        }
    }
}

/// A refusal cause token in storage of its own: `[a-z0-9-]{0,40}`.
///
/// [`Identifier`](crate::Identifier)'s alphabet for the reason that type gives
/// — it is what makes text safe to put on a console at all — and the
/// empty token is admitted where an identifier's is not, a refusal that names
/// no cause being a record rather than a malformed one.
///
/// This is what holds a token to [`MAX_CAUSE_LEN`], which until now nothing
/// could: the literals are minted in the crates that raise the refusals, and
/// the bound lived in prose and in one test walking one of those crates.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Cause {
    bytes: [u8; MAX_CAUSE_LEN],
    len: usize,
}

impl Cause {
    /// A refusal that names no cause.
    pub const EMPTY: Self = Self {
        bytes: [0; MAX_CAUSE_LEN],
        len: 0,
    };

    /// # Errors
    /// [`CauseError`] for text the console grammar or the ABI cannot carry.
    pub fn new(bytes: &[u8]) -> Result<Self, CauseError> {
        let len = bytes.len();
        if len > MAX_CAUSE_LEN {
            return Err(CauseError::TooLong { len });
        }
        let mut stored = [0u8; MAX_CAUSE_LEN];
        for (slot, (offset, &byte)) in stored.iter_mut().zip(bytes.iter().enumerate()) {
            if !matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'-') {
                return Err(CauseError::NotInAlphabet { offset });
            }
            *slot = byte;
        }
        Ok(Self { bytes: stored, len })
    }

    /// The fallback is unreachable on [`Identifier::as_bytes`]'s terms:
    /// [`Cause::new`] is what sets `len`, and only after comparing it against
    /// the array's own size.
    ///
    /// [`Identifier::as_bytes`]: crate::Identifier::as_bytes
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.get(..self.len).unwrap_or_default()
    }

    /// Unreachable for the same reason plus one step: the alphabet is
    /// single-byte UTF-8 throughout.
    #[must_use]
    pub fn as_str(&self) -> &str {
        core::str::from_utf8(self.as_bytes()).unwrap_or_default()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl fmt::Display for Cause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What a lifecycle point carries beyond its own name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DomainDetail<C = &'static str> {
    /// The state is the whole record.
    None,
    /// The feature bits a driver and its device settled on, as the bitmap:
    /// which bit means what is `virtio`'s vocabulary, and decoding it here
    /// would be a second copy of that vocabulary to keep in step.
    Features(u64),
    /// Receive descriptors primed before a driver entered its poll loop.
    ReceivePosted(u32),
    Refusal(Refusal<C>),
    /// What a domain established about time. The two travel together because
    /// neither is worth reading alone, and they are the measurement's own types
    /// rather than integers — `calibrate`'s and a `Calibration`'s — so a call
    /// site can report neither a zero frequency nor an instant it never derived.
    Established {
        tsc_hz: NonZeroU64,
        utc: UtcNanos,
    },
    /// What a terminal endpoint has taken off its pipeline since it started,
    /// cumulative and monotonic. Counts and nothing else: no byte an adversary
    /// put on a wire has a representation here.
    Received {
        frames: u64,
        bytes: u64,
    },
    /// What a domain established about the block medium under it: a capacity is
    /// volunteered before a byte crosses, a word says nothing without a size.
    Medium {
        capacity_sectors: u64,
        leading_word: u64,
    },
    /// Where one of a domain's recordings lives on that medium — the only way
    /// an operator learns it, there being no shell and no CLI.
    Extent {
        start_sector: u64,
        sectors: u64,
    },
    /// What the hardware probe proved about this part: the AES and carry-less
    /// multiply known answers held on every pass, and a live XMM pattern
    /// survived each preemption the counter gaps below observed. The two
    /// counts travel together because the claim is only as strong as the
    /// preemptions it was checked across — an unpreempted pass proves the
    /// instructions and nothing about the state the kernel saves.
    Proven {
        preemptions: u64,
        iterations: u64,
    },
    /// One cryptographic primitive answered every published vector this image
    /// carries for it. The count travels with the name because a primitive
    /// named without one claims a proof whose size nobody can see — and the
    /// size is the whole difference between a table that covers the edges and
    /// one that covers a single happy path.
    Proved {
        primitive: Primitive,
        vectors: u64,
    },
    /// What one primitive cost on this part, in thousandths of a cycle per
    /// byte. Fixed point rather than the two counts it came from, because two
    /// counts invite a reader to divide them and reach a different answer from
    /// the domain that did the measuring.
    Measured {
        primitive: Primitive,
        milli_cycles_per_byte: u64,
    },
    /// What a TLS session settled on, as the protocol registries number it.
    /// Code points and not names, because the names are the registries' to
    /// change and an operator comparing a boot against a specification is
    /// comparing numbers either way.
    Session {
        version: u16,
        suite: u16,
    },
    /// The key exchange that session ran, and how many bytes of application
    /// data made the round trip under its traffic keys. The two travel
    /// together because a group named without an exchange under it claims a
    /// handshake and not a working session.
    Exchange {
        group: u16,
        echoed: u64,
    },
    /// The device identifier of the peer a mutually-authenticated session
    /// admitted. The identifier and nothing else about the peer: its
    /// certificate is not an operator surface.
    Peer {
        device: u128,
    },
    /// A number of bytes about the bounded allocator, against the bound it is
    /// judged by: what a session held at its peak against what the arena has,
    /// and what a starved one was left with against what a phase needs. The
    /// pair is what makes either number judgeable — a byte count without the
    /// bound beside it is a number nobody can read.
    Arena {
        bytes: u64,
        bound: u64,
    },
    /// What one operation of a primitive cost, in whole cycles. Separate from
    /// [`DomainDetail::Measured`] because the unit is different and not
    /// convertible: a signature and a key exchange each have exactly one size,
    /// so a per-byte figure for either would be a number divided by an
    /// arbitrary denominator.
    Operation {
        primitive: Primitive,
        cycles: u64,
    },
    /// Which appliance this is, and how far its persistent state has advanced.
    ///
    /// The three travel together because none of them answers the operator's
    /// question alone: an identifier without a generation cannot say whether the
    /// appliance came back or was just minted, and a generation without an owner
    /// flag cannot say whether it has been adopted. **No key material has a
    /// representation here** — an identifier is a public name, and the scalar
    /// that stands behind it reaches no surface at all.
    Identity {
        device: u128,
        generation: u64,
        onboarded: bool,
    },
    /// The appliance's public-key fingerprint: SHA-256 over the DER
    /// `SubjectPublicKeyInfo`, carried whole as the digest it is.
    ///
    /// Its own detail rather than a field beside the identifier, because it is
    /// rendered as one field of 64 hexadecimal characters and an administrator
    /// compares it character for character. A digest split across two records is
    /// two strings somebody has to join before comparing, and a fingerprint
    /// joined by hand is a fingerprint compared carelessly.
    Fingerprint([u8; 32]),
    /// What a factory reset destroyed: the generation the record it overwrote
    /// stood at, how many configuration versions went with it, and whether the
    /// appliance had an owner to give up.
    ///
    /// Appended, never inserted, on the two details above's terms. The three
    /// travel together because they are the whole of what was lost: an owned
    /// appliance's reset destroyed a delivered certificate, a trust anchor and an
    /// endpoint besides what it minted for itself, and an unowned one's destroyed
    /// only the latter. **No key material has a representation here** — what is
    /// reported is a position, a count and a flag, and the bytes themselves are
    /// gone rather than moved somewhere a record could carry them.
    Reset {
        generation: u64,
        documents: u64,
        was_owned: bool,
    },
    /// What a domain that holds no private key learned by asking the domain that
    /// does: which appliance it signs for, how many signatures that holder has
    /// produced since it started, and how large the certificate it handed over is.
    ///
    /// Appended, never inserted, on the three details above's terms. The three
    /// together are what makes any of them worth reading. The identifier alone
    /// would say only that a channel answered; the signature count alone would say
    /// that something signed and not what for; the certificate's length alone would
    /// say that bytes arrived and not whose. Together they are the delegation
    /// working: a domain naming an appliance it cannot have generated, under a count
    /// that moves when it asks again, holding a certificate over the very key that
    /// appliance named.
    ///
    /// **No key material has a representation here**, and that is the whole
    /// point of the record: what a delegating domain can report is a public name,
    /// two tallies and nothing else, because a public name and tallies are all the
    /// channel it asked over lets it say. The certificate is public too and is
    /// still not printed — a length is what an operator can read.
    Delegated {
        device: u128,
        signatures: u64,
        /// Bytes of the certificate the holder handed over, which is a count and
        /// never the certificate: a public artifact is still 768 bytes of DER
        /// nobody reads off a serial line, and a length is what says one arrived.
        certificate: u64,
    },
    /// What became of the connection this appliance reached *out* of its
    /// management port with: where it dialled, how many attempts it spent, and
    /// how the last of them finished.
    ///
    /// Appended, never inserted, on the four details above's terms. The four
    /// fields travel together because no three of them answer the operator's
    /// question: an outcome without a destination does not say what could not be
    /// reached, and an outcome without an attempt count does not say whether the
    /// appliance gave up early or spent everything it had. **No byte of the
    /// exchange has a representation here** — what the peer said reaches the two
    /// recording sinks and nothing else, and what a console reports is where the
    /// appliance went and how it got on.
    Dialled {
        destination: Ipv4Address,
        port: u16,
        /// Sessions opened for this channel, the last of which is what
        /// `outcome` reports. Bounded by the caller's own attempt count, so a
        /// number here is a first-party decision and never a peer's.
        attempts: u64,
        outcome: DialOutcome,
    },
    /// Where the frames of a failed channel were **actually** handed, and what
    /// the link made of the asking.
    ///
    /// The first of the three that follow [`Dialled`](Self::Dialled) on a
    /// channel that did not come up. They are separate records rather than a
    /// wider one because the record carries four operand words and this is more
    /// than four facts: widening the array costs a page in every log region and
    /// would still not hold them, while a reader takes a sequence of lines as
    /// readily as one. They are emitted **only on a failure**, so a healthy boot
    /// says `answered` and stops.
    ///
    /// `via` travels with the address because the address alone cannot say
    /// which decision produced it, and the two are different halves of a
    /// configuration to go and read.
    DialRoute {
        next_hop: Ipv4Address,
        via: NextHopVia,
        /// Requests for that station's hardware address this channel put on the
        /// wire, retries and every session included.
        requests: u64,
        /// Replies that resolved it. Zero beside a non-zero `requests` is the
        /// whole of what `next-hop-unreachable` means.
        learned: u64,
    },
    /// The replies that reached this port during the channel and became no
    /// entry, one count per reason they were refused.
    ///
    /// It is the other half of [`DialRoute`](Self::DialRoute)'s story: requests
    /// that went out and nothing learned is a silent link, and requests that
    /// went out with these counts moving is a link where **somebody is
    /// answering and it is not the next hop**. `contradicted` is a reply whose
    /// own claim about its sender the frame carrying it disagreed with;
    /// `rebinding` is one for an address already resolved, which is an attempt
    /// to move a next hop this appliance is using.
    DialUnlearned {
        unsolicited: u64,
        rebinding: u64,
        not_unicast: u64,
        contradicted: u64,
    },
    /// What the channel's own connections did on the wire.
    ///
    /// `answered` is the fact the tokens rest on: a budget that ran out with
    /// this false is silence, and one that ran out with it true is a peer that
    /// said something. The two reset counts say which way it said it — one from
    /// the peer ends a connection, one from this end refuses a segment RFC 793
    /// says must be refused that way.
    DialSegments {
        /// `SYN`s the transport composed, retransmissions and every session
        /// included.
        syns: u64,
        resets_received: u64,
        resets_sent: u64,
        answered: bool,
    },
    /// What one onboarding session carried, and which end finished it.
    ///
    /// Emitted by **both** domains that carry such a session — the one that
    /// owns the network and the one that terminates the exchange — because the
    /// whole point of the split is that neither of them is the other's witness:
    /// two records that disagree are a relay that lost something, and one
    /// record could never say so.
    ///
    /// **No byte of the session has a representation here.** What crosses the
    /// relay is a peer's ciphertext and it reaches no surface at all; what is
    /// reported is how much of it there was, which way it went, and who hung
    /// up. The counts are this end's own and are bounded by this end's own
    /// constants, so nothing a peer sends decides how many records there are.
    Onboarded {
        /// Items handed over the relay for this session: the operations one end
        /// asked and the other answered. A count of handovers, not of bytes.
        relayed: u64,
        /// Bytes taken off the network for this session, as this end saw them.
        received: u64,
        /// Bytes put back on the network for it.
        sent: u64,
        ended: OnboardEnd,
    },
    /// What the onboarding **port** has done and refused, beside the account of a
    /// session that ended on it.
    ///
    /// Emitted by the domain that owns the network and by no other, the port
    /// being that domain's. It is what places a fault an
    /// [`Self::Onboarded`] record can state but not explain: a session that ended
    /// as forgotten with bytes refused past the window is a peer that overran it,
    /// and one accepted connection more than there are session records is a
    /// connection that never became a session at all.
    ///
    /// **These are the port's running totals over the boot, not the session's
    /// share of them.** A session's own account is the record beside this one,
    /// and a reader combines the two rather than being handed a subtraction it
    /// cannot check. Every count is the port's own and is bounded by the port's
    /// own constants, so nothing a peer sends decides how many records there are.
    ///
    /// **No byte of a session has a representation here.** What is reported is
    /// how many bytes there were and which way they went.
    OnboardingPort {
        /// Connections accepted on the port, whatever became of them.
        accepted: u64,
        /// Connections the transport stopped holding while a session was running
        /// on them: a reset, an eviction, a reaping.
        forgotten: u64,
        /// Bytes a peer sent past the room the port had left. Unreachable while
        /// the advertised window is honoured, so a number here is a peer that
        /// ignored it rather than a port that ran out.
        overflowed: u64,
        /// Bytes the terminating domain answered with that there was no room for.
        /// **Ours** rather than the peer's.
        refused: u64,
    },
    /// How one handshake on the onboarding port ended, and — where it
    /// completed — the three code points it settled on.
    ///
    /// The first of seven that report a handshake, and they share the
    /// `onboard-tls=` key so a boot's onboarding story is one grep. This one is
    /// the successful end: [`Self::OnboardingEnded`] and the five after it are
    /// the ways it does not complete.
    ///
    /// Code points and not names, on [`Self::Session`]'s terms: the names are
    /// the registries' to change, and an operator comparing a boot against a
    /// specification is comparing numbers either way.
    ///
    /// **No key, no traffic secret and no plaintext has a representation
    /// here**, and that holds for every one of the seven. What a peer sent is
    /// its own and reaches no surface at all; what these carry is which
    /// protocol was settled on, or which of a closed set of ways it was not.
    OnboardingHandshake {
        outcome: OnboardOutcome,
        version: u16,
        suite: u16,
        group: u16,
    },
    /// A handshake that ended carrying nothing beyond the way it did.
    ///
    /// The outcomes with no fact of their own — a peer that said nothing, one
    /// that went away, neither end able to progress — and the one whose facts
    /// are a record of their own: an exhausted arena is reported with the
    /// [`Self::Arena`] record beside it, which is where this appliance already
    /// states what was asked for against what was left.
    OnboardingEnded {
        outcome: OnboardOutcome,
    },
    /// A handshake the library and the peer had no protocol in common for, in
    /// the library's own vocabulary.
    ///
    /// The outcome travels beside the reason because the two answer different
    /// questions: whether the offer was rejected before there was a suite to
    /// compare, and which incompatibility it was.
    OnboardingIncompatible {
        outcome: OnboardOutcome,
        incompatible: TlsIncompatible,
    },
    /// A handshake this appliance refused, as the library's own error variant.
    OnboardingRefused {
        outcome: OnboardOutcome,
        refusal: TlsRefusal,
    },
    /// The fatal alert a peer gave up with, as the registry numbers it.
    ///
    /// A code point on [`Self::OnboardingHandshake`]'s terms. It is the peer's
    /// own statement about why it went away, which is a different fact from
    /// anything this end decided.
    OnboardingAlert {
        outcome: OnboardOutcome,
        alert: u16,
    },
    /// A direction of one handshake that outgrew what a session holds, carrying
    /// what it would have had to hold.
    ///
    /// The count is this appliance's own arithmetic over a peer's pacing, and
    /// it is the number that says whether a bound is too tight or a peer is
    /// misbehaving — which is why it is on the record rather than implied by
    /// the token.
    OnboardingBacklogged {
        outcome: OnboardOutcome,
        held: u64,
    },
    /// The cipher suites a client offered, where none of them was one this
    /// appliance has.
    ///
    /// Its own record rather than a field beside the outcome, and so is the
    /// group list after it: eight code points and a count do not fit beside a
    /// token, and the two lists together are what an administrator compares
    /// against what this appliance offers. Emitted only where the offer is what
    /// the failure is about.
    ///
    /// `offered` is what the client really listed, which may exceed what
    /// `points` holds — so a record that dropped some says so rather than
    /// reading as the whole offer.
    OnboardingSuites {
        points: [u16; MAX_OFFERED_POINTS],
        offered: u16,
    },
    /// The key-exchange groups a client offered, on [`Self::OnboardingSuites`]'s
    /// terms.
    OnboardingGroups {
        points: [u16; MAX_OFFERED_POINTS],
        offered: u16,
    },
    /// One request the onboarding surface answered: which of its two resources
    /// and how many bytes of body went back.
    ///
    /// A resource out of a closed vocabulary rather than the target a peer
    /// wrote, on the same terms every other record here is under: the target is
    /// adversary-chosen bytes and reaches no surface at all.
    ///
    /// It is per request and bounded by that: one response closes the
    /// connection and one connection carries one request, so the record count
    /// a peer can provoke is the session count the port already bounds and
    /// already reports.
    OnboardingServed {
        route: OnboardRoute,
        bytes: u64,
    },
    /// One request the onboarding surface refused, the status it was answered
    /// with, and the head this end was holding when it decided.
    ///
    /// The status travels because it is what the peer was told and an
    /// administrator comparing a client's complaint against this record is
    /// comparing that number. `held` is this end's own arithmetic over what
    /// arrived — never a byte of it — and it is what tells a bound that is too
    /// tight from a peer that is misbehaving.
    OnboardingRequest {
        refusal: OnboardRefusal,
        status: u16,
        held: u64,
    },
    /// What the limiter is doing, written beside the refusal it caused.
    ///
    /// Its own record rather than two more fields, because it answers a
    /// different question: not why this request was refused but **when the next
    /// one will not be**. `wait` is milliseconds until the next allowance and
    /// is always finite — the whole design of the limiter is that a lockout
    /// expires — and `strikes` is how many consecutive refusals lengthened it.
    OnboardingThrottled {
        strikes: u64,
        wait_millis: u64,
    },
    /// The two sequence numbers behind an unacceptable acknowledgement: what the
    /// peer claimed, and what this end had actually sent.
    ///
    /// Emitted only where one arrived, because only then do the numbers exist.
    /// **`claimed` is the peer's number**: it is reported so an operator can
    /// read the gap, and it is nothing this node computes with.
    DialSequence {
        claimed: u32,
        expected: u32,
    },
}

/// Why a domain refused to start, and what that left the hardware in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Refusal<C = &'static str> {
    /// What was refused, as the header's two forms: a literal where a call site
    /// mints one, a [`Cause`] where a decode reconstructs one.
    ///
    /// Deliberately not an enum: the refusal trees belong to the crates that
    /// raise them, and a copy of one in this crate would drift from it with
    /// nothing failing.
    pub cause: C,
    /// The numbers `cause` names, in the order it names them.
    pub detail: RefusalDetail,
    /// Whether the device was told to stop, or was left decoding nothing.
    pub signalled: bool,
}

/// Up to two numbers a refusal carries, so it reaches an operator as the values
/// that made it one and not only as its class.
///
/// Two is the console line's budget rather than an arbitrary cut: a refusal
/// with more to say names the pair that identifies it and says at the mapping
/// which it left out, so what is missing is recorded where it is dropped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefusalDetail {
    None,
    One(u64),
    Two(u64, u64),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::NextHopVia;
    use proptest::prelude::*;
    use std::{format, string::String, vec::Vec};

    #[test]
    fn the_empty_and_the_longest_admissible_causes_are_accepted() {
        for text in [&b""[..], b"a", b"not-virtio-net", &[b'a'; MAX_CAUSE_LEN]] {
            let cause = Cause::new(text).expect("within the alphabet and the length bound");
            assert_eq!(cause.as_bytes(), text);
            assert_eq!(cause.as_str().as_bytes(), text);
            assert_eq!(cause.len(), text.len());
            assert_eq!(cause.is_empty(), text.is_empty());
        }
        assert_eq!(Cause::new(b"").expect("empty is a cause"), Cause::EMPTY);
        assert!(Cause::EMPTY.is_empty());
    }

    #[test]
    fn one_byte_past_the_length_bound_is_refused_with_the_length_it_had() {
        let long = [b'a'; MAX_CAUSE_LEN + 1];
        assert_eq!(
            Cause::new(&long),
            Err(CauseError::TooLong {
                len: MAX_CAUSE_LEN + 1
            })
        );
        assert!(Cause::new(&long[..MAX_CAUSE_LEN]).is_ok());
    }

    #[test]
    fn a_byte_outside_the_alphabet_is_refused_and_its_position_named() {
        for (text, offset) in [(&b"NOT"[..], 0), (b"not virtio", 3), (b"not_virtio", 3)] {
            assert_eq!(
                Cause::new(text),
                Err(CauseError::NotInAlphabet { offset }),
                "{text:?}"
            );
        }
    }

    #[test]
    fn each_cause_rejection_reads_differently() {
        let mut messages: Vec<String> = [
            CauseError::TooLong { len: 41 },
            CauseError::NotInAlphabet { offset: 2 },
        ]
        .iter()
        .map(|error| format!("{error}"))
        .collect();
        messages.sort();
        let count = messages.len();
        messages.dedup();
        assert_eq!(messages.len(), count);
    }

    #[test]
    fn causes_compare_by_content_not_by_the_unused_tail() {
        let short = Cause::new(b"pool").expect("valid");
        assert_ne!(short, Cause::new(b"pool-").expect("valid"));
        assert_eq!(short, Cause::new(b"pool").expect("valid"));
        assert_eq!(format!("{short}"), "pool");
    }

    proptest! {
        /// Total over arbitrary bytes: every input is either a typed rejection
        /// or a cause that reproduces exactly what it was given.
        #[test]
        fn cause_construction_is_total_and_lossless(
            bytes in proptest::collection::vec(any::<u8>(), 0..96),
        ) {
            match Cause::new(&bytes) {
                Ok(cause) => {
                    prop_assert_eq!(cause.as_bytes(), &bytes[..]);
                    prop_assert_eq!(cause.len(), bytes.len());
                    prop_assert!(cause.len() <= MAX_CAUSE_LEN);
                }
                Err(CauseError::TooLong { len }) => {
                    prop_assert_eq!(len, bytes.len());
                    prop_assert!(len > MAX_CAUSE_LEN);
                }
                Err(CauseError::NotInAlphabet { offset }) => {
                    let byte = bytes.get(offset).copied().expect("the offset indexes the input");
                    prop_assert!(!matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'-'));
                }
            }
        }

        /// Everything the alphabet admits is accepted, so the rejection set is
        /// exactly its complement rather than something narrower.
        #[test]
        fn the_whole_cause_alphabet_is_accepted(text in "[a-z0-9-]{0,40}") {
            let cause = Cause::new(text.as_bytes()).expect("the pattern is the alphabet");
            prop_assert_eq!(cause.as_str(), text.as_str());
        }
    }

    #[test]
    fn a_refusal_keeps_every_field_it_was_given() {
        let refusal = Refusal {
            cause: "not-virtio-net",
            detail: RefusalDetail::Two(0x1af4, 0x1000),
            signalled: false,
        };
        assert_eq!(refusal.cause, "not-virtio-net");
        assert_eq!(refusal.detail, RefusalDetail::Two(0x1af4, 0x1000));
        assert!(!refusal.signalled);
        assert_eq!(
            DomainDetail::Refusal(refusal),
            DomainDetail::Refusal(refusal)
        );
    }

    /// Every shape, and each at the zero its neighbours also carry: a payload
    /// is what the *variant* names, so two shapes holding the same number must
    /// still not compare equal.
    #[test]
    fn every_detail_shape_is_distinguishable() {
        let shapes = [
            DomainDetail::None,
            DomainDetail::Features(0),
            DomainDetail::ReceivePosted(0),
            DomainDetail::Received {
                frames: 0,
                bytes: 0,
            },
            DomainDetail::Medium {
                capacity_sectors: 0,
                leading_word: 0,
            },
            DomainDetail::Established {
                tsc_hz: NonZeroU64::MIN,
                utc: lfw_clock::UtcNanos::from_unix_nanos(0),
            },
            DomainDetail::Proven {
                preemptions: 0,
                iterations: 0,
            },
            DomainDetail::Proved {
                primitive: Primitive::Sha256,
                vectors: 0,
            },
            DomainDetail::Measured {
                primitive: Primitive::Sha256,
                milli_cycles_per_byte: 0,
            },
            DomainDetail::Refusal(Refusal {
                cause: "",
                detail: RefusalDetail::None,
                signalled: false,
            }),
            // The four a failed channel adds. All four are counts at the same
            // zero, which is exactly the shape this test exists to keep apart:
            // three zeroed segment counts and three zeroed refusal counts are
            // different records about different things.
            DomainDetail::DialRoute {
                next_hop: Ipv4Address::from_octets([0, 0, 0, 0]),
                via: NextHopVia::Prefix,
                requests: 0,
                learned: 0,
            },
            DomainDetail::DialUnlearned {
                unsolicited: 0,
                rebinding: 0,
                not_unicast: 0,
                contradicted: 0,
            },
            DomainDetail::DialSegments {
                syns: 0,
                resets_received: 0,
                resets_sent: 0,
                answered: false,
            },
            DomainDetail::DialSequence {
                claimed: 0,
                expected: 0,
            },
        ];
        for (index, shape) in shapes.iter().enumerate() {
            for (other_index, other) in shapes.iter().enumerate() {
                assert_eq!(
                    shape == other,
                    index == other_index,
                    "{shape:?} vs {other:?}"
                );
            }
        }
    }
}
