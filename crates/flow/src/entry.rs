//! One flow's whole state, and the sixty-four bytes it is laid out in.
//!
//! # Why the size is a design constraint rather than a consequence
//!
//! The table holds a million of these, so every byte here is a mebibyte of a
//! memory region and every cache line a probe touches is a hot-path miss. The
//! layout is therefore chosen and asserted rather than left to the compiler: an
//! entry is exactly one 64-byte cache line, aligned to one, so a lookup that
//! reaches an entry at all reads one line and never straddles two. The tuple a
//! lookup compares sits at the front of it.
//!
//! # What is deliberately not here
//!
//! No payload, no reassembly, no per-flow byte counters, and no pointer of any
//! kind — the whole entry is integers, because the table it sits in is placed in
//! a shared memory region at an address this crate never learns. The links a
//! free list and a hash chain would need are slot *indices* for the same reason.
//!
//! There is also no separate record of when a flow's `FIN` was sent. It is
//! recoverable from [`DirectionState::end`]: a `FIN` occupies the last sequence
//! number a direction ever sends, so a direction that has sent one has its
//! `FIN` acknowledged exactly when the peer acknowledges everything up to that
//! end. Storing the number again would be four bytes carrying a fact the ones
//! already there imply.

use lfw_clock::{Duration, Monotonic};
use lfw_tcp::SeqNumber;
use net_headers::{Ipv4Address, Protocol};

use crate::key::{Direction, Endpoint, FlowKey};

/// The slot index that names no slot, in a link field and in a bucket.
///
/// `u32::MAX` rather than a separate flag: a table of that many entries cannot
/// be built, since the layout assertions below fix an entry at 64 bytes and the
/// product exceeds what any region could hold.
pub(crate) const NO_SLOT: u32 = u32::MAX;

/// How far behind everything a peer has sent an acknowledgement may still lag.
///
/// An acknowledgement legitimately trails the peer's newest data by at most what
/// this side told the peer it could have in flight — one advertised window. The
/// cap exists because a *scaled* window can be a gibibyte: accepting an
/// acknowledgement that far behind would make the test vacuous, so the slack is
/// the smaller of the advertised window and one unscaled window's worth, which
/// is what the field a peer without scaling can express.
pub(crate) const MAX_ACK_SLACK: u32 = 66_000;

/// What one flow is doing, which is what fixes its timeout and whether pressure
/// may take its slot.
///
/// One enum across all three protocols rather than three, because the table's
/// occupancy is one number per state and a caller reporting it should not have to
/// know which protocol a state belongs to. [`Vacant`](Self::Vacant) is a state
/// rather than a separate occupancy flag so that a zeroed region is a table with
/// no flows in it and there is exactly one place occupancy is recorded.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlowState {
    Vacant = 0,
    /// A TCP `SYN` from the originator, with nothing back.
    SynSent,
    /// Both ends have sent a `SYN`; the handshake is not complete.
    SynReceived,
    /// The handshake completed.
    Established,
    /// One end has sent a `FIN` that is not yet acknowledged.
    FinWait,
    /// One end's `FIN` is acknowledged; the other end may still send.
    CloseWait,
    /// Both ends have sent a `FIN` and at least one is unacknowledged.
    Closing,
    /// Both `FIN`s are acknowledged.
    TimeWait,
    /// A `RST` ended the flow.
    Closed,
    /// A UDP pseudo-flow with traffic in one direction only.
    UdpUnreplied,
    /// A UDP pseudo-flow the far end has answered.
    UdpAssured,
    /// An ICMP echo request with no reply yet.
    IcmpUnreplied,
    /// An ICMP echo request that has been answered.
    IcmpReplied,
}

impl FlowState {
    /// Every state, in discriminant order, so a caller reporting occupancy can
    /// enumerate them without knowing how many there are.
    pub const ALL: [Self; STATE_COUNT] = [
        Self::Vacant,
        Self::SynSent,
        Self::SynReceived,
        Self::Established,
        Self::FinWait,
        Self::CloseWait,
        Self::Closing,
        Self::TimeWait,
        Self::Closed,
        Self::UdpUnreplied,
        Self::UdpAssured,
        Self::IcmpUnreplied,
        Self::IcmpReplied,
    ];

    /// Where this state's count sits in an occupancy table.
    #[must_use]
    pub const fn index(self) -> usize {
        self as usize
    }

    /// A stable short name, for a metric label or a report line.
    ///
    /// [`Vacant`](Self::Vacant) is named rather than skipped: how much of the
    /// table is free is the number an operator watches a flood against, and
    /// deriving it by subtracting twelve series from a capacity nothing else
    /// publishes would be a gauge nobody computes.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Vacant => "vacant",
            Self::SynSent => "syn_sent",
            Self::SynReceived => "syn_received",
            Self::Established => "established",
            Self::FinWait => "fin_wait",
            Self::CloseWait => "close_wait",
            Self::Closing => "closing",
            Self::TimeWait => "time_wait",
            Self::Closed => "closed",
            Self::UdpUnreplied => "udp_unreplied",
            Self::UdpAssured => "udp_assured",
            Self::IcmpUnreplied => "icmp_unreplied",
            Self::IcmpReplied => "icmp_replied",
        }
    }

    /// Whether the flow has been confirmed in both directions, and so may never
    /// be taken back to make room for a new flow.
    ///
    /// This predicate is the whole of the fail-closed eviction policy: a flood of
    /// new flows can only ever reach a slot holding something that is *not*
    /// assured. `TimeWait` is deliberately outside it — the flow is over, and
    /// holding its slot against a new connection is the one situation where
    /// keeping the delayed-duplicate guarantee would deny service instead.
    #[must_use]
    pub const fn is_assured(self) -> bool {
        matches!(
            self,
            Self::Established
                | Self::FinWait
                | Self::CloseWait
                | Self::Closing
                | Self::UdpAssured
                | Self::IcmpReplied
        )
    }
}

/// How many states there are, and so how wide an occupancy table is.
pub const STATE_COUNT: usize = 13;

/// Bits of [`DirectionState::flags`].
mod direction_flags {
    /// Anything at all has been seen travelling in this direction. Distinct from
    /// a non-zero window, because a UDP or ICMP direction advertises none.
    pub(super) const SPOKEN: u8 = 1 << 0;
    /// A `SYN` has been seen from this side.
    pub(super) const SYN: u8 = 1 << 1;
    /// A `FIN` has been seen from this side.
    pub(super) const FIN: u8 = 1 << 2;
    /// The peer has acknowledged this side's `FIN`.
    pub(super) const FIN_ACKED: u8 = 1 << 3;
    /// This side's `SYN` carried a window-scale option. Recorded apart from the
    /// shift itself because RFC 7323 section 2.2 makes scaling apply only when
    /// *both* ends offer it, so "offered a shift of zero" and "offered nothing"
    /// are different facts.
    pub(super) const SCALE_OFFERED: u8 = 1 << 4;
}

/// What one direction of a flow has sent, in the terms a window check needs.
///
/// Every sequence value is stored as its raw `u32` and read back as a
/// [`SeqNumber`], so the modulo-2^32 comparisons are the only ones anything here
/// can perform: there is no accessor returning an integer a caller could order
/// with `<`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DirectionState {
    /// One past everything this side has sent: `max(sequence + length)`.
    end: u32,
    /// The furthest sequence number this side has been permitted to send to,
    /// which is the largest `acknowledgement + window` the peer has offered.
    max_end: u32,
    /// The largest window this side has advertised, already scaled.
    max_window: u32,
    /// The shift this side's windows are scaled by, zero unless both ends
    /// offered scaling.
    scale: u8,
    flags: u8,
    reserved: [u8; 2],
}

impl DirectionState {
    /// Nothing seen in this direction yet.
    pub(crate) const SILENT: Self = Self {
        end: 0,
        max_end: 0,
        max_window: 0,
        scale: 0,
        flags: 0,
        reserved: [0; 2],
    };

    /// One past everything this side has sent.
    #[must_use]
    pub fn end(&self) -> SeqNumber {
        SeqNumber::new(self.end)
    }

    /// The furthest sequence number the peer has authorised this side to reach.
    #[must_use]
    pub fn max_end(&self) -> SeqNumber {
        SeqNumber::new(self.max_end)
    }

    /// The largest window this side has advertised, scaled.
    #[must_use]
    pub const fn max_window(&self) -> u32 {
        self.max_window
    }

    /// The shift this side's windows are scaled by.
    #[must_use]
    pub const fn scale(&self) -> u8 {
        self.scale
    }

    #[must_use]
    pub const fn spoken(&self) -> bool {
        self.flags & direction_flags::SPOKEN != 0
    }

    #[must_use]
    pub const fn seen_syn(&self) -> bool {
        self.flags & direction_flags::SYN != 0
    }

    #[must_use]
    pub const fn seen_fin(&self) -> bool {
        self.flags & direction_flags::FIN != 0
    }

    #[must_use]
    pub const fn fin_acknowledged(&self) -> bool {
        self.flags & direction_flags::FIN_ACKED != 0
    }

    #[must_use]
    pub(crate) const fn scale_offered(&self) -> bool {
        self.flags & direction_flags::SCALE_OFFERED != 0
    }

    /// Record the first thing seen in this direction.
    ///
    /// `max_end` is raised to the segment's own end rather than set from a
    /// window: before the peer has spoken nothing has authorised this side to go
    /// further than what it has already sent, and the peer's first
    /// acknowledgement is what opens it.
    pub(crate) fn open(&mut self, end: SeqNumber, window: u32) {
        self.end = end.raw();
        self.max_window = window.max(1);
        self.flags |= direction_flags::SPOKEN;
        self.raise_max_end(end);
    }

    /// Move `end` forward over a segment, never back: a retransmission of older
    /// data does not shrink what this side has sent.
    pub(crate) fn extend_end(&mut self, end: SeqNumber) {
        if end.follows(self.end()) {
            self.end = end.raw();
        }
    }

    /// Widen the recorded window, never narrow it.
    ///
    /// Monotone on purpose: RFC 793 forbids shrinking a window, and data already
    /// in flight under the wider one must not start being refused because a later
    /// segment advertised less.
    pub(crate) fn widen_window(&mut self, window: u32) {
        self.max_window = self.max_window.max(window).max(1);
    }

    /// Raise the right edge this side may send to, never lower it, for the same
    /// reason [`widen_window`](Self::widen_window) only widens.
    pub(crate) fn raise_max_end(&mut self, edge: SeqNumber) {
        if edge.follows(self.max_end()) || !self.spoken() {
            self.max_end = edge.raw();
        }
    }

    /// Note that something travelled this way, for the two protocols that carry
    /// no sequence space to open the direction with.
    ///
    /// It is what makes [`spoken`](Self::spoken) mean the same thing for all
    /// three protocols — a direction this flow has actually carried traffic in —
    /// which is the fact an ICMP error's quote is corroborated against.
    pub(crate) fn note_traffic(&mut self) {
        self.flags |= direction_flags::SPOKEN;
    }

    pub(crate) fn note_syn(&mut self, offered_scale: Option<u8>) {
        self.flags |= direction_flags::SYN;
        if let Some(shift) = offered_scale {
            self.flags |= direction_flags::SCALE_OFFERED;
            self.scale = shift.min(MAX_WINDOW_SCALE);
        }
    }

    pub(crate) fn note_fin(&mut self) {
        self.flags |= direction_flags::FIN;
    }

    /// Note that the peer has acknowledged up to `acknowledgement`, which closes
    /// this side's `FIN` where it covers it.
    pub(crate) fn note_acknowledged(&mut self, acknowledgement: SeqNumber) {
        if self.seen_fin() && acknowledgement.follows_or_equals(self.end()) {
            self.flags |= direction_flags::FIN_ACKED;
        }
    }

    /// Give up window scaling on this side, which is what one end offering none
    /// costs both of them.
    pub(crate) fn abandon_scaling(&mut self) {
        self.scale = 0;
    }
}

/// The largest shift RFC 7323 section 2.3 permits a window to be scaled by.
pub(crate) const MAX_WINDOW_SCALE: u8 = 14;

/// Bits of [`FlowEntry::flags`].
mod entry_flags {
    /// The packet that opened the flow travelled from the *upper* endpoint of
    /// the canonical pair towards the lower one. Absent means it travelled the
    /// other way, so one bit carries the whole of a flow's own orientation.
    pub(super) const ORIGIN_IS_UPPER: u8 = 1 << 0;
}

/// One flow: its identity, its state, and what each direction has sent.
///
/// Exactly one cache line, asserted below. The tuple a probe compares occupies
/// the first sixteen bytes of it.
#[repr(C, align(64))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FlowEntry {
    lower_address: u32,
    upper_address: u32,
    lower_port: u16,
    upper_port: u16,
    protocol: u8,
    state: FlowState,
    flags: u8,
    reserved: u8,
    /// Bumped every time this slot is filled, so a handle to a flow that is over
    /// cannot address the one that replaced it.
    generation: u32,
    /// The next slot in whichever list this entry is on: the free list while
    /// vacant, and nothing while occupied.
    link: u32,
    last_seen: u64,
    lower: DirectionState,
    upper: DirectionState,
}

impl FlowEntry {
    /// An empty slot, off every list.
    pub(crate) const VACANT: Self = Self {
        lower_address: 0,
        upper_address: 0,
        lower_port: 0,
        upper_port: 0,
        protocol: 0,
        state: FlowState::Vacant,
        flags: 0,
        reserved: 0,
        generation: 0,
        link: NO_SLOT,
        last_seen: 0,
        lower: DirectionState::SILENT,
        upper: DirectionState::SILENT,
    };

    /// Fill a vacant slot with a new flow, bumping its generation.
    ///
    /// The direction states are reset rather than kept, so nothing a previous
    /// occupant of the slot recorded can be read by the new one.
    pub(crate) fn open(
        &mut self,
        key: &FlowKey,
        origin_is_lower: bool,
        state: FlowState,
        now: Monotonic,
    ) {
        let generation = self.generation.wrapping_add(1);
        *self = Self {
            lower_address: key.lower().address.bits(),
            upper_address: key.upper().address.bits(),
            lower_port: key.lower().port,
            upper_port: key.upper().port,
            protocol: key.protocol().0,
            state,
            flags: if origin_is_lower {
                0
            } else {
                entry_flags::ORIGIN_IS_UPPER
            },
            reserved: 0,
            generation,
            link: NO_SLOT,
            last_seen: now.as_nanos(),
            lower: DirectionState::SILENT,
            upper: DirectionState::SILENT,
        };
    }

    /// Empty the slot, keeping its generation so a handle to what was here is
    /// refused rather than resolved against nothing.
    pub(crate) fn close(&mut self) {
        let generation = self.generation;
        *self = Self::VACANT;
        self.generation = generation;
    }

    #[must_use]
    pub const fn state(&self) -> FlowState {
        self.state
    }

    #[must_use]
    pub const fn generation(&self) -> u32 {
        self.generation
    }

    #[must_use]
    pub const fn is_occupied(&self) -> bool {
        !matches!(self.state, FlowState::Vacant)
    }

    /// The identity this entry holds.
    #[must_use]
    pub fn key(&self) -> FlowKey {
        // Reconstructed rather than stored twice: the canonical pair is already
        // in the fields, so re-forming it cannot disagree with them.
        let (key, _) = FlowKey::of(
            Endpoint::new(
                Ipv4Address::from_octets(self.lower_address.to_be_bytes()),
                self.lower_port,
            ),
            Endpoint::new(
                Ipv4Address::from_octets(self.upper_address.to_be_bytes()),
                self.upper_port,
            ),
            Protocol(self.protocol),
        );
        key
    }

    /// Whether this entry holds exactly the flow `key` names.
    ///
    /// Compared field by field rather than through [`key`](Self::key), because
    /// this runs once per probe and a reconstruction would form two endpoints and
    /// sort them to answer a question four integers already settle.
    pub(crate) fn matches(&self, key: &FlowKey) -> bool {
        self.lower_address == key.lower().address.bits()
            && self.upper_address == key.upper().address.bits()
            && self.lower_port == key.lower().port
            && self.upper_port == key.upper().port
            && self.protocol == key.protocol().0
    }

    /// How long this flow has been idle, saturating at zero for a `now` behind
    /// the last thing that advanced it — which is what a counter that moved
    /// backwards looks like from here.
    ///
    /// The instant itself is not exposed. `lfw_clock` gives no way to build a
    /// [`Monotonic`] from an integer, deliberately, so a stamp read back out of a
    /// memory region can only ever be an elapsed span.
    #[must_use]
    pub const fn idle_for(&self, now: Monotonic) -> Duration {
        Duration::from_nanos(now.as_nanos().saturating_sub(self.last_seen))
    }

    /// The raw stamp, which is what orders eviction. Raw because ordering it is
    /// the whole point, and an elapsed span saturated at zero orders nothing.
    pub(crate) const fn last_seen_nanos(&self) -> u64 {
        self.last_seen
    }

    pub(crate) fn touch(&mut self, now: Monotonic) {
        self.last_seen = now.as_nanos();
    }

    pub(crate) fn set_state(&mut self, state: FlowState) {
        self.state = state;
    }

    pub(crate) const fn link(&self) -> u32 {
        self.link
    }

    pub(crate) const fn set_link(&mut self, link: u32) {
        self.link = link;
    }

    /// Which direction a packet travelling from the canonical lower endpoint is.
    #[must_use]
    pub const fn direction_of_lower(&self) -> Direction {
        if self.flags & entry_flags::ORIGIN_IS_UPPER == 0 {
            Direction::Original
        } else {
            Direction::Reply
        }
    }

    /// Which direction a packet travelling towards the upper endpoint is, given
    /// which way this packet went between the canonical pair.
    #[must_use]
    pub const fn direction_of(&self, from_lower: bool) -> Direction {
        let lower = self.direction_of_lower();
        if from_lower { lower } else { lower.reversed() }
    }

    /// What the direction a packet travelled in has sent, and what the other one
    /// has, in that order.
    pub(crate) fn halves(
        &mut self,
        from_lower: bool,
    ) -> (&mut DirectionState, &mut DirectionState) {
        if from_lower {
            (&mut self.lower, &mut self.upper)
        } else {
            (&mut self.upper, &mut self.lower)
        }
    }

    /// As [`halves`](Self::halves), for a caller that only reads.
    #[must_use]
    pub const fn sides(&self, from_lower: bool) -> (&DirectionState, &DirectionState) {
        if from_lower {
            (&self.lower, &self.upper)
        } else {
            (&self.upper, &self.lower)
        }
    }

    /// What the originating direction has sent.
    #[must_use]
    pub const fn original(&self) -> &DirectionState {
        match self.direction_of_lower() {
            Direction::Original => &self.lower,
            Direction::Reply => &self.upper,
        }
    }

    /// What the replying direction has sent.
    #[must_use]
    pub const fn reply(&self) -> &DirectionState {
        match self.direction_of_lower() {
            Direction::Original => &self.upper,
            Direction::Reply => &self.lower,
        }
    }

    /// Both `FIN` facts, in the order a closing state is computed from: whether
    /// each side has closed and whether that close is acknowledged.
    pub(crate) const fn closing_facts(&self) -> (bool, bool, bool, bool) {
        (
            self.lower.seen_fin(),
            self.lower.fin_acknowledged(),
            self.upper.seen_fin(),
            self.upper.fin_acknowledged(),
        )
    }

    /// Whether both ends offered window scaling, which is the only case RFC 7323
    /// section 2.2 lets either of them use it in.
    pub(crate) const fn both_offered_scaling(&self) -> bool {
        self.lower.scale_offered() && self.upper.scale_offered()
    }

    /// Give up scaling on both sides.
    pub(crate) fn abandon_scaling(&mut self) {
        self.lower.abandon_scaling();
        self.upper.abandon_scaling();
    }
}

/// The layout the table's size is computed from and the region it will live in is
/// declared against.
///
/// Asserted rather than documented: an entry that grew past one cache line would
/// double the table's memory and put every probe across two lines, and neither is
/// visible in a passing test.
const _: () = {
    use core::mem::{align_of, offset_of, size_of};
    assert!(size_of::<FlowEntry>() == 64);
    assert!(align_of::<FlowEntry>() == 64);
    assert!(size_of::<DirectionState>() == 16);
    assert!(align_of::<DirectionState>() == 4);
    // The tuple a probe compares, at the front and inside the first quarter of
    // the line.
    assert!(offset_of!(FlowEntry, lower_address) == 0);
    assert!(offset_of!(FlowEntry, upper_address) == 4);
    assert!(offset_of!(FlowEntry, lower_port) == 8);
    assert!(offset_of!(FlowEntry, upper_port) == 10);
    assert!(offset_of!(FlowEntry, protocol) == 12);
    assert!(offset_of!(FlowEntry, state) == 13);
    assert!(offset_of!(FlowEntry, flags) == 14);
    assert!(offset_of!(FlowEntry, generation) == 16);
    assert!(offset_of!(FlowEntry, link) == 20);
    assert!(offset_of!(FlowEntry, last_seen) == 24);
    assert!(offset_of!(FlowEntry, lower) == 32);
    assert!(offset_of!(FlowEntry, upper) == 48);
    // One state per discriminant, so an occupancy table indexed by `index()`
    // cannot be short of a state.
    assert!(FlowState::ALL.len() == STATE_COUNT);
};

#[cfg(test)]
mod tests;
