//! The connection tracker: one bounded table that says whether a packet belongs
//! to a flow the appliance already knows about, and refuses it where nothing
//! establishes that it does.
//!
//! # What this is for
//!
//! A stateless filter can only permit a reply by naming it in a rule of its own,
//! which means opening the port in both directions and losing the whole value of
//! a direction. This table is what makes `Established` a thing a rule can be
//! written about: a packet is [`Outcome::New`], [`Outcome::Established`],
//! [`Outcome::Related`], or a typed refusal, and nothing else.
//!
//! # Adversary
//!
//! Two, and both reach every byte here.
//!
//! * **Untrusted network traffic.** Every field a flow is keyed and validated by
//!   is a peer's choosing, and the ICMP path reads a five-tuple out of bytes a
//!   sender copied into its own message. Nothing is believed: a segment must be
//!   inside the window its peer authorised, a flow may only be opened by a `SYN`,
//!   and an ICMP error must corroborate its quote against a flow that exists.
//! * **A connection-flood or state-exhaustion attacker.** This is the crate the
//!   threat model's denial-of-service item is about, because a table with a slot
//!   per flow is the state a flood exists to exhaust. Two bounds answer it, and
//!   both are structural rather than tuned: the table is a fixed array, and
//!   **an assured flow is never evicted to make room for a new one**. A flood of
//!   new connections therefore cannot displace legitimate traffic — when every
//!   slot the eviction scan reaches holds an assured flow, the *new* flow is
//!   refused and counted, which is the fail-closed direction.
//!
//!   A third bound is the caller's and cannot be structural here, because this
//!   table classifies before anything decides: a packet that opens a flow has
//!   taken a slot by the time a policy behind it says no. So a caller that
//!   refuses such a packet calls [`FlowTable::withdraw`], and the flow costs
//!   nothing. A caller that does not turns its own default deny into the
//!   amplifier — every refused connection attempt holding a slot is how an
//!   attacker fills a table with connections that were never permitted.
//!
//! # Strictness, and what it costs
//!
//! Every decision below is the strict one, deliberately:
//!
//! * A TCP flow is opened by a `SYN` and by nothing else. A mid-stream segment
//!   for an unknown five-tuple is refused rather than adopted, because adopting
//!   one is a way around default-deny that costs an attacker a single packet.
//!   What it costs *us* is that connections do not survive a restart of this
//!   table, which is the right side of that trade for a firewall.
//! * A segment outside the window its peer authorised is refused with its own
//!   reason, and refusing it means it cannot move a state, cannot refresh a
//!   timeout and cannot close a flow.
//! * A refused packet never touches a flow's timer. Otherwise anything that can
//!   guess a five-tuple could hold a slot open indefinitely with garbage.
//! * An ICMP error is `Related` only where its quoted datagram corroborates
//!   itself against a flow this table holds — see [`icmp`].
//!
//! # The shape of the index, and why it is chains rather than probing
//!
//! A million entries cannot be walked per packet, so the table is a hash index: a
//! power-of-two array of bucket heads, one chain per bucket, with the chain link
//! living in the entry itself. Linear probing over the same array was the
//! obvious alternative and was rejected for one reason: a generational handle
//! must name a stable slot, so the backward-shift deletion that keeps a probed
//! table tombstone-free is unavailable — it moves entries — and the tombstones
//! that remain accumulate for the life of the node, since nothing here may stop
//! to rehash a million entries. Chains delete by unlinking, so the index does not
//! degrade with churn, and they cost a quarter of the memory a tagged probe array
//! would.
//!
//! Everything reachable from a packet is bounded by a constant the peer does not
//! choose: a chain walk by [`MAX_CHAIN`], the search for a slot under pressure by
//! [`EVICTION_SCAN`], and the timeout sweep by [`SWEEP_STRIDE`]. Those two bounds
//! together are also what a corrupted region buys nothing from: a link that
//! pointed into a vacant slot or looped back on itself produces a refusal, never
//! a wrong verdict and never a hang.
//!
//! # Hashing is orientation-free, and unkeyed
//!
//! A flow and its reply hash equal, because the endpoints are sorted before the
//! key is formed ([`key`]). The hash is **not** keyed by a per-boot secret, and
//! the consequence is worth stating rather than discovering: an attacker who
//! computes tuples that collide can fill one bucket's chain and have *new* flows
//! whose keys land there refused. It cannot slow a lookup (the chain is bounded),
//! cannot reach another bucket, and cannot displace anything already established;
//! and to deny new flows generally it would have to fill the table, which is the
//! ordinary flood the paragraph above answers. Closing even that needs a keyed
//! pseudo-random function, and the workspace's one implementation of one is
//! private to `lfw_tcp::isn` — so closing it means lifting SipHash into a crate of
//! its own, which is a change to that crate rather than to this one.
//!
//! # Time comes from the caller
//!
//! Every deadline is stated against [`lfw_clock::Monotonic`], which the caller
//! reads: a crate that reached for a clock could not be driven by a host test at
//! all, and reading one is a capability a protection domain is granted. Two
//! consequences follow and neither is a defect. A clock that runs *backwards*
//! expires nothing — an elapsed span saturates at zero — so a flow survives
//! rather than being reaped early. A clock that does not advance at all expires
//! nothing either, and the table fills and then refuses, which is the fail-closed
//! direction.
//!
//! # It holds no bytes, and no pointers
//!
//! No payload, no reassembly, and nothing that is not an integer: the whole table
//! is a `#[repr(C)]` value with a declared layout, sized by one constant, meant to
//! be placed in a memory region at an address this crate never learns. That is
//! also why the size of one entry is asserted rather than left to the compiler —
//! see [`entry`].
//!
//! # One dependency points the wrong way
//!
//! [`lfw_tcp::SeqNumber`] is used for the modulo-2^32 arithmetic every window
//! comparison is stated in. Reimplementing thirty lines of RFC 793 section 3.3
//! beside a tested implementation would be worse, but the edge is still wrong:
//! a connection *tracker* has no business depending on the appliance's own
//! *endpoint*. The fix is to lift that module into a crate of its own, which is a
//! change to `lfw_tcp` rather than to this crate.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

pub mod counters;
pub mod entry;
pub mod icmp;
pub mod key;
pub mod tcp;
pub mod timeout;

use lfw_clock::Monotonic;
use net_headers::{
    ICMP_HEADER_LEN, Ipv4Address, Protocol, TCP_HEADER_LEN, Transport, UDP_HEADER_LEN,
};

pub use counters::FlowCounters;
pub use entry::{DirectionState, FlowEntry, FlowState, STATE_COUNT};
pub use icmp::QuotedError;
pub use key::{Direction, Endpoint, FlowKey};
pub use tcp::WindowEdge;
pub use timeout::timeout;

use entry::NO_SLOT;
use icmp::Message;

/// How many flows the appliance's own table holds.
///
/// The one knob. Everything else about the table's memory follows from it: the
/// bucket array is one head per flow, so the index is a power-of-two array of the
/// same length, and [`FLOW_TABLE_BYTES`] is what the region holding it must be.
///
/// # What this number costs, measured
///
/// Two boot-time costs and nothing on the packet path — a classification walks
/// one bucket's chain, which is bounded by [`MAX_CHAIN`] whatever the capacity.
/// [`FlowTable::initialise`] walks every slot, which is about 13 ms under QEMU's
/// emulated CPU; and the region is 17 409 page frames for the Microkit loader to
/// create and the kernel to zero, which costs the emulated boot about 0.9 s.
/// Halving this constant halves both, and halves how many connections the
/// appliance can carry at once — so it is a decision about the product rather
/// than about the layout, and the numbers are here so that decision is taken
/// against them.
pub const FLOW_CAPACITY: usize = 1 << 20;

/// The appliance's table, at [`FLOW_CAPACITY`].
pub type ApplianceFlowTable = FlowTable<FLOW_CAPACITY>;

/// How large a memory region must be to hold [`ApplianceFlowTable`].
///
/// Unrounded: the caller placing it knows its own mapping granularity, and a
/// second constant here rounding to a page size this crate cannot see would be a
/// number two places could disagree about.
pub const FLOW_TABLE_BYTES: usize = core::mem::size_of::<ApplianceFlowTable>();

/// How many entries one bucket's chain may hold before a new flow hashing there
/// is refused.
///
/// A bound on work per packet, derived from something no peer chooses: a lookup,
/// an unlink and an insertion each walk at most this far. At one flow per bucket
/// on average a chain this long is unreachable by chance; it is reachable by
/// chosen collisions, and reaching it costs the attacker exactly the one bucket.
pub const MAX_CHAIN: usize = 32;

/// How many slots one [`FlowTable::poll`] examines.
///
/// The table cannot be walked per packet, so timeouts are collected by a cursor
/// that advances this far each poll. What it buys is bounded work; what it costs
/// is that a slot is reclaimed up to `CAPACITY / SWEEP_STRIDE` polls after its
/// flow expired. That staleness is memory only and never correctness: a lookup
/// checks a flow's own timeout, so an expired flow is reclaimed the moment
/// anything asks about it and can never classify a packet as established.
pub const SWEEP_STRIDE: usize = 256;

/// How many slots are examined for a victim when the table is full.
///
/// The alternative — the least recently seen evictable slot in the whole table —
/// is a million-slot scan on the packet that finds the table full, which is
/// precisely the packet a flood sends. So the scan is a bounded window from a
/// rotating cursor: expired first, then the least recently seen slot in the
/// window that is not assured. Where the window holds nothing evictable the new
/// flow is refused, which is the fail-closed answer.
pub const EVICTION_SCAN: usize = 64;

/// Which flow a caller means.
///
/// A slot index alone would be a handle that silently addresses whatever flow
/// took the slot over. The generation makes that unrepresentable rather than
/// merely unlikely: the table refuses a handle whose generation is not the one it
/// issued, so a stale handle is a typed absence and never a different flow.
///
/// The generation wraps after 2^32 reuses of one slot, which at a million flows a
/// second spread over a million slots is a reuse every second and a wrap every
/// hundred and thirty-six years.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FlowId {
    slot: u32,
    generation: u32,
}

impl FlowId {
    /// The slot this handle names. Readable because a recording has to carry the
    /// identity out to an analyst, and useful to one only as the pair below: on
    /// its own it is the number that silently merges two conversations which
    /// occupied one slot at different times.
    #[must_use]
    pub const fn slot(self) -> u32 {
        self.slot
    }

    /// Which occupant of that slot, which is what makes the merge impossible.
    #[must_use]
    pub const fn generation(self) -> u32 {
        self.generation
    }
}

/// One packet, as the tracker reads it.
///
/// The transport header is the one the frame parser already decoded, rather than
/// re-parsed here: two parsers over one header are two chances to disagree about
/// what a peer sent. The bytes are still needed, for the two things a decoded
/// header does not carry — a `SYN`'s option area and the datagram an ICMP error
/// quotes.
#[derive(Clone, Copy, Debug)]
pub struct Packet<'a> {
    pub source: Ipv4Address,
    pub destination: Ipv4Address,
    pub transport: Transport,
    /// The IPv4 payload exactly as the datagram's own total length bounds it: the
    /// transport header and everything behind it, and none of the Ethernet
    /// padding.
    pub transport_bytes: &'a [u8],
}

/// What one packet is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The packet opened a flow. Only an opening move reaches this: a TCP `SYN`,
    /// a first UDP datagram, or an ICMP echo request.
    New {
        flow: FlowId,
        state: FlowState,
    },
    /// The packet advanced a flow the table holds.
    Established {
        flow: FlowId,
        direction: Direction,
        /// Where the flow stood before this packet, so a caller can tell an
        /// advance that *moved* the connection from one that only refreshed its
        /// timer. Carried rather than left to be recovered: the state before is
        /// gone by the time a caller could look, and a caller comparing against
        /// its own memory of the flow would be keeping a second copy of the
        /// table.
        previous: FlowState,
        state: FlowState,
    },
    /// An ICMP error reporting on a flow the table holds. `quoted` is the
    /// direction the datagram it quotes was travelling in, which is the opposite
    /// of the error's own.
    Related {
        flow: FlowId,
        quoted: Direction,
    },
    Refused(Refusal),
}

impl Outcome {
    /// What this outcome classified the packet as, or `None` where it refused
    /// it.
    ///
    /// The one place the two vocabularies and this enum are related: a caller
    /// counting or labelling an outcome reads it from here rather than from a
    /// second match of its own.
    #[must_use]
    pub const fn classification(self) -> Option<Classification> {
        match self {
            Self::New { .. } => Some(Classification::New),
            Self::Established { .. } => Some(Classification::Established),
            Self::Related { .. } => Some(Classification::Related),
            Self::Refused(_) => None,
        }
    }
}

/// What one packet *is*, without the flow it names.
///
/// The classified half of the vocabulary [`RefusalKind`] is the refused half of,
/// and it exists for the same reason: an [`Outcome`] carries a handle, and a
/// counter and a metric label need the category alone. [`Outcome::classification`]
/// is the one place the two are related, so an outcome added to one without the
/// other does not compile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Classification {
    /// The packet opened a flow.
    New,
    /// The packet advanced a flow the table already held.
    Established,
    /// An ICMP error reporting on a flow the table holds.
    Related,
}

impl Classification {
    /// Every classification, so a counter table and a metric's label set are
    /// built by iteration rather than by a list that drifts from the enum.
    pub const ALL: [Self; 3] = [Self::New, Self::Established, Self::Related];

    /// A stable short name, for a metric label or a report line.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::New => "new",
            Self::Established => "established",
            Self::Related => "related",
        }
    }
}

/// Why a packet is not part of any flow, without the value that refused it.
///
/// [`Refusal`] carries that value, which is what an operator needs to see one
/// packet; a counter and a metric label need the category alone, and a variant
/// carrying data cannot be enumerated in a `const` array. So the vocabulary is
/// this enum and [`Refusal::kind`] is the one place the two are related — a
/// refusal added to one without the other does not compile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefusalKind {
    UnsupportedProtocol,
    Fragment,
    Malformed,
    InvalidFlags,
    MidStream,
    InvalidState,
    OutOfWindow,
    NoSuchFlow,
    QuotedInvalid,
    UnsupportedIcmp,
    TableFull,
    BucketFull,
}

impl RefusalKind {
    /// Every kind, so a counter table and a metric's label set are built by
    /// iteration rather than by a list that drifts from the enum.
    pub const ALL: [Self; 12] = [
        Self::UnsupportedProtocol,
        Self::Fragment,
        Self::Malformed,
        Self::InvalidFlags,
        Self::MidStream,
        Self::InvalidState,
        Self::OutOfWindow,
        Self::NoSuchFlow,
        Self::QuotedInvalid,
        Self::UnsupportedIcmp,
        Self::TableFull,
        Self::BucketFull,
    ];

    /// A stable short name, for a metric label or a report line.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::UnsupportedProtocol => "unsupported_protocol",
            Self::Fragment => "fragment",
            Self::Malformed => "malformed",
            Self::InvalidFlags => "invalid_flags",
            Self::MidStream => "mid_stream",
            Self::InvalidState => "invalid_state",
            Self::OutOfWindow => "out_of_window",
            Self::NoSuchFlow => "no_such_flow",
            Self::QuotedInvalid => "quoted_invalid",
            Self::UnsupportedIcmp => "unsupported_icmp",
            Self::TableFull => "table_full",
            Self::BucketFull => "bucket_full",
        }
    }
}

/// Why a packet is not part of any flow.
///
/// Every variant carries the value that refused it, and every one maps to exactly
/// one counter, so a refusal is attributable to a byte a peer sent rather than to
/// a category.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// A protocol this tracker holds no state for.
    UnsupportedProtocol(Protocol),
    /// A non-initial fragment, which carries no transport header to key by. This
    /// tracker does not reassemble, so there is nothing it could key one by later
    /// either.
    Fragment,
    /// A datagram too short for the transport header it claims, or claiming a
    /// header longer than it carries.
    Malformed { needed: usize, got: usize },
    /// A TCP flag combination no exchange produces.
    InvalidFlags,
    /// A TCP segment for a five-tuple with no flow that was not a `SYN`.
    MidStream,
    /// A packet the flow's own state does not admit.
    InvalidState(FlowState),
    /// A segment outside the window its peer authorised.
    OutOfWindow(WindowEdge),
    /// An ICMP echo reply or error naming a flow the table does not hold.
    NoSuchFlow,
    /// An ICMP error whose quoted datagram did not corroborate its own claim.
    QuotedInvalid(QuotedError),
    /// An ICMP type this tracker neither tracks nor relates.
    UnsupportedIcmp { message_type: u8, code: u8 },
    /// No slot: every slot the eviction scan reached holds a flow that may not be
    /// taken back. The fail-closed answer to a full table.
    TableFull,
    /// One bucket's chain is full, so this key has nowhere to go even though the
    /// table has slots.
    BucketFull,
}

impl Refusal {
    /// This refusal without its value: the category a counter and a metric label
    /// are stated in.
    #[must_use]
    pub const fn kind(self) -> RefusalKind {
        match self {
            Self::UnsupportedProtocol(_) => RefusalKind::UnsupportedProtocol,
            Self::Fragment => RefusalKind::Fragment,
            Self::Malformed { .. } => RefusalKind::Malformed,
            Self::InvalidFlags => RefusalKind::InvalidFlags,
            Self::MidStream => RefusalKind::MidStream,
            Self::InvalidState(_) => RefusalKind::InvalidState,
            Self::OutOfWindow(_) => RefusalKind::OutOfWindow,
            Self::NoSuchFlow => RefusalKind::NoSuchFlow,
            Self::QuotedInvalid(_) => RefusalKind::QuotedInvalid,
            Self::UnsupportedIcmp { .. } => RefusalKind::UnsupportedIcmp,
            Self::TableFull => RefusalKind::TableFull,
            Self::BucketFull => RefusalKind::BucketFull,
        }
    }
}

/// How many flows are in each state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Occupancy([u32; STATE_COUNT]);

impl Occupancy {
    /// How many flows are in `state`. [`FlowState::Vacant`] answers how many
    /// slots are free, so the counts sum to the table's capacity.
    #[must_use]
    pub fn get(&self, state: FlowState) -> u32 {
        self.0.get(state.index()).copied().unwrap_or(0)
    }

    /// How many slots hold a flow.
    #[must_use]
    pub fn occupied(&self) -> u32 {
        self.0
            .iter()
            .enumerate()
            .filter(|(index, _)| *index != FlowState::Vacant.index())
            .fold(0, |total, (_, count)| total.saturating_add(*count))
    }
}

/// What one [`FlowTable::poll`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sweep {
    /// Slots looked at, which is [`SWEEP_STRIDE`] or the whole table where it is
    /// smaller.
    pub examined: usize,
    /// Flows whose slot was taken back.
    pub expired: usize,
}

/// The connection table.
///
/// `CAPACITY` is the caller's and must be a power of two: it fixes the memory at
/// compile time and is the bound a flood is answered by. The bucket array is one
/// head per slot, so the index and the entries are sized by the same constant.
#[repr(C, align(64))]
pub struct FlowTable<const CAPACITY: usize> {
    counters: FlowCounters,
    /// How many flows are in each state, maintained as they move so reporting
    /// occupancy costs no scan. Held to the entries themselves by
    /// `tests::the_reported_occupancy_is_the_occupancy_held`.
    occupancy: [u32; STATE_COUNT],
    /// The head of the free list, or [`NO_SLOT`].
    free_head: u32,
    sweep_cursor: u32,
    evict_cursor: u32,
    /// One chain head per bucket. A slot index rather than a pointer: the table
    /// is placed at an address it never learns.
    buckets: [u32; CAPACITY],
    entries: [FlowEntry; CAPACITY],
}

impl<const CAPACITY: usize> FlowTable<CAPACITY> {
    /// The two things the layout needs of `CAPACITY`, forced by every
    /// constructor so an inadmissible one fails to compile rather than to run.
    ///
    /// A power of two, because a bucket index is a mask rather than a division;
    /// and below [`NO_SLOT`], because that value is what a link uses to mean
    /// nothing and a table that could hold a slot with that index would have a
    /// chain end nothing could express.
    const LAYOUT: () = {
        assert!(
            CAPACITY.is_power_of_two(),
            "a flow table's capacity is a power of two: the bucket index is a mask"
        );
        assert!(
            CAPACITY < NO_SLOT as usize,
            "a flow table's capacity is below u32::MAX, which is the slot index that names none"
        );
    };

    /// The mask a bucket index is taken with.
    const MASK: usize = CAPACITY - 1;

    /// An empty table.
    ///
    /// At the appliance's own capacity this value is far too large to move, so the
    /// protection domain placing one in a memory region calls
    /// [`initialise`](Self::initialise) on it in place instead. This constructor
    /// is for a table small enough to hold.
    #[must_use]
    pub fn new() -> Self {
        let () = Self::LAYOUT;
        let mut table = Self {
            counters: FlowCounters::new(),
            occupancy: [0; STATE_COUNT],
            free_head: NO_SLOT,
            sweep_cursor: 0,
            evict_cursor: 0,
            buckets: [NO_SLOT; CAPACITY],
            entries: [FlowEntry::VACANT; CAPACITY],
        };
        table.initialise();
        table
    }

    /// Reset a table to empty, in place.
    ///
    /// This reads nothing it has not written: every field is overwritten before
    /// anything looks at it, so a region holding a previous boot's table becomes
    /// an empty one.
    ///
    /// No handle survives it. The generations restart, so a caller holding a
    /// [`FlowId`] from before must discard it — which is why this is a bring-up
    /// call and not a way to clear a running table.
    ///
    /// # The one obligation on the caller placing a table in a region
    ///
    /// A table holds [`FlowState`], which is a `#[repr(u8)]` enum, so *forming* a
    /// reference to one over bytes that are not a valid table is undefined
    /// before this or any other method runs. The obligation is therefore on
    /// whoever turns a mapped region into a `&mut Self`, and it is discharged by
    /// the region being zero-filled: `FlowState::Vacant` is discriminant zero, so
    /// every byte pattern of an all-zero region is a valid — if unlinked — table,
    /// which this call then makes a usable one. Microkit zeroes a memory region
    /// before a protection domain maps it, and Microkit is part of the trusted
    /// base; a caller placing a table anywhere else owes the same guarantee.
    pub fn initialise(&mut self) {
        let () = Self::LAYOUT;
        self.counters = FlowCounters::new();
        self.occupancy = [0; STATE_COUNT];
        if let Some(count) = self.occupancy.get_mut(FlowState::Vacant.index()) {
            // Lossless: `LAYOUT` bounds the capacity below `u32::MAX`.
            *count = CAPACITY as u32;
        }
        self.sweep_cursor = 0;
        self.evict_cursor = 0;
        for bucket in &mut self.buckets {
            *bucket = NO_SLOT;
        }
        // Built from the back, so the head is slot zero and a fresh table fills
        // from the front — which is what makes a small table's behaviour
        // readable in a test.
        let mut next = NO_SLOT;
        let mut slot = CAPACITY;
        while slot > 0 {
            slot -= 1;
            if let Some(entry) = self.entries.get_mut(slot) {
                *entry = FlowEntry::VACANT;
                entry.set_link(next);
            }
            // Lossless: bounded by the capacity.
            next = slot as u32;
        }
        self.free_head = next;
    }

    /// How many flows the table can hold.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        CAPACITY
    }

    #[must_use]
    pub const fn counters(&self) -> &FlowCounters {
        &self.counters
    }

    /// How many flows are in each state.
    #[must_use]
    pub const fn occupancy(&self) -> Occupancy {
        Occupancy(self.occupancy)
    }

    /// How many slots hold a flow.
    #[must_use]
    pub fn len(&self) -> usize {
        self.occupancy().occupied() as usize
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The flow a handle names, or `None` where its slot is empty or has been
    /// reused.
    #[must_use]
    pub fn flow(&self, id: FlowId) -> Option<&FlowEntry> {
        let entry = self.entries.get(id.slot as usize)?;
        (entry.is_occupied() && entry.generation() == id.generation).then_some(entry)
    }

    /// Classify one packet.
    ///
    /// `now` is the caller's clock. Nothing here reads one, so a table is driven
    /// entirely by what it is told the time is — including backwards, which
    /// expires nothing.
    pub fn classify(&mut self, now: Monotonic, packet: &Packet<'_>) -> Outcome {
        FlowCounters::bump(&mut self.counters.packets_seen);
        match packet.transport {
            Transport::Tcp(header) => self.classify_tcp(now, packet, &header),
            Transport::Udp(header) => {
                self.classify_udp(now, packet, header.source_port, header.destination_port)
            }
            Transport::Icmp(header) => self.classify_icmp(now, packet, &header),
            Transport::TruncatedTcp { available } => self.refuse(Refusal::Malformed {
                needed: TCP_HEADER_LEN,
                got: available,
            }),
            Transport::TruncatedUdp { available } => self.refuse(Refusal::Malformed {
                needed: UDP_HEADER_LEN,
                got: available,
            }),
            Transport::TruncatedIcmp { available } => self.refuse(Refusal::Malformed {
                needed: ICMP_HEADER_LEN,
                got: available,
            }),
            Transport::NonInitialFragment => self.refuse(Refusal::Fragment),
            Transport::Unparsed(protocol) => self.refuse(Refusal::UnsupportedProtocol(protocol)),
        }
    }

    /// Give back the slot a flow was just opened in, because whatever asked for
    /// the classification then refused the packet that opened it.
    ///
    /// # Why a tracker needs this at all
    ///
    /// A filter that runs *behind* this table sees a packet already committed to
    /// a slot, so a policy that denies the opening packet of a connection leaves
    /// the flow behind. Under default deny that is the whole of a state-
    /// exhaustion amplifier: every rejected `SYN` costs a slot, and an attacker
    /// fills the table with connections the policy already refused — turning the
    /// fail-closed answer to a flood ([`Refusal::TableFull`]) into a denial of
    /// service against traffic the policy *does* permit. So the caller that
    /// refuses a packet a classification opened a flow for withdraws that flow,
    /// and occupancy returns to where it was.
    ///
    /// Answers whether a flow was taken back. A handle whose slot is empty or
    /// has been reused answers `false` and changes nothing, on
    /// [`flow`](Self::flow)'s terms — so a caller holding a stale handle cannot
    /// destroy a flow it does not name.
    pub fn withdraw(&mut self, id: FlowId) -> bool {
        let slot = id.slot as usize;
        let names_it = self
            .entries
            .get(slot)
            .is_some_and(|entry| entry.is_occupied() && entry.generation() == id.generation);
        if !names_it {
            return false;
        }
        self.release(slot);
        FlowCounters::bump(&mut self.counters.flows_withdrawn);
        true
    }

    /// Take the expired flows in one bounded window of slots.
    ///
    /// Called as often as the caller likes; each call advances a cursor by
    /// [`SWEEP_STRIDE`] slots, so the whole table is covered every
    /// `CAPACITY / SWEEP_STRIDE` calls and no call costs more than that window.
    pub fn poll(&mut self, now: Monotonic) -> Sweep {
        let stride = SWEEP_STRIDE.min(CAPACITY);
        let start = self.sweep_cursor as usize;
        let mut expired = 0;
        for step in 0..stride {
            let slot = (start.wrapping_add(step)) & Self::MASK;
            let dead = self
                .entries
                .get(slot)
                .is_some_and(|entry| has_expired(entry, now));
            if dead {
                self.release(slot);
                FlowCounters::bump(&mut self.counters.flows_expired);
                expired += 1;
            }
        }
        // Lossless: masked into the capacity, which is below `u32::MAX`.
        self.sweep_cursor = ((start.wrapping_add(stride)) & Self::MASK) as u32;
        Sweep {
            examined: stride,
            expired,
        }
    }

    /// One TCP segment.
    fn classify_tcp(
        &mut self,
        now: Monotonic,
        packet: &Packet<'_>,
        header: &net_headers::TcpHeader,
    ) -> Outcome {
        let segment = match tcp::Segment::read(header, packet.transport_bytes) {
            Ok(segment) => segment,
            Err(tcp::SegmentError::Truncated { needed, got }) => {
                return self.refuse(Refusal::Malformed { needed, got });
            }
            Err(tcp::SegmentError::HeaderLengthInvalid { data_offset }) => {
                return self.refuse(Refusal::Malformed {
                    needed: usize::from(data_offset) * 4,
                    got: packet.transport_bytes.len(),
                });
            }
        };
        let Some(event) = tcp::event(segment.flags) else {
            return self.refuse(Refusal::InvalidFlags);
        };
        let (key, from_lower) = FlowKey::of(
            Endpoint::new(packet.source, header.source_port),
            Endpoint::new(packet.destination, header.destination_port),
            Protocol::TCP,
        );
        match self.find(now, &key) {
            Some(slot) => self.advance_tcp(now, slot, from_lower, event, &segment),
            None => {
                if !matches!(event, tcp::Event::Syn) {
                    return self.refuse(Refusal::MidStream);
                }
                self.open_tcp(now, &key, from_lower, &segment)
            }
        }
    }

    /// A `SYN` for a five-tuple the table does not hold.
    fn open_tcp(
        &mut self,
        now: Monotonic,
        key: &FlowKey,
        from_lower: bool,
        segment: &tcp::Segment,
    ) -> Outcome {
        let slot = match self.open(now, key, from_lower, FlowState::SynSent) {
            Ok(slot) => slot,
            Err(refusal) => return self.refuse(refusal),
        };
        if let Some(entry) = self.entries.get_mut(slot) {
            let (sender, peer) = entry.halves(from_lower);
            tcp::record(sender, peer, segment);
        }
        Outcome::New {
            flow: self.id_of(slot),
            state: FlowState::SynSent,
        }
    }

    /// A TCP segment for a flow the table holds.
    fn advance_tcp(
        &mut self,
        now: Monotonic,
        slot: usize,
        from_lower: bool,
        event: tcp::Event,
        segment: &tcp::Segment,
    ) -> Outcome {
        // Everything the decision needs, read in one borrow so the refusals below
        // — which take the whole table, to count themselves — need none.
        let Some((state, direction, window)) = self.entries.get(slot).map(|entry| {
            let (sender, peer) = entry.sides(from_lower);
            (
                entry.state(),
                entry.direction_of(from_lower),
                tcp::in_window(sender, peer, segment),
            )
        }) else {
            return self.refuse(Refusal::NoSuchFlow);
        };
        if !tcp::admits(state, event, direction) {
            return self.refuse(Refusal::InvalidState(state));
        }
        if let Err(edge) = window {
            return self.refuse(Refusal::OutOfWindow(edge));
        }
        let Some(next) = self.entries.get_mut(slot).map(|entry| {
            let (sender, peer) = entry.halves(from_lower);
            tcp::record(sender, peer, segment);
            // RFC 7323 section 2.2: scaling applies only where both ends offered
            // it, so the second `SYN` is where one end's silence costs both.
            if segment.flags.syn() && !entry.both_offered_scaling() {
                entry.abandon_scaling();
            }
            entry.touch(now);
            tcp::next_state(state, event, direction, entry.closing_facts())
        }) else {
            return self.refuse(Refusal::NoSuchFlow);
        };
        self.transition(slot, state, next);
        FlowCounters::bump(&mut self.counters.packets_established);
        Outcome::Established {
            flow: self.id_of(slot),
            direction,
            previous: state,
            state: next,
        }
    }

    /// One UDP datagram. There is no sequence space to validate, so the tuple is
    /// the whole of the decision and a reply is what makes the flow two-way.
    fn classify_udp(
        &mut self,
        now: Monotonic,
        packet: &Packet<'_>,
        source_port: u16,
        destination_port: u16,
    ) -> Outcome {
        let (key, from_lower) = FlowKey::of(
            Endpoint::new(packet.source, source_port),
            Endpoint::new(packet.destination, destination_port),
            Protocol::UDP,
        );
        let Some(slot) = self.find(now, &key) else {
            return match self.open(now, &key, from_lower, FlowState::UdpUnreplied) {
                Ok(slot) => {
                    self.note_traffic(slot, from_lower);
                    Outcome::New {
                        flow: self.id_of(slot),
                        state: FlowState::UdpUnreplied,
                    }
                }
                Err(refusal) => self.refuse(refusal),
            };
        };
        let Some((state, direction)) = self
            .entries
            .get(slot)
            .map(|entry| (entry.state(), entry.direction_of(from_lower)))
        else {
            return self.refuse(Refusal::NoSuchFlow);
        };
        let next = match (state, direction) {
            (FlowState::UdpUnreplied, Direction::Original) => FlowState::UdpUnreplied,
            (FlowState::UdpUnreplied, Direction::Reply) | (FlowState::UdpAssured, _) => {
                FlowState::UdpAssured
            }
            // Unreachable: the protocol is part of a flow's identity, so a UDP
            // datagram never resolves to a flow of another protocol. Refused as a
            // value rather than asserted, this being a path a peer's traffic
            // reaches.
            _ => return self.refuse(Refusal::InvalidState(state)),
        };
        self.note_traffic(slot, from_lower);
        if let Some(entry) = self.entries.get_mut(slot) {
            entry.touch(now);
        }
        self.transition(slot, state, next);
        FlowCounters::bump(&mut self.counters.packets_established);
        Outcome::Established {
            flow: self.id_of(slot),
            direction,
            previous: state,
            state: next,
        }
    }

    /// One ICMP message: an echo exchange of its own, or a report about somebody
    /// else's flow.
    fn classify_icmp(
        &mut self,
        now: Monotonic,
        packet: &Packet<'_>,
        header: &net_headers::IcmpHeader,
    ) -> Outcome {
        let Some(message) = icmp::message(header) else {
            return self.refuse(Refusal::UnsupportedIcmp {
                message_type: header.message_type,
                code: header.code,
            });
        };
        match message {
            Message::EchoRequest { identifier } => self.echo_request(now, packet, identifier),
            Message::EchoReply { identifier } => self.echo_reply(now, packet, identifier),
            Message::Error => self.icmp_error(now, packet),
        }
    }

    /// An echo request, which is the only ICMP message that opens a flow.
    fn echo_request(&mut self, now: Monotonic, packet: &Packet<'_>, identifier: u16) -> Outcome {
        let (key, from_lower) = echo_key(packet, identifier);
        let Some(slot) = self.find(now, &key) else {
            return match self.open(now, &key, from_lower, FlowState::IcmpUnreplied) {
                Ok(slot) => {
                    self.note_traffic(slot, from_lower);
                    Outcome::New {
                        flow: self.id_of(slot),
                        state: FlowState::IcmpUnreplied,
                    }
                }
                Err(refusal) => self.refuse(refusal),
            };
        };
        // A repeated request — the ordinary case of a probe sent more than once —
        // refreshes the flow and leaves its state where it was: a request is not
        // an answer, in either direction.
        self.advance_echo(now, slot, from_lower, None)
    }

    /// An echo reply, which answers a flow and never opens one.
    fn echo_reply(&mut self, now: Monotonic, packet: &Packet<'_>, identifier: u16) -> Outcome {
        let (key, from_lower) = echo_key(packet, identifier);
        let Some(slot) = self.find(now, &key) else {
            return self.refuse(Refusal::NoSuchFlow);
        };
        self.advance_echo(now, slot, from_lower, Some(FlowState::IcmpReplied))
    }

    /// Advance an echo flow, moving it to `answered` where the message was a
    /// reply travelling the way a reply travels.
    fn advance_echo(
        &mut self,
        now: Monotonic,
        slot: usize,
        from_lower: bool,
        answered: Option<FlowState>,
    ) -> Outcome {
        let Some((state, direction)) = self
            .entries
            .get(slot)
            .map(|entry| (entry.state(), entry.direction_of(from_lower)))
        else {
            return self.refuse(Refusal::NoSuchFlow);
        };
        if !matches!(state, FlowState::IcmpUnreplied | FlowState::IcmpReplied) {
            // Unreachable for the reason `classify_udp`'s last arm states.
            return self.refuse(Refusal::InvalidState(state));
        }
        // A reply travelling the same way the request did is not an answer to it:
        // the requester does not answer itself.
        if answered.is_some() && matches!(direction, Direction::Original) {
            return self.refuse(Refusal::InvalidState(state));
        }
        let next = answered.unwrap_or(state);
        self.note_traffic(slot, from_lower);
        if let Some(entry) = self.entries.get_mut(slot) {
            entry.touch(now);
        }
        self.transition(slot, state, next);
        FlowCounters::bump(&mut self.counters.packets_established);
        Outcome::Established {
            flow: self.id_of(slot),
            direction,
            previous: state,
            state: next,
        }
    }

    /// An ICMP error, which is `Related` exactly where the datagram it quotes
    /// corroborates itself. See [`icmp`] for what corroboration means and why a
    /// checksum is not part of it.
    fn icmp_error(&mut self, now: Monotonic, packet: &Packet<'_>) -> Outcome {
        let bytes = icmp::quoted_bytes(packet.transport_bytes);
        let quoted = match icmp::quoted(packet.destination, bytes) {
            Ok(quoted) => quoted,
            Err(error) => return self.refuse(Refusal::QuotedInvalid(error)),
        };
        let (key, from_lower) = FlowKey::of(
            Endpoint::new(quoted.source, quoted.source_port),
            Endpoint::new(quoted.destination, quoted.destination_port),
            quoted.protocol,
        );
        let Some(slot) = self.find(now, &key) else {
            return self.refuse(Refusal::NoSuchFlow);
        };
        let Some((direction, spoken, sequence_ok)) = self.entries.get(slot).map(|entry| {
            let (sender, peer) = entry.sides(from_lower);
            (
                entry.direction_of(from_lower),
                sender.spoken(),
                quoted_sequence_is_authorised(sender, peer, quoted.sequence),
            )
        }) else {
            return self.refuse(Refusal::NoSuchFlow);
        };
        if !spoken {
            // The quote names a direction of this flow that has carried nothing,
            // so the datagram it claims to be about never travelled.
            return self.refuse(Refusal::QuotedInvalid(QuotedError::NotFromTheReporter {
                quoted_source: quoted.source,
            }));
        }
        if let Err(edge) = sequence_ok {
            return self.refuse(Refusal::OutOfWindow(edge));
        }
        // Deliberately not touched. An error must not extend the life of the flow
        // it reports on, or anything able to forge one holds a slot open with it.
        FlowCounters::bump(&mut self.counters.packets_related);
        Outcome::Related {
            flow: self.id_of(slot),
            quoted: direction,
        }
    }

    /// The slot holding the flow `key` names, reclaiming it instead where its own
    /// timeout has elapsed.
    ///
    /// That reclamation is what makes the sweep a memory concern rather than a
    /// correctness one: an expired flow is never returned, whichever poll would
    /// eventually have collected it.
    fn find(&mut self, now: Monotonic, key: &FlowKey) -> Option<usize> {
        let bucket = self.bucket_of(key);
        let mut slot = self.buckets.get(bucket).copied().unwrap_or(NO_SLOT);
        let mut collisions = 0u64;
        let mut found = None;
        for _ in 0..MAX_CHAIN {
            if slot == NO_SLOT {
                break;
            }
            let Some(entry) = self.entries.get(slot as usize) else {
                break;
            };
            // A vacant entry is never on a chain, so reaching one is a link this
            // table did not write. Counted as a collision and stepped over, which
            // together with the bound above turns a corrupted region into a
            // refusal rather than into a wrong flow or a walk that never ends.
            if entry.is_occupied() && entry.matches(key) {
                found = Some(slot as usize);
                break;
            }
            collisions = collisions.saturating_add(1);
            slot = entry.link();
        }
        self.counters.probe_tag_collisions = self
            .counters
            .probe_tag_collisions
            .saturating_add(collisions);
        let slot = found?;
        if self.entries.get(slot).is_some_and(|e| has_expired(e, now)) {
            self.release(slot);
            FlowCounters::bump(&mut self.counters.flows_expired);
            return None;
        }
        Some(slot)
    }

    /// Take a slot, fill it with a new flow, and put it on its bucket's chain.
    ///
    /// # Errors
    /// [`Refusal::TableFull`] where nothing may be taken back, and
    /// [`Refusal::BucketFull`] where this key's chain is at its bound.
    fn open(
        &mut self,
        now: Monotonic,
        key: &FlowKey,
        origin_is_lower: bool,
        state: FlowState,
    ) -> Result<usize, Refusal> {
        let slot = self.take_slot(now)?;
        if let Some(entry) = self.entries.get_mut(slot) {
            entry.open(key, origin_is_lower, state, now);
        }
        self.record_state_change(FlowState::Vacant, state);
        if !self.link(key, slot) {
            // Nothing was linked, so the slot goes straight back and the state
            // change above is undone by the release.
            self.release(slot);
            return Err(Refusal::BucketFull);
        }
        FlowCounters::bump(&mut self.counters.flows_created);
        Ok(slot)
    }

    /// A slot for a new flow: a free one, else one taken back under pressure.
    ///
    /// # Errors
    /// [`Refusal::TableFull`], which is the fail-closed answer: an assured flow is
    /// never a candidate, so a flood of new flows cannot displace one.
    fn take_slot(&mut self, now: Monotonic) -> Result<usize, Refusal> {
        if let Some(slot) = self.pop_free() {
            return Ok(slot);
        }
        let Some((slot, was_expired)) = self.victim(now) else {
            if self.len() < CAPACITY {
                // The free list is empty and the table is not full, which is this
                // crate's own bookkeeping disagreeing with itself.
                FlowCounters::bump(&mut self.counters.internal_slot_desync);
            }
            return Err(Refusal::TableFull);
        };
        self.release(slot);
        // A flow taken back because it was over is a reaping that pressure
        // happened to trigger; one taken back early is a real eviction, and the
        // two accuse different things.
        let count = if was_expired {
            &mut self.counters.flows_expired
        } else {
            &mut self.counters.flows_evicted
        };
        FlowCounters::bump(count);
        self.pop_free().ok_or(Refusal::TableFull)
    }

    /// The slot at the head of the free list.
    fn pop_free(&mut self) -> Option<usize> {
        if self.free_head == NO_SLOT {
            return None;
        }
        let slot = self.free_head as usize;
        let next = self.entries.get(slot).map_or(NO_SLOT, FlowEntry::link);
        self.free_head = next;
        if let Some(entry) = self.entries.get_mut(slot) {
            entry.set_link(NO_SLOT);
        }
        Some(slot)
    }

    /// A slot that may be taken back, and whether its flow was already over.
    ///
    /// Bounded by [`EVICTION_SCAN`] slots from a rotating cursor. An assured flow
    /// is skipped, always: that skip is the whole of the fail-closed eviction
    /// policy, and `tests::a_flood_of_new_flows_evicts_no_established_flow` is
    /// what holds it to it.
    fn victim(&mut self, now: Monotonic) -> Option<(usize, bool)> {
        let start = self.evict_cursor as usize;
        let scan = EVICTION_SCAN.min(CAPACITY);
        let mut oldest: Option<(usize, u64)> = None;
        let mut taken = None;
        for step in 0..scan {
            let slot = (start.wrapping_add(step)) & Self::MASK;
            let Some((occupied, expired, assured, stamp)) = self.entries.get(slot).map(|entry| {
                (
                    entry.is_occupied(),
                    has_expired(entry, now),
                    entry.state().is_assured(),
                    entry.last_seen_nanos(),
                )
            }) else {
                continue;
            };
            if !occupied {
                continue;
            }
            if expired {
                taken = Some((slot, true, step.saturating_add(1)));
                break;
            }
            if assured {
                continue;
            }
            if oldest.is_none_or(|(_, best)| stamp < best) {
                oldest = Some((slot, stamp));
            }
        }
        let (slot, was_expired, advance) = match taken {
            Some(found) => found,
            None => match oldest {
                Some((slot, _)) => (slot, false, scan),
                None => {
                    // Lossless: masked into the capacity.
                    self.evict_cursor = ((start.wrapping_add(scan)) & Self::MASK) as u32;
                    return None;
                }
            },
        };
        self.evict_cursor = ((start.wrapping_add(advance)) & Self::MASK) as u32;
        Some((slot, was_expired))
    }

    /// Empty a slot: off its chain, out of the occupancy, onto the free list.
    fn release(&mut self, slot: usize) {
        self.unlink(slot);
        let state = self
            .entries
            .get(slot)
            .map_or(FlowState::Vacant, FlowEntry::state);
        self.record_state_change(state, FlowState::Vacant);
        let free_head = self.free_head;
        if let Some(entry) = self.entries.get_mut(slot) {
            entry.close();
            entry.set_link(free_head);
        }
        // Lossless: a slot index is below the capacity.
        self.free_head = slot as u32;
    }

    /// Put a filled slot on its bucket's chain, answering whether there was room.
    fn link(&mut self, key: &FlowKey, slot: usize) -> bool {
        let bucket = self.bucket_of(key);
        let head = self.buckets.get(bucket).copied().unwrap_or(NO_SLOT);
        let mut walk = head;
        let mut length = 0;
        while walk != NO_SLOT && length < MAX_CHAIN {
            let Some(entry) = self.entries.get(walk as usize) else {
                break;
            };
            walk = entry.link();
            length += 1;
        }
        if length >= MAX_CHAIN {
            return false;
        }
        if let Some(entry) = self.entries.get_mut(slot) {
            entry.set_link(head);
        }
        if let Some(cell) = self.buckets.get_mut(bucket) {
            // Lossless: a slot index is below the capacity.
            *cell = slot as u32;
        }
        true
    }

    /// Take a slot off its bucket's chain. A slot that is on none — one whose
    /// linking was refused — is left alone.
    fn unlink(&mut self, slot: usize) {
        let Some(key) = self
            .entries
            .get(slot)
            .filter(|entry| entry.is_occupied())
            .map(FlowEntry::key)
        else {
            return;
        };
        let bucket = self.bucket_of(&key);
        // Lossless: a slot index is below the capacity.
        let target = slot as u32;
        let head = self.buckets.get(bucket).copied().unwrap_or(NO_SLOT);
        let after = self.entries.get(slot).map_or(NO_SLOT, FlowEntry::link);
        if head == target {
            if let Some(cell) = self.buckets.get_mut(bucket) {
                *cell = after;
            }
            return;
        }
        let mut previous = head;
        for _ in 0..MAX_CHAIN {
            if previous == NO_SLOT {
                return;
            }
            let next = self
                .entries
                .get(previous as usize)
                .map_or(NO_SLOT, FlowEntry::link);
            if next == target {
                if let Some(entry) = self.entries.get_mut(previous as usize) {
                    entry.set_link(after);
                }
                return;
            }
            previous = next;
        }
    }

    /// Note that something travelled one way on a flow with no sequence space of
    /// its own, so a later quote naming that direction is corroborated by traffic
    /// rather than by a tuple alone.
    fn note_traffic(&mut self, slot: usize, from_lower: bool) {
        if let Some(entry) = self.entries.get_mut(slot) {
            entry.halves(from_lower).0.note_traffic();
        }
    }

    /// Move a flow to a new state, keeping the occupancy and the closure count
    /// with it. The single place a state changes.
    fn transition(&mut self, slot: usize, from: FlowState, to: FlowState) {
        if from == to {
            return;
        }
        if let Some(entry) = self.entries.get_mut(slot) {
            entry.set_state(to);
        }
        self.record_state_change(from, to);
        if is_over(to) && !is_over(from) {
            FlowCounters::bump(&mut self.counters.flows_closed);
        }
    }

    /// Move one flow between two states in the occupancy table.
    fn record_state_change(&mut self, from: FlowState, to: FlowState) {
        if from == to {
            return;
        }
        if let Some(count) = self.occupancy.get_mut(from.index()) {
            *count = count.saturating_sub(1);
        }
        if let Some(count) = self.occupancy.get_mut(to.index()) {
            *count = count.saturating_add(1);
        }
    }

    /// Count a refusal and answer with it. The single place a refusal maps to a
    /// counter, so a refusal cannot be returned without moving one.
    fn refuse(&mut self, refusal: Refusal) -> Outcome {
        let count = match refusal {
            Refusal::UnsupportedProtocol(_) => &mut self.counters.refused_unsupported_protocol,
            Refusal::Fragment => &mut self.counters.refused_fragment,
            Refusal::Malformed { .. } => &mut self.counters.refused_malformed,
            Refusal::InvalidFlags => &mut self.counters.refused_invalid_flags,
            Refusal::MidStream => &mut self.counters.refused_mid_stream,
            Refusal::InvalidState(_) => &mut self.counters.refused_invalid_state,
            Refusal::OutOfWindow(_) => &mut self.counters.refused_out_of_window,
            Refusal::NoSuchFlow => &mut self.counters.refused_no_flow,
            Refusal::QuotedInvalid(_) => &mut self.counters.refused_quoted_invalid,
            Refusal::UnsupportedIcmp { .. } => &mut self.counters.refused_unsupported_icmp,
            Refusal::TableFull => &mut self.counters.refused_table_full,
            Refusal::BucketFull => &mut self.counters.refused_bucket_full,
        };
        FlowCounters::bump(count);
        Outcome::Refused(refusal)
    }

    /// Which bucket a key's chain hangs from.
    fn bucket_of(&self, key: &FlowKey) -> usize {
        // Lossless in the direction that matters: the mask keeps the index inside
        // the array however wide a `usize` is.
        (key.hash() as usize) & Self::MASK
    }

    /// The handle for a slot as it stands.
    fn id_of(&self, slot: usize) -> FlowId {
        FlowId {
            // Lossless: a slot index is below the capacity, itself below
            // `u32::MAX`.
            slot: slot as u32,
            generation: self.entries.get(slot).map_or(0, FlowEntry::generation),
        }
    }
}

impl<const CAPACITY: usize> Default for FlowTable<CAPACITY> {
    fn default() -> Self {
        Self::new()
    }
}

/// Whether a slot holds a flow whose own state's timeout has elapsed.
///
/// A free function rather than a method, so a caller already holding a borrow of
/// the entries can ask.
fn has_expired(entry: &FlowEntry, now: Monotonic) -> bool {
    entry.is_occupied() && entry.idle_for(now) >= timeout(entry.state())
}

/// Whether a state is one a flow's own endpoints ended it in.
const fn is_over(state: FlowState) -> bool {
    matches!(state, FlowState::Closed | FlowState::TimeWait)
}

/// The key an echo message names.
///
/// The identifier stands where a port would at *both* ends, because a reply
/// echoes back the one the requester chose — so the pair sorts by address alone
/// and a request and its reply produce one key.
fn echo_key(packet: &Packet<'_>, identifier: u16) -> (FlowKey, bool) {
    FlowKey::of(
        Endpoint::new(packet.source, identifier),
        Endpoint::new(packet.destination, identifier),
        Protocol::ICMP,
    )
}

/// Whether the sequence number a quoted TCP header carried is one the direction
/// it claims was authorised to send.
///
/// The two sequence edges of an ordinary window check, applied to a single number
/// because a quote carries no length. This is the check that makes `Related`
/// cost an off-path attacker the sequence number rather than only the tuple.
///
/// # Errors
/// [`WindowEdge`], naming the edge it fell outside.
fn quoted_sequence_is_authorised(
    sender: &DirectionState,
    peer: &DirectionState,
    sequence: Option<lfw_tcp::SeqNumber>,
) -> Result<(), WindowEdge> {
    let Some(sequence) = sequence else {
        return Ok(());
    };
    if sequence.follows(sender.max_end()) {
        return Err(WindowEdge::SequenceAhead);
    }
    if sequence.precedes(sender.end().sub(peer.max_window())) {
        return Err(WindowEdge::SequenceBehind);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
