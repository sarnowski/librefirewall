//! The neighbour cache: the hardware address of the next hop, learned by asking.
//!
//! # Adversary
//!
//! **Untrusted network traffic**, and this is the one structure in this crate a
//! peer *writes into*. Everything else here answers a frame and forgets it; a
//! cache entry outlives the frame that made it and decides where a later frame
//! this appliance originates is sent. An attacker that could place an entry could
//! therefore redirect the appliance's own outbound traffic — the management
//! channel included — to a station of its choosing, which is the whole of what
//! ARP poisoning is. On the management port the party doing it is the
//! **management-plane attacker**.
//!
//! # Three rules, and each removes a poisoning primitive rather than narrowing one
//!
//! * **Only a reply this end asked for is learned.** A reply naming an address no
//!   entry is waiting on changes nothing at all, which is what makes the classic
//!   unsolicited or gratuitous reply inert here rather than merely suspicious.
//!   A flood of distinct addresses therefore cannot insert a single entry: there
//!   is no request outstanding for any of them.
//! * **A resolved entry is immutable for its lifetime.** A second answer for an
//!   address already resolved does not replace the first, so an attacker cannot
//!   re-bind a live next hop by winning a later race. What that costs is stated
//!   rather than hidden: a next hop whose hardware address genuinely changes — a
//!   failover — is not followed until the entry expires, which is what bounds the
//!   cost to [`ENTRY_LIFETIME`].
//! * **The sender is judged before the payload is read.** A reply's own claim
//!   about who sent it must agree with the frame that carried it, and the address
//!   it answers for must be the one asked about. Both are the caller's checks
//!   (`Endpoint`) applied before anything reaches [`NeighbourCache::learn`], and
//!   both are counted there.
//!
//! # Nothing is queued, and that is the design rather than an omission
//!
//! A segment whose next hop is unresolved is **dropped**, with a typed reason its
//! caller acts on. Holding it would mean owning a buffer, which this crate does
//! not do anywhere — and it would be duplicating an obligation that already
//! exists one layer down: a `SYN` is recorded by the transport and re-sent under
//! RFC 6298's backoff, so the cost of dropping the first one is one
//! retransmission timeout and the cost of a queue is a buffer, a bound, and a
//! second answer to what happens when that bound is reached. The resolution runs
//! *while* the transport waits, so the retransmission finds the entry resolved.
//!
//! # Every bound is this end's own
//!
//! The table is a fixed array, the number of requests one resolution may send is
//! a constant here, and so is how long an answer is waited for and how long an
//! entry lives. None of them is a value a peer supplies or can grow, and a
//! resolution that runs out of requests is *reported* — a caller that was left
//! waiting forever would hold a dial open on an address nothing answers for.

use lfw_clock::{Duration, Monotonic};
use net_headers::{Ipv4Address, MacAddress};

/// Neighbours one port may hold at once.
///
/// A management port speaks to one next hop, so this is not sized for a subnet:
/// it is room for a re-addressing to be in progress while the old next hop's
/// entry is still alive, and for the answer to be found without a walk worth
/// measuring. It bounds nothing a peer chooses — an unsolicited reply is never
/// learned — so it is a bound on this end's own requests.
pub const NEIGHBOURS: usize = 4;

/// How long a resolved entry is used before it must be learned again.
///
/// It is the interval over which a hardware address that changed goes unnoticed,
/// which is the price of a resolved entry being immutable, and it is short enough
/// that a failover costs a minute of a management channel that re-dials anyway.
/// RFC 1122 section 2.3.2.1 asks for exactly this — a completed entry timed out
/// rather than trusted indefinitely.
pub const ENTRY_LIFETIME: Duration = Duration::from_millis(60_000);

/// How long one request waits for its answer before another is sent.
pub const REQUEST_TIMEOUT: Duration = Duration::from_millis(1_000);

/// How many requests one resolution sends before it gives up.
///
/// Three over [`REQUEST_TIMEOUT`] is three seconds of asking, which is inside the
/// transport's own give-up interval for the connection waiting on it — so a next
/// hop that answers nothing is reported here first, naming the neighbour, rather
/// than surfacing later as a connection that timed out for no stated reason.
pub const MAX_REQUESTS: u32 = 3;

/// What a caller must do about one next hop.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Resolution {
    /// The hardware address, and the frame may be addressed.
    Known(MacAddress),
    /// A request must be put on the wire. The cache has recorded that it was
    /// asked for, so a caller that fails to send it is answered `Ask` again once
    /// [`REQUEST_TIMEOUT`] has passed rather than waiting forever.
    Ask,
    /// A request is outstanding and its answer is not yet due. Nothing to send.
    Waiting,
    /// Every request went unanswered. The entry is gone, so a later attempt
    /// starts a fresh resolution — this is reported once per resolution rather
    /// than for ever, because the caller's own backoff is what decides whether to
    /// try again.
    Unreachable,
    /// The table is full of live entries, so this next hop cannot even be asked
    /// about. Unreachable while [`NEIGHBOURS`] exceeds the next hops a port has,
    /// and answered rather than asserted because a table under pressure is not a
    /// reason to fault a domain.
    NoRoom,
}

/// Why one reply did or did not become an entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Learned {
    /// It answered an outstanding request, and the entry is now resolved.
    Resolved,
    /// Nothing was waiting on this address. Not learned — see the module header
    /// on why an unsolicited reply is inert here.
    Unsolicited,
    /// The address is already resolved, and an entry is immutable for its
    /// lifetime. Not learned.
    AlreadyResolved,
    /// A reply whose sender hardware address is one no frame may be addressed to.
    NotUnicast,
}

/// What one cache has done, one field per decision.
///
/// Saturating and never reset, on `EndpointCounters`' terms: the rate of every
/// refusal below is the attacker's to choose, so a wrap would turn a sustained
/// poisoning attempt back into a small number.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NeighbourCounters {
    /// Requests this end composed, retries included.
    pub requested: u64,
    /// Replies that answered an outstanding request and became an entry.
    pub learned: u64,
    /// Replies nothing was waiting on. A number that moves at all is a station
    /// announcing itself, or one trying to place an entry.
    pub unsolicited: u64,
    /// Replies for an address already resolved, refused rather than taken. This
    /// is the re-binding attempt, counted separately from an unsolicited reply
    /// because it names a next hop the appliance is actually using.
    pub rebinding_refused: u64,
    /// Replies whose sender hardware address no frame may be addressed to.
    pub not_unicast: u64,
    /// Entries dropped because their lifetime ran out.
    pub expired: u64,
    /// Resolutions that spent every request without an answer.
    pub abandoned: u64,
    /// Next hops that could not be asked about, the table holding only live
    /// entries.
    pub no_room: u64,
}

impl NeighbourCounters {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            requested: 0,
            learned: 0,
            unsolicited: 0,
            rebinding_refused: 0,
            not_unicast: 0,
            expired: 0,
            abandoned: 0,
            no_room: 0,
        }
    }

    /// Every reply refused, which a caller compares against `learned` to see how
    /// much of what arrives on this port is trying to place an entry.
    #[must_use]
    pub const fn refused(&self) -> u64 {
        self.unsolicited
            .saturating_add(self.rebinding_refused)
            .saturating_add(self.not_unicast)
    }

    fn bump(count: &mut u64) {
        *count = count.saturating_add(1);
    }
}

/// One neighbour, in one of the two states an entry has.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    /// Asked about, and the answer is not in yet.
    Pending {
        /// When the request that is outstanding was handed to the caller.
        asked_at: Monotonic,
        /// How many have been handed over, bounded by [`MAX_REQUESTS`].
        requests: u32,
    },
    Resolved {
        mac: MacAddress,
        learned_at: Monotonic,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Neighbour {
    address: Ipv4Address,
    state: State,
}

/// The hardware addresses one port has learned, and the requests it has
/// outstanding.
///
/// Not `Copy`, and not by omission: it is the state a decision about where to
/// send a frame is taken from, so a copy would be a second, diverging answer to
/// the same question.
#[derive(Clone, Debug)]
pub struct NeighbourCache {
    entries: [Option<Neighbour>; NEIGHBOURS],
    counters: NeighbourCounters,
}

impl NeighbourCache {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: [const { None }; NEIGHBOURS],
            counters: NeighbourCounters::new(),
        }
    }

    #[must_use]
    pub const fn counters(&self) -> NeighbourCounters {
        self.counters
    }

    /// How many neighbours the cache holds, resolved or pending.
    #[must_use]
    pub fn held(&self) -> usize {
        self.entries.iter().flatten().count()
    }

    /// What to do about `address` right now, taking whatever the clock has made
    /// of the entries on the way.
    ///
    /// One call rather than an expiry sweep and a lookup, because the two answers
    /// have to be consistent: a caller that read a resolved entry and then swept
    /// it would address a frame to a hardware address the sweep had just decided
    /// was too old to use.
    pub fn resolve(&mut self, now: Monotonic, address: Ipv4Address) -> Resolution {
        self.expire(now);
        let Some(index) = self.index_of(address) else {
            return self.begin(now, address);
        };
        let Some(entry) = self.entries.get_mut(index).and_then(Option::as_mut) else {
            // Unreachable: `index_of` answered with an occupied slot. A value
            // rather than an assertion — no panic is admissible on a path a
            // peer's traffic drives — and it costs nothing, a fresh resolution
            // being the honest answer to a cache that holds nothing.
            return self.begin(now, address);
        };
        match entry.state {
            State::Resolved { mac, .. } => Resolution::Known(mac),
            State::Pending { asked_at, requests } => {
                // A `now` behind the request is not an elapsed span: the clock is
                // the caller's, and a reading that went backwards would otherwise
                // spend the whole request budget in one pass.
                if now < asked_at || now.since(asked_at) < REQUEST_TIMEOUT {
                    return Resolution::Waiting;
                }
                if requests >= MAX_REQUESTS {
                    // Reported once and then forgotten, so a later attempt is a
                    // fresh resolution rather than a permanent refusal: whether
                    // to try again is the caller's decision and its backoff.
                    self.entries.get_mut(index).map(Option::take);
                    NeighbourCounters::bump(&mut self.counters.abandoned);
                    return Resolution::Unreachable;
                }
                entry.state = State::Pending {
                    asked_at: now,
                    requests: requests.saturating_add(1),
                };
                NeighbourCounters::bump(&mut self.counters.requested);
                Resolution::Ask
            }
        }
    }

    /// Take one ARP reply: `address` claims to be at `mac`.
    ///
    /// The caller has already established that the frame was addressed to this
    /// port, that its Ethernet source is the sender the payload claims, and that
    /// the sender is an on-link unicast station. What is decided here is the one
    /// question those cannot answer: whether this end asked.
    pub fn learn(&mut self, now: Monotonic, address: Ipv4Address, mac: MacAddress) -> Learned {
        if !mac.is_unicast() {
            NeighbourCounters::bump(&mut self.counters.not_unicast);
            return Learned::NotUnicast;
        }
        self.expire(now);
        let Some(index) = self.index_of(address) else {
            NeighbourCounters::bump(&mut self.counters.unsolicited);
            return Learned::Unsolicited;
        };
        let Some(entry) = self.entries.get_mut(index).and_then(Option::as_mut) else {
            // Unreachable on `resolve`'s terms, and a refusal rather than a panic
            // for the same reason: nothing is learned from a slot that is not
            // there.
            NeighbourCounters::bump(&mut self.counters.unsolicited);
            return Learned::Unsolicited;
        };
        match entry.state {
            State::Resolved { .. } => {
                NeighbourCounters::bump(&mut self.counters.rebinding_refused);
                Learned::AlreadyResolved
            }
            State::Pending { .. } => {
                entry.state = State::Resolved {
                    mac,
                    learned_at: now,
                };
                NeighbourCounters::bump(&mut self.counters.learned);
                Learned::Resolved
            }
        }
    }

    /// Begin a resolution: take a slot and ask.
    fn begin(&mut self, now: Monotonic, address: Ipv4Address) -> Resolution {
        let Some(slot) = self.entries.iter_mut().find(|slot| slot.is_none()) else {
            NeighbourCounters::bump(&mut self.counters.no_room);
            return Resolution::NoRoom;
        };
        *slot = Some(Neighbour {
            address,
            state: State::Pending {
                asked_at: now,
                requests: 1,
            },
        });
        NeighbourCounters::bump(&mut self.counters.requested);
        Resolution::Ask
    }

    /// Drop every entry the clock has taken past its life.
    ///
    /// A `now` behind an entry's own instant leaves it alone, for the reason the
    /// transport's challenge budget treats a backwards reading that way: the
    /// clock is the caller's, and an entry read as enormously old would be
    /// dropped by a reading that went backwards rather than by time passing.
    fn expire(&mut self, now: Monotonic) {
        for slot in &mut self.entries {
            let stale = slot.as_ref().is_some_and(|entry| match entry.state {
                State::Resolved { learned_at, .. } => {
                    now >= learned_at && now.since(learned_at) >= ENTRY_LIFETIME
                }
                // A pending entry is not expired by this: its own request count is
                // what ends it, and dropping it here would restart the resolution
                // for ever instead of reporting that nothing answers.
                State::Pending { .. } => false,
            });
            if stale {
                *slot = None;
                NeighbourCounters::bump(&mut self.counters.expired);
            }
        }
    }

    fn index_of(&self, address: Ipv4Address) -> Option<usize> {
        self.entries
            .iter()
            .position(|slot| slot.as_ref().is_some_and(|entry| entry.address == address))
    }
}

impl Default for NeighbourCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests;
