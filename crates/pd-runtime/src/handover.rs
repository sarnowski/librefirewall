//! The consumer half of the configuration handover: taking a generation a
//! publishing domain offers, and switching to it between two polls.
//!
//! # Adversary
//!
//! A byzantine neighbour protection domain. The handover region is
//! written by another domain and is mapped here read-only, which stops nothing
//! that matters: every field in it is that domain's claim, the counts may name
//! more entries than the arrays hold, and the bytes may change again while they
//! are being read. So the image is copied out before anything is decided on it,
//! and every field of the copy is checked before it becomes a table.
//!
//! # Refusing is not failing
//!
//! An image this domain will not run leaves the running configuration exactly
//! as it was and leaves the acknowledgement unwritten, so the publisher never
//! sees the generation staged and never commits it. There is no partial apply
//! and no fallback table: the configuration in force is always one a check
//! passed, and generation 0 — which forwards nothing — is what a domain that
//! has passed no check yet runs under.
//!
//! # Why the switch is a value and not a lock
//!
//! A Microkit protection domain runs one entrypoint to completion, so the
//! window between two [`RouteStage::poll`](crate::RouteStage::poll) calls is
//! one nothing else runs in. Swapping the table there is what makes a frame
//! decided entirely under one generation, and it needs no lock to be true.

use lfw_ip_endpoint::{Endpoint, EndpointError, IsnSecret};
use lfw_log::{Event, RejectReason};
use lfw_metrics::{InterfaceInfo, InterfaceInventory};
use net_headers::{Ipv4Address, MacAddress};
use routing::{CapacityError, Interface, Neighbour, PortId, Router};
use wire::{
    CheckedConfig, ConfigAck, ConfigHandover, ConfigImage, ConfigImageError, MAX_INTERFACES,
    MAX_NEIGHBOURS,
};

use crate::Configuration;

/// Build the forwarding table a checked image describes.
///
/// The intermediate buffers are sized by the image ABI and the result by the
/// caller's own capacity, so a domain with less room than the ABI allows is
/// refused an image it could not hold rather than handed a table cut to fit.
///
/// # Errors
/// [`CapacityError`], when the image names more entries than `MAX_I` or `MAX_N`
/// hold.
pub fn router_from<const MAX_I: usize, const MAX_N: usize>(
    checked: &CheckedConfig,
) -> Result<Router<MAX_I, MAX_N>, CapacityError> {
    let mut interfaces = [Interface::UNUSED; MAX_INTERFACES];
    let mut written = 0usize;
    for (slot, entry) in interfaces.iter_mut().zip(checked.interfaces()) {
        *slot = Interface {
            port: PortId(entry.port()),
            mac: MacAddress(entry.mac()),
            address: Ipv4Address::from_octets(entry.address()),
            prefix_length: entry.prefix_length(),
            enabled: entry.enabled(),
        };
        written = written.saturating_add(1);
    }
    let filled_interfaces = interfaces.get(..written).ok_or(CapacityError::Interfaces {
        requested: written,
        capacity: MAX_INTERFACES,
    })?;

    let mut neighbours = [Neighbour::UNUSED; MAX_NEIGHBOURS];
    let mut written = 0usize;
    for (slot, entry) in neighbours.iter_mut().zip(checked.neighbours()) {
        *slot = Neighbour {
            port: PortId(entry.port()),
            address: Ipv4Address::from_octets(entry.address()),
            mac: MacAddress(entry.mac()),
        };
        written = written.saturating_add(1);
    }
    let filled_neighbours = neighbours.get(..written).ok_or(CapacityError::Neighbours {
        requested: written,
        capacity: MAX_NEIGHBOURS,
    })?;

    Router::from_slices(filled_interfaces, filled_neighbours)
}

/// The interface identities a checked image names, as the metric surface reports
/// them.
///
/// Every field comes out of the image except the `domain` each entry joins on,
/// which [`lfw_metrics::port_domain`] supplies from the port — a cross-artifact
/// build-time hardware fact no configuration carries. An interface whose port has no
/// driver is left out rather than reported under a wrong domain; the image's own
/// reader has already refused one, so it is unreachable from a commit.
#[must_use]
pub fn interfaces_from(checked: &CheckedConfig) -> InterfaceInventory {
    let mut inventory = InterfaceInventory::EMPTY;
    for entry in checked.interfaces() {
        let Some(info) = InterfaceInfo::dataplane(
            entry.port(),
            entry.id(),
            entry.address(),
            entry.prefix_length(),
            entry.mac(),
        ) else {
            continue;
        };
        // `MAX_INTERFACES` plus the management entry is exactly the inventory's
        // capacity, so this is unreachable — and dropped rather than asserted,
        // nothing about a metric being worth faulting a domain over.
        if inventory.push(info).is_err() {
            return inventory;
        }
    }
    if let Some(management) = checked.management() {
        let info = InterfaceInfo::management(
            management.address(),
            management.prefix_length(),
            management.mac(),
        );
        let _ = inventory.push(info);
    }
    inventory
}

/// Build the endpoint a checked image addresses the management port with, or
/// `None` where it addresses none.
///
/// [`Endpoint::new`] takes nothing on trust from the domain that published the
/// image, and today can refuse nothing it is handed: every pair
/// [`EndpointError`] names is one `ConfigImage::check` has already refused. The
/// call stays because that is a fact about the two rule sets together rather
/// than about this function, and either may move.
///
/// # Errors
/// [`EndpointError`], for a pair no endpoint can answer under.
pub fn endpoint_from(
    checked: &CheckedConfig,
    secret: IsnSecret,
) -> Result<Option<Endpoint>, EndpointError> {
    let Some(management) = checked.management() else {
        return Ok(None);
    };
    Endpoint::new(
        MacAddress(management.mac()),
        Ipv4Address::from_octets(management.address()),
        management.prefix_length(),
        secret,
    )
    .map(Some)
}

/// Why an offered image was refused, in the vocabulary a console line speaks,
/// and the one number that locates it.
///
/// The reader's errors are finer than the console's reasons because the reader
/// is naming a field and the record is naming something to go and fix.
fn refusal(error: ConfigImageError) -> (RejectReason, u32) {
    // Every `index` below came from enumerating an array of at most
    // `MAX_NEIGHBOURS` slots inside `ConfigImage::check`, so the narrowing is
    // over a value bounded by this build rather than by the writer of the
    // region; a `count` is already `u32`.
    match error {
        ConfigImageError::InterfaceCountExceedsCapacity { count }
        | ConfigImageError::NeighbourCountExceedsCapacity { count } => {
            (RejectReason::CapacityExceeded, count)
        }
        // An id no reader will take is a malformed value like any other; the
        // fault it names is finer than the console's vocabulary and is not carried.
        ConfigImageError::InterfaceEnabledNotBoolean { index, .. }
        | ConfigImageError::InterfaceIdNotAnIdentifier { index, .. } => {
            (RejectReason::MalformedValue, index as u32)
        }
        ConfigImageError::InterfacePortUnknown { index, .. }
        | ConfigImageError::NeighbourPortUnknown { index, .. } => {
            (RejectReason::PortOutOfRange, index as u32)
        }
        ConfigImageError::InterfacePrefixLengthTooLong { index, .. } => {
            (RejectReason::PrefixLengthOutOfRange, index as u32)
        }
        // A duplicated MAC shares the console's `mac-not-unicast` token, as the
        // management/interface collision already does: an L2 address two ports
        // answer to is not one either of them can be addressed at.
        ConfigImageError::InterfaceMacNotUnicast { index, .. }
        | ConfigImageError::NeighbourMacNotUnicast { index, .. }
        | ConfigImageError::InterfaceMacDuplicated { index, .. } => {
            (RejectReason::MacNotUnicast, index as u32)
        }
        ConfigImageError::InterfaceAddressNotUnicast { index, .. }
        | ConfigImageError::NeighbourAddressNotUnicast { index, .. } => {
            (RejectReason::AddressNotUnicast, index as u32)
        }
        ConfigImageError::InterfaceAddressNotAHostAddress { index, .. }
        | ConfigImageError::NeighbourAddressNotAHostAddress { index, .. } => {
            (RejectReason::AddressNotAHostAddress, index as u32)
        }
        ConfigImageError::InterfaceIdDuplicated { index, .. } => {
            (RejectReason::DuplicateIdentifier, index as u32)
        }
        ConfigImageError::InterfacePortDuplicated { index, .. } => {
            (RejectReason::DuplicatePort, index as u32)
        }
        ConfigImageError::InterfacePrefixesOverlap { index, .. } => {
            (RejectReason::OverlappingPrefixes, index as u32)
        }
        // A port no interface addresses is the image's spelling of the
        // document's dangling `interface` reference: the resolution the
        // validator made is the port, so this is that reference not resolving.
        ConfigImageError::NeighbourPortUnconfigured { index, .. } => {
            (RejectReason::UnknownInterfaceReference, index as u32)
        }
        ConfigImageError::NeighbourOutsidePrefix { index, .. } => {
            (RejectReason::NeighbourOutsidePrefix, index as u32)
        }
        ConfigImageError::NeighbourIsInterfaceAddress { index, .. } => {
            (RejectReason::NeighbourIsInterfaceAddress, index as u32)
        }
        ConfigImageError::NeighbourAddressDuplicated { index, .. } => {
            (RejectReason::DuplicateNeighbourAddress, index as u32)
        }
        // No index: an image holds one entry, so the number that locates the
        // fault is the value refused — except for the two collisions, which are
        // located by the interface they collided with.
        ConfigImageError::ManagementEnabledNotBoolean { enabled } => {
            (RejectReason::MalformedValue, u32::from(enabled))
        }
        ConfigImageError::ManagementPrefixLengthTooLong { prefix_length } => (
            RejectReason::PrefixLengthOutOfRange,
            u32::from(prefix_length),
        ),
        ConfigImageError::ManagementMacNotUnicast { mac } => {
            let [first, ..] = mac;
            (RejectReason::MacNotUnicast, u32::from(first))
        }
        ConfigImageError::ManagementAddressNotUnicast { address } => {
            (RejectReason::AddressNotUnicast, u32::from_be_bytes(address))
        }
        ConfigImageError::ManagementAddressNotAHostAddress { address } => (
            RejectReason::AddressNotAHostAddress,
            u32::from_be_bytes(address),
        ),
        ConfigImageError::ManagementPrefixCollidesWithInterface { index } => {
            (RejectReason::OverlappingPrefixes, index as u32)
        }
        ConfigImageError::ManagementMacCollidesWithInterface { index } => {
            (RejectReason::MacNotUnicast, index as u32)
        }
    }
}

/// What one pass over the handover region did with the generation it found.
/// "Nothing to answer" is absent from it, being `take_offer`'s `None`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Offer {
    /// Checked, built into a table, and acknowledged. The publisher has to be
    /// told, because it commits nothing until every consumer has.
    Staged { generation: u32 },
    /// The image was refused. Nothing was staged and nothing was acknowledged,
    /// so the publisher will not commit this generation.
    Refused {
        generation: u32,
        reason: RejectReason,
        /// The number `reason` names: which entry was refused, how many the
        /// image claimed, or the generation it labelled itself with.
        detail: u32,
    },
}

impl Offer {
    /// The record of this pass, where there is one.
    ///
    /// Staging is silent on purpose: it is the first half of a two-phase
    /// commit, the console vocabulary has no outcome that means "taken but not
    /// yet running", and a generation that reaches the dataplane says so when
    /// it does. What must never be silent is the refusal.
    #[must_use]
    pub const fn event(self) -> Option<Event> {
        match self {
            Self::Staged { .. } => None,
            Self::Refused {
                generation,
                reason,
                detail,
            } => Some(Event::ConfigRejected {
                generation,
                reason,
                offset: detail,
            }),
        }
    }
}

/// The publishing half of the handover: it offers one generation and releases
/// it once the consumer has acknowledged staging it.
///
/// Two phases rather than one because a consumer needs somewhere to fail: it
/// re-checks every field of an image and may refuse it, and a publisher that
/// committed as it offered would have moved the configuration forward on a
/// generation nobody is able to run.
///
/// One consumer, because the system has one. The type takes the single
/// [`ConfigAck`] region that consumer writes; a second consumer is a second
/// region, and "every consumer has staged" becomes a conjunction over them
/// rather than the one comparison below.
#[derive(Clone, Copy, Debug, Default)]
pub struct ConfigPublisher {
    /// The generation on offer, or zero while nothing has been offered —
    /// generation 0 being the fail-closed configuration nobody publishes.
    offered: u32,
}

/// Why an offer was not made: its generation was not newer than the one already
/// on offer.
///
/// A type rather than prose because the consumer's half of the handshake depends
/// on it: a consumer that has judged the number on offer does not look again, so
/// re-offering a corrected image under a generation it has seen is invisible to
/// it and the handshake stalls there for good. Retrying *is* bumping the
/// generation, and this is what makes that a returned error rather than a
/// silence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StaleOffer {
    /// The generation still on offer, which the region is untouched by this.
    pub offered: u32,
    pub refused: u32,
}

impl ConfigPublisher {
    #[must_use]
    pub const fn new() -> Self {
        Self { offered: 0 }
    }

    #[must_use]
    pub const fn offered(&self) -> u32 {
        self.offered
    }

    /// Write `image` into the region and offer its generation.
    ///
    /// Returns the generation offered, which is the image's own: the offered
    /// word and the bytes are published by one call, so a generation whose
    /// bytes are not yet in the region cannot be named.
    ///
    /// # Errors
    /// [`StaleOffer`], leaving the region exactly as it was. Monotonicity is
    /// what lets [`Self::take_acknowledgement`] key a commit on equality: an
    /// offer that could move backwards would let an acknowledgement of a newer
    /// generation release an older one.
    pub fn offer(
        &mut self,
        handover: &ConfigHandover,
        image: &ConfigImage,
    ) -> Result<u32, StaleOffer> {
        if image.generation <= self.offered {
            return Err(StaleOffer {
                offered: self.offered,
                refused: image.generation,
            });
        }
        handover.publish(image);
        self.offered = image.generation;
        Ok(self.offered)
    }

    /// Release the offered generation if the consumer has staged **that** one.
    ///
    /// Returns the generation released, once. `None` while nothing is offered,
    /// while the consumer has not staged it — which is also what a refusal
    /// looks like, the consumer never acknowledging what it will not run — or
    /// once it has already been released.
    ///
    /// Equality rather than "at least": an acknowledgement names the generation
    /// the consumer staged, and staging a *different* one is not consent to
    /// commit this one. [`Self::offer`] refusing to go backwards makes the two
    /// spellings agree in every reachable case; the comparison holds here so
    /// this half does not rest on the other.
    pub fn take_acknowledgement(
        &mut self,
        handover: &ConfigHandover,
        ack: &ConfigAck,
    ) -> Option<u32> {
        if self.offered == 0 || handover.committed_generation() >= self.offered {
            return None;
        }
        if ack.staged_generation() != self.offered {
            return None;
        }
        handover.publish_committed(self.offered);
        Some(self.offered)
    }
}

/// Counts of what the handover protocol did, which is otherwise invisible: a
/// publisher offering images this domain will not run looks exactly like a
/// publisher that has stopped offering any.
///
/// Monotonic and saturating, as [`PoolCounters`](crate::PoolCounters) explains.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ConfigCounters {
    /// Generations this domain switched to. Generation 0 is not among them: it
    /// is what the domain starts under rather than something it applied.
    pub applied: u64,
    /// Offered images refused, one per offer rather than per pass over it,
    /// each leaving the running configuration exactly as it was.
    pub refused: u64,
}

/// The configuration a forwarding domain decides under, and the protocol that
/// replaces it.
///
/// `MAX_I` and `MAX_N` are this domain's own capacity, deliberately not read
/// from the region: an image naming more entries than the domain can hold is
/// refused by a bound the writer of that region does not choose.
#[derive(Clone, Copy, Debug)]
pub struct ConfigurationSwitch<const MAX_I: usize, const MAX_N: usize> {
    active: Router<MAX_I, MAX_N>,
    active_generation: u32,
    staged: Option<(u32, Router<MAX_I, MAX_N>)>,
    /// The offered generation the last pass judged. A refusal advances neither
    /// field above — the number stays free — so nothing else records it.
    considered: u32,
    /// How many dataplane ports this domain is wired to. Held here rather than
    /// taken from the image, so the port a table names is checked against what
    /// the system description actually built.
    ports: u8,
    counters: ConfigCounters,
}

impl<const MAX_I: usize, const MAX_N: usize> ConfigurationSwitch<MAX_I, MAX_N> {
    /// Fail closed: generation 0, which forwards nothing, and no candidate.
    #[must_use]
    pub const fn new(ports: u8) -> Self {
        Self {
            active: Router::empty(),
            active_generation: 0,
            staged: None,
            considered: 0,
            ports,
            counters: ConfigCounters {
                applied: 0,
                refused: 0,
            },
        }
    }

    /// The generation every subsequent poll decides under.
    #[must_use]
    pub const fn generation(&self) -> u32 {
        self.active_generation
    }

    #[must_use]
    pub const fn counters(&self) -> ConfigCounters {
        self.counters
    }

    /// What a poll is handed: the table and the generation that produced it,
    /// paired where the pairing can still be got right.
    #[must_use]
    pub const fn configuration(&self) -> Configuration<'_, MAX_I, MAX_N> {
        Configuration::new(self.active_generation, &self.active)
    }

    /// Take whatever the publisher is offering that this domain has not already
    /// taken or already judged, acknowledging it on success.
    ///
    /// The image is copied out of the region before a field of it is looked at:
    /// a decision made on bytes the publisher may rewrite underneath it is no
    /// decision at all. One offer costs one read and yields one outcome however
    /// often this is called, which is what puts a refusal on the publisher's
    /// rate and not on the caller's polling rate — the console, which carries
    /// system state only, rests on that. A re-write under the word already on offer is therefore not an
    /// offer this side can read.
    ///
    /// The generation acknowledged is the *offered* word and never the label
    /// inside the image, the two being separate claims of the same publisher: a
    /// commit is keyed on the word, so acknowledging anything else would leave
    /// the publisher waiting for an acknowledgement that never arrives.
    pub fn take_offer(&mut self, handover: &ConfigHandover, ack: &ConfigAck) -> Option<Offer> {
        let offered = handover.offered_generation();
        if offered <= self.highest_taken() || offered == self.considered {
            return None;
        }
        self.considered = offered;
        let image = handover.load_image();
        let refuse = |reason, detail| {
            Some(Offer::Refused {
                generation: offered,
                reason,
                detail,
            })
        };
        let outcome = match image.check(self.ports) {
            Err(error) => {
                let (reason, detail) = refusal(error);
                refuse(reason, detail)
            }
            Ok(checked) => match router_from(&checked) {
                Err(_) => refuse(RejectReason::CapacityExceeded, offered),
                Ok(table) => {
                    self.staged = Some((offered, table));
                    ack.publish_staged(offered);
                    Some(Offer::Staged {
                        generation: offered,
                    })
                }
            },
        };
        if matches!(outcome, Some(Offer::Refused { .. })) {
            self.counters.refused = self.counters.refused.saturating_add(1);
        }
        outcome
    }

    /// Switch to the staged generation once the publisher has released it,
    /// which is the point between two polls this type exists to be.
    ///
    /// Returns the generation now in force, or `None` while there is nothing
    /// staged or the publisher has not committed it.
    pub fn take_commit(&mut self, handover: &ConfigHandover, ack: &ConfigAck) -> Option<u32> {
        let (generation, table) = self.staged?;
        if handover.committed_generation() < generation {
            return None;
        }
        self.active = table;
        self.active_generation = generation;
        self.staged = None;
        ack.publish_running(generation);
        self.counters.applied = self.counters.applied.saturating_add(1);
        Some(generation)
    }

    /// The newest generation this domain has committed itself to, staged or
    /// running.
    const fn highest_taken(&self) -> u32 {
        match self.staged {
            Some((generation, _)) => generation,
            None => self.active_generation,
        }
    }
}

/// The read-only consumer of the handover: it takes the **committed**
/// generation and nothing else.
///
/// A strictly weaker role than [`ConfigurationSwitch`], and the difference is
/// the point: that type reads the *offered* generation, stages from it and writes
/// the acknowledgement a commit waits for. This one never reads `offered`, so it
/// cannot be handed a generation nobody released; never writes, so it needs no
/// [`ConfigAck`] region and cannot forge that acknowledgement — the management
/// domain is granted `cfg` read-only and `cfgack` not at all; and cannot delay a
/// commit, an image it refuses being one the *forwarder* has already staged. The
/// cost: it learns of a commit only when something else next wakes it — for the
/// management port, the next frame that arrives.
#[derive(Clone, Copy, Debug, Default)]
pub struct CommittedReader {
    taken: u32,
}

/// What one pass over the committed generation found. `None` from
/// [`CommittedReader::take`] is "nothing newer", which is not one of these.
#[expect(
    clippy::large_enum_variant,
    reason = "boxing needs an allocator; the value is a temporary destructured at once"
)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Committed {
    Image {
        generation: u32,
        checked: CheckedConfig,
    },
    /// The committed image was refused. Nothing this reader had is replaced:
    /// refusing an image is not a reason to forget the one in force.
    Refused {
        generation: u32,
        reason: RejectReason,
        detail: u32,
    },
}

impl CommittedReader {
    #[must_use]
    pub const fn new() -> Self {
        Self { taken: 0 }
    }

    /// The newest committed generation this reader has taken, or 0 while it has
    /// taken none — generation 0 being the fail-closed configuration.
    #[must_use]
    pub const fn generation(&self) -> u32 {
        self.taken
    }

    /// Take the committed generation, once, if it is newer than the last one
    /// taken.
    ///
    /// The image is copied out of the region before a field of it is looked at,
    /// on [`ConfigurationSwitch::take_offer`]'s terms: the publisher may rewrite
    /// the bytes at any moment, so a decision made on them in place is no
    /// decision. One commit yields one outcome however often this is called,
    /// which is what puts a refusal on the publisher's rate rather than on the
    /// caller's polling rate.
    ///
    /// `ports` is the caller's own port count, so an image naming a port this
    /// build has no driver for is refused by a bound the publisher does not
    /// choose.
    pub fn take(&mut self, handover: &ConfigHandover, ports: u8) -> Option<Committed> {
        let generation = handover.committed_generation();
        if generation <= self.taken {
            return None;
        }
        self.taken = generation;
        match handover.load_image().check(ports) {
            Ok(checked) => Some(Committed::Image {
                generation,
                checked,
            }),
            Err(error) => {
                let (reason, detail) = refusal(error);
                Some(Committed::Refused {
                    generation,
                    reason,
                    detail,
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lfw_metrics::Role;
    use proptest::prelude::*;
    use wire::{IdentifierImage, InterfaceImage, NeighbourImage};

    const PORTS: u8 = 2;

    type Switch = ConfigurationSwitch<MAX_INTERFACES, MAX_NEIGHBOURS>;

    /// The interface on `port`, distinct from every other in each field a rule
    /// compares: its own port, MAC, `/24` and id. The id carries the port
    /// because two interfaces under one identity is a refusal rather than a
    /// fixture.
    fn interface(port: u8, last: u8) -> InterfaceImage {
        InterfaceImage {
            port,
            enabled: 1,
            prefix_length: 24,
            _pad: [0; 1],
            mac: [0x52, 0x54, 0x00, 0x12, 0x34, 0x50 + port],
            _pad2: [0; 2],
            address: [10, 0, port, last],
            id: IdentifierImage::from_text(&[
                b'd',
                b'a',
                b't',
                b'a',
                b'p',
                b'l',
                b'a',
                b'n',
                b'e',
                b'-',
                b'0' + port,
            ]),
        }
    }

    fn neighbour(port: u8) -> NeighbourImage {
        NeighbourImage {
            port,
            _pad: [0; 3],
            mac: [0x52, 0x54, 0x00, 0x00, 0x00, 0x0a + port],
            _pad2: [0; 2],
            address: [10, 0, port, 2],
        }
    }

    /// A two-port image of the shape the appliance actually runs.
    fn image(generation: u32) -> ConfigImage {
        let mut image = ConfigImage {
            generation,
            interface_count: 2,
            neighbour_count: 2,
            content_hash: 7,
            ..ConfigImage::ZERO
        };
        image.interfaces[0] = interface(0, 1);
        image.interfaces[1] = interface(1, 1);
        image.neighbours[0] = neighbour(0);
        image.neighbours[1] = neighbour(1);
        image
    }

    /// The two regions a consumer sits between.
    fn regions() -> (ConfigHandover, ConfigAck) {
        (ConfigHandover::zero(), ConfigAck::zero())
    }

    /// The management addressing the shipped document names, so the inventory
    /// tests are stated against a real document rather than a shape.
    fn management_image() -> wire::ManagementImage {
        wire::ManagementImage {
            enabled: 1,
            prefix_length: 24,
            _pad: [0; 2],
            mac: [0x52, 0x54, 0x00, 0x12, 0x34, 0x52],
            _pad2: [0; 2],
            address: [10, 0, 2, 15],
        }
    }

    fn checked(image: &ConfigImage) -> CheckedConfig {
        image.check(PORTS).expect("a valid image")
    }

    /// Every label of every info series is the document's own value, and the
    /// `domain` each joins on is the driver of the port the document put that
    /// interface on. Nothing here is derived from a build constant except that
    /// domain, which no configuration carries.
    #[test]
    fn the_inventory_reports_each_configured_interface_under_its_ports_driver() {
        let mut raw = image(1);
        raw.management = management_image();
        let inventory = interfaces_from(&checked(&raw));

        let entries: Vec<_> = inventory.entries().copied().collect();
        assert_eq!(entries.len(), 3);

        assert_eq!(entries[0].domain(), "nic_driver0");
        assert_eq!(entries[0].interface().as_str(), "dataplane-0");
        assert_eq!(entries[0].role(), Role::Dataplane);
        assert_eq!(entries[0].address(), [10, 0, 0, 1]);
        assert_eq!(entries[0].prefix_length(), 24);
        assert_eq!(entries[0].mac(), [0x52, 0x54, 0x00, 0x12, 0x34, 0x50]);

        assert_eq!(entries[1].domain(), "nic_driver1");
        assert_eq!(entries[1].interface().as_str(), "dataplane-1");
        assert_eq!(entries[1].role(), Role::Dataplane);
        assert_eq!(entries[1].address(), [10, 0, 1, 1]);

        assert_eq!(entries[2].domain(), "nic_driver2");
        assert_eq!(entries[2].interface().as_str(), "management");
        assert_eq!(entries[2].role(), Role::Management);
        assert_eq!(entries[2].address(), [10, 0, 2, 15]);
        assert_eq!(entries[2].prefix_length(), 24);
        assert_eq!(entries[2].mac(), [0x52, 0x54, 0x00, 0x12, 0x34, 0x52]);
    }

    /// Generation 0 configures nothing, so it reports nothing: an info series for
    /// a port with no addressing would name an interface the node does not have.
    #[test]
    fn the_fail_closed_generation_reports_no_interface() {
        assert!(interfaces_from(&checked(&ConfigImage::ZERO)).is_empty());
    }

    /// A document that addresses no management port leaves the dataplane series
    /// alone: the management entry is a separate element, and its absence is a
    /// port that answers nothing rather than a configuration that is incomplete.
    #[test]
    fn a_document_addressing_no_management_port_reports_only_its_dataplane_interfaces() {
        let inventory = interfaces_from(&checked(&image(1)));
        assert_eq!(inventory.len(), 2);
        assert!(
            inventory
                .entries()
                .all(|info| info.role() == Role::Dataplane)
        );
    }

    /// The identity travels from the document's own text, so two documents that
    /// name the same ports differently produce different series. This is the host
    /// half of what the QEMU gate asserts against a real scrape.
    #[test]
    fn a_renamed_interface_is_reported_under_its_new_name() {
        let mut raw = image(1);
        raw.interfaces[0].id = IdentifierImage::from_text(b"uplink");
        raw.interfaces[1].id = IdentifierImage::from_text(b"downlink");
        let inventory = interfaces_from(&checked(&raw));
        let names: Vec<String> = inventory
            .entries()
            .map(|info| String::from(info.interface().as_str()))
            .collect();
        assert_eq!(names, ["uplink", "downlink"]);
    }

    proptest! {
        /// Whatever a checked image holds, the inventory reports one entry per
        /// interface it names plus the management one, never more than the
        /// exposition is sized for, and every entry's `domain` is the driver of
        /// the port that entry sits on.
        #[test]
        fn the_inventory_is_bounded_and_attributes_every_entry_to_its_port(
            // One interface per port, so this build's two ports bound how many
            // a *checked* image can carry however many slots the ABI holds. The
            // exposition's own bound is asserted below and is the wider one.
            count in 0usize..=usize::from(PORTS),
            management in any::<bool>(),
        ) {
            let mut raw = ConfigImage {
                interface_count: count as u32,
                ..ConfigImage::ZERO
            };
            for (index, slot) in raw.interfaces.iter_mut().enumerate() {
                *slot = interface(index as u8, 1);
            }
            if management {
                raw.management = management_image();
            }
            let inventory = interfaces_from(&checked(&raw));
            prop_assert_eq!(inventory.len(), count + usize::from(management));
            prop_assert!(inventory.len() <= lfw_metrics::MAX_INTERFACE_SERIES);
            for info in inventory.entries() {
                match info.role() {
                    Role::Management => prop_assert_eq!(
                        info.domain(),
                        lfw_metrics::MANAGEMENT_PORT_DOMAIN
                    ),
                    Role::Dataplane => prop_assert!(
                        lfw_metrics::PORT_DOMAINS.contains(&info.domain())
                    ),
                }
            }
        }
    }

    #[test]
    fn a_fresh_switch_forwards_nothing_under_generation_zero() {
        let switch = Switch::new(PORTS);
        assert_eq!(switch.generation(), 0);
        assert_eq!(switch.counters(), ConfigCounters::default());
        let configuration = switch.configuration();
        assert_eq!(configuration.generation(), 0);
        // The table with no interface and no neighbour: the absence of policy,
        // which is the only compiled-in configuration this domain has.
        assert_eq!(*configuration.table(), Router::empty());
    }

    #[test]
    fn an_untouched_region_offers_nothing_to_take() {
        let (handover, ack) = regions();
        let mut switch = Switch::new(PORTS);
        assert_eq!(switch.take_offer(&handover, &ack), None);
        assert_eq!(switch.take_commit(&handover, &ack), None);
        assert_eq!(switch.generation(), 0);
    }

    #[test]
    fn a_generation_is_staged_acknowledged_and_only_then_switched_to() {
        let (handover, ack) = regions();
        let mut switch = Switch::new(PORTS);
        handover.publish(&image(1));

        assert_eq!(
            switch.take_offer(&handover, &ack),
            Some(Offer::Staged { generation: 1 })
        );
        assert_eq!(ack.staged_generation(), 1);
        // Staged is not running: the publisher has not released it.
        assert_eq!(switch.generation(), 0);
        assert_eq!(ack.running_generation(), 0);
        assert_eq!(switch.take_commit(&handover, &ack), None);

        handover.publish_committed(1);
        assert_eq!(switch.take_commit(&handover, &ack), Some(1));
        assert_eq!(switch.generation(), 1);
        assert_eq!(ack.running_generation(), 1);
        assert_eq!(switch.counters().applied, 1);
    }

    #[test]
    fn a_generation_already_taken_is_not_taken_twice() {
        let (handover, ack) = regions();
        let mut switch = Switch::new(PORTS);
        handover.publish(&image(1));
        assert!(switch.take_offer(&handover, &ack).is_some());
        assert_eq!(switch.take_offer(&handover, &ack), None);
        handover.publish_committed(1);
        assert_eq!(switch.take_commit(&handover, &ack), Some(1));
        assert_eq!(switch.take_commit(&handover, &ack), None);
        assert_eq!(switch.counters().applied, 1);
    }

    #[test]
    fn a_second_generation_replaces_the_first_at_the_commit_and_not_before() {
        let (handover, ack) = regions();
        let mut switch = Switch::new(PORTS);
        handover.publish(&image(1));
        switch.take_offer(&handover, &ack);
        handover.publish_committed(1);
        switch.take_commit(&handover, &ack);

        let mut second = image(2);
        second.interface_count = 1;
        // The neighbour on port 1 goes with the interface that addressed it: a
        // next hop on a port no interface claims is a link with no prefix to be
        // a neighbour of, and is refused.
        second.neighbour_count = 1;
        handover.publish(&second);
        assert_eq!(
            switch.take_offer(&handover, &ack),
            Some(Offer::Staged { generation: 2 })
        );
        assert_eq!(switch.generation(), 1, "the staged table is not in force");
        handover.publish_committed(2);
        assert_eq!(switch.take_commit(&handover, &ack), Some(2));
        assert_eq!(switch.generation(), 2);
    }

    /// A publisher that releases a generation ahead of the one this consumer
    /// staged has still released that one.
    #[test]
    fn a_commit_beyond_the_staged_generation_still_releases_it() {
        let (handover, ack) = regions();
        let mut switch = Switch::new(PORTS);
        handover.publish(&image(3));
        switch.take_offer(&handover, &ack);
        handover.publish_committed(9);
        assert_eq!(switch.take_commit(&handover, &ack), Some(3));
    }

    #[test]
    fn a_refused_image_changes_nothing_and_is_never_acknowledged() {
        let (handover, ack) = regions();
        let mut switch = Switch::new(PORTS);
        let mut bad = image(1);
        bad.interfaces[1].port = PORTS;
        handover.publish(&bad);

        assert_eq!(
            switch.take_offer(&handover, &ack),
            Some(Offer::Refused {
                generation: 1,
                reason: RejectReason::PortOutOfRange,
                detail: 1,
            })
        );
        assert_eq!(ack.staged_generation(), 0);
        assert_eq!(ack.running_generation(), 0);
        assert_eq!(switch.generation(), 0);
        assert_eq!(switch.counters().refused, 1);
        assert_eq!(switch.take_commit(&handover, &ack), None);
    }

    /// A refusal must not consume the generation: the publisher may correct the
    /// image and re-offer under the same number, which nothing staged or
    /// running stands in the way of. The intervening offer is what makes the
    /// correction visible — a re-write under the word already on offer changes
    /// nothing this side can read.
    #[test]
    fn a_generation_refused_once_can_be_offered_again() {
        let (handover, ack) = regions();
        let mut switch = Switch::new(PORTS);
        let mut bad = image(1);
        bad.interfaces[0].enabled = 3;
        handover.publish(&bad);
        assert!(matches!(
            switch.take_offer(&handover, &ack),
            Some(Offer::Refused {
                reason: RejectReason::MalformedValue,
                ..
            })
        ));

        let mut also_bad = image(2);
        also_bad.interfaces[0].enabled = 3;
        handover.publish(&also_bad);
        assert!(matches!(
            switch.take_offer(&handover, &ack),
            Some(Offer::Refused { generation: 2, .. })
        ));

        handover.publish(&image(1));
        assert_eq!(
            switch.take_offer(&handover, &ack),
            Some(Offer::Staged { generation: 1 })
        );
    }

    /// The console is the last-resort channel and carries system state alone,
    /// so a refusal is an event of the offer and never of the poll: a
    /// caller polling an unchanged refused offer must be told once. Anyone able
    /// to raise this domain's wakeup rate would otherwise set the rate of a
    /// console record.
    #[test]
    fn one_unchanged_refused_offer_is_one_refusal_however_many_passes_follow() {
        let (handover, ack) = regions();
        let mut switch = Switch::new(PORTS);
        let mut bad = image(1);
        bad.interfaces[1].port = PORTS;
        handover.publish(&bad);

        let mut records = 0usize;
        for _ in 0..1000 {
            if let Some(offer) = switch.take_offer(&handover, &ack) {
                records += usize::from(offer.event().is_some());
            }
        }
        assert_eq!(records, 1);
        assert_eq!(switch.counters().refused, 1);
        assert_eq!(switch.generation(), 0);
        assert_eq!(ack.staged_generation(), 0);
    }

    /// A domain with less room than the image ABI allows refuses rather than
    /// running a table cut to fit.
    #[test]
    fn an_image_larger_than_this_domain_can_hold_is_refused() {
        let (handover, ack) = regions();
        let mut narrow = ConfigurationSwitch::<1, 1>::new(PORTS);
        handover.publish(&image(1));
        assert_eq!(
            narrow.take_offer(&handover, &ack),
            Some(Offer::Refused {
                generation: 1,
                reason: RejectReason::CapacityExceeded,
                detail: 1,
            })
        );
        assert_eq!(narrow.counters().refused, 1);
    }

    #[test]
    fn every_image_refusal_reaches_the_console_as_a_reason_and_a_number() {
        let cases = [
            (
                ConfigImageError::InterfaceCountExceedsCapacity { count: 99 },
                RejectReason::CapacityExceeded,
                99,
            ),
            (
                ConfigImageError::NeighbourCountExceedsCapacity { count: 40 },
                RejectReason::CapacityExceeded,
                40,
            ),
            (
                ConfigImageError::InterfaceEnabledNotBoolean {
                    index: 2,
                    enabled: 7,
                },
                RejectReason::MalformedValue,
                2,
            ),
            (
                ConfigImageError::InterfacePortUnknown { index: 3, port: 9 },
                RejectReason::PortOutOfRange,
                3,
            ),
            (
                ConfigImageError::NeighbourPortUnknown { index: 4, port: 9 },
                RejectReason::PortOutOfRange,
                4,
            ),
            (
                ConfigImageError::InterfacePrefixLengthTooLong {
                    index: 5,
                    prefix_length: 33,
                },
                RejectReason::PrefixLengthOutOfRange,
                5,
            ),
            (
                ConfigImageError::InterfaceMacNotUnicast {
                    index: 6,
                    mac: [1; 6],
                },
                RejectReason::MacNotUnicast,
                6,
            ),
            (
                ConfigImageError::NeighbourMacNotUnicast {
                    index: 7,
                    mac: [1; 6],
                },
                RejectReason::MacNotUnicast,
                7,
            ),
        ];
        for (error, reason, detail) in cases {
            assert_eq!(refusal(error), (reason, detail), "{error:?}");
        }
    }

    #[test]
    fn a_refusal_is_recorded_and_a_staging_is_not() {
        assert_eq!(Offer::Staged { generation: 5 }.event(), None);
        assert_eq!(
            Offer::Refused {
                generation: 5,
                reason: RejectReason::MacNotUnicast,
                detail: 2,
            }
            .event(),
            Some(Event::ConfigRejected {
                generation: 5,
                reason: RejectReason::MacNotUnicast,
                offset: 2,
            })
        );
    }

    #[test]
    fn a_publisher_releases_a_generation_only_once_the_consumer_has_staged_it() {
        let (handover, ack) = regions();
        let mut publisher = ConfigPublisher::new();
        let mut consumer = Switch::new(PORTS);
        assert_eq!(publisher.offered(), 0);
        // Nothing offered yet, so there is nothing to release.
        assert_eq!(publisher.take_acknowledgement(&handover, &ack), None);

        assert_eq!(publisher.offer(&handover, &image(1)), Ok(1));
        assert_eq!(publisher.offered(), 1);
        // Offered but unacknowledged: the consumer has not run yet.
        assert_eq!(publisher.take_acknowledgement(&handover, &ack), None);
        assert_eq!(handover.committed_generation(), 0);

        assert!(consumer.take_offer(&handover, &ack).is_some());
        assert_eq!(publisher.take_acknowledgement(&handover, &ack), Some(1));
        assert_eq!(handover.committed_generation(), 1);
        // Released once; a second wakeup finds nothing to do.
        assert_eq!(publisher.take_acknowledgement(&handover, &ack), None);

        assert_eq!(consumer.take_commit(&handover, &ack), Some(1));
        assert_eq!(ack.running_generation(), 1);
    }

    /// An acknowledgement names the generation the consumer staged, and staging
    /// one generation is not consent to commit another. The publisher's own
    /// invariant, not the consumer's: the consumers survive an unstaged commit,
    /// but a publisher that released one would have moved the configuration
    /// forward on a generation nobody was able to run.
    #[test]
    fn an_acknowledgement_of_one_generation_does_not_release_another() {
        let (handover, ack) = regions();
        let mut publisher = ConfigPublisher::new();
        let mut consumer = Switch::new(PORTS);

        publisher.offer(&handover, &image(5)).expect("the first");
        assert!(consumer.take_offer(&handover, &ack).is_some());
        assert_eq!(ack.staged_generation(), 5);

        // Going backwards is refused outright, so the acknowledgement of 5
        // never gets the chance to release a 3 nobody staged.
        assert_eq!(
            publisher.offer(&handover, &image(3)),
            Err(StaleOffer {
                offered: 5,
                refused: 3,
            })
        );
        assert_eq!(publisher.offered(), 5, "the offer did not move");
        assert_eq!(handover.offered_generation(), 5);
        assert_eq!(handover.load_image().generation, 5, "nor did the region");

        // And the acknowledgement still releases the generation it named.
        assert_eq!(publisher.take_acknowledgement(&handover, &ack), Some(5));
        assert_eq!(handover.committed_generation(), 5);
    }

    /// Re-offering the generation already on offer is the same refusal, which is
    /// what makes "a publisher must bump the generation to retry" a returned
    /// error rather than a handshake that quietly stops progressing.
    #[test]
    fn re_offering_the_generation_already_on_offer_is_refused() {
        let (handover, _ack) = regions();
        let mut publisher = ConfigPublisher::new();
        publisher.offer(&handover, &image(1)).expect("the first");
        assert_eq!(
            publisher.offer(&handover, &image(1)),
            Err(StaleOffer {
                offered: 1,
                refused: 1,
            })
        );
        // Generation 0 is the fail-closed configuration nobody publishes, so it
        // is refused from a fresh publisher too.
        let mut fresh = ConfigPublisher::new();
        assert_eq!(
            fresh.offer(&handover, &image(0)),
            Err(StaleOffer {
                offered: 0,
                refused: 0,
            })
        );
    }

    /// A consumer that refuses an image never acknowledges it, so the publisher
    /// never releases it: the two halves fail closed together.
    #[test]
    fn a_refused_image_is_never_released_by_the_publisher() {
        let (handover, ack) = regions();
        let mut publisher = ConfigPublisher::new();
        let mut consumer = Switch::new(PORTS);
        let mut bad = image(1);
        bad.interfaces[0].mac = [0xff; 6];
        publisher
            .offer(&handover, &bad)
            .expect("the first generation");

        assert!(matches!(
            consumer.take_offer(&handover, &ack),
            Some(Offer::Refused {
                reason: RejectReason::MacNotUnicast,
                ..
            })
        ));
        assert_eq!(publisher.take_acknowledgement(&handover, &ack), None);
        assert_eq!(handover.committed_generation(), 0);
        assert_eq!(consumer.generation(), 0);
    }

    #[test]
    fn a_second_generation_goes_round_the_same_two_phases() {
        let (handover, ack) = regions();
        let mut publisher = ConfigPublisher::new();
        let mut consumer = Switch::new(PORTS);
        for generation in 1..=3 {
            publisher
                .offer(&handover, &image(generation))
                .expect("each generation is newer than the last");
            assert!(consumer.take_offer(&handover, &ack).is_some());
            assert_eq!(
                publisher.take_acknowledgement(&handover, &ack),
                Some(generation)
            );
            assert_eq!(consumer.take_commit(&handover, &ack), Some(generation));
            assert_eq!(consumer.generation(), generation);
        }
        assert_eq!(consumer.counters().applied, 3);
        assert_eq!(consumer.counters().refused, 0);
    }

    #[test]
    fn a_table_built_from_an_image_is_the_table_the_image_describes() {
        let checked = image(1).check(PORTS).expect("the fixture is valid");
        let built: Router<MAX_INTERFACES, MAX_NEIGHBOURS> =
            router_from(&checked).expect("it fits the ABI's own capacity");
        let expected = Router::from_slices(
            &[
                Interface {
                    port: PortId(0),
                    mac: MacAddress([0x52, 0x54, 0x00, 0x12, 0x34, 0x50]),
                    address: Ipv4Address::from_octets([10, 0, 0, 1]),
                    prefix_length: 24,
                    enabled: true,
                },
                Interface {
                    port: PortId(1),
                    mac: MacAddress([0x52, 0x54, 0x00, 0x12, 0x34, 0x51]),
                    address: Ipv4Address::from_octets([10, 0, 1, 1]),
                    prefix_length: 24,
                    enabled: true,
                },
            ],
            &[
                Neighbour {
                    port: PortId(0),
                    address: Ipv4Address::from_octets([10, 0, 0, 2]),
                    mac: MacAddress([0x52, 0x54, 0x00, 0x00, 0x00, 0x0a]),
                },
                Neighbour {
                    port: PortId(1),
                    address: Ipv4Address::from_octets([10, 0, 1, 2]),
                    mac: MacAddress([0x52, 0x54, 0x00, 0x00, 0x00, 0x0b]),
                },
            ],
        )
        .expect("the fixture fits");
        assert_eq!(built, expected);
    }

    /// A disabled interface survives the crossing: dropping the flag would turn
    /// an administratively down port back up on the far side of the handover.
    #[test]
    fn a_disabled_interface_stays_disabled_across_the_image() {
        let mut raw = image(1);
        raw.interfaces[1].enabled = 0;
        let checked = raw.check(PORTS).expect("zero is a boolean");
        let built: Router<MAX_INTERFACES, MAX_NEIGHBOURS> = router_from(&checked).expect("it fits");
        assert_ne!(
            built,
            router_from::<MAX_INTERFACES, MAX_NEIGHBOURS>(&image(1).check(PORTS).expect("valid"))
                .expect("it fits")
        );
    }

    /// The management entry the fixture image carries, addressed on a prefix the
    /// two interfaces do not claim.
    fn management(enabled: u8, mac: [u8; 6], address: [u8; 4]) -> wire::ManagementImage {
        wire::ManagementImage {
            enabled,
            prefix_length: 24,
            mac,
            address,
            ..wire::ManagementImage::ZERO
        }
    }

    /// A per-boot secret for the transport's initial sequence numbers, fixed here
    /// so the fixture is deterministic.
    fn secret() -> IsnSecret {
        IsnSecret::from_bytes([0xa5; 16])
    }

    const MGMT_MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x12, 0x34, 0x52];
    const MGMT_ADDRESS: [u8; 4] = [10, 0, 2, 15];

    #[test]
    fn an_endpoint_is_built_only_from_an_entry_that_addresses_the_port() {
        let checked = image(1).check(PORTS).expect("the fixture is valid");
        assert!(
            endpoint_from(&checked, secret())
                .expect("no entry is not an error")
                .is_none(),
            "the fixture addresses no management port"
        );

        let mut addressed = image(1);
        addressed.management = management(1, MGMT_MAC, MGMT_ADDRESS);
        let checked = addressed.check(PORTS).expect("an enabled entry");
        let endpoint = endpoint_from(&checked, secret())
            .expect("a unicast pair")
            .expect("an enabled entry");
        assert_eq!(endpoint.mac(), MacAddress(MGMT_MAC));
        assert_eq!(endpoint.address(), Ipv4Address::from_octets(MGMT_ADDRESS));
        assert_eq!(endpoint.prefix_length(), 24);

        // A disabled entry addresses nothing, whatever its other fields say.
        let mut disabled = addressed;
        disabled.management.enabled = 0;
        assert!(
            endpoint_from(&disabled.check(PORTS).expect("still valid"), secret())
                .expect("no entry is not an error")
                .is_none()
        );
    }

    /// Every pair a checked image can carry is one an endpoint can answer
    /// under, so this call cannot refuse what it is handed.
    ///
    /// That is a property of the two rule sets rather than of this function:
    /// [`lfw_ip_endpoint::EndpointError`] has exactly three variants — a MAC
    /// that is not unicast, an address that is not unicast, a prefix length past
    /// 32 — and `ConfigImage::check` refuses all three of an enabled management
    /// entry before one gets here. The `Result` stays because the signature is
    /// what stops this function trusting its caller, and a layer that cannot
    /// currently refuse anything is not the same as a layer that does not check;
    /// what has changed is that the refusal is now unreachable rather than
    /// merely unlikely, and this is the test that says so.
    #[test]
    fn every_management_entry_a_checked_image_carries_builds_an_endpoint() {
        for address in [[224, 0, 0, 1], [10, 0, 2, 0], [0, 0, 0, 0]] {
            let mut raw = image(1);
            raw.management = management(1, MGMT_MAC, address);
            assert!(
                raw.check(PORTS).is_err(),
                "the image reader admitted {address:?}, which no endpoint answers under"
            );
        }

        let mut addressed = image(1);
        addressed.management = management(1, MGMT_MAC, MGMT_ADDRESS);
        let checked = addressed.check(PORTS).expect("an enabled entry");
        endpoint_from(&checked, secret())
            .expect("a checked entry is one an endpoint answers under")
            .expect("an enabled entry builds one");
    }

    /// The reader takes the *committed* word and nothing else: an offer nobody
    /// has released is invisible to it, which is the whole difference between
    /// this role and the forwarder's.
    #[test]
    fn an_offer_that_is_not_committed_is_not_taken() {
        let (handover, ack) = regions();
        let mut reader = CommittedReader::new();
        assert_eq!(reader.generation(), 0);
        assert_eq!(reader.take(&handover, PORTS), None);

        handover.publish(&image(1));
        assert_eq!(
            reader.take(&handover, PORTS),
            None,
            "an offer is not a commit"
        );
        assert_eq!(reader.generation(), 0);

        handover.publish_committed(1);
        assert!(matches!(
            reader.take(&handover, PORTS),
            Some(Committed::Image { generation: 1, .. })
        ));
        assert_eq!(reader.generation(), 1);
        // Nothing is written on this side at all: the acknowledgement region is
        // not this reader's to touch, and the domain that uses it maps none.
        assert_eq!(ack.staged_generation(), 0);
        assert_eq!(ack.running_generation(), 0);
    }

    #[test]
    fn one_commit_yields_one_outcome_however_often_it_is_asked_for() {
        let (handover, _ack) = regions();
        let mut reader = CommittedReader::new();
        handover.publish(&image(3));
        handover.publish_committed(3);
        assert!(reader.take(&handover, PORTS).is_some());
        for _ in 0..100 {
            assert_eq!(reader.take(&handover, PORTS), None);
        }

        // And a newer commit is a new outcome.
        handover.publish(&image(4));
        handover.publish_committed(4);
        assert!(matches!(
            reader.take(&handover, PORTS),
            Some(Committed::Image { generation: 4, .. })
        ));
    }

    /// A committed image this reader will not read is reported once and consumes
    /// the generation: the publisher has already released it, so re-reading it
    /// would report the same refusal on the caller's polling rate.
    #[test]
    fn a_committed_image_that_cannot_be_read_is_refused_once() {
        let (handover, _ack) = regions();
        let mut reader = CommittedReader::new();
        let mut bad = image(1);
        bad.interfaces[0].port = PORTS;
        handover.publish(&bad);
        handover.publish_committed(1);
        assert_eq!(
            reader.take(&handover, PORTS),
            Some(Committed::Refused {
                generation: 1,
                reason: RejectReason::PortOutOfRange,
                detail: 0,
            })
        );
        assert_eq!(reader.take(&handover, PORTS), None);
        assert_eq!(reader.generation(), 1);
    }

    /// Every refusal the management entry can produce reaches the console as a
    /// reason and a number, on the same terms as the dataplane's.
    #[test]
    fn every_management_refusal_reaches_the_console_as_a_reason_and_a_number() {
        let cases = [
            (
                ConfigImageError::ManagementEnabledNotBoolean { enabled: 7 },
                RejectReason::MalformedValue,
                7,
            ),
            (
                ConfigImageError::ManagementPrefixLengthTooLong { prefix_length: 33 },
                RejectReason::PrefixLengthOutOfRange,
                33,
            ),
            (
                ConfigImageError::ManagementMacNotUnicast { mac: [0xff; 6] },
                RejectReason::MacNotUnicast,
                0xff,
            ),
        ];
        for (error, reason, detail) in cases {
            assert_eq!(refusal(error), (reason, detail), "{error:?}");
        }
    }

    proptest! {
        /// Whatever a publisher commits, the reader answers rather than
        /// panicking, takes each generation once, and never moves backwards.
        #[test]
        fn an_arbitrary_committed_region_is_read_once_and_never_backwards(
            generations in prop::collection::vec(0u32..6, 0..12),
            enabled in any::<u8>(),
            prefix_length in any::<u8>(),
            mac in any::<[u8; 6]>(),
            address in any::<[u8; 4]>(),
        ) {
            let (handover, ack) = regions();
            let mut reader = CommittedReader::new();
            let mut highest = 0u32;
            for generation in generations {
                let mut raw = image(generation);
                raw.management = wire::ManagementImage {
                    enabled,
                    prefix_length,
                    mac,
                    address,
                    ..wire::ManagementImage::ZERO
                };
                handover.publish(&raw);
                handover.publish_committed(generation);

                match reader.take(&handover, PORTS) {
                    None => prop_assert!(generation <= highest),
                    Some(Committed::Image { generation: taken, checked }) => {
                        prop_assert!(taken > highest);
                        highest = taken;
                        // An image that checked out either addresses the port
                        // with a pair an endpoint accepts or names one it
                        // refuses; an image that addresses none can only build
                        // nothing.
                        match (endpoint_from(&checked, secret()), checked.management()) {
                            (Ok(None), entry) => prop_assert!(entry.is_none()),
                            (Ok(Some(endpoint)), Some(entry)) => {
                                prop_assert_eq!(endpoint.mac(), MacAddress(entry.mac()));
                                prop_assert_eq!(endpoint.prefix_length(), entry.prefix_length());
                            }
                            (Err(_), entry) => prop_assert!(entry.is_some()),
                            (Ok(Some(_)), None) => {
                                prop_assert!(false, "an endpoint from no entry");
                            }
                        }
                    }
                    Some(Committed::Refused { generation: taken, .. }) => {
                        prop_assert!(taken > highest);
                        highest = taken;
                    }
                }
                prop_assert_eq!(reader.generation(), highest);
            }
            prop_assert_eq!(ack.staged_generation(), 0);
            prop_assert_eq!(ack.running_generation(), 0);
        }

        /// The headline property of a byzantine region: whatever is in it, a
        /// pass either refuses it or runs a table built from it, never panics,
        /// and never acknowledges a generation it did not stage.
        #[test]
        fn an_arbitrary_region_is_refused_or_staged_and_never_half_taken(
            generation in 0u32..8,
            interface_count in 0u32..12,
            neighbour_count in 0u32..40,
            enabled in any::<u8>(),
            port in any::<u8>(),
            prefix_length in any::<u8>(),
            mac in any::<[u8; 6]>(),
        ) {
            let (handover, ack) = regions();
            let mut switch = Switch::new(PORTS);
            let mut raw = ConfigImage {
                generation,
                interface_count,
                neighbour_count,
                content_hash: 0,
                ..ConfigImage::ZERO
            };
            for slot in &mut raw.interfaces {
                *slot = InterfaceImage {
                    port,
                    enabled,
                    prefix_length,
                    _pad: [0; 1],
                    mac,
                    _pad2: [0; 2],
                    address: [10, 0, 0, 1],
                    id: IdentifierImage::from_text(b"wan"),
                };
            }
            for slot in &mut raw.neighbours {
                *slot = NeighbourImage {
                    port,
                    _pad: [0; 3],
                    mac,
                    _pad2: [0; 2],
                    address: [10, 0, 0, 2],
                };
            }
            handover.publish(&raw);

            match switch.take_offer(&handover, &ack) {
                None => {
                    // Nothing newer was on offer, so nothing may have moved.
                    prop_assert_eq!(ack.staged_generation(), 0);
                    prop_assert_eq!(switch.counters(), ConfigCounters::default());
                }
                Some(Offer::Refused { .. }) => {
                    prop_assert_eq!(ack.staged_generation(), 0);
                    prop_assert_eq!(switch.generation(), 0);
                    prop_assert_eq!(switch.counters().refused, 1);
                }
                Some(Offer::Staged { generation: staged }) => {
                    prop_assert_eq!(staged, generation);
                    prop_assert_eq!(ack.staged_generation(), staged);
                    // Staging alone never moves what is in force.
                    prop_assert_eq!(switch.generation(), 0);
                    handover.publish_committed(staged);
                    prop_assert_eq!(switch.take_commit(&handover, &ack), Some(staged));
                    prop_assert_eq!(switch.generation(), staged);
                    prop_assert_eq!(ack.running_generation(), staged);
                }
            }
        }

        /// Bounded work regardless of what the publisher claims: a count naming
        /// more entries than the image holds is refused rather than iterated.
        #[test]
        fn a_count_beyond_the_image_is_refused_rather_than_followed(
            interface_count in (MAX_INTERFACES as u32 + 1)..=u32::MAX,
        ) {
            let (handover, ack) = regions();
            let mut switch = Switch::new(PORTS);
            handover.publish(&ConfigImage {
                interface_count,
                ..image(1)
            });
            prop_assert_eq!(
                switch.take_offer(&handover, &ack),
                Some(Offer::Refused {
                    generation: 1,
                    reason: RejectReason::CapacityExceeded,
                    detail: interface_count,
                })
            );
        }
    }
}
