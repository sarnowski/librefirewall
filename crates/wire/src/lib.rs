//! The layout of the descriptor protection domains exchange over the
//! shared-memory dataplane queues.
//!
//! Faces the byzantine peer protection domain (CONCEPT §7.1): everything read
//! out of a shared region here is peer-written input. The descriptor is fixed
//! but not checked — whether one is in bounds is a question about the pool it
//! indexes, so only the domain that owns that pool can answer it. The
//! configuration image is fixed *and* checked, because every rule about it is a
//! rule about this ABI and no later owner knows more than the layout does.
//!
//! Every field is a little-endian `u32` and no byte-swapping code exists,
//! because x86_64 is the only target (CONCEPT §3): the native image of a
//! `#[repr(C)]` struct of `u32`s already *is* the wire image. The byte-image
//! tests below exist so a port to a big-endian target fails them rather than
//! silently shipping swapped descriptors. That fixes the descriptor as a peer
//! domain reads it, and says nothing about byte order inside packet payloads.
//!
//! The verdict rides in the descriptor because a domain that decides against a
//! frame cannot return its buffer: a return is a produce on a free ring that
//! already has one producer. One `u32` moves the decision to the domain that
//! owns that producer, and costs no new grant.
//!
//! The configuration handover is the same kind of object and is here for the
//! same reason. A [`ConfigImage`] is an already-validated model as fixed-layout
//! POD, so the domain that applies it needs neither a parser nor an allocator —
//! keeping the document parser out of the dataplane is the whole point of
//! validating in a separate domain. [`ConfigImage::check`] is what turns one
//! into values a domain can decide under: it refuses or decodes every field,
//! and bounds both arrays by the capacities below rather than by the count the
//! writer put in the region.
//!
//! The domain that writes the handover only ever holds a shared reference to
//! the region, because no attach path mints a `&mut` to memory a second domain
//! maps. So the image in it is expressed as atomics rather than plain fields:
//! that is what lets a writer exist here without `unsafe`, and the assertions
//! below hold the result byte-identical to the plain image the reader maps.
//! [`ConfigImage`] stays that plain value — what a writer composes and a reader
//! copies out. Its words move `Relaxed` under the generation that publishes
//! them `Release`, and nothing stops the writer rewriting them afterwards,
//! which is why a [`CheckedConfig`] owns decoded values rather than borrowing.

#![cfg_attr(not(test), no_std)]

use core::{
    fmt,
    mem::{align_of, offset_of, size_of},
    sync::atomic::{AtomicU8, AtomicU32, Ordering},
};

/// The producing domain's decision about the frame a [`Descriptor`] names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Transmit,
    /// The buffer goes back to its owner unread.
    Discard,
}

impl Verdict {
    #[must_use]
    pub const fn to_bits(self) -> u32 {
        match self {
            Self::Transmit => 0,
            Self::Discard => 1,
        }
    }

    /// `None` for every other bit pattern: the field is peer-written, so an
    /// undecodable value is input to reject rather than one to coerce.
    #[must_use]
    pub const fn from_bits(bits: u32) -> Option<Self> {
        match bits {
            0 => Some(Self::Transmit),
            1 => Some(Self::Discard),
            _ => None,
        }
    }
}

/// The `len` bytes at `offset` in pool buffer `buffer`, and the verdict on them.
///
/// `offset` exists so a producer can publish data that does not begin at the
/// buffer's front: on a NIC receive the frame sits behind the device's own
/// header, and handing the descriptor on publishes it without moving a byte.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Descriptor {
    pub buffer: u32,
    pub offset: u32,
    pub len: u32,
    /// The producing domain's [`Verdict`] as raw bits — this crate fixes the
    /// ABI and validates nothing, so the consumer decodes and may refuse it.
    pub verdict: u32,
}

impl Descriptor {
    pub const ZERO: Self = Self {
        buffer: 0,
        offset: 0,
        len: 0,
        verdict: 0,
    };

    /// Takes a [`Verdict`] rather than bits, so only a peer writing the shared
    /// word directly can mint a descriptor its consumer cannot decode.
    #[must_use]
    pub const fn new(buffer: u32, offset: u32, len: u32, verdict: Verdict) -> Self {
        Self {
            buffer,
            offset,
            len,
            verdict: verdict.to_bits(),
        }
    }
}

impl Default for Descriptor {
    fn default() -> Self {
        Self::ZERO
    }
}

// The descriptor crosses protection domains byte for byte, so a field reorder
// or a width change must be a compile error here rather than a silent break of
// the image the peer domain reads.
const _: () = {
    assert!(size_of::<Descriptor>() == 16);
    assert!(align_of::<Descriptor>() == 4);
    assert!(offset_of!(Descriptor, buffer) == 0);
    assert!(offset_of!(Descriptor, offset) == 4);
    assert!(offset_of!(Descriptor, len) == 8);
    assert!(offset_of!(Descriptor, verdict) == 12);
    // Transmit is zero, so a zeroed region is still the valid empty state.
    assert!(Verdict::Transmit.to_bits() == 0);
};

// Slot counts are ABI rather than a tuning knob: each one sizes the region the
// system description reserves, so moving one rebuilds every domain that maps it.
pub const MAX_INTERFACES: usize = 8;
pub const MAX_NEIGHBOURS: usize = 32;

/// Bits an IPv4 prefix can name.
pub const MAX_PREFIX_LENGTH: u8 = 32;

/// The granularity Microkit maps a memory region at, so the smallest reservation
/// that can hold anything and the multiple every size rounds to.
pub const MAPPING_ALIGN: usize = 0x1000;

/// One interface as the validating domain left it.
///
/// The padding is explicit rather than implied, so these offsets are the ones a
/// writer in another language computes for the same declaration. No field is
/// placed in it, so the bytes a peer leaves there name nothing.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InterfaceImage {
    pub port: u8,
    /// 0 or 1 as raw bits. The region is peer-written, so any byte can appear
    /// here and [`ConfigImage::check`] refuses the ones that are neither.
    pub enabled: u8,
    pub prefix_length: u8,
    pub _pad: u8,
    pub mac: [u8; 6],
    pub _pad2: [u8; 2],
    /// Network order, as the address appears in a header.
    pub address: [u8; 4],
}

impl InterfaceImage {
    pub const ZERO: Self = Self {
        port: 0,
        enabled: 0,
        prefix_length: 0,
        _pad: 0,
        mac: [0; 6],
        _pad2: [0; 2],
        address: [0; 4],
    };
}

/// One statically configured neighbour. It carries no prefix: a neighbour is a
/// single host, and which prefix reaches it is its interface's business.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NeighbourImage {
    pub port: u8,
    pub _pad: [u8; 3],
    pub mac: [u8; 6],
    pub _pad2: [u8; 2],
    pub address: [u8; 4],
}

impl NeighbourImage {
    pub const ZERO: Self = Self {
        port: 0,
        _pad: [0; 3],
        mac: [0; 6],
        _pad2: [0; 2],
        address: [0; 4],
    };
}

/// A whole configuration generation as bytes in a shared region.
///
/// The arrays are always their full size, so the image is one fixed-size object
/// whatever it holds: the region is reserved once at build time and a
/// generation that fills it is the same shape as a generation that does not.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConfigImage {
    pub generation: u32,
    /// How many of `interfaces` the writer filled, as raw bits: peer-written,
    /// so it may name more than the array holds.
    pub interface_count: u32,
    pub neighbour_count: u32,
    /// Over the validated model, so re-offering an unchanged document is
    /// recognisable without comparing every field.
    pub content_hash: u32,
    pub interfaces: [InterfaceImage; MAX_INTERFACES],
    pub neighbours: [NeighbourImage; MAX_NEIGHBOURS],
}

impl ConfigImage {
    /// Generation zero: no interfaces, no neighbours. A zeroed region is
    /// therefore already the fail-closed configuration, which is what lets a
    /// domain come up before anything has been written to it.
    pub const ZERO: Self = Self {
        generation: 0,
        interface_count: 0,
        neighbour_count: 0,
        content_hash: 0,
        interfaces: [InterfaceImage::ZERO; MAX_INTERFACES],
        neighbours: [NeighbourImage::ZERO; MAX_NEIGHBOURS],
    };

    /// Decodes every field the counts cover, refusing the image on the first
    /// value that cannot be one.
    ///
    /// `port_count` is how many dataplane ports this build has; it comes from
    /// the calling domain, never from the region, so it is the bound the writer
    /// cannot move.
    ///
    /// # Errors
    /// [`ConfigImageError`], naming the field and the value that refused it.
    pub fn check(&self, port_count: u8) -> Result<CheckedConfig, ConfigImageError> {
        let raw_interfaces = self.interfaces.get(..self.interface_count as usize).ok_or(
            ConfigImageError::InterfaceCountExceedsCapacity {
                count: self.interface_count,
            },
        )?;
        let raw_neighbours = self.neighbours.get(..self.neighbour_count as usize).ok_or(
            ConfigImageError::NeighbourCountExceedsCapacity {
                count: self.neighbour_count,
            },
        )?;

        let mut interfaces = [None; MAX_INTERFACES];
        for ((index, raw), slot) in raw_interfaces.iter().enumerate().zip(interfaces.iter_mut()) {
            *slot = Some(check_interface(raw, index, port_count)?);
        }

        let mut neighbours = [None; MAX_NEIGHBOURS];
        for ((index, raw), slot) in raw_neighbours.iter().enumerate().zip(neighbours.iter_mut()) {
            *slot = Some(check_neighbour(raw, index, port_count)?);
        }

        Ok(CheckedConfig {
            generation: self.generation,
            content_hash: self.content_hash,
            interfaces,
            neighbours,
        })
    }
}

/// Copies `bytes` into the cells that hold them, one cell at a time. Bounded
/// by the arrays, which are the same length by the signature.
fn store_bytes<const N: usize>(cells: &[AtomicU8; N], bytes: [u8; N]) {
    for (cell, byte) in cells.iter().zip(bytes) {
        cell.store(byte, Ordering::Relaxed);
    }
}

/// The inverse of [`store_bytes`].
fn load_bytes<const N: usize>(cells: &[AtomicU8; N]) -> [u8; N] {
    let mut bytes = [0; N];
    for (byte, cell) in bytes.iter_mut().zip(cells) {
        *byte = cell.load(Ordering::Relaxed);
    }
    bytes
}

/// The shared-memory image of an [`InterfaceImage`].
///
/// One atomic per byte rather than four `AtomicU32` words: the entry is a
/// struct of `u8`s, so packing it into words would place a field inside a word
/// and make the byte order of the region a thing this crate chooses rather
/// than a thing it mirrors. Per-byte, each field is at the offset the plain
/// image puts it at, which is what the assertions below check.
#[repr(C)]
struct InterfaceSlot {
    port: AtomicU8,
    enabled: AtomicU8,
    prefix_length: AtomicU8,
    _pad: AtomicU8,
    mac: [AtomicU8; 6],
    _pad2: [AtomicU8; 2],
    address: [AtomicU8; 4],
}

impl InterfaceSlot {
    const fn zero() -> Self {
        Self {
            port: AtomicU8::new(0),
            enabled: AtomicU8::new(0),
            prefix_length: AtomicU8::new(0),
            _pad: AtomicU8::new(0),
            mac: [const { AtomicU8::new(0) }; 6],
            _pad2: [const { AtomicU8::new(0) }; 2],
            address: [const { AtomicU8::new(0) }; 4],
        }
    }

    /// Carries the padding too: this moves an image, and which bytes mean
    /// something is [`ConfigImage::check`]'s question rather than this one's.
    fn store(&self, entry: &InterfaceImage) {
        self.port.store(entry.port, Ordering::Relaxed);
        self.enabled.store(entry.enabled, Ordering::Relaxed);
        self.prefix_length
            .store(entry.prefix_length, Ordering::Relaxed);
        self._pad.store(entry._pad, Ordering::Relaxed);
        store_bytes(&self.mac, entry.mac);
        store_bytes(&self._pad2, entry._pad2);
        store_bytes(&self.address, entry.address);
    }

    fn load(&self) -> InterfaceImage {
        InterfaceImage {
            port: self.port.load(Ordering::Relaxed),
            enabled: self.enabled.load(Ordering::Relaxed),
            prefix_length: self.prefix_length.load(Ordering::Relaxed),
            _pad: self._pad.load(Ordering::Relaxed),
            mac: load_bytes(&self.mac),
            _pad2: load_bytes(&self._pad2),
            address: load_bytes(&self.address),
        }
    }
}

/// As [`InterfaceSlot`], for a [`NeighbourImage`].
#[repr(C)]
struct NeighbourSlot {
    port: AtomicU8,
    _pad: [AtomicU8; 3],
    mac: [AtomicU8; 6],
    _pad2: [AtomicU8; 2],
    address: [AtomicU8; 4],
}

impl NeighbourSlot {
    const fn zero() -> Self {
        Self {
            port: AtomicU8::new(0),
            _pad: [const { AtomicU8::new(0) }; 3],
            mac: [const { AtomicU8::new(0) }; 6],
            _pad2: [const { AtomicU8::new(0) }; 2],
            address: [const { AtomicU8::new(0) }; 4],
        }
    }

    fn store(&self, entry: &NeighbourImage) {
        self.port.store(entry.port, Ordering::Relaxed);
        store_bytes(&self._pad, entry._pad);
        store_bytes(&self.mac, entry.mac);
        store_bytes(&self._pad2, entry._pad2);
        store_bytes(&self.address, entry.address);
    }

    fn load(&self) -> NeighbourImage {
        NeighbourImage {
            port: self.port.load(Ordering::Relaxed),
            _pad: load_bytes(&self._pad),
            mac: load_bytes(&self.mac),
            _pad2: load_bytes(&self._pad2),
            address: load_bytes(&self.address),
        }
    }
}

/// The shared-memory image of a [`ConfigImage`], readable and writable through
/// a shared reference — the only kind of reference a mapped region is reached
/// by. Accesses are `Relaxed`: all the ordering the region needs is the
/// release/acquire pair on the generation that publishes it.
#[repr(C)]
struct ConfigSlot {
    generation: AtomicU32,
    interface_count: AtomicU32,
    neighbour_count: AtomicU32,
    content_hash: AtomicU32,
    interfaces: [InterfaceSlot; MAX_INTERFACES],
    neighbours: [NeighbourSlot; MAX_NEIGHBOURS],
}

impl ConfigSlot {
    const fn zero() -> Self {
        Self {
            generation: AtomicU32::new(0),
            interface_count: AtomicU32::new(0),
            neighbour_count: AtomicU32::new(0),
            content_hash: AtomicU32::new(0),
            interfaces: [const { InterfaceSlot::zero() }; MAX_INTERFACES],
            neighbours: [const { NeighbourSlot::zero() }; MAX_NEIGHBOURS],
        }
    }

    fn store(&self, image: &ConfigImage) {
        self.generation.store(image.generation, Ordering::Relaxed);
        self.interface_count
            .store(image.interface_count, Ordering::Relaxed);
        self.neighbour_count
            .store(image.neighbour_count, Ordering::Relaxed);
        self.content_hash
            .store(image.content_hash, Ordering::Relaxed);
        for (slot, entry) in self.interfaces.iter().zip(&image.interfaces) {
            slot.store(entry);
        }
        for (slot, entry) in self.neighbours.iter().zip(&image.neighbours) {
            slot.store(entry);
        }
    }

    fn load(&self) -> ConfigImage {
        let mut image = ConfigImage {
            generation: self.generation.load(Ordering::Relaxed),
            interface_count: self.interface_count.load(Ordering::Relaxed),
            neighbour_count: self.neighbour_count.load(Ordering::Relaxed),
            content_hash: self.content_hash.load(Ordering::Relaxed),
            ..ConfigImage::ZERO
        };
        for (entry, slot) in image.interfaces.iter_mut().zip(&self.interfaces) {
            *entry = slot.load();
        }
        for (entry, slot) in image.neighbours.iter_mut().zip(&self.neighbours) {
            *entry = slot.load();
        }
        image
    }
}

/// A whole configuration image with the two generation words that publish it.
///
/// Two words rather than one because a consumer has to be able to stage a
/// generation before anybody switches to it: `offered` invites, `committed`
/// releases, and the gap between them is where every consumer acknowledges.
///
/// Every field is private and the image has no accessor of its own, so the
/// ordering each word carries is a property of this type rather than a
/// convention its users are asked to keep (DOC-9).
#[repr(C)]
pub struct ConfigHandover {
    offered: AtomicU32,
    committed: AtomicU32,
    image: ConfigSlot,
}

impl ConfigHandover {
    /// A function rather than a `const`, because a `const` holding an atomic is
    /// copied at every mention: publishing through one would store into a
    /// temporary and be read back by nobody.
    #[must_use]
    pub const fn zero() -> Self {
        Self {
            offered: AtomicU32::new(0),
            committed: AtomicU32::new(0),
            image: ConfigSlot::zero(),
        }
    }

    /// Writes `image` and then releases its generation, in that order and as
    /// one call: a generation whose bytes are not yet in the region names
    /// nothing, so there is no way here to offer one that has not been written.
    pub fn publish(&self, image: &ConfigImage) {
        self.image.store(image);
        self.offered.store(image.generation, Ordering::Release);
    }

    #[must_use]
    pub fn offered_generation(&self) -> u32 {
        self.offered.load(Ordering::Acquire)
    }

    /// Copies the whole image out, because the writer may change the region
    /// again at any moment and a view into it decides nothing.
    #[must_use]
    pub fn load_image(&self) -> ConfigImage {
        self.image.load()
    }

    pub fn publish_committed(&self, generation: u32) {
        self.committed.store(generation, Ordering::Release);
    }

    #[must_use]
    pub fn committed_generation(&self) -> u32 {
        self.committed.load(Ordering::Acquire)
    }
}

/// What one consumer has done with the offered generation. Separate from
/// [`ConfigHandover`] because it travels the other way, and so is a region the
/// writer of that one maps read-only. Private for the reason
/// [`ConfigHandover`]'s fields are.
#[repr(C)]
pub struct ConfigAck {
    staged: AtomicU32,
    running: AtomicU32,
}

impl ConfigAck {
    /// As [`ConfigHandover::zero`].
    #[must_use]
    pub const fn zero() -> Self {
        Self {
            staged: AtomicU32::new(0),
            running: AtomicU32::new(0),
        }
    }

    /// Highest generation this consumer has staged and can switch to.
    pub fn publish_staged(&self, generation: u32) {
        self.staged.store(generation, Ordering::Release);
    }

    #[must_use]
    pub fn staged_generation(&self) -> u32 {
        self.staged.load(Ordering::Acquire)
    }

    /// Highest generation this consumer has actually switched to.
    pub fn publish_running(&self, generation: u32) {
        self.running.store(generation, Ordering::Release);
    }

    #[must_use]
    pub fn running_generation(&self) -> u32 {
        self.running.load(Ordering::Acquire)
    }
}

/// Bytes the system description reserves for the handover region, derived
/// rather than chosen: the fewest [`MAPPING_ALIGN`] pages that hold the type.
pub const CONFIG_REGION_SIZE: usize = size_of::<ConfigHandover>().next_multiple_of(MAPPING_ALIGN);

/// As [`CONFIG_REGION_SIZE`], for one consumer's acknowledgement region.
pub const CONFIG_ACK_REGION_SIZE: usize = size_of::<ConfigAck>().next_multiple_of(MAPPING_ALIGN);

/// Why a [`ConfigImage`] was refused. Every variant carries the value that made
/// it one, so a refusal is attributable to a field rather than to a category.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigImageError {
    InterfaceCountExceedsCapacity {
        count: u32,
    },
    NeighbourCountExceedsCapacity {
        count: u32,
    },
    /// Anything but 0 or 1, which no `bool` can be coerced from without picking
    /// a meaning the writer did not choose.
    InterfaceEnabledNotBoolean {
        index: usize,
        enabled: u8,
    },
    InterfacePortUnknown {
        index: usize,
        port: u8,
    },
    NeighbourPortUnknown {
        index: usize,
        port: u8,
    },
    InterfacePrefixLengthTooLong {
        index: usize,
        prefix_length: u8,
    },
    /// The group bit is set, or every byte is zero. Neither can be a source MAC
    /// the appliance forwards under.
    InterfaceMacNotUnicast {
        index: usize,
        mac: [u8; 6],
    },
    /// As [`Self::InterfaceMacNotUnicast`], for a destination the appliance
    /// would unicast a routed frame to.
    NeighbourMacNotUnicast {
        index: usize,
        mac: [u8; 6],
    },
}

impl fmt::Display for ConfigImageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InterfaceCountExceedsCapacity { count } => write!(
                f,
                "interface count {count} exceeds the {MAX_INTERFACES} slots the image holds"
            ),
            Self::NeighbourCountExceedsCapacity { count } => write!(
                f,
                "neighbour count {count} exceeds the {MAX_NEIGHBOURS} slots the image holds"
            ),
            Self::InterfaceEnabledNotBoolean { index, enabled } => {
                write!(f, "interface {index} enabled byte {enabled} is not 0 or 1")
            }
            Self::InterfacePortUnknown { index, port } => {
                write!(
                    f,
                    "interface {index} names port {port}, which does not exist"
                )
            }
            Self::NeighbourPortUnknown { index, port } => {
                write!(
                    f,
                    "neighbour {index} names port {port}, which does not exist"
                )
            }
            Self::InterfacePrefixLengthTooLong {
                index,
                prefix_length,
            } => write!(
                f,
                "interface {index} prefix length {prefix_length} exceeds {MAX_PREFIX_LENGTH}"
            ),
            Self::InterfaceMacNotUnicast { index, mac } => {
                write!(f, "interface {index} MAC ")?;
                write_mac(f, *mac)?;
                write!(f, " is not unicast")
            }
            Self::NeighbourMacNotUnicast { index, mac } => {
                write!(f, "neighbour {index} MAC ")?;
                write_mac(f, *mac)?;
                write!(f, " is not unicast")
            }
        }
    }
}

fn write_mac(f: &mut fmt::Formatter<'_>, mac: [u8; 6]) -> fmt::Result {
    let [a, b, c, d, e, g] = mac;
    write!(f, "{a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{g:02x}")
}

/// A unicast MAC: the group bit (IEEE 802.3 3.2.3) clear, and not the all-zero
/// address, which names nothing.
fn is_unicast(mac: [u8; 6]) -> bool {
    let [first, ..] = mac;
    first & 0x01 == 0 && mac != [0; 6]
}

/// Reads each field exactly once, by copying the whole entry out first: the
/// source may be the shared region, where reading a byte twice can return two
/// different values and validate one of them while keeping the other.
fn check_interface(
    raw: &InterfaceImage,
    index: usize,
    port_count: u8,
) -> Result<CheckedInterface, ConfigImageError> {
    let InterfaceImage {
        port,
        enabled,
        prefix_length,
        mac,
        address,
        ..
    } = *raw;

    let enabled = match enabled {
        0 => false,
        1 => true,
        other => {
            return Err(ConfigImageError::InterfaceEnabledNotBoolean {
                index,
                enabled: other,
            });
        }
    };
    if port >= port_count {
        return Err(ConfigImageError::InterfacePortUnknown { index, port });
    }
    if prefix_length > MAX_PREFIX_LENGTH {
        return Err(ConfigImageError::InterfacePrefixLengthTooLong {
            index,
            prefix_length,
        });
    }
    if !is_unicast(mac) {
        return Err(ConfigImageError::InterfaceMacNotUnicast { index, mac });
    }

    Ok(CheckedInterface {
        port,
        enabled,
        prefix_length,
        mac,
        address,
    })
}

/// As [`check_interface`], for an entry with neither an enable flag nor a
/// prefix to refuse.
fn check_neighbour(
    raw: &NeighbourImage,
    index: usize,
    port_count: u8,
) -> Result<CheckedNeighbour, ConfigImageError> {
    let NeighbourImage {
        port, mac, address, ..
    } = *raw;

    if port >= port_count {
        return Err(ConfigImageError::NeighbourPortUnknown { index, port });
    }
    if !is_unicast(mac) {
        return Err(ConfigImageError::NeighbourMacNotUnicast { index, mac });
    }

    Ok(CheckedNeighbour { port, mac, address })
}

/// One interface that survived [`ConfigImage::check`]. Its fields are private
/// and it has no public constructor, so the only way to hold one is to have
/// checked it — and `enabled` is a `bool` because the byte that was not 0 or 1
/// did not get this far.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CheckedInterface {
    port: u8,
    enabled: bool,
    prefix_length: u8,
    mac: [u8; 6],
    address: [u8; 4],
}

impl CheckedInterface {
    #[must_use]
    pub const fn port(&self) -> u8 {
        self.port
    }

    #[must_use]
    pub const fn enabled(&self) -> bool {
        self.enabled
    }

    #[must_use]
    pub const fn prefix_length(&self) -> u8 {
        self.prefix_length
    }

    #[must_use]
    pub const fn mac(&self) -> [u8; 6] {
        self.mac
    }

    /// Network order, as the address appears in a header.
    #[must_use]
    pub const fn address(&self) -> [u8; 4] {
        self.address
    }
}

/// As [`CheckedInterface`], for a neighbour.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CheckedNeighbour {
    port: u8,
    mac: [u8; 6],
    address: [u8; 4],
}

impl CheckedNeighbour {
    #[must_use]
    pub const fn port(&self) -> u8 {
        self.port
    }

    #[must_use]
    pub const fn mac(&self) -> [u8; 6] {
        self.mac
    }

    /// Network order, as the address appears in a header.
    #[must_use]
    pub const fn address(&self) -> [u8; 4] {
        self.address
    }
}

/// Everything a [`ConfigImage`] said, decoded and owned.
///
/// Owned rather than borrowed because the image it came from may be the shared
/// region itself, and a view into bytes the writer can still change is not a
/// configuration anybody can decide under. The entries are `Option` slots
/// filled from the front, so the length is carried by the data and the writer's
/// count bounds nothing here: iteration is bounded by the arrays (ENG-4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CheckedConfig {
    generation: u32,
    content_hash: u32,
    interfaces: [Option<CheckedInterface>; MAX_INTERFACES],
    neighbours: [Option<CheckedNeighbour>; MAX_NEIGHBOURS],
}

impl CheckedConfig {
    #[must_use]
    pub const fn generation(&self) -> u32 {
        self.generation
    }

    #[must_use]
    pub const fn content_hash(&self) -> u32 {
        self.content_hash
    }

    pub fn interfaces(&self) -> impl Iterator<Item = CheckedInterface> {
        self.interfaces.iter().flatten().copied()
    }

    pub fn neighbours(&self) -> impl Iterator<Item = CheckedNeighbour> {
        self.neighbours.iter().flatten().copied()
    }

    #[must_use]
    pub fn interface_count(&self) -> usize {
        self.interfaces().count()
    }

    #[must_use]
    pub fn neighbour_count(&self) -> usize {
        self.neighbours().count()
    }
}

// The configuration crosses protection domains byte for byte, so a field
// reorder or a width change must be a compile error here rather than a silent
// break of the image the reading domain maps.
const _: () = {
    assert!(size_of::<InterfaceImage>() == 16);
    assert!(align_of::<InterfaceImage>() == 1);
    assert!(offset_of!(InterfaceImage, port) == 0);
    assert!(offset_of!(InterfaceImage, enabled) == 1);
    assert!(offset_of!(InterfaceImage, prefix_length) == 2);
    assert!(offset_of!(InterfaceImage, _pad) == 3);
    assert!(offset_of!(InterfaceImage, mac) == 4);
    assert!(offset_of!(InterfaceImage, _pad2) == 10);
    assert!(offset_of!(InterfaceImage, address) == 12);

    assert!(size_of::<NeighbourImage>() == 16);
    assert!(align_of::<NeighbourImage>() == 1);
    assert!(offset_of!(NeighbourImage, port) == 0);
    assert!(offset_of!(NeighbourImage, _pad) == 1);
    assert!(offset_of!(NeighbourImage, mac) == 4);
    assert!(offset_of!(NeighbourImage, _pad2) == 10);
    assert!(offset_of!(NeighbourImage, address) == 12);

    assert!(size_of::<ConfigImage>() == 656);
    assert!(align_of::<ConfigImage>() == 4);
    assert!(offset_of!(ConfigImage, generation) == 0);
    assert!(offset_of!(ConfigImage, interface_count) == 4);
    assert!(offset_of!(ConfigImage, neighbour_count) == 8);
    assert!(offset_of!(ConfigImage, content_hash) == 12);
    assert!(offset_of!(ConfigImage, interfaces) == 16);
    assert!(offset_of!(ConfigImage, neighbours) == 144);

    // Expressing the image as atomics must leave the region the reading domain
    // maps byte-identical to a plain `ConfigImage`: same size, same alignment,
    // every field at the offset the plain image puts it at.
    assert!(size_of::<InterfaceSlot>() == size_of::<InterfaceImage>());
    assert!(align_of::<InterfaceSlot>() == align_of::<InterfaceImage>());
    assert!(offset_of!(InterfaceSlot, port) == offset_of!(InterfaceImage, port));
    assert!(offset_of!(InterfaceSlot, enabled) == offset_of!(InterfaceImage, enabled));
    assert!(offset_of!(InterfaceSlot, prefix_length) == offset_of!(InterfaceImage, prefix_length));
    assert!(offset_of!(InterfaceSlot, _pad) == offset_of!(InterfaceImage, _pad));
    assert!(offset_of!(InterfaceSlot, mac) == offset_of!(InterfaceImage, mac));
    assert!(offset_of!(InterfaceSlot, _pad2) == offset_of!(InterfaceImage, _pad2));
    assert!(offset_of!(InterfaceSlot, address) == offset_of!(InterfaceImage, address));

    assert!(size_of::<NeighbourSlot>() == size_of::<NeighbourImage>());
    assert!(align_of::<NeighbourSlot>() == align_of::<NeighbourImage>());
    assert!(offset_of!(NeighbourSlot, port) == offset_of!(NeighbourImage, port));
    assert!(offset_of!(NeighbourSlot, _pad) == offset_of!(NeighbourImage, _pad));
    assert!(offset_of!(NeighbourSlot, mac) == offset_of!(NeighbourImage, mac));
    assert!(offset_of!(NeighbourSlot, _pad2) == offset_of!(NeighbourImage, _pad2));
    assert!(offset_of!(NeighbourSlot, address) == offset_of!(NeighbourImage, address));

    assert!(size_of::<ConfigSlot>() == size_of::<ConfigImage>());
    assert!(align_of::<ConfigSlot>() == align_of::<ConfigImage>());
    assert!(offset_of!(ConfigSlot, generation) == offset_of!(ConfigImage, generation));
    assert!(offset_of!(ConfigSlot, interface_count) == offset_of!(ConfigImage, interface_count));
    assert!(offset_of!(ConfigSlot, neighbour_count) == offset_of!(ConfigImage, neighbour_count));
    assert!(offset_of!(ConfigSlot, content_hash) == offset_of!(ConfigImage, content_hash));
    assert!(offset_of!(ConfigSlot, interfaces) == offset_of!(ConfigImage, interfaces));
    assert!(offset_of!(ConfigSlot, neighbours) == offset_of!(ConfigImage, neighbours));

    assert!(size_of::<ConfigHandover>() == 664);
    assert!(align_of::<ConfigHandover>() == 4);
    assert!(offset_of!(ConfigHandover, offered) == 0);
    assert!(offset_of!(ConfigHandover, committed) == 4);
    assert!(offset_of!(ConfigHandover, image) == 8);

    assert!(size_of::<ConfigAck>() == 8);
    assert!(align_of::<ConfigAck>() == 4);
    assert!(offset_of!(ConfigAck, staged) == 0);
    assert!(offset_of!(ConfigAck, running) == 4);

    // A region must hold its type and be mappable, which is the whole of what
    // the derivation above is for.
    assert!(CONFIG_REGION_SIZE >= size_of::<ConfigHandover>());
    assert!(CONFIG_REGION_SIZE.is_multiple_of(MAPPING_ALIGN));
    assert!(CONFIG_ACK_REGION_SIZE >= size_of::<ConfigAck>());
    assert!(CONFIG_ACK_REGION_SIZE.is_multiple_of(MAPPING_ALIGN));
};

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// Either verdict, so a property covers both encodable values.
    fn any_verdict() -> impl Strategy<Value = Verdict> {
        prop_oneof![Just(Verdict::Transmit), Just(Verdict::Discard)]
    }

    #[test]
    fn zero_matches_default_and_explicit_zero() {
        assert_eq!(Descriptor::default(), Descriptor::ZERO);
        assert_eq!(
            Descriptor::ZERO,
            Descriptor::new(0, 0, 0, Verdict::Transmit)
        );
    }

    #[test]
    fn descriptor_has_stable_little_endian_byte_layout() {
        // The exact on-wire image the peer PD reads: four little-endian u32s in
        // declaration order. This is the ABI regression test beyond size/align.
        let d = Descriptor::new(0x1122_3344, 0x5566_7788, 0x99AA_BBCC, Verdict::Discard);
        // SAFETY: `Descriptor` is `#[repr(C)]`, `Copy`, and asserted to be 16
        // bytes with no padding, so transmuting it to `[u8; 16]` is sound.
        let bytes: [u8; 16] = unsafe { core::mem::transmute(d) };
        assert_eq!(
            bytes,
            [
                0x44, 0x33, 0x22, 0x11, 0x88, 0x77, 0x66, 0x55, 0xCC, 0xBB, 0xAA, 0x99, 0x01, 0x00,
                0x00, 0x00
            ]
        );
    }

    proptest! {
        /// For any field values, a descriptor round-trips through its wire image:
        /// its fields are exactly the constructor arguments, and its 16-byte
        /// `#[repr(C)]` image is the four fields as little-endian `u32`s in
        /// declaration order — and reconstructing a descriptor from those bytes
        /// yields the original.
        #[test]
        fn descriptor_round_trips_through_its_byte_image(
            buffer in any::<u32>(),
            offset in any::<u32>(),
            len in any::<u32>(),
            verdict in any_verdict(),
        ) {
            let descriptor = Descriptor::new(buffer, offset, len, verdict);
            prop_assert_eq!(descriptor.buffer, buffer);
            prop_assert_eq!(descriptor.offset, offset);
            prop_assert_eq!(descriptor.len, len);
            prop_assert_eq!(Verdict::from_bits(descriptor.verdict), Some(verdict));

            // SAFETY: `Descriptor` is `#[repr(C)]`, `Copy`, and asserted to be 16
            // bytes with no padding, so it transmutes to and from `[u8; 16]`.
            let bytes: [u8; 16] = unsafe { core::mem::transmute(descriptor) };
            let mut expected = [0u8; 16];
            expected[0..4].copy_from_slice(&buffer.to_le_bytes());
            expected[4..8].copy_from_slice(&offset.to_le_bytes());
            expected[8..12].copy_from_slice(&len.to_le_bytes());
            expected[12..16].copy_from_slice(&verdict.to_bits().to_le_bytes());
            prop_assert_eq!(bytes, expected);

            // SAFETY: same `repr(C)`, 16-byte, no-padding guarantee in reverse;
            // any bit pattern is a valid `Descriptor` (four `u32` fields).
            let recovered: Descriptor = unsafe { core::mem::transmute(bytes) };
            prop_assert_eq!(recovered, descriptor);
        }

        /// The verdict word is peer-written, so decoding is total over `u32`:
        /// exactly the values `to_bits` can produce decode, every other one is
        /// refused rather than coerced to a variant nobody chose.
        #[test]
        fn from_bits_accepts_exactly_what_to_bits_produces(bits in any::<u32>()) {
            let expected = [Verdict::Transmit, Verdict::Discard]
                .into_iter()
                .find(|verdict| verdict.to_bits() == bits);
            prop_assert_eq!(Verdict::from_bits(bits), expected);
            if let Some(verdict) = Verdict::from_bits(bits) {
                prop_assert_eq!(verdict.to_bits(), bits);
            }
        }
    }

    /// Ports this build has, in the tests. Two, as the appliance has.
    const PORTS: u8 = 2;

    /// A locally administered unicast address, so nothing about it is refusable.
    const UNICAST: [u8; 6] = [0x52, 0x54, 0x00, 0x12, 0x34, 0x50];

    fn interface(port: u8) -> InterfaceImage {
        InterfaceImage {
            port,
            enabled: 1,
            prefix_length: 24,
            mac: UNICAST,
            address: [10, 0, 0, 1],
            ..InterfaceImage::ZERO
        }
    }

    fn neighbour(port: u8) -> NeighbourImage {
        NeighbourImage {
            port,
            mac: UNICAST,
            address: [10, 0, 0, 2],
            ..NeighbourImage::ZERO
        }
    }

    /// An image whose first `interfaces` and `neighbours` slots are valid,
    /// with the counts to match.
    fn image(interfaces: usize, neighbours: usize) -> ConfigImage {
        let mut image = ConfigImage::ZERO;
        image.generation = 7;
        image.content_hash = 0xdead_beef;
        image.interface_count = interfaces as u32;
        image.neighbour_count = neighbours as u32;
        for (index, slot) in image.interfaces.iter_mut().enumerate() {
            *slot = interface((index % usize::from(PORTS)) as u8);
        }
        for (index, slot) in image.neighbours.iter_mut().enumerate() {
            *slot = neighbour((index % usize::from(PORTS)) as u8);
        }
        image
    }

    #[test]
    fn a_zeroed_region_is_the_fail_closed_configuration() {
        let checked = ConfigImage::ZERO.check(PORTS).expect("zero is valid");
        assert_eq!(checked.generation(), 0);
        assert_eq!(checked.content_hash(), 0);
        assert_eq!(checked.interface_count(), 0);
        assert_eq!(checked.neighbour_count(), 0);
        assert_eq!(checked.interfaces().next(), None);
        assert_eq!(checked.neighbours().next(), None);
    }

    #[test]
    fn a_checked_image_carries_its_generation_and_hash_and_every_decoded_field() {
        let checked = image(2, 3).check(PORTS).expect("valid");
        assert_eq!(checked.generation(), 7);
        assert_eq!(checked.content_hash(), 0xdead_beef);
        assert_eq!(checked.interface_count(), 2);
        assert_eq!(checked.neighbour_count(), 3);

        let first = checked.interfaces().next().expect("one interface");
        assert_eq!(first.port(), 0);
        assert!(first.enabled());
        assert_eq!(first.prefix_length(), 24);
        assert_eq!(first.mac(), UNICAST);
        assert_eq!(first.address(), [10, 0, 0, 1]);

        let hop = checked.neighbours().next().expect("one neighbour");
        assert_eq!(hop.port(), 0);
        assert_eq!(hop.mac(), UNICAST);
        assert_eq!(hop.address(), [10, 0, 0, 2]);
    }

    #[test]
    fn only_the_counted_prefix_is_read_whatever_follows_it() {
        // Every slot past the count is a value that would be refused if read.
        let mut raw = image(1, 1);
        for slot in raw.interfaces.iter_mut().skip(1) {
            slot.enabled = 0xff;
            slot.port = 0xff;
        }
        for slot in raw.neighbours.iter_mut().skip(1) {
            slot.mac = [0; 6];
        }
        let checked = raw.check(PORTS).expect("the garbage is beyond the counts");
        assert_eq!(checked.interface_count(), 1);
        assert_eq!(checked.neighbour_count(), 1);
    }

    #[test]
    fn an_interface_count_at_capacity_is_accepted() {
        let checked = image(MAX_INTERFACES, 0).check(PORTS).expect("valid");
        assert_eq!(checked.interface_count(), MAX_INTERFACES);
    }

    #[test]
    fn an_interface_count_above_capacity_is_refused() {
        let mut raw = image(MAX_INTERFACES, 0);
        raw.interface_count = MAX_INTERFACES as u32 + 1;
        assert_eq!(
            raw.check(PORTS),
            Err(ConfigImageError::InterfaceCountExceedsCapacity { count: 9 })
        );
    }

    #[test]
    fn an_interface_count_of_u32_max_is_refused_rather_than_wrapped() {
        let mut raw = image(0, 0);
        raw.interface_count = u32::MAX;
        assert_eq!(
            raw.check(PORTS),
            Err(ConfigImageError::InterfaceCountExceedsCapacity { count: u32::MAX })
        );
    }

    #[test]
    fn a_neighbour_count_at_capacity_is_accepted() {
        let checked = image(0, MAX_NEIGHBOURS).check(PORTS).expect("valid");
        assert_eq!(checked.neighbour_count(), MAX_NEIGHBOURS);
    }

    #[test]
    fn a_neighbour_count_above_capacity_is_refused() {
        let mut raw = image(0, MAX_NEIGHBOURS);
        raw.neighbour_count = MAX_NEIGHBOURS as u32 + 1;
        assert_eq!(
            raw.check(PORTS),
            Err(ConfigImageError::NeighbourCountExceedsCapacity { count: 33 })
        );
    }

    #[test]
    fn an_enabled_byte_of_zero_or_one_is_accepted() {
        for (bits, expected) in [(0u8, false), (1, true)] {
            let mut raw = image(1, 0);
            raw.interfaces[0].enabled = bits;
            let checked = raw.check(PORTS).expect("0 and 1 are the decodable values");
            assert_eq!(
                checked.interfaces().next().map(|i| i.enabled()),
                Some(expected)
            );
        }
    }

    #[test]
    fn an_enabled_byte_that_is_neither_zero_nor_one_is_refused() {
        for bits in [2u8, 255] {
            let mut raw = image(2, 0);
            raw.interfaces[1].enabled = bits;
            assert_eq!(
                raw.check(PORTS),
                Err(ConfigImageError::InterfaceEnabledNotBoolean {
                    index: 1,
                    enabled: bits
                })
            );
        }
    }

    #[test]
    fn an_interface_naming_a_port_the_build_does_not_have_is_refused() {
        let mut raw = image(1, 0);
        raw.interfaces[0].port = PORTS;
        assert_eq!(
            raw.check(PORTS),
            Err(ConfigImageError::InterfacePortUnknown { index: 0, port: 2 })
        );
    }

    #[test]
    fn a_neighbour_naming_a_port_the_build_does_not_have_is_refused() {
        let mut raw = image(0, 2);
        raw.neighbours[1].port = 200;
        assert_eq!(
            raw.check(PORTS),
            Err(ConfigImageError::NeighbourPortUnknown {
                index: 1,
                port: 200
            })
        );
    }

    #[test]
    fn a_build_with_no_ports_accepts_no_entry_at_all() {
        assert_eq!(
            image(1, 0).check(0),
            Err(ConfigImageError::InterfacePortUnknown { index: 0, port: 0 })
        );
        assert_eq!(
            image(0, 1).check(0),
            Err(ConfigImageError::NeighbourPortUnknown { index: 0, port: 0 })
        );
    }

    #[test]
    fn a_prefix_length_of_thirty_two_is_accepted() {
        let mut raw = image(1, 0);
        raw.interfaces[0].prefix_length = MAX_PREFIX_LENGTH;
        let checked = raw.check(PORTS).expect("a host route is a prefix");
        assert_eq!(
            checked.interfaces().next().map(|i| i.prefix_length()),
            Some(32)
        );
    }

    #[test]
    fn a_prefix_length_above_thirty_two_is_refused() {
        for length in [MAX_PREFIX_LENGTH + 1, 200, u8::MAX] {
            let mut raw = image(1, 0);
            raw.interfaces[0].prefix_length = length;
            assert_eq!(
                raw.check(PORTS),
                Err(ConfigImageError::InterfacePrefixLengthTooLong {
                    index: 0,
                    prefix_length: length
                })
            );
        }
    }

    #[test]
    fn an_interface_mac_that_is_not_unicast_is_refused() {
        for mac in [[0x01, 0, 0, 0, 0, 0], [0xff; 6], [0; 6]] {
            let mut raw = image(1, 0);
            raw.interfaces[0].mac = mac;
            assert_eq!(
                raw.check(PORTS),
                Err(ConfigImageError::InterfaceMacNotUnicast { index: 0, mac })
            );
        }
    }

    #[test]
    fn a_neighbour_mac_that_is_not_unicast_is_refused() {
        for mac in [[0x01, 0, 0, 0, 0, 0], [0xff; 6], [0; 6]] {
            let mut raw = image(0, 1);
            raw.neighbours[0].mac = mac;
            assert_eq!(
                raw.check(PORTS),
                Err(ConfigImageError::NeighbourMacNotUnicast { index: 0, mac })
            );
        }
    }

    #[test]
    fn padding_the_writer_chose_is_read_by_nothing() {
        let mut raw = image(1, 1);
        raw.interfaces[0]._pad = 0xaa;
        raw.interfaces[0]._pad2 = [0xbb; 2];
        raw.neighbours[0]._pad = [0xcc; 3];
        raw.neighbours[0]._pad2 = [0xdd; 2];
        assert_eq!(raw.check(PORTS), image(1, 1).check(PORTS));
    }

    #[test]
    fn the_layout_the_reading_domain_maps_is_the_recorded_one() {
        assert_eq!(size_of::<InterfaceImage>(), 16);
        assert_eq!(size_of::<NeighbourImage>(), 16);
        assert_eq!(size_of::<ConfigImage>(), 656);
        assert_eq!(size_of::<ConfigHandover>(), 664);
        assert_eq!(size_of::<ConfigAck>(), 8);
        assert_eq!(offset_of!(ConfigImage, interfaces), 16);
        assert_eq!(offset_of!(ConfigImage, neighbours), 144);
        assert_eq!(offset_of!(ConfigHandover, image), 8);
        assert_eq!(CONFIG_REGION_SIZE, 0x1000);
        assert_eq!(CONFIG_ACK_REGION_SIZE, 0x1000);
    }

    /// The compile-time assertions above prove the same equalities, but only
    /// for the build that compiles them away; this is the one a failure names.
    #[test]
    fn the_atomic_image_occupies_exactly_the_bytes_the_plain_one_does() {
        assert_eq!(size_of::<ConfigSlot>(), size_of::<ConfigImage>());
        assert_eq!(align_of::<ConfigSlot>(), align_of::<ConfigImage>());
        assert_eq!(
            [
                offset_of!(ConfigSlot, generation),
                offset_of!(ConfigSlot, interface_count),
                offset_of!(ConfigSlot, neighbour_count),
                offset_of!(ConfigSlot, content_hash),
                offset_of!(ConfigSlot, interfaces),
                offset_of!(ConfigSlot, neighbours),
            ],
            [
                offset_of!(ConfigImage, generation),
                offset_of!(ConfigImage, interface_count),
                offset_of!(ConfigImage, neighbour_count),
                offset_of!(ConfigImage, content_hash),
                offset_of!(ConfigImage, interfaces),
                offset_of!(ConfigImage, neighbours),
            ]
        );

        assert_eq!(size_of::<InterfaceSlot>(), size_of::<InterfaceImage>());
        assert_eq!(align_of::<InterfaceSlot>(), align_of::<InterfaceImage>());
        assert_eq!(
            [
                offset_of!(InterfaceSlot, port),
                offset_of!(InterfaceSlot, enabled),
                offset_of!(InterfaceSlot, prefix_length),
                offset_of!(InterfaceSlot, _pad),
                offset_of!(InterfaceSlot, mac),
                offset_of!(InterfaceSlot, _pad2),
                offset_of!(InterfaceSlot, address),
            ],
            [
                offset_of!(InterfaceImage, port),
                offset_of!(InterfaceImage, enabled),
                offset_of!(InterfaceImage, prefix_length),
                offset_of!(InterfaceImage, _pad),
                offset_of!(InterfaceImage, mac),
                offset_of!(InterfaceImage, _pad2),
                offset_of!(InterfaceImage, address),
            ]
        );

        assert_eq!(size_of::<NeighbourSlot>(), size_of::<NeighbourImage>());
        assert_eq!(align_of::<NeighbourSlot>(), align_of::<NeighbourImage>());
        assert_eq!(
            [
                offset_of!(NeighbourSlot, port),
                offset_of!(NeighbourSlot, _pad),
                offset_of!(NeighbourSlot, mac),
                offset_of!(NeighbourSlot, _pad2),
                offset_of!(NeighbourSlot, address),
            ],
            [
                offset_of!(NeighbourImage, port),
                offset_of!(NeighbourImage, _pad),
                offset_of!(NeighbourImage, mac),
                offset_of!(NeighbourImage, _pad2),
                offset_of!(NeighbourImage, address),
            ]
        );
    }

    /// A zeroed region reads back as the zeroed image, which is what lets a
    /// reader come up against one before anything has been published.
    #[test]
    fn an_untouched_handover_holds_the_zero_image() {
        assert_eq!(ConfigHandover::zero().load_image(), ConfigImage::ZERO);
        assert_eq!(ConfigSlot::zero().load(), ConfigImage::ZERO);
        assert_eq!(InterfaceSlot::zero().load(), InterfaceImage::ZERO);
        assert_eq!(NeighbourSlot::zero().load(), NeighbourImage::ZERO);
    }

    /// Publishing is one act: the generation the reader sees and the bytes it
    /// reads under that generation are the ones handed to the same call.
    #[test]
    fn publishing_offers_the_generation_and_the_bytes_it_names() {
        let handover = ConfigHandover::zero();
        let mut offered = image(2, 3);
        offered.generation = 9;
        handover.publish(&offered);
        assert_eq!(handover.offered_generation(), offered.generation);
        assert_eq!(handover.load_image(), offered);
        // Committing moves its own word and disturbs neither of the two.
        handover.publish_committed(8);
        assert_eq!(handover.committed_generation(), 8);
        assert_eq!(handover.offered_generation(), 9);
        assert_eq!(handover.load_image(), offered);

        // A second generation replaces both together.
        let mut next = image(1, 1);
        next.generation = 10;
        handover.publish(&next);
        assert_eq!(handover.offered_generation(), 10);
        assert_eq!(handover.load_image(), next);
    }

    #[test]
    fn a_published_generation_is_what_the_other_side_reads_back() {
        let handover = ConfigHandover::zero();
        assert_eq!(handover.offered_generation(), 0);
        assert_eq!(handover.committed_generation(), 0);
        let mut offered = ConfigImage::ZERO;
        offered.generation = 4;
        handover.publish(&offered);
        handover.publish_committed(3);
        assert_eq!(handover.offered_generation(), 4);
        assert_eq!(handover.committed_generation(), 3);
        assert_eq!(handover.load_image(), offered);

        let ack = ConfigAck::zero();
        assert_eq!(ack.staged_generation(), 0);
        assert_eq!(ack.running_generation(), 0);
        ack.publish_staged(4);
        ack.publish_running(2);
        assert_eq!(ack.staged_generation(), 4);
        assert_eq!(ack.running_generation(), 2);
    }

    #[test]
    fn every_refusal_names_the_field_and_the_value() {
        let rendered: Vec<String> = [
            ConfigImageError::InterfaceCountExceedsCapacity { count: 9 },
            ConfigImageError::NeighbourCountExceedsCapacity { count: 33 },
            ConfigImageError::InterfaceEnabledNotBoolean {
                index: 1,
                enabled: 2,
            },
            ConfigImageError::InterfacePortUnknown { index: 2, port: 7 },
            ConfigImageError::NeighbourPortUnknown { index: 3, port: 8 },
            ConfigImageError::InterfacePrefixLengthTooLong {
                index: 4,
                prefix_length: 200,
            },
            ConfigImageError::InterfaceMacNotUnicast {
                index: 5,
                mac: [0x01, 0x02, 0x03, 0x04, 0x05, 0x06],
            },
            ConfigImageError::NeighbourMacNotUnicast {
                index: 6,
                mac: [0; 6],
            },
        ]
        .iter()
        .map(|error| format!("{error}"))
        .collect();

        assert_eq!(
            rendered,
            [
                "interface count 9 exceeds the 8 slots the image holds",
                "neighbour count 33 exceeds the 32 slots the image holds",
                "interface 1 enabled byte 2 is not 0 or 1",
                "interface 2 names port 7, which does not exist",
                "neighbour 3 names port 8, which does not exist",
                "interface 4 prefix length 200 exceeds 32",
                "interface 5 MAC 01:02:03:04:05:06 is not unicast",
                "neighbour 6 MAC 00:00:00:00:00:00 is not unicast",
            ]
        );
    }

    /// Boxed, as every entry strategy below is: a 32-element array of the
    /// unboxed value trees is a stack frame the unoptimized test binary
    /// overflows on.
    fn any_interface_image() -> BoxedStrategy<InterfaceImage> {
        (
            any::<[u8; 4]>(),
            any::<[u8; 6]>(),
            any::<[u8; 2]>(),
            any::<[u8; 4]>(),
        )
            .prop_map(
                |([port, enabled, prefix_length, pad], mac, pad2, address)| InterfaceImage {
                    port,
                    enabled,
                    prefix_length,
                    _pad: pad,
                    mac,
                    _pad2: pad2,
                    address,
                },
            )
            .boxed()
    }

    fn any_neighbour_image() -> BoxedStrategy<NeighbourImage> {
        (
            any::<u8>(),
            any::<[u8; 3]>(),
            any::<[u8; 6]>(),
            any::<[u8; 2]>(),
            any::<[u8; 4]>(),
        )
            .prop_map(|(port, pad, mac, pad2, address)| NeighbourImage {
                port,
                _pad: pad,
                mac,
                _pad2: pad2,
                address,
            })
            .boxed()
    }

    /// A MAC that is usually unicast: the group bit cleared and the
    /// locally-administered bit set, which is also what makes it non-zero.
    fn plausible_mac() -> impl Strategy<Value = [u8; 6]> {
        prop_oneof![
            9 => any::<[u8; 6]>().prop_map(|[a, b, c, d, e, f]| [(a & 0xfe) | 0x02, b, c, d, e, f]),
            1 => any::<[u8; 6]>(),
        ]
    }

    /// An entry whose every field is usually the kind of value a well-behaved
    /// writer produces, and occasionally anything at all.
    ///
    /// Uniform bytes are not enough on their own: an arbitrary `enabled` byte
    /// is 0 or 1 twice in 256, so an image of even one interface is refused
    /// almost always and the accepted path — where the rules about what is
    /// *yielded* live — is never reached. The low-weight arms keep the whole
    /// input space in range.
    fn plausible_interface_image() -> BoxedStrategy<InterfaceImage> {
        (
            prop_oneof![9 => 0u8..=1, 1 => any::<u8>()],
            prop_oneof![9 => 0u8..=1, 1 => any::<u8>()],
            prop_oneof![9 => 0u8..=MAX_PREFIX_LENGTH, 1 => any::<u8>()],
            plausible_mac(),
            any::<[u8; 4]>(),
        )
            .prop_map(
                |(port, enabled, prefix_length, mac, address)| InterfaceImage {
                    port,
                    enabled,
                    prefix_length,
                    mac,
                    address,
                    ..InterfaceImage::ZERO
                },
            )
            .boxed()
    }

    /// As [`plausible_interface_image`], for a neighbour.
    fn plausible_neighbour_image() -> BoxedStrategy<NeighbourImage> {
        (
            prop_oneof![9 => 0u8..=1, 1 => any::<u8>()],
            plausible_mac(),
            any::<[u8; 4]>(),
        )
            .prop_map(|(port, mac, address)| NeighbourImage {
                port,
                mac,
                address,
                ..NeighbourImage::ZERO
            })
            .boxed()
    }

    /// An image built from whatever entries the given strategies produce. The
    /// counts are left at zero for the caller to set, because what a count says
    /// against what the arrays hold is the property under test.
    fn config_image(
        interfaces: BoxedStrategy<InterfaceImage>,
        neighbours: BoxedStrategy<NeighbourImage>,
    ) -> impl Strategy<Value = ConfigImage> {
        (
            any::<u32>(),
            any::<u32>(),
            proptest::array::uniform8(interfaces),
            proptest::array::uniform32(neighbours),
        )
            .prop_map(
                |(generation, content_hash, interfaces, neighbours)| ConfigImage {
                    generation,
                    content_hash,
                    interfaces,
                    neighbours,
                    ..ConfigImage::ZERO
                },
            )
    }

    /// Counts weighted low, then to the capacity boundary, then anywhere at
    /// all. A count drawn uniformly over `u32` exceeds capacity in every
    /// practical case, so on its own it would prove only that the reader
    /// refuses — the low arm is what makes the accepted path reachable often
    /// enough to assert anything about what is yielded.
    fn any_plausible_count() -> impl Strategy<Value = u32> {
        prop_oneof![
            4 => 0u32..=3,
            2 => 0u32..=40,
            1 => any::<u32>(),
        ]
    }

    /// The rules restated independently of the reader, in the order the reader
    /// applies them, so the property below pins totality and not merely
    /// agreement about which inputs are bad.
    fn expected_refusal(image: &ConfigImage, port_count: u8) -> Option<ConfigImageError> {
        if image.interface_count as usize > MAX_INTERFACES {
            return Some(ConfigImageError::InterfaceCountExceedsCapacity {
                count: image.interface_count,
            });
        }
        if image.neighbour_count as usize > MAX_NEIGHBOURS {
            return Some(ConfigImageError::NeighbourCountExceedsCapacity {
                count: image.neighbour_count,
            });
        }
        for (index, raw) in image
            .interfaces
            .iter()
            .enumerate()
            .take(image.interface_count as usize)
        {
            if raw.enabled > 1 {
                return Some(ConfigImageError::InterfaceEnabledNotBoolean {
                    index,
                    enabled: raw.enabled,
                });
            }
            if raw.port >= port_count {
                return Some(ConfigImageError::InterfacePortUnknown {
                    index,
                    port: raw.port,
                });
            }
            if raw.prefix_length > MAX_PREFIX_LENGTH {
                return Some(ConfigImageError::InterfacePrefixLengthTooLong {
                    index,
                    prefix_length: raw.prefix_length,
                });
            }
            if !is_unicast(raw.mac) {
                return Some(ConfigImageError::InterfaceMacNotUnicast {
                    index,
                    mac: raw.mac,
                });
            }
        }
        for (index, raw) in image
            .neighbours
            .iter()
            .enumerate()
            .take(image.neighbour_count as usize)
        {
            if raw.port >= port_count {
                return Some(ConfigImageError::NeighbourPortUnknown {
                    index,
                    port: raw.port,
                });
            }
            if !is_unicast(raw.mac) {
                return Some(ConfigImageError::NeighbourMacNotUnicast {
                    index,
                    mac: raw.mac,
                });
            }
        }
        None
    }

    proptest! {
        /// The byzantine-writer property over the region's whole input space:
        /// every field independently arbitrary, every byte of it a value the
        /// writer picked. The reader returns rather than panics, never yields
        /// more entries than the arrays hold nor more than the count named, and
        /// every entry it yields satisfies every rule.
        #[test]
        fn a_wholly_arbitrary_region_is_read_without_panicking_and_stays_bounded(
            mut image in config_image(any_interface_image(), any_neighbour_image()),
            interface_count in any_plausible_count(),
            neighbour_count in any_plausible_count(),
            port_count in any::<u8>(),
        ) {
            image.interface_count = interface_count;
            image.neighbour_count = neighbour_count;

            let Ok(checked) = image.check(port_count) else {
                return Ok(());
            };
            prop_assert!(checked.interface_count() <= MAX_INTERFACES);
            prop_assert!(checked.neighbour_count() <= MAX_NEIGHBOURS);
            prop_assert_eq!(checked.interface_count(), interface_count as usize);
            prop_assert_eq!(checked.neighbour_count(), neighbour_count as usize);
            for entry in checked.interfaces() {
                prop_assert!(entry.port() < port_count);
                prop_assert!(entry.prefix_length() <= MAX_PREFIX_LENGTH);
                prop_assert!(is_unicast(entry.mac()));
            }
            for entry in checked.neighbours() {
                prop_assert!(entry.port() < port_count);
                prop_assert!(is_unicast(entry.mac()));
            }
        }

        /// The same region, with each field weighted towards a value a
        /// well-behaved writer would produce so the accepted path is reached as
        /// often as the refused one. Beyond the bounds above it pins totality:
        /// the reader refuses exactly the images a rule refuses, with exactly
        /// the error that rule names, so nothing is accepted by omission and no
        /// refusal is attributed to the wrong field.
        #[test]
        fn an_arbitrary_region_is_read_totally_and_yields_only_valid_entries(
            mut image in config_image(plausible_interface_image(), plausible_neighbour_image()),
            interface_count in any_plausible_count(),
            neighbour_count in any_plausible_count(),
            port_count in 1u8..=4,
        ) {
            image.interface_count = interface_count;
            image.neighbour_count = neighbour_count;

            let outcome = image.check(port_count);
            prop_assert_eq!(outcome.err(), expected_refusal(&image, port_count));

            let Ok(checked) = image.check(port_count) else {
                return Ok(());
            };
            prop_assert!(checked.interface_count() <= MAX_INTERFACES);
            prop_assert!(checked.neighbour_count() <= MAX_NEIGHBOURS);
            prop_assert_eq!(checked.interface_count(), interface_count as usize);
            prop_assert_eq!(checked.neighbour_count(), neighbour_count as usize);
            prop_assert_eq!(checked.generation(), image.generation);
            prop_assert_eq!(checked.content_hash(), image.content_hash);

            for entry in checked.interfaces() {
                prop_assert!(entry.port() < port_count);
                prop_assert!(entry.prefix_length() <= MAX_PREFIX_LENGTH);
                prop_assert!(is_unicast(entry.mac()));
            }
            for entry in checked.neighbours() {
                prop_assert!(entry.port() < port_count);
                prop_assert!(is_unicast(entry.mac()));
            }
        }

        /// A count the writer inflates cannot make the reader read a slot the
        /// arrays do not have: the bound is the capacity, not the count.
        #[test]
        fn a_count_beyond_capacity_is_refused_for_being_one(
            interface_count in (MAX_INTERFACES as u32 + 1)..=u32::MAX,
            neighbour_count in (MAX_NEIGHBOURS as u32 + 1)..=u32::MAX,
        ) {
            let mut inflated = image(MAX_INTERFACES, MAX_NEIGHBOURS);
            inflated.interface_count = interface_count;
            prop_assert_eq!(
                inflated.check(PORTS),
                Err(ConfigImageError::InterfaceCountExceedsCapacity { count: interface_count })
            );

            let mut inflated = image(MAX_INTERFACES, MAX_NEIGHBOURS);
            inflated.neighbour_count = neighbour_count;
            prop_assert_eq!(
                inflated.check(PORTS),
                Err(ConfigImageError::NeighbourCountExceedsCapacity { count: neighbour_count })
            );
        }

        /// Every byte of an arbitrary image survives the region unchanged,
        /// padding included: the atomic image moves an image and rules on none
        /// of it, so a writer's bytes are the reader's bytes whatever they say.
        #[test]
        fn an_arbitrary_image_round_trips_through_the_region(
            mut written in config_image(any_interface_image(), any_neighbour_image()),
            interface_count in any::<u32>(),
            neighbour_count in any::<u32>(),
        ) {
            written.interface_count = interface_count;
            written.neighbour_count = neighbour_count;

            let slot = ConfigSlot::zero();
            slot.store(&written);
            prop_assert_eq!(slot.load(), written);

            // And again over an already-written region, so no field is left
            // holding what the previous generation put there.
            slot.store(&ConfigImage::ZERO);
            prop_assert_eq!(slot.load(), ConfigImage::ZERO);
            slot.store(&written);
            prop_assert_eq!(slot.load(), written);

            let handover = ConfigHandover::zero();
            handover.publish(&written);
            prop_assert_eq!(handover.load_image(), written);
            prop_assert_eq!(handover.offered_generation(), written.generation);
        }

        /// A generation published on either region is read back as itself, and
        /// the two words on a region do not disturb each other.
        #[test]
        fn published_generations_are_independent(offered in any::<u32>(), committed in any::<u32>()) {
            let handover = ConfigHandover::zero();
            handover.publish(&ConfigImage { generation: offered, ..ConfigImage::ZERO });
            handover.publish_committed(committed);
            prop_assert_eq!(handover.offered_generation(), offered);
            prop_assert_eq!(handover.committed_generation(), committed);

            let ack = ConfigAck::zero();
            ack.publish_staged(offered);
            ack.publish_running(committed);
            prop_assert_eq!(ack.staged_generation(), offered);
            prop_assert_eq!(ack.running_generation(), committed);
        }
    }
}
