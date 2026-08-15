//! What the appliance shipped up its channel, held to what is on its medium.
//!
//! # The pair this replaces, and why it is the same pair
//!
//! A recording is worth asserting on twice, from two places that cannot agree
//! with each other by construction. One reading is the appliance's own account
//! of the recording — the bytes it hands a management plane that asks. The other
//! is the medium itself, read on the host side of the emulation by a process the
//! guest cannot reach. A recorder that answered a plausible body out of its own
//! memory satisfies every client and leaves the disk empty; a recorder that
//! wrote a fine extent and shipped something else leaves a management server
//! holding a fiction. Neither surface notices on its own.
//!
//! The account used to be an HTTP response. It is now the shipment frames the
//! appliance writes onto the channel it dials, which is the only way a recording
//! leaves this appliance at all — so this module reads them off the management
//! server's transcript and holds them, byte for byte at the positions they
//! themselves state, to the extents [`crate::data_disk`] reads off the image.
//!
//! # Why byte-for-byte, and why at the peer's coordinate
//!
//! Because the framing contract says the ring bytes **are** the wire bytes: a
//! shipment carries a ring position and then the ring's own bytes from it,
//! verbatim, re-encoding nothing. That makes the comparison total rather than
//! statistical — there is no summary to agree on, only the bytes — and it makes
//! the position load-bearing: a shipment that names a position it did not ship
//! from would leave a server assembling a recording with a hole in it, and the
//! only thing that can catch it is a second reading of the same coordinate.
//!
//! # The transcript is not a clean stream, so the walk seeks rather than follows
//!
//! `openssl s_server` prints its own lines around the application data it
//! received, and the appliance re-dials as it pleases, so the file holds one or
//! more sessions with chatter between them and no single point where a frame
//! stream begins. The walk therefore **seeks** each shipment header — either
//! ring's type byte with the three reserved bytes this protocol holds at zero —
//! and follows the length it states. A header whose body the file does not carry
//! is stepped over by one byte rather than trusted, so `openssl`'s own text can
//! neither invent a shipment nor hide the one after it. Greetings are counted
//! the same way, which is what says how many sessions the file holds without
//! the count deciding where any frame is.
//!
//! # No adversary
//!
//! Build orchestration on the host side of an emulator; no threat-model
//! adversary is named for it. The guest composed every byte walked here — that
//! is the point — so the walk is bounded by the transcript's own length, follows
//! only lengths the bytes state, and answers a verdict rather than panicking, on
//! the terms this crate states for every reader of guest-composed bytes.

use std::collections::BTreeMap;
use std::fmt::Write as _;

/// The appliance's greeting, byte for byte: eight bytes of header and the
/// protocol version.
///
/// Written out rather than encoded, on [`crate::channel_contract`]'s terms
/// exactly — a harness that built it out of the code under test would be looking
/// for whatever that code emits rather than for what the contract page states.
pub(crate) const APPLIANCE_GREETING: [u8; 10] = [0, 0, 0, 2, 1, 0, 0, 0, 0, 1];

/// Bytes of frame header ahead of every payload.
pub(crate) const HEADER_LEN: usize = 8;

/// Bytes of ring position ahead of a shipment's recording bytes.
pub(crate) const POSITION_LEN: usize = 8;

/// The two frame types that carry recording bytes upstream, and the ring each
/// names.
pub(crate) const UP_RECORDS: u8 = 0x02;
pub(crate) const UP_CAPTURE: u8 = 0x03;

/// Which recording a shipment carries, as this contract names it in a verdict.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Ring {
    Log,
    Capture,
}

impl Ring {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Log => "the connection history",
            Self::Capture => "the capture",
        }
    }
}

/// One shipment frame the appliance wrote: which ring, from which position, and
/// the ring bytes it carried.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Shipment {
    pub ring: Ring,
    /// The byte position in the ring's own append space the bytes start at,
    /// which is the coordinate the ring's superblock keeps and the offset into
    /// the extent's payload area.
    pub position: u64,
    pub bytes: Vec<u8>,
}

/// What one walk of a transcript found.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Shipped {
    /// Sessions the walk anchored on, which is how many times the appliance
    /// greeted this server.
    pub sessions: usize,
    pub shipments: Vec<Shipment>,
}

impl Shipped {
    /// Bytes of one ring, in the order the shipments carried them.
    fn of(&self, ring: Ring) -> impl Iterator<Item = &Shipment> {
        self.shipments
            .iter()
            .filter(move |shipment| shipment.ring == ring)
    }

    /// Every shipment as the position and byte count the session-level contract
    /// reads them by, in the order the transcript holds them.
    #[must_use]
    pub fn positions(&self) -> Vec<(u8, u64, usize)> {
        self.shipments
            .iter()
            .map(|shipment| {
                (
                    match shipment.ring {
                        Ring::Log => UP_RECORDS,
                        Ring::Capture => UP_CAPTURE,
                    },
                    shipment.position,
                    shipment.bytes.len(),
                )
            })
            .collect()
    }
}

/// Read every shipment the appliance wrote out of a management server's
/// transcript.
///
/// Never fails: a transcript with nothing in it is a finding for [`judge`] to
/// state against what the boot owed, not an error here — this is the reading,
/// and what the reading has to contain is the caller's question.
#[must_use]
pub fn walk(transcript: &[u8]) -> Shipped {
    let mut found = Shipped {
        sessions: transcript
            .windows(APPLIANCE_GREETING.len())
            .filter(|window| *window == APPLIANCE_GREETING)
            .count(),
        shipments: Vec::new(),
    };
    let mut at = 0;
    while let Some(next) = transcript
        .get(at..)
        .and_then(|tail| tail.windows(HEADER_LEN).position(is_shipment))
    {
        let start = at + next;
        // By one, so a header the file does not carry a whole body for cannot
        // hide the real one behind it. Overwritten below where the body is there.
        at = start + 1;
        let Some(header) = transcript.get(start..start + HEADER_LEN) else {
            break;
        };
        let stated = u32::from_be_bytes([header[0], header[1], header[2], header[3]]) as usize;
        let Some(end) = start
            .checked_add(HEADER_LEN)
            .and_then(|body| body.checked_add(stated))
        else {
            continue;
        };
        let Some(body) = transcript.get(start + HEADER_LEN..end) else {
            continue;
        };
        let (Some(stated_position), Some(bytes)) =
            (body.get(..POSITION_LEN), body.get(POSITION_LEN..))
        else {
            continue;
        };
        let Ok(position) = <[u8; POSITION_LEN]>::try_from(stated_position) else {
            continue;
        };
        found.shipments.push(Shipment {
            ring: if header[4] == UP_RECORDS {
                Ring::Log
            } else {
                Ring::Capture
            },
            position: u64::from_be_bytes(position),
            bytes: bytes.to_vec(),
        });
        at = end;
    }
    found
}

/// Whether these eight bytes are a shipment's header: either ring's type byte,
/// and the three reserved bytes this protocol holds at zero.
fn is_shipment(window: &[u8]) -> bool {
    matches!(window.get(4), Some(&UP_RECORDS | &UP_CAPTURE))
        && window.get(5..8) == Some(&[0, 0, 0][..])
}

/// One extent as the medium holds it, which is what the shipments are held to.
pub struct Extent<'a> {
    pub ring: Ring,
    /// The extent's payload area, from payload byte zero — the same coordinate a
    /// shipment states its position in.
    pub payload: &'a [u8],
    /// How far into that area the superblock says the recording is durable.
    /// Bytes past it were never made durable, so a shipment reaching them is not
    /// a disagreement about content but about how much there was.
    pub durable: usize,
}

/// What the comparison established, for a run log to carry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Agreement {
    pub sessions: usize,
    /// Per ring: shipments, bytes they carried, and the highest position they
    /// reached.
    pub carried: BTreeMap<&'static str, (usize, usize, u64)>,
}

impl Agreement {
    #[must_use]
    pub fn evidence(&self) -> String {
        let mut out = format!(
            "  what the channel shipped, held byte for byte to the extents on the disk image \
             ({} session(s) greeted):",
            self.sessions
        );
        for (ring, (shipments, bytes, reach)) in &self.carried {
            let _ = write!(
                out,
                "\n    {ring}: {shipments} shipment(s) carrying {bytes} byte(s), reaching ring \
                 position {reach}, every byte identical to the medium at the position the \
                 shipment states"
            );
        }
        out
    }
}

/// Hold every shipment to the extent it names.
///
/// A pure function of the walked transcript and the extents, so every way the
/// two can disagree is exercised by a unit test rather than by a ten-minute
/// boot.
///
/// # Errors
/// A boot that greeted no server or shipped no ring bytes at all, a shipment
/// naming a position the medium does not reach, one running past what the
/// medium made durable, or any byte that differs — named with the ring, the
/// absolute ring position and both values.
pub fn judge(
    shipped: &Shipped,
    extents: &[Extent],
    least_bytes: usize,
) -> Result<Agreement, String> {
    if shipped.sessions == 0 {
        return Err(String::from(
            "the management server's transcript carries no greeting from the appliance, so no \
             session reached the point where a recording could be shipped and nothing the medium \
             holds has been corroborated",
        ));
    }
    let mut carried = BTreeMap::new();
    for extent in extents {
        let mut shipments = 0;
        let mut bytes = 0;
        let mut reach = 0;
        for shipment in shipped.of(extent.ring) {
            let start = usize::try_from(shipment.position).map_err(|_| {
                format!(
                    "a shipment of {} states ring position {}, which is past anything this \
                     medium could hold",
                    extent.ring.name(),
                    shipment.position
                )
            })?;
            let end = start.checked_add(shipment.bytes.len()).ok_or_else(|| {
                format!(
                    "a shipment of {} states ring position {start} and carries {} byte(s), whose \
                     sum leaves the type",
                    extent.ring.name(),
                    shipment.bytes.len()
                )
            })?;
            if end > extent.durable {
                return Err(format!(
                    "a shipment of {} carries bytes {start}..{end} of the ring and the \
                     superblock says only {} byte(s) of it were ever made durable; the appliance \
                     shipped a management server bytes its own medium does not stand behind",
                    extent.ring.name(),
                    extent.durable
                ));
            }
            let held = extent.payload.get(start..end).ok_or_else(|| {
                format!(
                    "a shipment of {} carries bytes {start}..{end} of the ring and the extent's \
                     payload area is {} byte(s) long",
                    extent.ring.name(),
                    extent.payload.len()
                )
            })?;
            if let Some(at) = held
                .iter()
                .zip(&shipment.bytes)
                .position(|(disk, wire)| disk != wire)
            {
                return Err(format!(
                    "a shipment of {} differs from the medium at ring position {}: the disk holds \
                     {:#04x} and the channel carried {:#04x}. The ring bytes are the wire bytes, \
                     so the appliance told its management server something its own medium does \
                     not say",
                    extent.ring.name(),
                    start + at,
                    held[at],
                    shipment.bytes[at],
                ));
            }
            shipments += 1;
            bytes += shipment.bytes.len();
            reach = reach.max(end as u64);
        }
        if bytes < least_bytes {
            return Err(format!(
                "the channel shipped {bytes} byte(s) of {} across {shipments} shipment(s) and \
                 this boot owed at least {least_bytes}; a comparison against a medium that was \
                 never asked for proves nothing about either",
                extent.ring.name(),
            ));
        }
        carried.insert(extent.ring.name(), (shipments, bytes, reach));
    }
    Ok(Agreement {
        sessions: shipped.sessions,
        carried,
    })
}

#[cfg(test)]
mod tests;
