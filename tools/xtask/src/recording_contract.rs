//! What a downloaded recording must be, judged as bytes rather than as a
//! console line.
//!
//! # What this proves that a metric cannot
//!
//! `librefirewall_recording_records_total` is the appliance's own count of what
//! it believes it encoded. It is worth exposing and it is not evidence: a
//! recorder that encoded twelve malformed blocks would publish the identical
//! number. What settles the question is a file a process outside the guest
//! pulled through a real HTTP client and parsed as pcapng, and the same bytes
//! read straight off the disk image afterwards — two paths to one artifact,
//! neither of them the guest's own account of itself.
//!
//! # No adversary
//!
//! Build orchestration on the host side of an emulator; no threat-model
//! adversary is named for it. The guest composes the bytes — that is the point —
//! and this module walks them by length, which is exactly the discipline it is
//! asserting the guest kept.

use std::{fmt::Write as _, process::Command, time::Duration};

/// pcapng framing: the block type, the total length, and the total length
/// again at the end.
const BLOCK_FRAMING_LEN: usize = 12;

/// The block types this walk recognises. Restated here as numbers rather than
/// imported from `lfw_pcapng`, deliberately: a reader recognises a block by its
/// number, and a harness that shared the encoder's constants could not tell a
/// renamed constant from a correct file.
const SECTION_HEADER_BLOCK: u32 = 0x0A0D_0D0A;
const INTERFACE_DESCRIPTION_BLOCK: u32 = 0x0000_0001;
const ENHANCED_PACKET_BLOCK: u32 = 0x0000_0006;

/// pcapng's byte-order magic, little-endian as this appliance writes it.
const BYTE_ORDER_MAGIC: u32 = 0x1A2B_3C4D;

/// One option's fixed head: the code and the value's length.
const OPTION_HEADER_LEN: usize = 4;

/// The option codes this walk reads back. Numbers for the same reason the block
/// types are.
const OPT_END_OF_OPT: u16 = 0;
const IF_NAME: u16 = 2;
const EPB_FLAGS: u16 = 2;

/// `epb_flags`' direction bits as the appliance writes them: 1 inbound, 2
/// outbound. A number on the block types' terms.
pub(crate) const FLAGS_INBOUND: u32 = 1;
const EPB_PACKETID: u16 = 5;
const EPB_VERDICT: u16 = 7;

/// The custom option the firewall annotation rides in: binary data, copyable.
const CUSTOM_BINARY_COPYABLE: u16 = 2989;

/// The Private Enterprise Number the annotation is tagged with. Nobody's, and
/// restated here as a number for the reason every other constant in this module
/// is: a harness that shared the encoder's constant could not tell a renamed
/// constant from a correct file.
const UNREGISTERED_PEN: u32 = 0xFFFF_FFFF;

/// The layout version the annotation must declare. A reader keys on this rather
/// than on the length it happens to see, so a file that grew a field without
/// saying so is a finding here.
pub const ANNOTATION_VERSION: u8 = 3;

/// Bytes of annotation this layout version carries.
pub const ANNOTATION_LEN: usize = 24;

/// The verdict kind octet a firewall's own verdict travels under: none of the
/// three registered kinds names one.
pub const VERDICT_KIND: u8 = 0xFF;

/// What the annotation's verdict octet says, and what `epb_verdict` says beside
/// it.
pub const VERDICT_FORWARDED: u8 = 0;
pub const VERDICT_DROPPED: u8 = 1;
/// Neither, because the record is about no frame: a conversation the appliance
/// ended itself when a policy commit stopped admitting it.
pub const VERDICT_REVOKED: u8 = 2;

/// The events an annotation may name, as the numbers the tap ABI encodes them
/// as. A vocabulary, restated as numbers, on the block types' terms.
pub const EVENT_FLOW_OPENED: u8 = 1;
pub const EVENT_FLOW_ADVANCED: u8 = 2;
pub const EVENT_FLOW_CLOSED: u8 = 3;
pub const EVENT_POLICY_DENIED: u8 = 4;
pub const EVENT_POLICY_NO_MATCH: u8 = 5;
pub const EVENT_FLOW_REFUSED: u8 = 6;
pub const EVENT_FLOW_REVOKED: u8 = 7;

/// The classifications an annotation may name.
pub const CLASSIFICATION_NEW: u8 = 1;
pub const CLASSIFICATION_ESTABLISHED: u8 = 2;
pub const CLASSIFICATION_RELATED: u8 = 3;

/// A stable short name for a classification, on [`event_name`]'s terms.
#[must_use]
pub fn classification_name(classification: u8) -> &'static str {
    match classification {
        0 => "no flow",
        CLASSIFICATION_NEW => "new",
        CLASSIFICATION_ESTABLISHED => "established",
        CLASSIFICATION_RELATED => "related",
        _ => "a classification this walk does not know",
    }
}

/// The two flow states a conversation does not leave, which are the two a close
/// may name.
pub const STATE_TIME_WAIT: u8 = 7;
pub const STATE_CLOSED: u8 = 8;

/// A stable short name for an event, so a verdict names what it saw rather than
/// a number a reader has to look up.
#[must_use]
pub fn event_name(event: u8) -> &'static str {
    match event {
        0 => "no event",
        EVENT_FLOW_OPENED => "flow-opened",
        EVENT_FLOW_ADVANCED => "flow-advanced",
        EVENT_FLOW_CLOSED => "flow-closed",
        EVENT_POLICY_DENIED => "policy-denied",
        EVENT_POLICY_NO_MATCH => "policy-no-match",
        EVENT_FLOW_REFUSED => "flow-refused",
        EVENT_FLOW_REVOKED => "flow-revoked",
        _ => "an event this walk does not know",
    }
}

/// Where an Interface Description Block's options begin: type, total length,
/// link type, a reserved half-word, and the snap length.
const IDB_OPTIONS_AT: usize = 16;

/// Where an Enhanced Packet Block's captured bytes begin: type, total length,
/// interface id, the two timestamp halves, the captured length and the original
/// length.
const EPB_CAPTURE_AT: usize = 28;

/// How long a recording download may take. Generous: the body is megabytes and
/// crosses the emulated wire one 32 KiB window per round trip.
const FETCH_TIMEOUT: Duration = Duration::from_secs(180);

/// What a real client got out of a recording endpoint.
#[derive(Clone, Debug)]
pub struct Download {
    /// The request target it came from, carried rather than recovered from
    /// [`Self::command`]: every caller that pairs a download with what it must
    /// be needs to know which recording it holds, and parsing that back out of
    /// a command line would be a second, weaker statement of the same fact.
    pub target: &'static str,
    /// The command as it was run, verbatim, so a reader can repeat it.
    pub command: String,
    pub status_line: String,
    pub headers: Vec<String>,
    /// The body as bytes. A recording is not text and reading it as one would
    /// silently replace every byte a `String` cannot hold.
    pub body: Vec<u8>,
}

impl Download {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.eq_ignore_ascii_case(name).then(|| value.trim())
        })
    }
}

/// One Interface Description Block, read back into the fields a reader resolves
/// a packet's `interface_id` through.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Interface {
    /// The `if_name` option, or empty where the block declares none. Empty
    /// rather than absent: a nameless interface is a finding for whoever
    /// asserts on the name, not a shape the walk has to model twice.
    pub name: String,
    /// The bytes of a frame this interface's sink retains, as the file itself
    /// declares them — which is what makes two sinks distinguishable as files
    /// rather than only as the constants that configured them.
    pub snap_len: u32,
    pub link_type: u16,
}

/// The firewall's own annotation, read back out of the PEN-tagged custom option
/// at the offsets a reader outside the appliance navigates by.
///
/// Fields rather than the raw octets, because what the contract is stated over is
/// *what the appliance decided*: a verdict, the flow it was about, what the
/// packet did to that flow, and which rule reached the decision. The offsets are
/// written out here and nowhere else in the harness.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Annotation {
    pub version: u8,
    pub verdict: u8,
    /// Why the frame was not forwarded; zero on a forwarded one.
    pub drop_reason: u8,
    pub interface_id: u8,
    pub direction: u8,
    /// What the tracker made of the frame; zero where it named no flow.
    pub classification: u8,
    /// The lifecycle or policy event it caused; zero where it caused none.
    pub event: u8,
    /// Where the flow stood after it; zero where there is no flow.
    pub flow_state: u8,
    pub configuration_generation: u32,
    pub flow_slot: u32,
    pub flow_generation: u32,
    /// One higher than the rule's position, so zero names *no rule matched*.
    pub rule: u16,
}

impl Annotation {
    /// The bytes of a custom option, read as this layout, or `None` where the
    /// option is not one — too short, or a length this version does not carry.
    fn read(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != ANNOTATION_LEN {
            return None;
        }
        let octet = |at: usize| bytes.get(at).copied().unwrap_or(0);
        let word = |at: usize| {
            bytes
                .get(at..)
                .and_then(<[u8; 4]>::try_from_slice_prefix)
                .map_or(0, u32::from_le_bytes)
        };
        Some(Self {
            version: octet(0),
            verdict: octet(1),
            drop_reason: octet(2),
            interface_id: octet(3),
            direction: octet(4),
            classification: octet(5),
            event: octet(6),
            flow_state: octet(7),
            configuration_generation: word(8),
            flow_slot: word(12),
            flow_generation: word(16),
            rule: bytes
                .get(20..)
                .and_then(<[u8; 2]>::try_from_slice_prefix)
                .map_or(0, u16::from_le_bytes),
        })
    }

    /// The flow's identity as a reader folds events by it: the pair, never the
    /// bare slot.
    #[must_use]
    pub const fn identity(&self) -> (u32, u32) {
        (self.flow_slot, self.flow_generation)
    }

    /// Whether the annotation names a flow at all.
    ///
    /// A classification, **or** the one record that names a flow and no packet: a
    /// revocation has nothing for a classification to be about, a classification
    /// being a statement about a frame and there having been none.
    #[must_use]
    pub const fn names_a_flow(&self) -> bool {
        self.classification != 0 || self.is_revocation()
    }

    /// Whether this record is about a flow the appliance ended rather than about a
    /// frame that crossed it.
    #[must_use]
    pub const fn is_revocation(&self) -> bool {
        self.verdict == VERDICT_REVOKED
    }

    /// The rule's position, or `None` where none matched.
    #[must_use]
    pub const fn rule_position(&self) -> Option<u16> {
        match self.rule.checked_sub(1) {
            Some(position) => Some(position),
            None => None,
        }
    }
}

/// Taking a fixed-width prefix of a slice without an index, so a short option
/// yields nothing rather than panicking on a length the file chose.
trait TryFromSlicePrefix: Sized {
    fn try_from_slice_prefix(bytes: &[u8]) -> Option<Self>;
}

impl TryFromSlicePrefix for [u8; 2] {
    fn try_from_slice_prefix(bytes: &[u8]) -> Option<Self> {
        bytes.first_chunk::<2>().copied()
    }
}

impl TryFromSlicePrefix for [u8; 4] {
    fn try_from_slice_prefix(bytes: &[u8]) -> Option<Self> {
        bytes.first_chunk::<4>().copied()
    }
}

/// One Enhanced Packet Block, read back into the fields the cross-surface
/// contract is stated over.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Packet {
    /// Which of the enclosing section's interfaces recorded it.
    pub interface_id: u32,
    /// The `epb_packetid` option, or `None` where the block declares none. It
    /// is what relates one appliance-wide observation across the two
    /// recordings, so a block without one cannot be paired at all.
    pub packet_id: Option<u64>,
    /// The frame's length on the wire, which exceeds `captured.len()` exactly
    /// when the sink truncated it.
    pub original_len: u32,
    /// The `epb_flags` option, or `None` where the block declares none — which is
    /// the one record that is about no frame, a direction being a property of a
    /// packet on a wire.
    pub flags: Option<u32>,
    /// The bytes the block retained.
    pub captured: Vec<u8>,
    /// The `epb_verdict` option's octets, or `None` where the block declares
    /// none. The first is the kind and the rest are what that kind means.
    pub verdict: Option<Vec<u8>>,
    /// The firewall's own annotation, or `None` where the block carries no
    /// custom option this walk recognises — which is itself a finding for
    /// whoever asserts on it.
    pub annotation: Option<Annotation>,
}

/// What one recording's bytes were found to be.
#[derive(Debug, Default)]
pub struct Parsed {
    pub sections: usize,
    /// Every Interface Description Block in the file, in the order it declares
    /// them. A section's interface table restarts at zero, so a file with more
    /// than one section holds each section's table end to end here — which is
    /// why the interface contract is stated per section
    /// ([`crate::surface_contract`]) rather than over this list as a whole.
    pub interfaces: Vec<Interface>,
    /// Every Enhanced Packet Block in the file, in the order it holds them.
    pub packets: Vec<Packet>,
    /// Bytes the walk consumed. Below the body's length exactly when a block's
    /// own length stopped it, which is the failure a reader would hit.
    pub consumed: usize,
}

impl Parsed {
    /// The largest captured length any packet block claimed, which is what the
    /// sink's snap length bounds.
    #[must_use]
    pub fn longest_capture(&self) -> usize {
        self.packets
            .iter()
            .map(|packet| packet.captured.len())
            .max()
            .unwrap_or(0)
    }
}

/// `GET path` through the forwarded host port, as bytes.
///
/// # Errors
/// A `curl` that could not be started, one that failed, or an answer with no
/// HTTP head in it.
pub fn fetch(host_port: u16, target: &'static str) -> Result<Download, String> {
    let url = format!("http://127.0.0.1:{host_port}{target}");
    let arguments = [
        "--silent",
        "--show-error",
        "--http1.1",
        "--include",
        "--max-time",
        // A string rather than the constant's `Debug`, so the printed command
        // is the command.
        "180",
        &url,
    ];
    let command = format!("curl {}", arguments.join(" "));
    debug_assert_eq!(FETCH_TIMEOUT.as_secs(), 180);

    let output = Command::new("curl")
        .args(arguments)
        .output()
        .map_err(|error| format!("run `{command}`: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "`{command}` failed ({}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let separator = b"\r\n\r\n";
    let at = output
        .stdout
        .windows(separator.len())
        .position(|window| window == separator)
        .ok_or_else(|| format!("`{command}` answered no HTTP head"))?;
    let head = String::from_utf8_lossy(&output.stdout[..at]).into_owned();
    let body = output.stdout[at + separator.len()..].to_vec();
    let mut lines = head.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| format!("`{command}` answered an empty head"))?
        .to_owned();
    Ok(Download {
        target,
        command,
        status_line,
        headers: lines.map(ToOwned::to_owned).collect(),
        body,
    })
}

/// Walk `bytes` as pcapng, block by block, by the lengths the file states.
///
/// Every block carries its total length twice, at its head and at its tail, and
/// a reader steps from one block to the next by that number. Walking the same
/// way is what makes this a statement about the file rather than about a search
/// for magic bytes: a length that disagrees with its own trailer, is not a
/// multiple of four, or runs past the body stops the walk, and `consumed` then
/// says where.
///
/// The walk is bounded by the body's own length rather than by anything in
/// it: the smallest legal block is [`BLOCK_FRAMING_LEN`] and the walk
/// refuses a shorter one, so no file of `n` bytes can present more than
/// `n / BLOCK_FRAMING_LEN` blocks however its length fields are written. The
/// same bound covers the memory this allocates, every captured slice being a
/// disjoint part of the body.
///
/// # Errors
/// A first block that is not a Section Header, or one whose byte-order magic is
/// not the little-endian one this appliance writes.
pub fn parse(bytes: &[u8]) -> Result<Parsed, String> {
    let mut at = 0;
    let mut found = Parsed::default();
    let ceiling = bytes.len() / BLOCK_FRAMING_LEN;
    for _ in 0..ceiling {
        let Some(header) = bytes.get(at..) else { break };
        let (Some(kind), Some(len)) = (word(header, 0), word(header, 4)) else {
            break;
        };
        let len = len as usize;
        if len < BLOCK_FRAMING_LEN || !len.is_multiple_of(4) {
            break;
        }
        // Checked rather than `at + len`: both come out of the body, and an
        // offset a file chose may not be added to a length the same file chose
        // without saying what happens when the sum leaves the type.
        let Some(end) = at.checked_add(len) else {
            break;
        };
        let Some(block) = bytes.get(at..end) else {
            break;
        };
        if word(block, len - 4) != Some(len as u32) {
            break;
        }
        match kind {
            SECTION_HEADER_BLOCK => {
                if found.sections == 0 && at != 0 {
                    return Err(format!(
                        "the first block is at offset {at} and is not a Section Header"
                    ));
                }
                let magic = word(block, 8)
                    .ok_or_else(|| String::from("a Section Header with no byte-order magic"))?;
                if magic != BYTE_ORDER_MAGIC {
                    return Err(format!(
                        "a Section Header whose byte-order magic is {magic:#010x} and not \
                         {BYTE_ORDER_MAGIC:#010x}"
                    ));
                }
                found.sections += 1;
            }
            INTERFACE_DESCRIPTION_BLOCK => found.interfaces.push(interface(block)),
            ENHANCED_PACKET_BLOCK => found.packets.push(packet(block)),
            // Every other block is one a reader skips by its length, which is
            // exactly what this walk does — the padding the recorder writes to
            // keep each device write a whole sector lands here.
            _ => {}
        }
        at = end;
        found.consumed = at;
    }
    if found.sections == 0 {
        return Err(format!(
            "no Section Header at all in {} bytes, so this is not a pcapng file",
            bytes.len()
        ));
    }
    Ok(found)
}

/// One Interface Description Block's fields. A block too short to hold one
/// reads as zeroes and an empty name, which is a finding for whoever asserts on
/// them rather than something to refuse here — the walk's job is to say what
/// the file holds.
fn interface(block: &[u8]) -> Interface {
    Interface {
        link_type: half(block, 8).unwrap_or(0),
        snap_len: word(block, 12).unwrap_or(0),
        name: option(block, IDB_OPTIONS_AT, IF_NAME)
            .map(String::from_utf8_lossy)
            .unwrap_or_default()
            .into_owned(),
    }
}

/// One Enhanced Packet Block's fields, with the captured bytes bounded by the
/// block rather than by the length the block claims for them: a claimed length
/// past the block's end takes what is there, which the clamping assertion in
/// [`crate::surface_contract`] then reports as the disagreement it is.
fn packet(block: &[u8]) -> Packet {
    // The fixed part that [`EPB_CAPTURE_AT`] ends: interface id at 8, the
    // timestamp's two halves at 12 and 16, the captured length at 20 and the
    // original length at 24.
    let captured_len = word(block, 20).unwrap_or(0) as usize;
    let captured = block
        .get(EPB_CAPTURE_AT..)
        .map(|rest| rest.get(..captured_len).unwrap_or(rest))
        .unwrap_or_default()
        .to_vec();
    // The options sit past the captured bytes, which the format pads to four.
    let options_at = EPB_CAPTURE_AT.saturating_add(captured_len.next_multiple_of(4));
    Packet {
        interface_id: word(block, 8).unwrap_or(0),
        packet_id: option(block, options_at, EPB_PACKETID).and_then(long),
        original_len: word(block, 24).unwrap_or(0),
        flags: option(block, options_at, EPB_FLAGS)
            .and_then(|value| value.first_chunk::<4>().copied())
            .map(u32::from_le_bytes),
        captured,
        verdict: option(block, options_at, EPB_VERDICT).map(<[u8]>::to_vec),
        // The PEN is the option's own first four octets and the annotation
        // follows it. An option under another enterprise number is somebody
        // else's and is read as absent rather than as this layout.
        annotation: option(block, options_at, CUSTOM_BINARY_COPYABLE).and_then(|value| {
            let (pen, rest) = value.split_at_checked(4)?;
            (u32::from_le_bytes(*pen.first_chunk::<4>()?) == UNREGISTERED_PEN)
                .then(|| Annotation::read(rest))
                .flatten()
        }),
    }
}

/// The value of the first option coded `wanted`, walking the option list that
/// starts at `from`.
///
/// Bounded like the block walk above and for the same reason: an option
/// occupies at least [`OPTION_HEADER_LEN`] bytes, so a block of `n` bytes holds
/// at most `n / OPTION_HEADER_LEN` of them whatever its length fields say.
fn option(block: &[u8], from: usize, wanted: u16) -> Option<&[u8]> {
    let mut at = from;
    for _ in 0..block.len() / OPTION_HEADER_LEN {
        let code = half(block, at)?;
        let len = half(block, at + 2)? as usize;
        if code == OPT_END_OF_OPT {
            return None;
        }
        // Every offset here is a sum of two numbers the block chose, so each is
        // checked rather than left to wrap.
        let value_at = at.checked_add(OPTION_HEADER_LEN)?;
        let value = block.get(value_at..value_at.checked_add(len)?)?;
        if code == wanted {
            return Some(value);
        }
        at = value_at.checked_add(len.next_multiple_of(4))?;
    }
    None
}

/// A little-endian `u32` at `at`, or `None` where the slice does not reach.
fn word(bytes: &[u8], at: usize) -> Option<u32> {
    bytes
        .get(at..)?
        .first_chunk::<4>()
        .map(|chunk| u32::from_le_bytes(*chunk))
}

/// A little-endian `u16` at `at`, or `None` where the slice does not reach.
fn half(bytes: &[u8], at: usize) -> Option<u16> {
    bytes
        .get(at..)?
        .first_chunk::<2>()
        .map(|chunk| u16::from_le_bytes(*chunk))
}

/// An option value read as a little-endian `u64`, or `None` where it is not
/// eight bytes — which for `epb_packetid` is a malformed option rather than an
/// absent one, and reads the same way to a caller that cannot pair the block.
fn long(value: &[u8]) -> Option<u64> {
    value
        .first_chunk::<8>()
        .filter(|_| value.len() == 8)
        .map(|chunk| u64::from_le_bytes(*chunk))
}

/// One recording the scenario judges: what it was fetched as, and the bounds it
/// must meet.
pub struct Expectation {
    pub target: &'static str,
    /// The sink's snap length, which no captured length may exceed.
    pub snap_len: usize,
    /// The fewest packet blocks the recording must hold, which is what the
    /// harness itself put on the wire.
    pub least_packets: usize,
}

/// Judge one download against its expectation, answering the evidence line.
///
/// # Errors
/// A response that is not `200`, one that declares no length at all or whose
/// declared length disagrees with its body, a body that does not parse as
/// pcapng, a body the walk did not consume whole, too few packets, or a
/// captured length past the sink's snap length.
pub fn judge(download: &Download, expected: &Expectation) -> Result<Parsed, String> {
    let target = expected.target;
    if download.target != target {
        return Err(format!(
            "a download of {} was judged against the contract for {target}, so the two \
             recordings have been paired the wrong way round",
            download.target
        ));
    }
    if !download.status_line.contains("200") {
        return Err(format!(
            "`{}` was answered {:?}",
            download.command, download.status_line
        ));
    }
    // Mandatory, not conditional: the endpoint answers an exact length, and a
    // regression that stopped emitting one would leave this contract green
    // because `curl` reads to close and the body still parses.
    let stated: usize = download
        .header("content-length")
        .ok_or_else(|| format!("GET {target} carries no Content-Length"))?
        .parse()
        .map_err(|error| format!("GET {target} stated an unreadable Content-Length: {error}"))?;
    if stated != download.body.len() {
        return Err(format!(
            "GET {target} states a Content-Length of {stated} and carries {} body bytes",
            download.body.len()
        ));
    }
    let parsed = parse(&download.body)
        .map_err(|error| format!("GET {target} did not answer a pcapng file: {error}"))?;
    if parsed.consumed != download.body.len() {
        return Err(format!(
            "GET {target} answered {} bytes of which the block walk consumed {}, so a block's \
             own length disagrees with the file",
            download.body.len(),
            parsed.consumed
        ));
    }
    if parsed.interfaces.is_empty() {
        return Err(format!(
            "GET {target} carries no Interface Description Block, so no packet in it names an \
             interface a reader can resolve"
        ));
    }
    if parsed.packets.len() < expected.least_packets {
        return Err(format!(
            "GET {target} holds {} packet blocks and the harness put {} frames across the \
             appliance, so the recording is missing observations",
            parsed.packets.len(),
            expected.least_packets
        ));
    }
    if parsed.longest_capture() > expected.snap_len {
        return Err(format!(
            "GET {target} holds a packet block claiming {} captured bytes, past the sink's snap \
             length of {}",
            parsed.longest_capture(),
            expected.snap_len
        ));
    }
    Ok(parsed)
}

/// The evidence line one judged download leaves.
#[must_use]
pub fn evidence(download: &Download, parsed: &Parsed, snap_len: usize) -> String {
    let mut line = String::new();
    let _ = write!(
        line,
        "  {}: {} bytes, {} section header(s), {} interface block(s), {} packet block(s), \
         longest capture {} of a snap length of {snap_len}",
        download.target,
        download.body.len(),
        parsed.sections,
        parsed.interfaces.len(),
        parsed.packets.len(),
        parsed.longest_capture(),
    );
    line
}

#[cfg(test)]
pub(crate) mod tests;
