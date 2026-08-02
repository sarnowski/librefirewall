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
//! neither of them the guest's own account of itself (TEST-13).
//!
//! # No adversary
//!
//! Build orchestration on the host side of an emulator (CON-2 names no CONCEPT
//! §7.1 adversary for it). The guest composes the bytes — that is the point —
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
const EPB_PACKETID: u16 = 5;

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
    /// The bytes the block retained.
    pub captured: Vec<u8>,
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
/// The walk is bounded by the body's own length rather than by anything in it
/// (ENG-4): the smallest legal block is [`BLOCK_FRAMING_LEN`] and the walk
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
        // without saying what happens when the sum leaves the type (ENG-5).
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
        captured,
    }
}

/// The value of the first option coded `wanted`, walking the option list that
/// starts at `from`.
///
/// Bounded like the block walk above and for the same reason (ENG-4): an option
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
        // checked rather than left to wrap (ENG-5).
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
/// A response that is not `200`, one whose declared length disagrees with its
/// body, a body that does not parse as pcapng, a body the walk did not consume
/// whole, too few packets, or a captured length past the sink's snap length.
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
    if let Some(stated) = download.header("content-length") {
        let stated: usize = stated.parse().map_err(|error| {
            format!("GET {target} stated an unreadable Content-Length: {error}")
        })?;
        if stated != download.body.len() {
            return Err(format!(
                "GET {target} states a Content-Length of {stated} and carries {} body bytes",
                download.body.len()
            ));
        }
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
mod tests;
