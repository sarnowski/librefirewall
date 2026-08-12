//! What a booted appliance's recorded transcript must agree with: the serial
//! console of the very same boot.
//!
//! The console domain renders every log record once and puts the bytes on two
//! surfaces — the serial port an operator reads, and a relay the recorder frames
//! into the connection history for a management server to store. Those are the
//! same bytes by construction, and that is exactly why holding them to each
//! other is worth doing: it is the only check that can catch the construction
//! being wrong. A relay that published a stale slot, an origin byte read at the
//! wrong offset, a length that lost a line's tail, a batch whose entries were
//! walked with the wrong stride — none of those is visible in either surface
//! alone, and every one of them is a line in the recording that the same boot
//! never printed.
//!
//! # Why containment and not equality
//!
//! The recording is a **subset** of the transcript and the direction matters.
//! Two things make it one. The console starts printing before the recorder has
//! finished bringing its block device up, so the earliest lines are published
//! into a relay nobody is draining yet and are dropped — counted, and reported on
//! the console's own shard, but gone from the recording. And a download is taken
//! at an instant, so the last lines printed may still be in the relay or staged
//! rather than on the medium.
//!
//! Neither direction of that is a defect, and the containment is still the whole
//! property: **every line in the recording occurred verbatim in the transcript**.
//! A recording carrying a line the boot did not print is a recording that
//! invented one, which is the failure this exists to refuse. The count and the
//! anchor below are what keep containment from passing vacuously on a recording
//! that carries nothing.
//!
//! # No adversary
//!
//! Build orchestration on the host side of an emulator, on
//! [`crate::surface_contract`]'s terms. The guest composes the recording and
//! every walk over it is bounded by the body's own length and performed by
//! [`crate::recording_contract::parse`] before a byte reaches this module.

use std::collections::BTreeSet;
use std::fmt::Write as _;

use lfw_log::Domain;

use crate::recording_contract::TranscriptLine;

/// What a run demands of the transcript its recording carries.
#[derive(Debug)]
pub struct Demanded {
    /// The fewest lines the recording must carry.
    ///
    /// A floor rather than a count: how much of a boot transcript reaches the
    /// medium before a download is taken depends on how fast the block device
    /// came up, which is an emulator's business and not a contract. What the
    /// floor refuses is the vacuous pass — a recording with no transcript in it
    /// at all satisfies containment perfectly.
    pub at_least: usize,
    /// A line the recording must carry, given as a substring of it.
    ///
    /// The anchor, and it is what makes the floor mean something specific: it
    /// names a record emitted late enough in a boot that the recorder is
    /// certainly draining by then, so a relay that filled once and never
    /// recovered fails here rather than passing on the lines it happened to take
    /// first.
    pub anchored_on: &'static str,
}

/// What the comparison established, for a run log to carry.
#[derive(Debug)]
pub struct Agreement {
    pub lines: Vec<String>,
}

impl Agreement {
    #[must_use]
    pub fn evidence(&self) -> String {
        let mut out = String::from(
            "  the console transcript the connection history carries, held to the same boot's \
             serial console:",
        );
        for line in &self.lines {
            out.push('\n');
            out.push_str(line);
        }
        out
    }
}

/// The console lines of a serial transcript, as a set to test containment
/// against.
///
/// A boot's serial output carries the boot manager's and the kernel's words too,
/// and the console domain's own lines are the ones that begin with this
/// appliance's two record tags. Splitting on either line ending rather than on
/// both is deliberate: the console writes CR and LF, an emulator's log may carry
/// either, and a line that kept a stray CR would compare unequal to the same
/// line out of a recording for no reason a reader would accept.
fn printed(serial: &[u8]) -> BTreeSet<String> {
    String::from_utf8_lossy(serial)
        .lines()
        .map(|line| line.trim_end_matches('\r').trim_start().to_owned())
        .filter(|line| line.starts_with("LFW-PD ") || line.starts_with("LFW-CFG "))
        .collect()
}

/// Hold every line a recording carries to the same boot's serial console.
///
/// # Errors
/// A recording with fewer lines than `demanded.at_least`, one missing the anchor,
/// one carrying a line the boot never printed, or one whose origin byte names no
/// protection domain.
pub fn judge(
    target: &str,
    carried: &[TranscriptLine],
    batches: usize,
    serial: &[u8],
    demanded: &Demanded,
) -> Result<Agreement, String> {
    let transcript = printed(serial);
    if transcript.is_empty() {
        return Err(format!(
            "this boot's serial console carries no console record at all, so there is nothing for \
             GET {target}'s transcript to be held to and the comparison would pass vacuously"
        ));
    }
    if carried.len() < demanded.at_least {
        return Err(format!(
            "GET {target} carries {} console line(s) and this run demands at least {}; the \
             recorder framed too little of the transcript for a management server to store it, or \
             the relay filled and never recovered",
            carried.len(),
            demanded.at_least
        ));
    }

    // Every line, before the anchor is looked for: a line the boot never printed
    // is the finding worth reporting first, and reporting it needs the line.
    for (at, line) in carried.iter().enumerate() {
        if Domain::ALL.get(line.origin as usize).is_none() {
            return Err(format!(
                "GET {target}'s line {} names origin {} and this build's vocabulary has {} \
                 protection domains, so the byte is being read at the wrong offset or the two \
                 vocabularies have parted: {:?}",
                at + 1,
                line.origin,
                Domain::ALL.len(),
                line.line
            ));
        }
        if !transcript.contains(&line.line) {
            return Err(format!(
                "GET {target}'s line {} of {} is not one this boot printed: {:?}. The recording \
                 and the console are two renderings of one record, so a line in only one of them \
                 is a line the appliance invented",
                at + 1,
                carried.len(),
                line.line
            ));
        }
    }

    let anchor = carried
        .iter()
        .find(|line| line.line.contains(demanded.anchored_on));
    let Some(anchor) = anchor else {
        return Err(format!(
            "GET {target} carries no line containing {:?}, so the transcript it holds is not the \
             one this boot printed past its own bring-up — the relay filled early and the \
             recording carries only what it took first",
            demanded.anchored_on
        ));
    };

    let stamped = carried
        .iter()
        .filter(|line| line.unix_nanos.is_some())
        .count();
    let origins: BTreeSet<&'static str> = carried
        .iter()
        .filter_map(|line| Domain::ALL.get(line.origin as usize))
        .map(|domain| domain.name())
        .collect();
    let mut lines = vec![
        format!(
            "    {target}: {} console line(s) in {batches} batch(es), every one of them printed \
             on this boot's serial console",
            carried.len()
        ),
        format!(
            "    {} of them carry an instant and {} were emitted before this node had a clock",
            stamped,
            carried.len() - stamped
        ),
    ];
    let mut origin_line = String::from("    drained from ");
    let _ = write!(origin_line, "{origins:?}, by the ring each came out of");
    lines.push(origin_line);
    let mut anchor_line = String::from("    anchored on ");
    let _ = write!(anchor_line, "{:?}", anchor.line);
    lines.push(anchor_line);
    Ok(Agreement { lines })
}

#[cfg(test)]
mod tests;
