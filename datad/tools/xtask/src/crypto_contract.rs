//! The cryptography domain's records, and the two things they must say.
//!
//! This is [`crate::probe_contract`]'s pattern applied to the domain that
//! answers the plan's cryptography milestone: that every primitive the
//! appliance owns answers its published vectors *on the shipped image*, and
//! that the accelerated backend rather than a portable fallback is the one
//! running.
//!
//! # Correctness: every primitive, and the list is read as data
//!
//! One `state=negotiated primitive=… vectors=…` record per member of
//! [`Primitive::ALL`], each with a non-zero count, then exactly one
//! `state=ready`. The list is `lfw_log`'s own array rather than a copy of it,
//! so a primitive added to the vocabulary and not to the domain's proof table
//! fails here for the record that never appeared — which is the only way the
//! two can be held exhaustive from outside either.
//!
//! # Acceleration: cost, because correctness cannot show it
//!
//! A portable AES answers the same vectors as an accelerated one, so no
//! correctness check can tell them apart. What can is throughput, and
//! [`CEILINGS`] is where the figure that separates them is written down with
//! the reasoning that produced it.
//!
//! # Why the verdict is only asserted on an accelerated run
//!
//! Under emulation every instruction is a host function call and the guest's
//! cycle counter advances against emulated time, so a cycles-per-byte figure
//! taken there is a figure about QEMU. Such a run is reported in full and
//! asserted against nothing, and the verdict says so rather than quietly
//! passing — a gate that reported "met" from a TCG boot would be the exact
//! failure this module exists to catch.

use std::{fmt::Write as _, path::Path};

use lfw_log::{Domain, DomainState, Primitive};

use crate::console_records::{LIFECYCLE_PREFIX, field, lifecycle_records, value as field_value};

/// The most thousandths of a cycle per byte a primitive may cost, and why that
/// figure and not another.
///
/// AES-256-GCM's is the whole accelerated-backend assertion, so it is derived
/// rather than picked. The published accelerated figure the architecture
/// chapter carries is 2,957 MB/s for AES-256-GCM on a Xeon Gold 5412U — about
/// one cycle per byte on a part of that class. The tightest published
/// *portable* figure is the classic bitsliced constant-time AES at 6.92 cycles
/// per byte on a Core i7, and that is AES alone: it is measured with SSSE3,
/// and it carries no GHASH, which without carry-less multiply is a table walk
/// costing several cycles per byte more. The RustCrypto fixsliced software
/// backend this image would fall back to is slower still on x86_64, being
/// written for parts with no vector unit at all. Four cycles per byte
/// therefore sits four times above the accelerated figure and comfortably
/// below the most optimistic portable one, which is the margin a floor wants
/// in both directions: loose enough not to fail on a slower accelerated part,
/// tight enough that no fallback could pass it.
///
/// The other two are regression ceilings and are not accelerated-backend
/// assertions. SHA-256 runs the *portable* path on this image — the adopted
/// crate's SHA-NI backend is unreachable here, which the crypto-profile page
/// states and explains — so a figure below its ceiling proves nothing about a
/// backend; what it catches is a tenfold regression. ChaCha20-Poly1305's is
/// the same kind of number.
const CEILINGS: &[(Primitive, u64)] = &[
    (Primitive::Aes256Gcm, 4_000),
    (Primitive::Sha256, 40_000),
    (Primitive::ChaCha20Poly1305, 40_000),
];

/// The primitives a ceiling holds, which is what the profile page's `measured`
/// column is compared against.
pub(crate) fn measured_primitives() -> Vec<Primitive> {
    CEILINGS.iter().map(|(primitive, _)| *primitive).collect()
}

/// Judge the cryptography domain's records in one boot's serial capture.
///
/// # Errors
/// The verdict, naming what the channel carried against what the appliance
/// owes it, and where the whole run log is.
pub(crate) fn judge(serial: &[u8], log: &Path, accelerated: bool) -> Result<String, String> {
    let text = String::from_utf8_lossy(serial);
    let ours: Vec<&str> = lifecycle_records(&text)
        .into_iter()
        .filter(|record| record.contains(&field("domain", Domain::Crypto.name())))
        .collect();

    let refused = field("state", DomainState::Refused.name());
    if let Some(record) = ours.iter().find(|record| record.contains(&refused)) {
        return Err(format!(
            "the cryptography domain refused: {record:?}. The cause token names what failed — a \
             `*-not-supported` token is a CPUID feature below the compile-time baseline (the \
             guest CPU model, on this bench), a `*-vector-mismatch` token is a primitive that \
             disagreed with the published row its number names, and an `rdrand-*` token is the \
             hardware entropy source. A primitive that fails its published vectors on the image \
             is a finding to report, never one to work around.\n  full run log: {}",
            log.display()
        ));
    }

    let negotiated = field("state", DomainState::Negotiated.name());
    let steps: Vec<&&str> = ours
        .iter()
        .filter(|record| record.contains(&negotiated))
        .collect();

    if !steps.iter().any(|record| record.contains(" features=0x")) {
        return Err(format!(
            "the cryptography domain published no `features=` record, and one boot produces \
             exactly one: it is the domain's statement of which CPUID feature words it accepted \
             the part on, and without it a `ready` record claims a baseline nothing named\n  \
             records observed: {ours:#?}\n  full run log: {}",
            log.display()
        ));
    }

    let mut proved = String::new();
    for primitive in Primitive::ALL {
        let vectors = count(&steps, primitive, "vectors").ok_or_else(|| {
            format!(
                "the cryptography domain published no `primitive={primitive} vectors=` record. \
                 Every member of the console's primitive vocabulary owes one, so this is either \
                 a primitive the domain's proof table does not carry — in which case it ships \
                 unproven — or one whose run never reached the console\n  records observed: \
                 {ours:#?}\n  full run log: {}",
                log.display()
            )
        })?;
        if vectors == 0 {
            return Err(format!(
                "the cryptography domain proved {primitive} against 0 published vectors, which \
                 is a table that would pass on a broken cipher\n  full run log: {}",
                log.display()
            ));
        }
        let _ = write!(proved, "{primitive}={vectors} ");
    }

    let mut costs = String::new();
    let mut breached = Vec::new();
    for (primitive, ceiling) in CEILINGS {
        let measured = count(&steps, *primitive, "milli-cycles-per-byte").ok_or_else(|| {
            format!(
                "the cryptography domain published no `primitive={primitive} \
                 milli-cycles-per-byte=` record, and the profile names it as measured. A \
                 primitive claimed as measured and not measured is the gap this check exists to \
                 close\n  records observed: {ours:#?}\n  full run log: {}",
                log.display()
            )
        })?;
        let _ = write!(costs, "{primitive}={measured} ");
        if measured == 0 {
            return Err(format!(
                "the cryptography domain measured {primitive} at 0 thousandths of a cycle per \
                 byte, which is a counter that did not advance or a loop the optimizer \
                 removed\n  full run log: {}",
                log.display()
            ));
        }
        if accelerated && measured > *ceiling {
            breached.push(format!(
                "{primitive} cost {measured} against a ceiling of {ceiling}"
            ));
        }
    }
    if !breached.is_empty() {
        return Err(format!(
            "the cryptography domain is slower on this part than a ceiling admits: {}. For \
             AES-256-GCM that ceiling is the accelerated-backend assertion — a figure above it \
             says the portable fallback is running, whatever the CPUID gate accepted — and for \
             the other two it is a regression bound. Lowering a ceiling to pass is not \
             available: the number is the result\n  full run log: {}",
            breached.join("; "),
            log.display()
        ));
    }

    let ready = field("state", DomainState::Ready.name());
    let complete: Vec<&&str> = ours
        .iter()
        .filter(|record| record.contains(&ready))
        .collect();
    if complete.len() != 1 {
        return Err(format!(
            "the console carried {} `{}` record(s) for the cryptography domain in the `ready` \
             state, and a boot produces exactly one: this domain runs once in `init` and then \
             parks, so none means it never finished — or faulted before it could — and several \
             mean something else is writing its ring\n  records observed: {ours:#?}\n  full run \
             log: {}",
            complete.len(),
            LIFECYCLE_PREFIX.trim_end(),
            log.display()
        ));
    }

    let verdict = if accelerated {
        "under every ceiling"
    } else {
        "unasserted, this boot being emulated rather than accelerated"
    };
    Ok(format!(
        "the cryptography domain proved {}vectors on this part and measured {}\
         milli-cycles-per-byte ({verdict})",
        proved, costs
    ))
}

/// The number a `primitive=` record carries under `key`, or `None` where no
/// record names that primitive with that key.
///
/// The primitive is compared as a whole field value and not as a substring,
/// because three of the names are prefixes of others: a `contains` would read
/// `chacha20`'s record off `chacha20-poly1305`'s line and report a primitive
/// as proved that the domain never mentioned.
fn count(records: &[&&str], primitive: Primitive, key: &str) -> Option<u64> {
    records
        .iter()
        .filter(|record| field_value(record, "primitive") == Some(primitive.name()))
        .find_map(|record| field_value(record, key))
        .and_then(|text| text.parse().ok())
}

#[cfg(test)]
mod tests;
