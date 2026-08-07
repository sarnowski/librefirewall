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
//! # The delegation, which is a claim about two domains and not one
//!
//! This domain authenticates under a key it does not hold, so two of its records
//! are about the domain that does. Both carry `delegated-device=` — the appliance
//! the key holder named — `delegated-signatures=`, that holder's own tally, and
//! `delegated-certificate=`, the size of the certificate the holder handed over.
//! [`delegation_records`] holds them to five things no single record can say: that
//! the identifier is the *same* on both, that it is the same one the `domain=store`
//! records report on the same boot, that the tally **moved** between them, that a
//! certificate arrived at all, and that its size is the same on both. The tally is
//! what proves the session's server half really ran on the delegated key: its
//! `CertificateVerify` was computed in the other domain, so a number that stayed
//! put would mean the handshake signed some other way and the seam was never on
//! the path. The certificate's size is the one field here that must **not** move —
//! one appliance has one certificate, so two sizes on one boot would be two
//! answers to one question.
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

/// The most whole cycles one operation of an asymmetric primitive may cost.
///
/// None of these is an accelerated-backend assertion and none could be: the
/// arithmetic under them runs on general-purpose registers, where ADX
/// accelerates without any of it being visible as a different code path. They
/// are regression bounds, set roughly four times above what this image
/// measures so that a change which made one of them several times slower — a
/// backend selection lost, a portable path taken where a tuned one was
/// intended — fails rather than passes quietly.
///
/// The figures they are four times above are this image's own, taken across
/// every boot of one accelerated gate run: ECDSA P-256 between 1.30 and 1.35
/// million cycles, X25519 between 259 and 264 thousand, ML-KEM-768 between 474
/// and 483 thousand. The ceilings had stood at twenty, twenty and sixty
/// million, which is fifteen to a hundred and twenty-five times the measurement
/// rather than four — a bound that loose catches a primitive that stopped
/// working, not one that got slower, which is what a regression bound is for.
///
/// Each figure is for a whole operation as a handshake performs it, not a
/// half: a signature is generated *and* verified, a key agreement is run from
/// both sides, and an encapsulation is followed by its decapsulation. A number
/// for half of one would be a number no path takes.
const OPERATION_CEILINGS: &[(Primitive, u64)] = &[
    (Primitive::EcdsaP256, 5_500_000),
    (Primitive::X25519, 1_100_000),
    (Primitive::MlKem768, 2_000_000),
];

/// The primitives a ceiling holds, whichever unit it is in, which is what the
/// profile page's `measured` column is compared against.
pub(crate) fn measured_primitives() -> Vec<Primitive> {
    CEILINGS
        .iter()
        .chain(OPERATION_CEILINGS)
        .map(|(primitive, _)| *primitive)
        .collect()
}

/// Whether the cryptography domain has finished, whichever way it went.
///
/// The domain runs to completion in `init` and then parks, and its `ready` and
/// `refused` records are the last thing it writes — so either one in the capture
/// means every record [`judge`] reads is already there. That is what makes this
/// usable as the point a boot may stop: a node whose only subject is this domain
/// keeps running afterwards, so nothing else would end it.
///
/// A refusal counts as finished on purpose. It is a verdict for [`judge`] to
/// report, naming the cause token, and waiting past it would turn a domain that
/// said exactly what went wrong into a timeout that says nothing.
pub(crate) fn finished(capture: &[u8]) -> bool {
    let text = String::from_utf8_lossy(capture);
    let ours = field("domain", Domain::Crypto.name());
    let done = [
        field("state", DomainState::Ready.name()),
        field("state", DomainState::Refused.name()),
    ];
    lifecycle_records(&text)
        .into_iter()
        .any(|record| record.contains(&ours) && done.iter().any(|state| record.contains(state)))
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
    for (ceilings, key, unit) in [
        (
            CEILINGS,
            "milli-cycles-per-byte",
            "thousandths of a cycle per byte",
        ),
        (
            OPERATION_CEILINGS,
            "cycles-per-operation",
            "cycles per operation",
        ),
    ] {
        for (primitive, ceiling) in ceilings {
            let measured = count(&steps, *primitive, key).ok_or_else(|| {
                format!(
                    "the cryptography domain published no `primitive={primitive} {key}=` record, \
                     and the profile names it as measured. A primitive claimed as measured and \
                     not measured is the gap this check exists to close\n  records observed: \
                     {ours:#?}\n  full run log: {}",
                    log.display()
                )
            })?;
            let _ = write!(costs, "{primitive}={measured} ");
            if measured == 0 {
                return Err(format!(
                    "the cryptography domain measured {primitive} at 0 {unit}, which is a \
                     counter that did not advance or a loop the optimizer removed\n  full run \
                     log: {}",
                    log.display()
                ));
            }
            if accelerated && measured > *ceiling {
                breached.push(format!(
                    "{primitive} cost {measured} against a ceiling of {ceiling}"
                ));
            }
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

    // The bring-up's own `ready`, which is the one with nothing after the state:
    // this domain finishes bring-up once and says so once. It no longer parks
    // there — it goes on to answer the relay, and every onboarding session it
    // carries leaves `ready` records of its own — so what is counted is the
    // bare one rather than every record in the state, and several of *those*
    // would still mean something else is writing its ring.
    let ready = field("state", DomainState::Ready.name());
    let complete: Vec<&&str> = ours
        .iter()
        .filter(|record| record.trim_end().ends_with(ready.trim_end()))
        .collect();
    if complete.len() != 1 {
        return Err(format!(
            "the console carried {} `{}` record(s) for the cryptography domain reporting `ready` \
             and nothing else, and a boot produces exactly one: bring-up runs once in `init`, so \
             none means it never finished — or faulted before it could — and several mean \
             something else is writing its ring\n  records observed: {ours:#?}\n  full run \
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
    let session = session_records(&steps, log)?;
    let delegation = delegation_records(&text, &steps, log)?;
    Ok(format!(
        "the cryptography domain proved {}vectors on this part, measured {}({verdict}), {}, and \
         {}",
        proved, costs, session, delegation
    ))
}

/// Judge the two records this domain leaves about the key it does not hold.
///
/// Three claims, and none of them is available from one record. The identifier
/// must be the same on both and must be the one the **store domain** reports on
/// the same boot, because that is what says the channel reached the appliance's
/// own key holder rather than answering out of a zeroed region. And the tally must
/// have moved, because that is what says the handshake between the two records
/// signed through the delegation rather than beside it.
///
/// The store domain's own `device=` is read out of the same capture rather than
/// through [`crate::store_contract`]: what is being compared is two domains'
/// renderings of one value, so both sides have to come off the wire.
fn delegation_records(text: &str, steps: &[&&str], log: &Path) -> Result<String, String> {
    let observed: Vec<(&str, &str, &str)> = steps
        .iter()
        .filter_map(|record| {
            Some((
                field_value(record, "delegated-device")?,
                field_value(record, "delegated-signatures")?,
                field_value(record, "delegated-certificate")?,
            ))
        })
        .collect();
    let [
        (first_device, first_count, first_certificate),
        (second_device, second_count, second_certificate),
    ] = observed[..]
    else {
        return Err(format!(
            "the cryptography domain published {} complete `delegated-device=` record(s) and a \
             boot produces exactly two: the direct proof that a signature made in the key \
             holder's domain verifies under the key that domain named — with the certificate over \
             that key held to it — and the same tally read again after a TLS session whose server \
             half ran under that key. One means the session never ran on the delegated key; none \
             means the delegation never answered at all. A record carrying the identifier without \
             `delegated-signatures=` or `delegated-certificate=` is not counted here, because a \
             partial record is a rendering that lost a field\n  records observed: {steps:#?}\n  \
             full run log: {}",
            observed.len(),
            log.display()
        ));
    };
    if first_device != second_device {
        return Err(format!(
            "the cryptography domain named appliance {first_device:?} before the session and \
             {second_device:?} after it, and a boot has one identity. Two values mean the key \
             holder answered as two different appliances\n  full run log: {}",
            log.display()
        ));
    }
    // The store domain's own rendering of the same value, off the same wire. A
    // disagreement here is the delegation reaching something other than this
    // node's key holder, which no amount of correct signing would make right.
    let held = lifecycle_records(text)
        .into_iter()
        .filter(|record| record.contains(&field("domain", Domain::Store.name())))
        .find_map(|record| field_value(record, "device"))
        .ok_or_else(|| {
            format!(
                "the store domain published no `device=` record, so there is nothing to hold the \
                 cryptography domain's `delegated-device=` to. The delegation's whole claim is \
                 that the two domains name one appliance\n  full run log: {}",
                log.display()
            )
        })?;
    if first_device != held {
        return Err(format!(
            "the cryptography domain signs for appliance {first_device:?} and the store domain \
             reports being {held:?}. The two are one node, so a difference means the delegation \
             reached a key that is not this appliance's — or a region nobody wired\n  full run \
             log: {}",
            log.display()
        ));
    }
    let number = |text: &str, which: &str| -> Result<u64, String> {
        text.parse::<u64>().map_err(|error| {
            format!(
                "the {which} `delegated-signatures={text}` is no number: {error}\n  full run log: \
                 {}",
                log.display()
            )
        })
    };
    let before = number(first_count, "first")?;
    let after = number(second_count, "second")?;
    // The certificate is the identity's other half, and the two records must agree
    // about it exactly: a size that moved would mean the holder answered with two
    // different certificates on one boot.
    if first_certificate != second_certificate {
        return Err(format!(
            "the key holder handed over a certificate of {first_certificate:?} bytes before the \
             session and {second_certificate:?} after it, and one appliance has one certificate. \
             Two sizes mean the holder answered with two different certificates\n  full run log: \
             {}",
            log.display()
        ));
    }
    let certificate = first_certificate.parse::<u64>().map_err(|error| {
        format!(
            "the `delegated-certificate={first_certificate}` is no number: {error}\n  full run \
             log: {}",
            log.display()
        )
    })?;
    if certificate == 0 {
        return Err(format!(
            "the key holder handed over 0 bytes of certificate, which is no certificate: the \
             cryptography domain refuses a certificate that does not carry the very public key \
             the same channel named, so a zero here is a boot that reported having one without \
             having asked\n  full run log: {}",
            log.display()
        ));
    }
    if before == 0 {
        return Err(format!(
            "the key holder reported having produced 0 signatures after the direct proof, and the \
             proof itself is one: a zero tally means the count is not the holder's own\n  full \
             run log: {}",
            log.display()
        ));
    }
    if after <= before {
        return Err(format!(
            "the key holder's signature tally was {before} before the TLS session and {after} \
             after it, and a session whose server half runs under the delegated key must move it: \
             the `CertificateVerify` is computed in that domain. A tally that did not move means \
             the handshake signed some other way, so the seam was never on the path this proof \
             exists to exercise\n  full run log: {}",
            log.display()
        ));
    }
    Ok(format!(
        "signed for appliance {first_device} under a key it does not hold, the holder's tally \
         moving {before} -> {after} across a session whose server half ran on that key, holding \
         a {certificate}-byte certificate over that very key"
    ))
}

/// The three code points the channel contract fixes, as their registries
/// number them: TLS 1.3, `TLS_CHACHA20_POLY1305_SHA256`, and the hybrid
/// `X25519MLKEM768` group. Written here as numbers because that is what the
/// domain reports and what a reader compares against a specification.
const OWED_VERSION: &str = "0x0304";
const OWED_SUITE: &str = "0x1303";
const OWED_GROUP: &str = "0x11ec";

/// Judge the session this domain establishes against itself.
///
/// The handshake is the claim the whole asymmetric half exists to support, and
/// nothing short of a completed one proves it: the key exchange, the
/// signature, the chain validation against an anchor, the key schedule and the
/// record layer all have to be right for a peer to be authenticated and for
/// application data to come back. So the records are checked for exactly the
/// parameters the channel contract fixes, and for data having moved.
fn session_records(steps: &[&&str], log: &Path) -> Result<String, String> {
    let named = |key: &str| -> Result<String, String> {
        steps
            .iter()
            .find_map(|record| field_value(record, key))
            .map(str::to_owned)
            .ok_or_else(|| {
                format!(
                    "the cryptography domain published no `{key}=` record. One boot establishes \
                     one mutually-authenticated session against itself and reports what it \
                     settled on, so a missing field is a session that did not complete\n  \
                     records observed: {steps:#?}\n  full run log: {}",
                    log.display()
                )
            })
    };
    let version = named("tls-version")?;
    let suite = named("tls-suite")?;
    let group = named("tls-group")?;
    let echoed = named("tls-echoed")?;
    let peer = named("peer-device")?;
    for (what, found, owed) in [
        ("protocol version", &version, OWED_VERSION),
        ("cipher suite", &suite, OWED_SUITE),
        ("key exchange group", &group, OWED_GROUP),
    ] {
        if found != owed {
            return Err(format!(
                "the session negotiated {what} {found} and the channel contract fixes {owed}. \
                 One end of this session is the appliance's own configuration, so a different \
                 answer is this build offering something the contract does not\n  full run log: \
                 {}",
                log.display()
            ));
        }
    }
    if echoed.parse::<u64>().unwrap_or_default() == 0 {
        return Err(format!(
            "the session carried 0 bytes of application data, so the traffic keys were never \
             used in either direction and the handshake is all that was proved\n  full run log: \
             {}",
            log.display()
        ));
    }
    if peer.trim_start_matches('0').is_empty() {
        return Err(format!(
            "the session's peer identity is all zeroes, which is no identity: a \
             mutually-authenticated session names the peer it admitted\n  full run log: {}",
            log.display()
        ));
    }
    let arena: Vec<&str> = steps
        .iter()
        .filter_map(|record| field_value(record, "arena-bytes"))
        .collect();
    if arena.len() != 2 {
        return Err(format!(
            "the cryptography domain published {} `arena-bytes=` record(s) and a boot \
             produces exactly two: what a session used against what the arena has, and what a \
             deliberately starved session was left with against what one step needs. The second \
             is the proof that reaching the bound is a refusal rather than a fault, and a boot \
             without it has shown a working allocator and nothing about its bound\n  full run \
             log: {}",
            arena.len(),
            log.display()
        ));
    }
    Ok(format!(
        "established a {version} session under {suite} and {group}, carried {echoed} bytes of \
         application data both ways, authenticated peer {peer}, and refused a starved one"
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
