//! The console grammar: one [`Event`] to one line of a closed vocabulary.

use core::fmt::{self, Write as _};

use lfw_clock::{RFC3339_LEN, render_rfc3339};

use crate::detail::{DomainDetail, Refusal, RefusalDetail};
use crate::event::Event;
use crate::stamp::Stamp;

/// An upper bound on what [`render`] produces, so a caller sizes one buffer
/// once and is done with it. Held by
/// `the_widest_line_of_each_shape_fits_the_maximum`, which renders the widest
/// value of every field of every shape against it, a refusal's `cause` at
/// [`crate::MAX_CAUSE_LEN`] — which [`Cause`](crate::Cause) now holds it to.
///
/// It is a bound on what any *representable* event renders to and not on what a
/// domain would really emit: the widest line is a channel's four refused-reply
/// counts under the longest domain name this vocabulary has, a pairing no
/// appliance produces and a byzantine writing domain can put in a record.
pub const MAX_LINE_LEN: usize = 256;

/// The buffer could not hold the line.
///
/// Refusing is the whole point: a truncated line is one an operator reads as
/// complete, and the field a console grammar loses off the end is the last one
/// — `to=`, the value something was just changed to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RenderError {
    BufferTooSmall,
}

impl fmt::Display for RenderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BufferTooSmall => f.write_str("the buffer is too small for the rendered line"),
        }
    }
}

/// Write `event`, stamped `at`, into `out` as its console line, without a
/// trailing newline, and return how many bytes it took.
///
/// There is no allocator, so the buffer is the caller's and the length comes
/// back rather than a string.
pub fn render<C: fmt::Display>(
    at: Stamp,
    event: &Event<C>,
    out: &mut [u8],
) -> Result<usize, RenderError> {
    let mut cursor = Cursor {
        out,
        written: 0usize,
    };
    match write_line(at, event, &mut cursor) {
        Ok(()) => Ok(cursor.written),
        // `fmt::Error` is a unit type, so this discards nothing: capacity is
        // all a failure here can have been.
        Err(fmt::Error) => Err(RenderError::BufferTooSmall),
    }
}

fn write_line<C: fmt::Display>(
    at: Stamp,
    event: &Event<C>,
    cursor: &mut Cursor<'_>,
) -> fmt::Result {
    match event {
        Event::Domain {
            domain,
            state,
            detail,
        } => {
            cursor.write_str("LFW-PD")?;
            write_stamp(at, cursor)?;
            write!(cursor, " domain={domain} state={state}")?;
            write_detail(detail, cursor)
        }
        Event::ConfigChange {
            generation,
            sequence,
            change,
            object,
            key,
            field,
            from,
            to,
        } => {
            cursor.write_str("LFW-CFG")?;
            write_stamp(at, cursor)?;
            write!(
                cursor,
                " generation={generation} seq={sequence} change={change} \
                 object={object} key={key} field={field}"
            )?;
            if let Some(value) = from {
                write!(cursor, " from={value}")?;
            }
            if let Some(value) = to {
                write!(cursor, " to={value}")?;
            }
            Ok(())
        }
        Event::ConfigGeneration {
            generation,
            outcome,
            changes,
        } => {
            cursor.write_str("LFW-CFG")?;
            write_stamp(at, cursor)?;
            write!(
                cursor,
                " generation={generation} outcome={outcome} changes={changes}"
            )
        }
        Event::ConfigRejected {
            generation,
            reason,
            offset,
        } => {
            cursor.write_str("LFW-CFG")?;
            write_stamp(at, cursor)?;
            write!(
                cursor,
                " generation={generation} rejected={reason} offset={offset}"
            )
        }
    }
}

/// The instant, immediately after the record identifier and before every field
/// that identifies *what* happened.
///
/// It goes after `LFW-…` rather than in front of it because that prefix is
/// a reader's only documented handle on where a record starts: a field written
/// ahead of it would be outside every record the documented scan recovers.
fn write_stamp(at: Stamp, cursor: &mut Cursor<'_>) -> fmt::Result {
    cursor.write_str(" time=")?;
    match at {
        Stamp::Unsynchronized => cursor.write_str(Stamp::UNSYNCHRONIZED),
        // The instant goes out as the ASCII bytes it is: a `from_utf8` here
        // would have no failure arm but a line missing the instant.
        Stamp::Utc(utc) => {
            let mut instant = [0u8; RFC3339_LEN];
            render_rfc3339(utc, &mut instant);
            cursor.write_ascii(&instant)
        }
    }
}

/// The `cause` key, named because its width decides whether a cause was written.
const CAUSE_KEY: &str = " cause=";

/// One offer list as its own field: the code points a client listed, comma
/// separated, bounded by what the record holds rather than by what the client
/// claimed.
///
/// `offered` is the client's own number and may exceed the storage beside it,
/// which is the whole reason it is on the record — so it bounds nothing here
/// and only says how much of the offer was kept.
fn write_offer(
    cursor: &mut Cursor<'_>,
    key: &str,
    points: &[u16; crate::MAX_OFFERED_POINTS],
    offered: u16,
) -> fmt::Result {
    cursor.write_str(key)?;
    let kept = usize::from(offered).min(points.len());
    let Some(listed) = points.get(..kept) else {
        return cursor.write_str("none");
    };
    if listed.is_empty() {
        return cursor.write_str("none");
    }
    for (index, point) in listed.iter().enumerate() {
        if index > 0 {
            cursor.write_str(",")?;
        }
        write!(cursor, "0x{point:04x}")?;
    }
    Ok(())
}

/// The tail of an `LFW-PD` line, absent for the lifecycle points that carry
/// nothing: a record ending in an empty field reads as a missing value.
fn write_detail<C: fmt::Display>(detail: &DomainDetail<C>, cursor: &mut Cursor<'_>) -> fmt::Result {
    match detail {
        DomainDetail::None => Ok(()),
        DomainDetail::Features(bits) => write!(cursor, " features={bits:#x}"),
        DomainDetail::ReceivePosted(count) => write!(cursor, " rx-posted={count}"),
        DomainDetail::Established { tsc_hz, utc } => {
            write!(cursor, " tsc-hz={tsc_hz} utc=")?;
            let mut instant = [0u8; RFC3339_LEN];
            render_rfc3339(*utc, &mut instant);
            cursor.write_ascii(&instant)
        }
        DomainDetail::Received { frames, bytes } => {
            write!(cursor, " frames={frames} bytes={bytes}")
        }
        // Decimal against a disk's size, hexadecimal against bytes — and padded
        // to all sixteen digits, so a superblock's first eight bytes line up
        // between two records rather than shortening around a zero byte.
        DomainDetail::Medium {
            capacity_sectors,
            leading_word,
        } => write!(
            cursor,
            " sectors={capacity_sectors} leading={leading_word:#018x}"
        ),
        DomainDetail::Extent {
            start_sector,
            sectors,
        } => write!(cursor, " start={start_sector} sectors={sectors}"),
        // `recording=` is a constant field on `proven`'s terms: the variant is
        // the answer, so a value reading the other way would be a state the type
        // cannot carry. The extent's first sector leads both, so a reader pairs
        // each with its `start=` record by value rather than by counting lines.
        DomainDetail::RecordingResumed {
            start_sector,
            generation,
            sequence,
            opened,
        } => write!(
            cursor,
            " recording-start={start_sector} recording=resumed \
             recording-generation={generation} recording-sequence={sequence} \
             recording-opened={opened}"
        ),
        DomainDetail::RecordingFresh {
            start_sector,
            rebound,
        } => write!(
            cursor,
            " recording-start={start_sector} recording=fresh recording-rebound={rebound}"
        ),
        // `proven` is written as two constant fields rather than derived from a
        // payload, because the variant is the proof: it is constructible only
        // by the domain whose every pass held both known answers, so a value
        // that could read "unproven" would be a state the type cannot carry.
        DomainDetail::Proven {
            preemptions,
            iterations,
        } => write!(
            cursor,
            " aes=proven pclmul=proven preemptions={preemptions} iterations={iterations}"
        ),
        DomainDetail::Proved { primitive, vectors } => {
            write!(cursor, " primitive={primitive} vectors={vectors}")
        }
        DomainDetail::Measured {
            primitive,
            milli_cycles_per_byte,
        } => write!(
            cursor,
            " primitive={primitive} milli-cycles-per-byte={milli_cycles_per_byte}"
        ),
        DomainDetail::Session { version, suite } => write!(
            cursor,
            " tls-version=0x{version:04x} tls-suite=0x{suite:04x}"
        ),
        DomainDetail::Exchange { group, echoed } => {
            write!(cursor, " tls-group=0x{group:04x} tls-echoed={echoed}")
        }
        // The identifier is written the one way it is ever written: 32
        // lowercase hexadecimal characters, which is what an administrator
        // compares against the management application's rendering.
        DomainDetail::Peer { device } => write!(cursor, " peer-device={device:032x}"),
        DomainDetail::Arena { bytes, bound } => {
            write!(cursor, " arena-bytes={bytes} arena-bound={bound}")
        }
        DomainDetail::Operation { primitive, cycles } => {
            write!(
                cursor,
                " primitive={primitive} cycles-per-operation={cycles}"
            )
        }
        // The identifier the one way it is ever written: 32 lowercase
        // hexadecimal characters, which is what an administrator compares
        // against the onboarding page's rendering — the same rendering
        // `peer-device=` above carries.
        DomainDetail::Identity {
            device,
            generation,
            onboarded,
        } => write!(
            cursor,
            " device={device:032x} generation={generation} onboarded={onboarded}"
        ),
        // 64 lowercase hexadecimal characters, no separators, as one field.
        // Written a nibble at a time rather than through a formatter over four
        // words, because a `{:016x}` per word would silently shorten a word with
        // a leading zero byte and produce a fingerprint that is not this one.
        DomainDetail::Fingerprint(digest) => {
            cursor.write_str(" fingerprint=")?;
            for byte in digest {
                write!(cursor, "{byte:02x}")?;
            }
            Ok(())
        }
        // The authority an appliance has just accepted, rendered exactly as its
        // own `fingerprint=` is and for the same reason: an administrator
        // compares this string against what the management server shows, and two
        // formats for one kind of digest would be two things to get right.
        DomainDetail::AnchorFingerprint(digest) => {
            cursor.write_str(" anchor-fingerprint=")?;
            for byte in digest {
                write!(cursor, "{byte:02x}")?;
            }
            Ok(())
        }
        // Whether this appliance has an owner, in the word the drop reason and
        // the metric label already use for it. One field: what an operator does
        // with this line is read the word.
        DomainDetail::Ownership(ownership) => write!(cursor, " ownership={ownership}"),
        // Where an appliance that has just been given an owner will answer to,
        // and the generation the record saying so stands at. The address is
        // spelled as an address on `dial-destination=`'s terms.
        DomainDetail::Adopted {
            destination,
            port,
            generation,
        } => write!(
            cursor,
            " adopted-endpoint={destination} adopted-port={port} \
             adopted-generation={generation}"
        ),
        // What a reset destroyed, as three fields keyed to the past: the record
        // this appliance no longer has, the versions that went with it, and
        // whether there was an owner to give up. `cleared-generation=0` is a
        // medium that carried no record this build could read, which is a state a
        // reset is honoured over rather than refused for.
        DomainDetail::Reset {
            generation,
            documents,
            was_owned,
        } => write!(
            cursor,
            " cleared-generation={generation} cleared-documents={documents} \
             was-owned={was_owned}"
        ),
        // The appliance a domain holding no key signs for, and the holder's own
        // tally. The identifier is rendered exactly as `device=` and
        // `peer-device=` are, so an operator comparing this line against the
        // holder's own is comparing one string against another rather than two
        // formats.
        DomainDetail::Delegated {
            device,
            signatures,
            certificate,
        } => write!(
            cursor,
            " delegated-device={device:032x} delegated-signatures={signatures} \
             delegated-certificate={certificate}"
        ),
        // Whether an anchor was delivered at all, then how large it is. The word
        // comes first because it is the one an operator reads: a size beside
        // `false` is a zero, and a zero is not a length anybody delivered.
        DomainDetail::DelegatedAnchor { delivered, anchor } => write!(
            cursor,
            " delegated-anchor-delivered={delivered} delegated-anchor={anchor}"
        ),
        // Where the domain holding the record has told the dialling domain to go,
        // and whether it has told it anywhere at all. The address is spelled as an
        // address on `dial-destination=`'s terms; the word after it is what stops
        // an all-zero address from reading as somewhere.
        DomainDetail::Published {
            destination,
            port,
            published,
        } => write!(
            cursor,
            " published-endpoint={destination} published-port={port} \
             published={published}"
        ),
        // Where this appliance reached out to and how it got on, as four fields
        // an operator reads in one direction: the place, the port, how many
        // attempts it took, and the outcome of the last of them. The destination
        // is spelled as an address rather than as the word that carries it, so a
        // line here and the configuration document's own `gateway=` compare as
        // one string against another.
        DomainDetail::Dialled {
            destination,
            port,
            attempts,
            outcome,
        } => write!(
            cursor,
            " dial-destination={destination} dial-port={port} dial-attempts={attempts} \
             dial-outcome={outcome}"
        ),
        // The three records a failed channel adds, each one line of counts. The
        // keys all begin `dial-` so a reader picking the channel's story out of
        // a boot transcript picks it out by one prefix, and none of them repeats
        // a key another record carries.
        DomainDetail::DialRoute {
            next_hop,
            via,
            requests,
            learned,
        } => write!(
            cursor,
            " dial-next-hop={next_hop} dial-next-hop-via={via} dial-requests={requests} \
             dial-learned={learned}"
        ),
        DomainDetail::DialUnlearned {
            unsolicited,
            rebinding,
            not_unicast,
            contradicted,
        } => write!(
            cursor,
            " dial-reply-unsolicited={unsolicited} dial-reply-rebinding={rebinding} \
             dial-reply-not-unicast={not_unicast} dial-reply-contradicted={contradicted}"
        ),
        DomainDetail::DialSegments {
            syns,
            resets_received,
            resets_sent,
            answered,
        } => write!(
            cursor,
            " dial-syns={syns} dial-resets-received={resets_received} \
             dial-resets-sent={resets_sent} dial-answered={answered}"
        ),
        // The keys all begin `onboard-` for the `dial-` group's reason: a
        // reader picks one session's story out of a boot transcript by one
        // prefix, and both domains that carry a session write the same four
        // keys, so the two accounts are compared field by field.
        DomainDetail::Onboarded {
            relayed,
            received,
            sent,
            ended,
        } => write!(
            cursor,
            " onboard-relayed={relayed} onboard-received={received} onboard-sent={sent} \
             onboard-ended={ended}"
        ),
        // The port's own totals, under keys naming the port rather than a
        // session: a reader who mistook one for the other would read a boot's
        // refusals as one session's.
        DomainDetail::OnboardingPort {
            accepted,
            forgotten,
            overflowed,
            refused,
        } => write!(
            cursor,
            " onboard-accepted={accepted} onboard-forgotten={forgotten} \
             onboard-overflowed={overflowed} onboard-refused={refused}"
        ),
        // The seven a handshake on that port produces, all under one
        // `onboard-tls=` key so a boot's whole onboarding story is one grep —
        // the `dial-` group's reason on the other port. The code points are
        // written as the registries number them, four hexadecimal digits with
        // the prefix, exactly as `tls-version=` and `tls-suite=` are above:
        // three renderings of one kind of value must not be three formats.
        DomainDetail::OnboardingHandshake {
            outcome,
            version,
            suite,
            group,
        } => write!(
            cursor,
            " onboard-tls={outcome} onboard-tls-version=0x{version:04x} \
             onboard-tls-suite=0x{suite:04x} onboard-tls-group=0x{group:04x}"
        ),
        DomainDetail::OnboardingEnded { outcome } => write!(cursor, " onboard-tls={outcome}"),
        DomainDetail::OnboardingIncompatible {
            outcome,
            incompatible,
        } => write!(
            cursor,
            " onboard-tls={outcome} onboard-tls-incompatible={incompatible}"
        ),
        DomainDetail::OnboardingRefused { outcome, refusal } => {
            write!(cursor, " onboard-tls={outcome} onboard-tls-error={refusal}")
        }
        DomainDetail::OnboardingAlert { outcome, alert } => write!(
            cursor,
            " onboard-tls={outcome} onboard-tls-alert=0x{alert:04x}"
        ),
        DomainDetail::OnboardingBacklogged { outcome, held } => {
            write!(cursor, " onboard-tls={outcome} onboard-tls-held={held}")
        }
        // The two offer records. The list is comma-separated inside one field,
        // which the grammar already carries for a refusal's number pair, and it
        // is spelled `none` rather than left empty where the client listed
        // nothing — a value-less key is the one shape a reader looking keys up
        // cannot read.
        DomainDetail::OnboardingSuites { points, offered } => {
            write_offer(cursor, " onboard-tls-suites=", points, *offered)?;
            write!(cursor, " onboard-tls-suites-offered={offered}")
        }
        DomainDetail::OnboardingGroups { points, offered } => {
            write_offer(cursor, " onboard-tls-groups=", points, *offered)?;
            write!(cursor, " onboard-tls-groups-offered={offered}")
        }
        // The request surface's three, under a key of their own rather than
        // `onboard-tls-`'s: they are a protocol above the record layer, and a
        // reader grepping one boot's handshakes must not also get its requests.
        DomainDetail::OnboardingServed { route, bytes } => {
            write!(cursor, " onboard-http={route} onboard-http-bytes={bytes}")
        }
        DomainDetail::OnboardingRequest {
            refusal,
            status,
            held,
        } => write!(
            cursor,
            " onboard-http-refused={refusal} onboard-http-status={status} \
             onboard-http-held={held}"
        ),
        DomainDetail::OnboardingThrottled {
            strikes,
            wait_millis,
        } => write!(
            cursor,
            " onboard-http-strikes={strikes} onboard-http-wait={wait_millis}"
        ),
        DomainDetail::OnboardingInstalled { bytes } => {
            write!(cursor, " onboard-http-installed={bytes}")
        }
        // Decimal, unlike a refusal's hexadecimal numbers below: these are
        // sequence numbers, and a peer's own capture and this appliance's
        // console are compared digit for digit.
        DomainDetail::DialSequence { claimed, expected } => write!(
            cursor,
            " dial-acknowledged={claimed} dial-expected={expected}"
        ),
        // Milliseconds, and both of them: an operator reads a wait against a
        // wall clock, and the bound beside it is what says whether the schedule
        // has been climbing.
        DomainDetail::DialRetry {
            delay_millis,
            bound_millis,
        } => write!(
            cursor,
            " dial-retry-in={delay_millis} dial-retry-bound={bound_millis}"
        ),
        // The management channel's eight, keyed `channel-` throughout: a boot's
        // channel story is one grep, and it is a different grep from the
        // onboarding port's because the two are the two ends of this
        // appliance's life and never run at once.
        DomainDetail::ChannelHandshake {
            outcome,
            version,
            suite,
            group,
        } => write!(
            cursor,
            " channel-tls={outcome} channel-tls-version=0x{version:04x} \
             channel-tls-suite=0x{suite:04x} channel-tls-group=0x{group:04x}"
        ),
        DomainDetail::ChannelEnded { outcome } => write!(cursor, " channel-tls={outcome}"),
        DomainDetail::ChannelIncompatible {
            outcome,
            incompatible,
        } => write!(
            cursor,
            " channel-tls={outcome} channel-tls-incompatible={incompatible}"
        ),
        DomainDetail::ChannelRefused { outcome, refusal } => {
            write!(cursor, " channel-tls={outcome} channel-tls-error={refusal}")
        }
        DomainDetail::ChannelCertificate { outcome, refusal } => write!(
            cursor,
            " channel-tls={outcome} channel-tls-certificate={refusal}"
        ),
        DomainDetail::ChannelAlert { outcome, alert } => write!(
            cursor,
            " channel-tls={outcome} channel-tls-alert=0x{alert:04x}"
        ),
        DomainDetail::ChannelBacklogged { outcome, held } => {
            write!(cursor, " channel-tls={outcome} channel-tls-held={held}")
        }
        DomainDetail::ChannelFrames {
            agreed,
            version,
            sent,
            received,
        } => write!(
            cursor,
            " channel-agreed={agreed} channel-version={version} channel-frames-sent={sent} \
             channel-frames-received={received}"
        ),
        DomainDetail::ChannelShipping {
            log_position,
            log_pending,
            capture_position,
            capture_pending,
        } => write!(
            cursor,
            " channel-log-shipped={log_position} channel-log-pending={log_pending} \
             channel-capture-shipped={capture_position} \
             channel-capture-pending={capture_pending}"
        ),
        // `configured-restored=false` is a version this boot committed, `true`
        // one it resumed off the medium.
        DomainDetail::Configured {
            generation,
            slot,
            bytes,
            restored,
        } => write!(
            cursor,
            " configured-generation={generation} configured-slot={slot} \
             configured-bytes={bytes} configured-restored={restored}"
        ),
        DomainDetail::Refusal(Refusal {
            cause,
            detail,
            signalled,
        }) => {
            // An absent value takes its key with it, as `None` above does: a
            // domain may refuse without naming a cause, and a value-less key is
            // the one shape a reader looking keys up cannot read. Written and
            // rewound, so one `Display` call decides it.
            let before = cursor.written;
            cursor.write_str(CAUSE_KEY)?;
            write!(cursor, "{cause}")?;
            if cursor.written == before.saturating_add(CAUSE_KEY.len()) {
                cursor.written = before;
            }
            write!(cursor, " signalled={signalled}")?;
            // Hexadecimal throughout: a refusal's numbers are device
            // identifiers, addresses and status bits, read against a datasheet.
            match detail {
                RefusalDetail::None => Ok(()),
                RefusalDetail::One(value) => write!(cursor, " detail={value:#x}"),
                RefusalDetail::Two(first, second) => {
                    write!(cursor, " detail={first:#x},{second:#x}")
                }
            }
        }
    }
}

/// A `core::fmt` sink over a fixed slice that refuses rather than truncates.
struct Cursor<'a> {
    out: &'a mut [u8],
    written: usize,
}

impl Cursor<'_> {
    fn write_ascii(&mut self, bytes: &[u8]) -> fmt::Result {
        let end = self.written.checked_add(bytes.len()).ok_or(fmt::Error)?;
        let slot = self.out.get_mut(self.written..end).ok_or(fmt::Error)?;
        slot.copy_from_slice(bytes);
        self.written = end;
        Ok(())
    }
}

impl fmt::Write for Cursor<'_> {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        self.write_ascii(text.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detail::{Cause, MAX_CAUSE_LEN};
    use crate::event::Primitive;
    use crate::event::{
        ChangeKind, ChannelOutcome, DialOutcome, Domain, DomainState, Field, GenerationOutcome,
        NextHopVia, ObjectKind, OnboardEnd, OnboardOutcome, OnboardRefusal, OnboardRoute,
        RejectReason, TlsCertificateRefusal, TlsIncompatible, TlsRefusal, Value,
    };
    use crate::identifier::{Identifier, MAX_IDENTIFIER_LEN};
    use crate::shapes::every_shape;
    use net_headers::{Ipv4Address, MacAddress};
    use proptest::prelude::*;
    use std::{boxed::Box, string::String, vec, vec::Vec};

    /// The established-time detail from the two numbers the ABI carries; see
    /// the identically named helper in `record/tests.rs`.
    fn established(tsc_hz: u64, unix_nanos: u64) -> DomainDetail {
        DomainDetail::Established {
            tsc_hz: core::num::NonZeroU64::new(tsc_hz).expect("a frequency above zero"),
            utc: lfw_clock::UtcNanos::from_unix_nanos(unix_nanos),
        }
    }

    fn id(text: &str) -> Identifier {
        Identifier::new(text.as_bytes()).expect("the fixture is within the alphabet")
    }

    /// The instant every expectation below is written against, so a literal
    /// line is a literal rather than whatever the host's counter said.
    const AT: Stamp = Stamp::Utc(lfw_clock::UtcNanos::from_unix_nanos(
        1_785_443_220 * 1_000_000_000 + 123_456_789,
    ));

    fn rendered(event: &Event) -> String {
        rendered_at(AT, event)
    }

    fn rendered_at(at: Stamp, event: &Event) -> String {
        rendered_cause(at, event)
    }

    /// The same, for the decoded shape whose cause is a [`Cause`] rather than a
    /// literal — which is the only one that can carry the empty token.
    fn rendered_cause<C: fmt::Display>(at: Stamp, event: &Event<C>) -> String {
        let mut buffer = [0u8; MAX_LINE_LEN];
        let written = render(at, event, &mut buffer).expect("MAX_LINE_LEN holds every line");
        String::from_utf8(buffer[..written].to_vec()).expect("the grammar is ASCII")
    }

    fn change(from: Option<Value>, to: Option<Value>) -> Event {
        Event::ConfigChange {
            generation: 4,
            sequence: 2,
            change: ChangeKind::Modified,
            object: ObjectKind::Interface,
            key: id("wan"),
            field: Field::PrefixLength,
            from,
            to,
        }
    }

    #[test]
    fn a_domain_lifecycle_point_renders_its_domain_and_state() {
        assert_eq!(
            rendered(&Event::Domain {
                domain: Domain::NicDriver,
                state: DomainState::Negotiated,
                detail: DomainDetail::None,
            }),
            "LFW-PD time=2026-07-30T20:27:00.123456789Z domain=nic-driver state=negotiated"
        );
        assert_eq!(
            rendered(&Event::Domain {
                domain: Domain::Forwarder,
                state: DomainState::Ready,
                detail: DomainDetail::None,
            }),
            "LFW-PD time=2026-07-30T20:27:00.123456789Z domain=forwarder state=ready"
        );
    }

    /// The two forms of the leading field. The absence renders as a token an
    /// operator can read and a parser can match, never as an instant — a record
    /// dated 1970 would be indistinguishable from one this node actually
    /// emitted at the epoch.
    #[test]
    fn a_record_with_no_time_carries_the_token_and_not_the_epoch() {
        let event = Event::Domain {
            domain: Domain::Clock,
            state: DomainState::Starting,
            detail: DomainDetail::None,
        };
        assert_eq!(
            rendered_at(Stamp::Unsynchronized, &event),
            "LFW-PD time=unsynchronized domain=clock state=starting"
        );
        assert_eq!(
            rendered_at(Stamp::Utc(lfw_clock::UtcNanos::from_unix_nanos(0)), &event),
            "LFW-PD time=1970-01-01T00:00:00.000000000Z domain=clock state=starting"
        );
    }

    /// The field sits after the record identifier, which is the documented
    /// handle a reader has for where a record starts: a stamp written
    /// in front of `LFW-` would fall outside every record the documented scan
    /// recovers.
    #[test]
    fn the_instant_follows_the_record_identifier_rather_than_preceding_it() {
        for shape in every_shape() {
            for at in [Stamp::Unsynchronized, AT] {
                let line = rendered_at(at, &shape);
                assert!(line.starts_with("LFW-"), "{line}");
                let (identifier, rest) = line.split_once(' ').expect("a record has fields");
                assert!(identifier.starts_with("LFW-"), "{line}");
                assert!(rest.starts_with("time="), "{line}");
            }
        }
    }

    #[test]
    fn a_lifecycle_point_that_carries_a_payload_renders_it_as_a_field() {
        assert_eq!(
            rendered(&Event::Domain {
                domain: Domain::NicDriver,
                state: DomainState::Negotiated,
                detail: DomainDetail::Features(0x1_3000_0020),
            }),
            "LFW-PD time=2026-07-30T20:27:00.123456789Z domain=nic-driver state=negotiated features=0x130000020"
        );
        assert_eq!(
            rendered(&Event::Domain {
                domain: Domain::NicDriver,
                state: DomainState::Ready,
                detail: DomainDetail::ReceivePosted(64),
            }),
            "LFW-PD time=2026-07-30T20:27:00.123456789Z domain=nic-driver state=ready rx-posted=64"
        );
    }

    /// The one record that states a time, and the only place a value on this
    /// surface is not `[a-z0-9-]`: an RFC 3339 instant carries `T`, `Z`, `:`
    /// and `.`, exactly as a MAC carries colons and an address dots.
    #[test]
    fn an_established_clock_renders_its_frequency_and_the_instant_it_anchored() {
        assert_eq!(
            rendered(&Event::Domain {
                domain: Domain::Clock,
                state: DomainState::Ready,
                detail: established(2_999_998_000, 1_785_443_220 * 1_000_000_000 + 123_456_789),
            }),
            "LFW-PD time=2026-07-30T20:27:00.123456789Z domain=clock state=ready tsc-hz=2999998000 \
             utc=2026-07-30T20:27:00.123456789Z"
        );
        // The two extremes of the pair, so the widest and narrowest fields are
        // rendered rather than only a plausible middle: one hertz at the epoch,
        // and the largest frequency and the last instant `u64` nanoseconds hold.
        assert_eq!(
            rendered(&Event::Domain {
                domain: Domain::Clock,
                state: DomainState::Ready,
                detail: established(1, 0),
            }),
            "LFW-PD time=2026-07-30T20:27:00.123456789Z domain=clock state=ready tsc-hz=1 utc=1970-01-01T00:00:00.000000000Z"
        );
        assert_eq!(
            rendered(&Event::Domain {
                domain: Domain::Clock,
                state: DomainState::Ready,
                detail: established(u64::MAX, u64::MAX),
            }),
            "LFW-PD time=2026-07-30T20:27:00.123456789Z domain=clock state=ready tsc-hz=18446744073709551615 \
             utc=2554-07-21T23:34:33.709551615Z"
        );
    }

    /// The management port's counts, at both ends of what the ABI carries: the
    /// pair a first frame produces, and the pair a `u64` cannot exceed.
    #[test]
    fn a_terminal_endpoint_renders_the_frames_and_bytes_it_has_taken() {
        let received = |frames, bytes| {
            rendered(&Event::Domain {
                domain: Domain::Management,
                state: DomainState::Ready,
                detail: DomainDetail::Received { frames, bytes },
            })
        };
        assert_eq!(
            received(1, 60),
            "LFW-PD time=2026-07-30T20:27:00.123456789Z domain=management state=ready frames=1 bytes=60"
        );
        assert_eq!(
            received(u64::MAX, u64::MAX),
            "LFW-PD time=2026-07-30T20:27:00.123456789Z domain=management state=ready \
             frames=18446744073709551615 bytes=18446744073709551615"
        );
    }

    /// Both at the widest a `u64` carries: the line is fixed-width, so the
    /// widest pair is what could overrun it.
    #[test]
    fn a_recorder_renders_the_capacity_and_the_word_it_read() {
        let medium = |capacity_sectors, leading_word| {
            rendered(&Event::Domain {
                domain: Domain::Recorder,
                state: DomainState::Ready,
                detail: DomainDetail::Medium {
                    capacity_sectors,
                    leading_word,
                },
            })
        };
        assert_eq!(
            medium(131_072, 0x0000_0000_0000_00EB),
            "LFW-PD time=2026-07-30T20:27:00.123456789Z domain=recorder state=ready \
             sectors=131072 leading=0x00000000000000eb"
        );
        assert_eq!(
            medium(u64::MAX, u64::MAX),
            "LFW-PD time=2026-07-30T20:27:00.123456789Z domain=recorder state=ready \
             sectors=18446744073709551615 leading=0xffffffffffffffff"
        );
    }

    /// Both counts at the widest a `u64` carries, and the pair a short run
    /// produces: the two constant fields are the variant's own claim, so they
    /// appear whatever the counts are.
    #[test]
    fn a_hardware_probe_renders_its_proof_and_the_preemptions_it_survived() {
        let proven = |preemptions, iterations| {
            rendered(&Event::Domain {
                domain: Domain::HardwareProbe,
                state: DomainState::Ready,
                detail: DomainDetail::Proven {
                    preemptions,
                    iterations,
                },
            })
        };
        assert_eq!(
            proven(3, 90_000),
            "LFW-PD time=2026-07-30T20:27:00.123456789Z domain=hardware-probe state=ready \
             aes=proven pclmul=proven preemptions=3 iterations=90000"
        );
        assert_eq!(
            proven(u64::MAX, u64::MAX),
            "LFW-PD time=2026-07-30T20:27:00.123456789Z domain=hardware-probe state=ready \
             aes=proven pclmul=proven preemptions=18446744073709551615 \
             iterations=18446744073709551615"
        );
    }

    /// The two records the store domain makes about the appliance itself.
    ///
    /// The identifier is 32 hexadecimal characters and the fingerprint is 64, in
    /// one field each and lowercase throughout: an administrator compares both
    /// against another rendering character for character, and a second rendering
    /// is what makes such a comparison careless.
    #[test]
    fn a_store_domain_renders_the_appliance_it_is_and_the_key_it_holds() {
        let identity = |device, generation, onboarded| {
            rendered(&Event::Domain {
                domain: Domain::Store,
                state: DomainState::Ready,
                detail: DomainDetail::Identity {
                    device,
                    generation,
                    onboarded,
                },
            })
        };
        assert_eq!(
            identity(0x0123_4567_89ab_cdef_fedc_ba98_7654_3210, 1, false),
            "LFW-PD time=2026-07-30T20:27:00.123456789Z domain=store state=ready \
             device=0123456789abcdeffedcba9876543210 generation=1 onboarded=false"
        );
        // A leading zero nibble stays: an identifier is a fixed-width string,
        // and one that shortened around a zero byte would be a different name.
        assert_eq!(
            identity(1, u64::MAX, true),
            "LFW-PD time=2026-07-30T20:27:00.123456789Z domain=store state=ready \
             device=00000000000000000000000000000001 \
             generation=18446744073709551615 onboarded=true"
        );

        let mut digest = [0_u8; 32];
        for (at, byte) in digest.iter_mut().enumerate() {
            *byte = at as u8;
        }
        assert_eq!(
            rendered(&Event::Domain {
                domain: Domain::Store,
                state: DomainState::Ready,
                detail: DomainDetail::Fingerprint(digest),
            }),
            "LFW-PD time=2026-07-30T20:27:00.123456789Z domain=store state=ready \
             fingerprint=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        );
        // The all-zero digest, which is the one a per-word formatter would
        // shorten to nothing at all.
        assert_eq!(
            rendered(&Event::Domain {
                domain: Domain::Store,
                state: DomainState::Ready,
                detail: DomainDetail::Fingerprint([0; 32]),
            }),
            format!(
                "LFW-PD time=2026-07-30T20:27:00.123456789Z domain=store state=ready \
                 fingerprint={}",
                "0".repeat(64)
            )
        );
    }

    /// The two records an appliance emits when it is given an owner: where it
    /// will answer to, and the fingerprint of the authority it will validate that
    /// channel against.
    ///
    /// The anchor's digest is rendered exactly as the appliance's own is —
    /// 64 lowercase hexadecimal characters, no separators — because an
    /// administrator compares both against strings a management server showed
    /// them, and a second format would be a second thing to read carefully.
    #[test]
    fn taking_ownership_reports_the_endpoint_and_the_authority() {
        assert_eq!(
            rendered(&Event::Domain {
                domain: Domain::Store,
                state: DomainState::Ready,
                detail: DomainDetail::Adopted {
                    destination: Ipv4Address::from_octets([192, 168, 42, 1]),
                    port: 8443,
                    generation: 2,
                },
            }),
            "LFW-PD time=2026-07-30T20:27:00.123456789Z domain=store state=ready \
             adopted-endpoint=192.168.42.1 adopted-port=8443 adopted-generation=2"
        );

        let mut digest = [0_u8; 32];
        for (at, byte) in digest.iter_mut().enumerate() {
            *byte = 0xff - at as u8;
        }
        assert_eq!(
            rendered(&Event::Domain {
                domain: Domain::Store,
                state: DomainState::Ready,
                detail: DomainDetail::AnchorFingerprint(digest),
            }),
            "LFW-PD time=2026-07-30T20:27:00.123456789Z domain=store state=ready \
             anchor-fingerprint=fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0"
        );
    }

    /// The record a factory reset leaves: what the appliance gave up, in the past
    /// tense, and nothing about what replaced it.
    #[test]
    fn a_store_domain_renders_what_a_factory_reset_destroyed() {
        let reset = |generation, documents, was_owned| {
            rendered(&Event::Domain {
                domain: Domain::Store,
                state: DomainState::Negotiated,
                detail: DomainDetail::Reset {
                    generation,
                    documents,
                    was_owned,
                },
            })
        };
        assert_eq!(
            reset(7, 3, true),
            "LFW-PD time=2026-07-30T20:27:00.123456789Z domain=store state=negotiated \
             cleared-generation=7 cleared-documents=3 was-owned=true"
        );
        // The medium that carried no record this build could read, and the widest
        // numbers the fields can hold.
        assert_eq!(
            reset(0, 0, false),
            "LFW-PD time=2026-07-30T20:27:00.123456789Z domain=store state=negotiated \
             cleared-generation=0 cleared-documents=0 was-owned=false"
        );
        assert_eq!(
            reset(u64::MAX, u64::MAX, true),
            "LFW-PD time=2026-07-30T20:27:00.123456789Z domain=store state=negotiated \
             cleared-generation=18446744073709551615 \
             cleared-documents=18446744073709551615 was-owned=true"
        );
    }

    /// The record a domain that holds no key leaves about the one that does: the
    /// appliance it signs for, how many signatures that holder has produced, and
    /// how many bytes of certificate it handed over. The identifier's rendering is
    /// the identity record's, character for character, which is what makes the two
    /// lines comparable at all.
    #[test]
    fn a_delegating_domain_renders_the_appliance_it_signs_for_and_the_holders_tally() {
        let delegated = |device, signatures, certificate| {
            rendered(&Event::Domain {
                domain: Domain::Crypto,
                state: DomainState::Negotiated,
                detail: DomainDetail::Delegated {
                    device,
                    signatures,
                    certificate,
                },
            })
        };
        assert_eq!(
            delegated(0x0123_4567_89ab_cdef_0123_4567_89ab_cdef, 1, 452),
            "LFW-PD time=2026-07-30T20:27:00.123456789Z domain=crypto state=negotiated \
             delegated-device=0123456789abcdef0123456789abcdef delegated-signatures=1 \
             delegated-certificate=452"
        );
        // A leading zero nibble survives, which is the whole reason the width is
        // fixed: an identifier rendered short is not this appliance's.
        assert_eq!(
            delegated(1, 0, 0),
            "LFW-PD time=2026-07-30T20:27:00.123456789Z domain=crypto state=negotiated \
             delegated-device=00000000000000000000000000000001 delegated-signatures=0 \
             delegated-certificate=0"
        );
        assert_eq!(
            delegated(u128::MAX, u64::MAX, u64::MAX),
            "LFW-PD time=2026-07-30T20:27:00.123456789Z domain=crypto state=negotiated \
             delegated-device=ffffffffffffffffffffffffffffffff \
             delegated-signatures=18446744073709551615 \
             delegated-certificate=18446744073709551615"
        );
    }

    /// The anchor the delegating domain was handed, in both readings: an
    /// appliance nobody has taken says so and carries no size, and an owned one
    /// carries the size of the authority its owner delivered.
    #[test]
    fn a_delegating_domain_renders_whether_it_was_handed_an_anchor() {
        let anchor = |delivered, anchor| {
            rendered(&Event::Domain {
                domain: Domain::Crypto,
                state: DomainState::Negotiated,
                detail: DomainDetail::DelegatedAnchor { delivered, anchor },
            })
        };
        assert_eq!(
            anchor(true, 398),
            "LFW-PD time=2026-07-30T20:27:00.123456789Z domain=crypto state=negotiated \
             delegated-anchor-delivered=true delegated-anchor=398"
        );
        // The un-onboarded reading, which is the ordinary state of an appliance
        // waiting for an owner rather than a failure of anything.
        assert_eq!(
            anchor(false, 0),
            "LFW-PD time=2026-07-30T20:27:00.123456789Z domain=crypto state=negotiated \
             delegated-anchor-delivered=false delegated-anchor=0"
        );
        assert_eq!(
            anchor(true, u64::MAX),
            "LFW-PD time=2026-07-30T20:27:00.123456789Z domain=crypto state=negotiated \
             delegated-anchor-delivered=true delegated-anchor=18446744073709551615"
        );
    }

    /// Where the domain holding the record told the dialling domain to go, in
    /// both readings — and the second is the one the flag exists for: an all-zero
    /// address is not somewhere, and the word beside it is what says so.
    #[test]
    fn a_store_domain_renders_where_it_told_the_channel_to_dial() {
        let published = |octets: [u8; 4], port, published| {
            rendered(&Event::Domain {
                domain: Domain::Store,
                state: DomainState::Ready,
                detail: DomainDetail::Published {
                    destination: Ipv4Address::from_octets(octets),
                    port,
                    published,
                },
            })
        };
        assert_eq!(
            published([10, 0, 2, 2], 8443, true),
            "LFW-PD time=2026-07-30T20:27:00.123456789Z domain=store state=ready \
             published-endpoint=10.0.2.2 published-port=8443 published=true"
        );
        assert_eq!(
            published([0, 0, 0, 0], 0, false),
            "LFW-PD time=2026-07-30T20:27:00.123456789Z domain=store state=ready \
             published-endpoint=0.0.0.0 published-port=0 published=false"
        );
        assert_eq!(
            published([255, 255, 255, 255], u16::MAX, true),
            "LFW-PD time=2026-07-30T20:27:00.123456789Z domain=store state=ready \
             published-endpoint=255.255.255.255 published-port=65535 published=true"
        );
    }

    /// The record the management port makes about one attempt on the channel it
    /// dials: where it went, which attempt it was, and how it stands — one line
    /// whichever way it went.
    #[test]
    fn a_management_domain_renders_where_it_dialled_and_how_that_ended() {
        let dialled = |octets: [u8; 4], port, attempts, outcome| {
            rendered(&Event::Domain {
                domain: Domain::Management,
                state: DomainState::Ready,
                detail: DomainDetail::Dialled {
                    destination: Ipv4Address::from_octets(octets),
                    port,
                    attempts,
                    outcome,
                },
            })
        };
        assert_eq!(
            dialled([10, 0, 2, 2], 4433, 1, DialOutcome::Established),
            "LFW-PD time=2026-07-30T20:27:00.123456789Z domain=management state=ready \
             dial-destination=10.0.2.2 dial-port=4433 dial-attempts=1 dial-outcome=established"
        );
        // The failure a station that never answered for the next hop leaves, and
        // the widest values the fields can hold.
        assert_eq!(
            dialled([10, 0, 2, 2], 4433, 3, DialOutcome::NextHopUnreachable),
            "LFW-PD time=2026-07-30T20:27:00.123456789Z domain=management state=ready \
             dial-destination=10.0.2.2 dial-port=4433 dial-attempts=3 \
             dial-outcome=next-hop-unreachable"
        );
        assert_eq!(
            dialled(
                [255, 255, 255, 255],
                u16::MAX,
                u64::MAX,
                DialOutcome::ConnectionLost
            ),
            "LFW-PD time=2026-07-30T20:27:00.123456789Z domain=management state=ready \
             dial-destination=255.255.255.255 dial-port=65535 \
             dial-attempts=18446744073709551615 dial-outcome=connection-lost"
        );
    }

    /// The three records a channel that did not come up adds after its outcome,
    /// and the fourth an unacceptable acknowledgement adds after those.
    ///
    /// One line each and every key prefixed `dial-`, so an operator picks the
    /// whole story of a channel out of a boot transcript by one prefix and reads
    /// it in the order the appliance found it out: where the frames went, what
    /// the link answered, what the connection did, and — where a peer claimed a
    /// number — which number.
    #[test]
    fn a_channel_that_failed_renders_the_counts_that_place_the_fault() {
        let reported = |detail| {
            rendered(&Event::Domain {
                domain: Domain::Management,
                state: DomainState::Ready,
                detail,
            })
        };
        assert_eq!(
            reported(DomainDetail::DialRoute {
                next_hop: Ipv4Address::from_octets([10, 0, 2, 2]),
                via: NextHopVia::Gateway,
                requests: 9,
                learned: 0,
            }),
            "LFW-PD time=2026-07-30T20:27:00.123456789Z domain=management state=ready \
             dial-next-hop=10.0.2.2 dial-next-hop-via=gateway dial-requests=9 dial-learned=0"
        );
        // The same three requests answered by a station holding the address, so
        // the difference between this line and the one above is the whole of
        // what `next-hop-unreachable` means.
        assert_eq!(
            reported(DomainDetail::DialRoute {
                next_hop: Ipv4Address::from_octets([10, 0, 2, 99]),
                via: NextHopVia::Prefix,
                requests: 3,
                learned: 1,
            }),
            "LFW-PD time=2026-07-30T20:27:00.123456789Z domain=management state=ready \
             dial-next-hop=10.0.2.99 dial-next-hop-via=prefix dial-requests=3 dial-learned=1"
        );
        assert_eq!(
            reported(DomainDetail::DialUnlearned {
                unsolicited: 9,
                rebinding: 0,
                not_unicast: 0,
                contradicted: 1,
            }),
            "LFW-PD time=2026-07-30T20:27:00.123456789Z domain=management state=ready \
             dial-reply-unsolicited=9 dial-reply-rebinding=0 dial-reply-not-unicast=0 \
             dial-reply-contradicted=1"
        );
        assert_eq!(
            reported(DomainDetail::DialSegments {
                syns: 15,
                resets_received: 0,
                resets_sent: 15,
                answered: true,
            }),
            "LFW-PD time=2026-07-30T20:27:00.123456789Z domain=management state=ready \
             dial-syns=15 dial-resets-received=0 dial-resets-sent=15 dial-answered=true"
        );
        assert_eq!(
            reported(DomainDetail::DialSegments {
                syns: 15,
                resets_received: 0,
                resets_sent: 0,
                answered: false,
            }),
            "LFW-PD time=2026-07-30T20:27:00.123456789Z domain=management state=ready \
             dial-syns=15 dial-resets-received=0 dial-resets-sent=0 dial-answered=false"
        );
        // Decimal, and both numbers whole: an operator compares them against a
        // capture of the same exchange digit for digit.
        assert_eq!(
            reported(DomainDetail::DialSequence {
                claimed: 3_735_928_559,
                expected: 1,
            }),
            "LFW-PD time=2026-07-30T20:27:00.123456789Z domain=management state=ready \
             dial-acknowledged=3735928559 dial-expected=1"
        );
    }

    /// The two records the cryptography domain makes about a primitive: what
    /// it proved and what it cost. The name is the vocabulary's own, so a
    /// primitive renamed there moves both lines rather than one.
    #[test]
    fn a_cryptography_domain_renders_a_primitive_it_proved_and_what_it_cost() {
        assert_eq!(
            rendered(&Event::Domain {
                domain: Domain::Crypto,
                state: DomainState::Negotiated,
                detail: DomainDetail::Proved {
                    primitive: Primitive::Aes256Gcm,
                    vectors: 22,
                },
            }),
            "LFW-PD time=2026-07-30T20:27:00.123456789Z domain=crypto state=negotiated \
             primitive=aes-256-gcm vectors=22"
        );
        assert_eq!(
            rendered(&Event::Domain {
                domain: Domain::Crypto,
                state: DomainState::Negotiated,
                detail: DomainDetail::Measured {
                    primitive: Primitive::Sha256,
                    milli_cycles_per_byte: u64::MAX,
                },
            }),
            "LFW-PD time=2026-07-30T20:27:00.123456789Z domain=crypto state=negotiated \
             primitive=sha-256 milli-cycles-per-byte=18446744073709551615"
        );
    }

    #[test]
    fn a_refusal_renders_its_cause_what_the_device_was_left_in_and_its_numbers() {
        let refusal = |detail| {
            rendered(&Event::Domain {
                domain: Domain::NicDriver,
                state: DomainState::Refused,
                detail: DomainDetail::Refusal(Refusal {
                    cause: "not-virtio-net",
                    detail,
                    signalled: false,
                }),
            })
        };
        assert_eq!(
            refusal(RefusalDetail::Two(0x1af4, 0x1000)),
            "LFW-PD time=2026-07-30T20:27:00.123456789Z domain=nic-driver state=refused cause=not-virtio-net signalled=false \
             detail=0x1af4,0x1000"
        );
        assert_eq!(
            refusal(RefusalDetail::One(0x31000000)),
            "LFW-PD time=2026-07-30T20:27:00.123456789Z domain=nic-driver state=refused cause=not-virtio-net signalled=false \
             detail=0x31000000"
        );
        assert_eq!(
            refusal(RefusalDetail::None),
            "LFW-PD time=2026-07-30T20:27:00.123456789Z domain=nic-driver state=refused cause=not-virtio-net signalled=false"
        );
    }

    /// A cause that names nothing takes its key with it. The record ABI admits
    /// the empty token deliberately, so a byzantine writing domain can publish
    /// one — and a key with nothing after it is the one shape a reader looking a
    /// key up cannot tell from a key whose value happens to be missing.
    #[test]
    fn a_refusal_naming_no_cause_omits_the_key_rather_than_writing_it_empty() {
        let line = |cause: Cause, detail| {
            rendered_cause(
                AT,
                &Event::Domain {
                    domain: Domain::Recorder,
                    state: DomainState::Refused,
                    detail: DomainDetail::Refusal(Refusal {
                        cause,
                        detail,
                        signalled: true,
                    }),
                },
            )
        };
        assert_eq!(
            line(Cause::EMPTY, RefusalDetail::None),
            "LFW-PD time=2026-07-30T20:27:00.123456789Z domain=recorder state=refused \
             signalled=true"
        );
        // The fields after it are unmoved, so omitting one does not shift a
        // reader's handle on the rest.
        assert_eq!(
            line(Cause::EMPTY, RefusalDetail::Two(1, 2)),
            "LFW-PD time=2026-07-30T20:27:00.123456789Z domain=recorder state=refused \
             signalled=true detail=0x1,0x2"
        );
        let named = Cause::new(b"extent-unusable").expect("the token is in the alphabet");
        assert_eq!(
            line(named, RefusalDetail::None),
            "LFW-PD time=2026-07-30T20:27:00.123456789Z domain=recorder state=refused \
             cause=extent-unusable signalled=true"
        );
    }

    /// The field an operator acts on first: whether the device is still
    /// decoding and mastering the bus.
    #[test]
    fn a_signalled_refusal_and_an_unsignalled_one_do_not_read_alike() {
        let line = |signalled| {
            rendered(&Event::Domain {
                domain: Domain::NicDriver,
                state: DomainState::Refused,
                detail: DomainDetail::Refusal(Refusal {
                    cause: "reset-not-acknowledged",
                    detail: RefusalDetail::One(0x0f),
                    signalled,
                }),
            })
        };
        assert!(line(true).contains("signalled=true"));
        assert!(line(false).contains("signalled=false"));
        assert_ne!(line(true), line(false));
    }

    #[test]
    fn a_modification_renders_both_ends_of_the_change() {
        assert_eq!(
            rendered(&change(
                Some(Value::PrefixLength(24)),
                Some(Value::PrefixLength(25)),
            )),
            "LFW-CFG time=2026-07-30T20:27:00.123456789Z generation=4 seq=2 change=modified object=interface key=wan \
             field=prefix-length from=24 to=25"
        );
    }

    #[test]
    fn an_addition_omits_from_and_a_removal_omits_to() {
        assert_eq!(
            rendered(&change(None, Some(Value::PrefixLength(25)))),
            "LFW-CFG time=2026-07-30T20:27:00.123456789Z generation=4 seq=2 change=modified object=interface key=wan \
             field=prefix-length to=25"
        );
        assert_eq!(
            rendered(&change(Some(Value::PrefixLength(24)), None)),
            "LFW-CFG time=2026-07-30T20:27:00.123456789Z generation=4 seq=2 change=modified object=interface key=wan \
             field=prefix-length from=24"
        );
    }

    #[test]
    fn a_record_with_neither_end_renders_the_key_and_stops() {
        assert_eq!(
            rendered(&change(None, None)),
            "LFW-CFG time=2026-07-30T20:27:00.123456789Z generation=4 seq=2 change=modified object=interface key=wan \
             field=prefix-length"
        );
    }

    #[test]
    fn an_added_neighbour_renders_the_value_types_it_carries() {
        let event = Event::ConfigChange {
            generation: 1,
            sequence: 0,
            change: ChangeKind::Added,
            object: ObjectKind::Neighbour,
            key: id("gateway-a"),
            field: Field::Mac,
            from: None,
            to: Some(Value::Mac(MacAddress([0x52, 0x54, 0, 0, 0, 0x0a]))),
        };
        assert_eq!(
            rendered(&event),
            "LFW-CFG time=2026-07-30T20:27:00.123456789Z generation=1 seq=0 change=added object=neighbour key=gateway-a \
             field=mac to=52:54:00:00:00:0a"
        );
    }

    #[test]
    fn a_removed_interface_renders_the_address_it_held() {
        let event = Event::ConfigChange {
            generation: 9,
            sequence: 3,
            change: ChangeKind::Removed,
            object: ObjectKind::Interface,
            key: id("lan"),
            field: Field::Address,
            from: Some(Value::Ipv4(Ipv4Address::from_octets([10, 0, 1, 1]))),
            to: None,
        };
        assert_eq!(
            rendered(&event),
            "LFW-CFG time=2026-07-30T20:27:00.123456789Z generation=9 seq=3 change=removed object=interface key=lan \
             field=address from=10.0.1.1"
        );
    }

    #[test]
    fn a_generation_outcome_renders_its_change_count() {
        // Every token in the vocabulary rather than a chosen few: the three the
        // management channel's stepped path produces render on the same line as
        // the three a one-step submission does, and a token that rendered as
        // another would be an operator reading the wrong outcome for a generation.
        for outcome in GenerationOutcome::ALL {
            let token = outcome.name();
            assert_eq!(
                rendered(&Event::ConfigGeneration {
                    generation: 0,
                    outcome,
                    changes: 0,
                }),
                std::format!(
                    "LFW-CFG time=2026-07-30T20:27:00.123456789Z \
                     generation=0 outcome={token} changes=0"
                )
            );
        }
        assert_eq!(GenerationOutcome::ALL.len(), 6);
    }

    #[test]
    fn a_rejection_renders_a_location_and_never_the_document() {
        assert_eq!(
            rendered(&Event::ConfigRejected {
                generation: 2,
                reason: RejectReason::Doctype,
                offset: 38,
            }),
            "LFW-CFG time=2026-07-30T20:27:00.123456789Z generation=2 rejected=doctype offset=38"
        );
    }

    #[test]
    fn every_reject_reason_renders_into_a_line_of_its_own() {
        let mut lines: Vec<String> = RejectReason::ALL
            .iter()
            .map(|&reason| {
                rendered(&Event::ConfigRejected {
                    generation: 1,
                    reason,
                    offset: 0,
                })
            })
            .collect();
        let count = lines.len();
        lines.sort();
        lines.dedup();
        assert_eq!(lines.len(), count, "two reasons render identically");
    }

    #[test]
    fn a_buffer_one_byte_short_is_refused_rather_than_truncated() {
        let event = change(Some(Value::PrefixLength(24)), Some(Value::PrefixLength(25)));
        let exact = rendered(&event).len();
        let mut just_enough = vec![0u8; exact];
        assert_eq!(render(AT, &event, &mut just_enough), Ok(exact));

        for size in 0..exact {
            let mut short = vec![0u8; size];
            assert_eq!(
                render(AT, &event, &mut short),
                Err(RenderError::BufferTooSmall),
                "a {size}-byte buffer should be refused"
            );
        }
    }

    #[test]
    fn a_refusal_reads_as_a_capacity_problem() {
        assert_eq!(
            std::format!("{}", RenderError::BufferTooSmall),
            "the buffer is too small for the rendered line"
        );
    }

    /// The widest line each shape can produce: every numeric field at its
    /// maximum, the widest vocabulary token, a full-length key, and the widest
    /// [`Value`] on both ends.
    #[test]
    fn the_widest_line_of_each_shape_fits_the_maximum() {
        let widest_key = id(&"a".repeat(MAX_IDENTIFIER_LEN));
        // Leaked because a `cause` is a `&'static str` by construction and this
        // is a host test with an allocator; nothing in a protection domain
        // reaches this path.
        let widest_cause: &'static String = Box::leak(Box::new("a".repeat(MAX_CAUSE_LEN)));
        let widest_value = Value::Mac(MacAddress([0xff; 6]));
        let widest_reason = RejectReason::ALL
            .into_iter()
            .max_by_key(|reason| reason.name().len())
            .expect("the vocabulary is not empty");
        let shapes = [
            Event::Domain {
                domain: Domain::NicDriver,
                state: DomainState::Negotiated,
                detail: DomainDetail::Refusal(Refusal {
                    cause: widest_cause.as_str(),
                    detail: RefusalDetail::Two(u64::MAX, u64::MAX),
                    signalled: false,
                }),
            },
            Event::ConfigChange {
                generation: u32::MAX,
                sequence: u32::MAX,
                change: ChangeKind::Modified,
                object: ObjectKind::Neighbour,
                key: widest_key,
                field: Field::PrefixLength,
                from: Some(widest_value),
                to: Some(widest_value),
            },
            Event::ConfigGeneration {
                generation: u32::MAX,
                outcome: GenerationOutcome::Unchanged,
                changes: u32::MAX,
            },
            Event::ConfigRejected {
                generation: u32::MAX,
                reason: widest_reason,
                offset: u32::MAX,
            },
        ];
        // The curated widest of each *shape*, and every shape the vocabularies
        // can spell beside them. Both, because neither reaches the other's
        // widest line: the curated set holds the widest value of every field,
        // and the enumeration holds the widest domain and state to put in front
        // of one — and the widest line this grammar has is a detail from the
        // first under a name from the second.
        for shape in shapes.iter().chain(every_shape().iter()) {
            let mut buffer = [0u8; MAX_LINE_LEN];
            let written = render(AT, shape, &mut buffer);
            assert!(
                matches!(written, Ok(len) if len <= MAX_LINE_LEN),
                "{shape:?} did not fit MAX_LINE_LEN"
            );
        }
    }

    #[test]
    fn every_line_carries_the_prefix_a_reader_keys_on() {
        for shape in every_shape() {
            let line = rendered(&shape);
            assert!(line.starts_with("LFW-"), "{line}");
            assert!(!line.contains('\n'), "{line}");
        }
    }

    fn any_detail() -> impl Strategy<Value = DomainDetail> {
        // A generated cause is one of a fixed set of literals rather than an
        // arbitrary string: `cause` is a `&'static str`, which is exactly the
        // property that keeps generated bytes out of it.
        let causes = ["", "a", "not-virtio-net", "queue-setup-queue-too-small"];
        prop_oneof![
            Just(DomainDetail::None),
            any::<u64>().prop_map(DomainDetail::Features),
            any::<u32>().prop_map(DomainDetail::ReceivePosted),
            (1..=u64::MAX, any::<u64>()).prop_map(|(hz, nanos)| established(hz, nanos)),
            any::<(u64, u64)>()
                .prop_map(|(frames, bytes)| DomainDetail::Received { frames, bytes }),
            any::<(u64, u64)>().prop_map(|(capacity_sectors, leading_word)| {
                DomainDetail::Medium {
                    capacity_sectors,
                    leading_word,
                }
            }),
            any::<(u64, u64)>().prop_map(|(start_sector, sectors)| DomainDetail::Extent {
                start_sector,
                sectors,
            }),
            any::<(u64, u64, u64, u64)>().prop_map(
                |(start_sector, generation, sequence, opened)| DomainDetail::RecordingResumed {
                    start_sector,
                    generation,
                    sequence,
                    opened,
                },
            ),
            any::<(u64, bool)>().prop_map(|(start_sector, rebound)| DomainDetail::RecordingFresh {
                start_sector,
                rebound,
            }),
            any::<(u64, u64)>().prop_map(|(preemptions, iterations)| DomainDetail::Proven {
                preemptions,
                iterations,
            }),
            (0..Primitive::ALL.len(), any::<u64>()).prop_map(|(at, vectors)| {
                DomainDetail::Proved {
                    primitive: Primitive::ALL[at],
                    vectors,
                }
            }),
            (0..Primitive::ALL.len(), any::<u64>()).prop_map(|(at, cost)| {
                DomainDetail::Measured {
                    primitive: Primitive::ALL[at],
                    milli_cycles_per_byte: cost,
                }
            }),
            any::<(u16, u16)>()
                .prop_map(|(version, suite)| DomainDetail::Session { version, suite }),
            any::<(u16, u64)>()
                .prop_map(|(group, echoed)| DomainDetail::Exchange { group, echoed }),
            any::<u128>().prop_map(|device| DomainDetail::Peer { device }),
            any::<(u64, u64)>().prop_map(|(bytes, bound)| DomainDetail::Arena { bytes, bound }),
            (0..Primitive::ALL.len(), any::<u64>()).prop_map(|(at, cycles)| {
                DomainDetail::Operation {
                    primitive: Primitive::ALL[at],
                    cycles,
                }
            }),
            any::<(u128, u64, bool)>().prop_map(|(device, generation, onboarded)| {
                DomainDetail::Identity {
                    device,
                    generation,
                    onboarded,
                }
            }),
            any::<[u8; 32]>().prop_map(DomainDetail::Fingerprint),
            any::<[u8; 32]>().prop_map(DomainDetail::AnchorFingerprint),
            any::<([u8; 4], u16, u64)>().prop_map(|(octets, port, generation)| {
                DomainDetail::Adopted {
                    destination: Ipv4Address::from_octets(octets),
                    port,
                    generation,
                }
            }),
            any::<(u64, u64, bool)>().prop_map(|(generation, documents, was_owned)| {
                DomainDetail::Reset {
                    generation,
                    documents,
                    was_owned,
                }
            }),
            (any::<([u8; 4], u16, u64)>(), (0..DialOutcome::ALL.len()),).prop_map(
                |((octets, port, attempts), outcome)| DomainDetail::Dialled {
                    destination: Ipv4Address::from_octets(octets),
                    port,
                    attempts,
                    outcome: DialOutcome::ALL[outcome],
                }
            ),
            any::<(u128, u64, u64)>().prop_map(|(device, signatures, certificate)| {
                DomainDetail::Delegated {
                    device,
                    signatures,
                    certificate,
                }
            }),
            (any::<([u8; 4], u64, u64)>(), (0..NextHopVia::ALL.len()),).prop_map(
                |((octets, requests, learned), via)| DomainDetail::DialRoute {
                    next_hop: Ipv4Address::from_octets(octets),
                    via: NextHopVia::ALL[via],
                    requests,
                    learned,
                }
            ),
            any::<(u64, u64, u64, u64)>().prop_map(
                |(unsolicited, rebinding, not_unicast, contradicted)| {
                    DomainDetail::DialUnlearned {
                        unsolicited,
                        rebinding,
                        not_unicast,
                        contradicted,
                    }
                }
            ),
            any::<(u64, u64, u64, bool)>().prop_map(
                |(syns, resets_received, resets_sent, answered)| DomainDetail::DialSegments {
                    syns,
                    resets_received,
                    resets_sent,
                    answered,
                }
            ),
            any::<(u32, u32)>()
                .prop_map(|(claimed, expected)| DomainDetail::DialSequence { claimed, expected }),
            any::<(u64, u64)>().prop_map(|(delay_millis, bound_millis)| DomainDetail::DialRetry {
                delay_millis,
                bound_millis,
            }),
            (0..ChannelOutcome::ALL.len(), any::<(u16, u16, u16)>(),).prop_map(
                |(outcome, (version, suite, group))| DomainDetail::ChannelHandshake {
                    outcome: ChannelOutcome::ALL[outcome],
                    version,
                    suite,
                    group,
                }
            ),
            (0..ChannelOutcome::ALL.len()).prop_map(|outcome| DomainDetail::ChannelEnded {
                outcome: ChannelOutcome::ALL[outcome],
            }),
            (0..ChannelOutcome::ALL.len(), 0..TlsIncompatible::ALL.len()).prop_map(
                |(outcome, incompatible)| DomainDetail::ChannelIncompatible {
                    outcome: ChannelOutcome::ALL[outcome],
                    incompatible: TlsIncompatible::ALL[incompatible],
                }
            ),
            (0..ChannelOutcome::ALL.len(), 0..TlsRefusal::ALL.len()).prop_map(
                |(outcome, refusal)| DomainDetail::ChannelRefused {
                    outcome: ChannelOutcome::ALL[outcome],
                    refusal: TlsRefusal::ALL[refusal],
                }
            ),
            (
                0..ChannelOutcome::ALL.len(),
                0..TlsCertificateRefusal::ALL.len()
            )
                .prop_map(|(outcome, refusal)| DomainDetail::ChannelCertificate {
                    outcome: ChannelOutcome::ALL[outcome],
                    refusal: TlsCertificateRefusal::ALL[refusal],
                }),
            (0..ChannelOutcome::ALL.len(), any::<u16>()).prop_map(|(outcome, alert)| {
                DomainDetail::ChannelAlert {
                    outcome: ChannelOutcome::ALL[outcome],
                    alert,
                }
            }),
            (0..ChannelOutcome::ALL.len(), any::<u64>()).prop_map(|(outcome, held)| {
                DomainDetail::ChannelBacklogged {
                    outcome: ChannelOutcome::ALL[outcome],
                    held,
                }
            }),
            any::<(bool, u16, u64, u64)>().prop_map(|(agreed, version, sent, received)| {
                DomainDetail::ChannelFrames {
                    agreed,
                    version,
                    sent,
                    received,
                }
            }),
            any::<(u64, u64, u64, u64)>().prop_map(
                |(log_position, log_pending, capture_position, capture_pending)| {
                    DomainDetail::ChannelShipping {
                        log_position,
                        log_pending,
                        capture_position,
                        capture_pending,
                    }
                },
            ),
            (any::<(u64, u8, u64)>(), any::<bool>()).prop_map(
                |((generation, slot, bytes), restored)| DomainDetail::Configured {
                    generation,
                    slot,
                    bytes,
                    restored,
                },
            ),
            (any::<(u64, u64, u64)>(), (0..OnboardEnd::ALL.len())).prop_map(
                |((relayed, received, sent), ended)| DomainDetail::Onboarded {
                    relayed,
                    received,
                    sent,
                    ended: OnboardEnd::ALL[ended],
                }
            ),
            any::<(u64, u64, u64, u64)>().prop_map(|(accepted, forgotten, overflowed, refused)| {
                DomainDetail::OnboardingPort {
                    accepted,
                    forgotten,
                    overflowed,
                    refused,
                }
            }),
            ((0..OnboardOutcome::ALL.len()), any::<(u16, u16, u16)>(),).prop_map(
                |(outcome, (version, suite, group))| {
                    DomainDetail::OnboardingHandshake {
                        outcome: OnboardOutcome::ALL[outcome],
                        version,
                        suite,
                        group,
                    }
                }
            ),
            (0..OnboardOutcome::ALL.len()).prop_map(|outcome| DomainDetail::OnboardingEnded {
                outcome: OnboardOutcome::ALL[outcome],
            }),
            (
                (0..OnboardOutcome::ALL.len()),
                (0..TlsIncompatible::ALL.len()),
            )
                .prop_map(|(outcome, incompatible)| {
                    DomainDetail::OnboardingIncompatible {
                        outcome: OnboardOutcome::ALL[outcome],
                        incompatible: TlsIncompatible::ALL[incompatible],
                    }
                }),
            ((0..OnboardOutcome::ALL.len()), (0..TlsRefusal::ALL.len()),).prop_map(
                |(outcome, refusal)| DomainDetail::OnboardingRefused {
                    outcome: OnboardOutcome::ALL[outcome],
                    refusal: TlsRefusal::ALL[refusal],
                }
            ),
            ((0..OnboardOutcome::ALL.len()), any::<u16>()).prop_map(|(outcome, alert)| {
                DomainDetail::OnboardingAlert {
                    outcome: OnboardOutcome::ALL[outcome],
                    alert,
                }
            }),
            ((0..OnboardOutcome::ALL.len()), any::<u64>()).prop_map(|(outcome, held)| {
                DomainDetail::OnboardingBacklogged {
                    outcome: OnboardOutcome::ALL[outcome],
                    held,
                }
            }),
            any::<([u16; crate::MAX_OFFERED_POINTS], u16)>().prop_map(|(points, offered)| {
                DomainDetail::OnboardingSuites { points, offered }
            }),
            any::<([u16; crate::MAX_OFFERED_POINTS], u16)>().prop_map(|(points, offered)| {
                DomainDetail::OnboardingGroups { points, offered }
            }),
            ((0..OnboardRoute::ALL.len()), any::<u64>()).prop_map(|(route, bytes)| {
                DomainDetail::OnboardingServed {
                    route: OnboardRoute::ALL[route],
                    bytes,
                }
            }),
            ((0..OnboardRefusal::ALL.len()), any::<(u16, u64)>()).prop_map(
                |(refusal, (status, held))| DomainDetail::OnboardingRequest {
                    refusal: OnboardRefusal::ALL[refusal],
                    status,
                    held,
                }
            ),
            any::<(u64, u64)>().prop_map(|(strikes, wait_millis)| {
                DomainDetail::OnboardingThrottled {
                    strikes,
                    wait_millis,
                }
            }),
            (
                (0..causes.len()),
                prop_oneof![
                    Just(RefusalDetail::None),
                    any::<u64>().prop_map(RefusalDetail::One),
                    any::<(u64, u64)>().prop_map(|(a, b)| RefusalDetail::Two(a, b)),
                ],
                any::<bool>(),
            )
                .prop_map(move |(index, detail, signalled)| DomainDetail::Refusal(
                    Refusal {
                        cause: causes[index],
                        detail,
                        signalled,
                    }
                )),
        ]
    }

    /// Both cases of the stamp, and every instant a `u64` of nanoseconds names:
    /// the widest instant must fit the same line the narrowest does.
    fn any_stamp() -> impl Strategy<Value = Stamp> {
        prop_oneof![
            Just(Stamp::Unsynchronized),
            any::<u64>().prop_map(|nanos| Stamp::Utc(lfw_clock::UtcNanos::from_unix_nanos(nanos))),
        ]
    }

    fn any_identifier() -> impl Strategy<Value = Identifier> {
        "[a-z0-9-]{1,16}"
            .prop_map(|text| Identifier::new(text.as_bytes()).expect("the pattern is the alphabet"))
    }

    fn any_value() -> impl Strategy<Value = Value> {
        prop_oneof![
            any::<u8>().prop_map(Value::Port),
            any::<[u8; 4]>().prop_map(|octets| Value::Ipv4(Ipv4Address::from_octets(octets))),
            any::<[u8; 6]>().prop_map(|octets| Value::Mac(MacAddress(octets))),
            any::<u8>().prop_map(Value::PrefixLength),
            any::<bool>().prop_map(Value::Bool),
            any::<u32>().prop_map(Value::Generation),
            any::<u32>().prop_map(Value::Count),
            any_identifier().prop_map(Value::Id),
        ]
    }

    fn pick<T: Copy + core::fmt::Debug, const N: usize>(
        all: [T; N],
    ) -> impl Strategy<Value = T> + Clone {
        (0..N).prop_map(move |index| all[index])
    }

    fn any_event() -> impl Strategy<Value = Event> {
        prop_oneof![
            (pick(Domain::ALL), pick(DomainState::ALL), any_detail()).prop_map(
                |(domain, state, detail)| Event::Domain {
                    domain,
                    state,
                    detail,
                }
            ),
            (
                any::<u32>(),
                any::<u32>(),
                pick(ChangeKind::ALL),
                pick(ObjectKind::ALL),
                any_identifier(),
                pick(Field::ALL),
                proptest::option::of(any_value()),
                proptest::option::of(any_value()),
            )
                .prop_map(
                    |(generation, sequence, change, object, key, field, from, to)| {
                        Event::ConfigChange {
                            generation,
                            sequence,
                            change,
                            object,
                            key,
                            field,
                            from,
                            to,
                        }
                    }
                ),
            (any::<u32>(), pick(GenerationOutcome::ALL), any::<u32>()).prop_map(
                |(generation, outcome, changes)| Event::ConfigGeneration {
                    generation,
                    outcome,
                    changes,
                }
            ),
            (any::<u32>(), pick(RejectReason::ALL), any::<u32>()).prop_map(
                |(generation, reason, offset)| Event::ConfigRejected {
                    generation,
                    reason,
                    offset,
                }
            ),
        ]
    }

    proptest! {
        /// Bounded work and bounded output: whatever an event carries, the line
        /// fits the advertised maximum and is the ASCII a console can print.
        #[test]
        fn every_event_fits_the_advertised_maximum(event in any_event(), at in any_stamp()) {
            let mut buffer = [0u8; MAX_LINE_LEN];
            let written = render(at, &event, &mut buffer).expect("MAX_LINE_LEN holds every line");
            prop_assert!(written <= MAX_LINE_LEN);
            let line = core::str::from_utf8(&buffer[..written]).expect("the grammar is ASCII");
            prop_assert!(line.starts_with("LFW-"));
            prop_assert!(line.is_ascii());
        }

        /// Total over buffer size: every size either yields a line that fits it
        /// or a typed refusal, and never a partial line reported as whole.
        #[test]
        fn any_buffer_size_yields_a_line_or_a_refusal(
            event in any_event(),
            at in any_stamp(),
            size in 0usize..=MAX_LINE_LEN,
        ) {
            let reference = rendered_at(at, &event);
            let mut buffer = vec![0u8; size];
            match render(at, &event, &mut buffer) {
                Ok(written) => {
                    prop_assert!(written <= size);
                    prop_assert_eq!(&buffer[..written], reference.as_bytes());
                }
                Err(RenderError::BufferTooSmall) => prop_assert!(size < reference.len()),
            }
        }
    }
}
