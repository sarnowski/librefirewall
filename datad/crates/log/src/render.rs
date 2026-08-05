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
pub const MAX_LINE_LEN: usize = 228;

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
        DomainDetail::Delegated { device, signatures } => write!(
            cursor,
            " delegated-device={device:032x} delegated-signatures={signatures}"
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
        ChangeKind, Domain, DomainState, Field, GenerationOutcome, ObjectKind, RejectReason, Value,
    };
    use crate::identifier::{Identifier, MAX_IDENTIFIER_LEN};
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
    /// appliance it signs for, and how many signatures that holder has produced.
    /// The identifier's rendering is the identity record's, character for
    /// character, which is what makes the two lines comparable at all.
    #[test]
    fn a_delegating_domain_renders_the_appliance_it_signs_for_and_the_holders_tally() {
        let delegated = |device, signatures| {
            rendered(&Event::Domain {
                domain: Domain::Crypto,
                state: DomainState::Negotiated,
                detail: DomainDetail::Delegated { device, signatures },
            })
        };
        assert_eq!(
            delegated(0x0123_4567_89ab_cdef_0123_4567_89ab_cdef, 1),
            "LFW-PD time=2026-07-30T20:27:00.123456789Z domain=crypto state=negotiated \
             delegated-device=0123456789abcdef0123456789abcdef delegated-signatures=1"
        );
        // A leading zero nibble survives, which is the whole reason the width is
        // fixed: an identifier rendered short is not this appliance's.
        assert_eq!(
            delegated(1, 0),
            "LFW-PD time=2026-07-30T20:27:00.123456789Z domain=crypto state=negotiated \
             delegated-device=00000000000000000000000000000001 delegated-signatures=0"
        );
        assert_eq!(
            delegated(u128::MAX, u64::MAX),
            "LFW-PD time=2026-07-30T20:27:00.123456789Z domain=crypto state=negotiated \
             delegated-device=ffffffffffffffffffffffffffffffff \
             delegated-signatures=18446744073709551615"
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
        for (outcome, token) in [
            (GenerationOutcome::Applied, "applied"),
            (GenerationOutcome::Refused, "refused"),
            (GenerationOutcome::Unchanged, "unchanged"),
        ] {
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
        for shape in shapes {
            let mut buffer = [0u8; MAX_LINE_LEN];
            let written = render(AT, &shape, &mut buffer);
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

    fn every_shape() -> Vec<Event> {
        let key = id("wan");
        let mut shapes = Vec::new();
        for domain in Domain::ALL {
            for state in DomainState::ALL {
                for detail in every_detail() {
                    shapes.push(Event::Domain {
                        domain,
                        state,
                        detail,
                    });
                }
            }
        }
        for change in ChangeKind::ALL {
            for object in ObjectKind::ALL {
                for field in Field::ALL {
                    shapes.push(Event::ConfigChange {
                        generation: 1,
                        sequence: 0,
                        change,
                        object,
                        key,
                        field,
                        from: Some(Value::Count(1)),
                        to: Some(Value::Bool(false)),
                    });
                }
            }
        }
        for outcome in GenerationOutcome::ALL {
            shapes.push(Event::ConfigGeneration {
                generation: 1,
                outcome,
                changes: 0,
            });
        }
        for reason in RejectReason::ALL {
            shapes.push(Event::ConfigRejected {
                generation: 1,
                reason,
                offset: 0,
            });
        }
        shapes
    }

    /// One of every payload shape, the refusal in each of its three widths.
    fn every_detail() -> Vec<DomainDetail> {
        let mut details = vec![
            DomainDetail::None,
            DomainDetail::Features(u64::MAX),
            DomainDetail::ReceivePosted(u32::MAX),
            established(u64::MAX, u64::MAX),
            DomainDetail::Received {
                frames: u64::MAX,
                bytes: u64::MAX,
            },
            DomainDetail::Medium {
                capacity_sectors: u64::MAX,
                leading_word: u64::MAX,
            },
            DomainDetail::Extent {
                start_sector: u64::MAX,
                sectors: u64::MAX,
            },
            DomainDetail::Proven {
                preemptions: u64::MAX,
                iterations: u64::MAX,
            },
            DomainDetail::Proved {
                primitive: Primitive::ChaCha20Poly1305,
                vectors: u64::MAX,
            },
            DomainDetail::Measured {
                primitive: Primitive::ChaCha20Poly1305,
                milli_cycles_per_byte: u64::MAX,
            },
            DomainDetail::Session {
                version: u16::MAX,
                suite: u16::MAX,
            },
            DomainDetail::Exchange {
                group: u16::MAX,
                echoed: u64::MAX,
            },
            DomainDetail::Peer { device: u128::MAX },
            DomainDetail::Arena {
                bytes: u64::MAX,
                bound: u64::MAX,
            },
            DomainDetail::Operation {
                primitive: Primitive::EcdsaP256,
                cycles: u64::MAX,
            },
            DomainDetail::Identity {
                device: u128::MAX,
                generation: u64::MAX,
                onboarded: false,
            },
            DomainDetail::Identity {
                device: u128::MAX,
                generation: u64::MAX,
                onboarded: true,
            },
            DomainDetail::Fingerprint([0xff; 32]),
            DomainDetail::Reset {
                generation: u64::MAX,
                documents: u64::MAX,
                was_owned: false,
            },
            DomainDetail::Reset {
                generation: u64::MAX,
                documents: u64::MAX,
                was_owned: true,
            },
            DomainDetail::Delegated {
                device: u128::MAX,
                signatures: u64::MAX,
            },
        ];
        for detail in [
            RefusalDetail::None,
            RefusalDetail::One(1),
            RefusalDetail::Two(1, 2),
        ] {
            for signalled in [false, true] {
                details.push(DomainDetail::Refusal(Refusal {
                    cause: "pool-dma-base-unusable",
                    detail,
                    signalled,
                }));
            }
        }
        details
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
            any::<(u64, u64, bool)>().prop_map(|(generation, documents, was_owned)| {
                DomainDetail::Reset {
                    generation,
                    documents,
                    was_owned,
                }
            }),
            any::<(u128, u64)>()
                .prop_map(|(device, signatures)| DomainDetail::Delegated { device, signatures }),
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
