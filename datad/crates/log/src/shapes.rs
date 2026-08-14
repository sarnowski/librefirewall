//! One of every console shape, enumerated once for the two test modules that need
//! it: the renderer's, which asserts each one puts a line on the console, and the
//! record ABI's, which asserts each one survives the conversion a sink performs.
//!
//! It exists because the enumeration is the expensive part and a second copy of it
//! is a second thing to forget a variant in — which for a closed vocabulary means a
//! shape neither module ever drives.

use std::vec::Vec;

use net_headers::Ipv4Address;

use crate::{
    ChangeKind, ChannelOutcome, DialOutcome, Domain, DomainDetail, DomainState, Event, Field,
    GenerationOutcome, Identifier, NextHopVia, ObjectKind, OnboardEnd, OnboardOutcome,
    OnboardRefusal, OnboardRoute, Primitive, Refusal, RefusalDetail, RejectReason,
    TlsCertificateRefusal, TlsIncompatible, TlsRefusal, Value,
};

/// A clock the appliance established, as the two words it publishes.
fn established(tsc_hz: u64, unix_nanos: u64) -> DomainDetail {
    DomainDetail::Established {
        tsc_hz: core::num::NonZeroU64::new(tsc_hz).expect("a frequency above zero"),
        utc: lfw_clock::UtcNanos::from_unix_nanos(unix_nanos),
    }
}

fn id(text: &str) -> Identifier {
    Identifier::new(text.as_bytes()).expect("the alphabet accepts it")
}

pub(crate) fn every_shape() -> Vec<Event> {
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
pub(crate) fn every_detail() -> Vec<DomainDetail> {
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
        DomainDetail::RecordingResumed {
            start_sector: u64::MAX,
            generation: u64::MAX,
            sequence: u64::MAX,
            opened: u64::MAX,
        },
        DomainDetail::RecordingFresh {
            start_sector: u64::MAX,
            rebound: true,
        },
        DomainDetail::RecordingFresh {
            start_sector: 0,
            rebound: false,
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
        DomainDetail::AnchorFingerprint([0xff; 32]),
        DomainDetail::Adopted {
            destination: Ipv4Address::from_octets([255, 255, 255, 255]),
            port: u16::MAX,
            generation: u64::MAX,
        },
        DomainDetail::Dialled {
            destination: Ipv4Address::from_octets([255, 255, 255, 255]),
            port: u16::MAX,
            attempts: u64::MAX,
            outcome: DialOutcome::NextHopUnreachable,
        },
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
            certificate: u64::MAX,
        },
        DomainDetail::DialRoute {
            next_hop: Ipv4Address::from_octets([255, 255, 255, 255]),
            via: NextHopVia::Gateway,
            requests: u64::MAX,
            learned: u64::MAX,
        },
        DomainDetail::DialUnlearned {
            unsolicited: u64::MAX,
            rebinding: u64::MAX,
            not_unicast: u64::MAX,
            contradicted: u64::MAX,
        },
        DomainDetail::DialSegments {
            syns: u64::MAX,
            resets_received: u64::MAX,
            resets_sent: u64::MAX,
            answered: false,
        },
        DomainDetail::DialSegments {
            syns: u64::MAX,
            resets_received: u64::MAX,
            resets_sent: u64::MAX,
            answered: true,
        },
        DomainDetail::DialSequence {
            claimed: u32::MAX,
            expected: u32::MAX,
        },
        DomainDetail::DialRetry {
            delay_millis: u64::MAX,
            bound_millis: u64::MAX,
        },
        DomainDetail::ChannelHandshake {
            outcome: ChannelOutcome::ServerCertificateRejected,
            version: u16::MAX,
            suite: u16::MAX,
            group: u16::MAX,
        },
        DomainDetail::ChannelEnded {
            outcome: ChannelOutcome::ServerCertificateRejected,
        },
        DomainDetail::ChannelIncompatible {
            outcome: ChannelOutcome::ServerCertificateRejected,
            incompatible: TlsIncompatible::NoCertificateRequestSignatureSchemesInCommon,
        },
        DomainDetail::ChannelRefused {
            outcome: ChannelOutcome::ServerCertificateRejected,
            refusal: TlsRefusal::InappropriateHandshakeMessage,
        },
        DomainDetail::ChannelCertificate {
            outcome: ChannelOutcome::ServerCertificateRejected,
            refusal: TlsCertificateRefusal::UnsupportedSignatureAlgorithmForPublicKey,
        },
        DomainDetail::ChannelAlert {
            outcome: ChannelOutcome::ServerCertificateRejected,
            alert: u16::MAX,
        },
        DomainDetail::ChannelBacklogged {
            outcome: ChannelOutcome::ServerCertificateRejected,
            held: u64::MAX,
        },
        DomainDetail::ChannelFrames {
            agreed: false,
            version: u16::MAX,
            sent: u64::MAX,
            received: u64::MAX,
        },
        DomainDetail::ChannelShipping {
            log_position: u64::MAX,
            log_pending: u64::MAX,
            capture_position: u64::MAX,
            capture_pending: u64::MAX,
        },
        DomainDetail::Configured {
            generation: u64::MAX,
            slot: u8::MAX,
            bytes: u64::MAX,
            restored: false,
        },
        DomainDetail::Configured {
            generation: u64::MAX,
            slot: u8::MAX,
            bytes: u64::MAX,
            restored: true,
        },
        DomainDetail::Onboarded {
            relayed: u64::MAX,
            received: u64::MAX,
            sent: u64::MAX,
            ended: OnboardEnd::Forgotten,
        },
        DomainDetail::OnboardingPort {
            accepted: u64::MAX,
            forgotten: u64::MAX,
            overflowed: u64::MAX,
            refused: u64::MAX,
        },
        DomainDetail::OnboardingHandshake {
            outcome: OnboardOutcome::NothingInCommon,
            version: u16::MAX,
            suite: u16::MAX,
            group: u16::MAX,
        },
        DomainDetail::OnboardingEnded {
            outcome: OnboardOutcome::NothingInCommon,
        },
        DomainDetail::OnboardingIncompatible {
            outcome: OnboardOutcome::NothingInCommon,
            incompatible: TlsIncompatible::ServerSentHelloRetryRequestWithUnknownExtension,
        },
        DomainDetail::OnboardingRefused {
            outcome: OnboardOutcome::NothingInCommon,
            refusal: TlsRefusal::InappropriateHandshakeMessage,
        },
        DomainDetail::OnboardingAlert {
            outcome: OnboardOutcome::NothingInCommon,
            alert: u16::MAX,
        },
        DomainDetail::OnboardingBacklogged {
            outcome: OnboardOutcome::NothingInCommon,
            held: u64::MAX,
        },
        DomainDetail::OnboardingSuites {
            points: [u16::MAX; crate::MAX_OFFERED_POINTS],
            offered: u16::MAX,
        },
        DomainDetail::OnboardingGroups {
            points: [u16::MAX; crate::MAX_OFFERED_POINTS],
            offered: u16::MAX,
        },
        DomainDetail::OnboardingServed {
            route: OnboardRoute::CertificateRequest,
            bytes: u64::MAX,
        },
        DomainDetail::OnboardingRequest {
            refusal: OnboardRefusal::StrayCarriageReturn,
            status: u16::MAX,
            held: u64::MAX,
        },
        DomainDetail::OnboardingThrottled {
            strikes: u64::MAX,
            wait_millis: u64::MAX,
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
