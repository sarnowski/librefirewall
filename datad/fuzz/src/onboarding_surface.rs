//! `lfw_onboarding` under the management-plane attacker.
//!
//! # The adversary and the surface
//!
//! Everything this crate reads arrived on the onboarding port inside a TLS
//! session that authenticates the *appliance* and nobody else, so the input here
//! is the plaintext stream itself: a request head, whatever follows it, and the
//! cuts the network put between them. There is no prologue this harness supplies
//! and no filter on the bytes — a corpus entry is a byte string, and a
//! well-formed upload is only one of the shapes it can be.
//!
//! # What the adversary may express, and why the cuts are part of it
//!
//! The pacing is the peer's, and it is the half of this surface a
//! request-at-a-time harness would delete. The whole reason the head buffer is
//! filled before it is parsed is that one delivery can carry a head *and* tens
//! of kibibytes of body; a harness that handed the surface one contiguous slice
//! would never drive the boundary that decision exists for. So the input carries
//! its own cut points, sorted, and the stream is delivered in those pieces —
//! including empty ones, including a cut inside the head, inside the terminator,
//! and inside the body.
//!
//! The upload the surface is given is adversarial too, in the three ways a real
//! one can be: it may refuse to begin, it may keep fewer bytes than it was
//! offered, and it may refuse to install. Modelling those is what reaches the
//! refusal arms; a sink that always said yes would leave three of them dead.
//!
//! # What the harness does not constrain
//!
//! Nothing about the bytes. In particular it does **not** compose a valid head
//! and mutate it: a head is what the parser says it is, and a harness that built
//! one would be fuzzing its own builder. The declared `Content-Length` and the
//! bytes that follow it are free to disagree in either direction, which is the
//! input the overrun refusal exists for.
//!
//! # What is asserted
//!
//! * **Totality.** Every byte string in every arrangement of cuts produces
//!   decisions and never a fault.
//! * **Nothing a peer sent reaches a record.** Every record a decision owes is
//!   one of the three shapes the surface can emit, and each carries tokens out
//!   of closed vocabularies and numbers this appliance computed — asserted by
//!   reading them back, since a record is what an operator sees.
//! * **One request per connection.** At most one decision is ever an outcome:
//!   once the surface has answered, everything after it is `Waiting` and nothing
//!   further is served, installed or refused.
//! * **A body is never installed short, and never long.** What the sink was
//!   handed is bounded by what the head declared, and an install happens only
//!   where exactly that many bytes arrived.
//! * **The close is absorbing.** A surface that installed a package refuses
//!   every later request under one token, and never serves again.
//! * **The head bound holds.** The bytes the surface reports holding never
//!   exceed the capacity it reserves for a head.

use arbitrary::Unstructured;
use lfw_onboarding::{
    Decision, Identity, MAX_UPLOAD_LEN, Monotonic, Onboarding, REQUEST_CAPACITY, Upload,
    UploadRefused,
};
use lfw_x509::{DEVICE_ID_LEN, FINGERPRINT_LEN};

use crate::{any_index, any_u16};

/// Deliveries one stream is cut into. A liveness bound on the harness and not on
/// the adversary: a peer may send as many segments as it likes, and what this
/// caps is how many *this input* describes, so no arrival pattern is excluded.
const MAX_DELIVERIES: usize = 24;

/// The name and fingerprint the surface serves. Fixed, exactly as a running
/// appliance's are fixed by the domain that minted them: they are not the
/// adversary's to choose, and a harness that let them be would be modelling an
/// authority the attacker does not have.
const DEVICE: &[u8; DEVICE_ID_LEN] = b"00000000000000000000000000000001";
const FINGERPRINT: &[u8; FINGERPRINT_LEN] =
    b"9f2b1c0d4e5a6789abcdef0123456789abcdef0123456789abcdef0123456789";

/// A request PEM that is not one, which is all the surface needs: it serves
/// these bytes and reads none of them.
const REQUEST: &[u8] = b"-----BEGIN CERTIFICATE REQUEST-----\nMIIBAA==\n-----END CERTIFICATE REQUEST-----\n";

/// The upload the surface is driven against: what it kept, and the three ways it
/// can say no.
struct Sink {
    kept: usize,
    declared: Option<usize>,
    opens: u32,
    installs: u32,
    refuse_open: bool,
    /// Bytes to keep out of each segment, or all of them.
    keep: Option<usize>,
    refuse_install: bool,
}

impl Upload for Sink {
    fn open(&mut self, declared: usize) -> Result<(), UploadRefused> {
        self.opens += 1;
        assert!(
            declared <= MAX_UPLOAD_LEN,
            "the surface opened an upload of {declared} bytes, past the bound it holds a \
             declared length to"
        );
        assert!(declared > 0, "the surface opened an upload of no bytes");
        if self.refuse_open {
            return Err(UploadRefused);
        }
        self.declared = Some(declared);
        Ok(())
    }

    fn take(&mut self, segment: &[u8]) -> usize {
        assert!(
            self.declared.is_some(),
            "the surface handed body bytes on without opening an upload"
        );
        let kept = self.keep.unwrap_or(segment.len()).min(segment.len());
        self.kept += kept;
        if let Some(declared) = self.declared {
            assert!(
                self.kept <= declared,
                "the surface handed on {} bytes for an upload it declared {declared} of",
                self.kept
            );
        }
        kept
    }

    fn install(&mut self) -> Result<(), UploadRefused> {
        self.installs += 1;
        assert_eq!(
            Some(self.kept),
            self.declared,
            "the surface installed a body that is not the length it declared"
        );
        if self.refuse_install {
            return Err(UploadRefused);
        }
        Ok(())
    }
}

/// What one run reached, so the committed seeds can be held to the paths they
/// are named for.
///
/// A seed corpus nobody checks is a corpus that reads as coverage: a byte string
/// whose prefix decodes to something other than the run its filename claims
/// still passes every assertion below, and every later run starts from it. This
/// is what makes the claim checkable.
#[derive(Default, Debug, PartialEq, Eq)]
pub struct Reached {
    pub served: u32,
    pub installed: u32,
    pub refusals: Vec<lfw_log::OnboardRefusal>,
    pub opens: u32,
    pub installs_asked: u32,
}

pub fn onboarding_surface_harness(data: &[u8]) {
    let _ = drive(data);
}

pub fn drive(data: &[u8]) -> Reached {
    let mut reached = Reached::default();
    let mut unstructured = Unstructured::new(data);
    let deliveries = any_index(&mut unstructured, MAX_DELIVERIES) + 1;
    let mut cuts: Vec<usize> = (0..deliveries)
        .map(|_| usize::from(any_u16(&mut unstructured)))
        .collect();
    // The appliance's own state, which the adversary does not choose but the
    // corpus must be able to reach both of: a surface that boots owned is a
    // different appliance and answers differently.
    let owned = any_index(&mut unstructured, 2) == 1;
    let with_identity = any_index(&mut unstructured, 8) != 0;
    let refuse_open = any_index(&mut unstructured, 4) == 0;
    let refuse_install = any_index(&mut unstructured, 4) == 0;
    let keep = match any_index(&mut unstructured, 4) {
        0 => Some(any_index(&mut unstructured, 64)),
        _ => None,
    };
    let stream = unstructured.take_rest();
    cuts.sort_unstable();

    let identity = with_identity.then(|| Identity::new(*DEVICE, *FINGERPRINT, REQUEST));
    let mut surface = Onboarding::new(identity, owned);
    let mut sink = Sink {
        kept: 0,
        declared: None,
        opens: 0,
        installs: 0,
        refuse_open,
        keep,
        refuse_install,
    };
    surface.opened();

    // A surface that booted owned is shut before a byte arrives, and nothing
    // below may reopen it.
    assert_eq!(
        surface.closed(),
        owned,
        "the surface's state at boot is not the ownership it was built with"
    );

    let mut outcomes = 0_u32;
    let mut installed = false;
    let mut at = 0_usize;
    for cut in cuts
        .into_iter()
        .chain(core::iter::once(stream.len()))
        .map(|cut| cut.min(stream.len()))
    {
        let end = cut.max(at);
        let delivery = stream.get(at..end).unwrap_or_default();
        at = end;

        let decision = surface.take(Some(Monotonic::BOOT), delivery, &mut sink);
        // Every record is a shape this surface can emit, and every field of it
        // is a closed token or a number this appliance computed. Read back
        // rather than trusted, a record being what an operator sees.
        for record in decision.records().into_iter().flatten() {
            assert!(
                matches!(
                    record,
                    lfw_log::DomainDetail::OnboardingServed { .. }
                        | lfw_log::DomainDetail::OnboardingInstalled { .. }
                        | lfw_log::DomainDetail::OnboardingRequest { .. }
                        | lfw_log::DomainDetail::OnboardingThrottled { .. }
                ),
                "the request surface emitted a record that is not one of its own"
            );
        }
        match decision {
            Decision::Waiting => {}
            Decision::Served { bytes, .. } => {
                outcomes += 1;
                reached.served += 1;
                assert!(!owned, "an owned appliance served a resource");
                assert!(!installed, "a shut surface served a resource");
                assert!(bytes > 0, "a served resource carried no bytes");
            }
            Decision::Installed { bytes } => {
                outcomes += 1;
                reached.installed += 1;
                installed = true;
                assert!(!owned, "an owned appliance installed a package");
                assert!(
                    surface.closed(),
                    "a package was installed and the surface stayed open"
                );
                assert_eq!(
                    bytes, sink.kept,
                    "the record's length is not what was handed on"
                );
            }
            Decision::Refused { held, refusal, .. } => {
                outcomes += 1;
                reached.refusals.push(refusal);
                assert!(
                    held <= REQUEST_CAPACITY,
                    "a refusal reported holding {held} bytes of head, past the capacity"
                );
            }
        }
        assert!(
            outcomes <= 1,
            "one connection produced {outcomes} outcomes; a response closes it"
        );
    }

    // What the sink was handed is bounded by what the head declared, whatever
    // the peer then sent.
    if let Some(declared) = sink.declared {
        assert!(sink.kept <= declared);
    }
    assert!(
        sink.installs <= 1,
        "one connection asked for {} installs",
        sink.installs
    );
    assert!(sink.opens <= 1, "one connection opened {} uploads", sink.opens);
    reached.opens = sink.opens;
    reached.installs_asked = sink.installs;
    // The close is absorbing: once shut, every later request on a fresh
    // connection is the same refusal and nothing is ever served again.
    if surface.closed() {
        for _ in 0..3 {
            surface.opened();
            let decision = surface.take(
                Some(Monotonic::BOOT),
                b"GET / HTTP/1.1\r\nHost: a\r\n\r\n",
                &mut sink,
            );
            assert!(
                !matches!(
                    decision,
                    Decision::Served { .. } | Decision::Installed { .. }
                ),
                "a shut surface answered a request with a resource"
            );
        }
    }
    reached
}

#[cfg(test)]
mod tests {
    use super::{Reached, drive};
    use lfw_log::OnboardRefusal;
    use std::{fs, path::PathBuf};

    fn seed(name: &str) -> Vec<u8> {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("corpus")
            .join("onboarding_surface")
            .join(name);
        fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
    }

    fn reached(name: &str) -> Reached {
        drive(&seed(name))
    }

    /// Every seed reaches the run its filename claims.
    ///
    /// A corpus is the thing a cold run starts from, and a seed whose prefix
    /// decodes to something other than what it is named for is a file that reads
    /// as coverage and provides none. This is the only check that catches that,
    /// because a mis-decoded seed passes the harness's own assertions.
    #[test]
    fn every_seed_reaches_the_run_it_is_named_for() {
        let installed = reached("whole_upload_one_delivery");
        assert_eq!(installed.installed, 1, "whole_upload_one_delivery");
        assert_eq!(installed.installs_asked, 1);

        let cut = reached("upload_cut_at_the_head_boundary");
        assert_eq!(cut.installed, 1, "upload_cut_at_the_head_boundary");

        assert_eq!(
            reached("body_past_the_declared_length").refusals,
            vec![OnboardRefusal::UploadOverran]
        );
        assert_eq!(
            reached("upload_declaring_no_body").refusals,
            vec![OnboardRefusal::UploadEmpty]
        );
        assert_eq!(
            reached("declared_past_the_bound").refusals,
            vec![OnboardRefusal::BodyTooLarge]
        );
        assert_eq!(
            reached("no_room_to_validate").refusals,
            vec![OnboardRefusal::UploadUnavailable]
        );
        assert_eq!(
            reached("the_key_holder_refuses").refusals,
            vec![OnboardRefusal::PackageRefused]
        );
        assert_eq!(
            reached("bytes_that_would_not_all_go").refusals,
            vec![OnboardRefusal::UploadUnstaged]
        );
        assert_eq!(
            reached("no_identity").refusals,
            vec![OnboardRefusal::IdentityAbsent]
        );
        assert_eq!(
            reached("a_head_that_never_ends").refusals,
            vec![OnboardRefusal::HeadTooLong]
        );

        // The owned appliance answers one way whatever it is asked, and the
        // three follow-up requests the harness makes on a shut surface are
        // refused too — so the count is what an absorbing close looks like.
        let owned = reached("owned_appliance_is_shut");
        assert!(
            owned
                .refusals
                .iter()
                .all(|refusal| *refusal == OnboardRefusal::AlreadyOwned),
            "{owned:?}"
        );
        assert_eq!(owned.served, 0);

        assert_eq!(reached("the_page").served, 1);
        assert_eq!(reached("the_certificate_request").served, 1);

        // A single bare line feed is refused at the first line ending rather
        // than waited out to the head bound, which is the strict reading this
        // parser takes on purpose.
        assert_eq!(
            reached("a_bare_line_feed").refusals,
            vec![OnboardRefusal::BareLineFeed]
        );

        // And an empty stream reaches no outcome at all, which is the waiting
        // path rather than a refusal.
        let quiet = reached("empty");
        assert_eq!(quiet.served, 0);
        assert_eq!(quiet.installed, 0);
        assert!(quiet.refusals.is_empty(), "{quiet:?}");
    }
}
