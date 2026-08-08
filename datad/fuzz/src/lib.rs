//! Persistent fuzz harnesses for every librefirewall surface that parses or
//! interprets untrusted input.
//!
//! # Which adversary each harness models
//!
//! Of the appliance's adversaries, three reach code in this
//! workspace, and every module below states which one it drives:
//!
//! | module | surface under test | adversary |
//! |---|---|---|
//! | [`virtio_pci`] | `virtio::pci` capability walk and BAR bounds, and the `nic_driver_core` bring-up typestate above them | a hostile or malfunctioning device |
//! | [`virtqueue`] | `virtio::queue` descriptor lifecycle | a hostile or malfunctioning device |
//! | [`frame`] | `net_headers` parsing and the `routing` decision above it | untrusted network traffic |
//! | [`ip_endpoint`] | `lfw_ip_endpoint`'s ARP and ICMP-echo answers, and the `net_headers` parsers and builders under them | untrusted network traffic **and** a management-plane attacker |
//! | [`neighbour`] | `lfw_ip_endpoint::neighbour`'s cache, the one endpoint structure a peer writes an entry into | untrusted network traffic **and** a management-plane attacker |
//! | [`tcp`] | `lfw_tcp`'s segment parser, its option area and the state machine over them, driven as a stack | untrusted network traffic **and** a management-plane attacker |
//! | [`flow`] | `lfw_flow`'s connection table: the TCP state machine and window checks over it, the UDP and ICMP pseudo-flows, and the quoted datagram inside an ICMP error | untrusted network traffic **and** a connection-flood attacker |
//! | [`http_request`] | `lfw_http`'s request-head parser, cut into arbitrary segments | a management-plane attacker |
//! | [`metrics_render`] | `lfw_metrics`' exposition renderer, over arbitrary counters and arbitrary storage | a byzantine neighbour PD **and** a management-plane attacker |
//! | [`document`] | the `config` reader, the rules over it, and the artifacts built from it | a management-plane attacker |
//! | [`handover`] | `wire`'s configuration handover image | a byzantine neighbour PD |
//! | [`free_list`] | `packet_buffer` ownership ledger | a byzantine neighbour PD |
//! | [`spsc_ring`] | `queue::SpscRing` cursors and slots | a byzantine neighbour PD |
//! | [`log_record`] | `wire`'s log record, and the `lfw_log` event and console line above it | a byzantine neighbour PD |
//! | [`log_ring`] | `wire`'s log records and consume regions, from both sides | a byzantine neighbour PD |
//! | [`pipeline`] | `pd_runtime` pool ownership and forwarding | a byzantine neighbour PD |
//! | [`driver`] | `nic_driver_core` rx/tx paths | a hostile device **and** a byzantine neighbour PD |
//! | [`recording`] | `lfw_recorder`'s pass and sink, and `lfw_capture_ring`'s superblock and ring | a byzantine neighbour PD on two channels **and** a hostile medium |
//! | [`pcapng`] | `lfw_pcapng`'s block encoders, over the lengths a frame and an annotation bring them | untrusted network traffic **and** a byzantine neighbour PD, one remove out |
//! | [`store_state`] | `lfw_store`'s own state record read back off the medium: the two copies, the digest over each, and the identity decoded out of the one that wins | an attacker holding the disk, composing offline with this decoder's source in hand |
//! | [`onboarding_tls`] | `lfw_tls`'s onboarding server: the record layer, the buffering either side of it, and the outcome it settles on | a management-plane attacker |
//! | [`onboarding_surface`] | `lfw_onboarding`'s request surface: the head read out of a plaintext stream cut into arbitrary deliveries, the body handed on to an upload as it arrives, and the twenty-six ways a request is refused | a management-plane attacker |
//! | [`onboarding_package`] | `lfw_package`'s uploaded archive: the ustar framing, the armour around the two certificates, the walk that finds the key one binds, the endpoint line, and the `config` reader under it | a management-plane attacker |
//! | [`onboarding_install`] | `lfw_store`'s install path: a staged region, the length a peer claims about it, the whole package contract read a second time, and the one signature this appliance verifies for itself | a management-plane attacker **and** a byzantine neighbour PD |
//!
//! Every crate in the workspace that interprets bytes it did not write appears
//! in that table, which is the reviewable form of that obligation: the
//! dependency list in `fuzz/Cargo.toml` is the workspace's crate list, and each
//! dependency has a target.
//!
//! # What a harness here asserts
//!
//! A target whose body is a bare call proves only that one input did not
//! crash. Each harness below therefore carries a **model** of the surface it
//! drives and asserts the code against it after every operation. Three kinds of
//! claim recur, and they are the claims the dataplane's safety rests on:
//!
//! * **Conservation.** Buffer indices and virtqueue descriptors are neither
//!   invented nor lost: what is free plus what is outstanding is the whole set,
//!   at every instant, and no identity is in both.
//! * **Boundedness.** A call driven by an untrusted producer performs work
//!   bounded by a quantity the adversary does not control, and the harness
//!   asserts the *bound* rather than imposing one of its own. Where a harness
//!   loop needs a cap it also asserts the loop exited by exhausting the queue
//!   and not by hitting that cap, so a regression that deletes a drain bound
//!   fails instead of being silently truncated.
//! * **Containment.** No address handed to a device, and no span handed to a
//!   peer, falls outside the region it must stay inside. This is the
//!   arbitrary-physical-write invariant, and it is asserted explicitly rather
//!   than inferred from the absence of a crash.
//! * **Multiplicity, counted rather than predicted.** Where a layer *permits*
//!   an outcome that would be a defect one layer up — [`spsc_ring`]'s
//!   redelivery of a descriptor under a forged cursor is the case — the harness
//!   observes and counts the occurrence and asserts the **bound** the layer
//!   really promises. Predicting the outcome from the adversary's own forged
//!   value instead is how a harness comes to assert that the defect is correct
//!   behaviour, which is what that module's header records.
//!
//! # Modelling authority, not politeness
//!
//! One rule shapes every harness here: a guard that keeps a
//! harness "sane" deletes precisely the region where the bug lives. The
//! adversary's *authority* is therefore reproduced in full — duplicate and
//! out-of-range indices, returns of buffers never lent, completions for
//! descriptors never posted, used indices forged between two polls, cursors
//! rewound and forged, single shared *words* rewritten so a reader assembles a
//! value from two writes, registers answered afresh on every access, arbitrary
//! bytes over any shared word the adversary can reach — and the assertion is
//! that the code **rejects** it, not that the harness never produced it.
//!
//! Authority also covers what a *caller* may do where no type stops it:
//! [`spsc_ring`] takes second producer and consumer handles, because
//! `SpscRing`'s single-handle rule is an unenforced contract its own header
//! calls out, and a harness that respected it would have left the redelivery it
//! warns about permanently unreachable.
//!
//! # The limits that are not capability filters
//!
//! Three, each justified where it appears:
//!
//! * An **operation-count budget** per input ([`MAX_OPERATIONS`]): a libFuzzer
//!   timeout budget, unrelated to what any single operation may contain. It
//!   also bounds every collection a harness grows one element per operation,
//!   such as [`spsc_ring`]'s extra handles.
//! * In [`driver`], suspending one **audit** — never an adversary action — once
//!   the device has scribbled the region the audit reads its evidence from.
//! * In [`free_list`], a ceiling on the payload length materialised for
//!   `BufferPool::write` (`free_list::MAX_PAYLOAD`). The parameter is a
//!   `&[u8]`, so its length is bounded by memory a caller already holds rather
//!   than by a `u32`; the ceiling is what a slice can be *made* to be, not what
//!   an adversary may ask for, and it leaves the decision boundary covered from
//!   both sides with room to spare.
//!
//! # Answering inside the call, not only between calls
//!
//! Three device behaviours are a disagreement *within* one driver call — a
//! reset that is never acknowledged, a `FEATURES_OK` cleared on readback, and a
//! feature bitmap whose two halves differ — so none of them is expressible
//! against a window of plain RAM, however the bytes in it are chosen.
//! `nic_driver_core::bringup::VirtioDevice` is the seam built for exactly that,
//! and [`virtio_pci`] holds an implementation of it that answers every access
//! from its own run of the fuzzer's bytes at the moment the driver asks. The
//! whole bring-up typestate is driven over it, so those three and the two
//! refusals that only a *second* virtqueue can carry are ordinary inputs.
//!
//! It is deterministic rather than threaded, for the same reason
//! [`ring_abi`]'s per-word peer stores are: a second thread writing the words
//! the code under test is reading would be a data race the harness
//! manufactured itself, and the finding would be the harness's.
//!
//! # Two ways to run
//!
//! The harness bodies live here rather than inside the `fuzz_targets/` binaries
//! so the identical code path can be driven two ways:
//!
//! - by the libFuzzer binaries (each wrapping one function in `fuzz_target!`),
//!   when libFuzzer can execute; and
//! - by the seed-corpus smoke tests (`cargo test --lib`), which exercise every
//!   harness on the committed seeds plus synthetic edge inputs.
//!
//! The second path exists because the pinned hermetic builder runs the gate in
//! a locked-down sandbox (`--cap-drop=all`, read-only rootfs,
//! `--security-opt=no-new-privileges`). libFuzzer with AddressSanitizer may be
//! unable to start under those restrictions; when it cannot, `make fuzz`
//! guarantees every target still *builds* and the smoke tests still drive every
//! harness over the seeds. See `tools/xtask` (`fuzz`) for the exact fallback.

pub mod blk;
pub mod config_submission;
pub mod document;
pub mod driver;
pub mod flow;
pub mod frame;
pub mod free_list;
pub mod guard;
pub mod handover;
pub mod http_request;
pub mod ip_endpoint;
pub mod log_record;
pub mod log_ring;
pub mod log_ring_abi;
pub mod metrics_render;
pub mod neighbour;
pub mod onboarding_install;
pub mod onboarding_package;
pub mod onboarding_surface;
pub mod onboarding_tls;
pub mod pcapng;
pub mod pipeline;
pub mod recording;
pub mod region;
pub mod ring_abi;
pub mod spsc_ring;
pub mod store_state;
pub mod tcp;
pub mod virtio_pci;
pub mod virtqueue;

use arbitrary::{Arbitrary, Unstructured};

/// How many operations one input may drive.
///
/// A libFuzzer *time* budget, not a bound on what any operation may express: a
/// single operation still carries a fully arbitrary index, cursor, or byte, so
/// no adversarial shape is unreachable. It exists because an input can
/// otherwise encode an arbitrarily long op stream and spend the whole run in
/// one execution, which starves coverage rather than finding anything.
///
/// The distinction matters, because the bound this replaces did the opposite:
/// it capped a *drain* loop and never asserted the loop had exited by
/// exhausting the queue, so a regression deleting the code's own drain bound
/// would have been truncated into a pass. Every drain loop below asserts its
/// exit condition instead of relying on a cap.
pub const MAX_OPERATIONS: usize = 512;

/// Pull the next operation selector, or `None` once the input is spent.
///
/// Returning `None` on exhaustion rather than padding with zeros keeps a short
/// input from driving 512 copies of operation zero, which is both wasted time
/// and a misleading corpus entry.
pub(crate) fn next_op(unstructured: &mut Unstructured<'_>) -> Option<u8> {
    if unstructured.is_empty() {
        return None;
    }
    u8::arbitrary(unstructured).ok()
}

/// Pull an arbitrary `u32` the adversary controls, defaulting to zero once the
/// input is spent so an operation already selected still runs to completion.
pub(crate) fn any_u32(unstructured: &mut Unstructured<'_>) -> u32 {
    u32::arbitrary(unstructured).unwrap_or(0)
}

/// Pull an arbitrary `u16` the adversary controls; see [`any_u32`].
pub(crate) fn any_u16(unstructured: &mut Unstructured<'_>) -> u16 {
    u16::arbitrary(unstructured).unwrap_or(0)
}

/// Pull an arbitrary `u64` the adversary controls; see [`any_u32`].
pub(crate) fn any_u64(unstructured: &mut Unstructured<'_>) -> u64 {
    u64::arbitrary(unstructured).unwrap_or(0)
}

/// Pull an arbitrary `usize` in `0..modulus`, or 0 when `modulus` is 0.
///
/// Used only to pick *which* of the harness's own held objects an operation
/// acts on. Never used to constrain a value that crosses a trust boundary —
/// those are taken with [`any_u32`] and friends, unreduced.
pub(crate) fn any_index(unstructured: &mut Unstructured<'_>, modulus: usize) -> usize {
    if modulus == 0 {
        return 0;
    }
    (any_u32(unstructured) as usize) % modulus
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    /// Every harness, paired with the corpus directory holding its seeds. One
    /// list so a target added without a seed corpus fails the smoke test
    /// instead of shipping an unseeded target.
    ///
    /// **Which** targets it names is held to the `[[bin]]` tables of this crate's
    /// own manifest by a test below, as `tools/xtask`'s `FUZZ_TARGETS` is on its
    /// own side: the manifest is the one place a target is declared, so neither
    /// list can come to disagree with it or, through it, with the other.
    ///
    /// The **order** is this list's own — from the smallest, most self-contained
    /// surface to the deepest composite one — and is not compared with anything,
    /// the two lists ordering the same set for different runs. A defect in
    /// the ledger shows up in `free_list_ownership`, in `pd_runtime_pipeline`,
    /// and in `nic_driver_paths` alike; one in the handover image shows up
    /// in `config_image` and again in `config_document`, which builds one; and
    /// one in the log record shows up in `log_record` and again in `log_ring`,
    /// which carries records through a ring. The narrowest of those is the one
    /// worth reading — so it is the one that fails first. It also means a
    /// harness whose failure aborts the process (a violated `unsafe`
    /// precondition does, being non-unwinding) takes the fewest other harnesses
    /// down with it.
    #[expect(
        clippy::type_complexity,
        reason = "a table of (target name, harness fn) pairs is clearer inline than behind an alias"
    )]
    const HARNESSES: &[(&str, fn(&[u8]))] = &[
        ("config_image", crate::handover::handover_harness),
        ("log_record", crate::log_record::log_record_harness),
        ("free_list_ownership", crate::free_list::free_list_harness),
        ("route_frame", crate::frame::frame_routing_harness),
        ("ip_endpoint", crate::ip_endpoint::ip_endpoint_harness),
        ("neighbour_cache", crate::neighbour::neighbour_cache_harness),
        ("tcp_segments", crate::tcp::tcp_segments_harness),
        ("flow_table", crate::flow::flow_table_harness),
        ("http_request", crate::http_request::http_request_harness),
        (
            "onboarding_tls",
            crate::onboarding_tls::onboarding_tls_harness,
        ),
        (
            "metrics_render",
            crate::metrics_render::metrics_render_harness,
        ),
        (
            "onboarding_surface",
            crate::onboarding_surface::onboarding_surface_harness,
        ),
        (
            "onboarding_package",
            crate::onboarding_package::onboarding_package_harness,
        ),
        (
            "onboarding_install",
            crate::onboarding_install::onboarding_install_harness,
        ),
        ("config_document", crate::document::document_harness),
        (
            "config_submission",
            crate::config_submission::config_submission_harness,
        ),
        ("spsc_ring_peer", crate::spsc_ring::spsc_ring_harness),
        ("log_ring", crate::log_ring::log_ring_harness),
        ("virtqueue_poll", crate::virtqueue::virtqueue_poll_harness),
        ("blk_requests", crate::blk::blk_requests_harness),
        ("pcapng_encode", crate::pcapng::pcapng_encode_harness),
        ("capture_superblock", crate::recording::capture_superblock),
        ("recorder_sink", crate::recording::recorder_sink),
        ("recording_pass", crate::recording::recording_pass),
        ("pd_runtime_pipeline", crate::pipeline::pipeline_harness),
        ("nic_driver_paths", crate::driver::driver_paths_harness),
        (
            "find_virtio_caps",
            crate::virtio_pci::find_virtio_caps_harness,
        ),
        // Driven here as well as by its own module test, which adds a sweep of
        // synthetic regions this shared loop has no way to express. Being absent
        // from this table was the same defect as being absent from the run list:
        // a target whose seeds this loop never carried, in a table that reads as
        // holding every one of them.
        ("store_state", crate::store_state::store_state_harness),
    ];

    /// Read every committed seed for a target so the smoke tests drive the
    /// harnesses over the same corpus libFuzzer would start from.
    fn seeds(target: &str) -> Vec<Vec<u8>> {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("corpus")
            .join(target);
        let mut inputs = Vec::new();
        for entry in fs::read_dir(&dir).expect("seed corpus directory exists") {
            let path = entry.expect("readable dir entry").path();
            if path.is_file() {
                let seed = fs::read(&path).expect("readable seed file");
                assert!(!seed.is_empty(), "empty seed {}", path.display());
                inputs.push(seed);
            }
        }
        assert!(!inputs.is_empty(), "no seeds for target {target}");
        inputs
    }

    /// Synthetic edge inputs every harness must survive regardless of corpus.
    fn edge_inputs() -> Vec<Vec<u8>> {
        vec![
            Vec::new(),
            vec![0u8; 1],
            vec![0xFFu8; 4096],
            vec![0xABu8; 40],
            (0..=255u8).collect(),
            (0..=255u8).rev().collect(),
        ]
    }

    #[test]
    fn every_harness_survives_its_seeds_and_the_shared_edges() {
        for (target, harness) in HARNESSES {
            for input in seeds(target).into_iter().chain(edge_inputs()) {
                harness(&input);
            }
        }
    }

    /// Every target this crate declares a binary for, which is the whole truth
    /// about which targets exist.
    fn declared_targets() -> Vec<String> {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
        let manifest = fs::read_to_string(&path).expect("this crate's own manifest");
        let declared: Vec<String> = manifest
            .split("[[bin]]")
            .skip(1)
            .map(|section| {
                section
                    .split_once("name = \"")
                    .expect("a [[bin]] table declares a name")
                    .1
                    .split_once('"')
                    .expect("the binary name is terminated")
                    .0
                    .to_owned()
            })
            .collect();
        assert!(
            declared.len() >= 3,
            "the manifest parse produced {declared:?}, which cannot be the whole target set"
        );
        declared
    }

    /// A libFuzzer binary and the harness the smoke tests drive are two readings
    /// of one target, and nothing but this compared them. A binary with no entry
    /// here is built and fuzzed but never carried over its seeds, so the corpus
    /// that is supposed to catch a lost rule with no live fuzzing at all is never
    /// read; an entry with no binary is a harness that no fuzzer ever drives.
    /// Both are the same defect the target list in `tools/xtask` had: a target
    /// counted as covered by a run that never touched it.
    #[test]
    fn every_declared_target_has_a_harness_and_every_harness_has_a_binary() {
        let declared = declared_targets();
        for target in &declared {
            assert!(
                HARNESSES.iter().any(|(name, _)| name == target),
                "Cargo.toml declares the target {target}, but no harness here is named for it, so \
                 its seed corpus is never driven by the smoke tests"
            );
        }
        for (target, _) in HARNESSES {
            assert!(
                declared.iter().any(|declared| declared == target),
                "a harness is named {target}, but Cargo.toml declares no [[bin]] for it, so no \
                 fuzzer ever drives it"
            );
        }
    }

    /// The seed corpus is what a cold fuzz run starts from, so a target with no
    /// directory at all would silently start from nothing. Asserted separately
    /// from the run above so the failure names the missing corpus rather than
    /// surfacing as a panic inside a harness.
    #[test]
    fn every_harness_has_a_committed_seed_corpus() {
        for (target, _) in HARNESSES {
            assert!(
                !seeds(target).is_empty(),
                "target {target} has no committed seeds"
            );
        }
    }
}
