//! Fuzz harness bodies for librefirewall's untrusted-device parsers.
//!
//! Each externally driven parser gets a persistent fuzz target (charter /
//! AGENTS.md). The device on the far side of a virtqueue is untrusted input:
//! its PCI configuration space and its used ring are attacker-controllable
//! bytes, so both must be driven to prove no panic, no out-of-bounds access,
//! and bounded work over arbitrary input.
//!
//! The actual harness logic lives here rather than inside the `fuzz_targets/`
//! binaries so that the identical code path can be driven two ways:
//!
//! - by the libFuzzer binaries ([`find_virtio_caps_harness`],
//!   [`virtqueue_poll_harness`] wrapped in `fuzz_target!`), when libFuzzer can
//!   execute; and
//! - by the seed-corpus smoke tests (`cargo test --lib`), which exercise the
//!   same harnesses on the committed seeds plus a few synthetic edge inputs.
//!
//! The second path exists because the pinned hermetic builder runs the gate in
//! a locked-down sandbox (`--cap-drop=all`, read-only rootfs,
//! `--security-opt=no-new-privileges`). libFuzzer with AddressSanitizer may be
//! unable to start under those restrictions; when it cannot, `make fuzz`
//! guarantees every target still *builds* and the smoke tests still drive the
//! parsers over the seeds. See `tools/xtask` (`fuzz`) for the exact fallback.

use std::sync::atomic::{Ordering, fence};

use arbitrary::{Arbitrary, Unstructured};
use virtio::pci::{PciConfig, find_virtio_caps};
use virtio::queue::SplitVirtqueue;

/// Interpret `data` as a 4 KiB PCI configuration space (padded or truncated to
/// exactly 4096 bytes) and run the virtio capability walk over it.
///
/// The device controls every byte, so `find_virtio_caps` must never panic and
/// must never read outside the 4 KiB page. The one invariant it guarantees for
/// a successful parse is asserted: the resolved BAR index is a valid PCI BAR
/// (`0..=5`). The structure *offsets* are the device's own and are not bounded
/// here — that is [`virtio::pci::VirtioCaps::within`]'s job, which is also
/// exercised so its arithmetic sees fuzzer input.
pub fn find_virtio_caps_harness(data: &[u8]) {
    let mut config_space = [0u8; 4096];
    let n = data.len().min(4096);
    config_space[..n].copy_from_slice(&data[..n]);
    // SAFETY: `config_space` is a live 4096-byte buffer that outlives `config`;
    // the capability walk only reads config registers within it.
    let config = unsafe { PciConfig::new(config_space.as_mut_ptr()) };
    if let Ok(caps) = find_virtio_caps(&config) {
        assert!(
            caps.bar <= 5,
            "find_virtio_caps accepted an invalid BAR index {}",
            caps.bar
        );
        // Drive the offset bounds-check too; the result is data-dependent and
        // intentionally unasserted.
        let _ = caps.within(0x4000);
    }
}

/// Queue size the poll harness drives. 16 matches the driver PD's virtqueues
/// and keeps the region well under the 4 KiB backing buffer.
const QSIZE: usize = 16;

/// A 16-byte-aligned backing region, as [`SplitVirtqueue::new`] requires.
#[repr(C, align(16))]
struct Region([u8; 4096]);

/// Drive `poll`/`recycle` against a fuzzer-controlled used ring.
///
/// The first input byte chooses how many receive descriptors to post; the rest
/// becomes the device (used-ring) region — wholly untrusted bytes. A bounded
/// sequence of `poll`/`recycle` calls must never panic, must terminate (`poll`
/// is internally capped at `QSIZE` skips per call), and must keep the
/// descriptor free count in range. Single-owner discipline is the driver PD's
/// responsibility, not the queue's — the queue does not deduplicate device
/// completions (see `crates/virtio/src/queue.rs`) — so the harness recycles
/// each posted descriptor at most once and leaves a duplicate completion
/// un-recycled, exactly as the driver PD must.
pub fn virtqueue_poll_harness(data: &[u8]) {
    let mut unstructured = Unstructured::new(data);
    let posts = (u8::arbitrary(&mut unstructured).unwrap_or(0) as usize) % (QSIZE + 1);
    let device = unstructured.take_rest();

    let mut region = Region([0u8; 4096]);
    let ptr = region.0.as_mut_ptr();
    // SAFETY: `region` is 16-byte aligned, zeroed, and larger than the queue's
    // total_bytes for QSIZE=16; it is the sole owner of this queue.
    let mut queue = unsafe { SplitVirtqueue::<QSIZE>::new(ptr) };

    // Post receive descriptors. Each decrements the free count, so a later
    // recycle of that descriptor is legitimate. Descriptor indices are handed
    // out from the free list, so track which we currently hold.
    let mut held = [false; QSIZE];
    for _ in 0..posts {
        match queue.add_writable(0x1000, 64) {
            Some(token) => held[token.index() as usize] = true,
            None => break,
        }
    }

    // Overwrite the device (used) region with fuzzer bytes; it is the untrusted
    // half of the shared ring. Only [device_offset, total_bytes) is touched, so
    // the descriptor table and available ring the driver owns stay intact.
    let used_base = SplitVirtqueue::<QSIZE>::LAYOUT.device_offset;
    let used_len = SplitVirtqueue::<QSIZE>::LAYOUT.total_bytes - used_base;
    for offset in 0..used_len {
        let byte = device.get(offset).copied().unwrap_or(0);
        // SAFETY: `used_base + offset < total_bytes <= region length`.
        unsafe { ptr.add(used_base + offset).write_volatile(byte) };
    }
    fence(Ordering::Release);

    for _ in 0..(4 * QSIZE) {
        match queue.poll() {
            Some((token, _len)) => {
                let index = token.index() as usize;
                assert!(index < QSIZE, "poll returned out-of-range descriptor {index}");
                if held[index] {
                    held[index] = false;
                    queue.recycle(token);
                }
            }
            None => break,
        }
        assert!(
            queue.free_count() <= QSIZE,
            "free count {} exceeds queue size",
            queue.free_count()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

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
                inputs.push(fs::read(&path).expect("readable seed file"));
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
        ]
    }

    #[test]
    fn find_virtio_caps_harness_survives_seeds_and_edges() {
        for input in seeds("find_virtio_caps").into_iter().chain(edge_inputs()) {
            find_virtio_caps_harness(&input);
        }
    }

    #[test]
    fn virtqueue_poll_harness_survives_seeds_and_edges() {
        for input in seeds("virtqueue_poll").into_iter().chain(edge_inputs()) {
            virtqueue_poll_harness(&input);
        }
    }
}
