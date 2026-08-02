//! The HPET register block as a protection domain reaches it: aligned 64-bit
//! volatile accesses into the page Microkit mapped, behind `lfw_hpet`'s
//! [`HpetMmio`] seam.
//!
//! # Adversary
//!
//! The **hostile or malfunctioning device** — the timer block, whose
//! every answer is its own choice and whose window may decode nothing at all.
//! Nothing here judges one: every value goes straight to `lfw_hpet`, which
//! ranges what it is told and bounds every wait. No peer domain and no network
//! byte reaches this path.
//!
//! # Why the accesses are here and not in `lfw_hpet`
//!
//! Dereferencing the mapping is `unsafe` and the pointer is authority this
//! protection domain was granted, so the code that performs it is bound to the
//! domain and cannot be written — or host-tested — in a portable crate. That is
//! the same split `pds/console/src/com1.rs` makes for the UART's ports, and it
//! is why `lfw_hpet` holds an `unsafe` count of zero while this file does not.
//! What stays there is everything a host test can judge: which registers exist,
//! what each answer has to be inside, and how long a wait may run.
//!
//! # Why every access is volatile
//!
//! A register read has an effect the compiler cannot see and a value it cannot
//! predict: the main counter answers a different number every time it is asked,
//! and the whole of `lfw_hpet::wait_ticks` is asking it repeatedly. A
//! non-volatile load is one the optimiser may hoist out of that loop, which
//! turns a bounded wait into an unbounded one against a value that never
//! changes.
//!
//! # Why no `Drop` and no teardown
//!
//! `Hpet::probe` sets `ENABLE_CNF` and leaves the counter running, deliberately:
//! the block is free-running hardware with no per-domain state, and stopping it
//! on the way out would take a running counter away from whatever reads it next.

use lfw_hpet::{HpetMmio, Register};
use sel4_microkit::memory_region_symbol;

/// The mapped block.
///
/// It carries the base and nothing else — no length and no register map — for
/// the reason `pds/console`'s `Com1` carries neither base nor capability
/// pointer: both are fixed by the system description at build time, and a
/// field would be a second, unchecked statement of what `lfw_hpet`'s
/// const-assertions already hold. The private field makes [`map`](Self::map)
/// the only way to obtain one, so no pointer this domain did not receive from
/// the Microkit tool can reach the accesses below.
pub struct HpetPage {
    base: *mut u8,
}

impl HpetPage {
    /// Take the block the `<memory_region name="hpet">` grant maps.
    ///
    /// It reads the patched symbol itself rather than taking a pointer, which
    /// is what leaves this constructor with no precondition to delegate: there
    /// is no argument a caller could get wrong, so there is no `# Safety`
    /// section here and no obligation for a call site to discharge.
    ///
    /// A second handle is a second view of one device and not a second device.
    /// Every access below is volatile and the block is what both would be
    /// talking to, so aliasing costs nothing here; what a duplicate would cost
    /// is a second `lfw_hpet::Hpet`, and that type is what makes "probed and
    /// running" a state rather than a claim.
    #[must_use]
    pub fn map() -> Self {
        Self {
            base: memory_region_symbol!(hpet_vaddr: *mut u8).as_ptr(),
        }
    }

    /// The address of one register within the mapped block.
    ///
    /// Every offset [`Register`] can produce is const-asserted in `lfw_hpet` to
    /// be 8-byte aligned and to end inside `MMIO_LENGTH`, and `MMIO_LENGTH`
    /// is asserted there to fit inside the page this grant is — so the sum
    /// cannot leave the mapping and cannot be misaligned for a `u64`.
    fn register(&self, register: Register) -> *mut u64 {
        // SAFETY: `self.base` is the mapped `hpet` region of
        // `systems/qemu-x86_64/librefirewall.system`, which maps one page at
        // `hpet_vaddr` into this PD and holds the mapping for the PD's whole
        // life. `Register::offset` is bounded by that crate's own
        // `MainCounter.offset() + size_of::<u64>() <= MMIO_LENGTH` and
        // `MMIO_BASE % PAGE_SIZE + MMIO_LENGTH <= PAGE_SIZE` const-assertions,
        // so the offset lands inside the same allocated object.
        unsafe { self.base.add(register.offset()).cast::<u64>() }
    }
}

impl HpetMmio for HpetPage {
    fn read_u64(&self, register: Register) -> u64 {
        // SAFETY: `register` returns a pointer inside the mapped page, aligned
        // for `u64` by the offset assertions named there; the mapping is live
        // for this PD's whole life and is uncached, which
        // `systems/qemu-x86_64/librefirewall.system` states on the `<map>`
        // (`cached="false"`). What the device answers is unconstrained and is
        // `lfw_hpet`'s to judge, not this file's.
        unsafe { self.register(register).read_volatile() }
    }

    fn write_u64(&mut self, register: Register, value: u64) {
        // SAFETY: as `read_u64`, and the write is to the same mapping, which
        // that row grants `perms="rw"`.
        unsafe { self.register(register).write_volatile(value) }
    }
}
