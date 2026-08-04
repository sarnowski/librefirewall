//! virtio 1.0 driver-side primitives: the split virtqueue, the modern x86 PCI
//! transport that programs it into a device, and virtio-net's own data types.
//!
//! The adversary is a hostile or malfunctioning device: every byte
//! read back from a device register or from the shared DMA region is its own.
//!
//! Written from scratch as a deliberate decision rather than reusing `virtio-drivers`,
//! whose rust-sel4 integration ships an ARM virtio-MMIO transport only — there
//! is no x86 PCI transport to reuse.

#![cfg_attr(not(test), no_std)]

pub mod net;
pub mod pci;
pub mod queue;
