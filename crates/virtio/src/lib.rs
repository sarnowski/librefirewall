//! First-party virtio primitives for the NIC driver protection domain.
//!
//! This crate is the device-facing counterpart to `crates/queue`: where the
//! SPSC ring moves buffer ownership between two of our protection domains, a
//! virtqueue moves buffer ownership between our driver and a virtio device over
//! DMA. It is implemented from scratch per CONCEPT §8 rather than reusing an
//! upstream virtio crate.
//!
//! Three modules divide along the virtio 1.0 seams. [`queue`] is the driver
//! half of the split-virtqueue protocol and is transport-agnostic; [`pci`] is
//! the one transport shipped — modern x86 PCI, with no MMIO transport yet — and
//! is what programs a queue's layout into a device; [`net`] is the virtio-net
//! device type's own data. Everything here is mechanism: the driver PD
//! (`pds/nic-driver`) owns policy and capability use, so PCI/BAR bring-up and
//! feature negotiation run there. Interrupt delivery (MSI-X) and VT-d-confined
//! DMA on real hardware are open items tracked in CONCEPT §13 and reflected in
//! the README status, not here.
//!
//! Both a virtio device and its transport are untrusted (CONCEPT §7.1); each
//! module's own header states what it validates and what it deliberately does
//! not.

#![cfg_attr(not(test), no_std)]

pub mod net;
pub mod pci;
pub mod queue;
