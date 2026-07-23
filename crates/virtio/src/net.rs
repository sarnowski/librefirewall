//! virtio-net data types and constants (virtio 1.0).
//!
//! These are the on-the-wire/in-DMA structures and negotiation constants a
//! driver parses and programs; the logic that uses them lives in the driver
//! protection domain. Only the pieces the Rx path needs are defined here;
//! offload/control-queue fields are added when their feature is implemented.

use core::mem::size_of;

/// The per-buffer header virtio-net prepends to every packet in both
/// directions. With virtio 1.0 (or `VIRTIO_NET_F_MRG_RXBUF`) the `num_buffers`
/// field is always present, fixing the header at 12 bytes.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct VirtioNetHdr {
    /// Bitmask of `VIRTIO_NET_HDR_F_*`.
    pub flags: u8,
    /// One of `VIRTIO_NET_HDR_GSO_*`.
    pub gso_type: u8,
    /// Size of the header to prepend, for GSO.
    pub hdr_len: u16,
    /// Maximum segment size, for GSO.
    pub gso_size: u16,
    /// Offset from packet start at which to begin the checksum.
    pub csum_start: u16,
    /// Offset from `csum_start` at which to store the checksum.
    pub csum_offset: u16,
    /// Number of merged receive buffers this packet spans.
    pub num_buffers: u16,
}

impl VirtioNetHdr {
    /// Serialised size of the header in a DMA buffer.
    pub const LEN: usize = size_of::<Self>();
}

// The header is DMA'd verbatim to and from the device, so its layout is a fixed
// ABI and must be exactly the 12-byte virtio 1.0 form.
const _: () = assert!(size_of::<VirtioNetHdr>() == 12);

// `flags`
pub const VIRTIO_NET_HDR_F_NEEDS_CSUM: u8 = 1;
pub const VIRTIO_NET_HDR_F_DATA_VALID: u8 = 2;

// `gso_type`
pub const VIRTIO_NET_HDR_GSO_NONE: u8 = 0;

/// Feature bits negotiated with a virtio-net device (subset the driver uses).
pub mod features {
    /// Device provides a MAC address in config space.
    pub const VIRTIO_NET_F_MAC: u64 = 1 << 5;
    /// Receive buffers may be merged; also forces the 12-byte header.
    pub const VIRTIO_NET_F_MRG_RXBUF: u64 = 1 << 15;
    /// Device exposes a link-status/announce config field.
    pub const VIRTIO_NET_F_STATUS: u64 = 1 << 16;
    /// virtio 1.0 (non-legacy) device. Mandatory for the modern layout.
    pub const VIRTIO_F_VERSION_1: u64 = 1 << 32;
}

/// Device status bits written during initialisation, in order.
pub mod status {
    pub const ACKNOWLEDGE: u8 = 1;
    pub const DRIVER: u8 = 2;
    pub const DRIVER_OK: u8 = 4;
    pub const FEATURES_OK: u8 = 8;
    pub const DEVICE_NEEDS_RESET: u8 = 0x40;
    pub const FAILED: u8 = 0x80;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_is_twelve_bytes() {
        assert_eq!(VirtioNetHdr::LEN, 12);
    }

    #[test]
    fn default_header_is_zeroed() {
        let hdr = VirtioNetHdr::default();
        assert_eq!(
            hdr,
            VirtioNetHdr {
                flags: 0,
                gso_type: 0,
                hdr_len: 0,
                gso_size: 0,
                csum_start: 0,
                csum_offset: 0,
                num_buffers: 0,
            }
        );
    }
}
