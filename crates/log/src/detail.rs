//! What a domain lifecycle point carries beyond its own name.
//!
//! A record of only `domain=` and `state=` would have cost the console three
//! payloads: the feature bitmap a driver and its device settled on, how many
//! receive descriptors were primed before the poll loop, and the whole reason a
//! start-up was refused. Each is a field of the record rather than text a call
//! site formats around it, so an exporter still sees attributes.

/// The longest `cause` token [`MAX_LINE_LEN`](crate::MAX_LINE_LEN) is derived
/// against.
///
/// Nothing here can hold a token to it — the tokens are literals in the crates
/// that raise the refusals. What enforces it is `nic_driver_core`'s
/// `every_refusal_token_is_distinct_and_fits_the_console_line`, which walks
/// that crate's whole refusal surface.
pub const MAX_CAUSE_LEN: usize = 40;

/// What a lifecycle point carries beyond its own name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DomainDetail {
    /// The state is the whole record.
    None,
    /// The feature bits a driver and its device settled on, as the bitmap:
    /// which bit means what is `virtio`'s vocabulary, and decoding it here
    /// would be a second copy of that vocabulary to keep in step.
    Features(u64),
    /// Receive descriptors primed before a driver entered its poll loop.
    ReceivePosted(u32),
    Refusal(Refusal),
}

/// Why a domain refused to start, and what that left the hardware in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Refusal {
    /// What was refused.
    ///
    /// Deliberately not an enum here: the refusal trees belong to the crates
    /// that raise them, and a copy of one in this crate would drift from it
    /// with nothing failing. `&'static str` is also what keeps the field unable
    /// to carry a byte an adversary chose — this crate has no allocator behind
    /// it, so a literal is the only thing that can reach the field (OBS-5).
    pub cause: &'static str,
    /// The numbers `cause` names, in the order it names them.
    pub detail: RefusalDetail,
    /// Whether the device was told to stop, or was left decoding nothing.
    pub signalled: bool,
}

/// Up to two numbers a refusal carries, so it reaches an operator as the values
/// that made it one and not only as its class.
///
/// Two is the console line's budget rather than an arbitrary cut: a refusal
/// with more to say names the pair that identifies it and says at the mapping
/// which it left out, so what is missing is recorded where it is dropped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefusalDetail {
    None,
    One(u64),
    Two(u64, u64),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_refusal_keeps_every_field_it_was_given() {
        let refusal = Refusal {
            cause: "not-virtio-net",
            detail: RefusalDetail::Two(0x1af4, 0x1000),
            signalled: false,
        };
        assert_eq!(refusal.cause, "not-virtio-net");
        assert_eq!(refusal.detail, RefusalDetail::Two(0x1af4, 0x1000));
        assert!(!refusal.signalled);
        assert_eq!(
            DomainDetail::Refusal(refusal),
            DomainDetail::Refusal(refusal)
        );
    }

    #[test]
    fn the_four_detail_shapes_are_distinguishable() {
        let shapes = [
            DomainDetail::None,
            DomainDetail::Features(0),
            DomainDetail::ReceivePosted(0),
            DomainDetail::Refusal(Refusal {
                cause: "",
                detail: RefusalDetail::None,
                signalled: false,
            }),
        ];
        for (index, shape) in shapes.iter().enumerate() {
            for (other_index, other) in shapes.iter().enumerate() {
                assert_eq!(
                    shape == other,
                    index == other_index,
                    "{shape:?} vs {other:?}"
                );
            }
        }
    }
}
