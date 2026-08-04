//! One declaration per shared-memory image, and the three artifacts that have
//! to agree with it byte for byte.
//!
//! A region's layout is written three times: the plain `#[repr(C)]` value a
//! reader copies out, the atomic mirror a writer stores through, and the
//! offset assertions that hold the second byte-identical to the first. All
//! three are mechanical and none of them is checkable by reading one of them —
//! a mirror that drifts from its image is a silent corruption of every
//! generation that crosses, and a hand-written assertion block is exactly as
//! likely to be forgotten as the field it would have caught. [`shared_image`]
//! takes the layout once and emits all three, so the drift is unrepresentable
//! rather than reviewed for.
//!
//! # What the declaration is, and why it reads as a byte map
//!
//! Each field states its own offset, and the macro asserts that offset against
//! the type the compiler actually laid out. That is the opposite of inferring
//! offsets from the field order: the declaration is the authority on where a
//! byte lands, and the compiler is what refuses a declaration that lies. A
//! reader answering "what is at offset 12" reads one column of one list, where
//! before they read a struct here and an assertion block six hundred lines
//! away. Padding is declared as `padding`, not `bytes`, so bytes that name
//! nothing say so in the same column.
//!
//! The macro stops there deliberately. It moves bytes and asserts positions; it
//! decides nothing about what a value *means* — no field is validated here,
//! no rule about one is expressible here, and every semantic question a region
//! raises stays hand-written where it can be read as a rule. A macro that could
//! hide a validation decision would buy brevity with the one property this
//! crate exists to have.

/// The plain image's type for one field kind.
///
/// This and the five tables below are one arm per field kind, laid out as a
/// table because that is the whole of what they are: reading them down the
/// column is how a reader checks that `bytes(6)` means the same six bytes in
/// the image, in the mirror and in the move between them. rustfmt would put
/// each arm on three lines and there would be no column left to read.
#[rustfmt::skip]
macro_rules! image_type {
    (byte)                                    => { u8 };
    (half)                                    => { u16 };
    (word)                                    => { u32 };
    (digest)                                  => { u32 };
    (bytes($len:expr))                        => { [u8; $len] };
    (padding($len:expr))                      => { [u8; $len] };
    (identifier)                              => { $crate::log_record::IdentifierImage };
    (nested($image:ident, $slot:ident))       => { $image };
    (array($image:ident, $slot:ident, $len:expr)) => { [$image; $len] };
}

/// The atomic mirror's type for one field kind. One atomic per byte for
/// everything but a word, for the reason the crate header gives: packing bytes
/// into a wider cell would place a field inside a word and make the region's
/// byte order a thing this crate chooses rather than one it mirrors.
#[rustfmt::skip]
macro_rules! slot_type {
    (byte)                                    => { ::core::sync::atomic::AtomicU8 };
    (half)                                    => { ::core::sync::atomic::AtomicU16 };
    (word)                                    => { ::core::sync::atomic::AtomicU32 };
    (digest)                                  => { ::core::sync::atomic::AtomicU32 };
    (bytes($len:expr))                        => { [::core::sync::atomic::AtomicU8; $len] };
    (padding($len:expr))                      => { [::core::sync::atomic::AtomicU8; $len] };
    (identifier)                              => {
        $crate::log_slot::TextSlot<{ $crate::log_record::LOG_IDENTIFIER_BYTES }>
    };
    (nested($image:ident, $slot:ident))       => { $slot };
    (array($image:ident, $slot:ident, $len:expr)) => { [$slot; $len] };
}

/// The zero value of one field, which is what makes a zeroed region a valid
/// image rather than a decoding accident.
#[rustfmt::skip]
macro_rules! image_zero {
    (byte)                                    => { 0 };
    (half)                                    => { 0 };
    (word)                                    => { 0 };
    (digest)                                  => { 0 };
    (bytes($len:expr))                        => { [0; $len] };
    (padding($len:expr))                      => { [0; $len] };
    (identifier)                              => { $crate::log_record::IdentifierImage::ZERO };
    (nested($image:ident, $slot:ident))       => { $image::ZERO };
    (array($image:ident, $slot:ident, $len:expr)) => { [$image::ZERO; $len] };
}

/// As [`image_zero`], for the mirror. A `const fn` call rather than a constant
/// throughout: a constant holding an atomic is copied at every mention, so a
/// slot built from one would be published into a temporary and read by nobody.
#[rustfmt::skip]
macro_rules! slot_zero {
    (byte)                                    => { ::core::sync::atomic::AtomicU8::new(0) };
    (half)                                    => { ::core::sync::atomic::AtomicU16::new(0) };
    (word)                                    => { ::core::sync::atomic::AtomicU32::new(0) };
    (digest)                                  => { ::core::sync::atomic::AtomicU32::new(0) };
    (bytes($len:expr))                        => { [const { ::core::sync::atomic::AtomicU8::new(0) }; $len] };
    (padding($len:expr))                      => { [const { ::core::sync::atomic::AtomicU8::new(0) }; $len] };
    (identifier)                              => { $crate::log_slot::TextSlot::zero() };
    (nested($image:ident, $slot:ident))       => { $slot::zero() };
    (array($image:ident, $slot:ident, $len:expr)) => { [const { $slot::zero() }; $len] };
}

/// Moving one field into the mirror. Padding moves with everything else: which
/// bytes mean something is a question for the checking step, and a mirror that
/// decided it would be deciding it twice.
#[rustfmt::skip]
macro_rules! slot_store {
    (byte, $cell:expr, $value:expr)           => { $cell.store($value, ::core::sync::atomic::Ordering::Relaxed) };
    (half, $cell:expr, $value:expr)           => { $cell.store($value, ::core::sync::atomic::Ordering::Relaxed) };
    (word, $cell:expr, $value:expr)           => { $cell.store($value, ::core::sync::atomic::Ordering::Relaxed) };
    (digest, $cell:expr, $value:expr)         => { $cell.store($value, ::core::sync::atomic::Ordering::Relaxed) };
    (bytes($len:expr), $cell:expr, $value:expr)   => { $crate::store_bytes(&$cell, $value) };
    (padding($len:expr), $cell:expr, $value:expr) => { $crate::store_bytes(&$cell, $value) };
    (identifier, $cell:expr, $value:expr)     => { $cell.store(&$value) };
    (nested($image:ident, $slot:ident), $cell:expr, $value:expr) => { $cell.store(&$value) };
    (array($image:ident, $slot:ident, $len:expr), $cell:expr, $value:expr) => {
        for (cell, entry) in $cell.iter().zip(&$value) {
            cell.store(entry);
        }
    };
}

/// The inverse of [`slot_store`], one field at a time.
#[rustfmt::skip]
macro_rules! slot_load {
    (byte, $cell:expr)                        => { $cell.load(::core::sync::atomic::Ordering::Relaxed) };
    (half, $cell:expr)                        => { $cell.load(::core::sync::atomic::Ordering::Relaxed) };
    (word, $cell:expr)                        => { $cell.load(::core::sync::atomic::Ordering::Relaxed) };
    (digest, $cell:expr)                      => { $cell.load(::core::sync::atomic::Ordering::Relaxed) };
    (bytes($len:expr), $cell:expr)            => { $crate::load_bytes(&$cell) };
    (padding($len:expr), $cell:expr)          => { $crate::load_bytes(&$cell) };
    (identifier, $cell:expr)                  => { $cell.load() };
    (nested($image:ident, $slot:ident), $cell:expr) => { $cell.load() };
    (array($image:ident, $slot:ident, $len:expr), $cell:expr) => {{
        let mut entries = [$image::ZERO; $len];
        for (entry, cell) in entries.iter_mut().zip($cell.iter()) {
            *entry = cell.load();
        }
        entries
    }};
}

/// Folding one field into the running digest, in the byte order the region
/// carries it. Every kind folds — padding with everything else, for
/// [`slot_store`]'s reason — except `digest`, which is the word the fold is
/// compared against and so cannot be part of what it covers.
#[rustfmt::skip]
macro_rules! image_fold {
    (byte, $hash:ident, $value:expr)          => { $hash = $crate::image::fold_bytes($hash, &[$value]); };
    (half, $hash:ident, $value:expr)          => { $hash = $crate::image::fold_bytes($hash, &$value.to_le_bytes()); };
    (word, $hash:ident, $value:expr)          => { $hash = $crate::image::fold_bytes($hash, &$value.to_le_bytes()); };
    (digest, $hash:ident, $value:expr)        => {};
    (bytes($len:expr), $hash:ident, $value:expr)   => { $hash = $crate::image::fold_bytes($hash, &$value); };
    (padding($len:expr), $hash:ident, $value:expr) => { $hash = $crate::image::fold_bytes($hash, &$value); };
    (identifier, $hash:ident, $value:expr)    => { $hash = $value.fold($hash); };
    (nested($image:ident, $slot:ident), $hash:ident, $value:expr) => { $hash = $value.fold($hash); };
    (array($image:ident, $slot:ident, $len:expr), $hash:ident, $value:expr) => {
        for entry in &$value {
            $hash = entry.fold($hash);
        }
    };
}

/// The multiplier of the FNV-1a fold the digests here are.
///
/// A basis of zero rather than FNV's own, which is the one deviation and is
/// load-bearing: folding a zero byte into a zero hash leaves it zero, so an
/// all-zero image digests to zero and a zeroed region is a coherent image
/// rather than one every reader refuses.
const DIGEST_PRIME: u32 = 0x0100_0193;

/// Fold `bytes` into a running digest.
pub(crate) fn fold_bytes(hash: u32, bytes: &[u8]) -> u32 {
    let mut hash = hash;
    for byte in bytes {
        hash = (hash ^ u32::from(*byte)).wrapping_mul(DIGEST_PRIME);
    }
    hash
}

/// Declare a shared-memory image, its atomic mirror, and the assertions that
/// hold the two byte-identical.
///
/// The header names both types, the image's size and its alignment; each field
/// names the offset it sits at. Everything a reader needs to answer "what is at
/// offset 12" is in the one list, and everything the compiler needs to refuse a
/// list that is wrong is there with it.
///
/// The field kinds, which are the whole vocabulary:
///
/// * `byte`, `half` and `word` — a `u8`, a little-endian `u16` and a
///   little-endian `u32`.
/// * `bytes(N)` — `N` bytes that mean something, and `padding(N)` — `N` that
///   mean nothing.
/// * `identifier` — the log record ABI's own text slot, rather than a second
///   one beside it.
/// * `nested(Image, Slot)` and `array(Image, Slot, N)` — another declared image,
///   once or `N` times.
macro_rules! shared_image {
    (
        $(#[$image_meta:meta])*
        $image:ident mirrored by $slot:ident, $size:literal bytes aligned $align:literal {
            $(
                $(#[$field_meta:meta])*
                @$offset:literal $field:ident: $kind:ident $(($($arg:tt)*))?,
            )+
        }
    ) => {
        $(#[$image_meta])*
        #[repr(C)]
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub struct $image {
            $(
                $(#[$field_meta])*
                pub $field: $crate::image::image_type!($kind $(($($arg)*))?),
            )+
        }

        impl $image {
            /// Every byte zero, which is what an unwritten region holds.
            pub const ZERO: Self = Self {
                $( $field: $crate::image::image_zero!($kind $(($($arg)*))?), )+
            };
        }

        #[repr(C)]
        struct $slot {
            $( $field: $crate::image::slot_type!($kind $(($($arg)*))?), )+
        }

        impl $slot {
            const fn zero() -> Self {
                Self {
                    $( $field: $crate::image::slot_zero!($kind $(($($arg)*))?), )+
                }
            }

            fn store(&self, image: &$image) {
                $( $crate::image::slot_store!($kind $(($($arg)*))?, self.$field, image.$field); )+
            }

            fn load(&self) -> $image {
                $image {
                    $(
                        $field: $crate::image::slot_load!($kind $(($($arg)*))?, self.$field),
                    )+
                }
            }
        }

        impl $image {
            /// Fold every byte this image carries into `hash`, in region order.
            ///
            /// Emitted from the same declaration the layout is, so a field added
            /// to the byte map joins the fold with it: a digest that could be
            /// left short of a field would be a digest an image can differ
            /// outside.
            pub(crate) fn fold(&self, hash: u32) -> u32 {
                let mut hash = hash;
                $( $crate::image::image_fold!($kind $(($($arg)*))?, hash, self.$field); )+
                hash
            }
        }

        // The declaration is the authority on the layout and this is what
        // refuses one that lies: a field reordered, a width changed or a
        // padding byte miscounted is a compile error here rather than a silent
        // break of the image the reading domain maps. The mirror is held to the
        // same offsets rather than to the image's, so neither can drift from
        // the declaration by agreeing with the other.
        const _: () = {
            assert!(::core::mem::size_of::<$image>() == $size);
            assert!(::core::mem::align_of::<$image>() == $align);
            assert!(::core::mem::size_of::<$slot>() == $size);
            assert!(::core::mem::align_of::<$slot>() == $align);
            $(
                assert!(::core::mem::offset_of!($image, $field) == $offset);
                assert!(::core::mem::offset_of!($slot, $field) == $offset);
            )+
        };
    };
}

/// Declare a value that survived checking: private fields, no public
/// constructor, and one reader per field.
///
/// The shape is the whole guarantee — holding one of these *is* the proof that
/// the bytes were checked, because nothing outside this crate can build one —
/// and the readers that carry it are a transcription of the field list. The
/// list is what a reader of the checking step needs; the readers are what the
/// compiler needs, so only one of the two is written by hand.
macro_rules! checked_value {
    (
        $(#[$value_meta:meta])*
        $value:ident {
            $(
                $(#[$field_meta:meta])*
                $field:ident: $type:ty,
            )+
        }
    ) => {
        $(#[$value_meta])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub struct $value {
            $($field: $type,)+
        }

        impl $value {
            $(
                $(#[$field_meta])*
                #[must_use]
                pub const fn $field(&self) -> $type {
                    self.$field
                }
            )+
        }
    };
}

pub(crate) use {
    checked_value, image_fold, image_type, image_zero, shared_image, slot_load, slot_store,
    slot_type, slot_zero,
};
