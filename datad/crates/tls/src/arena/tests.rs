use proptest::prelude::*;

use super::{ArenaExhausted, Bump, MAX_ALIGN};

#[test]
fn a_fresh_arena_has_all_of_its_room_and_none_of_it_used() {
    let arena = Bump::new(1024);
    assert_eq!(arena.capacity(), 1024);
    assert_eq!(arena.used(), 0);
    assert_eq!(arena.remaining(), 1024);
    assert_eq!(arena.high_water(), 0);
    assert_eq!(arena.refusals(), 0);
    assert_eq!(arena.mark(), 0);
}

#[test]
fn allocations_are_aligned_and_do_not_overlap() {
    let arena = Bump::new(1024);
    let first = arena.allocate(3, 1).expect("room");
    let second = arena.allocate(3, 16).expect("room");
    let third = arena.allocate(3, 8).expect("room");
    assert_eq!(first, 0);
    assert_eq!(second % 16, 0);
    assert_eq!(third % 8, 0);
    assert!(first + 3 <= second);
    assert!(second + 3 <= third);
}

#[test]
fn exhaustion_is_a_typed_refusal_naming_what_was_asked_for_and_what_was_left() {
    let arena = Bump::new(64);
    arena.allocate(48, 1).expect("room");
    assert_eq!(
        arena.allocate(32, 1),
        Err(ArenaExhausted {
            requested: 32,
            remaining: 16,
        })
    );
    assert_eq!(arena.refusals(), 1);
    // A refusal changes nothing: the next request that does fit still fits.
    assert_eq!(arena.used(), 48);
    assert!(arena.allocate(16, 1).is_ok());
    assert_eq!(arena.remaining(), 0);
}

#[test]
fn an_alignment_past_the_page_is_refused_rather_than_served_wrongly() {
    let arena = Bump::new(1 << 20);
    for align in [0_usize, 3, MAX_ALIGN * 2, usize::MAX] {
        assert!(
            arena.allocate(8, align).is_err(),
            "alignment {align} was served"
        );
    }
    assert_eq!(arena.refusals(), 4);
    assert!(arena.allocate(8, MAX_ALIGN).is_ok());
}

#[test]
fn an_allocation_that_would_wrap_the_address_space_is_refused() {
    let arena = Bump::new(usize::MAX);
    arena.allocate(64, 1).expect("room");
    assert!(arena.allocate(usize::MAX, 1).is_err());
    assert!(arena.allocate(usize::MAX - 1, MAX_ALIGN).is_err());
}

#[test]
fn releasing_the_top_block_recovers_it_and_releasing_another_does_not() {
    let arena = Bump::new(256);
    let first = arena.allocate(32, 1).expect("room");
    let second = arena.allocate(32, 1).expect("room");
    arena.release(first, 32);
    assert_eq!(arena.used(), 64, "a buried block was recovered");
    arena.release(second, 32);
    assert_eq!(arena.used(), 32, "the top block was not recovered");
    arena.release(first, 32);
    assert_eq!(arena.used(), 0);
    // A release naming a block that would overflow is ignored rather than
    // wrapping into a cursor that hands out bytes twice.
    arena.release(usize::MAX, 8);
    assert_eq!(arena.used(), 0);
}

#[test]
fn growing_the_top_block_moves_the_cursor_and_growing_another_refuses() {
    let arena = Bump::new(256);
    let first = arena.allocate(32, 1).expect("room");
    assert!(arena.grow_in_place(first, 32, 64));
    assert_eq!(arena.used(), 64);
    let second = arena.allocate(32, 1).expect("room");
    assert!(!arena.grow_in_place(first, 64, 128), "a buried block grew");
    assert!(arena.grow_in_place(second, 32, 64));
    assert_eq!(arena.used(), 128);
    assert!(
        !arena.grow_in_place(second, 64, 1024),
        "a block grew past the arena"
    );
    assert!(
        !arena.grow_in_place(second, 64, usize::MAX),
        "a growth that wraps was allowed"
    );
    assert_eq!(arena.used(), 128);
}

#[test]
fn a_reset_returns_to_a_mark_and_never_moves_forward() {
    let arena = Bump::new(256);
    arena.allocate(32, 1).expect("room");
    let mark = arena.mark();
    arena.allocate(64, 1).expect("room");
    assert_eq!(arena.used(), 96);
    arena.reset_to(mark);
    assert_eq!(arena.used(), 32);
    // A mark past the cursor is ignored: obeying it would hand out bytes that
    // are already in use.
    arena.reset_to(200);
    assert_eq!(arena.used(), 32);
    arena.reset_to(0);
    assert_eq!(arena.used(), 0);
}

#[test]
fn the_high_water_mark_records_the_peak_and_a_reset_does_not_lower_it() {
    let arena = Bump::new(256);
    arena.allocate(128, 1).expect("room");
    assert_eq!(arena.high_water(), 128);
    arena.reset_to(0);
    assert_eq!(arena.high_water(), 128, "a reset erased the measurement");
    arena.allocate(64, 1).expect("room");
    assert_eq!(arena.high_water(), 128);
    arena.allocate(192, 1).expect("room");
    assert_eq!(arena.high_water(), 256);
}

#[test]
fn a_zero_byte_allocation_is_served_and_takes_nothing() {
    let arena = Bump::new(16);
    let first = arena.allocate(0, 1).expect("room for nothing");
    let second = arena.allocate(0, 1).expect("room for nothing");
    assert_eq!(first, second);
    assert_eq!(arena.used(), 0);
}

proptest! {
    /// Arbitrary traffic against the invariant that matters: the cursor never
    /// passes the capacity, so no offset this ever hands out lies outside the
    /// region a caller paired it with.
    #[test]
    fn the_cursor_never_leaves_the_region(
        capacity in 0_usize..4096,
        requests in proptest::collection::vec((0_usize..512, 0_u32..13), 0..64),
    ) {
        let arena = Bump::new(capacity);
        for (size, shift) in requests {
            let align = 1_usize << shift;
            if let Ok(offset) = arena.allocate(size, align) {
                prop_assert!(offset % align == 0);
                prop_assert!(offset.saturating_add(size) <= capacity);
            }
            prop_assert!(arena.used() <= capacity);
            prop_assert!(arena.high_water() <= capacity);
            prop_assert_eq!(arena.remaining(), capacity - arena.used());
        }
    }

    /// A release-then-allocate cycle at the top never loses ground: the arena
    /// returns to where it was.
    #[test]
    fn releasing_the_top_is_the_inverse_of_allocating_it(
        size in 1_usize..256,
        shift in 0_u32..5,
    ) {
        let arena = Bump::new(1024);
        let before = arena.used();
        let align = 1_usize << shift;
        let offset = arena.allocate(size, align).expect("a fresh arena has room");
        arena.release(offset, size);
        prop_assert_eq!(arena.used(), before);
    }
}
