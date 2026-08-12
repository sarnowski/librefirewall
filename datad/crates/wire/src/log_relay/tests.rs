use super::*;
use std::vec::Vec;

/// A line of `len` printable bytes, distinguishable from every other.
fn line(mark: u8, len: usize) -> Vec<u8> {
    core::iter::repeat_n(mark, len).collect()
}

#[test]
fn the_region_is_one_page_and_holds_every_slot_that_fits() {
    assert_eq!(LOG_RELAY_REGION_SIZE, MAPPING_ALIGN);
    assert!(size_of::<LogRelay>() <= MAPPING_ALIGN);
    // One more slot would not fit, which is what "every slot that fits" means.
    assert!(
        RELAY_RING_HEADER_BYTES + (LOG_RELAY_SLOTS as usize + 1) * size_of::<LineSlot>()
            > MAPPING_ALIGN
    );
}

#[test]
fn a_published_line_reads_back_whole() {
    let relay = LogRelay::zero();
    let consume = LogRelayConsume::zero();
    let mut writer = relay.writer(&consume);
    let mut reader = consume.reader(&relay);
    let text = line(b'a', 100);
    assert!(writer.publish(7, Some(1_234), &text));
    let mut into = [0u8; RELAY_LINE_BYTES];
    let read = reader.read(&mut into).expect("a published line");
    assert_eq!(read.origin, 7);
    assert_eq!(read.unix_nanos, 1_234);
    assert_eq!(read.flags, FLAG_STAMPED);
    assert_eq!(read.len, 100);
    assert_eq!(into.get(..read.len), Some(&text[..]));
}

#[test]
fn an_unstamped_line_carries_no_instant_and_says_so() {
    let relay = LogRelay::zero();
    let consume = LogRelayConsume::zero();
    let mut writer = relay.writer(&consume);
    let mut reader = consume.reader(&relay);
    assert!(writer.publish(0, None, b"LFW-PD time=unsynchronized"));
    let mut into = [0u8; RELAY_LINE_BYTES];
    let read = reader.read(&mut into).expect("a published line");
    assert_eq!(read.flags & FLAG_STAMPED, 0);
    assert_eq!(read.unix_nanos, 0);
}

#[test]
fn an_empty_relay_reads_nothing() {
    let relay = LogRelay::zero();
    let consume = LogRelayConsume::zero();
    let mut reader = consume.reader(&relay);
    let mut into = [0u8; RELAY_LINE_BYTES];
    assert_eq!(reader.read(&mut into), None);
}

/// The hard requirement: a relay nobody drains costs a counted drop and never a
/// wait. Every publish answers, and the console's own write does not depend on
/// which answer it got.
#[test]
fn a_full_relay_refuses_the_newest_line_and_counts_it() {
    let relay = LogRelay::zero();
    let consume = LogRelayConsume::zero();
    let mut writer = relay.writer(&consume);
    for index in 0..writer.capacity() {
        assert!(
            writer.publish(0, None, &line(b'a', 8)),
            "slot {index} of the capacity was refused"
        );
    }
    assert_eq!(writer.dropped(), 0);
    for expected in 1..=5 {
        assert!(!writer.publish(0, None, b"refused"));
        assert_eq!(writer.dropped(), expected);
    }
    // And the reader sees the console's own claim about what it refused.
    let reader = consume.reader(&relay);
    assert_eq!(reader.dropped_by_writer(), 5);
}

/// A drained slot is reusable, so a relay that keeps up drops nothing however
/// many lines pass through it.
#[test]
fn a_drained_relay_never_fills() {
    let relay = LogRelay::zero();
    let consume = LogRelayConsume::zero();
    let mut writer = relay.writer(&consume);
    let mut reader = consume.reader(&relay);
    let mut into = [0u8; RELAY_LINE_BYTES];
    for round in 0..(LOG_RELAY_SLOTS * 7) {
        let text = line(b'a' + (round % 26) as u8, 1 + (round as usize % 200));
        assert!(writer.publish(0, None, &text));
        let read = reader.read(&mut into).expect("the line just published");
        assert_eq!(into.get(..read.len), Some(&text[..]));
    }
    assert_eq!(writer.dropped(), 0);
}

/// The tail of a longer line must not survive a shorter one into the same slot:
/// a reader would attribute bytes to a line that never carried them.
#[test]
fn a_shorter_line_leaves_no_tail_of_the_one_before_it() {
    let relay = LogRelay::zero();
    let consume = LogRelayConsume::zero();
    let mut writer = relay.writer(&consume);
    let mut reader = consume.reader(&relay);
    let mut into = [0u8; RELAY_LINE_BYTES];
    let long = line(b'L', RELAY_LINE_BYTES);
    for _ in 0..LOG_RELAY_SLOTS {
        assert!(writer.publish(0, None, &long));
        reader.read(&mut into).expect("the long line");
    }
    assert!(writer.publish(0, None, b"short"));
    let read = reader.read(&mut into).expect("the short line");
    assert_eq!(read.len, 5);
    assert_eq!(into.get(..5), Some(&b"short"[..]));
    assert!(
        into.iter().skip(5).all(|byte| *byte == 0),
        "the slot still holds the longer line's tail"
    );
}

/// The longest line the console grammar renders crosses whole, which is the
/// property that keeps a refusal line — the widest shape there is — out of the
/// drop count.
#[test]
fn the_widest_line_crosses_whole() {
    let relay = LogRelay::zero();
    let consume = LogRelayConsume::zero();
    let mut writer = relay.writer(&consume);
    let mut reader = consume.reader(&relay);
    let text = line(b'~', RELAY_LINE_BYTES);
    assert!(writer.publish(9, Some(u64::MAX), &text));
    let mut into = [0u8; RELAY_LINE_BYTES];
    let read = reader.read(&mut into).expect("a published line");
    assert_eq!(read.len, RELAY_LINE_BYTES);
    assert_eq!(into.as_slice(), &text[..]);
}

/// Unreachable from first-party code and still total: a line past the slot is
/// stated as what was written, never as what was offered.
#[test]
fn a_line_past_the_slot_is_stated_as_what_crossed() {
    let relay = LogRelay::zero();
    let consume = LogRelayConsume::zero();
    let mut writer = relay.writer(&consume);
    let mut reader = consume.reader(&relay);
    let text = line(b'x', RELAY_LINE_BYTES + 64);
    assert!(writer.publish(0, None, &text));
    let mut into = [0u8; RELAY_LINE_BYTES];
    let read = reader.read(&mut into).expect("a published line");
    assert_eq!(read.len, RELAY_LINE_BYTES);
}

/// A cursor no correct peer writes is an index of the array and never a fault:
/// the remainder is what makes that true for every `u32` there is.
#[test]
fn every_cursor_a_peer_can_forge_names_a_slot() {
    let relay = LogRelay::zero();
    for at in [0u32, 1, LOG_RELAY_SLOTS - 1, LOG_RELAY_SLOTS, u32::MAX] {
        assert!(relay.slot(at).is_some(), "cursor {at} named no slot");
    }
}

/// The half of the protocol a batch rests on: peeking reads without releasing,
/// so a batch the recording defers costs no line at all.
#[test]
fn a_peeked_batch_is_still_there_when_it_is_abandoned() {
    let relay = LogRelay::zero();
    let consume = LogRelayConsume::zero();
    let mut writer = relay.writer(&consume);
    let mut reader = consume.reader(&relay);
    for mark in [b'a', b'b', b'c'] {
        assert!(writer.publish(0, None, &line(mark, 4)));
    }
    let mut into = [0u8; RELAY_LINE_BYTES];
    assert_eq!(reader.queued(), 3);
    for at in 0..3 {
        let read = reader.peek(at, &mut into).expect("a queued line");
        assert_eq!(into.get(..read.len), Some(&line(b'a' + at as u8, 4)[..]));
    }
    assert_eq!(reader.peek(3, &mut into), None);
    // Abandoned: nothing was released, so the same three are still queued.
    assert_eq!(reader.queued(), 3);
    assert_eq!(reader.consume(3), 3);
    assert_eq!(reader.queued(), 0);
    assert_eq!(reader.peek(0, &mut into), None);
}

/// Releasing more than is queued releases what is queued: a caller that lost
/// count never advances over a slot the console has yet to fill.
#[test]
fn releasing_is_bounded_by_what_is_queued() {
    let relay = LogRelay::zero();
    let consume = LogRelayConsume::zero();
    let mut writer = relay.writer(&consume);
    let mut reader = consume.reader(&relay);
    assert!(writer.publish(0, None, b"one"));
    assert_eq!(reader.consume(u32::MAX), 1);
    assert_eq!(reader.queued(), 0);
    // And the console can still fill every slot afterwards, which it could not
    // if the cursor had run past its own.
    for _ in 0..writer.capacity() {
        assert!(writer.publish(0, None, b"after"));
    }
    assert_eq!(writer.dropped(), 0);
}

/// What is queued is never more than the relay holds, whatever cursor the
/// console publishes — which is what makes it safe to bound a batch by.
#[test]
fn what_is_queued_is_bounded_however_the_console_moves_its_cursor() {
    let relay = LogRelay::zero();
    let consume = LogRelayConsume::zero();
    let mut writer = relay.writer(&consume);
    let reader = consume.reader(&relay);
    for _ in 0..writer.capacity() {
        assert!(writer.publish(0, None, b"line"));
    }
    assert!(reader.queued() <= reader.capacity());
}
