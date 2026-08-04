use proptest::prelude::*;

use super::Utc;

#[test]
fn the_epoch_and_the_dates_around_it_convert() {
    for (seconds, expected) in [
        (
            0_i64,
            Utc {
                year: 1970,
                month: 1,
                day: 1,
                hour: 0,
                minute: 0,
                second: 0,
            },
        ),
        (
            86_399,
            Utc {
                year: 1970,
                month: 1,
                day: 1,
                hour: 23,
                minute: 59,
                second: 59,
            },
        ),
        (
            86_400,
            Utc {
                year: 1970,
                month: 1,
                day: 2,
                hour: 0,
                minute: 0,
                second: 0,
            },
        ),
        (
            -1,
            Utc {
                year: 1969,
                month: 12,
                day: 31,
                hour: 23,
                minute: 59,
                second: 59,
            },
        ),
        // A leap day, and the day after it.
        (
            951_782_400,
            Utc {
                year: 2000,
                month: 2,
                day: 29,
                hour: 0,
                minute: 0,
                second: 0,
            },
        ),
        (
            951_868_800,
            Utc {
                year: 2000,
                month: 3,
                day: 1,
                hour: 0,
                minute: 0,
                second: 0,
            },
        ),
        // 2100 is not a leap year, which the century rule is what decides: the
        // day this instant names is the last of February and not the 29th.
        (
            4_107_456_000,
            Utc {
                year: 2100,
                month: 2,
                day: 28,
                hour: 0,
                minute: 0,
                second: 0,
            },
        ),
        (
            1_784_000_000,
            Utc {
                year: 2026,
                month: 7,
                day: 14,
                hour: 3,
                minute: 33,
                second: 20,
            },
        ),
    ] {
        assert_eq!(Utc::from_unix_seconds(seconds), expected, "{seconds}");
    }
}

#[test]
fn a_utc_time_is_the_thirteen_characters_the_encoding_names() {
    assert_eq!(
        Utc::from_unix_seconds(1_784_000_000)
            .to_utc_time()
            .expect("inside the window"),
        *b"260714033320Z"
    );
    assert_eq!(
        Utc::from_unix_seconds(0).to_utc_time().expect("inside"),
        *b"700101000000Z"
    );
}

#[test]
fn a_year_outside_the_two_digit_window_is_refused_and_names_itself() {
    // 1949 and 2050 are the first years either side of what two digits name
    // without ambiguity, and both must be refused rather than written.
    assert_eq!(
        Utc::from_unix_seconds(-662_688_000).to_utc_time(),
        Err(1949)
    );
    assert_eq!(
        Utc::from_unix_seconds(2_524_608_000).to_utc_time(),
        Err(2050)
    );
    // And the years either side of those are accepted.
    assert!(Utc::from_unix_seconds(-631_152_000).to_utc_time().is_ok());
    assert!(Utc::from_unix_seconds(2_493_072_000).to_utc_time().is_ok());
}

proptest! {
    /// Every instant converts to a civil time whose fields are in range, and
    /// never panics.
    #[test]
    fn every_instant_has_a_civil_time(seconds in i64::MIN / 2..i64::MAX / 2) {
        let utc = Utc::from_unix_seconds(seconds);
        prop_assert!((1..=12).contains(&utc.month));
        prop_assert!((1..=31).contains(&utc.day));
        prop_assert!(utc.hour < 24);
        prop_assert!(utc.minute < 60);
        prop_assert!(utc.second < 60);
    }

    /// Inside the encodable window, a rendering is thirteen ASCII digits and a
    /// `Z`, and it round-trips back to the same civil time.
    #[test]
    fn a_rendering_is_digits_and_a_zulu(seconds in -631_152_000_i64..2_493_072_000) {
        let utc = Utc::from_unix_seconds(seconds);
        let rendered = utc.to_utc_time().expect("inside the window");
        prop_assert_eq!(rendered[12], b'Z');
        prop_assert!(rendered[..12].iter().all(u8::is_ascii_digit));
        let year = 1900 + i64::from(rendered[0] - b'0') * 10 + i64::from(rendered[1] - b'0');
        let year = if year < 1950 { year + 100 } else { year };
        prop_assert_eq!(year, utc.year);
    }

    /// One second later is never one second earlier.
    #[test]
    fn time_moves_forward(seconds in 0_i64..4_000_000_000) {
        let now = Utc::from_unix_seconds(seconds);
        let later = Utc::from_unix_seconds(seconds + 1);
        let key = |t: Utc| (t.year, t.month, t.day, t.hour, t.minute, t.second);
        prop_assert!(key(later) > key(now));
    }
}
