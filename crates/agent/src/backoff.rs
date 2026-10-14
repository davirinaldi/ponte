//! How long to wait before connecting again (RNF-16).
//!
//! Exponential with full jitter: after `failures` failed attempts in a row the wait is a
//! random time between zero and `min(5 min, 1 s * 2^failures)`. The ceiling grows so a
//! server in trouble is left alone; the random part spreads a fleet that lost its
//! connection at the same instant over the whole window, instead of having it come back
//! as one wave against a server that admits a fixed number of handshakes at a time.

use std::time::Duration;

const BASE_MILLIS: u64 = 1_000;
const CAP_MILLIS: u64 = 5 * 60 * 1_000;

/// The longest wait after `failures` failed attempts in a row, in milliseconds.
fn ceiling_millis(failures: u32) -> u64 {
    // Past 63 the shift has no bits left, and well before that the product has none.
    let factor = 1_u64.checked_shl(failures).unwrap_or(u64::MAX);
    BASE_MILLIS.saturating_mul(factor).min(CAP_MILLIS)
}

/// The wait after `failures` failed attempts in a row. `random` is 64 random bits, or
/// `None` when the operating system had none to give: then the wait is the ceiling, the
/// slow side, because a fleet without jitter must at least not hurry.
pub(crate) fn delay(failures: u32, random: Option<u64>) -> Duration {
    let ceiling = ceiling_millis(failures);
    // The ceiling is at most five minutes in milliseconds, so the bias of taking a
    // remainder of 64 random bits is far below anything a fleet could notice.
    Duration::from_millis(random.map_or(ceiling, |random| random % (ceiling + 1)))
}

/// 64 random bits from the operating system.
pub(crate) fn random() -> Option<u64> {
    let mut bytes = [0; 8];
    getrandom::fill(&mut bytes).ok()?;
    Some(u64::from_le_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    const CAP: Duration = Duration::from_secs(5 * 60);

    fn ceiling(failures: u32) -> Duration {
        Duration::from_millis(ceiling_millis(failures))
    }

    #[test]
    fn the_ceiling_doubles_from_one_second_up_to_five_minutes() {
        let secs: Vec<u64> = (0..10).map(|n| ceiling(n).as_secs()).collect();
        assert_eq!(secs, [1, 2, 4, 8, 16, 32, 64, 128, 256, 300]);
        assert_eq!(ceiling(9), CAP);
    }

    /// The shift and the multiplication both overflow long before `u32::MAX` failures.
    #[test]
    fn no_number_of_failures_overflows() {
        for failures in [10, 31, 32, 53, 54, 55, 63, 64, 65, 1_000, u32::MAX] {
            assert_eq!(ceiling(failures), CAP, "{failures}");
            assert_eq!(delay(failures, None), CAP, "{failures}");
            assert!(delay(failures, Some(u64::MAX)) <= CAP, "{failures}");
        }
    }

    #[test]
    fn the_wait_is_anywhere_from_zero_to_the_ceiling() {
        for failures in [0, 1, 5, 9, 40] {
            let ceiling = ceiling(failures);
            let millis = u64::try_from(ceiling.as_millis()).unwrap();

            assert_eq!(delay(failures, Some(0)), Duration::ZERO);
            assert_eq!(delay(failures, Some(millis)), ceiling);
            assert_eq!(delay(failures, Some(millis + 1)), Duration::ZERO);
            assert_eq!(delay(failures, Some(millis / 2)), ceiling / 2);
            for random in [1, 999, 123_456_789, u64::MAX / 3, u64::MAX - 1, u64::MAX] {
                assert!(
                    delay(failures, Some(random)) <= ceiling,
                    "{failures} {random}"
                );
            }
        }
    }

    /// Jitter that always lands on the same value is no jitter.
    #[test]
    fn different_random_bits_give_different_waits() {
        let waits: std::collections::HashSet<Duration> = (0..1_000_u64)
            .map(|n| delay(6, Some(n.wrapping_mul(0x9e37_79b9_7f4a_7c15))))
            .collect();
        assert!(waits.len() > 900, "{}", waits.len());
    }

    #[test]
    fn without_random_bits_the_wait_is_the_ceiling() {
        assert_eq!(delay(0, None), Duration::from_secs(1));
        assert_eq!(delay(3, None), Duration::from_secs(8));
    }

    #[test]
    fn the_operating_system_gives_random_bits() {
        let draws: std::collections::HashSet<u64> = (0..8).filter_map(|_| random()).collect();
        assert!(draws.len() > 1);
    }
}
