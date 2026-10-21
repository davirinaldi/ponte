//! The monotonic clock of Windows that also counts the time the machine slept
//! (`QueryInterruptTime`), so the clock's high-water mark keeps up across a sleep
//! (ADR-0010).

use std::time::Duration;

use windows_sys::Win32::System::WindowsProgramming::QueryInterruptTime;

/// Time since the machine started, sleep included.
pub(crate) fn interrupt_time() -> Duration {
    let mut ticks = 0_u64;
    // SAFETY: `ticks` is a valid place for the answer, in units of 100 ns.
    unsafe { QueryInterruptTime(&mut ticks) };
    Duration::from_nanos(ticks.saturating_mul(100))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_interrupt_time_moves_forward_with_the_clock() {
        let first = interrupt_time();
        std::thread::sleep(Duration::from_millis(50));
        let passed = interrupt_time() - first;
        assert!(passed >= Duration::from_millis(40), "{passed:?}");
        assert!(passed < Duration::from_secs(5), "{passed:?}");
    }
}
