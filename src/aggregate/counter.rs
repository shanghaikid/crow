use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// A sliding-window byte counter that tracks bytes over configurable time windows.
/// Maintains per-second samples and computes rates over 1s, 5s, and 30s windows.
pub struct RollingCounter {
    samples: VecDeque<(Instant, u64)>,
    max_window: Duration,
}

impl RollingCounter {
    pub fn new() -> Self {
        Self {
            samples: VecDeque::new(),
            max_window: Duration::from_secs(30),
        }
    }

    /// Record bytes at the current instant.
    pub fn add(&mut self, bytes: u64, now: Instant) {
        self.samples.push_back((now, bytes));
        self.prune(now);
    }

    /// Bytes per second over the last `window` duration.
    pub fn rate(&self, window: Duration, now: Instant) -> f64 {
        let cutoff = now - window;
        let total: u64 = self
            .samples
            .iter()
            .filter(|(t, _)| *t >= cutoff)
            .map(|(_, b)| b)
            .sum();
        let secs = window.as_secs_f64();
        if secs > 0.0 {
            total as f64 / secs
        } else {
            0.0
        }
    }

    /// Total bytes recorded within the max window.
    #[allow(dead_code)]
    pub fn total_in_window(&self, window: Duration, now: Instant) -> u64 {
        let cutoff = now - window;
        self.samples
            .iter()
            .filter(|(t, _)| *t >= cutoff)
            .map(|(_, b)| b)
            .sum()
    }

    /// Rate over the last 1 second.
    pub fn rate_1s(&self, now: Instant) -> f64 {
        self.rate(Duration::from_secs(1), now)
    }

    /// Rate over the last 5 seconds.
    #[allow(dead_code)]
    pub fn rate_5s(&self, now: Instant) -> f64 {
        self.rate(Duration::from_secs(5), now)
    }

    fn prune(&mut self, now: Instant) {
        let cutoff = now - self.max_window;
        while let Some((t, _)) = self.samples.front() {
            if *t < cutoff {
                self.samples.pop_front();
            } else {
                break;
            }
        }
    }
}

impl Default for RollingCounter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_counter() {
        let counter = RollingCounter::new();
        let now = Instant::now();
        assert_eq!(counter.rate_1s(now), 0.0);
        assert_eq!(counter.total_in_window(Duration::from_secs(1), now), 0);
    }

    #[test]
    fn test_add_and_rate() {
        let mut counter = RollingCounter::new();
        let now = Instant::now();
        counter.add(1000, now);
        // 1000 bytes in 1 second window = 1000 bytes/sec
        assert_eq!(counter.rate_1s(now), 1000.0);
    }

    #[test]
    fn test_windowed_rate() {
        let mut counter = RollingCounter::new();
        let start = Instant::now();
        // Add 1000 bytes at t=0
        counter.add(1000, start);
        // Query at t+2s: the sample is outside the 1s window
        let later = start + Duration::from_secs(2);
        assert_eq!(counter.rate_1s(later), 0.0);
        // But within the 5s window: 1000 bytes / 5s = 200 bytes/sec
        assert_eq!(counter.rate_5s(later), 200.0);
    }

    #[test]
    fn test_pruning() {
        let mut counter = RollingCounter::new();
        let start = Instant::now();
        counter.add(100, start);
        // Add sample well past the 30s max window
        let future = start + Duration::from_secs(31);
        counter.add(200, future);
        // Old sample should be pruned
        assert_eq!(counter.samples.len(), 1);
        assert_eq!(counter.total_in_window(Duration::from_secs(1), future), 200);
    }
}
