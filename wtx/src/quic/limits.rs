//! Limits on what a peer can make a connection do (spec section 5.12), each with a production
//! default.

// One second, the window of the per-second budgets
const BUDGET_WINDOW_US: u64 = 1_000_000;

/// Bounds on the work and the memory that a peer can make a connection spend.
///
/// Every limit has a production default ([`QuicLimits::default`]).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuicLimits {
  /// The most ranges of a received ACK frame that are processed. The ranges after them, which
  /// acknowledge the oldest packets, are ignored as if the frame did not have them.
  ///
  /// Defaults to 256.
  pub max_ack_ranges: usize,
  /// The most PING frames per second that make their packet ack-eliciting. A PING past the budget
  /// is ignored: its packet is still acknowledged, along with the next ack-eliciting one.
  ///
  /// Defaults to 64.
  pub ping_budget: u32,
  /// The most PATH_CHALLENGE frames per second that are answered. A challenge past the budget is
  /// ignored.
  ///
  /// Defaults to 16.
  pub path_challenge_budget: u32,
}

impl Default for QuicLimits {
  #[inline]
  fn default() -> Self {
    Self { max_ack_ranges: 256, ping_budget: 64, path_challenge_budget: 16 }
  }
}

/// Counts the uses of something that a budget per second limits.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct RateBudget {
  used: u32,
  window_start_us: u64,
}

impl RateBudget {
  /// Takes one use out of `budget` at `now_us`: `false` if the budget of the current window is
  /// spent. A window lasts one second from its first use.
  #[inline]
  pub(crate) fn take(&mut self, budget: u32, now_us: u64) -> bool {
    // A window starts with its first use, or when the clock went back (which wraps the
    // difference)
    if self.used == 0 || now_us.wrapping_sub(self.window_start_us) >= BUDGET_WINDOW_US {
      self.window_start_us = now_us;
      self.used = 0;
    }
    if self.used >= budget {
      return false;
    }
    self.used = self.used.wrapping_add(1);
    true
  }
}

#[cfg(test)]
mod tests {
  use crate::quic::limits::{QuicLimits, RateBudget};

  #[test]
  fn defaults_are_the_documented_ones() {
    let limits = QuicLimits::default();
    assert_eq!(limits.max_ack_ranges, 256);
    assert_eq!(limits.ping_budget, 64);
    assert_eq!(limits.path_challenge_budget, 16);
  }

  #[test]
  fn rate_budget_refills_each_second() {
    let mut budget = RateBudget::default();
    for _ in 0..3 {
      assert!(budget.take(3, 10));
    }
    assert!(!budget.take(3, 500_000));
    assert!(!budget.take(3, 1_000_009));
    // A new window starts one second after the first use of the previous one
    assert!(budget.take(3, 1_000_010));
    assert!(budget.take(3, 1_000_011));
    assert!(budget.take(3, 1_000_012));
    assert!(!budget.take(3, 1_000_013));
    // A budget of zero allows nothing
    assert!(!RateBudget::default().take(0, 5));
  }
}
