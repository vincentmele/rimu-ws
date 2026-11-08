//! Limits on what a peer can make a connection do (spec section 5.12), each with a production
//! default.

// One second, the window of the per-second budgets
const BUDGET_WINDOW_US: u64 = 1_000_000;
/// The window of [`QuicLimits::reset_budget`]: ten seconds.
pub(crate) const RESET_WINDOW_US: u64 = 10_000_000;

/// Bounds on the work and the memory that a peer can make a connection spend.
///
/// Every limit has a production default ([`QuicLimits::default`]).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuicLimits {
  /// The application error code of the CONNECTION_CLOSE that ends a connection whose peer went
  /// past a budget.
  ///
  /// Defaults to 0x0107, H3_EXCESSIVE_LOAD (RFC 9114 section 8.1): set it for other applications.
  pub excessive_load_app_code: u64,
  /// The most ranges of a received ACK frame that are processed. The ranges after them, which
  /// acknowledge the oldest packets, are ignored as if the frame did not have them.
  ///
  /// Defaults to 256.
  pub max_ack_ranges: usize,
  /// The most memory, in bytes, that the received stream data of a connection can take while it
  /// waits for earlier data or is retained by the application. It is held in blocks of 4 KiB,
  /// which count whole. Going past it is a connection error (PROTOCOL_VIOLATION).
  ///
  /// Defaults to 4 MiB.
  pub max_out_of_order_bytes_per_conn: u32,
  /// How far, in bytes, the received data of a stream that waits for earlier data can reach past
  /// the first byte that the application was not given, the bytes that it retains included.
  /// Going past it is a connection error (PROTOCOL_VIOLATION).
  ///
  /// Defaults to 256 KiB.
  pub max_out_of_order_bytes_per_stream: u32,
  /// The most separate ranges of received data that a stream holds while it waits for the data
  /// before them, at most 32. One more is a connection error (PROTOCOL_VIOLATION).
  ///
  /// Defaults to 32.
  pub max_out_of_order_ranges: u32,
  /// The most PING frames per second. Each one is acknowledged; one more closes the connection
  /// with [`Self::excessive_load_app_code`].
  ///
  /// Defaults to 64.
  pub ping_budget: u32,
  /// The most PATH_CHALLENGE frames per second. Each one is answered; one more closes the
  /// connection with [`Self::excessive_load_app_code`].
  ///
  /// Defaults to 16.
  pub path_challenge_budget: u32,
  /// The most streams that the peer abandons in ten seconds, counting the first RESET_STREAM and
  /// the first STOP_SENDING of each stream. One more closes the connection with
  /// [`Self::excessive_load_app_code`] (the rapid reset attack).
  ///
  /// Defaults to 100.
  pub reset_budget: u32,
}

impl Default for QuicLimits {
  #[inline]
  fn default() -> Self {
    Self {
      excessive_load_app_code: 0x0107,
      max_ack_ranges: 256,
      max_out_of_order_bytes_per_conn: 4 << 20,
      max_out_of_order_bytes_per_stream: 256 << 10,
      max_out_of_order_ranges: 32,
      ping_budget: 64,
      path_challenge_budget: 16,
      reset_budget: 100,
    }
  }
}

/// Counts the uses of something that a budget per window of time limits.
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
    self.take_within(budget, BUDGET_WINDOW_US, now_us)
  }

  /// [`Self::take`] with windows of `window_us`.
  #[inline]
  pub(crate) fn take_within(&mut self, budget: u32, window_us: u64, now_us: u64) -> bool {
    // A window starts with its first use, or when the clock went back (which wraps the
    // difference)
    if self.used == 0 || now_us.wrapping_sub(self.window_start_us) >= window_us {
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
  use crate::quic::limits::{QuicLimits, RESET_WINDOW_US, RateBudget};

  #[test]
  fn defaults_are_the_documented_ones() {
    let limits = QuicLimits::default();
    assert_eq!(limits.excessive_load_app_code, 0x0107);
    assert_eq!(limits.max_ack_ranges, 256);
    assert_eq!(limits.max_out_of_order_bytes_per_conn, 4 << 20);
    assert_eq!(limits.max_out_of_order_bytes_per_stream, 256 << 10);
    assert_eq!(limits.max_out_of_order_ranges, 32);
    assert_eq!(limits.ping_budget, 64);
    assert_eq!(limits.path_challenge_budget, 16);
    assert_eq!(limits.reset_budget, 100);
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

  #[test]
  fn rate_budget_takes_a_window_length() {
    let mut budget = RateBudget::default();
    assert!(budget.take_within(2, RESET_WINDOW_US, 0));
    assert!(budget.take_within(2, RESET_WINDOW_US, 5_000_000));
    assert!(!budget.take_within(2, RESET_WINDOW_US, RESET_WINDOW_US - 1));
    assert!(budget.take_within(2, RESET_WINDOW_US, RESET_WINDOW_US));
  }
}
