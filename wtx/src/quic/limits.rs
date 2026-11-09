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
  /// The most bytes of received stream data that a connection holds while they wait for earlier
  /// data or are retained by the application. The credit of the connection that is given to the
  /// peer is at most this, so that a peer within its credit never goes past it: going past the
  /// credit is a FLOW_CONTROL_ERROR. The data is held in blocks of 4 KiB, which count whole: on
  /// top of this, each stream that holds blocks may take four more, the blocks at the edges of its
  /// data, one for retained bytes and one that the ranges of its waiting data spill into.
  ///
  /// Outside of this cap, each stream with waiting data also holds an index of its blocks with
  /// room for all that it can hold: 16 bytes per 4 KiB of
  /// [`Self::max_out_of_order_bytes_per_stream`] (about 4.1 KiB at the default), for as long as
  /// data waits. The blocks and indexes go back to pools of the worker, whose free lists keep at
  /// most 1,024 entries each, the high-water ones, until the worker is idle.
  ///
  /// Defaults to 16 MiB, the connection window.
  pub max_out_of_order_bytes_per_conn: u32,
  /// How far, in bytes, the received data of a stream can reach past the first byte that the
  /// application consumed, the bytes that wait for earlier data and the ones that it retains
  /// included. The credit of each stream that is given to the peer is at most this, so that a
  /// peer within its credit never goes past it: going past the credit is a FLOW_CONTROL_ERROR.
  ///
  /// Defaults to 1 MiB, the stream window.
  pub max_out_of_order_bytes_per_stream: u32,
  /// The most separate ranges of received data that a stream holds while it waits for the data
  /// before them, at most 256: 32 inline, the others in a block of 4 KiB that counts like a block
  /// of data. One more is a connection error (PROTOCOL_VIOLATION).
  ///
  /// Defaults to 256, so that a peer that loses many packets of one flight is never closed.
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
      max_out_of_order_bytes_per_conn: 16 << 20,
      max_out_of_order_bytes_per_stream: 1 << 20,
      max_out_of_order_ranges: 256,
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
    assert_eq!(limits.max_out_of_order_bytes_per_conn, 16 << 20);
    assert_eq!(limits.max_out_of_order_bytes_per_stream, 1 << 20);
    assert_eq!(limits.max_out_of_order_ranges, 256);
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
