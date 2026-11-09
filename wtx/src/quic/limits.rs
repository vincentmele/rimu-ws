//! The settings of a QUIC endpoint ([`QuicParams`]) and the limits on what a peer can make it do
//! (spec section 5.12, [`QuicLimits`]), each with a production default.

use crate::quic::ConnParams;

// One second, the window of the per-second budgets
const BUDGET_WINDOW_US: u64 = 1_000_000;
// RFC 9000 section 18.2: the largest ACK Delay Exponent and Max ACK Delay, the smallest Max UDP
// Payload Size
const MAX_ACK_DELAY_EXPONENT: u8 = 20;
const MAX_MAX_ACK_DELAY_MS: u64 = (1 << 14) - 1;
const MIN_UDP_PAYLOAD_SIZE: u64 = 1200;
// The windows of the index arrays of the streams of the peer
const MAX_STREAMS_BIDI: u64 = 256;
const MAX_STREAMS_UNI: u64 = 16;
/// The window of [`QuicLimits::reset_budget`]: ten seconds.
pub(crate) const RESET_WINDOW_US: u64 = 10_000_000;

/// Bounds on the work and the memory that a peer can make a connection, or a worker, spend.
///
/// Every limit has a production default ([`QuicLimits::default`]).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuicLimits {
  /// The application error code of the CONNECTION_CLOSE that ends a connection whose peer went
  /// past a budget.
  ///
  /// Defaults to 0x0107, H3_EXCESSIVE_LOAD (RFC 9114 section 8.1): set it for other applications.
  pub excessive_load_app_code: u64,
  /// The most handshakes that a worker has under way at once. The first Initial packet of one
  /// more client is dropped.
  ///
  /// Defaults to 256.
  pub max_half_open_per_worker: u32,
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
  /// The most NEW_CONNECTION_ID frames per second. One more closes the connection with
  /// [`Self::excessive_load_app_code`].
  ///
  /// Defaults to 16: a client sends one for each connection ID that it gives, and the server
  /// stores at most two.
  pub new_connection_id_budget: u32,
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
  /// The handshakes under way on a worker from which the first Initial packet of a client is
  /// answered with a Retry (RFC 9000 section 8.1.2): the client proves its address before a
  /// signature or a connection is spent on it.
  ///
  /// Defaults to 64: the 65th concurrent handshake gets a Retry.
  pub retry_above_half_open: u32,
  /// The application error code of the CONNECTION_CLOSE that ends every connection of an
  /// endpoint that shuts down.
  ///
  /// Defaults to 0x0100, H3_NO_ERROR (RFC 9114 section 8.1): set it for other applications.
  pub shutdown_app_code: u64,
  /// How long, in milliseconds, the connections of an endpoint that shuts down have to finish
  /// what is under way when their application drains them itself (HTTP/3 sends GOAWAY and lets
  /// the requests that it accepted finish). Those still open then are closed with
  /// [`Self::shutdown_app_code`].
  ///
  /// Defaults to 2,000.
  pub shutdown_grace_ms: u64,
  /// The most stateless resets that a worker sends per second (RFC 9000 section 10.3), and,
  /// apart from them, the most Version Negotiation packets.
  ///
  /// Defaults to 100.
  pub stateless_reset_per_sec: u32,
  /// The application error code of the RESET_STREAM and STOP_SENDING that refuse a stream of the
  /// peer when the worker has no room for another stream.
  ///
  /// Defaults to 0x010B, H3_REQUEST_REJECTED (RFC 9114 section 8.1): set it for other
  /// applications.
  pub stream_rejected_app_code: u64,
}

impl Default for QuicLimits {
  #[inline]
  fn default() -> Self {
    Self {
      excessive_load_app_code: 0x0107,
      max_half_open_per_worker: 256,
      max_ack_ranges: 256,
      max_out_of_order_bytes_per_conn: 16 << 20,
      max_out_of_order_bytes_per_stream: 1 << 20,
      max_out_of_order_ranges: 256,
      new_connection_id_budget: 16,
      ping_budget: 64,
      path_challenge_budget: 16,
      reset_budget: 100,
      retry_above_half_open: 64,
      shutdown_app_code: 0x0100,
      shutdown_grace_ms: 2_000,
      stateless_reset_per_sec: 100,
      stream_rejected_app_code: 0x010b,
    }
  }
}

/// The limits of [`QuicLimits`] that a connection applies itself, which each connection keeps:
/// those of the endpoint stay with the endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ConnLimits {
  /// See [`QuicLimits::excessive_load_app_code`].
  pub(crate) excessive_load_app_code: u64,
  /// See [`QuicLimits::max_ack_ranges`], at most `u32::MAX`.
  pub(crate) max_ack_ranges: u32,
  /// See [`QuicLimits::max_out_of_order_bytes_per_conn`].
  pub(crate) max_out_of_order_bytes_per_conn: u32,
  /// See [`QuicLimits::max_out_of_order_bytes_per_stream`].
  pub(crate) max_out_of_order_bytes_per_stream: u32,
  /// See [`QuicLimits::max_out_of_order_ranges`].
  pub(crate) max_out_of_order_ranges: u32,
  /// See [`QuicLimits::new_connection_id_budget`].
  pub(crate) new_connection_id_budget: u32,
  /// See [`QuicLimits::ping_budget`].
  pub(crate) ping_budget: u32,
  /// See [`QuicLimits::path_challenge_budget`].
  pub(crate) path_challenge_budget: u32,
  /// See [`QuicLimits::reset_budget`].
  pub(crate) reset_budget: u32,
  /// See [`QuicLimits::stream_rejected_app_code`].
  pub(crate) stream_rejected_app_code: u64,
}

impl Default for ConnLimits {
  #[inline]
  fn default() -> Self {
    QuicLimits::default().into()
  }
}

impl From<QuicLimits> for ConnLimits {
  #[inline]
  fn from(from: QuicLimits) -> Self {
    Self {
      excessive_load_app_code: from.excessive_load_app_code,
      max_ack_ranges: u32::try_from(from.max_ack_ranges).unwrap_or(u32::MAX),
      max_out_of_order_bytes_per_conn: from.max_out_of_order_bytes_per_conn,
      max_out_of_order_bytes_per_stream: from.max_out_of_order_bytes_per_stream,
      max_out_of_order_ranges: from.max_out_of_order_ranges,
      new_connection_id_budget: from.new_connection_id_budget,
      ping_budget: from.ping_budget,
      path_challenge_budget: from.path_challenge_budget,
      reset_budget: from.reset_budget,
      stream_rejected_app_code: from.stream_rejected_app_code,
    }
  }
}

/// The settings of a QUIC endpoint: its connections, their transport parameters, sending and
/// the placement of new connections on workers. [`Self::default`] has the library defaults.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuicParams {
  ack_delay_exponent: u8,
  balance: bool,
  bodies_round_robin: bool,
  cid_steering: bool,
  conn_window: u64,
  flush_in_slot_order: bool,
  handshake_timeout_ms: u64,
  limits: QuicLimits,
  max_ack_delay_ms: u64,
  max_conns_per_worker: u32,
  max_idle_timeout_ms: u64,
  max_in_flight: usize,
  max_streams_bidi: u64,
  max_streams_uni: u64,
  max_udp_payload_size: u64,
  pacing: bool,
  pmtu_probe_after_rtt: bool,
  stream_window: u64,
}

impl QuicParams {
  /// The exponent of the ACK Delay field of the ACK frames that are sent, at most 20.
  ///
  /// Defaults to 3.
  #[inline]
  pub const fn ack_delay_exponent(&self) -> u8 {
    self.ack_delay_exponent
  }

  /// If the first Initial packet of a client goes to the worker with the fewest connections,
  /// when that worker has fewer than the one that received it (spec section 5.11). Only with
  /// [`Self::cid_steering`]: without it the packets that follow would reach the first worker.
  ///
  /// Defaults to `true`.
  #[inline]
  pub const fn balance(&self) -> bool {
    self.balance
  }

  /// If the streams whose next bytes are a body sent by reference take turns, one STREAM frame
  /// each, instead of going one at a time to the end of their body in the order in which they
  /// were written (the bytes written by copy take turns either way).
  ///
  /// Defaults to `false`, one body to its end at a time (task 19 measures it).
  #[inline]
  pub const fn bodies_round_robin(&self) -> bool {
    self.bodies_round_robin
  }

  /// If the sockets of the workers steer packets by the first byte of their destination
  /// connection ID, which names the worker. While it is on, a connection has exactly one
  /// connection ID of the server and no NEW_CONNECTION_ID is sent, since connection IDs that name
  /// the same worker correlate (RFC 9000 section 5.1), and new connections are balanced
  /// ([`Self::balance`]). Off, new connections stay on the worker that the kernel picks; spare
  /// connection IDs are not issued yet, so a connection has one connection ID either way.
  ///
  /// Defaults to `true`.
  #[inline]
  pub const fn cid_steering(&self) -> bool {
    self.cid_steering
  }

  /// The receive window of a connection, in bytes.
  ///
  /// Defaults to 16 MiB.
  #[inline]
  pub const fn conn_window(&self) -> u64 {
    self.conn_window
  }

  /// If a flush writes the connections that have something to send in the order of their slots,
  /// instead of the order in which they came to have something to send.
  ///
  /// Defaults to `false`, the order of arrival (task 16 measures it).
  #[inline]
  pub const fn flush_in_slot_order(&self) -> bool {
    self.flush_in_slot_order
  }

  /// The time that a client has to complete its handshake, from its first Initial packet.
  ///
  /// Defaults to 10,000 ms.
  #[inline]
  pub const fn handshake_timeout_ms(&self) -> u64 {
    self.handshake_timeout_ms
  }

  /// See [`QuicLimits`].
  #[inline]
  pub const fn limits(&self) -> &QuicLimits {
    &self.limits
  }

  /// The most time that an acknowledgment is delayed, as advertised, below 16,384 ms.
  ///
  /// Defaults to 25 ms.
  #[inline]
  pub const fn max_ack_delay_ms(&self) -> u64 {
    self.max_ack_delay_ms
  }

  /// The most connections of a worker, those whose handshake is under way included. The cap of
  /// the process is this times the number of workers.
  ///
  /// Defaults to 4,096.
  #[inline]
  pub const fn max_conns_per_worker(&self) -> u32 {
    self.max_conns_per_worker
  }

  /// The idle timeout that is advertised, zero for none.
  ///
  /// Defaults to 30,000 ms.
  #[inline]
  pub const fn max_idle_timeout_ms(&self) -> u64 {
    self.max_idle_timeout_ms
  }

  /// The most bytes in flight on a connection, whatever its congestion window.
  ///
  /// Defaults to 256 KiB.
  #[inline]
  pub const fn max_in_flight(&self) -> usize {
    self.max_in_flight
  }

  /// The bidirectional streams that a client can open at once, at most 256.
  ///
  /// Defaults to 256.
  #[inline]
  pub const fn max_streams_bidi(&self) -> u64 {
    self.max_streams_bidi
  }

  /// The unidirectional streams that a client can open at once, at most 16.
  ///
  /// Defaults to 16.
  #[inline]
  pub const fn max_streams_uni(&self) -> u64 {
    self.max_streams_uni
  }

  /// The largest UDP payload that is received, at least 1,200 bytes.
  ///
  /// Defaults to 1,472, an Ethernet frame of IPv4.
  #[inline]
  pub const fn max_udp_payload_size(&self) -> u64 {
    self.max_udp_payload_size
  }

  /// If sending is paced over the round trip time.
  ///
  /// Defaults to `true`.
  #[inline]
  pub const fn pacing(&self) -> bool {
    self.pacing
  }

  /// If the first probe of path MTU discovery waits one smoothed RTT after the handshake is
  /// confirmed, instead of going with the first flush after it.
  ///
  /// Defaults to `false`, at once (task 19 measures it).
  #[inline]
  pub const fn pmtu_probe_after_rtt(&self) -> bool {
    self.pmtu_probe_after_rtt
  }

  /// The receive window of a stream, in bytes.
  ///
  /// Defaults to 1 MiB.
  #[inline]
  pub const fn stream_window(&self) -> u64 {
    self.stream_window
  }

  /// Mutable version of [`Self::ack_delay_exponent`], clamped to 20.
  #[inline]
  #[must_use = must_use_itself_doc!()]
  pub const fn set_ack_delay_exponent(mut self, value: u8) -> Self {
    self.ack_delay_exponent =
      if value > MAX_ACK_DELAY_EXPONENT { MAX_ACK_DELAY_EXPONENT } else { value };
    self
  }

  /// Mutable version of [`Self::balance`].
  #[inline]
  #[must_use = must_use_itself_doc!()]
  pub const fn set_balance(mut self, value: bool) -> Self {
    self.balance = value;
    self
  }

  /// Mutable version of [`Self::bodies_round_robin`].
  #[inline]
  #[must_use = must_use_itself_doc!()]
  pub const fn set_bodies_round_robin(mut self, value: bool) -> Self {
    self.bodies_round_robin = value;
    self
  }

  /// Mutable version of [`Self::cid_steering`].
  #[inline]
  #[must_use = must_use_itself_doc!()]
  pub const fn set_cid_steering(mut self, value: bool) -> Self {
    self.cid_steering = value;
    self
  }

  /// Mutable version of [`Self::conn_window`].
  #[inline]
  #[must_use = must_use_itself_doc!()]
  pub const fn set_conn_window(mut self, value: u64) -> Self {
    self.conn_window = value;
    self
  }

  /// Mutable version of [`Self::flush_in_slot_order`].
  #[inline]
  #[must_use = must_use_itself_doc!()]
  pub const fn set_flush_in_slot_order(mut self, value: bool) -> Self {
    self.flush_in_slot_order = value;
    self
  }

  /// Mutable version of [`Self::handshake_timeout_ms`].
  #[inline]
  #[must_use = must_use_itself_doc!()]
  pub const fn set_handshake_timeout_ms(mut self, value: u64) -> Self {
    self.handshake_timeout_ms = value;
    self
  }

  /// Mutable version of [`Self::limits`].
  #[inline]
  #[must_use = must_use_itself_doc!()]
  pub const fn set_limits(mut self, value: QuicLimits) -> Self {
    self.limits = value;
    self
  }

  /// Mutable version of [`Self::max_ack_delay_ms`], clamped to 16,383 ms.
  #[inline]
  #[must_use = must_use_itself_doc!()]
  pub const fn set_max_ack_delay_ms(mut self, value: u64) -> Self {
    self.max_ack_delay_ms = if value > MAX_MAX_ACK_DELAY_MS { MAX_MAX_ACK_DELAY_MS } else { value };
    self
  }

  /// Mutable version of [`Self::max_conns_per_worker`].
  #[inline]
  #[must_use = must_use_itself_doc!()]
  pub const fn set_max_conns_per_worker(mut self, value: u32) -> Self {
    self.max_conns_per_worker = value;
    self
  }

  /// Mutable version of [`Self::max_idle_timeout_ms`].
  #[inline]
  #[must_use = must_use_itself_doc!()]
  pub const fn set_max_idle_timeout_ms(mut self, value: u64) -> Self {
    self.max_idle_timeout_ms = value;
    self
  }

  /// Mutable version of [`Self::max_in_flight`].
  #[inline]
  #[must_use = must_use_itself_doc!()]
  pub const fn set_max_in_flight(mut self, value: usize) -> Self {
    self.max_in_flight = value;
    self
  }

  /// Mutable version of [`Self::max_streams_bidi`], clamped to 256.
  #[inline]
  #[must_use = must_use_itself_doc!()]
  pub const fn set_max_streams_bidi(mut self, value: u64) -> Self {
    self.max_streams_bidi = if value > MAX_STREAMS_BIDI { MAX_STREAMS_BIDI } else { value };
    self
  }

  /// Mutable version of [`Self::max_streams_uni`], clamped to 16.
  #[inline]
  #[must_use = must_use_itself_doc!()]
  pub const fn set_max_streams_uni(mut self, value: u64) -> Self {
    self.max_streams_uni = if value > MAX_STREAMS_UNI { MAX_STREAMS_UNI } else { value };
    self
  }

  /// Mutable version of [`Self::max_udp_payload_size`], at least 1,200 bytes.
  #[inline]
  #[must_use = must_use_itself_doc!()]
  pub const fn set_max_udp_payload_size(mut self, value: u64) -> Self {
    self.max_udp_payload_size =
      if value < MIN_UDP_PAYLOAD_SIZE { MIN_UDP_PAYLOAD_SIZE } else { value };
    self
  }

  /// Mutable version of [`Self::pacing`].
  #[inline]
  #[must_use = must_use_itself_doc!()]
  pub const fn set_pacing(mut self, value: bool) -> Self {
    self.pacing = value;
    self
  }

  /// Mutable version of [`Self::pmtu_probe_after_rtt`].
  #[inline]
  #[must_use = must_use_itself_doc!()]
  pub const fn set_pmtu_probe_after_rtt(mut self, value: bool) -> Self {
    self.pmtu_probe_after_rtt = value;
    self
  }

  /// Mutable version of [`Self::stream_window`].
  #[inline]
  #[must_use = must_use_itself_doc!()]
  pub const fn set_stream_window(mut self, value: u64) -> Self {
    self.stream_window = value;
    self
  }

  /// The parameters of each connection.
  #[inline]
  pub(crate) fn conn_params(&self) -> ConnParams {
    ConnParams {
      stream_window: self.stream_window,
      conn_window: self.conn_window,
      max_streams_bidi: self.max_streams_bidi,
      max_streams_uni: self.max_streams_uni,
      max_idle_timeout_ms: self.max_idle_timeout_ms,
      ack_delay_exponent: self.ack_delay_exponent,
      max_ack_delay_ms: self.max_ack_delay_ms,
      max_udp_payload_size: self.max_udp_payload_size,
      pacing: self.pacing,
      max_in_flight: self.max_in_flight,
      bodies_round_robin: self.bodies_round_robin,
      pmtu_probe_after_rtt: self.pmtu_probe_after_rtt,
      limits: self.limits.into(),
      ..ConnParams::default()
    }
  }
}

impl Default for QuicParams {
  /// The library defaults of the spec.
  #[inline]
  fn default() -> Self {
    Self {
      ack_delay_exponent: 3,
      balance: true,
      bodies_round_robin: false,
      cid_steering: true,
      conn_window: 16 << 20,
      flush_in_slot_order: false,
      handshake_timeout_ms: 10_000,
      limits: QuicLimits::default(),
      max_ack_delay_ms: 25,
      max_conns_per_worker: 4096,
      max_idle_timeout_ms: 30_000,
      max_in_flight: 256 << 10,
      max_streams_bidi: MAX_STREAMS_BIDI,
      max_streams_uni: MAX_STREAMS_UNI,
      max_udp_payload_size: 1472,
      pacing: true,
      pmtu_probe_after_rtt: false,
      stream_window: 1 << 20,
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
  use crate::quic::{
    ConnParams,
    limits::{ConnLimits, QuicLimits, QuicParams, RESET_WINDOW_US, RateBudget},
  };

  #[test]
  fn defaults_are_the_documented_ones() {
    let limits = QuicLimits::default();
    assert_eq!(limits.excessive_load_app_code, 0x0107);
    assert_eq!(limits.max_half_open_per_worker, 256);
    assert_eq!(limits.max_ack_ranges, 256);
    assert_eq!(limits.max_out_of_order_bytes_per_conn, 16 << 20);
    assert_eq!(limits.max_out_of_order_bytes_per_stream, 1 << 20);
    assert_eq!(limits.max_out_of_order_ranges, 256);
    assert_eq!(limits.new_connection_id_budget, 16);
    assert_eq!(limits.ping_budget, 64);
    assert_eq!(limits.path_challenge_budget, 16);
    assert_eq!(limits.reset_budget, 100);
    assert_eq!(limits.retry_above_half_open, 64);
    assert_eq!(limits.shutdown_app_code, 0x0100);
    assert_eq!(limits.shutdown_grace_ms, 2_000);
    assert_eq!(limits.stateless_reset_per_sec, 100);
    assert_eq!(limits.stream_rejected_app_code, 0x010b);
  }

  #[test]
  fn params_defaults_are_the_spec_ones() {
    let params = QuicParams::default();
    assert_eq!(params.max_conns_per_worker(), 4096);
    assert_eq!(params.max_streams_bidi(), 256);
    assert_eq!(params.max_streams_uni(), 16);
    assert_eq!(params.stream_window(), 1 << 20);
    assert_eq!(params.conn_window(), 16 << 20);
    assert_eq!(params.max_idle_timeout_ms(), 30_000);
    assert_eq!(params.handshake_timeout_ms(), 10_000);
    assert_eq!(params.max_udp_payload_size(), 1472);
    assert_eq!(params.ack_delay_exponent(), 3);
    assert_eq!(params.max_ack_delay_ms(), 25);
    assert!(params.pacing());
    assert_eq!(params.max_in_flight(), 256 << 10);
    assert!(params.cid_steering());
    assert!(params.balance());
    assert!(!params.flush_in_slot_order());
    assert!(!params.bodies_round_robin());
    assert!(!params.pmtu_probe_after_rtt());
    assert_eq!(params.limits(), &QuicLimits::default());
    assert_eq!(ConnLimits::default(), QuicLimits::default().into());
    // The connections of the defaults have the defaults of a connection
    let (conn, default) = (params.conn_params(), ConnParams::default());
    assert_eq!(
      (conn.stream_window, conn.conn_window, conn.max_streams_bidi, conn.max_streams_uni),
      (
        default.stream_window,
        default.conn_window,
        default.max_streams_bidi,
        default.max_streams_uni
      )
    );
    assert_eq!(
      (conn.max_idle_timeout_ms, conn.ack_delay_exponent, conn.max_ack_delay_ms),
      (default.max_idle_timeout_ms, default.ack_delay_exponent, default.max_ack_delay_ms)
    );
    assert_eq!(
      (conn.max_udp_payload_size, conn.pacing, conn.max_in_flight, conn.limits),
      (default.max_udp_payload_size, default.pacing, default.max_in_flight, default.limits)
    );
    assert_eq!(
      (conn.bodies_round_robin, conn.pmtu_probe_after_rtt),
      (default.bodies_round_robin, default.pmtu_probe_after_rtt)
    );
    // The switches of the measurements of tasks 16 and 19 reach the connections
    let on = params.set_bodies_round_robin(true).set_pmtu_probe_after_rtt(true).conn_params();
    assert!(on.bodies_round_robin && on.pmtu_probe_after_rtt);
    assert!(params.set_flush_in_slot_order(true).flush_in_slot_order());
  }

  #[test]
  fn params_setters_set_and_clamp() {
    let limits = QuicLimits { ping_budget: 7, ..QuicLimits::default() };
    let params = QuicParams::default()
      .set_ack_delay_exponent(21)
      .set_balance(false)
      .set_cid_steering(false)
      .set_conn_window(1)
      .set_handshake_timeout_ms(2)
      .set_limits(limits)
      .set_max_ack_delay_ms(1 << 14)
      .set_max_conns_per_worker(3)
      .set_max_idle_timeout_ms(4)
      .set_max_in_flight(5)
      .set_max_streams_bidi(1000)
      .set_max_streams_uni(1000)
      .set_max_udp_payload_size(100)
      .set_pacing(false)
      .set_stream_window(6);
    assert_eq!(params.ack_delay_exponent(), 20);
    assert!(!params.balance() && !params.cid_steering() && !params.pacing());
    assert_eq!((params.conn_window(), params.handshake_timeout_ms()), (1, 2));
    assert_eq!(params.limits().ping_budget, 7);
    assert_eq!(params.max_ack_delay_ms(), (1 << 14) - 1);
    assert_eq!((params.max_conns_per_worker(), params.max_idle_timeout_ms()), (3, 4));
    assert_eq!((params.max_in_flight(), params.stream_window()), (5, 6));
    assert_eq!((params.max_streams_bidi(), params.max_streams_uni()), (256, 16));
    assert_eq!(params.max_udp_payload_size(), 1200);
    let conn = params.conn_params();
    assert_eq!((conn.conn_window, conn.stream_window, conn.max_in_flight), (1, 6, 5));
    assert_eq!(conn.limits.ping_budget, 7);
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
