//! The connection core (RFC 9000 and RFC 9001): the handshake over the three packet number
//! spaces, acknowledgments, the assembly of outgoing packets, idle timeout and closing.
//!
//! Sans-I/O. Datagrams come in through [`QuicConn::recv_datagram`], are decrypted in place and
//! their frames are processed in one walk; packets go out through [`QuicConn::flush`], built in
//! place in a [`TxArena`]. The connection never reads the clock: every call says what time it
//! is, and [`QuicConn::next_deadline`] when [`QuicConn::on_timeout`] is due.
//!
//! # Packets that go out
//!
//! A datagram holds, in this order, a packet of each space that has something to send: Initial,
//! Handshake and 1-RTT, coalesced while the handshake lasts. A packet carries an ACK frame if an
//! ack-eliciting packet arrived since the last one, then the control frames that are owed, then
//! CRYPTO data and, in 1-RTT packets, the credit and the data of the streams
//! ([`crate::quic::stream`]). An ACK-only packet is never acknowledged on its own: only ack-eliciting packets
//! make an ACK frame owed. Datagrams with an Initial packet of a client, or an ack-eliciting one
//! of a server, are padded to 1200 bytes (RFC 9000 section 14.1), and until the address of the
//! client is validated a server sends at most three times what it received (RFC 9000 section
//! 8.1).
//!
//! # Keys
//!
//! Initial keys are dropped once a Handshake packet is processed (server) or sent (client), and
//! Handshake keys once the handshake is confirmed (RFC 9001 section 4.9), when the TLS state goes
//! back, zeroed, to the thread's pools. Keys are dropped in their slot.
//!
//! The 1-RTT keys are updated (RFC 9001 section 6) when the peer flips the key phase, and by this
//! endpoint before a key seals as many packets as its cipher suite allows. The key generation that
//! opens a packet is chosen from its key phase and packet number before it is decrypted, once
//! (ruling T9-a); the generation before or after the current one lives in a second slot from the
//! pools, and which slot is current alternates with the phase, so that no key moves (ruling
//! T9-b). The previous generation stays three PTOs after a flip for packets that arrive late.
//!
//! # Loss recovery
//!
//! Acknowledgments feed the RTT estimator and loss detection ([`crate::quic::recovery`]); lost
//! frames are queued again; a probe timeout sends one or two ack-eliciting packets. Packets in
//! flight are bound by the congestion window ([`crate::quic::cc`]), at most
//! [`ConnParams::max_in_flight`], and paced; ACK-only packets, probes and CONNECTION_CLOSE are not.
//! Once the handshake is confirmed, path MTU discovery ([`crate::quic::pmtud`]) sends one probe
//! and adopts its size if it is acknowledged.
//!
//! # Paths
//!
//! A server follows its client to a new address after the confirmation, as a NAT rebinding moves
//! it, and validates that address (RFC 9000 sections 8.2 and 9); probing packets from elsewhere are
//! answered where they came from. See [`path`].

use crate::{
  crypto::AEAD_TAG_LEN,
  quic::{
    AckFrame, Cid, ConnCtx, ConnHandle, DatagramMeta, Frame, FrameReader, FrameWriter, HpBatch,
    PacketKeys, PacketTy, QUIC_V1, QuicApp, QuicError, Space, TransportErrorCode, TransportParams,
    TxArena,
    cc::{CongestionControl as _, PACING_BURST_DATAGRAMS},
    initial_keys,
    key_phase::{Generation, KeyPhase, confidentiality_limit, integrity_limit, threshold_for},
    keys_from_secret_with,
    limits::{ConnLimits, RateBudget},
    open_payload, parse_header,
    pmtud::Pmtud,
    pn_len_for,
    pools::{CRYPTO_BUFFER_LEN, CryptoBuffer, FrameRefPool, FrameRefQueue, QuicPools},
    protect, protect_deferred,
    recovery::{self, Recovery},
    recv_tracker::{AckWritten, RecvTracker},
    remove_header_protection,
    sent::{FrameRef, FrameRefRange, SentKind, SentPacket, SentRing},
    stream::{BIDI_WINDOW, Streams, UNI_REMOTE_WINDOW},
    token::tokens_match,
    varint::varint_len,
    writer::Writer,
  },
  rng::{CryptoRng, CryptoSeedableRng},
  tls::{AlertDescription, CipherSuite, QuicTls, TlsCtxSk},
};
use alloc::boxed::Box;
use core::{
  fmt::{Debug, Formatter},
  hint::cold_path,
  net::{IpAddr, Ipv4Addr, SocketAddr},
};
use path::{PATH_FRAME_LEN, Paths, RxPath};

/// The connection IDs of the peer that a connection stores, the `active_connection_id_limit`
/// that it sends.
pub(crate) const ACTIVE_CID_LIMIT: usize = 2;
// RFC 9000 section 8.1
const AMPLIFICATION_FACTOR: u64 = 3;
// The datagram size until path MTU discovery finds a larger one
const INITIAL_MAX_DATAGRAM: usize = 1200;
// The bit of the first byte of a short header that carries the key phase
const KEY_PHASE_BIT: u8 = 0x04;
// The Length field of a long header always takes two bytes, so that it can be written last
const LENGTH_FIELD_LEN: usize = 2;
const LONG_HEADER_BIT: u8 = 0x80;
const LONG_RESERVED_BITS: u8 = 0x0c;
// The smallest datagram that can carry the Initial packet of a client, an ack-eliciting Initial
// packet of a server or a PATH_RESPONSE (RFC 9000 sections 8.2.2 and 14.1)
const MIN_DATAGRAM_LEN: usize = 1200;
// The packet number and the payload together have at least four bytes, so that the header
// protection sample, which starts four bytes after the packet number, is within the packet
const MIN_PN_AND_PAYLOAD_LEN: usize = 4;
// The PING frame
/// The most PING frames a second that a connection takes with the allowance scaled by its RTT
/// (ruling T21-g), unless the base budget is larger.
const PING_ALLOWANCE_CAP: u32 = 16_384;
const PING_FRAME: [u8; 1] = [0x01];
// Probes sent after a probe timeout (RFC 9002 section 6.2.4)
const PTO_PROBES: u8 = 2;
// The RETIRE_CONNECTION_ID frames that can be owed at once: more is a CONNECTION_ID_LIMIT_ERROR
// (RFC 9000 section 5.1.2 asks for at least twice the active_connection_id_limit)
const MAX_RETIRES_OWED: u64 = 16;
// The bytes at the end of a stateless reset that are its token (RFC 9000 section 10.3)
const RESET_TOKEN_LEN: usize = 16;
const SHORT_RESERVED_BITS: u8 = 0x18;
const SPACES: [Space; 3] = [Space::Initial, Space::Handshake, Space::Data];

/// Where a connection is in its life.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ConnState {
  /// The handshake is not confirmed yet.
  Handshake,
  /// The handshake is confirmed (RFC 9001 section 4.1.2).
  Confirmed,
  /// This endpoint closed the connection and answers with CONNECTION_CLOSE for a while (RFC 9000
  /// section 10.2.1).
  Closing,
  /// The peer closed the connection, nothing is sent anymore (RFC 9000 section 10.2.2).
  Draining,
  /// Over: nothing is received or sent, and the resources of the connection are back in the
  /// pools.
  Closed,
}

/// The result of [`QuicConn::flush`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FlushOutcome {
  /// Everything that can be sent now was written.
  Done,
  /// The arena is full: flush again once space came back.
  ArenaFull,
}

/// The parameters of connections, from the endpoint's [`crate::quic::QuicLimits`] and settings.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ConnParams {
  /// The receive window of a stream.
  pub(crate) stream_window: u64,
  /// The receive window of the connection.
  pub(crate) conn_window: u64,
  /// The bidirectional streams that the peer can open at once, at most 256.
  pub(crate) max_streams_bidi: u64,
  /// The unidirectional streams that the peer can open at once, at most 16.
  pub(crate) max_streams_uni: u64,
  /// The idle timeout advertised, zero for none.
  pub(crate) max_idle_timeout_ms: u64,
  /// The exponent of the ACK Delay field of the ACK frames that are sent.
  pub(crate) ack_delay_exponent: u8,
  /// The most time that an acknowledgment is delayed, as advertised.
  pub(crate) max_ack_delay_ms: u64,
  /// The largest UDP payload that is received.
  pub(crate) max_udp_payload_size: u64,
  /// If sending is paced.
  pub(crate) pacing: bool,
  /// The datagrams that the pacer lets go at once ([`crate::quic::QuicParams::pacing_burst`]).
  pub(crate) pacing_burst: u16,
  /// If the first packet of a flush with stream data carries an ACK frame while an acknowledgment
  /// of ack-eliciting packets may not have reached the peer
  /// ([`crate::quic::QuicParams::repeat_ack`]).
  pub(crate) repeat_ack: bool,
  /// The most bytes in flight, whatever the congestion window.
  pub(crate) max_in_flight: usize,
  /// If the streams whose next bytes are a body take turns, a STREAM frame each, instead of going
  /// one at a time to the end of their body ([`crate::quic::QuicParams::bodies_round_robin`]).
  pub(crate) bodies_round_robin: bool,
  /// If the first probe of path MTU discovery waits a smoothed RTT after the confirmation of the
  /// handshake ([`crate::quic::QuicParams::pmtu_probe_after_rtt`]).
  pub(crate) pmtu_probe_after_rtt: bool,
  /// If the header protection of the 1-RTT packets of a flush is computed in batches
  /// ([`crate::quic::QuicParams::batched_header_protection`]).
  pub(crate) batched_hp: bool,
  /// The packets sealed with one key of 1-RTT packets after which a key update starts, if it is
  /// below the threshold of the cipher suite.
  pub(crate) key_update_threshold: u64,
  /// Lowers the confidentiality limit of the cipher suite, for tests (ruling T9-g).
  #[cfg(test)]
  pub(crate) test_confidentiality_limit: u32,
  /// Lowers the integrity limit of the cipher suite, for tests (ruling T9-g).
  #[cfg(test)]
  pub(crate) test_integrity_limit: u32,
  /// Abuse limits.
  pub(crate) limits: ConnLimits,
  /// The handle of the connection on the endpoint of its worker ([`QuicConn::set_handle`]).
  pub(crate) handle: ConnHandle,
  /// The address of the peer that opened the connection.
  pub(crate) peer: IpAddr,
}

impl ConnParams {
  /// The credit given to the peer for the connection: its window, at most the bytes that it can
  /// make the connection hold
  /// ([`crate::quic::QuicLimits::max_out_of_order_bytes_per_conn`], ruling T8-g).
  #[inline]
  pub(crate) fn conn_credit(&self) -> u64 {
    self.conn_window.min(u64::from(self.limits.max_out_of_order_bytes_per_conn))
  }

  /// The credit given to the peer for each stream: its window, at most the bytes that it can make
  /// a stream hold ([`crate::quic::QuicLimits::max_out_of_order_bytes_per_stream`], ruling T8-g).
  #[inline]
  pub(crate) fn stream_credit(&self) -> u64 {
    self.stream_window.min(u64::from(self.limits.max_out_of_order_bytes_per_stream))
  }

  /// The transport parameters that describe these parameters (RFC 9000 section 18.2), sent by an
  /// endpoint whose CID is `local_cid`. A server gives `original_dcid`, the destination CID of the
  /// first Initial packet of the client.
  #[inline]
  pub(crate) fn transport_params(
    &self,
    local_cid: Cid,
    original_dcid: Option<Cid>,
  ) -> TransportParams {
    TransportParams {
      original_destination_connection_id: original_dcid,
      max_idle_timeout_ms: self.max_idle_timeout_ms,
      stateless_reset_token: None,
      max_udp_payload_size: self.max_udp_payload_size,
      initial_max_data: self.conn_credit(),
      initial_max_stream_data_bidi_local: self.stream_credit(),
      initial_max_stream_data_bidi_remote: self.stream_credit(),
      initial_max_stream_data_uni: self.stream_credit(),
      // The windows of the index arrays of the streams
      initial_max_streams_bidi: self.max_streams_bidi.min(BIDI_WINDOW as u64),
      initial_max_streams_uni: self.max_streams_uni.min(UNI_REMOTE_WINDOW as u64),
      ack_delay_exponent: self.ack_delay_exponent,
      max_ack_delay_ms: self.max_ack_delay_ms,
      // Not sent (task 22b): a server follows a client to any new address once the handshake is
      // confirmed, as it does for a NAT rebinding, with the same validation ([`path`]). It gives
      // one CID only, so a client can not migrate on purpose anyway (RFC 9000 section 9.5), and the
      // parameter would only claim a restriction that the server does not apply (section 9 lets
      // it validate and follow a peer that ignores it)
      disable_active_migration: false,
      active_connection_id_limit: ACTIVE_CID_LIMIT as u64,
      initial_source_connection_id: Some(local_cid),
      retry_source_connection_id: None,
    }
  }
}

impl ConnParams {
  // The packets that one key of `suite` seals at most, which tests can lower (ruling T9-g).
  fn confidentiality_limit(&self, suite: CipherSuite) -> u64 {
    #[cfg(test)]
    return confidentiality_limit(suite).min(u64::from(self.test_confidentiality_limit));
    #[cfg(not(test))]
    confidentiality_limit(suite)
  }

  // The packets that may fail to open over a connection of `suite`, which tests can lower.
  fn integrity_limit(&self, suite: CipherSuite) -> u64 {
    #[cfg(test)]
    return integrity_limit(suite).min(u64::from(self.test_integrity_limit));
    #[cfg(not(test))]
    integrity_limit(suite)
  }
}

impl Default for ConnParams {
  /// The library defaults of the spec.
  #[inline]
  fn default() -> Self {
    Self {
      stream_window: 1 << 20,
      conn_window: 16 << 20,
      max_streams_bidi: 256,
      max_streams_uni: 16,
      max_idle_timeout_ms: 30_000,
      ack_delay_exponent: 3,
      max_ack_delay_ms: 25,
      max_udp_payload_size: 1472,
      pacing: true,
      pacing_burst: PACING_BURST_DATAGRAMS,
      repeat_ack: true,
      max_in_flight: 256 << 10,
      bodies_round_robin: false,
      pmtu_probe_after_rtt: false,
      batched_hp: false,
      key_update_threshold: u64::MAX,
      #[cfg(test)]
      test_confidentiality_limit: u32::MAX,
      #[cfg(test)]
      test_integrity_limit: u32::MAX,
      limits: ConnLimits::default(),
      handle: ConnHandle { generation: 0, slot: 0 },
      peer: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
    }
  }
}

/// Counters of a connection, kept with its seldom used state while it is open.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct ConnStats {
  /// Bytes of the datagrams received.
  pub(crate) bytes_in: u64,
  /// Bytes of the datagrams sent.
  pub(crate) bytes_out: u64,
  /// Datagrams received.
  pub(crate) datagrams_in: u64,
  /// Datagrams sent.
  pub(crate) datagrams_out: u64,
  /// Packets dropped as duplicates.
  pub(crate) duplicates: u64,
  /// Packets processed.
  pub(crate) packets_in: u64,
  /// Packets dropped: undecryptable, of an unsupported type or for keys that are gone.
  pub(crate) packets_dropped: u64,
  /// Packets sent.
  pub(crate) packets_out: u64,
  /// Packets sent that were not ack-eliciting, other than CONNECTION_CLOSE.
  pub(crate) ack_only_out: u64,
  /// Updates of the keys of the 1-RTT packets that are sent, started here or by the peer.
  pub(crate) key_updates: u64,
  /// Packets that were declared lost and acknowledged after that.
  pub(crate) late_acks: u64,
  /// Path MTU probes sent.
  pub(crate) mtu_probes: u64,
  /// Packets declared lost.
  pub(crate) packets_lost: u64,
  /// Losses that showed persistent congestion.
  pub(crate) persistent_congestions: u64,
  /// Probe timeouts that fired.
  pub(crate) pto_probes: u64,
  /// Flushes that sent the FIN of a stream (that finished a response, on a server).
  pub(crate) fin_flushes: u64,
  /// Of [`Self::fin_flushes`], those whose packets carried an ACK frame of the 1-RTT space: the
  /// answers that leave with the acknowledgment of what they answer.
  pub(crate) fin_flushes_acked: u64,
  /// Of [`Self::fin_flushes`], those that started with an acknowledgment owed in the 1-RTT space:
  /// one that no ACK frame reported yet, or one that the peer may not have, as no packet that
  /// carried it was acknowledged (ruling T19-d). With [`ConnParams::repeat_ack`] each of them
  /// carries an ACK frame.
  pub(crate) fin_flushes_ack_owed: u64,
  /// Of [`Self::fin_flushes_ack_owed`], those that carried an ACK frame: over the owed ones, a
  /// share that can not exceed 1.
  pub(crate) fin_flushes_owed_and_acked: u64,
  /// Flushes that stopped with ack-eliciting data that the pacer held back.
  pub(crate) pacer_holds: u64,
  /// DATA_BLOCKED frames received.
  pub(crate) data_blocked_in: u64,
  /// STREAM_DATA_BLOCKED frames received.
  pub(crate) stream_data_blocked_in: u64,
  /// STREAMS_BLOCKED frames received.
  pub(crate) streams_blocked_in: u64,
  /// Changes of the address of the peer that packets go to (RFC 9000 section 9.3).
  pub(crate) migrations: u64,
  /// New paths that were validated, their path MTU included (RFC 9000 section 8.2).
  pub(crate) paths_validated: u64,
  /// Validations of a path that were abandoned (RFC 9000 section 8.2.4).
  pub(crate) path_validation_failures: u64,
  /// PATH_CHALLENGE frames sent.
  pub(crate) path_challenges_out: u64,
}

impl ConnStats {
  /// Nothing counted.
  pub(crate) const EMPTY: Self = Self {
    bytes_in: 0,
    bytes_out: 0,
    datagrams_in: 0,
    datagrams_out: 0,
    duplicates: 0,
    packets_in: 0,
    packets_dropped: 0,
    packets_out: 0,
    ack_only_out: 0,
    key_updates: 0,
    late_acks: 0,
    mtu_probes: 0,
    packets_lost: 0,
    persistent_congestions: 0,
    pto_probes: 0,
    fin_flushes: 0,
    fin_flushes_acked: 0,
    fin_flushes_ack_owed: 0,
    fin_flushes_owed_and_acked: 0,
    pacer_holds: 0,
    data_blocked_in: 0,
    stream_data_blocked_in: 0,
    streams_blocked_in: 0,
    migrations: 0,
    paths_validated: 0,
    path_validation_failures: 0,
    path_challenges_out: 0,
  };
}

/// A QUIC connection of a server or, in tests, of a client (`IS_CLIENT`). See the
/// [module documentation](self).
///
/// Its resources go back to the pools when it reaches [`ConnState::Closed`], or when it is
/// aborted ([`QuicConn::abort`]): drop it after that.
pub(crate) struct QuicConn<A, RNG, TCX, const IS_CLIENT: bool = false>
where
  A: QuicApp,
{
  address_validated: bool,
  app_state: A::ConnState,
  // What the amplification limit counts
  bytes_received: u64,
  bytes_sent: u64,
  close: CloseFrame,
  close_deadline_us: u64,
  // From the worker's pool until the connection is closed
  cold: Option<Box<ConnCold>>,
  close_owed: bool,
  // In the closing state: datagrams received since the last CONNECTION_CLOSE, and how many make
  // the next one, which doubles each time
  closing_datagrams: u32,
  closing_threshold: u32,
  // An ACK frame of the 1-RTT space went out in the flush under way
  flush_acked: bool,
  // A client got an acknowledgment of a Handshake packet: the server validated its address
  handshake_acked: bool,
  handshake_complete: bool,
  handshake_done_owed: bool,
  has_peer_params: bool,
  idle_restart_on_send: bool,
  // Key updates of the 1-RTT keys
  key: KeyPhase,
  last_activity_us: u64,
  // Ruling T23-m: the PING allowance the last validated path had, kept until the path after an IP
  // change has its own RTT sample, so a legitimate client that rebinds is not closed for the PINGs
  // it already sent this second. Zero before the first validated path.
  ping_allowance_floor: u32,
  local: Option<IpAddr>,
  local_cid: Cid,
  max_datagram: usize,
  params: ConnParams,
  path_response: Option<[u8; 8]>,
  // The PATH_RESPONSE goes to the address of the latest probe from elsewhere ([`path`]), not to
  // the peer
  path_response_off: bool,
  peer: SocketAddr,
  peer_cid: Cid,
  peer_cid_known: bool,
  peer_ack_delay_exponent: u8,
  peer_idle_timeout_ms: u64,
  peer_max_ack_delay_ms: u64,
  pmtud: Pmtud,
  // Loss detection, congestion control and pacing
  recovery: Recovery,
  // The 1-RTT space
  data: PacketSpace,
  // The Initial and Handshake spaces, from the worker's pool until the handshake is confirmed
  handshake: Option<Box<HandshakeSpaces>>,
  state: ConnState,
  streams: Streams,
  tls: Option<QuicTls<IS_CLIENT, RNG, TCX>>,
  // What only tests keep, boxed so that tests measure about the size of the connection that
  // they do not have
  #[cfg(test)]
  test_client: Option<Box<TestClient>>,
}

/// What a connection of tests keeps: raw frames to send and, for the client, the Retry that it
/// followed and what the server sent.
#[cfg(test)]
#[derive(Debug, Default)]
pub(crate) struct TestClient {
  /// Raw frames for the next 1-RTT packet.
  pub(crate) frames: alloc::vec::Vec<u8>,
  /// NEW_CONNECTION_ID frames received.
  pub(crate) new_connection_ids: u32,
  /// The CONNECTION_CLOSE of the server, once it arrived: (application, code).
  pub(crate) peer_close: Option<(bool, u64)>,
  /// The stateless reset token of the transport parameters of the server.
  pub(crate) peer_reset_token: Option<[u8; 16]>,
  /// The source CID of the Retry that the client followed.
  pub(crate) retry_scid: Option<Cid>,
  /// The token of that Retry, which its Initial packets carry.
  pub(crate) retry_token: alloc::vec::Vec<u8>,
}

impl<A, RNG, TCX> QuicConn<A, RNG, TCX, false>
where
  A: QuicApp,
  RNG: CryptoRng + CryptoSeedableRng,
  TCX: TlsCtxSk,
{
  /// The connection that an Initial packet of a client opens, which `meta` came with and whose
  /// destination CID is `client_dcid`: the first one, or the one that answers a Retry, whose
  /// token validated the address of the client (`address_validated`, RFC 9000 section 8.1.2).
  /// `tls` sends the transport parameters of [`ConnParams::transport_params`] with `local_cid`
  /// and the original destination CID, and, after a Retry, `client_dcid` as its source CID. The
  /// state of the handshake comes from `pools`. The datagram is then given to
  /// [`Self::recv_datagram`].
  #[inline]
  pub(crate) fn new_server(
    params: &ConnParams,
    local_cid: Cid,
    client_dcid: &[u8],
    meta: DatagramMeta,
    tls: QuicTls<false, RNG, TCX>,
    now_us: u64,
    pools: &mut QuicPools,
    address_validated: bool,
  ) -> crate::Result<Self> {
    let dcid = Cid::new(client_dcid)?;
    // The Initial keys come from the CID that the client sends its Initial packets to (RFC 9001
    // section 5.2), the one of its Retry after one
    let initial = initial_keys(client_dcid, true)?;
    // The CID of the client is in the header of its first Initial packet
    let handshake = HandshakeSpaces::take(initial, dcid, pools);
    let mut this =
      Self::with_parts(params, local_cid, Cid::default(), meta, tls, handshake, now_us, pools);
    this.address_validated = address_validated;
    Ok(this)
  }
}

#[cfg(any(test, feature = "_h3-loopback-client"))]
impl<A, RNG, TCX> QuicConn<A, RNG, TCX, true>
where
  A: QuicApp,
  RNG: CryptoRng + CryptoSeedableRng,
  TCX: TlsCtxSk,
{
  /// The connection of a client, for tests, that sends its first Initial packet to `peer` with
  /// the destination CID `original_dcid`. `tls` sends the transport parameters of
  /// [`ConnParams::transport_params`] with `local_cid`.
  pub(crate) fn new_client(
    params: &ConnParams,
    local_cid: Cid,
    original_dcid: Cid,
    peer: SocketAddr,
    tls: QuicTls<true, RNG, TCX>,
    now_us: u64,
    pools: &mut QuicPools,
  ) -> crate::Result<Self> {
    let initial = initial_keys(original_dcid.as_slice(), false)?;
    let meta = DatagramMeta { peer, local: None, segment_size: None };
    let handshake = HandshakeSpaces::take(initial, original_dcid, pools);
    Ok(Self::with_parts(params, local_cid, original_dcid, meta, tls, handshake, now_us, pools))
  }
}

impl<A, RNG, TCX, const IS_CLIENT: bool> QuicConn<A, RNG, TCX, IS_CLIENT>
where
  A: QuicApp,
  RNG: CryptoRng + CryptoSeedableRng,
  TCX: TlsCtxSk,
{
  /// Ends the connection at once, without a CONNECTION_CLOSE, and gives back to `pools` all that
  /// it took: for an endpoint that evicts a connection or shuts down. A closed connection is left
  /// as it is.
  #[inline]
  pub(crate) fn abort(&mut self, app: &mut A, pools: &mut QuicPools) {
    if self.state != ConnState::Closed {
      self.enter_closed(app, pools);
    }
  }

  /// Closes the connection with an application error (CONNECTION_CLOSE of type 0x1d).
  #[inline]
  pub(crate) fn close_app(&mut self, now_us: u64, code: u64) {
    self.enter_closing(now_us, CloseFrame { app: true, code, requested: false });
  }

  /// The handle of the connection on the endpoint of its worker, which its [`ConnCtx`] gives the
  /// application ([`ConnCtx::handle`]).
  #[inline]
  pub(crate) const fn set_handle(&mut self, handle: ConnHandle) {
    self.params.handle = handle;
  }

  /// The endpoint shuts down: the application of an established connection is asked whether it
  /// drains the connection itself ([`QuicApp::on_shutdown`]). Returns `true` if it does and the
  /// connection is still open; `false` for a connection that the caller closes now, or that is
  /// not open anymore.
  #[inline]
  pub(crate) fn on_shutdown(&mut self, now_us: u64, app: &mut A, pools: &mut QuicPools) -> bool {
    if !self.handshake_complete
      || !matches!(self.state, ConnState::Handshake | ConnState::Confirmed)
    {
      return false;
    }
    let drains = app.on_shutdown(&mut ConnCtx::new(
      &mut self.app_state,
      &mut self.streams,
      pools,
      &self.params,
      now_us,
    ));
    let closing = self.apply_app_close(now_us);
    drains && !closing
  }

  /// Writes the packets that are due into `tx`, as many datagrams as needed. Packets in flight wait
  /// for room in the congestion window, or for the pacer ([`Self::next_deadline`]).
  ///
  /// The application of an established connection that is not closing is told first
  /// ([`QuicApp::on_flush`], ruling T13-c): what it writes then leaves with these packets.
  #[inline]
  pub(crate) fn flush(
    &mut self,
    now_us: u64,
    tx: &mut TxArena,
    app: &mut A,
    pools: &mut QuicPools,
  ) -> FlushOutcome {
    if self.handshake_complete && matches!(self.state, ConnState::Handshake | ConnState::Confirmed)
    {
      app.on_flush(&mut ConnCtx::new(
        &mut self.app_state,
        &mut self.streams,
        pools,
        &self.params,
        now_us,
      ));
      let _closing = self.apply_app_close(now_us);
    }
    let fins = self.streams.fins_out();
    let ack_owed = self.data.recv.ack_pending() || self.data.recv.ack_unconfirmed();
    self.flush_acked = false;
    let rslt = self.flush_datagrams(now_us, tx, pools);
    if self.streams.fins_out() != fins {
      let acked = self.flush_acked;
      self.count(|el| {
        el.fin_flushes = el.fin_flushes.wrapping_add(1);
        el.fin_flushes_acked = el.fin_flushes_acked.wrapping_add(u64::from(acked));
        el.fin_flushes_ack_owed = el.fin_flushes_ack_owed.wrapping_add(u64::from(ack_owed));
        let owed_and_acked = u64::from(ack_owed && acked);
        el.fin_flushes_owed_and_acked = el.fin_flushes_owed_and_acked.wrapping_add(owed_and_acked);
      });
    }
    if self.recovery.timer_stale {
      self.set_loss_timer(now_us);
    }
    rslt
  }

  fn flush_datagrams(
    &mut self,
    now_us: u64,
    tx: &mut TxArena,
    pools: &mut QuicPools,
  ) -> FlushOutcome {
    // With batched header protection the 1-RTT packets wait in `pools.hp_batch`, which is
    // protected whenever it fills and at the end, before any of its datagrams leaves (ruling T18-b)
    let batched = self.data.keys.as_ref().is_some_and(|el| el.local.hp().batches());
    let rslt = self.flush_datagrams_with(now_us, tx, pools, batched);
    if batched {
      self.protect_batch(now_us, tx, pools);
    }
    rslt
  }

  // Protects the 1-RTT packets that wait in `pools.hp_batch` with one batch of masks.
  fn protect_batch(&mut self, now_us: u64, tx: &mut TxArena, pools: &mut QuicPools) {
    if pools.hp_batch.len() == 0 {
      return;
    }
    // The 1-RTT keys are made before the first deferred packet and dropped only when the
    // connection is released, which is never during a flush: `None` is a programming error, and
    // `HpBatch::apply` protects every packet that it can before it reports one
    let rslt = match self.data.keys.as_ref() {
      Some(keys) => pools.hp_batch.apply(keys.local.hp(), tx.buffer_mut()),
      None => {
        cold_path();
        pools.hp_batch.truncate(0);
        Err(crate::Error::ProgrammingError)
      }
    };
    if let Err(err) = rslt {
      cold_path();
      self.close_on_error(now_us, &err);
    }
  }

  // `batched`: the 1-RTT packets go into `pools.hp_batch` instead of being protected at once.
  fn flush_datagrams_with(
    &mut self,
    now_us: u64,
    tx: &mut TxArena,
    pools: &mut QuicPools,
    batched: bool,
  ) -> FlushOutcome {
    loop {
      if !self.wants_send() {
        return FlushOutcome::Done;
      }
      // A datagram to another address than the one of the path goes alone
      if self.flush_off_path(now_us, tx, pools, batched) {
        continue;
      }
      // A probe of path MTU discovery goes alone, in a datagram of its size
      if let Some(size) = self.mtu_probe_due()
        && let Some((start, buffer)) = tx.begin_at(self.peer, self.local, size)
        && buffer.len() >= size
      {
        let waiting = pools.hp_batch.len();
        let hp_at = batched.then_some(start);
        match self.write_mtu_probe(now_us, buffer, size, hp_at, pools) {
          // Not now: the other packets go
          Ok(0) => pools.hp_batch.truncate(waiting),
          Ok(len) => {
            self.on_datagram_sent(tx, len);
            if pools.hp_batch.is_full() {
              self.protect_batch(now_us, tx, pools);
            }
            continue;
          }
          Err(err) => {
            cold_path();
            // A packet that waits for its mask is in bytes that do not go
            pools.hp_batch.truncate(waiting);
            self.close_on_error(now_us, &err);
            continue;
          }
        }
      }
      let max_len = self.max_datagram.min(self.amplification_budget());
      if max_len == 0 {
        return FlushOutcome::Done;
      }
      let Some((start, buffer)) = tx.begin_at(self.peer, self.local, max_len) else {
        return FlushOutcome::ArenaFull;
      };
      // The arena can give less than asked for, the room left in the train that the datagram
      // joins: what does not fit there waits for a flush with more room
      if buffer.len() < max_len && buffer.len() < MIN_DATAGRAM_LEN && self.needs_full_datagram() {
        return FlushOutcome::ArenaFull;
      }
      let short = buffer.len() < max_len;
      let waiting = pools.hp_batch.len();
      let hp_at = batched.then_some(start);
      match self.write_datagram(now_us, buffer, hp_at, pools) {
        Ok(0) => {
          pools.hp_batch.truncate(waiting);
          // Something ack-eliciting was wanted (an acknowledgment alone would have gone) and the
          // pacer held it back
          if self.recovery.pacer_release_us.is_some() {
            self.count(|el| el.pacer_holds = el.pacer_holds.wrapping_add(1));
          }
          return if short { FlushOutcome::ArenaFull } else { FlushOutcome::Done };
        }
        Ok(len) => {
          self.on_datagram_sent(tx, len);
          if pools.hp_batch.is_full() {
            self.protect_batch(now_us, tx, pools);
          }
        }
        Err(err) => {
          cold_path();
          // A packet that waits for its mask is in bytes that do not go
          pools.hp_batch.truncate(waiting);
          if self.state == ConnState::Closing {
            return FlushOutcome::Done;
          }
          // The next datagram carries the CONNECTION_CLOSE
          self.close_on_error(now_us, &err);
        }
      }
    }
  }

  /// Runs `f` with the context of the connection at `now_us`, for an application that writes
  /// outside of the callbacks of [`QuicApp`], such as a handler that finished later. A close that
  /// it asks for is applied when `f` returns.
  #[inline]
  #[cfg_attr(
    not(feature = "http3-server-framework"),
    allow(
      dead_code,
      reason = "only the HTTP/3 server framework resumes handlers that finish later"
    )
  )]
  pub(crate) fn with_ctx<R>(
    &mut self,
    now_us: u64,
    pools: &mut QuicPools,
    f: impl FnOnce(&mut ConnCtx<'_, A::ConnState>) -> R,
  ) -> R {
    let rslt =
      f(&mut ConnCtx::new(&mut self.app_state, &mut self.streams, pools, &self.params, now_us));
    let _closing = self.apply_app_close(now_us);
    rslt
  }

  /// When [`Self::on_timeout`] is due, if ever: the idle timeout, the loss detection timer, the
  /// release of a packet that the pacer holds back, the end of the previous 1-RTT keys or of the
  /// closing period. A flush is due after it.
  #[inline]
  pub(crate) fn next_deadline(&self) -> Option<u64> {
    match self.state {
      ConnState::Handshake | ConnState::Confirmed => {
        let paced = self.recovery.pacer_release_us.filter(|_| self.wants_send());
        [
          self.idle_deadline(),
          self.recovery.loss_timer_us,
          paced,
          self.key.discard_deadline(),
          self.pmtud.hold_deadline(),
          self.path_deadline(),
        ]
        .into_iter()
        .flatten()
        .min()
      }
      ConnState::Closing | ConnState::Draining => Some(self.close_deadline_us),
      ConnState::Closed => None,
    }
  }

  /// Runs what is due at `now_us`: the end of the closing or draining period, the idle timeout,
  /// loss detection and probe timeouts, the end of the previous 1-RTT keys.
  #[inline]
  pub(crate) fn on_timeout(&mut self, now_us: u64, app: &mut A, pools: &mut QuicPools) {
    let expired = match self.state {
      ConnState::Handshake | ConnState::Confirmed => {
        // The connection is silently closed (RFC 9000 section 10.1)
        self.idle_deadline().is_some_and(|elem| now_us >= elem)
      }
      ConnState::Closing | ConnState::Draining => now_us >= self.close_deadline_us,
      ConnState::Closed => false,
    };
    if expired {
      self.enter_closed(app, pools);
      return;
    }
    if !matches!(self.state, ConnState::Handshake | ConnState::Confirmed) {
      return;
    }
    if self.path_deadline().is_some_and(|elem| now_us >= elem) && self.on_path_timeout(app, pools) {
      return;
    }
    if self.recovery.pacer_release_us.is_some_and(|elem| now_us >= elem) {
      self.recovery.pacer_release_us = None;
    }
    self.pmtud.on_timeout(now_us);
    let mut rslt = Ok(());
    if self.key.discard_deadline().is_some_and(|elem| now_us >= elem) {
      rslt = self.key.discard_previous(self.data.keys.as_mut(), pools);
    }
    if rslt.is_ok() && self.recovery.loss_timer_us.is_some_and(|elem| now_us >= elem) {
      rslt = self.on_loss_timer(now_us, pools);
    }
    if let Err(err) = rslt {
      cold_path();
      self.close_on_error(now_us, &err);
    }
  }

  /// Takes the datagram `datagram`, which came with `meta`: its packets, coalesced or not, are
  /// decrypted in place and processed one after the other. Packets that can not be decrypted, are
  /// duplicates or are of an unsupported type are dropped.
  ///
  /// An error is the connection error that moved the connection to [`ConnState::Closing`]: the
  /// next flush sends the CONNECTION_CLOSE.
  #[inline]
  pub(crate) fn recv_datagram(
    &mut self,
    now_us: u64,
    datagram: &mut [u8],
    meta: DatagramMeta,
    app: &mut A,
    pools: &mut QuicPools,
  ) -> crate::Result<()> {
    // What the server may send to an address that is not validated is a multiple of what that
    // address sent (RFC 9000 section 8.1): the bytes that come from another address do not count
    // for the current path, but for that address, which may become the path ([`path`])
    let mut rx = self.rx_path(&meta);
    let datagram_len = datagram.len();
    let len = u64::try_from(datagram_len).unwrap_or(u64::MAX);
    let counted = if rx.from_peer { len } else { 0 };
    self.count(|el| {
      el.datagrams_in = el.datagrams_in.wrapping_add(1);
      el.bytes_in = el.bytes_in.wrapping_add(len);
    });
    match self.state {
      ConnState::Handshake | ConnState::Confirmed => {}
      ConnState::Closing => {
        // What the amplification limit lets the CONNECTION_CLOSE in reply be
        self.bytes_received = self.bytes_received.saturating_add(counted);
        self.on_datagram_while_closing();
        return Ok(());
      }
      ConnState::Draining | ConnState::Closed => return Ok(()),
    }
    self.bytes_received = self.bytes_received.saturating_add(counted);
    if !IS_CLIENT && !self.address_validated {
      // More room under the amplification limit, which may let the timer be armed
      self.recovery.timer_stale = true;
    }
    // A packet that fails to open loses its bytes (RFC 9001 section 5.3)
    let tail = datagram.last_chunk::<RESET_TOKEN_LEN>().copied();
    let processed = self.stats().packets_in;
    let rslt = self.recv_packets(now_us, datagram, &mut rx, app, pools);
    if rslt.is_ok()
      && self.stats().packets_in == processed
      && matches!(self.state, ConnState::Handshake | ConnState::Confirmed)
      && tail.is_some_and(|el| self.is_peer_reset(&el))
    {
      // A stateless reset of the peer (RFC 9000 section 10.3.1)
      self.enter_draining(now_us);
      return Ok(());
    }
    if rslt.is_ok()
      && !rx.from_peer
      && matches!(self.state, ConnState::Handshake | ConnState::Confirmed)
      && let Err(err) = self.after_other_address(now_us, &rx, &meta, len)
    {
      cold_path();
      self.close_on_error(now_us, &err);
      return Err(err);
    }
    if self.recovery.timer_stale
      && matches!(self.state, ConnState::Handshake | ConnState::Confirmed)
    {
      self.set_loss_timer(now_us);
    }
    rslt
  }

  // The packets of a datagram, coalesced or not.
  fn recv_packets(
    &mut self,
    now_us: u64,
    datagram: &mut [u8],
    rx: &mut RxPath,
    app: &mut A,
    pools: &mut QuicPools,
  ) -> crate::Result<()> {
    let datagram_len = datagram.len();
    let mut first_dcid = None;
    let mut rest = datagram;
    while !rest.is_empty() {
      let Ok(header) = parse_header(rest, self.local_cid.len()) else {
        self.drop_packet();
        break;
      };
      let (ty, pn_offset, packet_end) = (header.ty, header.pn_offset, header.packet_end);
      let (Ok(dcid), Ok(scid)) = (Cid::new(header.dcid), Cid::new(header.scid)) else {
        self.drop_packet();
        break;
      };
      #[cfg(test)]
      if IS_CLIENT && ty == PacketTy::Retry {
        let token = header.token.to_vec();
        let packet = rest.to_vec();
        self.on_retry(scid, &token, &packet, pools);
        break;
      }
      // Coalesced packets have the same destination CID (RFC 9000 section 12.2)
      if *first_dcid.get_or_insert(dcid) != dcid {
        self.drop_packet();
        break;
      }
      let Some((packet, tail)) = core::mem::take(&mut rest).split_at_mut_checked(packet_end) else {
        self.drop_packet();
        break;
      };
      rest = tail;
      let space = match ty {
        PacketTy::Initial => Space::Initial,
        PacketTy::Handshake => Space::Handshake,
        PacketTy::OneRtt => Space::Data,
        // 0-RTT is not accepted, and the others are for clients that sent such packets
        PacketTy::ZeroRtt
        | PacketTy::Retry
        | PacketTy::VersionNegotiation
        | PacketTy::UnknownVersion => {
          self.drop_packet();
          continue;
        }
      };
      // A server drops Initial packets of datagrams below 1200 bytes (RFC 9000 section 14.1)
      if !self.accepts_dcid(&dcid)
        || (!IS_CLIENT && space == Space::Initial && datagram_len < MIN_DATAGRAM_LEN)
      {
        self.drop_packet();
        continue;
      }
      if let Err(err) = self.recv_packet(now_us, space, packet, pn_offset, scid, rx, app, pools) {
        cold_path();
        self.close_on_error(now_us, &err);
        return Err(err);
      }
      if !matches!(self.state, ConnState::Handshake | ConnState::Confirmed) {
        break;
      }
    }
    Ok(())
  }

  /// Where the connection is.
  #[inline]
  pub(crate) const fn state(&self) -> ConnState {
    self.state
  }

  /// The counters of the connection, all zero once it is closed.
  #[inline]
  pub(crate) fn stats(&self) -> &ConnStats {
    self.cold.as_deref().map_or(&ConnStats::EMPTY, |el| &el.stats)
  }

  /// STREAM frames sent with the FIN of their stream the first time, STREAM frames sent again,
  /// and those of them that carried bytes already acknowledged.
  #[inline]
  pub(crate) fn stream_tally(&self) -> (u64, u64, u64) {
    (self.streams.fins_out(), self.streams.frames_resent(), self.streams.frames_resent_acked())
  }

  /// The bytes of stream data written into packets, those sent again included, and the bytes
  /// that the application wrote to streams by copy (ruling T19-a).
  #[inline]
  pub(crate) fn stream_bytes(&self) -> (u64, u64) {
    self.streams.bytes_out_and_copied()
  }

  // Counts something, while the connection is open
  fn count(&mut self, f: impl FnOnce(&mut ConnStats)) {
    if let Some(elem) = self.cold.as_deref_mut() {
      f(&mut elem.stats);
    }
  }

  // If any packet number space has an ack-eliciting packet in flight.
  fn any_ack_eliciting_in_flight(&self) -> bool {
    SPACES.into_iter().any(|space| {
      space_ref(&self.data, &self.handshake, space).is_some_and(|el| el.ack_eliciting_in_flight > 0)
    })
  }

  // Declares lost the packets of `space` that are (RFC 9002 appendix A.10): their frames are
  // queued again, and the window shrinks, to the minimum for persistent congestion.
  fn detect_lost(&mut self, space: Space, now_us: u64, pools: &mut QuicPools) -> crate::Result<()> {
    let persistent_us = self.persistent_congestion_us();
    let Self {
      cold,
      data,
      handshake,
      handshake_done_owed,
      max_datagram,
      pmtud,
      recovery,
      streams,
      ..
    } = self;
    let Some(sp) = space_mut(data, handshake, space) else {
      return Ok(());
    };
    let Some(largest) = sp.largest_acked else {
      return Ok(());
    };
    let rtt = recovery.rtt;
    let persistent = rtt.first_sample_us.map(|first| (first, persistent_us));
    let PacketSpace { ack_eliciting_in_flight, crypto_lost, loss_time_us, sent, .. } = sp;
    let mut lost_count = 0u64;
    let mut rslt = Ok(());
    let mut lost = LostCtx {
      ack_eliciting_in_flight,
      cold,
      crypto_lost,
      handshake_done_owed,
      max_datagram: *max_datagram,
      pmtud,
      recovery,
      streams,
    };
    let losses = recovery::detect_lost(
      sent,
      largest,
      now_us,
      rtt.loss_delay_us(),
      persistent,
      |pn, packet| {
        lost_count = lost_count.wrapping_add(1);
        let requeued = lost.on_lost(pn, &packet, pools);
        if rslt.is_ok() {
          rslt = requeued;
        }
      },
    );
    *loss_time_us = losses.loss_time_us;
    if let Some(sent_us) = losses.newest_lost_us {
      recovery.cc.on_congestion_event(sent_us, now_us);
    }
    if losses.persistent {
      recovery.cc.on_persistent_congestion();
      recovery.rtt.on_persistent_congestion();
    }
    let persistent = u64::from(losses.persistent);
    if lost_count > 0 {
      recovery.timer_stale = true;
    }
    if let Some(elem) = cold.as_deref_mut() {
      elem.stats.packets_lost = elem.stats.packets_lost.wrapping_add(lost_count);
      elem.stats.persistent_congestions =
        elem.stats.persistent_congestions.wrapping_add(persistent);
    }
    rslt
  }

  // How long losses must span to be persistent congestion, with the max_ack_delay of the peer in
  // every packet number space (RFC 9002 section 7.6.1, review J5).
  fn persistent_congestion_us(&self) -> u64 {
    self.recovery.rtt.persistent_congestion_us(self.peer_max_ack_delay_us())
  }

  // The earliest time of the packet number spaces at which a packet becomes lost by the time
  // threshold, and its space.
  fn earliest_loss_time(&self) -> Option<(u64, Space)> {
    SPACES
      .into_iter()
      .filter_map(|space| {
        space_ref(&self.data, &self.handshake, space)
          .and_then(|el| el.loss_time_us)
          .map(|el| (el, space))
      })
      .min_by_key(|el| el.0)
  }

  // If the next ack-eliciting Initial packet of a server needs a datagram of 1200 bytes: it has
  // CRYPTO data to send, new or lost, if `allow_ae`, or is a probe.
  fn initial_elicits(&self, allow_ae: bool) -> bool {
    let probe = self.recovery.probes > 0 && self.recovery.probe_space == Space::Initial;
    let crypto = !self.crypto_unsent(Space::Initial).is_empty()
      || self.handshake.as_deref().is_some_and(|el| !el.initial.crypto_lost.is_empty());
    probe || (allow_ae && crypto)
  }

  // The size of the path MTU probe that is due, once the handshake is confirmed and while the
  // address of the path is validated: the probe does not wait for the amplification limit.
  fn mtu_probe_due(&self) -> Option<usize> {
    let ready = self.state == ConnState::Confirmed
      && self.data.keys.is_some()
      && (IS_CLIENT || self.address_validated);
    self.pmtud.probe_due().filter(|_| ready)
  }

  // The datagram of `len` bytes that the arena handed out was written.
  fn on_datagram_sent(&mut self, tx: &mut TxArena, len: usize) {
    tx.commit(len);
    let len = u64::try_from(len).unwrap_or(u64::MAX);
    self.bytes_sent = self.bytes_sent.saturating_add(len);
    self.count(|el| {
      el.bytes_out = el.bytes_out.wrapping_add(len);
      el.datagrams_out = el.datagrams_out.wrapping_add(1);
    });
  }

  // The loss detection timer fired: packets became lost by the time threshold, or it is a probe
  // timeout, which owes probes and backs off (RFC 9002 appendix A.9).
  fn on_loss_timer(&mut self, now_us: u64, pools: &mut QuicPools) -> crate::Result<()> {
    if let Some((_, space)) = self.earliest_loss_time() {
      self.detect_lost(space, now_us, pools)?;
      self.set_loss_timer(now_us);
      return Ok(());
    }
    let space = if self.any_ack_eliciting_in_flight() {
      self.pto_time_and_space(now_us).map(|el| el.1)
    } else {
      // A client that the server may not have validated sends to unblock it
      Some(self.anti_deadlock_space())
    };
    if let Some(space) = space {
      self.recovery.probes = PTO_PROBES;
      self.recovery.probe_space = space;
      self.count(|el| el.pto_probes = el.pto_probes.wrapping_add(1));
      self.prepare_probe(space, pools)?;
    }
    self.recovery.pto_count = self.recovery.pto_count.saturating_add(1);
    self.set_loss_timer(now_us);
    Ok(())
  }

  // A packet failed to open with keys of `suite`: past the integrity limit of its AEAD, across
  // all keys of the connection, the connection closes (RFC 9001 section 6.6).
  fn on_open_failure(&mut self, suite: CipherSuite) -> crate::Result<()> {
    let Some(cold) = self.cold.as_deref_mut() else {
      return Ok(());
    };
    cold.open_failures = cold.open_failures.wrapping_add(1);
    if cold.open_failures >= self.params.integrity_limit(suite) {
      cold_path();
      return Err(crate::Error::QuicClose(
        TransportErrorCode::AeadLimitReached,
        QuicError::AeadLimitReached,
      ));
    }
    Ok(())
  }

  // NEW_CONNECTION_ID (RFC 9000 sections 5.1.1, 5.1.2 and 19.15, ruling T10-d): the CID is
  // stored, the ones below Retire Prior To are retired, packets go to a CID that is not.
  fn on_new_connection_id(
    &mut self,
    now_us: u64,
    seq: u64,
    retire_prior_to: u64,
    cid: &[u8],
    reset_token: &[u8; RESET_TOKEN_LEN],
  ) -> crate::Result<()> {
    let budget = self.params.limits.new_connection_id_budget;
    if !self.cold.as_deref_mut().is_none_or(|el| el.new_cids.take(budget, now_us)) {
      return Err(self.excessive_load(now_us));
    }
    let Some(cold) = self.cold.as_deref_mut() else {
      return Ok(());
    };
    // A peer that uses no CID can not give one
    if self.peer_cid.is_empty() {
      return Err(violation(QuicError::ConnectionIdInvalid));
    }
    let cid = Cid::new(cid)?;
    if cold.peer_cids.iter().all(Option::is_none)
      && let Some(first) = cold.peer_cids.first_mut()
    {
      *first = Some(PeerCid { cid: self.peer_cid, reset_token: None, seq: 0 });
    }
    // A repeat must be the same; a CID can not come back with another sequence number
    let known = cold.peer_cids.iter().flatten().find(|el| el.seq == seq);
    if let Some(elem) = known
      && (elem.cid != cid || elem.reset_token != Some(*reset_token))
    {
      return Err(violation(QuicError::ConnectionIdInvalid));
    }
    let is_new = known.is_none();
    if is_new && cold.peer_cids.iter().flatten().any(|el| el.cid == cid) {
      return Err(violation(QuicError::ConnectionIdInvalid));
    }
    if retire_prior_to > cold.retire_prior_to {
      if retire_prior_to.saturating_sub(cold.retire_next) > MAX_RETIRES_OWED {
        cold_path();
        return Err(crate::Error::QuicClose(
          TransportErrorCode::ConnectionIdLimitError,
          QuicError::ConnectionIdLimit,
        ));
      }
      cold.retire_prior_to = retire_prior_to;
      for elem in &mut cold.peer_cids {
        if elem.is_some_and(|el| el.seq < retire_prior_to) {
          *elem = None;
        }
      }
    }
    // One that was retired already is owed its RETIRE_CONNECTION_ID, which the range covers
    if is_new && seq >= cold.retire_prior_to {
      let Some(free) = cold.peer_cids.iter_mut().find(|el| el.is_none()) else {
        cold_path();
        return Err(crate::Error::QuicClose(
          TransportErrorCode::ConnectionIdLimitError,
          QuicError::ConnectionIdLimit,
        ));
      };
      *free = Some(PeerCid { cid, reset_token: Some(*reset_token), seq });
    }
    if cold.peer_cid_seq < cold.retire_prior_to
      && let Some(next) = cold.peer_cids.iter().flatten().min_by_key(|el| el.seq)
    {
      self.peer_cid = next.cid;
      cold.peer_cid_seq = next.seq;
    }
    Ok(())
  }

  // If `tail`, the last bytes of a datagram that could not be processed, is the stateless reset
  // token of a CID of the peer. Every stored token is compared, each in constant time: the
  // comparison tells nothing of a token (RFC 9000 section 10.3.1, review L1).
  fn is_peer_reset(&self, tail: &[u8; RESET_TOKEN_LEN]) -> bool {
    let Some(cold) = self.cold.as_deref() else {
      return false;
    };
    let mut found = false;
    for token in cold.peer_cids.iter().flatten().filter_map(|el| el.reset_token.as_ref()) {
      found |= tokens_match(token, tail);
    }
    found
  }

  // If the peer completed address validation: always for a server, which the handshake validates
  // to the client; for a client once a Handshake packet of it was acknowledged or the handshake is
  // confirmed (RFC 9002 appendix A.6).
  fn peer_validated_address(&self) -> bool {
    !IS_CLIENT || self.handshake_acked || self.state == ConnState::Confirmed
  }

  // The space of the probes of a client that has nothing in flight but is not sure that the server
  // validated its address: a Handshake packet proves it, a padded Initial one earns credit.
  fn anti_deadlock_space(&self) -> Space {
    let handshake = self.handshake.as_deref().is_some_and(|el| el.handshake.keys.is_some());
    if handshake { Space::Handshake } else { Space::Initial }
  }

  // Readies the probes of `space`: the CRYPTO data in flight of the handshake spaces goes again,
  // coalesced (RFC 9002 section 6.2.4), and a ring with no room for a probe gives up its oldest
  // packet as lost.
  fn prepare_probe(&mut self, space: Space, pools: &mut QuicPools) -> crate::Result<()> {
    if space != Space::Data
      && let Some(hs) = self.handshake.as_deref_mut()
    {
      requeue_crypto_in_flight(&mut hs.initial, pools)?;
      requeue_crypto_in_flight(&mut hs.handshake, pools)?;
    }
    let Self {
      cold,
      data,
      handshake,
      handshake_done_owed,
      max_datagram,
      pmtud,
      recovery,
      streams,
      ..
    } = self;
    let Some(sp) = space_mut(data, handshake, space) else {
      return Ok(());
    };
    if !sp.sent.is_full() {
      return Ok(());
    }
    // Every packet number of the ring is used and the oldest packet is in flight: a probe can not
    // go without its slot, so it counts as lost
    let base = sp.sent.base();
    let Some(record) = sp.sent.get_mut(base) else {
      return Ok(());
    };
    let packet = record.declare_lost();
    let PacketSpace { ack_eliciting_in_flight, crypto_lost, .. } = sp;
    let mut lost = LostCtx {
      ack_eliciting_in_flight,
      cold,
      crypto_lost,
      handshake_done_owed,
      max_datagram: *max_datagram,
      pmtud,
      recovery,
      streams,
    };
    lost.on_lost(base, &packet, pools)
  }

  // When the probe timeout fires and in which space (RFC 9002 appendix A.8): the earliest of the
  // spaces with ack-eliciting packets in flight, 1-RTT packets only once the handshake is
  // confirmed, with the `max_ack_delay` of the peer for them only (carried rule 2).
  fn pto_time_and_space(&self, now_us: u64) -> Option<(u64, Space)> {
    let backoff = 1u64.checked_shl(self.recovery.pto_count.min(30)).unwrap_or(u64::MAX);
    let mut duration = self.recovery.rtt.pto_base_us().saturating_mul(backoff);
    if !self.any_ack_eliciting_in_flight() {
      return Some((now_us.saturating_add(duration), self.anti_deadlock_space()));
    }
    let mut rslt: Option<(u64, Space)> = None;
    for space in SPACES {
      let Some(sp) = space_ref(&self.data, &self.handshake, space) else {
        continue;
      };
      if sp.ack_eliciting_in_flight == 0 {
        continue;
      }
      if space == Space::Data {
        if self.state != ConnState::Confirmed {
          break;
        }
        duration = duration.saturating_add(self.peer_max_ack_delay_us().saturating_mul(backoff));
      }
      let at = sp.last_ack_eliciting_us.saturating_add(duration);
      if rslt.is_none_or(|elem| at < elem.0) {
        rslt = Some((at, space));
      }
    }
    rslt
  }

  // Arms the loss detection timer (RFC 9002 appendix A.8): for the earliest time at which a packet
  // becomes lost, else for the probe timeout, unless nothing is in flight that needs one or a
  // server is held by the amplification limit (carried rule 2).
  fn set_loss_timer(&mut self, now_us: u64) {
    self.recovery.timer_stale = false;
    let blocked = !IS_CLIENT && self.amplification_budget() == 0;
    let idle = !self.any_ack_eliciting_in_flight() && self.peer_validated_address();
    self.recovery.loss_timer_us = if let Some((at, _)) = self.earliest_loss_time() {
      Some(at)
    } else if blocked || idle {
      None
    } else {
      self.pto_time_and_space(now_us).map(|el| el.0)
    };
  }

  // If the window and the pacer let a datagram of up to `len` bytes in flight go at `now_us`. The
  // pacer gives the time at which it will, which [`Self::next_deadline`] reports.
  fn window_allows(&mut self, now_us: u64, len: usize) -> bool {
    let max_in_flight = self.params.max_in_flight;
    self.recovery.pacer_release_us = None;
    if !self.recovery.can_send(max_in_flight, self.max_datagram) {
      return false;
    }
    if !self.params.pacing {
      return true;
    }
    let window = self.recovery.window(max_in_flight);
    let srtt = self.recovery.rtt.smoothed_us;
    let burst = self.params.pacing_burst;
    let release =
      self.recovery.pacer.release_time(now_us, len, (window, srtt), self.max_datagram, burst);
    self.recovery.pacer_release_us = release;
    release.is_none()
  }

  // A 1-RTT packet of a PING and PADDING that fills a datagram of `size` bytes, ack-eliciting and
  // not counted by congestion control (ruling T9-e). Returns its length, zero if it can not go
  // now.
  // `hp_at`: where `buffer` starts in the arena, if the header protection of the probe waits for
  // a batch.
  fn write_mtu_probe(
    &mut self,
    now_us: u64,
    buffer: &mut [u8],
    size: usize,
    hp_at: Option<usize>,
    pools: &mut QuicPools,
  ) -> crate::Result<usize> {
    let (dcid, scid, key_phase) = (self.peer_cid, self.local_cid, self.key.local_phase);
    let sp = &mut self.data;
    if sp.keys.is_none() || !sp.sent.reserve(pools) {
      return Ok(0);
    }
    let pn = sp.sent.next_pn();
    let pn_len = pn_len_for(pn, sp.largest_acked);
    let Some(buffer) = buffer.get_mut(..size) else {
      return Ok(0);
    };
    let Some((header_len, pn_offset, _)) =
      write_header(buffer, Space::Data, &dcid, &scid, (pn, pn_len), key_phase, &[])
    else {
      return Ok(0);
    };
    let payload_len = size.saturating_sub(header_len).saturating_sub(AEAD_TAG_LEN);
    let Some(payload) = buffer.get_mut(header_len..header_len.wrapping_add(payload_len)) else {
      return Ok(0);
    };
    if payload.len() < MIN_PN_AND_PAYLOAD_LEN {
      return Ok(0);
    }
    payload.fill(0);
    if let Some(first) = payload.first_mut() {
      *first = PING_FRAME[0];
    }
    let packet = OpenPacket {
      ack_eliciting: true,
      ack_only_largest: None,
      challenge: false,
      frames: FrameRefRange::EMPTY,
      full_datagram: false,
      header_len,
      length_at: None,
      mtu_probe: true,
      off_path: false,
      padded: true,
      payload_len,
      pn,
      pn_len,
      pn_offset,
      space: Space::Data,
      start: 0,
    };
    let len = self.seal(now_us, buffer, &packet, hp_at.map(|el| (el, &mut pools.hp_batch)))?;
    self.pmtud.on_probe_sent(pn);
    self.count(|el| el.mtu_probes = el.mtu_probes.wrapping_add(1));
    Ok(len)
  }

  fn accepts_dcid(&self, dcid: &Cid) -> bool {
    // The first Initial packets of a client go to the CID that it chose
    *dcid == self.local_cid
      || (!IS_CLIENT
        && self.state == ConnState::Handshake
        && self.handshake.as_ref().is_some_and(|el| el.original_dcid == *dcid))
  }

  // Records the processing of a packet of `space`.
  fn after_packet(
    &mut self,
    now_us: u64,
    space: Space,
    pools: &mut QuicPools,
  ) -> crate::Result<()> {
    self.count(|el| el.packets_in = el.packets_in.wrapping_add(1));
    self.last_activity_us = now_us;
    self.idle_restart_on_send = true;
    if !matches!(self.state, ConnState::Handshake | ConnState::Confirmed) {
      return Ok(());
    }
    if !IS_CLIENT && space == Space::Handshake {
      // A Handshake packet proves that the client got the Initial packets (RFC 9000 section
      // 8.1), whose keys are not needed anymore (RFC 9001 section 4.9.1)
      self.address_validated = true;
      if let Some(elem) = &mut self.handshake {
        elem.discard_initial(&mut self.recovery, pools);
      }
    }
    if !IS_CLIENT && self.handshake_complete && self.state == ConnState::Handshake {
      // A server confirms the handshake once it is complete (RFC 9001 section 4.1.2)
      self.confirm(now_us, pools)?;
    }
    Ok(())
  }

  // The application asked for a close: an application CONNECTION_CLOSE. Returns whether the
  // connection is closing.
  fn apply_app_close(&mut self, now_us: u64) -> bool {
    if let Some(code) = self.streams.take_close_request() {
      self.enter_closing(now_us, CloseFrame { app: true, code, requested: true });
    }
    !matches!(self.state, ConnState::Handshake | ConnState::Confirmed)
  }

  fn amplification_budget(&self) -> usize {
    if IS_CLIENT || self.address_validated {
      return usize::MAX;
    }
    let allowed = self.bytes_received.saturating_mul(AMPLIFICATION_FACTOR);
    usize::try_from(allowed.saturating_sub(self.bytes_sent)).unwrap_or(usize::MAX)
  }

  // Checks the CIDs of the transport parameters of the peer (RFC 9000 section 7.3).
  fn check_peer_params(&self, params: &TransportParams) -> crate::Result<()> {
    let original_dcid = self.handshake.as_ref().map(|el| el.original_dcid);
    #[cfg(test)]
    let retry_scid = self.test_client.as_deref().and_then(|el| el.retry_scid);
    #[cfg(not(test))]
    let retry_scid = None;
    let mismatch = params.initial_source_connection_id != Some(self.peer_cid)
      || (IS_CLIENT
        && (params.original_destination_connection_id != original_dcid
          || params.retry_source_connection_id != retry_scid));
    if mismatch {
      return Err(crate::Error::QuicClose(
        TransportErrorCode::TransportParameterError,
        QuicError::ConnectionIdMismatch,
      ));
    }
    Ok(())
  }

  fn close_on_error(&mut self, now_us: u64, err: &crate::Error) {
    let code = match err {
      crate::Error::QuicClose(code, _) => *code,
      _ => TransportErrorCode::InternalError,
    };
    self.enter_closing(now_us, CloseFrame { app: false, code: code.code(), requested: false });
  }

  // The handshake is confirmed: what only it needed goes back, and the keys of the next key phase
  // that open packets are made now, never while a packet is processed (RFC 9001 section 9.5,
  // review J12).
  fn confirm(&mut self, now_us: u64, pools: &mut QuicPools) -> crate::Result<()> {
    self.state = ConnState::Confirmed;
    if self.params.pmtu_probe_after_rtt {
      self.pmtud.hold_until(now_us.saturating_add(self.recovery.rtt.smoothed_us));
    }
    // The generator of the handshake leaves a seed for the challenges of path validation
    if !IS_CLIENT
      && let Some(tls) = self.tls.as_mut()
      && let Some(cold) = self.cold.as_deref_mut()
    {
      cold.paths.set_seed(tls.connection_seed()?);
    }
    self.release_handshake(pools);
    match self.data.keys.as_mut() {
      Some(keys) => self.key.prepare_next(keys, pools),
      None => Ok(()),
    }
  }

  fn crypto_unsent(&self, space: Space) -> &[u8] {
    let Some(tls) = &self.tls else {
      return &[];
    };
    let Some(sp) = space_ref(&self.data, &self.handshake, space) else {
      return &[];
    };
    let sent = usize::try_from(sp.crypto_tx).unwrap_or(usize::MAX);
    tls.output(space).get(sent..).unwrap_or_default()
  }

  fn drop_packet(&mut self) {
    self.count(|el| el.packets_dropped = el.packets_dropped.wrapping_add(1));
  }

  fn enter_closing(&mut self, now_us: u64, close: CloseFrame) {
    if !matches!(self.state, ConnState::Handshake | ConnState::Confirmed) {
      return;
    }
    self.state = ConnState::Closing;
    self.close = close;
    self.close_owed = true;
    self.streams.on_closing();
    self.close_deadline_us = now_us.saturating_add(self.pto_us().saturating_mul(3));
    self.recovery.loss_timer_us = None;
    self.recovery.probes = 0;
    self.closing_datagrams = 0;
    self.closing_threshold = 1;
  }

  fn enter_draining(&mut self, now_us: u64) {
    match self.state {
      ConnState::Handshake | ConnState::Confirmed => {
        self.close_deadline_us = now_us.saturating_add(self.pto_us().saturating_mul(3));
        self.recovery.loss_timer_us = None;
        self.recovery.probes = 0;
      }
      // What is left of the closing period
      ConnState::Closing => {}
      ConnState::Draining | ConnState::Closed => return,
    }
    self.state = ConnState::Draining;
    self.close_owed = false;
    self.streams.on_closing();
  }

  // The PING frames a window of one second takes (ruling T21-g): the base budget plus two per
  // smoothed RTT, because a conformant peer in a run of ACK-only packets pings once per RTT (RFC
  // 9000 section 13.2.4) and PTO and path MTU probes add to that. At most `PING_ALLOWANCE_CAP`,
  // or the base if that is larger. Before the first RTT sample the initial RTT is the smoothed one.
  // One division, and only for a PING frame.
  fn ping_allowance(&self) -> u32 {
    let base = self.params.limits.ping_budget;
    let per_rtt = 1_000_000u64 / self.recovery.rtt.smoothed_us.max(1);
    let scaled = u64::from(base).saturating_add(per_rtt.saturating_mul(2));
    let cap = u64::from(base.max(PING_ALLOWANCE_CAP));
    let computed = u32::try_from(scaled.min(cap)).unwrap_or(u32::MAX);
    // Ruling T23-m: an IP change resets the RTT estimate (RFC 9000 section 9.4), which would drop
    // the allowance to the pre-sample base mid-window and close a legitimate client that already
    // pinged within the old allowance. Until the new path has its own RTT sample, keep the floor
    // set at the IP change (the last validated path's allowance). A same-path flooder never sets
    // the floor, so it is still closed; a flooder that rebinds is still bounded by the floor.
    if self.recovery.rtt.first_sample_us.is_none() {
      computed.max(self.ping_allowance_floor)
    } else {
      computed
    }
  }

  // A budget is spent: the application closes the connection with its excessive load code. The
  // error has the code that such a close takes before 1-RTT (RFC 9000 section 10.2.3).
  fn excessive_load(&mut self, now_us: u64) -> crate::Error {
    cold_path();
    let code = self.params.limits.excessive_load_app_code;
    self.enter_closing(now_us, CloseFrame { app: true, code, requested: false });
    crate::Error::QuicClose(TransportErrorCode::ApplicationError, QuicError::ExcessiveLoad)
  }

  // A spent budget of the streams closes as the budgets of the connection do.
  fn on_streams_rslt(&mut self, now_us: u64, rslt: crate::Result<()>) -> crate::Result<()> {
    match rslt {
      Err(crate::Error::QuicClose(_, QuicError::ExcessiveLoad)) => Err(self.excessive_load(now_us)),
      _ => rslt,
    }
  }

  // If the next datagram must have at least 1200 bytes: it has the Initial packet of a client, an
  // ack-eliciting Initial packet of a server or a PATH_RESPONSE (RFC 9000 sections 8.2.2 and
  // 14.1).
  fn needs_full_datagram(&self) -> bool {
    let has_keys =
      |space| space_ref(&self.data, &self.handshake, space).is_some_and(|el| el.keys.is_some());
    if self.state == ConnState::Closing {
      return IS_CLIENT && has_keys(Space::Initial);
    }
    let initial =
      self.space_wants_send(Space::Initial) && (IS_CLIENT || self.initial_elicits(true));
    let path = (self.path_response.is_some() && !self.path_response_off)
      || self.cold.as_deref().is_some_and(|el| el.paths.challenge_due());
    initial || (path && has_keys(Space::Data))
  }

  fn idle_deadline(&self) -> Option<u64> {
    let local = self.params.max_idle_timeout_ms;
    let peer = if self.has_peer_params { self.peer_idle_timeout_ms } else { 0 };
    // The smaller of the two that are not zero (RFC 9000 section 10.1), at least 3 PTOs
    let timeout_ms = match (local, peer) {
      (0, 0) => return None,
      (0, elem) | (elem, 0) => elem,
      (local, peer) => local.min(peer),
    };
    let timeout = timeout_ms.saturating_mul(1_000).max(self.pto_us().saturating_mul(3));
    Some(self.last_activity_us.saturating_add(timeout))
  }

  // An ACK frame of `space` (RFC 9002 section 6 and appendix A.7): the frames of the packets that
  // it acknowledges go back, an RTT sample is taken, losses are detected.
  fn on_ack(
    &mut self,
    now_us: u64,
    space: Space,
    ack: &AckFrame<'_>,
    pools: &mut QuicPools,
  ) -> crate::Result<()> {
    let max_ranges = usize::try_from(self.params.limits.max_ack_ranges).unwrap_or(usize::MAX);
    let max_in_flight = self.params.max_in_flight;
    let Self {
      data,
      handshake,
      handshake_done_owed,
      key,
      max_datagram,
      pmtud,
      recovery,
      streams,
      ..
    } = self;
    let Some(sp) = space_mut(data, handshake, space) else {
      return Ok(());
    };
    if ack.largest >= sp.sent.next_pn() {
      return Err(violation(QuicError::AckOfUnsentPacket));
    }
    if sp.largest_acked.is_none_or(|elem| ack.largest > elem) {
      sp.largest_acked = Some(ack.largest);
    }
    let PacketSpace {
      ack_eliciting_in_flight,
      ack_only_largest,
      ack_only_pn,
      crypto_lost,
      recv,
      sent,
      ..
    } = sp;
    // The window grows after loss detection: what the packets acknowledged here would give, sent
    // after the recovery period that is current now (RFC 9002 appendix A.7, review J1)
    let recovery_start = recovery.cc.recovery_start_us();
    let (mut since_recovery, mut all) = ((0usize, None), (0usize, None));
    let mut our_ack = None;
    let (mut largest_sent_us, mut ack_eliciting, mut late, mut newly) = (None, false, 0u64, false);
    // The frames of every acknowledged packet go back, even after an error
    let mut rslt = Ok(());
    for range in ack.ranges().take(max_ranges) {
      let range = range?;
      for pn in sent.window(*range.start(), *range.end()) {
        let Some(packet) = sent.take(pn) else {
          continue;
        };
        newly = true;
        ack_eliciting |= packet.ack_eliciting;
        // The ACK frame of the newest ACK-only packet, which its record does not keep (task 23c)
        if pn == *ack_only_pn {
          our_ack = our_ack.max(Some(*ack_only_largest));
        }
        // A packet of another path gives no sample of this one (RFC 9000 section 9.4)
        if pn == ack.largest && packet.kind != SentKind::OffPath {
          largest_sent_us = Some(packet.time_us);
        }
        match packet.kind {
          SentKind::InFlight | SentKind::MtuProbe | SentKind::OffPath | SentKind::Probed => {
            recovery.on_acked(&packet);
            if packet.counts_for_congestion() {
              let size = usize::from(packet.size);
              all = (all.0.saturating_add(size), all.1.max(Some(packet.time_us)));
              if recovery_start.is_none_or(|elem| packet.time_us > elem) {
                let newest = since_recovery.1.max(Some(packet.time_us));
                since_recovery = (since_recovery.0.saturating_add(size), newest);
              }
            }
            if packet.ack_eliciting {
              *ack_eliciting_in_flight = ack_eliciting_in_flight.saturating_sub(1);
            }
            if let Some(size) = pmtud.on_probe_acked(pn) {
              *max_datagram = size;
              recovery.cc.set_max_datagram(size);
            }
          }
          SentKind::Lost => late = late.wrapping_add(1),
          SentKind::NotInFlight => {}
        }
        if space == Space::Data && pn >= key.local_first_pn && !key.local_acked {
          key.local_acked = true;
          key.local_acked_us = now_us;
        }
        let mut cursor = FrameRefPool::cursor(packet.frames);
        while let Some(frame) = cursor.next(&pools.frame_refs) {
          match frame {
            FrameRef::Ack { largest } => our_ack = our_ack.max(Some(largest)),
            FrameRef::Crypto { offset, len } => {
              if rslt.is_ok() {
                rslt = trim_acked_crypto(crypto_lost, offset, len, &mut pools.frame_refs);
              }
            }
            // Also late, before a copy owed for its loss went (review J8)
            FrameRef::HandshakeDone => *handshake_done_owed = false,
            FrameRef::PathChallenge | FrameRef::RetireConnectionId { .. } => {}
            _ => {
              if rslt.is_ok() {
                rslt = streams.on_frame_acked(frame, pools);
              }
            }
          }
        }
        pools.frame_refs.free(packet.frames);
      }
    }
    if let Some(elem) = our_ack {
      recv.on_ack_of_our_ack(elem, pools);
    }
    if !newly {
      return rslt;
    }
    // A sample of the largest packet acknowledged, if the frame acknowledged one that elicited it
    if let Some(sent_us) = largest_sent_us
      && ack_eliciting
    {
      // The ACK Delay of Initial and Handshake packets is meaningless (RFC 9002 section 5.3)
      let ack_delay = if space == Space::Data {
        ack.delay.checked_shl(u32::from(self.peer_ack_delay_exponent)).unwrap_or(u64::MAX)
      } else {
        0
      };
      let confirmed = self.state == ConnState::Confirmed;
      let max_ack_delay = self.peer_max_ack_delay_us();
      self.recovery.rtt.update(
        now_us.saturating_sub(sent_us),
        ack_delay,
        max_ack_delay,
        confirmed,
        now_us,
      );
    }
    self.count(|el| el.late_acks = el.late_acks.wrapping_add(late));
    if IS_CLIENT && space == Space::Handshake {
      self.handshake_acked = true;
    }
    rslt?;
    self.detect_lost(space, now_us, pools)?;
    self.recovery.grow(since_recovery, all, recovery_start, now_us, max_in_flight);
    // RFC 9002 appendix A.7: a client that is not sure that the server validated its address
    // keeps backing off
    if self.peer_validated_address() {
      self.recovery.pto_count = 0;
    }
    self.recovery.on_ack_done();
    Ok(())
  }

  // CRYPTO data, in order to TLS, what comes early buffered.
  fn on_crypto(
    &mut self,
    now_us: u64,
    space: Space,
    offset: u64,
    data: &[u8],
    app: &mut A,
    pools: &mut QuicPools,
  ) -> crate::Result<()> {
    let Some(tls) = &mut self.tls else {
      // Once the handshake is confirmed, only post-handshake messages could come, which a client
      // never sends to this server
      return Err(crate::Error::QuicClose(
        TransportErrorCode::Crypto(AlertDescription::UnexpectedMessage.into()),
        QuicError::CryptoDataAtWrongLevel,
      ));
    };
    let data_keys = &mut self.data.keys;
    let batched_hp = self.params.batched_hp;
    if space == Space::Data {
      // Nothing is read after the handshake: TLS closes the connection
      feed(tls, space, data, None, data_keys, batched_hp)?;
      return self.on_tls_progress(now_us, app, pools);
    }
    let Some(hs) = self.handshake.as_deref_mut() else {
      return Ok(());
    };
    let HandshakeSpaces { handshake, handshake_rx, initial_rx, .. } = hs;
    // Initial data yields the keys of Handshake, Handshake data those of 1-RTT
    let (rx, mut handshake_keys) = if space == Space::Initial {
      (initial_rx, Some(&mut handshake.keys))
    } else {
      (handshake_rx, None)
    };
    let direct = rx.accept(offset, data, pools)?;
    feed(tls, space, direct, handshake_keys.as_deref_mut(), data_keys, batched_hp)?;
    loop {
      let buffered = rx.buffered();
      if buffered.is_empty() {
        break;
      }
      let len = buffered.len();
      feed(tls, space, buffered, handshake_keys.as_deref_mut(), data_keys, batched_hp)?;
      rx.consume(len, pools);
    }
    self.on_tls_progress(now_us, app, pools)
  }

  fn on_datagram_while_closing(&mut self) {
    // A CONNECTION_CLOSE in reply after 1, 2, 4, ... datagrams (RFC 9000 section 10.2.1)
    self.closing_datagrams = self.closing_datagrams.saturating_add(1);
    if self.closing_datagrams >= self.closing_threshold {
      self.close_owed = true;
      self.closing_datagrams = 0;
      self.closing_threshold = self.closing_threshold.saturating_mul(2);
    }
  }

  // What TLS learned: the transport parameters of the peer, the end of the handshake.
  fn on_tls_progress(
    &mut self,
    now_us: u64,
    app: &mut A,
    pools: &mut QuicPools,
  ) -> crate::Result<()> {
    let Some(tls) = &self.tls else {
      return Ok(());
    };
    let peer_params = if self.has_peer_params {
      None
    } else {
      tls
        .peer_transport_params()
        .map(|elem| TransportParams::decode(elem, IS_CLIENT))
        .transpose()?
    };
    let is_complete = tls.is_complete();
    if let Some(elem) = peer_params {
      self.check_peer_params(&elem)?;
      #[cfg(test)]
      if IS_CLIENT {
        self.test_client.get_or_insert_default().peer_reset_token = elem.stateless_reset_token;
      }
      self.has_peer_params = true;
      self.peer_ack_delay_exponent = elem.ack_delay_exponent;
      self.peer_idle_timeout_ms = elem.max_idle_timeout_ms;
      self.peer_max_ack_delay_ms = elem.max_ack_delay_ms;
      self.streams.on_peer_params(&elem);
      // The probes wait for the confirmation of the handshake
      self.pmtud.start(elem.max_udp_payload_size, &self.peer, self.max_datagram);
      if let Some(cold) = self.cold.as_deref_mut() {
        cold.paths.set_peer_max_udp_payload_size(elem.max_udp_payload_size);
      }
    }
    if is_complete && !self.handshake_complete {
      self.handshake_complete = true;
      self.handshake_done_owed = !IS_CLIENT;
      let mut cx =
        ConnCtx::new(&mut self.app_state, &mut self.streams, pools, &self.params, now_us);
      app.on_established(&mut cx)?;
    }
    Ok(())
  }

  // The `max_ack_delay` of the peer.
  const fn peer_max_ack_delay_us(&self) -> u64 {
    self.peer_max_ack_delay_ms.saturating_mul(1_000)
  }

  // The current probe timeout of the 1-RTT space without backoff (RFC 9002 section 6.2.1), for the
  // timers of RFC 9000 that count in PTOs.
  const fn pto_us(&self) -> u64 {
    self.recovery.rtt.pto_base_us().saturating_add(self.peer_max_ack_delay_us())
  }

  // The frames of a decrypted packet, in one walk. Returns whether the packet was ack-eliciting.
  fn recv_frames(
    &mut self,
    now_us: u64,
    space: Space,
    payload: &[u8],
    rx: &mut RxPath,
    app: &mut A,
    pools: &mut QuicPools,
  ) -> crate::Result<bool> {
    let mut ack_eliciting = false;
    let mut is_empty = true;
    rx.non_probing = false;
    for frame in FrameReader::new(payload, space) {
      let frame = frame?;
      is_empty = false;
      // RFC 9000 section 9.1
      rx.non_probing |= !matches!(
        frame,
        Frame::Padding(_)
          | Frame::PathChallenge(_)
          | Frame::PathResponse(_)
          | Frame::NewConnectionId { .. }
      );
      match frame {
        Frame::Padding(_) => {}
        Frame::Ack(ack) => self.on_ack(now_us, space, &ack, pools)?,
        #[cfg_attr(not(test), expect(unused_variables, reason = "kept by clients of tests"))]
        Frame::ConnectionClose { app, code, .. } => {
          #[cfg(test)]
          if IS_CLIENT {
            self.test_client.get_or_insert_default().peer_close = Some((app, code));
          }
          self.enter_draining(now_us);
          return Ok(ack_eliciting);
        }
        Frame::Crypto { offset, data } => {
          ack_eliciting = true;
          self.on_crypto(now_us, space, offset, data, app, pools)?;
          if self.apply_app_close(now_us) {
            return Ok(ack_eliciting);
          }
        }
        Frame::HandshakeDone => {
          ack_eliciting = true;
          if !IS_CLIENT {
            return Err(violation(QuicError::FrameFromWrongRole));
          }
          // A client confirms the handshake when the server says so (RFC 9001 section 4.1.2)
          if self.state == ConnState::Handshake {
            self.confirm(now_us, pools)?;
          }
        }
        Frame::NewToken(_) => {
          ack_eliciting = true;
          if !IS_CLIENT {
            return Err(violation(QuicError::FrameFromWrongRole));
          }
        }
        Frame::PathChallenge(data) => {
          // Answered, always (RFC 9000 section 8.2.2), and the latest one only, on the path where
          // it came from
          ack_eliciting = true;
          self.path_response = Some(data);
          self.path_response_off = !rx.from_peer;
          rx.challenged = true;
          let budget = self.params.limits.path_challenge_budget;
          if !self.cold.as_deref_mut().is_none_or(|el| el.path_challenges.take(budget, now_us)) {
            return Err(self.excessive_load(now_us));
          }
        }
        Frame::Ping => {
          ack_eliciting = true;
          let budget = self.ping_allowance();
          if !self.cold.as_deref_mut().is_none_or(|el| el.pings.take(budget, now_us)) {
            return Err(self.excessive_load(now_us));
          }
        }
        Frame::Stream { id, offset, data, fin } => {
          ack_eliciting = true;
          let (params, streams) = (&self.params, &mut self.streams);
          let rslt = streams.on_stream(
            app,
            &mut self.app_state,
            pools,
            params,
            now_us,
            (id, offset, data, fin),
          );
          self.on_streams_rslt(now_us, rslt)?;
          if self.apply_app_close(now_us) {
            return Ok(ack_eliciting);
          }
        }
        Frame::ResetStream { id, code, final_size } => {
          ack_eliciting = true;
          let (params, streams) = (&self.params, &mut self.streams);
          let rslt = streams.on_reset_stream(
            app,
            &mut self.app_state,
            pools,
            params,
            now_us,
            (id, code, final_size),
          );
          self.on_streams_rslt(now_us, rslt)?;
          if self.apply_app_close(now_us) {
            return Ok(ack_eliciting);
          }
        }
        Frame::StopSending { id, code } => {
          ack_eliciting = true;
          let (params, streams) = (&self.params, &mut self.streams);
          let rslt =
            streams.on_stop_sending(app, &mut self.app_state, pools, params, now_us, id, code);
          self.on_streams_rslt(now_us, rslt)?;
          if self.apply_app_close(now_us) {
            return Ok(ack_eliciting);
          }
        }
        Frame::MaxData(max) => {
          ack_eliciting = true;
          self.streams.on_max_data(max);
        }
        Frame::MaxStreamData { id, max } => {
          ack_eliciting = true;
          self.streams.on_max_stream_data(pools, &self.params, id, max)?;
        }
        Frame::MaxStreams { bidi, max } => {
          ack_eliciting = true;
          self.streams.on_max_streams(bidi, max);
        }
        Frame::DataBlocked(_) => {
          ack_eliciting = true;
          self.count(|el| el.data_blocked_in = el.data_blocked_in.wrapping_add(1));
          self.streams.on_data_blocked(&self.params);
        }
        Frame::StreamDataBlocked { id, .. } => {
          ack_eliciting = true;
          self.count(|el| el.stream_data_blocked_in = el.stream_data_blocked_in.wrapping_add(1));
          self.streams.on_stream_data_blocked(pools, &self.params, id)?;
        }
        Frame::StreamsBlocked { bidi, .. } => {
          ack_eliciting = true;
          self.count(|el| el.streams_blocked_in = el.streams_blocked_in.wrapping_add(1));
          self.streams.on_streams_blocked(bidi);
        }
        Frame::NewConnectionId { seq, retire_prior_to, cid, reset_token } => {
          ack_eliciting = true;
          #[cfg(test)]
          if IS_CLIENT {
            let state = self.test_client.get_or_insert_default();
            state.new_connection_ids = state.new_connection_ids.wrapping_add(1);
          }
          self.on_new_connection_id(now_us, seq, retire_prior_to, cid, reset_token)?;
        }
        Frame::RetireConnectionId(_) => {
          ack_eliciting = true;
          // A server gives one CID, sequence 0, which every packet of the client is sent to (spec
          // section 5.4): retiring it, or a CID that was never given, is a violation (RFC 9000
          // section 19.16)
          if !IS_CLIENT {
            return Err(violation(QuicError::ConnectionIdInvalid));
          }
        }
        Frame::PathResponse(data) => {
          ack_eliciting = true;
          if !IS_CLIENT {
            self.on_path_response(now_us, data)?;
          }
        }
      }
    }
    if is_empty {
      return Err(violation(QuicError::EmptyPacket));
    }
    Ok(ack_eliciting)
  }

  // One packet of `space`, from its first byte to its last, whose packet number starts at
  // `pn_offset`. Errors are connection errors.
  fn recv_packet(
    &mut self,
    now_us: u64,
    space: Space,
    packet: &mut [u8],
    pn_offset: usize,
    scid: Cid,
    rx: &mut RxPath,
    app: &mut A,
    pools: &mut QuicPools,
  ) -> crate::Result<()> {
    let pto_us = self.pto_us();
    let Some(sp) = space_mut(&mut self.data, &mut self.handshake, space) else {
      self.drop_packet();
      return Ok(());
    };
    let Some(keys) = sp.keys.as_mut() else {
      self.drop_packet();
      return Ok(());
    };
    // Every generation of the 1-RTT keys has the same header protection key (RFC 9001 section 6)
    let Ok((pn, pn_len, first)) =
      remove_header_protection(keys.remote.hp(), packet, pn_offset, sp.recv.largest())
    else {
      self.drop_packet();
      return Ok(());
    };
    if sp.recv.is_duplicate(pn) {
      self.count(|el| el.duplicates = el.duplicates.wrapping_add(1));
      return Ok(());
    }
    let largest = sp.recv.largest();
    // The generation that opens the packet, chosen before it is decrypted: a failure loses the
    // buffer (ruling T9-a)
    let generation = if space == Space::Data {
      let Some(elem) = self.key.choose(first & KEY_PHASE_BIT != 0, pn, sp.recv.largest()) else {
        self.drop_packet();
        return Ok(());
      };
      elem
    } else {
      Generation::Current
    };
    let header_len = pn_offset.wrapping_add(pn_len);
    let suite = keys.remote.suite();
    let opened = self
      .key
      .remote(generation, keys)
      .and_then(|el| open_payload(el.aead(), el.iv(), packet, header_len, pn).ok());
    let Some(payload) = opened else {
      // Forged, corrupted or for other keys: the buffer is lost (RFC 9001 section 5.3)
      self.drop_packet();
      return self.on_open_failure(suite);
    };
    if generation == Generation::Next {
      let next_pn = sp.sent.next_pn();
      let followed = self.key.on_peer_update(pn, now_us, pto_us, keys, next_pn)?;
      self.count(|el| el.key_updates = el.key_updates.wrapping_add(u64::from(followed)));
    }
    let reserved = if first & LONG_HEADER_BIT == 0 {
      first & SHORT_RESERVED_BITS
    } else {
      first & LONG_RESERVED_BITS
    };
    if reserved != 0 {
      return Err(violation(QuicError::ReservedBitsSet));
    }
    if space == Space::Initial && !self.peer_cid_known {
      // The CID that the peer chose (RFC 9000 section 7.2)
      self.peer_cid = scid;
      self.peer_cid_known = true;
    }
    let ack_eliciting = self.recv_frames(now_us, space, payload, rx, app, pools)?;
    // The address changes only for the highest-numbered non-probing packet (RFC 9000 section 9.3)
    if space == Space::Data
      && !rx.from_peer
      && rx.non_probing
      && largest.is_none_or(|elem| pn > elem)
    {
      rx.migrate = true;
    }
    if let Some(sp) = space_mut(&mut self.data, &mut self.handshake, space) {
      let _is_new = sp.recv.on_packet(pn, ack_eliciting, now_us, pools);
    }
    self.after_packet(now_us, space, pools)?;
    Ok(())
  }

  // Seals `packet`, which is in `buffer`, and records it. With `hp`, where `buffer` starts in the
  // arena and the batch, a 1-RTT packet leaves its header protection to the batch (ruling T18-b).
  fn seal(
    &mut self,
    now_us: u64,
    buffer: &mut [u8],
    packet: &OpenPacket,
    hp: Option<(usize, &mut HpBatch)>,
  ) -> crate::Result<usize> {
    let Some(sp) = space_mut(&mut self.data, &mut self.handshake, packet.space) else {
      return Err(crate::Error::ProgrammingError);
    };
    let Some(keys) = &sp.keys else {
      return Err(crate::Error::ProgrammingError);
    };
    let Some(bytes) = buffer.get_mut(packet.start..) else {
      return Err(crate::Error::ProgrammingError);
    };
    if let Some(at) = packet.length_at {
      let length = packet.pn_len.wrapping_add(packet.payload_len).wrapping_add(AEAD_TAG_LEN);
      let [b0, b1] = u16::try_from(length).unwrap_or(u16::MAX).to_be_bytes();
      if let Some(field) = bytes.get_mut(at..at.wrapping_add(LENGTH_FIELD_LEN)) {
        field.copy_from_slice(&[0x40 | (b0 & 0x3f), b1]);
      }
    }
    let fields = (packet.pn_offset, packet.pn, packet.pn_len, packet.payload_len);
    let len = match hp {
      Some((at, batch)) if packet.space == Space::Data => {
        protect_deferred(&keys.local, bytes, fields, at.wrapping_add(packet.start), batch)?
      }
      _ => protect(&keys.local, bytes, fields.0, fields.1, fields.2, fields.3)?,
    };
    if self.state == ConnState::Closing {
      sp.sent.skip();
    } else {
      let kind = if packet.mtu_probe {
        SentKind::MtuProbe
      } else if packet.off_path {
        SentKind::OffPath
      } else if packet.ack_eliciting || packet.padded {
        SentKind::InFlight
      } else {
        SentKind::NotInFlight
      };
      let record = SentPacket {
        time_us: now_us,
        size: u16::try_from(len).unwrap_or(u16::MAX),
        ack_eliciting: packet.ack_eliciting,
        kind,
        frames: packet.frames,
      };
      sp.sent.on_sent(record);
      #[cfg(feature = "_h3-loopback-client")]
      if !IS_CLIENT && packet.ack_eliciting {
        let in_flight = sp.sent.records().filter(|el| el.in_flight()).count();
        crate::quic::diag::on_record(packet.frames.len().div_ceil(8), in_flight);
      }
      if let Some(largest) = packet.ack_only_largest {
        (sp.ack_only_pn, sp.ack_only_largest) = (packet.pn, largest);
      }
      if packet.ack_eliciting {
        sp.ack_eliciting_in_flight = sp.ack_eliciting_in_flight.saturating_add(1);
        sp.last_ack_eliciting_us = now_us;
      }
      self.recovery.on_sent(&record);
    }
    let ack_only = !packet.ack_eliciting && self.state != ConnState::Closing;
    self.count(|el| {
      el.packets_out = el.packets_out.wrapping_add(1);
      el.ack_only_out = el.ack_only_out.wrapping_add(u64::from(ack_only));
    });
    Ok(len)
  }

  fn space_wants_send(&self, space: Space) -> bool {
    let Some(sp) = space_ref(&self.data, &self.handshake, space) else {
      return false;
    };
    if sp.keys.is_none() {
      return false;
    }
    let probe = self.recovery.probes > 0 && self.recovery.probe_space == space;
    let mut wants = sp.recv.ack_pending()
      || !self.crypto_unsent(space).is_empty()
      || !sp.crypto_lost.is_empty()
      || probe;
    if space == Space::Data {
      wants |= self.handshake_done_owed
        || (self.path_response.is_some() && !self.path_response_off)
        || self.streams.wants_send()
        || self
          .cold
          .as_deref()
          .is_some_and(|el| el.retire_next < el.retire_prior_to || el.paths.challenge_due());
      #[cfg(test)]
      {
        wants |= self.test_client.as_ref().is_some_and(|el| !el.frames.is_empty());
      }
    }
    wants
  }

  fn enter_closed(&mut self, app: &mut A, pools: &mut QuicPools) {
    self.release_all(pools);
    app.on_closed(&mut self.app_state);
  }

  fn wants_send(&self) -> bool {
    match self.state {
      ConnState::Handshake | ConnState::Confirmed => {
        SPACES.into_iter().any(|space| self.space_wants_send(space))
          || self.mtu_probe_due().is_some()
          || self.off_path_due().is_some()
      }
      ConnState::Closing => self.close_owed,
      ConnState::Draining | ConnState::Closed => false,
    }
  }

  fn with_parts(
    params: &ConnParams,
    local_cid: Cid,
    peer_cid: Cid,
    meta: DatagramMeta,
    tls: QuicTls<IS_CLIENT, RNG, TCX>,
    handshake: Box<HandshakeSpaces>,
    now_us: u64,
    pools: &mut QuicPools,
  ) -> Self {
    Self {
      address_validated: false,
      app_state: A::ConnState::default(),
      bytes_received: 0,
      bytes_sent: 0,
      close: CloseFrame { app: false, code: 0, requested: false },
      close_deadline_us: 0,
      cold: Some(ConnCold::take(pools)),
      close_owed: false,
      closing_datagrams: 0,
      closing_threshold: 1,
      flush_acked: false,
      handshake_acked: false,
      handshake_complete: false,
      handshake_done_owed: false,
      has_peer_params: false,
      idle_restart_on_send: true,
      key: KeyPhase::new(),
      last_activity_us: now_us,
      ping_allowance_floor: 0,
      local: meta.local,
      local_cid,
      max_datagram: INITIAL_MAX_DATAGRAM,
      params: ConnParams { peer: meta.peer.ip(), ..*params },
      path_response: None,
      path_response_off: false,
      peer: meta.peer,
      peer_cid,
      peer_cid_known: false,
      peer_ack_delay_exponent: TransportParams::default().ack_delay_exponent,
      peer_idle_timeout_ms: 0,
      peer_max_ack_delay_ms: TransportParams::default().max_ack_delay_ms,
      pmtud: Pmtud::new(),
      recovery: Recovery::new(INITIAL_MAX_DATAGRAM),
      data: PacketSpace::new(),
      handshake: Some(handshake),
      state: ConnState::Handshake,
      streams: Streams::new(params, IS_CLIENT, pools),
      tls: Some(tls),
      #[cfg(test)]
      test_client: None,
    }
  }

  // One datagram: a packet of each space with something to send, padded and sealed. Returns its
  // length, zero if nothing fit. `hp_at`: where `buffer` starts in the arena, if the header
  // protection of its 1-RTT packet waits for a batch.
  fn write_datagram(
    &mut self,
    now_us: u64,
    buffer: &mut [u8],
    hp_at: Option<usize>,
    pools: &mut QuicPools,
  ) -> crate::Result<usize> {
    let closing = self.state == ConnState::Closing;
    // Probes owed in a space whose keys are gone are not owed anymore
    let probe_space = self.recovery.probe_space;
    if !space_ref(&self.data, &self.handshake, probe_space).is_some_and(|el| el.keys.is_some()) {
      self.recovery.probes = 0;
    }
    // Probes, CONNECTION_CLOSE and ACK-only packets are not held back by the window or the pacer
    let probing = !closing && self.recovery.probes > 0;
    let allow_ae = closing || probing || self.window_allows(now_us, buffer.len());
    let mut packets: [Option<OpenPacket>; 3] = [None, None, None];
    let mut pos = 0usize;
    for (nth, space) in SPACES.into_iter().enumerate() {
      let wanted = if closing {
        space_ref(&self.data, &self.handshake, space).is_some_and(|el| el.keys.is_some())
      } else {
        self.space_wants_send(space)
      };
      // An ack-eliciting Initial packet of a server, a probe included, needs a datagram of 1200
      // bytes, which the amplification limit may not leave (carried rule 1)
      let initial_too_short = !IS_CLIENT
        && !closing
        && space == Space::Initial
        && buffer.len() < MIN_DATAGRAM_LEN
        && self.initial_elicits(allow_ae);
      if !wanted || initial_too_short {
        continue;
      }
      let Some(out) = buffer.get_mut(pos..) else {
        break;
      };
      let probe = probing && self.recovery.probe_space == space;
      let mut frames = FrameRefRange::EMPTY;
      let written =
        match self.write_packet(now_us, space, out, closing, allow_ae, probe, &mut frames, pools) {
          Ok(elem) => elem,
          Err(err) => {
            cold_path();
            // Nothing of the datagram goes: the packets before this one give theirs back too
            pools.frame_refs.free(frames);
            for packet in packets.iter().flatten() {
              pools.frame_refs.free(packet.frames);
            }
            return Err(err);
          }
        };
      match (written, packets.get_mut(nth)) {
        (Some(mut packet), Some(slot)) => {
          packet.start = pos;
          pos = pos.wrapping_add(packet.len());
          *slot = Some(packet);
        }
        // A packet that does not go holds no reference, or gives them back
        _ => pools.frame_refs.free(frames),
      }
    }
    if packets.iter().all(Option::is_none) {
      return Ok(0);
    }
    let full = packets.iter().flatten().any(|el| el.full_datagram);
    let target = if full { MIN_DATAGRAM_LEN.min(buffer.len()) } else { 0 };
    if let Some(padding) = target.checked_sub(pos).filter(|elem| *elem > 0)
      && let Some(last) = packets.iter_mut().flatten().last()
    {
      // PADDING frames at the end of the last packet
      let from = last.start.wrapping_add(last.header_len).wrapping_add(last.payload_len);
      if let Some(bytes) = buffer.get_mut(from..from.wrapping_add(padding)) {
        bytes.fill(0);
        last.payload_len = last.payload_len.wrapping_add(padding);
        last.padded = true;
        pos = pos.wrapping_add(padding);
      }
    }
    if packets.iter().flatten().any(|el| el.challenge)
      && let Some(cold) = self.cold.as_deref_mut()
    {
      cold.paths.on_challenge_datagram(pos);
    }
    let mut sent_handshake = false;
    let mut ack_eliciting = false;
    let mut in_flight = false;
    for (nth, packet) in packets.iter().flatten().enumerate() {
      let hp = hp_at.map(|el| (el, &mut pools.hp_batch));
      if let Err(err) = self.seal(now_us, buffer, packet, hp) {
        cold_path();
        // The packets that are not sealed are not recorded: they give their frame references back
        for elem in packets.iter().flatten().skip(nth) {
          pools.frame_refs.free(elem.frames);
        }
        return Err(err);
      }
      sent_handshake |= packet.space == Space::Handshake;
      ack_eliciting |= packet.ack_eliciting;
      in_flight |= packet.ack_eliciting || packet.padded;
      if probing && packet.ack_eliciting && packet.space == self.recovery.probe_space {
        self.recovery.probes = self.recovery.probes.saturating_sub(1);
      }
    }
    if in_flight && !closing {
      self.recovery.pacer.on_sent(pos);
    }
    if closing {
      self.close_owed = false;
    }
    if ack_eliciting && self.idle_restart_on_send {
      // RFC 9000 section 10.1
      self.last_activity_us = now_us;
      self.idle_restart_on_send = false;
    }
    if IS_CLIENT && sent_handshake {
      // RFC 9001 section 4.9.1
      if let Some(elem) = &mut self.handshake {
        elem.discard_initial(&mut self.recovery, pools);
      }
    }
    Ok(pos)
  }

  // A packet of `space` at the start of `out`, not sealed yet, or `None` if nothing fit. Only an
  // ACK goes unless `allow_ae`; a `probe` is ack-eliciting, a PING if nothing else is.
  //
  // The frame references of the packet go into `frames`, empty at first, which the caller frees if
  // this fails: a frame-reference pool at its cap fails after some went in (final review I2).
  fn write_packet(
    &mut self,
    now_us: u64,
    space: Space,
    out: &mut [u8],
    closing: bool,
    allow_ae: bool,
    probe: bool,
    frames: &mut FrameRefRange,
    pools: &mut QuicPools,
  ) -> crate::Result<Option<OpenPacket>> {
    let (dcid, scid) = (self.peer_cid, self.local_cid);
    let confirmed = self.state == ConnState::Confirmed;
    let key_update_after = self.params.key_update_threshold;
    let pto_us = self.pto_us();
    let params = self.params;
    let full_room = out.len() >= MIN_DATAGRAM_LEN;
    let Some(sp) = space_mut(&mut self.data, &mut self.handshake, space) else {
      return Ok(None);
    };
    // A CONNECTION_CLOSE needs a packet number, not a record: it is neither ack-eliciting nor in
    // flight
    if sp.keys.is_none() || (!closing && !sp.sent.reserve(pools)) {
      return Ok(None);
    }
    let pn = sp.sent.next_pn();
    let mut key_phase = false;
    if space == Space::Data
      && let Some(keys) = sp.keys.as_mut()
    {
      let suite = keys.local.suite();
      let limit = params.confidentiality_limit(suite);
      if !closing && keys.local.packets_sealed() >= limit.saturating_sub(1) {
        // No update could come in time (RFC 9001 section 6.6)
        cold_path();
        return Err(crate::Error::QuicClose(
          TransportErrorCode::AeadLimitReached,
          QuicError::AeadLimitReached,
        ));
      }
      if !closing && confirmed {
        let threshold = threshold_for(limit, key_update_after);
        if self.key.maybe_initiate(keys, threshold, pn, now_us, pto_us)?
          && let Some(cold) = self.cold.as_deref_mut()
        {
          cold.stats.key_updates = cold.stats.key_updates.wrapping_add(1);
        }
      }
      key_phase = self.key.local_phase;
    }
    let pn_len = pn_len_for(pn, sp.largest_acked);
    #[cfg(test)]
    let token = match &self.test_client {
      Some(elem) if IS_CLIENT && space == Space::Initial => elem.retry_token.as_slice(),
      _ => &[],
    };
    #[cfg(not(test))]
    let token = &[];
    let Some((header_len, pn_offset, length_at)) =
      write_header(out, space, &dcid, &scid, (pn, pn_len), key_phase, token)
    else {
      return Ok(None);
    };
    let Some(limit) = out.len().checked_sub(AEAD_TAG_LEN) else {
      return Ok(None);
    };
    if limit < header_len.wrapping_add(MIN_PN_AND_PAYLOAD_LEN) {
      return Ok(None);
    }
    let Some(payload) = out.get_mut(header_len..limit) else {
      return Ok(None);
    };
    let mut fw = FrameWriter::new(payload);
    let mut ack_eliciting = false;
    // The Largest Acknowledged of the ACK frame of the packet, if it has one, until it is a frame
    // reference: left for an ACK-only packet
    let mut ack_largest = None;
    let mut challenge = false;
    let mut full_datagram = false;
    if closing {
      // An application close is a transport one with APPLICATION_ERROR before 1-RTT (RFC 9000
      // section 10.2.3)
      let (app, code) = if self.close.app && space != Space::Data {
        (false, TransportErrorCode::ApplicationError.code())
      } else {
        (self.close.app, self.close.code)
      };
      let reason = if app && self.close.requested { self.streams.close_reason() } else { &[] };
      let _written = fw.write_connection_close(app, code, (!app).then_some(0), reason);
    } else {
      // The first packet of the flush that sends stream data repeats an acknowledgment that the
      // peer may lack (ruling T19-d), in a datagram with room for the data too. It is kept only if
      // the packet ends up with an ack-eliciting frame (below): it never goes alone
      let pending = sp.recv.ack_pending();
      let repeat = space == Space::Data
        && !pending
        && params.repeat_ack
        && allow_ae
        && !self.flush_acked
        && full_room
        && self.streams.wants_send()
        && sp.recv.ack_unconfirmed();
      let mut repeated = None;
      if (pending || repeat)
        && let Some(largest) = sp.recv.largest()
        && let Some(written) = sp.recv.write_ack(&mut fw, self.params.ack_delay_exponent, now_us)
      {
        if repeat {
          repeated = Some((largest, written));
        } else {
          ack_largest = Some(largest);
          self.flush_acked |= space == Space::Data;
          // A frame with its first range only leaves the others owed (carried rule 4)
          if written == AckWritten::All {
            sp.recv.on_ack_sent(pools);
          }
        }
      }
      if space == Space::Data && allow_ae {
        if self.handshake_done_owed && fw.write_handshake_done() {
          pools.frame_refs.push(frames, FrameRef::HandshakeDone)?;
          self.handshake_done_owed = false;
          ack_eliciting = true;
        }
        if let Some(data) = self.path_response
          && !self.path_response_off
          && fw.write_path_response(data)
        {
          self.path_response = None;
          ack_eliciting = true;
          full_datagram = true;
        }
        // The validation of a new path (RFC 9000 sections 8.2.1 and 9.3), in a datagram of 1200
        // bytes if the amplification limit lets it be that large, with new data each time (RFC
        // 9000 section 13.3)
        if let Some(cold) = self.cold.as_deref_mut()
          && cold.paths.challenge_due()
          && fw.remaining() >= PATH_FRAME_LEN
          && fw.write_frame(&Frame::PathChallenge(cold.paths.take_challenge::<RNG>()?))
        {
          pools.frame_refs.push(frames, FrameRef::PathChallenge)?;
          cold.stats.path_challenges_out = cold.stats.path_challenges_out.wrapping_add(1);
          ack_eliciting = true;
          challenge = true;
          full_datagram = true;
        }
        if let Some(cold) = self.cold.as_deref_mut() {
          while cold.retire_next < cold.retire_prior_to
            && fw.write_frame(&Frame::RetireConnectionId(cold.retire_next))
          {
            pools
              .frame_refs
              .push(frames, FrameRef::RetireConnectionId { seq: cold.retire_next })?;
            cold.retire_next = cold.retire_next.wrapping_add(1);
            ack_eliciting = true;
          }
        }
      }
      // Raw frames of a test go whatever the window, as a peer that injects them would
      #[cfg(test)]
      if space == Space::Data
        && let Some(elem) = self.test_client.as_deref_mut()
        && !elem.frames.is_empty()
        && fw.write_bytes(&elem.frames)
      {
        elem.frames.clear();
        ack_eliciting = true;
      }
      if allow_ae {
        let output = self.tls.as_ref().map_or(&[][..], |el| el.output(space));
        ack_eliciting |= write_crypto(output, sp, &mut fw, frames, pools)?;
        if space == Space::Data {
          ack_eliciting |= self.streams.write_frames(&mut fw, frames, pools, &self.params)?;
        }
      }
      if probe && !ack_eliciting && fw.write_bytes(&PING_FRAME) {
        ack_eliciting = true;
      }
      // The ACK frame of an ack-eliciting packet is a frame reference, as its other frames are.
      // That of an ACK-only packet, of which nothing is sent again if it is lost and whose ACK
      // frame only serves ACK-of-ACK, goes with the packet space instead (task 23c): a peer that
      // never acknowledges ACK-only packets would otherwise keep a chunk for each in the sent ring
      if ack_eliciting && let Some(largest) = ack_largest.take() {
        pools.frame_refs.push(frames, FrameRef::Ack { largest })?;
      }
      if let Some((largest, written)) = repeated {
        if !ack_eliciting {
          // Nothing but the repeated ACK, the first frame: the packet does not go
          return Ok(None);
        }
        pools.frame_refs.push(frames, FrameRef::Ack { largest })?;
        self.flush_acked = true;
        if written == AckWritten::All {
          sp.recv.on_ack_sent(pools);
        }
      }
    }
    let mut payload_len = fw.len();
    if payload_len == 0 {
      return Ok(None);
    }
    let mut padded = false;
    if let Some(padding) = MIN_PN_AND_PAYLOAD_LEN.checked_sub(pn_len.wrapping_add(payload_len))
      && padding > 0
      && let Some(bytes) = out.get_mut(header_len.wrapping_add(payload_len)..)
      && let Some(bytes) = bytes.get_mut(..padding)
    {
      bytes.fill(0);
      payload_len = payload_len.wrapping_add(padding);
      padded = true;
    }
    full_datagram |= space == Space::Initial && (IS_CLIENT || ack_eliciting);
    Ok(Some(OpenPacket {
      ack_eliciting,
      ack_only_largest: ack_largest,
      challenge,
      frames: *frames,
      full_datagram,
      header_len,
      length_at,
      mtu_probe: false,
      off_path: false,
      padded,
      payload_len,
      pn,
      pn_len,
      pn_offset,
      space,
      start: 0,
    }))
  }
}

impl<A, RNG, TCX, const IS_CLIENT: bool> QuicConn<A, RNG, TCX, IS_CLIENT>
where
  A: QuicApp,
{
  /// [`Self::abort`] without telling the application: for an endpoint that is dropped, with the
  /// pools, without an application to tell.
  #[inline]
  pub(crate) fn discard(&mut self, pools: &mut QuicPools) {
    if self.state != ConnState::Closed {
      self.release_all(pools);
    }
  }

  // Closed: everything goes back to the pools.
  fn release_all(&mut self, pools: &mut QuicPools) {
    self.state = ConnState::Closed;
    self.release_handshake(pools);
    self.key.release(pools);
    self.data.clear(pools);
    self.streams.release(pools);
    if let Some(elem) = self.cold.take() {
      pools.conn_cold.give(elem);
    }
    self.close_owed = false;
    self.handshake_done_owed = false;
    self.path_response = None;
    self.path_response_off = false;
  }

  // The Initial and Handshake spaces, wiped, and the TLS state go back to their pools; their
  // packets leave the bytes in flight (RFC 9002 section 6.4).
  fn release_handshake(&mut self, pools: &mut QuicPools) {
    if let Some(elem) = self.handshake.take() {
      HandshakeSpaces::give(elem, &mut self.recovery, pools);
    }
    // Back to the thread's pools, zeroed
    self.tls = None;
  }
}

#[cfg(test)]
impl<A, RNG, TCX, const IS_CLIENT: bool> QuicConn<A, RNG, TCX, IS_CLIENT>
where
  A: QuicApp,
{
  /// The smoothed RTT.
  pub(crate) const fn smoothed_rtt_us(&self) -> u64 {
    self.recovery.rtt.smoothed_us
  }

  /// The CONNECTION_CLOSE that the connection owes, if it is closing: (application, code).
  pub(crate) const fn close_code(&self) -> Option<(bool, u64)> {
    match self.state {
      ConnState::Closing => Some((self.close.app, self.close.code)),
      _ => None,
    }
  }

  /// Updates the keys that seal 1-RTT packets now, whatever the rules for starting an update.
  pub(crate) fn force_key_update(&mut self) {
    let next_pn = self.data.sent.next_pn();
    if let Some(keys) = self.data.keys.as_mut() {
      self.key.update_local(keys, next_pn).unwrap();
    }
  }

  /// Forgets the 1-RTT packets that were sent, as if they were acknowledged, for a test that sends
  /// more than the ring holds.
  pub(crate) fn forget_sent_packets(&mut self, pools: &mut QuicPools) {
    for packet in self.data.sent.records() {
      self.recovery.on_gone(packet);
    }
    self.data.sent.release(pools);
    self.data.ack_eliciting_in_flight = 0;
  }

  /// Declares lost every 1-RTT packet in flight, as loss detection would.
  pub(crate) fn declare_in_flight_lost(&mut self, pools: &mut QuicPools) {
    let Self { cold, data, handshake_done_owed, max_datagram, pmtud, recovery, streams, .. } = self;
    let PacketSpace { ack_eliciting_in_flight, crypto_lost, sent, .. } = data;
    let mut lost = LostCtx {
      ack_eliciting_in_flight,
      cold,
      crypto_lost,
      handshake_done_owed,
      max_datagram: *max_datagram,
      pmtud,
      recovery,
      streams,
    };
    let (base, next) = (sent.base(), sent.next_pn());
    for pn in base..next {
      if let Some(record) = sent.get_mut(pn).filter(|el| el.in_flight()) {
        let packet = record.declare_lost();
        lost.on_lost(pn, &packet, pools).unwrap();
      }
    }
  }

  /// The bytes of the packets in flight that congestion control counts.
  pub(crate) const fn bytes_in_flight(&self) -> u64 {
    self.recovery.bytes_in_flight
  }

  /// The congestion window.
  pub(crate) fn cwnd(&self) -> usize {
    use crate::quic::cc::CongestionControl as _;
    self.recovery.cc.window()
  }

  /// The smallest RTT sample that counts.
  pub(crate) const fn min_rtt_us(&self) -> u64 {
    self.recovery.rtt.min_us
  }

  /// The slow start threshold.
  pub(crate) const fn ssthresh(&self) -> usize {
    self.recovery.cc.ssthresh()
  }

  /// The bytes that can be in flight: the congestion window, at most `max_in_flight`.
  pub(crate) fn window_in_use(&self) -> usize {
    self.recovery.window(self.params.max_in_flight)
  }

  /// The key phases of the 1-RTT packets that are sent and of those that arrive.
  pub(crate) const fn key_phases(&self) -> (bool, bool) {
    (self.key.local_phase, self.key.remote_phase)
  }

  /// If the keys of the previous key phase still open packets that arrive late.
  pub(crate) fn keeps_previous_keys(&self) -> bool {
    self.key.other == crate::quic::key_phase::OtherKeys::Previous
  }

  /// The size of the datagrams.
  pub(crate) const fn max_datagram(&self) -> usize {
    self.max_datagram
  }

  /// The probe timeout of the 1-RTT space, without backoff.
  pub(crate) const fn current_pto_us(&self) -> u64 {
    self.recovery.rtt.pto_base_us().saturating_add(self.peer_max_ack_delay_ms.saturating_mul(1_000))
  }

  /// Probe timeouts in a row.
  pub(crate) const fn pto_count(&self) -> u32 {
    self.recovery.pto_count
  }

  /// A Retry of the server, `packet`, with the source CID `scid` and `token` (RFC 9000 section
  /// 17.2.5.2): a client that did not get a packet of the server yet follows the first one whose
  /// integrity tag is valid, sends its Initial packets to `scid`, with the token and keys from
  /// `scid`, and sends its first flight again.
  fn on_retry(&mut self, scid: Cid, token: &[u8], packet: &[u8], pools: &mut QuicPools) {
    let followed = self.test_client.as_deref().is_some_and(|el| el.retry_scid.is_some());
    let Some(hs) = self.handshake.as_deref_mut().filter(|_| !self.peer_cid_known && !followed)
    else {
      return;
    };
    let mut expected = alloc::vec![0; packet.len() + 64];
    let local = self.local_cid;
    let Ok(len) = crate::quic::write_retry(
      local.as_slice(),
      scid.as_slice(),
      hs.original_dcid.as_slice(),
      token,
      &mut expected,
    ) else {
      return;
    };
    if expected.get(..len) != Some(packet) {
      return;
    }
    let Ok(keys) = initial_keys(scid.as_slice(), false) else {
      return;
    };
    hs.initial.discard(&mut self.recovery, pools);
    hs.initial.keys = Some(keys);
    self.peer_cid = scid;
    let state = self.test_client.get_or_insert_default();
    state.retry_scid = Some(scid);
    state.retry_token = token.to_vec();
  }

  /// What the client of tests learned.
  pub(crate) fn test_client(&self) -> Option<&TestClient> {
    self.test_client.as_deref()
  }

  /// Sends `frames`, raw, in the next 1-RTT packet.
  pub(crate) fn queue_test_frames(&mut self, frames: &[u8]) {
    self.test_client.get_or_insert_default().frames.extend_from_slice(frames);
  }

  /// The streams.
  pub(crate) const fn streams(&self) -> &Streams {
    &self.streams
  }

  /// The state of the application.
  pub(crate) const fn app_state(&self) -> &A::ConnState {
    &self.app_state
  }

  /// The streams, to change.
  pub(crate) const fn streams_mut(&mut self) -> &mut Streams {
    &mut self.streams
  }
}

#[cfg(any(test, feature = "_fuzz-conn"))]
#[allow(dead_code, reason = "what tests and the fuzz targets read")]
impl<A, RNG, TCX, const IS_CLIENT: bool> QuicConn<A, RNG, TCX, IS_CLIENT>
where
  A: QuicApp,
{
  /// If the address of the peer is validated.
  pub(crate) const fn address_validated(&self) -> bool {
    self.address_validated
  }

  /// The address that the packets of the connection are sent to.
  pub(crate) const fn peer_addr(&self) -> SocketAddr {
    self.peer
  }

  /// The CID that the packets of the connection are sent to.
  pub(crate) const fn peer_cid(&self) -> &Cid {
    &self.peer_cid
  }

  /// The address of the last validated path, while the current one is not validated.
  pub(crate) fn last_valid_peer(&self) -> Option<SocketAddr> {
    self.cold.as_deref().and_then(|el| el.paths.last_valid_peer())
  }

  /// The data of the latest PATH_CHALLENGE received, while its PATH_RESPONSE is owed.
  pub(crate) const fn path_response_data(&self) -> Option<[u8; 8]> {
    self.path_response
  }
}

#[cfg(all(feature = "_fuzz-conn", not(test)))]
impl<A, RNG, TCX, const IS_CLIENT: bool> QuicConn<A, RNG, TCX, IS_CLIENT>
where
  A: QuicApp,
{
  /// The CONNECTION_CLOSE that the connection owes, if it is closing: (application, code).
  pub(crate) const fn close_code(&self) -> Option<(bool, u64)> {
    match self.state {
      ConnState::Closing => Some((self.close.app, self.close.code)),
      _ => None,
    }
  }
}

impl<A, RNG, TCX, const IS_CLIENT: bool> Drop for QuicConn<A, RNG, TCX, IS_CLIENT>
where
  A: QuicApp,
{
  #[inline]
  fn drop(&mut self) {
    // What it holds of the pools of the worker goes back only once it is closed or aborted
    #[cfg(feature = "std")]
    debug_assert!(
      self.state == ConnState::Closed || std::thread::panicking(),
      "a QUIC connection was dropped before it was closed or aborted"
    );
    #[cfg(not(feature = "std"))]
    debug_assert!(
      self.state == ConnState::Closed,
      "a QUIC connection was dropped before it was closed or aborted"
    );
  }
}

impl<A, RNG, TCX, const IS_CLIENT: bool> Debug for QuicConn<A, RNG, TCX, IS_CLIENT>
where
  A: QuicApp,
{
  #[inline]
  fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
    f.debug_struct("QuicConn")
      .field("is_client", &IS_CLIENT)
      .field("local_cid", &self.local_cid)
      .field("peer", &self.peer)
      .field("state", &self.state)
      .field("stats", &self.cold.as_deref().map(|el| el.stats))
      .finish_non_exhaustive()
  }
}

// Spec section 5.4: a connection is at most 4 KiB in the build that runs, not only in tests,
// whose random number generators are smaller (ruling T10-j). The probe application keeps no state
// of its own: what an application keeps per connection counts on top.
//
// The budget is the one of `crypto-ring`, the backend of the production build, which the other
// backends give way to when it is on (final review I1). The 1-RTT keys are held in line, so a
// backend's expanded key state counts: with `crypto-ruco` alone a connection is about 6.4 KiB, and
// a build of that backend trades the size for having no C or assembly.
#[cfg(feature = "crypto-ring")]
const _: () = assert!(
  size_of::<QuicConn<SizeProbeApp, crate::rng::ChaCha20, crate::tls::SkCtx>>() <= 4096,
  "a QUIC connection of the production build is larger than 4 KiB"
);

// An application that keeps nothing, for the size of a connection of the production build.
#[cfg(feature = "crypto-ring")]
struct SizeProbeApp;

#[cfg(feature = "crypto-ring")]
impl QuicApp for SizeProbeApp {
  type ConnState = ();

  fn on_established(&mut self, _: &mut ConnCtx<'_, ()>) -> crate::Result<()> {
    Ok(())
  }

  fn on_stream_data(
    &mut self,
    _: &mut ConnCtx<'_, ()>,
    _: crate::quic::StreamId,
    _: &[u8],
    _: bool,
  ) -> crate::Result<()> {
    Ok(())
  }

  fn on_stream_reset(
    &mut self,
    _: &mut ConnCtx<'_, ()>,
    _: crate::quic::StreamId,
    _: u64,
  ) -> crate::Result<()> {
    Ok(())
  }

  fn on_stop_sending(
    &mut self,
    _: &mut ConnCtx<'_, ()>,
    _: crate::quic::StreamId,
    _: u64,
  ) -> crate::Result<()> {
    Ok(())
  }

  fn on_closed(&mut self, _: &mut ()) {}
}

/// The state of a connection that is seldom used: the budgets of the frames of the peer that a
/// flood would abuse, the packets that failed to open and the counters. It comes from the pools of
/// the worker and goes back once the connection is closed, which keeps the connection small (spec
/// section 5.4, rulings T8-c and T9-c). Without it, once the connection is closed, no frame is
/// processed, no budget is spent and nothing is counted.
#[derive(Debug)]
pub(crate) struct ConnCold {
  // NEW_CONNECTION_ID frames, for their budget
  new_cids: RateBudget,
  // Packets that failed to open, for the integrity limit
  open_failures: u64,
  path_challenges: RateBudget,
  // The paths other than the current one, and the validation of the current one
  paths: Paths,
  // The CIDs that the peer gave (RFC 9000 section 5.1.1), the one of its handshake, sequence 0,
  // included once a NEW_CONNECTION_ID arrived: at most the `active_connection_id_limit` that it
  // was given (ruling T10-d)
  peer_cids: [Option<PeerCid>; ACTIVE_CID_LIMIT],
  // The sequence number of the CID of the peer that packets are sent to
  peer_cid_seq: u64,
  pings: RateBudget,
  // The CIDs of the peer below this sequence number are retired: RETIRE_CONNECTION_ID is owed for
  // the ones from `retire_next`, as a range
  retire_next: u64,
  retire_prior_to: u64,
  stats: ConnStats,
}

// A connection ID of the peer and its stateless reset token, which the one of its handshake has
// not.
#[derive(Clone, Copy, Debug)]
struct PeerCid {
  cid: Cid,
  reset_token: Option<[u8; RESET_TOKEN_LEN]>,
  seq: u64,
}

impl ConnCold {
  // From the pool, or new
  fn take(pools: &mut QuicPools) -> Box<Self> {
    let fresh = Self {
      new_cids: RateBudget::default(),
      open_failures: 0,
      path_challenges: RateBudget::default(),
      paths: Paths::new(),
      peer_cids: [None; ACTIVE_CID_LIMIT],
      peer_cid_seq: 0,
      pings: RateBudget::default(),
      retire_next: 0,
      retire_prior_to: 0,
      stats: ConnStats::EMPTY,
    };
    match pools.conn_cold.take() {
      Some(mut elem) => {
        *elem = fresh;
        elem
      }
      None => Box::new(fresh),
    }
  }
}

// What a lost packet changes: the space it was in, the frames that it owes again, the bytes in
// flight, path MTU discovery.
struct LostCtx<'any> {
  ack_eliciting_in_flight: &'any mut u32,
  cold: &'any mut Option<Box<ConnCold>>,
  crypto_lost: &'any mut FrameRefQueue,
  handshake_done_owed: &'any mut bool,
  max_datagram: usize,
  pmtud: &'any mut Pmtud,
  recovery: &'any mut Recovery,
  streams: &'any mut Streams,
}

impl LostCtx<'_> {
  // `packet`, `pn`, was declared lost: its frames are owed again, CRYPTO and STREAM data by
  // range, control frames with their current values (carried rule 5), and go back to the pool,
  // its record keeping none ([`SentPacket::declare_lost`]), even after an error.
  fn on_lost(&mut self, pn: u64, packet: &SentPacket, pools: &mut QuicPools) -> crate::Result<()> {
    self.recovery.on_gone(packet);
    if packet.ack_eliciting && packet.in_flight() {
      *self.ack_eliciting_in_flight = self.ack_eliciting_in_flight.saturating_sub(1);
    }
    if packet.kind == SentKind::MtuProbe {
      self.pmtud.on_probe_lost(pn, self.max_datagram);
    }
    let mut rslt = Ok(());
    let mut cursor = FrameRefPool::cursor(packet.frames);
    while let Some(frame) = cursor.next(&pools.frame_refs) {
      let requeued = match frame {
        FrameRef::Ack { .. } => Ok(()),
        // A probe sent it again already
        FrameRef::Crypto { .. } if packet.kind == SentKind::Probed => Ok(()),
        FrameRef::Crypto { .. } => pools.frame_refs.queue_push(self.crypto_lost, frame),
        FrameRef::HandshakeDone => {
          *self.handshake_done_owed = true;
          Ok(())
        }
        FrameRef::PathChallenge => {
          if let Some(elem) = self.cold.as_deref_mut() {
            elem.paths.on_challenge_lost();
          }
          Ok(())
        }
        // Owed again, with the ones after it (owed as a range)
        FrameRef::RetireConnectionId { seq } => {
          if let Some(elem) = self.cold.as_deref_mut() {
            elem.retire_next = elem.retire_next.min(seq);
          }
          Ok(())
        }
        _ => self.streams.on_frame_lost(frame, pools),
      };
      if rslt.is_ok() {
        rslt = requeued;
      }
    }
    pools.frame_refs.free(packet.frames);
    rslt
  }
}

// The CONNECTION_CLOSE that the connection sends.
#[derive(Clone, Copy, Debug)]
struct CloseFrame {
  app: bool,
  code: u64,
  // The application asked for it, with the reason that the streams keep
  requested: bool,
}

// CRYPTO data of a level that arrives before the data that TLS reads next, buffered in a ring
// indexed by offset that is taken from the pool when needed and given back once empty.
#[derive(Debug)]
struct CryptoRx {
  buffer: Option<Box<CryptoBuffer>>,
  // The offset of the next byte that TLS reads
  offset: u64,
}

impl CryptoRx {
  const fn new() -> Self {
    Self { buffer: None, offset: 0 }
  }

  // Takes the CRYPTO data `data` at `offset`. Returns what TLS reads next out of it; what starts
  // later is buffered, at most `CRYPTO_BUFFER_LEN` bytes ahead.
  fn accept<'data>(
    &mut self,
    offset: u64,
    data: &'data [u8],
    pools: &mut QuicPools,
  ) -> crate::Result<&'data [u8]> {
    let len = u64::try_from(data.len()).unwrap_or(u64::MAX);
    let end = offset.saturating_add(len);
    if end <= self.offset {
      return Ok(&[]);
    }
    if let Some(skip) = self.offset.checked_sub(offset) {
      let fresh = data.get(usize::try_from(skip).unwrap_or(usize::MAX)..).unwrap_or_default();
      // What was buffered for these bytes is not needed anymore
      self.mark(self.offset, end, false);
      self.offset = end;
      return Ok(fresh);
    }
    if end.wrapping_sub(self.offset) > CRYPTO_BUFFER_LEN as u64 {
      return Err(crate::Error::QuicClose(
        TransportErrorCode::CryptoBufferExceeded,
        QuicError::CryptoDataTooFarAhead,
      ));
    }
    let buffer = self.buffer.get_or_insert_with(|| CryptoBuffer::take(pools));
    let start = ring_pos(offset);
    let (head, tail) = data.split_at(data.len().min(CRYPTO_BUFFER_LEN.wrapping_sub(start)));
    if let Some(dst) = buffer.data.get_mut(start..start.wrapping_add(head.len())) {
      dst.copy_from_slice(head);
    }
    if let Some(dst) = buffer.data.get_mut(..tail.len()) {
      dst.copy_from_slice(tail);
    }
    self.mark(offset, end, true);
    Ok(&[])
  }

  // The buffered bytes that TLS reads next, up to the end of the ring.
  fn buffered(&self) -> &[u8] {
    let Some(buffer) = &self.buffer else {
      return &[];
    };
    let start = ring_pos(self.offset);
    let len = run_len(&buffer.have, start, CRYPTO_BUFFER_LEN.wrapping_sub(start));
    buffer.data.get(start..start.wrapping_add(len)).unwrap_or_default()
  }

  // `len` bytes of `buffered` were read.
  fn consume(&mut self, len: usize, pools: &mut QuicPools) {
    let end = self.offset.saturating_add(u64::try_from(len).unwrap_or(u64::MAX));
    self.mark(self.offset, end, false);
    self.offset = end;
    if self.buffer.as_ref().is_some_and(|el| el.have.iter().all(|word| *word == 0)) {
      self.release(pools);
    }
  }

  // Sets or clears the bits of the bytes from `start` to `end`, of which only the last
  // `CRYPTO_BUFFER_LEN` matter.
  fn mark(&mut self, start: u64, end: u64, value: bool) {
    let Some(buffer) = &mut self.buffer else {
      return;
    };
    let len =
      usize::try_from(end.saturating_sub(start)).unwrap_or(usize::MAX).min(CRYPTO_BUFFER_LEN);
    let first = ring_pos(end.wrapping_sub(len as u64));
    let head = len.min(CRYPTO_BUFFER_LEN.wrapping_sub(first));
    set_bits(&mut buffer.have, first, head, value);
    set_bits(&mut buffer.have, 0, len.wrapping_sub(head), value);
  }

  fn release(&mut self, pools: &mut QuicPools) {
    if let Some(elem) = self.buffer.take() {
      CryptoBuffer::give(elem, pools);
    }
  }

  // Gives the buffer back and starts over, for the next handshake.
  fn reset(&mut self, pools: &mut QuicPools) {
    self.release(pools);
    self.offset = 0;
  }
}

// A packet written into a datagram but not sealed yet: the last one of a datagram can still take
// padding.
#[derive(Clone, Copy, Debug)]
struct OpenPacket {
  ack_eliciting: bool,
  // The Largest Acknowledged of its ACK frame if it is an ACK-only packet, whose record keeps no
  // frame reference (task 23c)
  ack_only_largest: Option<u64>,
  // It has the PATH_CHALLENGE of the validation of the current path
  challenge: bool,
  frames: FrameRefRange,
  // If the datagram must have at least 1200 bytes
  full_datagram: bool,
  // Up to and including the packet number
  header_len: usize,
  // Where the Length field of a long header is
  length_at: Option<usize>,
  // A probe of path MTU discovery
  mtu_probe: bool,
  // It goes to an address other than the one of the current path ([`path`])
  off_path: bool,
  padded: bool,
  payload_len: usize,
  pn: u64,
  pn_len: usize,
  pn_offset: usize,
  space: Space,
  // Where the packet is in the datagram
  start: usize,
}

impl OpenPacket {
  // Once sealed
  const fn len(&self) -> usize {
    self.header_len.wrapping_add(self.payload_len).wrapping_add(AEAD_TAG_LEN)
  }
}

// The state of one packet number space.
#[derive(Debug)]
struct PacketSpace {
  // The ack-eliciting packets in flight
  ack_eliciting_in_flight: u32,
  // The Largest Acknowledged of the ACK frame of the newest ACK-only packet, whose record keeps no
  // frame reference (task 23c): if the peer acknowledges that packet, the ranges up to it can go
  // (RFC 9000 section 13.2.4)
  ack_only_largest: u64,
  // The packet number of the newest ACK-only packet, `u64::MAX` before the first
  ack_only_pn: u64,
  // The CRYPTO data of lost packets, sent again before new data
  crypto_lost: FrameRefQueue,
  // The bytes of the TLS output of the level that were sent
  crypto_tx: u64,
  keys: Option<PacketKeys>,
  // The largest of our packet numbers that the peer acknowledged
  largest_acked: Option<u64>,
  // When the last ack-eliciting packet was sent
  last_ack_eliciting_us: u64,
  // When the oldest packet in flight that is not lost yet becomes lost by the time threshold
  loss_time_us: Option<u64>,
  recv: RecvTracker,
  sent: SentRing,
}

impl PacketSpace {
  const fn new() -> Self {
    Self {
      ack_eliciting_in_flight: 0,
      ack_only_largest: 0,
      ack_only_pn: u64::MAX,
      crypto_lost: FrameRefQueue::EMPTY,
      crypto_tx: 0,
      keys: None,
      largest_acked: None,
      last_ack_eliciting_us: 0,
      loss_time_us: None,
      recv: RecvTracker::new(),
      sent: SentRing::new(),
    }
  }

  // Drops the keys in their slot, which wipes them, gives the resources back and starts over.
  fn clear(&mut self, pools: &mut QuicPools) {
    self.keys = None;
    self.sent.release(pools);
    self.recv.release(pools);
    pools.frame_refs.queue_clear(&mut self.crypto_lost);
    *self = Self::new();
  }

  // The keys of the space are discarded: its packets leave the bytes in flight and the timers of
  // loss detection start over (RFC 9002 appendix A.11).
  fn discard(&mut self, recovery: &mut Recovery, pools: &mut QuicPools) {
    for packet in self.sent.records() {
      recovery.on_gone(packet);
    }
    if self.keys.is_some() {
      recovery.pto_count = 0;
      recovery.timer_stale = true;
    }
    self.clear(pools);
  }
}

/// The Initial and Handshake packet number spaces of a connection: keys, CRYPTO reassembly,
/// acknowledgments and sent packets, and the other state that only the handshake needs. A
/// connection takes them from the worker's pool for its handshake and gives them back, wiped,
/// once the handshake is confirmed (spec section 5.4).
#[derive(Debug)]
pub(crate) struct HandshakeSpaces {
  handshake: PacketSpace,
  handshake_rx: CryptoRx,
  initial: PacketSpace,
  initial_rx: CryptoRx,
  // The destination CID of the first Initial packet of the client
  original_dcid: Cid,
}

impl HandshakeSpaces {
  // Spaces from the pool, or new ones, with the keys of Initial.
  fn take(initial: PacketKeys, original_dcid: Cid, pools: &mut QuicPools) -> Box<Self> {
    let mut this = pools.handshake_spaces.take().unwrap_or_else(|| {
      Box::new(Self {
        handshake: PacketSpace::new(),
        handshake_rx: CryptoRx::new(),
        initial: PacketSpace::new(),
        initial_rx: CryptoRx::new(),
        original_dcid: Cid::default(),
      })
    });
    this.initial.keys = Some(initial);
    this.original_dcid = original_dcid;
    this
  }

  // The Initial keys, wiped, and what was buffered at that level are not needed anymore.
  fn discard_initial(&mut self, recovery: &mut Recovery, pools: &mut QuicPools) {
    self.initial.discard(recovery, pools);
    self.initial_rx.reset(pools);
  }

  // Wipes the keys where they are and gives the spaces back.
  fn give(mut this: Box<Self>, recovery: &mut Recovery, pools: &mut QuicPools) {
    this.discard_initial(recovery, pools);
    this.handshake.discard(recovery, pools);
    this.handshake_rx.reset(pools);
    pools.handshake_spaces.give(this);
  }
}

// Feeds TLS and installs the keys of every secret that it yields, in the slot of the level, which
// TLS requires after every feed. The secrets are dropped, and so wiped, once their keys are made.
// The 1-RTT keys have batched header protection if `batched_hp` (ruling T18-b).
fn feed<const IS_CLIENT: bool, RNG, TCX>(
  tls: &mut QuicTls<IS_CLIENT, RNG, TCX>,
  space: Space,
  data: &[u8],
  mut handshake_keys: Option<&mut Option<PacketKeys>>,
  data_keys: &mut Option<PacketKeys>,
  batched_hp: bool,
) -> crate::Result<()>
where
  RNG: CryptoRng + CryptoSeedableRng,
  TCX: TlsCtxSk,
{
  tls.feed(space, data)?;
  while let Some(secrets) = tls.poll_secrets() {
    let slot = match secrets.space {
      Space::Handshake => handshake_keys.as_deref_mut(),
      Space::Data => Some(&mut *data_keys),
      Space::Initial => None,
    };
    let Some(slot) = slot else {
      return Err(crate::Error::QuicClose(
        TransportErrorCode::InternalError,
        QuicError::TlsSecretsNotTaken,
      ));
    };
    let batched = batched_hp && secrets.space == Space::Data;
    let local = keys_from_secret_with(secrets.suite, secrets.tx.as_slice(), batched)?;
    let remote = keys_from_secret_with(secrets.suite, secrets.rx.as_slice(), batched)?;
    *slot = Some(PacketKeys { local, remote });
  }
  Ok(())
}

// The CRYPTO data of the packets of `sp` in flight goes again, unless lost data waits already, and
// they are marked so that their loss does not queue it once more.
fn requeue_crypto_in_flight(sp: &mut PacketSpace, pools: &mut QuicPools) -> crate::Result<()> {
  if sp.keys.is_none() || !sp.crypto_lost.is_empty() {
    return Ok(());
  }
  let (base, next) = (sp.sent.base(), sp.sent.next_pn());
  for pn in base..next {
    let Some(packet) = sp.sent.get_mut(pn).filter(|el| el.kind == SentKind::InFlight) else {
      continue;
    };
    // Its CRYPTO data is not queued once more if it is lost (review J9)
    packet.kind = SentKind::Probed;
    let mut cursor = FrameRefPool::cursor(packet.frames);
    while let Some(frame) = cursor.next(&pools.frame_refs) {
      if let FrameRef::Crypto { .. } = frame {
        pools.frame_refs.queue_push(&mut sp.crypto_lost, frame)?;
      }
    }
  }
  Ok(())
}

// Takes the bytes of an acknowledged CRYPTO frame, `len` from `offset`, out of the lost ranges that
// wait in `queue`: those that it splits leave two pieces at the end of the queue.
fn trim_acked_crypto(
  queue: &mut FrameRefQueue,
  offset: u64,
  len: u32,
  refs: &mut FrameRefPool,
) -> crate::Result<()> {
  let acked_end = offset.saturating_add(u64::from(len));
  for _ in 0..queue.len() {
    let Some(front) = refs.queue_front(queue) else {
      break;
    };
    refs.queue_pop(queue);
    let FrameRef::Crypto { offset: start, len: piece } = front else {
      continue;
    };
    let end = start.saturating_add(u64::from(piece));
    if start < offset {
      let len = u32::try_from(end.min(offset).wrapping_sub(start)).unwrap_or(u32::MAX);
      refs.queue_push(queue, FrameRef::Crypto { offset: start, len })?;
    }
    if end > acked_end {
      let from = start.max(acked_end);
      let len = u32::try_from(end.wrapping_sub(from)).unwrap_or(u32::MAX);
      refs.queue_push(queue, FrameRef::Crypto { offset: from, len })?;
    }
  }
  Ok(())
}

// CRYPTO frames of the TLS output `output` of the space of `sp`: the ranges of lost packets first,
// then what was never sent. Returns whether it wrote any.
fn write_crypto(
  output: &[u8],
  sp: &mut PacketSpace,
  fw: &mut FrameWriter<'_>,
  frames: &mut FrameRefRange,
  pools: &mut QuicPools,
) -> crate::Result<bool> {
  let mut wrote = false;
  while let Some(front) = pools.frame_refs.queue_front(&sp.crypto_lost) {
    let FrameRef::Crypto { offset, len } = front else {
      pools.frame_refs.queue_pop(&mut sp.crypto_lost);
      continue;
    };
    let start = usize::try_from(offset).unwrap_or(usize::MAX);
    let end = start.saturating_add(usize::try_from(len).unwrap_or(usize::MAX));
    let Some(data) = output.get(start..end).filter(|el| !el.is_empty()) else {
      pools.frame_refs.queue_pop(&mut sp.crypto_lost);
      continue;
    };
    let written = write_crypto_frame(fw, offset, data);
    if written == 0 {
      return Ok(wrote);
    }
    let written_u32 = u32::try_from(written).unwrap_or(u32::MAX);
    pools.frame_refs.push(frames, FrameRef::Crypto { offset, len: written_u32 })?;
    wrote = true;
    if written < data.len() {
      let rest = FrameRef::Crypto {
        offset: offset.wrapping_add(u64::from(written_u32)),
        len: len.wrapping_sub(written_u32),
      };
      pools.frame_refs.queue_set_front(&sp.crypto_lost, rest);
      return Ok(wrote);
    }
    pools.frame_refs.queue_pop(&mut sp.crypto_lost);
  }
  let sent = usize::try_from(sp.crypto_tx).unwrap_or(usize::MAX);
  let unsent = output.get(sent..).unwrap_or_default();
  let offset = sp.crypto_tx;
  let written = write_crypto_frame(fw, offset, unsent);
  if written > 0 {
    let len = u32::try_from(written).unwrap_or(u32::MAX);
    pools.frame_refs.push(frames, FrameRef::Crypto { offset, len })?;
    sp.crypto_tx = sp.crypto_tx.wrapping_add(u64::from(len));
    wrote = true;
  }
  Ok(wrote)
}

// A CRYPTO frame at `offset` with as much of `data` as fits. Returns how many bytes it has.
fn write_crypto_frame(fw: &mut FrameWriter<'_>, offset: u64, data: &[u8]) -> usize {
  // The header and the data must fit together
  let room = fw.remaining();
  let longest = data.len().min(room);
  let header = 1usize
    .wrapping_add(varint_len(offset))
    .wrapping_add(varint_len(u64::try_from(longest).unwrap_or(u64::MAX)));
  let data_len = longest.min(room.saturating_sub(header));
  match data.get(..data_len) {
    Some(bytes)
      if data_len > 0 && fw.write_crypto_header(offset, data_len) && fw.write_bytes(bytes) =>
    {
      data_len
    }
    _ => 0,
  }
}

const fn ring_pos(offset: u64) -> usize {
  (offset % CRYPTO_BUFFER_LEN as u64) as usize
}

// The number of consecutive bits set from `start`, at most `max`.
fn run_len(have: &[u64], start: usize, max: usize) -> usize {
  let mut count = 0usize;
  while count < max {
    let pos = start.wrapping_add(count);
    let bit = pos % 64;
    let Some(word) = have.get(pos / 64) else {
      break;
    };
    let ones = usize::try_from((word >> bit).trailing_ones()).unwrap_or(0);
    let take = ones.min(max.wrapping_sub(count));
    count = count.wrapping_add(take);
    if take < 64usize.wrapping_sub(bit) {
      break;
    }
  }
  count
}

// Sets or clears `len` bits from `start`, which do not go past the end of `have`.
fn set_bits(have: &mut [u64], start: usize, len: usize, value: bool) {
  let end = start.wrapping_add(len);
  let mut pos = start;
  while pos < end {
    let bit = pos % 64;
    let count = 64usize.wrapping_sub(bit).min(end.wrapping_sub(pos));
    let mask = if count == 64 { u64::MAX } else { ((1u64 << count).wrapping_sub(1)) << bit };
    if let Some(word) = have.get_mut(pos / 64) {
      if value {
        *word |= mask;
      } else {
        *word &= !mask;
      }
    }
    pos = pos.wrapping_add(count);
  }
}

// The state of `space`, if it is not gone.
fn space_mut<'conn>(
  data: &'conn mut PacketSpace,
  handshake: &'conn mut Option<Box<HandshakeSpaces>>,
  space: Space,
) -> Option<&'conn mut PacketSpace> {
  match space {
    Space::Initial => handshake.as_deref_mut().map(|el| &mut el.initial),
    Space::Handshake => handshake.as_deref_mut().map(|el| &mut el.handshake),
    Space::Data => Some(data),
  }
}

fn space_ref<'conn>(
  data: &'conn PacketSpace,
  handshake: &'conn Option<Box<HandshakeSpaces>>,
  space: Space,
) -> Option<&'conn PacketSpace> {
  match space {
    Space::Initial => handshake.as_deref().map(|el| &el.initial),
    Space::Handshake => handshake.as_deref().map(|el| &el.handshake),
    Space::Data => Some(data),
  }
}

#[inline(always)]
fn violation(kind: QuicError) -> crate::Error {
  cold_path();
  crate::Error::QuicClose(TransportErrorCode::ProtocolViolation, kind)
}

// The header of a packet of `space` with room for the Length field of a long header. Returns the
// length of the header with the packet number, where the packet number starts and where the
// Length field is, or `None` if `out` is too small.
fn write_header(
  out: &mut [u8],
  space: Space,
  dcid: &Cid,
  scid: &Cid,
  (pn, pn_len): (u64, usize),
  key_phase: bool,
  token: &[u8],
) -> Option<(usize, usize, Option<usize>)> {
  let pn_bits = u8::try_from(pn_len.wrapping_sub(1)).ok()? & 0b11;
  let mut w = Writer::new(out);
  let length_at = if space == Space::Data {
    // No spin bit
    let phase = if key_phase { KEY_PHASE_BIT } else { 0 };
    w.put_u8(0x40 | phase | pn_bits).ok()?;
    w.put(dcid.as_slice()).ok()?;
    None
  } else {
    let ty = if space == Space::Initial { 0 } else { 2 };
    w.put_u8(0xc0 | (ty << 4) | pn_bits).ok()?;
    w.put(&QUIC_V1.to_be_bytes()).ok()?;
    w.put_u8(u8::try_from(dcid.len()).ok()?).ok()?;
    w.put(dcid.as_slice()).ok()?;
    w.put_u8(u8::try_from(scid.len()).ok()?).ok()?;
    w.put(scid.as_slice()).ok()?;
    if space == Space::Initial {
      // The token of a Retry, which only a client sends
      w.varint(u64::try_from(token.len()).ok()?).ok()?;
      w.put(token).ok()?;
    }
    let at = w.pos();
    w.zeros(LENGTH_FIELD_LEN).ok()?;
    Some(at)
  };
  let pn_offset = w.pos();
  w.put(pn.to_be_bytes().get(8usize.wrapping_sub(pn_len)..)?).ok()?;
  Some((w.pos(), pn_offset, length_at))
}

#[cfg(any(test, feature = "_fuzz-conn"))]
#[doc(hidden)]
pub mod check;
mod path;

#[cfg(test)]
mod tests {
  use crate::{
    quic::{
      BodyRef, Cid, ConnState, FlushOutcome, Frame, PacketTy, QuicError, Space, TransportErrorCode,
      conn::CryptoRx,
      parse_header,
      pools::{CRYPTO_BUFFER_LEN, QuicPools, RX_BLOCK_LEN, TX_BLOCK_LEN},
      protect,
      sent::{FrameRef, FrameRefRange, SentKind},
      testing::{
        Behavior, CLIENT_ADDR, Impairment, Link, LinkOpts, Parts, SERVER_ADDR, TestApp,
        encode_frames, run_lossy_requests,
      },
    },
    sync::AtomicU64,
    tests::_count_allocations_in,
    tls::CipherSuite,
  };
  use alloc::{boxed::Box, vec, vec::Vec};
  use core::sync::atomic::Ordering;

  const PING: [u8; 1] = [0x01];
  // PTO with the initial RTT and a max_ack_delay of 25 ms (RFC 9002 section 6.2)
  const PTO_US: u64 = 333_000 + 4 * 166_500 + 25_000;

  fn settled(opts: &LinkOpts) -> Link {
    let mut link = Link::new(opts);
    link.run();
    assert_eq!(link.server.conn.state(), ConnState::Confirmed);
    assert_eq!(link.client.conn.state(), ConnState::Confirmed);
    link
  }

  // The types of the packets of a datagram, which are not decrypted.
  fn packet_types(mut datagram: &[u8]) -> Vec<PacketTy> {
    let mut rslt = Vec::new();
    while !datagram.is_empty() {
      let header = parse_header(datagram, 8).unwrap();
      rslt.push(header.ty);
      datagram = &datagram[header.packet_end..];
    }
    rslt
  }

  // A packet of the client with the keys of `space`: a header to `dcid` (the CID that the client
  // sends to if `None`) with the reserved bits `reserved`, a 4-byte packet number that the client
  // then skips, and `payload`, which can be anything.
  fn client_packet(
    link: &mut Link,
    space: Space,
    dcid: Option<Cid>,
    reserved: u8,
    payload: &[u8],
  ) -> Vec<u8> {
    let conn = &mut link.client.conn;
    let (dcid, scid) = (dcid.unwrap_or(conn.peer_cid), conn.local_cid);
    let sp = super::space_mut(&mut conn.data, &mut conn.handshake, space).unwrap();
    let pn = sp.sent.next_pn();
    sp.sent.skip();
    let mut out = vec![0; 2048];
    let (header_len, pn_offset, length_at) =
      super::write_header(&mut out, space, &dcid, &scid, (pn, 4), false, &[]).unwrap();
    out[0] |= reserved;
    out[header_len..header_len + payload.len()].copy_from_slice(payload);
    if let Some(at) = length_at {
      let length = u16::try_from(4 + payload.len() + 16).unwrap() | 0x4000;
      out[at..at + 2].copy_from_slice(&length.to_be_bytes());
    }
    let keys = sp.keys.as_ref().unwrap();
    let len = protect(&keys.local, &mut out, pn_offset, pn, 4, payload.len()).unwrap();
    out.truncate(len);
    out
  }

  // The error code of the CONNECTION_CLOSE that the server owes, which must be a transport one.
  fn server_close_code(link: &Link) -> Option<u64> {
    let conn = &link.server.conn;
    (conn.state() == ConnState::Closing && !conn.close.app).then_some(conn.close.code)
  }

  // A PING padded to `len` bytes: the payload of an Initial packet.
  fn initial_ping(len: usize) -> Vec<u8> {
    let mut payload = vec![0; len];
    payload[0] = 0x01;
    payload
  }

  fn server_data_ranges(link: &Link) -> Vec<(u64, u64)> {
    let recv = &link.server.conn.data.recv;
    recv.ranges().map(|el| (*el.start(), *el.end())).collect()
  }

  // Both sides end up confirmed, the client by HANDSHAKE_DONE, with the keys of the suite that
  // the server offered and nothing else left of the handshake, for each of the three suites.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn handshake_completes_in_process() {
    for suite in [
      CipherSuite::Aes128GcmSha256,
      CipherSuite::Aes256GcmSha384,
      CipherSuite::Chacha20Poly1305Sha256,
    ] {
      let link = settled(&LinkOpts::new(Some(suite)));
      assert_eq!((link.client.app.established, link.server.app.established), (1, 1));
      // A client is confirmed by HANDSHAKE_DONE only, and the server sent it once
      assert!(!link.server.conn.handshake_done_owed && link.client.conn.handshake_complete);
      for conn in [&link.client.conn.handshake, &link.server.conn.handshake] {
        assert!(conn.is_none(), "{suite:?}");
      }
      assert!(link.client.conn.tls.is_none() && link.server.conn.tls.is_none());
      for data in [&link.client.conn.data, &link.server.conn.data] {
        let keys = data.keys.as_ref().unwrap();
        assert_eq!((keys.local.suite(), keys.remote.suite()), (suite, suite));
      }
      // The server validated the address of the client with its Handshake packet
      assert!(link.server.conn.address_validated);
      assert_eq!(link.server.conn.peer_cid, link.client.conn.local_cid);
      assert_eq!(link.client.conn.peer_cid, link.server.conn.local_cid);
    }
  }

  // A flight longer than three times the first datagram of the client stops at that limit until
  // a Handshake packet of the client validates its address.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn server_respects_anti_amplification_before_validation() {
    let mut opts = LinkOpts::new(None);
    opts.server_tp_padding = 6000;
    let mut link = Link::new(&opts);
    let mut blocked = false;
    for _ in 0..16 {
      if link.server.conn.state() != ConnState::Handshake {
        break;
      }
      let _ = link.server.flush(link.now_us);
      let server = &link.server.conn;
      if !server.address_validated {
        let stats = server.stats();
        assert!(stats.bytes_out <= 3 * stats.bytes_in, "{stats:?}");
        blocked |= !server.crypto_unsent(Space::Handshake).is_empty();
      }
      let _ = link.deliver_to_client();
      let _ = link.client.flush(link.now_us);
      let _ = link.deliver_to_server();
    }
    assert!(blocked, "the flight must have been held back");
    link.run();
    assert_eq!(link.server.conn.state(), ConnState::Confirmed);
    assert_eq!(link.client.conn.state(), ConnState::Confirmed);
  }

  // The second copy of a packet is not processed again, and not acknowledged again.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn duplicate_packet_is_ignored() {
    let mut link = settled(&LinkOpts::new(None));
    link.client.conn.queue_test_frames(&PING);
    let _ = link.client.flush(link.now_us);
    let mut datagrams = link.client.take_datagrams();
    assert_eq!(datagrams.len(), 1);
    let mut copy = datagrams[0].clone();
    let before = *link.server.conn.stats();
    link.server.recv(link.now_us, &mut datagrams[0], CLIENT_ADDR);
    assert_eq!(link.server.conn.stats().packets_in, before.packets_in + 1);
    let _ = link.server.flush(link.now_us);
    assert_eq!(link.server.take_datagrams().len(), 1);
    link.server.recv(link.now_us, &mut copy, CLIENT_ADDR);
    let after = link.server.conn.stats();
    assert_eq!(after.packets_in, before.packets_in + 1);
    assert_eq!(after.duplicates, before.duplicates + 1);
    let _ = link.server.flush(link.now_us);
    assert!(link.server.take_datagrams().is_empty());
    assert_eq!(link.server.conn.state(), ConnState::Confirmed);
  }

  // The ranges of what the client sent stay in every ACK of the server until the client
  // acknowledges a packet that carried one of them.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn ack_ranges_kept_until_our_ack_is_acked() {
    let mut link = settled(&LinkOpts::new(None));
    for _ in 0..3 {
      link.client.conn.queue_test_frames(&PING);
      let _ = link.client.flush(link.now_us);
      assert_eq!(link.deliver_to_server(), 1);
    }
    let ranges = server_data_ranges(&link);
    let largest = ranges[0].1;
    assert!(largest >= 3, "{ranges:?}");
    // An ACK-only packet of the server, which the client does not acknowledge
    let _ = link.server.flush(link.now_us);
    assert_eq!(link.deliver_to_client(), 1);
    let _ = link.client.flush(link.now_us);
    assert_eq!(link.deliver_to_server(), 0);
    assert_eq!(server_data_ranges(&link), ranges);
    // One more from the client, acknowledged in an ack-eliciting packet of the server, which the
    // client acknowledges along with the ACK-only one
    link.client.conn.queue_test_frames(&PING);
    let _ = link.client.flush(link.now_us);
    assert_eq!(link.deliver_to_server(), 1);
    assert_eq!(server_data_ranges(&link)[0], (ranges[0].0, largest + 1));
    link.server.conn.queue_test_frames(&PING);
    let _ = link.server.flush(link.now_us);
    assert_eq!(link.deliver_to_client(), 1);
    let _ = link.client.flush(link.now_us);
    assert_eq!(link.deliver_to_server(), 1);
    // Everything up to the Largest Acknowledged of that ACK is forgotten, and refused: only the
    // ACK-only packet of the client, which came after, is left
    assert_eq!(server_data_ranges(&link), [(largest + 2, largest + 2)]);
    let recv = &link.server.conn.data.recv;
    assert!(recv.is_duplicate(ranges[0].0) && recv.is_duplicate(largest + 1));
  }

  // Task 23c: an ACK-only packet of the server is recorded without a frame-reference chunk: it is
  // neither ack-eliciting nor in flight, and its ACK frame is only of use for ACK-of-ACK.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn ack_only_packet_holds_no_frame_reference() {
    let mut link = settled(&LinkOpts::new(None));
    link.client.conn.queue_test_frames(&PING);
    let _ = link.client.flush(link.now_us);
    assert_eq!(link.deliver_to_server(), 1);
    let largest = link.server.conn.data.recv.largest().unwrap();
    let pn = link.server.conn.data.sent.next_pn();
    let (chunks, ack_only) =
      (link.server.parts.pools.frame_refs.live_chunks(), link.server.conn.stats().ack_only_out);
    let _ = link.server.flush(link.now_us);
    assert_eq!(link.server.conn.stats().ack_only_out, ack_only + 1);
    let record = *link.server.conn.data.sent.get_mut(pn).unwrap();
    assert_eq!((record.kind, record.frames), (SentKind::NotInFlight, FrameRefRange::EMPTY));
    assert_eq!(link.server.parts.pools.frame_refs.live_chunks(), chunks);
    // Its ACK frame is kept by the space
    let data = &link.server.conn.data;
    assert_eq!((data.ack_only_pn, data.ack_only_largest), (pn, largest));
  }

  // Task 23c: ACK-of-ACK still works for an ACK-only packet. The server's ACK-only packet, and
  // then a PING of its own that carries no ACK frame, are acknowledged by the client: everything
  // up to the Largest Acknowledged of the ACK-only packet is forgotten.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn acked_ack_only_packet_raises_the_receive_floor() {
    let mut link = settled(&LinkOpts::new(None));
    link.client.conn.queue_test_frames(&PING);
    let _ = link.client.flush(link.now_us);
    assert_eq!(link.deliver_to_server(), 1);
    let ranges = server_data_ranges(&link);
    let largest = ranges[0].1;
    let ack_only = link.server.conn.data.sent.next_pn();
    let _ = link.server.flush(link.now_us);
    let ping = link.server.conn.data.sent.next_pn();
    link.server.conn.queue_test_frames(&PING);
    let _ = link.server.flush(link.now_us);
    assert_eq!(ping, ack_only + 1);
    // The PING carries no ACK frame: only the ACK-only packet can raise the floor
    let pools = &link.server.parts.pools;
    let ping_frames = link.server.conn.data.sent.get_mut(ping).unwrap().frames;
    assert_eq!(pools.frame_refs.iter(ping_frames).count(), 0);
    assert_eq!(server_data_ranges(&link), ranges);
    assert_eq!(link.deliver_to_client(), 2);
    let _ = link.client.flush(link.now_us);
    assert_eq!(link.deliver_to_server(), 1);
    // Only the ACK-only packet of the client, which came after, is left
    assert_eq!(server_data_ranges(&link), [(largest + 1, largest + 1)]);
    let recv = &link.server.conn.data.recv;
    assert!(recv.is_duplicate(ranges[0].0) && recv.is_duplicate(largest));
  }

  // Task 23c: a packet with an ACK frame and ack-eliciting frames keeps its ACK frame in a
  // frame-reference chunk, as before.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn ack_with_ack_eliciting_frames_keeps_its_frame_reference() {
    let mut link = settled(&LinkOpts::new(None));
    link.client.conn.queue_test_frames(&PING);
    let _ = link.client.flush(link.now_us);
    assert_eq!(link.deliver_to_server(), 1);
    let largest = link.server.conn.data.recv.largest().unwrap();
    let pn = link.server.conn.data.sent.next_pn();
    let chunks = link.server.parts.pools.frame_refs.live_chunks();
    link.server.conn.queue_test_frames(&PING);
    let _ = link.server.flush(link.now_us);
    let record = *link.server.conn.data.sent.get_mut(pn).unwrap();
    assert!(record.ack_eliciting && record.kind == SentKind::InFlight);
    let pools = &link.server.parts.pools;
    let frames: Vec<_> = pools.frame_refs.iter(record.frames).collect();
    assert_eq!(frames, [FrameRef::Ack { largest }]);
    assert_eq!(pools.frame_refs.live_chunks(), chunks + 1);
  }

  // An ACK-only packet makes no packet in return, in either direction.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn never_acks_an_ack_only_packet() {
    let mut link = settled(&LinkOpts::new(None));
    for to_server in [true, false] {
      // A PING from one side, acknowledged by the other with an ACK-only packet
      if to_server {
        link.client.conn.queue_test_frames(&PING);
        let _ = link.client.flush(link.now_us);
        assert_eq!(link.deliver_to_server(), 1);
        let ack_only = link.server.conn.stats().ack_only_out;
        let _ = link.server.flush(link.now_us);
        assert_eq!(link.server.conn.stats().ack_only_out, ack_only + 1);
        let sent = link.client.conn.stats().packets_out;
        assert_eq!(link.deliver_to_client(), 1);
        let _ = link.client.flush(link.now_us);
        assert!(link.client.take_datagrams().is_empty());
        assert_eq!(link.client.conn.stats().packets_out, sent);
      } else {
        link.server.conn.queue_test_frames(&PING);
        let _ = link.server.flush(link.now_us);
        assert_eq!(link.deliver_to_client(), 1);
        let ack_only = link.client.conn.stats().ack_only_out;
        let _ = link.client.flush(link.now_us);
        assert_eq!(link.client.conn.stats().ack_only_out, ack_only + 1);
        let sent = link.server.conn.stats().packets_out;
        assert_eq!(link.deliver_to_server(), 1);
        let _ = link.server.flush(link.now_us);
        assert!(link.server.take_datagrams().is_empty());
        assert_eq!(link.server.conn.stats().packets_out, sent);
      }
    }
  }

  // The Finished of the client and its first request, coalesced in one datagram, are processed in
  // the same call: the 1-RTT packet decrypts with the keys that the Finished unlocks.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn coalesced_finished_and_request_served_in_one_turn() {
    let mut link = Link::new(&LinkOpts::new(None));
    // STREAM on stream 0 with LEN and FIN: a request
    link.client.conn.queue_test_frames(&[0x0b, 0x00, 0x05, b'h', b'e', b'l', b'l', b'o']);
    let _ = link.server.flush(link.now_us);
    assert_eq!(link.deliver_to_client(), 1);
    let _ = link.client.flush(link.now_us);
    let mut datagrams = link.client.take_datagrams();
    let idx = datagrams
      .iter()
      .position(|el| {
        let types = packet_types(el);
        types.contains(&PacketTy::Handshake) && types.last() == Some(&PacketTy::OneRtt)
      })
      .unwrap();
    for (nth, datagram) in datagrams.iter_mut().enumerate() {
      // The Finished is in the datagram with the request, not before it
      assert_eq!(link.server.conn.state(), ConnState::Handshake);
      assert_eq!(link.server.conn.data.recv.largest(), None);
      link.server.recv(link.now_us, datagram, CLIENT_ADDR);
      if nth == idx {
        break;
      }
    }
    assert_eq!(link.server.conn.state(), ConnState::Confirmed);
    assert_eq!(link.server.conn.data.recv.largest(), Some(0));
    assert_eq!(link.server.app.established, 1);
    // The request reached the application in that same call
    let log = &link.server.app.streams[&0];
    assert_eq!((log.data.as_slice(), log.fin), (b"hello".as_slice(), true));
    link.run();
    assert_eq!(link.client.conn.state(), ConnState::Confirmed);
  }

  // Without traffic both sides close, silently, at the smaller of the two timeouts, or at three
  // PTOs if that is longer. The PTO is the one of the measured RTT, zero on the fake clock.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn idle_timeout_closes() {
    for (client_ms, server_ms, three_ptos) in [(5_000, 10_000, false), (10, 10, true)] {
      let mut opts = LinkOpts::new(None);
      opts.client.max_idle_timeout_ms = client_ms;
      opts.server.max_idle_timeout_ms = server_ms;
      let mut link = settled(&opts);
      let pto_us = link.server.conn.current_pto_us();
      let expected_us = if three_ptos { 3 * pto_us } else { 5_000_000 };
      assert!(!three_ptos || 3 * pto_us > 10_000, "{pto_us}");
      let deadline = link.server.conn.next_deadline().unwrap();
      assert_eq!(deadline - link.now_us, expected_us);
      assert_eq!(link.client.conn.next_deadline(), Some(deadline));
      link.advance(expected_us - 1);
      assert_eq!(link.server.conn.state(), ConnState::Confirmed);
      assert_eq!(link.client.conn.state(), ConnState::Confirmed);
      link.advance(1);
      assert_eq!(link.server.conn.state(), ConnState::Closed);
      assert_eq!(link.client.conn.state(), ConnState::Closed);
      assert_eq!((link.client.app.closed, link.server.app.closed), (1, 1));
      assert_eq!(link.server.conn.next_deadline(), None);
      // Silently: no CONNECTION_CLOSE
      assert!(!link.step());
      // Everything went back to the pools
      assert_eq!(link.server.parts.pools.frame_refs.live_chunks(), 0);
      assert!(link.server.conn.handshake.is_none() && link.server.conn.data.keys.is_none());
    }
  }

  // The server closes: it sends CONNECTION_CLOSE and answers what arrives with more, less and
  // less often; the client drains and sends nothing; both are gone three PTOs later.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn connection_close_then_draining() {
    let mut link = settled(&LinkOpts::new(None));
    let mut late = Vec::new();
    for _ in 0..4 {
      link.client.conn.queue_test_frames(&PING);
      let _ = link.client.flush(link.now_us);
      late.extend(link.client.take_datagrams());
    }
    link.server.conn.close_app(link.now_us, 0x100);
    assert_eq!(link.server.conn.state(), ConnState::Closing);
    let _ = link.server.flush(link.now_us);
    let mut datagrams = link.server.take_datagrams();
    assert_eq!(datagrams.len(), 1);
    // Sent once
    let _ = link.server.flush(link.now_us);
    assert!(link.server.take_datagrams().is_empty());
    link.client.recv(link.now_us, &mut datagrams[0], SERVER_ADDR);
    assert_eq!(link.client.conn.state(), ConnState::Draining);
    link.client.conn.queue_test_frames(&PING);
    let _ = link.client.flush(link.now_us);
    assert!(link.client.take_datagrams().is_empty());
    // After 1, then 2 more, then 4 more datagrams
    let mut answers = Vec::new();
    for datagram in &mut late {
      link.server.recv(link.now_us, datagram, CLIENT_ADDR);
      let _ = link.server.flush(link.now_us);
      answers.push(link.server.take_datagrams().len());
    }
    assert_eq!(answers, [1, 0, 1, 0]);
    let deadline = link.server.conn.next_deadline().unwrap();
    // Three PTOs of the measured RTT, which is zero on the fake clock
    let pto_us = link.server.conn.current_pto_us();
    assert_eq!(deadline - link.now_us, 3 * pto_us);
    assert_eq!(link.client.conn.next_deadline(), Some(deadline));
    link.advance(3 * pto_us - 1);
    assert_eq!(link.server.conn.state(), ConnState::Closing);
    link.advance(1);
    assert_eq!(link.server.conn.state(), ConnState::Closed);
    assert_eq!(link.client.conn.state(), ConnState::Closed);
    assert_eq!((link.client.app.closed, link.server.app.closed), (1, 1));
  }

  // A CONNECTION_CLOSE needs a packet number, not a record: it goes out even when every record of
  // the sent ring is a packet in flight.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn close_goes_out_with_a_full_sent_ring() {
    let mut link = settled(&LinkOpts::new(None));
    let mut sent = 0;
    loop {
      link.server.conn.queue_test_frames(&PING);
      let _ = link.server.flush(link.now_us);
      if link.server.take_datagrams().is_empty() {
        break;
      }
      sent += 1;
    }
    assert_eq!(sent, crate::quic::sent::SENT_RING_LEN);
    link.server.conn.close_app(link.now_us, 0);
    let _ = link.server.flush(link.now_us);
    assert_eq!(link.server.take_datagrams().len(), 1);
  }

  // Datagrams that arrive in the closing state count towards the amplification limit: a server
  // that closes before validating the client answers once the client sends more.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn close_reply_counts_what_arrives_while_closing() {
    let mut opts = LinkOpts::new(None);
    opts.server_tp_padding = 6000;
    let mut link = Link::new(&opts);
    let _ = link.server.flush(link.now_us);
    let flight = link.server.take_datagrams();
    assert_eq!(flight.iter().map(Vec::len).sum::<usize>(), 3 * 1200);
    link.server.conn.close_app(link.now_us, 0);
    let _ = link.server.flush(link.now_us);
    assert!(link.server.take_datagrams().is_empty(), "nothing left of the 3x limit");
    for mut datagram in flight {
      link.client.recv(link.now_us, &mut datagram, SERVER_ADDR);
    }
    let _ = link.client.flush(link.now_us);
    assert!(link.deliver_to_server() > 0);
    assert!(!link.server.conn.address_validated);
    let _ = link.server.flush(link.now_us);
    assert_eq!(link.server.take_datagrams().len(), 1);
  }

  // 2,000 packets of the client in one turn of the server, twice what its window holds, are all
  // processed and all in its next ACK.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn two_thousand_packets_in_one_turn_are_all_processed_and_reported() {
    let mut opts = LinkOpts::new(None);
    opts.server.limits.ping_budget = 3000;
    let mut link = settled(&opts);
    let first = link.client.conn.data.sent.next_pn();
    let mut datagrams = Vec::new();
    for nth in 0..2000 {
      if nth % 200 == 0 {
        // As if acknowledged: the client sends more than its ring holds in flight
        link.client.conn.data.sent.release(&mut link.client.parts.pools);
      }
      link.client.conn.queue_test_frames(&PING);
      let _ = link.client.flush(link.now_us);
      datagrams.extend(link.client.take_datagrams());
    }
    assert_eq!(datagrams.len(), 2000);
    let before = *link.server.conn.stats();
    for datagram in &mut datagrams {
      link.server.recv(link.now_us, datagram, CLIENT_ADDR);
    }
    let after = *link.server.conn.stats();
    assert_eq!(after.packets_in, before.packets_in + 2000);
    assert_eq!(after.packets_dropped, before.packets_dropped);
    // With the ACK-only packets of the client before them, all in the first range
    let (start, end) = server_data_ranges(&link)[0];
    assert!(start <= first && end == first + 1999, "{start}..={end}");
    let ack_only = after.ack_only_out;
    let _ = link.server.flush(link.now_us);
    assert_eq!(link.server.conn.stats().ack_only_out, ack_only + 1);
    link.client.conn.data.sent.release(&mut link.client.parts.pools);
  }

  // An aborted connection, in the middle of its handshake or of a transfer, gives back at once all
  // that it took from the pools.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn abort_returns_everything_to_the_pools() {
    fn counts(parts: &Parts) -> (usize, usize, usize, usize, usize) {
      let pools = &parts.pools;
      (
        pools.frame_refs.live_chunks(),
        pools.handshake_spaces.len(),
        pools.sent_rings.len(),
        pools.crypto_buffers.len(),
        pools.conn_cold.len() + pools.streams_cold.len(),
      )
    }
    let opts = LinkOpts::new(None);
    // Warm counts, after a connection that closed normally
    let mut link = settled(&opts);
    link.client.conn.close_app(link.now_us, 0);
    link.run();
    link.advance(3 * PTO_US);
    let (client_parts, server_parts) = link.into_parts();
    let warm = counts(&server_parts);
    assert_eq!(warm.0, 0);
    // In the middle of the handshake: the flight of the server is not acknowledged
    let mut link = Link::with_parts(&opts, client_parts, server_parts);
    let _ = link.server.flush(link.now_us);
    assert!(link.server.parts.pools.frame_refs.live_chunks() > 0);
    link.server.conn.abort(&mut link.server.app, &mut link.server.parts.pools);
    assert_eq!(link.server.conn.state(), ConnState::Closed);
    assert_eq!(link.server.app.closed, 1);
    assert_eq!(counts(&link.server.parts), warm);
    let (client_parts, server_parts) = link.into_parts();
    // In the middle of a transfer: an ACK of the server, in an ack-eliciting packet (an ACK-only
    // one holds no frame reference, task 23c), is not acknowledged
    let mut link = Link::with_parts(&opts, client_parts, server_parts);
    link.run();
    link.client.conn.queue_test_frames(&PING);
    let _ = link.client.flush(link.now_us);
    assert_eq!(link.deliver_to_server(), 1);
    link.server.conn.queue_test_frames(&PING);
    let _ = link.server.flush(link.now_us);
    assert!(link.server.parts.pools.frame_refs.live_chunks() > 0);
    link.server.conn.abort(&mut link.server.app, &mut link.server.parts.pools);
    assert_eq!(counts(&link.server.parts), warm);
    // Aborting again changes nothing
    link.server.conn.abort(&mut link.server.app, &mut link.server.parts.pools);
    assert_eq!(link.server.app.closed, 1);
    // In the middle of streams: a response that is not acknowledged, with a block of the send
    // queue and a body by reference, and data that waits for earlier data in a receive block
    const HEAD: [u8; 300] = [b'h'; 300];
    let (client_parts, mut server_parts) = link.into_parts();
    for _ in 0..4 {
      server_parts.pools.rx_blocks.give(Box::new([0; RX_BLOCK_LEN]));
      server_parts.pools.tx_blocks.give(Box::new([0; TX_BLOCK_LEN]));
    }
    let body = crate::misc::SharedBytes::from_slice(&[1; 3000]);
    let mut opts = LinkOpts::new(None);
    let response = BodyRef::new(body.clone(), 0..3000).unwrap();
    opts.server_app = TestApp::new(Behavior::RespondBody(&HEAD, response));
    let mut link = Link::with_parts(&opts, client_parts, server_parts);
    drop(opts);
    link.run();
    let now_us = link.now_us;
    let id = link
      .client
      .with_ctx(now_us, |cx| {
        let id = cx.open_bidi()?;
        cx.write(id, b"GET /", true)?;
        Ok::<_, crate::Error>(id)
      })
      .unwrap();
    let frame = Frame::Stream { id: id.0 + 4, offset: 5000, data: b"x", fin: false };
    link.client.conn.queue_test_frames(&encode_frames(&[frame]));
    let _ = link.client.flush(link.now_us);
    assert_eq!(link.deliver_to_server(), 1);
    let _ = link.server.flush(link.now_us);
    let pools = &link.server.parts.pools;
    assert_eq!(pools.stream_slots.live(), 2);
    assert_eq!((pools.rx_blocks.len(), pools.tx_blocks.len()), (3, 3));
    link.server.app.behavior = Behavior::Collect;
    assert_eq!(body.strong_count(), 2);
    link.server.abort();
    let pools = &link.server.parts.pools;
    assert_eq!(counts(&link.server.parts), warm);
    assert_eq!(pools.stream_slots.live(), 0);
    assert_eq!((pools.rx_blocks.len(), pools.tx_blocks.len()), (4, 4));
    assert_eq!(body.strong_count(), 1);
    // In the middle of spills (review J13): the keys of the next phase, the block of spilled
    // ranges, the spill of received packet numbers, the index of waiting data and a send queue that
    // grew go back too. The same connection twice: the second one finds the pools warm
    fn new_counts(parts: &Parts) -> [usize; 5] {
      let pools = &parts.pools;
      [
        pools.key_slots.len(),
        pools.range_blocks.len(),
        pools.recv_spills.len(),
        pools.ooo_indexes.len(),
        pools.seg_queues.len(),
      ]
    }
    let (mut client_parts, mut server_parts) = link.into_parts();
    let mut opts = LinkOpts::new(None);
    opts.server_app = TestApp::new(Behavior::Echo);
    opts.server.limits.ping_budget = 3000;
    let mut warm: Option<([usize; 5], (usize, usize, usize, usize, usize))> = None;
    for _ in 0..2 {
      let mut link = Link::with_parts(&opts, client_parts, server_parts);
      link.run();
      // 40 separate ranges of waiting data on stream 0
      let pieces: Vec<Frame<'_>> = (0..40u64)
        .map(|el| Frame::Stream { id: 0, offset: 2 * el + 1, data: b"x", fin: false })
        .collect();
      link.client.conn.queue_test_frames(&encode_frames(&pieces));
      let _ = link.client.flush(link.now_us);
      assert_eq!(link.deliver_to_server(), 1);
      // 25,000 bytes in order on stream 4, which the server echoes into a send queue of 7 blocks
      let data = [3u8; 1000];
      for nth in 0..25u64 {
        let frame = Frame::Stream { id: 4, offset: nth * 1000, data: &data, fin: false };
        link.client.conn.queue_test_frames(&encode_frames(&[frame]));
        let _ = link.client.flush(link.now_us);
        assert_eq!(link.deliver_to_server(), 1);
      }
      // 1,100 packets before the server flushes: more than the window of received packet numbers
      for nth in 0..1100 {
        if nth % 200 == 0 {
          link.client.conn.forget_sent_packets(&mut link.client.parts.pools);
        }
        link.client.conn.queue_test_frames(&PING);
        let _ = link.client.flush(link.now_us);
        assert_eq!(link.deliver_to_server(), 1);
      }
      let during = new_counts(&link.server.parts);
      link.server.abort();
      let after = new_counts(&link.server.parts);
      for (idx, (held, back)) in during.iter().zip(after).enumerate() {
        assert!(*held < back, "{idx}: {during:?} then {after:?}");
      }
      let old = counts(&link.server.parts);
      assert_eq!(old.0, 0);
      if let Some(elem) = warm {
        assert_eq!((after, old), elem);
      }
      warm = Some((after, old));
      (client_parts, server_parts) = link.into_parts();
    }
  }

  // Final review I2: a packet that fails for want of a frame-reference chunk gives back the chunks
  // it took, and so do the packets of the same datagram before it. Once the connection is gone no
  // chunk is in use and the idle pool trims again.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn exhausted_frame_refs_come_back_once_the_connection_is_gone() {
    fn closes_with_internal_error(link: &mut Link) {
      let code = TransportErrorCode::InternalError.code();
      assert_eq!(link.server.conn.close_code(), Some((false, code)));
      for _ in 0..16 {
        let Some(deadline) = link.server.conn.next_deadline() else {
          break;
        };
        link.advance(deadline.saturating_sub(link.now_us).max(1));
      }
      assert_eq!(link.server.conn.state(), ConnState::Closed);
    }
    fn trims(pools: &mut QuicPools, held: FrameRefRange, cap: usize) {
      pools.frame_refs.free(held);
      pools.frame_refs.set_max_chunks(cap);
      assert_eq!(pools.frame_refs.live_chunks(), 0);
      let mut range = FrameRefRange::EMPTY;
      for _ in 0..1000 {
        pools.frame_refs.push(&mut range, FrameRef::HandshakeDone).unwrap();
      }
      pools.frame_refs.free(range);
      pools.trim_idle();
      assert_eq!(pools.frame_refs.chunk_count(), 64);
    }
    // A packet of many frames: the responses of 20 requests, after its first chunk
    let mut opts = LinkOpts::new(None);
    opts.server_app = TestApp::new(Behavior::Respond(b"ok"));
    let mut link = settled(&opts);
    let _ = link.client.with_ctx(link.now_us, |cx| {
      for _ in 0..20 {
        let id = cx.open_bidi()?;
        cx.write(id, b"GET /", true)?;
      }
      Ok::<_, crate::Error>(())
    });
    let _ = link.client.flush(link.now_us);
    assert!(link.deliver_to_server() > 0);
    assert_eq!(link.server.app.fins, 20);
    let (held, cap) = link.server.parts.pools.frame_refs.starve(1);
    let _ = link.server.flush(link.now_us);
    closes_with_internal_error(&mut link);
    trims(&mut link.server.parts.pools, held, cap);
    // The first flight of the server: its Initial packet took the chunk, its Handshake packet, in
    // the same datagram, finds none
    let (client_parts, mut server_parts) = link.into_parts();
    let (held, cap) = server_parts.pools.frame_refs.starve(1);
    let mut link = Link::with_parts(&LinkOpts::new(None), client_parts, server_parts);
    let _ = link.server.flush(link.now_us);
    closes_with_internal_error(&mut link);
    trims(&mut link.server.parts.pools, held, cap);
  }

  // What a connection holds of the pools goes back only if it is closed or aborted, so dropping it
  // before is a bug that debug builds catch.
  #[cfg_attr(miri, ignore)]
  #[test]
  #[should_panic(expected = "dropped before it was closed or aborted")]
  fn dropping_an_open_connection_is_a_bug() {
    let mut pools = QuicPools::new();
    let cid = crate::quic::Cid::new(&[1; 8]).unwrap();
    let mut rng = crate::rng::ChaCha20::from_key([3; 32]);
    let params = super::ConnParams::default();
    drop(crate::quic::testing::client_conn(&params, cid, cid, &mut rng, 0, &mut pools, |_| {}));
  }

  // Takes every train descriptor of `tx`, the newest one for a train to the client of datagrams
  // of `segment` bytes, which the server can still join.
  fn fill_descriptors(tx: &mut crate::quic::TxArena, segment: usize) {
    let other = core::net::IpAddr::V4(core::net::Ipv4Addr::new(10, 9, 9, 9));
    let mut port = 1;
    while let Some(buffer) = tx.begin(core::net::SocketAddr::new(other, port), None, segment) {
      buffer.fill(0);
      tx.commit(segment);
      port += 1;
    }
    let oldest = tx.pending().next().unwrap().id;
    tx.release(oldest);
    tx.begin(CLIENT_ADDR, None, segment).unwrap().fill(0);
    tx.commit(segment);
  }

  // A datagram that must have 1200 bytes, for a PATH_RESPONSE, does not go out in the short room
  // of a train that it can join: the flush stops with ArenaFull, and the answer goes out padded
  // once the arena has room. So does a packet that does not fit at all.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn a_short_arena_segment_holds_back_what_needs_more_room() {
    let mut link = settled(&LinkOpts::new(None));
    fill_descriptors(&mut link.server.parts.tx, 60);
    link.client.conn.queue_test_frames(&[0x1a, 1, 2, 3, 4, 5, 6, 7, 8]);
    let _ = link.client.flush(link.now_us);
    assert_eq!(link.deliver_to_server(), 1);
    assert_eq!(link.server.flush(link.now_us), FlushOutcome::ArenaFull);
    assert_eq!(link.server.conn.path_response, Some([1, 2, 3, 4, 5, 6, 7, 8]));
    // Only the 60-byte datagrams of the filler were there
    let filler = link.server.take_datagrams();
    assert!(filler.iter().all(|el| el.len() == 60), "{:?}", filler.last().map(Vec::len));
    assert_eq!(link.server.flush(link.now_us), FlushOutcome::Done);
    let answer = link.server.take_datagrams();
    assert_eq!(answer.iter().map(Vec::len).collect::<Vec<_>>(), [1200]);
    assert_eq!(link.server.conn.path_response, None);
    // Room for no packet at all: the ACK that is owed waits
    fill_descriptors(&mut link.server.parts.tx, 20);
    link.client.conn.queue_test_frames(&PING);
    let _ = link.client.flush(link.now_us);
    assert_eq!(link.deliver_to_server(), 1);
    assert_eq!(link.server.flush(link.now_us), FlushOutcome::ArenaFull);
    assert!(link.server.conn.data.recv.ack_pending());
    let _ = link.server.take_datagrams();
    assert_eq!(link.server.flush(link.now_us), FlushOutcome::Done);
    assert_eq!(link.server.take_datagrams().len(), 1);
    assert!(!link.server.conn.data.recv.ack_pending());
  }

  // A spent budget closes the connection, so `recv_datagram` reports it as a connection error.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn excessive_load_is_a_connection_error() {
    let mut opts = LinkOpts::new(None);
    opts.server.limits.ping_budget = 1;
    // No path MTU probe from the client, whose PING the budget would count
    opts.server.max_udp_payload_size = 1200;
    let mut link = settled(&opts);
    // Ruling T21-g: the allowance is the base plus 2 per RTT, which is thousands on this link;
    // an RTT over one second adds none, so the base is the allowance
    link.server.conn.recovery.rtt.smoothed_us = 10_000_000;
    let mut pings = Vec::new();
    for _ in 0..2 {
      link.client.conn.queue_test_frames(&PING);
      let _ = link.client.flush(link.now_us);
      pings.extend(link.client.take_datagrams());
    }
    let meta = crate::quic::DatagramMeta { peer: CLIENT_ADDR, local: None, segment_size: None };
    let server = &mut link.server;
    let (app, pools) = (&mut server.app, &mut server.parts.pools);
    assert!(server.conn.recv_datagram(link.now_us, &mut pings[0], meta, app, pools).is_ok());
    let rslt = server.conn.recv_datagram(link.now_us, &mut pings[1], meta, app, pools);
    assert!(
      matches!(
        rslt,
        Err(crate::Error::QuicClose(
          TransportErrorCode::ApplicationError,
          QuicError::ExcessiveLoad
        ))
      ),
      "{rslt:?}"
    );
    assert_eq!((server.conn.state(), server.conn.close.app), (ConnState::Closing, true));
  }

  // RFC 9000 table 3 lets 1-RTT packets carry HANDSHAKE_DONE, but only servers send it.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn handshake_done_from_a_client_is_protocol_violation() {
    let mut link = settled(&LinkOpts::new(None));
    link.client.conn.queue_test_frames(&[0x1e]);
    let _ = link.client.flush(link.now_us);
    assert_eq!(link.deliver_to_server(), 1);
    assert_eq!(link.server.conn.state(), ConnState::Closing);
    assert_eq!(link.server.conn.close.code, TransportErrorCode::ProtocolViolation.code());
    let _ = link.server.flush(link.now_us);
    assert_eq!(link.deliver_to_client(), 1);
    assert_eq!(link.client.conn.state(), ConnState::Draining);
  }

  // Every PING within the budget is acknowledged; one more in the same second closes the
  // connection with the excessive load code of the application.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn ping_flood_over_budget_closes_with_excessive_load() {
    let mut opts = LinkOpts::new(None);
    opts.server.limits.ping_budget = 4;
    // No path MTU probe from the client, whose PING the budget would count
    opts.server.max_udp_payload_size = 1200;
    let mut link = settled(&opts);
    // Ruling T21-g: as in `excessive_load_is_a_connection_error`, an RTT of 10 s leaves the base
    link.server.conn.recovery.rtt.smoothed_us = 10_000_000;
    for _ in 0..4 {
      link.client.conn.queue_test_frames(&PING);
      let _ = link.client.flush(link.now_us);
      assert_eq!(link.deliver_to_server(), 1);
      assert!(link.server.conn.data.recv.ack_pending());
      let _ = link.server.flush(link.now_us);
      assert_eq!(link.server.take_datagrams().len(), 1);
    }
    link.client.conn.queue_test_frames(&PING);
    let _ = link.client.flush(link.now_us);
    assert_eq!(link.deliver_to_server(), 1);
    assert_eq!(link.server.conn.state(), ConnState::Closing);
    assert!(link.server.conn.close.app);
    assert_eq!(link.server.conn.close.code, 0x0107);
    let _ = link.server.flush(link.now_us);
    assert_eq!(link.deliver_to_client(), 1);
    assert_eq!(link.client.conn.state(), ConnState::Draining);
  }

  // Task 21 (interop with the ngtcp2 example client, RFC 9000 section 13.2.4): a client in a run of
  // ACK-only packets adds a PING once per smoothed RTT, which is more than the default budget of 64
  // a second whenever that RTT is under 15 ms (the example client was closed with H3_EXCESSIVE_LOAD
  // in a 1 MiB transfer on loopback under 5% loss). A peer that pings once per millisecond for a
  // tenth of a second, 100 PINGs, is legal and must not be closed (ruling T21-g: the allowance
  // scales with the RTT).
  #[cfg_attr(miri, ignore)]
  #[test]
  fn a_peer_that_pings_once_per_rtt_is_not_closed() {
    let mut opts = LinkOpts::new(None);
    // No path MTU probe from the client, whose PING the budget would count
    opts.server.max_udp_payload_size = 1200;
    let mut link = settled(&opts);
    for _ in 0..100 {
      link.client.conn.queue_test_frames(&PING);
      let _ = link.client.flush(link.now_us);
      assert_eq!(link.deliver_to_server(), 1);
      assert_eq!(link.server.conn.state(), ConnState::Confirmed, "closed after a legal pinger");
      let _ = link.server.flush(link.now_us);
      let _ = link.server.take_datagrams();
      link.now_us = link.now_us.wrapping_add(1_000);
    }
  }

  // Ruling T21-g: the PINGs a second are 64 plus 2 per smoothed RTT. Sends PINGs at one instant
  // until the connection closes; the number taken before that.
  fn pings_until_closed(smoothed_rtt_us: u64, base: u32) -> (u32, ConnState) {
    let mut opts = LinkOpts::new(None);
    opts.server.limits.ping_budget = base;
    // No path MTU probe from the client, whose PING the budget would count
    opts.server.max_udp_payload_size = 1200;
    let mut link = settled(&opts);
    link.server.conn.recovery.rtt.smoothed_us = smoothed_rtt_us;
    let mut taken = 0;
    for _ in 0..20_000 {
      link.client.conn.queue_test_frames(&PING);
      let _ = link.client.flush(link.now_us);
      assert_eq!(link.deliver_to_server(), 1, "after {taken} PINGs");
      if link.server.conn.state() != ConnState::Confirmed {
        break;
      }
      taken += 1;
      let _ = link.server.flush(link.now_us);
      let _ = link.deliver_to_client();
    }
    let closing = (link.server.conn.close.app, link.server.conn.close.code);
    assert_eq!(closing, (true, 0x0107));
    (taken, link.server.conn.state())
  }

  // Ruling T21-g, a flooder past the scaled allowance is closed: with a long RTT (1 s, one PING
  // per RTT) the allowance is the base 64 plus 2, and the 67th PING closes the connection.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn ping_flood_with_a_long_rtt_gets_the_base_allowance() {
    assert_eq!(pings_until_closed(1_000_000, 64), (66, ConnState::Closing));
    // The base is the one that is configured
    assert_eq!(pings_until_closed(1_000_000, 10), (12, ConnState::Closing));
    // Before the first sample the initial RTT (333 ms) applies: 64 + 2 * 3
    assert_eq!(pings_until_closed(333_000, 64), (70, ConnState::Closing));
  }

  // Ruling T21-g, with a tiny RTT the allowance would be 64 + 2,000,000: the cap of 16,384 a
  // second applies, and the 16,385th PING closes the connection.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn ping_flood_with_a_tiny_rtt_is_capped() {
    assert_eq!(pings_until_closed(1, 64), (16_384, ConnState::Closing));
  }

  // Ruling T23-m: a legitimate client that has sent many PINGs this second at a short RTT and then
  // changes its IP must not be closed. An IP change resets the RTT estimate (RFC 9000 section 9.4),
  // which would otherwise drop the PING allowance to the pre-sample 70/s mid-window and close a
  // client already past it. The allowance of the last validated path is kept until the new path has
  // an RTT sample.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn a_legitimate_rebind_keeps_the_ping_allowance() {
    let mut opts = LinkOpts::new(None);
    // No path MTU probe from the client, whose PING the budget would count
    opts.server.max_udp_payload_size = 1200;
    let mut link = settled(&opts);
    // A 1 ms smoothed RTT: the allowance is 64 + 2 * 1000 = 2,064 a second
    link.server.conn.recovery.rtt.smoothed_us = 1_000;
    assert_eq!(link.server.conn.ping_allowance(), 2_064);
    // 200 PINGs this second, all within the allowance
    for _ in 0..200 {
      link.client.conn.queue_test_frames(&PING);
      let _ = link.client.flush(link.now_us);
      assert_eq!(link.deliver_to_server(), 1);
      assert_eq!(link.server.conn.state(), ConnState::Confirmed);
      let _ = link.server.flush(link.now_us);
      let _ = link.server.take_datagrams();
    }
    // The client rebinds to a new IP (the IP change resets the RTT estimate) and keeps pinging in
    // the same second, as quinn does in answer to the server's path challenge. Each PING after the
    // rebind is checked against the allowance of the new, sample-less path.
    let moved = core::net::SocketAddr::new(
      core::net::IpAddr::V4(core::net::Ipv4Addr::new(127, 0, 0, 2)),
      50_000,
    );
    for _ in 0..3 {
      link.client.conn.queue_test_frames(&PING);
      let _ = link.client.flush(link.now_us);
      let mut datagram = link.client.take_datagrams().pop().unwrap();
      link.server.recv(link.now_us, &mut datagram, moved);
      let _ = link.server.flush(link.now_us);
      let _ = link.server.take_datagrams();
    }
    assert_eq!(
      link.server.conn.state(),
      ConnState::Confirmed,
      "a legitimate rebind within the allowance must not be closed"
    );
  }

  // Ruling T21-g: the allowance follows the RTT between the two ends, and a base above the cap
  // stays the base.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn ping_allowance_follows_the_rtt() {
    let mut link = settled(&LinkOpts::new(None));
    let conn = &mut link.server.conn;
    for (srtt, want) in [(1_000_000, 66), (100_000, 84), (15_625, 192), (1_000, 2_064), (10, 16_384), (0, 16_384)] {
      conn.recovery.rtt.smoothed_us = srtt;
      assert_eq!(conn.ping_allowance(), want, "srtt {srtt} us");
    }
    conn.params.limits.ping_budget = 100_000;
    assert_eq!(conn.ping_allowance(), 100_000);
  }

  // A PATH_CHALLENGE is answered in a datagram of 1200 bytes; past the budget the connection
  // closes.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn path_challenges_are_answered_until_the_budget_closes() {
    let mut opts = LinkOpts::new(None);
    opts.server.limits.path_challenge_budget = 2;
    let mut link = settled(&opts);
    for _ in 0..2 {
      link.client.conn.queue_test_frames(&[0x1a, 1, 2, 3, 4, 5, 6, 7, 8]);
      let _ = link.client.flush(link.now_us);
      assert_eq!(link.deliver_to_server(), 1);
      assert_eq!(link.server.conn.path_response, Some([1, 2, 3, 4, 5, 6, 7, 8]));
      let _ = link.server.flush(link.now_us);
      let datagrams = link.server.take_datagrams();
      assert_eq!(datagrams.iter().map(Vec::len).collect::<Vec<_>>(), [1200]);
    }
    link.client.conn.queue_test_frames(&[0x1a, 1, 2, 3, 4, 5, 6, 7, 8]);
    let _ = link.client.flush(link.now_us);
    assert_eq!(link.deliver_to_server(), 1);
    assert_eq!(link.server.conn.state(), ConnState::Closing);
    assert_eq!((link.server.conn.close.app, link.server.conn.close.code), (true, 0x0107));
  }

  // Rule: a packet without frames is a PROTOCOL_VIOLATION (RFC 9000 section 12.4).
  #[cfg_attr(miri, ignore)]
  #[test]
  fn empty_packet_is_protocol_violation() {
    let mut link = settled(&LinkOpts::new(None));
    let mut packet = client_packet(&mut link, Space::Data, None, 0, &[]);
    link.server.recv(link.now_us, &mut packet, CLIENT_ADDR);
    assert_eq!(server_close_code(&link), Some(TransportErrorCode::ProtocolViolation.code()));
  }

  // Rule: the reserved bits of a header must be zero once protection is removed (RFC 9000
  // section 17.3.1).
  #[cfg_attr(miri, ignore)]
  #[test]
  fn reserved_bits_set_is_protocol_violation() {
    let mut link = settled(&LinkOpts::new(None));
    let mut packet = client_packet(&mut link, Space::Data, None, 0x18, &PING);
    link.server.recv(link.now_us, &mut packet, CLIENT_ADDR);
    assert_eq!(server_close_code(&link), Some(TransportErrorCode::ProtocolViolation.code()));
  }

  // Rule: 0-RTT packets are dropped before any frame is read, even one that the keys of the
  // connection would open.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn zero_rtt_packet_is_dropped() {
    let mut link = settled(&LinkOpts::new(None));
    let conn = &mut link.client.conn;
    let (dcid, scid) = (conn.peer_cid, conn.local_cid);
    let pn = conn.data.sent.next_pn();
    conn.data.sent.skip();
    // Long header of type 1 with a 4-byte packet number, a Length for it, a PING and the tag
    let mut datagram = vec![0xd3, 0, 0, 0, 1, 8];
    datagram.extend_from_slice(dcid.as_slice());
    datagram.push(8);
    datagram.extend_from_slice(scid.as_slice());
    datagram.extend_from_slice(&(0x4000u16 | (4 + 1 + 16)).to_be_bytes());
    let pn_offset = datagram.len();
    datagram.extend_from_slice(&u32::try_from(pn).unwrap().to_be_bytes());
    datagram.push(0x01);
    datagram.resize(datagram.len() + 16, 0);
    let keys = conn.data.keys.as_ref().unwrap();
    let len = protect(&keys.local, &mut datagram, pn_offset, pn, 4, 1).unwrap();
    assert_eq!(len, datagram.len());
    let before = *link.server.conn.stats();
    link.server.recv(link.now_us, &mut datagram, CLIENT_ADDR);
    assert_eq!(link.server.conn.stats().packets_dropped, before.packets_dropped + 1);
    assert_eq!(link.server.conn.stats().packets_in, before.packets_in);
    assert_eq!(link.server.conn.state(), ConnState::Confirmed);
    let _ = link.server.flush(link.now_us);
    assert!(link.server.take_datagrams().is_empty());
  }

  // Rule: only a server sends NEW_TOKEN (RFC 9000 section 19.7).
  #[cfg_attr(miri, ignore)]
  #[test]
  fn new_token_from_a_client_is_protocol_violation() {
    let mut link = settled(&LinkOpts::new(None));
    link.client.conn.queue_test_frames(&[0x07, 0x01, 0xaa]);
    let _ = link.client.flush(link.now_us);
    assert_eq!(link.deliver_to_server(), 1);
    assert_eq!(server_close_code(&link), Some(TransportErrorCode::ProtocolViolation.code()));
  }

  // An ACK of a packet number that was never sent is a PROTOCOL_VIOLATION (RFC 9000 section 13.1).
  #[cfg_attr(miri, ignore)]
  #[test]
  fn ack_of_an_unsent_packet_is_protocol_violation() {
    let mut link = settled(&LinkOpts::new(None));
    // An ACK of packet 1000, which the server is far from
    link.client.conn.queue_test_frames(&[0x02, 0x43, 0xe8, 0x00, 0x00, 0x00]);
    let _ = link.client.flush(link.now_us);
    assert_eq!(link.deliver_to_server(), 1);
    assert_eq!(server_close_code(&link), Some(TransportErrorCode::ProtocolViolation.code()));
  }

  // Rule: the CIDs of the transport parameters are those of the packets (RFC 9000 section 7.3),
  // on both sides.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn transport_parameter_cid_mismatch_is_transport_parameter_error() {
    let code = Some(TransportErrorCode::TransportParameterError.code());
    let client_cases: [fn(&mut crate::quic::TransportParams); 2] = [
      |el| el.initial_source_connection_id = Some(Cid::new(&[9; 8]).unwrap()),
      |el| el.initial_source_connection_id = None,
    ];
    for change in client_cases {
      let mut opts = LinkOpts::new(None);
      opts.client_tp = change;
      let link = Link::new(&opts);
      assert_eq!(server_close_code(&link), code);
    }
    let server_cases: [fn(&mut crate::quic::TransportParams); 3] = [
      |el| el.original_destination_connection_id = Some(Cid::new(&[9; 8]).unwrap()),
      |el| el.initial_source_connection_id = None,
      |el| el.retry_source_connection_id = Some(Cid::new(&[9; 8]).unwrap()),
    ];
    for change in server_cases {
      let mut opts = LinkOpts::new(None);
      opts.server_tp = change;
      let mut link = Link::new(&opts);
      let _ = link.server.flush(link.now_us);
      assert_eq!(link.deliver_to_client(), 1);
      let client = &link.client.conn;
      assert_eq!(client.state(), ConnState::Closing);
      assert_eq!((client.close.app, Some(client.close.code)), (false, code));
    }
  }

  // RFC 9000 section 14.1: a server pads a datagram with an ack-eliciting Initial packet to 1200
  // bytes, and not one with an ACK-only Initial packet.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn server_pads_only_ack_eliciting_initial_datagrams() {
    let mut link = Link::new(&LinkOpts::new(None));
    let _ = link.server.flush(link.now_us);
    let flight = link.server.take_datagrams();
    assert_eq!(flight.len(), 1);
    assert_eq!(flight[0].len(), 1200);
    assert_eq!(packet_types(&flight[0])[0], PacketTy::Initial);
    let mut ping = client_packet(&mut link, Space::Initial, None, 0, &initial_ping(1200));
    link.server.recv(link.now_us, &mut ping, CLIENT_ADDR);
    let _ = link.server.flush(link.now_us);
    let ack = link.server.take_datagrams();
    assert_eq!(ack.len(), 1);
    assert_eq!(packet_types(&ack[0]), [PacketTy::Initial]);
    assert!(ack[0].len() < 100, "{}", ack[0].len());
  }

  // Rule (RFC 9000 section 8.1; found by the fuzz target `quic_endpoint`): a server sends at most
  // three times what it received from the address of the client, so the bytes of datagrams from
  // another address (a packet of the same connection that an attacker sends from its own address)
  // do not raise the limit on what goes to the first address.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn datagrams_from_another_address_do_not_raise_the_amplification_budget() {
    let mut link = Link::new(&LinkOpts::new(None));
    let _ = link.server.flush(link.now_us);
    let _ = link.server.take_datagrams();
    let other = core::net::SocketAddr::new(core::net::IpAddr::V4(core::net::Ipv4Addr::new(192, 0, 2, 9)), 40_000);
    let before = link.server.conn.bytes_received;
    let mut ping = client_packet(&mut link, Space::Initial, None, 0, &initial_ping(1200));
    let len = ping.len() as u64;
    let mut again = ping.clone();
    link.server.recv(link.now_us, &mut ping, other);
    assert_eq!(link.server.conn.bytes_received, before);
    link.server.recv(link.now_us, &mut again, CLIENT_ADDR);
    assert_eq!(link.server.conn.bytes_received, before + len);
  }

  // Rule: a server drops an Initial packet of a datagram below 1200 bytes (RFC 9000 section 14.1).
  #[cfg_attr(miri, ignore)]
  #[test]
  fn client_initial_in_a_short_datagram_is_dropped() {
    let mut link = Link::new(&LinkOpts::new(None));
    let _ = link.server.flush(link.now_us);
    let _ = link.server.take_datagrams();
    let mut ping = client_packet(&mut link, Space::Initial, None, 0, &initial_ping(600));
    assert!(ping.len() < 1200);
    let before = *link.server.conn.stats();
    link.server.recv(link.now_us, &mut ping, CLIENT_ADDR);
    assert_eq!(link.server.conn.stats().packets_dropped, before.packets_dropped + 1);
    assert_eq!(link.server.conn.stats().packets_in, before.packets_in);
    let _ = link.server.flush(link.now_us);
    assert!(link.server.take_datagrams().is_empty());
  }

  // Rule: a packet coalesced after one with another destination CID is dropped (RFC 9000 section
  // 12.2); the first one is processed.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn coalesced_packet_with_another_dcid_is_dropped() {
    let mut link = Link::new(&LinkOpts::new(None));
    let _ = link.server.flush(link.now_us);
    let _ = link.server.take_datagrams();
    // The first packet goes to the CID that the client chose, the second one to the server's: the
    // server takes either alone, not both in one datagram
    let mut datagram = client_packet(&mut link, Space::Initial, None, 0, &initial_ping(700));
    let other = link.server.conn.local_cid;
    assert_ne!(other, link.client.conn.peer_cid);
    datagram.extend(client_packet(&mut link, Space::Initial, Some(other), 0, &initial_ping(700)));
    let before = *link.server.conn.stats();
    link.server.recv(link.now_us, &mut datagram, CLIENT_ADDR);
    assert_eq!(link.server.conn.stats().packets_in, before.packets_in + 1);
    assert_eq!(link.server.conn.stats().packets_dropped, before.packets_dropped + 1);
  }

  // A corrupted packet is dropped without a word, and the connection goes on.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn undecryptable_packet_is_dropped_silently() {
    let mut link = settled(&LinkOpts::new(None));
    link.client.conn.queue_test_frames(&PING);
    let _ = link.client.flush(link.now_us);
    let mut datagrams = link.client.take_datagrams();
    let last = datagrams[0].len() - 1;
    datagrams[0][last] ^= 1;
    let before = *link.server.conn.stats();
    link.server.recv(link.now_us, &mut datagrams[0], CLIENT_ADDR);
    assert_eq!(link.server.conn.stats().packets_dropped, before.packets_dropped + 1);
    assert_eq!(link.server.conn.stats().packets_in, before.packets_in);
    let _ = link.server.flush(link.now_us);
    assert!(link.server.take_datagrams().is_empty());
    assert_eq!(link.server.conn.state(), ConnState::Confirmed);
  }

  // Handshakes after the first batch find the pools of the server warm: its allocations, counted
  // apart from those of the client and of the harness, are at most ring's per handshake.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn steady_state_handshake_and_acks_allocate_nothing_after_warmup() {
    static OTHERS: AtomicU64 = AtomicU64::new(0);
    static SERVER: AtomicU64 = AtomicU64::new(0);
    const HANDSHAKES: u64 = 64;
    let mut opts = LinkOpts::new(None);
    opts.counters = Some((&SERVER, &OTHERS));
    _count_allocations_in(&OTHERS);
    let mut parts = (Parts::new(), Parts::new());
    let batch = |parts: (Parts, Parts)| {
      let (mut client_parts, mut server_parts) = parts;
      for _ in 0..HANDSHAKES {
        let mut link = Link::with_parts(&opts, client_parts, server_parts);
        link.run();
        assert_eq!(link.server.conn.state(), ConnState::Confirmed);
        for _ in 0..4 {
          link.client.conn.queue_test_frames(&PING);
          link.server.conn.queue_test_frames(&PING);
          link.run();
        }
        link.client.conn.close_app(link.now_us, 0);
        link.run();
        link.advance(3 * PTO_US);
        assert_eq!(link.server.conn.state(), ConnState::Closed);
        assert_eq!(link.client.conn.state(), ConnState::Closed);
        (client_parts, server_parts) = link.into_parts();
      }
      (client_parts, server_parts)
    };
    parts = batch(parts);
    // The counter sees the server: its pools and TLS state were allocated while warming up
    let before = SERVER.load(Ordering::Relaxed);
    assert!(before > 0);
    let parts = batch(parts);
    let allocations = SERVER.load(Ordering::Relaxed) - before;
    // The budget is ring's RSA signature, at most 9 per handshake. The test certificate is ECDSA
    // P-256, whose signature allocates nothing, so anything counted here would be a regression
    assert!(allocations <= 9 * HANDSHAKES);
    assert_eq!(allocations, 0, "{allocations} allocations in {HANDSHAKES} handshakes");
    assert_eq!(parts.1.pools.frame_refs.live_chunks(), 0);
  }

  // Spec section 5.4: a connection is at most 4 KiB, the state of the handshake comes from pools
  #[test]
  fn quic_conn_fits_in_4_kib() {
    use crate::quic::testing::{ClientConn, ServerConn};
    assert!(size_of::<ServerConn>() <= 4096, "{}", size_of::<ServerConn>());
    assert!(size_of::<ClientConn>() <= 4096, "{}", size_of::<ClientConn>());
  }

  // CRYPTO data in pieces, out of order and overlapping, reaches TLS in order and once.
  #[test]
  fn crypto_data_is_reassembled_in_order() {
    let mut pools = QuicPools::new();
    let mut rx = CryptoRx::new();
    let data: Vec<u8> = (0..6000u32).map(|el| el.to_le_bytes()[0] ^ (el >> 8) as u8).collect();
    let mut out = Vec::new();
    let mut take = |rx: &mut CryptoRx, offset: usize, len: usize, pools: &mut QuicPools| {
      let direct = rx.accept(offset as u64, &data[offset..offset + len], pools).unwrap();
      out.extend_from_slice(direct);
      loop {
        let buffered = rx.buffered().to_vec();
        if buffered.is_empty() {
          break;
        }
        out.extend_from_slice(&buffered);
        rx.consume(buffered.len(), pools);
      }
    };
    take(&mut rx, 1000, 500, &mut pools);
    take(&mut rx, 3000, 1000, &mut pools);
    take(&mut rx, 1400, 1700, &mut pools);
    assert!(rx.buffer.is_some());
    take(&mut rx, 0, 1200, &mut pools);
    assert_eq!(rx.offset, 4000);
    // A duplicate and an overlap
    take(&mut rx, 100, 100, &mut pools);
    take(&mut rx, 3500, 2500, &mut pools);
    assert_eq!(out, data);
    // The buffer went back once empty
    assert!(rx.buffer.is_none());
    assert_eq!(pools.crypto_buffers.len(), 1);
    // Data that wraps around the end of the ring
    let mut rx = CryptoRx::new();
    rx.offset = 3 * CRYPTO_BUFFER_LEN as u64 - 10;
    let start = rx.offset;
    let piece: Vec<u8> = (0..105).collect();
    assert!(rx.accept(start + 5, &piece[5..], &mut pools).unwrap().is_empty());
    assert_eq!(rx.accept(start, &piece[..5], &mut pools).unwrap(), &piece[..5]);
    assert_eq!(rx.buffered(), &piece[5..10]);
    rx.consume(5, &mut pools);
    assert_eq!(rx.buffered(), &piece[10..]);
    rx.consume(95, &mut pools);
    assert!(rx.buffered().is_empty() && rx.buffer.is_none());
  }

  // Data that starts more than 4096 bytes after what TLS read closes the connection.
  #[test]
  fn crypto_data_too_far_ahead_is_crypto_buffer_exceeded() {
    let mut pools = QuicPools::new();
    let mut rx = CryptoRx::new();
    assert!(rx.accept(CRYPTO_BUFFER_LEN as u64 - 10, &[0; 10], &mut pools).is_ok());
    assert!(matches!(
      rx.accept(CRYPTO_BUFFER_LEN as u64 - 10, &[0; 11], &mut pools),
      Err(crate::Error::QuicClose(
        TransportErrorCode::CryptoBufferExceeded,
        QuicError::CryptoDataTooFarAhead
      ))
    ));
  }

  // Ruling T9-g: packets that fail to open close the connection with AEAD_LIMIT_REACHED once
  // they reach the integrity limit; so does a key that sealed as many packets as the
  // confidentiality limit allows when no update can start, here as the peer acknowledges nothing.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn aead_limits_close_the_connection() {
    let code = Some(TransportErrorCode::AeadLimitReached.code());
    let mut opts = LinkOpts::new(None);
    opts.server.test_integrity_limit = 3;
    let mut link = settled(&opts);
    for nth in 0..3 {
      assert_eq!(link.server.conn.state(), ConnState::Confirmed, "{nth}");
      link.client.conn.queue_test_frames(&PING);
      let _ = link.client.flush(link.now_us);
      let mut datagrams = link.client.take_datagrams();
      let last = datagrams[0].len() - 1;
      datagrams[0][last] ^= 1;
      link.server.recv(link.now_us, &mut datagrams[0], CLIENT_ADDR);
    }
    assert_eq!(server_close_code(&link), code);
    let mut opts = LinkOpts::new(None);
    opts.server.test_confidentiality_limit = 40;
    let mut link = settled(&opts);
    let sealed = |link: &Link| link.server.conn.data.keys.as_ref().unwrap().local.packets_sealed();
    let mut most = 0;
    for _ in 0..100 {
      if link.server.conn.state() != ConnState::Confirmed {
        break;
      }
      most = most.max(sealed(&link));
      link.server.conn.queue_test_frames(&PING);
      let _ = link.server.flush(link.now_us);
      let _ = link.server.take_datagrams();
    }
    assert_eq!(server_close_code(&link), code);
    // One update at half the limit, which the peer never acknowledged, then the limit
    assert_eq!(link.server.conn.stats().key_updates, 1);
    assert!(most < 40 && sealed(&link) <= 40, "{most} {}", sealed(&link));
  }

  // Review J5, RFC 9002 section 7.6.1: the duration of persistent congestion includes the
  // max_ack_delay of the peer whatever the packet number space.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn persistent_congestion_counts_max_ack_delay_in_every_space() {
    let link = Link::new(&LinkOpts::new(None));
    let conn = &link.server.conn;
    // `detect_lost` takes it for every space
    let expected = 3 * (conn.recovery.rtt.pto_base_us() + 25_000);
    assert_eq!(conn.persistent_congestion_us(), expected);
  }

  // Review J7, RFC 9001 section 6.5: an update waits at least three PTOs (four, see
  // `maybe_initiate`) from the acknowledgment that confirmed the previous one, whatever the
  // threshold.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn key_updates_wait_three_ptos_after_the_previous_one() {
    let mut opts = LinkOpts::new(None);
    opts.server.key_update_threshold = 1;
    opts.server.limits.ping_budget = 100_000;
    opts.client.limits.ping_budget = 100_000;
    let mut link = Link::new(&opts);
    link.impair(Impairment::delay(5_000));
    while link.server.conn.state() != ConnState::Confirmed {
      if !link.step_impaired() {
        assert!(link.advance_to_next_event());
      }
    }
    let (mut phase, mut flips) = (link.server.conn.key_phases().0, Vec::new());
    for _ in 0..200 {
      link.server.conn.queue_test_frames(&PING);
      link.client.conn.queue_test_frames(&PING);
      for _ in 0..4 {
        if !link.step_impaired() {
          assert!(link.advance_to_next_event());
        }
        if link.server.conn.key_phases().0 != phase {
          phase = !phase;
          flips.push(link.now_us);
        }
      }
    }
    let pto = link.server.conn.current_pto_us();
    assert!(flips.len() >= 2, "{flips:?}");
    for pair in flips.windows(2) {
      assert!(pair[1] - pair[0] >= 3 * pto, "{flips:?}, PTO {pto}");
    }
  }

  // Review J8, changed by task 23c fix round 1 (ruling T23c-a): the record of a lost packet keeps
  // no frames, so an ACK of it that comes late, before its control frames went again, does not
  // cancel the copies owed: HANDSHAKE_DONE, MAX_DATA and MAX_STREAM_DATA with the current limits go
  // once more, and the ACK of that copy ends them.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn late_ack_of_a_lost_control_frame_leaves_one_copy_owed() {
    // The copies owed go, the client acknowledges them, and nothing is owed afterwards
    fn copies_go_once(link: &mut Link) {
      let _ = link.server.flush(link.now_us);
      assert!(link.deliver_to_client() > 0);
      let _ = link.client.flush(link.now_us);
      assert!(link.deliver_to_server() > 0);
      let _ = link.server.flush(link.now_us);
      assert!(link.server.take_datagrams().is_empty());
      assert_eq!(link.server.conn.state(), ConnState::Confirmed);
    }
    // No path MTU probes, whose PINGs would be acknowledged
    let mut opts = LinkOpts::new(None);
    opts.client.max_udp_payload_size = 1200;
    opts.server.max_udp_payload_size = 1200;
    let mut link = Link::new(&opts);
    while link.server.conn.state() != ConnState::Confirmed {
      let _ = link.server.flush(link.now_us);
      let _ = link.deliver_to_client();
      let _ = link.client.flush(link.now_us);
      assert!(link.deliver_to_server() > 0);
    }
    let _ = link.server.flush(link.now_us);
    assert!(link.deliver_to_client() > 0);
    assert_eq!(link.client.conn.state(), ConnState::Confirmed);
    let _ = link.client.flush(link.now_us);
    let mut acks = link.client.take_datagrams();
    link.server.conn.declare_in_flight_lost(&mut link.server.parts.pools);
    assert!(link.server.conn.handshake_done_owed);
    let late = link.server.conn.stats().late_acks;
    for datagram in &mut acks {
      link.server.recv(link.now_us, datagram, CLIENT_ADDR);
    }
    assert!(link.server.conn.stats().late_acks > late);
    assert!(link.server.conn.handshake_done_owed);
    copies_go_once(&mut link);
    assert!(!link.server.conn.handshake_done_owed);
    // MAX_DATA and MAX_STREAM_DATA
    let mut opts = LinkOpts::new(None);
    opts.server.stream_window = 4096;
    opts.server.conn_window = 8192;
    let mut link = settled(&opts);
    let now_us = link.now_us;
    let _ = link.client.with_ctx(now_us, |cx| {
      let id = cx.open_bidi()?;
      cx.write(id, &[1; 4096], false)
    });
    let _ = link.client.flush(link.now_us);
    assert!(link.deliver_to_server() > 0);
    let _ = link.server.flush(link.now_us);
    assert!(link.deliver_to_client() > 0);
    let _ = link.client.flush(link.now_us);
    let mut acks = link.client.take_datagrams();
    assert!(!acks.is_empty());
    link.server.conn.declare_in_flight_lost(&mut link.server.parts.pools);
    assert!(link.server.conn.streams().wants_send());
    for datagram in &mut acks {
      link.server.recv(link.now_us, datagram, CLIENT_ADDR);
    }
    assert!(link.server.conn.streams().wants_send());
    copies_go_once(&mut link);
  }

  // Task 23c fix round 1 (ruling T23c-a): a packet declared lost gives its frame references back
  // to the pool at once, its frames being owed again, so that the record that it keeps until its
  // sent ring wraps holds no chunk. An ACK of the packet that comes late finds no frames: it counts
  // as late, what was owed again goes again (a copy too many at worst), and the response arrives
  // whole.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn lost_records_hold_no_frames_and_a_late_ack_is_harmless() {
    const LEN: u32 = 60_000;
    let bytes: Vec<u8> = (0..LEN).map(|el| el as u8).collect();
    let body = BodyRef::new(crate::misc::SharedBytes::from_slice(&bytes), 0..LEN).unwrap();
    let mut opts = LinkOpts::new(None);
    opts.server_app = TestApp::new(Behavior::RespondBody(b"", body));
    let mut link = settled(&opts);
    let id = link
      .client
      .with_ctx(link.now_us, |cx| {
        let id = cx.open_bidi()?;
        cx.write(id, b"GET /", true)?;
        Ok::<_, crate::Error>(id)
      })
      .unwrap();
    let _ = link.client.flush(link.now_us);
    assert_eq!(link.deliver_to_server(), 1);
    let _ = link.server.flush(link.now_us);
    assert!(link.deliver_to_client() > 1);
    let _ = link.client.flush(link.now_us);
    let mut acks = link.client.take_datagrams();
    assert!(!acks.is_empty());
    link.server.conn.declare_in_flight_lost(&mut link.server.parts.pools);
    let sent = &link.server.conn.data.sent;
    let lost: Vec<_> = sent.records().filter(|el| el.kind == SentKind::Lost).collect();
    assert!(lost.len() > 1, "{} lost", lost.len());
    assert!(lost.iter().all(|el| el.frames == FrameRefRange::EMPTY), "{lost:?}");
    let late = link.server.conn.stats().late_acks;
    for datagram in &mut acks {
      link.server.recv(link.now_us, datagram, CLIENT_ADDR);
    }
    assert!(link.server.conn.stats().late_acks > late);
    link.run();
    assert_eq!(
      (link.server.conn.state(), link.client.conn.state()),
      (ConnState::Confirmed, ConnState::Confirmed)
    );
    let stream = &link.client.app.streams[&id.0];
    assert!(stream.fin);
    assert!(stream.data == bytes, "{} B", stream.data.len());
  }

  // Review J9: CRYPTO data that a probe sent again is not queued once more when the packets that
  // carried it first are declared lost: a server whose first flight of two datagrams is lost, and
  // whose probe carries part of it, has no more CRYPTO queued than its flight has, and then
  // completes the handshake.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn crypto_sent_again_by_a_probe_is_queued_once() {
    let mut opts = LinkOpts::new(None);
    opts.server_tp_padding = 1400;
    let mut link = Link::new(&opts);
    let _ = link.server.flush(link.now_us);
    assert_eq!(link.server.take_datagrams().len(), 2);
    let deadline = link.server.conn.next_deadline().unwrap();
    link.advance(deadline - link.now_us);
    // The probe, which the amplification limit cuts short of the flight
    let _ = link.server.flush(link.now_us);
    assert!(link.deliver_to_client() > 0);
    assert!(!link.client.conn.handshake_complete);
    let _ = link.client.flush(link.now_us);
    assert!(link.deliver_to_server() > 0);
    let conn = &link.server.conn;
    assert!(conn.stats().packets_lost > 0);
    let hs = conn.handshake.as_deref().unwrap();
    let pools = &link.server.parts.pools;
    for (space, sp) in [(Space::Initial, &hs.initial), (Space::Handshake, &hs.handshake)] {
      let queued: u64 = pools
        .frame_refs
        .queue_iter(&sp.crypto_lost)
        .map(|el| if let FrameRef::Crypto { len, .. } = el { u64::from(len) } else { 0 })
        .sum();
      let output = conn.tls.as_ref().unwrap().output(space).len() as u64;
      assert!(queued <= output, "{space:?}: {queued} queued of {output}");
    }
    link.run();
    assert_eq!(link.server.conn.state(), ConnState::Confirmed);
  }

  // Reviews J11 and J12, RFC 9001 sections 6.3, 6.5 and 9.5: the next keys that open packets are
  // made once the handshake is confirmed and once the previous ones go, never for a packet. A
  // packet of the previous phase that arrives late opens with the previous keys; a flip of the
  // peer while they are kept does not overwrite them: its packets are dropped until they go.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn previous_keys_open_late_packets_and_stay_until_their_time() {
    let mut link = settled(&LinkOpts::new(None));
    assert_eq!(link.server.conn.key.other, crate::quic::key_phase::OtherKeys::Next);
    // A packet of the client before its update, held back
    link.client.conn.queue_test_frames(&PING);
    let _ = link.client.flush(link.now_us);
    let mut late = link.client.take_datagrams();
    link.client.conn.force_key_update();
    link.client.conn.queue_test_frames(&PING);
    let _ = link.client.flush(link.now_us);
    assert_eq!(link.deliver_to_server(), 1);
    assert_eq!(link.server.conn.key_phases(), (true, true));
    assert!(link.server.conn.keeps_previous_keys());
    let before = *link.server.conn.stats();
    link.server.recv(link.now_us, &mut late[0], CLIENT_ADDR);
    let after = *link.server.conn.stats();
    assert_eq!((after.packets_in, after.packets_dropped), (before.packets_in + 1, 0));
    // Another update of the client within the three PTOs
    link.client.conn.force_key_update();
    link.client.conn.queue_test_frames(&PING);
    let _ = link.client.flush(link.now_us);
    assert_eq!(link.deliver_to_server(), 1);
    assert_eq!(link.server.conn.stats().packets_dropped, 1);
    assert_eq!(link.server.conn.key_phases(), (true, true));
    assert!(link.server.conn.keeps_previous_keys());
    // Once the previous keys go, the next ones are made and the packets of the client open
    let pto = link.server.conn.current_pto_us();
    link.advance(3 * pto + 1);
    assert_eq!(link.server.conn.key.other, crate::quic::key_phase::OtherKeys::Next);
    link.client.conn.queue_test_frames(&PING);
    link.run();
    assert_eq!(link.server.conn.key_phases(), (false, false));
    assert_eq!(link.server.conn.state(), ConnState::Confirmed);
  }

  // Requests of 3000 bytes that the server echoes, over a link with 5 ms of delay that reorders
  // `reorder` of the datagrams
  fn echo_run(opts: &mut LinkOpts, reorder: f32, count: usize) -> Link {
    opts.server_app = TestApp::new(Behavior::Echo);
    let mut link = Link::new(opts);
    link.impair(Impairment { reorder, ..Impairment::delay(5_000) });
    let requests: Vec<Vec<u8>> = (0..count).map(|nth| vec![nth as u8; 3000]).collect();
    let run = run_lossy_requests(&mut link, &requests, 16, 60_000_000);
    assert_eq!(run.responses, requests);
    link
  }

  // Review focus 5: the client updates its keys in the middle of a transfer, again and again. The
  // server follows each flip of the key phase (RFC 9001 section 6), answers with new keys of its
  // own, keeps serving, opens the packets of the old phase that arrive late, and lets the old keys
  // go three PTOs later.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn peer_key_update_mid_transfer() {
    let mut opts = LinkOpts::new(None);
    opts.client.key_update_threshold = 150;
    let mut link = echo_run(&mut opts, 0.1, 200);
    let (client, server) = (*link.client.conn.stats(), *link.server.conn.stats());
    assert!(client.key_updates >= 3, "{client:?}");
    // The server started none: each of its updates followed one of the client
    assert_eq!(server.key_updates, client.key_updates);
    assert_eq!(link.server.conn.key_phases(), link.client.conn.key_phases());
    // Nothing was dropped for want of keys, the packets of the previous phase included
    assert_eq!((server.packets_dropped, client.packets_dropped), (0, 0));
    // The previous keys go three PTOs after a flip; then one more update of the client, which the
    // server follows and whose previous keys it keeps three PTOs again
    let pto = link.server.conn.current_pto_us();
    link.advance(3 * pto + 1);
    assert!(!link.server.conn.keeps_previous_keys());
    link.client.conn.force_key_update();
    link.client.conn.queue_test_frames(&PING);
    link.run();
    assert!(link.server.conn.keeps_previous_keys());
    assert_eq!(link.server.conn.key_phases(), link.client.conn.key_phases());
    assert_eq!(link.server.conn.stats().key_updates, server.key_updates + 1);
    let pto = link.server.conn.current_pto_us();
    link.advance(3 * pto + 1);
    assert!(!link.server.conn.keeps_previous_keys());
    assert_eq!(link.server.conn.state(), ConnState::Confirmed);
    // And it goes on
    link.client.conn.queue_test_frames(&PING);
    link.run();
    assert_eq!(link.server.conn.stats().packets_dropped, 0);
  }

  // The server updates its keys once a key sealed as many packets as its threshold allows, but
  // never before the handshake is confirmed or before a packet sent with the current keys was
  // acknowledged; the client follows. AES-GCM keys update before the 2^23 packets of their
  // confidentiality limit, ChaCha20 ones need not.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn local_key_update_at_threshold() {
    use crate::tls::CipherSuite;
    assert_eq!(
      crate::quic::key_phase::key_update_threshold(CipherSuite::Aes128GcmSha256, u64::MAX),
      1 << 22
    );
    assert_eq!(
      crate::quic::key_phase::key_update_threshold(CipherSuite::Aes256GcmSha384, u64::MAX),
      1 << 22
    );
    assert_eq!(
      crate::quic::key_phase::key_update_threshold(CipherSuite::Chacha20Poly1305Sha256, u64::MAX),
      u64::MAX
    );
    assert_eq!(crate::quic::key_phase::key_update_threshold(CipherSuite::Aes128GcmSha256, 64), 64);
    // A threshold of one packet: an update as soon as the rules allow, once per round trip
    let mut opts = LinkOpts::new(None);
    opts.server.key_update_threshold = 1;
    opts.server.limits.ping_budget = 100_000;
    opts.client.limits.ping_budget = 100_000;
    let mut link = Link::new(&opts);
    link.impair(Impairment::delay(5_000));
    while link.server.conn.state() != ConnState::Confirmed {
      assert_eq!(link.server.conn.key_phases(), (false, false));
      if !link.step_impaired() {
        assert!(link.advance_to_next_event());
      }
    }
    let start = link.now_us;
    for _ in 0..200 {
      link.server.conn.queue_test_frames(&PING);
      link.client.conn.queue_test_frames(&PING);
      for _ in 0..4 {
        if !link.step_impaired() {
          assert!(link.advance_to_next_event());
        }
      }
    }
    let rounds = (link.now_us - start) / 10_000 + 1;
    let server = *link.server.conn.stats();
    assert!(server.key_updates >= 3 && server.key_updates <= rounds, "{server:?} in {rounds}");
    // A threshold of 64 packets, with traffic
    let mut opts = LinkOpts::new(None);
    opts.server.key_update_threshold = 64;
    let link = echo_run(&mut opts, 0.0, 600);
    let (client, server) = (*link.client.conn.stats(), *link.server.conn.stats());
    assert!(server.key_updates >= 3, "{server:?}");
    assert!(server.key_updates <= server.packets_out / 64, "{server:?}");
    assert_eq!(client.key_updates, server.key_updates);
    assert_eq!(link.server.conn.key_phases(), link.client.conn.key_phases());
    assert_eq!((server.packets_dropped, client.packets_dropped), (0, 0));
  }

  // The bytes in flight of the records that congestion control counts, over the spaces that are
  // left
  fn in_flight_of_records<const IS_CLIENT: bool, TCX>(
    conn: &crate::quic::QuicConn<TestApp, crate::rng::ChaCha20, TCX, IS_CLIENT>,
  ) -> u64 {
    let mut rslt = 0;
    for space in super::SPACES {
      if let Some(sp) = super::space_ref(&conn.data, &conn.handshake, space) {
        let sizes = sp.sent.records().filter(|el| el.counts_for_congestion()).map(|el| el.size);
        rslt += sizes.map(u64::from).sum::<u64>();
      }
    }
    rslt
  }

  // Carried rules 1 and 2: a lost first flight of the server is probed after a PTO of the initial
  // RTT without the max_ack_delay of the peer, with its CRYPTO data again in Initial and
  // Handshake packets coalesced in a datagram padded to 1200 bytes, which completes the handshake.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn server_initial_pto_probe_is_padded_without_ack_delay() {
    let mut link = Link::new(&LinkOpts::new(None));
    let _ = link.server.flush(link.now_us);
    assert_eq!(link.server.take_datagrams().len(), 1);
    let deadline = link.server.conn.next_deadline().unwrap();
    assert_eq!(deadline - link.now_us, 333_000 + 4 * 166_500);
    link.advance(deadline - link.now_us);
    assert_eq!(link.server.conn.pto_count(), 1);
    let _ = link.server.flush(link.now_us);
    let probes = link.server.take_datagrams();
    let types = packet_types(&probes[0]);
    assert!(
      types.contains(&PacketTy::Initial) && types.contains(&PacketTy::Handshake),
      "{types:?}"
    );
    assert!(probes.iter().all(|el| el.len() >= 1200), "{:?}", probes.iter().map(Vec::len));
    for mut datagram in probes {
      link.client.recv(link.now_us, &mut datagram, SERVER_ADDR);
    }
    link.run();
    assert_eq!(link.server.conn.state(), ConnState::Confirmed);
    assert_eq!(link.client.conn.state(), ConnState::Confirmed);
    assert_eq!(link.server.conn.stats().pto_probes, 1);
  }

  // Carried rule 2: a server that the amplification limit holds has no probe timeout armed, until
  // more of the client arrives and it can send again.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn amplification_limited_server_arms_no_pto() {
    let mut opts = LinkOpts::new(None);
    opts.server_tp_padding = 6000;
    let mut link = Link::new(&opts);
    let _ = link.server.flush(link.now_us);
    let flight = link.server.take_datagrams();
    assert_eq!(flight.iter().map(Vec::len).sum::<usize>(), 3 * 1200);
    assert_eq!(link.server.conn.recovery.loss_timer_us, None);
    assert_eq!(link.server.conn.next_deadline(), link.server.conn.idle_deadline());
    for mut datagram in flight {
      link.client.recv(link.now_us, &mut datagram, SERVER_ADDR);
    }
    let _ = link.client.flush(link.now_us);
    assert!(link.deliver_to_server() > 0);
    let _ = link.server.flush(link.now_us);
    assert!(link.server.conn.handshake.as_deref().unwrap().handshake.ack_eliciting_in_flight > 0);
    assert!(link.server.conn.recovery.loss_timer_us.is_some());
  }

  // Carried rule 2: discarded Initial and Handshake keys take their packets out of the bytes in
  // flight, which match the records left at every step of a lossy handshake and transfer.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn bytes_in_flight_match_the_records_through_discards() {
    let mut opts = LinkOpts::new(None);
    opts.server_app = TestApp::new(Behavior::Echo);
    let mut link = Link::new(&opts);
    link.impair(Impairment { drop: 0.2, ..Impairment::delay(2_000) });
    let mut discarded = false;
    for _ in 0..4000 {
      if !link.step_impaired() {
        assert!(link.advance_to_next_event());
      }
      assert_eq!(link.server.conn.bytes_in_flight(), in_flight_of_records(&link.server.conn));
      assert_eq!(link.client.conn.bytes_in_flight(), in_flight_of_records(&link.client.conn));
      discarded |= link.server.conn.handshake.is_none();
      if discarded && link.client.conn.state() == ConnState::Confirmed {
        let now_us = link.now_us;
        let _ = link.client.with_ctx(now_us, |cx| {
          let id = cx.open_bidi()?;
          cx.write(id, &[7; 3000], true)
        });
      }
    }
    assert!(discarded);
    assert!(link.server.app.fins > 10, "{}", link.server.app.fins);
  }

  // Carried rule 4: an ACK frame cut to its first range for want of room leaves the other ranges
  // owed, and the next flush reports them.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn first_range_only_ack_leaves_the_rest_owed() {
    let mut link = settled(&LinkOpts::new(None));
    for _ in 0..6 {
      // A packet number skipped before each one: separate ranges
      link.client.conn.data.sent.skip();
      link.client.conn.queue_test_frames(&PING);
      let _ = link.client.flush(link.now_us);
      assert_eq!(link.deliver_to_server(), 1);
    }
    let ranges = server_data_ranges(&link);
    assert!(ranges.len() >= 6, "{ranges:?}");
    fill_descriptors(&mut link.server.parts.tx, 38);
    assert_eq!(link.server.flush(link.now_us), FlushOutcome::ArenaFull);
    let partial = link.server.take_datagrams().last().map_or(0, Vec::len);
    assert!(link.server.conn.data.recv.ack_pending());
    assert_eq!(server_data_ranges(&link), ranges);
    assert_eq!(link.server.flush(link.now_us), FlushOutcome::Done);
    let mut full = link.server.take_datagrams();
    assert_eq!(full.len(), 1);
    // The second one has every range
    assert!(partial <= 38 && full[0].len() > partial + 6, "{partial} {}", full[0].len());
    assert!(!link.server.conn.data.recv.ack_pending());
    link.client.recv(link.now_us, &mut full[0], SERVER_ADDR);
    assert_eq!(link.client.conn.state(), ConnState::Confirmed);
  }

  // Carried rule 5: the frames of lost packets go again: HANDSHAKE_DONE, RESET_STREAM and
  // STOP_SENDING while their stream needs them, MAX_STREAM_DATA and MAX_DATA with the current
  // limits even when they did not move.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn lost_control_frames_are_sent_again() {
    // HANDSHAKE_DONE
    let mut link = Link::new(&LinkOpts::new(None));
    while link.server.conn.state() != ConnState::Confirmed {
      let _ = link.server.flush(link.now_us);
      let _ = link.deliver_to_client();
      let _ = link.client.flush(link.now_us);
      assert!(link.deliver_to_server() > 0);
    }
    let _ = link.server.flush(link.now_us);
    assert!(!link.server.take_datagrams().is_empty() && !link.server.conn.handshake_done_owed);
    link.server.conn.declare_in_flight_lost(&mut link.server.parts.pools);
    assert!(link.server.conn.handshake_done_owed);
    link.run();
    assert_eq!(link.client.conn.state(), ConnState::Confirmed);
    // RESET_STREAM and STOP_SENDING
    let mut link = settled(&LinkOpts::new(None));
    let now_us = link.now_us;
    let id = link
      .client
      .with_ctx(now_us, |cx| {
        let id = cx.open_bidi()?;
        cx.write(id, b"abc", false)?;
        Ok::<_, crate::Error>(id)
      })
      .unwrap();
    link.run();
    link.server.with_ctx(now_us, |cx| {
      cx.write(id, b"partial", false).unwrap();
      cx.reset(id, 0x11);
      cx.stop_sending(id, 0x12);
    });
    let _ = link.server.flush(link.now_us);
    assert_eq!(link.server.take_datagrams().len(), 1);
    link.server.conn.declare_in_flight_lost(&mut link.server.parts.pools);
    link.run();
    assert_eq!(link.client.app.resets, [(id, 0x11)]);
    assert_eq!(link.client.app.stops, [(id, 0x12)]);
    // MAX_STREAM_DATA and MAX_DATA
    let mut opts = LinkOpts::new(None);
    opts.server.stream_window = 4096;
    opts.server.conn_window = 8192;
    let mut link = settled(&opts);
    let now_us = link.now_us;
    let id = link
      .client
      .with_ctx(now_us, |cx| {
        let id = cx.open_bidi()?;
        cx.write(id, &[1; 4096], false)?;
        Ok::<_, crate::Error>(id)
      })
      .unwrap();
    let _ = link.client.flush(link.now_us);
    assert!(link.deliver_to_server() > 0);
    let _ = link.server.flush(link.now_us);
    assert!(!link.server.take_datagrams().is_empty());
    let (server_max, ..) = link.server.conn.streams().conn_credit();
    assert!(server_max > 8192);
    link.server.conn.declare_in_flight_lost(&mut link.server.parts.pools);
    let _ = link.server.flush(link.now_us);
    assert!(link.deliver_to_client() > 0);
    let pools = &link.client.parts.pools;
    assert_eq!(link.client.conn.streams().send_credit(&pools.stream_slots, id), Some(4096 + 4096));
    assert_eq!(link.client.conn.streams().conn_credit().2, server_max);
  }

  // NEW_CONNECTION_ID frames of the client in one packet, which the server receives.
  fn client_new_cids(link: &mut Link, frames: &[(u64, u64, [u8; 8], [u8; 16])]) {
    let frames: Vec<_> = frames
      .iter()
      .map(|(seq, retire_prior_to, cid, reset_token)| Frame::NewConnectionId {
        seq: *seq,
        retire_prior_to: *retire_prior_to,
        cid,
        reset_token,
      })
      .collect();
    link.client.conn.queue_test_frames(&encode_frames(&frames));
    let _ = link.client.flush(link.now_us);
    assert_eq!(link.deliver_to_server(), 1);
  }

  // Ruling T10-d: the server keeps the CIDs that the client gives, up to the
  // active_connection_id_limit of 2 that it sent; one more is a CONNECTION_ID_LIMIT_ERROR, and a
  // repeat changes nothing.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn peer_cids_are_kept_up_to_the_limit() {
    let mut link = settled(&LinkOpts::new(None));
    client_new_cids(&mut link, &[(1, 0, [0xa1; 8], [1; 16])]);
    assert_eq!(link.server.conn.state(), ConnState::Confirmed);
    client_new_cids(&mut link, &[(1, 0, [0xa1; 8], [1; 16])]);
    assert_eq!(link.server.conn.state(), ConnState::Confirmed);
    client_new_cids(&mut link, &[(2, 0, [0xa2; 8], [2; 16])]);
    assert_eq!(server_close_code(&link), Some(TransportErrorCode::ConnectionIdLimitError.code()));
  }

  // Ruling T10-d: a Retire Prior To that retires the CID in use moves the server to another one,
  // and the server owes a RETIRE_CONNECTION_ID for each retired one, again if it is lost.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn retire_prior_to_moves_to_another_cid_and_retires() {
    let mut link = settled(&LinkOpts::new(None));
    client_new_cids(&mut link, &[(1, 1, [0xa1; 8], [1; 16]), (2, 2, [0xa2; 8], [2; 16])]);
    let server = &link.server.conn;
    assert_eq!(server.state(), ConnState::Confirmed);
    assert_eq!(server.peer_cid, Cid::new(&[0xa2; 8]).unwrap());
    let cold = server.cold.as_deref().unwrap();
    assert_eq!((cold.retire_next, cold.retire_prior_to, cold.peer_cid_seq), (0, 2, 2));
    // The client takes the packets to its new CID
    link.client.conn.local_cid = Cid::new(&[0xa2; 8]).unwrap();
    let _ = link.server.flush(link.now_us);
    let datagrams = link.server.take_datagrams();
    assert!(!datagrams.is_empty());
    assert!(datagrams.iter().all(|el| el[1..9] == [0xa2; 8]));
    assert_eq!(link.server.conn.cold.as_deref().unwrap().retire_next, 2);
    // Lost: owed again
    link.server.conn.declare_in_flight_lost(&mut link.server.parts.pools);
    assert_eq!(link.server.conn.cold.as_deref().unwrap().retire_next, 0);
    let _ = link.server.flush(link.now_us);
    assert_eq!(link.server.conn.cold.as_deref().unwrap().retire_next, 2);
    // A CID that is retired already when it arrives is not kept: its retirement is owed
    client_new_cids(&mut link, &[(3, 3, [0xa3; 8], [3; 16]), (1, 0, [0xa1; 8], [1; 16])]);
    let cold = link.server.conn.cold.as_deref().unwrap();
    assert_eq!((cold.retire_next, cold.retire_prior_to), (2, 3));
    assert!(cold.peer_cids.iter().flatten().all(|el| el.seq == 3));
  }

  // Ruling T10-d: the CIDs of a client that sends none, a repeat that differs, a CID with two
  // sequence numbers, the retirement of the CID of the server or of one never given and too many
  // retirements owed are connection errors.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn connection_id_frames_that_break_the_rules_are_errors() {
    let violation = Some(TransportErrorCode::ProtocolViolation.code());
    let cases: [(&[(u64, u64, [u8; 8], [u8; 16])], Option<u64>); 3] = [
      (&[(1, 0, [0xa1; 8], [1; 16]), (1, 0, [0xa1; 8], [9; 16])], violation),
      (&[(1, 0, [0xa1; 8], [1; 16]), (2, 1, [0xa1; 8], [2; 16])], violation),
      (&[(20, 20, [0xa1; 8], [1; 16])], Some(TransportErrorCode::ConnectionIdLimitError.code())),
    ];
    for (frames, code) in cases {
      let mut link = settled(&LinkOpts::new(None));
      client_new_cids(&mut link, frames);
      assert_eq!(server_close_code(&link), code, "{frames:?}");
    }
    let mut link = settled(&LinkOpts::new(None));
    link.server.conn.peer_cid = Cid::default();
    client_new_cids(&mut link, &[(1, 0, [0xa1; 8], [1; 16])]);
    assert_eq!(server_close_code(&link), violation);
    for seq in [0, 1, 5] {
      let mut link = settled(&LinkOpts::new(None));
      link.client.conn.queue_test_frames(&encode_frames(&[Frame::RetireConnectionId(seq)]));
      let _ = link.client.flush(link.now_us);
      assert_eq!(link.deliver_to_server(), 1);
      assert_eq!(server_close_code(&link), violation, "{seq}");
    }
  }

  // Ruling T10-d (RFC 9000 section 10.3.1): a datagram that does not open and ends with the reset
  // token of a CID of the client is a stateless reset: the connection drains, silently.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn stateless_reset_of_the_peer_drains() {
    let mut link = settled(&LinkOpts::new(None));
    client_new_cids(&mut link, &[(1, 0, [0xa1; 8], [7; 16])]);
    let mut datagram = vec![0x45u8; 60];
    datagram[1..9].copy_from_slice(link.server.conn.local_cid.as_slice());
    // Not a token of the client: dropped
    link.server.recv(link.now_us, &mut datagram.clone(), CLIENT_ADDR);
    assert_eq!(link.server.conn.state(), ConnState::Confirmed);
    datagram[44..].copy_from_slice(&[7; 16]);
    link.server.recv(link.now_us, &mut datagram, CLIENT_ADDR);
    assert_eq!(link.server.conn.state(), ConnState::Draining);
    let _ = link.server.flush(link.now_us);
    assert!(link.server.take_datagrams().is_empty());
  }

  // Ruling T18-b: with batched header protection the 1-RTT packets of a flush are protected in
  // batches of up to eight, before the flush returns, and the client opens every one of them: a
  // response of many packets arrives whole, with no packet dropped. ChaCha20, or a CPU without
  // AES-NI, protects one packet at a time whatever the setting, and so does the default.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn batched_header_protection_packets_open_at_the_peer() {
    const RESPONSE: &[u8; 40_000] = &[b'h'; 40_000];
    let suites = [
      CipherSuite::Aes128GcmSha256,
      CipherSuite::Aes256GcmSha384,
      CipherSuite::Chacha20Poly1305Sha256,
    ];
    for suite in suites {
      for batched in [false, true] {
        let mut opts = LinkOpts::new(Some(suite));
        opts.server.batched_hp = batched;
        opts.server_app = TestApp::new(Behavior::Respond(RESPONSE));
        let mut link = settled(&opts);
        let now_us = link.now_us;
        let id = link
          .client
          .with_ctx(now_us, |cx| {
            let id = cx.open_bidi()?;
            cx.write(id, b"GET /", true)?;
            Ok::<_, crate::Error>(id)
          })
          .unwrap();
        let _ = link.client.flush(link.now_us);
        assert_eq!(link.deliver_to_server(), 1);
        let _ = link.server.flush(link.now_us);
        // Nothing waits once the flush returned
        assert_eq!(link.server.parts.pools.hp_batch.len(), 0);
        assert!(link.deliver_to_client() >= 9, "{suite:?}: the first flush sends a window");
        link.run();
        let log = link.client.app.streams.get(&id.0).unwrap();
        assert!(log.fin, "{suite:?} batched {batched}");
        assert_eq!(log.data.as_slice(), RESPONSE.as_slice(), "{suite:?} batched {batched}");
        assert_eq!(link.client.conn.stats().packets_dropped, 0, "{suite:?} batched {batched}");
        let batch = &link.server.parts.pools.hp_batch;
        let batches = batched
          && suite != CipherSuite::Chacha20Poly1305Sha256
          && crate::quic::crypto::has_aes_ni();
        if batches {
          assert!(batch.masked >= 30, "{suite:?}: {} packets masked in batches", batch.masked);
          assert_eq!(batch.largest, crate::quic::crypto::HP_BATCH_LEN, "{suite:?}");
        } else {
          assert_eq!(batch.masked, 0, "{suite:?} batched {batched}");
        }
      }
    }
  }

  // Ruling T18-b: without AES-NI the batched setting falls back to the header protection of the
  // backend, which computes the same masks one at a time.
  #[test]
  fn batched_header_protection_falls_back_without_aes_ni() {
    use crate::quic::crypto::QuicHp;
    let key = [0x42; 32];
    for suite in [CipherSuite::Aes128GcmSha256, CipherSuite::Aes256GcmSha384] {
      let key = &key[..usize::from(suite.cipher_key_len())];
      let fallback = QuicHp::with_batches(suite, key, true, false).unwrap();
      assert!(!fallback.batches());
      let samples: Vec<[u8; 16]> = (0..20u8).map(|el| [el; 16]).collect();
      let mut lhs = vec![[0; 5]; 20];
      fallback.masks(&samples, &mut lhs).unwrap();
      if crate::quic::crypto::has_aes_ni() {
        let batched = QuicHp::with_batches(suite, key, true, true).unwrap();
        assert!(batched.batches());
        let mut rhs = vec![[0; 5]; 20];
        batched.masks(&samples, &mut rhs).unwrap();
        assert_eq!(lhs, rhs, "{suite:?}");
      }
      assert_ne!(lhs[0], lhs[1]);
    }
    let chacha = QuicHp::with_batches(CipherSuite::Chacha20Poly1305Sha256, &key, true, true);
    assert!(!chacha.unwrap().batches());
    assert!(!QuicHp::new(CipherSuite::Aes128GcmSha256, &key[..16]).unwrap().batches());
  }

  // Ruling T19-d: a response that leaves over several flushes carries the acknowledgment of its
  // request again in the flushes after the first while the client may not have it: here the
  // datagram that carried it is lost, and the client, which closes a stream only once its request
  // is acknowledged (spec section 2.1), would wait for its own probe timeout. Once the client
  // acknowledged a packet with that acknowledgment, no flush repeats it.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn response_flushes_repeat_an_acknowledgment_the_client_may_lack() {
    let body = crate::misc::SharedBytes::from_slice(&[7; 30_000]);
    for repeat in [false, true] {
      let mut opts = LinkOpts::new(None);
      opts.server.repeat_ack = repeat;
      // A few datagrams in flight at a time: the response takes several flushes
      opts.server.max_in_flight = 6 * 1472;
      let response = BodyRef::new(body.clone(), 0..30_000).unwrap();
      opts.server_app = TestApp::new(Behavior::RespondBody(b"", response));
      let mut link = settled(&opts);
      let now_us = link.now_us;
      let id = link
        .client
        .with_ctx(now_us, |cx| {
          let id = cx.open_bidi()?;
          cx.write(id, b"GET /", true)?;
          Ok::<_, crate::Error>(id)
        })
        .unwrap();
      let _ = link.client.flush(link.now_us);
      assert_eq!(link.deliver_to_server(), 1);
      let before = *link.server.conn.stats();
      let _ = link.server.flush(link.now_us);
      let mut datagrams = link.server.take_datagrams();
      assert!(datagrams.len() >= 3, "{}", datagrams.len());
      // The first datagram, with the acknowledgment of the request, is lost
      for datagram in datagrams.iter_mut().skip(1) {
        link.client.recv(link.now_us, datagram, SERVER_ADDR);
      }
      assert!(link.client.conn.data.ack_eliciting_in_flight > 0);
      let mut rounds = 0;
      while !link.client.app.streams.get(&id.0).is_some_and(|el| el.fin) {
        rounds += 1;
        assert!(rounds < 50, "the response did not finish");
        let _ = link.client.flush(link.now_us);
        let _ = link.deliver_to_server();
        let _ = link.server.flush(link.now_us);
        let _ = link.deliver_to_client();
        link.advance(1_000);
      }
      let after = *link.server.conn.stats();
      let (flushes, acked) = (
        after.fin_flushes - before.fin_flushes,
        after.fin_flushes_acked - before.fin_flushes_acked,
      );
      let owed = after.fin_flushes_ack_owed - before.fin_flushes_ack_owed;
      let owed_acked = after.fin_flushes_owed_and_acked - before.fin_flushes_owed_and_acked;
      assert_eq!(flushes, 1, "repeat {repeat}");
      assert_eq!(owed_acked, if repeat { owed } else { 0 }, "repeat {repeat}");
      // The flush that finished the response owed the acknowledgment and did not carry it, or
      // carried every one it owed: the first flush after the loss repeated it, and the client
      // may have confirmed it before the last one
      if repeat {
        assert_eq!(acked, owed);
      } else {
        assert_eq!((owed, acked), (1, 0));
      }
      // The client has the acknowledgment of its request with the response, or still waits
      let waits = link.client.conn.data.ack_eliciting_in_flight > 0;
      assert_eq!(waits, !repeat, "repeat {repeat}");
      // Acknowledged by the client, the acknowledgment is not repeated
      let _ = link.client.flush(link.now_us);
      let _ = link.deliver_to_server();
      if repeat {
        assert!(!link.server.conn.data.recv.ack_unconfirmed());
      }
    }
  }

  // Ruling T19-a (review): a pacer hold counts a flush that stopped with ack-eliciting data held
  // back, not one that had only an acknowledgment to send, which the pacer never holds.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn pacer_holds_count_only_data_held_back() {
    const SMALL: &[u8] = &[1; 100];
    let body = crate::misc::SharedBytes::from_slice(&[2; 4000]);
    let mut opts = LinkOpts::new(None);
    opts.server.pacing_burst = 1;
    let body = BodyRef::new(body, 0..4000).unwrap();
    opts.server_app = TestApp::new(Behavior::Mixed { small: SMALL, body, large: SMALL });
    let mut link = settled(&opts);
    // A smoothed RTT that paces (the fake clock gives none) and a clock that stands still
    link.server.conn.recovery.rtt.smoothed_us = 10_000;
    let holds = |link: &Link| link.server.conn.stats().pacer_holds;
    let request = |link: &mut Link| {
      let now_us = link.now_us;
      let _id = link
        .client
        .with_ctx(now_us, |cx| {
          let id = cx.open_bidi()?;
          cx.write(id, b"GET /", true)
        })
        .unwrap();
      let _ = link.client.flush(link.now_us);
      assert_eq!(link.deliver_to_server(), 1);
      let _ = link.server.flush(link.now_us);
      link.server.take_datagrams().len()
    };
    // One datagram of response: the bucket of one datagram is spent, nothing waits
    assert_eq!(request(&mut link), 1);
    assert_eq!(holds(&link), 0);
    // A PING to acknowledge: the ACK goes alone, which the pacer does not hold
    link.client.conn.queue_test_frames(&PING);
    let _ = link.client.flush(link.now_us);
    assert_eq!(link.deliver_to_server(), 1);
    let _ = link.server.flush(link.now_us);
    assert_eq!(link.server.take_datagrams().len(), 1);
    assert_eq!(holds(&link), 0);
    // A body of three datagrams, held back at once (the ACK of its request goes alone): one flush
    // that stops
    let _ = request(&mut link);
    assert_eq!(holds(&link), 1);
  }

  // Ruling T19-d (review): the repeated acknowledgment stays only in a packet that carries an
  // ack-eliciting frame. Here the streams want to send a STREAM frame lost after its stream went
  // (which writes nothing) while the acknowledgment of a PING is unconfirmed: no packet goes, where
  // one with the repeated ACK alone would be an ACK-only packet that answers nothing new.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn a_repeated_acknowledgment_never_goes_alone() {
    let mut link = settled(&LinkOpts::new(None));
    link.client.conn.queue_test_frames(&PING);
    let _ = link.client.flush(link.now_us);
    assert_eq!(link.deliver_to_server(), 1);
    // The acknowledgment of the PING goes, and is lost
    let _ = link.server.flush(link.now_us);
    assert_eq!(link.server.take_datagrams().len(), 1);
    assert!(!link.server.conn.data.recv.ack_pending());
    assert!(link.server.conn.data.recv.ack_unconfirmed());
    let pools = &mut link.server.parts.pools;
    link.server.conn.streams.queue_stale_lost(pools).unwrap();
    assert!(link.server.conn.streams.wants_send());
    let before = *link.server.conn.stats();
    let _ = link.server.flush(link.now_us);
    let after = *link.server.conn.stats();
    assert_eq!(after.ack_only_out, before.ack_only_out, "{after:?}");
    assert_eq!(after.packets_out, before.packets_out, "{after:?}");
    assert!(link.server.take_datagrams().is_empty());
    // The stale entry is gone, and the acknowledgment is still unconfirmed for the next response
    assert!(!link.server.conn.streams.wants_send());
    assert!(link.server.conn.data.recv.ack_unconfirmed());
  }
}
