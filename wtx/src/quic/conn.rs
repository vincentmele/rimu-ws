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
//! CRYPTO data. An ACK-only packet is never acknowledged on its own: only ack-eliciting packets
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

use crate::{
  crypto::AEAD_TAG_LEN,
  quic::{
    AckFrame, Cid, DatagramMeta, Frame, FrameReader, FrameWriter, PacketKeys, PacketTy, QUIC_V1,
    QuicError, Space, TransportErrorCode, TransportParams, TxArena, initial_keys, keys_from_secret,
    limits::{QuicLimits, RateBudget},
    open_payload, parse_header, pn_len_for,
    pools::{CRYPTO_BUFFER_LEN, CryptoBuffer, QuicPools},
    protect,
    recv_tracker::RecvTracker,
    remove_header_protection,
    sent::{FrameRef, FrameRefRange, SentPacket, SentRing},
    varint::varint_len,
    writer::Writer,
  },
  rng::CryptoRng,
  tls::{AlertDescription, QuicTls, TlsCtxSk},
};
use alloc::boxed::Box;
use core::{
  fmt::{Debug, Formatter},
  hint::cold_path,
  net::{IpAddr, SocketAddr},
};

// RFC 9000 section 8.1
const AMPLIFICATION_FACTOR: u64 = 3;
// RFC 9002 section 6.1.2
const GRANULARITY_US: u64 = 1_000;
// The datagram size until path MTU discovery finds a larger one
const INITIAL_MAX_DATAGRAM: usize = 1200;
// RFC 9002 section 6.2.2
const INITIAL_RTT_US: u64 = 333_000;
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
const SHORT_RESERVED_BITS: u8 = 0x18;
const SPACES: [Space; 3] = [Space::Initial, Space::Handshake, Space::Data];

/// What a connection tells the application. The stream callbacks come with the streams.
pub(crate) trait QuicApp {
  /// The state that the application keeps for each connection.
  type ConnState: Default;

  /// The handshake is complete: the connection can carry application data. An error closes the
  /// connection.
  fn on_established(&mut self, state: &mut Self::ConnState) -> crate::Result<()>;

  /// The connection is over, whatever the reason: its state is not used anymore.
  fn on_closed(&mut self, state: &mut Self::ConnState);
}

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
  /// The bidirectional streams that the peer can open.
  pub(crate) max_streams_bidi: u64,
  /// The unidirectional streams that the peer can open.
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
  #[allow(dead_code, reason = "read by the pacer")]
  pub(crate) pacing: bool,
  /// The most bytes in flight.
  #[allow(dead_code, reason = "read by congestion control")]
  pub(crate) max_in_flight: usize,
  /// Abuse limits.
  pub(crate) limits: QuicLimits,
}

impl ConnParams {
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
      initial_max_data: self.conn_window,
      initial_max_stream_data_bidi_local: self.stream_window,
      initial_max_stream_data_bidi_remote: self.stream_window,
      initial_max_stream_data_uni: self.stream_window,
      initial_max_streams_bidi: self.max_streams_bidi,
      initial_max_streams_uni: self.max_streams_uni,
      ack_delay_exponent: self.ack_delay_exponent,
      max_ack_delay_ms: self.max_ack_delay_ms,
      disable_active_migration: false,
      active_connection_id_limit: 2,
      initial_source_connection_id: Some(local_cid),
      retry_source_connection_id: None,
    }
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
      max_in_flight: 256 << 10,
      limits: QuicLimits::default(),
    }
  }
}

/// Counters of a connection.
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
  close_owed: bool,
  // In the closing state: datagrams received since the last CONNECTION_CLOSE, and how many make
  // the next one, which doubles each time
  closing_datagrams: u32,
  closing_threshold: u32,
  handshake_complete: bool,
  handshake_done_owed: bool,
  has_peer_params: bool,
  idle_restart_on_send: bool,
  last_activity_us: u64,
  local: Option<IpAddr>,
  local_cid: Cid,
  max_datagram: usize,
  original_dcid: Cid,
  params: ConnParams,
  path_challenges: RateBudget,
  path_response: Option<[u8; 8]>,
  peer: SocketAddr,
  peer_cid: Cid,
  peer_cid_known: bool,
  peer_idle_timeout_ms: u64,
  peer_max_ack_delay_ms: u64,
  pings: RateBudget,
  // The 1-RTT space
  data: PacketSpace,
  // The Initial and Handshake spaces, from the worker's pool until the handshake is confirmed
  handshake: Option<Box<HandshakeSpaces>>,
  state: ConnState,
  stats: ConnStats,
  tls: Option<QuicTls<IS_CLIENT, RNG, TCX>>,
  // Raw frames for the next 1-RTT packet
  #[cfg(test)]
  test_frames: alloc::vec::Vec<u8>,
}

impl<A, RNG, TCX> QuicConn<A, RNG, TCX, false>
where
  A: QuicApp,
  RNG: CryptoRng,
  TCX: TlsCtxSk,
{
  /// The connection that the first Initial packet of a client opens, which `meta` came with and
  /// whose destination CID is `client_dcid`. `tls` sends the transport parameters of
  /// [`ConnParams::transport_params`] with `local_cid` and `client_dcid`. The state of the
  /// handshake comes from `pools`. The datagram is then given to [`Self::recv_datagram`].
  #[inline]
  pub(crate) fn new_server(
    params: &ConnParams,
    local_cid: Cid,
    client_dcid: &[u8],
    meta: DatagramMeta,
    tls: QuicTls<false, RNG, TCX>,
    now_us: u64,
    pools: &mut QuicPools,
  ) -> crate::Result<Self> {
    let original_dcid = Cid::new(client_dcid)?;
    let initial = initial_keys(client_dcid, true)?;
    // The CID of the client is in the header of its first Initial packet
    Ok(Self::with_parts(
      params,
      local_cid,
      original_dcid,
      Cid::default(),
      meta,
      tls,
      HandshakeSpaces::take(initial, pools),
      now_us,
    ))
  }
}

#[cfg(test)]
impl<A, RNG, TCX> QuicConn<A, RNG, TCX, true>
where
  A: QuicApp,
  RNG: CryptoRng,
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
    Ok(Self::with_parts(
      params,
      local_cid,
      original_dcid,
      original_dcid,
      meta,
      tls,
      HandshakeSpaces::take(initial, pools),
      now_us,
    ))
  }
}

impl<A, RNG, TCX, const IS_CLIENT: bool> QuicConn<A, RNG, TCX, IS_CLIENT>
where
  A: QuicApp,
  RNG: CryptoRng,
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
    self.enter_closing(now_us, CloseFrame { app: true, code });
  }

  /// Writes the packets that are due into `tx`, as many datagrams as needed.
  #[inline]
  pub(crate) fn flush(
    &mut self,
    now_us: u64,
    tx: &mut TxArena,
    _app: &mut A,
    pools: &mut QuicPools,
  ) -> FlushOutcome {
    loop {
      if !self.wants_send() {
        return FlushOutcome::Done;
      }
      let max_len = self.max_datagram.min(self.amplification_budget());
      if max_len == 0 {
        return FlushOutcome::Done;
      }
      let Some(buffer) = tx.begin(self.peer, self.local, max_len) else {
        return FlushOutcome::ArenaFull;
      };
      // The arena can give less than asked for, the room left in the train that the datagram
      // joins: what does not fit there waits for a flush with more room
      if buffer.len() < max_len && buffer.len() < MIN_DATAGRAM_LEN && self.needs_full_datagram() {
        return FlushOutcome::ArenaFull;
      }
      let short = buffer.len() < max_len;
      match self.write_datagram(now_us, buffer, pools) {
        Ok(0) if short => return FlushOutcome::ArenaFull,
        Ok(0) => return FlushOutcome::Done,
        Ok(len) => {
          tx.commit(len);
          let len = u64::try_from(len).unwrap_or(u64::MAX);
          self.bytes_sent = self.bytes_sent.saturating_add(len);
          self.stats.bytes_out = self.stats.bytes_out.wrapping_add(len);
          self.stats.datagrams_out = self.stats.datagrams_out.wrapping_add(1);
        }
        Err(err) => {
          cold_path();
          if self.state == ConnState::Closing {
            return FlushOutcome::Done;
          }
          // The next datagram carries the CONNECTION_CLOSE
          self.close_on_error(now_us, &err);
        }
      }
    }
  }

  /// When [`Self::on_timeout`] is due, if ever.
  #[inline]
  pub(crate) fn next_deadline(&self) -> Option<u64> {
    match self.state {
      ConnState::Handshake | ConnState::Confirmed => self.idle_deadline(),
      ConnState::Closing | ConnState::Draining => Some(self.close_deadline_us),
      ConnState::Closed => None,
    }
  }

  /// Runs what is due at `now_us`: the end of the closing or draining period, the idle timeout.
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
    // Connection migration and path validation are the endpoint's
    let _meta = meta;
    let datagram_len = datagram.len();
    let len = u64::try_from(datagram_len).unwrap_or(u64::MAX);
    self.stats.datagrams_in = self.stats.datagrams_in.wrapping_add(1);
    self.stats.bytes_in = self.stats.bytes_in.wrapping_add(len);
    match self.state {
      ConnState::Handshake | ConnState::Confirmed => {}
      ConnState::Closing => {
        // What the amplification limit lets the CONNECTION_CLOSE in reply be
        self.bytes_received = self.bytes_received.saturating_add(len);
        self.on_datagram_while_closing();
        return Ok(());
      }
      ConnState::Draining | ConnState::Closed => return Ok(()),
    }
    self.bytes_received = self.bytes_received.saturating_add(len);
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
      if let Err(err) = self.recv_packet(now_us, space, packet, pn_offset, scid, app, pools) {
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

  /// The counters of the connection.
  #[inline]
  pub(crate) const fn stats(&self) -> &ConnStats {
    &self.stats
  }

  fn accepts_dcid(&self, dcid: &Cid) -> bool {
    // The first Initial packets of a client go to the CID that it chose
    *dcid == self.local_cid
      || (!IS_CLIENT && self.state == ConnState::Handshake && *dcid == self.original_dcid)
  }

  // Records the processing of a packet of `space`.
  fn after_packet(&mut self, now_us: u64, space: Space, pools: &mut QuicPools) {
    self.stats.packets_in = self.stats.packets_in.wrapping_add(1);
    self.last_activity_us = now_us;
    self.idle_restart_on_send = true;
    if !matches!(self.state, ConnState::Handshake | ConnState::Confirmed) {
      return;
    }
    if !IS_CLIENT && space == Space::Handshake {
      // A Handshake packet proves that the client got the Initial packets (RFC 9000 section
      // 8.1), whose keys are not needed anymore (RFC 9001 section 4.9.1)
      self.address_validated = true;
      if let Some(elem) = &mut self.handshake {
        elem.initial.clear(pools);
      }
    }
    if !IS_CLIENT && self.handshake_complete && self.state == ConnState::Handshake {
      // A server confirms the handshake once it is complete (RFC 9001 section 4.1.2)
      self.confirm(pools);
    }
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
    let mismatch = params.initial_source_connection_id != Some(self.peer_cid)
      || (IS_CLIENT
        && (params.original_destination_connection_id != Some(self.original_dcid)
          || params.retry_source_connection_id.is_some()));
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
    self.enter_closing(now_us, CloseFrame { app: false, code: code.code() });
  }

  fn confirm(&mut self, pools: &mut QuicPools) {
    self.state = ConnState::Confirmed;
    self.release_handshake(pools);
  }

  // The Initial and Handshake spaces, wiped, and the TLS state go back to their pools.
  fn release_handshake(&mut self, pools: &mut QuicPools) {
    if let Some(elem) = self.handshake.take() {
      HandshakeSpaces::give(elem, pools);
    }
    // Back to the thread's pools, zeroed
    self.tls = None;
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
    self.stats.packets_dropped = self.stats.packets_dropped.wrapping_add(1);
  }

  fn enter_closing(&mut self, now_us: u64, close: CloseFrame) {
    if !matches!(self.state, ConnState::Handshake | ConnState::Confirmed) {
      return;
    }
    self.state = ConnState::Closing;
    self.close = close;
    self.close_owed = true;
    self.close_deadline_us = now_us.saturating_add(self.pto_us().saturating_mul(3));
    self.closing_datagrams = 0;
    self.closing_threshold = 1;
  }

  fn enter_draining(&mut self, now_us: u64) {
    match self.state {
      ConnState::Handshake | ConnState::Confirmed => {
        self.close_deadline_us = now_us.saturating_add(self.pto_us().saturating_mul(3));
      }
      // What is left of the closing period
      ConnState::Closing => {}
      ConnState::Draining | ConnState::Closed => return,
    }
    self.state = ConnState::Draining;
    self.close_owed = false;
  }

  // A budget is spent: the application closes the connection with its excessive load code. The
  // error has the code that such a close takes before 1-RTT (RFC 9000 section 10.2.3).
  fn excessive_load(&mut self, now_us: u64) -> crate::Error {
    cold_path();
    let code = self.params.limits.excessive_load_app_code;
    self.enter_closing(now_us, CloseFrame { app: true, code });
    crate::Error::QuicClose(TransportErrorCode::ApplicationError, QuicError::ExcessiveLoad)
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
    let initial = self.space_wants_send(Space::Initial)
      && (IS_CLIENT || !self.crypto_unsent(Space::Initial).is_empty());
    initial || (self.path_response.is_some() && has_keys(Space::Data))
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

  fn on_ack(
    &mut self,
    space: Space,
    ack: &AckFrame<'_>,
    pools: &mut QuicPools,
  ) -> crate::Result<()> {
    let max_ranges = self.params.limits.max_ack_ranges;
    let Some(sp) = space_mut(&mut self.data, &mut self.handshake, space) else {
      return Ok(());
    };
    if ack.largest >= sp.sent.next_pn() {
      return Err(violation(QuicError::AckOfUnsentPacket));
    }
    if sp.largest_acked.is_none_or(|elem| ack.largest > elem) {
      sp.largest_acked = Some(ack.largest);
    }
    let mut our_ack = None;
    for range in ack.ranges().take(max_ranges) {
      let range = range?;
      for pn in sp.sent.window(*range.start(), *range.end()) {
        let Some(packet) = sp.sent.take(pn) else {
          continue;
        };
        for frame in pools.frame_refs.iter(packet.frames) {
          if let FrameRef::Ack { largest } = frame {
            our_ack = our_ack.max(Some(largest));
          }
        }
        pools.frame_refs.free(packet.frames);
      }
    }
    if let Some(elem) = our_ack {
      sp.recv.on_ack_of_our_ack(elem);
    }
    Ok(())
  }

  // CRYPTO data, in order to TLS, what comes early buffered.
  fn on_crypto(
    &mut self,
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
    if space == Space::Data {
      // Nothing is read after the handshake: TLS closes the connection
      feed(tls, space, data, None, data_keys)?;
      return self.on_tls_progress(app);
    }
    let Some(hs) = self.handshake.as_deref_mut() else {
      return Ok(());
    };
    let HandshakeSpaces { handshake, initial } = hs;
    // Initial data yields the keys of Handshake, Handshake data those of 1-RTT
    let (rx, mut handshake_keys) = if space == Space::Initial {
      (&mut initial.crypto_rx, Some(&mut handshake.keys))
    } else {
      (&mut handshake.crypto_rx, None)
    };
    let direct = rx.accept(offset, data, pools)?;
    feed(tls, space, direct, handshake_keys.as_deref_mut(), data_keys)?;
    loop {
      let buffered = rx.buffered();
      if buffered.is_empty() {
        break;
      }
      let len = buffered.len();
      feed(tls, space, buffered, handshake_keys.as_deref_mut(), data_keys)?;
      rx.consume(len, pools);
    }
    self.on_tls_progress(app)
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
  fn on_tls_progress(&mut self, app: &mut A) -> crate::Result<()> {
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
      self.has_peer_params = true;
      self.peer_idle_timeout_ms = elem.max_idle_timeout_ms;
      self.peer_max_ack_delay_ms = elem.max_ack_delay_ms;
    }
    if is_complete && !self.handshake_complete {
      self.handshake_complete = true;
      self.handshake_done_owed = !IS_CLIENT;
      app.on_established(&mut self.app_state)?;
    }
    Ok(())
  }

  // The probe timeout of RFC 9002 section 6.2.1 with the initial RTT, until an RTT is measured.
  const fn pto_us(&self) -> u64 {
    let rttvar = INITIAL_RTT_US / 2;
    let variance = if 4 * rttvar > GRANULARITY_US { 4 * rttvar } else { GRANULARITY_US };
    INITIAL_RTT_US
      .saturating_add(variance)
      .saturating_add(self.peer_max_ack_delay_ms.saturating_mul(1_000))
  }

  // The frames of a decrypted packet, in one walk. Returns whether the packet was ack-eliciting.
  fn recv_frames(
    &mut self,
    now_us: u64,
    space: Space,
    payload: &[u8],
    app: &mut A,
    pools: &mut QuicPools,
  ) -> crate::Result<bool> {
    let mut ack_eliciting = false;
    let mut is_empty = true;
    for frame in FrameReader::new(payload, space) {
      let frame = frame?;
      is_empty = false;
      match frame {
        Frame::Padding(_) => {}
        Frame::Ack(ack) => self.on_ack(space, &ack, pools)?,
        Frame::ConnectionClose { .. } => {
          self.enter_draining(now_us);
          return Ok(ack_eliciting);
        }
        Frame::Crypto { offset, data } => {
          ack_eliciting = true;
          self.on_crypto(space, offset, data, app, pools)?;
        }
        Frame::HandshakeDone => {
          ack_eliciting = true;
          if !IS_CLIENT {
            return Err(violation(QuicError::FrameFromWrongRole));
          }
          // A client confirms the handshake when the server says so (RFC 9001 section 4.1.2)
          if self.state == ConnState::Handshake {
            self.confirm(pools);
          }
        }
        Frame::NewToken(_) => {
          ack_eliciting = true;
          if !IS_CLIENT {
            return Err(violation(QuicError::FrameFromWrongRole));
          }
        }
        Frame::PathChallenge(data) => {
          // Answered, always (RFC 9000 section 8.2.2), and the latest one only
          ack_eliciting = true;
          self.path_response = Some(data);
          if !self.path_challenges.take(self.params.limits.path_challenge_budget, now_us) {
            return Err(self.excessive_load(now_us));
          }
        }
        Frame::Ping => {
          ack_eliciting = true;
          if !self.pings.take(self.params.limits.ping_budget, now_us) {
            return Err(self.excessive_load(now_us));
          }
        }
        // Streams, flow control and connection IDs belong to the layers above
        Frame::ResetStream { .. }
        | Frame::StopSending { .. }
        | Frame::Stream { .. }
        | Frame::MaxData(_)
        | Frame::MaxStreamData { .. }
        | Frame::MaxStreams { .. }
        | Frame::DataBlocked(_)
        | Frame::StreamDataBlocked { .. }
        | Frame::StreamsBlocked { .. }
        | Frame::NewConnectionId { .. }
        | Frame::RetireConnectionId(_)
        | Frame::PathResponse(_) => ack_eliciting = true,
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
    app: &mut A,
    pools: &mut QuicPools,
  ) -> crate::Result<()> {
    let Some(sp) = space_mut(&mut self.data, &mut self.handshake, space) else {
      self.drop_packet();
      return Ok(());
    };
    let Some(keys) = &sp.keys else {
      self.drop_packet();
      return Ok(());
    };
    let Ok((pn, pn_len, first)) =
      remove_header_protection(keys.remote.hp(), packet, pn_offset, sp.recv.largest())
    else {
      self.drop_packet();
      return Ok(());
    };
    if sp.recv.is_duplicate(pn) {
      self.stats.duplicates = self.stats.duplicates.wrapping_add(1);
      return Ok(());
    }
    let header_len = pn_offset.wrapping_add(pn_len);
    let Ok(payload) = open_payload(keys.remote.aead(), keys.remote.iv(), packet, header_len, pn)
    else {
      // Forged, corrupted or for other keys: the buffer is lost (RFC 9001 section 5.3)
      self.drop_packet();
      return Ok(());
    };
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
    let ack_eliciting = self.recv_frames(now_us, space, payload, app, pools)?;
    if let Some(sp) = space_mut(&mut self.data, &mut self.handshake, space) {
      let _is_new = sp.recv.on_packet(pn, ack_eliciting, now_us);
    }
    self.after_packet(now_us, space, pools);
    Ok(())
  }

  // Seals `packet`, which is in `buffer`, and records it.
  fn seal(&mut self, now_us: u64, buffer: &mut [u8], packet: &OpenPacket) -> crate::Result<usize> {
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
    let len =
      protect(&keys.local, bytes, packet.pn_offset, packet.pn, packet.pn_len, packet.payload_len)?;
    if self.state == ConnState::Closing {
      sp.sent.skip();
    } else {
      sp.sent.on_sent(SentPacket {
        time_us: now_us,
        size: u16::try_from(len).unwrap_or(u16::MAX),
        ack_eliciting: packet.ack_eliciting,
        in_flight: packet.ack_eliciting || packet.padded,
        frames: packet.frames,
      });
    }
    self.stats.packets_out = self.stats.packets_out.wrapping_add(1);
    if !packet.ack_eliciting && self.state != ConnState::Closing {
      self.stats.ack_only_out = self.stats.ack_only_out.wrapping_add(1);
    }
    Ok(len)
  }

  fn space_wants_send(&self, space: Space) -> bool {
    let Some(sp) = space_ref(&self.data, &self.handshake, space) else {
      return false;
    };
    if sp.keys.is_none() {
      return false;
    }
    let mut wants = sp.recv.ack_pending() || !self.crypto_unsent(space).is_empty();
    if space == Space::Data {
      wants |= self.handshake_done_owed || self.path_response.is_some();
      #[cfg(test)]
      {
        wants |= !self.test_frames.is_empty();
      }
    }
    wants
  }

  fn enter_closed(&mut self, app: &mut A, pools: &mut QuicPools) {
    self.state = ConnState::Closed;
    self.release_handshake(pools);
    self.data.clear(pools);
    self.close_owed = false;
    self.handshake_done_owed = false;
    self.path_response = None;
    app.on_closed(&mut self.app_state);
  }

  fn wants_send(&self) -> bool {
    match self.state {
      ConnState::Handshake | ConnState::Confirmed => {
        SPACES.into_iter().any(|space| self.space_wants_send(space))
      }
      ConnState::Closing => self.close_owed,
      ConnState::Draining | ConnState::Closed => false,
    }
  }

  fn with_parts(
    params: &ConnParams,
    local_cid: Cid,
    original_dcid: Cid,
    peer_cid: Cid,
    meta: DatagramMeta,
    tls: QuicTls<IS_CLIENT, RNG, TCX>,
    handshake: Box<HandshakeSpaces>,
    now_us: u64,
  ) -> Self {
    Self {
      address_validated: false,
      app_state: A::ConnState::default(),
      bytes_received: 0,
      bytes_sent: 0,
      close: CloseFrame { app: false, code: 0 },
      close_deadline_us: 0,
      close_owed: false,
      closing_datagrams: 0,
      closing_threshold: 1,
      handshake_complete: false,
      handshake_done_owed: false,
      has_peer_params: false,
      idle_restart_on_send: true,
      last_activity_us: now_us,
      local: meta.local,
      local_cid,
      max_datagram: INITIAL_MAX_DATAGRAM,
      original_dcid,
      params: *params,
      path_challenges: RateBudget::default(),
      path_response: None,
      peer: meta.peer,
      peer_cid,
      peer_cid_known: false,
      peer_idle_timeout_ms: 0,
      peer_max_ack_delay_ms: TransportParams::default().max_ack_delay_ms,
      pings: RateBudget::default(),
      data: PacketSpace::new(),
      handshake: Some(handshake),
      state: ConnState::Handshake,
      stats: ConnStats::default(),
      tls: Some(tls),
      #[cfg(test)]
      test_frames: alloc::vec::Vec::new(),
    }
  }

  // One datagram: a packet of each space with something to send, padded and sealed. Returns its
  // length, zero if nothing fit.
  fn write_datagram(
    &mut self,
    now_us: u64,
    buffer: &mut [u8],
    pools: &mut QuicPools,
  ) -> crate::Result<usize> {
    let closing = self.state == ConnState::Closing;
    let mut packets = [None, None, None];
    let mut pos = 0usize;
    for (space, slot) in SPACES.into_iter().zip(&mut packets) {
      let wanted = if closing {
        space_ref(&self.data, &self.handshake, space).is_some_and(|el| el.keys.is_some())
      } else {
        self.space_wants_send(space)
      };
      // An ack-eliciting Initial packet of a server needs a datagram of 1200 bytes, which the
      // amplification limit may not leave
      let initial_too_short = !IS_CLIENT
        && !closing
        && space == Space::Initial
        && buffer.len() < MIN_DATAGRAM_LEN
        && !self.crypto_unsent(space).is_empty();
      if !wanted || initial_too_short {
        continue;
      }
      let Some(out) = buffer.get_mut(pos..) else {
        break;
      };
      if let Some(mut packet) = self.write_packet(now_us, space, out, closing, pools)? {
        packet.start = pos;
        pos = pos.wrapping_add(packet.len());
        *slot = Some(packet);
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
    let mut sent_handshake = false;
    let mut ack_eliciting = false;
    for packet in packets.iter().flatten() {
      let _len = self.seal(now_us, buffer, packet)?;
      sent_handshake |= packet.space == Space::Handshake;
      ack_eliciting |= packet.ack_eliciting;
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
        elem.initial.clear(pools);
      }
    }
    Ok(pos)
  }

  // A packet of `space` at the start of `out`, not sealed yet, or `None` if nothing fit.
  fn write_packet(
    &mut self,
    now_us: u64,
    space: Space,
    out: &mut [u8],
    closing: bool,
    pools: &mut QuicPools,
  ) -> crate::Result<Option<OpenPacket>> {
    let (dcid, scid) = (self.peer_cid, self.local_cid);
    let Some(sp) = space_mut(&mut self.data, &mut self.handshake, space) else {
      return Ok(None);
    };
    // A CONNECTION_CLOSE needs a packet number, not a record: it is neither ack-eliciting nor in
    // flight
    if sp.keys.is_none() || (!closing && !sp.sent.reserve(pools)) {
      return Ok(None);
    }
    let pn = sp.sent.next_pn();
    let pn_len = pn_len_for(pn, sp.largest_acked);
    let Some((header_len, pn_offset, length_at)) =
      write_header(out, space, &dcid, &scid, pn, pn_len)
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
    let mut frames = FrameRefRange::EMPTY;
    let mut ack_eliciting = false;
    let mut full_datagram = false;
    if closing {
      // An application close is a transport one with APPLICATION_ERROR before 1-RTT (RFC 9000
      // section 10.2.3)
      let (app, code) = if self.close.app && space != Space::Data {
        (false, TransportErrorCode::ApplicationError.code())
      } else {
        (self.close.app, self.close.code)
      };
      let _written = fw.write_connection_close(app, code, (!app).then_some(0), &[]);
    } else {
      if sp.recv.ack_pending()
        && let Some(largest) = sp.recv.largest()
        && sp.recv.write_ack(&mut fw, self.params.ack_delay_exponent, now_us)
      {
        pools.frame_refs.push(&mut frames, FrameRef::Ack { largest })?;
        sp.recv.on_ack_sent();
      }
      if space == Space::Data {
        if self.handshake_done_owed && fw.write_handshake_done() {
          pools.frame_refs.push(&mut frames, FrameRef::HandshakeDone)?;
          self.handshake_done_owed = false;
          ack_eliciting = true;
        }
        if let Some(data) = self.path_response
          && fw.write_path_response(data)
        {
          self.path_response = None;
          ack_eliciting = true;
          full_datagram = true;
        }
        #[cfg(test)]
        if !self.test_frames.is_empty() && fw.write_bytes(&self.test_frames) {
          self.test_frames.clear();
          ack_eliciting = true;
        }
      }
      if let Some(tls) = &self.tls {
        let sent = usize::try_from(sp.crypto_tx).unwrap_or(usize::MAX);
        let unsent = tls.output(space).get(sent..).unwrap_or_default();
        let offset = sp.crypto_tx;
        // The header and the data must fit together
        let room = fw.remaining();
        let longest = unsent.len().min(room);
        let header = 1usize
          .wrapping_add(varint_len(offset))
          .wrapping_add(varint_len(u64::try_from(longest).unwrap_or(u64::MAX)));
        let data_len = longest.min(room.saturating_sub(header));
        if let Some(data) = unsent.get(..data_len).filter(|elem| !elem.is_empty())
          && fw.write_crypto_header(offset, data_len)
          && fw.write_bytes(data)
        {
          let len = u32::try_from(data_len).unwrap_or(u32::MAX);
          pools.frame_refs.push(&mut frames, FrameRef::Crypto { offset, len })?;
          sp.crypto_tx = sp.crypto_tx.wrapping_add(u64::from(len));
          ack_eliciting = true;
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
      frames,
      full_datagram,
      header_len,
      length_at,
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

#[cfg(test)]
impl<A, RNG, TCX, const IS_CLIENT: bool> QuicConn<A, RNG, TCX, IS_CLIENT>
where
  A: QuicApp,
{
  /// Sends `frames`, raw, in the next 1-RTT packet.
  pub(crate) fn queue_test_frames(&mut self, frames: &[u8]) {
    self.test_frames.extend_from_slice(frames);
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
      .field("stats", &self.stats)
      .finish_non_exhaustive()
  }
}

// The CONNECTION_CLOSE that the connection sends.
#[derive(Clone, Copy, Debug)]
struct CloseFrame {
  app: bool,
  code: u64,
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
}

// A packet written into a datagram but not sealed yet: the last one of a datagram can still take
// padding.
#[derive(Clone, Copy, Debug)]
struct OpenPacket {
  ack_eliciting: bool,
  frames: FrameRefRange,
  // If the datagram must have at least 1200 bytes
  full_datagram: bool,
  // Up to and including the packet number
  header_len: usize,
  // Where the Length field of a long header is
  length_at: Option<usize>,
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
  crypto_rx: CryptoRx,
  // The bytes of the TLS output of the level that were sent
  crypto_tx: u64,
  keys: Option<PacketKeys>,
  // The largest of our packet numbers that the peer acknowledged
  largest_acked: Option<u64>,
  recv: RecvTracker,
  sent: SentRing,
}

impl PacketSpace {
  const fn new() -> Self {
    Self {
      crypto_rx: CryptoRx::new(),
      crypto_tx: 0,
      keys: None,
      largest_acked: None,
      recv: RecvTracker::new(),
      sent: SentRing::new(),
    }
  }

  // Drops the keys in their slot, which wipes them, gives the resources back and starts over.
  fn clear(&mut self, pools: &mut QuicPools) {
    self.keys = None;
    self.sent.release(pools);
    self.crypto_rx.release(pools);
    *self = Self::new();
  }
}

/// The Initial and Handshake packet number spaces of a connection: keys, CRYPTO reassembly,
/// acknowledgments and sent packets. A connection takes them from the worker's pool for its
/// handshake and gives them back, wiped, once the handshake is confirmed (spec section 5.4).
#[derive(Debug)]
pub(crate) struct HandshakeSpaces {
  handshake: PacketSpace,
  initial: PacketSpace,
}

impl HandshakeSpaces {
  // Spaces from the pool, or new ones, with the keys of Initial.
  fn take(initial: PacketKeys, pools: &mut QuicPools) -> Box<Self> {
    let mut this = pools.handshake_spaces.take().unwrap_or_else(|| {
      Box::new(Self { handshake: PacketSpace::new(), initial: PacketSpace::new() })
    });
    this.initial.keys = Some(initial);
    this
  }

  // Wipes the keys where they are and gives the spaces back.
  fn give(mut this: Box<Self>, pools: &mut QuicPools) {
    this.initial.clear(pools);
    this.handshake.clear(pools);
    pools.handshake_spaces.give(this);
  }
}

// Feeds TLS and installs the keys of every secret that it yields, in the slot of the level, which
// TLS requires after every feed. The secrets are dropped, and so wiped, once their keys are made.
fn feed<const IS_CLIENT: bool, RNG, TCX>(
  tls: &mut QuicTls<IS_CLIENT, RNG, TCX>,
  space: Space,
  data: &[u8],
  mut handshake_keys: Option<&mut Option<PacketKeys>>,
  data_keys: &mut Option<PacketKeys>,
) -> crate::Result<()>
where
  RNG: CryptoRng,
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
    let local = keys_from_secret(secrets.suite, secrets.tx.as_slice())?;
    let remote = keys_from_secret(secrets.suite, secrets.rx.as_slice())?;
    *slot = Some(PacketKeys { local, remote });
  }
  Ok(())
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
  pn: u64,
  pn_len: usize,
) -> Option<(usize, usize, Option<usize>)> {
  let pn_bits = u8::try_from(pn_len.wrapping_sub(1)).ok()? & 0b11;
  let mut w = Writer::new(out);
  let length_at = if space == Space::Data {
    // No spin bit and key phase zero
    w.put_u8(0x40 | pn_bits).ok()?;
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
      // No token
      w.varint(0).ok()?;
    }
    let at = w.pos();
    w.zeros(LENGTH_FIELD_LEN).ok()?;
    Some(at)
  };
  let pn_offset = w.pos();
  w.put(pn.to_be_bytes().get(8usize.wrapping_sub(pn_len)..)?).ok()?;
  Some((w.pos(), pn_offset, length_at))
}

#[cfg(test)]
mod tests {
  use crate::{
    quic::{
      Cid, ConnState, FlushOutcome, PacketTy, QuicError, Space, TransportErrorCode,
      conn::CryptoRx,
      parse_header,
      pools::{CRYPTO_BUFFER_LEN, QuicPools},
      protect,
      testing::{CLIENT_ADDR, Link, LinkOpts, Parts, SERVER_ADDR},
    },
    sync::AtomicU64,
    tests::_count_allocations_in,
    tls::CipherSuite,
  };
  use alloc::{vec, vec::Vec};
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
      super::write_header(&mut out, space, &dcid, &scid, pn, 4).unwrap();
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
    link.run();
    assert_eq!(link.client.conn.state(), ConnState::Confirmed);
  }

  // Without traffic both sides close, silently, at the smaller of the two timeouts, or at three
  // PTOs if that is longer.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn idle_timeout_closes() {
    for (client_ms, server_ms, expected_us) in
      [(5_000, 10_000, 5_000_000), (1_000, 1_000, 3 * PTO_US)]
    {
      let mut opts = LinkOpts::new(None);
      opts.client.max_idle_timeout_ms = client_ms;
      opts.server.max_idle_timeout_ms = server_ms;
      let mut link = settled(&opts);
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
    assert_eq!(deadline - link.now_us, 3 * PTO_US);
    assert_eq!(link.client.conn.next_deadline(), Some(deadline));
    link.advance(3 * PTO_US - 1);
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
    fn counts(parts: &Parts) -> (usize, usize, usize, usize) {
      let pools = &parts.pools;
      (
        pools.frame_refs.live_chunks(),
        pools.handshake_spaces.len(),
        pools.sent_rings.len(),
        pools.crypto_buffers.len(),
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
    // In the middle of a transfer: an ACK of the server is not acknowledged
    let mut link = Link::with_parts(&opts, client_parts, server_parts);
    link.run();
    link.client.conn.queue_test_frames(&PING);
    let _ = link.client.flush(link.now_us);
    assert_eq!(link.deliver_to_server(), 1);
    let _ = link.server.flush(link.now_us);
    assert!(link.server.parts.pools.frame_refs.live_chunks() > 0);
    link.server.conn.abort(&mut link.server.app, &mut link.server.parts.pools);
    assert_eq!(counts(&link.server.parts), warm);
    // Aborting again changes nothing
    link.server.conn.abort(&mut link.server.app, &mut link.server.parts.pools);
    assert_eq!(link.server.app.closed, 1);
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
    let mut link = settled(&opts);
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
    let mut link = settled(&opts);
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
}
