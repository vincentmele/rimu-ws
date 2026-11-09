//! TLS 1.3 for QUIC (RFC 9001): the handshake of [`TlsAcceptor`](crate::tls::TlsAcceptor), and
//! for tests of a client, carried in CRYPTO frames instead of records.
//!
//! Sans-I/O. The connection feeds the CRYPTO data of each encryption level in order, sends what
//! [`QuicTls::output`] has at each level and protects its packets with keys derived from the
//! traffic secrets that [`QuicTls::poll_secrets`] yields (RFC 9001 section 5.1). There are no
//! records and no ChangeCipherSpec, and the `quic_transport_parameters` extension (0x39) carries
//! the transport parameters of each side, which TLS does not look into.
//!
//! What a server does with a ClientHello, its EncryptedExtensions, Certificate, CertificateVerify
//! and Finished and the verification of the Finished of the client are those of the record path
//! ([`negotiate_client_hello`], [`write_server_flight`], [`verify_client_finished`]), and so is
//! what the client does with the messages of the server ([`manage_server_hello`],
//! [`manage_server_flight_msg`]).
//!
//! # Memory
//!
//! Besides the shared configuration, the whole state of a handshake (key schedule, transcript,
//! buffers, the seed of its random numbers) lives in a box that this thread pools, and the two
//! buffers come from this thread's TLS pools ([`TlsBuffer`]): both go back zeroed when this is
//! dropped, which a connection does once the handshake is confirmed. The handle that a connection
//! keeps inline is two pointers (ruling T10-j).
//!
//! The random numbers of a handshake come from a generator made, when they are needed, from a
//! seed of the pooled state, which the generator replaces with the first bytes that it gives. The
//! seed is drawn from the generator of the caller each time a state is taken: a state that came
//! back zeroed never gives the next handshake the numbers of the previous one.
//!
//! The reader buffer holds the transport parameters that are kept (the local ones of a server
//! until its EncryptedExtensions is written, then those of the peer), followed by the handshake
//! message that is arriving, at most [`MAX_HANDSHAKE_MESSAGE`] bytes. The writer buffer holds what
//! is sent: the bytes of Initial, then those of Handshake.

use crate::{
  collections::ArrayVectorCopy,
  crypto::MAX_HASH_LEN,
  misc::{LeaseMut, zero_volatile},
  quic::{QuicError, Space, TransportErrorCode},
  rng::{CryptoRng, CryptoSeedableRng},
  sync::Arc,
  tls::{
    AlertDescription, CipherSuite, DLFT_MAX_FRAGMENT_LENGTH, HandshakeTy, NamedGroup,
    SignatureScheme, TlsBuffer, TlsConfig, TlsCtxSk, TlsError,
    key_schedule::KeySchedule,
    protocol::handshake::Handshake,
    tls_acceptor::{
      filter_signature_algorithms, negotiate_client_hello, verify_client_finished,
      write_server_flight,
    },
    tls_hash::TlsHash,
  },
};
use alloc::boxed::Box;
use core::{
  fmt::{Debug, Formatter},
  hint::cold_path,
  marker::PhantomData,
  mem::{ManuallyDrop, MaybeUninit},
  ops::{Deref, DerefMut, Range},
  ptr,
};

/// The longest handshake message that is buffered: a longer one closes the connection with
/// `CRYPTO_BUFFER_EXCEEDED`.
pub(crate) const MAX_HANDSHAKE_MESSAGE: usize = 16 * 1024;

// The bytes of the seed of the random numbers of a handshake: at least the seed of its generator
const RNG_SEED_LEN: usize = 32;

const INITIAL_LEVEL: u8 = 0;
const HANDSHAKE_LEVEL: u8 = 1;
const DATA_LEVEL: u8 = 2;
const SECRET_LEN: usize = MAX_HASH_LEN;
// State boxes that a thread keeps: as many as a QUIC worker has handshakes under way, so that
// bursts of them allocate nothing once warm (ruling T10-l); trimmed when the thread is idle
#[cfg(feature = "std")]
const STATE_POOL_MAX: usize = 256;
#[cfg(all(feature = "std", feature = "io-uring", target_os = "linux"))]
const STATE_POOL_IDLE_KEEP: usize = 4;

#[cfg(feature = "std")]
std::thread_local! {
  #[allow(clippy::vec_box, reason = "the boxes are what is pooled")]
  static STATE_POOL: core::cell::RefCell<alloc::vec::Vec<Box<MaybeUninit<QuicTlsState>>>> =
    const { core::cell::RefCell::new(alloc::vec::Vec::new()) };
}

/// The state boxes that this thread's pool holds, for tests.
#[cfg(all(test, feature = "std"))]
pub(crate) fn pooled_states() -> usize {
  STATE_POOL.with(|pool| pool.borrow().len())
}

/// Frees the oldest state boxes of this thread's pool until a few are left: with the other TLS
/// pools ([`crate::tls::tls_pool`]), once the thread has no connection open.
#[cfg(all(feature = "std", feature = "io-uring", target_os = "linux"))]
#[inline]
pub(crate) fn trim_idle_states() {
  let _rslt = STATE_POOL.try_with(|pool| {
    if let Ok(mut elem) = pool.try_borrow_mut() {
      let excess = elem.len().saturating_sub(STATE_POOL_IDLE_KEEP);
      let _ = elem.drain(..excess);
    }
  });
}

/// The traffic secrets of one encryption level, from which the connection derives its packet
/// protection keys with [`crate::quic::keys_from_secret_with`].
///
/// Dropping it overwrites both secrets. They are `Copy` arrays: a copy taken out of it is not
/// wiped.
pub(crate) struct QuicTlsSecrets {
  /// The encryption level.
  pub(crate) space: Space,
  /// The negotiated cipher suite.
  pub(crate) suite: CipherSuite,
  /// The secret of what is received.
  pub(crate) rx: ArrayVectorCopy<u8, SECRET_LEN>,
  /// The secret of what is sent.
  pub(crate) tx: ArrayVectorCopy<u8, SECRET_LEN>,
}

impl Debug for QuicTlsSecrets {
  #[inline]
  fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
    f.debug_struct("QuicTlsSecrets")
      .field("space", &self.space)
      .field("suite", &self.suite)
      .finish_non_exhaustive()
  }
}

impl Drop for QuicTlsSecrets {
  #[inline]
  fn drop(&mut self) {
    for secret in [&mut self.rx, &mut self.tx] {
      // SAFETY: the array behind the pointer has room for `SECRET_LEN` bytes, overwritten here
      // as plain bytes, which leaves every byte initialized
      unsafe { zero_volatile(secret.as_ptr_mut(), SECRET_LEN) };
    }
  }
}

/// A TLS 1.3 handshake carried in QUIC CRYPTO frames (RFC 9001 section 4), of a server or, in
/// tests, of a client (`IS_CLIENT`).
///
/// The configuration is shared, so that its secret key is parsed once and never per handshake.
/// In QUIC the only application protocol is HTTP/3: whatever ALPN the configuration lists, the
/// server negotiates `h3` and nothing else.
pub(crate) struct QuicTls<const IS_CLIENT: bool, RNG, TCX> {
  config: Arc<TlsConfig<TCX>>,
  // The generator of the random numbers, made from the seed of the state when they are needed
  rng: PhantomData<fn() -> RNG>,
  // Everything else, in a box that this thread pools
  state: StateBox,
}

// The state of a handshake, which goes back to the thread's pool zeroed (see `StateBox`).
struct QuicTlsState {
  alpn: ArrayVectorCopy<u8, 8>,
  buffer: TlsBuffer,
  has_peer_transport_params: bool,
  key_schedule: KeySchedule,
  // Where the message that is arriving begins in the reader buffer
  msg_start: usize,
  named_group: NamedGroup,
  // What is sent in Initial and in Handshake: ranges of the writer buffer
  output_handshake: Range<usize>,
  output_initial: Range<usize>,
  // What the next generator of random numbers is made from (see the module documentation)
  rng_seed: [u8; RNG_SEED_LEN],
  // The levels whose secrets TLS has (Handshake, then Data), and how many of them were taken
  secrets_ready: u8,
  secrets_taken: u8,
  signature_algorithms: ArrayVectorCopy<(SignatureScheme, u8), { SignatureScheme::len() }>,
  stage: Stage,
  // The bytes at the beginning of the reader buffer that hold transport parameters
  stored_len: usize,
  transcript_hash: TlsHash,
}

impl<RNG, TCX> QuicTls<false, RNG, TCX>
where
  RNG: CryptoRng + CryptoSeedableRng,
  TCX: TlsCtxSk,
{
  /// The handshake of a server, which sends `local_transport_params` (encoded) in its
  /// EncryptedExtensions, and whose random numbers come from a seed drawn from `rng`.
  #[inline]
  pub(crate) fn new<R>(
    config: &Arc<TlsConfig<TCX>>,
    local_transport_params: &[u8],
    rng: &mut R,
  ) -> crate::Result<Self>
  where
    R: CryptoRng,
  {
    let mut this = Self::with_parts(Arc::clone(config), rng, Stage::ClientHello);
    let state = &mut *this.state;
    state.signature_algorithms = filter_signature_algorithms(config);
    state.buffer.reader_buffer.buffer_mut().extend_from_copyable_slice(local_transport_params)?;
    state.stored_len = local_transport_params.len();
    state.msg_start = state.stored_len;
    Ok(this)
  }
}

#[cfg(test)]
impl<RNG> QuicTls<true, RNG, crate::tls::UnverifiedCtx>
where
  RNG: CryptoRng + CryptoSeedableRng,
{
  /// The handshake of a client, for tests: it offers `alpn` and sends `local_transport_params`
  /// (encoded) in its ClientHello, which [`Self::output`] already holds. The certificate of the
  /// server is not verified, its CertificateVerify is.
  pub(crate) fn new_client<R>(
    server_name: &str,
    alpn: &[u8],
    local_transport_params: &[u8],
    seed_rng: &mut R,
  ) -> crate::Result<Self>
  where
    R: CryptoRng,
  {
    use crate::{
      codec::Encode as _,
      collections::ArrayVectorU8,
      tls::{
        Alpn, ServerName, ServerNameList, protocol::client_hello::ClientHello,
        tls_cc_wrappers::TlsEncodeWrapper,
      },
    };
    let mut config = TlsConfig::unverified();
    let mut alpn_list = Alpn::default();
    alpn_list.protocol_name_list.push(alpn.try_into()?)?;
    *config.alpn_mut() = Some(alpn_list);
    let mut server_names = ServerNameList::default();
    server_names.server_name_list.push(ServerName::from_name(server_name.try_into()?))?;
    *config.server_name_mut() = Some(server_names);
    let mut this = Self::with_parts(Arc::new(config), seed_rng, Stage::Failed);
    let mut rng = next_rng::<RNG>(&mut this.state.rng_seed)?;
    let mut secrets = ArrayVectorU8::new();
    for named_group in &this.config.supported_groups().named_group_list {
      secrets.push(named_group.agreement(&mut rng)?)?;
    }
    let client_hello = ClientHello::new(&secrets, &mut rng, &*this.config);
    let state = &mut *this.state;
    Handshake::new(HandshakeTy::ClientHello, client_hello.into_quic(local_transport_params))
      .encode(&mut TlsEncodeWrapper::from_buffer(&mut state.buffer.writer_buffer))?;
    state.output_initial = 0..state.buffer.writer_buffer.len();
    state.stage = Stage::ServerHello(secrets);
    Ok(this)
  }
}

impl<const IS_CLIENT: bool, RNG, TCX> QuicTls<IS_CLIENT, RNG, TCX>
where
  RNG: CryptoRng + CryptoSeedableRng,
  TCX: TlsCtxSk,
{
  /// The negotiated application protocol (`h3`), empty until it is known.
  #[allow(dead_code, reason = "for the application layer")]
  #[inline]
  pub(crate) fn alpn(&self) -> &[u8] {
    self.state.alpn.as_slice()
  }

  /// Marks the first `n` bytes of [`Self::output`] at `space` as sent.
  #[allow(dead_code, reason = "the connection keeps its own offsets into the output, to resend")]
  #[inline]
  pub(crate) fn consume_output(&mut self, space: Space, n: usize) {
    let range = match space {
      Space::Initial => &mut self.state.output_initial,
      Space::Handshake => &mut self.state.output_handshake,
      Space::Data => return,
    };
    range.start = range.start.saturating_add(n).min(range.end);
  }

  /// Takes the CRYPTO data `data` of `space`, which goes on from where the previous data of that
  /// space ended: the caller reassembles the frames. Handshake messages may arrive split across
  /// calls; one longer than [`MAX_HANDSHAKE_MESSAGE`] is an error.
  ///
  /// Every error is a [`crate::Error::QuicClose`]: the connection closes with its code, a TLS
  /// alert (`0x0100` plus the alert) for most of them, and this instance does nothing more.
  #[inline]
  pub(crate) fn feed(&mut self, space: Space, data: &[u8]) -> crate::Result<()> {
    if data.is_empty() {
      return Ok(());
    }
    if let Err(err) = self.read_level(space, data) {
      cold_path();
      self.state.stage = Stage::Failed;
      return Err(quic_close(err));
    }
    Ok(())
  }

  /// If the handshake is over: for a server, once the Finished of the client is verified.
  #[inline]
  pub(crate) fn is_complete(&self) -> bool {
    matches!(self.state.stage, Stage::Complete)
  }

  /// The handshake bytes to send in CRYPTO frames at `space`: a ServerHello (a ClientHello) in
  /// Initial, the rest of the flight in Handshake, nothing in Data.
  #[inline]
  pub(crate) fn output(&self, space: Space) -> &[u8] {
    let range = match space {
      Space::Initial => self.state.output_initial.clone(),
      Space::Handshake => self.state.output_handshake.clone(),
      Space::Data => return &[],
    };
    self.state.buffer.writer_buffer.get(range).unwrap_or_default()
  }

  /// The encoded transport parameters of the peer, once its ClientHello (its
  /// EncryptedExtensions) arrived. Their presence is checked, their content is not.
  #[inline]
  pub(crate) fn peer_transport_params(&self) -> Option<&[u8]> {
    if !self.state.has_peer_transport_params {
      return None;
    }
    self.state.buffer.reader_buffer.filled().get(..self.state.stored_len)
  }

  /// The traffic secrets of the next encryption level, once TLS has them: those of Handshake once
  /// the ServerHello is written (read), then those of Data. A server yields the secrets of Data
  /// only once the Finished of the client is verified. They must be taken after each call to
  /// [`Self::feed`]: TLS does not keep the secrets of a level that it moved past.
  #[inline]
  pub(crate) fn poll_secrets(&mut self) -> Option<QuicTlsSecrets> {
    if self.state.secrets_taken >= self.state.secrets_ready
      || matches!(self.state.stage, Stage::Failed)
    {
      return None;
    }
    let space = if self.state.secrets_taken == 0 { Space::Handshake } else { Space::Data };
    let mut secrets = QuicTlsSecrets {
      space,
      suite: self.state.key_schedule.cipher_suite(),
      rx: ArrayVectorCopy::new(),
      tx: ArrayVectorCopy::new(),
    };
    let (read, write) =
      (self.state.key_schedule.read().state(), self.state.key_schedule.write().state());
    secrets.rx.extend_from_copyable_slice(read.raw_traffic_secret()).ok()?;
    secrets.tx.extend_from_copyable_slice(write.raw_traffic_secret()).ok()?;
    self.state.secrets_taken = self.state.secrets_taken.wrapping_add(1);
    Some(secrets)
  }

  // Derives the secrets of Data from the transcript up to the Finished of the server.
  fn enter_data_level(&mut self) -> crate::Result<()> {
    if self.state.secrets_taken < HANDSHAKE_LEVEL {
      cold_path();
      return Err(crate::Error::QuicClose(
        TransportErrorCode::InternalError,
        QuicError::TlsSecretsNotTaken,
      ));
    }
    let state = &mut *self.state;
    state.key_schedule.master_secret::<IS_CLIENT>(&state.transcript_hash.clone().finalize())?;
    state.secrets_ready = DATA_LEVEL;
    state.stage = Stage::Complete;
    Ok(())
  }

  // Takes `data`, of the level of `space`, one handshake message at a time.
  fn read_level(&mut self, space: Space, mut data: &[u8]) -> crate::Result<()> {
    let Some(reading) = self.state.stage.reading_level() else {
      return Err(alert(AlertDescription::InternalError, QuicError::TlsAlert));
    };
    let level = level(space);
    if level < reading {
      // The data of that level was complete (RFC 9001 section 4.1.3)
      return Err(crate::Error::QuicClose(
        TransportErrorCode::ProtocolViolation,
        QuicError::CryptoDataAtWrongLevel,
      ));
    }
    if level > reading || reading == DATA_LEVEL {
      // Before TLS has keys for the level, or after the handshake, when only a KeyUpdate (which
      // RFC 9001 section 6 forbids) or a NewSessionTicket (which a client never sends and this
      // server does not ask for) could come
      return Err(alert(AlertDescription::UnexpectedMessage, QuicError::CryptoDataAtWrongLevel));
    }
    let header_len = Handshake::<()>::HEADER_LEN;
    loop {
      let state = &mut *self.state;
      let start = state.msg_start;
      let input = state.buffer.reader_buffer.buffer_mut();
      // The header, then the rest of the message, never more than the message
      let have = input.len().wrapping_sub(start);
      if have < header_len {
        let (head, rest) = split(data, header_len.wrapping_sub(have));
        input.extend_from_copyable_slice(head)?;
        data = rest;
      }
      let Some(&[_, b0, b1, b2]) = input.get(start..start.wrapping_add(header_len)) else {
        return Ok(());
      };
      let msg_len = header_len.wrapping_add(u32::from_be_bytes([0, b0, b1, b2]).try_into()?);
      if msg_len > MAX_HANDSHAKE_MESSAGE {
        return Err(crate::Error::QuicClose(
          TransportErrorCode::CryptoBufferExceeded,
          QuicError::HandshakeMessageTooLong,
        ));
      }
      let (body, rest) = split(data, msg_len.wrapping_sub(input.len().wrapping_sub(start)));
      input.extend_from_copyable_slice(body)?;
      data = rest;
      if input.len().wrapping_sub(start) < msg_len {
        return Ok(());
      }
      let keeps_messages = state.stage.keeps_messages();
      self.read_message(start, !data.is_empty())?;
      let state = &mut *self.state;
      if keeps_messages && state.stage.keeps_messages() {
        state.msg_start = state.buffer.reader_buffer.filled().len();
      } else {
        state.buffer.reader_buffer.truncate(state.stored_len);
        state.msg_start = state.stored_len;
      }
      if data.is_empty() {
        return Ok(());
      }
    }
  }

  // The complete message at `start` of the reader buffer, which `excess` data follows.
  fn read_message(&mut self, start: usize, excess: bool) -> crate::Result<()> {
    match self.state.stage {
      Stage::ClientHello => self.server_client_hello(start, excess),
      Stage::ClientFinished => self.server_client_finished(start, excess),
      #[cfg(test)]
      Stage::ServerHello(_) => self.client_server_hello(start, excess),
      #[cfg(test)]
      Stage::ServerFlight(_) => self.client_server_flight(start, excess),
      Stage::Complete | Stage::Failed => {
        Err(alert(AlertDescription::UnexpectedMessage, QuicError::CryptoDataAtWrongLevel))
      }
    }
  }

  // The ClientHello: in return, a ServerHello in Initial and the rest of the flight in Handshake.
  fn server_client_hello(&mut self, start: usize, excess: bool) -> crate::Result<()> {
    let state = &mut *self.state;
    if excess {
      // The ClientHello is all that a client sends in Initial
      return Err(unexpected_message());
    }
    let TlsBuffer { reader_buffer, writer_buffer } = &mut state.buffer;
    let (local_transport_params, client_hello) =
      reader_buffer.filled().split_at_checked(start).unwrap_or_default();
    if client_hello.first() != Some(&HandshakeTy::ClientHello.into()) {
      return Err(unexpected_message());
    }
    // QUIC packets are no records: the limits of records do not apply
    let (mut max_fragment_length, mut max_fragment_length_send) =
      (DLFT_MAX_FRAGMENT_LENGTH, DLFT_MAX_FRAGMENT_LENGTH);
    let initial_begin = writer_buffer.len();
    let mut rng = next_rng::<RNG>(&mut state.rng_seed)?;
    let negotiation = negotiate_client_hello::<_, _, true>(
      client_hello,
      &self.config,
      &mut state.key_schedule,
      (&mut max_fragment_length, &mut max_fragment_length_send),
      &mut state.named_group,
      writer_buffer,
      &mut rng,
      &state.signature_algorithms,
      &mut state.transcript_hash,
    )?;
    let handshake_begin = writer_buffer.len();
    if let Some(elem) = negotiation.alpn.as_ref().and_then(|el| el.protocol_name_list.first()) {
      state.alpn = *elem;
    }
    let peer_transport_params = negotiation.quic_transport_parameters.start.wrapping_add(start)
      ..negotiation.quic_transport_parameters.end.wrapping_add(start);
    let _indices = write_server_flight(
      &self.config,
      &mut state.key_schedule,
      negotiation,
      writer_buffer,
      Some(local_transport_params),
      &mut rng,
      &mut state.transcript_hash,
    )?;
    state.output_initial = initial_begin..handshake_begin;
    state.output_handshake = handshake_begin..writer_buffer.len();
    // The parameters of the client take the place of those of the server, which are sent
    keep_transport_params(reader_buffer.buffer_mut(), peer_transport_params, &mut state.stored_len);
    state.has_peer_transport_params = true;
    state.secrets_ready = HANDSHAKE_LEVEL;
    state.stage = Stage::ClientFinished;
    Ok(())
  }

  // The Finished of the client, after which the secrets of Data can be taken.
  fn server_client_finished(&mut self, start: usize, excess: bool) -> crate::Result<()> {
    let finished = self.state.buffer.reader_buffer.filled().get(start..).unwrap_or_default();
    verify_client_finished(&self.state.key_schedule, finished, &self.state.transcript_hash)?;
    if excess {
      return Err(crate::Error::TlsErrorReply(
        TlsError::ExcessHandshakeData(crate::net::RoleTy::Server),
        AlertDescription::UnexpectedMessage,
      ));
    }
    self.enter_data_level()
  }

  fn with_parts<R>(config: Arc<TlsConfig<TCX>>, rng: &mut R, stage: Stage) -> Self
  where
    R: CryptoRng,
  {
    let key_schedule = KeySchedule::default();
    let transcript_hash = key_schedule.cipher_suite().hash_new();
    let named_group =
      config.supported_groups().named_group_list.first().copied().unwrap_or(NamedGroup::default());
    let state = StateBox::new(QuicTlsState {
      alpn: ArrayVectorCopy::new(),
      buffer: TlsBuffer::pooled(),
      has_peer_transport_params: false,
      key_schedule,
      msg_start: 0,
      named_group,
      output_handshake: 0..0,
      output_initial: 0..0,
      // From the caller at every take of a state, which comes back zeroed (ruling T10-j)
      rng_seed: rng.u8_32(),
      secrets_ready: 0,
      secrets_taken: 0,
      signature_algorithms: ArrayVectorCopy::new(),
      stage,
      stored_len: 0,
      transcript_hash,
    });
    Self { config, rng: PhantomData, state }
  }

  /// Where the pooled state and buffers are.
  #[cfg(test)]
  fn pooled_addrs(&mut self) -> [usize; 3] {
    [
      (&raw const **self.state.0).addr(),
      self.state.buffer.reader_buffer.buffer_mut().as_ptr().addr(),
      self.state.buffer.writer_buffer.as_ptr().addr(),
    ]
  }
}

#[cfg(test)]
impl<const IS_CLIENT: bool, RNG, TCX> QuicTls<IS_CLIENT, RNG, TCX>
where
  RNG: CryptoRng + CryptoSeedableRng,
  TCX: TlsCtxSk,
{
  // The ServerHello, after which the secrets of Handshake can be taken.
  fn client_server_hello(&mut self, start: usize, excess: bool) -> crate::Result<()> {
    use crate::{
      codec::Decode as _,
      tls::{tls_cc_wrappers::TlsDecodeWrapper, tls_connector::manage_server_hello},
    };
    let state = &mut *self.state;
    let Stage::ServerHello(secrets) = &mut state.stage else {
      return Err(unexpected_message());
    };
    if excess {
      // The ServerHello is all that a server sends in Initial
      return Err(unexpected_message());
    }
    let server_hello = state.buffer.reader_buffer.filled().get(start..).unwrap_or_default();
    let mut dw = TlsDecodeWrapper::from_bytes(server_hello);
    let handshake = Handshake::<&[u8]>::decode(&mut dw)?;
    if handshake.msg_type != HandshakeTy::ServerHello {
      return Err(unexpected_message());
    }
    *dw.bytes_mut() = handshake.data;
    let mrsri = manage_server_hello(
      state.buffer.writer_buffer.get(..state.output_initial.end).unwrap_or_default(),
      &mut dw,
      &mut state.key_schedule,
      &mut state.named_group,
      secrets,
      server_hello,
      &mut state.transcript_hash,
    )?;
    state.secrets_ready = HANDSHAKE_LEVEL;
    state.stage = Stage::ServerFlight(mrsri);
    Ok(())
  }

  // One message of the flight of the server; after its Finished, the Finished of the client goes
  // in Handshake and the secrets of Data can be taken.
  fn client_server_flight(&mut self, start: usize, excess: bool) -> crate::Result<()> {
    use crate::{
      codec::{Decode as _, Encode as _},
      misc::Lease as _,
      tls::{
        protocol::finished::Finished,
        tls_cc_wrappers::{TlsDecodeWrapper, TlsEncodeWrapper},
        tls_connector::manage_server_flight_msg,
      },
    };
    let state = &mut *self.state;
    let Stage::ServerFlight(mrsri) = &mut state.stage else {
      return Err(unexpected_message());
    };
    let TlsBuffer { reader_buffer, writer_buffer } = &mut state.buffer;
    let filled = reader_buffer.filled();
    let msg = filled.get(start..).unwrap_or_default();
    let mut dw = TlsDecodeWrapper::from_bytes(msg);
    let handshake = Handshake::<&[u8]>::decode(&mut dw)?;
    // The EncryptedExtensions comes first (RFC 9846 section 4.3.1), which also leaves the
    // transport parameters as the last message
    if (handshake.msg_type == HandshakeTy::EncryptedExtensions) == state.has_peer_transport_params {
      return Err(unexpected_message());
    }
    *dw.bytes_mut() = handshake.data;
    let hostname = self
      .config
      .server_name()
      .as_ref()
      .and_then(|el| el.server_name_list.first())
      .map_or("", |el| el.name().as_str());
    let (mut max_fragment_length, mut max_fragment_length_send) =
      (DLFT_MAX_FRAGMENT_LENGTH, DLFT_MAX_FRAGMENT_LENGTH);
    let mut encrypted_extensions = None;
    let is_finished = manage_server_flight_msg(
      &self.config,
      &mut dw,
      &mut encrypted_extensions,
      excess,
      filled,
      false,
      hostname,
      &mut state.key_schedule,
      (&mut max_fragment_length, &mut max_fragment_length_send),
      mrsri,
      msg,
      handshake.msg_type,
      &mut state.transcript_hash,
    )?;
    let client_cert_requested = mrsri.client_cert_requested();
    if let Some(elem) = encrypted_extensions {
      let Some(peer_transport_params) = elem.quic_transport_parameters() else {
        return Err(missing_transport_params());
      };
      let Some(alpn) = elem.alpn().as_ref().and_then(|el| el.protocol_name_list.first()) else {
        return Err(crate::Error::TlsErrorReply(
          TlsError::MissingAlpn,
          AlertDescription::NoApplicationProtocol,
        ));
      };
      state.alpn = *alpn;
      let begin = peer_transport_params.as_ptr().addr().wrapping_sub(filled.as_ptr().addr());
      let range = begin..begin.wrapping_add(peer_transport_params.len());
      keep_transport_params(reader_buffer.buffer_mut(), range, &mut state.stored_len);
      state.has_peer_transport_params = true;
    }
    if !is_finished {
      return Ok(());
    }
    if client_cert_requested {
      return Err(TlsError::UnsupportedMtls.into());
    }
    let verify_data = state
      .key_schedule
      .write()
      .state()
      .create_finished_verify_data(state.transcript_hash.clone().finalize().lease())?;
    let begin = writer_buffer.len();
    Handshake::new(HandshakeTy::Finished, Finished::new(&verify_data))
      .encode(&mut TlsEncodeWrapper::from_buffer(writer_buffer))?;
    state.output_handshake = begin..writer_buffer.len();
    self.enter_data_level()
  }
}

impl<const IS_CLIENT: bool, RNG, TCX> Debug for QuicTls<IS_CLIENT, RNG, TCX> {
  #[inline]
  fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
    f.debug_struct("QuicTls")
      .field("is_client", &IS_CLIENT)
      .field("secrets_ready", &self.state.secrets_ready)
      .field("secrets_taken", &self.state.secrets_taken)
      .field("stage", &self.state.stage.reading_level())
      .finish_non_exhaustive()
  }
}

/// A boxed [`QuicTlsState`] whose box comes from, and goes back to, this thread's pool, every byte
/// of it zeroed, as [`crate::tls::KsBox`] does for the key schedules of the record path.
struct StateBox(ManuallyDrop<Box<QuicTlsState>>);

impl StateBox {
  // `state` in a pooled box, or a new one.
  fn new(state: QuicTlsState) -> Self {
    #[cfg(feature = "std")]
    if let Some(elem) = STATE_POOL.try_with(|pool| pool.try_borrow_mut().ok()?.pop()).ok().flatten()
    {
      return Self(ManuallyDrop::new(Box::write(elem, state)));
    }
    Self(ManuallyDrop::new(Box::new(state)))
  }
}

impl Deref for StateBox {
  type Target = QuicTlsState;

  fn deref(&self) -> &QuicTlsState {
    &self.0
  }
}

impl DerefMut for StateBox {
  fn deref_mut(&mut self) -> &mut QuicTlsState {
    &mut self.0
  }
}

impl Drop for StateBox {
  fn drop(&mut self) {
    // SAFETY: `self.0` is never used again
    let raw = Box::into_raw(unsafe { ManuallyDrop::take(&mut self.0) });
    // SAFETY: a valid state, dropped once, here: its buffers go back to their own pool
    unsafe { ptr::drop_in_place(raw) };
    // SAFETY: the allocation has room for a state, written here as plain bytes, with stores the
    // compiler may not drop: the box is pooled or freed right after
    unsafe { zero_volatile(raw.cast::<u8>(), size_of::<QuicTlsState>()) };
    // SAFETY: `MaybeUninit<QuicTlsState>` has the layout of `QuicTlsState`, which `raw` was boxed
    // with, and its value was dropped
    let elem = unsafe { Box::from_raw(raw.cast::<MaybeUninit<QuicTlsState>>()) };
    #[cfg(feature = "std")]
    {
      let mut elem = Some(elem);
      let _rslt = STATE_POOL.try_with(|pool| {
        if let Ok(mut pool) = pool.try_borrow_mut()
          && pool.len() < STATE_POOL_MAX
          && let Some(value) = elem.take()
        {
          pool.push(value);
        }
      });
      drop(elem);
    }
    #[cfg(not(feature = "std"))]
    drop(elem);
  }
}

/// Where a handshake is.
enum Stage {
  /// A server waits for the ClientHello, in Initial.
  ClientHello,
  /// A server waits for the Finished of the client, in Handshake.
  ClientFinished,
  /// A client waits for the ServerHello, in Initial, with its key shares.
  #[cfg(test)]
  ServerHello(
    crate::collections::ArrayVectorU8<
      crate::tls::protocol::named_group::NamedGroupAgreement,
      { NamedGroup::len() },
    >,
  ),
  /// A client waits for the rest of the flight of the server, in Handshake.
  #[cfg(test)]
  ServerFlight(crate::tls::ManageRemainingServerRecordsInput),
  /// The handshake is over.
  Complete,
  /// The handshake failed.
  Failed,
}

impl Stage {
  /// If the messages that arrive are kept while the stage lasts: those of the flight of a server,
  /// as with records, since a CertificateVerify refers to the Certificate before it.
  const fn keeps_messages(&self) -> bool {
    #[cfg(test)]
    if let Self::ServerFlight(_) = self {
      return true;
    }
    false
  }

  /// The level whose CRYPTO data TLS reads, or `None` once the handshake failed.
  const fn reading_level(&self) -> Option<u8> {
    match self {
      Self::ClientHello => Some(INITIAL_LEVEL),
      #[cfg(test)]
      Self::ServerHello(_) => Some(INITIAL_LEVEL),
      Self::ClientFinished => Some(HANDSHAKE_LEVEL),
      #[cfg(test)]
      Self::ServerFlight(_) => Some(HANDSHAKE_LEVEL),
      Self::Complete => Some(DATA_LEVEL),
      Self::Failed => None,
    }
  }
}

// A generator made from `seed`, which takes as the next seed the first bytes that the generator
// gives: no two generators give the same numbers.
fn next_rng<RNG>(seed: &mut [u8; RNG_SEED_LEN]) -> crate::Result<RNG>
where
  RNG: CryptoRng + CryptoSeedableRng,
{
  // A generator whose seed is longer than the one that the state keeps does not build (review
  // N3); the check below stays for a seed whose bytes are not inline
  const {
    assert!(
      size_of::<RNG::Seed>() <= RNG_SEED_LEN,
      "the generator of a QUIC handshake needs a seed of at most 32 bytes"
    );
  }
  let mut rng_seed = RNG::Seed::default();
  let dst = rng_seed.lease_mut();
  let Some(src) = seed.get(..dst.len()) else {
    cold_path();
    return Err(crate::Error::ProgrammingError);
  };
  dst.copy_from_slice(src);
  let mut rng = RNG::from_seed(rng_seed)?;
  rng.fill_slice(seed);
  Ok(rng)
}

fn alert(description: AlertDescription, err: QuicError) -> crate::Error {
  crate::Error::QuicClose(TransportErrorCode::Crypto(description.into()), err)
}

// Moves the transport parameters at `range` of `buffer` to its beginning, where they are kept,
// and drops everything after them: they lie in the last message, which the earlier ones (if any)
// are not needed after.
fn keep_transport_params(
  buffer: &mut crate::collections::VectorUsize<u8>,
  range: Range<usize>,
  stored_len: &mut usize,
) {
  let len = range.len();
  if buffer.get(range.clone()).is_some() {
    buffer.copy_within(range, 0);
  }
  buffer.truncate(len);
  *stored_len = len;
}

const fn level(space: Space) -> u8 {
  match space {
    Space::Initial => INITIAL_LEVEL,
    Space::Handshake => HANDSHAKE_LEVEL,
    Space::Data => DATA_LEVEL,
  }
}

#[cfg(test)]
fn missing_transport_params() -> crate::Error {
  crate::Error::TlsErrorReply(
    TlsError::MissingQuicTransportParameters,
    AlertDescription::MissingExtension,
  )
}

/// The error that closes the connection, in QUIC terms: a TLS alert `A` is the transport error
/// code `0x0100 + A` (RFC 9001 section 4.8).
fn quic_close(err: crate::Error) -> crate::Error {
  let description = match err {
    crate::Error::QuicClose(..) => return err,
    // There is no HelloRetryRequest: a ClientHello without a key share of a supported group can
    // only fail, with the alert RFC 9846 section 4.1.1 names for it (the record path, which is
    // kept as it was, sends unexpected_message)
    crate::Error::TlsErrorReply(TlsError::ServerHasNoCompatibleKeyShare, _) => {
      AlertDescription::HandshakeFailure
    }
    crate::Error::TlsErrorReply(_, elem) => elem,
    // RFC 9846 sections 4.4.3 and 4.4.4
    crate::Error::Tls(TlsError::BadSignature | TlsError::DigestCheckFailed) => {
      AlertDescription::DecryptError
    }
    crate::Error::Tls(TlsError::UnsupportedTlsVersion(_)) => AlertDescription::ProtocolVersion,
    _ => AlertDescription::HandshakeFailure,
  };
  alert(description, QuicError::TlsAlert)
}

// `data` cut after `len` bytes, or whole if it has fewer.
fn split(data: &[u8], len: usize) -> (&[u8], &[u8]) {
  data.split_at_checked(len).unwrap_or((data, &[]))
}

fn unexpected_message() -> crate::Error {
  crate::Error::TlsErrorReply(TlsError::InvalidHandshakeTy, AlertDescription::UnexpectedMessage)
}

#[cfg(all(test, feature = "std"))]
mod tests {
  use crate::{
    Error,
    collections::ArrayVectorCopy,
    quic::{QuicError, Space, TransportErrorCode, keys_from_secret},
    rng::{ChaCha20, CryptoSeedableRng as _},
    sync::Arc,
    tests::{_PUBLIC_KEY, _SECRET_KEY},
    tls::{
      CipherSuite, KeySchedule, NamedGroup, SkCtx, TlsBuffer, TlsConfig, UnverifiedCtx,
      quic_tls::{QuicTls, QuicTlsSecrets, QuicTlsState, STATE_POOL, Stage, StateBox},
      tls_pool,
    },
  };
  use alloc::vec::Vec;
  use core::{mem::MaybeUninit, ops::Range, ptr, slice};

  type Client = QuicTls<true, ChaCha20, UnverifiedCtx>;
  type Server = QuicTls<false, ChaCha20, SkCtx>;

  // Opaque to TLS: the connection encodes and decodes them
  const CLIENT_TP: &[u8] =
    &[0x04, 0x04, 0x80, 0x10, 0x00, 0x00, 0x0f, 0x08, 1, 2, 3, 4, 5, 6, 7, 8];
  const SERVER_TP: &[u8] =
    &[0x00, 0x04, 9, 9, 9, 9, 0x04, 0x02, 0x7f, 0xff, 0x0f, 0x08, 8, 7, 6, 5, 4, 3, 2, 1];

  const ALPN: u16 = 0x0010;
  const KEY_SHARE: u16 = 0x0033;
  const QUIC_TRANSPORT_PARAMETERS: u16 = 0x0039;
  // Not assigned by IANA, so skipped by the server
  const UNKNOWN_EXTENSION: u16 = 0xfa0a;

  fn client(alpn: &[u8]) -> Client {
    QuicTls::new_client("localhost", alpn, CLIENT_TP, &mut ChaCha20::from_std_random().unwrap())
      .unwrap()
  }

  fn server() -> Server {
    let config = Arc::new(TlsConfig::from_keys_pem(_PUBLIC_KEY, _SECRET_KEY).unwrap());
    QuicTls::new(&config, SERVER_TP, &mut ChaCha20::from_std_random().unwrap()).unwrap()
  }

  // What the client has to send in `space`, taken out of it.
  fn client_out(client: &mut Client, space: Space) -> Vec<u8> {
    let bytes = client.output(space).to_vec();
    client.consume_output(space, bytes.len());
    bytes
  }

  fn server_out(server: &mut Server, space: Space) -> Vec<u8> {
    let bytes = server.output(space).to_vec();
    server.consume_output(space, bytes.len());
    bytes
  }

  fn secrets_of<const IS_CLIENT: bool, TCX>(
    tls: &mut QuicTls<IS_CLIENT, ChaCha20, TCX>,
  ) -> Vec<QuicTlsSecrets>
  where
    TCX: crate::tls::TlsCtxSk,
  {
    let mut rslt = Vec::new();
    while let Some(elem) = tls.poll_secrets() {
      rslt.push(elem);
    }
    rslt
  }

  // The secrets of both sides, level by level, once `ch` (the client's Initial output, maybe
  // altered) reached the server.
  fn finish_handshake(
    client: &mut Client,
    server: &mut Server,
  ) -> (Vec<QuicTlsSecrets>, Vec<QuicTlsSecrets>) {
    let mut client_secrets = Vec::new();
    let mut server_secrets = secrets_of(server);
    client.feed(Space::Initial, &server_out(server, Space::Initial)).unwrap();
    client_secrets.extend(secrets_of(client));
    client.feed(Space::Handshake, &server_out(server, Space::Handshake)).unwrap();
    client_secrets.extend(secrets_of(client));
    server.feed(Space::Handshake, &client_out(client, Space::Handshake)).unwrap();
    server_secrets.extend(secrets_of(server));
    (client_secrets, server_secrets)
  }

  // The handshake messages of `bytes`, as (type, whole message) pairs, which must fill it.
  fn messages(mut bytes: &[u8]) -> Vec<(u8, Vec<u8>)> {
    let mut rslt = Vec::new();
    while !bytes.is_empty() {
      let len =
        4 + usize::from(bytes[1]) * 65536 + usize::from(bytes[2]) * 256 + usize::from(bytes[3]);
      rslt.push((bytes[0], bytes[..len].to_vec()));
      bytes = &bytes[len..];
    }
    rslt
  }

  // The extensions of the ClientHello message `ch`: type and where the data lies.
  fn extensions(ch: &[u8]) -> Vec<(u16, Range<usize>)> {
    let u16_at = |idx: usize| usize::from(u16::from_be_bytes([ch[idx], ch[idx + 1]]));
    // header, legacy_version, random
    let mut idx = 4 + 2 + 32;
    idx += 1 + usize::from(ch[idx]);
    idx += 2 + u16_at(idx);
    idx += 1 + usize::from(ch[idx]);
    let end = idx + 2 + u16_at(idx);
    idx += 2;
    let mut rslt = Vec::new();
    while idx < end {
      let (ty, len) = (u16_at(idx), u16_at(idx + 2));
      rslt.push((u16::try_from(ty).unwrap(), idx + 4..idx + 4 + len));
      idx += 4 + len;
    }
    assert_eq!(idx, ch.len());
    rslt
  }

  fn extension(ch: &[u8], ty: u16) -> Range<usize> {
    extensions(ch).into_iter().find(|el| el.0 == ty).unwrap().1
  }

  // Gives the extension `from` the type `to`, which hides it from the server.
  fn rename_extension(ch: &mut [u8], from: u16, to: u16) {
    let range = extension(ch, from);
    ch[range.start - 4..range.start - 2].copy_from_slice(&to.to_be_bytes());
  }

  fn crypto_alert(rslt: crate::Result<()>) -> u8 {
    match rslt {
      Err(Error::QuicClose(TransportErrorCode::Crypto(alert), QuicError::TlsAlert)) => alert,
      other => panic!("{other:?}"),
    }
  }

  fn crypto_alert_wrong_level(rslt: crate::Result<()>) -> Option<u8> {
    match rslt {
      Err(Error::QuicClose(
        TransportErrorCode::Crypto(alert),
        QuicError::CryptoDataAtWrongLevel,
      )) => Some(alert),
      _ => None,
    }
  }

  // The two sides complete, with the same secrets at each level in opposite directions, the
  // transport parameters of each other and the ALPN `h3`.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn quic_handshake_client_server_in_process() {
    let (mut client, mut server) = (client(b"h3"), server());
    assert!(client.poll_secrets().is_none());
    server.feed(Space::Initial, &client_out(&mut client, Space::Initial)).unwrap();
    let (client_secrets, server_secrets) = finish_handshake(&mut client, &mut server);
    assert!(client.is_complete() && server.is_complete());
    assert_eq!(client_secrets.len(), 2);
    assert_eq!(server_secrets.len(), 2);
    for ((client_el, server_el), space) in
      client_secrets.iter().zip(&server_secrets).zip([Space::Handshake, Space::Data])
    {
      assert_eq!((client_el.space, server_el.space), (space, space));
      assert_eq!(client_el.suite, server_el.suite);
      assert_eq!(client_el.tx.as_slice(), server_el.rx.as_slice());
      assert_eq!(client_el.rx.as_slice(), server_el.tx.as_slice());
      assert_ne!(client_el.rx.as_slice(), client_el.tx.as_slice());
      assert_eq!(client_el.rx.len(), client_el.suite.hash_len());
      let _keys = keys_from_secret(server_el.suite, &server_el.rx).unwrap();
    }
    assert_ne!(client_secrets[0].rx.as_slice(), client_secrets[1].rx.as_slice());
    assert_eq!(server.peer_transport_params(), Some(CLIENT_TP));
    assert_eq!(client.peer_transport_params(), Some(SERVER_TP));
    assert_eq!((client.alpn(), server.alpn()), (&b"h3"[..], &b"h3"[..]));
    for space in [Space::Initial, Space::Handshake, Space::Data] {
      assert!(client.output(space).is_empty() && server.output(space).is_empty());
    }
    assert!(client.poll_secrets().is_none() && server.poll_secrets().is_none());
  }

  // QUIC carries bare handshake messages: no record header, no ChangeCipherSpec.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn server_output_has_no_record_header_or_ccs() {
    let (mut client, mut server) = (client(b"h3"), server());
    let ch = client_out(&mut client, Space::Initial);
    assert_eq!(messages(&ch).iter().map(|el| el.0).collect::<Vec<_>>(), [1]);
    server.feed(Space::Initial, &ch).unwrap();
    let initial = server.output(Space::Initial);
    assert_eq!(initial.first(), Some(&0x02));
    assert_eq!(messages(initial).iter().map(|el| el.0).collect::<Vec<_>>(), [2]);
    let handshake = server.output(Space::Handshake);
    assert_eq!(messages(handshake).iter().map(|el| el.0).collect::<Vec<_>>(), [8, 11, 15, 20]);
    assert!(server.output(Space::Data).is_empty());
    // A partly consumed output goes on from where it was left
    let len = server.output(Space::Handshake).len();
    server.consume_output(Space::Handshake, 3);
    assert_eq!(server.output(Space::Handshake).len(), len - 3);
    server.consume_output(Space::Handshake, usize::MAX);
    assert!(server.output(Space::Handshake).is_empty());
  }

  // A ClientHello that spans Initial packets reaches TLS in pieces, the first of which does not
  // even hold the header of the message.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn client_hello_split_across_feeds() {
    let (mut client, mut server) = (client(b"h3"), server());
    let ch = client_out(&mut client, Space::Initial);
    let (first, rest) = ch.split_at(2);
    let (second, third) = rest.split_at(rest.len() / 2);
    for chunk in [first, second] {
      server.feed(Space::Initial, chunk).unwrap();
      assert!(server.output(Space::Initial).is_empty() && server.poll_secrets().is_none());
    }
    server.feed(Space::Initial, third).unwrap();
    let (client_secrets, server_secrets) = finish_handshake(&mut client, &mut server);
    assert!(client.is_complete() && server.is_complete());
    assert_eq!(client_secrets[1].tx.as_slice(), server_secrets[1].rx.as_slice());
    assert_eq!(server.peer_transport_params(), Some(CLIENT_TP));
  }

  // Key shares of groups we do not support only (curl on OpenSSL 3.5 can offer X25519MLKEM768
  // alone): there is no HelloRetryRequest, so the handshake fails at once, with handshake_failure.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn unsupported_key_share_only_is_handshake_failure() {
    let (mut client, mut server) = (client(b"h3"), server());
    let mut ch = client_out(&mut client, Space::Initial);
    let range = extension(&ch, KEY_SHARE);
    // X25519MLKEM768, SecP256r1MLKEM768 and X25519Kyber768Draft00
    let mut unknown = [0x11ec_u16, 0x11eb, 0x6399].into_iter();
    let mut idx = range.start + 2;
    while idx < range.end {
      ch[idx..idx + 2].copy_from_slice(&unknown.next().unwrap().to_be_bytes());
      idx += 4 + usize::from(u16::from_be_bytes([ch[idx + 2], ch[idx + 3]]));
    }
    assert_eq!(crypto_alert(server.feed(Space::Initial, &ch)), 0x28);
    assert!(server.output(Space::Initial).is_empty() && server.poll_secrets().is_none());
  }

  // The client must offer ALPN, and `h3`.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn no_alpn_is_no_application_protocol() {
    let (mut client0, mut server0) = (client(b"h3"), server());
    let mut ch = client_out(&mut client0, Space::Initial);
    rename_extension(&mut ch, ALPN, UNKNOWN_EXTENSION);
    assert_eq!(crypto_alert(server0.feed(Space::Initial, &ch)), 0x78);
    let (mut client1, mut server1) = (client(b"h2"), server());
    let ch = client_out(&mut client1, Space::Initial);
    assert_eq!(crypto_alert(server1.feed(Space::Initial, &ch)), 0x78);
    assert!(server1.output(Space::Initial).is_empty() && server1.poll_secrets().is_none());
  }

  // A client Finished that does not verify gives no 1-RTT keys.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn bad_client_finished_rejected_before_1rtt_rx() {
    let (mut client, mut server) = (client(b"h3"), server());
    server.feed(Space::Initial, &client_out(&mut client, Space::Initial)).unwrap();
    let server_secrets = secrets_of(&mut server);
    assert_eq!(server_secrets.len(), 1);
    client.feed(Space::Initial, &server_out(&mut server, Space::Initial)).unwrap();
    let _handshake = secrets_of(&mut client);
    client.feed(Space::Handshake, &server_out(&mut server, Space::Handshake)).unwrap();
    let mut finished = client_out(&mut client, Space::Handshake);
    assert_eq!(messages(&finished).iter().map(|el| el.0).collect::<Vec<_>>(), [20]);
    *finished.last_mut().unwrap() ^= 1;
    // decrypt_error
    assert_eq!(crypto_alert(server.feed(Space::Handshake, &finished)), 0x33);
    assert!(server.poll_secrets().is_none());
    assert!(!server.is_complete());
  }

  // RFC 9001 section 8.2: a ClientHello without quic_transport_parameters is missing_extension.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn missing_transport_params_rejected() {
    let (mut client, mut server) = (client(b"h3"), server());
    let mut ch = client_out(&mut client, Space::Initial);
    assert_eq!(&ch[extension(&ch, QUIC_TRANSPORT_PARAMETERS)], CLIENT_TP);
    rename_extension(&mut ch, QUIC_TRANSPORT_PARAMETERS, UNKNOWN_EXTENSION);
    assert_eq!(crypto_alert(server.feed(Space::Initial, &ch)), 0x6d);
    assert!(server.peer_transport_params().is_none() && server.poll_secrets().is_none());
  }

  // A message that announces more than the 16 KiB that are buffered for one fails as soon as its
  // header arrives, before any of it is buffered.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn handshake_message_longer_than_16_kib_is_crypto_buffer_exceeded() {
    // A ClientHello of 16,381 bytes, 16,385 with its header
    let mut server = server();
    assert!(matches!(
      server.feed(Space::Initial, &[1, 0, 0x3f, 0xfd]),
      Err(Error::QuicClose(
        TransportErrorCode::CryptoBufferExceeded,
        QuicError::HandshakeMessageTooLong
      ))
    ));
    // One byte less, the longest that is buffered, is waited for
    let mut server = self::server();
    server.feed(Space::Initial, &[1, 0, 0x3f, 0xfc]).unwrap();
    server.feed(Space::Initial, &[0; 100]).unwrap();
    assert!(server.output(Space::Initial).is_empty());
  }

  // CRYPTO data where TLS does not read: more data at a level that is over is a protocol
  // violation (RFC 9001 section 4.1.3), data after the handshake (a KeyUpdate, RFC 9001 section
  // 6) or at a level that TLS has no keys for is an unexpected message.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn crypto_data_at_a_wrong_level_closes() {
    // No keys for Handshake yet
    assert_eq!(
      crypto_alert_wrong_level(server().feed(Space::Handshake, &[20, 0, 0, 0])),
      Some(0x0a)
    );
    let (mut client0, mut server0) = (client(b"h3"), server());
    server0.feed(Space::Initial, &client_out(&mut client0, Space::Initial)).unwrap();
    assert!(matches!(
      server0.feed(Space::Initial, &[0]),
      Err(Error::QuicClose(
        TransportErrorCode::ProtocolViolation,
        QuicError::CryptoDataAtWrongLevel
      ))
    ));
    let (mut client, mut server) = (client(b"h3"), server());
    server.feed(Space::Initial, &client_out(&mut client, Space::Initial)).unwrap();
    let _secrets = finish_handshake(&mut client, &mut server);
    // A KeyUpdate that does not ask for one back
    let key_update = [24, 0, 0, 1, 0];
    assert_eq!(crypto_alert_wrong_level(server.feed(Space::Data, &key_update)), Some(0x0a));
    assert_eq!(crypto_alert_wrong_level(client.feed(Space::Data, &key_update)), Some(0x0a));
    // Once failed, nothing more
    assert!(server.feed(Space::Data, &key_update).is_err());
    assert!(server.poll_secrets().is_none());
  }

  // The secrets of Handshake are gone once TLS moves on: moving on before they are taken is an
  // error, never a wrong secret yielded later.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn untaken_secrets_are_an_error() {
    let (mut client, mut server) = (client(b"h3"), server());
    server.feed(Space::Initial, &client_out(&mut client, Space::Initial)).unwrap();
    client.feed(Space::Initial, &server_out(&mut server, Space::Initial)).unwrap();
    let _handshake = secrets_of(&mut client);
    client.feed(Space::Handshake, &server_out(&mut server, Space::Handshake)).unwrap();
    assert!(matches!(
      server.feed(Space::Handshake, &client_out(&mut client, Space::Handshake)),
      Err(Error::QuicClose(TransportErrorCode::InternalError, QuicError::TlsSecretsNotTaken))
    ));
    assert!(server.poll_secrets().is_none());
  }

  // Dropping the secrets overwrites the whole arrays of both, beyond their lengths too.
  #[test]
  fn quic_tls_secrets_are_wiped_when_dropped() {
    let mut slot = MaybeUninit::<QuicTlsSecrets>::uninit();
    let _ = slot.write(QuicTlsSecrets {
      space: Space::Handshake,
      suite: CipherSuite::Aes128GcmSha256,
      rx: ArrayVectorCopy::from_array([0xa5; 48]),
      tx: ArrayVectorCopy::from_array([0x5a; 32]),
    });
    let ptr = slot.as_mut_ptr();
    // SAFETY: the slot was initialized above and is not used as a value after the drop
    unsafe { ptr::drop_in_place(ptr) };
    // SAFETY: the fields of the slot, which stays allocated, still hold valid values
    let (rx, tx) = unsafe { (&(*ptr).rx, &(*ptr).tx) };
    for secret in [rx, tx] {
      // SAFETY: the array has room for 48 bytes, all of which the drop wrote
      let bytes = unsafe { slice::from_raw_parts(secret.as_ptr(), 48) };
      assert_eq!(bytes, [0; 48]);
    }
  }

  // The key schedule and the buffers of a handshake come from this thread's TLS pools and go
  // back there zeroed.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn handshake_state_zeroed_on_pool_return() {
    tls_pool::clear_thread_pools();
    STATE_POOL.with(|el| el.borrow_mut().clear());
    let (mut client, mut server) = (client(b"h3"), server());
    server.feed(Space::Initial, &client_out(&mut client, Space::Initial)).unwrap();
    let _secrets = finish_handshake(&mut client, &mut server);
    assert!(server.is_complete());
    let addrs = server.pooled_addrs();
    drop(client);
    drop(server);
    let (_, buffers) = tls_pool::last_pooled();
    assert_eq!(last_pooled_state(), Some((addrs[0], true)), "the state box");
    assert_eq!(buffers, Some([(addrs[1], true), (addrs[2], true)]), "the buffers");
    // The next handshake takes them again
    let mut again = self::server();
    assert_eq!(again.pooled_addrs(), addrs);
  }

  // Ruling T10-j: the random numbers of a handshake come from a seed of its pooled state, drawn
  // from the generator of the caller each time the state is taken: two handshakes in turn on the
  // same state box, from one generator, answer the same ClientHello with other randoms and key
  // shares, although the box came back zeroed in between.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn reused_states_draw_new_random_numbers() {
    tls_pool::clear_thread_pools();
    STATE_POOL.with(|el| el.borrow_mut().clear());
    let config = Arc::new(TlsConfig::from_keys_pem(_PUBLIC_KEY, _SECRET_KEY).unwrap());
    let mut parent = ChaCha20::from_key([3; 32]);
    let client_hello = client_out(&mut client(b"h3"), Space::Initial);
    let mut answers = Vec::new();
    let mut boxes = Vec::new();
    for _ in 0..2 {
      let mut server = Server::new(&config, SERVER_TP, &mut parent).unwrap();
      boxes.push(server.pooled_addrs()[0]);
      server.feed(Space::Initial, &client_hello).unwrap();
      let _secrets = secrets_of(&mut server);
      answers.push(server_out(&mut server, Space::Initial));
    }
    assert_eq!(boxes[0], boxes[1], "the same pooled state");
    // Handshake type, length, legacy version, then the random
    let (first, second) = (&answers[0], &answers[1]);
    assert_eq!(first.len(), second.len());
    assert_ne!(first[6..38], second[6..38], "the ServerHello randoms");
    assert_ne!(first[38..], second[38..], "the key shares");
  }

  // The last state box that this thread pooled, with whether every byte of it is zero.
  fn last_pooled_state() -> Option<(usize, bool)> {
    STATE_POOL.with(|pool| {
      let ptr = (&raw const **pool.borrow().last()?).cast::<u8>();
      // SAFETY: the bytes belong to the pooled box, every one of which was written with a zero
      // when it was pooled
      let bytes = unsafe { slice::from_raw_parts(ptr, size_of::<QuicTlsState>()) };
      Some((ptr.addr(), bytes.iter().all(|el| *el == 0)))
    })
  }

  // A state that is not zero anywhere it has a value, without a crypto backend.
  fn state_with_data() -> QuicTlsState {
    let key_schedule = KeySchedule::unset();
    let transcript_hash = key_schedule.cipher_suite().hash_new();
    QuicTlsState {
      alpn: ArrayVectorCopy::from_array(*b"h3"),
      buffer: TlsBuffer::new(),
      has_peer_transport_params: true,
      key_schedule,
      msg_start: 3,
      named_group: NamedGroup::default(),
      output_handshake: 5..9,
      output_initial: 1..5,
      rng_seed: [0x5a; 32],
      secrets_ready: 2,
      secrets_taken: 1,
      signature_algorithms: ArrayVectorCopy::new(),
      stage: Stage::Complete,
      stored_len: 7,
      transcript_hash,
    }
  }

  // A state box comes back zeroed, and is the next one's. No crypto backend is involved: Miri runs
  // this.
  #[test]
  fn state_box_comes_back_zeroed() {
    STATE_POOL.with(|el| el.borrow_mut().clear());
    let state = StateBox::new(state_with_data());
    let addr = (&raw const **state.0).addr();
    assert_eq!(state.stored_len, 7);
    drop(state);
    assert_eq!(last_pooled_state(), Some((addr, true)));
    let again = StateBox::new(state_with_data());
    assert_eq!((&raw const **again.0).addr(), addr);
    assert_eq!(again.output_initial, 1..5);
    assert!(STATE_POOL.with(|el| el.borrow().is_empty()));
  }
}
