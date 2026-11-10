use crate::{
  asn1::Asn1DecodeWrapperAux,
  codec::{Decode as _, Encode as _},
  collections::{ArrayVectorCopy, ArrayVectorU8, SingleTypeStorage},
  misc::Lease,
  net::{BufStreamReader, RoleTy, Stream, Uri},
  rng::CryptoRng,
  tls::{
    AlertDescription, CHANGE_CIPHER_SPEC, DLFT_MAX_FRAGMENT_LENGTH, HandshakePath, HandshakeTy,
    KsBox, MAX_CERTIFICATES, NamedGroup, ProtocolVersion, RECORD_HEADER_LEN, TlsBuffer, TlsConfig,
    TlsCtx, TlsError, TlsServerEndPoint, TlsStream,
    key_schedule::KeySchedule,
    misc::{
      fetch_rec_from_stream, handshake_bytes_adjust, handshake_bytes_decode, manage_err_handshake,
      post_handshake_dec_error, pre_handshake_dec_error, server_sig_msg,
    },
    protocol::{
      alert::Alert, certificate::Certificate, certificate_request::CertificateRequest,
      certificate_verify::CertificateVerify, client_hello::ClientHello,
      encrypted_extensions::EncryptedExtensions, finished::Finished, handshake::Handshake,
      named_group::NamedGroupAgreement, record::Record, server_hello::ServerHello,
    },
    read_record_info::ReadRecordInfo,
    record_content_ty::RecordContentTy,
    tls_cc_wrappers::{TlsDecodeWrapper, TlsEncodeWrapper},
    tls_hash::{TlsDigest, TlsHash},
  },
  x509::{CvEndEntity, CvIntermediate, KeyTy, ServerName, SignatureTy, SubjectPublicKeyInfo},
};
use core::ops::Range;

/// Returned by [`TlsConnector::manage_client_records`].
#[derive(Debug, PartialEq)]
pub enum ClientRecordsState {
  /// Finished processing client records
  Terminated(ArrayVectorCopy<u8, { 6 + 30 + 74 }>),
}

/// Returned by [`TlsConnector::manage_remaining_server_records`].
#[derive(Debug, PartialEq)]
pub enum ServerRecordsState<T> {
  /// Received an alert that requires a connection termination.
  Alert(Alert),
  /// It is necessary to fetch more external data
  NeedsMoreData,
  /// Finished processing server records
  Terminated(T),
}

/// Required by [`TlsConnector::manage_remaining_server_records`].
#[derive(Debug)]
pub struct ManageRemainingServerRecordsInput {
  certificate_kt: KeyTy,
  client_cert_requested: bool,
  has_certificate_verify: bool,
  has_certificate: bool,
  spki_range: Range<usize>,
  tls_server_end_point: TlsServerEndPoint,
  transcript_digest: TlsDigest,
}

impl ManageRemainingServerRecordsInput {
  /// If the server asked for a certificate of the client.
  #[cfg(all(feature = "quic", any(test, feature = "_h3-loopback-client")))]
  pub(crate) const fn client_cert_requested(&self) -> bool {
    self.client_cert_requested
  }
}

/// TLS Connector
///
/// Performs TLS handshakes for clients.
#[derive(Debug)]
pub struct TlsConnector<RNG, S, TCG, U> {
  buffer: TlsBuffer,
  config: TCG,
  handshake_path: HandshakePath,
  has_sent_ccs: bool,
  hash_leaf_cert: bool,
  key_schedule: KsBox,
  max_fragment_length_send: u16,
  max_fragment_length: u16,
  named_group: NamedGroup,
  rng: RNG,
  split_begin: usize,
  split_len: usize,
  stream: S,
  transcript_hash: TlsHash,
  uri: U,
}

impl<RNG, S, STR, TCG, TCX, U> TlsConnector<RNG, S, TCG, U>
where
  STR: Lease<str>,
  TCG: Lease<TlsConfig<TCX>> + SingleTypeStorage<Item = TCX>,
  TCX: TlsCtx,
  U: Lease<Uri<STR>> + SingleTypeStorage<Item = STR>,
{
  /// It is preferable to construct instances through the builder.
  #[inline]
  pub fn new(config: TCG, rng: RNG, stream: S, uri: U) -> Self {
    let cfg_ref = config.lease();
    let key_schedule = KsBox::new(if TCX::TY.is_plain_text() {
      KeySchedule::unset()
    } else {
      KeySchedule::default()
    });
    let transcript_hash = key_schedule.cipher_suite().hash_new();
    let max_fragment_length =
      cfg_ref.max_fragment_length().map_or(DLFT_MAX_FRAGMENT_LENGTH, |el| el.num());
    let max_fragment_length_send =
      cfg_ref.max_fragment_length_send().map_or(DLFT_MAX_FRAGMENT_LENGTH, |el| el.num());
    let named_group = cfg_ref.inner.supported_groups.named_group_list.first().copied();
    Self {
      buffer: TlsBuffer::new(),
      config,
      handshake_path: HandshakePath::Full,
      has_sent_ccs: false,
      hash_leaf_cert: false,
      key_schedule,
      max_fragment_length_send,
      max_fragment_length,
      named_group: named_group.unwrap_or(NamedGroup::default()),
      rng,
      split_begin: 0,
      split_len: 0,
      stream,
      transcript_hash,
      uri,
    }
  }

  /// The current handshake path. See [`HandshakePath`].
  #[inline]
  pub const fn handshake_path(&self) -> HandshakePath {
    self.handshake_path
  }

  /// The current signature algorithm. See [`NamedGroup`].
  #[inline]
  pub const fn named_group(&self) -> NamedGroup {
    self.named_group
  }

  /// Random Number Generator
  #[inline]
  pub const fn rng(&self) -> &RNG {
    &self.rng
  }

  /// Mutable version of [`Self::rng`].
  #[inline]
  pub const fn rng_mut(&mut self) -> &mut RNG {
    &mut self.rng
  }

  /// Underlying stream
  #[inline]
  pub const fn stream(&self) -> &S {
    &self.stream
  }

  /// Mutable version of [`Self::stream`].
  #[inline]
  pub const fn stream_mut(&mut self) -> &mut S {
    &mut self.stream
  }
}

impl<RNG, S, STR, TCG, TCX, U> TlsConnector<RNG, S, TCG, U>
where
  RNG: CryptoRng,
  S: Stream,
  STR: Lease<str>,
  TCG: Lease<TlsConfig<TCX>> + SingleTypeStorage<Item = TCX>,
  TCX: TlsCtx,
  U: Lease<Uri<STR>> + SingleTypeStorage<Item = STR>,
{
  /// High level operation that automatically performs a full asynchronous handshake.
  ///
  /// Low level operations must not be mixed with high level operations.
  #[inline]
  pub async fn connect(mut self) -> crate::Result<TlsConnectOutput<RNG, S, TCX, U>> {
    if TCX::TY.is_plain_text() {
      return Ok(TlsConnectOutput {
        handshake_path: self.handshake_path,
        named_group: self.named_group,
        rng: self.rng,
        server_end_point: TlsServerEndPoint::new(),
        tls_stream: TlsStream::new_boxed(
          self.buffer,
          self.key_schedule,
          self.max_fragment_length,
          self.max_fragment_length_send,
          self.stream,
        )?,
        uri: self.uri,
      });
    }

    let fut = async {
      let mut secrets = self.write_client_hello()?;
      self.stream.write_all(&self.buffer.writer_buffer).await?;
      let mut rri = self.fetch_rec_from_stream::<false>(false).await?;
      let mut mrsri = loop {
        match self.manage_initial_server_record(&rri, &mut secrets)? {
          ServerRecordsState::Alert(alert) => {
            self.write_alert(alert).await?;
            return Err(TlsError::AbortedHandshake(alert).into());
          }
          ServerRecordsState::NeedsMoreData => {
            rri = self.fetch_rec_from_stream::<false>(false).await?;
          }
          ServerRecordsState::Terminated(el) => break el,
        }
      };
      self.buffer.writer_buffer.clear();
      rri = self.fetch_rec_from_stream::<true>(true).await?;
      loop {
        match self.manage_remaining_server_records(&mut mrsri, &rri)? {
          ServerRecordsState::Alert(alert) => {
            self.write_alert(alert).await?;
            return Err(TlsError::AbortedHandshake(alert).into());
          }
          ServerRecordsState::NeedsMoreData => {
            rri = self.fetch_rec_from_stream::<false>(true).await?;
          }
          ServerRecordsState::Terminated(_) => break,
        }
      }
      match self.manage_client_records(&mrsri)? {
        ClientRecordsState::Terminated(data) => {
          _trace!("Write Finished");
          self.stream.write_all(&data).await?;
        }
      }
      Ok(mrsri.tls_server_end_point)
    };
    let rslt = fut.await;
    let kss = self.key_schedule.write_mut().state_mut();
    let tls_server_end_point =
      manage_err_handshake(self.has_sent_ccs, kss, rslt, &mut self.stream).await?;
    _trace!("Successful handshake");
    Ok(TlsConnectOutput {
      handshake_path: self.handshake_path,
      named_group: self.named_group,
      rng: self.rng,
      server_end_point: tls_server_end_point,
      tls_stream: TlsStream::new_boxed(
        self.buffer,
        self.key_schedule,
        self.max_fragment_length,
        self.max_fragment_length_send,
        self.stream,
      )?,
      uri: self.uri,
    })
  }

  /// If the leaf certificate received by clients should be hashed using the signature's hash.
  /// Mostly used in SCRAM scenarios with channel binding.
  #[inline]
  pub const fn hash_leaf_cert(&self) -> bool {
    self.hash_leaf_cert
  }

  /// Mutable version of [`Self::hash_leaf_cert`].
  #[inline]
  pub const fn hash_leaf_cert_mut(&mut self) -> &mut bool {
    &mut self.hash_leaf_cert
  }

  /// Low level operation that must be called after [`Self::manage_remaining_server_records`].
  ///
  /// High level operations must not be mixed with low level operations.
  #[inline]
  pub fn manage_client_records(
    &mut self,
    mrsri: &ManageRemainingServerRecordsInput,
  ) -> crate::Result<ClientRecordsState> {
    *self.buffer.reader_buffer.forbid_clear_mut() = false;
    self.buffer.reader_buffer.clear_if_exhausted();
    let ch_transcript = self.transcript_hash.clone();
    let mut empty_cert = ArrayVectorCopy::<u8, 30>::new();
    if mrsri.client_cert_requested {
      let unencrypted_msg = [HandshakeTy::Certificate.into(), 0, 0, 4, 0, 0, 0, 0];
      self.transcript_hash.update(&unencrypted_msg);
      let payload_len: u8 = 25;
      let header = [RecordContentTy::ApplicationData.into(), 3, 3, 0, payload_len];
      let mut encrypted = ArrayVectorCopy::<u8, { 4 + 4 + 1 }>::new();
      let _ = encrypted.extend_from_copyable_slices([
        &unencrypted_msg[..],
        &[RecordContentTy::Handshake.into()],
      ])?;
      let kss = self.key_schedule.write_mut().state_mut();
      let tag = kss.seal_record(&header, &mut encrypted)?;
      let _ = empty_cert.extend_from_copyable_slices([header.as_slice(), &encrypted, &tag])?;
    }
    let (_, ksw) = self.key_schedule.split_mut();
    let verify_data = ksw
      .state_mut()
      .create_finished_verify_data(self.transcript_hash.clone().finalize().lease())?;
    let finished = Finished::record_bytes(&verify_data, ksw.state_mut())?;
    self.key_schedule.master_secret::<true>(&ch_transcript.finalize())?;
    let mut terminated = ArrayVectorCopy::new();
    let array = [&CHANGE_CIPHER_SPEC[..], &empty_cert, &finished];
    let _ = terminated.extend_from_copyable_slices(array)?;
    self.has_sent_ccs = true;
    Ok(ClientRecordsState::Terminated(terminated))
  }

  /// Low level operation that must be called after [`Self::write_client_hello`].
  ///
  /// High level operations must not be mixed with low level operations.
  #[inline]
  pub fn manage_initial_server_record(
    &mut self,
    rri: &ReadRecordInfo,
    secrets: &mut ArrayVectorU8<NamedGroupAgreement, { NamedGroup::len() }>,
  ) -> crate::Result<ServerRecordsState<ManageRemainingServerRecordsInput>> {
    match rri.outer_ty {
      RecordContentTy::Alert => return alert(&self.buffer.reader_buffer, rri),
      RecordContentTy::Handshake => {}
      RecordContentTy::ApplicationData | RecordContentTy::ChangeCipherSpec => {
        return Err(TlsError::InvalidHandshakeTy.into());
      }
    }
    handshake_bytes_adjust(
      &mut self.buffer.reader_buffer,
      rri,
      (&mut self.split_begin, &mut self.split_len),
    );
    let Some((msg_type, range, mut dw)) = handshake_bytes_decode(
      &self.buffer.reader_buffer,
      (&mut self.split_begin, &mut self.split_len),
    )?
    else {
      return Ok(ServerRecordsState::NeedsMoreData);
    };
    if msg_type != HandshakeTy::ServerHello {
      return Err(TlsError::InvalidHandshakeTy.into());
    }
    pre_handshake_dec_error(self.split_len > 0)?;
    let mrsri = manage_server_hello(
      self.buffer.writer_buffer.get(RECORD_HEADER_LEN..).unwrap_or_default(),
      &mut dw,
      &mut self.key_schedule,
      &mut self.named_group,
      secrets,
      self.buffer.reader_buffer.filled().get(range).unwrap_or_default(),
      &mut self.transcript_hash,
    )?;
    self.split_begin = 0;
    self.split_len = 0;
    *self.buffer.reader_buffer.forbid_clear_mut() = false;
    self.buffer.reader_buffer.clear_if_exhausted();
    *self.buffer.reader_buffer.forbid_clear_mut() = true;
    Ok(ServerRecordsState::Terminated(mrsri))
  }

  /// Low level operation that must be called after [`Self::manage_initial_server_record`].
  ///
  /// High level operations must not be mixed with low level operations.
  #[inline]
  pub fn manage_remaining_server_records(
    &mut self,
    mrsri: &mut ManageRemainingServerRecordsInput,
    rri: &ReadRecordInfo,
  ) -> crate::Result<ServerRecordsState<()>> {
    match rri.inner_ty {
      RecordContentTy::Alert => return alert(&self.buffer.reader_buffer, rri),
      RecordContentTy::ApplicationData => return Err(TlsError::InvalidHandshakeTy.into()),
      RecordContentTy::ChangeCipherSpec => {
        return Ok(ServerRecordsState::NeedsMoreData);
      }
      RecordContentTy::Handshake => {}
    }
    handshake_bytes_adjust(
      &mut self.buffer.reader_buffer,
      rri,
      (&mut self.split_begin, &mut self.split_len),
    );
    let rec_end = self.split_begin.wrapping_add(rri.plaintext_len);
    while let Some((msg_type, range, mut dw)) = handshake_bytes_decode(
      &self.buffer.reader_buffer,
      (&mut self.split_begin, &mut self.split_len),
    )? {
      _trace!("Read handshake: {:?}", msg_type);
      let filled = self.buffer.reader_buffer.filled();
      let is_finished = manage_server_flight_msg(
        self.config.lease(),
        &mut dw,
        &mut None,
        self.split_begin < rec_end,
        filled,
        self.hash_leaf_cert,
        self.uri.lease().hostname(),
        &mut self.key_schedule,
        (&mut self.max_fragment_length, &mut self.max_fragment_length_send),
        mrsri,
        filled.get(range).unwrap_or_default(),
        msg_type,
        &mut self.transcript_hash,
      )?;
      if is_finished {
        return Ok(ServerRecordsState::Terminated(()));
      }
    }
    Ok(ServerRecordsState::NeedsMoreData)
  }

  /// Low level operation responsible for informing the local parameters to the remote server. No other method should
  /// be called before it.
  ///
  /// High level operations must not be mixed with low level operations.
  #[inline]
  pub fn write_client_hello(
    &mut self,
  ) -> crate::Result<ArrayVectorU8<NamedGroupAgreement, { NamedGroup::len() }>> {
    _trace!("Write CH");
    let mut secrets = ArrayVectorU8::new();
    for named_group in &self.config.lease().inner.supported_groups.named_group_list {
      secrets.push(named_group.agreement(&mut self.rng)?)?;
    }
    let handshake = Handshake::new(
      HandshakeTy::ClientHello,
      ClientHello::new(&secrets, &mut self.rng, self.config.lease()),
    );
    let record = Record::new(RecordContentTy::Handshake, ProtocolVersion::Tls1, &handshake);
    self.buffer.writer_buffer.clear();
    record.encode(&mut TlsEncodeWrapper::from_buffer(&mut self.buffer.writer_buffer))?;
    *self.buffer.reader_buffer.forbid_clear_mut() = true;
    Ok(secrets)
  }

  #[inline]
  async fn fetch_rec_from_stream<const CHECK_CCS: bool>(
    &mut self,
    decrypt: bool,
  ) -> crate::Result<ReadRecordInfo> {
    Ok(
      fetch_rec_from_stream::<_, CHECK_CCS, false>(
        decrypt.then(|| self.key_schedule.read_mut().state_mut()),
        self.max_fragment_length,
        &mut self.buffer.reader_buffer,
        &mut self.stream,
      )
      .await?
      .ok_or(TlsError::AbruptDisconnect)?,
    )
  }

  #[inline]
  async fn write_alert(&mut self, alert: Alert) -> crate::Result<()> {
    if !alert.is_close_notify() {
      return Ok(());
    }
    let kss = self.key_schedule.write_mut().state_mut();
    if kss.cipher_key().is_empty() {
      self.stream.write_all(&alert.record_bytes_unencrypted()).await?;
    } else {
      self.stream.write_all(&alert.record_bytes(kss)?).await?;
    }
    Ok(())
  }
}

/// Returned by [`TlsConnector::connect`].
#[derive(Debug)]
pub struct TlsConnectOutput<RNG, S, TCX, U> {
  /// See [`HandshakePath`].
  pub handshake_path: HandshakePath,
  /// See [`NamedGroup`].
  pub named_group: NamedGroup,
  /// Random Number Generator
  pub rng: RNG,
  /// See [`TlsServerEndPoint`]
  pub server_end_point: TlsServerEndPoint,
  /// See [`TlsStream`]
  pub tls_stream: TlsStream<S, TCX, true>,
  /// Uri
  pub uri: U,
}

/// Takes the ServerHello whose body is in `dw` and whose whole message is `server_hello`, with
/// `client_hello`, the ClientHello message of this client, and derives the handshake secrets: what
/// TLS over records and QUIC (RFC 9001) do alike with a ServerHello.
#[inline]
pub(crate) fn manage_server_hello(
  client_hello: &[u8],
  dw: &mut TlsDecodeWrapper<'_>,
  key_schedule: &mut KeySchedule,
  named_group: &mut NamedGroup,
  secrets: &mut ArrayVectorU8<NamedGroupAgreement, { NamedGroup::len() }>,
  server_hello: &[u8],
  transcript_hash: &mut TlsHash,
) -> crate::Result<ManageRemainingServerRecordsInput> {
  let sh = ServerHello::<'_>::decode(dw)?;
  post_handshake_dec_error(dw.bytes(), HandshakeTy::ServerHello)?;
  let secret_idx = secrets
    .iter_mut()
    .position(|el| el.named_group() == sh.key_share().group())
    .ok_or(TlsError::SecretMismatch)?;
  let Some(secret) = secrets.swap_remove(secret_idx.try_into()?) else {
    return Err(TlsError::SecretMismatch.into());
  };
  *named_group = secret.named_group();
  {
    key_schedule.set_cipher_suite(sh.cipher_suite());
    key_schedule.early_secret()?;
  }
  let shared_secret = secret.diffie_hellman::<true>(sh.key_share().opaque())?;
  *transcript_hash = key_schedule.cipher_suite().hash_new();
  transcript_hash.update(client_hello);
  transcript_hash.update(server_hello);
  key_schedule
    .handshake_secret::<true>(shared_secret.as_ref(), &transcript_hash.clone().finalize())?;
  Ok(ManageRemainingServerRecordsInput {
    certificate_kt: KeyTy::default(),
    client_cert_requested: false,
    has_certificate: false,
    has_certificate_verify: false,
    spki_range: 0..0,
    tls_server_end_point: TlsServerEndPoint::new(),
    transcript_digest: TlsDigest::default(),
  })
}

/// Takes one handshake message of the flight that a server sends after its ServerHello: `msg` is
/// the whole message, which lies in `filled`, and `dw` its body. Returns whether it was the
/// Finished, which ends the flight, after which `excess` tells whether more handshake bytes came.
/// What TLS over records and QUIC (RFC 9001) do alike with each of these messages.
///
/// An EncryptedExtensions is left in `encrypted_extensions`, for what QUIC takes from it.
#[inline]
pub(crate) fn manage_server_flight_msg<'de, TCX>(
  config: &TlsConfig<TCX>,
  dw: &mut TlsDecodeWrapper<'de>,
  encrypted_extensions: &mut Option<EncryptedExtensions<'de>>,
  excess: bool,
  filled: &[u8],
  hash_leaf_cert: bool,
  hostname: &str,
  key_schedule: &mut KeySchedule,
  (max_fragment_length, max_fragment_length_send): (&mut u16, &mut u16),
  mrsri: &mut ManageRemainingServerRecordsInput,
  msg: &[u8],
  msg_type: HandshakeTy,
  transcript_hash: &mut TlsHash,
) -> crate::Result<bool>
where
  TCX: TlsCtx,
{
  transcript_hash.update(msg);
  match msg_type {
    HandshakeTy::EncryptedExtensions => {
      *encrypted_extensions = Some(manage_encrypted_extensions(
        config,
        dw,
        max_fragment_length,
        max_fragment_length_send,
      )?);
    }
    HandshakeTy::CertificateRequest => {
      let cr = CertificateRequest::decode(dw)?;
      post_handshake_dec_error(dw.bytes(), HandshakeTy::CertificateRequest)?;
      let mut filtered = cr.signature_algorithms.signature_schemes;
      filtered.clear();
      let mut has_rsa_pkcs1 = false;
      for elem in cr.signature_algorithms.signature_schemes {
        if elem.is_rsa_pkcs1() {
          has_rsa_pkcs1 = true;
          continue;
        }
        filtered.push(elem)?;
      }
      if has_rsa_pkcs1 && filtered.is_empty() {
        return Err(crate::Error::TlsErrorReply(
          TlsError::UsageOfDeprecatedPKCS1,
          AlertDescription::HandshakeFailure,
        ));
      }
      mrsri.client_cert_requested = true;
    }
    HandshakeTy::Certificate => {
      manage_certificate(config, filled, hash_leaf_cert, hostname, mrsri, dw, transcript_hash)?;
      mrsri.has_certificate = true;
    }
    HandshakeTy::CertificateVerify => {
      manage_certificate_verify(filled, mrsri, dw)?;
      mrsri.has_certificate_verify = true;
      mrsri.transcript_digest = transcript_hash.clone().finalize();
    }
    HandshakeTy::Finished => {
      if !mrsri.has_certificate || !mrsri.has_certificate_verify {
        return Err(crate::Error::TlsErrorReply(
          TlsError::IncompleteHandshake,
          AlertDescription::UnexpectedMessage,
        ));
      }
      manage_finished(dw, excess, key_schedule, mrsri)?;
      return Ok(true);
    }
    HandshakeTy::ClientHello
    | HandshakeTy::EndOfEarlyData
    | HandshakeTy::KeyUpdate
    | HandshakeTy::MessageHash
    | HandshakeTy::NewSessionTicket
    | HandshakeTy::ServerHello => {
      return Err(TlsError::InvalidHandshakeTy.into());
    }
  }
  Ok(false)
}

fn check_alpn<TCX>(config: &TlsConfig<TCX>, ee: &EncryptedExtensions<'_>) -> Option<crate::Error> {
  match (config.lease().alpn(), ee.alpn()) {
    (None, Some(_)) => Some(crate::Error::TlsErrorReply(
      TlsError::UnofferedExtension,
      AlertDescription::UnsupportedExtension,
    )),
    (Some(client), Some(server)) => {
      for server_el in &server.protocol_name_list {
        if server_el.is_empty() {
          return Some(crate::Error::TlsErrorReply(
            TlsError::EmptyNegotiatedAlpnClient,
            AlertDescription::IllegalParameter,
          ));
        }
        if client.protocol_name_list.iter().find(|el| *el == server_el).is_none() {
          return Some(crate::Error::TlsErrorReply(
            TlsError::MismatchedNegotiatedAlpnClient,
            AlertDescription::IllegalParameter,
          ));
        }
      }
      None
    }
    _ => None,
  }
}

fn manage_certificate<TCX>(
  config: &TlsConfig<TCX>,
  filled: &[u8],
  hash_leaf_cert: bool,
  hostname: &str,
  mrsri: &mut ManageRemainingServerRecordsInput,
  remote_dw: &mut TlsDecodeWrapper<'_>,
  transcript_hash: &TlsHash,
) -> crate::Result<()>
where
  TCX: TlsCtx,
{
  let certificate = Certificate::decode(remote_dw)?;
  post_handshake_dec_error(remote_dw.bytes(), HandshakeTy::Certificate)?;
  let [end_entity, intermediates @ ..] = certificate.certificate_list().as_slice() else {
    return Err(TlsError::NoCertificate.into());
  };
  let cv_end_entity = {
    let mut dw = crate::codec::DecodeWrapper::new(
      end_entity.certificate_bytes(),
      Asn1DecodeWrapperAux::default(),
    );
    let cert = crate::x509::Certificate::decode(&mut dw).map_err(|_err| {
      crate::Error::TlsErrorReply(TlsError::InvalidX509, AlertDescription::DecodeError)
    })?;
    mrsri.certificate_kt = KeyTy::try_from(&cert)?;
    let filled_ptr = filled.as_ptr().addr();
    let certificate_bytes_ptr = end_entity.certificate_bytes().as_ptr().addr();
    let offset = certificate_bytes_ptr.wrapping_sub(filled_ptr);
    mrsri.spki_range = dw.decode_aux.spki_range();
    mrsri.spki_range.start = mrsri.spki_range.start.wrapping_add(offset);
    mrsri.spki_range.end = mrsri.spki_range.end.wrapping_add(offset);
    let sig = dw.decode_aux.tbs_cert(end_entity.certificate_bytes()).unwrap_or_default();
    CvEndEntity::from_certificate(cert, sig)?
  };
  if let Some(ku) = &cv_end_entity.key_usage
    && !ku.digital_signature()
  {
    return Err(TlsError::MissingDigitalSignatureInKeyUsage.into());
  }
  if hash_leaf_cert {
    SignatureTy::try_from(&cv_end_entity.signature_algorithm)?
      .hash_ty()
      .digest([end_entity.certificate_bytes()], |bytes| {
        mrsri.tls_server_end_point.extend_from_copyable_slice(bytes)
      })?;
  }
  if !TCX::TY.is_unverified() {
    if let Some(sn_list) = &config.inner.server_name {
      let [sn] = sn_list.server_name_list.as_inner()?;
      let server_name = ServerName::from_domain(sn.name().as_bytes());
      cv_end_entity.validate_subject_name([server_name])?;
    } else {
      let server_name = ServerName::from_ascii_bytes(hostname.as_bytes())?;
      cv_end_entity.validate_subject_name([server_name])?;
    }
  }
  let mut cv_intermediates = ArrayVectorU8::<_, MAX_CERTIFICATES>::new();
  for intermediate in intermediates {
    let cv_intermediate = {
      let mut local_dw = crate::codec::DecodeWrapper::new(
        intermediate.certificate_bytes(),
        Asn1DecodeWrapperAux::default(),
      );
      CvIntermediate::from_certificate(
        crate::x509::Certificate::decode(&mut local_dw)?,
        local_dw.decode_aux.tbs_cert(intermediate.certificate_bytes()).unwrap_or_default(),
      )?
    };
    cv_intermediates.push(cv_intermediate)?;
  }
  mrsri.transcript_digest = transcript_hash.clone().finalize();
  if TCX::TY.is_unverified() {
    return Ok(());
  }
  let mut cv_policy = config.cv_policy().map(|el| el);
  *cv_policy.extended_key_usage_mut().server_auth_mut() = true;
  drop(cv_end_entity.validate_chain(
    cv_intermediates.as_slice(),
    &cv_policy,
    config.trust_anchors(),
  )?);
  Ok(())
}

fn manage_certificate_verify(
  filled: &[u8],
  mrsri: &mut ManageRemainingServerRecordsInput,
  remote_dw: &mut TlsDecodeWrapper<'_>,
) -> crate::Result<()> {
  let certificate_verify = CertificateVerify::decode(remote_dw)?;
  post_handshake_dec_error(remote_dw.bytes(), HandshakeTy::CertificateVerify)?;
  let msg = server_sig_msg(mrsri.transcript_digest.lease())?;
  let spki = &SubjectPublicKeyInfo::<&[u8]>::decode(&mut crate::codec::DecodeWrapper::new(
    filled.get(mrsri.spki_range.clone()).unwrap_or_default(),
    Asn1DecodeWrapperAux::default(),
  ))?;
  if mrsri.certificate_kt != certificate_verify.algorithm().cert_kt() {
    return Err(TlsError::MismatchedCertificatePkAndSignature.into());
  }
  if certificate_verify
    .algorithm()
    .handshake_st()
    .validate_signature(
      &msg,
      spki.subject_public_key.bytes().lease(),
      certificate_verify.signature(),
    )
    .is_err()
  {
    return Err(TlsError::BadSignature.into());
  }
  Ok(())
}

fn manage_encrypted_extensions<'de, TCX>(
  config: &TlsConfig<TCX>,
  dw: &mut TlsDecodeWrapper<'de>,
  max_fragment_length: &mut u16,
  max_fragment_length_send: &mut u16,
) -> crate::Result<EncryptedExtensions<'de>> {
  let ee = EncryptedExtensions::decode(dw)?;
  post_handshake_dec_error(dw.bytes(), HandshakeTy::EncryptedExtensions)?;
  if let Some(err) = check_alpn(config, &ee) {
    return Err(err);
  }
  if let Some(el) = ee.max_fragment_length() {
    if Some(el) != config.max_fragment_length() {
      return Err(TlsError::InvalidNegotiatedMaxFragmentLength.into());
    }
    *max_fragment_length = el.num();
    *max_fragment_length_send = el.num().min(*max_fragment_length_send);
  } else if config.max_fragment_length().is_some() {
    return Err(TlsError::InvalidNegotiatedMaxFragmentLength.into());
  }
  if let Some(_server) = ee.server_name() {
    let Some(_client) = config.server_name() else {
      return Err(crate::Error::TlsErrorReply(
        TlsError::InvalidNegotiatedServerName,
        AlertDescription::UnsupportedExtension,
      ));
    };
  }
  Ok(ee)
}

fn manage_finished(
  dw: &mut TlsDecodeWrapper<'_>,
  excess: bool,
  key_schedule: &mut KeySchedule,
  mrsri: &mut ManageRemainingServerRecordsInput,
) -> crate::Result<()> {
  *dw.cipher_suite_mut() = key_schedule.cipher_suite();
  let finished = Finished::decode(dw)?;
  post_handshake_dec_error(dw.bytes(), HandshakeTy::Finished)?;
  if key_schedule
    .read_mut()
    .state_mut()
    .verify_finished_record(mrsri.transcript_digest.lease(), finished.verify_data())
    .is_err()
  {
    return Err(TlsError::DigestCheckFailed.into());
  }
  if excess {
    return Err(crate::Error::TlsErrorReply(
      TlsError::ExcessHandshakeData(RoleTy::Client),
      AlertDescription::UnexpectedMessage,
    ));
  }
  Ok(())
}

#[inline]
fn alert<T>(
  reader_buffer: &BufStreamReader,
  rri: &ReadRecordInfo,
) -> crate::Result<ServerRecordsState<T>> {
  let plaintext = reader_buffer.current().get(..rri.plaintext_len).unwrap_or_default();
  let dw = &mut TlsDecodeWrapper::from_bytes(plaintext);
  Ok(ServerRecordsState::Alert(Alert::decode(dw)?))
}

#[cfg(test)]
mod tests {
  use super::check_alpn;
  use alloc::vec::Vec;
  use crate::{
    codec::Decode,
    collections::ArrayVectorCopy,
    tls::{
      Alpn, TlsConfig, TlsError,
      protocol::encrypted_extensions::EncryptedExtensions,
      tls_cc_wrappers::TlsDecodeWrapper,
    },
  };

  fn alpn(names: &[&[u8]]) -> Alpn {
    let mut rslt = Alpn::default();
    for name in names {
      rslt.protocol_name_list.push(ArrayVectorCopy::try_from(*name).unwrap()).unwrap();
    }
    rslt
  }

  // The bytes of an EncryptedExtensions that selects `names`.
  fn encrypted_extensions(names: &[&[u8]]) -> Vec<u8> {
    let mut list = Vec::new();
    for name in names {
      list.push(u8::try_from(name.len()).unwrap());
      list.extend_from_slice(name);
    }
    let mut ext = Vec::from(0x0010u16.to_be_bytes());
    ext.extend_from_slice(&u16::try_from(list.len() + 2).unwrap().to_be_bytes());
    ext.extend_from_slice(&u16::try_from(list.len()).unwrap().to_be_bytes());
    ext.extend(list);
    let mut rslt = u16::try_from(ext.len()).unwrap().to_be_bytes().to_vec();
    rslt.extend(ext);
    rslt
  }

  // Rule (RFC 7301 section 3.1, review I-1): the selection of the server must be one name that
  // the client offered, whatever its length: the client reads it strictly.
  #[test]
  fn selection_that_was_not_offered_is_illegal_parameter() {
    let mut config = TlsConfig::from_trust_anchors_pem([crate::tests::_ROOT_CA]).unwrap();
    *config.alpn_mut() = Some(alpn(&[b"h2", b"http/1.1"]));
    let selects = |names: &[&[u8]]| {
      let bytes = encrypted_extensions(names);
      let ee = EncryptedExtensions::decode(&mut TlsDecodeWrapper::from_bytes(&bytes)).unwrap();
      check_alpn(&config, &ee)
    };
    assert!(selects(&[b"h2"]).is_none());
    assert!(matches!(
      selects(&[b"h3"]),
      Some(crate::Error::TlsErrorReply(TlsError::MismatchedNegotiatedAlpnClient, _))
    ));
    assert!(matches!(
      selects(&[b""]),
      Some(crate::Error::TlsErrorReply(TlsError::EmptyNegotiatedAlpnClient, _))
    ));
    // A name longer than any that can be offered is not decoded as an empty list that passes
    let bytes = encrypted_extensions(&[b"hq-interop"]);
    assert!(EncryptedExtensions::decode(&mut TlsDecodeWrapper::from_bytes(&bytes)).is_err());
  }
}
