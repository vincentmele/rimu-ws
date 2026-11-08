use crate::{
  codec::{Decode as _, Encode as _},
  collections::{ArrayVectorCopy, SingleTypeStorage, VectorUsize},
  misc::Lease,
  net::{RoleTy, Stream},
  rng::CryptoRng,
  tls::{
    AlertDescription, Alpn, CHANGE_CIPHER_SPEC, CipherSuite, DLFT_MAX_FRAGMENT_LENGTH,
    HandshakePath, HandshakeTy, KsBox, MaxFragmentLength, NamedGroup, ProtocolVersion,
    RECORD_HEADER_LEN, SignatureScheme, TlsBuffer, TlsConfig, TlsCtx, TlsCtxSk, TlsError,
    TlsStream,
    key_schedule::KeySchedule,
    misc::{
      build_header, fetch_rec_from_stream, manage_err_handshake, post_handshake_dec_error,
      pre_handshake_dec_error, server_sig_msg, write_payloads,
    },
    protocol::{
      certificate::{Certificate, CertificateEntry},
      certificate_verify::CertificateVerify,
      client_hello::ClientHello,
      encrypted_extensions::EncryptedExtensions,
      finished::Finished,
      handshake::Handshake,
      key_share_entry::KeyShareEntry,
      server_hello::ServerHello,
    },
    read_record_info::ReadRecordInfo,
    record_content_ty::RecordContentTy,
    tls_cc_wrappers::{TlsDecodeWrapper, TlsEncodeWrapper},
    tls_hash::TlsHash,
  },
};
use core::ops::Range;

/// TLS Acceptor
///
/// Performs TLS handshakes for servers.
#[derive(Debug)]
pub struct TlsAcceptor<RNG, S, TCG> {
  buffer: TlsBuffer,
  config: TCG,
  handshake_path: HandshakePath,
  key_schedule: KsBox,
  max_fragment_length: u16,
  max_fragment_length_send: u16,
  named_group: NamedGroup,
  rng: RNG,
  signature_algorithms: ArrayVectorCopy<(SignatureScheme, u8), { SignatureScheme::len() }>,
  stream: S,
  transcript_hash: TlsHash,
}

impl<RNG, S, TCG, TCX> TlsAcceptor<RNG, S, TCG>
where
  TCG: Lease<TlsConfig<TCX>> + SingleTypeStorage<Item = TCX>,
  TCX: TlsCtx,
{
  /// The main parameters are provided by the user.
  #[inline]
  pub fn new(config: TCG, rng: RNG, stream: S) -> Self {
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
    let named_group = cfg_ref
      .inner
      .supported_groups
      .named_group_list
      .first()
      .copied()
      .unwrap_or(NamedGroup::default());
    let signature_algorithms = filter_signature_algorithms(cfg_ref);
    Self {
      buffer: TlsBuffer::pooled(),
      config,
      handshake_path: HandshakePath::Full,
      key_schedule,
      max_fragment_length,
      max_fragment_length_send,
      named_group,
      rng,
      signature_algorithms,
      stream,
      transcript_hash,
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
}

impl<RNG, S, TCG, TCX> TlsAcceptor<RNG, S, TCG>
where
  RNG: CryptoRng,
  S: Stream,
  TCG: Lease<TlsConfig<TCX>> + SingleTypeStorage<Item = TCX>,
  TCX: TlsCtxSk,
{
  /// High level operation that automatically performs a full asynchronous handshake.
  ///
  /// Low level operations must not be mixed with low level operations.
  #[inline]
  pub async fn accept(mut self) -> crate::Result<TlsAcceptOutput<RNG, S, TCX>> {
    if TCX::TY.is_plain_text() {
      return Ok(TlsAcceptOutput {
        handshake_path: self.handshake_path,
        named_group: self.named_group,
        rng: self.rng,
        tls_stream: TlsStream::new_boxed(
          self.buffer,
          self.key_schedule,
          self.max_fragment_length,
          self.max_fragment_length_send,
          self.stream,
        )?,
      });
    }
    _trace!("Start");
    let fut = async {
      let first_rri = self.fetch_rec_from_stream::<false, true>(false).await?;
      _trace!("Read ClientHello: {:?}", &first_rri);
      let indices = self.manage_initial_client_record(&first_rri)?;
      let buffer = self.buffer.reader_buffer.buffer_mut();
      let payloads = match indices.as_slice() {
        [idx0, idx1] => {
          &[buffer.get(*idx0..*idx1).unwrap_or_default(), buffer.get(*idx1..).unwrap_or_default()][..]
        }
        [idx0, idx1, idx2, idx3] => &[
          buffer.get(*idx0..*idx1).unwrap_or_default(),
          buffer.get(*idx1..*idx2).unwrap_or_default(),
          buffer.get(*idx2..*idx3).unwrap_or_default(),
          buffer.get(*idx3..).unwrap_or_default(),
        ],
        _ => &[],
      };
      _trace!("Write Records");
      write_payloads(
        RecordContentTy::Handshake,
        self.key_schedule.write_mut(),
        self.max_fragment_length_send,
        payloads,
        &mut self.stream,
        &mut self.buffer.writer_buffer,
      )
      .await?;
      buffer.truncate(indices.first().copied().unwrap_or_default());
      let mut last_rri = self.fetch_rec_from_stream::<true, false>(true).await?;
      if last_rri.outer_ty == RecordContentTy::ChangeCipherSpec {
        last_rri = self.fetch_rec_from_stream::<false, false>(true).await?;
      }
      _trace!("Read Finished: {:?}", &last_rri);
      self.manage_final_client_record(&last_rri)?;
      Ok(())
    };
    let rslt = fut.await;
    let kss = self.key_schedule.write_mut().state_mut();
    manage_err_handshake(true, kss, rslt, &mut self.stream).await?;
    _trace!("Successful handshake");
    #[cfg(all(feature = "libc", feature = "std", target_os = "linux"))]
    let kernel_tls = self.config.lease().inner.kernel_tls;
    #[cfg_attr(
      not(all(feature = "libc", feature = "std", target_os = "linux")),
      expect(unused_mut, reason = "only kernel TLS changes the stream")
    )]
    let mut tls_stream = TlsStream::new_boxed(
      self.buffer,
      self.key_schedule,
      self.max_fragment_length,
      self.max_fragment_length_send,
      self.stream,
    )?;
    // The switch happens at a later read or write if it can't happen now (see `try_kernel_tls`).
    #[cfg(all(feature = "libc", feature = "std", target_os = "linux"))]
    if kernel_tls {
      tls_stream.kernel_tls_tries = crate::tls::kernel_tls::KERNEL_TLS_TRIES;
      tls_stream.try_kernel_tls()?;
    }
    Ok(TlsAcceptOutput {
      handshake_path: self.handshake_path,
      named_group: self.named_group,
      rng: self.rng,
      tls_stream,
    })
  }

  /// Low level operation responsible for processing data sent by clients. No other method should
  /// be called before it.
  ///
  /// High level operations must not be mixed with low level operations.
  #[inline]
  pub fn manage_initial_client_record(
    &mut self,
    rri: &ReadRecordInfo,
  ) -> crate::Result<ArrayVectorCopy<usize, 4>> {
    let RecordContentTy::Handshake = rri.outer_ty else {
      return Err(TlsError::InvalidHandshakeTy.into());
    };
    let output = self.negotiate(rri)?;
    self.buffer.reader_buffer.clear_if_exhausted();
    write_server_flight(
      self.config.lease(),
      &mut self.key_schedule,
      output,
      self.buffer.reader_buffer.buffer_mut(),
      None,
      &mut self.rng,
      &mut self.transcript_hash,
    )
  }

  /// Low level operation responsible for processing data sent by clients. No other method should
  /// be called before it.
  ///
  /// High level operations must not be mixed with low level operations.
  #[inline]
  pub fn manage_final_client_record(&mut self, rri: &ReadRecordInfo) -> crate::Result<()> {
    let rslt = self.do_manage_final_client_record(rri);
    self.key_schedule.master_secret::<false>(&self.transcript_hash.clone().finalize())?;
    rslt
  }

  #[inline]
  fn do_manage_final_client_record(&mut self, rri: &ReadRecordInfo) -> crate::Result<()> {
    if rri.outer_ty != RecordContentTy::ApplicationData
      || rri.inner_ty != RecordContentTy::Handshake
    {
      return Err(TlsError::InvalidHandshakeTy.into());
    }
    let current = self.buffer.reader_buffer.current();
    let plaintext = current.get(..rri.plaintext_len).unwrap_or_default();
    verify_client_finished(&self.key_schedule, plaintext, &self.transcript_hash)
  }

  #[inline]
  async fn fetch_rec_from_stream<const CHECK_CCS: bool, const IS_CH: bool>(
    &mut self,
    decrypt: bool,
  ) -> crate::Result<ReadRecordInfo> {
    Ok(
      fetch_rec_from_stream::<_, CHECK_CCS, IS_CH>(
        decrypt.then(|| self.key_schedule.read_mut().state_mut()),
        self.max_fragment_length,
        &mut self.buffer.reader_buffer,
        &mut self.stream,
      )
      .await?
      .ok_or(TlsError::AbruptDisconnect)?,
    )
  }

  // The ServerHello goes in a record, followed by a ChangeCipherSpec (the middlebox compatibility
  // mode of TLS over TCP).
  #[inline]
  fn negotiate(&mut self, rri: &ReadRecordInfo) -> crate::Result<NegotiateOutput>
  where
    TCX: TlsCtx,
  {
    let current = self.buffer.reader_buffer.current();
    let plaintext = current.get(..rri.plaintext_len).unwrap_or_default();
    let writer_buffer = &mut self.buffer.writer_buffer;
    writer_buffer.clear();
    // The length is known once the ServerHello is written
    writer_buffer.extend_from_copyable_slice(&build_header(RecordContentTy::Handshake, 0))?;
    let output = negotiate_client_hello::<_, _, false>(
      plaintext,
      self.config.lease(),
      &mut self.key_schedule,
      (&mut self.max_fragment_length, &mut self.max_fragment_length_send),
      &mut self.named_group,
      writer_buffer,
      &mut self.rng,
      &self.signature_algorithms,
      &mut self.transcript_hash,
    )?;
    let len = u16::try_from(writer_buffer.len().wrapping_sub(RECORD_HEADER_LEN))?;
    if let Some(header) = writer_buffer.get_mut(..RECORD_HEADER_LEN) {
      header.copy_from_slice(&build_header(RecordContentTy::Handshake, len));
    }
    writer_buffer.extend_from_copyable_slice(&CHANGE_CIPHER_SPEC)?;
    Ok(output)
  }
}

/// Returned by [`TlsAcceptor::accept`].
#[derive(Debug)]
pub struct TlsAcceptOutput<RNG, S, TCX> {
  /// See [`HandshakePath`].
  pub handshake_path: HandshakePath,
  /// See [`NamedGroup`].
  pub named_group: NamedGroup,
  /// Random Number Generator
  pub rng: RNG,
  /// See [`TlsStream`]
  pub tls_stream: TlsStream<S, TCX, false>,
}

/// What a server takes from a ClientHello for the messages that follow its ServerHello. See
/// [`negotiate_client_hello`].
#[derive(Debug)]
pub(crate) struct NegotiateOutput {
  pub(crate) alpn: Option<Alpn>,
  pub(crate) max_fragment_length: Option<MaxFragmentLength>,
  /// QUIC only: where the data of the `quic_transport_parameters` extension lies in the
  /// ClientHello message.
  #[cfg_attr(not(feature = "quic"), expect(dead_code, reason = "only QUIC reads it"))]
  pub(crate) quic_transport_parameters: Range<usize>,
  pub(crate) signature_scheme: (SignatureScheme, u8),
}

/// Negotiates with the ClientHello `client_hello` (one handshake message, header included, and
/// nothing else), writes the ServerHello handshake message at the end of `out` and derives the
/// handshake secrets: what TLS over records and QUIC (RFC 9001) do alike with a ClientHello.
///
/// `IS_QUIC` (RFC 9001 section 8): the ClientHello must carry the transport parameters of the
/// client and offer the ALPN `h3`, the only protocol negotiated, and its `max_fragment_length` is
/// ignored, QUIC packets are no records. Otherwise a `max_fragment_length` of the client lowers
/// `max_fragment_length` and `max_fragment_length_send`, the limits of the records received and
/// sent.
#[inline]
pub(crate) fn negotiate_client_hello<RNG, TCX, const IS_QUIC: bool>(
  client_hello: &[u8],
  config: &TlsConfig<TCX>,
  key_schedule: &mut KeySchedule,
  (max_fragment_length, max_fragment_length_send): (&mut u16, &mut u16),
  named_group: &mut NamedGroup,
  out: &mut VectorUsize<u8>,
  rng: &mut RNG,
  signature_algorithms: &[(SignatureScheme, u8)],
  transcript_hash: &mut TlsHash,
) -> crate::Result<NegotiateOutput>
where
  RNG: CryptoRng,
  TCX: TlsCtx,
{
  let mut dw = TlsDecodeWrapper::from_bytes(client_hello);
  let handshake = Handshake::<&[u8]>::decode(&mut dw)?;
  *dw.bytes_mut() = handshake.data;
  pre_handshake_dec_error(handshake.rec_len() != client_hello.len())?;
  let ch = ClientHello::decode(&mut dw)?;
  post_handshake_dec_error(dw.bytes(), HandshakeTy::ClientHello)?;
  if !ch.supported_versions().versions.iter().copied().any(|el| el == ProtocolVersion::Tls13) {
    return Err(
      TlsError::UnsupportedTlsVersion(ch.supported_versions().versions.last().copied()).into(),
    );
  }
  let quic_transport_parameters = if IS_QUIC {
    let Some(elem) = ch.quic_transport_parameters() else {
      return Err(crate::Error::TlsErrorReply(
        TlsError::MissingQuicTransportParameters,
        AlertDescription::MissingExtension,
      ));
    };
    let begin = elem.as_ptr().addr().wrapping_sub(client_hello.as_ptr().addr());
    begin..begin.wrapping_add(elem.len())
  } else {
    0..0
  };
  let cipher_suite =
    seek_cipher_suite(&ch.tls_config().cipher_suites, &config.inner.cipher_suites)?;
  key_schedule.set_cipher_suite(cipher_suite);
  key_schedule.early_secret()?;
  *transcript_hash = cipher_suite.hash_new();
  transcript_hash.update(client_hello);
  let key_share =
    seek_key_share(&ch.generic().client_shares, &config.inner.supported_groups.named_group_list)?;
  let alpn = if IS_QUIC {
    let mut h3 = Alpn::default();
    h3.protocol_name_list.push(ArrayVectorCopy::from_array(*b"h3"))?;
    let Some(elem) = seek_alpn(&ch.tls_config().alpn, &Some(h3))? else {
      return Err(crate::Error::TlsErrorReply(
        TlsError::MissingAlpn,
        AlertDescription::NoApplicationProtocol,
      ));
    };
    Some(elem)
  } else {
    seek_alpn(&ch.tls_config().alpn, &config.inner.alpn)?
  };
  *named_group = key_share.group();

  let client_max_fragment_length = if IS_QUIC { None } else { ch.tls_config().max_fragment_length };
  if let Some(client_mfg) = client_max_fragment_length {
    let client_num = client_mfg.num();
    if let Some(server_mfl) = config.max_fragment_length()
      && client_num > server_mfl.num()
    {
      return Err(TlsError::InvalidNegotiatedMaxFragmentLength.into());
    }
    *max_fragment_length = client_num;
    *max_fragment_length_send = (*max_fragment_length_send).min(client_num);
  }
  let Some(signature_scheme) = seek_signature_scheme(
    &ch.tls_config().signature_algorithms.signature_schemes,
    signature_algorithms,
  ) else {
    return Err(crate::Error::TlsErrorReply(
      TlsError::ServerHasNoCompatibleSignatureScheme,
      AlertDescription::HandshakeFailure,
    ));
  };
  let legacy_session_id = *ch.legacy_session_id();
  let agreement = key_share.group().agreement(rng)?;
  let ephemeral_pk = agreement.public_key()?;
  let secret = agreement.diffie_hellman::<false>(key_share.opaque())?;
  let begin = out.len();
  let server_hello = Handshake::new(
    HandshakeTy::ServerHello,
    ServerHello::new(
      cipher_suite,
      false,
      KeyShareEntry::new(key_share.group(), ephemeral_pk.as_ref()),
      legacy_session_id,
      rng,
    ),
  );
  server_hello.encode(&mut TlsEncodeWrapper::from_buffer(out))?;
  transcript_hash.update(out.get(begin..).unwrap_or_default());
  key_schedule.handshake_secret::<false>(secret.as_ref(), &transcript_hash.clone().finalize())?;
  Ok(NegotiateOutput {
    alpn,
    max_fragment_length: client_max_fragment_length,
    quic_transport_parameters,
    signature_scheme,
  })
}

/// Writes the EncryptedExtensions, Certificate, CertificateVerify and Finished messages of a
/// server at the end of `out`, after [`negotiate_client_hello`], and returns where each of them
/// begins. `quic_transport_parameters` are those of the server, in QUIC.
#[inline]
pub(crate) fn write_server_flight<RNG, TCX>(
  config: &TlsConfig<TCX>,
  key_schedule: &mut KeySchedule,
  negotiation: NegotiateOutput,
  out: &mut VectorUsize<u8>,
  quic_transport_parameters: Option<&[u8]>,
  rng: &mut RNG,
  transcript_hash: &mut TlsHash,
) -> crate::Result<ArrayVectorCopy<usize, 4>>
where
  RNG: CryptoRng,
  TCX: TlsCtxSk,
{
  let mut curr_idx = out.len();
  let mut indices = ArrayVectorCopy::new();
  let encrypted_extensions = Handshake::new(
    HandshakeTy::EncryptedExtensions,
    EncryptedExtensions::new(
      negotiation.alpn,
      negotiation.max_fragment_length,
      quic_transport_parameters,
      None,
      None,
    ),
  );
  encrypted_extensions.encode(&mut TlsEncodeWrapper::from_buffer(out))?;
  transcript_hash.update(out.get(curr_idx..).unwrap_or_default());
  drop(indices.push(curr_idx));
  curr_idx = out.len();
  drop(indices.push(curr_idx));
  let mut cert_list = ArrayVectorCopy::new();
  let Some(public_key) = config.public_keys().get(negotiation.signature_scheme.1) else {
    return Err(TlsError::UnsupportedSignAlgorithm.into());
  };
  for cert in public_key.certs() {
    cert_list.push(CertificateEntry::new(cert))?;
  }
  {
    let ty = HandshakeTy::Certificate;
    let certificate = Handshake::new(ty, Certificate::new(cert_list, &[]));
    certificate.encode(&mut TlsEncodeWrapper::from_buffer(out))?;
    transcript_hash.update(out.get(curr_idx..).unwrap_or_default());
    curr_idx = out.len();
    let _rslt = indices.push(curr_idx);
  }
  let signature;
  let signature_ref = if TCX::TY.is_unverified() {
    &[][..]
  } else {
    signature = config.inner.ctx.sign(
      &server_sig_msg(transcript_hash.clone().finalize().lease())?,
      rng,
      negotiation.signature_scheme.0,
    )?;
    signature.as_ref()
  };
  {
    let certificate_verify = Handshake::new(
      HandshakeTy::CertificateVerify,
      CertificateVerify::new(negotiation.signature_scheme.0, signature_ref),
    );
    certificate_verify.encode(&mut TlsEncodeWrapper::from_buffer(out))?;
    transcript_hash.update(out.get(curr_idx..).unwrap_or_default());
    curr_idx = out.len();
    let _rslt = indices.push(curr_idx);
  }
  let verify_data = key_schedule
    .write_mut()
    .state_mut()
    .create_finished_verify_data(transcript_hash.clone().finalize().lease())?;
  let finished = Handshake::new(HandshakeTy::Finished, Finished::new(verify_data.as_slice()));
  finished.encode(&mut TlsEncodeWrapper::from_buffer(out))?;
  transcript_hash.update(out.get(curr_idx..).unwrap_or_default());
  Ok(indices)
}

/// Verifies that `plaintext` begins with the Finished of the client and holds nothing else.
#[inline]
pub(crate) fn verify_client_finished(
  key_schedule: &KeySchedule,
  plaintext: &[u8],
  transcript_hash: &TlsHash,
) -> crate::Result<()> {
  let mut dw = TlsDecodeWrapper::from_bytes(plaintext);
  let hs = Handshake::<&[u8]>::decode(&mut dw)?;
  if hs.msg_type != HandshakeTy::Finished {
    return Err(crate::Error::TlsErrorReply(
      TlsError::ClientExpectedFinished,
      AlertDescription::UnexpectedMessage,
    ));
  }
  let trailing_len = dw.bytes().len();
  *dw.bytes_mut() = hs.data;
  *dw.cipher_suite_mut() = key_schedule.cipher_suite();
  let finished = Finished::decode(&mut dw)?;
  post_handshake_dec_error(dw.bytes(), HandshakeTy::Finished)?;
  if key_schedule
    .read()
    .state()
    .verify_finished_record(transcript_hash.clone().finalize().lease(), finished.verify_data())
    .is_err()
  {
    return Err(TlsError::DigestCheckFailed.into());
  }
  if trailing_len > 0 {
    return Err(crate::Error::TlsErrorReply(
      TlsError::ExcessHandshakeData(RoleTy::Server),
      AlertDescription::UnexpectedMessage,
    ));
  }
  Ok(())
}

/// The set of supported signature algorithms depend on the provided certificates
#[inline]
pub(crate) fn filter_signature_algorithms<TCX>(
  cfg_ref: &TlsConfig<TCX>,
) -> ArrayVectorCopy<(SignatureScheme, u8), { SignatureScheme::len() }> {
  let mut rslt = ArrayVectorCopy::new();
  let mut local_signature_schemes = cfg_ref.signature_algorithms().signature_schemes;
  let mut key_tys_idx: u8 = 0;
  for cert_kt in cfg_ref.public_keys().key_tys() {
    let mut idx = 0;
    while idx < local_signature_schemes.len() {
      let Some(local_signature_scheme) = local_signature_schemes.get(usize::from(idx)) else {
        break;
      };
      if !local_signature_scheme.is_rsa_pkcs1() && local_signature_scheme.cert_kt() == cert_kt {
        drop(rslt.push((*local_signature_scheme, key_tys_idx)));
        let _ = local_signature_schemes.swap_remove(idx);
        if cfg_ref.unique_signature_algorithms() {
          break;
        }
      } else {
        idx = idx.wrapping_add(1);
      }
    }
    key_tys_idx = key_tys_idx.wrapping_add(1);
  }
  rslt
}

#[inline]
fn seek_alpn(client_opt: &Option<Alpn>, server_opt: &Option<Alpn>) -> crate::Result<Option<Alpn>> {
  let (Some(client), Some(server)) = (client_opt, server_opt) else {
    return Ok(None);
  };
  if server.protocol_name_list.is_empty() {
    return Err(crate::Error::TlsErrorReply(
      TlsError::EmptyNegotiatedAlpnServer,
      AlertDescription::InternalError,
    ));
  }
  let mut rslt = None;
  for client_el in &client.protocol_name_list {
    if client_el.is_empty() {
      return Err(crate::Error::TlsErrorReply(
        TlsError::EmptyNegotiatedAlpnClient,
        AlertDescription::DecodeError,
      ));
    }
    if rslt.is_none() && server.protocol_name_list.contains(client_el) {
      let mut alpn = Alpn::default();
      let _rslt = alpn.protocol_name_list.push(*client_el);
      rslt = Some(alpn);
    }
  }
  if let Some(elem) = rslt {
    Ok(Some(elem))
  } else {
    Err(crate::Error::TlsErrorReply(
      TlsError::MismatchedNegotiatedAlpnServer,
      AlertDescription::NoApplicationProtocol,
    ))
  }
}

#[inline]
fn seek_cipher_suite(client: &[CipherSuite], server: &[CipherSuite]) -> crate::Result<CipherSuite> {
  for elem in server {
    if client.contains(elem) {
      return Ok(*elem);
    }
  }
  Err(TlsError::ServerHasNoCompatibleCypherSuite.into())
}

#[inline]
fn seek_key_share<'client, 'rslt, 'server>(
  client: &'client [KeyShareEntry<&'client [u8]>],
  server: &'server [NamedGroup],
) -> crate::Result<KeyShareEntry<&'rslt [u8]>>
where
  'client: 'rslt,
  'server: 'rslt,
{
  for server_el in server {
    let Some(client_el) = client.iter().find(|client_el| client_el.group() == *server_el) else {
      continue;
    };
    return Ok(*client_el);
  }
  Err(crate::Error::TlsErrorReply(
    TlsError::ServerHasNoCompatibleKeyShare,
    AlertDescription::UnexpectedMessage,
  ))
}

#[inline]
fn seek_signature_scheme(
  client_signature_schemes: &[SignatureScheme],
  server_signature_schemes: &[(SignatureScheme, u8)],
) -> Option<(SignatureScheme, u8)> {
  for (server_signature_scheme, idx) in server_signature_schemes {
    if !client_signature_schemes.contains(server_signature_scheme) {
      continue;
    }
    return Some((*server_signature_scheme, *idx));
  }
  None
}

#[cfg(all(test, feature = "std"))]
mod tests {
  use crate::{
    codec::Encode as _,
    collections::{ArrayVectorU8, VectorUsize},
    net::{BytesStream, StreamWriter as _},
    rng::{ChaCha20, CryptoSeedableRng as _},
    tests::{_PUBLIC_KEY, _SECRET_KEY},
    tls::{
      CHANGE_CIPHER_SPEC, HandshakeTy, NamedGroup, ProtocolVersion, TlsAcceptor, TlsConfig,
      protocol::{
        client_hello::ClientHello, handshake::Handshake, named_group::NamedGroupAgreement,
        record::Record,
      },
      record_content_ty::RecordContentTy,
      tls_cc_wrappers::TlsEncodeWrapper,
    },
  };
  use core::{
    pin::pin,
    task::{Context, Poll, Waker},
  };

  fn ready<F>(fut: F) -> F::Output
  where
    F: Future,
  {
    let Poll::Ready(elem) = pin!(fut).poll(&mut Context::from_waker(Waker::noop())) else {
      panic!("an in-memory stream is always ready");
    };
    elem
  }

  fn message_len(bytes: &[u8]) -> usize {
    4 + usize::from(bytes[1]) * 65536 + usize::from(bytes[2]) * 256 + usize::from(bytes[3])
  }

  // The record path keeps its framing now that QUIC shares the handshake messages: the
  // ServerHello alone in a record followed by a ChangeCipherSpec, then EncryptedExtensions,
  // Certificate, CertificateVerify and Finished, whole and back to back, where the indices say.
  // The rest of the record path is what the TLS, HTTP/1.1, HTTP/2 and WebSocket tests cover.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn record_path_tls_tests_unchanged() {
    let mut rng = ChaCha20::from_std_random().unwrap();
    let client_config = TlsConfig::unverified();
    let mut secrets = ArrayVectorU8::<NamedGroupAgreement, { NamedGroup::len() }>::new();
    for group in &client_config.supported_groups().named_group_list {
      secrets.push(group.agreement(&mut rng).unwrap()).unwrap();
    }
    let mut record = VectorUsize::new();
    let client_hello = ClientHello::new(&secrets, &mut rng, &client_config);
    Record::new(
      RecordContentTy::Handshake,
      ProtocolVersion::Tls1,
      Handshake::new(HandshakeTy::ClientHello, client_hello),
    )
    .encode(&mut TlsEncodeWrapper::from_buffer(&mut record))
    .unwrap();
    let mut stream = BytesStream::default();
    ready(stream.write_all(&record)).unwrap();
    let config = TlsConfig::from_keys_pem(_PUBLIC_KEY, _SECRET_KEY).unwrap();
    let mut acceptor = TlsAcceptor::new(&config, &mut rng, stream);
    let rri = ready(acceptor.fetch_rec_from_stream::<false, true>(false)).unwrap();
    let indices = acceptor.manage_initial_client_record(&rri).unwrap();
    let out = acceptor.buffer.writer_buffer.as_slice();
    let record_len = usize::from(u16::from_be_bytes([out[3], out[4]]));
    assert_eq!(out[..3], [22, 3, 3]);
    assert_eq!((out[5], message_len(&out[5..])), (2, record_len));
    assert_eq!(&out[5 + record_len..], &CHANGE_CIPHER_SPEC);
    let flight = acceptor.buffer.reader_buffer.buffer_mut().as_slice();
    let mut ends = indices.iter().skip(1).copied().chain([flight.len()]);
    for (idx, ty) in indices.iter().copied().zip([8, 11, 15, 20]) {
      assert_eq!(flight[idx], ty);
      assert_eq!(idx + message_len(&flight[idx..]), ends.next().unwrap());
    }
  }
}
