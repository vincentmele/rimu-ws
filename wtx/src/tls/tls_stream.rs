use crate::{
  AFTER_CLOSE_TIMEOUT_MS,
  collections::{MaybeUninitSlice, ShortBoxSliceU16},
  futures::Sleep,
  net::{ConnectionState, Stream, StreamCommon, StreamReader, StreamWriter, TryRead},
  sync::{Arc, AtomicBool, AtomicU8, AtomicWaker},
  tls::{
    AlertDescription, AlertLevel, KsBox, RECORD_HEADER_LEN, TlsBuffer, TlsCtx, TlsError,
    TlsStreamBridge, TlsStreamReader, TlsStreamWriter,
    key_schedule::{KeySchedule, KeyScheduleWrite},
    misc::{
      manage_err_ad, manage_key_update, manage_user_canceled, read_after_handshake_data,
      seal_payloads, sealed_len, write_payloads,
    },
    protocol::{
      alert::Alert,
      key_update::{KeyUpdate, KeyUpdateRequest},
      new_session_ticket::NewSessionTicket,
    },
    record_content_ty::RecordContentTy,
    tls_stream_common::TlsStreamCommon,
  },
};
use alloc::{boxed::Box, vec::Vec};
use core::{
  future::poll_fn,
  hint::cold_path,
  marker::PhantomData,
  num::NonZeroUsize,
  pin::{Pin, pin},
  task::{Poll, ready},
  time::Duration,
};

/// Transport Layer Security (TLS)
///
/// This structure assumes a previously established handshake.
// `repr(C)` with the stream and its state first: they are all a plaintext stream touches per
// read or write, and in the compiler's order they sat at opposite ends of the struct. The other
// small fields follow them, filling what would be padding.
#[derive(Debug)]
#[repr(C)]
pub struct TlsStream<S, TCX, const IS_CLIENT: bool> {
  pub(crate) stream: S,
  pub(crate) connection_state: ConnectionState,
  pub(crate) can_reply_key_update: bool,
  pub(crate) key_updates: u8,
  pub(crate) warning_alerts: u8,
  // The kernel encrypts and decrypts this connection's records (see `kernel_tls`)
  pub(crate) kernel_tls: bool,
  // Reads left that may still hand the records to the kernel
  pub(crate) kernel_tls_tries: u8,
  pub(crate) max_fragment_length: u16,
  pub(crate) max_fragment_length_send: u16,
  pub(crate) phantom: PhantomData<TCX>,
  pub(crate) buffer: TlsBuffer,
  // Boxed: it is most of the stream's size, and a plaintext stream moves it without using it. The
  // box comes from, and goes back zeroed to, its thread's pool.
  pub(crate) key_schedule: KsBox,
  pub(crate) new_session_ticket: Option<NewSessionTicket<ShortBoxSliceU16<u8>>>,
  pub(crate) plaintext_consumed: usize,
  pub(crate) plaintext_len: usize,
  pub(crate) split_begin: usize,
  pub(crate) split_len: usize,
  // Created when first needed: after we sent a close notify and still read.
  pub(crate) timer: Option<Pin<Box<Sleep>>>,
}

impl<S, TCX, const IS_CLIENT: bool> TlsStream<S, TCX, IS_CLIENT>
where
  S: Stream,
  TCX: TlsCtx,
{
  /// Creates a new instance with a stream that supposedly already performed a handshake.
  #[inline]
  pub fn new(
    buffer: TlsBuffer,
    key_schedule: KeySchedule,
    max_fragment_length: u16,
    max_fragment_length_send: u16,
    stream: S,
  ) -> crate::Result<Self> {
    Self::new_boxed(
      buffer,
      KsBox::new(key_schedule),
      max_fragment_length,
      max_fragment_length_send,
      stream,
    )
  }

  #[inline]
  pub(crate) fn new_boxed(
    buffer: TlsBuffer,
    key_schedule: KsBox,
    max_fragment_length: u16,
    max_fragment_length_send: u16,
    stream: S,
  ) -> crate::Result<Self> {
    Ok(Self {
      buffer,
      can_reply_key_update: true,
      connection_state: ConnectionState::Open,
      kernel_tls: false,
      kernel_tls_tries: 0,
      key_schedule,
      key_updates: 0,
      max_fragment_length,
      max_fragment_length_send,
      new_session_ticket: None,
      phantom: PhantomData,
      plaintext_consumed: 0,
      plaintext_len: 0,
      split_begin: 0,
      split_len: 0,
      stream,
      timer: None,
      warning_alerts: 0,
    })
  }

  /// See [`ConnectionState`].
  #[inline]
  pub const fn connection_state(&self) -> ConnectionState {
    self.connection_state
  }

  /// Exports keying material
  #[inline]
  pub fn export_keying_material(
    &self,
    context: Option<&[u8]>,
    label: &[u8],
    output: &mut [u8],
  ) -> crate::Result<()> {
    KeySchedule::export_keying_material(
      self.key_schedule.cipher_suite(),
      context,
      self.key_schedule.exporter_secret(),
      label,
      output,
    )
  }

  /// Exports the read and write application traffic secrets.
  #[inline]
  pub fn export_traffic_secrets(&self) -> (&[u8], &[u8]) {
    (
      self.key_schedule.read().state().raw_traffic_secret(),
      self.key_schedule.write().state().raw_traffic_secret(),
    )
  }

  /// Returns the last received [`NewSessionTicket`], if any.
  ///
  /// NO-OP if `IS_CLIENT` is `false`.
  #[inline]
  pub const fn new_session_ticket(&self) -> &Option<NewSessionTicket<ShortBoxSliceU16<u8>>> {
    &self.new_session_ticket
  }

  /// Refreshes the connection's keys through the sending of a `KeyUpdate` record.
  #[inline]
  pub async fn refresh_traffic_keys(&mut self) -> crate::Result<()> {
    if self.kernel_tls {
      return Err(TlsError::KernelTlsKeyUpdate.into());
    }
    let key_update = KeyUpdate::new(KeyUpdateRequest::UpdateRequested);
    let kss = self.key_schedule.write_mut().state_mut();
    self.stream.write_all(&key_update.record_bytes(kss)?).await?;
    kss.rotate()?;
    Ok(())
  }

  /// Sends a warning alert of type `CloseNotify`, closing the connection.
  #[inline]
  pub async fn send_close_notify(&mut self) -> crate::Result<()> {
    #[cfg(all(feature = "libc", feature = "std", target_os = "linux"))]
    if self.kernel_tls {
      let alert = Alert::close_notify();
      self.stream.send_kernel_tls_alert(alert.level().into(), alert.description().into())?;
      self.connection_state = ConnectionState::WriteClosed;
      return Ok(());
    }
    self
      .stream
      .write_all(&Alert::close_notify().record_bytes(self.key_schedule.write_mut().state_mut())?)
      .await?;
    self.connection_state = ConnectionState::WriteClosed;
    Ok(())
  }

  /// References the inner stream responsible for sending and receiving data.
  #[inline]
  pub const fn stream(&self) -> &S {
    &self.stream
  }

  /// Mutable version of [`Self::stream`].
  #[inline]
  pub const fn stream_mut(&mut self) -> &mut S {
    &mut self.stream
  }

  /// Whether the kernel encrypts and decrypts this connection's records. See
  /// [`crate::tls::TlsConfig::kernel_tls`].
  #[inline]
  pub const fn is_kernel_tls(&self) -> bool {
    self.kernel_tls
  }

  /// A kernel TLS read met a record that isn't application data. A `close_notify` ends the stream
  /// as in user space, answered with one of ours; anything else ends the connection.
  #[cfg(all(feature = "libc", feature = "std", target_os = "linux"))]
  #[cold]
  fn kernel_tls_record(&mut self) -> crate::Result<Option<NonZeroUsize>> {
    use crate::tls::kernel_tls::{RECORD_ALERT, RECORD_HANDSHAKE};
    let mut buffer = [0; 256];
    let (ty, len) = self.stream.read_kernel_tls_record(&mut buffer)?;
    match (ty, buffer.get(..len).unwrap_or_default()) {
      (RECORD_ALERT, [level, description]) => {
        let alert = Alert::new((*level).try_into()?, (*description).try_into()?);
        if alert.level() == AlertLevel::Warning
          && alert.description() == AlertDescription::CloseNotify
        {
          if !self.connection_state.cannot_write() {
            let _rslt = self.stream.send_kernel_tls_alert(*level, *description);
          }
          self.connection_state = ConnectionState::ClosedGracefully;
          return Ok(None);
        }
        self.connection_state = ConnectionState::ClosedAbruptly;
        Err(TlsError::AbortedHandshake(alert).into())
      }
      (RECORD_HANDSHAKE, _) => {
        self.connection_state = ConnectionState::ClosedAbruptly;
        Err(TlsError::KernelTlsKeyUpdate.into())
      }
      _ => {
        self.connection_state = ConnectionState::ClosedAbruptly;
        Err(TlsError::InvalidAlert.into())
      }
    }
  }
}

impl<S, TCX, const IS_CLIENT: bool> TlsStream<S, TCX, IS_CLIENT>
where
  S: StreamCommon,
  TCX: TlsCtx,
{
  /// Hands the records to the kernel when it can take them: at a record boundary both ways, with
  /// nothing read past the records user space has decrypted and nothing user space encrypted still
  /// waiting to be sent. A client usually sends its first request right behind its `Finished`, and
  /// a reply waits to be sent right after it's written, so the switch is tried at the start of
  /// every read and write until it happens; a stream gives up after `KERNEL_TLS_TRIES` tries.
  #[cfg(all(feature = "libc", feature = "std", target_os = "linux"))]
  #[cold]
  #[inline(never)]
  pub(crate) fn try_kernel_tls(&mut self) -> crate::Result<()> {
    if TCX::TY.is_plain_text()
      || !matches!(self.connection_state, ConnectionState::Draining | ConnectionState::Open)
    {
      self.kernel_tls_tries = 0;
      return Ok(());
    }
    if !self.buffer.reader_buffer.following().is_empty()
      || self.plaintext_len > self.plaintext_consumed
    {
      return Ok(());
    }
    self.kernel_tls_tries = self.kernel_tls_tries.saturating_sub(1);
    let (read, write) = (self.key_schedule.read().state(), self.key_schedule.write().state());
    self.kernel_tls =
      self.stream.with_kernel_tls(|fd| crate::tls::kernel_tls::enable(fd, read, write))?;
    if self.kernel_tls {
      self.kernel_tls_tries = 0;
    }
    Ok(())
  }
}

impl<S, TCX, const IS_CLIENT: bool> Stream for TlsStream<S, TCX, IS_CLIENT>
where
  S: Stream,
  TCX: TlsCtx,
{
  type BridgeOwned = TlsStreamBridge<IS_CLIENT>;
  type ReadHalfOwned = TlsStreamReader<S::ReadHalfOwned, TCX, IS_CLIENT>;
  type WriteHalfOwned = TlsStreamWriter<S::WriteHalfOwned, TCX, IS_CLIENT>;

  #[inline]
  fn into_split(
    mut self,
  ) -> crate::Result<(Self::BridgeOwned, Self::ReadHalfOwned, Self::WriteHalfOwned)> {
    let stream_bridge = TlsStreamBridge::new();
    let exporter_secret = *self.key_schedule.exporter_secret();
    let (ksr, ksw) = self.key_schedule.into_inner().into_split();
    let (_, stream_reader, stream_writer) = self.stream.into_split()?;
    let common = Arc::new(TlsStreamCommon {
      can_reply_key_update: AtomicBool::new(self.can_reply_key_update),
      connection_state: AtomicU8::new(self.connection_state.into()),
      kernel_tls: self.kernel_tls,
      reader_waker: AtomicWaker::new(),
    });
    Ok((
      stream_bridge.clone(),
      TlsStreamReader::new(
        common.clone(),
        ksr,
        self.max_fragment_length,
        self.new_session_ticket,
        self.plaintext_consumed,
        self.plaintext_len,
        core::mem::take(&mut self.buffer.reader_buffer),
        stream_bridge,
        stream_reader,
      )?,
      TlsStreamWriter::new(
        common,
        exporter_secret,
        ksw,
        self.max_fragment_length_send,
        stream_writer,
        core::mem::take(&mut self.buffer.writer_buffer),
      ),
    ))
  }
}

impl<S, TCX, const IS_CLIENT: bool> StreamCommon for TlsStream<S, TCX, IS_CLIENT> {}

impl<S, TCX, const IS_CLIENT: bool> StreamReader for TlsStream<S, TCX, IS_CLIENT>
where
  S: Stream,
  TCX: TlsCtx,
{
  #[inline]
  async fn read(&mut self, bytes: MaybeUninitSlice<'_, u8>) -> crate::Result<Option<NonZeroUsize>> {
    // An open plaintext connection reads straight from the stream: `poll_pending_read` below only
    // ever passes `Pending` through for these states.
    if TCX::TY.is_plain_text()
      && matches!(self.connection_state, ConnectionState::Draining | ConnectionState::Open)
    {
      return self.stream.read(bytes).await;
    }
    // So does one whose records the kernel decrypts, but for the records that aren't data.
    #[cfg(all(feature = "libc", feature = "std", target_os = "linux"))]
    if self.kernel_tls_tries > 0 {
      self.try_kernel_tls()?;
    }
    #[cfg(all(feature = "libc", feature = "std", target_os = "linux"))]
    if self.kernel_tls {
      if self.connection_state.cannot_read() {
        return Ok(None);
      }
      return match self.stream.read(bytes).await {
        Err(err) if crate::tls::kernel_tls::is_record_error(&err) => self.kernel_tls_record(),
        rslt => rslt,
      };
    }
    let Self {
      buffer,
      can_reply_key_update,
      connection_state,
      kernel_tls: _,
      kernel_tls_tries: _,
      key_schedule,
      key_updates,
      max_fragment_length_send: _,
      max_fragment_length,
      new_session_ticket,
      phantom: _,
      plaintext_consumed,
      plaintext_len,
      split_begin,
      split_len,
      stream,
      timer,
      warning_alerts,
    } = self;
    let local_connection_state = *connection_state;
    // Kept apart from the record layer's future below, whose state plaintext reads never need.
    if TCX::TY.is_plain_text() {
      let mut read_fut = pin!(stream.read(bytes));
      return poll_fn(|cx| match read_fut.as_mut().poll(cx) {
        Poll::Ready(res) => Poll::Ready(res),
        Poll::Pending => poll_pending_read(local_connection_state, timer, cx),
      })
      .await;
    }
    let mut read_fut = pin!(async {
      if connection_state.cannot_read() {
        cold_path();
        return Ok(None);
      }
      let (ksr, ksw) = key_schedule.split_mut();
      let rslt = read_after_handshake_data::<_, _, IS_CLIENT>(
        Aux {
          connection_state: &mut *connection_state,
          can_reply_key_update,
          key_updates,
          ksw,
          warning_alerts,
        },
        bytes,
        ksr,
        *max_fragment_length,
        new_session_ticket,
        plaintext_consumed,
        plaintext_len,
        &mut buffer.reader_buffer,
        split_begin,
        split_len,
        stream,
        alert_cb,
        closed_conn_cb,
        key_update_cb,
        key_update_reset_cb,
      )
      .await;
      manage_err_ad(rslt, async |description| {
        let kss = key_schedule.write_mut().state_mut();
        stream.write_all(&Alert::fatal(description).record_bytes(kss)?[..]).await
      })
      .await
    });
    poll_fn(|cx| match read_fut.as_mut().poll(cx) {
      Poll::Ready(res) => Poll::Ready(res),
      Poll::Pending => poll_pending_read(local_connection_state, timer, cx),
    })
    .await
  }

  /// Plaintext forwards to the stream while open, as [`Self::read`] does; anything else reads
  /// records or tracks a closing connection, which only [`Self::read`] does.
  #[inline]
  fn try_read(&mut self, bytes: MaybeUninitSlice<'_, u8>) -> crate::Result<TryRead> {
    if TCX::TY.is_plain_text()
      && matches!(self.connection_state, ConnectionState::Draining | ConnectionState::Open)
    {
      return self.stream.try_read(bytes);
    }
    // A record that isn't data needs `read`, which is async.
    #[cfg(all(feature = "libc", feature = "std", target_os = "linux"))]
    if self.kernel_tls && !self.connection_state.cannot_read() {
      return match self.stream.try_read(bytes) {
        Err(err) if crate::tls::kernel_tls::is_record_error(&err) => Ok(TryRead::Unsupported),
        rslt => rslt,
      };
    }
    Ok(TryRead::Unsupported)
  }

  /// The stream's own: records the peer sent before it ended its side stay to be read, and nothing
  /// is decrypted meanwhile.
  #[inline]
  fn peer_ended(&mut self) -> impl Future<Output = crate::Result<()>> {
    self.stream.peer_ended()
  }

  /// The stream's own readiness, but ready at once when user space holds input the socket can't
  /// show: decrypted bytes not read yet, or a whole record read from the socket along with an
  /// earlier one (a `read` decrypts one record).
  #[inline]
  fn readable(&mut self) -> impl Future<Output = crate::Result<()>> {
    let buffered = !TCX::TY.is_plain_text() && !self.kernel_tls && self.has_buffered_input();
    let readable = self.stream.readable();
    async move {
      if buffered {
        return Ok(());
      }
      readable.await
    }
  }
}

impl<S, TCX, const IS_CLIENT: bool> StreamWriter for TlsStream<S, TCX, IS_CLIENT>
where
  S: StreamWriter,
  TCX: TlsCtx,
{
  #[inline]
  async fn write_all(&mut self, bytes: &[u8]) -> crate::Result<()> {
    if TCX::TY.is_plain_text() {
      return self.stream.write_all(bytes).await;
    }
    if self.connection_state.cannot_write() {
      cold_path();
      return Ok(());
    }
    #[cfg(all(feature = "libc", feature = "std", target_os = "linux"))]
    if self.kernel_tls_tries > 0 {
      self.try_kernel_tls()?;
    }
    if self.kernel_tls {
      return self.stream.write_all(bytes).await;
    }
    write_payloads(
      RecordContentTy::ApplicationData,
      self.key_schedule.write_mut(),
      self.max_fragment_length_send,
      &[bytes],
      &mut self.stream,
      &mut self.buffer.writer_buffer,
    )
    .await?;
    self.can_reply_key_update = true;
    Ok(())
  }

  #[inline]
  async fn write_all_vectored(&mut self, bytes: &[&[u8]]) -> crate::Result<()> {
    if TCX::TY.is_plain_text() {
      return self.stream.write_all_vectored(bytes).await;
    }
    if self.connection_state.cannot_write() {
      cold_path();
      return Ok(());
    }
    #[cfg(all(feature = "libc", feature = "std", target_os = "linux"))]
    if self.kernel_tls_tries > 0 {
      self.try_kernel_tls()?;
    }
    if self.kernel_tls {
      return self.stream.write_all_vectored(bytes).await;
    }
    write_payloads(
      RecordContentTy::ApplicationData,
      self.key_schedule.write_mut(),
      self.max_fragment_length_send,
      bytes,
      &mut self.stream,
      &mut self.buffer.writer_buffer,
    )
    .await?;
    self.can_reply_key_update = true;
    Ok(())
  }

  /// Plaintext and kernel TLS forward to the stream. User-space records are sealed straight into
  /// the buffer the stream sends them from (see [`StreamWriter::try_send_with`]).
  #[inline]
  fn try_write_all_vectored(&mut self, bytes: &[&[u8]]) -> crate::Result<bool> {
    #[cfg(all(feature = "libc", feature = "std", target_os = "linux"))]
    if self.kernel_tls_tries > 0 {
      self.try_kernel_tls()?;
    }
    if TCX::TY.is_plain_text() || (self.kernel_tls && !self.connection_state.cannot_write()) {
      return self.stream.try_write_all_vectored(bytes);
    }
    self.try_seal_and_send(bytes)
  }

  /// The stream's room: plaintext, kernel and user-space records all wait in its queue. A
  /// connection that can't write any more can't tell: its writes take the awaited path.
  #[inline]
  async fn send_room(&mut self) -> crate::Result<bool> {
    if self.connection_state.cannot_write() {
      return Ok(false);
    }
    self.stream.send_room().await
  }

  /// As [`Self::try_write_all_vectored`].
  #[inline]
  fn try_send_owned(&mut self, bytes: &mut Vec<u8>) -> crate::Result<bool> {
    #[cfg(all(feature = "libc", feature = "std", target_os = "linux"))]
    if self.kernel_tls_tries > 0 {
      self.try_kernel_tls()?;
    }
    if TCX::TY.is_plain_text() || (self.kernel_tls && !self.connection_state.cannot_write()) {
      return self.stream.try_send_owned(bytes);
    }
    if self.try_seal_and_send(&[bytes.as_slice()])? {
      bytes.clear();
      return Ok(true);
    }
    Ok(false)
  }
}

impl<S, TCX, const IS_CLIENT: bool> TlsStream<S, TCX, IS_CLIENT>
where
  S: StreamWriter,
  TCX: TlsCtx,
{
  /// Seals `bytes` into records written straight into the stream's send buffer, if the stream
  /// can take them now. `false` seals nothing.
  fn try_seal_and_send(&mut self, bytes: &[&[u8]]) -> crate::Result<bool> {
    if self.kernel_tls || self.connection_state.cannot_write() {
      return Ok(false);
    }
    let total_len = bytes.iter().map(|el| el.len()).sum();
    let len = sealed_len(total_len, self.max_fragment_length_send);
    let Self { key_schedule, max_fragment_length_send, stream, .. } = self;
    let ksw = key_schedule.write_mut();
    let sent = stream.try_send_with(len, &mut |records| {
      let ty = RecordContentTy::ApplicationData;
      seal_payloads(ty, ksw, *max_fragment_length_send, bytes, records)
    })?;
    if sent {
      self.can_reply_key_update = true;
    }
    Ok(sent)
  }
}

impl<S, TCX, const IS_CLIENT: bool> TlsStream<S, TCX, IS_CLIENT> {
  /// Decrypted bytes not read yet, or a whole record in the read buffer.
  fn has_buffered_input(&self) -> bool {
    if self.plaintext_len > self.plaintext_consumed {
      return true;
    }
    let following = self.buffer.reader_buffer.following();
    let Some([_, _, _, hi, lo]) = following.first_chunk::<RECORD_HEADER_LEN>() else {
      return false;
    };
    let body_len = usize::from(u16::from_be_bytes([*hi, *lo]));
    following.len() >= RECORD_HEADER_LEN.wrapping_add(body_len)
  }
}

/// What a pending read becomes given the state of the connection when the read started.
fn poll_pending_read(
  local_connection_state: ConnectionState,
  timer: &mut Option<Pin<Box<Sleep>>>,
  cx: &mut core::task::Context<'_>,
) -> Poll<crate::Result<Option<NonZeroUsize>>> {
  match local_connection_state {
    // Normal operation
    ConnectionState::Draining | ConnectionState::Open => Poll::Pending,
    // * An abrupt close signal was received/generated by us or the user abruptly closed
    // the connection.
    // * `ReadClosed` should be unreachable in sequential code.
    ConnectionState::ClosedAbruptly
    | ConnectionState::ClosedGracefully
    | ConnectionState::ReadClosed => {
      cold_path();
      Poll::Ready(Ok(None))
    }
    // Only called when the user sent a close notify and also decided to read data.
    ConnectionState::WriteClosed => {
      cold_path();
      let timer = match after_close_timer(timer) {
        Ok(elem) => elem,
        Err(err) => return Poll::Ready(Err(err)),
      };
      let _rslt = ready!(timer.as_mut().poll(cx));
      Poll::Ready(Ok(None))
    }
  }
}

/// The timer that bounds reads after a close notify was sent, started on first use.
pub(crate) fn after_close_timer(
  timer: &mut Option<Pin<Box<Sleep>>>,
) -> crate::Result<&mut Pin<Box<Sleep>>> {
  if let Some(elem) = timer {
    return Ok(elem);
  }
  Ok(timer.insert(Box::pin(Sleep::new(Duration::from_millis(AFTER_CLOSE_TIMEOUT_MS))?)))
}

async fn alert_cb<S>(aux: &mut Aux<'_>, alert: Alert, stream: &mut S) -> crate::Result<bool>
where
  S: Stream,
{
  match (alert.level(), alert.description()) {
    (AlertLevel::Warning, AlertDescription::CloseNotify) => {
      stream.write_all(&alert.record_bytes(aux.ksw.state_mut())?).await?;
      *aux.connection_state = ConnectionState::ClosedGracefully;
      Ok(true)
    }
    (AlertLevel::Warning, AlertDescription::UserCanceled) => {
      manage_user_canceled(aux.warning_alerts)
    }
    _ => Err(crate::Error::TlsErrorReply(TlsError::WrongAlert, AlertDescription::DecodeError)),
  }
}

// This branch is only entered when the peer closed the connection without an alert.
const fn closed_conn_cb(aux: &mut Aux<'_>) {
  *aux.connection_state = ConnectionState::ClosedAbruptly;
}

async fn key_update_cb<S>(
  aux: &mut Aux<'_>,
  key_update: Option<KeyUpdate>,
  stream: &mut S,
) -> crate::Result<()>
where
  S: StreamWriter,
{
  manage_key_update(aux.key_updates)?;
  let Some(elem) = key_update else {
    return Ok(());
  };
  if !*aux.can_reply_key_update {
    return Ok(());
  }
  let kss = aux.ksw.state_mut();
  let record = elem.record_bytes(kss)?;
  // The reply is queued and the write key rotated in one synchronous step: this future is
  // dropped when a user-space TLS read is given up, and a reply queued without the rotation would
  // have every later record sealed with the key the peer just replaced. Dropped while it waits for
  // room, neither happened.
  loop {
    if stream.try_write_all_vectored(&[&record])? {
      break;
    }
    if !stream.send_room().await? {
      // A stream that can only write by awaiting.
      stream.write_all(&record).await?;
      break;
    }
  }
  kss.rotate()?;
  *aux.can_reply_key_update = false;
  Ok(())
}

async fn key_update_reset_cb<S>(aux: &mut Aux<'_>, _stream: &mut S) -> crate::Result<()>
where
  S: Stream,
{
  *aux.key_updates = 0;
  Ok(())
}

struct Aux<'any> {
  can_reply_key_update: &'any mut bool,
  connection_state: &'any mut ConnectionState,
  key_updates: &'any mut u8,
  ksw: &'any mut KeyScheduleWrite,
  warning_alerts: &'any mut u8,
}

#[cfg(test)]
mod tests {
  use crate::{
    net::{ConnectionState, StreamCommon, StreamWriter},
    tls::{
      key_schedule::{KeySchedule, KeyScheduleWrite},
      protocol::{
        cipher_suite::CipherSuite,
        key_update::{KeyUpdate, KeyUpdateRequest},
      },
      tls_stream::{Aux, key_update_cb},
    },
  };
  use alloc::vec::Vec;
  use core::{
    future::{Future as _, pending},
    pin::pin,
    task::{Context, Poll, Waker},
  };

  /// A writer whose awaited writes queue their bytes and then never complete, whose room never
  /// comes, and whose synchronous writes queue only when `accept`.
  struct Queueing {
    accept: bool,
    queued: Vec<u8>,
  }

  impl StreamCommon for Queueing {}

  impl StreamWriter for Queueing {
    async fn write_all(&mut self, bytes: &[u8]) -> crate::Result<()> {
      self.queued.extend_from_slice(bytes);
      pending().await
    }

    async fn write_all_vectored(&mut self, bytes: &[&[u8]]) -> crate::Result<()> {
      for elem in bytes {
        self.queued.extend_from_slice(elem);
      }
      pending().await
    }

    fn try_write_all_vectored(&mut self, bytes: &[&[u8]]) -> crate::Result<bool> {
      if !self.accept {
        return Ok(false);
      }
      for elem in bytes {
        self.queued.extend_from_slice(elem);
      }
      Ok(true)
    }

    async fn send_room(&mut self) -> crate::Result<bool> {
      pending().await
    }
  }

  fn write_schedule() -> KeyScheduleWrite {
    let cipher_suite = CipherSuite::default();
    let mut key_schedule = KeySchedule::from_cipher_suite(cipher_suite);
    key_schedule.early_secret().unwrap();
    let digest = cipher_suite.hash_digest([&b"transcript"[..]]);
    key_schedule.handshake_secret::<false>(&[1; 32], &digest).unwrap();
    key_schedule.master_secret::<false>(&digest).unwrap();
    key_schedule.into_split().1
  }

  // A KeyUpdate reply is queued in the same step that rotates the write key: dropped before it is
  // queued (a user-space TLS read the driver gave up on) neither happened, so later records are
  // never sealed with a key the peer doesn't expect.
  #[test]
  fn key_update_reply_queued_with_its_rotation() {
    for accept in [false, true] {
      let mut ksw = write_schedule();
      let before = ksw.state().raw_traffic_secret().to_vec();
      let (mut can_reply, mut state, mut key_updates, mut warnings) =
        (true, ConnectionState::Open, 0, 0);
      let mut stream = Queueing { accept, queued: Vec::new() };
      {
        let mut aux = Aux {
          can_reply_key_update: &mut can_reply,
          connection_state: &mut state,
          key_updates: &mut key_updates,
          ksw: &mut ksw,
          warning_alerts: &mut warnings,
        };
        let reply = Some(KeyUpdate::new(KeyUpdateRequest::UpdateNotRequested));
        let fut = pin!(key_update_cb(&mut aux, reply, &mut stream));
        let _: Poll<_> = fut.poll(&mut Context::from_waker(Waker::noop()));
      }
      let rotated = ksw.state().raw_traffic_secret() != before.as_slice();
      assert_eq!(!stream.queued.is_empty(), rotated, "accept {accept}: queued without a rotation");
      assert_eq!(can_reply, !rotated, "accept {accept}");
    }
  }
}
