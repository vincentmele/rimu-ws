use crate::{
  collections::VectorUsize,
  misc::{Lease, LeaseMut},
  net::{NetError, StreamReader},
};
use core::{fmt::Debug, hint::cold_path, mem::MaybeUninit};

/// Buffered stream reader
///
/// ```txt
/// Antecedent | Current | Following | Trailing | Unallocated |
///            |         |           |          |             |
///            |         |           |          |             |-> capacity_ub
///            |         |           |          |
///            |         |           |          |---------------> buffer.capacity()
///            |         |           |
///            |         |           |--------------------------> buffer.len()
///            |         |
///            |         |--------------------------------------> current_end_idx
///            |
///            |------------------------------------------------> antecedent_end_idx
/// ```
pub struct BufStreamReader {
  antecedent_end_idx: usize,
  buffer: VectorUsize<u8>,
  capacity_ub: usize,
  current_end_idx: usize,
  forbid_clear: bool,
}

impl BufStreamReader {
  /// Empty instance with a default upper bound capacity
  #[inline]
  pub const fn new() -> Self {
    Self {
      antecedent_end_idx: 0,
      buffer: VectorUsize::new(),
      capacity_ub: 1024 * 1024 * 32,
      current_end_idx: 0,
      forbid_clear: false,
    }
  }

  /// [`Self::new`] reading into `buffer`, emptied first.
  #[cfg(feature = "tls")]
  #[inline]
  pub(crate) fn with_buffer(mut buffer: VectorUsize<u8>) -> Self {
    buffer.clear();
    Self { buffer, ..Self::new() }
  }

  /// Takes the internal buffer out, leaving an empty one and nothing to read.
  #[cfg(feature = "tls")]
  #[inline]
  pub(crate) fn take_buffer(&mut self) -> VectorUsize<u8> {
    self.antecedent_end_idx = 0;
    self.current_end_idx = 0;
    core::mem::take(&mut self.buffer)
  }

  /// The antecedent (already consumed) region.
  #[inline]
  pub fn antecedent(&self) -> &[u8] {
    let range = 0..self.antecedent_end_idx;
    // SAFETY: All methods ensure that `antecedent_end_idx` will never be greater than
    //         the buffer's length
    unsafe { self.buffer.get(range).unwrap_unchecked() }
  }

  /// The end index of the antecedent (already consumed) region.
  #[inline]
  pub const fn antecedent_end_idx(&self) -> usize {
    self.antecedent_end_idx
  }

  /// Capacity Upper Bound
  ///
  /// The maximum buffer's length.
  #[inline]
  pub const fn capacity_ub(&self) -> usize {
    self.capacity_ub
  }

  /// Clears the internal buffer if all fetched data has been fully consumed. In other words,
  /// if [`Self::following`] is empty.
  ///
  /// NO-OP if [`Self::forbid_clear`] is `true`.
  #[inline]
  pub fn clear_if_exhausted(&mut self) {
    if self.current_end_idx == self.buffer.len() {
      self.clear();
    }
  }

  /// The current readable region.
  #[inline]
  pub fn current(&self) -> &[u8] {
    let range = self.antecedent_end_idx..self.current_end_idx;
    // SAFETY: All methods ensure that `antecedent_end_idx` and `current_end_idx`
    //         will never be greater than the buffer's length
    unsafe { self.buffer.get(range).unwrap_unchecked() }
  }

  /// Mutable version of [`Self::current`].
  #[inline]
  pub fn current_mut(&mut self) -> &mut [u8] {
    let range = self.antecedent_end_idx..self.current_end_idx;
    // SAFETY: All methods ensure that `antecedent_end_idx` and `current_end_idx`
    //         will never be greater than the buffer's length
    unsafe { self.buffer.get_mut(range).unwrap_unchecked() }
  }

  /// The end index of the current readable region.
  #[inline]
  pub const fn current_end_idx(&self) -> usize {
    self.current_end_idx
  }

  /// The entire internal buffer as a slice.
  #[inline]
  pub fn filled(&self) -> &[u8] {
    &self.buffer
  }

  /// Mutable version of [`Self::filled`].
  #[inline]
  pub fn filled_mut(&mut self) -> &mut [u8] {
    &mut self.buffer
  }

  /// The filled but unread region.
  #[inline]
  pub fn following(&self) -> &[u8] {
    // SAFETY: All methods ensure that `current_end_idx` will never be greater than the
    //         buffer's length
    unsafe { self.buffer.get(self.current_end_idx..).unwrap_unchecked() }
  }

  /// Mutable version of [`Self::following`].
  #[cfg(feature = "web-socket")]
  #[inline]
  pub(crate) fn following_mut(&mut self) -> &mut [u8] {
    let current_end_idx = self.current_end_idx;
    self.buffer.get_mut(current_end_idx..).unwrap_or_default()
  }

  /// Whether buffer clearing is currently forbidden.
  ///
  /// Should be used temporally to avoid capacity overflow.
  #[inline]
  pub const fn forbid_clear(&self) -> bool {
    self.forbid_clear
  }

  /// Mutable version of [`Self::forbid_clear`].
  #[inline]
  pub const fn forbid_clear_mut(&mut self) -> &mut bool {
    &mut self.forbid_clear
  }

  /// Reads `LEN` buffer that are intended to form the header of a protocol message.
  ///
  /// Also removes the references that compose the current readable region.
  ///
  /// Returns `None` if the peer closed the connection or timeout was triggered.
  #[inline]
  pub async fn read_header<SR, const LEN: usize>(
    &mut self,
    stream_reader: &mut SR,
  ) -> crate::Result<Option<[u8; LEN]>>
  where
    SR: StreamReader,
  {
    self.manage_capacity(LEN)?;
    let Self { antecedent_end_idx, buffer, current_end_idx, capacity_ub: _, forbid_clear: _ } =
      self;
    let read_fut = async move {
      let local_current_end_idx = *current_end_idx;
      loop {
        let (init, uninit) = buffer.split_at_spare_mut();
        // SAFETY: All methods ensure that `current_end_idx` will never be greater than the
        //         buffer's length
        let following = unsafe { init.get(local_current_end_idx..).unwrap_unchecked() };
        if let Some(slice) = following.get(..LEN) {
          let rslt = slice.try_into().unwrap_or([0; LEN]);
          Self::remove_current(antecedent_end_idx, current_end_idx, LEN);
          return Ok(Some(rslt));
        }
        let Some(len) = stream_reader.read(uninit.into()).await? else {
          cold_path();
          if init.len() > local_current_end_idx {
            return Err(NetError::AbruptDisconnect.into());
          }
          return Ok(None);
        };
        let new_len = init.len().wrapping_add(len.get());
        // SAFETY: `stream_reader.read` just initialized `len` buffer
        unsafe {
          buffer.set_len(new_len);
        }
      }
    };
    read_fut.await
  }

  /// Reads `payload_len` buffer that are intended to form the body of a protocol message. Should
  /// be called after [`Self::read_header`].
  ///
  /// Also creates the references that compose the current readable region.
  #[inline]
  pub async fn read_payload<SR>(
    &mut self,
    payload_len: usize,
    stream_reader: &mut SR,
  ) -> crate::Result<()>
  where
    SR: StreamReader,
  {
    self.manage_capacity(payload_len)?;
    let current_end_idx = self.current_end_idx;
    loop {
      let (init, uninit) = self.split_at_spare_mut();
      let following_len = init.len().wrapping_sub(current_end_idx);
      if following_len >= payload_len {
        self.current_end_idx = current_end_idx.wrapping_add(payload_len);
        return Ok(());
      }
      let Some(len) = stream_reader.read(uninit.into()).await? else {
        // Headers with 0-length payloads can't enter here and because of that, this branch only
        // happens when the peer closed the connection without a graceful stop, which is an error!
        cold_path();
        return Err(NetError::AbruptDisconnect.into());
      };
      let new_len = init.len().wrapping_add(len.get());
      // SAFETY: `stream_reader.read` just initialized `len` buffer
      unsafe {
        self.buffer.set_len(new_len);
      }
    }
  }

  /// `value` can not be lesser than the current capacity upper bound.
  #[inline]
  pub fn set_capacity_ub(&mut self, value: usize) {
    self.capacity_ub = self.capacity_ub.max(value);
  }

  /// Returns vector content as a slice of `T`, along with the remaining spare capacity of the
  /// vector as a slice of `MaybeUninit<T>`.
  #[inline]
  pub fn split_at_spare_mut(&mut self) -> (&mut [u8], &mut [MaybeUninit<u8>]) {
    self.buffer.split_at_spare_mut()
  }

  /// Shortens the instance, keeping the first len elements and dropping the rest.
  #[inline]
  pub fn truncate(&mut self, len: usize) {
    self.buffer.truncate(len);
    self.current_end_idx = self.current_end_idx.min(len);
    self.antecedent_end_idx = self.antecedent_end_idx.min(self.current_end_idx);
  }

  #[cfg(any(feature = "tls", feature = "postgres"))]
  #[inline]
  pub(crate) const fn buffer_mut(&mut self) -> &mut VectorUsize<u8> {
    &mut self.buffer
  }

  /// Clears internal state
  #[inline]
  pub(crate) fn clear(&mut self) {
    let Self { antecedent_end_idx, buffer, capacity_ub: _, current_end_idx, forbid_clear } = self;
    if *forbid_clear {
      return;
    }
    *antecedent_end_idx = 0;
    buffer.clear();
    *current_end_idx = 0;
    *forbid_clear = false;
  }

  /// Marks the first `len` bytes of [`Self::following`] as consumed, like [`Self::read_header`]
  /// does with the bytes it returns. `len` is capped to the following length.
  #[cfg(feature = "web-socket")]
  #[inline]
  pub(crate) fn consume_following(&mut self, len: usize) {
    let following_len = self.buffer.len().wrapping_sub(self.current_end_idx);
    Self::remove_current(
      &mut self.antecedent_end_idx,
      &mut self.current_end_idx,
      len.min(following_len),
    );
  }

  /// Marks `header_len` bytes of [`Self::following`] as consumed and the `payload_len` bytes after
  /// them as the current region, like [`Self::read_header`] followed by [`Self::read_payload`],
  /// and returns the current region. Empty and unchanged if the following bytes are fewer.
  #[cfg(feature = "web-socket")]
  #[inline]
  pub(crate) fn consume_frame(&mut self, header_len: usize, payload_len: usize) -> &mut [u8] {
    let begin = self.current_end_idx.saturating_add(header_len);
    let end = begin.saturating_add(payload_len);
    if end > self.buffer.len() {
      return &mut [];
    }
    self.antecedent_end_idx = begin;
    self.current_end_idx = end;
    self.buffer.get_mut(begin..end).unwrap_or_default()
  }

  /// Reads once from the stream, appending to [`Self::following`], with room for at least
  /// `reserve_len` following bytes.
  ///
  /// Returns `false` if the peer closed the connection with nothing left to read. Closing in the
  /// middle of a message is an error.
  #[cfg(feature = "web-socket")]
  #[inline]
  pub(crate) async fn read_following<SR>(
    &mut self,
    reserve_len: usize,
    stream_reader: &mut SR,
  ) -> crate::Result<bool>
  where
    SR: StreamReader,
  {
    self.compact_for(reserve_len);
    self.manage_capacity(reserve_len)?;
    let (init, uninit) = self.buffer.split_at_spare_mut();
    let init_len = init.len();
    let Some(len) = stream_reader.read(uninit.into()).await? else {
      cold_path();
      if init_len > self.current_end_idx {
        return Err(NetError::AbruptDisconnect.into());
      }
      return Ok(false);
    };
    // SAFETY: `stream_reader.read` just initialized `len` bytes
    unsafe {
      self.buffer.set_len(init_len.wrapping_add(len.get()));
    }
    Ok(true)
  }

  /// [`Self::read_following`] without awaiting: see [`StreamReader::try_read`].
  #[cfg(feature = "web-socket")]
  #[inline]
  pub(crate) fn try_read_following<SR>(
    &mut self,
    reserve_len: usize,
    stream_reader: &mut SR,
  ) -> crate::Result<crate::net::TryRead>
  where
    SR: StreamReader,
  {
    use crate::net::TryRead;
    self.compact_for(reserve_len);
    self.manage_capacity(reserve_len)?;
    let (init, uninit) = self.buffer.split_at_spare_mut();
    let init_len = init.len();
    let rslt = stream_reader.try_read(uninit.into())?;
    match rslt {
      TryRead::Read(len) => {
        // SAFETY: `stream_reader.try_read` just initialized `len` bytes
        unsafe {
          self.buffer.set_len(init_len.wrapping_add(len.get()));
        }
      }
      TryRead::Closed => {
        cold_path();
        if init_len > self.current_end_idx {
          return Err(NetError::AbruptDisconnect.into());
        }
      }
      TryRead::Pending | TryRead::Unsupported => {}
    }
    Ok(rslt)
  }

  /// Moves the following bytes to the front when there is no room for `reserve_len` of them past
  /// the consumed ones. A stream of small frames always leaves part of one unread, so the buffer
  /// never empties and [`Self::manage_capacity`] would grow it towards `capacity_ub` on every
  /// connection. Only for callers that keep no indices into the buffer across reads.
  #[cfg(feature = "web-socket")]
  #[inline]
  fn compact_for(&mut self, reserve_len: usize) {
    let current_end_idx = self.current_end_idx;
    if current_end_idx == 0
      || self.forbid_clear
      || self.buffer.capacity() >= current_end_idx.wrapping_add(reserve_len)
    {
      return;
    }
    cold_path();
    let following_len = self.buffer.len().wrapping_sub(current_end_idx);
    self.buffer.copy_within(current_end_idx.., 0);
    self.buffer.truncate(following_len);
    self.antecedent_end_idx = 0;
    self.current_end_idx = 0;
  }

  /// Both indices will be capped to avoid data corruption.
  #[cfg(feature = "web-socket")]
  pub(crate) fn set_indices(&mut self, antecedent_end_idx: usize, current_end_idx: usize) {
    self.current_end_idx = current_end_idx.min(self.buffer.len());
    self.antecedent_end_idx = antecedent_end_idx.min(self.current_end_idx);
  }

  #[cfg(any(feature = "postgres", feature = "web-socket"))]
  pub(crate) fn suffix_pusher(
    &mut self,
  ) -> crate::collections::SuffixGuardVectorMut<'_, usize, u8> {
    crate::collections::SuffixGuardVectorMut::from(&mut self.buffer)
  }

  /// `additional` refers `following`, `trailing` and unreserved memory. In other words, fetched
  /// but unread buffer, uninitialized buffer and unallocated buffer.
  ///
  /// In a partially filled buffer, if `additional` is greater than `current_end_idx - capacity_ub`,
  /// then everything before `current_end_idx` should be left shifted only if `additional` <= `capacity_ub`.
  #[inline]
  fn manage_capacity(&mut self, additional: usize) -> crate::Result<()> {
    let buffer_len = self.buffer.len();
    let capacity_ub = self.capacity_ub;
    let current_end_idx = self.current_end_idx;
    let following_len = buffer_len.wrapping_sub(current_end_idx);
    if additional > capacity_ub {
      cold_path();
      return Err(NetError::CapacityOverflow.into());
    }
    if following_len == 0 && !self.forbid_clear {
      let used = self.buffer.len();
      self.clear();
      release_if_oversized(&mut self.buffer, used.max(additional));
      if self.buffer.capacity() < additional {
        self.buffer.reserve(additional)?;
      }
      return Ok(());
    }
    let required_capacity = current_end_idx.wrapping_add(additional);
    if self.buffer.capacity() >= required_capacity {
      return Ok(());
    }
    if required_capacity <= capacity_ub {
      self.buffer.reserve(required_capacity.wrapping_sub(buffer_len))?;
      return Ok(());
    }
    cold_path();
    if self.forbid_clear {
      return Err(NetError::ForbiddenClear.into());
    }
    self.antecedent_end_idx = 0;
    self.current_end_idx = 0;
    self.buffer.copy_within(current_end_idx.., 0);
    self.buffer.truncate(following_len);
    self.buffer.reserve(additional.wrapping_sub(following_len))?;
    Ok(())
  }

  #[inline]
  const fn remove_current(
    antecedent_end_idx: &mut usize,
    current_end_idx: &mut usize,
    offset: usize,
  ) {
    let idx = current_end_idx.wrapping_add(offset);
    *antecedent_end_idx = idx;
    *current_end_idx = idx;
  }
}

impl Lease<BufStreamReader> for BufStreamReader {
  #[inline]
  fn lease(&self) -> &BufStreamReader {
    self
  }
}

impl LeaseMut<BufStreamReader> for BufStreamReader {
  #[inline]
  fn lease_mut(&mut self) -> &mut BufStreamReader {
    self
  }
}

impl Debug for BufStreamReader {
  #[inline]
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    f.debug_struct("BufStreamReader").finish()
  }
}

impl Default for BufStreamReader {
  #[inline]
  fn default() -> Self {
    Self::new()
  }
}

/// Buffers past this size are released once a use takes under a quarter of them.
pub(crate) const RETAINED_BUFFER_LEN: usize = 1 << 20;

/// Releases an empty buffer that one large message grew, if its last use (`used` bytes) took
/// under a quarter of it. Without this a buffer keeps its peak size for the connection's life,
/// so a single large (or inflated) message held its memory until the connection closed. A run of
/// large messages keeps its buffer, so each doesn't pay for a new allocation.
#[inline]
pub(crate) fn release_if_oversized(buffer: &mut VectorUsize<u8>, used: usize) {
  let capacity = buffer.capacity();
  if capacity > RETAINED_BUFFER_LEN && used < capacity / 4 {
    cold_path();
    *buffer = VectorUsize::new();
  }
}

#[cfg(test)]
mod tests {
  use crate::net::{BufStreamReader, BytesStream, StreamWriter};

  #[rimu_ws::test]
  async fn read_header_and_payload() {
    let mut stream = BytesStream::default();
    stream.write_all(&[0, 2, 1, 2]).await.unwrap();
    let mut nrb = BufStreamReader::default();
    let header = nrb.read_header::<_, 2>(&mut stream).await.unwrap().unwrap();
    let len = u16::from_be_bytes(header);
    nrb.read_payload(len.into(), &mut stream).await.unwrap();
    assert_eq!(nrb.current(), &[1, 2][..]);
  }

  // A peer that streams small frames back to back always leaves part of one unread, so the
  // buffer is never empty: the room already consumed must be reused instead of the buffer growing
  // towards `capacity_ub` on every connection.
  #[cfg(feature = "web-socket")]
  #[rimu_ws::test]
  async fn an_unread_tail_does_not_grow_the_buffer() {
    use crate::{
      collections::MaybeUninitSlice,
      net::{StreamCommon, StreamReader},
    };
    use core::num::NonZeroUsize;

    struct Chunks(usize);

    impl StreamCommon for Chunks {}

    impl StreamReader for Chunks {
      async fn read(
        &mut self,
        mut bytes: MaybeUninitSlice<'_, u8>,
      ) -> crate::Result<Option<NonZeroUsize>> {
        let initialized = bytes.initialize_all_bytes();
        let len = initialized.len().min(100);
        self.0 += len;
        Ok(NonZeroUsize::new(len))
      }
    }

    let mut nrb = BufStreamReader::default();
    let mut stream = Chunks(0);
    // One byte off: what is read (100 a time) never ends on a frame boundary, so following
    // bytes always remain.
    assert!(nrb.read_following(64, &mut stream).await.unwrap());
    nrb.consume_following(1);
    while stream.0 < 1 << 20 {
      assert!(nrb.read_following(64, &mut stream).await.unwrap());
      while nrb.following().len() >= 64 {
        nrb.consume_following(64);
      }
    }
    let capacity = nrb.buffer.capacity();
    assert!(capacity <= 64 * 1024, "{capacity} bytes for 64-byte frames");
  }

  // One large message must not hold its memory for the rest of the connection: once a small
  // message follows it, the buffer is released. A run of large messages keeps it, so that each doesn't pay
  // for a new allocation.
  #[rimu_ws::test]
  async fn a_large_read_does_not_keep_its_buffer() {
    let mut stream = BytesStream::default();
    let large = alloc::vec![7; 4 << 20];
    let mut nrb = BufStreamReader::default();
    for _ in 0..2 {
      stream.write_all(&large).await.unwrap();
      nrb.read_payload(large.len(), &mut stream).await.unwrap();
      assert!(nrb.buffer.capacity() >= 4 << 20);
    }
    let kept = nrb.buffer.capacity();
    // The drain after the large message still counts it; the one after a small message releases.
    for _ in 0..2 {
      stream.write_all(&[0, 2, 1, 2]).await.unwrap();
      let header = nrb.read_header::<_, 2>(&mut stream).await.unwrap().unwrap();
      nrb.read_payload(u16::from_be_bytes(header).into(), &mut stream).await.unwrap();
      assert_eq!(nrb.current(), &[1, 2][..]);
    }
    let capacity = nrb.buffer.capacity();
    assert!(capacity <= 1 << 20, "{capacity} bytes kept after a small read (was {kept})");
  }

  #[rimu_ws::test]
  async fn zero_payload() {
    let mut stream = BytesStream::default();
    stream.write_all(&[0, 0]).await.unwrap();
    let mut nrb = BufStreamReader::default();
    let header = nrb.read_header::<_, 2>(&mut stream).await.unwrap().unwrap();
    let len = u16::from_be_bytes(header);
    nrb.read_payload(len.into(), &mut stream).await.unwrap();
    assert!(nrb.current().is_empty());
  }
}

// PSN: `BufStreamReader` is the result of **years** of research, empirical approaches and
//      headaches. It wouldn't exist without my persistence and ignorance, as such, let us
//      celebrate the struggle and the fallibility of human nature.
