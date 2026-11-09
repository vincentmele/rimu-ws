// https://datatracker.ietf.org/doc/html/rfc9846#section-7.1

use crate::{
  collections::ArrayVectorCopy,
  crypto::AEAD_TAG_LEN,
  misc::{Lease as _, TryArithmetic as _, zero_volatile},
  tls::{
    CipherSuite, IV_LEN, MAX_CIPHER_KEY_LEN, MAX_HASH_LEN, MAX_LABEL_LEN, TrafficAead,
    tls_hash::TlsDigest, tls_hkdf::TlsHkdf,
  },
};
use core::{
  fmt::{Debug, Formatter},
  mem::ManuallyDrop,
  ops::Deref,
  ptr,
};

/// Responsible for deriving keys used for encryption.
pub struct KeySchedule {
  cipher_suite: CipherSuite,
  common_hkdf: TlsHkdf,
  common_secret: ArrayVectorCopy<u8, MAX_HASH_LEN>,
  exporter_secret: ArrayVectorCopy<u8, MAX_HASH_LEN>,
  read: KeyScheduleRead,
  write: KeyScheduleWrite,
}

impl KeySchedule {
  /// A schedule with nothing derived, for plaintext streams: [`Self::default`] runs three HKDF
  /// extractions that a plaintext stream never uses.
  #[inline]
  pub(crate) fn unset() -> Self {
    let cipher_suite = CipherSuite::default();
    let state = || KeyScheduleState {
      aead: Wiped::new(None),
      cipher_key: ArrayVectorCopy::new(),
      cipher_suite,
      counter: 0,
      iv: [0; IV_LEN],
      raw_traffic_secret: ArrayVectorCopy::new(),
      traffic_secret: Wiped::new(TlsHkdf::Unset),
      #[cfg(test)]
      expansions: 0,
    };
    Self {
      cipher_suite,
      common_hkdf: TlsHkdf::Unset,
      common_secret: cipher_suite.zeroed_hash(),
      exporter_secret: ArrayVectorCopy::new(),
      read: KeyScheduleRead { state: state() },
      write: KeyScheduleWrite { state: state() },
    }
  }

  #[inline]
  pub(crate) fn from_cipher_suite(cipher_suite: CipherSuite) -> Self {
    let counter = 0;
    let iv = [0; IV_LEN];
    Self {
      cipher_suite,
      common_hkdf: cipher_suite.hkdf_extract(None, &[]),
      common_secret: cipher_suite.zeroed_hash(),
      exporter_secret: ArrayVectorCopy::new(),
      read: KeyScheduleRead {
        state: KeyScheduleState {
          aead: Wiped::new(None),
          cipher_key: ArrayVectorCopy::new(),
          cipher_suite,
          counter,
          iv,
          raw_traffic_secret: ArrayVectorCopy::new(),
          traffic_secret: Wiped::new(cipher_suite.hkdf_extract(None, &[])),
          #[cfg(test)]
          expansions: 0,
        },
      },
      write: KeyScheduleWrite {
        state: KeyScheduleState {
          aead: Wiped::new(None),
          cipher_key: ArrayVectorCopy::new(),
          cipher_suite,
          counter,
          iv,
          raw_traffic_secret: ArrayVectorCopy::new(),
          traffic_secret: Wiped::new(cipher_suite.hkdf_extract(None, &[])),
          #[cfg(test)]
          expansions: 0,
        },
      },
    }
  }

  #[inline]
  pub(crate) const fn cipher_suite(&self) -> CipherSuite {
    self.cipher_suite
  }

  #[inline]
  pub(crate) fn early_secret(&mut self) -> crate::Result<()> {
    self.hkdf_extract(&self.cipher_suite.zeroed_hash());
    self.common_secret = derive_secret_derived(self.cipher_suite, &self.common_hkdf)?;
    Ok(())
  }

  #[inline]
  pub(crate) fn export_keying_material(
    cipher_suite: CipherSuite,
    context: Option<&[u8]>,
    exporter_secret: &ArrayVectorCopy<u8, MAX_HASH_LEN>,
    label: &[u8],
    output: &mut [u8],
  ) -> crate::Result<()> {
    let exporter_hkdf = cipher_suite.hkdf_from_prk(exporter_secret)?;
    let empty_hash = cipher_suite.hash_digest([&[][..]]);
    let derived_secret = hkdf_expand_label::<MAX_HASH_LEN>(
      Some(empty_hash.lease()),
      label,
      cipher_suite.hash_len(),
      &exporter_hkdf,
    )?;
    let context_hash = cipher_suite.hash_digest([context.unwrap_or(&[])]);
    let derived_hkdf = cipher_suite.hkdf_from_prk(&derived_secret)?;
    let concatenated =
      hkdf_array(Some(context_hash.lease()), b"exporter", output.len().try_into()?)?;
    derived_hkdf.expand(concatenated.as_slice(), output)?;
    Ok(())
  }

  #[inline]
  pub(crate) const fn exporter_secret(&self) -> &ArrayVectorCopy<u8, MAX_HASH_LEN> {
    &self.exporter_secret
  }

  #[inline]
  pub(crate) fn handshake_secret<const IS_CLIENT: bool>(
    &mut self,
    ikm: &[u8],
    transcript_hash: &TlsDigest,
  ) -> crate::Result<()> {
    let tuple = if IS_CLIENT {
      ("c hs traffic".as_bytes(), "s hs traffic".as_bytes())
    } else {
      ("s hs traffic".as_bytes(), "c hs traffic".as_bytes())
    };
    self.hkdf_extract(ikm);
    self.calculate_traffic_secrets(tuple, transcript_hash)?;
    self.common_secret = derive_secret_derived(self.cipher_suite, &self.common_hkdf)?;
    Ok(())
  }

  #[inline]
  pub(crate) fn into_split(self) -> (KeyScheduleRead, KeyScheduleWrite) {
    (self.read, self.write)
  }

  #[inline]
  pub(crate) fn master_secret<const IS_CLIENT: bool>(
    &mut self,
    transcript_hash: &TlsDigest,
  ) -> crate::Result<()> {
    let tuple = if IS_CLIENT {
      ("c ap traffic".as_bytes(), "s ap traffic".as_bytes())
    } else {
      ("s ap traffic".as_bytes(), "c ap traffic".as_bytes())
    };
    self.hkdf_extract(&self.cipher_suite.zeroed_hash());
    self.calculate_traffic_secrets(tuple, transcript_hash)?;
    self.exporter_secret = derive_secret(
      self.cipher_suite,
      Some(transcript_hash.lease()),
      b"exp master",
      &self.common_hkdf,
    )?;
    Ok(())
  }

  #[inline]
  pub(crate) const fn read(&self) -> &KeyScheduleRead {
    &self.read
  }

  #[inline]
  pub(crate) const fn read_mut(&mut self) -> &mut KeyScheduleRead {
    &mut self.read
  }

  #[inline]
  pub(crate) fn set_cipher_suite(&mut self, cipher_suite: CipherSuite) {
    if self.cipher_suite == cipher_suite {
      self.cipher_suite = cipher_suite;
      self.read.state.cipher_suite = cipher_suite;
      self.write.state.cipher_suite = cipher_suite;
    } else {
      *self = Self::from_cipher_suite(cipher_suite);
    }
  }

  #[inline]
  pub(crate) const fn split_mut(&mut self) -> (&mut KeyScheduleRead, &mut KeyScheduleWrite) {
    (&mut self.read, &mut self.write)
  }

  #[inline]
  pub(crate) const fn write(&self) -> &KeyScheduleWrite {
    &self.write
  }

  #[inline]
  pub(crate) const fn write_mut(&mut self) -> &mut KeyScheduleWrite {
    &mut self.write
  }

  #[inline]
  fn calculate_traffic_secrets(
    &mut self,
    (lhs, rhs): (&'static [u8], &'static [u8]),
    transcript_hash: &TlsDigest,
  ) -> crate::Result<()> {
    self.read.state.update(Some(&self.common_hkdf), rhs, Some(transcript_hash))?;
    self.write.state.update(Some(&self.common_hkdf), lhs, Some(transcript_hash))?;
    Ok(())
  }

  #[inline]
  fn hkdf_extract(&mut self, ikm: &[u8]) {
    let hkdf = self.cipher_suite.hkdf_extract(Some(&self.common_secret), ikm);
    self.common_hkdf = hkdf;
  }
}

impl Debug for KeySchedule {
  #[inline]
  fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
    f.debug_struct("KeySchedule").finish()
  }
}

impl Default for KeySchedule {
  #[inline]
  fn default() -> Self {
    Self::from_cipher_suite(CipherSuite::default())
  }
}

pub(crate) struct KeyScheduleRead {
  state: KeyScheduleState,
}

impl KeyScheduleRead {
  #[inline]
  pub(crate) const fn state(&self) -> &KeyScheduleState {
    &self.state
  }

  #[inline]
  pub(crate) const fn state_mut(&mut self) -> &mut KeyScheduleState {
    &mut self.state
  }
}

impl Debug for KeyScheduleRead {
  #[inline]
  fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
    f.debug_struct("KeyScheduleRead").finish()
  }
}

pub(crate) struct KeyScheduleState {
  // The AEAD of `cipher_key`, expanded by the first record that needs it, where the state lives
  // then (not where the key was derived, which the state may be moved out of), and dropped (which
  // wipes it) when the key changes. Records are sealed and opened with it, the key is never
  // expanded per record (ruling T18-a).
  aead: Wiped<Option<TrafficAead>>,
  cipher_key: ArrayVectorCopy<u8, MAX_CIPHER_KEY_LEN>,
  // Expansions of the record AEAD key
  #[cfg(test)]
  pub(crate) expansions: u32,
  cipher_suite: CipherSuite,
  counter: u64,
  iv: [u8; IV_LEN],
  raw_traffic_secret: ArrayVectorCopy<u8, MAX_HASH_LEN>,
  traffic_secret: Wiped<TlsHkdf>,
}

// Ruling T18-e: the halves of a split stream drop their states by value, wherever they live, so the
// state wipes its own secrets. The expanded AEAD and the HKDF state wipe themselves (`Wiped`); the
// plain fields are overwritten here. Pooled boxes (`KsBox`, `StateBox`) drop their value in place
// before they zero the box, and a value moved out of its box is not dropped there, so nothing is
// wiped while it lives.
impl Drop for KeyScheduleState {
  #[inline]
  fn drop(&mut self) {
    wipe_value(&mut self.cipher_key);
    wipe_value(&mut self.iv);
    wipe_value(&mut self.raw_traffic_secret);
  }
}

impl KeyScheduleState {
  #[inline]
  pub(crate) fn create_finished_verify_data(
    &self,
    hash: &[u8],
  ) -> crate::Result<ArrayVectorCopy<u8, MAX_HASH_LEN>> {
    let hash_len = self.cipher_suite.hash_len();
    let key = hkdf_expand_label::<MAX_HASH_LEN>(None, b"finished", hash_len, &self.traffic_secret)?;
    let mut rslt = ArrayVectorCopy::new();
    let mut hmac = self.cipher_suite.hmac_from_key(&key)?;
    hmac.update(hash);
    rslt.extend_from_copyable_slice(hmac.finalize().lease())?;
    Ok(rslt)
  }

  #[inline]
  pub(crate) fn rotate(&mut self) -> crate::Result<()> {
    self.update(None, b"traffic upd", None)
  }

  #[inline]
  pub(crate) fn verify_finished_record(
    &self,
    hash: &[u8],
    verify_data: &[u8],
  ) -> crate::Result<()> {
    let hash_len = self.cipher_suite.hash_len();
    let key = hkdf_expand_label::<MAX_HASH_LEN>(None, b"finished", hash_len, &self.traffic_secret)?;
    let mut hmac = self.cipher_suite.hmac_from_key(&key)?;
    hmac.update(hash);
    hmac.verify(verify_data)?;
    Ok(())
  }

  #[inline]
  pub(crate) const fn cipher_key(&self) -> &ArrayVectorCopy<u8, MAX_CIPHER_KEY_LEN> {
    &self.cipher_key
  }

  #[inline]
  pub(crate) const fn cipher_suite(&self) -> CipherSuite {
    self.cipher_suite
  }

  /// The sequence number of the next record.
  #[inline]
  pub(crate) const fn counter(&self) -> u64 {
    self.counter
  }

  #[inline]
  pub(crate) const fn iv(&self) -> [u8; IV_LEN] {
    self.iv
  }

  /// Opens the record whose header is `header` and whose ciphertext, followed by the tag, is
  /// `data`, in place, as the record of the next sequence number. Returns the plaintext, a prefix
  /// of `data`; the sequence number advances only if the record is authentic.
  #[inline]
  pub(crate) fn open_record<'data>(
    &mut self,
    header: &[u8],
    data: &'data mut [u8],
  ) -> crate::Result<&'data mut [u8]> {
    let nonce = nonce(self.counter, &self.iv);
    let plaintext = self.record_aead()?.open_in_place(nonce, header, data)?;
    self.counter = self.counter.wrapping_add(1);
    Ok(plaintext)
  }

  /// Seals the plaintext `data` of the record whose header is `header`, in place, as the record of
  /// the next sequence number, which advances. Returns the tag.
  #[inline]
  pub(crate) fn seal_record(
    &mut self,
    header: &[u8],
    data: &mut [u8],
  ) -> crate::Result<[u8; AEAD_TAG_LEN]> {
    let nonce = nonce(self.counter, &self.iv);
    let tag = self.record_aead()?.seal_in_place(nonce, header, data)?;
    self.counter = self.counter.wrapping_add(1);
    Ok(tag)
  }

  #[inline]
  pub(crate) fn raw_traffic_secret(&self) -> &[u8] {
    self.raw_traffic_secret.as_slice()
  }

  #[inline(always)]
  fn update(
    &mut self,
    hkdf: Option<&TlsHkdf>,
    label: &'static [u8],
    transcript_hash: Option<&TlsDigest>,
  ) -> crate::Result<()> {
    let cipher_suite = self.cipher_suite;
    let secret = match (hkdf, transcript_hash) {
      (None, None) => derive_secret(cipher_suite, None, label, &self.traffic_secret)?,
      (None, Some(el)) => {
        derive_secret(cipher_suite, Some(el.lease()), label, &self.traffic_secret)?
      }
      (Some(el), None) => derive_secret(cipher_suite, None, label, el)?,
      (Some(lhs), Some(rhs)) => derive_secret(cipher_suite, Some(rhs.lease()), label, lhs)?,
    };
    self.raw_traffic_secret = secret;
    self.traffic_secret.set(cipher_suite.hkdf_from_prk(&secret)?);
    let cipher_key_len = cipher_suite.cipher_key_len();
    let iv = hkdf_expand_label(None, b"iv", IV_LEN.try_into()?, &self.traffic_secret)?;
    self.cipher_key = hkdf_expand_label(None, b"key", cipher_key_len, &self.traffic_secret)?;
    // The AEAD of the previous key is dropped, and so wiped, where it lives
    self.aead.set(None);
    self.counter = 0;
    self.iv = iv.into_inner()?;
    Ok(())
  }

  // The AEAD of the current key, expanded on the first call after the key changed.
  #[inline]
  fn record_aead(&mut self) -> crate::Result<&TrafficAead> {
    if self.aead.is_none() {
      self.aead.set(Some(TrafficAead::new(self.cipher_suite, self.cipher_key.as_slice())?));
      #[cfg(test)]
      {
        self.expansions = self.expansions.wrapping_add(1);
      }
    }
    self.aead.as_ref().ok_or(crate::Error::ProgrammingError)
  }
}

/// A value that is dropped in place and then overwritten with zeros when it is dropped or
/// replaced ([`Self::set`]): what it derived from a secret does not stay in the memory it leaves.
/// Only its own bytes are overwritten, memory that it owns elsewhere is left to its destructor.
struct Wiped<T>(ManuallyDrop<T>);

impl<T> Wiped<T> {
  #[inline]
  const fn new(value: T) -> Self {
    Self(ManuallyDrop::new(value))
  }

  /// Drops and wipes the current value in place, then puts `value` there.
  #[inline]
  fn set(&mut self, value: T) {
    // SAFETY: the current value is valid; it is dropped once, here, and its bytes are not read as a
    // `T` again before `value` is written over them
    unsafe { drop_and_wipe(&mut self.0) };
    // SAFETY: the place is valid for a write of a `T` and holds no value to drop
    unsafe { ptr::write(&mut self.0, ManuallyDrop::new(value)) };
  }
}

impl<T> Deref for Wiped<T> {
  type Target = T;

  #[inline]
  fn deref(&self) -> &T {
    &self.0
  }
}

impl<T> Drop for Wiped<T> {
  #[inline]
  fn drop(&mut self) {
    // SAFETY: the value is valid and never used again
    unsafe { drop_and_wipe(&mut self.0) };
  }
}

// Drops `value` in place and overwrites its bytes with zeros.
//
// SAFETY: `value` must be valid, and not be used or dropped again before a new value is written.
unsafe fn drop_and_wipe<T>(value: &mut ManuallyDrop<T>) {
  // SAFETY: up to the caller
  unsafe { ManuallyDrop::drop(value) };
  // The pointer is taken after the drop so that it is not invalidated by it
  let ptr = ptr::from_mut(value).cast::<u8>();
  // SAFETY: the place of `value`, `size_of::<T>()` bytes (`ManuallyDrop` has the layout of `T`),
  // which nothing reads as a `T` again
  unsafe { zero_volatile(ptr, size_of::<T>()) };
}

// Overwrites the bytes of `value`, which has no destructor, with zeros: it is all zeros after.
fn wipe_value<T: Copy>(value: &mut T) {
  // SAFETY: the place of `value`, `size_of::<T>()` bytes; the plain fields that this is used for
  // (byte arrays and `ArrayVectorCopy` of bytes) are valid when all zeros
  unsafe { zero_volatile(ptr::from_mut(value).cast::<u8>(), size_of::<T>()) };
}

pub(crate) struct KeyScheduleWrite {
  state: KeyScheduleState,
}

impl KeyScheduleWrite {
  #[inline]
  pub(crate) const fn state(&self) -> &KeyScheduleState {
    &self.state
  }

  #[inline]
  pub(crate) const fn state_mut(&mut self) -> &mut KeyScheduleState {
    &mut self.state
  }
}

impl Debug for KeyScheduleWrite {
  #[inline]
  fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
    f.debug_struct("KeyScheduleWrite").finish()
  }
}

// Differently from the RFC, this function expects a hash instead of raw bytes
#[inline]
fn derive_secret(
  cipher_suite: CipherSuite,
  context: Option<&[u8]>,
  label: &'static [u8],
  secret: &TlsHkdf,
) -> crate::Result<ArrayVectorCopy<u8, MAX_HASH_LEN>> {
  hkdf_expand_label(context, label, cipher_suite.hash_len(), secret)
}

#[inline]
fn derive_secret_derived(
  cipher_suite: CipherSuite,
  secret: &TlsHkdf,
) -> crate::Result<ArrayVectorCopy<u8, MAX_HASH_LEN>> {
  let mut context_buffer = ArrayVectorCopy::<_, MAX_HASH_LEN>::new();
  context_buffer.extend_from_copyable_slice(cipher_suite.hash_digest([]).lease())?;
  derive_secret(cipher_suite, Some(context_buffer.as_slice()), b"derived", secret)
}

#[inline]
fn hkdf_array(
  context: Option<&[u8]>,
  label: &[u8],
  output_len: u16,
) -> crate::Result<ArrayVectorCopy<u8, MAX_LABEL_LEN>> {
  let label_len = 6u8.try_add(label.len().try_into()?)?;
  let mut concatenated = ArrayVectorCopy::<_, MAX_LABEL_LEN>::new();
  match context {
    None => {
      let _ = concatenated.extend_from_copyable_slices([
        output_len.to_be_bytes().as_slice(),
        &label_len.to_be_bytes(),
        b"tls13 ",
        label,
        &[0][..],
      ])?;
    }
    Some(value) => {
      let _ = concatenated.extend_from_copyable_slices([
        output_len.to_be_bytes().as_slice(),
        &label_len.to_be_bytes(),
        b"tls13 ",
        label,
        u8::try_from(value.len())?.to_be_bytes().as_slice(),
        value,
      ])?;
    }
  }
  Ok(concatenated)
}

#[inline]
pub(crate) fn hkdf_expand_label<const LENGTH: usize>(
  context: Option<&[u8]>,
  label: &[u8],
  output_len: u8,
  secret: &TlsHkdf,
) -> crate::Result<ArrayVectorCopy<u8, LENGTH>> {
  let concatenated = hkdf_array(context, label, output_len.into())?;
  let mut output = ArrayVectorCopy::from_array([0; LENGTH]);
  output.truncate(output_len);
  secret.expand(concatenated.as_slice(), &mut output)?;
  Ok(output)
}

#[inline]
fn nonce(counter: u64, iv: &[u8; IV_LEN]) -> [u8; IV_LEN] {
  let padded = pad_left::<IV_LEN>(&counter.to_be_bytes());
  let mut nonce = [0; IV_LEN];
  for (elem, (lhs, rhs)) in nonce.iter_mut().zip(iv.iter().zip(padded)) {
    *elem = lhs ^ rhs;
  }
  nonce
}

#[inline]
fn pad_left<const N: usize>(bytes: &[u8]) -> [u8; N] {
  let mut padded = [0u8; N];
  let len = bytes.len().min(N);
  let dst_idx = N.wrapping_sub(len);
  let src_idx = bytes.len().wrapping_sub(len);
  let Some(dst) = padded.get_mut(dst_idx..) else {
    return padded;
  };
  let Some(src) = bytes.get(src_idx..) else {
    return padded;
  };
  dst.copy_from_slice(src);
  padded
}

#[cfg(test)]
mod tests {
  use crate::{
    collections::ArrayVectorCopy,
    crypto::{AEAD_TAG_LEN, Aead as _, Aes128GcmGlobal, Aes256GcmGlobal, Chacha20Poly1305Global},
    sync::AtomicU64,
    tests::_count_allocations_in,
    tls::{
      CipherSuite, IV_LEN, KeySchedule, MAX_CIPHER_KEY_LEN, MAX_HASH_LEN, RECORD_HEADER_LEN,
      key_schedule::{KeyScheduleState, KeyScheduleWrite, Wiped},
      misc::seal_payloads,
      record_content_ty::RecordContentTy,
    },
  };
  use alloc::vec::Vec;
  use core::{
    cell::Cell,
    mem::{MaybeUninit, offset_of},
    ptr, slice,
    sync::atomic::Ordering,
  };

  // A server's and a client's schedules after the same handshake secret: the server's write side
  // is the client's read side.
  fn pair(suite: CipherSuite) -> (KeySchedule, KeySchedule) {
    let transcript = suite.hash_digest([&b"client hello, server hello"[..]]);
    let mut server = KeySchedule::from_cipher_suite(suite);
    let mut client = KeySchedule::from_cipher_suite(suite);
    for ks in [&mut server, &mut client] {
      ks.early_secret().unwrap();
    }
    server.handshake_secret::<false>(&[7; 32], &transcript).unwrap();
    client.handshake_secret::<true>(&[7; 32], &transcript).unwrap();
    (server, client)
  }

  // Opens the record at the start of `records` with the one-shot AEAD and the read keys of the
  // client at the sequence number `seq`: what the peer sees, whatever the server sealed with.
  fn open_with_one_shot(client: &KeySchedule, seq: u64, records: &mut [u8]) -> Vec<u8> {
    let state = client.read().state();
    let mut nonce = state.iv();
    for (elem, byte) in nonce.iter_mut().skip(4).zip(seq.to_be_bytes()) {
      *elem ^= byte;
    }
    let (header, rest) = records.split_at_mut(RECORD_HEADER_LEN);
    let len = usize::from(u16::from_be_bytes([header[3], header[4]]));
    let (data, key) = (&mut rest[..len], state.cipher_key().as_slice());
    let plaintext = match state.cipher_suite() {
      CipherSuite::Aes128GcmSha256 => {
        Aes128GcmGlobal::decrypt_parts(header, data, nonce, key.try_into().unwrap())
      }
      CipherSuite::Aes256GcmSha384 => {
        Aes256GcmGlobal::decrypt_parts(header, data, nonce, key.try_into().unwrap())
      }
      CipherSuite::Chacha20Poly1305Sha256 => {
        Chacha20Poly1305Global::decrypt_parts(header, data, nonce, key.try_into().unwrap())
      }
    };
    plaintext.unwrap().to_vec()
  }

  // The byte ranges of the secret fields of a `KeyScheduleWrite`: (name, offset, length).
  fn secret_fields() -> [(&'static str, usize, usize); 5] {
    let base = offset_of!(KeyScheduleWrite, state);
    [
      ("aead", base + offset_of!(KeyScheduleState, aead), size_of_field(|el| &el.aead)),
      (
        "cipher_key",
        base + offset_of!(KeyScheduleState, cipher_key),
        size_of_field(|el| &el.cipher_key),
      ),
      ("iv", base + offset_of!(KeyScheduleState, iv), size_of_field(|el| &el.iv)),
      (
        "raw_traffic_secret",
        base + offset_of!(KeyScheduleState, raw_traffic_secret),
        size_of_field(|el| &el.raw_traffic_secret),
      ),
      (
        "traffic_secret",
        base + offset_of!(KeyScheduleState, traffic_secret),
        size_of_field(|el| &el.traffic_secret),
      ),
    ]
  }

  // The size of the field that `f` borrows, without a value of the state.
  fn size_of_field<T>(_: fn(&KeyScheduleState) -> &T) -> usize {
    size_of::<T>()
  }

  // Ruling T18-e: a split stream drops its halves by value, so the state of each half wipes its
  // secrets where it lives: the expanded AEAD, the traffic key, the IV, the raw traffic secret and
  // the HKDF state derived from it. Checked without reading freed memory: the half lives in a slot
  // that the test owns.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn key_schedule_state_is_wiped_on_drop() {
    for suite in CipherSuite::PRIORITY {
      let (server, _) = pair(suite);
      let (_, mut ksw) = server.into_split();
      let mut records = Vec::new();
      seal_payloads(RecordContentTy::ApplicationData, &mut ksw, 16_384, &[b"x"], &mut records)
        .unwrap();
      assert_eq!(ksw.state().expansions, 1);
      let mut slot = MaybeUninit::<KeyScheduleWrite>::uninit();
      slot.write(ksw);
      // SAFETY: the slot was initialized above and nothing reads it as a value after this
      unsafe { ptr::drop_in_place(slot.as_mut_ptr()) };
      for (name, offset, len) in secret_fields() {
        // SAFETY: the range is a field of the slot, which the drop overwrote byte by byte, so all
        // of its bytes are initialized
        let bytes = unsafe { slice::from_raw_parts(slot.as_ptr().cast::<u8>().add(offset), len) };
        let left = bytes.iter().filter(|el| **el != 0).count();
        assert_eq!(left, 0, "{suite:?}: {left} non-zero bytes left in {name}");
      }
    }
  }

  // Ruling T18-e, without the crypto backend so that Miri runs it: the plain secrets of a state
  // are wiped when it drops, and a `Wiped` value is dropped once per value, in place, before its
  // bytes are cleared, when it is replaced and when it drops.
  #[test]
  fn plain_secrets_and_wiped_values_are_cleared() {
    struct Probe<'drops>([u8; 24], &'drops Cell<u32>);
    impl Drop for Probe<'_> {
      fn drop(&mut self) {
        self.1.set(self.1.get() + 1);
      }
    }

    let (_, mut ksw) = KeySchedule::unset().into_split();
    let state = ksw.state_mut();
    state.cipher_key = ArrayVectorCopy::from_array([0xa5; MAX_CIPHER_KEY_LEN]);
    state.iv = [0x5a; IV_LEN];
    state.raw_traffic_secret = ArrayVectorCopy::from_array([0x3c; MAX_HASH_LEN]);
    let mut slot = MaybeUninit::<KeyScheduleWrite>::uninit();
    slot.write(ksw);
    // SAFETY: the slot was initialized above and nothing reads it as a value after this
    unsafe { ptr::drop_in_place(slot.as_mut_ptr()) };
    for (name, offset, len) in secret_fields() {
      // SAFETY: the range is a field of the slot, which the drop overwrote byte by byte
      let bytes = unsafe { slice::from_raw_parts(slot.as_ptr().cast::<u8>().add(offset), len) };
      assert!(bytes.iter().all(|el| *el == 0), "{name} kept its bytes");
    }

    let drops = Cell::new(0);
    let mut slot = MaybeUninit::<Wiped<Probe<'_>>>::uninit();
    slot.write(Wiped::new(Probe([1; 24], &drops)));
    // SAFETY: the slot was initialized above
    let wiped = unsafe { slot.assume_init_mut() };
    wiped.set(Probe([2; 24], &drops));
    assert_eq!((drops.get(), wiped.0.0), (1, [2; 24]));
    // SAFETY: initialized, and nothing reads it as a value after this
    unsafe { ptr::drop_in_place(slot.as_mut_ptr()) };
    assert_eq!(drops.get(), 2);
    // SAFETY: the drop overwrote every byte of the slot
    let bytes =
      unsafe { slice::from_raw_parts(slot.as_ptr().cast::<u8>(), size_of::<Wiped<Probe<'_>>>()) };
    assert!(bytes.iter().all(|el| *el == 0), "a wiped value kept its bytes");
  }

  // Opens the record at the start of `records` in place with `ksr`, the read side of the peer, as
  // its next record. Returns the plaintext.
  fn open_next(ksr: &mut KeyScheduleState, records: &mut [u8]) -> Vec<u8> {
    let (header, rest) = records.split_at_mut(RECORD_HEADER_LEN);
    let len = usize::from(u16::from_be_bytes([header[3], header[4]]));
    ksr.open_record(header, &mut rest[..len]).unwrap().to_vec()
  }

  // Ruling T18-a: records are sealed and opened with the AEAD of the traffic key, expanded once per
  // traffic secret (and again after a key update) on each side, never once per record, and neither
  // sealing nor opening allocates once the buffer of the records is warm. The records are the ones
  // the one-shot AEAD opens.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn tls_record_seal_allocates_and_rekeys_nothing_per_record() {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let rounds: u32 = 1000;
    for suite in CipherSuite::PRIORITY {
      let (server, client) = pair(suite);
      let (_, mut ksw) = server.into_split();
      // The same handshake again: the read side of a peer that opens what the server seals
      let (mut ksr, _) = pair(suite).1.into_split();
      let payload = b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\n{}";
      let mut records = Vec::new();
      seal_payloads(RecordContentTy::ApplicationData, &mut ksw, 16_384, &[payload], &mut records)
        .unwrap();
      let mut first = records.clone();
      let mut expected = payload.to_vec();
      expected.push(RecordContentTy::ApplicationData.into());
      assert_eq!(open_with_one_shot(&client, 0, &mut first), expected, "{suite:?}");
      assert_eq!(records.len(), RECORD_HEADER_LEN + expected.len() + AEAD_TAG_LEN);
      assert_eq!(open_next(ksr.state_mut(), &mut records), expected, "{suite:?}");

      _count_allocations_in(&COUNTER);
      let before = COUNTER.load(Ordering::SeqCst);
      for _ in 0..rounds {
        records.clear();
        seal_payloads(RecordContentTy::ApplicationData, &mut ksw, 16_384, &[payload], &mut records)
          .unwrap();
        let (header, rest) = records.split_at_mut(RECORD_HEADER_LEN);
        let len = usize::from(u16::from_be_bytes([header[3], header[4]]));
        let plaintext = ksr.state_mut().open_record(header, &mut rest[..len]).unwrap();
        assert_eq!(plaintext.len(), expected.len());
      }
      assert_eq!(COUNTER.load(Ordering::SeqCst) - before, 0, "{suite:?}: allocations");
      assert_eq!(ksw.state().expansions, 1, "{suite:?}: key expansions for {} records", rounds + 1);
      assert_eq!(ksr.state().expansions, 1, "{suite:?}: read keys for {} records", rounds + 1);
      assert_eq!(ksw.state().counter(), u64::from(rounds) + 1);
      assert_eq!(ksr.state().counter(), u64::from(rounds) + 1);
      // The next record, which the one-shot AEAD opens at its sequence number too
      records.clear();
      seal_payloads(RecordContentTy::ApplicationData, &mut ksw, 16_384, &[payload], &mut records)
        .unwrap();
      let mut copy = records.clone();
      assert_eq!(open_with_one_shot(&client, u64::from(rounds) + 1, &mut copy), expected);
      assert_eq!(open_next(ksr.state_mut(), &mut records), expected, "{suite:?}");

      // A key update expands the next key once on each side
      ksw.state_mut().rotate().unwrap();
      ksr.state_mut().rotate().unwrap();
      for _ in 0..3 {
        records.clear();
        seal_payloads(RecordContentTy::ApplicationData, &mut ksw, 16_384, &[payload], &mut records)
          .unwrap();
        assert_eq!(open_next(ksr.state_mut(), &mut records), expected, "{suite:?}");
      }
      assert_eq!(ksw.state().expansions, 2, "{suite:?}: after a key update");
      assert_eq!(ksr.state().expansions, 2, "{suite:?}: read side after a key update");
    }
  }
}
