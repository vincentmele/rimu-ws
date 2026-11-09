//! The QPACK decoder over arbitrary bytes, for tests and the fuzzer: whatever the encoder stream
//! and the field sections are, the decoder returns fields or an error of the RFC, never panics,
//! keeps its table within its bounds, gives the same results with and without the memo, and
//! decodes what a conformant encoder writes to what that encoder put in.

use crate::{
  Error,
  collections::VectorUsize,
  http::prefix_int::decode_prefix_int,
  http3::{
    DecodeMemo, DecodeOutcome, H3ErrorCode, H3Settings, Http3Error, QpackDecoder, STATIC_TABLE,
    decode_frame_header, encode_frame_header, encode_static,
  },
};
use alloc::{collections::VecDeque, format, vec::Vec};

type Fields = Vec<(Vec<u8>, Vec<u8>)>;

/// Feeds `data` to the QPACK decoder, the frame and settings codecs and the static encoder.
#[inline]
pub fn check_bytes(data: &[u8]) {
  check_decoders(data);
  check_model(data);
  check_codecs(data);
}

/// Reads `data` as the choices of a conformant encoder: its encoder stream and field sections,
/// fed in pieces and out of order, decode to what it put in, and the decoder stream acknowledges
/// exactly what was inserted.
pub(crate) fn check_model(data: &[u8]) {
  let mut input = Input(data);
  let max_capacity = [0u32, 100, 220, 4096][usize::from(input.byte() & 3)];
  let max_entries = u64::from(max_capacity / 32);
  let mut decoder = QpackDecoder::new(max_capacity, 4).unwrap();
  let mut memo = DecodeMemo::<4>::new();
  // The encoder starts with the whole capacity, as one that uses the dynamic table does
  let mut model = Model { capacity: max_capacity.into(), entries: VecDeque::new(), inserted: 0 };
  let mut peer = Peer { cancelled: Vec::new(), known_received: 0, unacknowledged: Vec::new() };
  let mut encoder_stream = Vec::new();
  wire::set_capacity(&mut encoder_stream, max_capacity.into());
  let mut kept: Vec<(u64, Vec<u64>, Vec<u8>, Fields)> = Vec::new();
  let mut stream = 0u64;
  // Instructions, and bytes copied out of the table, written since the turn of the decoder
  // started: the encoder keeps them below the budgets of a turn (at least 64 instructions and 4
  // times the capacity), starting a new turn when it would go past half of them
  let (mut since_flush, mut copied) = (0u32, 0u64);
  fn new_turn(decoder: &mut QpackDecoder, encoder_stream: &mut Vec<u8>) {
    feed(decoder, encoder_stream, usize::MAX);
    decoder.start_turn();
  }
  while !input.0.is_empty() {
    if since_flush >= 32 {
      new_turn(&mut decoder, &mut encoder_stream);
      (since_flush, copied) = (0, 0);
    }
    match input.byte() % 10 {
      0 => {
        let capacity = u64::from(input.u16()) % (u64::from(max_capacity) + 1);
        wire::set_capacity(&mut encoder_stream, capacity);
        since_flush += 1;
        model.capacity = capacity;
        model.evict_down_to(capacity);
      }
      1 | 2 => {
        let (name, value, huffman) = (input.word(), input.word(), input.bit());
        if model.insert(&name, &value) {
          wire::insert_literal(&mut encoder_stream, &name, &value, huffman);
          since_flush += 1;
        }
      }
      3 => {
        let idx = input.byte() % 99;
        let (value, huffman) = (input.word(), input.bit());
        let name = STATIC_TABLE.get(usize::from(idx)).unwrap().0;
        if model.insert(name, &value) {
          wire::insert_name_ref(&mut encoder_stream, true, idx.into(), &value, huffman);
          since_flush += 1;
        }
      }
      4 | 5 => {
        let Some(relative) = model.pick_relative(&mut input) else {
          continue;
        };
        let duplicate = input.bit();
        let (name, old_value) = model.relative(relative).clone();
        let value = if duplicate { old_value } else { input.word() };
        let to_copy = u64::try_from(name.len() + if duplicate { value.len() } else { 0 }).unwrap();
        if copied + to_copy > u64::from(max_capacity) {
          new_turn(&mut decoder, &mut encoder_stream);
          (since_flush, copied) = (0, 0);
        }
        copied += to_copy;
        if duplicate {
          if model.insert(&name, &value) {
            wire::duplicate(&mut encoder_stream, relative);
            since_flush += 1;
          }
        } else {
          let huffman = input.bit();
          if model.insert(&name, &value) {
            wire::insert_name_ref(&mut encoder_stream, false, relative, &value, huffman);
            since_flush += 1;
          }
        }
      }
      6 => {
        // A piece of the encoder stream arrives
        let len = usize::from(input.byte()).min(encoder_stream.len());
        feed(&mut decoder, &mut encoder_stream, len);
      }
      7 => {
        stream = stream.wrapping_add(4);
        decoder.on_stream_cancelled(stream).unwrap();
        if max_capacity > 0 {
          peer.cancelled.push(stream);
        }
      }
      8 => {
        // A section seen before, repeated byte for byte while it is decodable
        let Some((ric, refs, section, expected)) =
          kept.get(usize::from(input.byte()) % kept.len().max(1)).cloned()
        else {
          continue;
        };
        feed(&mut decoder, &mut encoder_stream, usize::MAX);
        if ric > 0 && ric <= model.inserted.saturating_sub(max_entries) {
          continue;
        }
        stream = stream.wrapping_add(4);
        let rslt = decode(&mut decoder, &mut memo, input.bit(), stream, &section);
        if refs.iter().all(|abs| *abs >= model.oldest()) {
          assert_eq!(
            rslt.unwrap(),
            (DecodeOutcome::Done { referenced_dynamic: ric > 0 }, expected)
          );
          if ric > 0 {
            peer.unacknowledged.push((stream, ric));
          }
        } else {
          assert!(matches!(
            rslt,
            Err(Error::Http3Close(
              H3ErrorCode::QpackDecompressionFailed,
              Http3Error::InvalidDynamicIndex
            ))
          ));
          return;
        }
      }
      _ => {
        let (ric, refs, section, expected) = model.section(&mut input, max_entries);
        stream = stream.wrapping_add(4);
        // Before the inserts that it needs, the stream blocks while the decoder can tell the
        // Required Insert Count apart
        if ric > decoder.insert_count() && ric <= decoder.insert_count().wrapping_add(max_entries) {
          let rslt = decode(&mut decoder, &mut memo, input.bit(), stream, &section);
          assert_eq!(
            rslt.unwrap(),
            (DecodeOutcome::Blocked { required_insert_count: ric }, Vec::new())
          );
        }
        feed(&mut decoder, &mut encoder_stream, usize::MAX);
        let rslt = decode(&mut decoder, &mut memo, input.bit(), stream, &section);
        assert_eq!(
          rslt.unwrap(),
          (DecodeOutcome::Done { referenced_dynamic: ric > 0 }, expected.clone())
        );
        if ric > 0 {
          peer.unacknowledged.push((stream, ric));
        }
        if kept.len() < 8 {
          kept.push((ric, refs, section, expected));
        }
      }
    }
    decoder.check_invariants();
    if input.bit() {
      peer.read(&mut decoder);
    }
  }
  feed(&mut decoder, &mut encoder_stream, usize::MAX);
  peer.read(&mut decoder);
  decoder.check_invariants();
  // Every insert is acknowledged, every section and every cancellation was seen
  assert_eq!(peer.known_received, decoder.insert_count());
  assert!(peer.unacknowledged.is_empty());
  assert!(peer.cancelled.is_empty());
}

// Two decoders, one with a memo, fed the same arbitrary encoder stream and sections: they return
// the same, their errors are those of the RFC, and their state stays consistent
fn check_decoders(data: &[u8]) {
  let Some((setup, mut rest)) = data.split_first() else {
    return;
  };
  let capacity = [0u32, 64, 220, 1024][usize::from(setup & 3)];
  let blocked = u16::from((setup >> 2) & 3);
  let mut plain = QpackDecoder::new(capacity, blocked).unwrap();
  let mut memoized = QpackDecoder::new(capacity, blocked).unwrap();
  let mut memo = DecodeMemo::<4>::new();
  let mut encoder_stream = Vec::new();
  let mut sections: Vec<Vec<u8>> = Vec::new();
  while let Some((tag, tail)) = rest.split_first() {
    let (chunk, tail) = tail.split_at(usize::from(tag >> 3).min(tail.len()));
    rest = tail;
    let stream = u64::from(tag >> 5).wrapping_mul(4);
    match tag & 7 {
      0 | 1 => {
        encoder_stream.extend_from_slice(chunk);
        let one = plain.on_encoder_stream(&encoder_stream);
        let other = memoized.on_encoder_stream(&encoder_stream);
        assert_eq!(format!("{one:?}"), format!("{other:?}"));
        match one {
          Ok(len) => {
            assert!(len <= encoder_stream.len());
            let _ = encoder_stream.drain(..len);
          }
          Err(err) => {
            assert!(
              matches!(
                err,
                Error::Http3Close(
                  H3ErrorCode::QpackEncoderStreamError | H3ErrorCode::ExcessiveLoad,
                  _
                )
              ),
              "{err:?}"
            );
            return;
          }
        }
      }
      2 | 3 => {
        let section = match sections.get(usize::from(tag >> 4) % sections.len().max(1)) {
          Some(elem) if tag & 1 == 1 => elem.clone(),
          _ => chunk.to_vec(),
        };
        let one = decode(&mut plain, &mut memo, false, stream, &section);
        let other = decode(&mut memoized, &mut memo, true, stream, &section);
        assert_eq!(format!("{one:?}"), format!("{other:?}"));
        assert_eq!(plain.decoder_stream_output(), memoized.decoder_stream_output());
        if let Err(err) = one {
          assert!(
            matches!(
              err,
              Error::Http3Close(
                H3ErrorCode::QpackDecompressionFailed | H3ErrorCode::ExcessiveLoad,
                _
              )
            ),
            "{err:?}"
          );
          return;
        }
        if sections.len() < 8 {
          sections.push(section);
        }
      }
      4 => {
        let one = plain.on_stream_cancelled(stream);
        let other = memoized.on_stream_cancelled(stream);
        assert_eq!(format!("{one:?}"), format!("{other:?}"));
        if one.is_err() {
          return;
        }
      }
      5 | 6 => {
        let len = usize::from(tag >> 3);
        plain.consume_decoder_output(len);
        memoized.consume_decoder_output(len);
      }
      _ if *tag == 0xff => {
        // A new connection on pooled decoders; the memo stays and the kept sections are tried
        // again: the memo must not replay the old table
        plain.reset(capacity, blocked).unwrap();
        memoized.reset(capacity, blocked).unwrap();
        encoder_stream.clear();
      }
      _ => {
        plain.start_turn();
        memoized.start_turn();
      }
    }
    assert_eq!(plain.decoder_stream_output(), memoized.decoder_stream_output());
    assert_eq!(plain.insert_count(), memoized.insert_count());
    plain.check_invariants();
    memoized.check_invariants();
  }
}

// The frame header, settings and static encoder codecs over the same bytes
fn check_codecs(data: &[u8]) {
  let mut out = [0u8; 64];
  match decode_frame_header(data) {
    Ok(Some((ty, len, header_len))) => {
      assert!(header_len <= data.len());
      let written = encode_frame_header(ty, len, &mut out).unwrap();
      assert!(written <= header_len);
      assert_eq!(
        decode_frame_header(out.get(..written).unwrap()).unwrap(),
        Some((ty, len, written))
      );
    }
    Ok(None) => assert!(data.len() < 16),
    Err(err) => assert!(matches!(
      err,
      Error::Http3Close(H3ErrorCode::FrameUnexpected, Http3Error::ReservedFrameType)
    )),
  }
  match H3Settings::decode(data) {
    Ok(settings) => {
      if let Some(len) = settings.encode(&mut out) {
        let (_, _, header_len) = decode_frame_header(&out).unwrap().unwrap();
        let payload = out.get(header_len..len).unwrap();
        assert_eq!(H3Settings::decode(payload).unwrap(), settings);
      }
    }
    Err(err) => assert!(matches!(
      err,
      Error::Http3Close(
        H3ErrorCode::SettingsError | H3ErrorCode::FrameError | H3ErrorCode::ExcessiveLoad,
        _
      )
    )),
  }
  // Fields of arbitrary bytes go through the static encoder and come back
  let mut fields: Vec<(&[u8], &[u8])> = Vec::new();
  let mut rest = data;
  while let Some((len, tail)) = rest.split_first() {
    let (name, tail) = tail.split_at(usize::from(len & 15).min(tail.len()));
    let (value, tail) = tail.split_at(usize::from(len >> 4).min(tail.len()));
    fields.push((name, value));
    rest = tail;
  }
  let mut section = VectorUsize::new();
  encode_static(&fields, &mut section).unwrap();
  let mut decoder = QpackDecoder::new(0, 0).unwrap();
  let mut memo = DecodeMemo::<0>::new();
  let (outcome, decoded) = decode(&mut decoder, &mut memo, false, 0, &section).unwrap();
  assert_eq!(outcome, DecodeOutcome::Done { referenced_dynamic: false });
  assert_eq!(decoded.len(), fields.len());
  for ((name, value), (expected_name, expected_value)) in decoded.iter().zip(fields) {
    assert_eq!((name.as_slice(), value.as_slice()), (expected_name, expected_value));
  }
}

fn decode<const N: usize>(
  decoder: &mut QpackDecoder,
  memo: &mut DecodeMemo<N>,
  with_memo: bool,
  stream: u64,
  section: &[u8],
) -> crate::Result<(DecodeOutcome, Fields)> {
  let mut scratch = VectorUsize::new();
  let mut fields = Vec::new();
  let mut sink = |name: &[u8], value: &[u8]| {
    fields.push((name.to_vec(), value.to_vec()));
    Ok(())
  };
  let outcome = if with_memo {
    decoder.decode_with_memo(memo, stream, section, &mut scratch, &mut sink)?
  } else {
    decoder.decode(stream, section, &mut scratch, &mut sink)?
  };
  // Nothing goes to the sink of a blocked stream
  if matches!(outcome, DecodeOutcome::Blocked { .. }) {
    assert!(fields.is_empty());
  }
  Ok((outcome, fields))
}

// Gives the decoder up to `len` bytes of the encoder stream; what it does not consume stays.
fn feed(decoder: &mut QpackDecoder, encoder_stream: &mut Vec<u8>, len: usize) {
  let total = encoder_stream.len();
  let len = len.min(total);
  let consumed = decoder.on_encoder_stream(encoder_stream.get(..len).unwrap()).unwrap();
  assert!(consumed <= len);
  let _ = encoder_stream.drain(..consumed);
  // The model writes whole instructions: given all of them, the decoder consumes all of them
  if len == total {
    assert!(encoder_stream.is_empty());
  }
}

struct Input<'bytes>(&'bytes [u8]);

impl Input<'_> {
  fn bit(&mut self) -> bool {
    self.byte() & 1 == 1
  }

  fn byte(&mut self) -> u8 {
    let Some((first, rest)) = self.0.split_first() else {
      return 0;
    };
    self.0 = rest;
    *first
  }

  fn u16(&mut self) -> u16 {
    u16::from_be_bytes([self.byte(), self.byte()])
  }

  // A field name or value: lower-case letters, digits and a few symbols, 0 to 47 bytes
  fn word(&mut self) -> Vec<u8> {
    let len = usize::from(self.byte() % 48);
    let alphabet = b"abcdefghijklmnopqrstuvwxyz0123456789-:/._~ ";
    (0..len).map(|_| alphabet.get(usize::from(self.byte() % 43)).copied().unwrap_or(b'a')).collect()
  }
}

// The dynamic table as the encoder sees it
struct Model {
  capacity: u64,
  entries: VecDeque<(Vec<u8>, Vec<u8>)>,
  inserted: u64,
}

impl Model {
  fn evict_down_to(&mut self, size: u64) {
    while self.size() > size {
      let _ = self.entries.pop_front();
    }
  }

  // Inserts if the entry fits, as a conformant encoder does
  fn insert(&mut self, name: &[u8], value: &[u8]) -> bool {
    let size = u64::try_from(name.len() + value.len()).unwrap() + 32;
    if size > self.capacity {
      return false;
    }
    self.evict_down_to(self.capacity - size);
    self.entries.push_back((name.to_vec(), value.to_vec()));
    self.inserted += 1;
    true
  }

  fn oldest(&self) -> u64 {
    self.inserted - u64::try_from(self.entries.len()).unwrap()
  }

  fn pick_relative(&self, input: &mut Input<'_>) -> Option<u64> {
    if self.entries.is_empty() {
      return None;
    }
    Some(u64::from(input.byte()) % u64::try_from(self.entries.len()).unwrap())
  }

  fn relative(&self, relative: u64) -> &(Vec<u8>, Vec<u8>) {
    let idx = self.entries.len() - 1 - usize::try_from(relative).unwrap();
    self.entries.get(idx).unwrap()
  }

  fn absolute(&self, abs: u64) -> &(Vec<u8>, Vec<u8>) {
    self.entries.get(usize::try_from(abs - self.oldest()).unwrap()).unwrap()
  }

  // A field section of up to four field lines of every representation, with its Required Insert
  // Count, the absolute indices that it references and the fields that it decodes to
  fn section(&self, input: &mut Input<'_>, max_entries: u64) -> (u64, Vec<u64>, Vec<u8>, Fields) {
    enum Line {
      Indexed(u64),
      Literal(Vec<u8>, Vec<u8>),
      NameRef(u64, Vec<u8>),
      StaticIndexed(u8),
      StaticNameRef(u8, Vec<u8>),
    }
    let mut lines = Vec::new();
    let mut refs = Vec::new();
    let mut expected = Vec::new();
    for _ in 0..1 + input.byte() % 4 {
      let choice = input.byte() % 5;
      let live = !self.entries.is_empty();
      let abs = if live {
        self.oldest() + u64::from(input.byte()) % u64::try_from(self.entries.len()).unwrap()
      } else {
        0
      };
      let line = match choice {
        0 if live => Line::Indexed(abs),
        1 if live => Line::NameRef(abs, input.word()),
        2 => Line::Literal(input.word(), input.word()),
        3 => Line::StaticNameRef(input.byte() % 99, input.word()),
        _ => Line::StaticIndexed(input.byte() % 99),
      };
      match &line {
        Line::Indexed(abs) => {
          refs.push(*abs);
          expected.push(self.absolute(*abs).clone());
        }
        Line::Literal(name, value) => expected.push((name.clone(), value.clone())),
        Line::NameRef(abs, value) => {
          refs.push(*abs);
          expected.push((self.absolute(*abs).0.clone(), value.clone()));
        }
        Line::StaticIndexed(idx) => {
          let (name, value) = STATIC_TABLE.get(usize::from(*idx)).unwrap();
          expected.push((name.to_vec(), value.to_vec()));
        }
        Line::StaticNameRef(idx, value) => {
          expected.push((STATIC_TABLE.get(usize::from(*idx)).unwrap().0.to_vec(), value.clone()));
        }
      }
      lines.push(line);
    }
    let ric = refs.iter().max().map_or(0, |el| el + 1);
    let base = u64::from(input.byte() % 4) + ric.saturating_sub(u64::from(input.byte() % 4));
    let mut section = Vec::new();
    wire::prefix(&mut section, ric, base, max_entries);
    for line in lines {
      let (never_indexed, huffman) = (input.bit(), input.bit());
      match line {
        Line::Indexed(abs) if abs < base => wire::indexed(&mut section, false, base - 1 - abs),
        Line::Indexed(abs) => wire::indexed_post_base(&mut section, abs - base),
        Line::Literal(name, value) => {
          wire::literal(&mut section, never_indexed, &name, &value, huffman)
        }
        Line::NameRef(abs, value) if abs < base => {
          wire::name_ref(&mut section, false, never_indexed, base - 1 - abs, &value, huffman)
        }
        Line::NameRef(abs, value) => {
          wire::post_base_name_ref(&mut section, never_indexed, abs - base, &value, huffman)
        }
        Line::StaticIndexed(idx) => wire::indexed(&mut section, true, idx.into()),
        Line::StaticNameRef(idx, value) => {
          wire::name_ref(&mut section, true, never_indexed, idx.into(), &value, huffman)
        }
      }
    }
    (ric, refs, section, expected)
  }

  fn size(&self) -> u64 {
    self
      .entries
      .iter()
      .map(|(name, value)| u64::try_from(name.len() + value.len()).unwrap() + 32)
      .sum()
  }
}

// The encoder side of the decoder stream: what it learns from the instructions
struct Peer {
  cancelled: Vec<u64>,
  known_received: u64,
  unacknowledged: Vec<(u64, u64)>,
}

impl Peer {
  fn read(&mut self, decoder: &mut QpackDecoder) {
    let out = decoder.decoder_stream_output().to_vec();
    decoder.consume_decoder_output(out.len());
    let mut rest = out.as_slice();
    while let Some(first) = rest.first().copied() {
      let prefix_bits = if first & 0b1000_0000 != 0 { 7 } else { 6 };
      let (value, len) = decode_prefix_int(rest, prefix_bits).unwrap().unwrap();
      rest = rest.get(len..).unwrap();
      if first & 0b1000_0000 != 0 {
        // Section Acknowledgment: of a section of the stream that referenced the dynamic table
        let idx = self.unacknowledged.iter().position(|el| el.0 == value).unwrap();
        let (_, ric) = self.unacknowledged.remove(idx);
        self.known_received = self.known_received.max(ric);
      } else if first & 0b0100_0000 != 0 {
        let idx = self.cancelled.iter().position(|el| *el == value).unwrap();
        let _ = self.cancelled.remove(idx);
      } else {
        // Insert Count Increment: never 0, never past the inserts (RFC 9204 section 4.4.3)
        assert!(value > 0);
        self.known_received += value;
      }
      assert!(self.known_received <= decoder.insert_count());
    }
  }
}

/// Writers of encoder instructions and field line representations (RFC 9204 section 4), as an
/// encoder writes them.
pub(crate) mod wire {
  use crate::{
    collections::VectorUsize,
    http::{
      huffman::{huffman_decode, huffman_encode},
      prefix_int::encode_prefix_int,
    },
  };
  use alloc::vec::Vec;

  /// A prefixed integer.
  pub(crate) fn int(out: &mut Vec<u8>, value: u64, prefix_bits: u8, flags: u8) {
    let mut buffer = [0u8; 16];
    let len = encode_prefix_int(value, prefix_bits, flags, &mut buffer).unwrap();
    out.extend_from_slice(buffer.get(..len).unwrap());
  }

  /// A string literal with a prefix of `prefix_bits` bits: the Huffman bit is the highest of
  /// them, the length takes the others.
  pub(crate) fn string(out: &mut Vec<u8>, bytes: &[u8], prefix_bits: u8, flags: u8, huffman: bool) {
    let h_bit = 1u8 << (prefix_bits - 1);
    if huffman {
      let mut coded = VectorUsize::new();
      huffman_encode(bytes, &mut coded).unwrap();
      // Outside of tests the encoder writes a string raw when Huffman coding would lengthen it
      let mut back = VectorUsize::new();
      if huffman_decode(&coded, &mut back).is_ok() && back.as_slice() == bytes {
        int(out, coded.len().try_into().unwrap(), prefix_bits - 1, flags | h_bit);
        out.extend_from_slice(&coded);
        return;
      }
    }
    int(out, bytes.len().try_into().unwrap(), prefix_bits - 1, flags);
    out.extend_from_slice(bytes);
  }

  /// Set Dynamic Table Capacity.
  pub(crate) fn set_capacity(out: &mut Vec<u8>, capacity: u64) {
    int(out, capacity, 5, 0b0010_0000);
  }

  /// Insert with Name Reference, static or relative to the last insert.
  pub(crate) fn insert_name_ref(
    out: &mut Vec<u8>,
    is_static: bool,
    idx: u64,
    value: &[u8],
    huffman: bool,
  ) {
    int(out, idx, 6, if is_static { 0b1100_0000 } else { 0b1000_0000 });
    string(out, value, 8, 0, huffman);
  }

  /// Insert with Literal Name.
  pub(crate) fn insert_literal(out: &mut Vec<u8>, name: &[u8], value: &[u8], huffman: bool) {
    string(out, name, 6, 0b0100_0000, huffman);
    string(out, value, 8, 0, huffman);
  }

  /// Duplicate, relative to the last insert.
  pub(crate) fn duplicate(out: &mut Vec<u8>, relative: u64) {
    int(out, relative, 5, 0);
  }

  /// The prefix of a field section (RFC 9204 section 4.5.1) for a table of `max_entries`.
  pub(crate) fn prefix(out: &mut Vec<u8>, ric: u64, base: u64, max_entries: u64) {
    let encoded = if ric == 0 { 0 } else { ric % (2 * max_entries) + 1 };
    int(out, encoded, 8, 0);
    if base >= ric {
      int(out, base - ric, 7, 0);
    } else {
      int(out, ric - base - 1, 7, 0b1000_0000);
    }
  }

  /// Indexed Field Line, static or relative to the Base.
  pub(crate) fn indexed(out: &mut Vec<u8>, is_static: bool, idx: u64) {
    int(out, idx, 6, if is_static { 0b1100_0000 } else { 0b1000_0000 });
  }

  /// Indexed Field Line with Post-Base Index.
  pub(crate) fn indexed_post_base(out: &mut Vec<u8>, idx: u64) {
    int(out, idx, 4, 0b0001_0000);
  }

  /// Literal Field Line with Name Reference, static or relative to the Base.
  pub(crate) fn name_ref(
    out: &mut Vec<u8>,
    is_static: bool,
    never_indexed: bool,
    idx: u64,
    value: &[u8],
    huffman: bool,
  ) {
    let flags = 0b0100_0000 | if never_indexed { 0b0010_0000 } else { 0 };
    int(out, idx, 4, flags | if is_static { 0b0001_0000 } else { 0 });
    string(out, value, 8, 0, huffman);
  }

  /// Literal Field Line with Post-Base Name Reference.
  pub(crate) fn post_base_name_ref(
    out: &mut Vec<u8>,
    never_indexed: bool,
    idx: u64,
    value: &[u8],
    huffman: bool,
  ) {
    int(out, idx, 3, if never_indexed { 0b0000_1000 } else { 0 });
    string(out, value, 8, 0, huffman);
  }

  /// Literal Field Line with Literal Name.
  pub(crate) fn literal(
    out: &mut Vec<u8>,
    never_indexed: bool,
    name: &[u8],
    value: &[u8],
    huffman: bool,
  ) {
    string(out, name, 4, 0b0010_0000 | if never_indexed { 0b0001_0000 } else { 0 }, huffman);
    string(out, value, 8, 0, huffman);
  }
}

#[cfg(test)]
mod tests {
  use crate::http3::qpack_check::check_bytes;
  use alloc::vec::Vec;

  #[test]
  fn arbitrary_bytes_do_not_break_the_qpack_decoder() {
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    let mut next = || {
      state ^= state << 13;
      state ^= state >> 7;
      state ^= state << 17;
      state
    };
    let mut data = Vec::new();
    for _ in 0..3_000 {
      data.clear();
      for _ in 0..next() % 512 {
        data.push(u8::try_from(next() & 0xff).unwrap());
      }
      check_bytes(&data);
    }
  }
}
