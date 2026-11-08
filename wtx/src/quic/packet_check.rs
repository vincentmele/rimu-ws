//! The wire codecs over arbitrary bytes, for tests and the fuzzer: whatever the input is, they
//! return a value or an error, never panic, and the values are consistent with the input.

use crate::quic::{
  PacketTy, QUIC_V1, TransportParams, VARINT_MAX, decode_varint, encode_varint, parse_header,
  varint_len, write_retry, write_version_negotiation,
};

/// Feeds `data` to every codec of the module. The first byte is a selector.
#[inline]
pub fn check_bytes(data: &[u8]) {
  let Some((&selector, rest)) = data.split_first() else {
    return;
  };
  check_datagram(rest, usize::from(selector >> 3));
  check_varint(rest);
  check_transport_params(rest);
  check_stateless_packets(rest);
}

// Walks through the coalesced packets of a datagram
fn check_datagram(datagram: &[u8], short_dcid_len: usize) {
  let mut rest = datagram;
  while !rest.is_empty() {
    let Ok(header) = parse_header(rest, short_dcid_len) else {
      return;
    };
    assert!(header.pn_offset <= header.packet_end);
    assert!(header.packet_end <= rest.len());
    assert!(header.packet_end > 0);
    assert!(header.dcid.len() <= rest.len());
    assert!(header.scid.len() <= rest.len());
    assert!(header.token.len() <= rest.len());
    if header.version == QUIC_V1 && header.ty != PacketTy::OneRtt {
      assert!(header.dcid.len() <= 20 && header.scid.len() <= 20);
    }
    match header.ty {
      PacketTy::Initial | PacketTy::ZeroRtt | PacketTy::Handshake => {
        assert!(header.packet_end - header.pn_offset >= 20);
        assert!(header.pn_offset >= 8);
      }
      PacketTy::OneRtt => {
        assert_eq!(header.dcid.len(), short_dcid_len);
        assert_eq!(header.pn_offset, short_dcid_len + 1);
        assert_eq!(header.packet_end, rest.len());
        assert!(header.packet_end - header.pn_offset >= 20);
      }
      PacketTy::Retry | PacketTy::UnknownVersion | PacketTy::VersionNegotiation => {
        assert_eq!(header.packet_end, rest.len());
        assert_eq!(header.pn_offset, rest.len());
      }
    }
    let Some(next) = rest.get(header.packet_end..) else {
      return;
    };
    rest = next;
  }
}

fn check_stateless_packets(data: &[u8]) {
  let Some((&[dcid_len, scid_len, odcid_len], rest)) = data.split_first_chunk::<3>() else {
    return;
  };
  let (dcid_len, scid_len, odcid_len) =
    (usize::from(dcid_len % 21), usize::from(scid_len % 21), usize::from(odcid_len % 21));
  let Some(dcid) = rest.get(..dcid_len) else {
    return;
  };
  let Some(scid) = rest.get(dcid_len..dcid_len + scid_len) else {
    return;
  };
  let Some(odcid) = rest.get(dcid_len + scid_len..dcid_len + scid_len + odcid_len) else {
    return;
  };
  let token = rest.get(dcid_len + scid_len + odcid_len..).unwrap_or_default();

  let mut out = [0; 1024];
  let len = write_version_negotiation(dcid, scid, &mut out);
  assert_eq!(len, 1 + 4 + 1 + dcid.len() + 1 + scid.len() + 4);
  let header = parse_header(&out[..len], 8).unwrap();
  assert_eq!(header.ty, PacketTy::VersionNegotiation);
  assert_eq!((header.dcid, header.scid), (dcid, scid));

  if let Ok(len) = write_retry(dcid, scid, odcid, token, &mut out) {
    let header = parse_header(&out[..len], 8).unwrap();
    assert_eq!(header.ty, PacketTy::Retry);
    assert_eq!((header.dcid, header.scid, header.token), (dcid, scid, token));
    assert_eq!(header.packet_end, len);
  } else {
    assert!(token.len() > 1024 - 100);
  }
}

fn check_transport_params(data: &[u8]) {
  for from_server in [false, true] {
    let Ok(params) = TransportParams::decode(data, from_server) else {
      continue;
    };
    let mut buffer = [0; 512];
    let len = params.encode(&mut buffer).unwrap();
    assert_eq!(TransportParams::decode(&buffer[..len], from_server).unwrap(), params);
  }
}

fn check_varint(data: &[u8]) {
  let Some((value, len)) = decode_varint(data) else {
    return;
  };
  assert!(matches!(len, 1 | 2 | 4 | 8));
  assert!(len <= data.len());
  assert!(value <= VARINT_MAX);
  let mut out = [0; 8];
  let shortest = encode_varint(value, &mut out).unwrap();
  assert_eq!(shortest, varint_len(value));
  assert!(shortest <= len);
  assert_eq!(decode_varint(&out[..shortest]), Some((value, shortest)));
}

#[cfg(test)]
mod tests {
  use crate::quic::packet_check::check_bytes;

  #[test]
  fn arbitrary_bytes_do_not_break_the_codecs() {
    let mut state = 0x853c_49e6_748f_ea9bu64;
    let mut next = || {
      state ^= state << 13;
      state ^= state >> 7;
      state ^= state << 17;
      state
    };
    let mut data = [0u8; 300];
    for round in 0..3_000 {
      let len = usize::try_from(next() % 300).unwrap();
      for byte in &mut data[..len] {
        *byte = u8::try_from(next() & 0xff).unwrap();
      }
      // Make long headers of version 1 and transport parameter lists more frequent
      if round % 3 == 0 && len > 6 {
        data[1] = 0xc0 | (data[1] & 0x3f);
        data[2..6].copy_from_slice(&1u32.to_be_bytes());
      }
      check_bytes(&data[..len]);
    }
  }
}
