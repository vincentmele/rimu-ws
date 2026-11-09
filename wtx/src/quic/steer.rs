//! The classic BPF program that steers the datagrams of a `SO_REUSEPORT` group of UDP sockets,
//! one per worker, to the worker that the first byte of their destination connection ID names
//! (spec section 5.11), attached with `SO_ATTACH_REUSEPORT_CBPF`.
//!
//! The program sees the UDP payload. It returns `DCID[0] mod workers`: byte 1 of a short header,
//! byte 6 of a long header (after the first byte, the version and the length of the DCID). For a
//! datagram too short to have that byte it returns an index past the group, and the kernel picks
//! a socket by its hash instead (ruling T10-i). The program needs `BPF_ALU | BPF_MOD`, Linux 3.7
//! or later; `SO_ATTACH_REUSEPORT_CBPF` itself needs Linux 4.5.

/// The instructions of the program of [`steering_cbpf`].
pub const STEERING_PROGRAM_LEN: usize = 12;

// Classic BPF (linux/bpf_common.h and linux/filter.h)
const BPF_LD: u16 = 0x00;
const BPF_ALU: u16 = 0x04;
const BPF_JMP: u16 = 0x05;
const BPF_RET: u16 = 0x06;
const BPF_W: u16 = 0x00;
const BPF_B: u16 = 0x10;
const BPF_ABS: u16 = 0x20;
const BPF_LEN: u16 = 0x80;
const BPF_MOD: u16 = 0x90;
const BPF_JA: u16 = 0x00;
const BPF_JGE: u16 = 0x30;
const BPF_JSET: u16 = 0x40;
const BPF_K: u16 = 0x00;
const BPF_A: u16 = 0x10;
// Past every socket of a group, which makes the kernel pick one by its hash
const FALLBACK: u32 = u32::MAX;
// The byte of a short header and of a long header that is the first of the destination CID
const LONG_DCID_AT: u32 = 6;
const SHORT_DCID_AT: u32 = 1;

/// The program of [`steering_cbpf`], given to `SO_ATTACH_REUSEPORT_CBPF` in a `sock_fprog`.
pub type SteeringProgram = [libc::sock_filter; STEERING_PROGRAM_LEN];

/// The classic BPF program that steers each datagram to the socket of index
/// `DCID[0] mod workers` of its `SO_REUSEPORT` group, to attach with `SO_ATTACH_REUSEPORT_CBPF`
/// (Linux 4.5; the program uses `BPF_ALU | BPF_MOD`, Linux 3.7). The first byte of the destination
/// connection ID is byte 1 of a short header and byte 6 of a long header. A datagram too short to
/// have it gets an index past the group, which makes the kernel pick a socket by its hash.
/// `workers` is at least one.
#[inline]
pub fn steering_cbpf(workers: u8) -> SteeringProgram {
  const fn insn(code: u16, jt: u8, jf: u8, k: u32) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
  }
  // Jumps count the instructions that they skip
  [
    // 0: A = the length of the datagram; long enough for byte 1, or to 11
    insn(BPF_LD | BPF_W | BPF_LEN, 0, 0, 0),
    insn(BPF_JMP | BPF_JGE | BPF_K, 0, 9, SHORT_DCID_AT + 1),
    // 2: A = the first byte; a long header goes to 6
    insn(BPF_LD | BPF_B | BPF_ABS, 0, 0, 0),
    insn(BPF_JMP | BPF_JSET | BPF_K, 2, 0, 0x80),
    // 4: A = byte 1, to 9
    insn(BPF_LD | BPF_B | BPF_ABS, 0, 0, SHORT_DCID_AT),
    insn(BPF_JMP | BPF_JA, 0, 0, 3),
    // 6: long enough for byte 6, or to 11; A = byte 6
    insn(BPF_LD | BPF_W | BPF_LEN, 0, 0, 0),
    insn(BPF_JMP | BPF_JGE | BPF_K, 0, 3, LONG_DCID_AT + 1),
    insn(BPF_LD | BPF_B | BPF_ABS, 0, 0, LONG_DCID_AT),
    // 9: the index of the socket
    insn(BPF_ALU | BPF_MOD | BPF_K, 0, 0, u32::from(workers.max(1))),
    insn(BPF_RET | BPF_A, 0, 0, 0),
    // 11: the hash of the kernel
    insn(BPF_RET | BPF_K, 0, 0, FALLBACK),
  ]
}

#[cfg(test)]
mod tests {
  use crate::quic::steer::{
    BPF_A, BPF_ABS, BPF_ALU, BPF_B, BPF_JA, BPF_JGE, BPF_JMP, BPF_JSET, BPF_K, BPF_LD, BPF_LEN,
    BPF_MOD, BPF_RET, BPF_W, STEERING_PROGRAM_LEN, SteeringProgram, steering_cbpf,
  };

  // What the kernel computes: the return value of the program over `packet`, or `None` for an
  // instruction that it does not know, a jump out of the program or a load past the packet,
  // which ends the program with zero in the kernel and is a bug of the program here.
  fn run(program: &SteeringProgram, packet: &[u8]) -> Option<u32> {
    let mut acc = 0u32;
    let mut pc = 0usize;
    loop {
      let insn = program.get(pc)?;
      pc += 1;
      let class = insn.code & 0x07;
      match class {
        BPF_LD => match insn.code & 0xe0 {
          BPF_LEN if insn.code & 0x18 == BPF_W => acc = u32::try_from(packet.len()).ok()?,
          BPF_ABS if insn.code & 0x18 == BPF_B => {
            acc = u32::from(*packet.get(usize::try_from(insn.k).ok()?)?);
          }
          _ => return None,
        },
        BPF_ALU => {
          if insn.code != (BPF_ALU | BPF_MOD | BPF_K) || insn.k == 0 {
            return None;
          }
          acc %= insn.k;
        }
        BPF_JMP => {
          let taken = match insn.code & 0xf0 {
            BPF_JA => {
              pc += usize::try_from(insn.k).ok()?;
              continue;
            }
            BPF_JGE => acc >= insn.k,
            BPF_JSET => acc & insn.k != 0,
            _ => return None,
          };
          pc += usize::from(if taken { insn.jt } else { insn.jf });
        }
        BPF_RET => {
          return match insn.code & 0x18 {
            BPF_K => Some(insn.k),
            BPF_A => Some(acc),
            _ => None,
          };
        }
        _ => return None,
      }
    }
  }

  // Short headers are steered by byte 1, long ones by byte 6, modulo the workers; a datagram
  // without that byte gets an index past the group, which makes the kernel fall back to its hash.
  #[test]
  fn cbpf_program_selects_dcid_byte() {
    for workers in [1u8, 2, 3, 7, 64, 255] {
      let program = steering_cbpf(workers);
      assert_eq!(program.len(), STEERING_PROGRAM_LEN);
      for byte in [0u8, 1, 2, 5, 63, 64, 200, 255] {
        let expected = u32::from(byte) % u32::from(workers);
        // A short header: first byte 0b01xx_xxxx, then the DCID
        let mut short = [0x41u8; 30];
        short[1] = byte;
        assert_eq!(run(&program, &short), Some(expected), "{workers} {byte} short");
        assert_eq!(run(&program, &short[..2]), Some(expected), "{workers} {byte} short, 2 B");
        // A long header: first byte, version, DCID length, DCID
        let mut long = [0u8; 1200];
        long[..6].copy_from_slice(&[0xc3, 0, 0, 0, 1, 8]);
        long[6] = byte;
        // Byte 1 of a long header is part of the version, never the steering byte
        long[1] = byte.wrapping_add(1);
        assert_eq!(run(&program, &long), Some(expected), "{workers} {byte} long");
        assert_eq!(run(&program, &long[..7]), Some(expected), "{workers} {byte} long, 7 B");
        // Too short for the byte: past every index of the group
        assert!(run(&program, &long[..6]).unwrap() >= 256, "{workers} {byte} long, 6 B");
      }
      for len in 0..2 {
        assert!(run(&program, &[0x41; 2][..len]).unwrap() >= 256, "{workers} {len} B");
      }
    }
    // Zero workers are one
    assert_eq!(run(&steering_cbpf(0), &[0x41, 9, 0, 0]), Some(0));
  }
}
