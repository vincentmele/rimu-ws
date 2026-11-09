//! The packets sent in one packet number space, kept until they are acknowledged (RFC 9002
//! appendix A.1), and what they carried.
//!
//! A ring indexed by packet number holds one record per packet, ACK-only packets included: an
//! acknowledged ACK frame of ours lets the receiver forget ranges (RFC 9000 section 13.2.4). The
//! frames of a packet are references into the worker-wide pool of frame references
//! ([`QuicPools::frame_refs`]), so that a record stays small whatever the packet carried.
//!
//! A packet that is declared lost keeps its record, out of flight, until the ring needs its slot:
//! an acknowledgment that comes late still tells which of its frames arrived, so that they are
//! not sent again ([`crate::quic::recovery`]).

use crate::quic::pools::QuicPools;
use alloc::vec::Vec;

/// Records per ring: the most packets of a space whose fate is unknown at once.
pub(crate) const SENT_RING_LEN: usize = 256;

/// A frame of a sent packet: what is needed of it once the packet is acknowledged or lost.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FrameRef {
  /// An ACK frame, by its Largest Acknowledged.
  Ack {
    /// The Largest Acknowledged field of the frame.
    largest: u64,
  },
  /// CRYPTO data of the space of the packet.
  Crypto {
    /// The offset of the data in the stream of the space.
    offset: u64,
    /// The number of bytes.
    len: u32,
  },
  /// DATA_BLOCKED
  DataBlocked {
    /// The connection credit of the peer that the frame reported.
    max: u64,
  },
  /// HANDSHAKE_DONE
  HandshakeDone,
  /// MAX_DATA
  MaxData {
    /// The limit that the frame gave.
    max: u64,
  },
  /// MAX_STREAM_DATA of the stream in slot `slot` of [`QuicPools::stream_slots`], if the slot
  /// still has the generation `generation`.
  MaxStreamData {
    /// The slot of the stream.
    slot: u32,
    /// The generation of the slot when the frame was sent.
    generation: u32,
    /// The limit that the frame gave.
    max: u64,
  },
  /// MAX_STREAMS, of bidirectional or unidirectional streams.
  MaxStreams {
    /// If the frame was for bidirectional streams.
    bidi: bool,
    /// The limit that the frame gave.
    max: u64,
  },
  /// RESET_STREAM of a stream (see [`Self::MaxStreamData`] for the fields).
  ResetStream {
    /// The slot of the stream.
    slot: u32,
    /// The generation of the slot when the frame was sent.
    generation: u32,
  },
  /// STOP_SENDING of a stream (see [`Self::MaxStreamData`] for the fields).
  StopSending {
    /// The slot of the stream.
    slot: u32,
    /// The generation of the slot when the frame was sent.
    generation: u32,
  },
  /// A STREAM frame, with what is needed to send it again. Its bytes stay with the stream until
  /// every frame that carries them is acknowledged, or the stream is reset.
  Stream {
    /// The slot of the stream (see [`Self::MaxStreamData`]).
    slot: u32,
    /// The generation of the slot when the frame was sent.
    generation: u32,
    /// The offset of the data in the stream.
    offset: u64,
    /// The number of bytes.
    len: u16,
    /// If the frame had the FIN bit.
    fin: bool,
  },
  /// STREAM_DATA_BLOCKED of a stream (see [`Self::MaxStreamData`] for the fields).
  StreamDataBlocked {
    /// The slot of the stream.
    slot: u32,
    /// The generation of the slot when the frame was sent.
    generation: u32,
  },
}

// A chunk of the frame reference pool holds eight of them
const _: () = assert!(size_of::<FrameRef>() <= 24);

/// The frames of a sent packet, in [`QuicPools::frame_refs`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FrameRefRange {
  pub(crate) head: u32,
  pub(crate) len: u16,
  pub(crate) tail: u32,
}

impl FrameRefRange {
  /// No frames.
  pub(crate) const EMPTY: Self = Self { head: u32::MAX, len: 0, tail: u32::MAX };

  /// The number of frames.
  #[inline]
  pub(crate) const fn len(&self) -> usize {
    self.len as usize
  }
}

/// Where a sent packet is.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SentKind {
  /// Neither ack-eliciting nor padded: not in flight (RFC 9002 section 2).
  NotInFlight,
  /// In flight: ack-eliciting or padded, and counted by congestion control.
  InFlight,
  /// In flight, and its CRYPTO data queued again for a probe: its loss does not queue it once
  /// more (review J9).
  Probed,
  /// A probe of path MTU discovery: in flight until it is acknowledged or lost, but not counted
  /// by congestion control, whose loss is no congestion signal (ruling T9-e).
  MtuProbe,
  /// Declared lost: out of flight, its frames queued again, kept for a late acknowledgment.
  Lost,
}

/// The record of a sent packet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SentPacket {
  /// When it was sent.
  pub(crate) time_us: u64,
  /// Its size in bytes.
  pub(crate) size: u16,
  /// If it had frames other than ACK, PADDING and CONNECTION_CLOSE.
  pub(crate) ack_eliciting: bool,
  /// Where it is.
  pub(crate) kind: SentKind,
  /// What it carried.
  pub(crate) frames: FrameRefRange,
}

impl SentPacket {
  /// If it counts towards the bytes in flight of congestion control.
  #[inline]
  pub(crate) fn counts_for_congestion(&self) -> bool {
    matches!(self.kind, SentKind::InFlight | SentKind::Probed)
  }

  /// If its fate is still unknown: in flight, a probe included.
  #[inline]
  pub(crate) fn in_flight(&self) -> bool {
    matches!(self.kind, SentKind::InFlight | SentKind::MtuProbe | SentKind::Probed)
  }
}

// A record stays as small as before the kinds
const _: () = assert!(size_of::<Option<SentPacket>>() <= 24);

/// See the [module documentation](self).
#[derive(Debug)]
pub(crate) struct SentRing {
  // The oldest packet number whose record may be held, every record before it is gone
  base: u64,
  next_pn: u64,
  // Empty until the first packet, then `SENT_RING_LEN` slots from the worker's pool
  slots: Vec<Option<SentPacket>>,
}

impl SentRing {
  /// No packet sent.
  pub(crate) const fn new() -> Self {
    Self { base: 0, next_pn: 0, slots: Vec::new() }
  }

  /// The oldest packet number whose record may be held.
  #[inline]
  pub(crate) const fn base(&self) -> u64 {
    self.base
  }

  /// The record of `pn`, if it is held.
  #[inline]
  pub(crate) fn get_mut(&mut self, pn: u64) -> Option<&mut SentPacket> {
    if !self.holds(pn) {
      return None;
    }
    self.slot_mut(pn)?.as_mut()
  }

  /// If every packet number that a record can be held for is used, and the oldest one is in
  /// flight: a packet can only be sent once it is acknowledged or lost.
  #[inline]
  pub(crate) fn is_full(&self) -> bool {
    self.next_pn.wrapping_sub(self.base) >= SENT_RING_LEN as u64
      && self.slot(self.base).is_some_and(|el| el.is_some_and(|packet| packet.in_flight()))
  }

  /// The records that are held, in no order.
  #[inline]
  pub(crate) fn records(&self) -> impl Iterator<Item = &SentPacket> {
    self.slots.iter().flatten()
  }

  /// The number of packets whose record is held.
  #[inline]
  pub(crate) fn len(&self) -> usize {
    self.slots.iter().filter(|el| el.is_some()).count()
  }

  /// The packet number of the next packet.
  #[inline]
  pub(crate) const fn next_pn(&self) -> u64 {
    self.next_pn
  }

  /// Records the packet that was just sent with [`Self::next_pn`], for which [`Self::reserve`]
  /// made room.
  #[inline]
  pub(crate) fn on_sent(&mut self, packet: SentPacket) {
    let pn = self.next_pn;
    if let Some(slot) = self.slot_mut(pn) {
      *slot = Some(packet);
      self.next_pn = pn.wrapping_add(1);
    }
  }

  /// Gives the records and their frames back to the pools: the space is discarded.
  #[inline]
  pub(crate) fn release(&mut self, pools: &mut QuicPools) {
    for slot in &mut self.slots {
      if let Some(packet) = slot.take() {
        pools.frame_refs.free(packet.frames);
      }
    }
    let slots = core::mem::take(&mut self.slots);
    if slots.capacity() == SENT_RING_LEN {
      pools.sent_rings.give(slots);
    }
    self.base = self.next_pn;
  }

  /// Makes room for the record of the next packet, taking the ring from the pool on first use and
  /// forgetting the oldest record if it is not in flight. Returns `false` if every slot holds a
  /// packet in flight.
  #[inline]
  pub(crate) fn reserve(&mut self, pools: &mut QuicPools) -> bool {
    if self.slots.is_empty() {
      // Pooled rings come back with every slot empty
      self.slots = pools.sent_rings.take().unwrap_or_else(|| Vec::with_capacity(SENT_RING_LEN));
      self.slots.resize(SENT_RING_LEN, None);
    }
    // Packet numbers used without a record (`skip`) can leave more than one slot to free
    while self.next_pn.wrapping_sub(self.base) >= SENT_RING_LEN as u64 {
      let base = self.base;
      let Some(slot) = self.slot_mut(base) else {
        return false;
      };
      match *slot {
        Some(packet) if packet.in_flight() => return false,
        Some(packet) => {
          *slot = None;
          pools.frame_refs.free(packet.frames);
        }
        None => {}
      }
      self.base = base.wrapping_add(1);
      self.advance_base();
    }
    true
  }

  /// Uses up the next packet number without a record: the packet needs none, as a
  /// CONNECTION_CLOSE.
  #[inline]
  pub(crate) const fn skip(&mut self) {
    self.next_pn = self.next_pn.wrapping_add(1);
  }

  /// Takes the record of `pn` out of the ring, if it is held.
  #[inline]
  pub(crate) fn take(&mut self, pn: u64) -> Option<SentPacket> {
    if !self.holds(pn) {
      return None;
    }
    let packet = self.slot_mut(pn)?.take();
    if pn == self.base {
      self.advance_base();
    }
    packet
  }

  /// The packet numbers of `range` whose records can be held, from the smallest.
  #[inline]
  pub(crate) fn window(&self, start: u64, end: u64) -> core::ops::RangeInclusive<u64> {
    let last = end.min(self.next_pn.saturating_sub(1));
    start.max(self.base)..=last
  }

  // Records are only ever held for the `SENT_RING_LEN` packet numbers from the base
  fn holds(&self, pn: u64) -> bool {
    pn >= self.base && pn < self.next_pn && pn.wrapping_sub(self.base) < SENT_RING_LEN as u64
  }

  fn slot(&self, pn: u64) -> Option<&Option<SentPacket>> {
    let idx = usize::try_from(pn % SENT_RING_LEN as u64).ok()?;
    self.slots.get(idx)
  }

  fn advance_base(&mut self) {
    while self.base < self.next_pn && self.slot_mut(self.base).is_some_and(|el| el.is_none()) {
      self.base = self.base.wrapping_add(1);
    }
  }

  fn slot_mut(&mut self, pn: u64) -> Option<&mut Option<SentPacket>> {
    let idx = usize::try_from(pn % SENT_RING_LEN as u64).ok()?;
    self.slots.get_mut(idx)
  }
}

#[cfg(test)]
mod tests {
  use crate::quic::{
    pools::QuicPools,
    sent::{FrameRef, FrameRefRange, SENT_RING_LEN, SentKind, SentPacket, SentRing},
  };

  fn packet(in_flight: bool, frames: FrameRefRange) -> SentPacket {
    let kind = if in_flight { SentKind::InFlight } else { SentKind::NotInFlight };
    SentPacket { time_us: 0, size: 1200, ack_eliciting: in_flight, kind, frames }
  }

  #[test]
  fn records_are_found_by_packet_number() {
    let mut pools = QuicPools::new();
    let mut ring = SentRing::new();
    for pn in 0..5u64 {
      assert!(ring.reserve(&mut pools));
      assert_eq!(ring.next_pn(), pn);
      let mut frames = FrameRefRange::EMPTY;
      pools.frame_refs.push(&mut frames, FrameRef::Ack { largest: pn }).unwrap();
      ring.on_sent(packet(true, frames));
    }
    assert_eq!(ring.len(), 5);
    let third = ring.take(2).unwrap();
    assert_eq!(
      pools.frame_refs.iter(third.frames).collect::<alloc::vec::Vec<_>>(),
      [FrameRef::Ack { largest: 2 }]
    );
    pools.frame_refs.free(third.frames);
    assert!(ring.take(2).is_none() && ring.take(5).is_none());
    assert_eq!(ring.window(0, 100), 0..=4);
    assert!(ring.take(0).is_some() && ring.take(1).is_some());
    // The base moved past the taken records
    assert_eq!(ring.window(0, 100), 3..=4);
    ring.release(&mut pools);
    assert_eq!(ring.len(), 0);
    // The frames of the released records went back too, the taken ones are freed by the caller
    assert_eq!(pools.frame_refs.live_chunks(), 2);
  }

  #[test]
  fn a_full_ring_forgets_records_not_in_flight_only() {
    let mut pools = QuicPools::new();
    let mut ring = SentRing::new();
    for _ in 0..SENT_RING_LEN {
      assert!(ring.reserve(&mut pools));
      ring.on_sent(packet(false, FrameRefRange::EMPTY));
    }
    // The oldest record is not in flight: it makes room
    assert!(ring.reserve(&mut pools));
    ring.on_sent(packet(true, FrameRefRange::EMPTY));
    assert_eq!(ring.len(), SENT_RING_LEN);
    assert!(ring.take(0).is_none());
    let mut ring = SentRing::new();
    for _ in 0..SENT_RING_LEN {
      assert!(ring.reserve(&mut pools));
      ring.on_sent(packet(true, FrameRefRange::EMPTY));
    }
    assert!(!ring.reserve(&mut pools));
    assert!(ring.take(0).is_some());
    assert!(ring.reserve(&mut pools));
  }

  // Packet numbers without a record leave the records that are held where they are
  #[test]
  fn skipped_packet_numbers_have_no_record() {
    let mut pools = QuicPools::new();
    let mut ring = SentRing::new();
    assert!(ring.reserve(&mut pools));
    ring.on_sent(packet(true, FrameRefRange::EMPTY));
    for _ in 0..SENT_RING_LEN {
      ring.skip();
    }
    assert_eq!(ring.next_pn(), 1 + SENT_RING_LEN as u64);
    // Packet 256 shares the slot of packet 0, whose record it is not
    assert!(ring.take(SENT_RING_LEN as u64).is_none());
    // The record of 0, in flight, holds the ring back
    assert!(!ring.reserve(&mut pools));
    assert!(ring.take(0).is_some());
    assert!(ring.reserve(&mut pools));
    ring.on_sent(packet(false, FrameRefRange::EMPTY));
    assert!(ring.take(SENT_RING_LEN as u64 + 1).is_some());
  }

  // Carried rule 3: a packet declared lost at the base of a ring is out of flight, and its slot is
  // given up for the next packet once every other slot is used.
  #[test]
  fn a_lost_record_at_the_base_gives_its_slot() {
    let mut pools = QuicPools::new();
    let mut ring = SentRing::new();
    for _ in 0..SENT_RING_LEN {
      assert!(ring.reserve(&mut pools));
      let mut frames = FrameRefRange::EMPTY;
      pools.frame_refs.push(&mut frames, FrameRef::HandshakeDone).unwrap();
      ring.on_sent(packet(true, frames));
    }
    assert!(ring.is_full() && !ring.reserve(&mut pools));
    ring.get_mut(0).unwrap().kind = SentKind::Lost;
    assert!(!ring.is_full());
    let live = pools.frame_refs.live_chunks();
    assert!(ring.reserve(&mut pools));
    // Its frames went back with it
    assert_eq!(pools.frame_refs.live_chunks(), live - 1);
    assert!(ring.take(0).is_none());
    ring.release(&mut pools);
  }

  #[test]
  fn rings_come_from_the_pool_and_go_back() {
    let mut pools = QuicPools::new();
    let mut ring = SentRing::new();
    assert!(ring.reserve(&mut pools));
    ring.on_sent(packet(true, FrameRefRange::EMPTY));
    let addr = ring.slots.as_ptr().addr();
    ring.release(&mut pools);
    let mut other = SentRing::new();
    assert!(other.reserve(&mut pools));
    assert_eq!(other.slots.as_ptr().addr(), addr);
    assert!(other.slots.iter().all(Option::is_none));
  }
}
