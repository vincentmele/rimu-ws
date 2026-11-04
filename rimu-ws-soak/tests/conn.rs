mod support;

use rimu_ws_soak::{
  codec::client_frame,
  conn::{Conn, ConnError, ConnOpts, Next},
  rng::{rng, seed_for},
};
use std::time::Duration;
use support::{Faults, spawn_fake};
use tokio::time::Instant;

#[test]
fn seed_for_is_stable_and_distinct() {
  assert_eq!(seed_for(1, 2, 3), seed_for(1, 2, 3));
  assert_ne!(seed_for(1, 2, 3), seed_for(1, 2, 4));
  assert_ne!(seed_for(1, 2, 3), seed_for(1, 3, 3));
}

#[tokio::test]
async fn upgrade_and_echo_against_fake() {
  let addr = spawn_fake(Faults::default()).await;
  let mut rng = rng(1);
  let mut conn = Conn::connect(addr, &ConnOpts::default()).await.unwrap();
  conn.upgrade("localhost", "/", &mut rng).await.unwrap();
  let mut out = Vec::new();
  client_frame(true, 1, b"hi", [9, 8, 7, 6], &mut out);
  conn.send(&out).await.unwrap();
  let deadline = Instant::now() + Duration::from_secs(1);
  match conn.next_frame(deadline).await.unwrap() {
    Next::Frame(frame) => assert_eq!((frame.opcode, frame.payload.as_slice()), (1, &b"hi"[..])),
    Next::Eof => panic!("EOF"),
  }
  let mut close = Vec::new();
  client_frame(true, 8, &1000u16.to_be_bytes(), [1, 1, 1, 1], &mut close);
  conn.send(&close).await.unwrap();
  conn.expect_close(&[1000], deadline).await.unwrap();
}

#[tokio::test]
async fn expect_eof_times_out_as_server_failure() {
  let addr = spawn_fake(Faults::default()).await;
  let mut conn = Conn::connect(addr, &ConnOpts::default()).await.unwrap();
  let begin = Instant::now();
  let rslt = conn.expect_eof(begin + Duration::from_millis(200)).await;
  let elapsed = begin.elapsed();
  assert!(matches!(rslt, Err(ConnError::Server(_))), "{rslt:?}");
  assert!(
    elapsed >= Duration::from_millis(200) && elapsed < Duration::from_millis(400),
    "{elapsed:?}"
  );
}

#[tokio::test]
async fn connect_refused_is_server_failure_but_addr_not_available_is_harness() {
  let closed = {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap()
  };
  let refused = Conn::connect(closed, &ConnOpts::default()).await;
  assert!(matches!(refused, Err(ConnError::Server(_))), "{refused:?}");
  let opts = ConnOpts { source_ip: Some("192.0.2.1".parse().unwrap()), ..ConnOpts::default() };
  let unavailable = Conn::connect(closed, &opts).await;
  assert!(matches!(unavailable, Err(ConnError::Harness(_))), "{unavailable:?}");
}

#[tokio::test]
async fn transcript_keeps_last_64_events_and_limits_hex() {
  let addr = spawn_fake(Faults::default()).await;
  let mut conn = Conn::connect(addr, &ConnOpts::default()).await.unwrap();
  for _ in 0..100 {
    conn.send(&[0xAB; 200]).await.unwrap();
  }
  let dump = conn.transcript().dump();
  assert_eq!(dump.lines().count(), 64);
  for line in dump.lines() {
    let hex = line.split_whitespace().last().unwrap();
    assert!(hex.len() <= 128, "{line}");
  }
}
