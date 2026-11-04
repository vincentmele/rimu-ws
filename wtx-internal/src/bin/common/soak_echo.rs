//! What the soak servers share: settings from the environment and the three echo loops, which
//! differ in how they read and write frames.
//!
//! `WTX_LOOP` picks the loop: `plain` (one frame read, one written, an `await` each), `drain`
//! (frames that arrived together are written without an `await` each) or `queue` (the default:
//! as `drain`, writing through the write queue). `WTX_DEFLATE=1` negotiates permessage-deflate.
//! `WTX_SNDBUF` sets the listener's (and so every connection's) `SO_SNDBUF`. `WTX_MAX_PAYLOAD`
//! (default 1048576) is the largest message. `WTX_LOG_ERRORS=1` prints connection errors, which
//! hostile clients cause by the thousand.

use rimu_ws::{
  collections::VectorUsize,
  net::{Stream, TcpParams},
  tls::PlaintextCtx,
  web_socket::{
    Fill, OpCode, WebSocket, WebSocketPayloadOrigin, web_socket_compression::NegotiatedWsCompression,
  },
};
use std::sync::OnceLock;

#[derive(Clone, Copy, Debug)]
pub(crate) enum Loop {
  Plain,
  Drain,
  Queue,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Settings {
  pub(crate) deflate: bool,
  pub(crate) log_errors: bool,
  pub(crate) echo_loop: Loop,
  pub(crate) max_payload: usize,
  pub(crate) sndbuf: Option<u32>,
}

static SETTINGS: OnceLock<Settings> = OnceLock::new();

pub(crate) fn env(name: &str, default: u64) -> u64 {
  std::env::var(name).ok().and_then(|el| el.parse().ok()).unwrap_or(default)
}

/// Read once, from the environment.
pub(crate) fn settings() -> Settings {
  *SETTINGS.get_or_init(|| {
    let echo_loop = match std::env::var("WTX_LOOP").as_deref() {
      Ok("plain") => Loop::Plain,
      Ok("drain") => Loop::Drain,
      Ok("queue") | Err(_) => Loop::Queue,
      Ok(other) => panic!("WTX_LOOP: unknown loop `{other}`"),
    };
    Settings {
      deflate: env("WTX_DEFLATE", 0) != 0,
      log_errors: env("WTX_LOG_ERRORS", 0) != 0,
      echo_loop,
      max_payload: usize::try_from(env("WTX_MAX_PAYLOAD", 1 << 20)).unwrap_or(1 << 20),
      sndbuf: Some(env("WTX_SNDBUF", 0)).filter(|el| *el > 0).and_then(|el| u32::try_from(el).ok()),
    }
  })
}

pub(crate) fn tcp_params() -> TcpParams {
  TcpParams::default().set_send_buffer_size(settings().sndbuf)
}

/// Echoes every message with the loop `WTX_LOOP` picks.
pub(crate) async fn echo<NC, S>(
  mut buffer: VectorUsize<u8>,
  mut ws: WebSocket<NC, S, PlaintextCtx, false>,
) -> rimu_ws::Result<()>
where
  NC: NegotiatedWsCompression,
  S: Stream,
{
  let settings = settings();
  *ws.max_payload_len_mut() = settings.max_payload;
  let (mut common, mut reader, mut writer) = ws.split_mut();
  let origin = WebSocketPayloadOrigin::Adaptive;
  loop {
    match settings.echo_loop {
      Loop::Plain => {}
      Loop::Drain => {
        while let Some(mut frame) = reader.read_buffered_frame(&mut buffer, &common, origin)? {
          if !writer.try_write_frame_buffered(&mut common, &mut frame)? {
            writer.write_frame_buffered(&mut common, &mut frame).await?;
          }
        }
      }
      Loop::Queue => {
        while let Some(mut frame) = reader.read_buffered_frame(&mut buffer, &common, origin)? {
          if !writer.queue_frame(&mut common, &mut frame)? {
            writer.write_frame_buffered(&mut common, &mut frame).await?;
          }
        }
        let _ = writer.try_flush(&mut common)?;
        match reader.fill(&mut common).await? {
          Fill::Buffered => continue,
          Fill::Closed => break,
          Fill::ReadFrame => {}
        }
      }
    }
    let mut frame = reader.read_frame(&mut buffer, &mut common, origin).await?;
    match frame.op_code() {
      OpCode::Binary | OpCode::Text => match settings.echo_loop {
        Loop::Plain => writer.write_frame(&mut common, &mut frame).await?,
        Loop::Drain | Loop::Queue => writer.write_frame_buffered(&mut common, &mut frame).await?,
      },
      OpCode::Close => break,
      _ => {}
    }
  }
  Ok(())
}
