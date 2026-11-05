#[cfg(test)]
mod tests;

macro_rules! check_headers {
  ($headers:expr, $($header:expr),*) => {{
    let rslt = check_headers(
      [
        (KnownHeaderName::Connection, Some(b"upgrade")),
        (KnownHeaderName::Upgrade, Some(b"websocket")),
        $($header,)*
      ],
      $headers
    );
    let _ = check_header_value(rslt[0])?;
    let _ = check_header_value(rslt[1])?;
    rslt
  }};
}

use crate::{
  codec::{Base64Alphabet, base64_encode, base64_encoded_len},
  collections::{SingleTypeStorage, SuffixGuardVectorMut},
  crypto::{Hash as _, Sha1Global},
  http::{GenericHeader as _, GenericRequest as _, HttpError, KnownHeaderName, Method},
  misc::{Lease, bytes_split1},
  net::{Stream, StreamWriter as _, Uri},
  rng::{CryptoRng, Rng, SeedableRng as _, Xorshift64},
  tls::{TlsAcceptor, TlsConfig, TlsConnector, TlsCtx, TlsCtxSk},
  web_socket::{
    WebSocket, WebSocketAcceptor, WebSocketConnector, WebSocketError, WsCompression,
    web_socket_compression::NegotiatedWsCompression,
  },
};
use httparse::{EMPTY_HEADER, Header, Request, Response, Status};

/// Proxies and CDNs add their own headers to a browser's dozen or so.
const MAX_HEADERS: usize = 64;
/// The largest upgrade request (or response) read: past it, a peer that never ends one would
/// make the reader hold, and re-parse, as much as it sent.
pub(crate) const MAX_REQUEST_LEN: usize = 16 * 1024;
const READ_INCREMENT: usize = 1024;
const VERSION: &str = "13";

impl<C, E, R> WebSocketAcceptor<C, R>
where
  C: WsCompression<false>,
  E: From<crate::Error>,
  R: FnOnce(&Request<'_, '_>) -> Result<bool, E>,
{
  /// Reads external data to establish an WebSocket connection.
  #[inline]
  pub async fn accept<RNG, S, TCG, TCX>(
    mut self,
    tls_acceptor: TlsAcceptor<RNG, S, TCG>,
  ) -> Result<WebSocket<C::NegotiatedCompression, S, TCX, false>, E>
  where
    RNG: CryptoRng,
    S: Stream,
    TCG: Lease<TlsConfig<TCX>> + SingleTypeStorage<Item = TCX>,
    TCX: TlsCtxSk,
  {
    self.wsb.clear();
    let mut tls_stream = tls_acceptor.accept().await?.tls_stream;
    let nb = &mut self.wsb.network_buffer;
    let mut scanned = 0;
    loop {
      // Into `following`, which `BufStreamReader` keeps across reads: a request that arrives in
      // several reads is parsed whole.
      // The reserve counts from the start of `following`, which holds the request so far.
      let reserve = nb.following().len().wrapping_add(READ_INCREMENT);
      if !nb.read_following(reserve, &mut tls_stream).await? {
        return Err(crate::Error::from(WebSocketError::ClosedConnection).into());
      }
      let buffer = nb.following();
      // Parsed only once the blank line may have arrived, so a request sent a byte at a time
      // costs linear time, not quadratic.
      let ended = has_blank_line(buffer, scanned);
      scanned = buffer.len();
      if !ended {
        if buffer.len() > MAX_REQUEST_LEN {
          build_and_send_res431(&mut tls_stream).await?;
          return Err(crate::Error::from(WebSocketError::VeryLargeHandshake).into());
        }
        continue;
      }
      let mut req_buffer = [EMPTY_HEADER; MAX_HEADERS];
      let mut req = Request::new(&mut req_buffer);
      let len = match req.parse(buffer) {
        Ok(Status::Complete(len)) => len,
        Ok(Status::Partial) => {
          if buffer.len() > MAX_REQUEST_LEN {
            build_and_send_res431(&mut tls_stream).await?;
            return Err(crate::Error::from(WebSocketError::VeryLargeHandshake).into());
          }
          continue;
        }
        Err(err) => {
          if err == httparse::Error::TooManyHeaders {
            build_and_send_res431(&mut tls_stream).await?;
          } else {
            build_and_send_res400(&mut tls_stream, false).await?;
          }
          return Err(crate::Error::from(err).into());
        }
      };
      if !(self.req)(&req)? {
        build_and_send_res400(&mut tls_stream, false).await?;
        return Err(crate::Error::from(WebSocketError::ClosedHandshake).into());
      }
      if !req.method().trim_ascii().eq_ignore_ascii_case(b"get") {
        build_and_send_res400(&mut tls_stream, false).await?;
        return Err(
          crate::Error::from(HttpError::UnexpectedHttpMethod { expected: Some(Method::Get) })
            .into(),
        );
      }
      let mut key_buffer = [0; 30];
      let swa = match Self::check_req_headers(&mut self.no_masking, &req, &mut key_buffer) {
        Ok(el) => el,
        Err(bad_version) => {
          build_and_send_res400(&mut tls_stream, bad_version).await?;
          return Err(crate::Error::from(WebSocketError::InvalidHandshakeRequest).into());
        }
      };
      let nc = self.compression.negotiate(req.headers.iter())?;
      build_and_send_res101(swa, &nc, self.no_masking, &mut tls_stream).await?;
      self.wsb.network_buffer.set_indices(len, len);
      let rng = Xorshift64::from_simple_seed()?;
      return Ok(WebSocket::new(nc, self.no_masking, rng, tls_stream, self.wsb));
    }
  }

  /// The `Sec-WebSocket-Accept` of a request RFC 6455 (4.2.1) lets the server upgrade: HTTP/1.1,
  /// with `Host`, `Upgrade: websocket`, `Connection: Upgrade` (tokens in any case, in lists), one
  /// key of 16 bytes in base64 and version 13. `Err(true)` when only the version is wrong, which
  /// the 400 then names.
  fn check_req_headers<'kb>(
    no_masking: &mut bool,
    req: &Request<'_, '_>,
    key_buffer: &'kb mut [u8; 30],
  ) -> Result<&'kb [u8], bool> {
    let (mut host, mut upgrade, mut connection, mut key, mut version) =
      (false, false, false, None, None);
    // Off unless the client asks for it.
    let mut asks_no_masking = false;
    for header in req.headers.iter() {
      let name = header.name.as_bytes().trim_ascii();
      let value = header.value.trim_ascii();
      let has_token = |token: &[u8]| {
        bytes_split1(value, b',').any(|el| el.trim_ascii().eq_ignore_ascii_case(token))
      };
      if name.eq_ignore_ascii_case(b"host") {
        host = true;
      } else if name.eq_ignore_ascii_case(b"upgrade") {
        upgrade |= has_token(b"websocket");
      } else if name.eq_ignore_ascii_case(b"connection") {
        connection |= has_token(b"upgrade");
      } else if name.eq_ignore_ascii_case(b"sec-websocket-key") {
        if key.is_some() {
          return Err(false);
        }
        key = Some(value);
      } else if name.eq_ignore_ascii_case(b"sec-websocket-version") {
        version = Some(value);
      } else if name.eq_ignore_ascii_case(b"sec-websocket-extensions") {
        asks_no_masking |= has_no_masking(value);
      }
    }
    let Some(key) = key.filter(|el| is_valid_key(el)) else { return Err(false) };
    if req.version != Some(1) || !host || !upgrade || !connection {
      return Err(false);
    }
    if version != Some(VERSION.as_bytes()) {
      return Err(true);
    }
    *no_masking &= asks_no_masking;
    Ok(derived_key(key_buffer, key))
  }
}

impl<'headers, C, E, H, R> WebSocketConnector<C, H, R>
where
  C: WsCompression<true>,
  E: From<crate::Error>,
  H: IntoIterator<Item = (&'headers str, &'headers str)>,
  R: FnOnce(&Response<'_, '_>) -> Result<(), E>,
{
  /// Sends data to establish an WebSocket connection.
  #[inline]
  pub async fn connect<RNG, S, STR, TCG, TCX, U>(
    mut self,
    tls_connector: TlsConnector<RNG, S, TCG, U>,
  ) -> Result<WebSocket<C::NegotiatedCompression, S, TCX, true>, E>
  where
    RNG: CryptoRng,
    S: Stream,
    STR: Lease<str>,
    TCG: Lease<TlsConfig<TCX>> + SingleTypeStorage<Item = TCX>,
    TCX: TlsCtx,
    U: Lease<Uri<STR>> + SingleTypeStorage<Item = STR>,
  {
    self.wsb.clear();
    let mut out = tls_connector.connect().await?;
    let key_buffer = &mut [0; 26];
    let key = {
      let mut sw = self.wsb.network_buffer.suffix_pusher();
      let key = build_req(
        &self.compression,
        &mut sw,
        self.headers,
        key_buffer,
        self.no_masking,
        &mut out.rng,
        out.uri.lease(),
      )?;
      out.tls_stream.write_all(sw.curr()).await?;
      key
    };
    let mut scanned = 0;
    let (nc, len) = loop {
      let nb = &mut self.wsb.network_buffer;
      let reserve = nb.following().len().wrapping_add(READ_INCREMENT);
      if !nb.read_following(reserve, &mut out.tls_stream).await? {
        return Err(crate::Error::from(WebSocketError::ClosedConnection).into());
      }
      let buffer = nb.following();
      let ended = has_blank_line(buffer, scanned);
      scanned = buffer.len();
      if buffer.len() > MAX_REQUEST_LEN && !ended {
        return Err(crate::Error::from(WebSocketError::VeryLargeHandshake).into());
      }
      if !ended {
        continue;
      }
      let mut httparse_headers = [EMPTY_HEADER; MAX_HEADERS];
      let mut res = Response::new(&mut httparse_headers);
      let len = match res.parse(buffer).map_err(From::from)? {
        Status::Complete(len) => len,
        Status::Partial if buffer.len() > MAX_REQUEST_LEN => {
          return Err(crate::Error::from(WebSocketError::VeryLargeHandshake).into());
        }
        Status::Partial => continue,
      };
      if res.code != Some(101) {
        return Err(
          crate::Error::from(WebSocketError::MissingSwitchingProtocols { found: res.code }).into(),
        );
      }
      (self.res_cb)(&res)?;
      let [_, _, b2, b3] = check_headers!(
        res.headers,
        (KnownHeaderName::SecWebsocketAccept, Some(derived_key(&mut [0; 30], key))),
        (KnownHeaderName::SecWebsocketExtensions, None)
      );
      // RFC 6455 4.1: a client that gets the wrong key fails the connection.
      let _ = check_header_value(b2)?;
      self.no_masking &= check_header_value(b3).is_ok_and(has_no_masking);
      break (self.compression.negotiate(res.headers.iter())?, len);
    };
    self.wsb.network_buffer.set_indices(len, len);
    let rng = Xorshift64::from_simple_seed()?;
    Ok(WebSocket::new(nc, self.no_masking, rng, out.tls_stream, self.wsb))
  }
}

fn base64_from_array<'output, const I: usize, const O: usize>(
  input: &[u8; I],
  output: &'output mut [u8; O],
) -> &'output [u8] {
  const {
    let rslt = if let Some(elem) = base64_encoded_len(I, false) { elem } else { 0 };
    assert!(O >= rslt);
  }
  base64_encode(Base64Alphabet::Standard, input, output).map_or_default(str::as_bytes)
}

/// Client request
fn build_req<'headers, 'kb, C, RNG, STR>(
  compression: &C,
  sw: &mut SuffixGuardVectorMut<'_, usize, u8>,
  headers: impl IntoIterator<Item = (&'headers str, &'headers str)>,
  key_buffer: &'kb mut [u8; 26],
  no_masking: bool,
  rng: &mut RNG,
  uri: &Uri<STR>,
) -> crate::Result<&'kb [u8]>
where
  C: WsCompression<true>,
  RNG: CryptoRng,
  STR: Lease<str>,
{
  let host = match uri.port() {
    Some(80 | 443) => uri.hostname().as_bytes(),
    _ => uri.host().as_bytes(),
  };
  let key = gen_key(key_buffer, rng);
  let _ = sw.inner_mut().extend_from_copyable_slices([
    b"GET ",
    uri.relative_reference_slash().as_bytes(),
    b" HTTP/1.1\r\n",
    b"Connection: Upgrade\r\n",
    b"Host: ",
    host,
    b"\r\n",
    b"Sec-WebSocket-Key: ",
    key,
    b"\r\n",
    no_masking_bytes(no_masking),
    b"Sec-WebSocket-Version: 13\r\n",
    b"Upgrade: websocket\r\n",
    compression.req_headers().as_ref(),
  ])?;
  for (name, value) in headers {
    let _ = sw.inner_mut().extend_from_copyable_slices([
      name.as_bytes(),
      b": ",
      value.as_bytes(),
      b"\r\n",
    ])?;
  }
  sw.inner_mut().extend_from_copyable_slice(b"\r\n")?;
  Ok(key)
}

/// With `bad_version`, names the version the server speaks (RFC 6455 4.4).
async fn build_and_send_res400<S>(stream: &mut S, bad_version: bool) -> crate::Result<()>
where
  S: Stream,
{
  if bad_version {
    stream.write_all(b"HTTP/1.1 400 Bad Request\r\nSec-WebSocket-Version: 13\r\n\r\n").await?;
  } else {
    stream.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await?;
  }
  Ok(())
}

async fn build_and_send_res431<S>(stream: &mut S) -> crate::Result<()>
where
  S: Stream,
{
  stream.write_all(b"HTTP/1.1 431 Request Header Fields Too Large\r\n\r\n").await?;
  Ok(())
}

/// Whether `buffer` holds the blank line that ends an HTTP head (CRLF or bare LF), looking only
/// at what arrived after its first `scanned` bytes and the 2 before them.
fn has_blank_line(buffer: &[u8], scanned: usize) -> bool {
  let from = scanned.saturating_sub(2).min(buffer.len());
  buffer.get(from..).unwrap_or_default().windows(2).any(|el| el == b"\n\n")
    || buffer.get(from..).unwrap_or_default().windows(3).any(|el| el == b"\n\r\n")
}

/// 16 bytes in base64: 22 characters, the last carrying 2 bits, then `==`.
fn is_valid_key(key: &[u8]) -> bool {
  let [body @ .., last, b'=', b'='] = key else { return false };
  let is_b64 = |el: &u8| el.is_ascii_alphanumeric() || *el == b'+' || *el == b'/';
  body.len() == 21 && body.iter().all(is_b64) && matches!(last, b'A' | b'Q' | b'g' | b'w')
}

/// Server response
async fn build_and_send_res101<NC, S>(
  key: &[u8],
  nc: &NC,
  no_masking: bool,
  stream: &mut S,
) -> crate::Result<()>
where
  NC: NegotiatedWsCompression,
  S: Stream,
{
  let begin = b"HTTP/1.1 101 Switching Protocols\r\n";
  let middle = b"Connection: Upgrade\r\nSec-WebSocket-Accept: ";
  let end = b"\r\nUpgrade: websocket\r\n\r\n";
  stream
    .write_all_vectored(&[
      begin,
      no_masking_bytes(no_masking),
      nc.res_headers().as_slice(),
      middle,
      key,
      end,
    ])
    .await?;
  Ok(())
}

fn check_header_value((name, value): (KnownHeaderName, Option<&[u8]>)) -> crate::Result<&[u8]> {
  let Some(elem) = value else {
    return Err(crate::Error::from(HttpError::MissingHeader(name)));
  };
  Ok(elem)
}

fn check_headers<'headers, const N: usize>(
  array: [(KnownHeaderName, Option<&[u8]>); N],
  headers: &'headers [Header<'_>],
) -> [(KnownHeaderName, Option<&'headers [u8]>); N] {
  let mut rslt = [(KnownHeaderName::Accept, None); N];
  for header in headers {
    let trimmed_name = header.name().trim_ascii();
    let trimmed_value = header.value().trim_ascii();
    for ((name, value_opt), rslt_elem) in array.into_iter().zip(&mut rslt) {
      let has_name = rslt_elem.1.is_none() && trimmed_name.eq_ignore_ascii_case(name.into());
      if has_name {
        if let Some(value) = value_opt {
          for sub_value in bytes_split1(trimmed_value, b',') {
            if sub_value.trim_ascii().eq_ignore_ascii_case(value) {
              *rslt_elem = (name, Some(sub_value));
              break;
            }
          }
          if rslt_elem.1.is_some() {
            break;
          }
        } else {
          *rslt_elem = (name, Some(trimmed_value));
        }
      }
    }
  }
  rslt
}

fn derived_key<'buffer>(buffer: &'buffer mut [u8; 30], key: &[u8]) -> &'buffer [u8] {
  let array = Sha1Global::digest([key, b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"]);
  base64_from_array(&array, buffer)
}

fn gen_key<'buffer>(buffer: &'buffer mut [u8; 26], rng: &mut impl Rng) -> &'buffer [u8] {
  base64_from_array(&rng.u8_16(), buffer)
}

const fn has_no_masking(el: &[u8]) -> bool {
  el.eq_ignore_ascii_case(b"no-masking")
}

const fn no_masking_bytes(no_masking: bool) -> &'static [u8] {
  if no_masking { b"Sec-WebSocket-Extensions: no-masking\r\n" } else { &[] }
}
