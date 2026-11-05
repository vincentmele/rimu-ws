use crate::{
  executor::StdRuntime,
  net::{StreamReader, StreamWriter},
  rng::{ChaCha20, CryptoSeedableRng},
  tests::{_PUBLIC_KEY, _ROOT_CA, _SECRET_KEY, _uri},
  tls::{TlsAcceptor, TlsConfig, TlsConnectorBuilder},
};
use std::net::TcpListener;

#[cfg_attr(miri, ignore)]
#[rimu_ws::test]
async fn simple_connection(runtime: &StdRuntime) {
  let uri = _uri();
  let mut client_rng = ChaCha20::from_std_random().unwrap();
  let mut server_rng = ChaCha20::from_crypto_rng(&mut client_rng).unwrap();

  let listener = TcpListener::bind(uri.hostname_with_implied_port()).unwrap();

  let _client_jh = runtime
    .spawn(async move {
      let mut tls_stream = TlsConnectorBuilder::std(uri)
        .build(TlsConfig::from_trust_anchors_pem([_ROOT_CA]).unwrap(), &mut client_rng)
        .await
        .unwrap()
        .connect()
        .await
        .unwrap()
        .tls_stream;
      tls_stream.write_all(b"hello").await.unwrap();
      tls_stream.send_close_notify().await.unwrap();
    })
    .unwrap();

  let stream = listener.accept().unwrap().0;
  let mut tls_stream = TlsAcceptor::new(
    TlsConfig::from_keys_pem(_PUBLIC_KEY, _SECRET_KEY).unwrap(),
    &mut server_rng,
    stream,
  )
  .accept()
  .await
  .unwrap()
  .tls_stream;
  let mut buffer = [0; 128];
  loop {
    let Some(read) = tls_stream.read(buffer.as_mut_slice().into()).await.unwrap() else {
      break;
    };
    let slice = buffer.get(..read.get()).unwrap();
    assert_eq!(slice, b"hello");
  }
}

// With kernel TLS on (the default) and the kernel's `tls` module available, the server hands the
// connection to the kernel after the handshake. The bytes still arrive, and the client's
// close_notify ends the stream cleanly instead of failing the read with EIO.
#[cfg(all(feature = "libc", target_os = "linux"))]
#[cfg_attr(miri, ignore)]
#[rimu_ws::test]
async fn kernel_tls_connection(runtime: &StdRuntime) {
  for kernel_tls in [true, false] {
    let uri = _uri();
    let mut client_rng = ChaCha20::from_std_random().unwrap();
    let mut server_rng = ChaCha20::from_crypto_rng(&mut client_rng).unwrap();
    let listener = TcpListener::bind(uri.hostname_with_implied_port()).unwrap();
    let _client_jh = runtime
      .spawn(async move {
        let mut tls_stream = TlsConnectorBuilder::std(uri)
          .build(TlsConfig::from_trust_anchors_pem([_ROOT_CA]).unwrap(), &mut client_rng)
          .await
          .unwrap()
          .connect()
          .await
          .unwrap()
          .tls_stream;
        // The kernel takes only an established socket: stay connected until the server has
        // switched, with one record sent before the switch and one after.
        tls_stream.write_all(b"hello").await.unwrap();
        std::thread::sleep(core::time::Duration::from_millis(100));
        tls_stream.write_all(b" kernel").await.unwrap();
        tls_stream.send_close_notify().await.unwrap();
      })
      .unwrap();
    let stream = listener.accept().unwrap().0;
    let mut config = TlsConfig::from_keys_pem(_PUBLIC_KEY, _SECRET_KEY).unwrap();
    *config.kernel_tls_mut() = kernel_tls;
    let mut tls_stream =
      TlsAcceptor::new(config, &mut server_rng, stream).accept().await.unwrap().tls_stream;
    let mut got = std::vec::Vec::new();
    let mut buffer = [0; 128];
    while let Some(read) = tls_stream.read(buffer.as_mut_slice().into()).await.unwrap() {
      got.extend_from_slice(buffer.get(..read.get()).unwrap());
    }
    assert_eq!(got, b"hello kernel", "kernel_tls = {kernel_tls}");
    // A first record that came with the handshake is read in user space; the switch happens at
    // the next read, before the second one arrives.
    let ulp = std::fs::read_to_string("/proc/sys/net/ipv4/tcp_available_ulp").unwrap_or_default();
    if kernel_tls && ulp.split_whitespace().any(|el| el == "tls") {
      assert!(tls_stream.is_kernel_tls(), "the kernel offers TLS but the stream didn't use it");
    } else {
      assert!(!tls_stream.is_kernel_tls());
    }
  }
}
