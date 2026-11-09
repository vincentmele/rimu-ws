use crate::{
  executor::StdRuntime,
  http::{
    AutoStream, Header, Method, MsgBufferString, Request, StatusCode,
    http2_server_framework::{Endpoint, Get, HttpRouter, StaticFiles},
    static_files::opens,
  },
  paths,
};
use alloc::{
  format,
  string::{String, ToString as _},
  vec::Vec,
};
use core::net::{IpAddr, Ipv4Addr};
use std::{fs, path::PathBuf};

struct Reply {
  body: Vec<u8>,
  headers: Vec<(String, String)>,
  status: StatusCode,
}

impl Reply {
  fn header(&self, name: &str) -> Option<&str> {
    self.headers.iter().find(|el| el.0 == name).map(|el| el.1.as_str())
  }
}

/// A fresh directory for one test: `<tmp>/<name>/root` is served, `<tmp>/<name>` holds files
/// a traversal would reach.
fn dirs(name: &str) -> (PathBuf, PathBuf) {
  let base = std::env::temp_dir().join(format!("rimu-static-{name}-{}", std::process::id()));
  let _rslt = fs::remove_dir_all(&base);
  let root = base.join("root");
  fs::create_dir_all(&root).unwrap();
  (base, root)
}

/// `GET path` through a router that mounts `files` at `/static/{*file}`. Clones of one
/// [`StaticFiles`] share its cache.
fn get(files: &StaticFiles, path: &str, accept: Option<&str>) -> Reply {
  let router = HttpRouter::paths(paths!(("/static/{*file}", Get(files.clone())))).unwrap();
  StdRuntime::new().block_on(async {
    let mut auto_stream = AutoStream::new(
      (),
      IpAddr::V4(Ipv4Addr::LOCALHOST),
      None,
      Request::new(Method::Get, MsgBufferString::default()),
    );
    auto_stream.req.msg_data.uri.reset().push_str(&format!("http://localhost{path}"));
    if let Some(elem) = accept {
      let header = Header::from_name_and_value("accept-encoding", [elem]);
      auto_stream.req.msg_data.headers.push_from_iter(header).unwrap();
    }
    let status = match router.router.find(path) {
      Ok(found) => {
        let matches = found.data().0;
        Endpoint::<(), crate::Error, ()>::auto(&router, &mut auto_stream, (0, &matches))
          .await
          .unwrap()
      }
      Err(_) => StatusCode::NotFound,
    };
    let msg = &auto_stream.req.msg_data;
    let headers =
      msg.headers.iter().map(|el| (el.name.to_string(), el.value.to_string())).collect();
    let body = match &auto_stream.shared_body {
      Some(elem) => elem.as_slice().to_vec(),
      None => msg.body.as_slice().to_vec(),
    };
    Reply { body, headers, status }
  })
}

#[test]
fn static_serves_br_when_accepted() {
  let (_, root) = dirs("br");
  let files = StaticFiles::new(&root).unwrap();
  fs::write(root.join("a.css"), b"body{}").unwrap();
  fs::write(root.join("a.css.br"), b"BROTLI").unwrap();
  fs::write(root.join("a.css.gz"), b"GZIP").unwrap();
  let reply = get(&files, "/static/a.css", Some("br;q=1, gzip;q=0.8"));
  assert_eq!(reply.status, StatusCode::Ok);
  assert_eq!(reply.body, b"BROTLI");
  assert_eq!(reply.header("content-encoding"), Some("br"));
  assert_eq!(reply.header("content-type"), Some("text/css"));
  assert_eq!(reply.header("vary"), Some("accept-encoding"));
  let reply = get(&files, "/static/a.css", Some("br;q=0.5, gzip;q=0.8"));
  assert_eq!((reply.body.as_slice(), reply.header("content-encoding")), (&b"GZIP"[..], Some("gzip")));
  let reply = get(&files, "/static/a.css", Some("br;q=0, gzip"));
  assert_eq!(reply.header("content-encoding"), Some("gzip"));
  let reply = get(&files, "/static/a.css", Some("identity"));
  assert_eq!((reply.body.as_slice(), reply.header("content-encoding")), (&b"body{}"[..], None));
  let reply = get(&files, "/static/a.css", None);
  assert_eq!((reply.body.as_slice(), reply.header("content-encoding")), (&b"body{}"[..], None));
}

#[test]
fn static_falls_back_to_identity() {
  let (_, root) = dirs("identity");
  let files = StaticFiles::new(&root).unwrap();
  fs::write(root.join("font.woff2"), b"WOFF2").unwrap();
  let reply = get(&files, "/static/font.woff2", Some("br;q=1, gzip;q=0.8"));
  assert_eq!(reply.status, StatusCode::Ok);
  assert_eq!(reply.body, b"WOFF2");
  assert_eq!(reply.header("content-encoding"), None);
  assert_eq!(reply.header("content-type"), Some("font/woff2"));
}

#[test]
fn static_follows_disk() {
  let (_, root) = dirs("follow");
  let files = StaticFiles::new(&root).unwrap();
  fs::write(root.join("app.js"), b"old-bytes").unwrap();
  let reply = get(&files, "/static/app.js", None);
  assert_eq!(reply.body, b"old-bytes");
  assert_eq!(reply.header("content-type"), Some("text/javascript"));
  fs::write(root.join("app.js"), b"new-bytes").unwrap();
  std::thread::sleep(std::time::Duration::from_millis(1200));
  assert_eq!(get(&files, "/static/app.js", None).body, b"new-bytes");
  // A compressed twin that appears later is found, and one that goes away is no longer served.
  fs::write(root.join("app.js.br"), b"BR").unwrap();
  std::thread::sleep(std::time::Duration::from_millis(1200));
  assert_eq!(get(&files, "/static/app.js", Some("br")).body, b"BR");
  fs::remove_file(root.join("app.js.br")).unwrap();
  fs::remove_file(root.join("app.js")).unwrap();
  std::thread::sleep(std::time::Duration::from_millis(1200));
  assert_eq!(get(&files, "/static/app.js", Some("br")).status, StatusCode::NotFound);
}

#[test]
fn static_rejects_traversal() {
  let (base, root) = dirs("traversal");
  let files = StaticFiles::new(&root).unwrap();
  fs::write(base.join("Cargo.toml"), b"secret").unwrap();
  fs::write(base.join("x"), b"secret").unwrap();
  fs::write(root.join("ok.txt"), b"fine").unwrap();
  for path in [
    "/static/../Cargo.toml",
    "/static/%2e%2e/x",
    "/static/%2E%2E%2Fx",
    "/static//etc/passwd",
    "/static/./ok.txt",
    "/static/ok.txt%00",
    "/static/a\\..\\x",
  ] {
    let reply = get(&files, path, None);
    assert_eq!(reply.status, StatusCode::NotFound, "{path}");
    assert!(reply.body.is_empty(), "{path}");
  }
  assert_eq!(get(&files, "/static/ok.txt", None).body, b"fine");
  assert_eq!(get(&files, "/static/ok%2etxt", None).body, b"fine");
}

#[test]
fn static_missing_404() {
  let (_, root) = dirs("missing");
  let files = StaticFiles::new(&root).unwrap();
  fs::create_dir_all(root.join("dir")).unwrap();
  for path in ["/static/nonexistent.txt", "/static/dir", "/static/dir/"] {
    let reply = get(&files, path, Some("br;q=1, gzip;q=0.8"));
    assert_eq!(reply.status, StatusCode::NotFound, "{path}");
    assert!(reply.body.is_empty(), "{path}");
    assert_eq!(reply.header("content-type"), None, "{path}");
  }
}

#[test]
fn static_caches_large_file() {
  let (_, root) = dirs("large");
  let files = StaticFiles::new(&root).unwrap();
  let bytes: Vec<u8> = (0..70_000u32).map(|el| el as u8).collect();
  fs::write(root.join("vendor.js"), &bytes).unwrap();
  let first = get(&files, "/static/vendor.js", Some("br;q=1, gzip;q=0.8"));
  assert_eq!(first.body, bytes);
  let opened = opens();
  let second = get(&files, "/static/vendor.js", Some("br;q=1, gzip;q=0.8"));
  assert_eq!(second.body, bytes);
  assert_eq!(opens(), opened);
}

// Requests for paths that don't exist don't push real files out of the cache: past a bound only
// the misses are dropped, so a scan of random paths doesn't make every hit a disk read again.
#[test]
fn static_misses_do_not_evict_files() {
  let (_, root) = dirs("misses");
  let files = StaticFiles::new(&root).unwrap();
  fs::write(root.join("app.js"), b"app").unwrap();
  assert_eq!(get(&files, "/static/app.js", None).body, b"app");
  let opened = opens();
  for idx in 0..9000 {
    assert_eq!(get(&files, &format!("/static/missing-{idx}"), None).status, StatusCode::NotFound);
  }
  assert_eq!(get(&files, "/static/app.js", None).body, b"app");
  assert_eq!(opens(), opened, "the file was read again");
}
