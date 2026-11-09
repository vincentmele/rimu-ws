//! Files from a directory, from a per-thread cache that follows the disk.

#[cfg(test)]
mod tests;

use crate::{
  http::{
    AutoStream, Header, KnownHeaderName, Mime, StatusCode,
    http2_server_framework::{Endpoint, RouteMatch, path::manage_path},
  },
  misc::{SharedBytes, from_utf8_basic},
  sync::{Arc, AtomicU64},
};
use alloc::{string::String, vec::Vec};
use core::{cell::RefCell, sync::atomic::Ordering, time::Duration};
use hashbrown::HashMap;
use std::{
  fs::{self, File, Metadata},
  io::Read as _,
  path::{Path, PathBuf},
  time::{Instant, SystemTime},
};

/// A cached file is checked against the disk at most this often.
const RECHECK: Duration = Duration::from_secs(1);
/// Default of [`StaticFiles::set_cache_bytes`].
const CACHE_BYTES: usize = 32 * 1024 * 1024;
/// Above this many entries (files, twins and misses) a thread's cache starts over.
const MAX_ENTRIES: usize = 8 * 1024;
/// Above this many entries for paths with no file, those entries alone are dropped: requests for
/// random missing paths don't push the real files out.
const MAX_MISSES: usize = 1024;

static NEXT_ID: AtomicU64 = AtomicU64::new(0);

std::thread_local! {
  static CACHES: RefCell<Vec<Cache>> = const { RefCell::new(Vec::new()) };
}

#[cfg(test)]
std::thread_local! {
  static OPENS: core::cell::Cell<u64> = const { core::cell::Cell::new(0) };
}

/// Files opened by this thread's caches.
#[cfg(test)]
pub(crate) fn opens() -> u64 {
  OPENS.get()
}

/// Serves the files under a directory: `GET` of the route's last parameter, a catch-all such as
/// `/static/{*file}`, gives `root/<file>`.
///
/// * `content-type` comes from the extension of the file asked for.
/// * A request whose `accept-encoding` takes `br` or `gzip` gets the `.br` or `.gz` twin of the
///   file if it exists, the higher q-value first and `br` on a tie, with `content-encoding`. Every
///   response carries `vary: accept-encoding`. A twin is only served beside its original.
/// * Paths with `.` or `..` segments, empty segments, backslashes or NUL give 404, as do
///   directories and missing files.
///
/// Files are kept in memory per thread, up to [`Self::set_cache_bytes`], and sent by reference.
/// A cached file is compared with the disk (size, modification time, inode) at most once a
/// second and read again if it changed; a deleted file gives 404 from then on. A request costs
/// neither a `stat` nor an `open` in between.
#[derive(Clone, Debug)]
pub struct StaticFiles {
  cache_bytes: usize,
  id: u64,
  root: Arc<PathBuf>,
}

impl StaticFiles {
  /// Serves the files under `root`. Fails if `root` exists and is not a directory.
  #[inline]
  pub fn new(root: impl Into<PathBuf>) -> crate::Result<Self> {
    let root = root.into();
    if let Ok(meta) = fs::metadata(&root)
      && !meta.is_dir()
    {
      return Err(std::io::Error::from(std::io::ErrorKind::NotADirectory).into());
    }
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    Ok(Self { cache_bytes: CACHE_BYTES, id, root: Arc::new(root) })
  }

  /// Bytes of file contents each thread keeps in memory, 32 MiB by default. The least recently
  /// used files make room for new ones; a file larger than this is read from disk on every
  /// request.
  #[inline]
  #[must_use]
  pub fn set_cache_bytes(mut self, value: usize) -> Self {
    self.cache_bytes = value;
    self
  }

  fn serve<D>(
    &self,
    auto_stream: &mut AutoStream<D>,
    path_defs: (u8, &[RouteMatch]),
  ) -> crate::Result<StatusCode> {
    CACHES.with_borrow_mut(|caches| {
      let cache = Cache::of(caches, self);
      let msg = &mut auto_stream.req.msg_data;
      let is_valid = manage_path(path_defs, &msg.uri)
        .is_ok_and(|raw| decode_path(raw, &mut cache.path));
      let accepted = msg
        .headers
        .get_by_name(<&str>::from(KnownHeaderName::AcceptEncoding).as_bytes())
        .map(|el| Accepted::parse(el.value))
        .unwrap_or_default();
      auto_stream.req.clear();
      if !is_valid {
        return Ok(StatusCode::NotFound);
      }
      let now = Instant::now();
      if !cache.exists(&self.root, Encoding::Identity, now) {
        return Ok(StatusCode::NotFound);
      }
      let mut chosen = None;
      for encoding in accepted.order() {
        if let Some(body) = cache.body(&self.root, encoding, now)? {
          chosen = Some((encoding, body));
          break;
        }
      }
      let (encoding, body) = match chosen {
        Some(elem) => elem,
        None => match cache.body(&self.root, Encoding::Identity, now)? {
          Some(body) => (Encoding::Identity, body),
          None => return Ok(StatusCode::NotFound),
        },
      };
      let ext = cache.path.rsplit_once('/').map_or(cache.path.as_str(), |el| el.1);
      let mime = ext
        .rsplit_once('.')
        .and_then(|el| Mime::from_extension(el.1))
        .unwrap_or(Mime::ApplicationOctetStream);
      let headers = &mut auto_stream.req.msg_data.headers;
      let content_type = <&str>::from(KnownHeaderName::ContentType);
      headers.push_from_iter(Header::from_name_and_value(content_type, [mime.as_str()]))?;
      if let Some(elem) = encoding.token() {
        let content_encoding = <&str>::from(KnownHeaderName::ContentEncoding);
        headers.push_from_iter(Header::from_name_and_value(content_encoding, [elem]))?;
      }
      let vary = <&str>::from(KnownHeaderName::Vary);
      headers.push_from_iter(Header::from_name_and_value(vary, ["accept-encoding"]))?;
      auto_stream.shared_body = Some(body);
      Ok(StatusCode::Ok)
    })
  }
}

impl<D, E, S> Endpoint<D, E, S> for StaticFiles
where
  E: From<crate::Error>,
{
  #[inline]
  async fn auto(
    &self,
    auto_stream: &mut AutoStream<D>,
    path_defs: (u8, &[RouteMatch]),
  ) -> Result<StatusCode, E> {
    Ok(self.serve(auto_stream, path_defs)?)
  }
}

/// The codings of `accept-encoding` this handler can serve, in thousandths.
#[derive(Clone, Copy, Debug, Default)]
struct Accepted {
  br: Option<u16>,
  gzip: Option<u16>,
  star: Option<u16>,
}

impl Accepted {
  fn parse(value: &str) -> Self {
    let mut this = Self::default();
    for item in value.split(',') {
      let mut parts = item.split(';');
      let coding = parts.next().unwrap_or_default().trim();
      let mut q = Some(1000);
      for param in parts {
        if let Some((name, value)) = param.split_once('=')
          && name.trim().eq_ignore_ascii_case("q")
        {
          q = parse_q(value.trim());
        }
      }
      let Some(q) = q else {
        continue;
      };
      if coding.eq_ignore_ascii_case("br") {
        this.br = Some(q);
      } else if coding.eq_ignore_ascii_case("gzip") || coding.eq_ignore_ascii_case("x-gzip") {
        this.gzip = Some(q);
      } else if coding == "*" {
        this.star = Some(q);
      }
    }
    this
  }

  /// The compressed codings to try, the preferred first.
  fn order(self) -> impl Iterator<Item = Encoding> {
    let br = self.br.or(self.star).unwrap_or(0);
    let gzip = self.gzip.or(self.star).unwrap_or(0);
    let pair = if gzip > br {
      [(Encoding::Gzip, gzip), (Encoding::Br, br)]
    } else {
      [(Encoding::Br, br), (Encoding::Gzip, gzip)]
    };
    pair.into_iter().filter(|el| el.1 > 0).map(|el| el.0)
  }
}

/// A q-value (`0`, `0.8`, `1.000`) in thousandths; `None` if malformed.
fn parse_q(value: &str) -> Option<u16> {
  let (int, frac) = value.split_once('.').unwrap_or((value, ""));
  if frac.len() > 3 || !frac.bytes().all(|el| el.is_ascii_digit()) {
    return None;
  }
  let mut thousandths: u16 = match int {
    "0" => 0,
    "1" => 1000,
    _ => return None,
  };
  let mut scale: u16 = 100;
  for digit in frac.bytes() {
    thousandths = thousandths.wrapping_add(u16::from(digit.wrapping_sub(b'0')).wrapping_mul(scale));
    scale /= 10;
  }
  (thousandths <= 1000).then_some(thousandths)
}

/// Percent-decodes `raw` into `out` and checks it is a relative path inside the root: segments
/// neither empty nor `.` nor `..`, and no NUL or backslash.
fn decode_path(raw: &str, out: &mut String) -> bool {
  out.clear();
  if raw.contains('%') {
    let mut bytes = Vec::with_capacity(raw.len());
    let mut iter = raw.bytes();
    while let Some(byte) = iter.next() {
      if byte == b'%' {
        let (Some(hi), Some(lo)) = (iter.next().and_then(hex), iter.next().and_then(hex)) else {
          return false;
        };
        bytes.push((hi << 4) | lo);
      } else {
        bytes.push(byte);
      }
    }
    let Ok(decoded) = from_utf8_basic(&bytes) else {
      return false;
    };
    out.push_str(decoded);
  } else {
    out.push_str(raw);
  }
  !out.is_empty()
    && !out.contains(['\0', '\\'])
    && out.split('/').all(|el| !el.is_empty() && el != "." && el != "..")
}

fn hex(byte: u8) -> Option<u8> {
  char::from(byte).to_digit(16).and_then(|el| u8::try_from(el).ok())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Encoding {
  Br,
  Gzip,
  Identity,
}

impl Encoding {
  /// Leads the cache key.
  const fn tag(self) -> char {
    match self {
      Self::Br => 'b',
      Self::Gzip => 'g',
      Self::Identity => 'i',
    }
  }

  const fn suffix(self) -> &'static str {
    match self {
      Self::Br => ".br",
      Self::Gzip => ".gz",
      Self::Identity => "",
    }
  }

  const fn token(self) -> Option<&'static str> {
    match self {
      Self::Br => Some("br"),
      Self::Gzip => Some("gzip"),
      Self::Identity => None,
    }
  }
}

/// What the disk held when last checked.
#[derive(Debug)]
struct Entry {
  /// The contents, read when first asked for and dropped when the file changes.
  body: Option<SharedBytes>,
  checked: Instant,
  /// `None` for no regular file.
  file: Option<FileId>,
  last_use: u64,
}

/// What tells a changed file: replaced (inode), rewritten (modification time) or resized.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileId {
  inode: u64,
  len: u64,
  modified: Option<SystemTime>,
}

impl FileId {
  fn of(meta: &Metadata) -> Option<Self> {
    if !meta.is_file() {
      return None;
    }
    #[cfg(unix)]
    let inode = std::os::unix::fs::MetadataExt::ino(meta);
    #[cfg(not(unix))]
    let inode = 0;
    Some(Self { inode, len: meta.len(), modified: meta.modified().ok() })
  }
}

/// One [`StaticFiles`]' files on one thread.
#[derive(Debug)]
struct Cache {
  budget: usize,
  entries: HashMap<String, Entry>,
  id: u64,
  key: String,
  /// Entries for paths with no regular file.
  misses: usize,
  /// The path of the current request, decoded.
  path: String,
  used: usize,
  uses: u64,
}

impl Cache {
  fn of<'caches>(caches: &'caches mut Vec<Cache>, sf: &StaticFiles) -> &'caches mut Cache {
    let idx = if let Some(idx) = caches.iter().position(|el| el.id == sf.id) {
      idx
    } else {
      caches.push(Cache {
        budget: sf.cache_bytes,
        entries: HashMap::new(),
        id: sf.id,
        key: String::new(),
        misses: 0,
        path: String::new(),
        used: 0,
        uses: 0,
      });
      caches.len().wrapping_sub(1)
    };
    #[expect(clippy::indexing_slicing, reason = "`idx` was just found or pushed")]
    &mut caches[idx]
  }

  /// If the current path exists as a regular file in `encoding`.
  fn exists(&mut self, root: &Path, encoding: Encoding, now: Instant) -> bool {
    self.entry(root, encoding, now).is_some_and(|el| el.file.is_some())
  }

  /// The contents of the current path in `encoding`, if it is a regular file.
  fn body(
    &mut self,
    root: &Path,
    encoding: Encoding,
    now: Instant,
  ) -> crate::Result<Option<SharedBytes>> {
    let Some(entry) = self.entry(root, encoding, now) else {
      return Ok(None);
    };
    if entry.file.is_none() {
      return Ok(None);
    }
    if let Some(body) = &entry.body {
      return Ok(Some(body.clone()));
    }
    let path = root.join(self.key.get(1..).unwrap_or_default());
    let (file, body) = read(&path)?;
    let len = body.len();
    if len > self.budget {
      return Ok(file.map(|_| body));
    }
    self.make_room(len);
    let Some(entry) = self.entries.get_mut(self.key.as_str()) else {
      return Ok(None);
    };
    entry.checked = now;
    let gone = entry.file.is_some() && file.is_none();
    entry.file = file;
    if gone {
      // Removed between the stat and the read.
      self.misses = self.misses.wrapping_add(1);
      return Ok(None);
    }
    if entry.file.is_none() {
      return Ok(None);
    }
    entry.body = Some(body.clone());
    self.used = self.used.wrapping_add(len);
    Ok(Some(body))
  }

  /// The entry of the current path in `encoding`, checked against the disk if its last check is
  /// older than [`RECHECK`]. `self.key` is left as its key.
  fn entry(&mut self, root: &Path, encoding: Encoding, now: Instant) -> Option<&mut Entry> {
    self.uses = self.uses.wrapping_add(1);
    self.key.clear();
    self.key.push(encoding.tag());
    self.key.push_str(&self.path);
    self.key.push_str(encoding.suffix());
    let Self { entries, key, misses, used, uses, .. } = self;
    if let Some(entry) = entries.get_mut(key.as_str()) {
      entry.last_use = *uses;
      if now.saturating_duration_since(entry.checked) >= RECHECK {
        let file = stat(root, key);
        if file != entry.file {
          if let Some(body) = entry.body.take() {
            *used = used.saturating_sub(body.len());
          }
          match (entry.file.is_some(), file.is_some()) {
            (true, false) => *misses = misses.wrapping_add(1),
            (false, true) => *misses = misses.saturating_sub(1),
            _ => {}
          }
          entry.file = file;
        }
        entry.checked = now;
      }
      // Reborrowed: returning `entry` from inside the `if let` would hold `entries` borrowed.
      return entries.get_mut(key.as_str());
    }
    let file = stat(root, key);
    if file.is_none() {
      if *misses >= MAX_MISSES {
        entries.retain(|_, el| el.file.is_some());
        *misses = 0;
      }
      *misses = misses.wrapping_add(1);
    }
    if entries.len() >= MAX_ENTRIES {
      entries.clear();
      *misses = usize::from(file.is_none());
      *used = 0;
    }
    let entry = Entry { body: None, checked: now, file, last_use: *uses };
    Some(entries.entry(key.clone()).or_insert(entry))
  }

  /// Drops the least recently used contents until `len` more bytes fit in the budget.
  fn make_room(&mut self, len: usize) {
    while self.used.saturating_add(len) > self.budget {
      let oldest = self
        .entries
        .values_mut()
        .filter(|el| el.body.is_some())
        .min_by_key(|el| el.last_use);
      let Some(entry) = oldest else {
        break;
      };
      if let Some(body) = entry.body.take() {
        self.used = self.used.saturating_sub(body.len());
      }
    }
  }
}

/// The file of `key` (its encoding tag, then its path under `root`), if a regular one.
fn stat(root: &Path, key: &str) -> Option<FileId> {
  fs::metadata(root.join(key.get(1..).unwrap_or_default())).ok().and_then(|el| FileId::of(&el))
}

/// The contents of `path` and what it was when read.
fn read(path: &Path) -> crate::Result<(Option<FileId>, SharedBytes)> {
  #[cfg(test)]
  OPENS.set(OPENS.get().wrapping_add(1));
  let mut file = match File::open(path) {
    Ok(elem) => elem,
    Err(_) => return Ok((None, SharedBytes::from_slice(&[]))),
  };
  let meta = file.metadata()?;
  let Some(id) = FileId::of(&meta) else {
    return Ok((None, SharedBytes::from_slice(&[])));
  };
  let mut bytes = Vec::with_capacity(usize::try_from(meta.len()).unwrap_or(0));
  let _ = file.read_to_end(&mut bytes)?;
  Ok((Some(id), SharedBytes::new(Arc::from(bytes.into_boxed_slice()))))
}
