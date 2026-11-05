use alloc::{string::String, vec};
use core::{
  iter,
  net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
  option, slice,
};

use crate::executor::Executor;

/// A trait for objects which can be converted or resolved to one or more
/// [`SocketAddr`] values.
pub trait ToSocketAddrs {
  /// Returned iterator over socket addresses which this type may correspond
  /// to.
  type Iter: Iterator<Item = SocketAddr>;

  /// Converts this object to an iterator of resolved [`SocketAddr`]s.
  fn to_socket_addrs<EX>(&self, executor: &EX) -> impl Future<Output = crate::Result<Self::Iter>>
  where
    EX: Executor;
}

impl ToSocketAddrs for SocketAddr {
  type Iter = option::IntoIter<SocketAddr>;

  #[inline]
  async fn to_socket_addrs<EX>(&self, _executor: &EX) -> crate::Result<Self::Iter>
  where
    EX: Executor,
  {
    Ok(Some(*self).into_iter())
  }
}

impl ToSocketAddrs for SocketAddrV4 {
  type Iter = option::IntoIter<SocketAddr>;

  #[inline]
  async fn to_socket_addrs<EX>(&self, executor: &EX) -> crate::Result<Self::Iter>
  where
    EX: Executor,
  {
    SocketAddr::V4(*self).to_socket_addrs(executor).await
  }
}

impl ToSocketAddrs for SocketAddrV6 {
  type Iter = option::IntoIter<SocketAddr>;

  #[inline]
  async fn to_socket_addrs<EX>(&self, executor: &EX) -> crate::Result<Self::Iter>
  where
    EX: Executor,
  {
    SocketAddr::V6(*self).to_socket_addrs(executor).await
  }
}

impl ToSocketAddrs for (IpAddr, u16) {
  type Iter = option::IntoIter<SocketAddr>;

  #[inline]
  async fn to_socket_addrs<EX>(&self, executor: &EX) -> crate::Result<Self::Iter>
  where
    EX: Executor,
  {
    let (ip, port) = *self;
    match ip {
      IpAddr::V4(el) => (el, port).to_socket_addrs(executor).await,
      IpAddr::V6(el) => (el, port).to_socket_addrs(executor).await,
    }
  }
}

impl ToSocketAddrs for (Ipv4Addr, u16) {
  type Iter = option::IntoIter<SocketAddr>;

  #[inline]
  async fn to_socket_addrs<EX>(&self, executor: &EX) -> crate::Result<Self::Iter>
  where
    EX: Executor,
  {
    let (ip, port) = *self;
    SocketAddrV4::new(ip, port).to_socket_addrs(executor).await
  }
}

impl ToSocketAddrs for (Ipv6Addr, u16) {
  type Iter = option::IntoIter<SocketAddr>;

  #[inline]
  async fn to_socket_addrs<EX>(&self, executor: &EX) -> crate::Result<Self::Iter>
  where
    EX: Executor,
  {
    let (ip, port) = *self;
    SocketAddrV6::new(ip, port, 0, 0).to_socket_addrs(executor).await
  }
}

impl ToSocketAddrs for (&str, u16) {
  type Iter = vec::IntoIter<SocketAddr>;

  #[inline]
  async fn to_socket_addrs<EX>(&self, _executor: &EX) -> crate::Result<Self::Iter>
  where
    EX: Executor,
  {
    if let Ok(ip) = self.0.parse::<IpAddr>() {
      return Ok(vec![SocketAddr::new(ip, self.1)].into_iter());
    }
    lookup::<EX>(Query::Pair(String::from(self.0), self.1)).await
  }
}

impl ToSocketAddrs for (String, u16) {
  type Iter = vec::IntoIter<SocketAddr>;

  #[inline]
  async fn to_socket_addrs<EX>(&self, executor: &EX) -> crate::Result<Self::Iter>
  where
    EX: Executor,
  {
    (&*self.0, self.1).to_socket_addrs(executor).await
  }
}

impl ToSocketAddrs for str {
  type Iter = vec::IntoIter<SocketAddr>;

  #[inline]
  async fn to_socket_addrs<EX>(&self, _executor: &EX) -> crate::Result<Self::Iter>
  where
    EX: Executor,
  {
    if let Ok(addr) = self.parse::<SocketAddr>() {
      return Ok(vec![addr].into_iter());
    }
    lookup::<EX>(Query::Str(String::from(self))).await
  }
}
impl<'any> ToSocketAddrs for &'any [SocketAddr] {
  type Iter = iter::Copied<slice::Iter<'any, SocketAddr>>;

  #[inline]
  async fn to_socket_addrs<EX>(&self, _executor: &EX) -> crate::Result<Self::Iter>
  where
    EX: Executor,
  {
    Ok(self.iter().copied())
  }
}

impl<T: ToSocketAddrs + ?Sized> ToSocketAddrs for &T {
  type Iter = T::Iter;

  #[inline]
  async fn to_socket_addrs<EX>(&self, executor: &EX) -> crate::Result<T::Iter>
  where
    EX: Executor,
  {
    (**self).to_socket_addrs(executor).await
  }
}

impl ToSocketAddrs for String {
  type Iter = vec::IntoIter<SocketAddr>;

  #[inline]
  async fn to_socket_addrs<EX>(&self, executor: &EX) -> crate::Result<Self::Iter>
  where
    EX: Executor,
  {
    (**self).to_socket_addrs(executor).await
  }
}

/// A name to resolve: `host:port`, or a host and a port.
enum Query {
  #[cfg_attr(not(feature = "std"), expect(dead_code, reason = "no resolver without std"))]
  Pair(String, u16),
  #[cfg_attr(not(feature = "std"), expect(dead_code, reason = "no resolver without std"))]
  Str(String),
}

#[cfg(feature = "std")]
impl Query {
  fn resolve(&self) -> std::io::Result<vec::IntoIter<SocketAddr>> {
    match self {
      Self::Pair(host, port) => std::net::ToSocketAddrs::to_socket_addrs(&(host.as_str(), *port)),
      Self::Str(elem) => std::net::ToSocketAddrs::to_socket_addrs(elem.as_str()),
    }
  }
}

/// Resolves a name the way the runtime of `EX` should: tokio with its own resolver, a
/// `UringRuntime` on a thread of its own (`getaddrinfo` can block for seconds, and every task of
/// the runtime would wait with it), anything else in place.
#[cfg_attr(not(feature = "std"), expect(clippy::unused_async, reason = "no resolver without std"))]
async fn lookup<EX>(query: Query) -> crate::Result<vec::IntoIter<SocketAddr>>
where
  EX: Executor,
{
  let ty = EX::TY;
  #[cfg(feature = "tokio")]
  if matches!(ty, crate::executor::ExecutorTy::Tokio) {
    let addrs = match &query {
      Query::Pair(host, port) => tokio::net::lookup_host((host.as_str(), *port)).await?,
      Query::Str(elem) => {
        return Ok(vec::Vec::from_iter(tokio::net::lookup_host(elem.as_str()).await?).into_iter());
      }
    };
    return Ok(vec::Vec::from_iter(addrs).into_iter());
  }
  #[cfg(all(feature = "io-uring", target_os = "linux"))]
  if matches!(ty, crate::executor::ExecutorTy::Uring) {
    return lookup_on_thread(query).await;
  }
  let _ty = ty;
  cfg_select! {
    feature = "std" => Ok(query.resolve()?),
    _ => {
      let _query = query;
      Err(crate::net::NetError::NoResolutionBackend.into())
    }
  }
}

/// Resolves on a new thread, which wakes the task when it is done. A dropped future leaves the
/// thread to finish on its own.
#[cfg(all(feature = "io-uring", target_os = "linux"))]
async fn lookup_on_thread(query: Query) -> crate::Result<vec::IntoIter<SocketAddr>> {
  use std::sync::{Mutex, PoisonError};

  #[derive(Default)]
  struct Shared {
    rslt: Option<std::io::Result<vec::IntoIter<SocketAddr>>>,
    waker: Option<core::task::Waker>,
  }

  let shared = crate::sync::Arc::new(Mutex::new(Shared::default()));
  let thread_shared = shared.clone();
  let _jh = std::thread::Builder::new().name("rimu-ws-resolve".into()).spawn(move || {
    let rslt = query.resolve();
    let waker = {
      let mut guard = thread_shared.lock().unwrap_or_else(PoisonError::into_inner);
      guard.rslt = Some(rslt);
      guard.waker.take()
    };
    if let Some(elem) = waker {
      elem.wake();
    }
  })?;
  core::future::poll_fn(|cx| {
    let mut guard = shared.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some(rslt) = guard.rslt.take() {
      return core::task::Poll::Ready(rslt.map_err(crate::Error::from));
    }
    guard.waker = Some(cx.waker().clone());
    core::task::Poll::Pending
  })
  .await
}
