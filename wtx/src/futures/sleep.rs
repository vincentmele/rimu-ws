use crate::misc::{Lease, LeaseMut};
use core::{
  pin::Pin,
  task::{Context, Poll},
  time::Duration,
};

/// Waits until a certain duration has elapsed.
///
/// The timer comes from the runtime the instance is created on: a `UringRuntime`'s ring, tokio's
/// timer inside a tokio runtime, or embassy's. Anywhere else it re-polls itself until the time is
/// up.
#[derive(Debug)]
pub struct Sleep {
  item: Item,
}

#[derive(Debug)]
enum Item {
  #[cfg(feature = "embassy-time")]
  Embassy(embassy_time::Timer),
  // Boxed: tokio's sleep is `!Unpin`, and `Sleep` is polled in place by its callers.
  #[cfg(feature = "tokio")]
  Tokio(Pin<alloc::boxed::Box<tokio::time::Sleep>>),
  #[cfg(all(feature = "io-uring", target_os = "linux"))]
  Uring(crate::executor::UringSleep),
  #[cfg_attr(feature = "embassy-time", expect(dead_code, reason = "embassy has its own timer"))]
  Poll(Duration, crate::calendar::Instant),
}

impl Sleep {
  /// New instance
  #[inline]
  pub fn new(duration: Duration) -> crate::Result<Self> {
    #[cfg(all(feature = "io-uring", target_os = "linux"))]
    if let Some(elem) = crate::executor::UringSleep::new(duration) {
      return Ok(Self { item: Item::Uring(elem) });
    }
    Ok(Self {
      item: cfg_select! {
        feature = "embassy-time" => {
          Item::Embassy(embassy_time::Timer::after(duration.try_into()?))
        }
        feature = "tokio" => {
          // `tokio::time::sleep` panics outside a tokio runtime.
          if tokio::runtime::Handle::try_current().is_ok() {
            Item::Tokio(alloc::boxed::Box::pin(tokio::time::sleep(duration)))
          } else {
            Item::Poll(duration, crate::calendar::Instant::new())
          }
        }
        _ => Item::Poll(duration, crate::calendar::Instant::new()),
      },
    })
  }
}

impl Lease<Sleep> for Sleep {
  #[inline]
  fn lease(&self) -> &Sleep {
    self
  }
}

impl LeaseMut<Sleep> for Sleep {
  #[inline]
  fn lease_mut(&mut self) -> &mut Sleep {
    self
  }
}

impl Future for Sleep {
  type Output = crate::Result<()>;

  #[inline]
  fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
    match &mut self.item {
      #[cfg(feature = "embassy-time")]
      Item::Embassy(item) => {
        core::task::ready!(Pin::new(item).poll(cx));
        Poll::Ready(Ok(()))
      }
      #[cfg(feature = "tokio")]
      Item::Tokio(item) => {
        core::task::ready!(item.as_mut().poll(cx));
        Poll::Ready(Ok(()))
      }
      #[cfg(all(feature = "io-uring", target_os = "linux"))]
      Item::Uring(item) => Pin::new(item).poll(cx),
      Item::Poll(duration, begin) => {
        if begin.elapsed()? >= *duration {
          return Poll::Ready(Ok(()));
        }
        cx.waker().wake_by_ref();
        Poll::Pending
      }
    }
  }
}
