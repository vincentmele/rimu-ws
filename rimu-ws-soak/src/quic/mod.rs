//! QUIC and HTTP/3 soak scenarios (task 23): a well-behaved steady client that runs for the whole
//! run beside abusive clients, each abuser bounded by one of the limits of [`rimu_ws::quic`] (spec
//! section 5.12). The library abusers are driven with `quinn`/`h3`; the raw ones with [`raw`],
//! which speaks QUIC through codecs of the harness's own (ruling T23-b).

pub mod client;
pub mod driver;
pub mod onertt;
pub mod raw;
pub mod scenario;
pub mod wrapsock;
