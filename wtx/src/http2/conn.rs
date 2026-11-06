//! A connection's whole protocol state, owned by one value and driven by bytes in and bytes out.

pub(crate) mod scan;
#[cfg(test)]
pub(crate) mod test_frames;
