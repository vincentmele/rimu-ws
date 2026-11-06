//! The `date` header a server sends (RFC 9110 §6.6.1), formatted once a second.

const DAYS: [&[u8; 3]; 7] = [b"Thu", b"Fri", b"Sat", b"Sun", b"Mon", b"Tue", b"Wed"];
const MONTHS: [&[u8; 3]; 12] =
  [b"Jan", b"Feb", b"Mar", b"Apr", b"May", b"Jun", b"Jul", b"Aug", b"Sep", b"Oct", b"Nov", b"Dec"];

/// An IMF-fixdate (`Sun, 06 Nov 1994 08:49:37 GMT`) refreshed when the second changes.
#[derive(Debug)]
pub(crate) struct DateHeader {
  secs: u64,
  text: [u8; 29],
}

impl DateHeader {
  pub(crate) fn new() -> Self {
    let mut this = Self { secs: u64::MAX, text: [b' '; 29] };
    this.refresh();
    this
  }

  /// Reads the clock and reformats if the second changed.
  pub(crate) fn refresh(&mut self) {
    let secs = std::time::SystemTime::now()
      .duration_since(std::time::UNIX_EPOCH)
      .map_or(0, |el| el.as_secs());
    if secs != self.secs {
      self.secs = secs;
      format_imf_fixdate(secs, &mut self.text);
    }
  }

  pub(crate) fn as_str(&self) -> &str {
    crate::misc::from_utf8_basic(&self.text).unwrap_or_default()
  }
}

/// Writes `unix_secs` as an IMF-fixdate (RFC 9110 §5.6.7).
pub(crate) fn format_imf_fixdate(unix_secs: u64, out: &mut [u8; 29]) {
  let days = unix_secs / 86_400;
  let rem = unix_secs % 86_400;
  let (year, month, day) = civil_from_days(days);
  let weekday = DAYS.get(usize::try_from(days % 7).unwrap_or(0)).copied().unwrap_or(b"Thu");
  let month_name = MONTHS.get(usize::from(month).wrapping_sub(1)).copied().unwrap_or(b"Jan");
  let two = |value: u64| [b'0'.wrapping_add((value / 10 % 10) as u8), b'0'.wrapping_add((value % 10) as u8)];
  let [d0, d1] = two(u64::from(day));
  let [h0, h1] = two(rem / 3600);
  let [m0, m1] = two(rem / 60 % 60);
  let [s0, s1] = two(rem % 60);
  let [y0, y1] = two(u64::from(year) / 100);
  let [y2, y3] = two(u64::from(year) % 100);
  let [w0, w1, w2] = *weekday;
  let [n0, n1, n2] = *month_name;
  *out = [
    w0, w1, w2, b',', b' ', d0, d1, b' ', n0, n1, n2, b' ', y0, y1, y2, y3, b' ', h0, h1, b':', m0,
    m1, b':', s0, s1, b' ', b'G', b'M', b'T',
  ];
}

/// (year, month 1-12, day 1-31) of a count of days since 1970-01-01 (H. Hinnant's algorithm).
fn civil_from_days(days: u64) -> (u32, u8, u8) {
  let z = days.wrapping_add(719_468);
  let era = z / 146_097;
  let doe = z % 146_097;
  let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
  let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
  let mp = (5 * doy + 2) / 153;
  let day = doy - (153 * mp + 2) / 5 + 1;
  let month = if mp < 10 { mp + 3 } else { mp - 9 };
  let year = yoe + era * 400 + u64::from(month <= 2);
  (u32::try_from(year).unwrap_or(u32::MAX), month as u8, day as u8)
}

#[cfg(test)]
mod tests {
  use crate::http::date_header::format_imf_fixdate;

  #[test]
  fn date_known_values() {
    let mut out = [0; 29];
    format_imf_fixdate(0, &mut out);
    assert_eq!(&out, b"Thu, 01 Jan 1970 00:00:00 GMT");
    format_imf_fixdate(1_700_000_000, &mut out);
    assert_eq!(&out, b"Tue, 14 Nov 2023 22:13:20 GMT");
    format_imf_fixdate(951_782_400, &mut out);
    assert_eq!(&out, b"Tue, 29 Feb 2000 00:00:00 GMT");
    format_imf_fixdate(4_102_444_799, &mut out);
    assert_eq!(&out, b"Thu, 31 Dec 2099 23:59:59 GMT");
  }
}
