//! Basic time operation.

extern crate rimu_ws;

use rimu_ws::calendar::{Datetime, IDuration};

fn main() -> rimu_ws::Result<()> {
  println!(
    "ISO 8601 representation of the next 2 minutes in UTC: {}",
    Datetime::now()?.add(IDuration::from_minutes(2)?)?
  );
  Ok(())
}
