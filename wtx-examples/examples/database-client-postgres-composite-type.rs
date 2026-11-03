//! ```sql
//! CREATE TYPE custom_composite_type AS (int_value INT, varchar_value VARCHAR);
//! CREATE TABLE custom_composite_table (id INT, custom_composite_type CUSTOM_COMPOSITE_TYPE);
//! ```

extern crate tokio;
extern crate rimu_ws;
extern crate rimu_ws_examples;

use rimu_ws::{
  codec::{Decode, Encode},
  database::{
    DbClient as _, Record, Typed,
    client::postgres::{
      Postgres, PostgresDecodeWrapper, PostgresEncodeWrapper, StructDecoder, StructEncoder, Ty,
    },
  },
};

#[tokio::main]
async fn main() -> rimu_ws::Result<()> {
  let uri = "postgres://USER:PASSWORD@localhost/DATABASE";
  let mut executor = rimu_ws_examples::postgres_client(uri).await?;
  executor
    .execute_stmt_none(
      "INSERT INTO custom_composite_table VALUES ($1, $2::custom_composite_type)",
      (1, CustomCompositeType(2, 9)),
    )
    .await?;
  let record = executor.execute_stmt_single("SELECT * FROM custom_composite_table", ()).await?;
  assert_eq!(record.decode::<_, i32>(0)?, 1);
  assert_eq!(record.decode::<_, CustomCompositeType>(1)?, CustomCompositeType(2, 9));
  Ok(())
}

#[derive(Debug, PartialEq)]
struct CustomCompositeType(u32, u64);

impl Decode<'_, Postgres<rimu_ws::Error>> for CustomCompositeType {
  #[inline]
  fn decode(dw: &mut PostgresDecodeWrapper<'_, '_>) -> Result<Self, rimu_ws::Error> {
    let mut sd = StructDecoder::<rimu_ws::Error>::new(dw);
    Ok(Self(sd.decode()?, sd.decode()?))
  }
}

impl Encode<Postgres<rimu_ws::Error>> for CustomCompositeType {
  #[inline]
  fn encode(&self, ew: &mut PostgresEncodeWrapper<'_>) -> Result<(), rimu_ws::Error> {
    let _ev = StructEncoder::<rimu_ws::Error>::new(ew)?.encode(self.0)?.encode(self.1)?;
    Ok(())
  }
}

impl Typed<Postgres<rimu_ws::Error>> for CustomCompositeType {
  #[inline]
  fn runtime_ty(&self) -> Option<Ty> {
    None
  }

  #[inline]
  fn static_ty() -> Option<Ty> {
    None
  }
}
