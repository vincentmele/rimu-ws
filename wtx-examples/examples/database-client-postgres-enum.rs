//! ```sql
//! CREATE TYPE custom_enum AS ENUM ('foo', 'bar', 'baz');
//! CREATE TABLE custom_enum_table (id INT, custom_enum CUSTOM_ENUM);
//! ```

extern crate tokio;
extern crate rimu_ws;
extern crate rimu_ws_examples;

use rimu_ws::{
  codec::{Decode, Encode},
  database::{
    DbClient as _, Record, Typed,
    client::postgres::{Postgres, PostgresDecodeWrapper, PostgresEncodeWrapper, Ty},
  },
};

#[tokio::main]
async fn main() -> rimu_ws::Result<()> {
  let uri = "postgres://USER:PASSWORD@localhost/DATABASE";
  let mut executor = rimu_ws_examples::postgres_client(uri).await?;
  executor
    .execute_stmt_none("INSERT INTO custom_enum_table VALUES ($1, $2)", (1, Enum::Bar))
    .await?;
  let record = executor.execute_stmt_single("SELECT * FROM custom_enum_table;", ()).await?;
  assert_eq!(record.decode::<_, i32>(0)?, 1);
  assert_eq!(record.decode::<_, Enum>(1)?, Enum::Bar);
  Ok(())
}

#[derive(Debug, PartialEq)]
enum Enum {
  Foo,
  Bar,
  Baz,
}

impl Decode<'_, Postgres<rimu_ws::Error>> for Enum {
  #[inline]
  fn decode(dw: &mut PostgresDecodeWrapper<'_, '_>) -> Result<Self, rimu_ws::Error> {
    let string = <&str as Decode<Postgres<rimu_ws::Error>>>::decode(dw)?;
    Ok(match string {
      "foo" => Self::Foo,
      "bar" => Self::Bar,
      "baz" => Self::Baz,
      _ => return Err(rimu_ws::Error::UnexpectedString { length: 3 }),
    })
  }
}

impl Encode<Postgres<rimu_ws::Error>> for Enum {
  #[inline]
  fn encode(&self, ew: &mut PostgresEncodeWrapper<'_>) -> Result<(), rimu_ws::Error> {
    let string = match self {
      Self::Foo => "foo",
      Self::Bar => "bar",
      Self::Baz => "baz",
    };
    <_ as Encode<Postgres<rimu_ws::Error>>>::encode(&string, ew)?;
    Ok(())
  }
}

impl Typed<Postgres<rimu_ws::Error>> for Enum {
  #[inline]
  fn runtime_ty(&self) -> Option<Ty> {
    None
  }

  #[inline]
  fn static_ty() -> Option<Ty> {
    None
  }
}
