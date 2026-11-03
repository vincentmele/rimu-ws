use crate::clap::EmbedMigrations;
use core::fmt::Write as _;
use std::path::Path;
use tokio::{fs::OpenOptions, io::AsyncWriteExt as _};
use rimu_ws::database::schema_manager::misc::{group_and_migrations_from_path, parse_root_toml};

pub(crate) async fn embed_migrations(elem: EmbedMigrations) -> rimu_ws::Result<()> {
  let (mut migration_groups, _) = parse_root_toml(Path::new(&elem.input))?;
  let mut buffer = String::new();

  migration_groups.sort();

  buffer.push_str(
    "#[rustfmt::skip]pub(crate) static GROUPS: rimu_ws::database::schema_manager::EmbeddedMigrationsTy = &[",
  );

  for mg_path in migration_groups {
    let (mg, ms) = group_and_migrations_from_path(&mg_path, Ord::cmp)?;
    let mg_name = mg.name().to_ascii_uppercase();
    let mg_uid = mg.uid();

    buffer.write_fmt(format_args!(
      concat!(
        "{{",
        r#"const {mg_name}: &rimu_ws::database::schema_manager::UserMigrationGroup<&'static str> = &rimu_ws::database::schema_manager::UserMigrationGroup::new("{mg_name}",{mg_uid});"#,
        r#"const {mg_name}_MIGRATIONS: &[rimu_ws::database::schema_manager::UserMigrationRef<'static, 'static>] = &["#
      ),
      mg_name = mg_name,
      mg_uid = mg_uid
    ))?;

    for rslt in ms {
      let migration = rslt?;
      let checksum = migration.checksum();
      let dbs = migration.dbs();
      let name = migration.name();
      let sql_down = migration.sql_down();
      let sql_up = migration.sql_up();
      let uid = migration.uid();

      buffer.write_fmt(format_args!(
        "rimu_ws::database::schema_manager::UserMigrationRef::from_all_parts({checksum},&["
      ))?;
      for db in dbs {
        buffer.push_str("rimu_ws::database::DatabaseTy::");
        buffer.push_str(db.strings().ident);
        buffer.push(',');
      }
      buffer.write_fmt(format_args!(r#"],"{name}","#))?;
      match migration.repeatability() {
        None => buffer.push_str("None"),
        Some(repeatability) => buffer.write_fmt(format_args!(
          "Some(rimu_ws::database::schema_manager::Repeatability::{})",
          repeatability.strings().ident
        ))?,
      }
      buffer.write_fmt(format_args!(r#","{sql_down}","{sql_up}",{uid}),"#))?;
    }

    buffer.write_fmt(format_args!("];({mg_name},{mg_name}_MIGRATIONS)}},"))?;
  }

  buffer.push_str("];\n");

  OpenOptions::new()
    .create(true)
    .truncate(true)
    .write(true)
    .open(&elem.output)
    .await?
    .write_all(buffer.as_bytes())
    .await?;

  Ok(())
}
