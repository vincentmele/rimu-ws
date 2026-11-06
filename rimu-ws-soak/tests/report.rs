//! The report card: one row per server, one column per check, from the runs' summaries.

use rimu_ws_soak::report::{card, load, merge};
use std::path::PathBuf;

fn fixture(name: &str) -> PathBuf {
  PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/report").join(name)
}

#[test]
fn merges_rounds_by_label() {
  let rows = merge(load(&[fixture("b.jsonl"), fixture("b2.jsonl")]).unwrap());
  let other = &rows["other"];
  assert_eq!(other.scenarios[&rimu_ws_soak::scenario::Scenario::Echo].runs, 400);
  assert_eq!(other.scenarios[&rimu_ws_soak::scenario::Scenario::Echo].should, 3);
  assert_eq!(other.violations.len(), 1);
  assert_eq!(rows.len(), 1);
}

#[test]
fn gated_row_first_and_pass_line() {
  let rows = merge(load(&[fixture("b.jsonl"), fixture("a.jsonl")]).unwrap());
  let text = card(&rows, "rimu-ws");
  let first_row =
    text.lines().find(|el| el.starts_with("| ") && !el.starts_with("| Server")).unwrap();
  assert!(first_row.starts_with("| rimu-ws |"), "{text}");
  assert!(text.contains("rimu-ws: PASS"), "{text}");
  assert!(text.contains("SHOULD 1"), "{text}");
  let toughness = text.split("## Toughness").nth(1).unwrap().split("## Examples").next().unwrap();
  assert!(toughness.contains("`invalid`"), "{text}");
  assert!(!toughness.contains("`echo`"), "{text}");
}

#[test]
fn dead_server_shows_in_survival() {
  let rows = merge(load(&[fixture("dead.jsonl"), fixture("a.jsonl")]).unwrap());
  let text = card(&rows, "rimu-ws");
  let header = text.lines().find(|el| el.starts_with("| Server")).unwrap();
  let column = header.split('|').map(str::trim).position(|el| el == "PidGone").unwrap();
  let dead = text.lines().find(|el| el.starts_with("| dead |")).unwrap();
  assert_eq!(dead.split('|').map(str::trim).nth(column), Some("1"), "{text}");
}

#[test]
fn did_not_start_is_invalid() {
  let rows = merge(load(&[fixture("nostart.jsonl")]).unwrap());
  let text = card(&rows, "rimu-ws");
  let row = text.lines().find(|el| el.starts_with("| nostart |")).unwrap();
  assert!(row.contains("did not start"), "{text}");
}

#[test]
fn gate_fails_on_a_gated_failure() {
  let mut rows = merge(load(&[fixture("a.jsonl")]).unwrap());
  let summary = rows.get_mut("rimu-ws").unwrap();
  summary.violations.push(rimu_ws_soak::monitor::Violation::PidGone);
  assert!(card(&rows, "rimu-ws").contains("rimu-ws: FAIL"));
}
