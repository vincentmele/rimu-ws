//! The report card: one row per server and one column per check, from the summaries of runs
//! judged by the common rules (`RULES.md`), with the gate line for the server held to them and the
//! checks no other server failed.

use crate::{
  cycle::{ScenarioCounts, Summary},
  monitor::Violation,
  scenario::{Scenario, profile},
};
use std::{collections::BTreeMap, fmt::Write as _, path::PathBuf};

/// The survival checks, as the card's columns, in order.
const SURVIVAL: [&str; 13] = [
  "PidGone",
  "RssCeiling",
  "Rss",
  "Fds",
  "CloseWait",
  "Leak",
  "Trend",
  "Latency",
  "ProbeFailures",
  "NoRecovery",
  "Burst",
  "Busy",
  "Unreadable",
];

/// The last `summary` line of each file.
pub fn load(paths: &[PathBuf]) -> Result<Vec<Summary>, String> {
  let mut out = Vec::with_capacity(paths.len());
  for path in paths {
    let text = std::fs::read_to_string(path).map_err(|err| format!("{}: {err}", path.display()))?;
    let line = text
      .lines()
      .rev()
      .find(|el| el.contains("\"kind\":\"summary\""))
      .ok_or_else(|| format!("{}: no summary line", path.display()))?;
    let summary =
      serde_json::from_str(line).map_err(|err| format!("{}: summary: {err}", path.display()))?;
    out.push(summary);
  }
  Ok(out)
}

/// The summaries of each server, by label, as one: counts summed, violations together.
pub fn merge(summaries: Vec<Summary>) -> BTreeMap<String, Summary> {
  let mut rows: BTreeMap<String, Summary> = BTreeMap::new();
  for summary in summaries {
    let label = summary.label.clone().unwrap_or_else(|| "unlabelled".into());
    let Some(row) = rows.get_mut(&label) else {
      let _ = rows.insert(label, summary);
      continue;
    };
    row.cycles += summary.cycles;
    row.records += summary.records;
    row.fails += summary.fails;
    row.should_fails += summary.should_fails;
    row.marks += summary.marks;
    row.harness_errors += summary.harness_errors;
    row.violations.extend(summary.violations);
    if row.invalid.is_none() {
      row.invalid = summary.invalid;
    }
    for (scenario, counts) in summary.scenarios {
      add(row.scenarios.entry(scenario).or_default(), counts);
    }
  }
  rows
}

fn add(into: &mut ScenarioCounts, from: ScenarioCounts) {
  into.runs += from.runs;
  into.must += from.must;
  into.should += from.should;
  into.marks += from.marks;
  into.harness_errors += from.harness_errors;
  for (to, example) in [
    (&mut into.example_must, from.example_must),
    (&mut into.example_should, from.example_should),
    (&mut into.example_mark, from.example_mark),
  ] {
    if to.is_none() {
      *to = example;
    }
  }
}

/// A violation's name: its variant.
fn violation_name(violation: &Violation) -> String {
  match serde_json::to_value(violation) {
    Ok(serde_json::Value::String(name)) => name,
    Ok(serde_json::Value::Object(map)) => map.keys().next().cloned().unwrap_or_default(),
    _ => String::new(),
  }
}

/// A scenario's cell, and whether it is a failure (MUST or SHOULD).
fn scenario_cell(counts: Option<&ScenarioCounts>) -> (String, bool) {
  let Some(counts) = counts.filter(|el| el.runs > 0) else { return ("n/a".into(), false) };
  let mut parts = Vec::new();
  if counts.must > 0 {
    parts.push(format!("MUST {}", counts.must));
  }
  if counts.should > 0 {
    parts.push(format!("SHOULD {}", counts.should));
  }
  let failed = !parts.is_empty();
  if counts.marks > 0 {
    parts.push(format!("limit {}", counts.marks));
  }
  if parts.is_empty() { ("✓".into(), false) } else { (parts.join(" / "), failed) }
}

fn scenario_name(scenario: Scenario) -> String {
  serde_json::to_value(scenario)
    .ok()
    .and_then(|el| el.as_str().map(str::to_owned))
    .unwrap_or_else(|| format!("{scenario:?}"))
}

/// The card in Markdown: `gated`'s row first, the rest by name.
pub fn card(rows: &BTreeMap<String, Summary>, gated: &str) -> String {
  let scenarios: Vec<Scenario> =
    profile("common").map(|el| el.0.into_iter().map(|el| el.0).collect()).unwrap_or_default();
  let mut order: Vec<&String> = rows.keys().filter(|el| el.as_str() != gated).collect();
  if let Some((name, _)) = rows.get_key_value(gated) {
    order.insert(0, name);
  }
  let mut out = String::from("# Soak report card\n\n");
  let _ = write!(out, "| Server |");
  for scenario in &scenarios {
    let _ = write!(out, " {} |", scenario_name(*scenario));
  }
  for name in SURVIVAL {
    let _ = write!(out, " {name} |");
  }
  out.push_str(" invalid |\n|---|");
  for _ in 0..scenarios.len() + SURVIVAL.len() + 1 {
    out.push_str("---|");
  }
  out.push('\n');
  // Columns any server other than the gated one failed.
  let mut failed_somewhere: Vec<String> = Vec::new();
  let mut gate_pass = rows.contains_key(gated);
  let mut examples = Vec::new();
  for name in &order {
    let summary = &rows[*name];
    let is_gated = name.as_str() == gated;
    let _ = write!(out, "| {name} |");
    for scenario in &scenarios {
      let counts = summary.scenarios.get(scenario);
      let (cell, failed) = scenario_cell(counts);
      if is_gated && cell != "✓" && cell != "n/a" {
        gate_pass = false;
      }
      if failed && !is_gated {
        failed_somewhere.push(scenario_name(*scenario));
      }
      if let Some(counts) = counts {
        for (kind, example) in [
          ("MUST", &counts.example_must),
          ("SHOULD", &counts.example_should),
          ("limit", &counts.example_mark),
        ] {
          if let Some(id) = example {
            examples
              .push(format!("- {name} / `{}`: {kind}, replay `{id}`", scenario_name(*scenario)));
          }
        }
      }
      let _ = write!(out, " {cell} |");
    }
    let mut counts: BTreeMap<String, u64> = BTreeMap::new();
    for violation in &summary.violations {
      *counts.entry(violation_name(violation)).or_default() += 1;
    }
    for check in SURVIVAL {
      match counts.get(check) {
        Some(count) => {
          if is_gated {
            gate_pass = false;
          } else {
            failed_somewhere.push(check.to_owned());
          }
          let _ = write!(out, " {count} |");
        }
        None => out.push_str(" ✓ |"),
      }
    }
    match &summary.invalid {
      Some(reason) => {
        if is_gated {
          gate_pass = false;
        }
        let _ = writeln!(out, " {reason} |");
      }
      None => out.push_str(" ✓ |\n"),
    }
  }
  out.push_str("\n## Gate\n\n");
  let _ = writeln!(out, "{gated}: {}", if gate_pass { "PASS" } else { "FAIL" });
  out.push_str("\n## Toughness\n\nChecks no server other than the gated one failed:\n\n");
  let all: Vec<String> = scenarios
    .iter()
    .map(|el| scenario_name(*el))
    .chain(SURVIVAL.iter().map(|el| (*el).to_owned()))
    .collect();
  for check in all.iter().filter(|el| !failed_somewhere.contains(el)) {
    let _ = writeln!(out, "- `{check}`");
  }
  if !examples.is_empty() {
    out.push_str("\n## Examples\n\n");
    for line in examples {
      let _ = writeln!(out, "{line}");
    }
  }
  out
}
