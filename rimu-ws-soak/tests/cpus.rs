//! Pinning the probes to their own CPUs and keeping the load off them: probes that share CPUs with
//! the load measure the harness, not the server.

mod support;

use rimu_ws_soak::{
  conn::ConnOpts,
  cpus::{current_cpus, load_runtime, without},
  probe::Probes,
  scenario::{Ctx, Limits, Mode},
};
use support::{Faults, spawn_fake};

#[test]
fn without_removes_the_probe_cpus() {
  assert_eq!(without(&[6, 7, 11, 18, 23], &[11, 23]), vec![6, 7, 18]);
}

#[test]
fn load_runtime_threads_stay_on_the_load_cpus() {
  let cpus = current_cpus();
  assert!(!cpus.is_empty());
  let load = vec![cpus[0]];
  let runtime = load_runtime(load.clone());
  let seen = runtime.block_on(async {
    let mut seen = Vec::new();
    for _ in 0..8 {
      seen.push(tokio::spawn(async { current_cpus() }).await.unwrap());
    }
    seen.push(current_cpus());
    seen
  });
  assert!(seen.iter().all(|el| *el == load), "{seen:?}");
}

#[test]
fn probes_run_on_their_cpus() {
  let cpus = current_cpus();
  let probe_cpu = vec![*cpus.last().unwrap()];
  let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
  let addr = runtime.block_on(spawn_fake(Faults::default()));
  let ctx = Ctx {
    addr,
    host: "localhost".into(),
    path: "/".into(),
    limits: Limits::default(),
    mode: Mode::Common,
    opts: ConnOpts::default(),
  };
  let probes = Probes::spawn(ctx, 1, 10, probe_cpu.clone());
  std::thread::sleep(std::time::Duration::from_millis(300));
  assert_eq!(probes.cpus(), probe_cpu);
  assert!(probes.snapshot().count > 0);
  probes.stop();
}
