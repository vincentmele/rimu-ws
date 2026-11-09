//! CPU affinity for the harness's threads. The probes measure the server only if they never wait
//! for a CPU the load is using: at a burst's start the load runtime keeps every CPU it has busy,
//! and a probe thread sharing them waited a scheduler slice (milliseconds) for its echoes.

/// The CPUs the calling thread may run on.
pub fn current_cpus() -> Vec<usize> {
  // SAFETY: zeroed is a valid empty set, and the pointer is to it
  let mut set: libc::cpu_set_t = unsafe { core::mem::zeroed() };
  // SAFETY: valid set and size; 0 is the calling thread
  if unsafe { libc::sched_getaffinity(0, size_of::<libc::cpu_set_t>(), &mut set) } != 0 {
    return Vec::new();
  }
  // SAFETY: `set` is initialized
  (0..libc::CPU_SETSIZE as usize).filter(|cpu| unsafe { libc::CPU_ISSET(*cpu, &set) }).collect()
}

/// Pins the calling thread to `cpus`; empty leaves it as it is.
pub fn pin_current(cpus: &[usize]) -> std::io::Result<()> {
  if cpus.is_empty() {
    return Ok(());
  }
  // SAFETY: zeroed is a valid empty set
  let mut set: libc::cpu_set_t = unsafe { core::mem::zeroed() };
  for cpu in cpus {
    // SAFETY: `set` is valid, and CPU_SET ignores CPUs past its size
    unsafe { libc::CPU_SET(*cpu, &mut set) };
  }
  // SAFETY: valid set and size; 0 is the calling thread
  if unsafe { libc::sched_setaffinity(0, size_of::<libc::cpu_set_t>(), &set) } != 0 {
    return Err(std::io::Error::last_os_error());
  }
  Ok(())
}

/// `cpus` without `remove`.
pub fn without(cpus: &[usize], remove: &[usize]) -> Vec<usize> {
  cpus.iter().copied().filter(|el| !remove.contains(el)).collect()
}

/// The runtime the slots, the monitor and the cycles run on, every thread of it on `cpus` (the
/// calling thread too, which `block_on` uses). Empty pins nothing.
pub fn load_runtime(cpus: Vec<usize>) -> tokio::runtime::Runtime {
  if let Err(err) = pin_current(&cpus) {
    eprintln!("warning: pinning the harness to {cpus:?}: {err}");
  }
  let workers = if cpus.is_empty() { None } else { Some(cpus.len()) };
  let mut builder = tokio::runtime::Builder::new_multi_thread();
  let _ = builder.enable_all().on_thread_start(move || {
    let _ = pin_current(&cpus);
  });
  if let Some(workers) = workers {
    let _ = builder.worker_threads(workers);
  }
  builder.build().expect("runtime")
}
