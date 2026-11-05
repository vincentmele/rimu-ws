/// Executor Error
#[derive(Clone, Copy, Debug)]
pub enum ExecutorError {
  /// Could not resolve to any address
  InvalidResolvedAddress,
  /// An operation that needs the runtime of the current thread ran outside of it
  MissingRuntime,
  /// A spawned task panicked. The panic hook has reported it.
  TaskPanicked,
  /// The std runtime does not implement `spawn_local`
  UnsupportedStdSpawnLocal,
}
