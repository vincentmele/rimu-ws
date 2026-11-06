//! A soak and abuse harness for WebSocket servers: thousands of simulated clients mixing verified
//! echo traffic with hostile behaviour, and checks that the server stays correct and bounded.
//!
//! It speaks raw bytes through its own codec and doesn't depend on rimu-ws, so its clients can
//! misbehave freely and a bug the two shared couldn't hide.

pub mod burst;
pub mod codec;
pub mod conn;
pub mod cycle;
pub mod fdflood;
pub mod monitor;
pub mod probe;
pub mod report;
pub mod rng;
pub mod rules;
pub mod runner;
pub mod scenario;
