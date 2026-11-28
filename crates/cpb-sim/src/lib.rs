// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 HunterEwok

//! A deterministic in-memory simulator of **Ciphered Private Bus** (CPB) for application
//! authors.
//!
//! Several bus nodes run in one process, without a network and **without cryptography**. Each
//! node offers the application exactly the local interface of R-API-2 ([`cpb_api::LocalApi`])
//! and follows the bus's membership, channel and call rules. The rules come from the Quint
//! models of verification level V2: the [`engine`] modules are those models written as Rust,
//! and a trace replay test checks that they take the same transitions.
//!
//! **Not a security boundary.** Nothing here is encrypted or signed. The simulator shows the
//! behaviour an application sees at the interface; it says nothing about secrecy.
//!
//! A run is fully determined by its seed (R-VER-7). Faults are injected per hop: loss,
//! duplication, reordering; links go up and down; nodes sleep, reboot, and receive the host
//! events "reset nonces" and "rotate key epoch".
//!
//! Errors follow R-ERR-2 and R-ERR-3: the mode follows the build type and is overridden by the
//! environment variable `CPB_ERRORS=debug|release` or by [`Config::mode`].
//!
//! Version 0.x: enrollment, membership, channels, calls and streams. Bus creation, root
//! change, halt propagation and power loss at every step arrive next.
//!
//! ```
//! use cpb_api::{Channel, DeviceId, Event, LocalApi, Rights};
//! use cpb_sim::{Config, Sim};
//!
//! let root = DeviceId::from_u64(1);
//! let sensor = DeviceId::from_u64(2);
//! let mut sim = Sim::new(Config::default(), root);
//! sim.admit(sensor, Rights::MEMBER, false, Vec::new());
//! sim.link(root, sensor);
//!
//! let ch = Channel(16);
//! if let Some(mut app) = sim.node(root) {
//!     app.subscribe(sensor, ch).unwrap();
//! }
//! if let Some(mut app) = sim.node(sensor) {
//!     app.publish(ch, b"21.5", 1).unwrap();
//! }
//! sim.settle().unwrap();
//! let got = sim.drain_events(root);
//! assert!(got.iter().any(|e| matches!(e, Event::Publication(p) if p.data == b"21.5")));
//! ```

pub mod engine;
mod node;
mod rng;
mod sim;

pub use node::{
    DEFAULT_BLOB_SEGMENT, DEFAULT_JOIN_BUFFER, DEFAULT_MAX_STREAMS, DEFAULT_PAIRING_ATTEMPTS, DEFAULT_STREAM_CHUNK,
    Profile,
};
pub use sim::{Config, ERROR_MODE_VAR, Faults, NodeApi, Sim, StepLimit};
