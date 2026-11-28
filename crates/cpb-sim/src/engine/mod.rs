// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 HunterEwok

//! The model engine: the state machines of the Quint models, written as Rust.
//!
//! Each submodule mirrors one model and has no I/O. The node composes them, and the trace
//! replay test drives them directly with the actions of a model trace.

pub mod calls;
pub mod channels;
pub mod enrollment;
pub mod membership;
pub mod streams;
