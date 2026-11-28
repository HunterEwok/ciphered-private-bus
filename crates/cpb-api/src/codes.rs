// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 HunterEwok

//! Rule codes (R-ERR-1).
//!
//! Every rejection has a stable code of the form `area/rule`. This module is the single
//! source of the list: the simulator, the core and the conformance vectors refer to it. The
//! codes of the format layer (signatures, encoding) are added together with their vectors at
//! gate G2.

use core::fmt;

/// What kind of failure a rule code reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ErrorKind {
    /// The application called an operation with an argument the interface does not accept.
    InvalidArgument,
    /// A message or an operation was refused by a rule of the bus.
    Refused,
    /// The host failed to do what the core asked of it.
    Host,
}

impl ErrorKind {
    /// The name of the kind as shown in debug mode.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::InvalidArgument => "invalid argument",
            Self::Refused => "refused",
            Self::Host => "host failure",
        }
    }
}

/// A stable rule code `area/rule`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RuleCode {
    area: &'static str,
    rule: &'static str,
    kind: ErrorKind,
    requirement: &'static str,
    message: &'static str,
}

impl RuleCode {
    const fn new(
        area: &'static str,
        rule: &'static str,
        kind: ErrorKind,
        requirement: &'static str,
        message: &'static str,
    ) -> Self {
        Self { area, rule, kind, requirement, message }
    }

    /// The area, the part before the slash.
    #[must_use]
    pub const fn area(&self) -> &'static str {
        self.area
    }

    /// The rule, the part after the slash.
    #[must_use]
    pub const fn rule(&self) -> &'static str {
        self.rule
    }

    /// The kind of failure.
    #[must_use]
    pub const fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// The requirement that defines the rule.
    #[must_use]
    pub const fn requirement(&self) -> &'static str {
        self.requirement
    }

    /// A short human-readable message, safe to show in release mode.
    #[must_use]
    pub const fn message(&self) -> &'static str {
        self.message
    }

    /// Looks a code up by its text `area/rule`.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let (area, rule) = text.split_once('/')?;
        ALL.iter().copied().find(|c| c.area == area && c.rule == rule)
    }

    // ------------------------------------------------------------------ interface

    /// The application tried to use a channel reserved for the bus.
    pub const API_RESERVED_CHANNEL: Self = Self::new(
        "api",
        "reserved-channel",
        ErrorKind::InvalidArgument,
        "R-CH-16",
        "This channel is reserved for the bus.",
    );
    /// Publication data, call arguments or a call result exceed 4096 bytes.
    pub const API_DATA_TOO_LARGE: Self = Self::new(
        "api",
        "data-too-large",
        ErrorKind::InvalidArgument,
        "R-CH-17",
        "The data is too large; send it as a blob.",
    );
    /// The retention depth exceeds the profile limit.
    pub const API_DEPTH_TOO_LARGE: Self = Self::new(
        "api",
        "depth-too-large",
        ErrorKind::InvalidArgument,
        "R-CH-10",
        "The retention depth exceeds the profile limit.",
    );
    /// The action number is outside 1..64.
    pub const API_BAD_ACTION: Self = Self::new(
        "api",
        "bad-action",
        ErrorKind::InvalidArgument,
        "R-CALL-3",
        "The action number must be between 1 and 64.",
    );
    /// The node name is longer than 64 bytes.
    pub const API_NAME_TOO_LONG: Self =
        Self::new("api", "name-too-long", ErrorKind::InvalidArgument, "R-API-2", "The device name is too long.");
    /// The call or the host request is not known, or was already answered.
    pub const API_UNKNOWN_ID: Self = Self::new(
        "api",
        "unknown-id",
        ErrorKind::InvalidArgument,
        "R-API-2",
        "There is no such pending call or request.",
    );
    /// The root key was asked for on a device that is not the root device.
    pub const API_NOT_ROOT: Self = Self::new(
        "api",
        "not-root",
        ErrorKind::InvalidArgument,
        "R-CALL-4",
        "Only the root device can use the root key.",
    );
    /// The bus result code given by the application is reserved for the bus.
    pub const API_BUS_RESULT: Self = Self::new(
        "api",
        "bus-result",
        ErrorKind::InvalidArgument,
        "R-CALL-11",
        "Result codes below 256 belong to the bus.",
    );

    // ----------------------------------------------------------------- membership

    /// The sender is not a valid member under the receiver's checkpoint.
    pub const MEM_NOT_MEMBER: Self =
        Self::new("mem", "not-member", ErrorKind::Refused, "R-MEM-2", "The sender is not a member of the bus.");
    /// The sender carries a newer checkpoint; the message is dropped and the checkpoint requested.
    pub const MEM_BEHIND: Self = Self::new(
        "mem",
        "behind",
        ErrorKind::Refused,
        "R-MEM-6",
        "The message was dropped while the membership catches up.",
    );
    /// A checkpoint whose number is not greater than the current one.
    pub const MEM_STALE_CHECKPOINT: Self =
        Self::new("mem", "stale-checkpoint", ErrorKind::Refused, "R-MEM-5", "An old membership record was ignored.");
    /// A passport beyond the next free number of the checkpoint.
    pub const MEM_EARLY_PASSPORT: Self =
        Self::new("mem", "early-passport", ErrorKind::Refused, "R-MEM-3", "A passport arrived before its checkpoint.");
    /// Two records of one author with one number and different bodies.
    pub const MEM_FORK: Self =
        Self::new("mem", "fork", ErrorKind::Refused, "R-MEM-8", "The bus has stopped: the owner's records conflict.");
    /// The node is halted and does not perform the operation.
    pub const MEM_HALTED: Self =
        Self::new("mem", "halted", ErrorKind::Refused, "R-MEM-9", "The bus has stopped and waits for the owner.");

    // ------------------------------------------------------------------- channels

    /// The source of a publication or a grant has no publish right.
    pub const PUB_NO_RIGHT: Self =
        Self::new("pub", "no-right", ErrorKind::Refused, "R-CH-13", "The sender may not publish.");
    /// A publication under a key the reader does not hold.
    pub const PUB_NO_KEY: Self =
        Self::new("pub", "no-key", ErrorKind::Refused, "R-CH-9", "A publication arrived before its key.");
    /// A publication that is neither new nor missing from the window.
    pub const PUB_OUTSIDE_WINDOW: Self =
        Self::new("pub", "outside-window", ErrorKind::Refused, "R-CH-9", "An old or repeated publication was ignored.");
    /// A grant to a device without the read right.
    pub const GRANT_NO_READ_RIGHT: Self =
        Self::new("grant", "no-read-right", ErrorKind::Refused, "R-CH-13", "This device may not read channels.");
    /// A grant with a lower generation, or with another key at the same generation.
    pub const GRANT_OLD: Self =
        Self::new("grant", "old", ErrorKind::Refused, "R-CH-9", "An old channel key was ignored.");
    /// A key request from a device that is not a reader of the channel.
    pub const GRANT_NOT_READER: Self =
        Self::new("grant", "not-reader", ErrorKind::Refused, "R-API-2", "The device is not a reader of this channel.");

    // ---------------------------------------------------------------------- calls

    /// A nonce request or a call from a device the target creates no slot for.
    pub const CALL_NO_SLOT: Self = Self::new(
        "call",
        "no-slot",
        ErrorKind::Refused,
        "R-CALL-7",
        "The target does not accept calls from this device.",
    );
    /// The nonce of a call does not match the slot.
    pub const CALL_NONCE_MISMATCH: Self = Self::new(
        "call",
        "nonce-mismatch",
        ErrorKind::Refused,
        "R-CALL-13",
        "The call was not executed: its nonce is stale.",
    );
    /// The call was sealed to a key epoch the target no longer holds.
    pub const CALL_STALE_EPOCH: Self =
        Self::new("call", "stale-epoch", ErrorKind::Refused, "R-CALL-13", "The call was sealed to an old key.");
    /// The signing key has no right to the action under the target's passport.
    pub const CALL_NO_RIGHT: Self =
        Self::new("call", "no-right", ErrorKind::Refused, "R-CALL-4", "The caller has no right to this action.");
    /// The host refused the user-presence or root signature.
    pub const CALL_NOT_CONFIRMED: Self =
        Self::new("call", "not-confirmed", ErrorKind::Refused, "R-API-3", "The action was not confirmed by the user.");

    // -------------------------------------------------------------------- storage

    /// The host reported a failed storage write.
    pub const STORE_FAILED: Self =
        Self::new("store", "failed", ErrorKind::Host, "R-CORE-7", "The device could not save its state.");
}

/// Every rule code, in the order of this module.
pub const ALL: &[RuleCode] = &[
    RuleCode::API_RESERVED_CHANNEL,
    RuleCode::API_DATA_TOO_LARGE,
    RuleCode::API_DEPTH_TOO_LARGE,
    RuleCode::API_BAD_ACTION,
    RuleCode::API_NAME_TOO_LONG,
    RuleCode::API_UNKNOWN_ID,
    RuleCode::API_NOT_ROOT,
    RuleCode::API_BUS_RESULT,
    RuleCode::MEM_NOT_MEMBER,
    RuleCode::MEM_BEHIND,
    RuleCode::MEM_STALE_CHECKPOINT,
    RuleCode::MEM_EARLY_PASSPORT,
    RuleCode::MEM_FORK,
    RuleCode::MEM_HALTED,
    RuleCode::PUB_NO_RIGHT,
    RuleCode::PUB_NO_KEY,
    RuleCode::PUB_OUTSIDE_WINDOW,
    RuleCode::GRANT_NO_READ_RIGHT,
    RuleCode::GRANT_OLD,
    RuleCode::GRANT_NOT_READER,
    RuleCode::CALL_NO_SLOT,
    RuleCode::CALL_NONCE_MISMATCH,
    RuleCode::CALL_STALE_EPOCH,
    RuleCode::CALL_NO_RIGHT,
    RuleCode::CALL_NOT_CONFIRMED,
    RuleCode::STORE_FAILED,
];

impl fmt::Display for RuleCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.area, self.rule)
    }
}
