// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 HunterEwok

//! Error reports and the two reporting modes (R-ERR-2 to R-ERR-5).

use alloc::format;
use alloc::string::String;
use core::fmt;

use crate::codes::RuleCode;

/// How much of an error is shown to the user (R-ERR-2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ErrorMode {
    /// The short message, then the rule code, the error kind and the underlying message.
    Debug,
    /// The short message only; the details go to the log.
    Release,
}

impl ErrorMode {
    /// The mode that follows the build type (R-ERR-3): `Debug` in a debug build.
    #[must_use]
    pub const fn for_build() -> Self {
        if cfg!(debug_assertions) { Self::Debug } else { Self::Release }
    }

    /// Parses an override value: `debug` or `release`, in any letter case.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let t = text.trim();
        if t.eq_ignore_ascii_case("debug") {
            Some(Self::Debug)
        } else if t.eq_ignore_ascii_case("release") {
            Some(Self::Release)
        } else {
            None
        }
    }

    /// The mode from an optional override, falling back to the build type.
    #[must_use]
    pub fn resolve(overridden: Option<&str>) -> Self {
        overridden.and_then(Self::parse).unwrap_or_else(Self::for_build)
    }
}

/// A rejection, as the application sees it.
///
/// The detail names identifiers and numbers only: never keys, publication content or call
/// arguments (R-ERR-5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    code: RuleCode,
    detail: String,
}

impl Report {
    /// A report of a rule with an underlying message.
    #[must_use]
    pub fn new(code: RuleCode, detail: impl Into<String>) -> Self {
        Self { code, detail: detail.into() }
    }

    /// The rule code.
    #[must_use]
    pub const fn code(&self) -> RuleCode {
        self.code
    }

    /// The underlying message.
    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }

    /// The text shown to the user in the given mode (R-ERR-2).
    #[must_use]
    pub fn render(&self, mode: ErrorMode) -> String {
        match mode {
            ErrorMode::Release => String::from(self.code.message()),
            ErrorMode::Debug => self.log_line(),
        }
    }

    /// The full line written to the log in both modes.
    #[must_use]
    pub fn log_line(&self) -> String {
        format!(
            "{}\n  code: {} ({})\n  kind: {}\n  detail: {}",
            self.code.message(),
            self.code,
            self.code.requirement(),
            self.code.kind().name(),
            self.detail
        )
    }
}

impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.detail)
    }
}

impl core::error::Error for Report {}
