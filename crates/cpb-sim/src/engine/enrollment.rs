// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 HunterEwok

//! Device enrollment: the Quint model `models/enrollment/enrollment.qnt` in Rust.
//!
//! The engine holds what the model checks: the attempts each side counts per code
//! (R-JOIN-3), the payload a joiner signs over its pairing session, the join request an
//! acceptor makes from it (R-JOIN-4), and the Root's check of the joiner's signature before
//! a request reaches the owner (R-JOIN-5). Pairing itself is `CPace` in the core; here a
//! session is named by its transcript, as in the model.

use std::collections::VecDeque;

use cpb_api::{DeviceId, RuleCode};

/// The runs one side has made with one code (R-JOIN-3).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Attempts {
    limit: u8,
    used: u8,
}

impl Attempts {
    /// A fresh code that allows `limit` runs.
    #[must_use]
    pub fn new(limit: u8) -> Self {
        Self { limit, used: 0 }
    }

    /// Counts a run. False if the code is spent: the run must not happen.
    pub fn take(&mut self) -> bool {
        if self.used >= self.limit {
            return false;
        }
        self.used = self.used.saturating_add(1);
        true
    }

    /// Runs made.
    #[must_use]
    pub fn used(&self) -> u8 {
        self.used
    }

    /// Runs the code still allows.
    #[must_use]
    pub fn left(&self) -> u8 {
        self.limit.saturating_sub(self.used)
    }
}

/// What a joiner signs: its device key, its user-presence key, its name, and the transcript
/// of the pairing session (R-JOIN-4). A key is named by the device that holds it.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Payload {
    /// The joiner's device key.
    pub key: DeviceId,
    /// The user-presence key, named by its owner's device.
    pub presence: Option<DeviceId>,
    /// The proposed name.
    pub name: String,
    /// The transcript of the session the payload was signed in.
    pub tid: u64,
}

/// A join request: the fields the Root shows and admits, and the payload the joiner's
/// signature covers.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Request {
    /// The joiner's device key.
    pub key: DeviceId,
    /// The user-presence key.
    pub presence: Option<DeviceId>,
    /// The name.
    pub name: String,
    /// The transcript of the acceptor's pairing session.
    pub tid: u64,
    /// The joiner's signed payload.
    pub signed: Payload,
    /// The member that submitted the request.
    pub acceptor: DeviceId,
}

impl Request {
    /// An honest acceptor, or the Root pairing directly, turns a payload it received in its
    /// session `tid` into a join request.
    ///
    /// # Errors
    /// `join/transcript` if the payload was signed over another session: a man in the middle
    /// relayed it (R-JOIN-4).
    pub fn from_session(tid: u64, acceptor: DeviceId, p: &Payload) -> Result<Self, RuleCode> {
        if p.tid != tid {
            return Err(RuleCode::JOIN_TRANSCRIPT);
        }
        Ok(Self { key: p.key, presence: p.presence, name: p.name.clone(), tid, signed: p.clone(), acceptor })
    }

    /// The joiner's signature verifies over the request: the key, the presence key, the name
    /// and the transcript are the ones it signed (R-JOIN-4).
    #[must_use]
    pub fn signature_ok(&self) -> bool {
        let s = &self.signed;
        s.key == self.key && s.tid == self.tid && s.presence == self.presence && s.name == self.name
    }
}

/// A bounded buffer of join requests, oldest first: the Root's requests waiting for the
/// owner, and the requests a relay or an acceptor holds for the Root (R-JOIN-8).
#[derive(Clone, Debug)]
pub struct Buffer {
    limit: usize,
    held: VecDeque<Request>,
}

impl Buffer {
    /// An empty buffer of at most `limit` requests.
    #[must_use]
    pub fn new(limit: usize) -> Self {
        Self { limit, held: VecDeque::new() }
    }

    /// Holds a request without looking into it, as a relay does. A request already held is
    /// not held twice; on overflow the oldest is evicted and returned.
    pub fn hold(&mut self, r: Request) -> Option<Request> {
        if self.held.contains(&r) {
            return None;
        }
        self.held.push_back(r);
        if self.held.len() > self.limit { self.held.pop_front() } else { None }
    }

    /// The Root receives a request: it verifies the joiner's signature and holds the request
    /// for the owner. Returns false for a request it already holds.
    ///
    /// # Errors
    /// `join/signature` if the signature does not cover the request; it is dropped.
    pub fn receive(&mut self, r: Request) -> Result<bool, RuleCode> {
        if !r.signature_ok() {
            return Err(RuleCode::JOIN_SIGNATURE);
        }
        if self.held.contains(&r) {
            return Ok(false);
        }
        let _evicted = self.hold(r);
        Ok(true)
    }

    /// The requests held, oldest first.
    pub fn iter(&self) -> impl Iterator<Item = &Request> {
        self.held.iter()
    }

    /// Whether nothing is held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.held.is_empty()
    }

    /// Removes a request.
    pub fn remove(&mut self, r: &Request) -> bool {
        let before = self.held.len();
        self.held.retain(|x| x != r);
        self.held.len() != before
    }

    /// Takes every request out, oldest first.
    pub fn drain(&mut self) -> Vec<Request> {
        self.held.drain(..).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::{Attempts, Buffer, Payload, Request};
    use cpb_api::{DeviceId, RuleCode};

    const JOINER: DeviceId = DeviceId::from_u64(1);
    const ACCEPTOR: DeviceId = DeviceId::from_u64(2);

    fn payload(tid: u64) -> Payload {
        Payload { key: JOINER, presence: Some(JOINER), name: "j".to_owned(), tid }
    }

    /// The model's `limitTest`: a side stops after its attempts (R-JOIN-3).
    #[test]
    fn a_code_allows_its_attempts_and_no_more() {
        let mut a = Attempts::new(2);
        assert!(a.take() && a.take());
        assert!(!a.take());
        assert_eq!((a.used(), a.left()), (2, 0));
    }

    /// The model's `relayTest`: a payload signed in the joiner's session with a man in the
    /// middle makes no request in the acceptor's own session (R-JOIN-4).
    #[test]
    fn a_relayed_payload_makes_no_request() {
        assert_eq!(Request::from_session(2, ACCEPTOR, &payload(1)), Err(RuleCode::JOIN_TRANSCRIPT));
        assert!(Request::from_session(1, ACCEPTOR, &payload(1)).is_ok_and(|r| r.signature_ok()));
    }

    /// The model's `tamperTest`: the Root drops a request whose presence key, name, key or
    /// transcript the joiner did not sign (R-JOIN-4).
    #[test]
    fn the_root_drops_a_tampered_request() {
        let good = Request::from_session(1, ACCEPTOR, &payload(1));
        let Ok(good) = good else { return };
        let tampered = [
            Request { presence: None, ..good.clone() },
            Request { name: "other".to_owned(), ..good.clone() },
            Request { key: ACCEPTOR, ..good.clone() },
            Request { tid: 2, ..good.clone() },
        ];
        let mut inbox = Buffer::new(4);
        for r in tampered {
            assert_eq!(inbox.receive(r), Err(RuleCode::JOIN_SIGNATURE));
        }
        assert!(inbox.is_empty());
        assert_eq!(inbox.receive(good.clone()), Ok(true));
        assert_eq!(inbox.receive(good), Ok(false));
    }

    /// R-JOIN-8: the buffer is bounded and keeps the newest request.
    #[test]
    fn a_full_buffer_evicts_the_oldest() {
        let mut held = Buffer::new(2);
        let requests: Vec<Request> =
            (1..=3).filter_map(|t| Request::from_session(t, ACCEPTOR, &payload(t)).ok()).collect();
        let evicted: Vec<Option<Request>> = requests.iter().map(|r| held.hold(r.clone())).collect();
        assert_eq!(evicted, vec![None, None, requests.first().cloned()]);
        assert_eq!(held.drain(), requests.get(1..).unwrap_or_default().to_vec());
    }
}
