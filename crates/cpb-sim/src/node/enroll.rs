// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 HunterEwok

//! Enrollment on a node: pairing by a code, the join request, and the Root's answer
//! (Section 7, Appendix B, Section B.11).
//!
//! The simulator has no cryptography, so the pairing messages carry the code itself where the
//! core carries `CPace` values and confirmations: `PairConfirm` stands for the joiner's
//! confirmation and `PairDone` for the acceptor's, followed by the sealed `PairBus`. A session
//! is named by its transcript, a value of the two nonces, and the joiner's signature is the
//! payload itself (the enrollment model does the same).

use std::collections::BTreeSet;

use cpb_api::{
    DeviceId, Event, Fingerprint, HostRequestId, HostRequestKind, JoinRequestId, KeyFingerprint, OwnerOperation,
    Paired, PairingCode, PairingId, Permit, Report, Rights, RuleCode,
};

use super::{Body, HostWait, Node, digest};
use crate::engine::enrollment::{Payload, Request};
use crate::engine::membership::{Checkpoint, View};

/// `PairAbort` codes (Appendix B, Section B.11).
const ABORT_WRONG_CODE: u8 = 1;
const ABORT_DECLINED: u8 = 4;
const ABORT_OTHER_PEER: u8 = 5;

/// A pairing run on the acceptor: one joiner on one link.
#[derive(Clone, Copy, Debug)]
struct AcceptorRun {
    tid: u64,
    /// The joiner's confirmation was correct; its sealed payload is awaited.
    confirmed: bool,
}

/// The joiner's run: the acceptor that replied, and the transcript.
#[derive(Clone, Copy, Debug)]
struct JoinerRun {
    peer: DeviceId,
    tid: u64,
}

/// The pairing a node has in progress.
#[derive(Clone, Debug)]
pub(super) struct Pairing {
    id: PairingId,
    code: PairingCode,
    /// The joiner's nonce of the current `PairInit`.
    nonce: u64,
    joiner: Option<JoinerRun>,
    acceptor: std::collections::BTreeMap<DeviceId, AcceptorRun>,
}

/// A joiner that is paired and waits for the checkpoint of its bus.
#[derive(Clone, Copy, Debug)]
pub(super) struct Bootstrap {
    pairing: PairingId,
    acceptor: DeviceId,
}

/// The stand-in for `KeyFingerprint` (Appendix B, Section B.8): a device key is named by its
/// device.
pub(crate) fn key_fingerprint(d: DeviceId) -> KeyFingerprint {
    KeyFingerprint(digest(u64::from_be_bytes(*b"cpb fpr\0"), &d.0))
}

/// The stand-in for the bus fingerprint (Appendix B, Section B.11).
pub(super) fn bus_fingerprint(bus: &[u8; 32]) -> Fingerprint {
    fingerprint(u64::from_be_bytes(*b"cpb bus\0"), bus)
}

fn fingerprint(label: u64, data: &[u8]) -> Fingerprint {
    let d = digest(label, data);
    let mut first = [0u8; 8];
    for (a, b) in first.iter_mut().zip(d) {
        *a = b;
    }
    Fingerprint(u64::from_be_bytes(first))
}

fn transcript(nonce_n: u64, nonce_a: u64) -> u64 {
    let mut both = nonce_n.to_be_bytes().to_vec();
    both.extend_from_slice(&nonce_a.to_be_bytes());
    fingerprint(u64::from_be_bytes(*b"cpb pair"), &both).0
}

impl Node {
    // -------------------------------------------------------------------- pairing

    fn arm(&mut self, code: PairingCode) -> PairingId {
        let id = PairingId(self.fresh_id());
        let nonce = self.rng.nonzero();
        self.enroll.pairing =
            Some(Pairing { id, code, nonce, joiner: None, acceptor: std::collections::BTreeMap::new() });
        id
    }

    fn pairing_free(&self) -> Result<(), Report> {
        if self.enroll.pairing.is_some() || self.enroll.bootstrap.is_some() {
            return Err(Report::new(RuleCode::JOIN_BUSY, format!("{} has a pairing in progress", self.id)));
        }
        Ok(())
    }

    /// The joiner generates a code and starts the exchange on every link (R-JOIN-1).
    pub(crate) fn show_pairing_code(&mut self) -> Result<(PairingId, PairingCode), Report> {
        if self.on_bus {
            return Err(Report::new(RuleCode::JOIN_ON_BUS, format!("{} is on a bus", self.id)));
        }
        self.pairing_free()?;
        let mut secret = [0u8; 16];
        for chunk in secret.chunks_mut(8) {
            chunk.copy_from_slice(&self.rng.next_u64().to_be_bytes());
        }
        let code = PairingCode { secret, device: key_fingerprint(self.id) };
        let id = self.arm(code);
        self.start_runs();
        Ok((id, code))
    }

    /// The joiner sends `PairInit` on every link it has.
    fn start_runs(&mut self) {
        let Some(nonce) = self.enroll.pairing.as_ref().map(|p| p.nonce) else { return };
        let links: Vec<DeviceId> = self.links.iter().copied().collect();
        for l in links {
            self.send(l, Body::PairInit { nonce });
        }
    }

    /// The acceptor takes the code it read from a joiner and answers the joiners that
    /// started before it had one.
    pub(crate) fn enter_pairing_code(&mut self, code: PairingCode) -> Result<PairingId, Report> {
        self.halted_err()?;
        self.pairing_free()?;
        if self.root.is_none() && !self.own_passport().is_some_and(|p| p.rights.accept) {
            return Err(Report::new(RuleCode::JOIN_NO_RIGHT, format!("{} has no accept right", self.id)));
        }
        let id = self.arm(code);
        let waiting: Vec<(DeviceId, u64)> = self.enroll.pair_inits.iter().map(|(d, n)| (*d, *n)).collect();
        self.enroll.pair_inits.clear();
        for (peer, nonce_n) in waiting {
            self.on_pair_init(peer, nonce_n);
        }
        Ok(id)
    }

    pub(crate) fn cancel_pairing(&mut self, id: PairingId) -> Result<(), Report> {
        let Some(p) = self.enroll.pairing.take_if(|p| p.id == id) else {
            return Err(Report::new(RuleCode::API_UNKNOWN_ID, format!("pairing {}", id.0)));
        };
        let peers: Vec<DeviceId> = p.acceptor.keys().copied().chain(p.joiner.map(|r| r.peer)).collect();
        for peer in peers {
            self.send(peer, Body::PairAbort { code: ABORT_DECLINED });
        }
        Ok(())
    }

    /// Ends the pairing with a result.
    fn end_pairing(&mut self, result: Result<Paired, Report>) {
        if let Some(p) = self.enroll.pairing.take() {
            if let Err(r) = &result {
                self.log.push(format!("{} {}", self.id, r.log_line()));
            }
            self.events.push_back(Event::PairingFinished { pairing: p.id, result });
        }
    }

    /// A run failed: the two sides held different secrets, or the other side gave up. Runs
    /// are not counted (R-JOIN-3). The joiner keeps its code and starts again; the acceptor
    /// ends the pairing, and its application reads the joiner's code again.
    fn run_failed(&mut self, code: RuleCode) {
        let Some(p) = self.enroll.pairing.as_mut() else { return };
        if self.on_bus {
            self.end_pairing(Err(Report::new(code, "the run with the joiner failed".to_owned())));
        } else {
            p.joiner = None;
            self.note("a pairing run failed; the code stays");
            self.start_runs();
        }
    }

    /// A link came up on a node that is not on a bus.
    pub(super) fn link_up_off_bus(&mut self, peer: DeviceId) {
        if let Some(b) = self.enroll.bootstrap {
            if b.acceptor == peer {
                self.send(peer, Body::Get);
            }
        } else if let Some(p) = &self.enroll.pairing {
            if p.joiner.is_none() {
                let nonce = p.nonce;
                self.send(peer, Body::PairInit { nonce });
            }
        }
    }

    pub(super) fn link_down_pairing(&mut self, peer: DeviceId) {
        self.enroll.pair_inits.remove(&peer);
        if let Some(p) = self.enroll.pairing.as_mut() {
            p.acceptor.remove(&peer);
            if p.joiner.is_some_and(|r| r.peer == peer) {
                self.run_failed(RuleCode::JOIN_STOPPED);
            }
        }
    }

    pub(super) fn on_pair_init(&mut self, from: DeviceId, nonce_n: u64) {
        if !self.on_bus || self.view.halted {
            return;
        }
        let Some(p) = self.enroll.pairing.as_mut() else {
            self.enroll.pair_inits.insert(from, nonce_n);
            return;
        };
        let nonce_a = self.rng.nonzero();
        p.acceptor.insert(from, AcceptorRun { tid: transcript(nonce_n, nonce_a), confirmed: false });
        self.send(from, Body::PairReply { nonce: nonce_a });
    }

    pub(super) fn on_pair_reply(&mut self, from: DeviceId, nonce_a: u64) {
        if self.on_bus {
            return;
        }
        let Some(p) = self.enroll.pairing.as_mut() else { return };
        if p.joiner.is_some() {
            return;
        }
        p.joiner = Some(JoinerRun { peer: from, tid: transcript(p.nonce, nonce_a) });
        let code = p.code;
        self.send(from, Body::PairConfirm { code });
    }

    pub(super) fn on_pair_confirm(&mut self, from: DeviceId, code: PairingCode) {
        let Some(p) = self.enroll.pairing.as_mut() else { return };
        let Some(run) = p.acceptor.get_mut(&from) else { return };
        if p.code.secret == code.secret {
            run.confirmed = true;
            let bus = self.bus;
            self.send(from, Body::PairDone { code, bus });
        } else {
            p.acceptor.remove(&from);
            self.send(from, Body::PairAbort { code: ABORT_WRONG_CODE });
            self.run_failed(RuleCode::JOIN_WRONG_CODE);
        }
    }

    pub(super) fn on_pair_done(&mut self, from: DeviceId, code: PairingCode, bus: [u8; 32]) {
        let Some(p) = self.enroll.pairing.as_ref() else { return };
        let Some(run) = p.joiner.filter(|r| r.peer == from) else { return };
        if p.code.secret != code.secret {
            // The other side did not know the secret: its confirmation fails.
            self.run_failed(RuleCode::JOIN_WRONG_CODE);
            return;
        }
        let id = p.id;
        self.enroll.pairing = None;
        self.bus = bus;
        self.enroll.bootstrap = Some(Bootstrap { pairing: id, acceptor: from });
        let presence = self.enroll.has_presence.then_some(self.id);
        let payload = Payload { key: self.id, presence, name: self.name.clone(), tid: run.tid };
        self.send(from, Body::PairDevice { payload });
        self.send(from, Body::Get);
    }

    pub(super) fn on_pair_abort(&mut self, from: DeviceId, code: u8) {
        let Some(p) = self.enroll.pairing.as_mut() else { return };
        let mine = p.acceptor.remove(&from).is_some() || p.joiner.is_some_and(|r| r.peer == from);
        if mine {
            self.run_failed(if code == ABORT_WRONG_CODE { RuleCode::JOIN_WRONG_CODE } else { RuleCode::JOIN_STOPPED });
        }
    }

    pub(super) fn on_pair_device(&mut self, from: DeviceId, payload: &Payload) {
        let Some(p) = self.enroll.pairing.as_ref() else { return };
        let Some(run) = p.acceptor.get(&from).filter(|r| r.confirmed) else { return };
        // The code names the joiner's device key (R-JOIN-7).
        if p.code.device != key_fingerprint(payload.key) {
            self.send(from, Body::PairAbort { code: ABORT_OTHER_PEER });
            self.end_pairing(Err(Report::new(RuleCode::JOIN_FINGERPRINT, format!("the device key of {from}"))));
            return;
        }
        match Request::from_session(run.tid, self.id, payload) {
            Ok(r) => {
                let paired = Paired::Acceptor { name: r.name.clone() };
                self.end_pairing(Ok(paired));
                self.submit_join(r);
            }
            Err(code) => {
                self.send(from, Body::PairAbort { code: ABORT_DECLINED });
                self.end_pairing(Err(Report::new(code, format!("payload from {from}"))));
            }
        }
    }

    /// The paired joiner receives the checkpoint of its bus: it is on the bus now, and a
    /// member once its passport arrives.
    pub(super) fn on_first_checkpoint(&mut self, from: DeviceId, c: &Checkpoint) {
        let Some(b) = self.enroll.bootstrap.filter(|b| b.acceptor == from) else { return };
        // The joiner takes the root key of the generation from the records the pairing gave
        // it (R-JOIN-2); here the checkpoint names it.
        self.view = View::first(c.key);
        self.view.generation = c.generation;
        self.view.changed = c.generation > 1;
        self.view.checkpoint = Checkpoint::genesis(c.generation, c.key);
        if self.view.on_checkpoint(c).is_err() {
            return;
        }
        self.on_bus = true;
        self.enroll.bootstrap = None;
        self.enroll.announce = true;
        self.refresh_target();
        let bus = self.bus;
        self.events.push_back(Event::PairingFinished { pairing: b.pairing, result: Ok(Paired::Joiner { bus }) });
        let links: Vec<DeviceId> = self.links.iter().copied().collect();
        for l in links {
            self.link_up(l);
        }
        // The passports the checkpoint names.
        self.send(from, Body::Get);
    }

    // ---------------------------------------------------------------- join requests

    /// The acceptor's own request: the Root takes it at once (R-JOIN-9); any other acceptor
    /// keeps it until a link to the Root or to a relay carries it.
    fn submit_join(&mut self, r: Request) {
        if self.root.is_some() {
            self.root_receive(r);
        } else {
            let _evicted = self.enroll.own_joins.hold(r);
            self.flush_joins();
        }
    }

    /// Sends held join requests on: to the Root if it is connected; an acceptor's own
    /// requests also to a connected relay, which holds them for the Root (R-JOIN-8).
    pub(super) fn flush_joins(&mut self) {
        if self.enroll.own_joins.is_empty() && self.enroll.relay_joins.is_empty() {
            return;
        }
        let Some(root) = self.view.checkpoint.root_device else { return };
        if self.links.contains(&root) {
            let all: Vec<Request> =
                self.enroll.relay_joins.drain().into_iter().chain(self.enroll.own_joins.drain()).collect();
            for r in all {
                self.send(root, Body::JoinRequest(r));
            }
            return;
        }
        let relay = self.links.iter().copied().find(|l| self.view.valid(*l).is_some_and(|p| p.rights.relay));
        if let Some(relay) = relay {
            for r in self.enroll.own_joins.drain() {
                self.send(relay, Body::JoinRequest(r));
            }
        }
    }

    pub(super) fn on_join_request(&mut self, r: &Request) {
        if self.root.is_some() {
            let accepts = r.acceptor == self.id || self.view.valid(r.acceptor).is_some_and(|p| p.rights.accept);
            if accepts {
                self.root_receive(r.clone());
            } else {
                self.reject(RuleCode::JOIN_NOT_ACCEPTOR, format!("join request from {}", r.acceptor));
            }
        } else if self.own_passport().is_some_and(|p| p.rights.relay) {
            // A relay makes no decisions about requests: it holds them for the Root.
            if let Some(old) = self.enroll.relay_joins.hold(r.clone()) {
                self.note(&format!("evicted the oldest join request, from {}", old.acceptor));
            }
            self.flush_joins();
        } else {
            self.note("dropped a join request: this device is neither the Root nor a relay");
        }
    }

    /// The Root verifies the joiner's signature and shows the request to the owner
    /// (R-JOIN-4, R-JOIN-5).
    fn root_receive(&mut self, r: Request) {
        match self.enroll.inbox.receive(r.clone()) {
            Ok(true) => {
                let held: BTreeSet<&Request> = self.enroll.inbox.iter().collect();
                self.enroll.join_ids.retain(|_, x| held.contains(&*x));
                let request = JoinRequestId(self.fresh_id());
                self.events.push_back(Event::JoinRequested {
                    request,
                    device: r.key,
                    name: r.name.clone(),
                    acceptor: r.acceptor,
                    presence: r.presence.is_some(),
                });
                self.enroll.join_ids.insert(request, r);
            }
            Ok(false) => {}
            Err(code) => self.reject(code, format!("join request from {}", r.acceptor)),
        }
    }

    fn not_root(&self) -> Result<(), Report> {
        if self.root.is_some() {
            Ok(())
        } else {
            Err(Report::new(RuleCode::API_NOT_ROOT, format!("{} is not the root device", self.id)))
        }
    }

    fn join_request(&self, id: JoinRequestId) -> Result<Request, Report> {
        self.enroll
            .join_ids
            .get(&id)
            .cloned()
            .ok_or_else(|| Report::new(RuleCode::API_UNKNOWN_ID, format!("join request {}", id.0)))
    }

    pub(crate) fn admit(
        &mut self,
        id: JoinRequestId,
        presented: KeyFingerprint,
        rights: Rights,
        permits: Vec<Permit>,
    ) -> Result<HostRequestId, Report> {
        self.halted_err()?;
        self.not_root()?;
        let r = self.join_request(id)?;
        // R-JOIN-7: the root device compares the key in the request with the fingerprint it
        // got from the joiner; the owner compares nothing.
        if presented != key_fingerprint(r.key) {
            return Err(Report::new(
                RuleCode::JOIN_FINGERPRINT,
                format!("join request {} names another device key than the presented fingerprint", id.0),
            ));
        }
        let host = HostRequestId(self.fresh_id());
        let device = r.key;
        self.host.insert(host, HostWait::Admit { join: id, rights, permits });
        let kind = HostRequestKind::SignMembership { device, operation: OwnerOperation::Admit };
        self.events.push_back(Event::HostRequest { id: host, kind });
        Ok(host)
    }

    pub(crate) fn decline_join(&mut self, id: JoinRequestId) -> Result<(), Report> {
        self.not_root()?;
        let r = self.join_request(id)?;
        self.enroll.join_ids.remove(&id);
        self.enroll.inbox.remove(&r);
        self.note(&format!("owner declined the join request of {}", r.key));
        Ok(())
    }

    /// The owner confirmed an admission: the Root issues the passport with the presence key
    /// the joiner signed, and a checkpoint (R-JOIN-5, R-MEM-3).
    pub(super) fn admit_confirmed(&mut self, id: JoinRequestId, rights: Rights, permits: Vec<Permit>) {
        let Some(r) = self.enroll.join_ids.remove(&id) else {
            self.note("the join request was gone before the owner confirmed it");
            return;
        };
        self.enroll.inbox.remove(&r);
        self.root_issue(r.key, rights, r.presence.is_some(), permits);
    }

    /// Pairing state is in RAM (R-CORE-5 does not list it).
    pub(super) fn reboot_enrollment(&mut self) {
        self.enroll.pairing = None;
        self.enroll.pair_inits.clear();
        self.enroll.own_joins.drain();
        self.enroll.relay_joins.drain();
        self.enroll.inbox.drain();
        self.enroll.join_ids.clear();
    }
}
