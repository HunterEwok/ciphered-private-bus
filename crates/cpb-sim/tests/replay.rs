// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 HunterEwok

//! Trace equivalence with the Quint models (verification level V3 for the simulator).
//!
//! Each file in `tests/traces` is a trace of the `channels`, `calls`, `streams`, `enrollment` or `membership` model, converted from
//! the Informal Trace Format by `tools/sim/itf2trace.py`. The test feeds every action to the
//! model engine and checks, after every step, that the engine's state projected onto the
//! model's variables equals the state the model reached. A mismatch names the file, the step
//! and both states.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "tests"
)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::path::Path;

use cpb_api::{Action, ActionSet, DeviceId, Rights, StreamMode};
use cpb_sim::engine::calls::{CallBody, CmdRights, Commander, SigKey, Target};
use cpb_sim::engine::channels::{Grant, Pub, Reader, Source};
use cpb_sim::engine::enrollment::{Attempts, Buffer, Payload, Request};
use cpb_sim::engine::membership::{Checkpoint, HaltKind, HaltProof, Passport, Root, RootChange, RootKey, View};
use cpb_sim::engine::streams::{Chunk, Kind, Side, Table};

/// Model device names become device identifiers; the order of the names is kept.
fn dev(name: &str) -> DeviceId {
    let mut b = [0u8; 16];
    for (i, c) in name.bytes().enumerate().take(16) {
        b[i] = c;
    }
    DeviceId(b)
}

fn name(d: DeviceId) -> String {
    d.0.iter().take_while(|c| **c != 0).map(|c| char::from(*c)).collect()
}

fn names(s: &BTreeSet<DeviceId>) -> String {
    let mut v: Vec<String> = s.iter().map(|d| name(*d)).collect();
    v.sort();
    v.join(",")
}

fn bit(b: bool) -> u8 {
    u8::from(b)
}

fn consts(line: &str) -> BTreeMap<String, String> {
    line.trim_start_matches("const ")
        .split_whitespace()
        .filter_map(|kv| kv.split_once('='))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn list(v: &str) -> Vec<String> {
    v.split(',').filter(|s| !s.is_empty()).map(str::to_string).collect()
}

// ------------------------------------------------------------------------ channels

struct Channels {
    devices: Vec<String>,
    no_read: BTreeSet<DeviceId>,
    block: u64,
    source: Source,
    readers: BTreeMap<String, Reader>,
    members: BTreeSet<DeviceId>,
}

impl Channels {
    fn new(c: &BTreeMap<String, String>) -> Self {
        let devices = list(&c["devices"]);
        let late: BTreeSet<DeviceId> = list(c.get("late").map_or("", String::as_str)).iter().map(|d| dev(d)).collect();
        Self {
            readers: devices.iter().map(|d| (d.clone(), Reader::default())).collect(),
            members: devices.iter().map(|d| dev(d)).filter(|d| !late.contains(d)).collect(),
            devices,
            no_read: list(&c["no_read"]).iter().map(|d| dev(d)).collect(),
            block: c["block"].parse().unwrap(),
            source: Source::new(),
        }
    }

    fn project(&self) -> Vec<String> {
        let s = &self.source;
        let mut out = vec![format!(
            "= source gen={} kid={} keyok={} granted={} next={} reserved={} rotate={} togrant={}",
            s.generation,
            s.kid,
            bit(s.key_ok),
            names(&s.granted),
            s.next_no,
            s.reserved,
            bit(s.must_rotate),
            names(&s.to_grant)
        )];
        for d in &self.devices {
            let r = &self.readers[d];
            let kept: Vec<String> = r.retained.keys().map(u64::to_string).collect();
            out.push(format!(
                "= reader {d} gen={} kid={} higen={} hino={} floor={} depth={} retained={}",
                r.generation,
                r.kid,
                r.hi_gen,
                r.hi_no,
                r.floor,
                r.depth,
                kept.join(",")
            ));
        }
        out.push(format!("= members {}", names(&self.members)));
        out
    }

    fn step(&mut self, a: &[&str]) {
        let n = |i: usize| -> u64 { a[i].parse().unwrap() };
        let flag = |i: usize| a[i] == "1";
        match a[0] {
            "envRemove" => {
                self.source.remove_reader();
                self.members.remove(&dev(a[1]));
            }
            "envJoin" => {
                self.members.insert(dev(a[1]));
            }
            "sourceRotate" => {
                let readers = self.members.difference(&self.no_read).copied().collect();
                self.source.rotate(n(1), readers);
            }
            "sourceGrant" => {
                let d = dev(a[1]);
                assert!(self.members.contains(&d) && !self.no_read.contains(&d), "grant not enabled");
                assert!(self.source.grant_to(d).is_some(), "grant refused");
            }
            "sourcePublish" => {
                let data = if flag(2) { Vec::new() } else { vec![1] };
                let depth = u16::try_from(n(1)).unwrap();
                let p = self.source.publish(depth, data, None, &self.members, self.block);
                assert!(p.is_some(), "publication refused");
            }
            "sourceEpoch" => self.source.epoch(),
            "sourceReboot" => self.source.reboot(flag(1)),
            "readerGrant" => {
                let d = dev(a[1]);
                let g = Grant { generation: u32::try_from(n(2)).unwrap(), kid: n(3), reader: dev(a[4]) };
                let read = !self.no_read.contains(&d);
                let _ = self.readers.get_mut(a[1]).unwrap().on_grant(d, g, read);
            }
            "readerPub" => {
                let p = Pub {
                    generation: u32::try_from(n(2)).unwrap(),
                    kid: n(3),
                    no: n(4),
                    depth: u16::try_from(n(5)).unwrap(),
                    data: if flag(6) { Vec::new() } else { vec![1] },
                    blob: None,
                };
                let _ = self.readers.get_mut(a[1]).unwrap().on_pub(&p);
            }
            "readerReboot" => self.readers.get_mut(a[1]).unwrap().reboot(),
            other => panic!("unknown channels action {other}"),
        }
    }
}

// --------------------------------------------------------------------------- calls

struct Calls {
    devices: Vec<String>,
    presence: BTreeSet<DeviceId>,
    root: DeviceId,
    rights: BTreeMap<DeviceId, String>,
    target: Target,
    cmds: BTreeMap<String, Commander>,
}

fn act(n: u64) -> Action {
    Action::new(u8::try_from(n).unwrap()).unwrap()
}

fn rights_of(digits: &str, presence: bool) -> CmdRights {
    let mut r = CmdRights { presence, ..CmdRights::default() };
    if digits.contains('1') {
        r.automatic = ActionSet::of(&[act(1)]);
    }
    if digits.contains('2') {
        r.confirmation = ActionSet::of(&[act(2)]);
    }
    r
}

fn key_of(k: &str) -> SigKey {
    match k {
        "device" => SigKey::Device,
        "presence" => SigKey::Presence,
        "root" => SigKey::Root,
        other => panic!("unknown key {other}"),
    }
}

fn key_name(k: SigKey) -> &'static str {
    match k {
        SigKey::Device => "device",
        SigKey::Presence => "presence",
        SigKey::Root => "root",
    }
}

impl Calls {
    fn new(c: &BTreeMap<String, String>, initial: &[String]) -> Self {
        // The initial rights come from the first state of the trace: `named=a:1,b:12`.
        let named_line = initial.iter().find(|l| l.starts_with("= target")).unwrap();
        let named = named_line.split("named=").nth(1).unwrap_or("");
        let presence: BTreeSet<DeviceId> = list(&c["presence"]).iter().map(|d| dev(d)).collect();
        let rights: BTreeMap<DeviceId, String> =
            list(named).iter().filter_map(|e| e.split_once(':')).map(|(d, r)| (dev(d), r.to_string())).collect();
        let root = dev(&c["root"]);
        let mut target =
            Target::new(root, rights.iter().map(|(d, r)| (*d, rights_of(r, presence.contains(d)))).collect());
        target.retained_epochs = c["epochs"].parse().unwrap();
        target.max_nonce = c["max_nonce"].parse().unwrap();
        let devices: Vec<String> = initial
            .iter()
            .filter_map(|l| l.strip_prefix("= cmd "))
            .map(|l| l.split_whitespace().next().unwrap().to_string())
            .collect();
        Self {
            cmds: devices.iter().map(|d| (d.clone(), Commander::default())).collect(),
            devices,
            presence,
            root,
            rights,
            target,
        }
    }

    fn project(&self) -> Vec<String> {
        let t = &self.target;
        let mut slots: Vec<(String, u64)> =
            t.slots.iter().filter(|(_, n)| **n != 0).map(|(d, n)| (name(*d), *n)).collect();
        slots.sort();
        let slots: Vec<String> = slots.iter().map(|(d, n)| format!("{d}:{n}")).collect();
        let mut named: Vec<String> = t.named.keys().map(|d| format!("{}:{}", name(*d), self.rights[d])).collect();
        named.sort();
        let mut out = vec![format!("= target tepoch={} slots={} named={}", t.tepoch, slots.join(","), named.join(","))];
        for d in &self.devices {
            let k = &self.cmds[d];
            let mut line = format!("= cmd {d} nonce={} epoch={} pending=", k.nonce, k.epoch);
            match &k.pending {
                None => line.push('-'),
                Some(p) => {
                    let c = &p.call;
                    let _ = write!(
                        line,
                        "id:{},act:{},idem:{},key:{},nonce:{},epoch:{},te:{},tm:{}",
                        c.id,
                        c.act.number(),
                        bit(c.idem),
                        key_name(c.key),
                        c.nonce,
                        c.epoch,
                        bit(p.tried_epoch),
                        bit(p.tried_mismatch)
                    );
                }
            }
            out.push(line);
        }
        out
    }

    fn step(&mut self, a: &[&str]) {
        let n = |i: usize| -> u64 { a[i].parse().unwrap() };
        match a[0] {
            "targetAnswer" => {
                let _ = self.target.answer(dev(a[1]));
            }
            "cmdLearn" => self.cmds.get_mut(a[1]).unwrap().learn(n(2)),
            "cmdMismatch" => {
                let _ = self.cmds.get_mut(a[1]).unwrap().on_mismatch(n(2));
            }
            "cmdStart" => {
                let x = self.cmds.get_mut(a[1]).unwrap().start(
                    dev(a[1]),
                    n(2),
                    act(n(3)),
                    n(3) == 2,
                    a[4] == "1",
                    key_of(a[5]),
                );
                assert!(x.is_some(), "start refused");
            }
            "cmdEpoch" => {
                let _ = self.cmds.get_mut(a[1]).unwrap().on_epoch(u32::try_from(n(2)).unwrap());
            }
            "cmdReply" => {
                assert!(self.cmds.get_mut(a[1]).unwrap().on_reply(n(2), n(3)), "reply not taken");
            }
            "envChange" => {
                let c = dev(a[1]);
                let mut named = self.target.named.clone();
                if a[2] == "-" {
                    named.remove(&c);
                } else {
                    named.insert(c, rights_of(a[2], self.presence.contains(&c)));
                    self.rights.insert(c, a[2].to_string());
                }
                self.target.set_commanders(named, self.root);
            }
            "targetCall" => {
                let x = CallBody {
                    cmd: dev(a[1]),
                    id: n(2),
                    idem: a[3] == "1",
                    act: act(n(4)),
                    confirm: n(4) == 2,
                    key: key_of(a[5]),
                    nonce: n(6),
                    epoch: u32::try_from(n(7)).unwrap(),
                };
                let _ = self.target.on_call(&x);
            }
            "targetReset" => self.target.reset(),
            "targetRotate" => self.target.rotate_epoch(),
            other => panic!("unknown calls action {other}"),
        }
    }
}

// ---------------------------------------------------------------------------- runner

enum Engine {
    Channels(Channels),
    Calls(Calls),
    Streams(Streams),
    Enrollment(Enrollment),
    Membership(Membership),
}

impl Engine {
    fn project(&self) -> Vec<String> {
        match self {
            Self::Channels(e) => e.project(),
            Self::Calls(e) => e.project(),
            Self::Streams(e) => e.project(),
            Self::Enrollment(e) => e.project(),
            Self::Membership(e) => e.project(),
        }
    }

    fn step(&mut self, a: &[&str]) {
        match self {
            Self::Channels(e) => e.step(a),
            Self::Calls(e) => e.step(a),
            Self::Streams(e) => e.step(a),
            Self::Enrollment(e) => e.step(a),
            Self::Membership(e) => e.step(a),
        }
    }
}

// ------------------------------------------------------------------------- streams

/// One party of the streams model: its streams with the peer and the two flags.
#[derive(Default)]
struct Party {
    table: Table,
    halted: bool,
    revoked: bool,
}

/// The streams model: commander `C` and target `T`. A model unit of data is a chunk of one
/// byte, and a unit of credit is one byte.
struct Streams {
    limit: usize,
    c: Party,
    t: Party,
    pending: BTreeMap<u64, (StreamMode, u64)>,
    done: BTreeSet<u64>,
}

fn mode_of(m: &str) -> StreamMode {
    match m {
        "ordered" => StreamMode::Ordered,
        "lossy" => StreamMode::Lossy,
        other => panic!("unknown mode {other}"),
    }
}

fn mode_name(m: StreamMode) -> &'static str {
    match m {
        StreamMode::Ordered => "ordered",
        StreamMode::Lossy => "lossy",
    }
}

impl Streams {
    fn new(c: &BTreeMap<String, String>) -> Self {
        Self {
            limit: c["max_streams"].parse().unwrap(),
            c: Party::default(),
            t: Party::default(),
            pending: BTreeMap::new(),
            done: BTreeSet::new(),
        }
    }

    fn party(&mut self, p: &str) -> &mut Party {
        match p {
            "C" => &mut self.c,
            "T" => &mut self.t,
            other => panic!("unknown party {other}"),
        }
    }

    fn project(&self) -> Vec<String> {
        let mut out = Vec::new();
        for (name, p) in [("C", &self.c), ("T", &self.t)] {
            let sides: Vec<String> = p
                .table
                .streams
                .iter()
                .map(|(sid, s)| {
                    format!(
                        "{sid}:k={},mode={},next={},high={},sc={},rc={},idle={},got={},granted={},sent={},recvd={}",
                        s.k,
                        mode_name(s.mode),
                        s.next,
                        s.high,
                        s.send_credit,
                        s.recv_credit,
                        bit(s.idle),
                        s.got,
                        s.granted,
                        s.sent,
                        s.recvd
                    )
                })
                .collect();
            out.push(format!(
                "= node {name} halted={} revoked={} streams={}",
                bit(p.halted),
                bit(p.revoked),
                sides.join(";")
            ));
        }
        let pending: Vec<String> =
            self.pending.iter().map(|(k, (m, c))| format!("{k}:{}:{c}", mode_name(*m))).collect();
        out.push(format!("= pending {}", pending.join(",")));
        let done: Vec<String> = self.done.iter().map(u64::to_string).collect();
        out.push(format!("= done {}", done.join(",")));
        out
    }

    fn step(&mut self, a: &[&str]) {
        let n = |i: usize| -> u64 { a[i].parse().unwrap() };
        let sid = |i: usize| -> u32 { a[i].parse().unwrap() };
        match a[0] {
            "commanderCall" => {
                // Whether the commander has room is its own check before it calls; the model's
                // scenarios start calls without it.
                self.pending.insert(n(1), (mode_of(a[2]), n(3)));
            }
            "targetOpen" => {
                assert!(!self.t.halted && !self.t.revoked && !self.done.contains(&n(1)), "open not enabled");
                let room = self.t.table.streams.len() < self.limit;
                let _ = self.t.table.open(Side::new(n(1), mode_of(a[2]), n(3), n(4)), room);
                self.done.insert(n(1));
            }
            "commanderReply" => {
                let (mode, credit) = self.pending.remove(&n(1)).expect("the reply answers a pending call");
                if a[4] == "1" && !self.c.halted && !self.c.revoked {
                    let _ = self.c.table.open_as(sid(2), Side::new(n(1), mode, n(3), credit));
                }
            }
            "sendChunk" => {
                let kind = match a[3] {
                    "data" => Kind::Data(vec![0]),
                    "credit" => Kind::Credit(a[4].parse().unwrap()),
                    "end" => Kind::End,
                    other => panic!("unknown kind {other}"),
                };
                let p = self.party(a[1]);
                assert!(!p.halted, "send not enabled");
                p.table.send(sid(2), kind).expect("the model sent this chunk");
            }
            // A faulty peer sends data without credit: its own side only takes the number.
            "overrun" => {
                let s = self.party(a[1]).table.streams.get_mut(&sid(2)).expect("the stream is open");
                assert!(s.mode == StreamMode::Ordered && s.send_credit == 0, "overrun not enabled");
                s.next += 1;
                s.idle = false;
            }
            "receive" => {
                let from_commander = a[2] == "c2t";
                assert_eq!(from_commander, a[1] == "T", "a party takes only its peer's direction");
                let kind = match a[6] {
                    "data" => Kind::Data(vec![0]),
                    "credit" => Kind::Credit(a[7].parse().unwrap()),
                    "end" => Kind::End,
                    other => panic!("unknown kind {other}"),
                };
                let chunk = Chunk { k: n(4), no: a[5].parse().unwrap(), kind };
                let p = self.party(a[1]);
                assert!(!p.halted, "receive not enabled");
                let _ = p.table.receive(sid(3), &chunk);
            }
            "resetNonces" => {
                let _ = self.party(a[1]).table.reset_period();
            }
            "halt" => {
                let p = self.party(a[1]);
                p.halted = true;
                let _ = p.table.close_all();
            }
            "learnRevoked" => {
                let p = self.party(a[1]);
                p.revoked = true;
                let _ = p.table.close_all();
            }
            "reboot" => {
                let _ = self.party(a[1]).table.close_all();
                if a[1] == "C" {
                    self.pending.clear();
                }
            }
            "linkDown" => {
                let _ = self.c.table.close_all();
                let _ = self.t.table.close_all();
            }
            other => panic!("unknown streams action {other}"),
        }
    }
}

// ---------------------------------------------------------------------- enrollment

/// The enrollment model: the engine counts the attempts, makes the join requests and checks
/// the joiner's signature at the Root; the harness keeps the model's ghost state (the
/// sessions and what was sent in them) and plays the owner, who confirms a request only if
/// its key is the key of the device in front of them (R-JOIN-7).
struct Enrollment {
    presence: BTreeSet<String>,
    tid: u64,
    /// Session transcript to (joiner, acceptor).
    sessions: BTreeMap<u64, (String, String)>,
    current: BTreeMap<String, u64>,
    joiner: BTreeMap<String, Attempts>,
    acceptor: BTreeMap<String, BTreeMap<String, Attempts>>,
    sent: BTreeSet<(Payload, String)>,
    inbox: Buffer,
    passports: BTreeSet<String>,
}

fn pres_name(p: Option<DeviceId>) -> String {
    p.map_or_else(|| "none".to_string(), name)
}

fn pres_of(text: &str) -> Option<DeviceId> {
    (text != "none").then(|| dev(text))
}

fn payload_of(text: &str) -> Payload {
    let f: Vec<&str> = text.split(':').collect();
    Payload { key: dev(f[0]), presence: pres_of(f[1]), name: f[2].to_string(), tid: f[3].parse().unwrap() }
}

fn payload_text(p: &Payload) -> String {
    format!("{}:{}:{}:{}", name(p.key), pres_name(p.presence), p.name, p.tid)
}

fn request_of(text: &str) -> Request {
    let (head, signed) = text.split_once('/').unwrap();
    let f: Vec<&str> = head.split(':').collect();
    Request {
        key: dev(f[0]),
        presence: pres_of(f[1]),
        name: f[2].to_string(),
        tid: f[3].parse().unwrap(),
        signed: payload_of(signed),
        acceptor: dev(f[4]),
    }
}

fn request_text(r: &Request) -> String {
    let head = format!("{}:{}:{}:{}:{}", name(r.key), pres_name(r.presence), r.name, r.tid, name(r.acceptor));
    format!("{head}/{}", payload_text(&r.signed))
}

impl Enrollment {
    fn new(c: &BTreeMap<String, String>) -> Self {
        let limit: u8 = c["limit"].parse().unwrap();
        let joiners = list(&c["joiners"]);
        Self {
            presence: list(&c["presence"]).into_iter().collect(),
            tid: 0,
            sessions: BTreeMap::new(),
            current: joiners.iter().map(|j| (j.clone(), 0)).collect(),
            joiner: joiners.iter().map(|j| (j.clone(), Attempts::new(limit))).collect(),
            acceptor: list(&c["acceptors"])
                .into_iter()
                .map(|a| (a, joiners.iter().map(|j| (j.clone(), Attempts::new(limit))).collect()))
                .collect(),
            sent: BTreeSet::new(),
            inbox: Buffer::new(usize::MAX),
            passports: BTreeSet::new(),
        }
    }

    fn project(&self) -> Vec<String> {
        let mut out = vec![format!("= tid {}", self.tid)];
        for (j, t) in &self.current {
            out.push(format!("= joiner {j} tries={} current={t}", self.joiner[j].used()));
        }
        for (a, m) in &self.acceptor {
            let tries: Vec<String> = m.iter().map(|(j, n)| format!("{j}={}", n.used())).collect();
            out.push(format!("= acceptor {a} {}", tries.join(",")));
        }
        let mut sent: Vec<String> = self.sent.iter().map(|(p, to)| format!("{}>{to}", payload_text(p))).collect();
        sent.sort();
        out.push(format!("= sent {}", sent.join(",")));
        let mut inbox: Vec<String> = self.inbox.iter().map(request_text).collect();
        inbox.sort();
        out.push(format!("= inbox {}", inbox.join(",")));
        let passports: Vec<String> = self.passports.iter().cloned().collect();
        out.push(format!("= passports {}", passports.join(",")));
        out
    }

    fn session(&mut self, joiner: &str, acceptor: &str) {
        self.sessions.insert(self.tid, (joiner.to_string(), acceptor.to_string()));
    }

    fn step(&mut self, a: &[&str]) {
        match a[0] {
            "pairHonest" => {
                assert!(self.joiner.get_mut(a[1]).unwrap().take(), "the joiner's code is spent");
                // The compromised acceptor keeps no count.
                if let Some(m) = self.acceptor.get_mut(a[2]) {
                    assert!(m.get_mut(a[1]).unwrap().take(), "the acceptor's code is spent");
                }
                self.tid += 1;
                self.session(a[1], a[2]);
                self.current.insert(a[1].to_string(), self.tid);
            }
            "advPairJoiner" => {
                assert!(self.joiner.get_mut(a[1]).unwrap().take(), "the joiner's code is spent");
                self.tid += 1;
                if a[2] == "1" {
                    self.session(a[1], "adv");
                    self.current.insert(a[1].to_string(), self.tid);
                }
            }
            "advPairAcceptor" => {
                let counted = self.acceptor.get_mut(a[1]).unwrap().get_mut(a[2]).unwrap().take();
                assert!(counted, "the acceptor's code is spent");
                self.tid += 1;
                if a[3] == "1" {
                    self.session("adv", a[1]);
                }
            }
            "joinerSend" => {
                let tid = self.current[a[1]];
                let to = self.sessions[&tid].1.clone();
                let presence = self.presence.contains(a[1]).then(|| dev(a[1]));
                let p = Payload { key: dev(a[1]), presence, name: a[1].to_string(), tid };
                self.sent.insert((p, to));
            }
            "acceptorRequest" => {
                let r = Request::from_session(a[2].parse().unwrap(), dev(a[1]), &payload_of(a[3]));
                self.inbox.receive(r.expect("the payload is of this session")).expect("the signature covers it");
            }
            "badRequest" => {
                let signed = payload_of(a[5]);
                let r = Request {
                    key: dev(a[1]),
                    presence: pres_of(a[2]),
                    name: a[3].to_string(),
                    tid: a[4].parse().unwrap(),
                    signed,
                    acceptor: dev("c"),
                };
                // The Root drops a request the joiner's signature does not cover.
                let _dropped = self.inbox.receive(r);
            }
            "rootAdmit" => {
                let r = request_of(a[1]);
                assert!(self.inbox.iter().any(|x| *x == r), "the request is in the inbox");
                assert!(r.signature_ok());
                assert_eq!(r.key, dev(a[2]), "the root device checked the fingerprint");
                self.passports.insert(format!("{}:{}:{}", name(r.key), pres_name(r.presence), r.name));
            }
            other => panic!("unknown enrollment action {other}"),
        }
    }
}

// ---------------------------------------------------------------------- membership

/// The nodes and the Root of the membership model. The model names a root key by the
/// generation and the number of the root change record (0 the record the Root of the
/// generation signs with, 1 the other one); the engine takes any distinct numbers.
struct Membership {
    nodes: BTreeMap<String, View>,
    root: Root,
    window: u32,
}

/// The first root key.
const FIRST_KEY: RootKey = 1;
/// The device that holds the root key; the model does not name it.
const ROOT_DEVICE: &str = "root";

/// The root key that the root change record `record` of a generation names.
fn change_key(generation: u32, record: u32) -> RootKey {
    RootKey::from(generation) * 4 + 1 + RootKey::from(record)
}

/// The key that signs the passports and checkpoints of a generation.
fn signer(generation: u32) -> RootKey {
    if generation == 1 { FIRST_KEY } else { change_key(generation, 0) }
}

fn member_rights(bits: &str) -> Rights {
    let r: u8 = bits.parse().unwrap();
    Rights { read: r % 2 == 1, publish: (r / 2) % 2 == 1, relay: false }
}

fn rights_bits(r: Rights) -> u8 {
    bit(r.read) + 2 * bit(r.publish)
}

fn numbers(text: &str) -> BTreeSet<u32> {
    text.split('.').filter(|s| !s.is_empty() && *s != "-").map(|s| s.parse().unwrap()).collect()
}

fn numbers_text(s: &BTreeSet<u32>) -> String {
    s.iter().map(u32::to_string).collect::<Vec<_>>().join(".")
}

/// `generation:number:start:valid:next`.
fn checkpoint_of(text: &str) -> Checkpoint {
    let f: Vec<&str> = text.split(':').collect();
    let generation = f[0].parse().unwrap();
    Checkpoint {
        generation,
        number: f[1].parse().unwrap(),
        start: f[2].parse().unwrap(),
        valid: numbers(f[3]),
        next_free: f[4].parse().unwrap(),
        root_device: Some(dev(ROOT_DEVICE)),
        key: signer(generation),
    }
}

fn checkpoint_text(c: &Checkpoint) -> String {
    format!("{}:{}:{}:{}:{}", c.generation, c.number, c.start, numbers_text(&c.valid), c.next_free)
}

/// `generation:number:device:rights`.
fn passport_of(text: &str) -> Passport {
    let f: Vec<&str> = text.split(':').collect();
    let generation = f[0].parse().unwrap();
    Passport {
        generation,
        number: f[1].parse().unwrap(),
        device: dev(f[2]),
        rights: member_rights(f[3]),
        presence: false,
        permits: Vec::new(),
        key: signer(generation),
    }
}

fn passport_text(p: &Passport) -> String {
    format!("{}:{}:{}:{}", p.generation, p.number, name(p.device), rights_bits(p.rights))
}

impl Membership {
    fn new(c: &BTreeMap<String, String>) -> Self {
        let window = c["window"].parse().unwrap();
        Self {
            nodes: list(&c["devices"]).into_iter().map(|d| (d, View::first(FIRST_KEY))).collect(),
            root: Root::new(1, FIRST_KEY, dev(ROOT_DEVICE), window),
            window,
        }
    }

    fn project(&self) -> Vec<String> {
        let mut out = Vec::new();
        for (d, v) in &self.nodes {
            let record = if v.changed { i64::try_from(v.root_key - change_key(v.generation, 0)).unwrap() } else { -1 };
            let mut pps: Vec<String> = v.passports.values().map(passport_text).collect();
            pps.sort();
            out.push(format!(
                "= node {d} gen={} rc={record} halted={} forever={} cp={} pps={}",
                v.generation,
                bit(v.halted),
                bit(v.forever),
                checkpoint_text(&v.checkpoint),
                pps.join(",")
            ));
        }
        let valid: BTreeSet<u32> = self.root.valid.keys().copied().collect();
        out.push(format!(
            "= root gen={} cp={} next={} valid={}",
            self.root.generation,
            self.root.checkpoint,
            self.root.next_passport,
            numbers_text(&valid)
        ));
        out
    }

    fn step(&mut self, a: &[&str]) {
        match a[0] {
            "rootIssue" => {
                self.root
                    .issue_replacing(dev(a[1]), member_rights(a[2]), false, Vec::new(), &numbers(a[3]))
                    .expect("the model issued within the window");
            }
            "rootRevoke" => {
                self.root.revoke_number(a[1].parse().unwrap()).expect("the model revoked a valid passport");
            }
            "recoveryChange" => {
                let generation = self.root.generation + 1;
                self.root = Root::new(generation, change_key(generation, 0), dev(ROOT_DEVICE), self.window);
            }
            // The second records and the proofs reach the engine when a node receives them;
            // a send changes nothing a node or the Root holds.
            "rootEquivocateCp" | "rootEquivocatePp" | "recoveryEquivocate" | "adversaryProof" | "nodeSend" => {}
            "nodeRecvCp" => {
                let _refused = self.nodes.get_mut(a[1]).unwrap().on_checkpoint(&checkpoint_of(a[2]));
            }
            "nodeRecvPp" => {
                let _refused = self.nodes.get_mut(a[1]).unwrap().on_passport(&passport_of(a[2]));
            }
            "nodeRecvRc" => {
                let (generation, record) = a[2].split_once(':').unwrap();
                let generation = generation.parse().unwrap();
                let change = RootChange { generation, key: change_key(generation, record.parse().unwrap()) };
                let _refused = self.nodes.get_mut(a[1]).unwrap().on_root_change(change);
            }
            "nodeRecvHp" => {
                let f: Vec<&str> = a[2].split(':').collect();
                let generation = f[1].parse().unwrap();
                let kind = match f[0] {
                    "cp" => HaltKind::Checkpoint,
                    "pp" => HaltKind::Passport,
                    "rc" => HaltKind::RootChange,
                    other => panic!("unknown proof kind {other}"),
                };
                let key = if kind == HaltKind::RootChange { 0 } else { signer(generation) };
                let proof = HaltProof { kind, generation, number: f[2].parse().unwrap(), key };
                let _refused = self.nodes.get_mut(a[1]).unwrap().on_halt_proof(proof);
            }
            "nodeReboot" => self.nodes.get_mut(a[1]).unwrap().reboot(),
            // The model took the step, so the engine must allow it.
            "nodeAcceptData" => {
                let f: Vec<&str> = a[2].split(':').collect();
                let pair = (f[2].parse().unwrap(), f[3].parse().unwrap());
                let taken = self.nodes[a[1]].accept_data(dev(f[0]), f[1].parse().unwrap(), pair, f[4] == "1");
                assert!(taken.is_ok(), "{} refuses data {} that the model accepts: {taken:?}", a[1], a[2]);
            }
            "nodeGrant" => {
                let p = passport_of(a[2]);
                let reader = self.nodes[a[1]].may_grant(p.device).map(|q| q.number);
                assert_eq!(reader, Some(p.number), "{} grants to {}", a[1], a[2]);
            }
            other => panic!("unknown membership action {other}"),
        }
    }
}

/// Splits a trace into its header, the initial state, and the steps with their states.
fn replay(path: &Path) -> usize {
    let text = fs::read_to_string(path).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    let model = lines[0].trim_start_matches("model ");
    let c = consts(lines[1]);
    let mut i = 2;
    let block = |i: &mut usize| -> Vec<String> {
        let mut v = Vec::new();
        while *i < lines.len() && lines[*i].starts_with("= ") {
            v.push(lines[*i].to_string());
            *i += 1;
        }
        v
    };
    let initial = block(&mut i);
    let mut engine = match model {
        "channels" => Engine::Channels(Channels::new(&c)),
        "calls" => Engine::Calls(Calls::new(&c, &initial)),
        "streams" => Engine::Streams(Streams::new(&c)),
        "enrollment" => Engine::Enrollment(Enrollment::new(&c)),
        "membership" => Engine::Membership(Membership::new(&c)),
        other => panic!("unknown model {other}"),
    };
    assert_eq!(engine.project(), initial, "{}: initial state", path.display());
    let mut steps = 0;
    while i < lines.len() {
        let action = lines[i];
        i += 1;
        let expected = block(&mut i);
        let words: Vec<&str> = action.split_whitespace().collect();
        engine.step(&words);
        steps += 1;
        assert_eq!(engine.project(), expected, "{}: step {steps} `{action}`", path.display());
    }
    steps
}

#[test]
fn engines_follow_the_model_traces() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/traces");
    let mut files: Vec<_> = fs::read_dir(&dir).unwrap().map(|e| e.unwrap().path()).collect();
    files.sort();
    let mut total = 0;
    let mut models = BTreeSet::new();
    for f in &files {
        total += replay(f);
        models.insert(fs::read_to_string(f).unwrap().lines().next().unwrap().to_string());
    }
    assert!(models.len() == 5, "traces of the five models are present: {models:?}");
    assert!(total > 500, "only {total} steps replayed");
}
