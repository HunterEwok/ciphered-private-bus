// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 HunterEwok

//! Trace equivalence with the Quint models (verification level V3 for the simulator).
//!
//! Each file in `tests/traces` is a trace of the `channels` or `calls` model, converted from
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

use cpb_api::{Action, ActionSet, DeviceId};
use cpb_sim::engine::calls::{CallBody, CmdRights, Commander, SigKey, Target};
use cpb_sim::engine::channels::{Grant, Pub, Reader, Source};

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
}

impl Engine {
    fn project(&self) -> Vec<String> {
        match self {
            Self::Channels(e) => e.project(),
            Self::Calls(e) => e.project(),
        }
    }

    fn step(&mut self, a: &[&str]) {
        match self {
            Self::Channels(e) => e.step(a),
            Self::Calls(e) => e.step(a),
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
    assert!(models.len() == 2, "traces of both models are present: {models:?}");
    assert!(total > 500, "only {total} steps replayed");
}
