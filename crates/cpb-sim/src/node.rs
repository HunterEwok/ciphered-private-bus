// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 HunterEwok

//! One simulated node: the engines composed behind the local interface.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use cpb_api::{
    Action, BlobInfo, BlobWriteId, BusState, CallId, CallOutcome, Channel, DeviceId, ErrorMode, Event, HostAnswer,
    HostRequestId, HostRequestKind, IncomingId, InvokeOptions, MAX_APP_INFO, MAX_BLOB_SEGMENTS, MAX_DATA, MAX_NAME,
    Member, OwnerOperation, Permit, Publication, Readers, Report, ResultCode, Rights, RuleCode,
};

use crate::engine::calls::{CallBody, CmdRights, Commander, Next, SigKey, Target, Verdict};
use crate::engine::channels::{Accepted, Grant, Pub, Reader, Source};
use crate::engine::membership::{Change, Checkpoint, Passport, Root, View};
use crate::rng::Rng;

/// Profile parameters the simulator uses (Section 13.2).
#[derive(Clone, Copy, Debug)]
pub struct Profile {
    /// Highest channel retention depth.
    pub max_depth: u16,
    /// Publication numbers reserved per storage write (R-CH-8).
    pub number_block: u64,
    /// Retained sealing key epochs.
    pub retained_epochs: u32,
    /// Bytes of blob per segment, before encryption.
    pub blob_segment: u32,
}

/// The default segment: the 4096-byte segment frame of Section 13.2, less the 38-byte frame
/// header and the 16-byte authentication tag (Appendix B, Section B.7).
pub const DEFAULT_BLOB_SEGMENT: u32 = 4096 - 38 - 16;

impl Default for Profile {
    fn default() -> Self {
        Self { max_depth: 16, number_block: 16, retained_epochs: 4, blob_segment: DEFAULT_BLOB_SEGMENT }
    }
}

/// What travels between nodes. There is no encryption: the simulator is not a security
/// boundary, and every rule is checked on these values directly.
#[derive(Clone, Debug)]
pub(crate) enum Body {
    Hello { passport: Option<Passport>, epoch: u32 },
    Checkpoint(Checkpoint),
    Passport(Passport),
    Get,
    Grant { channel: Channel, grant: Grant },
    KeyRequest { channel: Channel },
    Publication { channel: Channel, publication: Pub },
    NonceRequest,
    Nonce { nonce: u64, refusal: Option<u64> },
    StaleEpoch { epoch: u32, call: u64 },
    Call { body: CallBody, args: Vec<u8> },
    Reply { call: u64, code: ResultCode, data: Vec<u8>, next: u64 },
    BlobGet { channel: Channel, number: u64, segment: u32 },
    BlobSegment { channel: Channel, number: u64, segment: u32, data: Vec<u8>, last: bool },
}

impl Body {
    /// Objects that carry the sender's pair under the rule of R-MEM-6.
    fn carries_pair(&self) -> bool {
        matches!(self, Self::Hello { .. } | Self::Grant { .. } | Self::Publication { .. } | Self::Call { .. })
    }

    pub(crate) fn kind(&self) -> &'static str {
        match self {
            Self::Hello { .. } => "Hello",
            Self::Checkpoint(_) => "Checkpoint",
            Self::Passport(_) => "Passport",
            Self::Get => "Get",
            Self::Grant { .. } => "Grant",
            Self::KeyRequest { .. } => "KeyRequest",
            Self::Publication { .. } => "Publication",
            Self::NonceRequest => "NonceRequest",
            Self::Nonce { .. } => "Nonce",
            Self::StaleEpoch { .. } => "StaleEpoch",
            Self::Call { .. } => "Call",
            Self::Reply { .. } => "Reply",
            Self::BlobGet { .. } => "BlobGet",
            Self::BlobSegment { .. } => "BlobSegment",
        }
    }
}

/// A message between two devices.
#[derive(Clone, Debug)]
pub(crate) struct Msg {
    pub(crate) from: DeviceId,
    pub(crate) to: DeviceId,
    pub(crate) pair: (u32, u32),
    pub(crate) body: Body,
}

#[derive(Clone, Debug)]
struct OwnChannel {
    src: Source,
    readers: Readers,
}

#[derive(Clone, Debug)]
struct Invocation {
    call: CallId,
    action: Action,
    args: Vec<u8>,
    options: InvokeOptions,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Stage {
    AwaitNonce,
    AwaitHost(HostRequestId),
    Sent,
}

#[derive(Clone, Debug)]
struct Current {
    inv: Invocation,
    stage: Stage,
    key: SigKey,
    confirm: bool,
}

#[derive(Clone, Debug, Default)]
struct CmdState {
    engine: Commander,
    queue: VecDeque<Invocation>,
    current: Option<Current>,
}

/// What a host request is waiting for.
#[derive(Clone, Debug)]
enum HostWait {
    Call(DeviceId),
    Change { device: DeviceId, rights: Rights, presence: bool, permits: Vec<Permit> },
    Revoke(DeviceId),
}

/// A blob being written; in the core it goes to host storage segment by segment.
#[derive(Clone, Debug)]
struct Draft {
    channel: Channel,
    data: Vec<u8>,
    depth: u16,
    bytes: Vec<u8>,
}

#[derive(Clone, Copy, Debug)]
struct Incoming {
    commander: DeviceId,
    call: u64,
    next: u64,
}

/// A simulated node.
#[derive(Debug)]
pub(crate) struct Node {
    pub(crate) id: DeviceId,
    bus: [u8; 32],
    profile: Profile,
    mode: ErrorMode,
    rng: Rng,
    pub(crate) view: View,
    pub(crate) root: Option<Root>,
    own: BTreeMap<Channel, OwnChannel>,
    reading: BTreeMap<(DeviceId, Channel), Reader>,
    subscribed: BTreeSet<(DeviceId, Channel)>,
    key_requested: BTreeSet<(DeviceId, Channel)>,
    target: Target,
    cmds: BTreeMap<DeviceId, CmdState>,
    handlers: BTreeSet<Action>,
    incoming: BTreeMap<IncomingId, Incoming>,
    host: BTreeMap<HostRequestId, HostWait>,
    next_id: u64,
    events: VecDeque<Event>,
    pub(crate) outbox: Vec<Msg>,
    pub(crate) links: BTreeSet<DeviceId>,
    pub(crate) log: Vec<String>,
    halt_reported: bool,
    name: String,
    app: Vec<u8>,
    drafts: BTreeMap<BlobWriteId, Draft>,
    /// Blobs of own retained publications, as host storage holds them.
    blobs: BTreeMap<(Channel, u64), Vec<u8>>,
    /// Blob fetches in progress: the next segment expected.
    fetches: BTreeMap<(DeviceId, Channel, u64), u32>,
}

fn too_large(n: usize) -> Result<(), Report> {
    if n > MAX_DATA {
        Err(Report::new(RuleCode::API_DATA_TOO_LARGE, format!("{n} bytes, limit {MAX_DATA}")))
    } else {
        Ok(())
    }
}

impl Node {
    pub(crate) fn new(id: DeviceId, bus: [u8; 32], view: View, profile: Profile, mode: ErrorMode, seed: u64) -> Self {
        let root_device = view.checkpoint.root_device;
        let mut target = Target::new(root_device, BTreeMap::new());
        target.retained_epochs = profile.retained_epochs;
        let mut n = Self {
            id,
            bus,
            profile,
            mode,
            rng: Rng::new(seed),
            view,
            root: None,
            own: BTreeMap::new(),
            reading: BTreeMap::new(),
            subscribed: BTreeSet::new(),
            key_requested: BTreeSet::new(),
            target,
            cmds: BTreeMap::new(),
            handlers: BTreeSet::new(),
            incoming: BTreeMap::new(),
            host: BTreeMap::new(),
            next_id: 1,
            events: VecDeque::new(),
            outbox: Vec::new(),
            links: BTreeSet::new(),
            log: Vec::new(),
            halt_reported: false,
            name: id.to_string(),
            app: Vec::new(),
            drafts: BTreeMap::new(),
            blobs: BTreeMap::new(),
            fetches: BTreeMap::new(),
        };
        n.refresh_target();
        n
    }

    fn fresh_id(&mut self) -> u64 {
        let v = self.next_id;
        self.next_id = self.next_id.saturating_add(1);
        v
    }

    // ------------------------------------------------------------------ reporting

    /// Logs a rejection in both modes; shows it to the application in debug mode (R-ERR-2).
    fn reject(&mut self, code: RuleCode, detail: String) {
        let r = Report::new(code, detail);
        self.log.push(format!("{} {}", self.id, r.log_line()));
        if self.mode == ErrorMode::Debug {
            self.events.push_back(Event::Rejected(r));
        }
    }

    fn note(&mut self, text: &str) {
        self.log.push(format!("{} {text}", self.id));
    }

    fn halted_err(&self) -> Result<(), Report> {
        if self.view.halted { Err(Report::new(RuleCode::MEM_HALTED, format!("{} is halted", self.id))) } else { Ok(()) }
    }

    fn check_halt(&mut self) {
        if self.view.halted && !self.halt_reported {
            self.halt_reported = true;
            self.events.push_back(Event::Halted);
            for cmd in self.cmds.values_mut() {
                cmd.current = None;
                cmd.queue.clear();
            }
        }
    }

    // -------------------------------------------------------------------- sending

    fn send(&mut self, to: DeviceId, body: Body) {
        let m = Msg { from: self.id, to, pair: self.view.pair(), body };
        self.outbox.push(m);
    }

    fn flood(&mut self, body: &Body, except: Option<DeviceId>) {
        let links: Vec<DeviceId> = self.links.iter().copied().collect();
        for l in links {
            if Some(l) != except {
                self.send(l, body.clone());
            }
        }
    }

    fn send_records(&mut self, to: DeviceId) {
        self.send(to, Body::Checkpoint(self.view.checkpoint.clone()));
        let ps: Vec<Passport> = self.view.members().cloned().collect();
        for p in ps {
            self.send(to, Body::Passport(p));
        }
    }

    // ---------------------------------------------------------------- membership

    fn own_passport(&self) -> Option<&Passport> {
        self.view.valid(self.id)
    }

    fn rights_read(&self) -> bool {
        self.own_passport().is_some_and(|p| p.rights.read)
    }

    /// The commanders of this node as a target (R-CALL-7).
    fn refresh_target(&mut self) {
        let mut named = BTreeMap::new();
        if let Some(me) = self.view.valid(self.id) {
            for permit in &me.permits {
                if let Some(c) = self.view.valid(permit.commander) {
                    named.insert(
                        permit.commander,
                        CmdRights {
                            automatic: permit.automatic,
                            confirmation: permit.confirmation,
                            presence: c.presence,
                        },
                    );
                }
            }
        }
        let root = self.view.checkpoint.root_device;
        self.target.set_commanders(named, root);
    }

    fn eligible(&self, channel: Channel, readers: &Readers) -> BTreeSet<DeviceId> {
        let valid = self.view.readers();
        let mut set: BTreeSet<DeviceId> = if channel == Channel::NODE_INFO {
            valid
        } else {
            match readers {
                Readers::AllMembers => valid,
                Readers::Only(list) => list.iter().filter(|d| valid.contains(d)).copied().collect(),
            }
        };
        set.remove(&self.id);
        set
    }

    /// After a membership change: readers that left lose the key at the next rotation, new
    /// readers get the current key (R-CH-5, R-CH-6).
    fn refresh_channels(&mut self) {
        let channels: Vec<Channel> = self.own.keys().copied().collect();
        for ch in channels {
            let Some(oc) = self.own.get(&ch) else { continue };
            let now = self.eligible(ch, &oc.readers);
            let had: BTreeSet<DeviceId> = oc.src.granted.union(&oc.src.to_grant).copied().collect();
            if had.difference(&now).next().is_some() {
                if let Some(oc) = self.own.get_mut(&ch) {
                    oc.src.remove_reader();
                }
            }
            let fresh: Vec<DeviceId> = now.difference(&had).copied().collect();
            for d in fresh {
                self.grant(ch, d);
            }
        }
    }

    fn membership_changed(&mut self) {
        let (generation, checkpoint) = (self.view.checkpoint.generation, self.view.checkpoint.number);
        self.events.push_back(Event::MembershipChanged { generation, checkpoint });
        self.refresh_target();
        self.refresh_channels();
        let gone: Vec<DeviceId> = self.cmds.keys().filter(|t| self.view.valid(**t).is_none()).copied().collect();
        for t in gone {
            self.fail_target(t, &CallOutcome::Unknown);
        }
    }

    /// Applies a checkpoint and a passport made by this node's Root (R-MEM-3).
    pub(crate) fn root_records(&mut self, c: Checkpoint, p: Option<Passport>) {
        let mut accepted = false;
        if self.view.on_checkpoint(&c) == Ok(Change::Accepted) {
            accepted = true;
            self.flood(&Body::Checkpoint(c), None);
        }
        if let Some(p) = p {
            if self.view.on_passport(&p) == Ok(Change::Accepted) {
                accepted = true;
                self.flood(&Body::Passport(p), None);
            }
        }
        self.check_halt();
        if accepted {
            self.membership_changed();
        }
    }

    fn on_checkpoint(&mut self, from: DeviceId, c: &Checkpoint) {
        match self.view.on_checkpoint(c) {
            Ok(Change::Accepted) => {
                self.flood(&Body::Checkpoint(c.clone()), Some(from));
                let missing = c.valid.iter().any(|n| !self.view.passports.contains_key(n));
                if missing {
                    self.send(from, Body::Get);
                }
                self.membership_changed();
            }
            Ok(Change::Known) | Err(RuleCode::MEM_STALE_CHECKPOINT) => {}
            Ok(Change::Halted) => {
                self.reject(RuleCode::MEM_FORK, format!("two checkpoints numbered {}", c.number));
                self.check_halt();
            }
            Err(code) => self.reject(code, format!("checkpoint {} from {from}", c.number)),
        }
    }

    fn on_passport(&mut self, from: DeviceId, p: &Passport) {
        match self.view.on_passport(p) {
            Ok(Change::Accepted) => {
                self.flood(&Body::Passport(p.clone()), Some(from));
                self.membership_changed();
                self.after_peer_known(p.device);
            }
            Ok(Change::Known) | Err(RuleCode::MEM_STALE_CHECKPOINT) => {}
            Ok(Change::Halted) => {
                self.reject(RuleCode::MEM_FORK, format!("two passports numbered {}", p.number));
                self.check_halt();
            }
            Err(code) => self.reject(code, format!("passport {} from {from}", p.number)),
        }
    }

    /// R-MEM-6: compares the sender's pair with ours. A newer pair drops the message and asks
    /// for the checkpoint; an older one gets ours.
    fn check_pair(&mut self, m: &Msg) -> bool {
        let ours = self.view.pair();
        if m.pair > ours {
            self.send(m.from, Body::Get);
            self.reject(
                RuleCode::MEM_BEHIND,
                format!("{} from {} at checkpoint {:?}, ours {:?}", m.body.kind(), m.from, m.pair, ours),
            );
            return false;
        }
        if m.pair < ours {
            self.send(m.from, Body::Checkpoint(self.view.checkpoint.clone()));
        }
        true
    }

    fn sender(&mut self, m: &Msg) -> Option<Passport> {
        if let Some(p) = self.view.valid(m.from) {
            return Some(p.clone());
        }
        let known = self.view.passports.values().any(|p| p.device == m.from);
        if !known {
            self.send(m.from, Body::Get);
        }
        self.reject(RuleCode::MEM_NOT_MEMBER, format!("{} from {}", m.body.kind(), m.from));
        None
    }

    /// A peer's passport became known: ask for keys it may grant us.
    fn after_peer_known(&mut self, d: DeviceId) {
        let wanted: Vec<Channel> = self.subscribed.iter().filter(|(s, _)| *s == d).map(|(_, c)| *c).collect();
        for ch in wanted {
            self.request_key(d, ch);
        }
    }

    // ------------------------------------------------------------------ channels

    fn grant(&mut self, ch: Channel, d: DeviceId) {
        let Some(oc) = self.own.get_mut(&ch) else { return };
        if let Some(g) = oc.src.grant_to(d) {
            let retained: Vec<Pub> = oc.src.retained.values().cloned().collect();
            self.send(d, Body::Grant { channel: ch, grant: g });
            for p in retained {
                self.send(d, Body::Publication { channel: ch, publication: p });
            }
        }
    }

    fn rotate_and_grant(&mut self, ch: Channel) {
        let kid = self.rng.nonzero();
        let Some(oc) = self.own.get(&ch) else { return };
        let readers = self.eligible(ch, &oc.readers);
        if let Some(oc) = self.own.get_mut(&ch) {
            oc.src.rotate(kid, readers.clone());
        }
        for d in readers {
            self.grant(ch, d);
        }
    }

    fn check_depth(&self, depth: u16) -> Result<(), Report> {
        if depth > self.profile.max_depth {
            return Err(Report::new(
                RuleCode::API_DEPTH_TOO_LARGE,
                format!("depth {depth}, limit {}", self.profile.max_depth),
            ));
        }
        Ok(())
    }

    fn publish_inner(&mut self, ch: Channel, data: &[u8], blob: Option<BlobInfo>, depth: u16) -> Result<u64, Report> {
        self.halted_err()?;
        too_large(data.len())?;
        self.check_depth(depth)?;
        if !self.own_passport().is_some_and(|p| p.rights.publish) && ch != Channel::NODE_INFO {
            return Err(Report::new(RuleCode::PUB_NO_RIGHT, format!("{} has no publish right", self.id)));
        }
        self.own.entry(ch).or_insert_with(|| OwnChannel { src: Source::new(), readers: Readers::AllMembers });
        if self.own.get(&ch).is_some_and(|oc| oc.src.must_rotate_now()) {
            self.rotate_and_grant(ch);
        }
        // Readers still owed the current key get it first (R-CH-5).
        let owed: Vec<DeviceId> =
            self.own.get(&ch).map(|oc| oc.src.to_grant.iter().copied().collect()).unwrap_or_default();
        for d in owed {
            self.grant(ch, d);
        }
        let readers = self.own.get(&ch).map(|oc| self.eligible(ch, &oc.readers)).unwrap_or_default();
        let block = self.profile.number_block;
        let oc = self.own.get_mut(&ch).ok_or_else(|| Report::new(RuleCode::API_RESERVED_CHANNEL, "no channel"))?;
        let p = oc
            .src
            .publish(depth, data.to_vec(), blob, &readers, block)
            .ok_or_else(|| Report::new(RuleCode::STORE_FAILED, format!("channel {} cannot publish now", ch.0)))?;
        let to: Vec<DeviceId> = oc.src.granted.iter().copied().collect();
        let no = p.no;
        for d in to {
            self.send(d, Body::Publication { channel: ch, publication: p.clone() });
        }
        self.prune_blobs(ch);
        Ok(no)
    }

    /// Host storage keeps a blob while its publication is retained (R-CH-15).
    fn prune_blobs(&mut self, ch: Channel) {
        let retained: BTreeSet<u64> =
            self.own.get(&ch).map(|oc| oc.src.retained.keys().copied().collect()).unwrap_or_default();
        self.blobs.retain(|(c, n), _| *c != ch || retained.contains(n));
    }

    fn blob_info(&mut self, blob: &[u8]) -> Option<BlobInfo> {
        let info = self.blob_shape(blob.len())?;
        let key = self.rng.next_u64();
        Some(BlobInfo { hash: digest(key, blob), ..info })
    }

    fn blob_shape(&self, len: usize) -> Option<BlobInfo> {
        let size = u64::try_from(len).ok()?;
        let seg = u64::from(self.profile.blob_segment.max(1));
        let segments = u32::try_from(size.div_ceil(seg)).ok().filter(|n| *n <= MAX_BLOB_SEGMENTS)?;
        Some(BlobInfo { size, segments, segment_size: self.profile.blob_segment.max(1), hash: [0; 32] })
    }

    /// The bytes of segment `i` of a blob held in host storage.
    fn segment_of(blob: &[u8], info: BlobInfo, i: u32) -> Option<(u64, Vec<u8>, bool)> {
        let seg = usize::try_from(info.segment_size).ok()?;
        let start = usize::try_from(i).ok()?.checked_mul(seg)?;
        let end = start.checked_add(seg)?.min(blob.len());
        let bytes = blob.get(start..end)?.to_vec();
        let last = i.checked_add(1)? == info.segments;
        Some((u64::try_from(start).ok()?, bytes, last))
    }

    /// The retained publication `(s, ch, n)` as this node holds it.
    fn held(&self, s: DeviceId, ch: Channel, n: u64) -> Option<&Pub> {
        if s == self.id {
            self.own.get(&ch).and_then(|oc| oc.src.retained.get(&n))
        } else {
            self.reading.get(&(s, ch)).and_then(|r| r.retained.get(&n))
        }
    }

    /// Fetches whose publication left retention end here.
    fn drop_gone_fetches(&mut self, s: DeviceId, ch: Channel) {
        let gone: Vec<u64> = self
            .fetches
            .keys()
            .filter(|(fs, fc, n)| *fs == s && *fc == ch && self.held(s, ch, *n).is_none())
            .map(|(_, _, n)| *n)
            .collect();
        for n in gone {
            self.fetches.remove(&(s, ch, n));
            let report = Report::new(RuleCode::BLOB_GONE, format!("publication {n} of {s} on channel {}", ch.0));
            self.log.push(format!("{} {}", self.id, report.log_line()));
            self.events.push_back(Event::BlobFailed { source: s, channel: ch, number: n, report });
        }
    }

    fn on_blob_get(&mut self, from: DeviceId, ch: Channel, n: u64, i: u32) {
        let Some(info) = self.held(self.id, ch, n).and_then(|p| p.blob) else {
            self.note(&format!("blob {n} on channel {} asked by {from} is not retained", ch.0));
            return;
        };
        let seg = self.blobs.get(&(ch, n)).and_then(|b| Self::segment_of(b, info, i));
        if let Some((_, data, last)) = seg {
            self.send(from, Body::BlobSegment { channel: ch, number: n, segment: i, data, last });
        }
    }

    fn on_blob_segment(&mut self, from: DeviceId, ch: Channel, n: u64, i: u32, data: Vec<u8>, last: bool) {
        if self.fetches.get(&(from, ch, n)) != Some(&i) {
            return;
        }
        let Some(info) = self.held(from, ch, n).and_then(|p| p.blob) else {
            self.drop_gone_fetches(from, ch);
            return;
        };
        let offset = u64::from(i).saturating_mul(u64::from(info.segment_size));
        self.events.push_back(Event::BlobSegment {
            source: from,
            channel: ch,
            number: n,
            segment: i,
            offset,
            data,
            last,
        });
        if last {
            self.fetches.remove(&(from, ch, n));
        } else {
            let next = i.saturating_add(1);
            self.fetches.insert((from, ch, n), next);
            self.send(from, Body::BlobGet { channel: ch, number: n, segment: next });
        }
    }

    fn request_key(&mut self, s: DeviceId, ch: Channel) {
        if s == self.id || self.key_requested.contains(&(s, ch)) {
            return;
        }
        self.key_requested.insert((s, ch));
        self.send(s, Body::KeyRequest { channel: ch });
    }

    fn on_key_request(&mut self, from: DeviceId, ch: Channel) {
        let Some(oc) = self.own.get(&ch) else {
            self.reject(RuleCode::GRANT_NOT_READER, format!("no channel {} for {from}", ch.0));
            return;
        };
        if !self.eligible(ch, &oc.readers).contains(&from) {
            self.reject(RuleCode::GRANT_NOT_READER, format!("{from} on channel {}", ch.0));
            return;
        }
        if oc.src.must_rotate_now() {
            self.rotate_and_grant(ch);
        } else {
            self.grant(ch, from);
        }
    }

    fn on_grant(&mut self, m: &Msg, ch: Channel, g: Grant, source: &Passport) {
        if ch != Channel::NODE_INFO && !source.rights.publish {
            self.reject(RuleCode::PUB_NO_RIGHT, format!("grant from {} on channel {}", m.from, ch.0));
            return;
        }
        let read = self.rights_read();
        let me = self.id;
        let r = self.reading.entry((m.from, ch)).or_default();
        match r.on_grant(me, g, read) {
            Ok(()) => {
                self.key_requested.remove(&(m.from, ch));
            }
            Err(code) => {
                self.reject(code, format!("grant generation {} from {} on channel {}", g.generation, m.from, ch.0));
            }
        }
    }

    fn on_publication(&mut self, m: &Msg, ch: Channel, p: &Pub, source: &Passport) {
        if ch != Channel::NODE_INFO && !source.rights.publish {
            self.reject(RuleCode::PUB_NO_RIGHT, format!("publication from {} on channel {}", m.from, ch.0));
            return;
        }
        let r = self.reading.entry((m.from, ch)).or_default();
        match r.on_pub(p) {
            Ok(acc) => {
                let retained = r.retained.contains_key(&p.no);
                self.deliver(m.from, ch, p, acc, retained);
                self.drop_gone_fetches(m.from, ch);
            }
            Err(RuleCode::PUB_NO_KEY) => {
                self.reject(RuleCode::PUB_NO_KEY, format!("publication {} from {} on channel {}", p.no, m.from, ch.0));
                self.request_key(m.from, ch);
            }
            Err(code) => self.reject(code, format!("publication {} from {} on channel {}", p.no, m.from, ch.0)),
        }
    }

    fn deliver(&mut self, s: DeviceId, ch: Channel, p: &Pub, acc: Accepted, retained: bool) {
        if ch == Channel::NODE_INFO {
            if let Some((name, app)) = decode_node_info(&p.data) {
                self.events.push_back(Event::NodeInfo { device: s, name, app });
            }
            return;
        }
        if !self.subscribed.contains(&(s, ch)) {
            return;
        }
        let publication = Publication { source: s, channel: ch, number: p.no, data: p.data.clone(), blob: p.blob };
        match acc {
            Accepted::New { .. } if p.is_empty() && p.depth > 0 => {
                self.events.push_back(Event::Cleared { source: s, channel: ch });
            }
            Accepted::LateClear => {
                self.events.push_back(Event::Cleared { source: s, channel: ch });
            }
            Accepted::New { .. } => self.events.push_back(Event::Publication(publication)),
            Accepted::Refill if retained => self.events.push_back(Event::Publication(publication)),
            Accepted::Refill => {}
        }
    }

    // --------------------------------------------------------------------- calls

    fn finish(&mut self, t: DeviceId, outcome: CallOutcome) {
        let Some(cmd) = self.cmds.get_mut(&t) else { return };
        if let Some(cur) = cmd.current.take() {
            if let Stage::AwaitHost(h) = cur.stage {
                self.host.remove(&h);
            }
            self.events.push_back(Event::CallFinished { call: cur.inv.call, outcome });
        }
        self.pump(t);
    }

    fn fail_target(&mut self, t: DeviceId, outcome: &CallOutcome) {
        let queued: Vec<CallId> =
            self.cmds.get_mut(&t).map(|c| c.queue.drain(..).map(|i| i.call).collect()).unwrap_or_default();
        if let Some(cmd) = self.cmds.get_mut(&t) {
            cmd.engine.pending = None;
        }
        self.finish(t, outcome.clone());
        for call in queued {
            self.events.push_back(Event::CallFinished { call, outcome: outcome.clone() });
        }
    }

    /// Starts the next queued call to `t` if none is in flight.
    fn pump(&mut self, t: DeviceId) {
        let Some(cmd) = self.cmds.get_mut(&t) else { return };
        if cmd.current.is_some() {
            return;
        }
        let Some(inv) = cmd.queue.pop_front() else { return };
        cmd.current = Some(Current { inv, stage: Stage::AwaitNonce, key: SigKey::Device, confirm: false });
        if cmd.engine.nonce == 0 {
            self.send(t, Body::NonceRequest);
        } else {
            self.prepare(t);
        }
    }

    /// The key and the class come from the target's passport (R-CALL-4); a confirmation
    /// class or the root key needs the host first (R-API-3).
    fn prepare(&mut self, t: DeviceId) {
        let me = self.id;
        let Some(cur) = self.cmds.get(&t).and_then(|c| c.current.clone()) else { return };
        let action = cur.inv.action;
        let (key, confirm, ask) = if cur.inv.options.as_root {
            (SigKey::Root, false, Some(HostRequestKind::SignWithRootKey { target: t, action }))
        } else {
            let permit = self.view.valid(t).and_then(|p| p.permits.iter().find(|q| q.commander == me).copied());
            match permit {
                Some(q) if q.confirmation.contains(action) => {
                    if !self.own_passport().is_some_and(|p| p.presence) {
                        self.finish(
                            t,
                            CallOutcome::NotSent(Report::new(
                                RuleCode::CALL_NO_RIGHT,
                                format!("action {} needs a user-presence key", action.number()),
                            )),
                        );
                        return;
                    }
                    (SigKey::Presence, true, Some(HostRequestKind::SignWithPresenceKey { target: t, action }))
                }
                _ => (SigKey::Device, false, None),
            }
        };
        let hid = ask.map(|_| HostRequestId(self.fresh_id()));
        if let Some(cmd) = self.cmds.get_mut(&t) {
            if let Some(c) = cmd.current.as_mut() {
                c.key = key;
                c.confirm = confirm;
                c.stage = hid.map_or(Stage::Sent, Stage::AwaitHost);
            }
        }
        match (hid, ask) {
            (Some(id), Some(kind)) => {
                self.host.insert(id, HostWait::Call(t));
                self.events.push_back(Event::HostRequest { id, kind });
            }
            _ => self.send_call(t),
        }
    }

    fn send_call(&mut self, t: DeviceId) {
        let me = self.id;
        let Some(cmd) = self.cmds.get_mut(&t) else { return };
        let Some(cur) = cmd.current.as_mut() else { return };
        let body =
            cmd.engine.start(me, cur.inv.call.0, cur.inv.action, cur.confirm, cur.inv.options.idempotent, cur.key);
        if let Some(b) = body {
            cur.stage = Stage::Sent;
            let args = cur.inv.args.clone();
            self.send(t, Body::Call { body: b, args });
        } else {
            cur.stage = Stage::AwaitNonce;
            self.send(t, Body::NonceRequest);
        }
    }

    fn resend(&mut self, t: DeviceId, body: CallBody) {
        let args = self.cmds.get(&t).and_then(|c| c.current.as_ref()).map(|c| c.inv.args.clone()).unwrap_or_default();
        self.send(t, Body::Call { body, args });
    }

    fn on_nonce(&mut self, from: DeviceId, nonce: u64, refusal: Option<u64>) {
        let cmd = self.cmds.entry(from).or_default();
        let sent = cmd.current.as_ref().is_some_and(|c| c.stage == Stage::Sent && Some(c.inv.call.0) == refusal);
        if sent {
            self.reject(RuleCode::CALL_NONCE_MISMATCH, format!("call to {from}"));
            let next = self.cmds.get_mut(&from).map_or(Next::Nothing, |c| c.engine.on_mismatch(nonce));
            match next {
                Next::Retry(b) => self.resend(from, b),
                Next::Unknown => self.finish(from, CallOutcome::Unknown),
                Next::Nothing => {}
            }
            return;
        }
        cmd.engine.learn(nonce);
        let waiting = cmd.current.as_ref().is_some_and(|c| c.stage == Stage::AwaitNonce);
        if waiting {
            self.prepare(from);
        }
    }

    fn on_stale_epoch(&mut self, from: DeviceId, epoch: u32, call: u64) {
        let Some(cmd) = self.cmds.get_mut(&from) else { return };
        let ours = cmd.current.as_ref().is_some_and(|c| c.inv.call.0 == call);
        let next = cmd.engine.on_epoch(epoch);
        if !ours {
            return;
        }
        self.reject(RuleCode::CALL_STALE_EPOCH, format!("call to {from}"));
        match next {
            Next::Retry(b) => self.resend(from, b),
            Next::Unknown => self.finish(from, CallOutcome::Unknown),
            Next::Nothing => {}
        }
    }

    fn on_reply(&mut self, from: DeviceId, call: u64, code: ResultCode, data: Vec<u8>, next: u64) {
        let done = self.cmds.get_mut(&from).is_some_and(|c| c.engine.on_reply(call, next));
        if done {
            self.finish(from, CallOutcome::Replied { code, data });
        }
    }

    fn on_call(&mut self, m: &Msg, body: &CallBody, args: Vec<u8>) {
        if body.cmd != m.from {
            self.reject(RuleCode::CALL_NO_SLOT, format!("call body names {}", body.cmd));
            return;
        }
        match self.target.on_call(body) {
            Verdict::Mismatch(Some(n)) => {
                self.send(m.from, Body::Nonce { nonce: n, refusal: Some(body.id) });
            }
            Verdict::Mismatch(None) => {
                self.reject(RuleCode::CALL_NO_SLOT, format!("call from {}", m.from));
            }
            Verdict::StaleEpoch(e) => {
                self.send(m.from, Body::StaleEpoch { epoch: e, call: body.id });
            }
            Verdict::Consumed { ok: false, next } => {
                self.reject(RuleCode::CALL_NO_RIGHT, format!("action {} from {}", body.act.number(), m.from));
                self.send(m.from, Body::Reply { call: body.id, code: ResultCode::NO_RIGHT, data: Vec::new(), next });
            }
            Verdict::Consumed { ok: true, next } => {
                if self.handlers.contains(&body.act) {
                    let id = IncomingId(self.fresh_id());
                    self.incoming.insert(id, Incoming { commander: m.from, call: body.id, next });
                    self.events.push_back(Event::IncomingCall {
                        id,
                        commander: m.from,
                        action: body.act,
                        confirmed: body.key != SigKey::Device,
                        args,
                    });
                } else {
                    self.send(
                        m.from,
                        Body::Reply { call: body.id, code: ResultCode::NOT_SERVED, data: Vec::new(), next },
                    );
                }
            }
        }
    }

    // ------------------------------------------------------------------ dispatch

    pub(crate) fn link_up(&mut self, peer: DeviceId) {
        self.links.insert(peer);
        self.key_requested.retain(|(s, _)| *s != peer);
        let passport = self.own_passport().cloned();
        let epoch = self.target.tepoch;
        self.send(peer, Body::Hello { passport, epoch });
        self.send_records(peer);
        // A segment request lost with the old link is asked again.
        let resume: Vec<(Channel, u64, u32)> =
            self.fetches.iter().filter(|((s, _, _), _)| *s == peer).map(|((_, c, n), i)| (*c, *n, *i)).collect();
        for (channel, number, segment) in resume {
            self.send(peer, Body::BlobGet { channel, number, segment });
        }
    }

    pub(crate) fn link_down(&mut self, peer: DeviceId) {
        self.links.remove(&peer);
    }

    fn on_hello(&mut self, m: &Msg, passport: Option<&Passport>, epoch: u32) {
        if let Some(p) = passport {
            if self.view.valid(p.device).is_none() {
                self.on_passport(m.from, p);
            }
        }
        if let Some(cmd) = self.cmds.get_mut(&m.from) {
            if cmd.current.is_none() {
                let _ = cmd.engine.on_epoch(epoch);
            }
        }
        // As a holder: the latest grant and the retained publications (R-CH-11).
        let channels: Vec<Channel> = self.own.keys().copied().collect();
        for ch in channels {
            let send = self
                .own
                .get(&ch)
                .is_some_and(|oc| oc.src.granted.contains(&m.from) || self.eligible(ch, &oc.readers).contains(&m.from));
            if send {
                self.grant(ch, m.from);
            }
        }
        self.after_peer_known(m.from);
    }

    pub(crate) fn handle(&mut self, m: &Msg) {
        if self.view.halted && !matches!(m.body, Body::Get) {
            return;
        }
        if m.body.carries_pair() && !self.check_pair(m) {
            return;
        }
        match &m.body {
            Body::Checkpoint(c) => self.on_checkpoint(m.from, c),
            Body::Passport(p) => self.on_passport(m.from, p),
            Body::Get => self.send_records(m.from),
            Body::Hello { passport, epoch } => self.on_hello(m, passport.as_ref(), *epoch),
            Body::Grant { channel, grant } => {
                if let Some(src) = self.sender(m) {
                    self.on_grant(m, *channel, *grant, &src);
                }
            }
            Body::Publication { channel, publication } => {
                if let Some(src) = self.sender(m) {
                    self.on_publication(m, *channel, publication, &src);
                }
            }
            Body::KeyRequest { channel } => {
                if self.sender(m).is_some() {
                    self.on_key_request(m.from, *channel);
                }
            }
            Body::NonceRequest => match self.target.answer(m.from) {
                Some(n) => self.send(m.from, Body::Nonce { nonce: n, refusal: None }),
                None => self.reject(RuleCode::CALL_NO_SLOT, format!("nonce request from {}", m.from)),
            },
            Body::Nonce { nonce, refusal } => self.on_nonce(m.from, *nonce, *refusal),
            Body::StaleEpoch { epoch, call } => self.on_stale_epoch(m.from, *epoch, *call),
            Body::Call { body, args } => self.on_call(m, body, args.clone()),
            Body::Reply { call, code, data, next } => {
                self.on_reply(m.from, *call, *code, data.clone(), *next);
            }
            Body::BlobGet { channel, number, segment } => {
                if self.sender(m).is_some() {
                    self.on_blob_get(m.from, *channel, *number, *segment);
                }
            }
            Body::BlobSegment { channel, number, segment, data, last } => {
                if self.sender(m).is_some() {
                    self.on_blob_segment(m.from, *channel, *number, *segment, data.clone(), *last);
                }
            }
        }
    }

    // ---------------------------------------------------------------- host events

    /// "Reset nonces" (R-CALL-8). The node also forgets the nonces it holds as a commander,
    /// so its next call starts with a nonce request instead of a stale nonce.
    pub(crate) fn reset_nonces(&mut self) {
        self.target.reset();
        for cmd in self.cmds.values_mut() {
            cmd.engine.learn(0);
        }
        self.note("reset nonces");
    }

    /// "Rotate key epoch" (R-CORE-3): the sealing key epoch moves on and every own channel
    /// is marked for rotation (R-CH-5).
    pub(crate) fn rotate_epoch(&mut self) {
        self.target.rotate_epoch();
        for oc in self.own.values_mut() {
            oc.src.epoch();
        }
        self.note("rotate key epoch");
    }

    /// A reboot: RAM is lost, persisted state survives (R-CORE-5, R-CORE-6). Links drop.
    pub(crate) fn reboot(&mut self) {
        self.target.reset();
        let targets: Vec<DeviceId> = self.cmds.keys().copied().collect();
        for t in targets {
            self.fail_target(t, &CallOutcome::Unknown);
        }
        self.cmds.clear();
        for r in self.reading.values_mut() {
            r.reboot();
        }
        for oc in self.own.values_mut() {
            oc.src.reboot(true);
        }
        self.incoming.clear();
        self.host.clear();
        self.key_requested.clear();
        // The retained publications are gone from RAM, so their blobs are no longer served;
        // blobs being written and fetched are lost with the core state.
        self.blobs.clear();
        self.drafts.clear();
        self.fetches.clear();
        self.links.clear();
        self.outbox.clear();
        self.note("reboot");
    }

    // ------------------------------------------------------------- local interface

    pub(crate) fn publish(&mut self, ch: Channel, data: &[u8], depth: u16) -> Result<u64, Report> {
        app_channel(ch)?;
        self.publish_inner(ch, data, None, depth)
    }

    pub(crate) fn begin_blob(&mut self, ch: Channel, data: &[u8], depth: u16) -> Result<BlobWriteId, Report> {
        app_channel(ch)?;
        self.halted_err()?;
        too_large(data.len())?;
        self.check_depth(depth)?;
        if depth == 0 {
            return Err(Report::new(RuleCode::API_BAD_BLOB, "a blob at depth 0 would never be served"));
        }
        let id = BlobWriteId(self.fresh_id());
        self.drafts.insert(id, Draft { channel: ch, data: data.to_vec(), depth, bytes: Vec::new() });
        Ok(id)
    }

    pub(crate) fn write_blob(&mut self, id: BlobWriteId, bytes: &[u8]) -> Result<(), Report> {
        let len = self.drafts.get(&id).map(|d| d.bytes.len().saturating_add(bytes.len()));
        let Some(len) = len else {
            return Err(Report::new(RuleCode::API_UNKNOWN_ID, format!("blob write {}", id.0)));
        };
        if self.blob_shape(len).is_none() {
            return Err(Report::new(RuleCode::API_DATA_TOO_LARGE, format!("{len} bytes exceed the largest blob")));
        }
        if let Some(d) = self.drafts.get_mut(&id) {
            d.bytes.extend_from_slice(bytes);
        }
        Ok(())
    }

    pub(crate) fn finish_blob(&mut self, id: BlobWriteId) -> Result<u64, Report> {
        let d = self
            .drafts
            .remove(&id)
            .ok_or_else(|| Report::new(RuleCode::API_UNKNOWN_ID, format!("blob write {}", id.0)))?;
        if d.bytes.is_empty() {
            return Err(Report::new(RuleCode::API_BAD_BLOB, "the blob is empty"));
        }
        let info = self.blob_info(&d.bytes).ok_or_else(|| Report::new(RuleCode::API_DATA_TOO_LARGE, "blob"))?;
        let no = self.publish_inner(d.channel, &d.data, Some(info), d.depth)?;
        self.blobs.insert((d.channel, no), d.bytes);
        self.prune_blobs(d.channel);
        Ok(no)
    }

    pub(crate) fn abort_blob(&mut self, id: BlobWriteId) -> Result<(), Report> {
        self.drafts
            .remove(&id)
            .map(|_| ())
            .ok_or_else(|| Report::new(RuleCode::API_UNKNOWN_ID, format!("blob write {}", id.0)))
    }

    pub(crate) fn fetch_blob(&mut self, s: DeviceId, ch: Channel, n: u64, first: u32) -> Result<(), Report> {
        self.halted_err()?;
        let unknown = || Report::new(RuleCode::API_UNKNOWN_ID, format!("no blob {n} of {s} on channel {}", ch.0));
        let info = self.held(s, ch, n).and_then(|p| p.blob).ok_or_else(unknown)?;
        if first >= info.segments {
            return Err(unknown());
        }
        if s == self.id {
            // An own blob is in host storage already.
            let blob = self.blobs.get(&(ch, n)).cloned().unwrap_or_default();
            for i in first..info.segments {
                if let Some((offset, data, last)) = Self::segment_of(&blob, info, i) {
                    self.events.push_back(Event::BlobSegment {
                        source: s,
                        channel: ch,
                        number: n,
                        segment: i,
                        offset,
                        data,
                        last,
                    });
                }
            }
            return Ok(());
        }
        self.fetches.insert((s, ch, n), first);
        self.send(s, Body::BlobGet { channel: ch, number: n, segment: first });
        Ok(())
    }

    pub(crate) fn read(&self, s: DeviceId, ch: Channel) -> Vec<Publication> {
        let to_pub = |p: &Pub| Publication { source: s, channel: ch, number: p.no, data: p.data.clone(), blob: p.blob };
        if s == self.id {
            return self.own.get(&ch).map(|oc| oc.src.retained.values().map(to_pub).collect()).unwrap_or_default();
        }
        self.reading.get(&(s, ch)).map(|r| r.retained.values().map(to_pub).collect()).unwrap_or_default()
    }

    pub(crate) fn subscribe(&mut self, s: DeviceId, ch: Channel) -> Result<(), Report> {
        self.halted_err()?;
        self.subscribed.insert((s, ch));
        // What is already retained is delivered at once, as to a late joiner.
        for p in self.read(s, ch) {
            self.events.push_back(Event::Publication(p));
        }
        let has = self.reading.get(&(s, ch)).is_some_and(Reader::has_key);
        if !has {
            self.key_requested.remove(&(s, ch));
            self.request_key(s, ch);
        }
        Ok(())
    }

    pub(crate) fn set_readers(&mut self, ch: Channel, readers: Readers) -> Result<(), Report> {
        app_channel(ch)?;
        self.halted_err()?;
        let oc = self.own.entry(ch).or_insert_with(|| OwnChannel { src: Source::new(), readers: Readers::AllMembers });
        oc.readers = readers;
        self.refresh_channels();
        Ok(())
    }

    pub(crate) fn invoke(
        &mut self,
        t: DeviceId,
        action: Action,
        args: &[u8],
        options: InvokeOptions,
    ) -> Result<CallId, Report> {
        self.halted_err()?;
        too_large(args.len())?;
        if options.as_root && self.view.checkpoint.root_device != self.id {
            return Err(Report::new(RuleCode::API_NOT_ROOT, format!("{} is not the root device", self.id)));
        }
        let call = CallId(self.fresh_id());
        let cmd = self.cmds.entry(t).or_default();
        cmd.queue.push_back(Invocation { call, action, args: args.to_vec(), options });
        self.pump(t);
        Ok(call)
    }

    pub(crate) fn reply(&mut self, id: IncomingId, code: ResultCode, data: &[u8]) -> Result<(), Report> {
        if !code.allowed_in_reply() {
            return Err(Report::new(RuleCode::API_BUS_RESULT, format!("result code {}", code.0)));
        }
        too_large(data.len())?;
        let inc = self
            .incoming
            .remove(&id)
            .ok_or_else(|| Report::new(RuleCode::API_UNKNOWN_ID, format!("incoming {}", id.0)))?;
        self.send(inc.commander, Body::Reply { call: inc.call, code, data: data.to_vec(), next: inc.next });
        Ok(())
    }

    pub(crate) fn register_action(&mut self, a: Action) {
        self.handlers.insert(a);
    }

    pub(crate) fn set_name(&mut self, name: &str) -> Result<(), Report> {
        if name.is_empty() || name.len() > MAX_NAME {
            return Err(Report::new(
                RuleCode::API_NAME_TOO_LONG,
                format!("{} bytes, allowed 1..{MAX_NAME}", name.len()),
            ));
        }
        self.halted_err()?;
        name.clone_into(&mut self.name);
        self.publish_node_info()
    }

    pub(crate) fn set_app_info(&mut self, app: &[u8]) -> Result<(), Report> {
        if app.len() > MAX_APP_INFO {
            return Err(Report::new(
                RuleCode::API_APP_INFO_TOO_LARGE,
                format!("{} bytes, limit {MAX_APP_INFO}", app.len()),
            ));
        }
        self.halted_err()?;
        self.app = app.to_vec();
        self.publish_node_info()
    }

    fn publish_node_info(&mut self) -> Result<(), Report> {
        let data = encode_node_info(&self.name, &self.app);
        self.publish_inner(Channel::NODE_INFO, &data, None, 1).map(|_| ())
    }

    pub(crate) fn state(&self) -> BusState {
        let members = self.view.members().map(|p| Member { device: p.device, rights: p.rights }).collect();
        let retained: usize = self
            .reading
            .values()
            .flat_map(|r| r.retained.values())
            .chain(self.own.values().flat_map(|o| o.src.retained.values()))
            .map(|p| p.data.len())
            .fold(0usize, usize::saturating_add);
        BusState {
            bus: self.bus,
            device: self.id,
            generation: self.view.checkpoint.generation,
            checkpoint: self.view.checkpoint.number,
            root_device: self.view.checkpoint.root_device,
            halted: self.view.halted,
            members,
            links: self.links.iter().copied().collect(),
            memory_used: retained,
        }
    }

    pub(crate) fn poll_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    pub(crate) fn answer_host(&mut self, id: HostRequestId, answer: HostAnswer) -> Result<(), Report> {
        let wait = self
            .host
            .remove(&id)
            .ok_or_else(|| Report::new(RuleCode::API_UNKNOWN_ID, format!("host request {}", id.0)))?;
        match (wait, answer) {
            (HostWait::Call(t), HostAnswer::Approve) => self.send_call(t),
            (HostWait::Call(t), HostAnswer::Refuse) => {
                self.finish(t, CallOutcome::NotSent(Report::new(RuleCode::CALL_NOT_CONFIRMED, format!("call to {t}"))));
            }
            (HostWait::Change { device, rights, presence, permits }, HostAnswer::Approve) => {
                let records = self.root.as_mut().map(|r| r.issue(device, rights, presence, permits));
                if let Some((p, c)) = records {
                    self.root_records(c, Some(p));
                }
            }
            (HostWait::Revoke(device), HostAnswer::Approve) => {
                if let Some(c) = self.root.as_mut().and_then(|r| r.revoke(device)) {
                    self.root_records(c, None);
                }
            }
            (HostWait::Change { device, .. } | HostWait::Revoke(device), HostAnswer::Refuse) => {
                self.note(&format!("owner declined the operation on {device}"));
            }
        }
        Ok(())
    }

    fn owner_request(
        &mut self,
        device: DeviceId,
        operation: OwnerOperation,
        wait: HostWait,
    ) -> Result<HostRequestId, Report> {
        self.halted_err()?;
        let Some(root) = self.root.as_ref() else {
            return Err(Report::new(RuleCode::API_NOT_ROOT, format!("{} is not the root device", self.id)));
        };
        if root.passport_of(device).is_none() {
            return Err(Report::new(RuleCode::API_UNKNOWN_ID, format!("{device} is not a member")));
        }
        let id = HostRequestId(self.fresh_id());
        self.host.insert(id, wait);
        self.events.push_back(Event::HostRequest { id, kind: HostRequestKind::SignMembership { device, operation } });
        Ok(id)
    }

    pub(crate) fn change_member(
        &mut self,
        device: DeviceId,
        rights: Rights,
        presence: bool,
        permits: Vec<Permit>,
    ) -> Result<HostRequestId, Report> {
        let wait = HostWait::Change { device, rights, presence, permits };
        self.owner_request(device, OwnerOperation::Change, wait)
    }

    /// Removes the host request event a harness shortcut has already answered.
    pub(crate) fn drop_host_request(&mut self, id: HostRequestId) {
        self.events.retain(|e| !matches!(e, Event::HostRequest { id: x, .. } if *x == id));
    }

    pub(crate) fn revoke(&mut self, device: DeviceId) -> Result<HostRequestId, Report> {
        self.owner_request(device, OwnerOperation::Revoke, HostWait::Revoke(device))
    }
}

/// The simulator's encoding of the node info: the name length, the name, the application
/// part. The core encodes `NodeInfo` as CBOR (Appendix B, Section B.5); the simulator only
/// needs the two values back.
fn encode_node_info(name: &str, app: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(name.len().saturating_add(app.len()).saturating_add(1));
    v.push(u8::try_from(name.len()).unwrap_or(u8::MAX));
    v.extend_from_slice(name.as_bytes());
    v.extend_from_slice(app);
    v
}

fn decode_node_info(data: &[u8]) -> Option<(String, Vec<u8>)> {
    let (&len, rest) = data.split_first()?;
    let name = rest.get(..usize::from(len))?;
    let app = rest.get(usize::from(len)..)?;
    Some((String::from_utf8_lossy(name).into_owned(), app.to_vec()))
}

/// The simulator's stand-in for SHA-256 of the encrypted blob: it depends on the blob and on
/// a value drawn for this publication, as the real hash depends on the blob key. It is not a
/// cryptographic hash.
fn digest(key: u64, blob: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (lane, chunk) in (0u64..).zip(out.chunks_mut(8)) {
        // FNV-1a, 64 bits, one lane per eight bytes of output.
        let mut h = 0xcbf2_9ce4_8422_2325u64 ^ key ^ lane;
        for b in blob {
            h = (h ^ u64::from(*b)).wrapping_mul(0x0000_0100_0000_01b3);
        }
        chunk.copy_from_slice(&h.to_be_bytes());
    }
    out
}

fn app_channel(ch: Channel) -> Result<(), Report> {
    if ch.is_application() {
        Ok(())
    } else {
        Err(Report::new(RuleCode::API_RESERVED_CHANNEL, format!("channel {}", ch.0)))
    }
}
