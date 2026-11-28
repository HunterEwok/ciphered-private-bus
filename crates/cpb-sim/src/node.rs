// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 HunterEwok

//! One simulated node: the engines composed behind the local interface.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use cpb_api::{
    Action, BlobInfo, BlobWriteId, BusState, CallId, CallKey, CallOutcome, Channel, DEFAULT_INITIAL_CREDIT, DeviceId,
    ErrorMode, Event, FetchId, HostAnswer, HostRequestId, HostRequestKind, IncomingId, InvokeOptions, MAX_APP_INFO,
    MAX_APP_TAG, MAX_BLOB_SEGMENTS, MAX_DATA, MAX_INITIAL_CREDIT, MAX_MESSAGE, MAX_NAME, MAX_STREAM_DATA, Member,
    OwnerOperation, Permit, Publication, Readers, Report, ResultCode, Rights, RuleCode, StreamEnd, StreamId,
    StreamMode, StreamRequest,
};

use crate::engine::calls::{CallBody, CmdRights, Commander, Next, SigKey, Target, Verdict};
use crate::engine::channels::{Accepted, Grant, Pub, Reader, Source};
use crate::engine::membership::{Change, Checkpoint, Passport, Root, View};
use crate::engine::streams::{Chunk, Kind, Received, SendError, Side, Table, Taken};
use crate::rng::Rng;

mod enroll;

use crate::engine::enrollment::{Attempts, Buffer, Payload, Request};
use cpb_api::{JoinRequestId, PairingCode};
pub(crate) use enroll::key_fingerprint;
use enroll::{Bootstrap, Pairing};

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
    /// Open streams per node, 0 to 256 (R-STR-6).
    pub max_streams: u16,
    /// Bytes of data per stream chunk.
    pub stream_chunk: u32,
    /// Lossy mode: bytes of stream data the core holds for the application; a chunk that
    /// does not fit is dropped (R-STR-3).
    pub stream_buffer: u32,
    /// The checkpoint bitmap length, 64 to 32768 bits (R-MEM-14).
    pub window: u32,
    /// Pairing runs one short code allows, 1 to 10 (R-JOIN-3).
    pub pairing_attempts: u8,
    /// Join requests a relay holds for the Root, and the Root for the owner, 1 to 256
    /// (R-JOIN-8).
    pub join_buffer: u16,
}

/// The default segment: the 4096-byte segment frame of Section 13.2, less the 38-byte frame
/// header and the 16-byte authentication tag (Appendix B, Section B.7).
pub const DEFAULT_BLOB_SEGMENT: u32 = 4096 - 38 - 16;

/// The default data of a stream chunk: the 4096-byte chunk frame of Section 13.2, less the
/// 46-byte chunk header and the 16-byte authentication tag (Appendix B, Section B.7).
pub const DEFAULT_STREAM_CHUNK: u32 = 4096 - 46 - 16;

/// The default limit of open streams per node (Section 13.2).
pub const DEFAULT_MAX_STREAMS: u16 = 8;

/// The default checkpoint bitmap length, in bits (Section 13.2).
pub const DEFAULT_WINDOW: u32 = 4096;

/// The default number of pairing runs per short code (Section 13.2).
pub const DEFAULT_PAIRING_ATTEMPTS: u8 = 3;

/// The default number of join requests held (Section 13.2).
pub const DEFAULT_JOIN_BUFFER: u16 = 16;

impl Default for Profile {
    fn default() -> Self {
        Self {
            max_depth: 16,
            number_block: 16,
            retained_epochs: 4,
            blob_segment: DEFAULT_BLOB_SEGMENT,
            max_streams: DEFAULT_MAX_STREAMS,
            stream_chunk: DEFAULT_STREAM_CHUNK,
            // What an ordered stream holds under the default initial credit.
            stream_buffer: DEFAULT_INITIAL_CREDIT,
            window: DEFAULT_WINDOW,
            pairing_attempts: DEFAULT_PAIRING_ATTEMPTS,
            join_buffer: DEFAULT_JOIN_BUFFER,
        }
    }
}

/// What travels between nodes. There is no encryption: the simulator is not a security
/// boundary, and every rule is checked on these values directly.
#[derive(Clone, Debug)]
pub(crate) enum Body {
    Hello {
        passport: Option<Passport>,
        epoch: u32,
    },
    Checkpoint(Checkpoint),
    Passport(Passport),
    Get,
    Grant {
        channel: Channel,
        grant: Grant,
    },
    KeyRequest {
        channel: Channel,
    },
    Publication {
        channel: Channel,
        publication: Pub,
    },
    NonceRequest,
    Nonce {
        nonce: u64,
        refusal: Option<u64>,
    },
    StaleEpoch {
        epoch: u32,
        call: u64,
    },
    Call {
        body: CallBody,
        args: Vec<u8>,
        stream: Option<StreamRequest>,
    },
    /// `stream` is the stream number and the target's initial credit (R-CALL-10).
    Reply {
        call: u64,
        code: ResultCode,
        message: String,
        data: Vec<u8>,
        next: u64,
        stream: Option<(u32, u32)>,
    },
    Chunk {
        from_commander: bool,
        sid: u32,
        chunk: Chunk,
    },
    BlobGet {
        channel: Channel,
        number: u64,
        segment: u32,
    },
    BlobSegment {
        channel: Channel,
        number: u64,
        segment: u32,
        data: Vec<u8>,
        last: bool,
    },
    PairInit {
        nonce: u64,
    },
    PairReply {
        nonce: u64,
    },
    /// Stands for the joiner's `CPace` value and confirmation.
    PairConfirm {
        code: PairingCode,
    },
    /// Stands for the acceptor's confirmation and the sealed `PairBus` that follows it.
    PairDone {
        code: PairingCode,
        bus: [u8; 32],
    },
    /// The sealed `PairDevice`.
    PairDevice {
        payload: Payload,
    },
    PairAbort {
        code: u8,
    },
    JoinRequest(Request),
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
            Self::Chunk { .. } => "StreamChunk",
            Self::PairInit { .. } => "PairInit",
            Self::PairReply { .. } => "PairReply",
            Self::PairConfirm { .. } => "PairConfirm",
            Self::PairDone { .. } => "PairDone",
            Self::PairDevice { .. } => "PairDevice",
            Self::PairAbort { .. } => "PairAbort",
            Self::JoinRequest(_) => "JoinRequest",
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
    Admit { join: JoinRequestId, rights: Rights, permits: Vec<Permit> },
    AppData { signature: Vec<u8> },
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

/// What a blob fetch waits for.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum FetchWait {
    /// The segment `next`, asked from the source.
    Segment,
    /// The application, to take the segment event already queued.
    Application,
}

/// A blob fetch in progress: segments `next..end` are still to be delivered.
#[derive(Clone, Copy, Debug)]
struct Fetch {
    source: DeviceId,
    channel: Channel,
    number: u64,
    next: u32,
    end: u32,
    wait: FetchWait,
}

#[derive(Clone, Copy, Debug)]
struct Incoming {
    commander: DeviceId,
    call: u64,
    next: u64,
    stream: Option<StreamRequest>,
}

/// This node's part in a stream.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
enum Role {
    Commander,
    Target,
}

/// An open stream as the application knows it.
#[derive(Clone, Copy, Debug)]
struct Open {
    peer: DeviceId,
    role: Role,
    sid: u32,
    mode: StreamMode,
    /// The link that carries the stream: the peer, or the relay toward it (R-STR-5).
    via: DeviceId,
    /// Bytes delivered as events the application has not taken yet.
    held: u64,
}

/// The enrollment state of a node: its pairing, and the join requests it holds.
#[derive(Debug)]
struct Enrollment {
    /// The device has a user-presence key, which its join request names.
    has_presence: bool,
    /// The node publishes its node info once it is admitted (R-CH-16).
    announce: bool,
    pairing: Option<Pairing>,
    /// The code last entered here and the runs made with it (R-JOIN-3).
    entered: Option<(PairingCode, Attempts)>,
    /// `PairInit` nonces of joiners that started before this node had a code.
    pair_inits: BTreeMap<DeviceId, u64>,
    bootstrap: Option<Bootstrap>,
    /// Join requests this acceptor made and has not sent on yet.
    own_joins: Buffer,
    /// Join requests this relay holds for the Root (R-JOIN-8).
    relay_joins: Buffer,
    /// On the root device: requests waiting for the owner.
    inbox: Buffer,
    join_ids: BTreeMap<JoinRequestId, Request>,
}

impl Enrollment {
    fn new(profile: Profile) -> Self {
        let buffer = || Buffer::new(usize::from(profile.join_buffer));
        Self {
            has_presence: false,
            announce: false,
            pairing: None,
            entered: None,
            pair_inits: BTreeMap::new(),
            bootstrap: None,
            own_joins: buffer(),
            relay_joins: buffer(),
            inbox: buffer(),
            join_ids: BTreeMap::new(),
        }
    }
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
    fetches: BTreeMap<FetchId, Fetch>,
    /// Stream state by peer and role; the application's handles are in `open`.
    tables: BTreeMap<(DeviceId, Role), Table>,
    open: BTreeMap<StreamId, Open>,
    /// False until a pairing gives the node its bus and the first checkpoint.
    pub(crate) on_bus: bool,
    enroll: Enrollment,
}

/// Stands for the root device while the checkpoint names none: no device has this identifier.
const NO_ROOT: DeviceId = DeviceId([0xff; 16]);

fn too_large(n: usize) -> Result<(), Report> {
    if n > MAX_DATA {
        Err(Report::new(RuleCode::API_DATA_TOO_LARGE, format!("{n} bytes, limit {MAX_DATA}")))
    } else {
        Ok(())
    }
}

impl Node {
    pub(crate) fn new(id: DeviceId, bus: [u8; 32], view: View, profile: Profile, mode: ErrorMode, seed: u64) -> Self {
        let mut target = Target::new(view.checkpoint.root_device.unwrap_or(NO_ROOT), BTreeMap::new());
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
            tables: BTreeMap::new(),
            open: BTreeMap::new(),
            on_bus: true,
            enroll: Enrollment::new(profile),
        };
        n.refresh_target();
        n
    }

    /// A device that is not on a bus: it has its keys and nothing else. Its view is a
    /// placeholder until pairing gives it the checkpoint of its bus.
    pub(crate) fn unpaired(id: DeviceId, presence: bool, profile: Profile, mode: ErrorMode, seed: u64) -> Self {
        let mut n = Self::new(id, [0u8; 32], View::first(0), profile, mode, seed);
        n.on_bus = false;
        n.enroll.has_presence = presence;
        n
    }

    /// The error of an operation that needs a bus (R-API-2).
    pub(crate) fn needs_bus(&self) -> Result<(), Report> {
        if self.on_bus {
            Ok(())
        } else {
            Err(Report::new(RuleCode::API_NO_BUS, format!("{} is not on a bus", self.id)))
        }
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
            self.fetches.clear();
            // A halted node closes its streams (R-MEM-9).
            self.close_streams(|_| true, Some(StreamEnd::Halted));
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
        let root = self.view.checkpoint.root_device.unwrap_or(NO_ROOT);
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
        let (generation, checkpoint) = self.view.pair();
        self.events.push_back(Event::MembershipChanged { generation, checkpoint });
        self.refresh_target();
        self.refresh_channels();
        let gone: Vec<DeviceId> = self.cmds.keys().filter(|t| self.view.valid(**t).is_none()).copied().collect();
        for t in gone {
            self.fail_target(t, &CallOutcome::Unknown);
        }
        // The revocation of either party closes their streams (R-STR-5).
        let me_valid = self.own_passport().is_some();
        let invalid: BTreeSet<DeviceId> =
            self.open.values().map(|o| o.peer).filter(|p| !me_valid || self.view.valid(*p).is_none()).collect();
        self.close_streams(|o| invalid.contains(&o.peer), Some(StreamEnd::Revoked));
        // A device admitted after pairing publishes its node info with the name it proposed.
        if self.enroll.announce && self.own_passport().is_some_and(|p| p.rights.publish) {
            self.enroll.announce = false;
            if let Err(r) = self.publish_node_info() {
                self.log.push(format!("{} {}", self.id, r.log_line()));
            }
        }
        self.flush_joins();
    }

    /// The Root on this node issues a passport, moving the window first if it must
    /// (R-MEM-14), and the node applies and sends the records.
    pub(crate) fn root_issue(&mut self, device: DeviceId, rights: Rights, presence: bool, permits: Vec<Permit>) {
        let Some(root) = self.root.as_mut() else { return };
        match root.issue(device, rights, presence, permits) {
            Ok(records) => {
                for (p, c) in records {
                    self.root_records(c, Some(p));
                }
            }
            Err(_) => self.reject(RuleCode::MEM_WINDOW_FULL, format!("no room for a passport of {device}")),
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
            Ok(Change::Halted(_)) => {
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
            Ok(Change::Halted(_)) => {
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
            // The retained publications under this key follow the grant (R-CH-11).
            let retained: Vec<Pub> = oc.src.retained.values().filter(|p| p.kid == g.kid).cloned().collect();
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
        let gone: Vec<(FetchId, u64)> = self
            .fetches
            .iter()
            .filter(|(_, f)| f.source == s && f.channel == ch && self.held(s, ch, f.number).is_none())
            .map(|(id, f)| (*id, f.number))
            .collect();
        for (id, n) in gone {
            self.fetches.remove(&id);
            let report = Report::new(RuleCode::BLOB_GONE, format!("publication {n} of {s} on channel {}", ch.0));
            self.log.push(format!("{} {}", self.id, report.log_line()));
            self.events.push_back(Event::BlobFetchFinished { fetch: id, result: Err(report) });
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

    /// Takes the next step of a fetch: an own blob is read from host storage, any other is
    /// asked from its source, one segment at a time.
    fn fetch_step(&mut self, id: FetchId) {
        let Some(f) = self.fetches.get(&id).copied() else { return };
        if f.source == self.id {
            let seg = self.held(f.source, f.channel, f.number).and_then(|p| p.blob).and_then(|info| {
                self.blobs.get(&(f.channel, f.number)).and_then(|b| Self::segment_of(b, info, f.next))
            });
            match seg {
                Some((offset, data, _)) => self.push_segment(id, f.next, offset, data),
                None => self.drop_gone_fetches(f.source, f.channel),
            }
        } else {
            if let Some(f) = self.fetches.get_mut(&id) {
                f.wait = FetchWait::Segment;
            }
            self.send(f.source, Body::BlobGet { channel: f.channel, number: f.number, segment: f.next });
        }
    }

    /// Queues a segment for the application. The next one is asked for when the application
    /// takes this event, so undelivered segments do not pile up (R-CORE-4).
    fn push_segment(&mut self, id: FetchId, segment: u32, offset: u64, data: Vec<u8>) {
        let Some(f) = self.fetches.get_mut(&id) else { return };
        self.events.push_back(Event::BlobSegment { fetch: id, segment, offset, data });
        f.next = segment.saturating_add(1);
        f.wait = FetchWait::Application;
        if f.next >= f.end {
            self.fetches.remove(&id);
            self.events.push_back(Event::BlobFetchFinished { fetch: id, result: Ok(()) });
        }
    }

    fn on_blob_segment(&mut self, from: DeviceId, ch: Channel, n: u64, i: u32, data: &[u8], last: bool) {
        let waiting: Vec<FetchId> = self
            .fetches
            .iter()
            .filter(|(_, f)| {
                f.source == from && f.channel == ch && f.number == n && f.next == i && f.wait == FetchWait::Segment
            })
            .map(|(id, _)| *id)
            .collect();
        if waiting.is_empty() {
            return;
        }
        let Some(info) = self.held(from, ch, n).and_then(|p| p.blob) else {
            self.drop_gone_fetches(from, ch);
            return;
        };
        // The last-segment flag is authenticated (R-CH-15): it must agree with the header.
        if last != (i.saturating_add(1) == info.segments) {
            return;
        }
        let offset = u64::from(i).saturating_mul(u64::from(info.segment_size));
        for id in waiting {
            self.push_segment(id, i, offset, data.to_vec());
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
        let hid = ask.as_ref().map(|_| HostRequestId(self.fresh_id()));
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
            let stream = cur.inv.options.stream;
            self.send(t, Body::Call { body: b, args, stream });
        } else {
            cur.stage = Stage::AwaitNonce;
            self.send(t, Body::NonceRequest);
        }
    }

    fn resend(&mut self, t: DeviceId, body: CallBody) {
        let cur = self.cmds.get(&t).and_then(|c| c.current.as_ref());
        let args = cur.map(|c| c.inv.args.clone()).unwrap_or_default();
        let stream = cur.and_then(|c| c.inv.options.stream);
        self.send(t, Body::Call { body, args, stream });
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

    fn on_reply(&mut self, from: DeviceId, r: ReplyIn) {
        let done = self.cmds.get_mut(&from).is_some_and(|c| c.engine.on_reply(r.call, r.next));
        if !done {
            return;
        }
        let asked = self.cmds.get(&from).and_then(|c| c.current.as_ref()).and_then(|c| c.inv.options.stream);
        // The reply opens the commander's side (R-STR-1); a stale side under the same number
        // is replaced.
        let stream = match (asked, r.stream) {
            (Some(req), Some((sid, credit))) if self.view.valid(from).is_some() => {
                let side = Side::new(r.call, req.mode, u64::from(credit), u64::from(req.credit));
                let stale = self.tables.entry((from, Role::Commander)).or_default().open_as(sid, side);
                if stale.is_some() {
                    self.forget_stream(from, Role::Commander, sid, Some(StreamEnd::Replaced));
                }
                Some(self.remember_stream(from, Role::Commander, sid, req.mode))
            }
            _ => None,
        };
        self.finish(from, CallOutcome::Replied { code: r.code, message: r.message, data: r.data, stream });
    }

    fn on_call(&mut self, m: &Msg, body: &CallBody, args: Vec<u8>, stream: Option<StreamRequest>) {
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
                self.send_reply(m.from, body.id, ResultCode::NO_RIGHT, next);
            }
            Verdict::Consumed { ok: true, next } => {
                if self.handlers.contains(&body.act) {
                    let id = IncomingId(self.fresh_id());
                    self.incoming.insert(id, Incoming { commander: m.from, call: body.id, next, stream });
                    let signed_by = match body.key {
                        SigKey::Device => CallKey::Device,
                        SigKey::Presence => CallKey::Presence,
                        SigKey::Root => CallKey::Root,
                    };
                    self.events.push_back(Event::IncomingCall {
                        id,
                        commander: m.from,
                        action: body.act,
                        signed_by,
                        args,
                        stream,
                    });
                } else {
                    self.send_reply(m.from, body.id, ResultCode::NOT_SERVED, next);
                }
            }
        }
    }

    /// A reply the core gives itself: a bus result code and nothing else.
    fn send_reply(&mut self, to: DeviceId, call: u64, code: ResultCode, next: u64) {
        let body = Body::Reply { call, code, message: String::new(), data: Vec::new(), next, stream: None };
        self.send(to, body);
    }

    // ------------------------------------------------------------------- streams

    /// Open streams plus the calls that asked for one and await their reply: what counts
    /// toward the limit of R-STR-6.
    fn stream_load(&self) -> usize {
        let pending = self
            .cmds
            .values()
            .flat_map(|c| c.queue.iter().chain(c.current.as_ref().map(|cur| &cur.inv)))
            .filter(|i| i.options.stream.is_some())
            .count();
        self.open.len().saturating_add(pending)
    }

    fn stream_room(&self) -> bool {
        self.stream_load() < usize::from(self.profile.max_streams)
    }

    /// The link a stream with `peer` runs over: the direct link, or the first member relay.
    fn via(&self, peer: DeviceId) -> DeviceId {
        if self.links.contains(&peer) {
            return peer;
        }
        let relay = self.links.iter().find(|l| self.view.valid(**l).is_some_and(|p| p.rights.relay));
        relay.copied().unwrap_or(peer)
    }

    fn remember_stream(&mut self, peer: DeviceId, role: Role, sid: u32, mode: StreamMode) -> StreamId {
        let id = StreamId(self.fresh_id());
        let via = self.via(peer);
        self.open.insert(id, Open { peer, role, sid, mode, via, held: 0 });
        id
    }

    fn stream_of(&self, peer: DeviceId, role: Role, sid: u32) -> Option<StreamId> {
        self.open.iter().find(|(_, o)| o.peer == peer && o.role == role && o.sid == sid).map(|(id, _)| *id)
    }

    /// Drops the handle of a stream the engine has closed, and tells the application why.
    fn forget_stream(&mut self, peer: DeviceId, role: Role, sid: u32, reason: Option<StreamEnd>) {
        let Some(id) = self.stream_of(peer, role, sid) else { return };
        self.open.remove(&id);
        if let Some(reason) = reason {
            self.events.push_back(Event::StreamClosed { stream: id, reason });
        }
    }

    /// Closes every stream that matches; without a reason the application is not told.
    fn close_streams(&mut self, which: impl Fn(&Open) -> bool, reason: Option<StreamEnd>) {
        let ids: Vec<(StreamId, Open)> = self.open.iter().filter(|(_, o)| which(o)).map(|(i, o)| (*i, *o)).collect();
        for (id, o) in ids {
            if let Some(t) = self.tables.get_mut(&(o.peer, o.role)) {
                t.streams.remove(&o.sid);
            }
            self.open.remove(&id);
            if let Some(reason) = reason {
                self.events.push_back(Event::StreamClosed { stream: id, reason });
            }
        }
    }

    fn on_chunk(&mut self, from: DeviceId, from_commander: bool, sid: u32, chunk: &Chunk) {
        let role = if from_commander { Role::Target } else { Role::Commander };
        let taken = self.tables.get_mut(&(from, role)).map_or(Taken::Unknown, |t| t.receive(sid, chunk));
        let got = match taken {
            // No such stream: dropped without a state change and without an answer (R-STR-3).
            Taken::Unknown => {
                self.note(&format!("dropped a chunk of an unknown stream {sid} from {from}"));
                return;
            }
            Taken::Stream(got) => got,
        };
        let Some(id) = self.stream_of(from, role, sid) else { return };
        match got {
            Received::Data(data) => {
                let len = u64::try_from(data.len()).unwrap_or(u64::MAX);
                let buffer = u64::from(self.profile.stream_buffer);
                let Some(o) = self.open.get_mut(&id) else { return };
                if o.mode == StreamMode::Lossy && o.held.saturating_add(len) > buffer {
                    // Lossy mode has no credit: the recipient drops the excess (R-STR-3).
                    self.note(&format!("dropped a chunk of lossy stream {sid} from {from}: the buffer is full"));
                    return;
                }
                o.held = o.held.saturating_add(len);
                self.events.push_back(Event::StreamData { stream: id, data });
            }
            Received::Credit(added) => self.events.push_back(Event::StreamCredit { stream: id, added }),
            Received::Dropped => {}
            Received::End => self.forget_stream(from, role, sid, Some(StreamEnd::Ended)),
            Received::OutOfOrder => {
                self.reject(RuleCode::STR_OUT_OF_ORDER, format!("stream {sid} from {from}, chunk {}", chunk.no));
                self.forget_stream(from, role, sid, Some(StreamEnd::OutOfOrder));
            }
            Received::OverCredit => {
                self.reject(RuleCode::STR_OVER_CREDIT, format!("stream {sid} from {from}, chunk {}", chunk.no));
                self.forget_stream(from, role, sid, Some(StreamEnd::OverCredit));
            }
        }
    }

    /// The relay on the stream's path refused a chunk: it does not serve streams (R-STR-7,
    /// `RelayRefusal` code 4). The refusal is an unsigned hint, so nothing changes: the
    /// application is told and decides.
    pub(crate) fn stream_refused(&mut self, peer: DeviceId, from_commander: bool, sid: u32) {
        let role = if from_commander { Role::Commander } else { Role::Target };
        if let Some(stream) = self.stream_of(peer, role, sid) {
            self.events.push_back(Event::StreamRefused { stream });
        }
    }

    fn stream_send(&mut self, id: StreamId, kind: Kind) -> Result<(), Report> {
        self.halted_err()?;
        let unknown = || Report::new(RuleCode::API_UNKNOWN_ID, format!("stream {}", id.0));
        let o = *self.open.get(&id).ok_or_else(unknown)?;
        let end = kind == Kind::End;
        let sent = self.tables.get_mut(&(o.peer, o.role)).ok_or_else(unknown)?.send(o.sid, kind);
        let chunk = sent.map_err(|e| match e {
            None => unknown(),
            Some(SendError::NoCredit) => {
                Report::new(RuleCode::STR_NO_CREDIT, format!("stream {}: the peer granted less", id.0))
            }
            Some(SendError::LossyCredit) => {
                Report::new(RuleCode::API_BAD_STREAM, format!("stream {} is lossy and has no credit", id.0))
            }
            Some(SendError::Exhausted) => {
                Report::new(RuleCode::API_BAD_STREAM, format!("stream {}: the chunk numbers are used up", id.0))
            }
        })?;
        if end {
            self.open.remove(&id);
        }
        self.send(o.peer, Body::Chunk { from_commander: o.role == Role::Commander, sid: o.sid, chunk });
        Ok(())
    }

    pub(crate) fn stream_write(&mut self, id: StreamId, data: &[u8]) -> Result<(), Report> {
        if data.is_empty() {
            return Err(Report::new(RuleCode::API_BAD_STREAM, "a data chunk carries at least one byte"));
        }
        let limit = MAX_STREAM_DATA.min(usize::try_from(self.profile.stream_chunk).unwrap_or(usize::MAX));
        if data.len() > limit {
            return Err(Report::new(RuleCode::API_DATA_TOO_LARGE, format!("{} bytes, limit {limit}", data.len())));
        }
        self.stream_send(id, Kind::Data(data.to_vec()))
    }

    pub(crate) fn stream_grant(&mut self, id: StreamId, bytes: u32) -> Result<(), Report> {
        if bytes == 0 {
            return Err(Report::new(RuleCode::API_BAD_STREAM, "a credit chunk adds at least one byte"));
        }
        self.stream_send(id, Kind::Credit(bytes))
    }

    pub(crate) fn stream_end(&mut self, id: StreamId) -> Result<(), Report> {
        self.stream_send(id, Kind::End)
    }

    // ------------------------------------------------------------------ dispatch

    pub(crate) fn link_up(&mut self, peer: DeviceId) {
        self.links.insert(peer);
        if !self.on_bus {
            self.link_up_off_bus(peer);
            return;
        }
        self.key_requested.retain(|(s, _)| *s != peer);
        let passport = self.own_passport().cloned();
        let epoch = self.target.tepoch;
        self.send(peer, Body::Hello { passport, epoch });
        self.send_records(peer);
        // A segment request lost with the old link is asked again.
        let resume: Vec<FetchId> = self
            .fetches
            .iter()
            .filter(|(_, f)| f.source == peer && f.wait == FetchWait::Segment)
            .map(|(id, _)| *id)
            .collect();
        for id in resume {
            self.fetch_step(id);
        }
    }

    pub(crate) fn link_down(&mut self, peer: DeviceId) {
        self.links.remove(&peer);
        self.link_down_pairing(peer);
        // Link down closes the streams the link carried (R-STR-5).
        self.close_streams(|o| o.via == peer, Some(StreamEnd::LinkDown));
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
        self.flush_joins();
    }

    /// What a node that is not on a bus takes: the pairing messages, and the checkpoint of
    /// its bus once it is paired.
    fn handle_off_bus(&mut self, m: &Msg) {
        match &m.body {
            Body::PairReply { nonce } => self.on_pair_reply(m.from, *nonce),
            Body::PairDone { code, bus } => self.on_pair_done(m.from, *code, *bus),
            Body::PairAbort { code } => self.on_pair_abort(m.from, *code),
            Body::Checkpoint(c) => self.on_first_checkpoint(m.from, c),
            _ => {}
        }
    }

    pub(crate) fn handle(&mut self, m: &Msg) {
        if !self.on_bus {
            self.handle_off_bus(m);
            return;
        }
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
            Body::Call { body, args, stream } => self.on_call(m, body, args.clone(), *stream),
            Body::Reply { call, code, message, data, next, stream } => {
                let r = ReplyIn {
                    call: *call,
                    code: *code,
                    message: message.clone(),
                    data: data.clone(),
                    next: *next,
                    stream: *stream,
                };
                self.on_reply(m.from, r);
            }
            Body::Chunk { from_commander, sid, chunk } => self.on_chunk(m.from, *from_commander, *sid, chunk),
            Body::BlobGet { channel, number, segment } => {
                if self.sender(m).is_some() {
                    self.on_blob_get(m.from, *channel, *number, *segment);
                }
            }
            Body::BlobSegment { channel, number, segment, data, last } => {
                if self.sender(m).is_some() {
                    self.on_blob_segment(m.from, *channel, *number, *segment, data, *last);
                }
            }
            Body::PairInit { nonce } => self.on_pair_init(m.from, *nonce),
            Body::PairConfirm { code } => self.on_pair_confirm(m.from, *code),
            Body::PairDevice { payload } => self.on_pair_device(m.from, payload),
            Body::PairAbort { code } => self.on_pair_abort(m.from, *code),
            // A member does not start a pairing exchange.
            Body::PairReply { .. } | Body::PairDone { .. } => {}
            Body::JoinRequest(r) => {
                if self.sender(m).is_some() {
                    self.on_join_request(r);
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
        // A stream without traffic since the previous such event closes (R-STR-5).
        let keys: Vec<(DeviceId, Role)> = self.tables.keys().copied().collect();
        for (peer, role) in keys {
            let idle = self.tables.get_mut(&(peer, role)).map(Table::reset_period).unwrap_or_default();
            for sid in idle {
                self.forget_stream(peer, role, sid, Some(StreamEnd::Idle));
            }
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
        // The passport cache is volatile; the node's own passport is persisted (R-CORE-5).
        let own = self.own_passport().cloned();
        self.view.reboot();
        if let Some(p) = own {
            let _known = self.view.on_passport(&p);
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
        // Open streams do not survive a reboot (R-CORE-6).
        self.tables.clear();
        self.open.clear();
        // Events the application has not taken were in RAM too.
        self.events.clear();
        self.reboot_enrollment();
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

    pub(crate) fn fetch_blob(
        &mut self,
        s: DeviceId,
        ch: Channel,
        n: u64,
        first: u32,
        count: u32,
    ) -> Result<FetchId, Report> {
        self.halted_err()?;
        let info = self
            .held(s, ch, n)
            .and_then(|p| p.blob)
            .ok_or_else(|| Report::new(RuleCode::API_UNKNOWN_ID, format!("no blob {n} of {s} on channel {}", ch.0)))?;
        let end = first.checked_add(count).filter(|e| count > 0 && *e <= info.segments).ok_or_else(|| {
            Report::new(
                RuleCode::API_BAD_RANGE,
                format!("{count} segments from {first}, the blob has {}", info.segments),
            )
        })?;
        let id = FetchId(self.fresh_id());
        let fetch = Fetch { source: s, channel: ch, number: n, next: first, end, wait: FetchWait::Segment };
        self.fetches.insert(id, fetch);
        self.fetch_step(id);
        Ok(id)
    }

    pub(crate) fn cancel_fetch(&mut self, id: FetchId) -> Result<(), Report> {
        self.fetches
            .remove(&id)
            .ok_or_else(|| Report::new(RuleCode::API_UNKNOWN_ID, format!("blob fetch {}", id.0)))?;
        self.events.retain(|e| !matches!(e, Event::BlobSegment { fetch, .. } if *fetch == id));
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

    /// The application asks for a new key: the same mark as "rotate key epoch", for one
    /// channel (R-CH-5).
    pub(crate) fn rotate_channel_key(&mut self, ch: Channel) -> Result<(), Report> {
        app_channel(ch)?;
        self.halted_err()?;
        if let Some(oc) = self.own.get_mut(&ch) {
            oc.src.epoch();
        }
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
        if options.as_root && self.view.checkpoint.root_device != Some(self.id) {
            return Err(Report::new(RuleCode::API_NOT_ROOT, format!("{} is not the root device", self.id)));
        }
        if let Some(req) = options.stream {
            check_credit(req.mode, req.credit)?;
            if !self.stream_room() {
                return Err(self.too_many_streams());
            }
        }
        let call = CallId(self.fresh_id());
        let cmd = self.cmds.entry(t).or_default();
        cmd.queue.push_back(Invocation { call, action, args: args.to_vec(), options });
        self.pump(t);
        Ok(call)
    }

    fn too_many_streams(&self) -> Report {
        Report::new(
            RuleCode::STR_TOO_MANY,
            format!("{} streams, limit {}", self.stream_load(), self.profile.max_streams),
        )
    }

    fn check_reply(code: ResultCode, message: &str, data: &[u8]) -> Result<(), Report> {
        if !code.allowed_in_reply() {
            return Err(Report::new(RuleCode::API_BUS_RESULT, format!("result code {}", code.0)));
        }
        if message.len() > MAX_MESSAGE {
            return Err(Report::new(
                RuleCode::API_MESSAGE_TOO_LONG,
                format!("{} bytes, limit {MAX_MESSAGE}", message.len()),
            ));
        }
        too_large(data.len())
    }

    fn take_incoming(&mut self, id: IncomingId) -> Result<Incoming, Report> {
        self.incoming.remove(&id).ok_or_else(|| Report::new(RuleCode::API_UNKNOWN_ID, format!("incoming {}", id.0)))
    }

    pub(crate) fn reply(&mut self, id: IncomingId, code: ResultCode, message: &str, data: &[u8]) -> Result<(), Report> {
        Self::check_reply(code, message, data)?;
        let inc = self.take_incoming(id)?;
        let body = Body::Reply {
            call: inc.call,
            code,
            message: message.to_owned(),
            data: data.to_vec(),
            next: inc.next,
            stream: None,
        };
        self.send(inc.commander, body);
        Ok(())
    }

    pub(crate) fn reply_with_stream(
        &mut self,
        id: IncomingId,
        code: ResultCode,
        message: &str,
        data: &[u8],
        credit: u32,
    ) -> Result<StreamId, Report> {
        Self::check_reply(code, message, data)?;
        let unknown = || Report::new(RuleCode::API_UNKNOWN_ID, format!("incoming {}", id.0));
        let req = self
            .incoming
            .get(&id)
            .ok_or_else(unknown)?
            .stream
            .ok_or_else(|| Report::new(RuleCode::API_BAD_STREAM, "the call asked for no stream"))?;
        check_credit(req.mode, credit)?;
        let inc = self.take_incoming(id)?;
        // Opening beyond the limit is refused with a result code; existing streams stay
        // (R-STR-6).
        let room = self.stream_room();
        let side = Side::new(inc.call, req.mode, u64::from(req.credit), u64::from(credit));
        let Some(sid) = self.tables.entry((inc.commander, Role::Target)).or_default().open(side, room) else {
            self.send_reply(inc.commander, inc.call, ResultCode::TOO_MANY_STREAMS, inc.next);
            return Err(self.too_many_streams());
        };
        let stream = self.remember_stream(inc.commander, Role::Target, sid, req.mode);
        let body = Body::Reply {
            call: inc.call,
            code,
            message: message.to_owned(),
            data: data.to_vec(),
            next: inc.next,
            stream: Some((sid, credit)),
        };
        self.send(inc.commander, body);
        Ok(stream)
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
        // Before admission the name is only proposed: it goes into the join request.
        if self.own_passport().is_none() {
            return Ok(());
        }
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
        if self.own_passport().is_none() {
            return Ok(());
        }
        self.publish_node_info()
    }

    fn publish_node_info(&mut self) -> Result<(), Report> {
        let data = encode_node_info(&self.name, &self.app);
        self.publish_inner(Channel::NODE_INFO, &data, None, 1).map(|_| ())
    }

    pub(crate) fn state(&self) -> Option<BusState> {
        self.on_bus.then(|| self.snapshot())
    }

    fn snapshot(&self) -> BusState {
        let members = self
            .view
            .members()
            .map(|p| Member { device: p.device, rights: p.rights, presence: p.presence, permits: p.permits.clone() })
            .collect();
        let retained: usize = self
            .reading
            .values()
            .flat_map(|r| r.retained.values())
            .chain(self.own.values().flat_map(|o| o.src.retained.values()))
            .map(|p| p.data.len())
            .fold(0usize, usize::saturating_add);
        BusState {
            bus: self.bus,
            fingerprint: enroll::bus_fingerprint(&self.bus),
            device: self.id,
            generation: self.view.generation,
            checkpoint: self.view.checkpoint.number,
            root_device: self.view.checkpoint.root_device,
            halted: self.view.halted,
            members,
            links: self.links.iter().copied().collect(),
            memory_used: retained,
        }
    }

    pub(crate) fn poll_event(&mut self) -> Option<Event> {
        let e = self.events.pop_front();
        // The application took stream data: the core no longer holds it.
        if let Some(Event::StreamData { stream, data }) = &e {
            if let Some(o) = self.open.get_mut(stream) {
                o.held = o.held.saturating_sub(u64::try_from(data.len()).unwrap_or(u64::MAX));
            }
        }
        // The application took a segment: the fetch moves on.
        if let Some(Event::BlobSegment { fetch, .. }) = &e {
            if self.fetches.get(fetch).is_some_and(|f| f.wait == FetchWait::Application) {
                self.fetch_step(*fetch);
            }
        }
        e
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
                self.root_issue(device, rights, presence, permits);
            }
            (HostWait::Admit { join, rights, permits }, HostAnswer::Approve) => {
                self.admit_confirmed(join, rights, permits);
            }
            (HostWait::Admit { .. }, HostAnswer::Refuse) => self.note("owner declined the admission"),
            (HostWait::Revoke(device), HostAnswer::Approve) => {
                if let Some(c) = self.root.as_mut().and_then(|r| r.revoke(device).ok()) {
                    self.root_records(c, None);
                }
            }
            (HostWait::AppData { signature }, answer) => {
                let signature = (answer == HostAnswer::Approve).then_some(signature);
                self.events.push_back(Event::AppDataSigned { request: id, signature });
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

    /// The simulator's stand-in for the root signature over application data: a value of the
    /// signed input of R-KEY-12 (bus, root generation, tag, data). Anyone can compute it; the
    /// simulator is not a security boundary.
    fn app_signature(&self, tag: &str, data: &[u8]) -> Vec<u8> {
        let mut input = self.bus.to_vec();
        input.extend_from_slice(&self.view.generation.to_be_bytes());
        input.extend_from_slice(&digest(0, tag.as_bytes()));
        input.extend_from_slice(&digest(0, data));
        digest(u64::from_be_bytes(*b"cpb app\0"), &input).to_vec()
    }

    fn check_tag(tag: &str) -> Result<(), Report> {
        if tag.is_empty() || tag.len() > MAX_APP_TAG {
            return Err(Report::new(RuleCode::API_BAD_TAG, format!("{} bytes, allowed 1..{MAX_APP_TAG}", tag.len())));
        }
        Ok(())
    }

    pub(crate) fn sign_app_data(&mut self, tag: &str, data: &[u8]) -> Result<HostRequestId, Report> {
        Self::check_tag(tag)?;
        self.halted_err()?;
        if self.root.is_none() {
            return Err(Report::new(RuleCode::API_NOT_ROOT, format!("{} is not the root device", self.id)));
        }
        let id = HostRequestId(self.fresh_id());
        self.host.insert(id, HostWait::AppData { signature: self.app_signature(tag, data) });
        let size = u64::try_from(data.len()).unwrap_or(u64::MAX);
        self.events
            .push_back(Event::HostRequest { id, kind: HostRequestKind::SignAppData { tag: tag.to_owned(), size } });
        Ok(id)
    }

    pub(crate) fn verify_app_data(&self, tag: &str, data: &[u8], signature: &[u8]) -> Result<(), Report> {
        Self::check_tag(tag)?;
        self.halted_err()?;
        if self.app_signature(tag, data) == signature {
            Ok(())
        } else {
            Err(Report::new(
                RuleCode::MEM_APP_SIGNATURE,
                format!("tag {tag}, root generation {}", self.view.generation),
            ))
        }
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

/// The initial credit a side names: none in lossy mode, and at most the bound of Section
/// 13.2 in ordered mode (R-STR-3, R-STR-4).
fn check_credit(mode: StreamMode, credit: u32) -> Result<(), Report> {
    match mode {
        StreamMode::Lossy if credit != 0 => Err(Report::new(RuleCode::API_BAD_STREAM, "a lossy stream has no credit")),
        StreamMode::Ordered if credit > MAX_INITIAL_CREDIT => {
            Err(Report::new(RuleCode::API_BAD_STREAM, format!("initial credit {credit}, limit {MAX_INITIAL_CREDIT}")))
        }
        _ => Ok(()),
    }
}

/// A reply as it arrives.
struct ReplyIn {
    call: u64,
    code: ResultCode,
    message: String,
    data: Vec<u8>,
    next: u64,
    stream: Option<(u32, u32)>,
}

fn app_channel(ch: Channel) -> Result<(), Report> {
    if ch.is_application() {
        Ok(())
    } else {
        Err(Report::new(RuleCode::API_RESERVED_CHANNEL, format!("channel {}", ch.0)))
    }
}
