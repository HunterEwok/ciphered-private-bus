// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 HunterEwok

//! The harness: nodes, links, the message queue, faults and host events.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use cpb_api::{
    Action, BlobWriteId, BusState, CallId, Channel, DeviceId, ErrorMode, Event, FetchId, HostAnswer, HostRequestId,
    IncomingId, InvokeOptions, LocalApi, Permit, Publication, Readers, Report, ResultCode, Rights,
};

use crate::engine::membership::{Root, View};
use crate::node::{Msg, Node, Profile};
use crate::rng::Rng;

/// The environment variable that overrides the error mode (R-ERR-3).
pub const ERROR_MODE_VAR: &str = "CPB_ERRORS";

/// Faults the harness injects on every hop.
#[derive(Clone, Copy, Debug, Default)]
pub struct Faults {
    /// Messages lost, per thousand.
    pub loss_permille: u16,
    /// Messages delivered twice, per thousand.
    pub duplicate_permille: u16,
    /// Deliver queued messages in random order instead of first in, first out.
    pub reorder: bool,
}

/// Simulator settings.
#[derive(Clone, Copy, Debug, Default)]
pub struct Config {
    /// The seed; a run is fully determined by it (R-VER-7).
    pub seed: u64,
    /// Profile parameters.
    pub profile: Profile,
    /// Faults.
    pub faults: Faults,
    /// The error mode; `None` follows the build type and `CPB_ERRORS` (R-ERR-3).
    pub mode: Option<ErrorMode>,
}

/// Why a run stopped before the bus went quiet.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct StepLimit(pub usize);

impl std::fmt::Display for StepLimit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "the bus did not go quiet within {} steps", self.0)
    }
}

impl std::error::Error for StepLimit {}

#[derive(Clone, Debug)]
struct Hop {
    from: DeviceId,
    to: DeviceId,
    msg: Msg,
}

fn edge(a: DeviceId, b: DeviceId) -> (DeviceId, DeviceId) {
    if a <= b { (a, b) } else { (b, a) }
}

/// Several bus nodes in one process.
///
/// Owner operations (admit, change, revoke) are methods of the simulator until enrollment
/// arrives in M2. Everything an application does goes through [`Sim::node`] and the
/// [`LocalApi`] trait.
#[derive(Debug)]
pub struct Sim {
    config: Config,
    mode: ErrorMode,
    rng: Rng,
    bus: [u8; 32],
    root_device: DeviceId,
    nodes: BTreeMap<DeviceId, Node>,
    links: BTreeSet<(DeviceId, DeviceId)>,
    asleep: BTreeMap<DeviceId, Vec<DeviceId>>,
    queue: VecDeque<Hop>,
    log: Vec<String>,
    steps: u64,
}

impl Sim {
    /// A bus with one node, its root device.
    #[must_use]
    pub fn new(config: Config, root_device: DeviceId) -> Self {
        let mode = config.mode.unwrap_or_else(|| ErrorMode::resolve(std::env::var(ERROR_MODE_VAR).ok().as_deref()));
        let mut rng = Rng::new(config.seed);
        let mut bus = [0u8; 32];
        for chunk in bus.chunks_mut(8) {
            chunk.copy_from_slice(&rng.next_u64().to_be_bytes());
        }
        let (root, passport, checkpoint) = Root::create(root_device);
        let view = View::new(checkpoint, [passport]);
        let seed = rng.next_u64();
        let mut node = Node::new(root_device, bus, view, config.profile, mode, seed);
        node.root = Some(root);
        let mut nodes = BTreeMap::new();
        nodes.insert(root_device, node);
        Self {
            config,
            mode,
            rng,
            bus,
            root_device,
            nodes,
            links: BTreeSet::new(),
            asleep: BTreeMap::new(),
            queue: VecDeque::new(),
            log: Vec::new(),
            steps: 0,
        }
    }

    /// The error mode in effect.
    #[must_use]
    pub fn error_mode(&self) -> ErrorMode {
        self.mode
    }

    /// The root device.
    #[must_use]
    pub fn root_device(&self) -> DeviceId {
        self.root_device
    }

    /// The log of every node: rejections with their rule codes and host events (R-ERR-2).
    #[must_use]
    pub fn log(&self) -> &[String] {
        &self.log
    }

    /// Steps taken so far.
    #[must_use]
    pub fn steps(&self) -> u64 {
        self.steps
    }

    // ---------------------------------------------------------------- owner

    fn owner_records(&mut self, f: impl FnOnce(&mut Root) -> Option<RootOut>) -> bool {
        let Some(node) = self.nodes.get_mut(&self.root_device) else { return false };
        let Some(root) = node.root.as_mut() else { return false };
        let Some(out) = f(root) else { return false };
        node.root_records(out.0, out.1);
        self.flush();
        true
    }

    /// The owner admits a device: the Root issues its passport and a checkpoint. A device not
    /// yet simulated gets a node that starts with the records it would receive at the end of
    /// enrollment.
    pub fn admit(&mut self, device: DeviceId, rights: Rights, presence: bool, permits: Vec<Permit>) {
        self.owner_records(|r| {
            let (p, c) = r.issue(device, rights, presence, permits);
            Some((c, Some(p)))
        });
        if !self.nodes.contains_key(&device) {
            let Some(root) = self.nodes.get(&self.root_device) else { return };
            let view = View::new(root.view.checkpoint.clone(), root.view.members().cloned());
            let seed = self.rng.next_u64();
            let node = Node::new(device, self.bus, view, self.config.profile, self.mode, seed);
            self.nodes.insert(device, node);
        }
    }

    /// The owner revokes a device and confirms it at once: a shortcut for
    /// [`LocalApi::revoke`] on the root device followed by an approving host answer.
    pub fn revoke(&mut self, device: DeviceId) -> bool {
        let root = self.root_device;
        let Some(mut api) = self.node(root) else { return false };
        match api.revoke(device) {
            Ok(id) => {
                // The request event is consumed here: the shortcut stands for the owner.
                let _ = api.answer_host(id, HostAnswer::Approve);
                if let Some(n) = self.nodes.get_mut(&root) {
                    n.drop_host_request(id);
                }
                true
            }
            Err(_) => false,
        }
    }

    // ---------------------------------------------------------------- links

    /// Connects two devices. Both send hello, their checkpoint and the passports they know.
    pub fn link(&mut self, a: DeviceId, b: DeviceId) {
        if a == b || !self.nodes.contains_key(&a) || !self.nodes.contains_key(&b) {
            return;
        }
        if self.links.insert(edge(a, b)) {
            if let Some(n) = self.nodes.get_mut(&a) {
                n.link_up(b);
            }
            if let Some(n) = self.nodes.get_mut(&b) {
                n.link_up(a);
            }
            self.flush();
        }
    }

    /// Disconnects two devices; messages in flight between them are lost.
    pub fn unlink(&mut self, a: DeviceId, b: DeviceId) {
        if self.links.remove(&edge(a, b)) {
            self.queue.retain(|h| edge(h.from, h.to) != edge(a, b));
            if let Some(n) = self.nodes.get_mut(&a) {
                n.link_down(b);
            }
            if let Some(n) = self.nodes.get_mut(&b) {
                n.link_down(a);
            }
        }
    }

    fn peers(&self, d: DeviceId) -> Vec<DeviceId> {
        self.links
            .iter()
            .filter_map(|(x, y)| {
                if *x == d {
                    Some(*y)
                } else if *y == d {
                    Some(*x)
                } else {
                    None
                }
            })
            .collect()
    }

    /// The device goes to sleep: all its links drop until [`Sim::wake`].
    pub fn sleep(&mut self, d: DeviceId) {
        let peers = self.peers(d);
        for p in &peers {
            self.unlink(d, *p);
        }
        self.asleep.insert(d, peers);
    }

    /// The device wakes up and its links come back.
    pub fn wake(&mut self, d: DeviceId) {
        if let Some(peers) = self.asleep.remove(&d) {
            for p in peers {
                self.link(d, p);
            }
        }
    }

    // ---------------------------------------------------------------- host events

    /// A reboot: the node keeps what it persists and loses the rest; its links drop.
    pub fn reboot(&mut self, d: DeviceId) {
        let peers = self.peers(d);
        for p in peers {
            self.unlink(d, p);
        }
        if let Some(n) = self.nodes.get_mut(&d) {
            n.reboot();
        }
        self.flush();
    }

    /// The host event "reset nonces" (R-CALL-8).
    pub fn reset_nonces(&mut self, d: DeviceId) {
        if let Some(n) = self.nodes.get_mut(&d) {
            n.reset_nonces();
        }
        self.flush();
    }

    /// The host event "rotate key epoch" (R-CORE-3).
    pub fn rotate_epoch(&mut self, d: DeviceId) {
        if let Some(n) = self.nodes.get_mut(&d) {
            n.rotate_epoch();
        }
        self.flush();
    }

    // ---------------------------------------------------------------- running

    fn relays(&self, d: DeviceId) -> Vec<DeviceId> {
        let Some(root) = self.nodes.get(&self.root_device) else { return Vec::new() };
        self.peers(d).into_iter().filter(|r| root.view.valid(*r).is_some_and(|p| p.rights.relay)).collect()
    }

    fn route(&mut self, msg: Msg) {
        let (from, to) = (msg.from, msg.to);
        if self.links.contains(&edge(from, to)) {
            self.queue.push_back(Hop { from, to, msg });
            return;
        }
        let relay = self.relays(from).into_iter().find(|r| self.links.contains(&edge(*r, to)));
        match relay {
            Some(r) => self.queue.push_back(Hop { from, to: r, msg }),
            None => self.log.push(format!("{from} no path to {to} for {}", msg.body.kind())),
        }
    }

    fn flush(&mut self) {
        let ids: Vec<DeviceId> = self.nodes.keys().copied().collect();
        for id in ids {
            let (out, log) = match self.nodes.get_mut(&id) {
                Some(n) => (std::mem::take(&mut n.outbox), std::mem::take(&mut n.log)),
                None => continue,
            };
            self.log.extend(log);
            for m in out {
                self.route(m);
            }
        }
    }

    /// Delivers one message. Returns false when nothing is in flight.
    pub fn step(&mut self) -> bool {
        if self.queue.is_empty() {
            return false;
        }
        let f = self.config.faults;
        let i = if f.reorder { self.rng.below(self.queue.len()) } else { 0 };
        let Some(hop) = self.queue.remove(i) else { return false };
        self.steps = self.steps.saturating_add(1);
        if self.rng.chance(f.loss_permille) {
            self.log.push(format!("{} lost {} to {}", hop.from, hop.msg.body.kind(), hop.to));
            return true;
        }
        if self.rng.chance(f.duplicate_permille) {
            self.queue.push_back(hop.clone());
        }
        if hop.to == hop.msg.to {
            if let Some(n) = self.nodes.get_mut(&hop.to) {
                n.handle(&hop.msg);
            }
        } else if self.links.contains(&edge(hop.to, hop.msg.to)) {
            // A member relay forwards without modification (R-CH-4).
            let (relay, to) = (hop.to, hop.msg.to);
            self.queue.push_back(Hop { from: relay, to, msg: hop.msg });
        } else {
            self.log.push(format!("{} cannot reach {} for {}", hop.to, hop.msg.to, hop.msg.body.kind()));
        }
        self.flush();
        true
    }

    /// Runs until nothing is in flight.
    ///
    /// # Errors
    /// [`StepLimit`] if the bus is still busy after `limit` steps.
    pub fn run(&mut self, limit: usize) -> Result<usize, StepLimit> {
        for n in 0..limit {
            if !self.step() {
                return Ok(n);
            }
        }
        if self.queue.is_empty() { Ok(limit) } else { Err(StepLimit(limit)) }
    }

    /// Runs until quiet with a generous limit.
    ///
    /// # Errors
    /// [`StepLimit`] if the bus does not go quiet.
    pub fn settle(&mut self) -> Result<usize, StepLimit> {
        self.run(1_000_000)
    }

    // ---------------------------------------------------------------- applications

    /// The local interface of a node, if the device is simulated.
    pub fn node(&mut self, d: DeviceId) -> Option<NodeApi<'_>> {
        if self.nodes.contains_key(&d) { Some(NodeApi { sim: self, id: d }) } else { None }
    }

    /// Every pending event of a node.
    pub fn drain_events(&mut self, d: DeviceId) -> Vec<Event> {
        let mut v = Vec::new();
        if let Some(n) = self.nodes.get_mut(&d) {
            while let Some(e) = n.poll_event() {
                v.push(e);
            }
        }
        self.flush();
        v
    }
}

type RootOut = (crate::engine::membership::Checkpoint, Option<crate::engine::membership::Passport>);

/// The local interface of one simulated node.
#[derive(Debug)]
pub struct NodeApi<'a> {
    sim: &'a mut Sim,
    id: DeviceId,
}

impl NodeApi<'_> {
    fn with<T>(&mut self, f: impl FnOnce(&mut Node) -> T) -> Option<T> {
        let out = self.sim.nodes.get_mut(&self.id).map(f);
        self.sim.flush();
        out
    }

    fn gone(&self) -> Report {
        Report::new(cpb_api::RuleCode::API_UNKNOWN_ID, format!("no node {}", self.id))
    }
}

impl LocalApi for NodeApi<'_> {
    fn publish(&mut self, channel: Channel, data: &[u8], depth: u16) -> Result<u64, Report> {
        let e = self.gone();
        self.with(|n| n.publish(channel, data, depth)).unwrap_or(Err(e))
    }

    fn begin_blob(&mut self, channel: Channel, data: &[u8], depth: u16) -> Result<BlobWriteId, Report> {
        let e = self.gone();
        self.with(|n| n.begin_blob(channel, data, depth)).unwrap_or(Err(e))
    }

    fn write_blob(&mut self, id: BlobWriteId, bytes: &[u8]) -> Result<(), Report> {
        let e = self.gone();
        self.with(|n| n.write_blob(id, bytes)).unwrap_or(Err(e))
    }

    fn finish_blob(&mut self, id: BlobWriteId) -> Result<u64, Report> {
        let e = self.gone();
        self.with(|n| n.finish_blob(id)).unwrap_or(Err(e))
    }

    fn abort_blob(&mut self, id: BlobWriteId) -> Result<(), Report> {
        let e = self.gone();
        self.with(|n| n.abort_blob(id)).unwrap_or(Err(e))
    }

    fn fetch_blob(
        &mut self,
        source: DeviceId,
        channel: Channel,
        number: u64,
        first: u32,
        count: u32,
    ) -> Result<FetchId, Report> {
        let e = self.gone();
        self.with(|n| n.fetch_blob(source, channel, number, first, count)).unwrap_or(Err(e))
    }

    fn cancel_fetch(&mut self, fetch: FetchId) -> Result<(), Report> {
        let e = self.gone();
        self.with(|n| n.cancel_fetch(fetch)).unwrap_or(Err(e))
    }

    fn read(&self, source: DeviceId, channel: Channel) -> Vec<Publication> {
        self.sim.nodes.get(&self.id).map(|n| n.read(source, channel)).unwrap_or_default()
    }

    fn subscribe(&mut self, source: DeviceId, channel: Channel) -> Result<(), Report> {
        let e = self.gone();
        self.with(|n| n.subscribe(source, channel)).unwrap_or(Err(e))
    }

    fn set_readers(&mut self, channel: Channel, readers: Readers) -> Result<(), Report> {
        let e = self.gone();
        self.with(|n| n.set_readers(channel, readers)).unwrap_or(Err(e))
    }

    fn invoke(
        &mut self,
        target: DeviceId,
        action: Action,
        args: &[u8],
        options: InvokeOptions,
    ) -> Result<CallId, Report> {
        let e = self.gone();
        self.with(|n| n.invoke(target, action, args, options)).unwrap_or(Err(e))
    }

    fn reply(&mut self, call: IncomingId, code: ResultCode, data: &[u8]) -> Result<(), Report> {
        let e = self.gone();
        self.with(|n| n.reply(call, code, data)).unwrap_or(Err(e))
    }

    fn register_action(&mut self, action: Action) {
        self.with(|n| n.register_action(action));
    }

    fn set_name(&mut self, name: &str) -> Result<(), Report> {
        let e = self.gone();
        self.with(|n| n.set_name(name)).unwrap_or(Err(e))
    }

    fn set_app_info(&mut self, app: &[u8]) -> Result<(), Report> {
        let e = self.gone();
        self.with(|n| n.set_app_info(app)).unwrap_or(Err(e))
    }

    fn state(&self) -> BusState {
        self.sim.nodes.get(&self.id).map_or_else(
            || BusState {
                bus: self.sim.bus,
                device: self.id,
                generation: 0,
                checkpoint: 0,
                root_device: self.sim.root_device,
                halted: false,
                members: Vec::new(),
                links: Vec::new(),
                memory_used: 0,
            },
            Node::state,
        )
    }

    fn poll_event(&mut self) -> Option<Event> {
        self.with(Node::poll_event).flatten()
    }

    fn answer_host(&mut self, id: HostRequestId, answer: HostAnswer) -> Result<(), Report> {
        let e = self.gone();
        self.with(|n| n.answer_host(id, answer)).unwrap_or(Err(e))
    }

    fn change_member(
        &mut self,
        device: DeviceId,
        rights: Rights,
        presence: bool,
        permits: Vec<Permit>,
    ) -> Result<HostRequestId, Report> {
        let e = self.gone();
        self.with(|n| n.change_member(device, rights, presence, permits)).unwrap_or(Err(e))
    }

    fn revoke(&mut self, device: DeviceId) -> Result<HostRequestId, Report> {
        let e = self.gone();
        self.with(|n| n.revoke(device)).unwrap_or(Err(e))
    }
}
