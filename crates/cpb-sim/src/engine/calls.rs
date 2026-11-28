// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 HunterEwok

//! Call nonce slots: the target and the commander.
//!
//! This is the `calls` Quint model (models/calls) written as Rust, with the same state and
//! the same transitions; the trace replay test checks that they agree. Nonces come from a
//! per-target counter that survives reboots, standing in for 16 random bytes that never
//! repeat (Section 13.1). 0 means "no nonce".

use std::collections::{BTreeMap, BTreeSet};

use cpb_api::{Action, ActionSet, DeviceId};

/// The key a call is signed with (R-CALL-4).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum SigKey {
    /// The commander's device key: automatic actions.
    Device,
    /// The commander's user-presence key: confirmation-class actions.
    Presence,
    /// The root key, from the root device only: every action.
    Root,
}

/// A signed call body. `id` names the commander's call; an automatic retry is another body
/// of the same call.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CallBody {
    /// The commander device.
    pub cmd: DeviceId,
    /// The commander's call number.
    pub id: u64,
    /// Marked idempotent by the application (R-CALL-13).
    pub idem: bool,
    /// The action.
    pub act: Action,
    /// Confirmation-class for this commander, as the commander determined it.
    pub confirm: bool,
    /// The signing key.
    pub key: SigKey,
    /// The nonce.
    pub nonce: u64,
    /// The target's sealing key epoch the command is sealed to.
    pub epoch: u32,
}

/// The rights of one commander in the target's passport.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct CmdRights {
    /// Automatic actions.
    pub automatic: ActionSet,
    /// Confirmation-class actions.
    pub confirmation: ActionSet,
    /// The commander holds a user-presence key.
    pub presence: bool,
}

/// What the target does with a call.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Verdict {
    /// "Nonce mismatch": nothing executed, the slot unchanged; carries the current nonce, or
    /// none if the commander gets no slot (then nothing is answered).
    Mismatch(Option<u64>),
    /// "Stale key epoch": carries the target's current epoch; the nonce is not consumed.
    StaleEpoch(u32),
    /// The nonce was consumed. `ok` if the action runs; the reply carries `next`.
    Consumed {
        /// The action runs.
        ok: bool,
        /// The next nonce, 0 if the target issues none.
        next: u64,
    },
}

/// The target side.
#[derive(Clone, Debug)]
pub struct Target {
    /// The nonce slot of each device (RAM only).
    pub slots: BTreeMap<DeviceId, u64>,
    /// Current sealing key epoch.
    pub tepoch: u32,
    /// Sealing key epochs retained (Section 13.2), at least 2.
    pub retained_epochs: u32,
    /// The commanders named in the target's passport with their rights.
    pub named: BTreeMap<DeviceId, CmdRights>,
    /// The root device named in the checkpoint.
    pub root: DeviceId,
    /// Nonces issued so far; stands in for randomness and survives reboots.
    pub issued: u64,
    /// Highest nonce the target may issue; `u64::MAX` outside replay.
    pub max_nonce: u64,
}

impl Target {
    /// A target with no slots.
    #[must_use]
    pub fn new(root: DeviceId, named: BTreeMap<DeviceId, CmdRights>) -> Self {
        Self { slots: BTreeMap::new(), tepoch: 1, retained_epochs: 4, named, root, issued: 0, max_nonce: u64::MAX }
    }

    /// R-CALL-7: slots only for named commanders and the root device.
    #[must_use]
    pub fn allowed(&self, c: DeviceId) -> bool {
        self.named.contains_key(&c) || c == self.root
    }

    fn fresh(&mut self) -> Option<u64> {
        if self.issued < self.max_nonce {
            self.issued = self.issued.saturating_add(1);
            Some(self.issued)
        } else {
            None
        }
    }

    fn slot(&self, c: DeviceId) -> u64 {
        self.slots.get(&c).copied().unwrap_or(0)
    }

    /// A nonce request (R-CALL-1, R-CALL-7): the current slot value, creating the slot on the
    /// first request. `None`: not answered.
    pub fn answer(&mut self, c: DeviceId) -> Option<u64> {
        if !self.allowed(c) {
            return None;
        }
        let cur = self.slot(c);
        if cur != 0 {
            return Some(cur);
        }
        let n = self.fresh()?;
        self.slots.insert(c, n);
        Some(n)
    }

    /// R-CALL-4: the signing key has the right to the action. The class is the target's.
    #[must_use]
    pub fn permitted(&self, x: &CallBody) -> bool {
        if x.key == SigKey::Root {
            return x.cmd == self.root;
        }
        let Some(r) = self.named.get(&x.cmd) else {
            return false;
        };
        (x.key == SigKey::Device && r.automatic.contains(x.act))
            || (x.key == SigKey::Presence && r.presence && r.confirmation.contains(x.act))
    }

    /// A call arrives (R-CALL-4..6, R-CALL-13).
    pub fn on_call(&mut self, x: &CallBody) -> Verdict {
        let cur = self.slot(x.cmd);
        if cur == 0 || x.nonce != cur {
            // Without a slot the refusal is the answer to a nonce request (R-CALL-6).
            if cur == 0 {
                return Verdict::Mismatch(self.answer(x.cmd));
            }
            return Verdict::Mismatch(Some(cur));
        }
        if x.epoch.saturating_add(self.retained_epochs) <= self.tepoch {
            return Verdict::StaleEpoch(self.tepoch);
        }
        let ok = self.allowed(x.cmd) && self.permitted(x);
        let next = self.fresh().unwrap_or(0);
        if next == 0 {
            self.slots.remove(&x.cmd);
        } else {
            self.slots.insert(x.cmd, next);
        }
        Verdict::Consumed { ok, next }
    }

    /// "Reset nonces" (R-CALL-8) or a reboot (R-CORE-6): every slot is erased.
    pub fn reset(&mut self) {
        self.slots.clear();
    }

    /// The sealing key moves to the next epoch.
    pub fn rotate_epoch(&mut self) {
        self.tepoch = self.tepoch.saturating_add(1);
    }

    /// A new passport of the target, or a new checkpoint: the commanders and their rights.
    /// The slot of a device that is no longer named is erased in the same event (R-CALL-7).
    pub fn set_commanders(&mut self, named: BTreeMap<DeviceId, CmdRights>, root: DeviceId) {
        let gone: BTreeSet<DeviceId> = self.named.keys().filter(|c| !named.contains_key(c)).copied().collect();
        self.named = named;
        self.root = root;
        let root_now = self.root;
        self.slots.retain(|c, _| !gone.contains(c) || *c == root_now);
    }
}

/// A call in flight at the commander.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Pending {
    /// The latest body sent.
    pub call: CallBody,
    /// Retried after "stale key epoch".
    pub tried_epoch: bool,
    /// Retried after "nonce mismatch".
    pub tried_mismatch: bool,
}

/// What the commander does after an open refusal.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Next {
    /// Send this body.
    Retry(CallBody),
    /// The outcome is unknown (L7).
    Unknown,
    /// Nothing changes for the call.
    Nothing,
}

/// The commander side, for one target.
#[derive(Clone, Debug)]
pub struct Commander {
    /// The nonce held, 0 for none.
    pub nonce: u64,
    /// The target's sealing key epoch known to the commander.
    pub epoch: u32,
    /// The call in flight.
    pub pending: Option<Pending>,
}

impl Default for Commander {
    fn default() -> Self {
        Self { nonce: 0, epoch: 1, pending: None }
    }
}

impl Commander {
    /// Takes a nonce from an answer while no call is in flight. 0 forgets the nonce held.
    pub fn learn(&mut self, n: u64) {
        if self.pending.is_none() {
            self.nonce = n;
        }
    }

    /// Starts a call with the nonce held. `None` if a call is in flight or no nonce is held.
    pub fn start(
        &mut self,
        cmd: DeviceId,
        id: u64,
        act: Action,
        confirm: bool,
        idem: bool,
        key: SigKey,
    ) -> Option<CallBody> {
        if self.pending.is_some() || self.nonce == 0 {
            return None;
        }
        let x = CallBody { cmd, id, idem, act, confirm, key, nonce: self.nonce, epoch: self.epoch };
        self.nonce = 0;
        self.pending = Some(Pending { call: x.clone(), tried_epoch: false, tried_mismatch: false });
        Some(x)
    }

    /// A reply to the pending call, or to an earlier body of it, ends the call.
    pub fn on_reply(&mut self, id: u64, next: u64) -> bool {
        match &self.pending {
            Some(p) if p.call.id == id => {
                self.nonce = next;
                self.pending = None;
                true
            }
            _ => false,
        }
    }

    /// A "nonce mismatch" refusal for the pending call (R-CALL-13). Only an idempotent call
    /// that is not confirmation-class is retried, once.
    pub fn on_mismatch(&mut self, n: u64) -> Next {
        let Some(p) = self.pending.as_mut() else {
            return Next::Nothing;
        };
        let retry = n != 0 && !p.tried_mismatch && !p.call.confirm && p.call.idem;
        if retry {
            p.call.nonce = n;
            p.tried_mismatch = true;
            self.nonce = 0;
            Next::Retry(p.call.clone())
        } else {
            self.nonce = n;
            self.pending = None;
            Next::Unknown
        }
    }

    /// A signed claim of the target's key epoch. Accepted only above the known epoch; the
    /// pending call is then retried once with the same nonce, except a confirmation-class call.
    pub fn on_epoch(&mut self, e: u32) -> Next {
        if e <= self.epoch {
            return Next::Nothing;
        }
        self.epoch = e;
        let Some(p) = self.pending.as_mut() else {
            return Next::Nothing;
        };
        if !p.tried_epoch && !p.call.confirm {
            p.call.epoch = e;
            p.tried_epoch = true;
            Next::Retry(p.call.clone())
        } else {
            self.pending = None;
            Next::Unknown
        }
    }
}
