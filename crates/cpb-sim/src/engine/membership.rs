// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 HunterEwok

//! Membership records and their verification (Section 6): passports and checkpoints signed by
//! the Root, the validity rule, and the halt on two records with one number.
//!
//! Signatures are not modelled: a record exists only if the Root made it, so every record a
//! node receives is "signed by the Root of its generation". Root change records arrive in M2.

use std::collections::{BTreeMap, BTreeSet};

use cpb_api::{DeviceId, Permit, Rights, RuleCode};

/// A passport (Section 6.1).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Passport {
    /// Root generation.
    pub generation: u32,
    /// Passport number.
    pub number: u32,
    /// The device.
    pub device: DeviceId,
    /// Rights.
    pub rights: Rights,
    /// The device holds a user-presence key.
    pub presence: bool,
    /// Permits: who may command this device.
    pub permits: Vec<Permit>,
}

/// A checkpoint (Section 6.1).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Checkpoint {
    /// Root generation.
    pub generation: u32,
    /// Checkpoint number.
    pub number: u32,
    /// Valid passport numbers (the bitmap).
    pub valid: BTreeSet<u32>,
    /// Next free passport number.
    pub next_free: u32,
    /// The root device.
    pub root_device: DeviceId,
}

/// What a node knows about membership.
#[derive(Clone, Debug)]
pub struct View {
    /// The latest accepted checkpoint.
    pub checkpoint: Checkpoint,
    /// Passports by number (a cache; R-MEM-7).
    pub passports: BTreeMap<u32, Passport>,
    /// The node is halted (R-MEM-8).
    pub halted: bool,
}

/// How a record changed the view.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Change {
    /// The record was new and accepted.
    Accepted,
    /// The record was already known.
    Known,
    /// Two records with one number and different bodies: the node halted.
    Halted,
}

impl View {
    /// A view that starts from a checkpoint and the passports it makes valid.
    pub fn new(checkpoint: Checkpoint, passports: impl IntoIterator<Item = Passport>) -> Self {
        let mut v = Self { checkpoint, passports: BTreeMap::new(), halted: false };
        for p in passports {
            v.passports.insert(p.number, p);
        }
        v
    }

    /// The pair (generation, checkpoint number) carried by every message (R-MEM-6).
    #[must_use]
    pub fn pair(&self) -> (u32, u32) {
        (self.checkpoint.generation, self.checkpoint.number)
    }

    fn valid_number(&self, p: &Passport) -> bool {
        p.generation == self.checkpoint.generation
            && p.number < self.checkpoint.next_free
            && self.checkpoint.valid.contains(&p.number)
    }

    /// The valid passport of a device, if any (R-MEM-2).
    #[must_use]
    pub fn valid(&self, d: DeviceId) -> Option<&Passport> {
        self.passports.values().find(|p| p.device == d && self.valid_number(p))
    }

    /// Every valid passport.
    pub fn members(&self) -> impl Iterator<Item = &Passport> {
        self.passports.values().filter(|p| self.valid_number(p))
    }

    /// Valid members with the read right.
    #[must_use]
    pub fn readers(&self) -> BTreeSet<DeviceId> {
        self.members().filter(|p| p.rights.read).map(|p| p.device).collect()
    }

    /// Receives a checkpoint (R-MEM-5, R-MEM-8). On acceptance, passports whose bit is cleared
    /// leave the cache (R-MEM-7).
    ///
    /// # Errors
    /// `mem/stale-checkpoint`, or `mem/halted` if the node is halted.
    pub fn on_checkpoint(&mut self, c: &Checkpoint) -> Result<Change, RuleCode> {
        if self.halted {
            return Err(RuleCode::MEM_HALTED);
        }
        if c.generation != self.checkpoint.generation {
            // Root change records arrive in M2; another generation cannot be checked yet.
            return Err(RuleCode::MEM_STALE_CHECKPOINT);
        }
        if c.number == self.checkpoint.number {
            if *c == self.checkpoint {
                return Ok(Change::Known);
            }
            self.halted = true;
            return Ok(Change::Halted);
        }
        if c.number < self.checkpoint.number {
            return Err(RuleCode::MEM_STALE_CHECKPOINT);
        }
        self.checkpoint = c.clone();
        let cp = &self.checkpoint;
        self.passports.retain(|n, _| *n >= cp.next_free || cp.valid.contains(n));
        Ok(Change::Accepted)
    }

    /// Receives a passport (R-MEM-3, R-MEM-8).
    ///
    /// # Errors
    /// `mem/early-passport`, `mem/stale-checkpoint` for a revoked or foreign one, `mem/halted`.
    pub fn on_passport(&mut self, p: &Passport) -> Result<Change, RuleCode> {
        if self.halted {
            return Err(RuleCode::MEM_HALTED);
        }
        if p.generation != self.checkpoint.generation {
            return Err(RuleCode::MEM_STALE_CHECKPOINT);
        }
        if p.number >= self.checkpoint.next_free {
            return Err(RuleCode::MEM_EARLY_PASSPORT);
        }
        if let Some(old) = self.passports.get(&p.number) {
            if old == p {
                return Ok(Change::Known);
            }
            self.halted = true;
            return Ok(Change::Halted);
        }
        if !self.checkpoint.valid.contains(&p.number) {
            return Err(RuleCode::MEM_STALE_CHECKPOINT);
        }
        self.passports.insert(p.number, p.clone());
        Ok(Change::Accepted)
    }
}

/// The Root's own counters and records (R-MEM-1, R-MEM-3, R-MEM-4).
#[derive(Clone, Debug)]
pub struct Root {
    /// Root generation.
    pub generation: u32,
    /// Next passport number.
    pub next_passport: u32,
    /// Next checkpoint number.
    pub next_checkpoint: u32,
    /// Valid passports by number.
    pub valid: BTreeMap<u32, Passport>,
    /// The root device.
    pub root_device: DeviceId,
}

impl Root {
    /// A new bus whose root device holds passport 1 with every right.
    #[must_use]
    pub fn create(root_device: DeviceId) -> (Self, Passport, Checkpoint) {
        let mut r = Self { generation: 1, next_passport: 1, next_checkpoint: 1, valid: BTreeMap::new(), root_device };
        let rights = Rights { read: true, publish: true, relay: false, accept: true };
        let (p, c) = r.issue(root_device, rights, true, Vec::new());
        (r, p, c)
    }

    fn checkpoint(&mut self) -> Checkpoint {
        let c = Checkpoint {
            generation: self.generation,
            number: self.next_checkpoint,
            valid: self.valid.keys().copied().collect(),
            next_free: self.next_passport,
            root_device: self.root_device,
        };
        self.next_checkpoint = self.next_checkpoint.saturating_add(1);
        c
    }

    /// The valid passport of a device.
    #[must_use]
    pub fn passport_of(&self, d: DeviceId) -> Option<&Passport> {
        self.valid.values().find(|p| p.device == d)
    }

    /// Issues a passport and, together with it, a checkpoint (R-MEM-3). A device that already
    /// has a passport gets a new one and the old bit is cleared (R-MEM-4).
    pub fn issue(
        &mut self,
        device: DeviceId,
        rights: Rights,
        presence: bool,
        permits: Vec<Permit>,
    ) -> (Passport, Checkpoint) {
        self.valid.retain(|_, p| p.device != device);
        let p = Passport { generation: self.generation, number: self.next_passport, device, rights, presence, permits };
        self.next_passport = self.next_passport.saturating_add(1);
        self.valid.insert(p.number, p.clone());
        let c = self.checkpoint();
        (p, c)
    }

    /// Revokes a device: a new checkpoint with its bit cleared (R-MEM-4).
    pub fn revoke(&mut self, device: DeviceId) -> Option<Checkpoint> {
        let before = self.valid.len();
        self.valid.retain(|_, p| p.device != device);
        if self.valid.len() == before { None } else { Some(self.checkpoint()) }
    }
}
