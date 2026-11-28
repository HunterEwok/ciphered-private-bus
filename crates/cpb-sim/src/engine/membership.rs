// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 HunterEwok

//! Membership: the Quint model `models/membership/membership.qnt` in Rust.
//!
//! Passports and checkpoints with their window, root change records, the halt on two records
//! with one number, halt proofs and the permanent halt (Section 6). The trace replay test
//! checks that the node side and the Root side follow the model.
//!
//! Signatures are not computed. A record names the root key that signed it, and a node
//! verifies a record by comparing that key with the one it installed for the generation
//! (Appendix B, Section B.3, rule 1). A root change record exists only if the recovery key
//! made it.

use std::collections::{BTreeMap, BTreeSet};

use cpb_api::{DeviceId, Permit, Rights, RuleCode};

/// A root key, named by a number: the host generates a new one for every generation.
pub type RootKey = u64;

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
    /// The root key that signed it.
    pub key: RootKey,
}

/// A checkpoint (Section 6.1).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Checkpoint {
    /// Root generation.
    pub generation: u32,
    /// Checkpoint number; 0 is the empty checkpoint a generation starts from.
    pub number: u32,
    /// The window start: the bitmap covers `start..next_free` (R-MEM-14).
    pub start: u32,
    /// Valid passport numbers (the bitmap).
    pub valid: BTreeSet<u32>,
    /// Next free passport number.
    pub next_free: u32,
    /// The root device; none before the first checkpoint of a generation.
    pub root_device: Option<DeviceId>,
    /// The root key that signed it.
    pub key: RootKey,
}

impl Checkpoint {
    /// The empty checkpoint a generation starts from: nobody is a member yet.
    #[must_use]
    pub fn genesis(generation: u32, key: RootKey) -> Self {
        Self { generation, number: 0, start: 1, valid: BTreeSet::new(), next_free: 1, root_device: None, key }
    }

    /// R-MEM-2, R-MEM-14: the passport is valid under this checkpoint. A number outside the
    /// window has no bit and is not valid.
    #[must_use]
    pub fn makes_valid(&self, p: &Passport) -> bool {
        p.generation == self.generation
            && self.start <= p.number
            && p.number < self.next_free
            && self.valid.contains(&p.number)
    }
}

/// A root change record: signed by K1 and K2, it names the root key of a generation
/// (R-MEM-11).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct RootChange {
    /// The generation the record starts.
    pub generation: u32,
    /// Its root key.
    pub key: RootKey,
}

/// What two conflicting records were (Appendix B, Section B.3).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum HaltKind {
    /// Two checkpoints with one number.
    Checkpoint,
    /// Two passports with one number.
    Passport,
    /// Two root change records of one generation: the halt is permanent (R-MEM-13).
    RootChange,
}

/// A halt proof: the head two conflicting records share (R-MEM-10). It exists only if the two
/// records do.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct HaltProof {
    /// The kind of the records.
    pub kind: HaltKind,
    /// Their generation.
    pub generation: u32,
    /// Their number; 0 for root change records.
    pub number: u32,
    /// The root key that signed both; not used for root change records, which K1 and K2
    /// sign.
    pub key: RootKey,
}

/// How a record changed the view.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Change {
    /// The record was new and accepted.
    Accepted,
    /// The record was already known.
    Known,
    /// The node halted; the proof is for the other nodes (R-MEM-10).
    Halted(HaltProof),
}

/// What a node knows about membership.
#[derive(Clone, Debug)]
pub struct View {
    /// The root generation.
    pub generation: u32,
    /// The root key installed for it: the first root key, or the key of the root change
    /// record the node accepted.
    pub root_key: RootKey,
    /// Whether the generation was installed from a root change record.
    pub changed: bool,
    /// The latest accepted checkpoint.
    pub checkpoint: Checkpoint,
    /// Passports by number (a cache; R-MEM-7).
    pub passports: BTreeMap<u32, Passport>,
    /// The node is halted (R-MEM-8).
    pub halted: bool,
    /// The halt is permanent (R-MEM-13).
    pub forever: bool,
}

impl View {
    /// A node of the first generation that holds no record yet.
    #[must_use]
    pub fn first(first_root_key: RootKey) -> Self {
        Self {
            generation: 1,
            root_key: first_root_key,
            changed: false,
            checkpoint: Checkpoint::genesis(1, first_root_key),
            passports: BTreeMap::new(),
            halted: false,
            forever: false,
        }
    }

    /// The pair (generation, checkpoint number) carried by every message (R-MEM-6).
    #[must_use]
    pub fn pair(&self) -> (u32, u32) {
        (self.generation, self.checkpoint.number)
    }

    /// The valid passport of a device, if any (R-MEM-2).
    #[must_use]
    pub fn valid(&self, d: DeviceId) -> Option<&Passport> {
        self.passports.values().find(|p| p.device == d && self.checkpoint.makes_valid(p))
    }

    /// Every valid passport.
    pub fn members(&self) -> impl Iterator<Item = &Passport> {
        self.passports.values().filter(|p| self.checkpoint.makes_valid(p))
    }

    /// Valid members with the read right.
    #[must_use]
    pub fn readers(&self) -> BTreeSet<DeviceId> {
        self.members().filter(|p| p.rights.read).map(|p| p.device).collect()
    }

    /// Checks a publication or a key grant that `src` sent under its passport `number` with
    /// the pair `pair` (R-MEM-6, R-MEM-12, R-CH-13). A message of an older generation names
    /// a passport of a replaced Root and is dropped; one with a newer pair is dropped until
    /// the node has that checkpoint. Off channel 0 the passport needs the publish right.
    ///
    /// # Errors
    /// `mem/halted`; `mem/stale-checkpoint` for an older generation; `mem/behind` for a newer
    /// pair; `mem/not-member` without a valid passport of that number; `pub/no-right`.
    pub fn accept_data(
        &self,
        src: DeviceId,
        number: u32,
        pair: (u32, u32),
        channel_0: bool,
    ) -> Result<&Passport, RuleCode> {
        if self.halted {
            return Err(RuleCode::MEM_HALTED);
        }
        if pair.0 < self.generation {
            return Err(RuleCode::MEM_STALE_CHECKPOINT);
        }
        if pair > self.pair() {
            return Err(RuleCode::MEM_BEHIND);
        }
        let p = self
            .passports
            .get(&number)
            .filter(|p| p.device == src && self.checkpoint.makes_valid(p))
            .ok_or(RuleCode::MEM_NOT_MEMBER)?;
        if !channel_0 && !p.rights.publish {
            return Err(RuleCode::PUB_NO_RIGHT);
        }
        Ok(p)
    }

    /// The passport under which `reader` may get a channel key: valid, with the read right,
    /// and only while the node is not halted (R-CH-13, R-MEM-9).
    #[must_use]
    pub fn may_grant(&self, reader: DeviceId) -> Option<&Passport> {
        if self.halted {
            return None;
        }
        self.valid(reader).filter(|p| p.rights.read)
    }

    /// A record of this generation signed by the key the node installed for it.
    fn verifies(&self, generation: u32, key: RootKey) -> Result<(), RuleCode> {
        if generation != self.generation {
            return Err(RuleCode::MEM_STALE_CHECKPOINT);
        }
        if key != self.root_key {
            return Err(RuleCode::MEM_NOT_ROOT);
        }
        Ok(())
    }

    fn halt(&mut self, kind: HaltKind, number: u32) -> Change {
        self.halted = true;
        Change::Halted(HaltProof { kind, generation: self.generation, number, key: self.root_key })
    }

    /// Receives a checkpoint (R-MEM-5, R-MEM-8, R-MEM-9, R-MEM-12). On acceptance, passports
    /// whose bit is cleared leave the cache (R-MEM-7).
    ///
    /// # Errors
    /// `mem/halted`; `mem/stale-checkpoint` for another generation or a lower number;
    /// `mem/not-root` for a record the installed root key did not sign.
    pub fn on_checkpoint(&mut self, c: &Checkpoint) -> Result<Change, RuleCode> {
        if self.halted {
            return Err(RuleCode::MEM_HALTED);
        }
        self.verifies(c.generation, c.key)?;
        if c.number == self.checkpoint.number {
            if *c == self.checkpoint {
                return Ok(Change::Known);
            }
            return Ok(self.halt(HaltKind::Checkpoint, c.number));
        }
        if c.number < self.checkpoint.number {
            return Err(RuleCode::MEM_STALE_CHECKPOINT);
        }
        self.checkpoint = c.clone();
        let cp = &self.checkpoint;
        self.passports.retain(|_, p| cp.makes_valid(p));
        Ok(Change::Accepted)
    }

    /// Receives a passport (R-MEM-2, R-MEM-3, R-MEM-8).
    ///
    /// # Errors
    /// `mem/halted`; `mem/early-passport` for a number the checkpoint does not cover yet;
    /// `mem/stale-checkpoint` for a revoked one or one of another generation; `mem/not-root`.
    pub fn on_passport(&mut self, p: &Passport) -> Result<Change, RuleCode> {
        if self.halted {
            return Err(RuleCode::MEM_HALTED);
        }
        self.verifies(p.generation, p.key)?;
        if let Some(old) = self.passports.get(&p.number) {
            if old == p {
                return Ok(Change::Known);
            }
            return Ok(self.halt(HaltKind::Passport, p.number));
        }
        if p.number >= self.checkpoint.next_free {
            return Err(RuleCode::MEM_EARLY_PASSPORT);
        }
        if !self.checkpoint.makes_valid(p) {
            return Err(RuleCode::MEM_STALE_CHECKPOINT);
        }
        self.passports.insert(p.number, p.clone());
        Ok(Change::Accepted)
    }

    /// Receives a root change record (R-MEM-11, R-MEM-13). A record of a higher generation
    /// moves the node there directly, with no member until the new Root's records arrive,
    /// and ends a halt. A second record of the current generation is a permanent halt.
    ///
    /// # Errors
    /// `mem/halted` for a node halted for good; `mem/stale-checkpoint` for a lower
    /// generation; `mem/root-key-reused` for a record that names the root key the node holds.
    pub fn on_root_change(&mut self, rc: RootChange) -> Result<Change, RuleCode> {
        if self.forever {
            return Err(RuleCode::MEM_HALTED);
        }
        if rc.generation == self.generation && self.changed {
            if rc.key == self.root_key {
                return Ok(Change::Known);
            }
            self.halted = true;
            self.forever = true;
            let proof = HaltProof { kind: HaltKind::RootChange, generation: rc.generation, number: 0, key: 0 };
            return Ok(Change::Halted(proof));
        }
        if rc.generation <= self.generation {
            return Err(RuleCode::MEM_STALE_CHECKPOINT);
        }
        if rc.key == self.root_key {
            return Err(RuleCode::MEM_ROOT_KEY_REUSED);
        }
        self.generation = rc.generation;
        self.root_key = rc.key;
        self.changed = true;
        self.checkpoint = Checkpoint::genesis(rc.generation, rc.key);
        self.passports.clear();
        self.halted = false;
        Ok(Change::Accepted)
    }

    /// Receives a halt proof (R-MEM-10; Appendix B, Section B.3, rules 2 and 3). A proof of
    /// two root change records halts a node of any generation for good. A proof of two
    /// passports or checkpoints halts a node of their generation whatever checkpoint it is
    /// at; of another generation, or of a key the node did not install, it is dropped.
    ///
    /// # Errors
    /// `mem/halted` for a node halted for good; `mem/stale-checkpoint` and `mem/not-root`
    /// for a proof the node cannot verify.
    pub fn on_halt_proof(&mut self, h: HaltProof) -> Result<Change, RuleCode> {
        if self.forever {
            return Err(RuleCode::MEM_HALTED);
        }
        if h.kind == HaltKind::RootChange {
            self.halted = true;
            self.forever = true;
            return Ok(Change::Halted(h));
        }
        self.verifies(h.generation, h.key)?;
        if self.halted {
            return Ok(Change::Known);
        }
        self.halted = true;
        Ok(Change::Halted(h))
    }

    /// A reboot: the generation, the root key and the checkpoint survive (R-CORE-5); the
    /// passport cache is volatile.
    pub fn reboot(&mut self) {
        self.passports.clear();
    }
}

/// Why the Root could not issue a record.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RootError {
    /// The window would grow beyond the profile limit and cannot move (R-MEM-14).
    WindowFull,
    /// No such valid passport.
    Unknown,
}

/// The Root's own counters and records (R-MEM-1, R-MEM-3, R-MEM-4, R-MEM-14).
#[derive(Clone, Debug)]
pub struct Root {
    /// Root generation.
    pub generation: u32,
    /// The root key of this generation.
    pub key: RootKey,
    /// The number of the latest checkpoint.
    pub checkpoint: u32,
    /// Next passport number.
    pub next_passport: u32,
    /// Valid passports by number.
    pub valid: BTreeMap<u32, Passport>,
    /// The root device.
    pub root_device: DeviceId,
    /// The profile limit on the bitmap length (R-MEM-14).
    pub window: u32,
}

impl Root {
    /// The Root of a generation that has issued nothing yet (R-MEM-12).
    #[must_use]
    pub fn new(generation: u32, key: RootKey, root_device: DeviceId, window: u32) -> Self {
        Self { generation, key, checkpoint: 0, next_passport: 1, valid: BTreeMap::new(), root_device, window }
    }

    /// A checkpoint over the given valid numbers. The window start moves as far as R-MEM-14
    /// allows: past every leading cleared bit.
    fn make_checkpoint(&self, valid: &BTreeSet<u32>, next_free: u32) -> Checkpoint {
        let start = valid.first().copied().unwrap_or(next_free);
        Checkpoint {
            generation: self.generation,
            number: self.checkpoint.saturating_add(1),
            start,
            valid: valid.clone(),
            next_free,
            root_device: Some(self.root_device),
            key: self.key,
        }
    }

    /// The valid passport of a device.
    #[must_use]
    pub fn passport_of(&self, d: DeviceId) -> Option<&Passport> {
        self.valid.values().find(|p| p.device == d)
    }

    /// Issues a passport and, together with it, a checkpoint that clears the numbers in
    /// `replaces` (R-MEM-3, R-MEM-4).
    ///
    /// # Errors
    /// [`RootError::WindowFull`] if the checkpoint would span more than the window.
    pub fn issue_replacing(
        &mut self,
        device: DeviceId,
        rights: Rights,
        presence: bool,
        permits: Vec<Permit>,
        replaces: &BTreeSet<u32>,
    ) -> Result<(Passport, Checkpoint), RootError> {
        let number = self.next_passport;
        let mut valid: BTreeSet<u32> = self.valid.keys().copied().filter(|k| !replaces.contains(k)).collect();
        valid.insert(number);
        let c = self.make_checkpoint(&valid, number.saturating_add(1));
        if c.next_free.saturating_sub(c.start) > self.window {
            return Err(RootError::WindowFull);
        }
        let p = Passport { generation: self.generation, number, device, rights, presence, permits, key: self.key };
        self.valid.retain(|k, _| !replaces.contains(k));
        self.valid.insert(number, p.clone());
        self.next_passport = c.next_free;
        self.checkpoint = c.number;
        Ok((p, c))
    }

    /// Admits a device or changes its passport: the old passport of the device, if any, is
    /// replaced. When the window is full, the Root first reissues its oldest passports to
    /// move it (R-MEM-14); every pair of records made is returned in order.
    ///
    /// # Errors
    /// [`RootError::WindowFull`] if as many devices are valid as the window has bits.
    pub fn issue(
        &mut self,
        device: DeviceId,
        rights: Rights,
        presence: bool,
        permits: Vec<Permit>,
    ) -> Result<Vec<(Passport, Checkpoint)>, RootError> {
        let others = self.valid.values().filter(|p| p.device != device).count();
        if u32::try_from(others).map_or(true, |n| n >= self.window) {
            return Err(RootError::WindowFull);
        }
        let mut out = Vec::new();
        loop {
            let replaces: BTreeSet<u32> =
                self.valid.values().filter(|p| p.device == device).map(|p| p.number).collect();
            let kept = self.valid.keys().copied().find(|k| !replaces.contains(k));
            let start = kept.unwrap_or(self.next_passport);
            if self.next_passport.saturating_add(1).saturating_sub(start) <= self.window {
                out.push(self.issue_replacing(device, rights, presence, permits, &replaces)?);
                return Ok(out);
            }
            // The oldest passport of another device moves to a new number.
            let Some(old) = self.valid.values().find(|p| p.device != device).cloned() else {
                return Err(RootError::WindowFull);
            };
            let moved =
                self.issue_replacing(old.device, old.rights, old.presence, old.permits, &BTreeSet::from([old.number]))?;
            out.push(moved);
        }
    }

    /// Revokes a passport number: a new checkpoint with its bit cleared (R-MEM-4).
    ///
    /// # Errors
    /// [`RootError::Unknown`] if the number is not valid.
    pub fn revoke_number(&mut self, number: u32) -> Result<Checkpoint, RootError> {
        if self.valid.remove(&number).is_none() {
            return Err(RootError::Unknown);
        }
        let valid: BTreeSet<u32> = self.valid.keys().copied().collect();
        let c = self.make_checkpoint(&valid, self.next_passport);
        self.checkpoint = c.number;
        Ok(c)
    }

    /// Revokes a device.
    ///
    /// # Errors
    /// [`RootError::Unknown`] if the device has no valid passport.
    pub fn revoke(&mut self, device: DeviceId) -> Result<Checkpoint, RootError> {
        let number = self.passport_of(device).map(|p| p.number).ok_or(RootError::Unknown)?;
        self.revoke_number(number)
    }
}

#[cfg(test)]
#[allow(clippy::panic, reason = "tests")]
mod tests {
    use super::*;

    const KEY: RootKey = 1;

    fn dev(n: u8) -> DeviceId {
        DeviceId([n; 16])
    }

    fn pair(issued: Result<(Passport, Checkpoint), RootError>) -> (Passport, Checkpoint) {
        match issued {
            Ok(records) => records,
            Err(e) => panic!("the Root could not issue: {e:?}"),
        }
    }

    fn pair_list(issued: Result<Vec<(Passport, Checkpoint)>, RootError>) -> Vec<(Passport, Checkpoint)> {
        match issued {
            Ok(records) => records,
            Err(e) => panic!("the Root could not issue: {e:?}"),
        }
    }

    /// A node that holds the passport of device 2 with the given rights, at checkpoint 1.
    fn view(rights: Rights) -> View {
        let mut root = Root::new(1, KEY, dev(1), 4);
        let mut v = View::first(KEY);
        let (p, c) = pair(root.issue_replacing(dev(2), rights, false, Vec::new(), &BTreeSet::new()));
        assert_eq!(v.on_checkpoint(&c), Ok(Change::Accepted));
        assert_eq!(v.on_passport(&p), Ok(Change::Accepted));
        v
    }

    #[test]
    fn data_is_accepted_from_a_valid_publisher() {
        let v = view(Rights::MEMBER);
        assert!(v.accept_data(dev(2), 1, (1, 1), false).is_ok());
        assert!(v.accept_data(dev(2), 1, (1, 0), false).is_ok());
    }

    #[test]
    fn data_refusals() {
        let v = view(Rights::MEMBER);
        assert_eq!(v.accept_data(dev(2), 1, (1, 2), false).err(), Some(RuleCode::MEM_BEHIND));
        assert_eq!(v.accept_data(dev(2), 1, (2, 0), false).err(), Some(RuleCode::MEM_BEHIND));
        assert_eq!(v.accept_data(dev(3), 1, (1, 1), false).err(), Some(RuleCode::MEM_NOT_MEMBER));
        assert_eq!(v.accept_data(dev(2), 2, (1, 1), false).err(), Some(RuleCode::MEM_NOT_MEMBER));
        let reader = view(Rights { publish: false, ..Rights::MEMBER });
        assert_eq!(reader.accept_data(dev(2), 1, (1, 1), false).err(), Some(RuleCode::PUB_NO_RIGHT));
        assert!(reader.accept_data(dev(2), 1, (1, 1), true).is_ok());
    }

    #[test]
    fn data_of_an_older_generation_is_dropped() {
        let mut v = view(Rights::MEMBER);
        assert_eq!(v.on_root_change(RootChange { generation: 2, key: 9 }), Ok(Change::Accepted));
        let mut root = Root::new(2, 9, dev(1), 4);
        let (p, c) = pair(root.issue_replacing(dev(2), Rights::MEMBER, false, Vec::new(), &BTreeSet::new()));
        assert_eq!(v.on_checkpoint(&c), Ok(Change::Accepted));
        assert_eq!(v.on_passport(&p), Ok(Change::Accepted));
        assert_eq!(v.accept_data(dev(2), 1, (1, 1), false).err(), Some(RuleCode::MEM_STALE_CHECKPOINT));
        assert!(v.accept_data(dev(2), 1, (2, 1), false).is_ok());
    }

    #[test]
    fn a_halted_node_accepts_and_grants_nothing() {
        let mut v = view(Rights::MEMBER);
        assert!(v.may_grant(dev(2)).is_some());
        let proof = HaltProof { kind: HaltKind::Passport, generation: 1, number: 1, key: KEY };
        assert_eq!(v.on_halt_proof(proof), Ok(Change::Halted(proof)));
        assert_eq!(v.accept_data(dev(2), 1, (1, 1), false).err(), Some(RuleCode::MEM_HALTED));
        assert!(v.may_grant(dev(2)).is_none());
    }

    #[test]
    fn a_proof_of_older_records_halts_too() {
        // R-MEM-10: the node is at checkpoint 1, the proof is of two checkpoints with a lower
        // number; it halts whatever checkpoint it is at.
        let mut v = view(Rights::MEMBER);
        let proof = HaltProof { kind: HaltKind::Checkpoint, generation: 1, number: 0, key: KEY };
        assert_eq!(v.on_halt_proof(proof), Ok(Change::Halted(proof)));
        assert!(v.halted && !v.forever);
    }

    #[test]
    fn keys_go_only_to_readers() {
        let v = view(Rights { read: false, ..Rights::MEMBER });
        assert!(v.may_grant(dev(2)).is_none());
        assert!(v.may_grant(dev(3)).is_none());
    }

    #[test]
    fn records_of_another_key_are_refused() {
        let mut v = View::first(KEY);
        let mut other = Root::new(1, 7, dev(1), 4);
        let (p, c) = pair(other.issue_replacing(dev(2), Rights::MEMBER, false, Vec::new(), &BTreeSet::new()));
        assert_eq!(v.on_checkpoint(&c), Err(RuleCode::MEM_NOT_ROOT));
        assert_eq!(v.on_passport(&p), Err(RuleCode::MEM_NOT_ROOT));
        let proof = HaltProof { kind: HaltKind::Checkpoint, generation: 1, number: 1, key: 7 };
        assert_eq!(v.on_halt_proof(proof), Err(RuleCode::MEM_NOT_ROOT));
        assert!(!v.halted);
    }

    #[test]
    fn a_second_root_change_record_halts_for_good() {
        let mut v = View::first(KEY);
        assert_eq!(v.on_root_change(RootChange { generation: 2, key: 9 }), Ok(Change::Accepted));
        assert_eq!(v.on_root_change(RootChange { generation: 2, key: 9 }), Ok(Change::Known));
        assert!(matches!(v.on_root_change(RootChange { generation: 2, key: 10 }), Ok(Change::Halted(_))));
        assert!(v.halted && v.forever);
        assert_eq!(v.on_root_change(RootChange { generation: 3, key: 11 }), Err(RuleCode::MEM_HALTED));
    }

    #[test]
    fn the_window_is_bounded() {
        let mut root = Root::new(1, KEY, dev(1), 2);
        let none = BTreeSet::new();
        assert!(root.issue_replacing(dev(1), Rights::MEMBER, false, Vec::new(), &none).is_ok());
        assert!(root.issue_replacing(dev(2), Rights::MEMBER, false, Vec::new(), &none).is_ok());
        assert_eq!(
            root.issue_replacing(dev(3), Rights::MEMBER, false, Vec::new(), &none).err(),
            Some(RootError::WindowFull)
        );
        assert_eq!(root.issue(dev(3), Rights::MEMBER, false, Vec::new()).err(), Some(RootError::WindowFull));
    }

    #[test]
    fn the_root_reissues_the_oldest_passports_to_move_the_window() {
        let mut root = Root::new(1, KEY, dev(1), 2);
        let none = BTreeSet::new();
        assert!(root.issue_replacing(dev(1), Rights::MEMBER, false, Vec::new(), &none).is_ok());
        assert!(root.issue_replacing(dev(2), Rights::MEMBER, false, Vec::new(), &none).is_ok());
        assert!(root.revoke(dev(2)).is_ok());
        // Numbers 1 and 3 would span three: device 1 moves to number 3, device 3 gets 4.
        let records = pair_list(root.issue(dev(3), Rights::MEMBER, false, Vec::new()));
        let issued: Vec<(u32, DeviceId)> = records.iter().map(|(p, _)| (p.number, p.device)).collect();
        assert_eq!(issued, vec![(3, dev(1)), (4, dev(3))]);
        assert_eq!(records.last().map(|(_, c)| (c.start, c.next_free)), Some((3, 5)));
    }
}
