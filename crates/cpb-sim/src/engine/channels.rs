// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 HunterEwok

//! Channel keys and retention: the source and the reader of one channel.
//!
//! This is the `channels` Quint model (models/channels) written as Rust, with the same state
//! and the same transitions; the trace replay test checks that they agree. The model's ghost
//! key identity `kid` stands in for the key itself and its commitment (R-CH-1).

use std::collections::{BTreeMap, BTreeSet};

use cpb_api::{BlobInfo, DeviceId, RuleCode};

/// A key grant as it travels: the generation and the key, for one reader.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Grant {
    /// Channel key generation (R-CH-8).
    pub generation: u32,
    /// The key itself; equal values are the same key.
    pub kid: u64,
    /// The reader the key is sealed to.
    pub reader: DeviceId,
}

/// A publication as it travels.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Pub {
    /// Channel key generation.
    pub generation: u32,
    /// The key it is encrypted under.
    pub kid: u64,
    /// Publication number.
    pub no: u64,
    /// Retention depth (R-CH-10).
    pub depth: u16,
    /// Data, up to 4096 bytes.
    pub data: Vec<u8>,
    /// The blob's size and segment count; its bytes travel separately (R-CH-15).
    pub blob: Option<BlobInfo>,
}

impl Pub {
    /// A publication without data and without a blob (R-CH-10).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty() && self.blob.is_none()
    }

    /// Never retained: a clearing publication or one of depth 0.
    fn clears(&self) -> bool {
        self.depth == 0 || self.is_empty()
    }
}

/// The source side of one own channel.
#[derive(Clone, Debug, Default)]
pub struct Source {
    /// Persisted: generation of the current key, 0 before the first.
    pub generation: u32,
    /// The current key.
    pub kid: u64,
    /// The current key is held (it may not survive a reboot).
    pub key_ok: bool,
    /// Readers granted the current key.
    pub granted: BTreeSet<DeviceId>,
    /// Next publication number to hand out.
    pub next_no: u64,
    /// Persisted: upper bound of the reserved block of numbers (R-CH-8).
    pub reserved: u64,
    /// Persisted: the key must be rotated before the next publication (R-CH-5).
    pub must_rotate: bool,
    /// Persisted: readers still to be granted the current key before a publication.
    pub to_grant: BTreeSet<DeviceId>,
    /// The source's own retained publications, in number order (R-CH-11); RAM only.
    pub retained: BTreeMap<u64, Pub>,
}

impl Source {
    /// A channel that has never published.
    #[must_use]
    pub fn new() -> Self {
        Self { next_no: 1, ..Self::default() }
    }

    /// R-CH-5: a key must be made before the next publication.
    #[must_use]
    pub fn must_rotate_now(&self) -> bool {
        !self.key_ok || self.must_rotate
    }

    /// A device leaves the readers (revoked, or removed by the application). The mark is
    /// persisted in the same event: after a reboot the source no longer knows whom it granted.
    ///
    /// `granted` and `to_grant` keep the device: the mark blocks every grant and publication
    /// under the current key, and the rotation clears both.
    pub fn remove_reader(&mut self) {
        if self.generation > 0 {
            self.must_rotate = true;
        }
    }

    /// The host signalled "rotate key epoch".
    pub fn epoch(&mut self) {
        self.must_rotate = true;
    }

    /// A new key; `readers` are the valid readers with the read right now.
    pub fn rotate(&mut self, kid: u64, readers: BTreeSet<DeviceId>) {
        self.generation = self.generation.saturating_add(1);
        self.kid = kid;
        self.key_ok = true;
        self.granted.clear();
        self.must_rotate = false;
        self.to_grant = readers;
    }

    /// Grants the current key to `d`, whose eligibility the caller has checked (R-CH-13).
    /// While the rotation mark is set the marked key is granted to no one.
    pub fn grant_to(&mut self, d: DeviceId) -> Option<Grant> {
        if !self.key_ok || self.must_rotate {
            return None;
        }
        self.granted.insert(d);
        self.to_grant.remove(&d);
        Some(Grant { generation: self.generation, kid: self.kid, reader: d })
    }

    /// Publishes under the current key, if no rotation and no grant is outstanding for a
    /// current reader in `members`. Returns the publication, or `None` if the caller must
    /// rotate or grant first, or the counter is exhausted (R-LIM-3).
    pub fn publish(
        &mut self,
        depth: u16,
        data: Vec<u8>,
        blob: Option<BlobInfo>,
        members: &BTreeSet<DeviceId>,
        block: u64,
    ) -> Option<Pub> {
        if self.must_rotate_now() || self.to_grant.iter().any(|d| members.contains(d)) {
            return None;
        }
        let no = self.next_no;
        if no > self.reserved {
            self.reserved = no.checked_add(block)?.checked_sub(1)?;
        }
        self.next_no = no.checked_add(1)?;
        let p = Pub { generation: self.generation, kid: self.kid, no, depth, data, blob };
        if p.clears() {
            self.retained.clear();
        } else {
            self.retained.insert(no, p.clone());
            trim(&mut self.retained, depth);
        }
        Some(p)
    }

    /// Reboot (R-CORE-5): the generation, the block bound, the mark and the readers still to
    /// be granted survive; the key may not; memory is lost.
    pub fn reboot(&mut self, keep_key: bool) {
        self.key_ok = keep_key && self.key_ok;
        self.granted.clear();
        self.retained.clear();
        self.next_no = self.reserved.saturating_add(1).max(1);
    }
}

/// How a reader took a publication.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Accepted {
    /// A new publication; `cleared` if it emptied the channel.
    New {
        /// The publication cleared the channel or had depth 0.
        cleared: bool,
    },
    /// A late clearing publication cleared the window up to its number.
    LateClear,
    /// A missing publication refilled the window.
    Refill,
}

/// The reader side of one channel of one source.
#[derive(Clone, Debug)]
pub struct Reader {
    /// Persisted: generation of the held key, 0 for none.
    pub generation: u32,
    /// The held key, 0 for none.
    pub kid: u64,
    /// Persisted: highest accepted generation.
    pub hi_gen: u32,
    /// Persisted: highest accepted publication number.
    pub hi_no: u64,
    /// Persisted: window floor; the window is `[floor, hi_no]`.
    pub floor: u64,
    /// Persisted: depth of the latest accepted publication.
    pub depth: u16,
    /// Retained publications; refilled after a reboot.
    pub retained: BTreeMap<u64, Pub>,
}

impl Default for Reader {
    fn default() -> Self {
        Self { generation: 0, kid: 0, hi_gen: 0, hi_no: 0, floor: 1, depth: 0, retained: BTreeMap::new() }
    }
}

/// Keeps the `n` publications with the highest numbers (R-CH-11).
fn trim(s: &mut BTreeMap<u64, Pub>, n: u16) {
    while s.len() > usize::from(n) {
        if s.pop_first().is_none() {
            break;
        }
    }
}

impl Reader {
    /// Whether the reader holds a key.
    #[must_use]
    pub fn has_key(&self) -> bool {
        self.kid != 0
    }

    /// Receives a grant addressed to `me` (R-CH-9, R-CH-13).
    ///
    /// # Errors
    /// The rule that refused the grant.
    pub fn on_grant(&mut self, me: DeviceId, g: Grant, read_right: bool) -> Result<(), RuleCode> {
        if g.reader != me || !read_right {
            return Err(RuleCode::GRANT_NO_READ_RIGHT);
        }
        if g.generation > self.hi_gen || (g.generation == self.hi_gen && g.kid == self.kid) {
            self.generation = g.generation;
            self.kid = g.kid;
            self.hi_gen = g.generation;
            Ok(())
        } else {
            Err(RuleCode::GRANT_OLD)
        }
    }

    /// Receives a publication (R-CH-9, R-CH-10, R-CH-11).
    ///
    /// # Errors
    /// `pub/no-key` or `pub/outside-window`.
    pub fn on_pub(&mut self, p: &Pub) -> Result<Accepted, RuleCode> {
        if self.kid == 0 || p.kid != self.kid {
            return Err(RuleCode::PUB_NO_KEY);
        }
        let is_new = p.no > self.hi_no;
        // A publication of depth 0 has no window and is never accepted late.
        let in_window = self.depth > 0
            && p.depth > 0
            && self.floor <= p.no
            && p.no <= self.hi_no
            && !self.retained.contains_key(&p.no);
        if is_new {
            let cleared = p.clears();
            let before: BTreeSet<u64> = self.retained.keys().copied().collect();
            if cleared {
                self.retained.clear();
            } else {
                self.retained.insert(p.no, p.clone());
                trim(&mut self.retained, p.depth);
            }
            let left = before.iter().any(|n| !self.retained.contains_key(n))
                || (!cleared && !self.retained.contains_key(&p.no));
            self.floor = if cleared {
                p.no.saturating_add(1)
            } else if left {
                self.retained.keys().next().copied().unwrap_or(p.no)
            } else {
                self.floor
            };
            self.hi_no = p.no;
            self.depth = p.depth;
            Ok(Accepted::New { cleared })
        } else if !in_window {
            Err(RuleCode::PUB_OUTSIDE_WINDOW)
        } else if p.is_empty() {
            // A late clearing publication clears everything up to its number.
            self.retained.retain(|n, _| *n > p.no);
            self.floor = p.no.saturating_add(1);
            Ok(Accepted::LateClear)
        } else {
            // Refill; only the depth of the latest publication governs. If something leaves
            // the window, the floor rises to the lowest retained number.
            self.retained.insert(p.no, p.clone());
            let before = self.retained.len();
            trim(&mut self.retained, self.depth);
            if self.retained.len() < before {
                self.floor = self.retained.keys().next().copied().unwrap_or(self.hi_no);
            }
            Ok(Accepted::Refill)
        }
    }

    /// Reboot (R-CORE-5): the key and the numbers survive, the retained publications do not.
    pub fn reboot(&mut self) {
        self.retained.clear();
    }
}
