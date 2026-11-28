// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 HunterEwok

//! The simulator's only source of nondeterminism: a seeded generator (R-CORE-9, R-VER-7).

/// `SplitMix64`: small, fast, and fully determined by its seed. Not for cryptography.
#[derive(Clone, Debug)]
pub(crate) struct Rng(u64);

impl Rng {
    /// A generator with the given seed.
    pub(crate) fn new(seed: u64) -> Self {
        Self(seed)
    }

    /// The next 64 random bits.
    pub(crate) fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// A nonzero value.
    pub(crate) fn nonzero(&mut self) -> u64 {
        loop {
            let v = self.next_u64();
            if v != 0 {
                return v;
            }
        }
    }

    /// True with probability `permille` / 1000.
    pub(crate) fn chance(&mut self, permille: u16) -> bool {
        self.next_u64().checked_rem(1000).unwrap_or(0) < u64::from(permille)
    }

    /// An index in `0..n`, for `n > 0`.
    pub(crate) fn below(&mut self, n: usize) -> usize {
        let n64 = u64::try_from(n).unwrap_or(u64::MAX).max(1);
        usize::try_from(self.next_u64().checked_rem(n64).unwrap_or(0)).unwrap_or(0)
    }
}
