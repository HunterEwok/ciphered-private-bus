// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 HunterEwok
//
// Instances of the channels model. `small` and `tiny` are checked in CI; each
// `probe_*` instance contains one deliberate defect and is expected to violate
// `safety` (R-VER-2).

module small {
  import channels(DEVICES = Set("a", "b", "c"), NO_READ = Set("c"), LATE = Set("b"), MAX_GEN = 3, MAX_NO = 5,
                  MAX_DEPTH = 2, BLOCK = 2, MUTANT = "none").* from "./channels"
}

module tiny {
  import channels(DEVICES = Set("a", "b"), NO_READ = Set(), LATE = Set(), MAX_GEN = 2, MAX_NO = 4,
                  MAX_DEPTH = 2, BLOCK = 2, MUTANT = "none").* from "./channels"
}
module probe_no_rotate_on_remove { import channels(DEVICES = Set("a", "b", "c"), NO_READ = Set("c"), LATE = Set("b"), MAX_GEN = 3, MAX_NO = 5, MAX_DEPTH = 2, BLOCK = 2, MUTANT = "no_rotate_on_remove").* from "./channels" }
module probe_grant_removed { import channels(DEVICES = Set("a", "b", "c"), NO_READ = Set("c"), LATE = Set("b"), MAX_GEN = 3, MAX_NO = 5, MAX_DEPTH = 2, BLOCK = 2, MUTANT = "grant_removed").* from "./channels" }
module probe_grant_no_read { import channels(DEVICES = Set("a", "b", "c"), NO_READ = Set("c"), LATE = Set("b"), MAX_GEN = 3, MAX_NO = 5, MAX_DEPTH = 2, BLOCK = 2, MUTANT = "grant_no_read").* from "./channels" }
module probe_no_block_skip { import channels(DEVICES = Set("a", "b", "c"), NO_READ = Set("c"), LATE = Set("b"), MAX_GEN = 3, MAX_NO = 5, MAX_DEPTH = 2, BLOCK = 2, MUTANT = "no_block_skip").* from "./channels" }
module probe_gen_not_persisted { import channels(DEVICES = Set("a", "b", "c"), NO_READ = Set("c"), LATE = Set("b"), MAX_GEN = 3, MAX_NO = 5, MAX_DEPTH = 2, BLOCK = 2, MUTANT = "gen_not_persisted").* from "./channels" }
module probe_accept_old_grant { import channels(DEVICES = Set("a", "b", "c"), NO_READ = Set("c"), LATE = Set("b"), MAX_GEN = 3, MAX_NO = 5, MAX_DEPTH = 2, BLOCK = 2, MUTANT = "accept_old_grant").* from "./channels" }
module probe_accept_without_key { import channels(DEVICES = Set("a", "b", "c"), NO_READ = Set("c"), LATE = Set("b"), MAX_GEN = 3, MAX_NO = 5, MAX_DEPTH = 2, BLOCK = 2, MUTANT = "accept_without_key").* from "./channels" }
module probe_empty_no_clear { import channels(DEVICES = Set("a", "b", "c"), NO_READ = Set("c"), LATE = Set("b"), MAX_GEN = 3, MAX_NO = 5, MAX_DEPTH = 2, BLOCK = 2, MUTANT = "empty_no_clear").* from "./channels" }
module probe_refill_moves_high { import channels(DEVICES = Set("a", "b", "c"), NO_READ = Set("c"), LATE = Set("b"), MAX_GEN = 3, MAX_NO = 5, MAX_DEPTH = 2, BLOCK = 2, MUTANT = "refill_moves_high").* from "./channels" }
module probe_high_not_persisted { import channels(DEVICES = Set("a", "b", "c"), NO_READ = Set("c"), LATE = Set("b"), MAX_GEN = 3, MAX_NO = 5, MAX_DEPTH = 2, BLOCK = 2, MUTANT = "high_not_persisted").* from "./channels" }
module probe_no_trim { import channels(DEVICES = Set("a", "b", "c"), NO_READ = Set("c"), LATE = Set("b"), MAX_GEN = 3, MAX_NO = 5, MAX_DEPTH = 2, BLOCK = 2, MUTANT = "no_trim").* from "./channels" }
module probe_mark_not_persisted { import channels(DEVICES = Set("a", "b", "c"), NO_READ = Set("c"), LATE = Set("b"), MAX_GEN = 3, MAX_NO = 5, MAX_DEPTH = 2, BLOCK = 2, MUTANT = "mark_not_persisted").* from "./channels" }
module probe_late_clear_kept { import channels(DEVICES = Set("a", "b", "c"), NO_READ = Set("c"), LATE = Set("b"), MAX_GEN = 3, MAX_NO = 5, MAX_DEPTH = 2, BLOCK = 2, MUTANT = "late_clear_kept").* from "./channels" }
module probe_grant_marked { import channels(DEVICES = Set("a", "b", "c"), NO_READ = Set("c"), LATE = Set("b"), MAX_GEN = 3, MAX_NO = 5, MAX_DEPTH = 2, BLOCK = 2, MUTANT = "grant_marked").* from "./channels" }
module probe_floor_stays { import channels(DEVICES = Set("a", "b", "c"), NO_READ = Set("c"), LATE = Set("b"), MAX_GEN = 3, MAX_NO = 5, MAX_DEPTH = 2, BLOCK = 2, MUTANT = "floor_stays").* from "./channels" }
