// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 HunterEwok
//
// Instances of the membership model. `small` is the configuration checked in
// CI; each `probe_*` instance contains one deliberate defect and is expected to
// violate `safety` (R-VER-2).

module small {
  import membership(DEVICES = Set("a", "b", "c"), MAX_GEN = 2, MAX_NO = 3, MUTANT = "none", TRACK_RECV = true).* from "./membership"
}

module tiny {
  import membership(DEVICES = Set("a", "b"), MAX_GEN = 2, MAX_NO = 2, MUTANT = "none", TRACK_RECV = true).* from "./membership"
}

module probe_ignore_bitmap { import membership(DEVICES = Set("a", "b", "c"), MAX_GEN = 2, MAX_NO = 3, MUTANT = "ignore_bitmap", TRACK_RECV = true).* from "./membership" }
module probe_keep_bit { import membership(DEVICES = Set("a", "b", "c"), MAX_GEN = 2, MAX_NO = 3, MUTANT = "keep_bit", TRACK_RECV = true).* from "./membership" }
module probe_accept_old_gen { import membership(DEVICES = Set("a", "b", "c"), MAX_GEN = 2, MAX_NO = 3, MUTANT = "accept_old_gen", TRACK_RECV = true).* from "./membership" }
module probe_accept_lower { import membership(DEVICES = Set("a", "b", "c"), MAX_GEN = 2, MAX_NO = 3, MUTANT = "accept_lower", TRACK_RECV = true).* from "./membership" }
module probe_no_halt { import membership(DEVICES = Set("a", "b", "c"), MAX_GEN = 2, MAX_NO = 3, MUTANT = "no_halt", TRACK_RECV = true).* from "./membership" }
module probe_halted_accepts { import membership(DEVICES = Set("a", "b", "c"), MAX_GEN = 2, MAX_NO = 3, MUTANT = "halted_accepts", TRACK_RECV = true).* from "./membership" }
module probe_rc_no_forever { import membership(DEVICES = Set("a", "b", "c"), MAX_GEN = 2, MAX_NO = 3, MUTANT = "rc_no_forever", TRACK_RECV = true).* from "./membership" }
module probe_proof_needs_cp { import membership(DEVICES = Set("a", "b", "c"), MAX_GEN = 2, MAX_NO = 3, MUTANT = "proof_needs_cp", TRACK_RECV = true).* from "./membership" }
module probe_reboot_rollback { import membership(DEVICES = Set("a", "b", "c"), MAX_GEN = 2, MAX_NO = 3, MUTANT = "reboot_rollback", TRACK_RECV = true).* from "./membership" }
module probe_grant_no_right { import membership(DEVICES = Set("a", "b", "c"), MAX_GEN = 2, MAX_NO = 3, MUTANT = "grant_no_right", TRACK_RECV = true).* from "./membership" }
module probe_accept_old_data_gen { import membership(DEVICES = Set("a", "b"), MAX_GEN = 2, MAX_NO = 2, MUTANT = "accept_old_data_gen", TRACK_RECV = false).* from "./membership" }
module probe_no_prune { import membership(DEVICES = Set("a", "b", "c"), MAX_GEN = 2, MAX_NO = 3, MUTANT = "no_prune", TRACK_RECV = true).* from "./membership" }
module probe_halted_silent { import membership(DEVICES = Set("a", "b"), MAX_GEN = 2, MAX_NO = 2, MUTANT = "halted_silent", TRACK_RECV = false).* from "./membership" }

// For exhaustive TLC runs: the same model without the processed-record sets,
// which only `convergence` reads; `convergence` is checked by the simulator
// and in a separate run.
module tiny_tlc {
  import membership(DEVICES = Set("a", "b"), MAX_GEN = 2, MAX_NO = 2, MUTANT = "none", TRACK_RECV = false).* from "./membership"
}
