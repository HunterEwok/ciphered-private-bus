// SPDX-License-Identifier: MPL-2.0
//
// Instances of the membership model. `small` is the configuration checked in
// CI; each `probe_*` instance contains one deliberate defect and is expected to
// violate `safety` (R-VER-2).

module small {
  import membership(DEVICES = Set("a", "b", "c"), MAX_GEN = 2, MAX_NO = 3, MUTANT = "none").* from "./membership"
}

module tiny {
  import membership(DEVICES = Set("a", "b"), MAX_GEN = 2, MAX_NO = 2, MUTANT = "none").* from "./membership"
}

module probe_ignore_bitmap { import membership(DEVICES = Set("a", "b", "c"), MAX_GEN = 2, MAX_NO = 3, MUTANT = "ignore_bitmap").* from "./membership" }
module probe_keep_bit { import membership(DEVICES = Set("a", "b", "c"), MAX_GEN = 2, MAX_NO = 3, MUTANT = "keep_bit").* from "./membership" }
module probe_accept_old_gen { import membership(DEVICES = Set("a", "b", "c"), MAX_GEN = 2, MAX_NO = 3, MUTANT = "accept_old_gen").* from "./membership" }
module probe_accept_lower { import membership(DEVICES = Set("a", "b", "c"), MAX_GEN = 2, MAX_NO = 3, MUTANT = "accept_lower").* from "./membership" }
module probe_no_halt { import membership(DEVICES = Set("a", "b", "c"), MAX_GEN = 2, MAX_NO = 3, MUTANT = "no_halt").* from "./membership" }
module probe_halted_accepts { import membership(DEVICES = Set("a", "b", "c"), MAX_GEN = 2, MAX_NO = 3, MUTANT = "halted_accepts").* from "./membership" }
module probe_rc_no_forever { import membership(DEVICES = Set("a", "b", "c"), MAX_GEN = 2, MAX_NO = 3, MUTANT = "rc_no_forever").* from "./membership" }
module probe_proof_needs_cp { import membership(DEVICES = Set("a", "b", "c"), MAX_GEN = 2, MAX_NO = 3, MUTANT = "proof_needs_cp").* from "./membership" }
module probe_reboot_rollback { import membership(DEVICES = Set("a", "b", "c"), MAX_GEN = 2, MAX_NO = 3, MUTANT = "reboot_rollback").* from "./membership" }
module probe_grant_no_right { import membership(DEVICES = Set("a", "b", "c"), MAX_GEN = 2, MAX_NO = 3, MUTANT = "grant_no_right").* from "./membership" }
