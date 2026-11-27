// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 HunterEwok
//
// Instances of the membership model. `small` is the configuration checked in
// CI; each `probe_*` instance contains one deliberate defect and is expected to
// violate `safety` (R-VER-2). WINDOW = 2 with three numbers per generation
// makes the window limit bind; with two it never binds, but the start still
// moves past revoked numbers.

module small {
  import membership(DEVICES = Set("a", "b", "c"), MAX_GEN = 2, MAX_NO = 3, WINDOW = 2, MUTANT = "none", TRACK_RECV = true).* from "./membership"
}

module tiny {
  import membership(DEVICES = Set("a", "b"), MAX_GEN = 2, MAX_NO = 2, WINDOW = 2, MUTANT = "none", TRACK_RECV = true).* from "./membership"
}

module probe_ignore_bitmap { import membership(DEVICES = Set("a", "b", "c"), MAX_GEN = 2, MAX_NO = 3, WINDOW = 2, MUTANT = "ignore_bitmap", TRACK_RECV = true).* from "./membership" }
module probe_keep_bit { import membership(DEVICES = Set("a", "b", "c"), MAX_GEN = 2, MAX_NO = 3, WINDOW = 2, MUTANT = "keep_bit", TRACK_RECV = true).* from "./membership" }
module probe_accept_old_gen { import membership(DEVICES = Set("a", "b", "c"), MAX_GEN = 2, MAX_NO = 3, WINDOW = 2, MUTANT = "accept_old_gen", TRACK_RECV = true).* from "./membership" }
module probe_accept_lower { import membership(DEVICES = Set("a", "b", "c"), MAX_GEN = 2, MAX_NO = 3, WINDOW = 2, MUTANT = "accept_lower", TRACK_RECV = true).* from "./membership" }
module probe_no_halt { import membership(DEVICES = Set("a", "b", "c"), MAX_GEN = 2, MAX_NO = 3, WINDOW = 2, MUTANT = "no_halt", TRACK_RECV = true).* from "./membership" }
module probe_halted_accepts { import membership(DEVICES = Set("a", "b", "c"), MAX_GEN = 2, MAX_NO = 3, WINDOW = 2, MUTANT = "halted_accepts", TRACK_RECV = true).* from "./membership" }
module probe_rc_no_forever { import membership(DEVICES = Set("a", "b"), MAX_GEN = 2, MAX_NO = 2, WINDOW = 2, MUTANT = "rc_no_forever", TRACK_RECV = false).* from "./membership" }
module probe_proof_needs_cp { import membership(DEVICES = Set("a", "b", "c"), MAX_GEN = 2, MAX_NO = 3, WINDOW = 2, MUTANT = "proof_needs_cp", TRACK_RECV = true).* from "./membership" }
module probe_reboot_rollback { import membership(DEVICES = Set("a", "b", "c"), MAX_GEN = 2, MAX_NO = 3, WINDOW = 2, MUTANT = "reboot_rollback", TRACK_RECV = true).* from "./membership" }
module probe_grant_no_right { import membership(DEVICES = Set("a", "b", "c"), MAX_GEN = 2, MAX_NO = 3, WINDOW = 2, MUTANT = "grant_no_right", TRACK_RECV = true).* from "./membership" }
module probe_accept_old_data_gen { import membership(DEVICES = Set("a", "b"), MAX_GEN = 2, MAX_NO = 2, WINDOW = 2, MUTANT = "accept_old_data_gen", TRACK_RECV = false).* from "./membership" }
module probe_no_prune { import membership(DEVICES = Set("a", "b", "c"), MAX_GEN = 2, MAX_NO = 3, WINDOW = 2, MUTANT = "no_prune", TRACK_RECV = true).* from "./membership" }
module probe_halted_silent { import membership(DEVICES = Set("a", "b"), MAX_GEN = 2, MAX_NO = 2, WINDOW = 2, MUTANT = "halted_silent", TRACK_RECV = false).* from "./membership" }
module probe_accept_no_publish { import membership(DEVICES = Set("a", "b", "c"), MAX_GEN = 2, MAX_NO = 3, WINDOW = 2, MUTANT = "accept_no_publish", TRACK_RECV = true).* from "./membership" }
module probe_below_window_valid { import membership(DEVICES = Set("a", "b", "c"), MAX_GEN = 2, MAX_NO = 3, WINDOW = 2, MUTANT = "below_window_valid", TRACK_RECV = true).* from "./membership" }
module probe_window_past_set_bit { import membership(DEVICES = Set("a", "b", "c"), MAX_GEN = 2, MAX_NO = 3, WINDOW = 2, MUTANT = "window_past_set_bit", TRACK_RECV = true).* from "./membership" }
module probe_unbounded_window { import membership(DEVICES = Set("a", "b", "c"), MAX_GEN = 2, MAX_NO = 3, WINDOW = 2, MUTANT = "unbounded_window", TRACK_RECV = true).* from "./membership" }
module probe_ignore_signer { import membership(DEVICES = Set("a", "b", "c"), MAX_GEN = 2, MAX_NO = 3, WINDOW = 2, MUTANT = "ignore_signer", TRACK_RECV = true).* from "./membership" }
module probe_need_next { import membership(DEVICES = Set("a", "b"), MAX_GEN = 2, MAX_NO = 2, WINDOW = 2, MUTANT = "need_next", TRACK_RECV = true).* from "./membership" }

// For exhaustive TLC runs: the same model without the processed-record sets,
// which only `convergence` reads; `convergence` is checked by the simulator
// and in a separate run.
module tiny_tlc {
  import membership(DEVICES = Set("a", "b"), MAX_GEN = 2, MAX_NO = 2, WINDOW = 2, MUTANT = "none", TRACK_RECV = false).* from "./membership"
}

// For TLC runs of convergence (S7): the model with the processed-record sets,
// with one number per generation, where records can conflict, halt a node and
// arrive across a root change. Two checkpoints arriving out of order need two
// numbers; that case is a fixed scenario and the probe need_next.
module conv_tlc {
  import membership(DEVICES = Set("a", "b"), MAX_GEN = 2, MAX_NO = 1, WINDOW = 1, MUTANT = "none", TRACK_RECV = true).* from "./membership"
}

// For TLC runs of the liveness property haltPropagates: one passport and one
// checkpoint number per generation, enough for a halt (two records with one
// number) and a permanent halt (two root change records).
module live_tlc {
  import membership(DEVICES = Set("a", "b"), MAX_GEN = 2, MAX_NO = 1, WINDOW = 1, MUTANT = "none", TRACK_RECV = false).* from "./membership"
}
module probe_halted_silent_live { import membership(DEVICES = Set("a", "b"), MAX_GEN = 2, MAX_NO = 1, WINDOW = 1, MUTANT = "halted_silent", TRACK_RECV = false).* from "./membership" }
