// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 HunterEwok
//
// Instances of the calls model. `small` and `tiny` are checked in CI; each
// `probe_*` instance contains one deliberate defect and is expected to violate
// `safety` (R-VER-2).

module small {
  import calls(COMMANDERS = Set("a", "b"), OUTSIDERS = Set("x"), ROOT = "r", PRESENCE = Set("b"), RIGHTS = Map("a" -> Set(1), "b" -> Set(1, 2)), MAX_NONCE = 6, MAX_EPOCH = 3, MAX_CALLS = 2, MAX_RESETS = 2, MUTANT = "none").* from "./calls"
}

module tiny {
  import calls(COMMANDERS = Set("a"), OUTSIDERS = Set(), ROOT = "r", PRESENCE = Set("a"), RIGHTS = Map("a" -> Set(1, 2)), MAX_NONCE = 4, MAX_EPOCH = 3, MAX_CALLS = 2, MAX_RESETS = 1, MUTANT = "none").* from "./calls"
}
module probe_no_erase { import calls(COMMANDERS = Set("a", "b"), OUTSIDERS = Set("x"), ROOT = "r", PRESENCE = Set("b"), RIGHTS = Map("a" -> Set(1), "b" -> Set(1, 2)), MAX_NONCE = 6, MAX_EPOCH = 3, MAX_CALLS = 2, MAX_RESETS = 2, MUTANT = "no_erase").* from "./calls" }
module probe_mismatch_changes { import calls(COMMANDERS = Set("a", "b"), OUTSIDERS = Set("x"), ROOT = "r", PRESENCE = Set("b"), RIGHTS = Map("a" -> Set(1), "b" -> Set(1, 2)), MAX_NONCE = 6, MAX_EPOCH = 3, MAX_CALLS = 2, MAX_RESETS = 2, MUTANT = "mismatch_changes").* from "./calls" }
module probe_slot_for_anyone { import calls(COMMANDERS = Set("a", "b"), OUTSIDERS = Set("x"), ROOT = "r", PRESENCE = Set("b"), RIGHTS = Map("a" -> Set(1), "b" -> Set(1, 2)), MAX_NONCE = 6, MAX_EPOCH = 3, MAX_CALLS = 2, MAX_RESETS = 2, MUTANT = "slot_for_anyone").* from "./calls" }
module probe_no_right_check { import calls(COMMANDERS = Set("a", "b"), OUTSIDERS = Set("x"), ROOT = "r", PRESENCE = Set("b"), RIGHTS = Map("a" -> Set(1), "b" -> Set(1, 2)), MAX_NONCE = 6, MAX_EPOCH = 3, MAX_CALLS = 2, MAX_RESETS = 2, MUTANT = "no_right_check").* from "./calls" }
module probe_presence_not_required { import calls(COMMANDERS = Set("a", "b"), OUTSIDERS = Set("x"), ROOT = "r", PRESENCE = Set("b"), RIGHTS = Map("a" -> Set(1), "b" -> Set(1, 2)), MAX_NONCE = 6, MAX_EPOCH = 3, MAX_CALLS = 2, MAX_RESETS = 2, MUTANT = "presence_not_required").* from "./calls" }
module probe_revoked_calls { import calls(COMMANDERS = Set("a", "b"), OUTSIDERS = Set("x"), ROOT = "r", PRESENCE = Set("b"), RIGHTS = Map("a" -> Set(1), "b" -> Set(1, 2)), MAX_NONCE = 6, MAX_EPOCH = 3, MAX_CALLS = 2, MAX_RESETS = 2, MUTANT = "revoked_calls").* from "./calls" }
module probe_retry_on_mismatch { import calls(COMMANDERS = Set("a", "b"), OUTSIDERS = Set("x"), ROOT = "r", PRESENCE = Set("b"), RIGHTS = Map("a" -> Set(1), "b" -> Set(1, 2)), MAX_NONCE = 6, MAX_EPOCH = 3, MAX_CALLS = 2, MAX_RESETS = 2, MUTANT = "retry_on_mismatch").* from "./calls" }
module probe_retry_confirmation { import calls(COMMANDERS = Set("a", "b"), OUTSIDERS = Set("x"), ROOT = "r", PRESENCE = Set("b"), RIGHTS = Map("a" -> Set(1), "b" -> Set(1, 2)), MAX_NONCE = 6, MAX_EPOCH = 3, MAX_CALLS = 2, MAX_RESETS = 2, MUTANT = "retry_confirmation").* from "./calls" }
module probe_accept_any_epoch { import calls(COMMANDERS = Set("a", "b"), OUTSIDERS = Set("x"), ROOT = "r", PRESENCE = Set("b"), RIGHTS = Map("a" -> Set(1), "b" -> Set(1, 2)), MAX_NONCE = 6, MAX_EPOCH = 3, MAX_CALLS = 2, MAX_RESETS = 2, MUTANT = "accept_any_epoch").* from "./calls" }
module probe_reset_keeps_slots { import calls(COMMANDERS = Set("a", "b"), OUTSIDERS = Set("x"), ROOT = "r", PRESENCE = Set("b"), RIGHTS = Map("a" -> Set(1), "b" -> Set(1, 2)), MAX_NONCE = 6, MAX_EPOCH = 3, MAX_CALLS = 2, MAX_RESETS = 2, MUTANT = "reset_keeps_slots").* from "./calls" }
module probe_reboot_keeps_slots { import calls(COMMANDERS = Set("a", "b"), OUTSIDERS = Set("x"), ROOT = "r", PRESENCE = Set("b"), RIGHTS = Map("a" -> Set(1), "b" -> Set(1, 2)), MAX_NONCE = 6, MAX_EPOCH = 3, MAX_CALLS = 2, MAX_RESETS = 2, MUTANT = "reboot_keeps_slots").* from "./calls" }
module probe_keep_revoked_slot { import calls(COMMANDERS = Set("a", "b"), OUTSIDERS = Set("x"), ROOT = "r", PRESENCE = Set("b"), RIGHTS = Map("a" -> Set(1), "b" -> Set(1, 2)), MAX_NONCE = 6, MAX_EPOCH = 3, MAX_CALLS = 2, MAX_RESETS = 2, MUTANT = "keep_revoked_slot").* from "./calls" }
