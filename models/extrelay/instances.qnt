// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 HunterEwok
//
// Instances of the external relay model. `small` and `tiny` are checked in
// CI; each `probe_*` instance contains one deliberate defect and is expected
// to violate `safety` (R-VER-2).

module small {
  import extrelay(MEMBERS = Set("a", "b", "c"), FIRST = Set("a", "b"), MAX_E = 3, MAX_RD = 2, MAX_GEN = 2, MAX_EVENTS = 4, MUTANT = "none").* from "./extrelay"
}

module tiny {
  import extrelay(MEMBERS = Set("a", "b"), FIRST = Set("a"), MAX_E = 2, MAX_RD = 2, MAX_GEN = 2, MAX_EVENTS = 3, MUTANT = "none").* from "./extrelay"
}

module probe_no_new_epoch { import extrelay(MEMBERS = Set("a", "b", "c"), FIRST = Set("a", "b"), MAX_E = 3, MAX_RD = 2, MAX_GEN = 2, MAX_EVENTS = 4, MUTANT = "no_new_epoch").* from "./extrelay" }
module probe_epoch_only_order { import extrelay(MEMBERS = Set("a", "b", "c"), FIRST = Set("a", "b"), MAX_E = 3, MAX_RD = 2, MAX_GEN = 2, MAX_EVENTS = 4, MUTANT = "epoch_only_order").* from "./extrelay" }
module probe_no_rd_check { import extrelay(MEMBERS = Set("a", "b", "c"), FIRST = Set("a", "b"), MAX_E = 3, MAX_RD = 2, MAX_GEN = 2, MAX_EVENTS = 4, MUTANT = "no_rd_check").* from "./extrelay" }
module probe_no_bridges { import extrelay(MEMBERS = Set("a", "b", "c"), FIRST = Set("a", "b"), MAX_E = 3, MAX_RD = 2, MAX_GEN = 2, MAX_EVENTS = 4, MUTANT = "no_bridges").* from "./extrelay" }
module probe_bridge_to_revoked { import extrelay(MEMBERS = Set("a", "b", "c"), FIRST = Set("a", "b"), MAX_E = 3, MAX_RD = 2, MAX_GEN = 2, MAX_EVENTS = 4, MUTANT = "bridge_to_revoked").* from "./extrelay" }
module probe_unlisted_bridges { import extrelay(MEMBERS = Set("a", "b", "c"), FIRST = Set("a", "b"), MAX_E = 3, MAX_RD = 2, MAX_GEN = 2, MAX_EVENTS = 4, MUTANT = "unlisted_bridges").* from "./extrelay" }
module probe_keep_on_close { import extrelay(MEMBERS = Set("a", "b", "c"), FIRST = Set("a", "b"), MAX_E = 3, MAX_RD = 2, MAX_GEN = 2, MAX_EVENTS = 4, MUTANT = "keep_on_close").* from "./extrelay" }
module probe_member_root_obj { import extrelay(MEMBERS = Set("a", "b", "c"), FIRST = Set("a", "b"), MAX_E = 3, MAX_RD = 2, MAX_GEN = 2, MAX_EVENTS = 4, MUTANT = "member_root_obj").* from "./extrelay" }
module probe_hello_no_tree { import extrelay(MEMBERS = Set("a", "b", "c"), FIRST = Set("a", "b"), MAX_E = 3, MAX_RD = 2, MAX_GEN = 2, MAX_EVENTS = 4, MUTANT = "hello_no_tree").* from "./extrelay" }
module probe_ticket_rollback { import extrelay(MEMBERS = Set("a", "b", "c"), FIRST = Set("a", "b"), MAX_E = 3, MAX_RD = 2, MAX_GEN = 2, MAX_EVENTS = 4, MUTANT = "ticket_rollback").* from "./extrelay" }
module probe_bridge_without_records { import extrelay(MEMBERS = Set("a", "b", "c"), FIRST = Set("a", "b"), MAX_E = 3, MAX_RD = 2, MAX_GEN = 2, MAX_EVENTS = 4, MUTANT = "bridge_without_records").* from "./extrelay" }
