// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 HunterEwok
//
// Instances of the relay model. `small` and `tiny` are checked in CI; each
// `probe_*` instance contains one deliberate defect and is expected to violate
// `safety` (R-VER-2).

module small {
  import relay(N_DEV = 3, CHANS = Set(1, 2), MAX_NO = 3, MAX_DEPTH = 2, SIZES = Set(1, 2), SOURCE_BYTES = 3, BUS_BYTES = 5, JOIN_MAX = 2, MAX_ARR = 8, MAX_EVENTS = 4, MUTANT = "none").* from "./relay"
}

module tiny {
  import relay(N_DEV = 2, CHANS = Set(1), MAX_NO = 2, MAX_DEPTH = 1, SIZES = Set(1, 2), SOURCE_BYTES = 2, BUS_BYTES = 3, JOIN_MAX = 1, MAX_ARR = 4, MAX_EVENTS = 3, MUTANT = "none").* from "./relay"
}
module probe_no_verify { import relay(N_DEV = 2, CHANS = Set(1), MAX_NO = 2, MAX_DEPTH = 1, SIZES = Set(1, 2), SOURCE_BYTES = 2, BUS_BYTES = 3, JOIN_MAX = 1, MAX_ARR = 4, MAX_EVENTS = 3, MUTANT = "no_verify").* from "./relay" }
module probe_store_call { import relay(N_DEV = 2, CHANS = Set(1), MAX_NO = 2, MAX_DEPTH = 1, SIZES = Set(1, 2), SOURCE_BYTES = 2, BUS_BYTES = 3, JOIN_MAX = 1, MAX_ARR = 4, MAX_EVENTS = 3, MUTANT = "store_call").* from "./relay" }
module probe_store_depth0 { import relay(N_DEV = 2, CHANS = Set(1), MAX_NO = 2, MAX_DEPTH = 1, SIZES = Set(1, 2), SOURCE_BYTES = 2, BUS_BYTES = 3, JOIN_MAX = 1, MAX_ARR = 4, MAX_EVENTS = 3, MUTANT = "store_depth0").* from "./relay" }
module probe_serve_ungranted { import relay(N_DEV = 2, CHANS = Set(1), MAX_NO = 2, MAX_DEPTH = 1, SIZES = Set(1, 2), SOURCE_BYTES = 2, BUS_BYTES = 3, JOIN_MAX = 1, MAX_ARR = 4, MAX_EVENTS = 3, MUTANT = "serve_ungranted").* from "./relay" }
module probe_keep_revoked { import relay(N_DEV = 2, CHANS = Set(1), MAX_NO = 2, MAX_DEPTH = 1, SIZES = Set(1, 2), SOURCE_BYTES = 2, BUS_BYTES = 3, JOIN_MAX = 1, MAX_ARR = 4, MAX_EVENTS = 3, MUTANT = "keep_revoked").* from "./relay" }
module probe_accept_revoked { import relay(N_DEV = 2, CHANS = Set(1), MAX_NO = 2, MAX_DEPTH = 1, SIZES = Set(1, 2), SOURCE_BYTES = 2, BUS_BYTES = 3, JOIN_MAX = 1, MAX_ARR = 4, MAX_EVENTS = 3, MUTANT = "accept_revoked").* from "./relay" }
module probe_over_quota { import relay(N_DEV = 2, CHANS = Set(1), MAX_NO = 2, MAX_DEPTH = 1, SIZES = Set(1, 2), SOURCE_BYTES = 2, BUS_BYTES = 3, JOIN_MAX = 1, MAX_ARR = 4, MAX_EVENTS = 3, MUTANT = "over_quota").* from "./relay" }
module probe_evict_other { import relay(N_DEV = 2, CHANS = Set(1), MAX_NO = 2, MAX_DEPTH = 2, SIZES = Set(1, 2), SOURCE_BYTES = 3, BUS_BYTES = 3, JOIN_MAX = 1, MAX_ARR = 4, MAX_EVENTS = 3, MUTANT = "evict_other").* from "./relay" }
module probe_evict_grant { import relay(N_DEV = 2, CHANS = Set(1), MAX_NO = 2, MAX_DEPTH = 1, SIZES = Set(1, 2), SOURCE_BYTES = 2, BUS_BYTES = 3, JOIN_MAX = 1, MAX_ARR = 4, MAX_EVENTS = 3, MUTANT = "evict_grant").* from "./relay" }
module probe_unfair { import relay(N_DEV = 2, CHANS = Set(1), MAX_NO = 2, MAX_DEPTH = 2, SIZES = Set(1, 2), SOURCE_BYTES = 3, BUS_BYTES = 3, JOIN_MAX = 1, MAX_ARR = 4, MAX_EVENTS = 3, MUTANT = "unfair").* from "./relay" }
module probe_grant_downgrade { import relay(N_DEV = 2, CHANS = Set(1), MAX_NO = 2, MAX_DEPTH = 1, SIZES = Set(1, 2), SOURCE_BYTES = 2, BUS_BYTES = 3, JOIN_MAX = 1, MAX_ARR = 4, MAX_EVENTS = 3, MUTANT = "grant_downgrade").* from "./relay" }
module probe_two_requests { import relay(N_DEV = 2, CHANS = Set(1), MAX_NO = 2, MAX_DEPTH = 1, SIZES = Set(1, 2), SOURCE_BYTES = 2, BUS_BYTES = 3, JOIN_MAX = 1, MAX_ARR = 4, MAX_EVENTS = 3, MUTANT = "two_requests").* from "./relay" }
module probe_retain_all { import relay(N_DEV = 2, CHANS = Set(1), MAX_NO = 2, MAX_DEPTH = 1, SIZES = Set(1, 2), SOURCE_BYTES = 2, BUS_BYTES = 3, JOIN_MAX = 1, MAX_ARR = 4, MAX_EVENTS = 3, MUTANT = "retain_all").* from "./relay" }
module probe_join_unbounded { import relay(N_DEV = 2, CHANS = Set(1), MAX_NO = 2, MAX_DEPTH = 1, SIZES = Set(1, 2), SOURCE_BYTES = 2, BUS_BYTES = 3, JOIN_MAX = 1, MAX_ARR = 4, MAX_EVENTS = 3, MUTANT = "join_unbounded").* from "./relay" }
module probe_join_drop_new { import relay(N_DEV = 2, CHANS = Set(1), MAX_NO = 2, MAX_DEPTH = 1, SIZES = Set(1, 2), SOURCE_BYTES = 2, BUS_BYTES = 3, JOIN_MAX = 1, MAX_ARR = 4, MAX_EVENTS = 3, MUTANT = "join_drop_new").* from "./relay" }
module probe_keep_unserved { import relay(N_DEV = 2, CHANS = Set(1), MAX_NO = 2, MAX_DEPTH = 1, SIZES = Set(1, 2), SOURCE_BYTES = 2, BUS_BYTES = 3, JOIN_MAX = 1, MAX_ARR = 4, MAX_EVENTS = 3, MUTANT = "keep_unserved").* from "./relay" }
module probe_cp_rollback { import relay(N_DEV = 2, CHANS = Set(1), MAX_NO = 2, MAX_DEPTH = 1, SIZES = Set(1, 2), SOURCE_BYTES = 2, BUS_BYTES = 3, JOIN_MAX = 1, MAX_ARR = 4, MAX_EVENTS = 3, MUTANT = "cp_rollback").* from "./relay" }
module probe_cp_number_only { import relay(N_DEV = 2, CHANS = Set(1), MAX_NO = 2, MAX_DEPTH = 1, SIZES = Set(1, 2), SOURCE_BYTES = 2, BUS_BYTES = 3, JOIN_MAX = 1, MAX_ARR = 4, MAX_EVENTS = 3, MUTANT = "cp_number_only").* from "./relay" }
module probe_old_gen_cp { import relay(N_DEV = 2, CHANS = Set(1), MAX_NO = 2, MAX_DEPTH = 1, SIZES = Set(1, 2), SOURCE_BYTES = 2, BUS_BYTES = 3, JOIN_MAX = 1, MAX_ARR = 4, MAX_EVENTS = 3, MUTANT = "old_gen_cp").* from "./relay" }
