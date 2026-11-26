// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 HunterEwok
//
// Instances of the streams model. `small` and `tiny` are checked in CI; each
// `probe_*` instance contains one deliberate defect and is expected to violate
// `safety` (R-VER-2).

module small {
  import streams(MAX_STREAMS = 2, MAX_CALLS = 3, MAX_NO = 3, MAX_CREDIT = 2, MAX_EVENTS = 3, MUTANT = "none").* from "./streams"
}

module tiny {
  import streams(MAX_STREAMS = 1, MAX_CALLS = 2, MAX_NO = 2, MAX_CREDIT = 1, MAX_EVENTS = 2, MUTANT = "none").* from "./streams"
}

module probe_ordered_gap { import streams(MAX_STREAMS = 2, MAX_CALLS = 3, MAX_NO = 3, MAX_CREDIT = 2, MAX_EVENTS = 3, MUTANT = "ordered_gap").* from "./streams" }
module probe_lossy_old { import streams(MAX_STREAMS = 2, MAX_CALLS = 3, MAX_NO = 3, MAX_CREDIT = 2, MAX_EVENTS = 3, MUTANT = "lossy_old").* from "./streams" }
module probe_id_only { import streams(MAX_STREAMS = 2, MAX_CALLS = 3, MAX_NO = 3, MAX_CREDIT = 2, MAX_EVENTS = 3, MUTANT = "id_only").* from "./streams" }
module probe_no_dir { import streams(MAX_STREAMS = 2, MAX_CALLS = 3, MAX_NO = 3, MAX_CREDIT = 2, MAX_EVENTS = 3, MUTANT = "no_dir").* from "./streams" }
module probe_unknown_opens { import streams(MAX_STREAMS = 2, MAX_CALLS = 3, MAX_NO = 3, MAX_CREDIT = 2, MAX_EVENTS = 3, MUTANT = "unknown_opens").* from "./streams" }
module probe_reuse_no { import streams(MAX_STREAMS = 2, MAX_CALLS = 3, MAX_NO = 3, MAX_CREDIT = 2, MAX_EVENTS = 3, MUTANT = "reuse_no").* from "./streams" }
module probe_ignore_credit { import streams(MAX_STREAMS = 2, MAX_CALLS = 3, MAX_NO = 3, MAX_CREDIT = 2, MAX_EVENTS = 3, MUTANT = "ignore_credit").* from "./streams" }
module probe_no_credit_check { import streams(MAX_STREAMS = 2, MAX_CALLS = 3, MAX_NO = 3, MAX_CREDIT = 2, MAX_EVENTS = 3, MUTANT = "no_credit_check").* from "./streams" }
module probe_credit_replay { import streams(MAX_STREAMS = 2, MAX_CALLS = 3, MAX_NO = 3, MAX_CREDIT = 2, MAX_EVENTS = 3, MUTANT = "credit_replay").* from "./streams" }
module probe_evict { import streams(MAX_STREAMS = 2, MAX_CALLS = 3, MAX_NO = 3, MAX_CREDIT = 2, MAX_EVENTS = 3, MUTANT = "evict").* from "./streams" }
module probe_reset_busy { import streams(MAX_STREAMS = 2, MAX_CALLS = 3, MAX_NO = 3, MAX_CREDIT = 2, MAX_EVENTS = 3, MUTANT = "reset_busy").* from "./streams" }
module probe_halt_keeps { import streams(MAX_STREAMS = 2, MAX_CALLS = 3, MAX_NO = 3, MAX_CREDIT = 2, MAX_EVENTS = 3, MUTANT = "halt_keeps").* from "./streams" }
module probe_revoke_keeps { import streams(MAX_STREAMS = 2, MAX_CALLS = 3, MAX_NO = 3, MAX_CREDIT = 2, MAX_EVENTS = 3, MUTANT = "revoke_keeps").* from "./streams" }
