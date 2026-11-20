// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 HunterEwok
//
// Instances of the enrollment model. `small` and `tiny` are checked in CI;
// each `probe_*` instance contains one deliberate defect and is expected to
// violate `safety` (R-VER-2).

module small {
  import enrollment(JOINERS = Set("j1", "j2"), PRESENCE = Set("j1"), ACCEPTORS = Set("h", "root"), LIMIT = 2, MAX_TID = 6, MUTANT = "none").* from "./enrollment"
}

module tiny {
  import enrollment(JOINERS = Set("j1"), PRESENCE = Set("j1"), ACCEPTORS = Set("h"), LIMIT = 2, MAX_TID = 4, MUTANT = "none").* from "./enrollment"
}
module probe_no_fingerprint_compare { import enrollment(JOINERS = Set("j1", "j2"), PRESENCE = Set("j1"), ACCEPTORS = Set("h", "root"), LIMIT = 2, MAX_TID = 6, MUTANT = "no_fingerprint_compare").* from "./enrollment" }
module probe_sig_key_only { import enrollment(JOINERS = Set("j1", "j2"), PRESENCE = Set("j1"), ACCEPTORS = Set("h", "root"), LIMIT = 2, MAX_TID = 6, MUTANT = "sig_key_only").* from "./enrollment" }
module probe_no_transcript_binding { import enrollment(JOINERS = Set("j1", "j2"), PRESENCE = Set("j1"), ACCEPTORS = Set("h", "root"), LIMIT = 2, MAX_TID = 6, MUTANT = "no_transcript_binding").* from "./enrollment" }
module probe_joiner_no_count { import enrollment(JOINERS = Set("j1", "j2"), PRESENCE = Set("j1"), ACCEPTORS = Set("h", "root"), LIMIT = 2, MAX_TID = 6, MUTANT = "joiner_no_count").* from "./enrollment" }
module probe_acceptor_no_count { import enrollment(JOINERS = Set("j1", "j2"), PRESENCE = Set("j1"), ACCEPTORS = Set("h", "root"), LIMIT = 2, MAX_TID = 6, MUTANT = "acceptor_no_count").* from "./enrollment" }
module probe_acceptor_issues { import enrollment(JOINERS = Set("j1", "j2"), PRESENCE = Set("j1"), ACCEPTORS = Set("h", "root"), LIMIT = 2, MAX_TID = 6, MUTANT = "acceptor_issues").* from "./enrollment" }
