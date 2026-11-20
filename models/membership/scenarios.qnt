// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 HunterEwok
//
// Fixed scenarios (`quint test`). Some defects need a long, specific sequence
// that random simulation rarely produces; each such probe also has a scenario
// here that drives the model straight to it.

// Data sent under passport 1 of generation 1 must not be accepted after a root
// change, even though the new Root reissued passport number 1 to the same
// device (R-MEM-12).
module scenarios {
  import membership(DEVICES = Set("a", "b"), MAX_GEN = 2, MAX_NO = 2, MUTANT = "none").* from "./membership"

  val oldData = { src: "b", ppNo: 1, gen: 1, cpNo: 0 }

  run oldGenerationDataIsDroppedTest =
    init
      .then(rootIssue("b", 1, Set()))
      .then(nodeSend("b"))
      .then(recoveryChange)
      .then(rootIssue("b", 1, Set()))
      .then(nodeRecvRc("a", { gen: 2, key: 0 }))
      .then(nodeRecvCp("a", { gen: 2, no: 1, valid: Set(1), nextNo: 2 }))
      .then(nodeRecvPp("a", { gen: 2, no: 1, dev: "b", rights: 1 }))
      .expect(pool.data.contains(oldData) and nodes.get("a").pps.size() == 1)
      .then(nodeAcceptData("a", oldData))
      .fail()
}

module scenarios_probe_accept_old_data_gen {
  import membership(DEVICES = Set("a", "b"), MAX_GEN = 2, MAX_NO = 2, MUTANT = "accept_old_data_gen").* from "./membership"

  val oldData = { src: "b", ppNo: 1, gen: 1, cpNo: 0 }

  run oldGenerationDataViolatesSafetyTest =
    init
      .then(rootIssue("b", 1, Set()))
      .then(nodeSend("b"))
      .then(recoveryChange)
      .then(rootIssue("b", 1, Set()))
      .then(nodeRecvRc("a", { gen: 2, key: 0 }))
      .then(nodeRecvCp("a", { gen: 2, no: 1, valid: Set(1), nextNo: 2 }))
      .then(nodeRecvPp("a", { gen: 2, no: 1, dev: "b", rights: 1 }))
      .then(nodeAcceptData("a", oldData))
      .expect(not(safety))
}
