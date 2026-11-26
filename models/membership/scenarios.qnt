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
  import membership(DEVICES = Set("a", "b"), MAX_GEN = 2, MAX_NO = 2, WINDOW = 2, MUTANT = "none", TRACK_RECV = true).* from "./membership"

  val oldData = { src: "b", ppNo: 1, gen: 1, cpNo: 0, ch0: false }

  run oldGenerationDataIsDroppedTest =
    init
      .then(rootIssue("b", 3, Set()))
      .then(nodeSend("b"))
      .then(recoveryChange)
      .then(rootIssue("b", 3, Set()))
      .then(nodeRecvRc("a", { gen: 2, key: 0 }))
      .then(nodeRecvCp("a", { gen: 2, no: 1, start: 1, valid: Set(1), nextNo: 2 }))
      .then(nodeRecvPp("a", { gen: 2, no: 1, dev: "b", rights: 3 }))
      .expect(pool.data.exists(m => m.src == "b" and m.ppNo == 1 and m.gen == 1) and nodes.get("a").pps.size() == 1)
      .then(nodeAcceptData("a", oldData))
      .fail()

  // The case the model found (R-MEM-6, R-MEM-10): a proof of generation 2
  // reaches b while b is still in generation 1 and is dropped; after the root
  // change b talks to the halted peer a and gets the proof again.
  val proof = { kind: "pp", gen: 2, no: 1 }

  run droppedProofComesBackTest =
    init
      .then(recoveryChange)
      .then(rootIssue("a", 1, Set()))
      .then(rootEquivocatePp)
      .then(nodeRecvRc("a", { gen: 2, key: 0 }))
      .then(nodeRecvCp("a", { gen: 2, no: 1, start: 1, valid: Set(1), nextNo: 2 }))
      .then(nodeRecvPp("a", { gen: 2, no: 1, dev: "a", rights: 1 }))
      .then(nodeRecvPp("a", { gen: 2, no: 1, dev: "a", rights: 2 }))
      .expect(nodes.get("a").halted and pool.hp.contains(proof))
      .then(nodeRecvHp("b", proof))
      .expect(not(nodes.get("b").halted) and nodes.get("b").gen == 1)
      .then(nodeRecvRc("b", { gen: 2, key: 0 }))
      .expect(not(nodes.get("b").halted) and nodes.get("b").gen == 2)
      .then(nodeHearsHalted("b"))
      .expect(nodes.get("b").halted and safety)
}

module scenarios_probe_accept_old_data_gen {
  import membership(DEVICES = Set("a", "b"), MAX_GEN = 2, MAX_NO = 2, WINDOW = 2, MUTANT = "accept_old_data_gen", TRACK_RECV = true).* from "./membership"

  val oldData = { src: "b", ppNo: 1, gen: 1, cpNo: 0, ch0: false }

  run oldGenerationDataViolatesSafetyTest =
    init
      .then(rootIssue("b", 3, Set()))
      .then(nodeSend("b"))
      .then(recoveryChange)
      .then(rootIssue("b", 3, Set()))
      .then(nodeRecvRc("a", { gen: 2, key: 0 }))
      .then(nodeRecvCp("a", { gen: 2, no: 1, start: 1, valid: Set(1), nextNo: 2 }))
      .then(nodeRecvPp("a", { gen: 2, no: 1, dev: "b", rights: 3 }))
      .then(nodeAcceptData("a", oldData))
      .expect(not(safety))
}

// Without the answer of R-MEM-6 the dropped proof never comes back.
module scenarios_probe_halted_silent {
  import membership(DEVICES = Set("a", "b"), MAX_GEN = 2, MAX_NO = 2, WINDOW = 2, MUTANT = "halted_silent", TRACK_RECV = true).* from "./membership"

  val proof = { kind: "pp", gen: 2, no: 1 }

  run haltedPeerStaysSilentTest =
    init
      .then(recoveryChange)
      .then(rootIssue("a", 1, Set()))
      .then(rootEquivocatePp)
      .then(nodeRecvRc("a", { gen: 2, key: 0 }))
      .then(nodeRecvCp("a", { gen: 2, no: 1, start: 1, valid: Set(1), nextNo: 2 }))
      .then(nodeRecvPp("a", { gen: 2, no: 1, dev: "a", rights: 1 }))
      .then(nodeRecvPp("a", { gen: 2, no: 1, dev: "a", rights: 2 }))
      .then(nodeRecvHp("b", proof))
      .then(nodeRecvRc("b", { gen: 2, key: 0 }))
      .then(nodeHearsHalted("b"))
      .fail()
}

// S7: two nodes that receive the same two checkpoints in opposite orders end
// at the same one. With "need_next" the node that got the later one first
// drops it and stays behind.
module scenarios_convergence {
  import membership(DEVICES = Set("a", "b"), MAX_GEN = 2, MAX_NO = 2, WINDOW = 2, MUTANT = "none", TRACK_RECV = true).* from "./membership"

  val cp1 = { gen: 1, no: 1, start: 1, valid: Set(1), nextNo: 2 }
  val cp2 = { gen: 1, no: 2, start: 1, valid: Set(1, 2), nextNo: 3 }

  run orderDoesNotMatterTest =
    init
      .then(rootIssue("a", 3, Set()))
      .then(rootIssue("b", 3, Set()))
      .then(nodeRecvCp("a", cp1))
      .then(nodeRecvCp("a", cp2))
      .then(nodeRecvCp("b", cp2))
      .then(nodeRecvCp("b", cp1))
      .expect(nodes.get("a").cp == cp2 and nodes.get("b").cp == cp2 and safety)
}

module scenarios_probe_need_next {
  import membership(DEVICES = Set("a", "b"), MAX_GEN = 2, MAX_NO = 2, WINDOW = 2, MUTANT = "need_next", TRACK_RECV = true).* from "./membership"

  val cp1 = { gen: 1, no: 1, start: 1, valid: Set(1), nextNo: 2 }
  val cp2 = { gen: 1, no: 2, start: 1, valid: Set(1, 2), nextNo: 3 }

  run orderMattersTest =
    init
      .then(rootIssue("a", 3, Set()))
      .then(rootIssue("b", 3, Set()))
      .then(nodeRecvCp("a", cp1))
      .then(nodeRecvCp("a", cp2))
      .then(nodeRecvCp("b", cp2))
      .then(nodeRecvCp("b", cp1))
      .expect(not(convergence))
}

// R-MEM-14: passport 1 is replaced, the window start moves to 2, and the
// replaced passport, which no longer has a bit, leaves the cache.
module scenarios_window {
  import membership(DEVICES = Set("a", "b"), MAX_GEN = 2, MAX_NO = 2, WINDOW = 2, MUTANT = "none", TRACK_RECV = true).* from "./membership"

  val cp1 = { gen: 1, no: 1, start: 1, valid: Set(1), nextNo: 2 }
  val cp2 = { gen: 1, no: 2, start: 2, valid: Set(2), nextNo: 3 }

  run windowMovesPastReplacedTest =
    init
      .then(rootIssue("a", 3, Set()))
      .then(rootIssue("a", 3, Set(1)))
      .expect(pool.cp == Set(cp1, cp2))
      .then(nodeRecvCp("b", cp1))
      .then(nodeRecvPp("b", { gen: 1, no: 1, dev: "a", rights: 3 }))
      .expect(nodes.get("b").pps.size() == 1)
      .then(nodeRecvCp("b", cp2))
      .expect(nodes.get("b").pps == Set() and safety)
}

module scenarios_probe_below_window_valid {
  import membership(DEVICES = Set("a", "b"), MAX_GEN = 2, MAX_NO = 2, WINDOW = 2, MUTANT = "below_window_valid", TRACK_RECV = true).* from "./membership"

  val cp1 = { gen: 1, no: 1, start: 1, valid: Set(1), nextNo: 2 }
  val cp2 = { gen: 1, no: 2, start: 2, valid: Set(2), nextNo: 3 }

  run replacedPassportSurvivesTest =
    init
      .then(rootIssue("a", 3, Set()))
      .then(rootIssue("a", 3, Set(1)))
      .then(nodeRecvCp("b", cp1))
      .then(nodeRecvPp("b", { gen: 1, no: 1, dev: "a", rights: 3 }))
      .then(nodeRecvCp("b", cp2))
      .expect(nodes.get("b").pps.size() == 1 and not(safety))
}
