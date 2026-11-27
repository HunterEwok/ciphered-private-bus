// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 HunterEwok
//
// Fixed scenarios (`quint test`). Each drives the model straight to a case
// that matters, and the matching probe shows the defect on the same steps.

// R-REL-19: member "b" sleeps through a root change. The root device bridges
// the old alias, registers the new one and closes the old one. "b" wakes up
// with the checkpoint of the old generation, fetches its bridge, takes the
// checkpoint served with it and accepts the relay access object of the new
// generation.
module scenarios {
  import extrelay(MEMBERS = Set("a", "b"), FIRST = Set("a", "b"), MAX_E = 2, MAX_RD = 1, MAX_GEN = 2, MAX_EVENTS = 1, MUTANT = "none").* from "./extrelay"

  val a1 = { g: 1, rd: 0, e: 1 }
  val a2 = { g: 2, rd: 0, e: 1 }
  val bridgeB = { a: a1, to: "b", next: a2, cpNo: 2 }

  run sleeperFollowsRootChangeTest =
    init
      .then(rootChange)
      .then(rootBridges)
      .then(rootRegister)
      .then(rootClose)
      .expect(tickets.get(a1).closed and bridges.contains(bridgeB) and nodes.get("b").cpGen == 1)
      .then(nodeBridge("b", "b", bridgeB))
      .expect(nodes.get("b").ra == a2 and nodes.get("b").cpGen == 2 and not(bridges.contains(bridgeB)) and safety)
}

module scenarios_probe_bridge_without_records {
  import extrelay(MEMBERS = Set("a", "b"), FIRST = Set("a", "b"), MAX_E = 2, MAX_RD = 1, MAX_GEN = 2, MAX_EVENTS = 1, MUTANT = "bridge_without_records").* from "./extrelay"

  val a1 = { g: 1, rd: 0, e: 1 }
  val a2 = { g: 2, rd: 0, e: 1 }
  val bridgeB = { a: a1, to: "b", next: a2, cpNo: 2 }

  run sleeperIsStrandedTest =
    init
      .then(rootChange)
      .then(rootBridges)
      .then(rootRegister)
      .then(rootClose)
      .then(nodeBridge("b", "b", bridgeB))
      .expect(not(nodes.get("b").keys.contains(a2)) and not(bridgeForEveryMember))
}

// R-REL-13, B.10 relay access rule: the root device is lost and replaced.
// The stolen key of the old root device signs a relay access object with an
// epoch far ahead. A member that has taken the checkpoint naming the new
// root device refuses it, and accepts epoch 1 of the new root device.
module scenarios_far_epoch {
  import extrelay(MEMBERS = Set("a", "b"), FIRST = Set("a", "b"), MAX_E = 3, MAX_RD = 2, MAX_GEN = 1, MAX_EVENTS = 1, MUTANT = "none").* from "./extrelay"

  val far = { g: 1, rd: 0, e: 3, dev: "a" }
  val fresh = { g: 1, rd: 1, e: 1, dev: "a" }

  run farEpochIsRefusedTest =
    init
      .then(newRootDevice)
      .then(adversaryForge(3, "a"))
      .then(nodeCheckpoint("a"))
      .expect(nodes.get("a").ra == NONE and not(acceptable(nodes.get("a"), far)))
      .then(nodeAccess("a", fresh))
      .expect(nodes.get("a").ra == aliasOf(fresh) and tookForged == Set() and safety)
}

// With objects ordered by epoch alone, the member keeps the forged object of
// the old root device and can no longer accept epoch 1 of the new one.
module scenarios_probe_epoch_only_order {
  import extrelay(MEMBERS = Set("a", "b"), FIRST = Set("a", "b"), MAX_E = 3, MAX_RD = 2, MAX_GEN = 1, MAX_EVENTS = 1, MUTANT = "epoch_only_order").* from "./extrelay"

  val far = { g: 1, rd: 0, e: 3, dev: "a" }
  val fresh = { g: 1, rd: 1, e: 1, dev: "a" }

  run farEpochLocksOutTest =
    init
      .then(newRootDevice)
      .then(adversaryForge(3, "a"))
      .then(nodeAccess("a", far))
      .then(nodeCheckpoint("a"))
      .expect(nodes.get("a").ra == { g: 1, rd: 0, e: 3 } and not(acceptable(nodes.get("a"), fresh))
              and not(accessOfNamedRoot))
}

// R-REL-13, R-REL-19: a revoked member gets no bridge and no relay access
// object of the new epoch, and the remaining member is bridged.
module scenarios_revoke {
  import extrelay(MEMBERS = Set("a", "b"), FIRST = Set("a", "b"), MAX_E = 2, MAX_RD = 1, MAX_GEN = 1, MAX_EVENTS = 1, MUTANT = "none").* from "./extrelay"

  val a1 = { g: 1, rd: 0, e: 1 }
  val a2 = { g: 1, rd: 0, e: 2 }

  run revokedIsNotBridgedTest =
    init
      .then(rootRevoke("b"))
      .then(rootBridges)
      .expect(bridges == Set({ a: a1, to: "a", next: a2, cpNo: 2 })
              and not(access.exists(x => x.dev == "b" and x.e == 2)))
      .then(rootRegister)
      .then(rootClose)
      .expect(tickets.get(a1).closed and objs.forall(o => o.a != a1) and safety)
}
