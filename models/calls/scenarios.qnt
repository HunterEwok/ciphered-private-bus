// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 HunterEwok
//
// Fixed scenarios for behaviours that random simulation rarely reaches: the
// correct model must reach them with safety intact, and each probe listed
// here must violate safety after the same steps (R-VER-2).

module scenarios {
  import calls(COMMANDERS = Set("a"), OUTSIDERS = Set(), ROOT = "r", PRESENCE = Set("a"),
               RIGHTS = Map("a" -> Set(1, 2)), MAX_NONCE = 4, MAX_EPOCH = 3, MAX_CALLS = 2, MAX_RESETS = 1,
               MUTANT = "none").* from "./calls"

  val x1 = { cmd: "a", id: 1, idem: false, act: 1, key: "device", nonce: 1, epoch: 1 }

  // An executed call whose reply is withheld is replayed: the target refuses
  // it with the next nonce, and the commander reports the outcome as unknown
  // instead of retrying (R-CALL-13, S10).
  run replayNotRetriedTest =
    init
      .then(targetAnswer("a"))
      .then(cmdLearn("a", 1))
      .then(cmdStart("a", 1, false, "device"))
      .then(targetCall(x1))
      .then(targetCall(x1))
      .expect(shown.contains(2) and executed.size() == 1)
      .then(cmdMismatch("a", 2))
      .expect(not(cmds.get("a").pending.active) and calls == Set(x1) and safety)

  // A call sealed to a retired key epoch is refused before the nonce check
  // consumes anything; the commander retries once with the same nonce and the
  // new key, and the retry is executed; the original body then no longer
  // matches (R-CALL-13).
  run epochRetryTest =
    init
      .then(targetAnswer("a"))
      .then(cmdLearn("a", 1))
      .then(cmdStart("a", 1, false, "device"))
      .then(targetRotate)
      .then(targetRotate)
      .then(targetCall(x1))
      .expect(slots.get("a") == 1 and seen.contains("staleEpoch"))
      .then(cmdEpoch("a", 3))
      .then(targetCall({ ...x1, epoch: 3 }))
      .expect(seen.contains("epochRetryExecuted") and safety)
      .then(targetCall(x1))
      .expect(executed.size() == 1 and safety)

  // A confirmation-class call is not retried after a newer key claim
  // (R-CALL-13).
  run confirmNotRetriedTest =
    init
      .then(targetAnswer("a"))
      .then(cmdLearn("a", 1))
      .then(cmdStart("a", 2, false, "presence"))
      .then(targetRotate)
      .then(cmdEpoch("a", 2))
      .expect(not(cmds.get("a").pending.active) and calls.size() == 1 and safety)

  // "Reset nonces" erases the slot, so a call over a nonce issued before it
  // is refused (R-CALL-8).
  run resetTest =
    init
      .then(targetAnswer("a"))
      .then(cmdLearn("a", 1))
      .then(cmdStart("a", 1, false, "device"))
      .then(targetReset("reset"))
      .then(targetCall(x1))
      .expect(executed == Set() and seen.contains("staleNonce") and safety)
}

module scenarios_probe_retry_on_mismatch {
  import calls(COMMANDERS = Set("a"), OUTSIDERS = Set(), ROOT = "r", PRESENCE = Set("a"),
               RIGHTS = Map("a" -> Set(1, 2)), MAX_NONCE = 4, MAX_EPOCH = 3, MAX_CALLS = 2, MAX_RESETS = 1,
               MUTANT = "retry_on_mismatch").* from "./calls"

  val x1 = { cmd: "a", id: 1, idem: false, act: 1, key: "device", nonce: 1, epoch: 1 }

  run retryOnMismatchViolatesSafetyTest =
    init
      .then(targetAnswer("a"))
      .then(cmdLearn("a", 1))
      .then(cmdStart("a", 1, false, "device"))
      .then(targetCall(x1))
      .then(targetCall(x1))
      .then(cmdMismatch("a", 2))
      .then(targetCall({ ...x1, nonce: 2 }))
      .expect(not(safety))
}
