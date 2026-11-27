// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 HunterEwok
//
// Fixed scenarios for the enrollment model: the correct model must reach them
// with safety intact (R-VER-2).

module scenarios {
  import enrollment(JOINERS = Set("j1"), PRESENCE = Set("j1"), ACCEPTORS = Set("h"), LIMIT = 2, MAX_TID = 4,
                    MUTANT = "none").* from "./enrollment"

  val p1 = { key: "j1", presence: "j1", name: "j1", tid: 1 }

  // A joiner paired with an honest acceptor is admitted after the owner
  // compares the fingerprint.
  run admitTest =
    init
      .then(pairHonest("j1", "h"))
      .then(joinerSend("j1"))
      .then(acceptorRequest("h", { tid: 1, joiner: "j1", acceptor: "h" }, p1))
      .then(rootAdmit({ key: "j1", presence: "j1", name: "j1", tid: 1, signed: p1, acceptor: "h" }, "j1"))
      .expect(passports == Set({ key: "j1", presence: "j1", name: "j1" }) and safety)

  // A compromised acceptor that drops the joiner's presence key is caught by
  // the joiner's signature (R-JOIN-4).
  run tamperTest =
    init
      .then(pairHonest("j1", "c"))
      .then(joinerSend("j1"))
      .then(badRequest("j1", "none", "j1", 1, p1))
      .expect(inbox == Set() and seen.contains("tampered") and safety)

  // A man in the middle that won a pairing with the joiner relays its payload
  // to an honest acceptor; the payload's transcript does not match the
  // acceptor's session, so no request is made (R-JOIN-4).
  run relayTest =
    init
      .then(advPairJoiner("j1", true))
      .then(joinerSend("j1"))
      .then(advPairAcceptor("h", "j1", true))
      .then(acceptorRequest("h", { tid: 2, joiner: "adv", acceptor: "h" }, p1))
      .fail()

  // The joiner stops after LIMIT attempts with its code (R-JOIN-3).
  run limitTest =
    init
      .then(advPairJoiner("j1", false))
      .then(advPairJoiner("j1", false))
      .then(advPairJoiner("j1", false))
      .fail()
}
