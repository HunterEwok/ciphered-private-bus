// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 HunterEwok
//
// Fixed scenarios for the enrollment model: the correct model must reach them
// with safety intact (R-VER-2).

module scenarios {
  import enrollment(JOINERS = Set("j1"), PRESENCE = Set("j1"), ACCEPTORS = Set("h"), MAX_TID = 4,
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
      .then(advPairJoiner("j1"))
      .then(joinerSend("j1"))
      .then(advPairAcceptor("h"))
      .then(acceptorRequest("h", { tid: 2, joiner: "adv", acceptor: "h" }, p1))
      .fail()

  // A compromised acceptor that read the joiner's code files a request with
  // its own key; the Root reads the fingerprint from the joiner in front of
  // it and admits no other key (R-JOIN-5, R-JOIN-7).
  val pAdv = { key: "adv", presence: "none", name: "adv", tid: 1 }
  run substituteTest =
    init
      .then(pairHonest("j1", "c"))
      .then(badRequest("adv", "none", "adv", 1, pAdv))
      .then(rootAdmit({ key: "adv", presence: "none", name: "adv", tid: 1, signed: pAdv, acceptor: "c" }, "j1"))
      .fail()
}
