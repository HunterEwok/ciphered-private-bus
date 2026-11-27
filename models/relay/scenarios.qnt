// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 HunterEwok
//
// Fixed scenarios (`quint test`). Each drives the model straight to a case
// that matters, and the matching probe shows the defect on the same steps.

// S14, B.10 rule 4: source 2 holds one unit, within its fair share of a bus
// of 3 units. Source 1 fills the bus within its own limit; the bus overflows
// and the relay evicts from the source that occupies most, source 1, so
// source 2 keeps its publication.
module scenarios {
  import relay(N_DEV = 2, CHANS = Set(1), MAX_NO = 2, MAX_DEPTH = 2, SIZES = Set(1, 2), SOURCE_BYTES = 3, BUS_BYTES = 3, JOIN_MAX = 1, MAX_ARR = 4, MAX_EVENTS = 3, MUTANT = "none").* from "./relay"

  pure def pub(s: int, no: int, units: int): Obj =
    { kind: "pub", src: s, ch: 1, reader: 0, no: no, gen: 0, depth: 2, size: units, ok: true, arr: 0 }

  run fairShareTest =
    init
      .then(recvPub(pub(2, 1, 1)))
      .then(recvPub(pub(1, 1, 2)))
      .then(recvPub(pub(1, 2, 1)))
      .expect(relay.store.exists(o => o.src == 2) and total(relay.store) <= BUS_BYTES and safety)

  // R-JOIN-8: the buffer holds one request; a second evicts the first.
  run joinOverflowTest =
    init
      .then(recvJoin)
      .then(recvJoin)
      .expect(relay.joins == List(2) and safety)

  // R-REL-6: after the checkpoint that revokes device 2, nothing from or for
  // it is stored, and it gets no hello.
  run revocationPurgesTest =
    init
      .then(recvPub(pub(2, 1, 1)))
      .then(recvGrant({ kind: "grant", src: 1, ch: 1, reader: 2, no: 0, gen: 1, depth: 0, size: 0, ok: true, arr: 0 }))
      .then(rootRevoke(2))
      .then(learnCp(2))
      .expect(relay.store == Set() and safety)
      .then(connect(2))
      .fail()

  // R-REL-3, R-CH-18: the source answers a key request of reader 2 with a
  // grant of the generation the relay already holds, carrying the request's
  // nonce; it replaces the held grant, reaches the connected reader, and the
  // request is deleted.
  pure def grant(no: int): Obj = { kind: "grant", src: 1, ch: 1, reader: 2, no: no, gen: 1, depth: 0, size: 0, ok: true, arr: 0 }
  run sameGenGrantTest =
    init
      .then(recvGrant(grant(0)))
      .then(recvReq({ kind: "req", src: 1, ch: 1, reader: 2, no: 1, gen: 0, depth: 0, size: 0, ok: true, arr: 0 }))
      .then(connect(2))
      .expect(relay.store.exists(o => o.kind == "req"))
      .then(recvGrant(grant(1)))
      .expect(relay.store.filter(o => o.kind != "pub").map(o => (o.kind, o.no)) == Set(("grant", 1)) and safety)
}

module scenarios_probe_unfair {
  import relay(N_DEV = 2, CHANS = Set(1), MAX_NO = 2, MAX_DEPTH = 2, SIZES = Set(1, 2), SOURCE_BYTES = 3, BUS_BYTES = 3, JOIN_MAX = 1, MAX_ARR = 4, MAX_EVENTS = 3, MUTANT = "unfair").* from "./relay"

  pure def pub(s: int, no: int, units: int): Obj =
    { kind: "pub", src: s, ch: 1, reader: 0, no: no, gen: 0, depth: 2, size: units, ok: true, arr: 0 }

  run unfairEvictsSmallTest =
    init
      .then(recvPub(pub(2, 1, 1)))
      .then(recvPub(pub(1, 1, 2)))
      .then(recvPub(pub(1, 2, 1)))
      .expect(not(fairShare))
}

// R-REL-4, B.10 rule 1: source 1 goes over its own limit of 3 units on a bus
// of 6 and evicts its own oldest publication; the publication of source 2
// stays (and `evict_other` evicts it instead).
module scenarios_own_limit {
  import relay(N_DEV = 2, CHANS = Set(1), MAX_NO = 2, MAX_DEPTH = 2, SIZES = Set(1, 2), SOURCE_BYTES = 3, BUS_BYTES = 6, JOIN_MAX = 1, MAX_ARR = 4, MAX_EVENTS = 3, MUTANT = "none").* from "./relay"

  pure def pub(s: int, no: int, units: int): Obj =
    { kind: "pub", src: s, ch: 1, reader: 0, no: no, gen: 0, depth: 2, size: units, ok: true, arr: 0 }

  run ownLimitTest =
    init
      .then(recvPub(pub(2, 1, 1)))
      .then(recvPub(pub(1, 1, 2)))
      .then(recvPub(pub(1, 2, 2)))
      .expect(relay.store.exists(o => o.src == 2) and not(relay.store.exists(o => o.src == 1 and o.no == 1)) and safety)
}

module scenarios_probe_evict_other {
  import relay(N_DEV = 2, CHANS = Set(1), MAX_NO = 2, MAX_DEPTH = 2, SIZES = Set(1, 2), SOURCE_BYTES = 3, BUS_BYTES = 6, JOIN_MAX = 1, MAX_ARR = 4, MAX_EVENTS = 3, MUTANT = "evict_other").* from "./relay"

  pure def pub(s: int, no: int, units: int): Obj =
    { kind: "pub", src: s, ch: 1, reader: 0, no: no, gen: 0, depth: 2, size: units, ok: true, arr: 0 }

  run evictOtherViolatesSafetyTest =
    init
      .then(recvPub(pub(2, 1, 1)))
      .then(recvPub(pub(1, 1, 2)))
      .then(recvPub(pub(1, 2, 2)))
      .expect(not(evictsOnlyOwn))
}
