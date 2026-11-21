// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 HunterEwok
//
// Fixed scenarios (`quint test`). Each drives the model straight to a case
// that matters, and the matching probe shows the defect on the same steps.

// S11, R-STR-3: the target reboots and opens a new stream under the same
// number for a new call. A chunk of the old stream, still in the network,
// does not decrypt under the new key and is dropped without any change.
module scenarios {
  import streams(MAX_STREAMS = 1, MAX_CALLS = 2, MAX_NO = 2, MAX_CREDIT = 1, MAX_EVENTS = 2, MUTANT = "none").* from "./streams"

  // The commander's call k, ordered, with credit 1 for the target.
  action startCall(k: int): bool = all {
    val call = { k: k, mode: "ordered", credit: 1 }
    commitWith(nodes, pending.put(k, call), done, calls.union(Set(call)), replies, pool, k + 1, Set(), Set()),
  }
  def replyTo(k: int): Reply = replies.filter(r => r.k == k).fold({ k: 0, sid: 0, credit: 0, ok: false }, (a, r) => r)
  val old = { dir: "t2c", sid: 1, k: 1, no: 1, kind: "data", credit: 0 }

  run staleChunkIsDroppedTest =
    init
      .then(startCall(1))
      .then(targetOpen({ k: 1, mode: "ordered", credit: 1 }))
      .then(commanderReply(replyTo(1)))
      .then(sendChunk("T", 1, nodes.get("T").streams.get(1), "data", 0))
      .expect(pool.contains(old))
      .then(reboot("T"))
      .then(startCall(2))
      .then(targetOpen({ k: 2, mode: "ordered", credit: 1 }))
      .then(commanderReply(replyTo(2)))
      .expect(nodes.get("C").streams.get(1).k == 2)
      .then(receive("C", old))
      .expect(nodes.get("C").streams.get(1).high == 0 and seen.contains("staleDropped") and safety)
}

module scenarios_probe_id_only {
  import streams(MAX_STREAMS = 1, MAX_CALLS = 2, MAX_NO = 2, MAX_CREDIT = 1, MAX_EVENTS = 2, MUTANT = "id_only").* from "./streams"

  action startCall(k: int): bool = all {
    val call = { k: k, mode: "ordered", credit: 1 }
    commitWith(nodes, pending.put(k, call), done, calls.union(Set(call)), replies, pool, k + 1, Set(), Set()),
  }
  def replyTo(k: int): Reply = replies.filter(r => r.k == k).fold({ k: 0, sid: 0, credit: 0, ok: false }, (a, r) => r)
  val old = { dir: "t2c", sid: 1, k: 1, no: 1, kind: "data", credit: 0 }

  run staleChunkIsTakenTest =
    init
      .then(startCall(1))
      .then(targetOpen({ k: 1, mode: "ordered", credit: 1 }))
      .then(commanderReply(replyTo(1)))
      .then(sendChunk("T", 1, nodes.get("T").streams.get(1), "data", 0))
      .then(reboot("T"))
      .then(startCall(2))
      .then(targetOpen({ k: 2, mode: "ordered", credit: 1 }))
      .then(commanderReply(replyTo(2)))
      .then(receive("C", old))
      .expect(not(chunkBinding))
}

// R-STR-5: "reset nonces" closes only a stream without traffic since the
// previous reset. Here the stream carries a chunk between the two resets
// and stays open; a third reset, after a quiet period, closes it.
module scenarios_reset {
  import streams(MAX_STREAMS = 1, MAX_CALLS = 2, MAX_NO = 2, MAX_CREDIT = 1, MAX_EVENTS = 3, MUTANT = "none").* from "./streams"

  action startCall(k: int): bool = all {
    val call = { k: k, mode: "lossy", credit: 0 }
    commitWith(nodes, pending.put(k, call), done, calls.union(Set(call)), replies, pool, k + 1, Set(), Set()),
  }

  run resetClosesOnlyIdleTest =
    init
      .then(startCall(1))
      .then(targetOpen({ k: 1, mode: "lossy", credit: 0 }))
      .then(resetNonces("T"))
      .expect(nodes.get("T").streams.keys() == Set(1))
      .then(sendChunk("T", 1, nodes.get("T").streams.get(1), "data", 0))
      .then(resetNonces("T"))
      .expect(nodes.get("T").streams.keys() == Set(1))
      .then(resetNonces("T"))
      .expect(nodes.get("T").streams.keys() == Set() and safety)
}
