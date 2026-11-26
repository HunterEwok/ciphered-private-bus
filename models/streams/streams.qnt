// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 HunterEwok
//
// Streams of Ciphered Private Bus (verification level V2).
//
// Scope: one commander and one target; a stream opened by the reply to a
// call, in ordered or lossy mode, with chunks in both directions, credit,
// the "end" chunk, the limit on open streams, and every event that closes a
// stream: link down, "reset nonces" after a period without traffic, halt,
// revocation of the peer, and reboot. Requirements: R-STR-3..6, R-CORE-6,
// R-MEM-9 (streams of a halted node), the chunk-number half of R-KEY-9;
// properties S5, S8, S11, S14.
//
// Abstractions:
// - The call and its reply are delivered at most once each and cannot be
//   forged: nonce slots are the calls model's (models/calls), and the keys
//   of a stream are the Tamarin calls model's (proofs/calls). Each call
//   creates a new HPKE context, named here by the number `k` of the call:
//   a chunk of one stream instance never decrypts under the key of another,
//   so the receiver's AEAD check is "the chunk's k equals the stream's k".
// - The network is a pool of every call, reply and chunk ever sent; an
//   adversary delivers any of them to either party at any time, any number
//   of times, or never. It cannot forge a chunk: it has no stream key.
// - Bytes are abstracted to units: a data chunk carries one unit, and credit
//   is counted in units. A chunk always fits in a frame.
// - In lossy mode credit does not apply (R-STR-3): the sender sends without
//   credit and the recipient takes what it can; no credit chunks are sent.
// - The commander opens a stream only while it has room for one more; the
//   limit is enforced where the spec places the result code, at the target.
// - The revocation of the peer is learned by each party on its own, as the
//   membership model's checkpoint arrives; the halt is the membership model's.
// - A peer may be faulty or compromised and send data beyond its credit
//   (overrun); the recipient's check of R-STR-4 is what protects it (S14).
module streams {
  // ---------------------------------------------------------------- parameters
  const MAX_STREAMS: int  // open streams per node (profile limit, R-STR-6)
  const MAX_CALLS: int    // calls the commander may start
  const MAX_NO: int       // highest chunk number per direction
  const MAX_CREDIT: int   // largest credit a side may hold out to its peer at once
  const MAX_EVENTS: int   // host and membership events (link down, reset, halt, revocation, reboot)
  const MUTANT: str       // "none", or the name of a deliberate defect (R-VER-2)

  // --------------------------------------------------------------------- types
  val PARTIES = Set("C", "T")
  val MODES = Set("ordered", "lossy")
  val IDS = 1.to(MAX_STREAMS)
  pure def peer(p: str): str = if (p == "C") "T" else "C"
  // The direction a party sends in: bit 0 of the chunk flags (B.7).
  pure def out(p: str): str = if (p == "C") "c2t" else "t2c"

  type Call = { k: int, mode: str, credit: int }
  type Reply = { k: int, sid: int, credit: int, ok: bool }
  type Chunk = { dir: str, sid: int, k: int, no: int, kind: str, credit: int }
  // One side of an open stream. `sendCredit` is what this side may still
  // send, `recvCredit` what it still lets the peer send. The ghost counters
  // `got` and `granted` count all credit received and given, initial credit
  // included; `sent` and `recvd` count data units.
  type Side = {
    k: int, mode: str, next: int, high: int, sendCredit: int, recvCredit: int, idle: bool,
    got: int, granted: int, sent: int, recvd: int,
  }
  type Node = { streams: int -> Side, halted: bool, peerRevoked: bool }

  // ----------------------------------------------------------------- variables
  var nodes: str -> Node
  var pending: int -> Call        // commander: calls that requested a stream and await their reply
  var done: Set[int]              // target: calls it has executed (at most once, R-CALL-5)
  var calls: Set[Call]            // pool
  var replies: Set[Reply]         // pool
  var pool: Set[Chunk]            // pool of chunks
  var nextK: int
  var events: int                 // events so far, bounded so that streams live long enough to matter
  // Monitor: properties of a single step are checked when it is taken, and
  // the name of a violated one is added here.
  var broken: Set[str]
  var seen: Set[str]              // ghost: behaviours that happened (witnesses)

  // ------------------------------------------------------------------- helpers
  pure def newSide(k: int, mode: str, sendCredit: int, recvCredit: int): Side = {
    k: k, mode: mode, next: 1, high: 0, sendCredit: sendCredit, recvCredit: recvCredit, idle: false,
    got: sendCredit, granted: recvCredit, sent: 0, recvd: 0,
  }
  pure def initNode: Node = { streams: Map(), halted: false, peerRevoked: false }

  pure def without(m: int -> Side, sid: int): int -> Side =
    m.keys().exclude(Set(sid)).mapBy(x => m.get(x))

  action commitWith(n2: str -> Node, pe2: int -> Call, d2: Set[int], c2: Set[Call], r2: Set[Reply],
                    p2: Set[Chunk], k2: int, extra: Set[str], tags: Set[str]): bool = all {
    nodes' = n2, pending' = pe2, done' = d2, calls' = c2, replies' = r2, pool' = p2, nextK' = k2,
    events' = events, broken' = broken.union(extra), seen' = seen.union(tags),
  }

  // An event: the same as commitWith, and it counts.
  action eventWith(n2: str -> Node, pe2: int -> Call, extra: Set[str], tags: Set[str]): bool = all {
    events < MAX_EVENTS,
    nodes' = n2, pending' = pe2, done' = done, calls' = calls, replies' = replies, pool' = pool, nextK' = nextK,
    events' = events + 1, broken' = broken.union(extra), seen' = seen.union(tags),
  }

  action setNodes(n2: str -> Node, p2: Set[Chunk], extra: Set[str], tags: Set[str]): bool =
    commitWith(n2, pending, done, calls, replies, p2, nextK, extra, tags)

  // -------------------------------------------------------------- initial state
  action init = all {
    nodes' = PARTIES.mapBy(p => initNode),
    pending' = Map(),
    done' = Set(),
    calls' = Set(),
    replies' = Set(),
    pool' = Set(),
    nextK' = 1,
    events' = 0,
    broken' = Set(),
    seen' = Set(),
  }

  // ------------------------------------------------------------ opening (R-STR-1)
  // The commander calls with a stream request: the mode and its initial
  // credit, which the target may then send (R-STR-4).
  action commanderCall = {
    val c = nodes.get("C")
    all {
      nextK <= MAX_CALLS,
      not(c.halted), not(c.peerRevoked),
      c.streams.keys().size() + pending.keys().size() < MAX_STREAMS,
      nondet mode = MODES.oneOf()
      nondet cr = 0.to(MAX_CREDIT).oneOf()
      val call = { k: nextK, mode: mode, credit: if (mode == "ordered") cr else 0 }
      commitWith(nodes, pending.put(nextK, call), done, calls.union(Set(call)), replies, pool, nextK + 1,
        Set(), Set()),
    }
  }

  // The target executes the call once. With room for a stream it opens one
  // under the smallest free number and replies with its own initial credit;
  // otherwise it replies with "too many streams" and leaves its streams as
  // they are (R-STR-6). Mutant "evict": at the limit it closes a stream to
  // make room.
  action targetOpen(call: Call): bool = {
    val t = nodes.get("T")
    val free = IDS.filter(i => not(t.streams.keys().contains(i)))
    all {
      not(t.halted), not(t.peerRevoked),
      not(done.contains(call.k)),
      nondet cr = 0.to(MAX_CREDIT).oneOf()
      val tcr = if (call.mode == "ordered") cr else 0
      if (free != Set()) {
        val sid = free.fold(MAX_STREAMS + 1, (m, i) => if (i < m) i else m)
        val t2 = { ...t, streams: t.streams.put(sid, newSide(call.k, call.mode, call.credit, tcr)) }
        commitWith(nodes.set("T", t2), pending, done.union(Set(call.k)), calls,
          replies.union(Set({ k: call.k, sid: sid, credit: tcr, ok: true })), pool, nextK, Set(), Set())
      } else if (MUTANT == "evict") {
        nondet victim = t.streams.keys().oneOf()
        val t2 = { ...t, streams: without(t.streams, victim).put(victim, newSide(call.k, call.mode, call.credit, tcr)) }
        commitWith(nodes.set("T", t2), pending, done.union(Set(call.k)), calls,
          replies.union(Set({ k: call.k, sid: victim, credit: tcr, ok: true })), pool, nextK,
          Set("openKeepsStreams"), Set())
      } else {
        commitWith(nodes, pending, done.union(Set(call.k)), calls,
          replies.union(Set({ k: call.k, sid: 0, credit: 0, ok: false })), pool, nextK, Set(), Set("tooMany"))
      }
    }
  }

  // The commander takes the reply to a pending call. A reply that opens a
  // stream opens the commander's side; a stale side with the same number
  // (the target closed it without the commander noticing) is replaced.
  action commanderReply(r: Reply): bool = {
    val c = nodes.get("C")
    all {
      pending.keys().contains(r.k),
      val call = pending.get(r.k)
      val pe2 = pending.keys().exclude(Set(r.k)).mapBy(x => pending.get(x))
      if (r.ok and not(c.halted) and not(c.peerRevoked)) {
        val c2 = { ...c, streams: c.streams.put(r.sid, newSide(r.k, call.mode, r.credit, call.credit)) }
        commitWith(nodes.set("C", c2), pe2, done, calls, replies, pool, nextK, Set(), Set())
      } else {
        commitWith(nodes, pe2, done, calls, replies, pool, nextK, Set(), Set())
      }
    }
  }

  // --------------------------------------------------------------- sending
  // A chunk always takes the next number of its direction (R-STR-2, B.7: a
  // chunk without the data flag consumes a number too). Mutant "reuse_no":
  // a chunk without data does not consume a number.
  action sendChunk(p: str, sid: int, s: Side, kind: str, add: int): bool = {
    val n = nodes.get(p)
    val ch = { dir: out(p), sid: sid, k: s.k, no: s.next, kind: kind, credit: add }
    // R-KEY-9: a chunk number is never used twice under one key and direction.
    val reused = pool.exists(x => x.dir == ch.dir and x.k == ch.k and x.no == ch.no)
    val nx = if (MUTANT == "reuse_no" and kind != "data") s.next else s.next + 1
    val s2 = { ...s, next: nx, idle: false,
               sendCredit: if (kind == "data" and s.mode == "ordered") s.sendCredit - 1 else s.sendCredit,
               sent: if (kind == "data") s.sent + 1 else s.sent,
               recvCredit: s.recvCredit + add, granted: s.granted + add }
    val st = if (kind == "end") without(n.streams, sid) else n.streams.put(sid, s2)
    // R-STR-4: in ordered mode the sender stays within its credit.
    val over = kind == "data" and s.mode == "ordered" and s.sendCredit < 1
    setNodes(nodes.set(p, { ...n, streams: st }), pool.union(Set(ch)),
      (if (reused) Set("chunkNumbersUnique") else Set()).union(if (over) Set("senderWithinCredit") else Set()),
      Set())
  }

  // A faulty peer sends a data chunk although it has no credit left. It
  // still numbers chunks correctly: it cannot do otherwise and be read.
  action overrun(p: str): bool = {
    val n = nodes.get(p)
    all {
      not(n.halted),
      n.streams.keys() != Set(),
      nondet sid = n.streams.keys().oneOf()
      val s = n.streams.get(sid)
      all {
        s.mode == "ordered", s.sendCredit < 1, s.next <= MAX_NO,
        val ch = { dir: out(p), sid: sid, k: s.k, no: s.next, kind: "data", credit: 0 }
        setNodes(nodes.set(p, { ...n, streams: n.streams.put(sid, { ...s, next: s.next + 1, idle: false }) }),
          pool.union(Set(ch)), Set(), Set("overrun")),
      }
    }
  }

  action send(p: str): bool = {
    val n = nodes.get(p)
    all {
      not(n.halted),
      n.streams.keys() != Set(),
      nondet sid = n.streams.keys().oneOf()
      val s = n.streams.get(sid)
      all {
        s.next <= MAX_NO,
        nondet kind = Set("data", "credit", "end").oneOf()
        nondet add = 1.to(MAX_CREDIT).oneOf()
        any {
          all { kind == "data", s.mode == "lossy" or s.sendCredit >= 1 or MUTANT == "ignore_credit",
                sendChunk(p, sid, s, "data", 0) },
          all { kind == "credit", s.mode == "ordered", s.recvCredit + add <= MAX_CREDIT,
                sendChunk(p, sid, s, "credit", add) },
          all { kind == "end", sendChunk(p, sid, s, "end", 0) },
        }
      }
    }
  }

  // ------------------------------------------------------------- receiving
  // A chunk whose stream the recipient does not have, or whose key is not
  // the key of the recipient's stream with that number, is dropped: no state
  // changes and nothing is sent (R-STR-3). Mutant "id_only": the recipient
  // matches the stream by number alone. Mutant "no_dir": the recipient does
  // not check the direction, so its own chunks reflected back are taken.
  // Mutant "unknown_opens": a chunk of an unknown stream opens one.
  action receive(p: str, ch: Chunk): bool = {
    val n = nodes.get(p)
    val known = n.streams.keys().contains(ch.sid)
      and (n.streams.get(ch.sid).k == ch.k or MUTANT == "id_only")
    all {
      not(n.halted),
      ch.dir == out(peer(p)) or MUTANT == "no_dir",
      if (not(known)) {
        if (MUTANT == "unknown_opens" and not(n.streams.keys().contains(ch.sid)))
          setNodes(nodes.set(p, { ...n, streams: n.streams.put(ch.sid, newSide(ch.k, "lossy", 0, 0)) }), pool,
            Set("unknownIsDropped"), Set())
        else
          setNodes(nodes, pool, Set(), if (n.streams.keys().contains(ch.sid)) Set("staleDropped") else Set())
      } else {
        val s = n.streams.get(ch.sid)
        // S11: whatever is taken is a chunk of this stream instance from the peer.
        val bound = if (ch.k == s.k and ch.dir == out(peer(p))) Set() else Set("chunkBinding")
        if (s.mode == "ordered") {
          // R-STR-3: only the next number; anything else closes the stream.
          // Mutant "ordered_gap": any higher number is taken. Mutant
          // "credit_replay": a credit chunk is taken whatever its number.
          val inOrder = ch.no == s.high + 1
            or (MUTANT == "ordered_gap" and ch.no > s.high)
            or (MUTANT == "credit_replay" and ch.kind == "credit")
          if (not(inOrder)) {
            setNodes(nodes.set(p, { ...n, streams: without(n.streams, ch.sid) }), pool, Set(), Set("orderClose"))
          } else {
            val order = if (ch.no == s.high + 1) Set() else Set("orderedInOrder")
            val s1 = { ...s, high: if (ch.no > s.high) ch.no else s.high, idle: false }
            if (ch.kind == "end") {
              setNodes(nodes.set(p, { ...n, streams: without(n.streams, ch.sid) }), pool, bound.union(order), Set())
            } else if (ch.kind == "credit") {
              val s2 = { ...s1, sendCredit: s1.sendCredit + ch.credit, got: s1.got + ch.credit }
              setNodes(nodes.set(p, { ...n, streams: n.streams.put(ch.sid, s2) }), pool, bound.union(order),
                Set("creditAdded"))
            } else if (s.recvCredit >= 1 or MUTANT == "no_credit_check") {
              val s2 = { ...s1, recvCredit: if (s1.recvCredit >= 1) s1.recvCredit - 1 else 0, recvd: s1.recvd + 1 }
              setNodes(nodes.set(p, { ...n, streams: n.streams.put(ch.sid, s2) }), pool, bound.union(order),
                Set("orderedData"))
            } else {
              // R-STR-4: exceeding the credit closes the stream.
              setNodes(nodes.set(p, { ...n, streams: without(n.streams, ch.sid) }), pool, Set(), Set("creditClose"))
            }
          }
        } else {
          // R-STR-3, lossy: a higher number is taken, gaps are not filled, a
          // lower or equal one is dropped. Mutant "lossy_old": an equal or
          // lower number is taken as well.
          if (ch.no > s.high or MUTANT == "lossy_old") {
            val order = if (ch.no > s.high) Set() else Set("lossyIncreasing")
            val gap = if (ch.no > s.high + 1) Set("lossyGap") else Set()
            val s2 = { ...s, high: if (ch.no > s.high) ch.no else s.high, idle: false,
                       recvd: if (ch.kind == "data") s.recvd + 1 else s.recvd }
            val st = if (ch.kind == "end") without(n.streams, ch.sid) else n.streams.put(ch.sid, s2)
            setNodes(nodes.set(p, { ...n, streams: st }), pool, bound.union(order), gap)
          } else {
            setNodes(nodes, pool, Set(), Set())
          }
        }
      }
    }
  }

  // ------------------------------------------------------- closing (R-STR-5)
  // Link down closes every stream on both sides.
  action linkDown = {
    val n2 = PARTIES.mapBy(p => { ...nodes.get(p), streams: Map() })
    eventWith(n2, pending, Set(), Set())
  }

  // "Reset nonces" closes the streams that have had no traffic since the
  // previous such event and starts a new period for the others. Mutant
  // "reset_busy": it closes busy streams too.
  action resetNonces(p: str): bool = {
    val n = nodes.get(p)
    val keep = n.streams.keys().filter(i => not(n.streams.get(i).idle) and MUTANT != "reset_busy")
    val busyClosed = n.streams.keys().exists(i => not(n.streams.get(i).idle) and not(keep.contains(i)))
    val n2 = { ...n, streams: keep.mapBy(i => { ...n.streams.get(i), idle: true }) }
    eventWith(nodes.set(p, n2), pending, if (busyClosed) Set("resetOnlyIdle") else Set(),
      if (keep.size() < n.streams.keys().size()) Set("resetClosed") else Set())
  }

  // A halted node closes its streams (R-MEM-9). Mutant "halt_keeps".
  action halt(p: str): bool = {
    val n = nodes.get(p)
    eventWith(nodes.set(p, { ...n, halted: true, streams: if (MUTANT == "halt_keeps") n.streams else Map() }),
      pending, Set(), Set())
  }

  // A node that learns its peer was revoked closes its streams with it.
  // Mutant "revoke_keeps".
  action learnRevoked(p: str): bool = {
    val n = nodes.get(p)
    eventWith(nodes.set(p, { ...n, peerRevoked: true, streams: if (MUTANT == "revoke_keeps") n.streams else Map() }),
      pending, Set(), Set())
  }

  // Open streams and pending calls do not survive a reboot (R-CORE-6).
  action reboot(p: str): bool = {
    val n = nodes.get(p)
    eventWith(nodes.set(p, { ...n, streams: Map() }), if (p == "C") Map() else pending, Set(), Set())
  }

  // ---------------------------------------------------------------------- step
  action step = any {
    commanderCall,
    all { calls != Set(), nondet c = calls.oneOf() targetOpen(c) },
    all { replies != Set(), nondet r = replies.oneOf() commanderReply(r) },
    nondet p = PARTIES.oneOf()
    any {
      send(p),
      overrun(p),
      all { pool != Set(), nondet ch = pool.oneOf() receive(p, ch) },
      resetNonces(p),
      halt(p),
      learnRevoked(p),
      reboot(p),
    },
    linkDown,
  }

  // ---------------------------------------------------------------- invariants
  // Step properties, checked by the monitor.
  val chunkNumbersUnique = not(broken.contains("chunkNumbersUnique"))   // R-KEY-9, R-STR-2
  val orderedInOrder = not(broken.contains("orderedInOrder"))           // R-STR-3
  val lossyIncreasing = not(broken.contains("lossyIncreasing"))         // R-STR-3
  val chunkBinding = not(broken.contains("chunkBinding"))               // S11
  val unknownIsDropped = not(broken.contains("unknownIsDropped"))       // R-STR-3
  val senderWithinCredit = not(broken.contains("senderWithinCredit"))   // R-STR-4
  val openKeepsStreams = not(broken.contains("openKeepsStreams"))       // R-STR-6
  val resetOnlyIdle = not(broken.contains("resetOnlyIdle"))             // R-STR-5

  // R-STR-4, S14: in ordered mode a recipient never takes more data than it
  // granted, even from a peer that overruns its credit.
  val creditRespected = PARTIES.forall(p =>
    val n = nodes.get(p)
    n.streams.keys().forall(i =>
      val s = n.streams.get(i)
      s.mode == "ordered" implies s.recvd <= s.granted))

  // R-STR-4: a sender never believes in more credit than its peer gave for
  // this stream instance, so a replayed credit chunk is not counted twice.

  val creditSound = PARTIES.forall(p => PARTIES.forall(q => p != q implies {
    val a = nodes.get(p)
    val b = nodes.get(q)
    a.streams.keys().forall(i => b.streams.keys().forall(j =>
      val s = a.streams.get(i)
      val r = b.streams.get(j)
      (s.k == r.k and s.mode == "ordered") implies s.got <= r.granted))
  }))

  // R-STR-6: never more open streams than the profile allows.
  val streamsBounded = PARTIES.forall(p => nodes.get(p).streams.keys().size() <= MAX_STREAMS)

  // R-STR-5, R-MEM-9: a halted node, and a node that knows its peer was
  // revoked, has no open stream.
  val haltClosesStreams = PARTIES.forall(p => nodes.get(p).halted implies nodes.get(p).streams.keys() == Set())
  val revocationClosesStreams = PARTIES.forall(p =>
    nodes.get(p).peerRevoked implies nodes.get(p).streams.keys() == Set())

  val safety = chunkNumbersUnique and orderedInOrder and lossyIncreasing and chunkBinding
    and unknownIsDropped and senderWithinCredit and openKeepsStreams and resetOnlyIdle
    and creditRespected and creditSound and streamsBounded and haltClosesStreams and revocationClosesStreams

  // ------------------------------------------------- non-vacuity witnesses
  // Each witness is expected to be VIOLATED: the behaviour is reachable.
  val witnessOrderedData = not(seen.contains("orderedData"))
  val witnessCreditAdded = not(seen.contains("creditAdded"))
  val witnessLossyGap = not(seen.contains("lossyGap"))
  val witnessTooMany = not(seen.contains("tooMany"))
  val witnessStaleDropped = not(seen.contains("staleDropped"))
  val witnessResetClosed = not(seen.contains("resetClosed"))
  val witnessOrderClose = not(seen.contains("orderClose"))
  val witnessCreditClose = not(seen.contains("creditClose"))
}
