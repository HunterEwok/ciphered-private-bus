// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 HunterEwok
//
// A state view of the relay model for exhaustive TLC runs (TLC option VIEW).
// TLC stores and expands one state per value of `viewOf`; module `bisim`
// below proves with Apalache that states with equal views are
// interchangeable for `safety`, so the reduced search finds a violation
// exactly when the full one does. Valid only for MUTANT = "none".
//
// The view drops only what can never influence `safety`:
// - the witness tags `seen`: no guard and no invariant of `safety` reads them,
//   and the relay records up to fourteen of them in any combination;
// - the numbers of the buffered join requests and the ghost counter
//   `nextJoin` that produces them: `safety` reads only the length of the
//   buffer, and a new request is always the newest one, so whether it is kept
//   (`newestJoinKept`) does not depend on the numbers. The view keeps the
//   length of the buffer.
// Every other variable is kept as it is.
module viewdefs {
  type RObj = { kind: str, src: int, ch: int, reader: int, no: int, gen: int, depth: int, size: int, ok: bool, arr: int }
  type RBytes = { pub: (int, int, int) -> int, grant: (int, int, int) -> int, req: (int, int, int) -> int }
  type RRelay = {
    served: bool, cpNo: int, cpMax: int, revoked: Set[int], rootGen: int, tGen: int, tNo: int, store: Set[RObj],
    bytes: RBytes, hi: (int, int) -> int, dep: (int, int) -> int, arr: int, joins: List[int], online: Set[int],
  }
  type RRoot = { gen: int, tNo: int, cpNo: int, listed: bool }
  type View = { relay: RRelay, joinCount: int, cps: int -> Set[int], root: RRoot, events: int, broken: Set[str] }

  pure def viewOf(r: RRelay, c: int -> Set[int], rt: RRoot, ev: int, b: Set[str]): View =
    { relay: { ...r, joins: List() }, joinCount: r.joins.length(), cps: c, root: rt, events: ev, broken: b }
}

// The TLC instance: the constants of `tiny` in instances.qnt.
module tiny_view {
  import relay(N_DEV = 2, CHANS = Set(1), MAX_NO = 2, MAX_DEPTH = 1, SIZES = Set(1, 2), SOURCE_BYTES = 2,
               BUS_BYTES = 3, JOIN_MAX = 1, MAX_ARR = 4, MAX_EVENTS = 3, MUTANT = "none").* from "./relay"
  import viewdefs.*
  val safetyView = viewOf(relay, cps, root, events, broken)
}

// Proof that the view is exact for `safety` (R-VER-3), checked by Apalache on
// two copies A and B of the model:
//   O1. init implies Struct                             (initStruct, 0 steps, invariant structA)
//   O2. Struct, safety and one step imply Struct         (initSafe, stepX, 1 step, invariant structA)
//   O3. two Struct states with equal views agree on safety (initPair, 0 steps, invariant sameSafety)
//   O4. for two Struct states with equal views, A safe, every step of A is
//       answered by B with no step or one step, and the views are equal again
//       (initPair, matchX, 2 steps, invariant matched).
// Why this suffices: take a shortest behaviour of the model that ends in a
// state violating `safety`. Every earlier state is safe, so by O1 and O2 it
// satisfies Struct, and so does the last state (O2 from the one before it).
// TLC with the view reaches a state of the same view as the initial state
// (it is the initial state). If TLC holds a state r with the view of the i-th
// state s, then r is reachable and every state on TLC's path to r is safe
// (otherwise TLC has already reported a violation), so r satisfies Struct,
// and by O4 the step from s to the next state is answered from r by a state
// TLC also generates, with the same view as the next state. By induction TLC
// generates a state with the view of the last state, which violates `safety`
// by O3.
//
// Struct is the bounded types of the variables, the bookkeeping of
// checkpoints, root changes and events, and the fact that the store holds at
// most one object per key slot. For grants and key requests the last fact is
// also the conjunct oneGrantOneRequest of `safety`; Struct needs it so that
// the draws can build the store slot by slot, and the argument above uses
// Struct only for states it has shown to satisfy it (by O1 and O2), never
// `safety` itself. Struct leaves `broken` arbitrary and does not include the
// other conjuncts of `safety` (forged, transient or revoked objects in the
// store, the quota accounting, retention, the join buffer bound beyond its
// type, the checkpoint order).
//
// B's answer: no step when A's step left the views equal (it only added a
// witness tag); otherwise the same action with the same parameters. Every
// guard reads only variables the view keeps (recvJoin reads the buffer only
// through its length), so it holds in B, and the action changes the kept
// variables of A and B in the same way.
module bisim {
  const P_N_DEV: int
  const P_CHANS: Set[int]
  const P_MAX_NO: int
  const P_MAX_DEPTH: int
  const P_SIZES: Set[int]
  const P_SOURCE_BYTES: int
  const P_BUS_BYTES: int
  const P_JOIN_MAX: int
  const P_MAX_ARR: int
  const P_MAX_EVENTS: int
  import relay(N_DEV = P_N_DEV, CHANS = P_CHANS, MAX_NO = P_MAX_NO, MAX_DEPTH = P_MAX_DEPTH, SIZES = P_SIZES,
               SOURCE_BYTES = P_SOURCE_BYTES, BUS_BYTES = P_BUS_BYTES, JOIN_MAX = P_JOIN_MAX, MAX_ARR = P_MAX_ARR,
               MAX_EVENTS = P_MAX_EVENTS, MUTANT = "none") as A from "./relay"
  import relay(N_DEV = P_N_DEV, CHANS = P_CHANS, MAX_NO = P_MAX_NO, MAX_DEPTH = P_MAX_DEPTH, SIZES = P_SIZES,
               SOURCE_BYTES = P_SOURCE_BYTES, BUS_BYTES = P_BUS_BYTES, JOIN_MAX = P_JOIN_MAX, MAX_ARR = P_MAX_ARR,
               MAX_EVENTS = P_MAX_EVENTS, MUTANT = "none") as B from "./relay"
  import viewdefs.*

  // ------------------------------------------------------------ bounded types
  pure val DEVS = 1.to(P_N_DEV)
  pure val NOS = 1.to(P_MAX_NO)
  pure val KEYS = tuples(DEVS, P_CHANS)
  pure val PSLOTS = tuples(DEVS, P_CHANS, NOS)
  pure val GSLOTS = tuples(DEVS, P_CHANS, DEVS).filter(t => t._1 != t._3)
  pure val CPNOS = 1.to(P_MAX_EVENTS + 1)
  pure val ARRS = 1.to(P_MAX_ARR)
  pure val TAGS = Set("ownEvicted", "busEvicted", "noVictim", "grantReplaced", "servedPub", "forwarded0",
                      "requestAnswered", "revokedPurged", "unlisted", "joinEvicted", "newGenTicket", "refused",
                      "callForwarded", "callRefused")
  pure val BROKEN = Set("onlyVerified", "servedOnlyGranted", "nothingForRevoked", "fairShare", "evictsOnlyOwn",
                        "grantsKept", "latestGrant", "newestJoinKept", "ticketOfCurrentRoot")

  // An object the relay can store, field by field: the kinds it stores and the
  // values the actions can give them (the signature flag and the depth are
  // left free; `safety` speaks about them).
  pure def isObj(o: RObj): bool = and {
    DEVS.contains(o.src), P_CHANS.contains(o.ch), ARRS.contains(o.arr),
    if (o.kind == "pub") and {
      o.reader == 0, NOS.contains(o.no), o.gen == 0, 0 <= o.depth, o.depth <= P_MAX_DEPTH, P_SIZES.contains(o.size),
    } else if (o.kind == "grant") and {
      DEVS.contains(o.reader), o.reader != o.src, 0 <= o.no, o.no <= 1, 1 <= o.gen, o.gen <= 2,
      o.depth == 0, o.size == 0,
    } else and {
      o.kind == "req", DEVS.contains(o.reader), o.reader != o.src, o.no == 1, o.gen == 0, o.depth == 0, o.size == 0,
    },
  }
  pure def sameSlot(a: RObj, x: RObj): bool =
    a.kind == x.kind and a.src == x.src and a.ch == x.ch
      and (if (a.kind == "pub") a.no == x.no else a.reader == x.reader)

  // ------------------------------------------------------------------ Struct
  pure def structOf(r: RRelay, c: int -> Set[int], rt: RRoot, ev: int, nj: int, b: Set[str], s: Set[str]): bool = and {
    0 <= ev, ev <= P_MAX_EVENTS, 0 <= nj,
    // every new checkpoint, root change and join request is one event
    (rt.cpNo - 1) + (rt.gen - 1) + nj <= ev,
    1 <= rt.gen, rt.gen <= 2, 0 <= rt.tNo, rt.tNo <= 2, CPNOS.contains(rt.cpNo),
    c.keys() == CPNOS.filter(k => k <= rt.cpNo), c.keys().forall(k => c.get(k).subseteq(DEVS)),
    0 <= r.arr, r.arr <= P_MAX_ARR,
    r.hi.keys() == KEYS, r.dep.keys() == KEYS,
    KEYS.forall(k => 0 <= r.hi.get(k) and r.hi.get(k) <= P_MAX_NO and 0 <= r.dep.get(k) and r.dep.get(k) <= P_MAX_DEPTH),
    r.joins.length() <= P_JOIN_MAX, r.joins.indices().forall(i => 1 <= r.joins.nth(i) and r.joins.nth(i) <= nj),
    r.online.subseteq(DEVS), r.revoked.subseteq(DEVS),
    1 <= r.rootGen, r.rootGen <= rt.gen, 1 <= r.tGen, r.tGen <= 2, 1 <= r.tNo, r.tNo <= 2,
    // the relay's checkpoints are ones the Root issued
    c.keys().contains(r.cpNo), c.keys().contains(r.cpMax),
    // the store: objects of the stored kinds, at most one per key slot
    r.store.forall(o => isObj(o)),
    r.store.forall(a => r.store.forall(x => sameSlot(a, x) implies a == x)),
    // the accounting: one entry per key slot, within the sizes
    r.bytes.pub.keys() == PSLOTS, r.bytes.grant.keys() == GSLOTS, r.bytes.req.keys() == GSLOTS,
    PSLOTS.forall(k => r.bytes.pub.get(k) == 0 or P_SIZES.contains(r.bytes.pub.get(k))),
    GSLOTS.forall(k => 0 <= r.bytes.grant.get(k) and r.bytes.grant.get(k) <= 1
      and 0 <= r.bytes.req.get(k) and r.bytes.req.get(k) <= 1),
    b.subseteq(BROKEN), s.subseteq(TAGS),
  }

  val structA = structOf(A::relay, A::cps, A::root, A::events, A::nextJoin, A::broken, A::seen)
  val structB = structOf(B::relay, B::cps, B::root, B::events, B::nextJoin, B::broken, B::seen)
  val viewA = viewOf(A::relay, A::cps, A::root, A::events, A::broken)
  val viewB = viewOf(B::relay, B::cps, B::root, B::events, B::broken)

  // ------------------------------------------------------------- bookkeeping
  pure val NO_OBJ: RObj = { kind: "", src: 0, ch: 0, reader: 0, no: 0, gen: 0, depth: 0, size: 0, ok: false, arr: 0 }
  type Move = { kind: str, o: RObj, d: int, n: int, g: int }
  pure val NO_MOVE: Move = { kind: "", o: NO_OBJ, d: 0, n: 0, g: 0 }
  var stage: int      // 0: before A's step, 1: after it, 2: after B's answer
  var mv: Move        // A's step, as B needs it
  var matchOk: bool   // B's answer was enabled

  action aStay = all {
    A::relay' = A::relay, A::cps' = A::cps, A::root' = A::root, A::events' = A::events,
    A::nextJoin' = A::nextJoin, A::broken' = A::broken, A::seen' = A::seen,
  }
  action bStay = all {
    B::relay' = B::relay, B::cps' = B::cps, B::root' = B::root, B::events' = B::events,
    B::nextJoin' = B::nextJoin, B::broken' = B::broken, B::seen' = B::seen,
  }

  // --------------------------------------------- an arbitrary state of Struct
  // The store is drawn slot by slot, as indInit in inductive.qnt draws it:
  // whether a slot is occupied and every field of its object. Every set of
  // objects with at most one per slot arises this way, and every other
  // variable is drawn from its whole bounded type and filtered by Struct, so
  // the draws reach every state of Struct.
  action drawA = {
    nondet pIn = setOfMaps(PSLOTS, Set(false, true)).oneOf()
    nondet pDepth = setOfMaps(PSLOTS, 0.to(P_MAX_DEPTH)).oneOf()
    nondet pSize = setOfMaps(PSLOTS, P_SIZES).oneOf()
    nondet pOk = setOfMaps(PSLOTS, Set(false, true)).oneOf()
    nondet pArr = setOfMaps(PSLOTS, ARRS).oneOf()
    nondet gIn = setOfMaps(GSLOTS, Set(false, true)).oneOf()
    nondet gGen = setOfMaps(GSLOTS, 1.to(2)).oneOf()
    nondet gNo = setOfMaps(GSLOTS, 0.to(1)).oneOf()
    nondet gOk = setOfMaps(GSLOTS, Set(false, true)).oneOf()
    nondet gArr = setOfMaps(GSLOTS, ARRS).oneOf()
    nondet qIn = setOfMaps(GSLOTS, Set(false, true)).oneOf()
    nondet qOk = setOfMaps(GSLOTS, Set(false, true)).oneOf()
    nondet qArr = setOfMaps(GSLOTS, ARRS).oneOf()
    nondet pB = setOfMaps(PSLOTS, Set(0).union(P_SIZES)).oneOf()
    nondet gB = setOfMaps(GSLOTS, 0.to(1)).oneOf()
    nondet qB = setOfMaps(GSLOTS, 0.to(1)).oneOf()
    nondet served = Set(false, true).oneOf()
    nondet cpNo = CPNOS.oneOf()
    nondet cpMax = CPNOS.oneOf()
    nondet revoked = DEVS.powerset().oneOf()
    nondet revAll = setOfMaps(CPNOS, DEVS.powerset()).oneOf()
    nondet rootGen = 1.to(2).oneOf()
    nondet tGen = 1.to(2).oneOf()
    nondet tNo = 1.to(2).oneOf()
    nondet hi = setOfMaps(KEYS, 0.to(P_MAX_NO)).oneOf()
    nondet dep = setOfMaps(KEYS, 0.to(P_MAX_DEPTH)).oneOf()
    nondet arr = 0.to(P_MAX_ARR).oneOf()
    nondet jl = 0.to(P_JOIN_MAX).oneOf()
    nondet jv = setOfMaps(1.to(P_JOIN_MAX), 1.to(P_MAX_EVENTS)).oneOf()
    nondet online = DEVS.powerset().oneOf()
    nondet rGen = 1.to(2).oneOf()
    nondet rTNo = 0.to(2).oneOf()
    nondet rCpNo = CPNOS.oneOf()
    nondet listed = Set(false, true).oneOf()
    nondet ev = 0.to(P_MAX_EVENTS).oneOf()
    nondet nj = 0.to(P_MAX_EVENTS).oneOf()
    nondet b = BROKEN.powerset().oneOf()
    nondet sn = TAGS.powerset().oneOf()
    val pubs = PSLOTS.filter(t => pIn.get(t)).map(t =>
      { kind: "pub", src: t._1, ch: t._2, reader: 0, no: t._3, gen: 0, depth: pDepth.get(t), size: pSize.get(t),
        ok: pOk.get(t), arr: pArr.get(t) })
    val grants = GSLOTS.filter(t => gIn.get(t)).map(t =>
      { kind: "grant", src: t._1, ch: t._2, reader: t._3, no: gNo.get(t), gen: gGen.get(t), depth: 0, size: 0,
        ok: gOk.get(t), arr: gArr.get(t) })
    val reqs = GSLOTS.filter(t => qIn.get(t)).map(t =>
      { kind: "req", src: t._1, ch: t._2, reader: t._3, no: 1, gen: 0, depth: 0, size: 0, ok: qOk.get(t),
        arr: qArr.get(t) })
    val c = CPNOS.filter(k => k <= rCpNo).mapBy(k => revAll.get(k))
    val r = {
      served: served, cpNo: cpNo, cpMax: cpMax, revoked: revoked, rootGen: rootGen, tGen: tGen, tNo: tNo,
      store: pubs.union(grants).union(reqs), bytes: { pub: pB, grant: gB, req: qB }, hi: hi, dep: dep, arr: arr,
      joins: range(0, P_JOIN_MAX).foldl(List(), (l, i) => if (i < jl) l.append(jv.get(i + 1)) else l),
      online: online,
    }
    val rt = { gen: rGen, tNo: rTNo, cpNo: rCpNo, listed: listed }
    all {
      structOf(r, c, rt, ev, nj, b, sn),
      A::relay' = r, A::cps' = c, A::root' = rt, A::events' = ev, A::nextJoin' = nj, A::broken' = b, A::seen' = sn,
    }
  }

  action drawB = {
    nondet pIn = setOfMaps(PSLOTS, Set(false, true)).oneOf()
    nondet pDepth = setOfMaps(PSLOTS, 0.to(P_MAX_DEPTH)).oneOf()
    nondet pSize = setOfMaps(PSLOTS, P_SIZES).oneOf()
    nondet pOk = setOfMaps(PSLOTS, Set(false, true)).oneOf()
    nondet pArr = setOfMaps(PSLOTS, ARRS).oneOf()
    nondet gIn = setOfMaps(GSLOTS, Set(false, true)).oneOf()
    nondet gGen = setOfMaps(GSLOTS, 1.to(2)).oneOf()
    nondet gNo = setOfMaps(GSLOTS, 0.to(1)).oneOf()
    nondet gOk = setOfMaps(GSLOTS, Set(false, true)).oneOf()
    nondet gArr = setOfMaps(GSLOTS, ARRS).oneOf()
    nondet qIn = setOfMaps(GSLOTS, Set(false, true)).oneOf()
    nondet qOk = setOfMaps(GSLOTS, Set(false, true)).oneOf()
    nondet qArr = setOfMaps(GSLOTS, ARRS).oneOf()
    nondet pB = setOfMaps(PSLOTS, Set(0).union(P_SIZES)).oneOf()
    nondet gB = setOfMaps(GSLOTS, 0.to(1)).oneOf()
    nondet qB = setOfMaps(GSLOTS, 0.to(1)).oneOf()
    nondet served = Set(false, true).oneOf()
    nondet cpNo = CPNOS.oneOf()
    nondet cpMax = CPNOS.oneOf()
    nondet revoked = DEVS.powerset().oneOf()
    nondet revAll = setOfMaps(CPNOS, DEVS.powerset()).oneOf()
    nondet rootGen = 1.to(2).oneOf()
    nondet tGen = 1.to(2).oneOf()
    nondet tNo = 1.to(2).oneOf()
    nondet hi = setOfMaps(KEYS, 0.to(P_MAX_NO)).oneOf()
    nondet dep = setOfMaps(KEYS, 0.to(P_MAX_DEPTH)).oneOf()
    nondet arr = 0.to(P_MAX_ARR).oneOf()
    nondet jl = 0.to(P_JOIN_MAX).oneOf()
    nondet jv = setOfMaps(1.to(P_JOIN_MAX), 1.to(P_MAX_EVENTS)).oneOf()
    nondet online = DEVS.powerset().oneOf()
    nondet rGen = 1.to(2).oneOf()
    nondet rTNo = 0.to(2).oneOf()
    nondet rCpNo = CPNOS.oneOf()
    nondet listed = Set(false, true).oneOf()
    nondet ev = 0.to(P_MAX_EVENTS).oneOf()
    nondet nj = 0.to(P_MAX_EVENTS).oneOf()
    nondet b = BROKEN.powerset().oneOf()
    nondet sn = TAGS.powerset().oneOf()
    val pubs = PSLOTS.filter(t => pIn.get(t)).map(t =>
      { kind: "pub", src: t._1, ch: t._2, reader: 0, no: t._3, gen: 0, depth: pDepth.get(t), size: pSize.get(t),
        ok: pOk.get(t), arr: pArr.get(t) })
    val grants = GSLOTS.filter(t => gIn.get(t)).map(t =>
      { kind: "grant", src: t._1, ch: t._2, reader: t._3, no: gNo.get(t), gen: gGen.get(t), depth: 0, size: 0,
        ok: gOk.get(t), arr: gArr.get(t) })
    val reqs = GSLOTS.filter(t => qIn.get(t)).map(t =>
      { kind: "req", src: t._1, ch: t._2, reader: t._3, no: 1, gen: 0, depth: 0, size: 0, ok: qOk.get(t),
        arr: qArr.get(t) })
    val c = CPNOS.filter(k => k <= rCpNo).mapBy(k => revAll.get(k))
    val r = {
      served: served, cpNo: cpNo, cpMax: cpMax, revoked: revoked, rootGen: rootGen, tGen: tGen, tNo: tNo,
      store: pubs.union(grants).union(reqs), bytes: { pub: pB, grant: gB, req: qB }, hi: hi, dep: dep, arr: arr,
      joins: range(0, P_JOIN_MAX).foldl(List(), (l, i) => if (i < jl) l.append(jv.get(i + 1)) else l),
      online: online,
    }
    val rt = { gen: rGen, tNo: rTNo, cpNo: rCpNo, listed: listed }
    all {
      structOf(r, c, rt, ev, nj, b, sn),
      B::relay' = r, B::cps' = c, B::root' = rt, B::events' = ev, B::nextJoin' = nj, B::broken' = b, B::seen' = sn,
    }
  }

  // ----------------------------------------------------------- initial states
  action initStruct = all { A::init, B::init, stage' = 0, mv' = NO_MOVE, matchOk' = true }
  action initSafe = all { drawA, B::init, stage' = 0, mv' = NO_MOVE, matchOk' = true }
  action initPair = all { drawA, drawB, stage' = 0, mv' = NO_MOVE, matchOk' = true }

  // Names run-inductive.ps1 uses for its first, cheap check (Apalache download).
  action modelInit = initStruct
  action modelStep = stepDisconnect
  val IndInv = structA

  val sameSafety = (viewA == viewB) implies (A::safety iff B::safety)
  val matched = stage != 2 or (matchOk and viewA == viewB)
  // Non-vacuity: expected to be violated (a pair with equal views exists; B answers).
  val witnessPair = viewA != viewB
  val witnessAnswered = stage != 2

  // ------------------------------------------------- A's step, branch by branch
  // The branches of `step` in relay.qnt as inductive.qnt splits them. O2 runs
  // stepX from initSafe; O4 runs matchX from initPair.
  action pre = all { stage == 0, A::safety }
  action stepRecvPub = all { pre, bStay, stage' = 1, matchOk' = true,
    nondet o = A::PUBS.oneOf() all { A::recvPub(o), mv' = { ...NO_MOVE, kind: "pub", o: o } } }
  action stepRecvGrant = all { pre, bStay, stage' = 1, matchOk' = true,
    nondet o = A::GRANTS.oneOf() all { A::recvGrant(o), mv' = { ...NO_MOVE, kind: "grant", o: o } } }
  action stepRecvReq = all { pre, bStay, stage' = 1, matchOk' = true,
    nondet o = A::REQS.oneOf() all { A::recvReq(o), mv' = { ...NO_MOVE, kind: "req", o: o } } }
  action stepRecvCall = all { pre, bStay, stage' = 1, matchOk' = true,
    nondet o = A::CALLS.oneOf() all { A::recvCall(o), mv' = { ...NO_MOVE, kind: "call", o: o } } }
  action stepConnect = all { pre, bStay, stage' = 1, matchOk' = true,
    nondet d = DEVS.oneOf() all { A::connect(d), mv' = { ...NO_MOVE, kind: "connect", d: d } } }
  action stepDisconnect = all { pre, bStay, stage' = 1, matchOk' = true,
    nondet d = DEVS.oneOf() all { A::disconnect(d), mv' = { ...NO_MOVE, kind: "disconnect", d: d } } }
  action stepRootRevoke = all { pre, bStay, stage' = 1, matchOk' = true,
    nondet d = DEVS.oneOf() all { A::rootRevoke(d), mv' = { ...NO_MOVE, kind: "revoke", d: d } } }
  action stepRootUnlist = all { pre, bStay, stage' = 1, matchOk' = true,
    A::rootUnlist, mv' = { ...NO_MOVE, kind: "unlist" } }
  action stepRootChange = all { pre, bStay, stage' = 1, matchOk' = true,
    A::root.gen < 2, A::rootChange, mv' = { ...NO_MOVE, kind: "rootChange" } }
  action stepRootTicket = all { pre, bStay, stage' = 1, matchOk' = true,
    A::root.tNo < 2, A::rootTicket, mv' = { ...NO_MOVE, kind: "rootTicket" } }
  action stepLearnCp = all { pre, bStay, stage' = 1, matchOk' = true,
    nondet n = A::cps.keys().oneOf() all { A::learnCp(n), mv' = { ...NO_MOVE, kind: "learnCp", n: n } } }
  action stepLearnRootChange = all { pre, bStay, stage' = 1, matchOk' = true,
    A::learnRootChange, mv' = { ...NO_MOVE, kind: "learnRootChange" } }
  action stepLearnTicket = all { pre, bStay, stage' = 1, matchOk' = true,
    nondet g = 1.to(2).oneOf() nondet n = 1.to(2).oneOf()
    all { A::learnTicket(g, n), mv' = { ...NO_MOVE, kind: "learnTicket", g: g, n: n } } }
  action stepRecvJoin = all { pre, bStay, stage' = 1, matchOk' = true,
    A::recvJoin, mv' = { ...NO_MOVE, kind: "join" } }

  // --------------------------------------------------------------- B's answer
  // B does nothing when the views already agree; otherwise it takes the same
  // action as A with the same parameters. Each guard copies the guard of that
  // action in relay.qnt (with the condition of its branch in `step`) under
  // MUTANT = "none", so that B's step is taken exactly when the guard holds;
  // matchOk records it.
  action bNone = all { bStay, matchOk' = false }
  action answer = {
    val r = B::relay
    val o = mv.o
    if (mv.kind == "pub")
      if (o.ok and r.served and not(r.revoked.contains(o.src)) and o.kind == "pub" and r.arr < P_MAX_ARR)
        all { B::recvPub(o), matchOk' = true }
      else bNone
    else if (mv.kind == "grant") {
      val old = r.store.filter(x => x.kind == "grant" and x.src == o.src and x.ch == o.ch and x.reader == o.reader)
      if (o.ok and r.served and not(r.revoked.contains(o.src) or r.revoked.contains(o.reader)) and o.kind == "grant"
          and o.src != o.reader and old.forall(x => o.gen > x.gen) and r.arr < P_MAX_ARR)
        all { B::recvGrant(o), matchOk' = true }
      else bNone
    }
    else if (mv.kind == "req")
      if (o.ok and r.served and not(r.revoked.contains(o.reader) or r.revoked.contains(o.src)) and o.kind == "req"
          and o.src != o.reader and r.arr < P_MAX_ARR)
        all { B::recvReq(o), matchOk' = true }
      else bNone
    else if (mv.kind == "call")
      if (o.ok and r.served and o.kind == "call" and o.src != o.reader and r.arr < P_MAX_ARR
          and not(r.revoked.contains(o.src)))
        all { B::recvCall(o), matchOk' = true }
      else bNone
    else if (mv.kind == "connect")
      if (r.served and not(r.online.contains(mv.d)) and not(r.revoked.contains(mv.d)))
        all { B::connect(mv.d), matchOk' = true }
      else bNone
    else if (mv.kind == "disconnect")
      if (r.online.contains(mv.d)) all { B::disconnect(mv.d), matchOk' = true }
      else bNone
    else if (mv.kind == "revoke")
      if (B::events < P_MAX_EVENTS and B::root.listed and not(B::cps.get(B::root.cpNo).contains(mv.d)))
        all { B::rootRevoke(mv.d), matchOk' = true }
      else bNone
    else if (mv.kind == "unlist")
      if (B::events < P_MAX_EVENTS and B::root.listed) all { B::rootUnlist, matchOk' = true }
      else bNone
    else if (mv.kind == "rootChange")
      if (B::events < P_MAX_EVENTS and B::root.gen < 2) all { B::rootChange, matchOk' = true }
      else bNone
    else if (mv.kind == "rootTicket")
      if (B::events < P_MAX_EVENTS and B::root.tNo < 2) all { B::rootTicket, matchOk' = true }
      else bNone
    else if (mv.kind == "learnCp")
      if (B::cps.keys().contains(mv.n) and mv.n > r.cpNo) all { B::learnCp(mv.n), matchOk' = true }
      else bNone
    else if (mv.kind == "learnRootChange")
      if (r.rootGen < B::root.gen) all { B::learnRootChange, matchOk' = true }
      else bNone
    else if (mv.kind == "learnTicket")
      if (r.served and mv.g <= B::root.gen and (mv.g < B::root.gen or mv.n <= B::root.tNo) and mv.n >= 1
          and (mv.g > r.tGen or (mv.g == r.tGen and mv.n > r.tNo)) and mv.g == r.rootGen)
        all { B::learnTicket(mv.g, mv.n), matchOk' = true }
      else bNone
    else if (mv.kind == "join")
      if (B::events < P_MAX_EVENTS and r.served) all { B::recvJoin, matchOk' = true }
      else bNone
    else bNone
  }
  action respond = all { stage == 1, aStay, stage' = 2, mv' = mv,
    if (viewA == viewB) all { bStay, matchOk' = true } else answer }
  action matchRecvPub = any { all { viewA == viewB, stepRecvPub }, respond }
  action matchRecvGrant = any { all { viewA == viewB, stepRecvGrant }, respond }
  action matchRecvReq = any { all { viewA == viewB, stepRecvReq }, respond }
  action matchRecvCall = any { all { viewA == viewB, stepRecvCall }, respond }
  action matchConnect = any { all { viewA == viewB, stepConnect }, respond }
  action matchDisconnect = any { all { viewA == viewB, stepDisconnect }, respond }
  action matchRootRevoke = any { all { viewA == viewB, stepRootRevoke }, respond }
  action matchRootUnlist = any { all { viewA == viewB, stepRootUnlist }, respond }
  action matchRootChange = any { all { viewA == viewB, stepRootChange }, respond }
  action matchRootTicket = any { all { viewA == viewB, stepRootTicket }, respond }
  action matchLearnCp = any { all { viewA == viewB, stepLearnCp }, respond }
  action matchLearnRootChange = any { all { viewA == viewB, stepLearnRootChange }, respond }
  action matchLearnTicket = any { all { viewA == viewB, stepLearnTicket }, respond }
  action matchRecvJoin = any { all { viewA == viewB, stepRecvJoin }, respond }
}

// The proof instance: the constants of `tiny` in instances.qnt.
module tiny_bisim {
  import bisim(P_N_DEV = 2, P_CHANS = Set(1), P_MAX_NO = 2, P_MAX_DEPTH = 1, P_SIZES = Set(1, 2), P_SOURCE_BYTES = 2,
               P_BUS_BYTES = 3, P_JOIN_MAX = 1, P_MAX_ARR = 4, P_MAX_EVENTS = 3).*
}
