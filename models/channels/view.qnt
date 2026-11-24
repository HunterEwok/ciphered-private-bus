// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 HunterEwok
//
// A state view of the channels model for exhaustive TLC runs (TLC option
// VIEW). TLC stores and expands one state per value of `viewOf`; the module
// `bisim` below proves with Apalache that states with equal views are
// interchangeable for `safety`, so the reduced search finds a violation exactly
// when the full one does. Valid only for MUTANT = "none".
//
// The view drops what can no longer influence `safety`:
// - the witness tags `seen`, and the readers the source granted the current
//   key, which only feed a witness tag;
// - the ghost counter `made`, which equals the source's generation;
// - of `gone` and `joined`, all but the late devices that may still join;
// - every grant that its reader can no longer accept and that is not of the
//   current key (the current key's grants decide whether a publication leaks);
// - every publication that no reader can ever accept again: no reader holds
//   its key or can still be granted it, or for each reader that may hold it,
//   its number is not new and it cannot enter the window.
// Each condition is monotone: a reader's highest generation, highest number
// and window floor never go back, and the source's key never returns to an
// older generation, so a dropped grant or publication stays droppable.
module viewdefs {
  const V_DEVICES: Set[str]
  const V_LATE: Set[str]

  type VPub = { gen: int, kid: int, no: int, depth: int, empty: bool }
  type VGrant = { gen: int, kid: int, reader: str }
  type VSource = { gen: int, kid: int, keyOk: bool, granted: Set[str], nextNo: int, reserved: int, mustRotate: bool }
  type VReader = { gen: int, kid: int, hiGen: int, hiNo: int, floor: int, depth: int, retained: Set[VPub] }
  type VPool = { pubs: Set[VPub], grants: Set[VGrant] }
  type View = {
    source: VSource, readers: str -> VReader, members: Set[str], mayJoin: Set[str], pubs: Set[VPub],
    grants: Set[VGrant], broken: Set[str],
  }

  // A grant its reader can still accept, or one of the current key.
  pure def liveGrant(s: VSource, rs: str -> VReader, x: VGrant): bool =
    x.kid == s.kid or x.gen > rs.get(x.reader).hiGen

  // Reader d holds the key of p, or may still be granted it: by a grant in
  // the pool it can accept, or by the source while that key is current.
  pure def mayHold(s: VSource, rs: str -> VReader, gs: Set[VGrant], d: str, p: VPub): bool = {
    val r = rs.get(d)
    r.kid == p.kid
      or (p.gen > r.hiGen and (p.kid == s.kid or gs.exists(x => x.reader == d and x.kid == p.kid)))
  }

  // Some reader may still accept p: as a new publication, or late into its window.
  pure def livePub(s: VSource, rs: str -> VReader, gs: Set[VGrant], p: VPub): bool =
    V_DEVICES.exists(d => {
      val r = rs.get(d)
      mayHold(s, rs, gs, d, p) and (p.no > r.hiNo or (p.depth > 0 and r.floor <= p.no))
    })

  pure def viewOf(s: VSource, rs: str -> VReader, m: Set[str], gn: Set[str], jn: Set[str], pl: VPool,
                  b: Set[str]): View = {
    val gs = pl.grants.filter(x => liveGrant(s, rs, x))
    { source: { ...s, granted: Set() }, readers: rs, members: m, mayJoin: V_LATE.exclude(jn).exclude(gn),
      pubs: pl.pubs.filter(p => livePub(s, rs, gs, p)), grants: gs, broken: b }
  }
}

// The instance `tiny` of instances.qnt with its view, for TLC. The constants
// must stay those of `tiny`.
module tiny_view {
  import channels(DEVICES = Set("a", "b"), NO_READ = Set(), LATE = Set(), MAX_GEN = 2, MAX_NO = 4,
                  MAX_DEPTH = 2, BLOCK = 2, MUTANT = "none").* from "./channels"
  import viewdefs(V_DEVICES = Set("a", "b"), V_LATE = Set()).*
  // Force TLC 1.7.4 to normalize the lazy map `readers` in the state before
  // StatePoolWriter spills states to disk when VIEW drops or wraps them.
  val safetyView = {
    val v = viewOf(source, readers, members, gone, joined, pool, broken)
    if (readers != Map()) v else v
  }
}

// Proof that the view is exact for `safety` (R-VER-3), checked by Apalache on
// two copies A and B of the model:
//   O1. init implies Struct                             (initStruct, 0 steps, invariant structA)
//   O2. Struct, safety and one step imply Struct         (initSafe, stepX, 1 step, invariant structA)
//   O3. two Struct states with equal views agree on safety (initPair, 0 steps, invariant sameSafety)
//   O4. for two Struct states with equal views, A safe, every step of A is
//       answered by B with no step or one step, and the views are equal again
//       (initPair, matchX, 2 steps, invariant matched).
// Struct is the inductive invariant of inductive.qnt. Why this suffices: take
// a shortest behaviour of the model that ends in a state violating `safety`.
// Every earlier state is safe, so by O1 and O2 it satisfies Struct. TLC with
// the view reaches a state of the same view as the initial state (it is the
// initial state). If TLC holds a state r with the view of the i-th state s,
// then r is reachable and safe (otherwise TLC has already reported a
// violation), so r satisfies Struct, and by O4 the step from s to the next
// state is answered from r by a state TLC also generates, with the same view
// as the next state. By induction TLC generates a state with the view of the
// last state, which violates `safety` by O3.
//
// B answers each step of A with the same step and the same choices. A step
// that reads a grant or a publication the view drops changes nothing in A (the
// reader cannot accept it), so B answers it with no step.
module bisim {
  const P_DEVICES: Set[str]
  const P_NO_READ: Set[str]
  const P_LATE: Set[str]
  const P_MAX_GEN: int
  const P_MAX_NO: int
  const P_MAX_DEPTH: int
  const P_BLOCK: int
  import channels(DEVICES = P_DEVICES, NO_READ = P_NO_READ, LATE = P_LATE, MAX_GEN = P_MAX_GEN, MAX_NO = P_MAX_NO,
                  MAX_DEPTH = P_MAX_DEPTH, BLOCK = P_BLOCK, MUTANT = "none") as A from "./channels"
  import channels(DEVICES = P_DEVICES, NO_READ = P_NO_READ, LATE = P_LATE, MAX_GEN = P_MAX_GEN, MAX_NO = P_MAX_NO,
                  MAX_DEPTH = P_MAX_DEPTH, BLOCK = P_BLOCK, MUTANT = "none") as B from "./channels"
  import viewdefs(V_DEVICES = P_DEVICES, V_LATE = P_LATE).*

  // ------------------------------------------------------------ bounded types
  pure val GENS = 1.to(P_MAX_GEN)
  pure val NOS = 1.to(P_MAX_NO)
  pure val DEPTHS = 0.to(P_MAX_DEPTH)
  // In the correct model a key's identity equals its generation.
  pure val PUBS: Set[VPub] = tuples(GENS, NOS, DEPTHS, Set(false, true))
    .map(t => { gen: t._1, kid: t._1, no: t._2, depth: t._3, empty: t._4 })
  pure val GRANTS: Set[VGrant] = tuples(GENS, P_DEVICES).map(t => { gen: t._1, kid: t._1, reader: t._2 })
  pure val TAGS = Set("accept", "refill", "lateClear", "clear", "shrink", "rotateAfterRemove")

  pure def distinctNumbers(s: Set[VPub]): bool = s.forall(a => s.forall(b => a.no == b.no implies a == b))

  // ------------------------------------------------------------------ Struct
  // The inductive invariant of inductive.qnt (IndInv), with the same parts.
  pure def sourceOk(s: VSource, mk: int): bool = and {
    0.to(P_MAX_GEN).contains(s.gen), s.kid == s.gen, s.gen == mk,
    0.to(P_MAX_NO + P_BLOCK - 1).contains(s.reserved), 1 <= s.nextNo, s.nextNo <= s.reserved + 1,
    s.granted.subseteq(P_DEVICES),
    s.keyOk implies s.gen >= 1,
  }

  pure def readerOk(d: str, r: VReader, p: VPool): bool = and {
    0.to(P_MAX_GEN).contains(r.gen), r.kid == r.gen, r.hiGen == r.gen,
    0.to(P_MAX_NO).contains(r.hiNo), 1 <= r.floor, r.floor <= r.hiNo + 1, DEPTHS.contains(r.depth),
    r.retained.subseteq(PUBS),
    r.retained.size() <= r.depth,
    r.retained.forall(q => r.floor <= q.no and q.no <= r.hiNo),
    distinctNumbers(r.retained),
    r.retained.forall(q => not(q.empty) and q.depth > 0),
    r.retained.subseteq(p.pubs),
    P_NO_READ.contains(d) implies r.kid == 0,
  }

  pure def poolOk(p: VPool, s: VSource, m: Set[str]): bool = and {
    p.pubs.subseteq(PUBS), p.grants.subseteq(GRANTS),
    p.pubs.forall(q => q.no < s.nextNo and q.no <= s.reserved and q.gen <= s.gen),
    p.grants.forall(x => x.gen <= s.gen),
    distinctNumbers(p.pubs),
    (s.keyOk and not(s.mustRotate)) implies
      p.grants.forall(x => x.kid == s.kid implies m.contains(x.reader)),
  }

  pure def structOf(s: VSource, rs: str -> VReader, m: Set[str], gn: Set[str], jn: Set[str], mk: int, p: VPool,
                    b: Set[str], sn: Set[str]): bool = and {
    rs.keys() == P_DEVICES,
    sourceOk(s, mk),
    P_DEVICES.forall(d => readerOk(d, rs.get(d), p)),
    poolOk(p, s, m),
    m.subseteq(P_DEVICES), gn.subseteq(P_DEVICES), jn.subseteq(P_DEVICES),
    0.to(P_MAX_GEN).contains(mk),
    b == Set(),
    sn.subseteq(TAGS),
  }

  val structA = structOf(A::source, A::readers, A::members, A::gone, A::joined, A::made, A::pool, A::broken, A::seen)
  val structB = structOf(B::source, B::readers, B::members, B::gone, B::joined, B::made, B::pool, B::broken, B::seen)
  val viewA = viewOf(A::source, A::readers, A::members, A::gone, A::joined, A::pool, A::broken)
  val viewB = viewOf(B::source, B::readers, B::members, B::gone, B::joined, B::pool, B::broken)

  // ------------------------------------------------------------- bookkeeping
  type Move = { kind: str, d: str, x: VGrant, p: VPub, depth: int, empty: bool, keep: bool }
  pure val NO_GRANT: VGrant = { gen: 0, kid: 0, reader: "" }
  pure val NO_PUB: VPub = { gen: 0, kid: 0, no: 0, depth: 0, empty: false }
  pure val NO_MOVE: Move = { kind: "", d: "", x: NO_GRANT, p: NO_PUB, depth: 0, empty: false, keep: false }
  var stage: int      // 0: before A's step, 1: after it, 2: after B's answer
  var mv: Move        // A's step, as B needs it
  var matchOk: bool   // B's answer was enabled

  action aStay = all {
    A::source' = A::source, A::readers' = A::readers, A::members' = A::members, A::gone' = A::gone,
    A::joined' = A::joined, A::made' = A::made, A::pool' = A::pool, A::broken' = A::broken, A::seen' = A::seen,
  }
  action bStay = all {
    B::source' = B::source, B::readers' = B::readers, B::members' = B::members, B::gone' = B::gone,
    B::joined' = B::joined, B::made' = B::made, B::pool' = B::pool, B::broken' = B::broken, B::seen' = B::seen,
  }

  // --------------------------------------------- an arbitrary state of Struct
  // Drawn as indInit in inductive.qnt draws one, so these draw every state of
  // Struct.
  action drawA = {
    nondet sgen = 0.to(P_MAX_GEN).oneOf()
    nondet sok = Set(false, true).oneOf()
    nondet sgranted = P_DEVICES.powerset().oneOf()
    nondet snext = 1.to(P_MAX_NO + P_BLOCK).oneOf()
    nondet sres = 0.to(P_MAX_NO + P_BLOCK - 1).oneOf()
    nondet srot = Set(false, true).oneOf()
    nondet rgen = setOfMaps(P_DEVICES, 0.to(P_MAX_GEN)).oneOf()
    nondet rhi = setOfMaps(P_DEVICES, 0.to(P_MAX_NO)).oneOf()
    nondet rfloor = setOfMaps(P_DEVICES, 1.to(P_MAX_NO + 1)).oneOf()
    nondet rdepth = setOfMaps(P_DEVICES, DEPTHS).oneOf()
    nondet rret = setOfMaps(P_DEVICES, PUBS.powerset()).oneOf()
    nondet m = P_DEVICES.powerset().oneOf()
    nondet gn = P_DEVICES.powerset().oneOf()
    nondet jn = P_DEVICES.powerset().oneOf()
    nondet pp = PUBS.powerset().oneOf()
    nondet pg = GRANTS.powerset().oneOf()
    val s = { gen: sgen, kid: sgen, keyOk: sok, granted: sgranted, nextNo: snext, reserved: sres,
              mustRotate: srot }
    val rs = P_DEVICES.mapBy(d => { gen: rgen.get(d), kid: rgen.get(d), hiGen: rgen.get(d), hiNo: rhi.get(d),
                                    floor: rfloor.get(d), depth: rdepth.get(d), retained: rret.get(d) })
    val p = { pubs: pp, grants: pg }
    all {
      structOf(s, rs, m, gn, jn, sgen, p, Set(), Set()),
      A::source' = s, A::readers' = rs, A::members' = m, A::gone' = gn, A::joined' = jn, A::made' = sgen,
      A::pool' = p, A::broken' = Set(), A::seen' = Set(),
    }
  }

  action drawB = {
    nondet sgen = 0.to(P_MAX_GEN).oneOf()
    nondet sok = Set(false, true).oneOf()
    nondet sgranted = P_DEVICES.powerset().oneOf()
    nondet snext = 1.to(P_MAX_NO + P_BLOCK).oneOf()
    nondet sres = 0.to(P_MAX_NO + P_BLOCK - 1).oneOf()
    nondet srot = Set(false, true).oneOf()
    nondet rgen = setOfMaps(P_DEVICES, 0.to(P_MAX_GEN)).oneOf()
    nondet rhi = setOfMaps(P_DEVICES, 0.to(P_MAX_NO)).oneOf()
    nondet rfloor = setOfMaps(P_DEVICES, 1.to(P_MAX_NO + 1)).oneOf()
    nondet rdepth = setOfMaps(P_DEVICES, DEPTHS).oneOf()
    nondet rret = setOfMaps(P_DEVICES, PUBS.powerset()).oneOf()
    nondet m = P_DEVICES.powerset().oneOf()
    nondet gn = P_DEVICES.powerset().oneOf()
    nondet jn = P_DEVICES.powerset().oneOf()
    nondet pp = PUBS.powerset().oneOf()
    nondet pg = GRANTS.powerset().oneOf()
    val s = { gen: sgen, kid: sgen, keyOk: sok, granted: sgranted, nextNo: snext, reserved: sres,
              mustRotate: srot }
    val rs = P_DEVICES.mapBy(d => { gen: rgen.get(d), kid: rgen.get(d), hiGen: rgen.get(d), hiNo: rhi.get(d),
                                    floor: rfloor.get(d), depth: rdepth.get(d), retained: rret.get(d) })
    val p = { pubs: pp, grants: pg }
    all {
      structOf(s, rs, m, gn, jn, sgen, p, Set(), Set()),
      B::source' = s, B::readers' = rs, B::members' = m, B::gone' = gn, B::joined' = jn, B::made' = sgen,
      B::pool' = p, B::broken' = Set(), B::seen' = Set(),
    }
  }

  // ----------------------------------------------------------- initial states
  action initStruct = all { A::init, B::init, stage' = 0, mv' = NO_MOVE, matchOk' = true }
  action initSafe = all { drawA, B::init, stage' = 0, mv' = NO_MOVE, matchOk' = true }
  action initPair = all { drawA, drawB, stage' = 0, mv' = NO_MOVE, matchOk' = true }

  // Names run-inductive.ps1 uses for its first, cheap check (Apalache download).
  action modelInit = initStruct
  action modelStep = stepSourceEpoch
  val IndInv = structA

  val sameSafety = (viewA == viewB) implies (A::safety iff B::safety)
  val matched = stage != 2 or (matchOk and viewA == viewB)
  // Non-vacuity: expected to be violated (a pair with equal views exists; B answers).
  val witnessPair = viewA != viewB
  val witnessAnswered = stage != 2

  // ------------------------------------------------- A's step, branch by branch
  // O2 runs stepX from initSafe; O4 runs matchX from initPair.
  action pre = all { stage == 0, A::safety }
  action stepEnvRemove = all { pre, bStay, stage' = 1, matchOk' = true, A::members != Set(),
    nondet d = A::members.oneOf() all { A::envRemoveDevice(d), mv' = { ...NO_MOVE, kind: "remove", d: d } } }
  action stepEnvJoin = all { pre, bStay, stage' = 1, matchOk' = true,
    val cand = P_LATE.exclude(A::joined).exclude(A::gone)
    all { cand != Set(), nondet d = cand.oneOf()
          all { A::commitWith(A::source, A::readers, A::members.union(Set(d)), A::pool, Set(), Set()),
                mv' = { ...NO_MOVE, kind: "join", d: d } } } }
  action stepSourceRotate = all { pre, bStay, stage' = 1, matchOk' = true, A::sourceRotate,
    mv' = { ...NO_MOVE, kind: "rotate" } }
  action stepSourceGrant = all { pre, bStay, stage' = 1, matchOk' = true,
    nondet d = P_DEVICES.oneOf() all { A::sourceGrantTo(d), mv' = { ...NO_MOVE, kind: "grant", d: d } } }
  action stepSourcePublish = all { pre, bStay, stage' = 1, matchOk' = true,
    nondet depth = DEPTHS.oneOf() nondet empty = Set(false, true).oneOf()
    all { A::sourcePublishWith(depth, empty), mv' = { ...NO_MOVE, kind: "publish", depth: depth, empty: empty } } }
  action stepSourceEpoch = all { pre, bStay, stage' = 1, matchOk' = true, A::sourceEpoch,
    mv' = { ...NO_MOVE, kind: "epoch" } }
  action stepSourceReboot = all { pre, bStay, stage' = 1, matchOk' = true,
    nondet keep = Set(false, true).oneOf()
    val start = A::source.reserved + 1
    all { A::commitWith({ ...A::source, keyOk: keep and A::source.keyOk, granted: Set(),
                          nextNo: if (start < 1) 1 else start }, A::readers, A::members, A::pool, Set(), Set()),
          mv' = { ...NO_MOVE, kind: "reboot", keep: keep } } }
  action stepReaderGrant = all { pre, bStay, stage' = 1, matchOk' = true, A::pool.grants != Set(),
    nondet d = P_DEVICES.oneOf() nondet x = A::pool.grants.oneOf()
    all { A::readerGrant(d, x), mv' = { ...NO_MOVE, kind: "readerGrant", d: d, x: x } } }
  action stepReaderPub = all { pre, bStay, stage' = 1, matchOk' = true, A::pool.pubs != Set(),
    nondet d = P_DEVICES.oneOf() nondet p = A::pool.pubs.oneOf()
    all { A::readerPub(d, p), mv' = { ...NO_MOVE, kind: "readerPub", d: d, p: p } } }
  action stepReaderReboot = all { pre, bStay, stage' = 1, matchOk' = true,
    nondet d = P_DEVICES.oneOf() all { A::readerReboot(d), mv' = { ...NO_MOVE, kind: "readerReboot", d: d } } }

  // ------------------------------------------------------------- B's answer
  action bNone = all { bStay, matchOk' = false }
  action bDo(ok: bool, act: bool): bool = if (ok) all { act, matchOk' = true } else bNone
  action answer =
    if (mv.kind == "remove") bDo(B::members.contains(mv.d), B::envRemoveDevice(mv.d))
    else if (mv.kind == "join")
      bDo(P_LATE.exclude(B::joined).exclude(B::gone).contains(mv.d),
          B::commitWith(B::source, B::readers, B::members.union(Set(mv.d)), B::pool, Set(), Set()))
    else if (mv.kind == "rotate") bDo(true, B::sourceRotate)
    else if (mv.kind == "grant") bDo(true, B::sourceGrantTo(mv.d))
    else if (mv.kind == "publish") bDo(true, B::sourcePublishWith(mv.depth, mv.empty))
    else if (mv.kind == "epoch") bDo(true, B::sourceEpoch)
    else if (mv.kind == "reboot") {
      val start = B::source.reserved + 1
      bDo(true, B::commitWith({ ...B::source, keyOk: mv.keep and B::source.keyOk, granted: Set(),
                                nextNo: if (start < 1) 1 else start }, B::readers, B::members, B::pool, Set(), Set()))
    }
    else if (mv.kind == "readerGrant") bDo(B::pool.grants.contains(mv.x), B::readerGrant(mv.d, mv.x))
    else if (mv.kind == "readerPub") bDo(B::pool.pubs.contains(mv.p), B::readerPub(mv.d, mv.p))
    else if (mv.kind == "readerReboot") bDo(true, B::readerReboot(mv.d))
    else bNone

  action respond = all { stage == 1, aStay, stage' = 2, mv' = mv,
    if (viewA == viewB) all { bStay, matchOk' = true } else answer }
  action matchEnvRemove = any { all { viewA == viewB, stepEnvRemove }, respond }
  action matchEnvJoin = any { all { viewA == viewB, stepEnvJoin }, respond }
  action matchSourceRotate = any { all { viewA == viewB, stepSourceRotate }, respond }
  action matchSourceGrant = any { all { viewA == viewB, stepSourceGrant }, respond }
  action matchSourcePublish = any { all { viewA == viewB, stepSourcePublish }, respond }
  action matchSourceEpoch = any { all { viewA == viewB, stepSourceEpoch }, respond }
  action matchSourceReboot = any { all { viewA == viewB, stepSourceReboot }, respond }
  action matchReaderGrant = any { all { viewA == viewB, stepReaderGrant }, respond }
  action matchReaderPub = any { all { viewA == viewB, stepReaderPub }, respond }
  action matchReaderReboot = any { all { viewA == viewB, stepReaderReboot }, respond }
}

module tiny_bisim {
  import bisim(P_DEVICES = Set("a", "b"), P_NO_READ = Set(), P_LATE = Set(), P_MAX_GEN = 2, P_MAX_NO = 4,
               P_MAX_DEPTH = 2, P_BLOCK = 2).*
}
