// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 HunterEwok
//
// A state view of the membership model for exhaustive TLC runs (TLC option
// VIEW) of the instance tiny_tlc. TLC stores and expands one state per value
// of `viewOf`; module `bisim` below proves with Apalache that states with
// equal views are interchangeable for `safety`, so the reduced search finds a
// violation exactly when the full one does. Valid only for MUTANT = "none"
// and TRACK_RECV = false.
//
// The view drops only what can never influence `safety`:
// - the witness tags `seen`: no guard and no invariant of `safety` reads them;
// - the Root's ghost map `rights`: it is written when a passport is issued and
//   read by nothing (the rights a node uses are those of the passport);
// - the processed halt proofs of a node, `recvHp`, beyond two facts: whether
//   one is a root change proof, and whether one of another kind is of the
//   node's current generation. proofIsObeyed reads exactly these, and they
//   stay exact across later steps: a node only records proofs of its own
//   generation or root change proofs, and its generation never decreases;
// - data messages that no node can accept any more, and among data messages
//   that differ only in the sender's checkpoint number all but the lowest
//   number. A node accepts a message only of its own generation, which never
//   decreases, so a message of a generation below that of every possible
//   receiver is dead; and the checkpoint number only enters the guard
//   "not ahead of the receiver", which the lowest number passes whenever a
//   higher one does, while the acceptance itself does not depend on it.
// Every other variable is kept as it is.
module viewdefs {
  type MCheckpoint = { gen: int, no: int, start: int, valid: Set[int], nextNo: int }
  type MPassport = { gen: int, no: int, dev: str, rights: int }
  type MRootChange = { gen: int, key: int }
  type MHaltProof = { kind: str, gen: int, no: int }
  type MData = { src: str, ppNo: int, gen: int, cpNo: int, ch0: bool }
  type MNode = {
    gen: int, cp: MCheckpoint, pps: Set[MPassport], rc: int, halted: bool, forever: bool,
    recvCp: Set[MCheckpoint], recvPp: Set[MPassport], recvRc: Set[MRootChange], recvHp: Set[MHaltProof],
  }
  type MRoot = { gen: int, cpNo: int, nextNo: int, valid: Set[int], rights: int -> int, revoked: Set[int] }
  type MPool = { cp: Set[MCheckpoint], pp: Set[MPassport], rc: Set[MRootChange], hp: Set[MHaltProof], data: Set[MData] }

  type NodeView = {
    gen: int, cp: MCheckpoint, pps: Set[MPassport], rc: int, halted: bool, forever: bool,
    recvCp: Set[MCheckpoint], recvPp: Set[MPassport], recvRc: Set[MRootChange], rcProof: bool, curProof: bool,
  }
  type RootView = { gen: int, cpNo: int, nextNo: int, valid: Set[int], revoked: Set[int] }
  type View = { nodes: str -> NodeView, root: RootView, pool: MPool, history: Set[MCheckpoint], broken: Set[str] }

  pure def nodeView(n: MNode): NodeView = {
    gen: n.gen, cp: n.cp, pps: n.pps, rc: n.rc, halted: n.halted, forever: n.forever,
    recvCp: n.recvCp, recvPp: n.recvPp, recvRc: n.recvRc,
    rcProof: n.recvHp.exists(h => h.kind == "rc"),
    curProof: n.recvHp.exists(h => h.kind != "rc" and h.gen == n.gen),
  }
  pure def sameData(x: MData, m: MData): bool =
    x.src == m.src and x.ppNo == m.ppNo and x.gen == m.gen and x.ch0 == m.ch0
  // A message some device other than its sender may still accept: one whose
  // generation that device has not passed.
  pure def liveMsg(ns: str -> MNode, m: MData): bool =
    ns.keys().exists(d => d != m.src and ns.get(d).gen <= m.gen)
  pure def liveData(ns: str -> MNode, data: Set[MData]): Set[MData] =
    data.filter(m => liveMsg(ns, m) and data.forall(x => not(sameData(x, m) and x.cpNo < m.cpNo)))

  pure def viewOf(ns: str -> MNode, r: MRoot, p: MPool, h: Set[MCheckpoint], b: Set[str]): View = {
    nodes: ns.keys().mapBy(d => nodeView(ns.get(d))),
    root: { gen: r.gen, cpNo: r.cpNo, nextNo: r.nextNo, valid: r.valid, revoked: r.revoked },
    pool: { ...p, data: liveData(ns, p.data) },
    history: h,
    broken: b,
  }
}

// The TLC instance: the constants of `tiny_tlc` in instances.qnt.
module tiny_tlc_view {
  import membership(DEVICES = Set("a", "b"), MAX_GEN = 2, MAX_NO = 2, WINDOW = 2, MUTANT = "none",
                    TRACK_RECV = false).* from "./membership"
  import viewdefs.*
  val safetyView = viewOf(nodes, root, pool, history, broken)
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
// Struct is the bounded types of the variables as inductive.qnt states them
// (including the shape of every checkpoint and the window of the Root's next
// one, which keep issued checkpoints in that shape), one passport per number
// in a node's cache, one honest checkpoint per generation and number, and
// processed proofs other than root change proofs of the node's generation or
// an older one. Two of these facts are also parts of `safety`: the window
// bound of every issued checkpoint (windowBounded) and one passport per number
// in a cache (the conflict half of cacheConsistent). O1 and O2 prove them like
// every other fact of Struct, so no part of `safety` is assumed; the per-number
// cache fact is what makes the answer to an acceptance deterministic. `broken`
// is left arbitrary.
//
// B's answer: no step when A's step left the views equal; otherwise the step
// of B that the case analysis below gives. Several actions of the model pick
// a value inside (a passport number, a checkpoint, a passport, a proof); B
// takes the same action with A's value fixed, written as the action's body
// with that value, because another value would make a different state. For
// data acceptance B takes the message of the same sender, passport number,
// generation and channel with the lowest checkpoint number, which the view
// keeps.
module bisim {
  const P_DEVICES: Set[str]
  const P_MAX_GEN: int
  const P_MAX_NO: int
  const P_WINDOW: int
  import membership(DEVICES = P_DEVICES, MAX_GEN = P_MAX_GEN, MAX_NO = P_MAX_NO, WINDOW = P_WINDOW, MUTANT = "none",
                    TRACK_RECV = false) as A from "./membership"
  import membership(DEVICES = P_DEVICES, MAX_GEN = P_MAX_GEN, MAX_NO = P_MAX_NO, WINDOW = P_WINDOW, MUTANT = "none",
                    TRACK_RECV = false) as B from "./membership"
  import viewdefs.*

  // ------------------------------------------------------------ bounded types
  pure val GENS = 1.to(P_MAX_GEN)
  pure val NOS = 1.to(P_MAX_NO)
  pure val RIGHTS = Set(0, 1, 2, 3)
  pure val CPS: Set[MCheckpoint] = tuples(GENS, 0.to(P_MAX_NO), 1.to(P_MAX_NO + 1), NOS.powerset(), 1.to(P_MAX_NO + 1))
    .map(t => { gen: t._1, no: t._2, start: t._3, valid: t._4, nextNo: t._5 })
    .filter(c => and {
      c.nextNo <= c.no + 1, c.start <= c.nextNo, c.nextNo - c.start <= P_WINDOW,
      c.valid.forall(k => c.start <= k and k < c.nextNo),
    })
  pure val PPS: Set[MPassport] = tuples(GENS, NOS, P_DEVICES, RIGHTS)
    .map(t => { gen: t._1, no: t._2, dev: t._3, rights: t._4 })
  pure val RCS: Set[MRootChange] = tuples(GENS, Set(0, 1)).map(t => { gen: t._1, key: t._2 })
  pure val HPS: Set[MHaltProof] = tuples(Set("cp", "pp", "rc"), GENS, 0.to(P_MAX_NO))
    .map(t => { kind: t._1, gen: t._2, no: t._3 })
  pure val DATAS: Set[MData] = tuples(P_DEVICES, NOS, GENS, 0.to(P_MAX_NO), Set(false, true))
    .map(t => { src: t._1, ppNo: t._2, gen: t._3, cpNo: t._4, ch0: t._5 })
  pure val BROKEN = Set("noRollback", "currentGeneration", "haltIsSticky", "haltedIsInert", "revokedIsRejected",
                        "grantsNeedRead", "dataNeedsPublish")

  // Membership in the types above, field by field (as in inductive.qnt).
  pure def isCp(c: MCheckpoint): bool = and {
    GENS.contains(c.gen), 0 <= c.no, c.no <= P_MAX_NO, 1 <= c.start, c.start <= P_MAX_NO + 1,
    1 <= c.nextNo, c.nextNo <= P_MAX_NO + 1, c.valid.subseteq(NOS),
    c.nextNo <= c.no + 1, c.start <= c.nextNo, c.nextNo - c.start <= P_WINDOW,
    c.valid.forall(k => c.start <= k and k < c.nextNo),
  }
  pure def isPp(p: MPassport): bool =
    and { GENS.contains(p.gen), NOS.contains(p.no), P_DEVICES.contains(p.dev), RIGHTS.contains(p.rights) }
  pure def isRc(r: MRootChange): bool = and { GENS.contains(r.gen), Set(0, 1).contains(r.key) }
  pure def isHp(h: MHaltProof): bool =
    and { Set("cp", "pp", "rc").contains(h.kind), GENS.contains(h.gen), 0 <= h.no, h.no <= P_MAX_NO }
  pure def isData(m: MData): bool =
    and { P_DEVICES.contains(m.src), NOS.contains(m.ppNo), GENS.contains(m.gen), 0 <= m.cpNo, m.cpNo <= P_MAX_NO }

  // ------------------------------------------------------------------ Struct
  pure def nodeOk(n: MNode): bool = and {
    GENS.contains(n.gen), isCp(n.cp), n.pps.forall(p => isPp(p)), Set(-1, 0, 1).contains(n.rc),
    n.recvCp == Set(), n.recvPp == Set(), n.recvRc == Set(), n.recvHp.forall(h => isHp(h)),
    // one passport per number in the cache: a conflicting passport halts the
    // node without entering it (this makes the passport data acceptance
    // relies on unique)
    n.pps.forall(p => n.pps.forall(q => p.no == q.no implies p == q)),
    // processed proofs other than root change proofs are of the node's
    // generation or an older one (this keeps the two facts the view keeps
    // exact when the generation grows)
    n.recvHp.forall(h => h.kind == "rc" or h.gen <= n.gen),
  }
  pure def rootOk(r: MRoot): bool = and {
    GENS.contains(r.gen), 0 <= r.cpNo, r.cpNo <= P_MAX_NO, 1 <= r.nextNo, r.nextNo <= P_MAX_NO + 1,
    r.nextNo <= r.cpNo + 1,
    r.valid.forall(k => 1 <= k and k < r.nextNo),
    r.revoked.forall(k => 1 <= k and k < r.nextNo),
    r.rights.keys() == NOS.filter(k => k < r.nextNo),
    r.rights.keys().forall(k => RIGHTS.contains(r.rights.get(k))),
    // the window of the Root's next checkpoint fits (R-MEM-14)
    r.valid.forall(k => r.nextNo - k <= P_WINDOW),
  }
  pure def structOf(ns: str -> MNode, r: MRoot, p: MPool, h: Set[MCheckpoint], b: Set[str], s: Set[str]): bool = and {
    ns.keys() == P_DEVICES,
    P_DEVICES.forall(d => nodeOk(ns.get(d))),
    rootOk(r),
    h.forall(c => isCp(c) and c.no >= 1),
    h.forall(c1 => h.forall(c2 => (c1.gen == c2.gen and c1.no == c2.no) implies c1 == c2)),
    p.cp.forall(c => isCp(c)), p.pp.forall(x => isPp(x)), p.rc.forall(x => isRc(x)), p.hp.forall(x => isHp(x)),
    p.data.forall(x => isData(x)),
    b.subseteq(BROKEN), s.subseteq(Set("accept", "grant")),
  }

  val structA = structOf(A::nodes, A::root, A::pool, A::history, A::broken, A::seen)
  val structB = structOf(B::nodes, B::root, B::pool, B::history, B::broken, B::seen)
  val viewA = viewOf(A::nodes, A::root, A::pool, A::history, A::broken)
  val viewB = viewOf(B::nodes, B::root, B::pool, B::history, B::broken)

  // ------------------------------------------------------------- bookkeeping
  pure val NO_CP: MCheckpoint = { gen: 0, no: 0, start: 0, valid: Set(), nextNo: 0 }
  pure val NO_PP: MPassport = { gen: 0, no: 0, dev: "", rights: 0 }
  pure val NO_RC: MRootChange = { gen: 0, key: 0 }
  pure val NO_HP: MHaltProof = { kind: "", gen: 0, no: 0 }
  pure val NO_DATA: MData = { src: "", ppNo: 0, gen: 0, cpNo: 0, ch0: false }
  type Move = { kind: str, d: str, r: int, k: int, c: MCheckpoint, p: MPassport, rc: MRootChange, h: MHaltProof,
                m: MData, ppNo: int, ch0: bool }
  pure val NO_MOVE: Move = { kind: "", d: "", r: 0, k: 0, c: NO_CP, p: NO_PP, rc: NO_RC, h: NO_HP, m: NO_DATA,
                             ppNo: 0, ch0: false }
  var stage: int      // 0: before A's step, 1: after it, 2: after B's answer
  var mv: Move        // A's step, as B needs it
  var matchOk: bool   // B's answer was enabled

  action aStay = all {
    A::nodes' = A::nodes, A::root' = A::root, A::pool' = A::pool, A::history' = A::history,
    A::broken' = A::broken, A::seen' = A::seen,
  }
  action bStay = all {
    B::nodes' = B::nodes, B::root' = B::root, B::pool' = B::pool, B::history' = B::history,
    B::broken' = B::broken, B::seen' = B::seen,
  }

  // --------------------------------------------- an arbitrary state of Struct
  // Drawn as indInit in inductive.qnt draws a state: a node's cache one
  // passport per number, the history one checkpoint per generation and
  // number, everything else from its whole bounded type, then filtered by
  // Struct. Every state of Struct arises this way.
  pure val SLOTS = tuples(GENS, NOS)
  action drawA = {
    nondet gens = setOfMaps(P_DEVICES, GENS).oneOf()
    nondet cpNo = setOfMaps(P_DEVICES, 0.to(P_MAX_NO)).oneOf()
    nondet cpStart = setOfMaps(P_DEVICES, 1.to(P_MAX_NO + 1)).oneOf()
    nondet cpValid = setOfMaps(P_DEVICES, NOS.powerset()).oneOf()
    nondet cpNext = setOfMaps(P_DEVICES, 1.to(P_MAX_NO + 1)).oneOf()
    nondet cpGen = setOfMaps(P_DEVICES, GENS).oneOf()
    nondet ppIn = setOfMaps(P_DEVICES, setOfMaps(NOS, Set(false, true))).oneOf()
    nondet ppGen = setOfMaps(P_DEVICES, setOfMaps(NOS, GENS)).oneOf()
    nondet ppDev = setOfMaps(P_DEVICES, setOfMaps(NOS, P_DEVICES)).oneOf()
    nondet ppRights = setOfMaps(P_DEVICES, setOfMaps(NOS, RIGHTS)).oneOf()
    nondet hIn = setOfMaps(SLOTS, Set(false, true)).oneOf()
    nondet hStart = setOfMaps(SLOTS, 1.to(P_MAX_NO + 1)).oneOf()
    nondet hValid = setOfMaps(SLOTS, NOS.powerset()).oneOf()
    nondet hNext = setOfMaps(SLOTS, 1.to(P_MAX_NO + 1)).oneOf()
    nondet rcs = setOfMaps(P_DEVICES, Set(-1, 0, 1)).oneOf()
    nondet halts = setOfMaps(P_DEVICES, Set(false, true)).oneOf()
    nondet forevers = setOfMaps(P_DEVICES, Set(false, true)).oneOf()
    nondet hps = setOfMaps(P_DEVICES, HPS.powerset()).oneOf()
    nondet rg = GENS.oneOf()
    nondet rcp = 0.to(P_MAX_NO).oneOf()
    nondet rnx = 1.to(P_MAX_NO + 1).oneOf()
    nondet rv = NOS.powerset().oneOf()
    nondet rrv = NOS.powerset().oneOf()
    nondet rfull = setOfMaps(NOS, RIGHTS).oneOf()
    nondet pcp = CPS.powerset().oneOf()
    nondet ppp = PPS.powerset().oneOf()
    nondet prc = RCS.powerset().oneOf()
    nondet php = HPS.powerset().oneOf()
    nondet pdata = DATAS.powerset().oneOf()
    nondet b = BROKEN.powerset().oneOf()
    nondet sn = Set("accept", "grant").powerset().oneOf()
    val hist = SLOTS.filter(s => hIn.get(s))
      .map(s => { gen: s._1, no: s._2, start: hStart.get(s), valid: hValid.get(s), nextNo: hNext.get(s) })
    val ns = P_DEVICES.mapBy(d => {
      gen: gens.get(d),
      cp: { gen: cpGen.get(d), no: cpNo.get(d), start: cpStart.get(d), valid: cpValid.get(d), nextNo: cpNext.get(d) },
      pps: NOS.filter(k => ppIn.get(d).get(k))
        .map(k => { gen: ppGen.get(d).get(k), no: k, dev: ppDev.get(d).get(k), rights: ppRights.get(d).get(k) }),
      rc: rcs.get(d), halted: halts.get(d),
      forever: forevers.get(d), recvCp: Set(), recvPp: Set(), recvRc: Set(), recvHp: hps.get(d),
    })
    val r = { gen: rg, cpNo: rcp, nextNo: rnx, valid: rv,
              rights: NOS.filter(k => k < rnx).mapBy(k => rfull.get(k)), revoked: rrv }
    val p = { cp: pcp, pp: ppp, rc: prc, hp: php, data: pdata }
    all {
      structOf(ns, r, p, hist, b, sn),
      A::nodes' = ns, A::root' = r, A::pool' = p, A::history' = hist, A::broken' = b, A::seen' = sn,
    }
  }

  action drawB = {
    nondet gens = setOfMaps(P_DEVICES, GENS).oneOf()
    nondet cpNo = setOfMaps(P_DEVICES, 0.to(P_MAX_NO)).oneOf()
    nondet cpStart = setOfMaps(P_DEVICES, 1.to(P_MAX_NO + 1)).oneOf()
    nondet cpValid = setOfMaps(P_DEVICES, NOS.powerset()).oneOf()
    nondet cpNext = setOfMaps(P_DEVICES, 1.to(P_MAX_NO + 1)).oneOf()
    nondet cpGen = setOfMaps(P_DEVICES, GENS).oneOf()
    nondet ppIn = setOfMaps(P_DEVICES, setOfMaps(NOS, Set(false, true))).oneOf()
    nondet ppGen = setOfMaps(P_DEVICES, setOfMaps(NOS, GENS)).oneOf()
    nondet ppDev = setOfMaps(P_DEVICES, setOfMaps(NOS, P_DEVICES)).oneOf()
    nondet ppRights = setOfMaps(P_DEVICES, setOfMaps(NOS, RIGHTS)).oneOf()
    nondet hIn = setOfMaps(SLOTS, Set(false, true)).oneOf()
    nondet hStart = setOfMaps(SLOTS, 1.to(P_MAX_NO + 1)).oneOf()
    nondet hValid = setOfMaps(SLOTS, NOS.powerset()).oneOf()
    nondet hNext = setOfMaps(SLOTS, 1.to(P_MAX_NO + 1)).oneOf()
    nondet rcs = setOfMaps(P_DEVICES, Set(-1, 0, 1)).oneOf()
    nondet halts = setOfMaps(P_DEVICES, Set(false, true)).oneOf()
    nondet forevers = setOfMaps(P_DEVICES, Set(false, true)).oneOf()
    nondet hps = setOfMaps(P_DEVICES, HPS.powerset()).oneOf()
    nondet rg = GENS.oneOf()
    nondet rcp = 0.to(P_MAX_NO).oneOf()
    nondet rnx = 1.to(P_MAX_NO + 1).oneOf()
    nondet rv = NOS.powerset().oneOf()
    nondet rrv = NOS.powerset().oneOf()
    nondet rfull = setOfMaps(NOS, RIGHTS).oneOf()
    nondet pcp = CPS.powerset().oneOf()
    nondet ppp = PPS.powerset().oneOf()
    nondet prc = RCS.powerset().oneOf()
    nondet php = HPS.powerset().oneOf()
    nondet pdata = DATAS.powerset().oneOf()
    nondet b = BROKEN.powerset().oneOf()
    nondet sn = Set("accept", "grant").powerset().oneOf()
    val hist = SLOTS.filter(s => hIn.get(s))
      .map(s => { gen: s._1, no: s._2, start: hStart.get(s), valid: hValid.get(s), nextNo: hNext.get(s) })
    val ns = P_DEVICES.mapBy(d => {
      gen: gens.get(d),
      cp: { gen: cpGen.get(d), no: cpNo.get(d), start: cpStart.get(d), valid: cpValid.get(d), nextNo: cpNext.get(d) },
      pps: NOS.filter(k => ppIn.get(d).get(k))
        .map(k => { gen: ppGen.get(d).get(k), no: k, dev: ppDev.get(d).get(k), rights: ppRights.get(d).get(k) }),
      rc: rcs.get(d), halted: halts.get(d),
      forever: forevers.get(d), recvCp: Set(), recvPp: Set(), recvRc: Set(), recvHp: hps.get(d),
    })
    val r = { gen: rg, cpNo: rcp, nextNo: rnx, valid: rv,
              rights: NOS.filter(k => k < rnx).mapBy(k => rfull.get(k)), revoked: rrv }
    val p = { cp: pcp, pp: ppp, rc: prc, hp: php, data: pdata }
    all {
      structOf(ns, r, p, hist, b, sn),
      B::nodes' = ns, B::root' = r, B::pool' = p, B::history' = hist, B::broken' = b, B::seen' = sn,
    }
  }

  // ----------------------------------------------------------- initial states
  action initStruct = all { A::init, B::init, stage' = 0, mv' = NO_MOVE, matchOk' = true }
  action initSafe = all { drawA, B::init, stage' = 0, mv' = NO_MOVE, matchOk' = true }
  action initPair = all { drawA, drawB, stage' = 0, mv' = NO_MOVE, matchOk' = true }

  // Names run-inductive.ps1 uses for its first, cheap check (Apalache download).
  action modelInit = initStruct
  action modelStep = stepReboot
  val IndInv = structA

  val sameSafety = (viewA == viewB) implies (A::safety iff B::safety)
  val matched = stage != 2 or (matchOk and viewA == viewB)
  // Non-vacuity: expected to be violated (a pair with equal views exists; B answers).
  val witnessPair = viewA != viewB
  val witnessAnswered = stage != 2

  // ------------------------------------------------- A's step, branch by branch
  // The branches of `step` in membership.qnt as inductive.qnt splits them,
  // with the values each action picks inside drawn here and recorded. O2
  // runs stepX from initSafe; O4 runs matchX from initPair.
  action pre = all { stage == 0, A::safety }
  action stepRootAdmit = all { pre, bStay, stage' = 1, matchOk' = true,
    nondet d = P_DEVICES.oneOf() nondet r = RIGHTS.oneOf()
    all { A::rootIssue(d, r, Set()), mv' = { ...NO_MOVE, kind: "admit", d: d, r: r } } }
  action stepRootChangeRights = all { pre, bStay, stage' = 1, matchOk' = true,
    A::root.valid != Set(),
    nondet k = A::root.valid.oneOf()
    val old = A::pool.pp.filter(p => p.gen == A::root.gen and p.no == k)
    all { old != Set(), nondet p = old.oneOf() nondet r = RIGHTS.oneOf()
          all { A::rootIssue(p.dev, r, Set(k)), mv' = { ...NO_MOVE, kind: "change", d: p.dev, r: r, k: k } } } }
  action stepRootRevoke = all { pre, bStay, stage' = 1, matchOk' = true,
    A::root.valid != Set(), A::root.cpNo < P_MAX_NO,
    nondet k = A::root.valid.oneOf()
    val v = A::root.valid.exclude(Set(k))
    val c = A::rootCheckpoint(v, A::root.nextNo)
    all { A::commit(A::nodes, { ...A::root, cpNo: A::root.cpNo + 1, valid: v, revoked: A::root.revoked.union(Set(k)) },
                    { ...A::pool, cp: A::pool.cp.union(Set(c)) }, A::history.union(Set(c))),
          mv' = { ...NO_MOVE, kind: "revoke", k: k } } }
  action stepRootEquivocateCp = all { pre, bStay, stage' = 1, matchOk' = true,
    nondet c = A::pool.cp.filter(c => c.gen == A::root.gen and c.no >= 1).oneOf()
    nondet k = 1.to(P_MAX_NO).oneOf()
    val v = if (c.valid.contains(k)) c.valid.exclude(Set(k)) else c.valid.union(Set(k))
    val c2 = { ...c, valid: v.filter(x => c.start <= x and x < c.nextNo) }
    all { c2 != c, A::commit(A::nodes, A::root, { ...A::pool, cp: A::pool.cp.union(Set(c2)) }, A::history),
          mv' = { ...NO_MOVE, kind: "eqCp", c: c, k: k } } }
  action stepRootEquivocatePp = all { pre, bStay, stage' = 1, matchOk' = true,
    nondet p = A::pool.pp.filter(p => p.gen == A::root.gen).oneOf()
    val p2 = { ...p, rights: 3 - p.rights }
    all { A::commit(A::nodes, A::root, { ...A::pool, pp: A::pool.pp.union(Set(p2)) }, A::history),
          mv' = { ...NO_MOVE, kind: "eqPp", p: p } } }
  action stepRecoveryChange = all { pre, bStay, stage' = 1, matchOk' = true,
    A::recoveryChange, mv' = { ...NO_MOVE, kind: "recovery" } }
  action stepRecoveryEquivocate = all { pre, bStay, stage' = 1, matchOk' = true,
    nondet rc = A::pool.rc.oneOf()
    val rc2 = { ...rc, key: 1 - rc.key }
    all { A::commit(A::nodes, A::root, { ...A::pool, rc: A::pool.rc.union(Set(rc2)) }, A::history),
          mv' = { ...NO_MOVE, kind: "eqRc", rc: rc } } }
  // adversaryProof: the proof assembled from two conflicting records.
  action stepAdversaryProof = all { pre, bStay, stage' = 1, matchOk' = true,
    any {
      nondet a = A::pool.cp.oneOf() nondet b = A::pool.cp.oneOf()
      all { A::cpConflict(a, b), A::setNodeless(A::pool.hp.union(Set({ kind: "cp", gen: a.gen, no: a.no }))),
            mv' = { ...NO_MOVE, kind: "proof", h: { kind: "cp", gen: a.gen, no: a.no } } },
      nondet a = A::pool.pp.oneOf() nondet b = A::pool.pp.oneOf()
      all { A::ppConflict(a, b), A::setNodeless(A::pool.hp.union(Set({ kind: "pp", gen: a.gen, no: a.no }))),
            mv' = { ...NO_MOVE, kind: "proof", h: { kind: "pp", gen: a.gen, no: a.no } } },
      nondet a = A::pool.rc.oneOf() nondet b = A::pool.rc.oneOf()
      all { a.gen == b.gen and a != b, A::setNodeless(A::pool.hp.union(Set({ kind: "rc", gen: a.gen, no: 0 }))),
            mv' = { ...NO_MOVE, kind: "proof", h: { kind: "rc", gen: a.gen, no: 0 } } },
    } }
  action stepRecvCp = all { pre, bStay, stage' = 1, matchOk' = true,
    nondet d = P_DEVICES.oneOf()
    all { A::pool.cp != Set(), nondet c = A::pool.cp.oneOf()
          all { A::nodeRecvCp(d, c), mv' = { ...NO_MOVE, kind: "recvCp", d: d, c: c } } } }
  action stepRecvPp = all { pre, bStay, stage' = 1, matchOk' = true,
    nondet d = P_DEVICES.oneOf()
    all { A::pool.pp != Set(), nondet p = A::pool.pp.oneOf()
          all { A::nodeRecvPp(d, p), mv' = { ...NO_MOVE, kind: "recvPp", d: d, p: p } } } }
  action stepRecvRc = all { pre, bStay, stage' = 1, matchOk' = true,
    nondet d = P_DEVICES.oneOf()
    all { A::pool.rc != Set(), nondet rc = A::pool.rc.oneOf()
          all { A::nodeRecvRc(d, rc), mv' = { ...NO_MOVE, kind: "recvRc", d: d, rc: rc } } } }
  action stepRecvHp = all { pre, bStay, stage' = 1, matchOk' = true,
    nondet d = P_DEVICES.oneOf()
    all { A::pool.hp != Set(), nondet h = A::pool.hp.oneOf()
          all { A::nodeRecvHp(d, h), mv' = { ...NO_MOVE, kind: "recvHp", d: d, h: h } } } }
  action stepAcceptData = all { pre, bStay, stage' = 1, matchOk' = true,
    nondet d = P_DEVICES.oneOf()
    all { A::pool.data != Set(), nondet m = A::pool.data.oneOf()
          all { A::nodeAcceptData(d, m), mv' = { ...NO_MOVE, kind: "accept", d: d, m: m } } } }
  // nodeHearsHalted: the proof it hands to nodeRecvHp.
  action stepHearsHalted = all { pre, bStay, stage' = 1, matchOk' = true,
    nondet d = P_DEVICES.oneOf()
    val n = A::nodes.get(d)
    val proofs = A::pool.hp.filter(h =>
      (h.kind != "rc" and h.gen == n.gen and A::haltedPeer(d, n.gen)) or (h.kind == "rc" and A::foreverPeer(d)))
    all { proofs != Set(), nondet h = proofs.oneOf()
          all { A::nodeRecvHp(d, h), mv' = { ...NO_MOVE, kind: "hears", d: d, h: h } } } }
  action stepReboot = all { pre, bStay, stage' = 1, matchOk' = true,
    nondet d = P_DEVICES.oneOf() all { A::nodeReboot(d), mv' = { ...NO_MOVE, kind: "reboot", d: d } } }
  // nodeSend: the passport number and channel of the message.
  action stepSend = all { pre, bStay, stage' = 1, matchOk' = true,
    nondet d = P_DEVICES.oneOf()
    val n = A::nodes.get(d)
    val mine = A::pool.pp.filter(p => p.dev == d and p.gen == n.gen)
    all { not(n.halted), mine != Set(), nondet p = mine.oneOf() nondet ch0 = Set(false, true).oneOf()
          all { A::setNode(d, n, { ...A::pool, data: A::pool.data.union(Set({ src: d, ppNo: p.no, gen: n.gen,
                                                                               cpNo: n.cp.no, ch0: ch0 })) }),
                mv' = { ...NO_MOVE, kind: "send", d: d, ppNo: p.no, ch0: ch0 } } } }
  // nodeGrant: the passport it grants to.
  action stepGrant = all { pre, bStay, stage' = 1, matchOk' = true,
    nondet d = P_DEVICES.oneOf()
    val n = A::nodes.get(d)
    all { n.pps != Set(), not(n.halted), nondet p = n.pps.oneOf()
          all { p.dev != d, A::canRead(p.rights), A::validUnder(p, n.cp),
                val e = { node: d, peer: p.dev, ppNo: p.no, msgGen: p.gen, rights: p.rights, ch0: false, cp: n.cp,
                          halted: n.halted }
                A::commitWith(A::nodes, A::root, A::pool, A::history, A::entryProblems(e, A::history, true), Set("grant")),
                mv' = { ...NO_MOVE, kind: "grant", d: d, p: p } } } }

  // --------------------------------------------------------------- B's answer
  // B does nothing when the views already agree; otherwise it takes the same
  // action as A with A's values. Each guard copies the guard of that action
  // in membership.qnt under MUTANT = "none" (with the condition of its branch
  // in `step` and the set its value is picked from), so that B's step is taken
  // exactly when the guard holds; matchOk records it.
  action bNone = all { bStay, matchOk' = false }
  action answer = {
    val r = B::root
    if (mv.kind == "admit") {
      val c = B::rootCheckpoint(r.valid.union(Set(r.nextNo)), r.nextNo + 1)
      if (r.nextNo <= P_MAX_NO and r.cpNo < P_MAX_NO and c.nextNo - c.start <= P_WINDOW)
        all { B::rootIssue(mv.d, mv.r, Set()), matchOk' = true }
      else bNone
    }
    else if (mv.kind == "change") {
      val c = B::rootCheckpoint(r.valid.exclude(Set(mv.k)).union(Set(r.nextNo)), r.nextNo + 1)
      if (r.valid != Set() and r.valid.contains(mv.k)
          and B::pool.pp.exists(p => p.gen == r.gen and p.no == mv.k and p.dev == mv.d)
          and r.nextNo <= P_MAX_NO and r.cpNo < P_MAX_NO and c.nextNo - c.start <= P_WINDOW)
        all { B::rootIssue(mv.d, mv.r, Set(mv.k)), matchOk' = true }
      else bNone
    }
    else if (mv.kind == "revoke")
      if (r.valid != Set() and r.cpNo < P_MAX_NO and r.valid.contains(mv.k)) {
        val v = r.valid.exclude(Set(mv.k))
        val c = B::rootCheckpoint(v, r.nextNo)
        all { B::commit(B::nodes, { ...r, cpNo: r.cpNo + 1, valid: v, revoked: r.revoked.union(Set(mv.k)) },
                        { ...B::pool, cp: B::pool.cp.union(Set(c)) }, B::history.union(Set(c))),
              matchOk' = true }
      } else bNone
    else if (mv.kind == "eqCp") {
      val c = mv.c
      val v = if (c.valid.contains(mv.k)) c.valid.exclude(Set(mv.k)) else c.valid.union(Set(mv.k))
      val c2 = { ...c, valid: v.filter(x => c.start <= x and x < c.nextNo) }
      if (B::pool.cp.contains(c) and c.gen == r.gen and c.no >= 1 and 1 <= mv.k and mv.k <= P_MAX_NO and c2 != c)
        all { B::commit(B::nodes, r, { ...B::pool, cp: B::pool.cp.union(Set(c2)) }, B::history), matchOk' = true }
      else bNone
    }
    else if (mv.kind == "eqPp") {
      val p2 = { ...mv.p, rights: 3 - mv.p.rights }
      if (B::pool.pp.contains(mv.p) and mv.p.gen == r.gen)
        all { B::commit(B::nodes, r, { ...B::pool, pp: B::pool.pp.union(Set(p2)) }, B::history), matchOk' = true }
      else bNone
    }
    else if (mv.kind == "recovery")
      if (r.gen < P_MAX_GEN) all { B::recoveryChange, matchOk' = true }
      else bNone
    else if (mv.kind == "eqRc") {
      val rc2 = { ...mv.rc, key: 1 - mv.rc.key }
      if (B::pool.rc.contains(mv.rc))
        all { B::commit(B::nodes, r, { ...B::pool, rc: B::pool.rc.union(Set(rc2)) }, B::history), matchOk' = true }
      else bNone
    }
    else if (mv.kind == "proof") {
      val h = mv.h
      val ok = if (h.kind == "cp")
                 B::pool.cp.exists(a => B::pool.cp.exists(b => B::cpConflict(a, b) and a.gen == h.gen and a.no == h.no))
               else if (h.kind == "pp")
                 B::pool.pp.exists(a => B::pool.pp.exists(b => B::ppConflict(a, b) and a.gen == h.gen and a.no == h.no))
               else
                 B::pool.rc.exists(a => B::pool.rc.exists(b => a.gen == b.gen and a != b and a.gen == h.gen))
      if (ok) all { B::setNodeless(B::pool.hp.union(Set(h))), matchOk' = true }
      else bNone
    }
    else if (mv.kind == "recvCp")
      if (B::pool.cp.contains(mv.c)) all { B::nodeRecvCp(mv.d, mv.c), matchOk' = true }
      else bNone
    else if (mv.kind == "recvPp")
      if (B::pool.pp.contains(mv.p)) all { B::nodeRecvPp(mv.d, mv.p), matchOk' = true }
      else bNone
    else if (mv.kind == "recvRc")
      if (B::pool.rc.contains(mv.rc)) all { B::nodeRecvRc(mv.d, mv.rc), matchOk' = true }
      else bNone
    else if (mv.kind == "recvHp")
      if (B::pool.hp.contains(mv.h)) all { B::nodeRecvHp(mv.d, mv.h), matchOk' = true }
      else bNone
    else if (mv.kind == "accept") {
      val n = B::nodes.get(mv.d)
      // The message of the same sender, passport number, generation and
      // channel with the lowest checkpoint number: the one the view keeps
      // (there is exactly one). nodeAcceptData then picks the passport of
      // that sender and number from the cache, which holds one per number
      // (Struct), so the answer is deterministic.
      val ms = B::pool.data.filter(x => sameData(x, mv.m)
                                        and B::pool.data.forall(y => not(sameData(y, mv.m) and y.cpNo < x.cpNo)))
      if (ms != Set()) {
        nondet m = ms.oneOf()
        if (not(n.halted) and m.src != mv.d and m.gen == n.gen and not(B::lexGt(m.gen, m.cpNo, n.gen, n.cp.no))
            and n.pps.exists(p => p.dev == m.src and p.no == m.ppNo and B::validUnder(p, n.cp)
                                  and (m.ch0 or B::canPublish(p.rights))))
          all { B::nodeAcceptData(mv.d, m), matchOk' = true }
        else bNone
      } else bNone
    }
    else if (mv.kind == "hears") {
      val n = B::nodes.get(mv.d)
      val proofs = B::pool.hp.filter(h =>
        (h.kind != "rc" and h.gen == n.gen and B::haltedPeer(mv.d, n.gen)) or (h.kind == "rc" and B::foreverPeer(mv.d)))
      if (proofs != Set() and proofs.contains(mv.h)) all { B::nodeRecvHp(mv.d, mv.h), matchOk' = true }
      else bNone
    }
    else if (mv.kind == "reboot") all { B::nodeReboot(mv.d), matchOk' = true }
    else if (mv.kind == "send") {
      val n = B::nodes.get(mv.d)
      val mine = B::pool.pp.filter(p => p.dev == mv.d and p.gen == n.gen)
      if (not(n.halted) and mine != Set() and mine.exists(p => p.no == mv.ppNo))
        all { B::setNode(mv.d, n, { ...B::pool, data: B::pool.data.union(Set({ src: mv.d, ppNo: mv.ppNo, gen: n.gen,
                                                                               cpNo: n.cp.no, ch0: mv.ch0 })) }),
              matchOk' = true }
      else bNone
    }
    else if (mv.kind == "grant") {
      val n = B::nodes.get(mv.d)
      val p = mv.p
      if (n.pps != Set() and not(n.halted) and n.pps.contains(p) and p.dev != mv.d and B::canRead(p.rights)
          and B::validUnder(p, n.cp)) {
        val e = { node: mv.d, peer: p.dev, ppNo: p.no, msgGen: p.gen, rights: p.rights, ch0: false, cp: n.cp,
                  halted: n.halted }
        all { B::commitWith(B::nodes, r, B::pool, B::history, B::entryProblems(e, B::history, true), Set("grant")),
              matchOk' = true }
      } else bNone
    }
    else bNone
  }
  action respond = all { stage == 1, aStay, stage' = 2, mv' = mv,
    if (viewA == viewB) all { bStay, matchOk' = true } else answer }
  action matchRootAdmit = any { all { viewA == viewB, stepRootAdmit }, respond }
  action matchRootChangeRights = any { all { viewA == viewB, stepRootChangeRights }, respond }
  action matchRootRevoke = any { all { viewA == viewB, stepRootRevoke }, respond }
  action matchRootEquivocateCp = any { all { viewA == viewB, stepRootEquivocateCp }, respond }
  action matchRootEquivocatePp = any { all { viewA == viewB, stepRootEquivocatePp }, respond }
  action matchRecoveryChange = any { all { viewA == viewB, stepRecoveryChange }, respond }
  action matchRecoveryEquivocate = any { all { viewA == viewB, stepRecoveryEquivocate }, respond }
  action matchAdversaryProof = any { all { viewA == viewB, stepAdversaryProof }, respond }
  action matchRecvCp = any { all { viewA == viewB, stepRecvCp }, respond }
  action matchRecvPp = any { all { viewA == viewB, stepRecvPp }, respond }
  action matchRecvRc = any { all { viewA == viewB, stepRecvRc }, respond }
  action matchRecvHp = any { all { viewA == viewB, stepRecvHp }, respond }
  action matchAcceptData = any { all { viewA == viewB, stepAcceptData }, respond }
  action matchHearsHalted = any { all { viewA == viewB, stepHearsHalted }, respond }
  action matchReboot = any { all { viewA == viewB, stepReboot }, respond }
  action matchSend = any { all { viewA == viewB, stepSend }, respond }
  action matchGrant = any { all { viewA == viewB, stepGrant }, respond }
}

// The proof instance: the constants of `tiny_tlc` in instances.qnt.
module tiny_tlc_bisim {
  import bisim(P_DEVICES = Set("a", "b"), P_MAX_GEN = 2, P_MAX_NO = 2, P_WINDOW = 2).*
}
