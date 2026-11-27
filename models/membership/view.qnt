// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 HunterEwok
//
// A state view of the membership model for exhaustive TLC runs (TLC option
// VIEW). TLC stores and expands one state per value of `viewOf`; `bisim`
// proves with Apalache that states with equal views are interchangeable for
// `safety`, so the reduced search finds a violation exactly when the full one
// does. Valid only for MUTANT = "none", TRACK_RECV = false.
//
// The view drops what can no longer influence `safety`:
// - the witness tags `seen` and `root.rights`, which are write-only;
// - `root.revoked` beyond the boolean `rootHonorsRevocation`
//   (`root.valid.intersect(root.revoked) == Set()`);
// - `pool.data` completely: under MUTANT = "none" and `Struct` (honest
//   history monotonicity), `nodeAcceptData` never adds to `broken` and changes
//   only `seen`, so `nodeSend` and `nodeAcceptData` stutter on the view;
// - `history` beyond the two booleans `windowBounded` and `windowKeepsValid`
//   (no action guard reads `history`, and `nodeGrant` never adds to `broken`
//   under `Struct`);
// - passport `dev` and `rights` fields in both `pool.pp` and per-node `pps`:
//   `pool.pp` collapses to the count (`0`, `1`, or `2`) per needed `(gen, no)`
//   slot (dropping non-equivocated slots of old generations `< root.gen`) and
//   each node's `pps` collapses to its set of `(gen, no)` pairs that can still
//   conflict (`gen == root.gen` or already equivocated);
// - `pool.hp` beyond `(hpRc, hpGens)` (whether an `"rc"` proof exists and
//   which live generations have a non-`"rc"` proof): under MUTANT = "none",
//   `h.no` and `"cp"` vs `"pp"` are never distinguished;
// - per-node `recvHp` beyond `(hasRcHp, proofObeyedOk)` (and `recvCp`,
//   `recvPp`, `recvRc` are empty when `TRACK_RECV = false`);
// - all fields of a permanently halted node (`forever`), and `(cp, pps)` of a
//   temporarily halted node (`halted and not(forever)`), once `currentGeneration`
//   holds for that node;
// - `(cp, pps)` of any live node in a generation `g` that either already has a
//   non-`"rc"` proof in `pool.hp` (`hpGens.contains(g)`) or is an old
//   conflict-free generation (`g < root.gen` with no `cp`/`pp` conflict in `g`,
//   so no halt in `g` is possible anymore);
// - in any old generation `g < root.gen` with a conflict (`oldConflict`:
//   `not(hpGens.contains(g))`, `hasConflict`, some unhalted node in `g`),
//   checkpoints in `pool.cp` and live nodes' `n.cp` are projected to
//   `(no, valid intersected with equivNos(g))` (`oldCpProjs` and `tag = "live_old"`), plus
//   `oldCpConfl` recording which `(g, no)` slots have >= 2 checkpoints: no new
//   records can be issued in `g`, `start`/`nextNo` and non-equivocated bits
//   are never read, and a conflict halt at `cp.no >= 1` is enabled iff
//   `(g, cp.no)` is in `oldCpConfl`;
// - `pool.cp` and `pool.pp` for any generation `g` where `hpGens.contains(g)`,
//   or `g` is old and conflict-free, or neither `root` nor any unhalted node
//   is in `g` (keeping only `poolPp` presence `0|1` when `root.gen == g` for
//   `rootChangeRights`, `2` on equivocated slots of `oldConflict`, and
//   `canProveGens` if a proof can still be assembled);
// - every field except `broken` once all nodes are permanently halted (with
//   `rootRevOk`, `windowBoundedOk`, `windowKeepsValidOk`).
module viewdefs {
  const V_DEVICES: Set[str]
  const V_MAX_GEN: int
  const V_MAX_NO: int
  const V_WINDOW: int

  type VPassport = { gen: int, no: int, dev: str, rights: int }
  type VCheckpoint = { gen: int, no: int, start: int, valid: Set[int], nextNo: int }
  type VRootChange = { gen: int, key: int }
  type VHaltProof = { kind: str, gen: int, no: int }
  type VData = { src: str, ppNo: int, gen: int, cpNo: int, ch0: bool }
  type VNode = {
    gen: int,
    cp: VCheckpoint,
    pps: Set[VPassport],
    rc: int,
    halted: bool,
    forever: bool,
    recvCp: Set[VCheckpoint],
    recvPp: Set[VPassport],
    recvRc: Set[VRootChange],
    recvHp: Set[VHaltProof],
  }
  type VRoot = {
    gen: int,
    cpNo: int,
    nextNo: int,
    valid: Set[int],
    rights: int -> int,
    revoked: Set[int],
  }
  type VPool = {
    cp: Set[VCheckpoint],
    pp: Set[VPassport],
    rc: Set[VRootChange],
    hp: Set[VHaltProof],
    data: Set[VData],
  }

  type NodeView = {
    tag: str,
    gen: int,
    cp: VCheckpoint,
    pps: Set[(int, int)],
    rc: int,
    halted: bool,
    forever: bool,
    hasRcHp: bool,
    proofObeyedOk: bool,
    curGenOk: bool,
    cacheOk: bool,
    keyOk: bool,
  }
  type RootView = {
    gen: int,
    cpNo: int,
    nextNo: int,
    valid: Set[int],
    revOk: bool,
  }
  type View = {
    allForever: bool,
    nodes: str -> NodeView,
    root: RootView,
    poolCp: Set[VCheckpoint],
    oldCpProjs: (int, int, Set[int]) -> bool,
    oldCpConfl: Set[(int, int)],
    poolPp: (int, int) -> int,
    poolRc: Set[VRootChange],
    hpRc: bool,
    hpGens: Set[int],
    canProveGens: Set[int],
    windowBoundedOk: bool,
    windowKeepsValidOk: bool,
    broken: Set[str],
  }

  pure val V_GENS = 1.to(V_MAX_GEN)
  pure val V_NOS = 1.to(V_MAX_NO)
  pure val V_SLOTS = tuples(V_GENS, V_NOS)
  pure val V_OLD_KEYS: Set[(int, int, Set[int])] =
    if (V_MAX_NO == 2)
      tuples(V_GENS, Set((1, Set()), (1, Set(1)), (2, Set()), (2, Set(1)), (2, Set(2)), (2, Set(1, 2))))
        .map(t => (t._1, t._2._1, t._2._2))
    else
      tuples(V_GENS, V_NOS, V_NOS.powerset())
  pure def vGenesis(g: int): VCheckpoint = { gen: g, no: 0, start: 1, valid: Set(), nextNo: 1 }
  pure def oldCpProj(c: VCheckpoint, eNos: Set[int]): VCheckpoint =
    { gen: c.gen, no: c.no, start: 1, valid: c.valid.intersect(eNos), nextNo: 1 }
  pure def vValidIn(p: VPassport, c: VCheckpoint): bool =
    p.gen == c.gen and c.start <= p.no and p.no < c.nextNo and c.valid.contains(p.no)
  pure def curGenOk(n: VNode): bool = n.cp.gen == n.gen and n.pps.forall(p => p.gen == n.gen)
  pure def cacheOk(n: VNode): bool = n.pps.forall(p => vValidIn(p, n.cp))
  // The node's part of installedKeyOnly (signer in membership.qnt).
  pure def keyOkOf(n: VNode): bool =
    n.rc == (if (n.gen == 1) -1 else 0) or (n.cp == vGenesis(n.gen) and n.pps == Set())
  pure val FOREVER_NODE: NodeView = {
    tag: "forever",
    gen: 0,
    cp: vGenesis(0),
    pps: Set(),
    rc: 0,
    halted: true,
    forever: true,
    hasRcHp: true,
    proofObeyedOk: true,
    curGenOk: true,
    cacheOk: true,
    keyOk: true,
  }
  pure val ZERO_ROOT: RootView = { gen: 0, cpNo: 0, nextNo: 0, valid: Set(), revOk: true }

  pure def nodeViewOf(n: VNode, rGen: int, hpGens: Set[int], cleanOld: Set[int],
                      oldConflict: Set[int], equivPp: Set[(int, int)]): NodeView = {
    val hasRcHp = n.recvHp.exists(x => x.kind == "rc")
    val proofObeyedOk = n.recvHp.exists(x => x.gen == n.gen or x.kind == "rc") implies n.halted
    val cg = curGenOk(n)
    val co = cacheOk(n)
    val ko = keyOkOf(n)
    if (n.forever and n.halted and cg and ko) FOREVER_NODE
    else if (n.halted and not(n.forever) and cg and ko) {
      tag: "halted",
      gen: n.gen,
      cp: vGenesis(n.gen),
      pps: Set(),
      rc: n.rc,
      halted: true,
      forever: false,
      hasRcHp: hasRcHp,
      proofObeyedOk: true,
      curGenOk: true,
      cacheOk: true,
      keyOk: true,
    } else if (not(n.halted) and not(n.forever) and (hpGens.contains(n.gen) or cleanOld.contains(n.gen)) and cg and co and ko) {
      tag: if (hpGens.contains(n.gen)) "live_hp" else "live_clean",
      gen: n.gen,
      cp: vGenesis(n.gen),
      pps: Set(),
      rc: n.rc,
      halted: false,
      forever: false,
      hasRcHp: hasRcHp,
      proofObeyedOk: proofObeyedOk,
      curGenOk: true,
      cacheOk: true,
      keyOk: true,
    } else if (not(n.halted) and not(n.forever) and oldConflict.contains(n.gen) and cg and co and ko) {
      val eNos = V_NOS.filter(k => equivPp.contains((n.gen, k)))
      {
        tag: "live_old",
        gen: n.gen,
        cp: oldCpProj(n.cp, eNos),
        pps: n.pps.filter(x => equivPp.contains((x.gen, x.no))).map(x => (x.gen, x.no)),
        rc: n.rc,
        halted: false,
        forever: false,
        hasRcHp: hasRcHp,
        proofObeyedOk: proofObeyedOk,
        curGenOk: true,
        cacheOk: true,
        keyOk: true,
      }
    } else {
      tag: "live",
      gen: n.gen,
      cp: n.cp,
      pps: n.pps.filter(x => x.gen == rGen or equivPp.contains((x.gen, x.no))).map(x => (x.gen, x.no)),
      rc: n.rc,
      halted: n.halted,
      forever: n.forever,
      hasRcHp: hasRcHp,
      proofObeyedOk: proofObeyedOk,
      curGenOk: cg,
      cacheOk: co,
      keyOk: ko,
    }
  }

  pure def viewOf(ns: str -> VNode, r: VRoot, p: VPool, h: Set[VCheckpoint], b: Set[str]): View = {
    val isForever = V_DEVICES.mapBy(d => {
      val n = ns.get(d)
      n.forever and n.halted and curGenOk(n) and keyOkOf(n)
    })
    val rootRevOk = r.valid.intersect(r.revoked) == Set()
    val windowBoundedOk = h.forall(c => c.nextNo - c.start <= V_WINDOW)
    val windowKeepsValidOk = h.forall(c =>
      (c.gen == r.gen and c.no == r.cpNo) implies (c.valid == r.valid and c.nextNo == r.nextNo))
    val allForever = V_DEVICES.forall(d => isForever.get(d)) and rootRevOk and windowBoundedOk and windowKeepsValidOk
    if (allForever) {
      allForever: true,
      nodes: V_DEVICES.mapBy(d => FOREVER_NODE),
      root: ZERO_ROOT,
      poolCp: Set(),
      oldCpProjs: V_OLD_KEYS.mapBy(q => false),
      oldCpConfl: Set(),
      poolPp: V_SLOTS.mapBy(s => 0),
      poolRc: Set(),
      hpRc: true,
      hpGens: Set(),
      canProveGens: Set(),
      windowBoundedOk: true,
      windowKeepsValidOk: true,
      broken: b,
    } else {
      val liveGens = V_DEVICES.filter(d => not(isForever.get(d))).map(d => ns.get(d).gen).union(Set(r.gen))
      val minGen = liveGens.fold(V_MAX_GEN, (m, g) => if (g < m) g else m)
      val hpGens = V_GENS.filter(g => g >= minGen and p.hp.exists(x => x.kind != "rc" and x.gen == g))
      val cpSlotConfl = V_SLOTS.filter(s =>
        p.cp.exists(x => x.gen == s._1 and x.no == s._2
                         and p.cp.exists(y => y.gen == s._1 and y.no == s._2 and x != y)))
      val equivPp = V_SLOTS.filter(s =>
        p.pp.exists(x => x.gen == s._1 and x.no == s._2
                         and p.pp.exists(y => y.gen == s._1 and y.no == s._2 and x != y)))
      val hasConflict = V_GENS.mapBy(g =>
        V_NOS.exists(k => cpSlotConfl.contains((g, k)) or equivPp.contains((g, k))))
      val cleanOld = V_GENS.filter(g => g < r.gen and not(hpGens.contains(g)) and not(hasConflict.get(g)))
      val hasUnhalted = V_GENS.mapBy(g => V_DEVICES.exists(d => not(ns.get(d).halted) and ns.get(d).gen == g))
      val oldConflict = V_GENS.filter(g =>
        g < r.gen and not(hpGens.contains(g)) and hasConflict.get(g) and hasUnhalted.get(g))
      val cpNeeded = V_GENS.filter(g =>
        not(hpGens.contains(g)) and not(cleanOld.contains(g)) and not(oldConflict.contains(g))
        and (r.gen == g or hasUnhalted.get(g)))
      val canProveGens = V_GENS.filter(g =>
        g >= minGen and not(hpGens.contains(g)) and not(cpNeeded.contains(g)) and not(oldConflict.contains(g))
        and hasConflict.get(g))
      {
        allForever: false,
        nodes: V_DEVICES.mapBy(d => nodeViewOf(ns.get(d), r.gen, hpGens, cleanOld, oldConflict, equivPp)),
        root: {
          gen: r.gen,
          cpNo: r.cpNo,
          nextNo: r.nextNo,
          valid: r.valid,
          revOk: rootRevOk,
        },
        poolCp: p.cp.filter(c => cpNeeded.contains(c.gen)),
        oldCpProjs: V_OLD_KEYS.mapBy(q =>
          oldConflict.contains(q._1)
          and p.cp.exists(c => c.gen == q._1 and c.no == q._2
                               and c.valid.intersect(V_NOS.filter(k => equivPp.contains((q._1, k)))) == q._3)),
        oldCpConfl: cpSlotConfl.filter(s => oldConflict.contains(s._1)),
        poolPp: V_SLOTS.mapBy(s =>
          if (cpNeeded.contains(s._1)) {
            if (equivPp.contains(s)) 2
            else if (s._1 == r.gen and p.pp.exists(x => x.gen == s._1 and x.no == s._2)) 1
            else 0
          } else if (oldConflict.contains(s._1)) {
            if (equivPp.contains(s)) 2 else 0
          } else if (s._1 == r.gen and p.pp.exists(x => x.gen == s._1 and x.no == s._2)) 1
          else 0),
        poolRc: p.rc,
        hpRc: p.hp.exists(x => x.kind == "rc"),
        hpGens: hpGens,
        canProveGens: canProveGens,
        windowBoundedOk: windowBoundedOk,
        windowKeepsValidOk: windowKeepsValidOk,
        broken: b,
      }
    }
  }
}

// The instance `tiny_tlc` of instances.qnt with its view, for TLC. The
// constants must stay those of `tiny_tlc`.
module tiny_tlc_view {
  import membership(DEVICES = Set("a", "b"), MAX_GEN = 2, MAX_NO = 2, WINDOW = 2, MUTANT = "none",
                    TRACK_RECV = false).* from "./membership"
  import viewdefs(V_DEVICES = Set("a", "b"), V_MAX_GEN = 2, V_MAX_NO = 2, V_WINDOW = 2).*
  // Force TLC 1.7.4 to normalize every lazy map (FcnLambdaValue) in the state
  // before StatePoolWriter spills states to disk when VIEW drops or wraps them.
  val safetyView = {
    val v = viewOf(nodes, root, pool, history, broken)
    if (nodes != Map() and (root.rights == Map() or root.rights != Map())) v else v
  }
}

// Proof that the view is exact for `safety` (R-VER-3), checked by Apalache on
// two copies A and B of the model:
//   O1. init implies Struct                               (initStruct, 0 steps, invariant structA)
//   O2. Struct, safety and one step imply Struct          (initSafe, stepX, 1 step, invariant structA)
//   O3. two Struct states with equal views agree on safety (initPair, 0 steps, invariant sameSafety)
//   O4. for two Struct states with equal views, A safe, every step of A is
//       answered by B with no step or one step, and the views are equal again
//       (initPair, matchX, 2 steps, invariant matched).
// Struct is a set of facts about the model's counters and structure. It does
// not assume `broken == Set()`; one of its facts, one passport per number in a
// node's cache, is also the conflict half of `cacheConsistent`, and O1 and O2
// prove it like every other fact of Struct.
//
// O4 splits each step with several outcomes into cases whose extra guards
// cover every choice of the step (halt / advance / no-op and the like), and
// each case still takes the model's own action; O2 checks the whole step.
module bisim {
  const P_DEVICES: Set[str]
  const P_MAX_GEN: int
  const P_MAX_NO: int
  const P_WINDOW: int
  import membership(DEVICES = P_DEVICES, MAX_GEN = P_MAX_GEN, MAX_NO = P_MAX_NO, WINDOW = P_WINDOW,
                    MUTANT = "none", TRACK_RECV = false) as A from "./membership"
  import membership(DEVICES = P_DEVICES, MAX_GEN = P_MAX_GEN, MAX_NO = P_MAX_NO, WINDOW = P_WINDOW,
                    MUTANT = "none", TRACK_RECV = false) as B from "./membership"
  import viewdefs(V_DEVICES = P_DEVICES, V_MAX_GEN = P_MAX_GEN, V_MAX_NO = P_MAX_NO, V_WINDOW = P_WINDOW).*

  // ------------------------------------------------------------ bounded types
  pure val RIGHTS = Set(0, 1, 2, 3)
  pure val SLOTS = V_SLOTS
  pure val BROKEN = Set("noRollback", "currentGeneration", "haltIsSticky", "haltedIsInert",
                        "revokedIsRejected", "grantsNeedRead", "dataNeedsPublish")
  pure val TAGS = Set("accept", "grant", "revokedSend")

  pure val SHAPES_2: Set[(int, int, int, Set[int])] = Set(
    (1, 1, 1, Set()), (1, 1, 2, Set()), (1, 1, 2, Set(1)), (1, 2, 2, Set()),
    (2, 1, 1, Set()), (2, 1, 2, Set()), (2, 1, 2, Set(1)), (2, 2, 2, Set()),
    (2, 1, 3, Set()), (2, 1, 3, Set(1)), (2, 1, 3, Set(2)), (2, 1, 3, Set(1, 2)),
    (2, 2, 3, Set()), (2, 2, 3, Set(2)), (2, 3, 3, Set())
  )
  pure val CPS: Set[VCheckpoint] =
    if (P_MAX_NO == 2)
      tuples(V_GENS, SHAPES_2).map(t => { gen: t._1, no: t._2._1, start: t._2._2, valid: t._2._4, nextNo: t._2._3 })
    else
      tuples(V_GENS, V_NOS, 1.to(P_MAX_NO + 1), V_NOS.powerset(), 1.to(P_MAX_NO + 1))
        .map(t => { gen: t._1, no: t._2, start: t._3, valid: t._4, nextNo: t._5 })
        .filter(c => and {
          c.nextNo <= c.no + 1, c.start <= c.nextNo,
          c.valid.forall(k => c.start <= k and k < c.nextNo),
        })
  pure val RCS: Set[VRootChange] = tuples(V_GENS, Set(0, 1)).map(t => { gen: t._1, key: t._2 })
  pure val HPS: Set[VHaltProof] = tuples(Set("cp", "pp", "rc"), V_GENS, 0.to(P_MAX_NO))
    .map(t => { kind: t._1, gen: t._2, no: t._3 })
  pure val DATAS: Set[VData] = tuples(P_DEVICES, V_NOS, V_GENS, 0.to(P_MAX_NO), Set(false, true))
    .map(t => { src: t._1, ppNo: t._2, gen: t._3, cpNo: t._4, ch0: t._5 })

  pure def below(s: Set[int], c: VCheckpoint): Set[int] = s.filter(k => k < c.nextNo)
  pure def vWindowStart(valid: Set[int], nx: int): int = valid.fold(nx, (m, k) => if (k < m) k else m)

  pure def isCp(c: VCheckpoint): bool = and {
    V_GENS.contains(c.gen), 0 <= c.no, c.no <= P_MAX_NO, 1 <= c.start, c.start <= P_MAX_NO + 1,
    1 <= c.nextNo, c.nextNo <= P_MAX_NO + 1, c.valid.subseteq(V_NOS),
    c.nextNo <= c.no + 1, c.start <= c.nextNo,
    c.valid.forall(k => c.start <= k and k < c.nextNo),
  }
  pure def isPp(p: VPassport): bool = and {
    V_GENS.contains(p.gen), V_NOS.contains(p.no), P_DEVICES.contains(p.dev), RIGHTS.contains(p.rights),
  }
  pure def isRc(r: VRootChange): bool = and { V_GENS.contains(r.gen), Set(0, 1).contains(r.key) }
  pure def isHp(h: VHaltProof): bool = and {
    Set("cp", "pp", "rc").contains(h.kind), V_GENS.contains(h.gen), 0 <= h.no, h.no <= P_MAX_NO,
  }
  pure def isData(m: VData): bool = and {
    P_DEVICES.contains(m.src), V_NOS.contains(m.ppNo), V_GENS.contains(m.gen), 0 <= m.cpNo, m.cpNo <= P_MAX_NO,
  }

  // ------------------------------------------------------------------ Struct
  // Counter and structural bounds without `broken == Set()`: omits
  // `currentGeneration`, `proofIsObeyed`, `rootHonorsRevocation`, `windowBounded`,
  // `windowKeepsValid`, and the validity half of `cacheConsistent` (it keeps one
  // passport per number in a cache, the conflict half).
  pure def structNode(n: VNode): bool = and {
    V_GENS.contains(n.gen), isCp(n.cp), n.pps.forall(p => isPp(p)), Set(-1, 0, 1).contains(n.rc),
    n.recvCp == Set(), n.recvPp == Set(), n.recvRc == Set(), n.recvHp.forall(h => isHp(h)),
    n.pps.forall(p => n.pps.forall(q => (p.gen == q.gen and p.no == q.no) implies p == q)),
    n.forever implies n.halted,
    n.recvHp.forall(h => h.kind == "rc" or h.gen <= n.gen),
  }

  pure def structRoot(r: VRoot): bool = and {
    V_GENS.contains(r.gen), 0.to(P_MAX_NO).contains(r.cpNo), 1.to(P_MAX_NO + 1).contains(r.nextNo),
    r.nextNo <= r.cpNo + 1,
    r.valid.forall(k => 1 <= k and k < r.nextNo),
    r.revoked.forall(k => 1 <= k and k < r.nextNo),
    r.rights.keys() == V_NOS.filter(k => k < r.nextNo),
    r.rights.keys().forall(k => RIGHTS.contains(r.rights.get(k))),
  }

  pure def structHistory(r: VRoot, h: Set[VCheckpoint]): bool = and {
    h.forall(c => isCp(c) and c.no >= 1),
    h.forall(c1 => h.forall(c2 => (c1.gen == c2.gen and c1.no == c2.no) implies c1 == c2)),
    h.forall(c => c.gen <= r.gen and (c.gen == r.gen implies and {
      c.no <= r.cpNo, c.nextNo <= r.nextNo, below(r.valid, c).subseteq(c.valid),
    })),
    h.forall(c1 => h.forall(c2 => (c1.gen == c2.gen and c1.no <= c2.no) implies
      (c1.nextNo <= c2.nextNo and below(c2.valid, c1).subseteq(c1.valid)))),
  }

  pure def structPool(r: VRoot, p: VPool): bool = and {
    p.cp.forall(c => isCp(c) and c.no >= 1 and c.gen <= r.gen and (c.gen == r.gen implies c.no <= r.cpNo)),
    p.pp.forall(x => isPp(x)), p.rc.forall(x => isRc(x) and x.gen >= 2 and x.gen <= r.gen),
    p.hp.forall(x => isHp(x) and x.gen <= r.gen), p.data.forall(x => isData(x)),
    p.pp.forall(x => x.gen <= r.gen and (x.gen == r.gen implies x.no < r.nextNo)),
    p.pp.forall(a => p.pp.forall(b =>
      (a.gen == b.gen and a.no == b.no) implies (a.dev == b.dev and (a.rights == b.rights or a.rights == 3 - b.rights)))),
  }

  pure def structOf(ns: str -> VNode, r: VRoot, p: VPool, h: Set[VCheckpoint], b: Set[str], s: Set[str]): bool = and {
    ns.keys() == P_DEVICES,
    P_DEVICES.forall(d => and {
      structNode(ns.get(d)),
      ns.get(d).gen <= r.gen,
      ns.get(d).pps.subseteq(p.pp),
      ns.get(d).cp == vGenesis(ns.get(d).cp.gen) or p.cp.contains(ns.get(d).cp),
    }),
    structRoot(r),
    structHistory(r, h),
    structPool(r, p),
    b.subseteq(BROKEN),
    s.subseteq(TAGS),
  }

  val structA = structOf(A::nodes, A::root, A::pool, A::history, A::broken, A::seen)
  val structB = structOf(B::nodes, B::root, B::pool, B::history, B::broken, B::seen)
  val viewA = viewOf(A::nodes, A::root, A::pool, A::history, A::broken)
  val viewB = viewOf(B::nodes, B::root, B::pool, B::history, B::broken)

  pure def hpGensOf(ns: str -> VNode, r: VRoot, p: VPool): Set[int] = {
    val liveGens = V_DEVICES.filter(d => {
      val n = ns.get(d)
      not(n.forever and n.halted and curGenOk(n) and keyOkOf(n))
    }).map(d => ns.get(d).gen).union(Set(r.gen))
    val minGen = liveGens.fold(V_MAX_GEN, (m, g) => if (g < m) g else m)
    V_GENS.filter(g => g >= minGen and p.hp.exists(x => x.kind != "rc" and x.gen == g))
  }

  // ------------------------------------------------------------- bookkeeping
  pure val NO_CP: VCheckpoint = vGenesis(0)
  pure val NO_PP: VPassport = { gen: 0, no: 0, dev: "", rights: 0 }
  pure val NO_RC: VRootChange = { gen: 0, key: 0 }
  pure val NO_HP: VHaltProof = { kind: "", gen: 0, no: 0 }
  type Move = { d: str, rights: int, k: int, c: VCheckpoint, p: VPassport, rc: VRootChange, h: VHaltProof }
  pure val NO_MOVE: Move = { d: "", rights: 0, k: 0, c: NO_CP, p: NO_PP, rc: NO_RC, h: NO_HP }
  var stage: int      // 0: before A's step, 1: after it, 2: after B's answer
  var mv: Move        // A's step parameters, as B needs them
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
  pure def mkPoolPp(dev: (int, int) -> str, loR: (int, int) -> int,
                    hasLo: (int, int) -> bool, hasHi: (int, int) -> bool): Set[VPassport] =
    SLOTS.filter(s => hasLo.get(s))
      .map(s => { gen: s._1, no: s._2, dev: dev.get(s), rights: loR.get(s) })
      .union(SLOTS.filter(s => hasHi.get(s))
        .map(s => { gen: s._1, no: s._2, dev: dev.get(s), rights: 3 - loR.get(s) }))

  action drawA = {
    nondet gens = setOfMaps(P_DEVICES, V_GENS).oneOf()
    nondet cpGen = setOfMaps(P_DEVICES, V_GENS).oneOf()
    nondet cpNo = setOfMaps(P_DEVICES, 0.to(P_MAX_NO)).oneOf()
    nondet cpStart = setOfMaps(P_DEVICES, 1.to(P_MAX_NO + 1)).oneOf()
    nondet cpValid = setOfMaps(P_DEVICES, V_NOS.powerset()).oneOf()
    nondet cpNext = setOfMaps(P_DEVICES, 1.to(P_MAX_NO + 1)).oneOf()
    nondet ppIn = setOfMaps(P_DEVICES, setOfMaps(SLOTS, Set(false, true))).oneOf()
    nondet ppDev = setOfMaps(P_DEVICES, setOfMaps(SLOTS, P_DEVICES)).oneOf()
    nondet ppRights = setOfMaps(P_DEVICES, setOfMaps(SLOTS, RIGHTS)).oneOf()
    nondet hIn = setOfMaps(SLOTS, Set(false, true)).oneOf()
    nondet hStart = setOfMaps(SLOTS, 1.to(P_MAX_NO + 1)).oneOf()
    nondet hValid = setOfMaps(SLOTS, V_NOS.powerset()).oneOf()
    nondet hNext = setOfMaps(SLOTS, 1.to(P_MAX_NO + 1)).oneOf()
    nondet rcs = setOfMaps(P_DEVICES, Set(-1, 0, 1)).oneOf()
    nondet halts = setOfMaps(P_DEVICES, Set(false, true)).oneOf()
    nondet forevers = setOfMaps(P_DEVICES, Set(false, true)).oneOf()
    nondet hps = setOfMaps(P_DEVICES, HPS.powerset()).oneOf()
    nondet rg = V_GENS.oneOf()
    nondet rcp = 0.to(P_MAX_NO).oneOf()
    nondet rnx = 1.to(P_MAX_NO + 1).oneOf()
    nondet rv = V_NOS.powerset().oneOf()
    nondet rrv = V_NOS.powerset().oneOf()
    nondet rfull = setOfMaps(V_NOS, RIGHTS).oneOf()
    nondet pcp = CPS.powerset().oneOf()
    nondet pppDev = setOfMaps(SLOTS, P_DEVICES).oneOf()
    nondet pppLoR = setOfMaps(SLOTS, Set(0, 1)).oneOf()
    nondet pppHasLo = setOfMaps(SLOTS, Set(false, true)).oneOf()
    nondet pppHasHi = setOfMaps(SLOTS, Set(false, true)).oneOf()
    nondet prc = RCS.powerset().oneOf()
    nondet php = HPS.powerset().oneOf()
    nondet pdata = DATAS.powerset().oneOf()
    nondet br = BROKEN.powerset().oneOf()
    nondet sn = TAGS.powerset().oneOf()
    val hist = SLOTS.filter(s => hIn.get(s))
      .map(s => { gen: s._1, no: s._2, start: hStart.get(s), valid: hValid.get(s), nextNo: hNext.get(s) })
    val ns = P_DEVICES.mapBy(d => {
      gen: gens.get(d),
      cp: { gen: cpGen.get(d), no: cpNo.get(d), start: cpStart.get(d), valid: cpValid.get(d), nextNo: cpNext.get(d) },
      pps: SLOTS.filter(s => ppIn.get(d).get(s))
        .map(s => { gen: s._1, no: s._2, dev: ppDev.get(d).get(s), rights: ppRights.get(d).get(s) }),
      rc: rcs.get(d), halted: halts.get(d), forever: forevers.get(d),
      recvCp: Set(), recvPp: Set(), recvRc: Set(), recvHp: hps.get(d),
    })
    val r = { gen: rg, cpNo: rcp, nextNo: rnx, valid: rv,
              rights: V_NOS.filter(k => k < rnx).mapBy(k => rfull.get(k)), revoked: rrv }
    val p = { cp: pcp, pp: mkPoolPp(pppDev, pppLoR, pppHasLo, pppHasHi), rc: prc, hp: php, data: pdata }
    all {
      structOf(ns, r, p, hist, br, sn),
      A::nodes' = ns, A::root' = r, A::pool' = p, A::history' = hist, A::broken' = br, A::seen' = sn,
    }
  }

  action drawB = {
    nondet gens = setOfMaps(P_DEVICES, V_GENS).oneOf()
    nondet cpGen = setOfMaps(P_DEVICES, V_GENS).oneOf()
    nondet cpNo = setOfMaps(P_DEVICES, 0.to(P_MAX_NO)).oneOf()
    nondet cpStart = setOfMaps(P_DEVICES, 1.to(P_MAX_NO + 1)).oneOf()
    nondet cpValid = setOfMaps(P_DEVICES, V_NOS.powerset()).oneOf()
    nondet cpNext = setOfMaps(P_DEVICES, 1.to(P_MAX_NO + 1)).oneOf()
    nondet ppIn = setOfMaps(P_DEVICES, setOfMaps(SLOTS, Set(false, true))).oneOf()
    nondet ppDev = setOfMaps(P_DEVICES, setOfMaps(SLOTS, P_DEVICES)).oneOf()
    nondet ppRights = setOfMaps(P_DEVICES, setOfMaps(SLOTS, RIGHTS)).oneOf()
    nondet hIn = setOfMaps(SLOTS, Set(false, true)).oneOf()
    nondet hStart = setOfMaps(SLOTS, 1.to(P_MAX_NO + 1)).oneOf()
    nondet hValid = setOfMaps(SLOTS, V_NOS.powerset()).oneOf()
    nondet hNext = setOfMaps(SLOTS, 1.to(P_MAX_NO + 1)).oneOf()
    nondet rcs = setOfMaps(P_DEVICES, Set(-1, 0, 1)).oneOf()
    nondet halts = setOfMaps(P_DEVICES, Set(false, true)).oneOf()
    nondet forevers = setOfMaps(P_DEVICES, Set(false, true)).oneOf()
    nondet hps = setOfMaps(P_DEVICES, HPS.powerset()).oneOf()
    nondet rg = V_GENS.oneOf()
    nondet rcp = 0.to(P_MAX_NO).oneOf()
    nondet rnx = 1.to(P_MAX_NO + 1).oneOf()
    nondet rv = V_NOS.powerset().oneOf()
    nondet rrv = V_NOS.powerset().oneOf()
    nondet rfull = setOfMaps(V_NOS, RIGHTS).oneOf()
    nondet pcp = CPS.powerset().oneOf()
    nondet pppDev = setOfMaps(SLOTS, P_DEVICES).oneOf()
    nondet pppLoR = setOfMaps(SLOTS, Set(0, 1)).oneOf()
    nondet pppHasLo = setOfMaps(SLOTS, Set(false, true)).oneOf()
    nondet pppHasHi = setOfMaps(SLOTS, Set(false, true)).oneOf()
    nondet prc = RCS.powerset().oneOf()
    nondet php = HPS.powerset().oneOf()
    nondet pdata = DATAS.powerset().oneOf()
    nondet br = BROKEN.powerset().oneOf()
    nondet sn = TAGS.powerset().oneOf()
    val hist = SLOTS.filter(s => hIn.get(s))
      .map(s => { gen: s._1, no: s._2, start: hStart.get(s), valid: hValid.get(s), nextNo: hNext.get(s) })
    val ns = P_DEVICES.mapBy(d => {
      gen: gens.get(d),
      cp: { gen: cpGen.get(d), no: cpNo.get(d), start: cpStart.get(d), valid: cpValid.get(d), nextNo: cpNext.get(d) },
      pps: SLOTS.filter(s => ppIn.get(d).get(s))
        .map(s => { gen: s._1, no: s._2, dev: ppDev.get(d).get(s), rights: ppRights.get(d).get(s) }),
      rc: rcs.get(d), halted: halts.get(d), forever: forevers.get(d),
      recvCp: Set(), recvPp: Set(), recvRc: Set(), recvHp: hps.get(d),
    })
    val r = { gen: rg, cpNo: rcp, nextNo: rnx, valid: rv,
              rights: V_NOS.filter(k => k < rnx).mapBy(k => rfull.get(k)), revoked: rrv }
    val p = { cp: pcp, pp: mkPoolPp(pppDev, pppLoR, pppHasLo, pppHasHi), rc: prc, hp: php, data: pdata }
    all {
      structOf(ns, r, p, hist, br, sn),
      B::nodes' = ns, B::root' = r, B::pool' = p, B::history' = hist, B::broken' = br, B::seen' = sn,
    }
  }

  // ----------------------------------------------------------- initial states
  action initStruct = all { A::init, B::init, stage' = 0, mv' = NO_MOVE, matchOk' = true }
  action initSafe = all { drawA, B::init, stage' = 0, mv' = NO_MOVE, matchOk' = true }
  action initPair = all { drawA, drawB, stage' = 0, mv' = NO_MOVE, matchOk' = true }

  // Names run-inductive.ps1 uses for its first, cheap check (Apalache download).
  action modelInit = initStruct
  action modelStep = stepRecoveryChange
  val IndInv = structA

  val sameSafety = (viewA == viewB) implies (A::safety iff B::safety)
  val matched = stage != 2 or (matchOk and viewA == viewB)
  // Non-vacuity: expected to be violated (a pair with equal views exists; B answers).
  val witnessPair = viewA != viewB
  val witnessAnswered = stage != 2

  // ------------------------------------------------- A's step, branch by branch
  action pre = all { stage == 0, A::safety }

  action stepRootAdmit = all { pre, bStay, stage' = 1, matchOk' = true,
    nondet d = P_DEVICES.oneOf() nondet r = RIGHTS.oneOf()
    all { A::rootIssue(d, r, Set()), mv' = { ...NO_MOVE, d: d, rights: r } } }
  action stepRootChangeRights = all { pre, bStay, stage' = 1, matchOk' = true, A::root.valid != Set(),
    nondet k = A::root.valid.oneOf()
    val old = A::pool.pp.filter(p => p.gen == A::root.gen and p.no == k)
    all { old != Set(), nondet p = old.oneOf() nondet r = RIGHTS.oneOf()
          all { A::rootIssue(p.dev, r, Set(k)), mv' = { ...NO_MOVE, k: k, rights: r } } } }
  action stepRootRevoke = all { pre, bStay, stage' = 1, matchOk' = true, A::rootRevoke, mv' = NO_MOVE }
  action stepRootEquivocateCp = all { pre, bStay, stage' = 1, matchOk' = true, A::rootEquivocateCp, mv' = NO_MOVE }
  action stepRootEquivocatePp = all { pre, bStay, stage' = 1, matchOk' = true, A::rootEquivocatePp, mv' = NO_MOVE }
  action stepRecoveryChange = all { pre, bStay, stage' = 1, matchOk' = true, A::recoveryChange, mv' = NO_MOVE }
  action stepRecoveryEquivocate = all { pre, bStay, stage' = 1, matchOk' = true, A::recoveryEquivocate, mv' = NO_MOVE }
  action stepAdversaryProof = all { pre, bStay, stage' = 1, matchOk' = true, A::adversaryProof, mv' = NO_MOVE }
  action stepRecvCp = all { pre, bStay, stage' = 1, matchOk' = true, A::pool.cp != Set(),
    nondet d = P_DEVICES.oneOf() nondet c = A::pool.cp.oneOf()
    all { A::nodeRecvCp(d, c), mv' = { ...NO_MOVE, d: d, c: c } } }
  action stepRecvPp = all { pre, bStay, stage' = 1, matchOk' = true, A::pool.pp != Set(),
    nondet d = P_DEVICES.oneOf() nondet p = A::pool.pp.oneOf()
    all { A::nodeRecvPp(d, p), mv' = { ...NO_MOVE, d: d, p: p } } }
  action stepRecvRc = all { pre, bStay, stage' = 1, matchOk' = true, A::pool.rc != Set(),
    nondet d = P_DEVICES.oneOf() nondet rc = A::pool.rc.oneOf()
    all { A::nodeRecvRc(d, rc), mv' = { ...NO_MOVE, d: d, rc: rc } } }
  action stepRecvHp = all { pre, bStay, stage' = 1, matchOk' = true, A::pool.hp != Set(),
    nondet d = P_DEVICES.oneOf() nondet h = A::pool.hp.oneOf()
    all { A::nodeRecvHp(d, h), mv' = { ...NO_MOVE, d: d, h: h } } }
  action stepAcceptData = all { pre, bStay, stage' = 1, matchOk' = true, A::pool.data != Set(),
    nondet d = P_DEVICES.oneOf() nondet m = A::pool.data.oneOf()
    all { A::nodeAcceptData(d, m), mv' = NO_MOVE } }
  action stepHearsHalted = all { pre, bStay, stage' = 1, matchOk' = true,
    nondet d = P_DEVICES.oneOf() all { A::nodeHearsHalted(d), mv' = { ...NO_MOVE, d: d } } }
  action stepReboot = all { pre, bStay, stage' = 1, matchOk' = true,
    nondet d = P_DEVICES.oneOf() all { A::nodeReboot(d), mv' = { ...NO_MOVE, d: d } } }
  action stepSend = all { pre, bStay, stage' = 1, matchOk' = true,
    nondet d = P_DEVICES.oneOf() all { A::nodeSend(d), mv' = NO_MOVE } }
  action stepGrant = all { pre, bStay, stage' = 1, matchOk' = true,
    nondet d = P_DEVICES.oneOf() all { A::nodes.get(d).pps != Set(), A::nodeGrant(d), mv' = NO_MOVE } }

  pure def cpFlip(c: VCheckpoint, k: int): VCheckpoint = {
    val v = if (c.valid.contains(k)) c.valid.exclude(Set(k)) else c.valid.union(Set(k))
    { ...c, valid: v.filter(x => c.start <= x and x < c.nextNo) }
  }

  action stepRootEquivocateCpM = all { pre, bStay, stage' = 1, matchOk' = true,
    val cands = A::pool.cp.filter(c => c.gen == A::root.gen and c.no >= 1)
    all { cands != Set(), nondet c = cands.oneOf() nondet k = V_NOS.oneOf()
          val c2 = cpFlip(c, k)
          all { c2 != c,
                A::commit(A::nodes, A::root, { ...A::pool, cp: A::pool.cp.union(Set(c2)) }, A::history),
                mv' = { ...NO_MOVE, c: c, k: k } } } }
  action stepRootEquivocatePpM = all { pre, bStay, stage' = 1, matchOk' = true,
    val cands = A::pool.pp.filter(p => p.gen == A::root.gen)
    all { cands != Set(), nondet p = cands.oneOf()
          val p2 = { ...p, rights: 3 - p.rights }
          all { A::commit(A::nodes, A::root, { ...A::pool, pp: A::pool.pp.union(Set(p2)) }, A::history),
                mv' = { ...NO_MOVE, k: p.no } } } }

  action stepAdversaryProofCp = all { pre, bStay, stage' = 1, matchOk' = true, A::pool.cp != Set(),
    nondet a = A::pool.cp.oneOf() nondet b = A::pool.cp.oneOf()
    all { A::cpConflict(a, b),
          A::setNodeless(A::pool.hp.union(Set({ kind: "cp", gen: a.gen, no: a.no }))),
          mv' = { ...NO_MOVE, k: a.gen } } }
  action stepAdversaryProofPp = all { pre, bStay, stage' = 1, matchOk' = true, A::pool.pp != Set(),
    nondet a = A::pool.pp.oneOf() nondet b = A::pool.pp.oneOf()
    all { A::ppConflict(a, b),
          A::setNodeless(A::pool.hp.union(Set({ kind: "pp", gen: a.gen, no: a.no }))),
          mv' = { ...NO_MOVE, k: a.gen } } }
  action stepAdversaryProofRc = all { pre, bStay, stage' = 1, matchOk' = true, A::pool.rc != Set(),
    nondet a = A::pool.rc.oneOf() nondet b = A::pool.rc.oneOf()
    all { a.gen == b.gen and a != b,
          A::setNodeless(A::pool.hp.union(Set({ kind: "rc", gen: a.gen, no: 0 }))),
          mv' = NO_MOVE } }

  // Exhaustive 3-way split of nodeRecvCp (halt / advance / noop).
  action stepRecvCpHalt = all { pre, bStay, stage' = 1, matchOk' = true, A::pool.cp != Set(),
    nondet d = P_DEVICES.oneOf() nondet c = A::pool.cp.oneOf()
    val n = A::nodes.get(d)
    all { not(n.forever or n.halted), c.gen == n.gen, A::verifies(n, c.gen), A::cpConflict(c, n.cp),
          A::nodeRecvCp(d, c), mv' = { ...NO_MOVE, d: d, c: c } } }
  action stepRecvCpAdv = all { pre, bStay, stage' = 1, matchOk' = true, A::pool.cp != Set(),
    nondet d = P_DEVICES.oneOf() nondet c = A::pool.cp.oneOf()
    val n = A::nodes.get(d)
    all { not(n.forever or n.halted), c.gen == n.gen, A::verifies(n, c.gen), not(A::cpConflict(c, n.cp)), c.no > n.cp.no,
          A::nodeRecvCp(d, c), mv' = { ...NO_MOVE, d: d, c: c } } }
  action stepRecvCpNoop = all { pre, bStay, stage' = 1, matchOk' = true, A::pool.cp != Set(),
    nondet d = P_DEVICES.oneOf() nondet c = A::pool.cp.oneOf()
    val n = A::nodes.get(d)
    all { n.forever or n.halted or c.gen != n.gen or not(A::verifies(n, c.gen))
            or (not(A::cpConflict(c, n.cp)) and c.no <= n.cp.no),
          A::nodeRecvCp(d, c), mv' = NO_MOVE } }

  // Exhaustive 3-way split of nodeRecvPp (halt / add / noop).
  action stepRecvPpHalt = all { pre, bStay, stage' = 1, matchOk' = true, A::pool.pp != Set(),
    nondet d = P_DEVICES.oneOf() nondet p = A::pool.pp.oneOf()
    val n = A::nodes.get(d)
    all { not(n.halted or n.forever), A::verifies(n, p.gen), n.pps.exists(q => A::ppConflict(p, q)),
          A::nodeRecvPp(d, p), mv' = { ...NO_MOVE, d: d, p: p } } }
  action stepRecvPpAdd = all { pre, bStay, stage' = 1, matchOk' = true, A::pool.pp != Set(),
    nondet d = P_DEVICES.oneOf() nondet p = A::pool.pp.oneOf()
    val n = A::nodes.get(d)
    all { not(n.halted or n.forever), A::verifies(n, p.gen), not(n.pps.exists(q => A::ppConflict(p, q))), A::validUnder(p, n.cp),
          A::nodeRecvPp(d, p), mv' = { ...NO_MOVE, d: d, p: p } } }
  action stepRecvPpNoop = all { pre, bStay, stage' = 1, matchOk' = true, A::pool.pp != Set(),
    nondet d = P_DEVICES.oneOf() nondet p = A::pool.pp.oneOf()
    val n = A::nodes.get(d)
    all { n.halted or n.forever or not(A::verifies(n, p.gen))
            or (not(n.pps.exists(q => A::ppConflict(p, q))) and not(A::validUnder(p, n.cp))),
          A::nodeRecvPp(d, p), mv' = NO_MOVE } }

  // Exhaustive 3-way split of nodeRecvRc (forever / advance / noop).
  action stepRecvRcForever = all { pre, bStay, stage' = 1, matchOk' = true, A::pool.rc != Set(),
    nondet d = P_DEVICES.oneOf() nondet rc = A::pool.rc.oneOf()
    val n = A::nodes.get(d)
    all { not(n.forever), rc.gen == n.gen, n.rc != rc.key, n.rc >= 0,
          A::nodeRecvRc(d, rc), mv' = { ...NO_MOVE, d: d, rc: rc } } }
  action stepRecvRcAdv = all { pre, bStay, stage' = 1, matchOk' = true, A::pool.rc != Set(),
    nondet d = P_DEVICES.oneOf() nondet rc = A::pool.rc.oneOf()
    val n = A::nodes.get(d)
    all { not(n.forever), rc.gen > n.gen,
          A::nodeRecvRc(d, rc), mv' = { ...NO_MOVE, d: d, rc: rc } } }
  action stepRecvRcNoop = all { pre, bStay, stage' = 1, matchOk' = true, A::pool.rc != Set(),
    nondet d = P_DEVICES.oneOf() nondet rc = A::pool.rc.oneOf()
    val n = A::nodes.get(d)
    all { n.forever or (not(rc.gen == n.gen and n.rc != rc.key and n.rc >= 0) and rc.gen <= n.gen),
          A::nodeRecvRc(d, rc), mv' = NO_MOVE } }

  // Exhaustive 3-way split of nodeRecvHp (rc / same-gen / noop).
  action stepRecvHpRc = all { pre, bStay, stage' = 1, matchOk' = true, A::pool.hp != Set(),
    nondet d = P_DEVICES.oneOf() nondet h = A::pool.hp.oneOf()
    val n = A::nodes.get(d)
    all { not(n.forever), h.kind == "rc",
          A::nodeRecvHp(d, h), mv' = { ...NO_MOVE, d: d, h: h } } }
  action stepRecvHpGen = all { pre, bStay, stage' = 1, matchOk' = true, A::pool.hp != Set(),
    nondet d = P_DEVICES.oneOf() nondet h = A::pool.hp.oneOf()
    val n = A::nodes.get(d)
    all { not(n.forever), h.kind != "rc", h.gen == n.gen, A::verifies(n, h.gen),
          A::nodeRecvHp(d, h), mv' = { ...NO_MOVE, d: d, h: h } } }
  action stepRecvHpNoop = all { pre, bStay, stage' = 1, matchOk' = true, A::pool.hp != Set(),
    nondet d = P_DEVICES.oneOf() nondet h = A::pool.hp.oneOf()
    val n = A::nodes.get(d)
    all { n.forever or (h.kind != "rc" and (h.gen != n.gen or not(A::verifies(n, h.gen)))),
          A::nodeRecvHp(d, h), mv' = NO_MOVE } }

  // Exhaustive 2-way split of nodeHearsHalted (forever peer / halted same-gen peer).
  action stepHearsHaltedRc = all { pre, bStay, stage' = 1, matchOk' = true,
    nondet d = P_DEVICES.oneOf()
    val proofs = A::pool.hp.filter(h => h.kind == "rc" and A::foreverPeer(d))
    all { proofs != Set(), nondet h = proofs.oneOf()
          all { A::nodeRecvHp(d, h), mv' = { ...NO_MOVE, d: d } } } }
  action stepHearsHaltedGen = all { pre, bStay, stage' = 1, matchOk' = true,
    nondet d = P_DEVICES.oneOf()
    val n = A::nodes.get(d)
    val proofs = A::pool.hp.filter(h => h.kind != "rc" and h.gen == n.gen and A::haltedPeer(d, n.gen))
    all { proofs != Set(), nondet h = proofs.oneOf()
          all { A::nodeRecvHp(d, h), mv' = { ...NO_MOVE, d: d } } } }

  // --------------------------------------------------------------- B's answer
  action bNone = all { bStay, matchOk' = false }

  action respondRootAdmit = all {
    stage == 1, aStay, stage' = 2, mv' = mv,
    if (viewA == viewB) all { bStay, matchOk' = true }
    else if (B::root.nextNo <= P_MAX_NO and B::root.cpNo < P_MAX_NO
             and (B::root.nextNo + 1) - vWindowStart(B::root.valid.union(Set(B::root.nextNo)), B::root.nextNo + 1) <= P_WINDOW)
      all { B::rootIssue(mv.d, mv.rights, Set()), matchOk' = true }
    else bNone,
  }
  action respondRootChangeRights = all {
    stage == 1, aStay, stage' = 2, mv' = mv,
    if (viewA == viewB) all { bStay, matchOk' = true }
    else {
      val old = B::pool.pp.filter(p => p.gen == B::root.gen and p.no == mv.k)
      if (B::root.valid.contains(mv.k) and old != Set()
          and B::root.nextNo <= P_MAX_NO and B::root.cpNo < P_MAX_NO
          and (B::root.nextNo + 1) - vWindowStart(B::root.valid.exclude(Set(mv.k)).union(Set(B::root.nextNo)), B::root.nextNo + 1) <= P_WINDOW)
        all { matchOk' = true, nondet p = old.oneOf() B::rootIssue(p.dev, mv.rights, Set(mv.k)) }
      else bNone
    },
  }
  action respondRootRevoke = all {
    stage == 1, aStay, stage' = 2, mv' = mv,
    if (viewA == viewB) all { bStay, matchOk' = true }
    else {
      val ks = B::root.valid.exclude(A::root.valid)
      if (ks != Set() and B::root.cpNo < P_MAX_NO) {
        nondet k = ks.oneOf()
        val v = B::root.valid.exclude(Set(k))
        val c = B::rootCheckpoint(v, B::root.nextNo)
        all {
          B::commit(B::nodes, { ...B::root, cpNo: B::root.cpNo + 1, valid: v, revoked: B::root.revoked.union(Set(k)) },
            { ...B::pool, cp: B::pool.cp.union(Set(c)) }, B::history.union(Set(c))),
          matchOk' = true,
        }
      } else bNone
    },
  }
  action respondRootEquivocateCp = all {
    stage == 1, aStay, stage' = 2, mv' = mv,
    if (viewA == viewB) all { bStay, matchOk' = true }
    else {
      val c2 = cpFlip(mv.c, mv.k)
      if (B::pool.cp.contains(mv.c) and mv.c.gen == B::root.gen and mv.c.no >= 1
          and V_NOS.contains(mv.k) and c2 != mv.c)
        all { B::commit(B::nodes, B::root, { ...B::pool, cp: B::pool.cp.union(Set(c2)) }, B::history), matchOk' = true }
      else bNone
    },
  }
  action respondRootEquivocatePp = all {
    stage == 1, aStay, stage' = 2, mv' = mv,
    if (viewA == viewB) all { bStay, matchOk' = true }
    else {
      val cands = B::pool.pp.filter(p => p.gen == B::root.gen and p.no == mv.k)
      if (cands != Set()) {
        nondet p = cands.oneOf()
        val p2 = { ...p, rights: 3 - p.rights }
        all { B::commit(B::nodes, B::root, { ...B::pool, pp: B::pool.pp.union(Set(p2)) }, B::history), matchOk' = true }
      } else bNone
    },
  }
  action respondRecoveryChange = all {
    stage == 1, aStay, stage' = 2, mv' = mv,
    if (viewA == viewB) all { bStay, matchOk' = true }
    else if (B::root.gen < P_MAX_GEN)
      all { B::recoveryChange, matchOk' = true }
    else bNone,
  }
  action respondRecoveryEquivocate = all {
    stage == 1, aStay, stage' = 2, mv' = mv,
    if (viewA == viewB) all { bStay, matchOk' = true }
    else {
      val added = A::pool.rc.exclude(B::pool.rc)
      val validRc2 = added.filter(rc2 => B::pool.rc.contains({ ...rc2, key: 1 - rc2.key }))
      if (validRc2 != Set()) {
        nondet rc2 = validRc2.oneOf()
        all { B::commit(B::nodes, B::root, { ...B::pool, rc: B::pool.rc.union(Set(rc2)) }, B::history), matchOk' = true }
      } else bNone
    },
  }
  action respondAdversaryProofGen = all {
    stage == 1, aStay, stage' = 2, mv' = mv,
    if (viewA == viewB) all { bStay, matchOk' = true }
    else {
      val cpCands = B::pool.cp.filter(a => a.gen == mv.k
                                           and B::pool.cp.exists(b => a.gen == b.gen and a.no == b.no and a != b))
      val ppCands = B::pool.pp.filter(a => a.gen == mv.k
                                           and B::pool.pp.exists(b => a.gen == b.gen and a.no == b.no and a != b))
      if (cpCands != Set()) {
        nondet a = cpCands.oneOf()
        all { B::setNodeless(B::pool.hp.union(Set({ kind: "cp", gen: a.gen, no: a.no }))), matchOk' = true }
      } else if (ppCands != Set()) {
        nondet a = ppCands.oneOf()
        all { B::setNodeless(B::pool.hp.union(Set({ kind: "pp", gen: a.gen, no: a.no }))), matchOk' = true }
      } else bNone
    },
  }
  action respondAdversaryProofRc = all {
    stage == 1, aStay, stage' = 2, mv' = mv,
    if (viewA == viewB) all { bStay, matchOk' = true }
    else {
      val rcs = B::pool.rc.filter(a => B::pool.rc.exists(b => a.gen == b.gen and a != b))
      if (rcs != Set()) {
        nondet a = rcs.oneOf()
        all { B::setNodeless(B::pool.hp.union(Set({ kind: "rc", gen: a.gen, no: 0 }))), matchOk' = true }
      } else bNone
    },
  }
  // When A halts a live node via nodeRecvCp in a generation that already has a
  // non-"rc" halt proof in pool.hp, B's view collapsed n.cp so B answers with
  // nodeRecvHp using that proof; otherwise B answers with nodeRecvCp.
  action respondRecvCpHalt = all {
    stage == 1, aStay, stage' = 2, mv' = mv,
    if (P_DEVICES.contains(mv.d)) {
      val nB = B::nodes.get(mv.d)
      val hpHit = hpGensOf(B::nodes, B::root, B::pool).contains(nB.gen)
      val hs = B::pool.hp.filter(x => x.kind != "rc" and x.gen == nB.gen)
      val cands =
        if (nB.gen < B::root.gen)
          B::pool.cp.filter(x => x.gen == nB.gen and x.no == nB.cp.no and x != nB.cp)
        else if (B::pool.cp.contains(mv.c)) Set(mv.c)
        else Set()
      if (hpHit and hs != Set()) all { matchOk' = true, nondet x = hs.oneOf() B::nodeRecvHp(mv.d, x) }
      else if (not(hpHit) and cands != Set()) all { matchOk' = true, nondet x = cands.oneOf() B::nodeRecvCp(mv.d, x) }
      else bNone
    } else bNone,
  }
  action respondRecvCpAdv = all {
    stage == 1, aStay, stage' = 2, mv' = mv,
    if (viewA == viewB) all { bStay, matchOk' = true }
    else if (P_DEVICES.contains(mv.d)) {
      val nB = B::nodes.get(mv.d)
      val eNos = V_NOS.filter(k =>
        B::pool.pp.exists(x => x.gen == nB.gen and x.no == k
                               and B::pool.pp.exists(y => y.gen == nB.gen and y.no == k and x != y)))
      val want = oldCpProj(mv.c, eNos)
      val cands =
        if (nB.gen < B::root.gen)
          B::pool.cp.filter(x => x.gen == nB.gen and oldCpProj(x, eNos) == want)
        else if (B::pool.cp.contains(mv.c)) Set(mv.c)
        else Set()
      if (cands != Set()) all { matchOk' = true, nondet x = cands.oneOf() B::nodeRecvCp(mv.d, x) }
      else bNone
    } else bNone,
  }
  // Same rationale as respondRecvCpHalt: B uses nodeRecvHp if hpGens already
  // covers nB.gen, otherwise nodeRecvPp with a conflicting passport.
  action respondRecvPpHalt = all {
    stage == 1, aStay, stage' = 2, mv' = mv,
    if (P_DEVICES.contains(mv.d)) {
      val nB = B::nodes.get(mv.d)
      val hpHit = hpGensOf(B::nodes, B::root, B::pool).contains(nB.gen)
      val hs = B::pool.hp.filter(x => x.kind != "rc" and x.gen == nB.gen)
      val cands = B::pool.pp.filter(x => x.gen == mv.p.gen and x.no == mv.p.no
                                         and nB.pps.exists(q => q.gen == x.gen and q.no == x.no and q != x))
      if (hpHit and hs != Set()) all { matchOk' = true, nondet x = hs.oneOf() B::nodeRecvHp(mv.d, x) }
      else if (not(hpHit) and cands != Set()) all { matchOk' = true, nondet x = cands.oneOf() B::nodeRecvPp(mv.d, x) }
      else bNone
    } else bNone,
  }
  action respondRecvPpAdd = all {
    stage == 1, aStay, stage' = 2, mv' = mv,
    if (viewA == viewB) all { bStay, matchOk' = true }
    else if (P_DEVICES.contains(mv.d)) {
      val cands = B::pool.pp.filter(x => x.gen == mv.p.gen and x.no == mv.p.no)
      if (cands != Set()) all { matchOk' = true, nondet x = cands.oneOf() B::nodeRecvPp(mv.d, x) }
      else bNone
    } else bNone,
  }
  action respondRecvRcForever = all {
    stage == 1, aStay, stage' = 2, mv' = mv,
    if (P_DEVICES.contains(mv.d)) {
      val nB = B::nodes.get(mv.d)
      val cands = B::pool.rc.filter(x => x.gen == nB.gen and nB.rc >= 0 and x.key != nB.rc)
      if (cands != Set()) all { matchOk' = true, nondet x = cands.oneOf() B::nodeRecvRc(mv.d, x) }
      else bNone
    } else bNone,
  }
  action respondRecvRcAdv = all {
    stage == 1, aStay, stage' = 2, mv' = mv,
    if (viewA == viewB) all { bStay, matchOk' = true }
    else if (P_DEVICES.contains(mv.d) and B::pool.rc.contains(mv.rc))
      all { matchOk' = true, B::nodeRecvRc(mv.d, mv.rc) }
    else bNone,
  }
  action respondRecvHpRc = all {
    stage == 1, aStay, stage' = 2, mv' = mv,
    if (viewA == viewB) all { bStay, matchOk' = true }
    else if (P_DEVICES.contains(mv.d)) {
      val hs = B::pool.hp.filter(x => x.kind == "rc")
      if (hs != Set()) all { matchOk' = true, nondet x = hs.oneOf() B::nodeRecvHp(mv.d, x) }
      else bNone
    } else bNone,
  }
  action respondRecvHpGen = all {
    stage == 1, aStay, stage' = 2, mv' = mv,
    if (viewA == viewB) all { bStay, matchOk' = true }
    else if (P_DEVICES.contains(mv.d)) {
      val hs = B::pool.hp.filter(x => x.kind != "rc" and x.gen == mv.h.gen)
      if (hs != Set()) all { matchOk' = true, nondet x = hs.oneOf() B::nodeRecvHp(mv.d, x) }
      else bNone
    } else bNone,
  }
  action respondHearsHaltedRc = all {
    stage == 1, aStay, stage' = 2, mv' = mv,
    if (viewA == viewB) all { bStay, matchOk' = true }
    else if (P_DEVICES.contains(mv.d) and B::foreverPeer(mv.d)) {
      val hs = B::pool.hp.filter(x => x.kind == "rc")
      if (hs != Set()) all { matchOk' = true, nondet x = hs.oneOf() B::nodeRecvHp(mv.d, x) }
      else bNone
    } else bNone,
  }
  action respondHearsHaltedGen = all {
    stage == 1, aStay, stage' = 2, mv' = mv,
    if (viewA == viewB) all { bStay, matchOk' = true }
    else if (P_DEVICES.contains(mv.d)) {
      val g = B::nodes.get(mv.d).gen
      val hs = if (B::haltedPeer(mv.d, g)) B::pool.hp.filter(x => x.kind != "rc" and x.gen == g) else Set()
      if (hs != Set()) all { matchOk' = true, nondet x = hs.oneOf() B::nodeRecvHp(mv.d, x) }
      else bNone
    } else bNone,
  }
  action respondReboot = all {
    stage == 1, aStay, stage' = 2, mv' = mv,
    if (viewA == viewB) all { bStay, matchOk' = true }
    else if (P_DEVICES.contains(mv.d)) all { B::nodeReboot(mv.d), matchOk' = true }
    else bNone,
  }
  action respondStutter = all {
    stage == 1, aStay, stage' = 2, mv' = mv,
    if (viewA == viewB) all { bStay, matchOk' = true }
    else bNone,
  }

  action matchRootAdmit = any { all { viewA == viewB, stepRootAdmit }, respondRootAdmit }
  action matchRootChangeRights = any { all { viewA == viewB, stepRootChangeRights }, respondRootChangeRights }
  action matchRootRevoke = any { all { viewA == viewB, stepRootRevoke }, respondRootRevoke }
  action matchRootEquivocateCp = any { all { viewA == viewB, stepRootEquivocateCpM }, respondRootEquivocateCp }
  action matchRootEquivocatePp = any { all { viewA == viewB, stepRootEquivocatePpM }, respondRootEquivocatePp }
  action matchRecoveryChange = any { all { viewA == viewB, stepRecoveryChange }, respondRecoveryChange }
  action matchRecoveryEquivocate = any { all { viewA == viewB, stepRecoveryEquivocate }, respondRecoveryEquivocate }
  action matchAdversaryProofCp = any { all { viewA == viewB, stepAdversaryProofCp }, respondAdversaryProofGen }
  action matchAdversaryProofPp = any { all { viewA == viewB, stepAdversaryProofPp }, respondAdversaryProofGen }
  action matchAdversaryProofRc = any { all { viewA == viewB, stepAdversaryProofRc }, respondAdversaryProofRc }
  action matchRecvCpHalt = any { all { viewA == viewB, stepRecvCpHalt }, respondRecvCpHalt }
  action matchRecvCpAdv = any { all { viewA == viewB, stepRecvCpAdv }, respondRecvCpAdv }
  action matchRecvCpNoop = any { all { viewA == viewB, stepRecvCpNoop }, respondStutter }
  action matchRecvPpHalt = any { all { viewA == viewB, stepRecvPpHalt }, respondRecvPpHalt }
  action matchRecvPpAdd = any { all { viewA == viewB, stepRecvPpAdd }, respondRecvPpAdd }
  action matchRecvPpNoop = any { all { viewA == viewB, stepRecvPpNoop }, respondStutter }
  action matchRecvRcForever = any { all { viewA == viewB, stepRecvRcForever }, respondRecvRcForever }
  action matchRecvRcAdv = any { all { viewA == viewB, stepRecvRcAdv }, respondRecvRcAdv }
  action matchRecvRcNoop = any { all { viewA == viewB, stepRecvRcNoop }, respondStutter }
  action matchRecvHpRc = any { all { viewA == viewB, stepRecvHpRc }, respondRecvHpRc }
  action matchRecvHpGen = any { all { viewA == viewB, stepRecvHpGen }, respondRecvHpGen }
  action matchRecvHpNoop = any { all { viewA == viewB, stepRecvHpNoop }, respondStutter }
  action matchAcceptData = any { all { viewA == viewB, stepAcceptData }, respondStutter }
  action matchHearsHaltedRc = any { all { viewA == viewB, stepHearsHaltedRc }, respondHearsHaltedRc }
  action matchHearsHaltedGen = any { all { viewA == viewB, stepHearsHaltedGen }, respondHearsHaltedGen }
  action matchReboot = any { all { viewA == viewB, stepReboot }, respondReboot }
  action matchSend = any { all { viewA == viewB, stepSend }, respondStutter }
  action matchGrant = any { all { viewA == viewB, stepGrant }, respondStutter }
}

module tiny_tlc_bisim {
  import bisim(P_DEVICES = Set("a", "b"), P_MAX_GEN = 2, P_MAX_NO = 2, P_WINDOW = 2).*
}
