// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 HunterEwok
//
// Inductive invariant for convergence (S7, R-ARC-6). The model is run with
// TRACK_RECV = true, so every node records the records it processed.
// convergence compares pairs of nodes; it is proved through a per-node
// lemma instead: every field that convergence compares (gen, cp, forever)
// is a function of the node's own processed-record sets (nodeConv below).
// Apalache proves four facts, each for all reachable states:
//   1. init implies IndInv               (--init=modelInit --invariant=IndInv, 0 steps)
//   2. IndInv and one step imply IndInv   (--init=indInit --invariant=IndInv, 1 step)
//   3. IndInv implies safety without convergence
//                                         (--init=indInit --invariant=modelSafetyRest, 0 steps)
//   4. two nodes that satisfy nodeOk and share their processed-record sets
//      satisfy convergence               (--init=pairInit --invariant=modelConvergence, 0 steps)
// Fact 4 needs no comparison of sets: the two nodes are built from one
// drawing of the sets. Facts 1 to 3 run on one device (see the instances
// below for why that covers every node of a larger model), and fact 4 then
// gives convergence for every pair. The safety invariant of inductive.qnt is unchanged; this file
// repeats it because the processed-record sets change the state space.
module conv_inductive {
  const I_DEVICES: Set[str]
  const I_MAX_GEN: int
  const I_MAX_NO: int
  const I_WINDOW: int
  const I_MUTANT: str
  import membership(DEVICES = I_DEVICES, MAX_GEN = I_MAX_GEN, MAX_NO = I_MAX_NO, WINDOW = I_WINDOW, MUTANT = I_MUTANT, TRACK_RECV = true).* from "./membership"

  // ------------------------------------------------------------ bounded types
  val GENS = 1.to(MAX_GEN)
  val NOS = 1.to(MAX_NO)
  // Every checkpoint, honest or not, has its valid numbers in its window
  // [start, nextNo), a window of at most WINDOW numbers, and a next number at
  // most one above its own number: each passport the Root issues comes with a
  // new checkpoint. Limiting the type to such checkpoints keeps the solver's
  // sets small.
  val CPS: Set[Checkpoint] = tuples(GENS, 0.to(MAX_NO), 1.to(MAX_NO + 1), NOS.powerset(), 1.to(MAX_NO + 1))
    .map(t => { gen: t._1, no: t._2, start: t._3, valid: t._4, nextNo: t._5 })
    .filter(c => and {
      c.nextNo <= c.no + 1, c.start <= c.nextNo, c.nextNo - c.start <= WINDOW,
      c.valid.forall(k => c.start <= k and k < c.nextNo),
    })
  val PPS: Set[Passport] = tuples(GENS, NOS, DEVICES, RIGHTS)
    .map(t => { gen: t._1, no: t._2, dev: t._3, rights: t._4 })
  val RCS: Set[RootChange] = tuples(GENS, Set(0, 1)).map(t => { gen: t._1, key: t._2 })
  val HPS: Set[HaltProof] = tuples(Set("cp", "pp", "rc"), GENS, 0.to(MAX_NO))
    .map(t => { kind: t._1, gen: t._2, no: t._3 })
  val DATAS: Set[Data] = tuples(DEVICES, NOS, GENS, 0.to(MAX_NO), Set(false, true))
    .map(t => { src: t._1, ppNo: t._2, gen: t._3, cpNo: t._4, ch0: t._5 })

  pure def below(s: Set[int], c: Checkpoint): Set[int] = s.filter(k => k < c.nextNo)

  // Membership in the bounded types, written as predicates on the fields.
  // "x in CPS" for a symbolic x makes the solver compare x with every element
  // of CPS, and a subset of CPS checked that way costs |CPS| squared; these
  // predicates cost one comparison per field. Each is exactly membership in
  // the set above with the same name.
  def isCp(c: Checkpoint): bool = and {
    GENS.contains(c.gen), 0 <= c.no, c.no <= MAX_NO, 1 <= c.start, c.start <= MAX_NO + 1,
    1 <= c.nextNo, c.nextNo <= MAX_NO + 1, c.valid.subseteq(NOS),
    c.nextNo <= c.no + 1, c.start <= c.nextNo, c.nextNo - c.start <= WINDOW,
    c.valid.forall(k => c.start <= k and k < c.nextNo),
  }
  def isPp(p: Passport): bool = and { GENS.contains(p.gen), NOS.contains(p.no), DEVICES.contains(p.dev), RIGHTS.contains(p.rights) }
  def isRc(r: RootChange): bool = and { GENS.contains(r.gen), Set(0, 1).contains(r.key) }
  def isHp(h: HaltProof): bool = and { Set("cp", "pp", "rc").contains(h.kind), GENS.contains(h.gen), 0 <= h.no, h.no <= MAX_NO }
  def isData(m: Data): bool = and { DEVICES.contains(m.src), NOS.contains(m.ppNo), GENS.contains(m.gen), 0 <= m.cpNo, m.cpNo <= MAX_NO }

  // ------------------------------------------------------------------- parts
  def nodeOk(n: Node): bool = and {
    // types
    GENS.contains(n.gen), isCp(n.cp), n.pps.forall(p => isPp(p)), Set(-1, 0, 1).contains(n.rc),
    n.recvCp.forall(c => isCp(c)), n.recvPp.forall(x => isPp(x)), n.recvRc.forall(x => isRc(x)),
    n.recvHp.forall(h => isHp(h)),
    // the cache holds at most one passport per number, halted or not: a
    // conflicting passport halts the node without entering the cache, and a
    // halted node takes no passport
    n.pps.forall(p => n.pps.forall(q => p.no == q.no implies p == q)),
    // a permanent halt is a halt
    n.forever implies n.halted,
    // a processed root change proof made the halt permanent; any other
    // processed proof is of the current generation or an older one
    n.recvHp.exists(h => h.kind == "rc") implies n.forever,
    n.recvHp.forall(h => h.kind == "rc" or h.gen <= n.gen),
    // currentGeneration (state part)
    n.cp.gen == n.gen, n.pps.forall(p => p.gen == n.gen),
    // proofIsObeyed
    n.recvHp.exists(h => h.gen == n.gen or h.kind == "rc") implies n.halted,
    // installedKeyOnly
    n.rc == signer(n.gen) or (n.cp == genesis(n.gen) and n.pps == Set()),
    // cacheConsistent
    n.halted or n.pps.forall(p => validIn(p, n.cp) and n.pps.forall(q => not(ppConflict(p, q)))),
    nodeConv(n),
  }

  // The state that convergence compares is a function of the processed
  // records. Records of another generation are not recorded, so the sets
  // never hold a checkpoint or proof of a later generation; root change
  // records are of generation 2 or later (the pool holds no other).
  def nodeConv(n: Node): bool = and {
    n.recvCp.forall(c => c.gen <= n.gen),
    n.recvRc.forall(r => r.gen >= 2),
    // generation 1 is the only one without a root change record
    (n.gen == 1) == (n.rc == -1),
    // forever: a root change proof, or two root change records of one
    // generation with different keys
    n.forever == (n.recvHp.exists(h => h.kind == "rc")
      or n.recvRc.exists(a => n.recvRc.exists(b => a.gen == b.gen and a.key != b.key))),
    // gen and rc: the latest root change record, unique per generation
    not(n.forever) implies and {
      n.recvRc.forall(r => r.gen <= n.gen and (r.gen == n.gen implies r.key == n.rc)),
      n.gen >= 2 implies n.recvRc.exists(r => r.gen == n.gen),
    },
    // cp: the checkpoint of the current generation with the highest number,
    // the only one with that number, or genesis if there is none
    (not(n.forever) and not(n.halted)) implies (
      if (n.recvCp.forall(c => c.gen != n.gen)) n.cp == genesis(n.gen)
      // (with the forall below, the same as n.recvCp.contains(n.cp), but it
      // compares whole records only once)
      else n.recvCp.exists(c => c.gen == n.gen and c.no == n.cp.no)
        and n.recvCp.forall(c => c.gen == n.gen implies (c.no < n.cp.no or c == n.cp))),
  }

  def rootOk(r: Root): bool = and {
    GENS.contains(r.gen), 0.to(MAX_NO).contains(r.cpNo), 1.to(MAX_NO + 1).contains(r.nextNo),
    r.nextNo <= r.cpNo + 1,
    r.valid.forall(k => 1 <= k and k < r.nextNo),
    r.revoked.forall(k => 1 <= k and k < r.nextNo),
    r.rights.keys() == NOS.filter(k => k < r.nextNo),
    r.rights.keys().forall(k => RIGHTS.contains(r.rights.get(k))),
    // the window of the Root's next checkpoint fits (R-MEM-14)
    // (the same as r.nextNo - windowStart(r.valid, r.nextNo) <= WINDOW,
    // without the fold)
    r.valid.forall(k => r.nextNo - k <= WINDOW),
    // rootHonorsRevocation
    r.valid.intersect(r.revoked) == Set(),
  }

  // The honest checkpoints of one generation never bring a cleared bit back:
  // this is what makes "revoked at or before the receiver's checkpoint"
  // equivalent to "not valid under it".
  def historyOk(r: Root, h: Set[Checkpoint]): bool = and {
    h.forall(c => isCp(c) and c.no >= 1),
    // one honest checkpoint per generation and number: the Root's counter
    // only grows within a generation, and equivocations are not history
    h.forall(c1 => h.forall(c2 => (c1.gen == c2.gen and c1.no == c2.no) implies c1 == c2)),
    h.forall(c => c.gen <= r.gen and (c.gen == r.gen implies and {
      c.no <= r.cpNo, c.nextNo <= r.nextNo, below(r.valid, c).subseteq(c.valid),
      // windowKeepsValid
      c.no == r.cpNo implies (c.valid == r.valid and c.nextNo == r.nextNo),
    })),
    h.forall(c1 => h.forall(c2 => (c1.gen == c2.gen and c1.no <= c2.no) implies
      (c1.nextNo <= c2.nextNo and below(c2.valid, c1).subseteq(c1.valid)))),
  }

  def poolOk(p: Pool): bool = and {
    p.cp.forall(c => isCp(c)), p.pp.forall(x => isPp(x)), p.rc.forall(x => isRc(x)), p.hp.forall(x => isHp(x)),
    p.data.forall(x => isData(x)),
    p.rc.forall(x => x.gen >= 2),
  }

  def indInvOf(ns: str -> Node, r: Root, p: Pool, h: Set[Checkpoint], b: Set[str], s: Set[str]): bool = and {
    ns.keys() == DEVICES,
    DEVICES.forall(d => nodeOk(ns.get(d))),
    rootOk(r),
    historyOk(r, h),
    poolOk(p),
    // behind every halt lies a proof in the pool: a halt of a generation has
    // a proof of that generation, a permanent halt a root change proof
    // (haltPropagates rests on these, see HearingEnabled)
    DEVICES.forall(d => (ns.get(d).halted and not(ns.get(d).forever))
      implies p.hp.exists(x => x.kind != "rc" and x.gen == ns.get(d).gen)),
    DEVICES.forall(d => ns.get(d).forever implies p.hp.exists(x => x.kind == "rc")),
    b == Set(),
    s.subseteq(Set("accept", "grant")),
  }

  val IndInv = indInvOf(nodes, root, pool, history, broken, seen)

  // The model's own initial state, step, and safety, under names that the
  // instances below can see (an instance does not pass on what it imports).
  action modelInit = init
  action modelStep = step
  val modelSafety = safety
  val modelConvergence = convergence
  // safety without convergence, which fact 4 covers: comparing the
  // processed-record sets of two nodes inside one state is what makes the
  // solver's work quadratic. Exactly the other conjuncts of safety.
  val modelSafetyRest = noRollback and currentGeneration and haltIsSticky and haltedIsInert
    and proofIsObeyed and rootHonorsRevocation and cacheConsistent
    and revokedIsRejected and grantsNeedRead and dataNeedsPublish
    and windowBounded and windowKeepsValid

  // The branches of step, one by one, so that the obligation "IndInv and one
  // step imply IndInv" can be checked as independent parts in parallel. The
  // list must name every branch of step in membership.qnt, and nothing else:
  // step is exactly their disjunction.
  action stepRootAdmit = rootAdmit
  action stepRootChangeRights = rootChangeRights
  action stepRootRevoke = rootRevoke
  action stepRootEquivocateCp = rootEquivocateCp
  action stepRootEquivocatePp = rootEquivocatePp
  action stepRecoveryChange = recoveryChange
  action stepRecoveryEquivocate = recoveryEquivocate
  action stepAdversaryProof = adversaryProof
  action stepRecvCp = { nondet d = DEVICES.oneOf() all { pool.cp != Set(), nondet c = pool.cp.oneOf() nodeRecvCp(d, c) } }
  action stepRecvPp = { nondet d = DEVICES.oneOf() all { pool.pp != Set(), nondet p = pool.pp.oneOf() nodeRecvPp(d, p) } }
  action stepRecvRc = { nondet d = DEVICES.oneOf() all { pool.rc != Set(), nondet r = pool.rc.oneOf() nodeRecvRc(d, r) } }
  action stepRecvHp = { nondet d = DEVICES.oneOf() all { pool.hp != Set(), nondet h = pool.hp.oneOf() nodeRecvHp(d, h) } }
  action stepAcceptData = { nondet d = DEVICES.oneOf() all { pool.data != Set(), nondet m = pool.data.oneOf() nodeAcceptData(d, m) } }
  action stepHearsHalted = { nondet d = DEVICES.oneOf() nodeHearsHalted(d) }
  action stepReboot = { nondet d = DEVICES.oneOf() nodeReboot(d) }
  action stepSend = { nondet d = DEVICES.oneOf() nodeSend(d) }
  action stepGrant = { nondet d = DEVICES.oneOf() all { nodes.get(d).pps != Set(), nodeGrant(d) } }

  // ------------------------------------------- an arbitrary state of IndInv
  // A node's cache and the history are built from slots rather than picked
  // from the powersets of PPS and CPS: a cache has one passport per number
  // of the node's generation, the history one checkpoint per generation and
  // number (both are part of IndInv). Every state of IndInv is still among
  // the states built here, and the solver's sets have 3 and 9 elements
  // instead of 108 and 102.
  val SLOTS = tuples(GENS, NOS)
  action indInit = {
    nondet gens = setOfMaps(DEVICES, GENS).oneOf()
    nondet cpNo = setOfMaps(DEVICES, 0.to(MAX_NO)).oneOf()
    nondet cpStart = setOfMaps(DEVICES, 1.to(MAX_NO + 1)).oneOf()
    nondet cpValid = setOfMaps(DEVICES, NOS.powerset()).oneOf()
    nondet cpNext = setOfMaps(DEVICES, 1.to(MAX_NO + 1)).oneOf()
    nondet ppIn = setOfMaps(DEVICES, setOfMaps(NOS, Set(false, true))).oneOf()
    nondet ppDev = setOfMaps(DEVICES, setOfMaps(NOS, DEVICES)).oneOf()
    nondet ppRights = setOfMaps(DEVICES, setOfMaps(NOS, RIGHTS)).oneOf()
    nondet hIn = setOfMaps(SLOTS, Set(false, true)).oneOf()
    nondet hStart = setOfMaps(SLOTS, 1.to(MAX_NO + 1)).oneOf()
    nondet hValid = setOfMaps(SLOTS, NOS.powerset()).oneOf()
    nondet hNext = setOfMaps(SLOTS, 1.to(MAX_NO + 1)).oneOf()
    nondet rcs = setOfMaps(DEVICES, Set(-1, 0, 1)).oneOf()
    nondet halts = setOfMaps(DEVICES, Set(false, true)).oneOf()
    nondet forevers = setOfMaps(DEVICES, Set(false, true)).oneOf()
    nondet hps = setOfMaps(DEVICES, HPS.powerset()).oneOf()
    // the processed-record sets: one flag per device and record, since a
    // map from devices to subsets of CPS is expanded by the solver
    nondet rcpIn = setOfMaps(tuples(DEVICES, CPS), Set(false, true)).oneOf()
    nondet rppIn = setOfMaps(tuples(DEVICES, PPS), Set(false, true)).oneOf()
    nondet rrcIn = setOfMaps(tuples(DEVICES, RCS), Set(false, true)).oneOf()
    nondet rg = GENS.oneOf()
    nondet rcp = 0.to(MAX_NO).oneOf()
    nondet rnx = 1.to(MAX_NO + 1).oneOf()
    nondet rv = NOS.powerset().oneOf()
    nondet rrv = NOS.powerset().oneOf()
    nondet rfull = setOfMaps(NOS, RIGHTS).oneOf()
    nondet pcp = CPS.powerset().oneOf()
    nondet ppp = PPS.powerset().oneOf()
    nondet prc = RCS.powerset().oneOf()
    nondet php = HPS.powerset().oneOf()
    nondet pdata = DATAS.powerset().oneOf()
    val hist = SLOTS.filter(s => hIn.get(s))
      .map(s => { gen: s._1, no: s._2, start: hStart.get(s), valid: hValid.get(s), nextNo: hNext.get(s) })
    nondet sn = Set("accept", "grant").powerset().oneOf()
    val ns = DEVICES.mapBy(d => {
      gen: gens.get(d),
      cp: { gen: gens.get(d), no: cpNo.get(d), start: cpStart.get(d), valid: cpValid.get(d), nextNo: cpNext.get(d) },
      pps: NOS.filter(k => ppIn.get(d).get(k))
        .map(k => { gen: gens.get(d), no: k, dev: ppDev.get(d).get(k), rights: ppRights.get(d).get(k) }),
      rc: rcs.get(d), halted: halts.get(d),
      forever: forevers.get(d), recvCp: CPS.filter(c => rcpIn.get((d, c))), recvPp: PPS.filter(x => rppIn.get((d, x))),
      recvRc: RCS.filter(x => rrcIn.get((d, x))), recvHp: hps.get(d),
    })
    val r = { gen: rg, cpNo: rcp, nextNo: rnx, valid: rv,
              rights: NOS.filter(k => k < rnx).mapBy(k => rfull.get(k)), revoked: rrv }
    val p = { cp: pcp, pp: ppp, rc: prc, hp: php, data: pdata }
    all {
      indInvOf(ns, r, p, hist, Set(), sn),
      nodes' = ns,
      root' = r,
      pool' = p,
      history' = hist,
      broken' = Set(),
      seen' = sn,
    }
  }

  // ------------------------------- two nodes with the same processed records
  // Fact 4: the nodes share one drawing of the processed-record sets and are
  // otherwise arbitrary nodes satisfying nodeOk. convergence reads only the
  // nodes, so the rest of the state is the initial one.
  action pairInit = {
    nondet gens = setOfMaps(DEVICES, GENS).oneOf()
    nondet cpNo = setOfMaps(DEVICES, 0.to(MAX_NO)).oneOf()
    nondet cpStart = setOfMaps(DEVICES, 1.to(MAX_NO + 1)).oneOf()
    nondet cpValid = setOfMaps(DEVICES, NOS.powerset()).oneOf()
    nondet cpNext = setOfMaps(DEVICES, 1.to(MAX_NO + 1)).oneOf()
    nondet rcs = setOfMaps(DEVICES, Set(-1, 0, 1)).oneOf()
    nondet halts = setOfMaps(DEVICES, Set(false, true)).oneOf()
    nondet forevers = setOfMaps(DEVICES, Set(false, true)).oneOf()
    nondet rcp = CPS.powerset().oneOf()
    nondet rpp = PPS.powerset().oneOf()
    nondet rrc = RCS.powerset().oneOf()
    nondet rhp = HPS.powerset().oneOf()
    val ns = DEVICES.mapBy(d => {
      gen: gens.get(d),
      cp: { gen: gens.get(d), no: cpNo.get(d), start: cpStart.get(d), valid: cpValid.get(d), nextNo: cpNext.get(d) },
      pps: Set(), rc: rcs.get(d), halted: halts.get(d), forever: forevers.get(d),
      recvCp: rcp, recvPp: rpp, recvRc: rrc, recvHp: rhp,
    })
    all {
      DEVICES.forall(d => nodeOk(ns.get(d))),
      nodes' = ns,
      root' = initRoot,
      pool' = emptyPool,
      history' = Set(),
      broken' = Set(),
      seen' = Set(),
    }
  }
}

// Facts 1 to 3 run on one device. nodeOk speaks of one node; a node's
// actions read only that node and the pool; the actions of the Root, the
// recovery key and the adversary change no node; nodeAcceptData and
// nodeGrant change no node either, and nodeHearsHalted has the effect of
// nodeRecvHp with a proof from the pool. So every step of a model with more
// devices preserves nodeOk of each node exactly when the one-device steps
// do. With one device those three actions are never enabled and are not
// checked. Two devices in one state make the solver run out of memory.
// Fact 4 runs on two devices.

// Checked in CI: two generations, two numbers.
module conv_tiny_ind {
  import conv_inductive(I_DEVICES = Set("a"), I_MAX_GEN = 2, I_MAX_NO = 2, I_WINDOW = 2, I_MUTANT = "none").*
}
module conv_tiny_pair {
  import conv_inductive(I_DEVICES = Set("a", "b"), I_MAX_GEN = 2, I_MAX_NO = 2, I_WINDOW = 2, I_MUTANT = "none").*
}

// For a long run (R-VER-3), the generations and numbers of large_ind: three
// generations (generation 1 has no root change record, so the moves 2 -> 3
// and 1 -> 3 need three) and three numbers.
module conv_large_ind {
  import conv_inductive(I_DEVICES = Set("a"), I_MAX_GEN = 3, I_MAX_NO = 3, I_WINDOW = 2, I_MUTANT = "none").*
}
module conv_large_pair {
  import conv_inductive(I_DEVICES = Set("a", "b"), I_MAX_GEN = 3, I_MAX_NO = 3, I_WINDOW = 2, I_MUTANT = "none").*
}

// Probe (R-VER-2): with mutant need_next a node takes only the checkpoint
// right after its own, so its checkpoint is not a function of what it
// processed and fact 2 must fail for stepRecvCp.
module conv_probe_need_next_ind {
  import conv_inductive(I_DEVICES = Set("a"), I_MAX_GEN = 2, I_MAX_NO = 2, I_WINDOW = 2, I_MUTANT = "need_next").*
}
