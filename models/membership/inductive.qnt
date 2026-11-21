// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 HunterEwok
//
// Inductive invariant of the membership model for the instance tiny_tlc
// (R-VER-3). Apalache proves three facts, each for all reachable states and
// not only up to a bound:
//   1. init implies IndInv               (--init=modelInit --invariant=IndInv, 0 steps)
//   2. IndInv and one step imply IndInv   (--init=indInit --invariant=IndInv, 1 step)
//   3. IndInv implies safety              (--init=indInit --invariant=modelSafety, 0 steps)
// with --step=modelStep.
// indInit picks an arbitrary state of the bounded types that satisfies
// IndInv, so fact 2 starts from every such state, reachable or not.
module inductive {
  const I_DEVICES: Set[str]
  const I_MAX_GEN: int
  const I_MAX_NO: int
  const I_WINDOW: int
  const I_MUTANT: str
  import membership(DEVICES = I_DEVICES, MAX_GEN = I_MAX_GEN, MAX_NO = I_MAX_NO, WINDOW = I_WINDOW, MUTANT = I_MUTANT, TRACK_RECV = false).* from "./membership"

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

  // ------------------------------------------------------------------- parts
  def nodeOk(n: Node): bool = and {
    // types
    GENS.contains(n.gen), CPS.contains(n.cp), n.pps.subseteq(PPS), Set(-1, 0, 1).contains(n.rc),
    n.recvCp == Set(), n.recvPp == Set(), n.recvRc == Set(), n.recvHp.subseteq(HPS),
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
    // cacheConsistent
    n.halted or n.pps.forall(p => validIn(p, n.cp) and n.pps.forall(q => not(ppConflict(p, q)))),
  }

  def rootOk(r: Root): bool = and {
    GENS.contains(r.gen), 0.to(MAX_NO).contains(r.cpNo), 1.to(MAX_NO + 1).contains(r.nextNo),
    r.nextNo <= r.cpNo + 1,
    r.valid.forall(k => 1 <= k and k < r.nextNo),
    r.revoked.forall(k => 1 <= k and k < r.nextNo),
    r.rights.keys() == NOS.filter(k => k < r.nextNo),
    r.rights.keys().forall(k => RIGHTS.contains(r.rights.get(k))),
    // the window of the Root's next checkpoint fits (R-MEM-14)
    r.nextNo - windowStart(r.valid, r.nextNo) <= WINDOW,
    // rootHonorsRevocation
    r.valid.intersect(r.revoked) == Set(),
  }

  // The honest checkpoints of one generation never bring a cleared bit back:
  // this is what makes "revoked at or before the receiver's checkpoint"
  // equivalent to "not valid under it".
  def historyOk(r: Root, h: Set[Checkpoint]): bool = and {
    h.subseteq(CPS),
    h.forall(c => c.gen <= r.gen and (c.gen == r.gen implies and {
      c.no <= r.cpNo, c.nextNo <= r.nextNo, below(r.valid, c).subseteq(c.valid),
      // windowKeepsValid
      c.no == r.cpNo implies (c.valid == r.valid and c.nextNo == r.nextNo),
    })),
    h.forall(c1 => h.forall(c2 => (c1.gen == c2.gen and c1.no <= c2.no) implies
      (c1.nextNo <= c2.nextNo and below(c2.valid, c1).subseteq(c1.valid)))),
  }

  def poolOk(p: Pool): bool = and {
    p.cp.subseteq(CPS), p.pp.subseteq(PPS), p.rc.subseteq(RCS), p.hp.subseteq(HPS), p.data.subseteq(DATAS),
  }

  def indInvOf(ns: str -> Node, r: Root, p: Pool, h: Set[Checkpoint], b: Set[str], s: Set[str]): bool = and {
    ns.keys() == DEVICES,
    DEVICES.forall(d => nodeOk(ns.get(d))),
    rootOk(r),
    historyOk(r, h),
    poolOk(p),
    b == Set(),
    s.subseteq(Set("accept", "grant")),
  }

  val IndInv = indInvOf(nodes, root, pool, history, broken, seen)

  // The model's own initial state, step, and safety, under names that the
  // instances below can see (an instance does not pass on what it imports).
  action modelInit = init
  action modelStep = step
  val modelSafety = safety

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
  action indInit = {
    nondet gens = setOfMaps(DEVICES, GENS).oneOf()
    nondet cps = setOfMaps(DEVICES, CPS).oneOf()
    nondet ppss = setOfMaps(DEVICES, PPS.powerset()).oneOf()
    nondet rcs = setOfMaps(DEVICES, Set(-1, 0, 1)).oneOf()
    nondet halts = setOfMaps(DEVICES, Set(false, true)).oneOf()
    nondet forevers = setOfMaps(DEVICES, Set(false, true)).oneOf()
    nondet hps = setOfMaps(DEVICES, HPS.powerset()).oneOf()
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
    nondet hist = CPS.powerset().oneOf()
    nondet sn = Set("accept", "grant").powerset().oneOf()
    val ns = DEVICES.mapBy(d => {
      gen: gens.get(d), cp: cps.get(d), pps: ppss.get(d), rc: rcs.get(d), halted: halts.get(d),
      forever: forevers.get(d), recvCp: Set(), recvPp: Set(), recvRc: Set(), recvHp: hps.get(d),
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
}

// The instance tiny_tlc.
module tiny_ind {
  import inductive(I_DEVICES = Set("a", "b"), I_MAX_GEN = 2, I_MAX_NO = 2, I_WINDOW = 2, I_MUTANT = "none").*
}

// The size of small: three devices, three numbers per generation.
module small_ind {
  import inductive(I_DEVICES = Set("a", "b", "c"), I_MAX_GEN = 2, I_MAX_NO = 3, I_WINDOW = 2, I_MUTANT = "none").*
}

// For a long run (R-VER-3): three devices, three generations, three numbers.
module large_ind {
  import inductive(I_DEVICES = Set("a", "b", "c"), I_MAX_GEN = 3, I_MAX_NO = 3, I_WINDOW = 2, I_MUTANT = "none").*
}
