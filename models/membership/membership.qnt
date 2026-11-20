// SPDX-License-Identifier: MPL-2.0
//
// Membership state machine of Ciphered Private Bus (verification level V2).
//
// Scope: passports, checkpoints, revocation, change of rights, root change,
// halt and halt proofs, reboot, and the acceptance of data and key grants
// against the receiver's checkpoint. Requirements: R-MEM-1..13, R-MEM-16, R-CH-2,
// R-VER-4; properties S4..S9.
//
// Abstractions (each one is stated so that a reader can judge what a green
// run does and does not show):
// - Signatures are perfect. The adversary cannot forge a record; it can only
//   deliver, delay, reorder, duplicate, and drop records that exist. The
//   network is therefore modelled as pools of every record ever issued; any
//   node may receive any record at any time, any number of times.
// - The Root may equivocate (two different records with one number). This
//   models a Root restored from an old backup (R-MEM-15 violated) or a stolen
//   root key (L4); the bus must detect it, not prevent it.
// - The recovery key may equivocate (two root change records of one
//   generation, L6).
// - A checkpoint bitmap is the set of valid passport numbers; the window
//   (R-MEM-14) is not modelled.
// - Rights are reduced to one bit: 1 = read, 0 = no read.
// - A data message stands for a publication or a call: it carries the
//   sender's device, passport number, and (generation, checkpoint number).
module membership {
  // ---------------------------------------------------------------- parameters
  const DEVICES: Set[str]
  const MAX_GEN: int      // highest root generation the recovery key may create
  const MAX_NO: int       // highest passport and checkpoint number per generation
  const MUTANT: str       // "none", or the name of a deliberate defect (R-VER-2)

  // --------------------------------------------------------------------- types
  type Passport = { gen: int, no: int, dev: str, rights: int }
  type Checkpoint = { gen: int, no: int, valid: Set[int], nextNo: int }
  type RootChange = { gen: int, key: int }
  // A halt proof names the kind and the head it proves. It is valid by
  // construction: it is only ever created from two conflicting records.
  type HaltProof = { kind: str, gen: int, no: int }
  type Data = { src: str, ppNo: int, gen: int, cpNo: int }

  type Node = {
    gen: int,
    cp: Checkpoint,
    pps: Set[Passport],       // passport cache (R-MEM-7)
    rc: int,                  // key of the root change record of the current generation, -1 for generation 1
    halted: bool,
    forever: bool,            // permanent halt (R-MEM-13, L6)
    // ghost: every record the node has processed, accepted or not. A record
    // of another generation is dropped unprocessed and not recorded: the
    // core has no wait buffer (R-MEM-6), and a record of a future generation
    // can only be verified after its root change record (Appendix B,
    // Section B.3, rule 3). Getting it again is a liveness matter.
    recvCp: Set[Checkpoint],
    recvPp: Set[Passport],
    recvRc: Set[RootChange],
    recvHp: Set[HaltProof],
  }

  type Root = {
    gen: int,
    cpNo: int,
    nextNo: int,
    valid: Set[int],
    rights: int -> int,        // rights of each valid passport number
    revoked: Set[int],         // ghost: passport numbers the owner asked to revoke
  }

  type Pool = {
    cp: Set[Checkpoint],
    pp: Set[Passport],
    rc: Set[RootChange],
    hp: Set[HaltProof],
    data: Set[Data],
  }

  // A log entry records the receiver's checkpoint at the moment it accepted
  // data from, or granted a key to, a device.
  type Entry = { node: str, peer: str, ppNo: int, cp: Checkpoint, halted: bool }

  type Snap = { gen: int, cp: Checkpoint, halted: bool, forever: bool }

  // ----------------------------------------------------------------- variables
  var nodes: str -> Node
  var root: Root
  var pool: Pool
  var accepted: Set[Entry]     // data accepted by a node
  var granted: Set[Entry]      // channel keys granted by a node
  var history: Set[Checkpoint] // ghost: checkpoints issued by the honest Root sequence
  var prev: str -> Snap        // ghost: node state before the last step

  // ------------------------------------------------------------------- helpers
  pure def genesis(g: int): Checkpoint = { gen: g, no: 0, valid: Set(), nextNo: 1 }

  pure def snap(n: Node): Snap = { gen: n.gen, cp: n.cp, halted: n.halted, forever: n.forever }

  pure def lexGt(g1: int, c1: int, g2: int, c2: int): bool =
    g1 > g2 or (g1 == g2 and c1 > c2)

  pure def cpConflict(a: Checkpoint, b: Checkpoint): bool =
    a.gen == b.gen and a.no == b.no and a != b

  pure def ppConflict(a: Passport, b: Passport): bool =
    a.gen == b.gen and a.no == b.no and a != b

  // R-MEM-2: valid for a verifier with checkpoint c.
  // The set of valid numbers stands for the window and bitmap, so a number at
  // or above nextNo is never in it: the check "number below next" is part of
  // reading the bitmap and has no separate probe.
  pure def validUnder(p: Passport, c: Checkpoint): bool =
    p.gen == c.gen
      and p.no < c.nextNo
      and (MUTANT == "ignore_bitmap" or c.valid.contains(p.no))

  pure def initNode: Node = {
    gen: 1, cp: genesis(1), pps: Set(), rc: -1, halted: false, forever: false,
    recvCp: Set(), recvPp: Set(), recvRc: Set(), recvHp: Set(),
  }

  pure def initRoot: Root = { gen: 1, cpNo: 0, nextNo: 1, valid: Set(), rights: Map(), revoked: Set() }

  pure def emptyPool: Pool = { cp: Set(), pp: Set(), rc: Set(), hp: Set(), data: Set() }

  action commit(n2: str -> Node, r2: Root, p2: Pool, a2: Set[Entry], g2: Set[Entry], h2: Set[Checkpoint]): bool = all {
    nodes' = n2,
    root' = r2,
    pool' = p2,
    accepted' = a2,
    granted' = g2,
    history' = h2,
    prev' = nodes.keys().mapBy(d => snap(nodes.get(d))),
  }

  action setNode(d: str, n: Node, p2: Pool): bool =
    commit(nodes.set(d, n), root, p2, accepted, granted, history)

  // -------------------------------------------------------------- initial state
  action init = all {
    nodes' = DEVICES.mapBy(d => initNode),
    root' = initRoot,
    pool' = emptyPool,
    accepted' = Set(),
    granted' = Set(),
    history' = Set(),
    prev' = DEVICES.mapBy(d => snap(initNode)),
  }

  // ------------------------------------------------------------- Root actions
  def rootCheckpoint(valid: Set[int], nx: int): Checkpoint =
    { gen: root.gen, no: root.cpNo + 1, valid: valid, nextNo: nx }

  // Admit a device, or change its rights: the passport and the checkpoint are
  // issued together (R-MEM-3, R-MEM-4).
  action rootIssue(d: str, rights: int, replaces: Set[int]): bool = all {
    root.nextNo <= MAX_NO,
    root.cpNo < MAX_NO,
    val p = { gen: root.gen, no: root.nextNo, dev: d, rights: rights }
    val v = root.valid.exclude(replaces).union(Set(root.nextNo))
    val c = rootCheckpoint(v, root.nextNo + 1)
    commit(nodes,
      { ...root, cpNo: root.cpNo + 1, nextNo: root.nextNo + 1, valid: v,
        rights: root.rights.put(root.nextNo, rights), revoked: root.revoked.union(replaces) },
      { ...pool, pp: pool.pp.union(Set(p)), cp: pool.cp.union(Set(c)) },
      accepted, granted, history.union(Set(c))),
  }

  action rootAdmit = {
    nondet d = DEVICES.oneOf()
    nondet r = Set(0, 1).oneOf()
    rootIssue(d, r, Set())
  }

  // Change of rights: a new passport for the same device, the old one revoked.
  action rootChangeRights = all {
    root.valid != Set(),
    nondet k = root.valid.oneOf()
    val old = pool.pp.filter(p => p.gen == root.gen and p.no == k)
    all {
      old != Set(),
      nondet p = old.oneOf()
      rootIssue(p.dev, 1 - root.rights.get(k), Set(k)),
    }
  }

  // Revocation: a new checkpoint with the bit cleared (R-MEM-4).
  action rootRevoke = all {
    root.valid != Set(),
    root.cpNo < MAX_NO,
    nondet k = root.valid.oneOf()
    // Mutant "keep_bit": the Root issues the revoking checkpoint with the bit
    // still set.
    val v = if (MUTANT == "keep_bit") root.valid else root.valid.exclude(Set(k))
    val c = rootCheckpoint(v, root.nextNo)
    commit(nodes, { ...root, cpNo: root.cpNo + 1, valid: v, revoked: root.revoked.union(Set(k)) },
      { ...pool, cp: pool.cp.union(Set(c)) }, accepted, granted, history.union(Set(c))),
  }

  // Equivocation: a second, different checkpoint with an already used number.
  // It is not part of the honest history.
  action rootEquivocateCp = {
    nondet c = pool.cp.filter(c => c.gen == root.gen and c.no >= 1).oneOf()
    nondet k = 1.to(MAX_NO).oneOf()
    val v = if (c.valid.contains(k)) c.valid.exclude(Set(k)) else c.valid.union(Set(k))
    val c2 = { ...c, valid: v.filter(x => x < c.nextNo) }
    all {
      c2 != c,
      commit(nodes, root, { ...pool, cp: pool.cp.union(Set(c2)) }, accepted, granted, history),
    }
  }

  // Equivocation: a second passport with an already used number.
  action rootEquivocatePp = {
    nondet p = pool.pp.filter(p => p.gen == root.gen).oneOf()
    val p2 = { ...p, rights: 1 - p.rights }
    commit(nodes, root, { ...pool, pp: pool.pp.union(Set(p2)) }, accepted, granted, history)
  }

  // ------------------------------------------------------ Recovery key actions
  // Root change: the new Root starts its counters over (R-MEM-12) and reissues
  // passports with rootAdmit.
  action recoveryChange = all {
    root.gen < MAX_GEN,
    val rc = { gen: root.gen + 1, key: 0 }
    commit(nodes, { ...initRoot, gen: root.gen + 1 },
      { ...pool, rc: pool.rc.union(Set(rc)) }, accepted, granted, history),
  }

  // Two root change records with one generation (L6).
  action recoveryEquivocate = {
    nondet rc = pool.rc.oneOf()
    val rc2 = { ...rc, key: 1 - rc.key }
    commit(nodes, root, { ...pool, rc: pool.rc.union(Set(rc2)) }, accepted, granted, history)
  }

  // ---------------------------------------------------------- Adversary actions
  // Anyone holding two conflicting records can assemble a halt proof.
  action adversaryProof = any {
    nondet a = pool.cp.oneOf()
    nondet b = pool.cp.oneOf()
    all {
      cpConflict(a, b),
      setNodeless(pool.hp.union(Set({ kind: "cp", gen: a.gen, no: a.no }))),
    },
    nondet a = pool.pp.oneOf()
    nondet b = pool.pp.oneOf()
    all {
      ppConflict(a, b),
      setNodeless(pool.hp.union(Set({ kind: "pp", gen: a.gen, no: a.no }))),
    },
    nondet a = pool.rc.oneOf()
    nondet b = pool.rc.oneOf()
    all {
      a.gen == b.gen and a != b,
      setNodeless(pool.hp.union(Set({ kind: "rc", gen: a.gen, no: 0 }))),
    },
  }

  action setNodeless(hp: Set[HaltProof]): bool =
    commit(nodes, root, { ...pool, hp: hp }, accepted, granted, history)

  // ------------------------------------------------------------- Node actions
  pure def halt(n: Node): Node = { ...n, halted: true }

  // Receive a checkpoint (R-MEM-5, R-MEM-8, R-MEM-9, R-MEM-12).
  action nodeRecvCp(d: str, c: Checkpoint): bool = {
    val n0 = nodes.get(d)
    val acceptOld = MUTANT == "accept_old_gen" and c.gen < n0.gen
    val n = if (c.gen == n0.gen or acceptOld) { ...n0, recvCp: n0.recvCp.union(Set(c)) } else n0
    if (n.forever or (n.halted and MUTANT != "halted_accepts"))
      setNode(d, n, pool)
    else if (c.gen != n.gen and not(acceptOld))
      setNode(d, n, pool)
    else if (cpConflict(c, n.cp) and MUTANT != "no_halt")
      setNode(d, halt(n), { ...pool, hp: pool.hp.union(Set({ kind: "cp", gen: c.gen, no: c.no })) })
    else if (c.no > n.cp.no or acceptOld or (MUTANT == "accept_lower" and c.no < n.cp.no))
      setNode(d, { ...n, cp: c, gen: c.gen, pps: n.pps.filter(p => validUnder(p, c)) }, pool)
    else
      setNode(d, n, pool)
  }

  // Receive a passport (R-MEM-2, R-MEM-3, R-MEM-8).
  action nodeRecvPp(d: str, p: Passport): bool = {
    val n0 = nodes.get(d)
    val n = if (p.gen == n0.gen) { ...n0, recvPp: n0.recvPp.union(Set(p)) } else n0
    if (n.halted or n.forever)
      setNode(d, n, pool)
    else if (n.pps.exists(q => ppConflict(p, q)) and MUTANT != "no_halt")
      setNode(d, halt(n), { ...pool, hp: pool.hp.union(Set({ kind: "pp", gen: p.gen, no: p.no })) })
    else if (validUnder(p, n.cp))
      setNode(d, { ...n, pps: n.pps.union(Set(p)) }, pool)
    else
      setNode(d, n, pool)
  }

  // Receive a root change record (R-MEM-11, R-MEM-13).
  action nodeRecvRc(d: str, rc: RootChange): bool = {
    val n0 = nodes.get(d)
    val n = if (rc.gen >= n0.gen) { ...n0, recvRc: n0.recvRc.union(Set(rc)) } else n0
    if (n.forever)
      setNode(d, n, pool)
    else if (rc.gen == n.gen and n.rc != rc.key and n.rc >= 0 and MUTANT != "rc_no_forever")
      setNode(d, { ...n, halted: true, forever: true },
        { ...pool, hp: pool.hp.union(Set({ kind: "rc", gen: rc.gen, no: 0 })) })
    else if (rc.gen > n.gen or (MUTANT == "rc_no_forever" and rc.gen == n.gen and n.rc != rc.key))
      setNode(d, { ...n, gen: rc.gen, rc: rc.key, cp: genesis(rc.gen), pps: Set(),
                   halted: false }, pool)
    else
      setNode(d, n, pool)
  }

  // Receive a halt proof (R-MEM-10; Appendix B, Section B.3, rules 2 and 3).
  action nodeRecvHp(d: str, h: HaltProof): bool = {
    val n0 = nodes.get(d)
    val n = if (h.kind == "rc" or h.gen == n0.gen) { ...n0, recvHp: n0.recvHp.union(Set(h)) } else n0
    val sameGen = h.gen == n.gen and (MUTANT != "proof_needs_cp" or h.no >= n.cp.no)
    if (n.forever)
      setNode(d, n, pool)
    else if (h.kind == "rc")
      setNode(d, { ...n, halted: true, forever: true }, pool)
    else if (h.kind != "rc" and sameGen)
      setNode(d, halt(n), pool)
    else
      setNode(d, n, pool)
  }

  // Reboot: everything in R-CORE-5 survives; the passport cache is volatile.
  action nodeReboot(d: str): bool = {
    val n = nodes.get(d)
    val n2 = if (MUTANT == "reboot_rollback") { ...n, cp: genesis(n.gen), pps: Set() }
             else { ...n, pps: Set() }
    setNode(d, n2, pool)
  }

  // A device sends data under any passport it was ever issued in its
  // generation, including a revoked one: a revoked device may still consider
  // itself a member (R-MEM-16).
  action nodeSend(d: str): bool = {
    val n = nodes.get(d)
    val mine = pool.pp.filter(p => p.dev == d and p.gen == n.gen)
    all {
      not(n.halted),
      mine != Set(),
      nondet p = mine.oneOf()
      setNode(d, n, { ...pool, data: pool.data.union(Set({ src: d, ppNo: p.no, gen: n.gen, cpNo: n.cp.no })) }),
    }
  }

  // Accept data (R-MEM-6, S4, S5). A receiver with an older pair drops the
  // message and requests the checkpoint; nothing changes in its state.
  action nodeAcceptData(d: str, m: Data): bool = {
    val n = nodes.get(d)
    all {
      not(n.halted) or MUTANT == "halted_accepts",
      m.src != d,
      not(lexGt(m.gen, m.cpNo, n.gen, n.cp.no)),
      n.pps.exists(p => p.dev == m.src and p.no == m.ppNo and validUnder(p, n.cp)),
      commit(nodes, root, pool,
        accepted.union(Set({ node: d, peer: m.src, ppNo: m.ppNo, cp: n.cp, halted: n.halted })), granted, history),
    }
  }

  // Grant a channel key to a reader with the read right (R-CH-2, R-MEM-9).
  action nodeGrant(d: str): bool = {
    val n = nodes.get(d)
    all {
      not(n.halted) or MUTANT == "halted_accepts",
      nondet p = n.pps.oneOf()
      all {
        p.dev != d,
        p.rights == 1 or MUTANT == "grant_no_right",
        validUnder(p, n.cp),
        commit(nodes, root, pool, accepted,
          granted.union(Set({ node: d, peer: p.dev, ppNo: p.no, cp: n.cp, halted: n.halted })), history),
      },
    }
  }

  // ---------------------------------------------------------------------- step
  action step = any {
    rootAdmit,
    rootChangeRights,
    rootRevoke,
    rootEquivocateCp,
    rootEquivocatePp,
    recoveryChange,
    recoveryEquivocate,
    adversaryProof,
    nondet d = DEVICES.oneOf()
    any {
      all { pool.cp != Set(), nondet c = pool.cp.oneOf() nodeRecvCp(d, c) },
      all { pool.pp != Set(), nondet p = pool.pp.oneOf() nodeRecvPp(d, p) },
      all { pool.rc != Set(), nondet r = pool.rc.oneOf() nodeRecvRc(d, r) },
      all { pool.hp != Set(), nondet h = pool.hp.oneOf() nodeRecvHp(d, h) },
      all { pool.data != Set(), nondet m = pool.data.oneOf() nodeAcceptData(d, m) },
      nodeReboot(d),
      nodeSend(d),
      all { nodes.get(d).pps != Set(), nodeGrant(d) },
    },
  }

  // ---------------------------------------------------------------- invariants

  // S6, R-MEM-5: within one generation the checkpoint number never decreases,
  // including across a reboot.
  val noRollback = DEVICES.forall(d =>
    val n = nodes.get(d)
    val p = prev.get(d)
    n.gen > p.gen or (n.gen == p.gen and n.cp.no >= p.cp.no))

  // S9, R-MEM-12: a node holds only records of its current generation, and the
  // generation never decreases.
  val currentGeneration = DEVICES.forall(d =>
    val n = nodes.get(d)
    n.cp.gen == n.gen and n.pps.forall(p => p.gen == n.gen) and n.gen >= prev.get(d).gen)

  // S8, R-MEM-9: only a root change record leaves the halted state, and a
  // permanent halt is never left.
  val haltIsSticky = DEVICES.forall(d =>
    val n = nodes.get(d)
    val p = prev.get(d)
    (p.forever implies n.forever) and ((p.halted and not(n.halted)) implies n.gen > p.gen))

  // S8, R-MEM-9: a halted node accepts no checkpoint, data, or grant.
  val haltedIsInert = DEVICES.forall(d =>
    val n = nodes.get(d)
    val p = prev.get(d)
    (p.halted and n.gen == p.gen) implies n.cp == p.cp)
    and accepted.forall(e => not(e.halted)) and granted.forall(e => not(e.halted))

  // R-MEM-10: a node that processed a halt proof of its current generation is
  // halted, whatever checkpoint it is at.
  val proofIsObeyed = DEVICES.forall(d =>
    val n = nodes.get(d)
    n.recvHp.exists(h => h.gen == n.gen or h.kind == "rc") implies n.halted)

  // R-MEM-4: every checkpoint the Root issues has the bit of each passport
  // the owner revoked or replaced cleared.
  val rootHonorsRevocation = root.valid.intersect(root.revoked) == Set()

  // S8, R-MEM-8: a node that is not halted never holds a checkpoint and a
  // passport cache in conflict with each other.
  val cacheConsistent = DEVICES.forall(d =>
    val n = nodes.get(d)
    n.halted or n.pps.forall(p => n.pps.forall(q => not(ppConflict(p, q)))))

  // S4, S5, R-VER-4: no node accepts data from, or grants a key to, a passport
  // that the honest Root sequence has revoked at or before the receiver's
  // checkpoint. Passport numbers are never reused, so "revoked at checkpoint
  // c" means: number below c.nextNo and not in c.valid.
  def revokedBy(ppNo: int, c: Checkpoint): bool = ppNo < c.nextNo and not(c.valid.contains(ppNo))

  def neverAfterRevocation(log: Set[Entry]): bool = log.forall(e =>
    not(history.contains(e.cp)) or history.forall(c =>
      not(c.gen == e.cp.gen and c.no <= e.cp.no and revokedBy(e.ppNo, c))))

  val revokedIsRejected = neverAfterRevocation(accepted) and neverAfterRevocation(granted)

  // R-CH-2: keys are granted only to passports with the read right.
  val grantsNeedRead = granted.forall(e =>
    pool.pp.exists(p => p.gen == e.cp.gen and p.no == e.ppNo and p.dev == e.peer and p.rights == 1))

  // S7: two nodes that processed the same records are in the same state, with
  // one exception: a node that saw two conflicting records halted while the
  // other did not notice, and no halt proof has reached them yet.
  val convergence = DEVICES.forall(a => DEVICES.forall(b =>
    val x = nodes.get(a)
    val y = nodes.get(b)
    val same = x.recvCp == y.recvCp and x.recvPp == y.recvPp
      and x.recvRc == y.recvRc and x.recvHp == y.recvHp
    // A permanent halt is terminal: the rest of the state no longer matters.
    same implies (
      x.forever == y.forever and (x.forever or (
        x.gen == y.gen
          and (x.halted or y.halted or x.cp == y.cp)
          and (x.halted == y.halted or x.recvHp.forall(h => h.gen != x.gen)))))))

  val safety = noRollback and currentGeneration and haltIsSticky and haltedIsInert
    and proofIsObeyed and rootHonorsRevocation and cacheConsistent
    and revokedIsRejected and grantsNeedRead and convergence

  // ------------------------------------------------- non-vacuity witnesses
  // Each witness is expected to be VIOLATED: the violation shows that the
  // behaviour is reachable, so the safety checks above are not vacuous.
  val witnessHalt = DEVICES.forall(d => not(nodes.get(d).halted))
  val witnessForever = DEVICES.forall(d => not(nodes.get(d).forever))
  val witnessAccept = accepted == Set()
  val witnessGrant = granted == Set()
  val witnessRootChange = DEVICES.forall(d => nodes.get(d).gen == 1)
  val witnessRevokedSends = not(pool.data.exists(m =>
    DEVICES.exists(d => revokedBy(m.ppNo, nodes.get(d).cp) and nodes.get(d).gen == m.gen)))
}
