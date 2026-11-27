// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 HunterEwok
//
// Inductive invariant of the channels model (R-VER-3). Apalache proves three
// obligations, so that `safety` holds in every reachable state:
//   1. init implies IndInv               (--init=modelInit --invariant=IndInv, 0 steps)
//   2. IndInv and one step imply IndInv   (--init=indInit --invariant=IndInv, 1 step)
//   3. IndInv implies safety              (--init=indInit --invariant=modelSafety, 0 steps)
// with --step=modelStep, or with --step=stepX for each branch X of the step.
// indInit picks an arbitrary state of the bounded types that satisfies IndInv.
module inductive {
  const I_DEVICES: Set[str]
  const I_NO_READ: Set[str]
  const I_LATE: Set[str]
  const I_MAX_GEN: int
  const I_MAX_NO: int
  const I_MAX_DEPTH: int
  const I_BLOCK: int
  const I_MUTANT: str
  import channels(DEVICES = I_DEVICES, NO_READ = I_NO_READ, LATE = I_LATE, MAX_GEN = I_MAX_GEN, MAX_NO = I_MAX_NO,
                  MAX_DEPTH = I_MAX_DEPTH, BLOCK = I_BLOCK, MUTANT = I_MUTANT).* from "./channels"

  // ------------------------------------------------------------ bounded types
  val GENS = 1.to(MAX_GEN)
  val NOS = 1.to(MAX_NO)
  val DEPTHS = 0.to(MAX_DEPTH)
  // In the correct model a key's identity equals its generation.
  val PUBS: Set[Pub] = tuples(GENS, NOS, DEPTHS, Set(false, true))
    .map(t => { gen: t._1, kid: t._1, no: t._2, depth: t._3, empty: t._4 })
  val GRANTS: Set[Grant] = tuples(GENS, DEVICES).map(t => { gen: t._1, kid: t._1, reader: t._2 })
  val TAGS = Set("accept", "refill", "lateClear", "clear", "shrink", "rotateAfterRemove")

  pure def distinctNumbers(s: Set[Pub]): bool = s.forall(a => s.forall(b => a.no == b.no implies a == b))

  // ------------------------------------------------------------------- parts
  pure def sourceOk(s: Source, mk: int): bool = and {
    0.to(MAX_GEN).contains(s.gen), s.kid == s.gen, s.gen == mk,
    0.to(MAX_NO + BLOCK - 1).contains(s.reserved), 1 <= s.nextNo, s.nextNo <= s.reserved + 1,
    s.granted.subseteq(DEVICES),
    // R-CH-5: the readers still to be granted the key were readers when it
    // was made, and those were readers or have left since
    s.toGrant.subseteq(s.atRotation), s.atRotation.subseteq(DEVICES),
    // a key exists only once one was created
    s.keyOk implies s.gen >= 1,
  }

  pure def readerOk(d: str, r: Reader, p: Pool): bool = and {
    0.to(MAX_GEN).contains(r.gen), r.kid == r.gen, r.hiGen == r.gen,
    0.to(MAX_NO).contains(r.hiNo), 1 <= r.floor, r.floor <= r.hiNo + 1, DEPTHS.contains(r.depth),
    r.retained.subseteq(PUBS),
    // retention
    r.retained.size() <= r.depth,
    r.retained.forall(p => r.floor <= p.no and p.no <= r.hiNo),
    distinctNumbers(r.retained),
    r.retained.forall(q => not(q.empty) and q.depth > 0),
    // what a reader retains was published
    r.retained.subseteq(p.pubs),
    // noReadNoKey
    NO_READ.contains(d) implies r.kid == 0,
  }

  pure def poolOk(p: Pool, s: Source, m: Set[str]): bool = and {
    p.pubs.subseteq(PUBS), p.grants.subseteq(GRANTS),
    // numbers and generations already used are behind the source's counters
    p.pubs.forall(q => q.no < s.nextNo and q.no <= s.reserved and q.gen <= s.gen),
    p.grants.forall(x => x.gen <= s.gen),
    distinctNumbers(p.pubs),
    // R-CH-5: while the key may be used, every holder of it is a reader
    (s.keyOk and not(s.mustRotate)) implies
      p.grants.forall(x => x.kid == s.kid implies m.contains(x.reader)),
  }

  pure def indInvOf(s: Source, rs: str -> Reader, m: Set[str], gn: Set[str], jn: Set[str], mk: int, p: Pool,
                    b: Set[str], sn: Set[str]): bool = and {
    rs.keys() == DEVICES,
    sourceOk(s, mk),
    DEVICES.forall(d => readerOk(d, rs.get(d), p)),
    poolOk(p, s, m),
    m.subseteq(DEVICES), gn.subseteq(DEVICES), jn.subseteq(DEVICES),
    s.atRotation.subseteq(m.union(gn)),
    // R-CH-5: every reader that was valid when the current key was made, is
    // still valid, and is no longer waiting for it holds a grant of it
    s.keyOk implies s.atRotation.forall(d => (m.contains(d) and not(s.toGrant.contains(d))) implies
      p.grants.contains({ gen: s.gen, kid: s.kid, reader: d })),
    0.to(MAX_GEN).contains(mk),
    b == Set(),
    sn.subseteq(TAGS),
  }

  val IndInv = indInvOf(source, readers, members, gone, joined, made, pool, broken, seen)

  // The model's own initial state, step, and safety, and the branches of the
  // step one by one (they must name every branch of step in channels.qnt).
  action modelInit = init
  action modelStep = step
  val modelSafety = safety
  action stepEnvRemove = envRemove
  action stepEnvJoin = envJoin
  action stepSourceRotate = sourceRotate
  action stepSourceGrant = sourceGrant
  action stepSourcePublish = sourcePublish
  action stepSourceEpoch = sourceEpoch
  action stepSourceReboot = sourceReboot
  action stepReaderGrant = { nondet d = DEVICES.oneOf() all { pool.grants != Set(), nondet x = pool.grants.oneOf() readerGrant(d, x) } }
  action stepReaderPub = { nondet d = DEVICES.oneOf() all { pool.pubs != Set(), nondet p = pool.pubs.oneOf() readerPub(d, p) } }
  action stepReaderReboot = { nondet d = DEVICES.oneOf() readerReboot(d) }

  // ------------------------------------------- an arbitrary state of IndInv
  action indInit = {
    nondet sgen = 0.to(MAX_GEN).oneOf()
    nondet sok = Set(false, true).oneOf()
    nondet sgranted = DEVICES.powerset().oneOf()
    nondet stogrant = DEVICES.powerset().oneOf()
    nondet satrot = DEVICES.powerset().oneOf()
    nondet snext = 1.to(MAX_NO + BLOCK).oneOf()
    nondet sres = 0.to(MAX_NO + BLOCK - 1).oneOf()
    nondet srot = Set(false, true).oneOf()
    nondet rgen = setOfMaps(DEVICES, 0.to(MAX_GEN)).oneOf()
    nondet rhi = setOfMaps(DEVICES, 0.to(MAX_NO)).oneOf()
    nondet rfloor = setOfMaps(DEVICES, 1.to(MAX_NO + 1)).oneOf()
    nondet rdepth = setOfMaps(DEVICES, DEPTHS).oneOf()
    nondet rret = setOfMaps(DEVICES, PUBS.powerset()).oneOf()
    nondet m = DEVICES.powerset().oneOf()
    nondet gn = DEVICES.powerset().oneOf()
    nondet jn = DEVICES.powerset().oneOf()
    nondet pp = PUBS.powerset().oneOf()
    nondet pg = GRANTS.powerset().oneOf()
    nondet sn = TAGS.powerset().oneOf()
    val s = { gen: sgen, kid: sgen, keyOk: sok, granted: sgranted, nextNo: snext, reserved: sres,
              mustRotate: srot, toGrant: stogrant, atRotation: satrot }
    val rs = DEVICES.mapBy(d => { gen: rgen.get(d), kid: rgen.get(d), hiGen: rgen.get(d), hiNo: rhi.get(d),
                                  floor: rfloor.get(d), depth: rdepth.get(d), retained: rret.get(d) })
    val p = { pubs: pp, grants: pg }
    all {
      indInvOf(s, rs, m, gn, jn, sgen, p, Set(), sn),
      source' = s,
      readers' = rs,
      members' = m,
      gone' = gn,
      joined' = jn,
      made' = sgen,
      pool' = p,
      broken' = Set(),
      seen' = sn,
    }
  }
}

module tiny_ind {
  import inductive(I_DEVICES = Set("a", "b"), I_NO_READ = Set(), I_LATE = Set(), I_MAX_GEN = 2, I_MAX_NO = 4,
                   I_MAX_DEPTH = 2, I_BLOCK = 2, I_MUTANT = "none").*
}

module small_ind {
  import inductive(I_DEVICES = Set("a", "b", "c"), I_NO_READ = Set("c"), I_LATE = Set("b"), I_MAX_GEN = 3,
                   I_MAX_NO = 5, I_MAX_DEPTH = 2, I_BLOCK = 2, I_MUTANT = "none").*
}
