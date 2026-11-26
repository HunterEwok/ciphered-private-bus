// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 HunterEwok
//
// Inductive invariant of the relay model (R-VER-3). Apalache proves three
// facts, each for all reachable states and not only up to a bound:
//   1. init implies IndInv               (--init=modelInit --invariant=IndInv, 0 steps)
//   2. IndInv and one step imply IndInv   (--init=indInit --invariant=IndInv, 1 step)
//   3. IndInv implies safety              (--init=indInit --invariant=modelSafety, 0 steps)
// with --step=modelStep. indInit picks an arbitrary state of the bounded
// types that satisfies IndInv, so fact 2 starts from every such state,
// reachable or not.
module inductive {
  const I_N_DEV: int
  const I_CHANS: Set[int]
  const I_MAX_NO: int
  const I_MAX_DEPTH: int
  const I_SIZES: Set[int]
  const I_SOURCE_BYTES: int
  const I_BUS_BYTES: int
  const I_JOIN_MAX: int
  const I_MAX_ARR: int
  const I_MAX_EVENTS: int
  import relay(N_DEV = I_N_DEV, CHANS = I_CHANS, MAX_NO = I_MAX_NO, MAX_DEPTH = I_MAX_DEPTH, SIZES = I_SIZES,
               SOURCE_BYTES = I_SOURCE_BYTES, BUS_BYTES = I_BUS_BYTES, JOIN_MAX = I_JOIN_MAX,
               MAX_ARR = I_MAX_ARR, MAX_EVENTS = I_MAX_EVENTS, MUTANT = "none").* from "./relay"

  // ------------------------------------------------------------ bounded types
  val KEYS = tuples(DEVS, CHANS)
  val CPNOS = 1.to(MAX_EVENTS + 1)
  val TAGS = Set("ownEvicted", "busEvicted", "noVictim", "grantReplaced", "servedPub", "forwarded0",
                 "requestAnswered", "revokedPurged", "unlisted", "joinEvicted", "newGenTicket", "refused",
                 "callForwarded", "callRefused")

  // What the relay can hold, field by field (membership of a record in a big
  // set costs Apalache the size of that set per element).
  def isStored(o: Obj, arrNow: int): bool = and {
    DEVS.contains(o.src), CHANS.contains(o.ch), o.ok, 1 <= o.arr, o.arr <= arrNow,
    if (o.kind == "pub") and {
      o.reader == 0, NOS.contains(o.no), o.gen == 0, 1 <= o.depth, o.depth <= MAX_DEPTH, SIZES.contains(o.size),
    } else if (o.kind == "grant") and {
      DEVS.contains(o.reader), o.reader != o.src, 0 <= o.no, o.no <= 1, 1 <= o.gen, o.gen <= 2,
      o.depth == 0, o.size == 0,
    } else and {
      o.kind == "req", DEVS.contains(o.reader), o.reader != o.src, o.no == 1, o.gen == 0, o.depth == 0, o.size == 0,
    },
  }

  def indInvOf(r: Relay, c: int -> Set[int], rt: { gen: int, tNo: int, cpNo: int, listed: bool }, ev: int, nj: int,
               b: Set[str], s: Set[str]): bool = and {
    // bounds
    0 <= ev, ev <= MAX_EVENTS, 0 <= nj,
    // every new checkpoint, root change and join request is one event
    (rt.cpNo - 1) + (rt.gen - 1) + nj <= ev,
    1 <= rt.gen, rt.gen <= 2, 0 <= rt.tNo, rt.tNo <= 2, CPNOS.contains(rt.cpNo),
    c.keys() == CPNOS.filter(k => k <= rt.cpNo), c.keys().forall(k => c.get(k).subseteq(DEVS)),
    // the Root's checkpoints only add revoked devices
    c.keys().forall(k => c.keys().forall(m => k <= m implies c.get(k).subseteq(c.get(m)))),
    0 <= r.arr, r.arr <= MAX_ARR,
    r.hi.keys() == KEYS, r.dep.keys() == KEYS,
    KEYS.forall(k => 0 <= r.hi.get(k) and r.hi.get(k) <= MAX_NO and 0 <= r.dep.get(k) and r.dep.get(k) <= MAX_DEPTH),
    r.joins.length() <= JOIN_MAX, r.joins.indices().forall(i => 1 <= r.joins.nth(i) and r.joins.nth(i) <= nj),
    r.online.subseteq(DEVS), r.revoked.subseteq(DEVS),
    1 <= r.rootGen, r.rootGen <= rt.gen, 1 <= r.tGen, r.tGen <= 2, 1 <= r.tNo, r.tNo <= 2,
    // the relay's checkpoint is one the Root issued, the latest it accepted
    1 <= r.cpNo, r.cpNo <= rt.cpNo, r.cpMax == r.cpNo, r.revoked == c.get(r.cpNo),
    // a relay no longer listed holds the Root's last checkpoint, which unlisted it
    not(r.served) implies (r.cpNo == rt.cpNo and not(rt.listed) and r.online == Set() and r.joins == List()),
    // nothing revoked is connected
    r.online.forall(d => not(r.revoked.contains(d))),
    // the store
    r.store.forall(o => isStored(o, r.arr)),
    r.store.forall(a => r.store.forall(x => (a.kind == "pub" and x.kind == "pub" and a.src == x.src and a.ch == x.ch
      and a.no == x.no) implies a == x)),
    r.store.forall(o => o.kind == "pub" implies o.no <= r.hi.get((o.src, o.ch))),
    // state parts of safety
    r.store.forall(o => not(r.revoked.contains(o.src)) and (o.kind == "pub" or not(r.revoked.contains(o.reader)))),
    r.bytes.pub.keys() == PSLOTS, r.bytes.grant.keys() == GSLOTS, r.bytes.req.keys() == GSLOTS,
    PSLOTS.forall(k => r.bytes.pub.get(k) == 0 or SIZES.contains(r.bytes.pub.get(k))),
    GSLOTS.forall(k => 0 <= r.bytes.grant.get(k) and r.bytes.grant.get(k) <= 1
      and 0 <= r.bytes.req.get(k) and r.bytes.req.get(k) <= 1),
    bytesMatch(r), DEVS.forall(d => bytesOf(r.bytes, d) <= SOURCE_BYTES), sumOf(usageOf(r.bytes), DEVS) <= BUS_BYTES,
    r.store.forall(a => r.store.forall(x =>
      (a.kind == x.kind and a.kind != "pub" and a.src == x.src and a.ch == x.ch and a.reader == x.reader) implies a == x)),
    KEYS.forall(k => r.hi.get(k) > 0 implies
      r.store.filter(o => o.kind == "pub" and (o.src, o.ch) == k).size() <= r.dep.get(k)),
    not(r.served) implies r.store == Set(),
    b == Set(),
    s.subseteq(TAGS),
  }

  val IndInv = indInvOf(relay, cps, root, events, nextJoin, broken, seen)

  action modelInit = init
  action modelStep = step
  val modelSafety = safety

  // The branches of step, one by one. Together they are exactly step.
  action stepRecvPub = { nondet o = PUBS.oneOf() recvPub(o) }
  action stepRecvGrant = { nondet o = GRANTS.oneOf() recvGrant(o) }
  action stepRecvReq = { nondet o = REQS.oneOf() recvReq(o) }
  action stepRecvCall = { nondet o = CALLS.oneOf() recvCall(o) }
  action stepConnect = { nondet d = DEVS.oneOf() connect(d) }
  action stepDisconnect = { nondet d = DEVS.oneOf() disconnect(d) }
  action stepRootRevoke = { nondet d = DEVS.oneOf() rootRevoke(d) }
  action stepRootUnlist = rootUnlist
  action stepRootChange = all { root.gen < 2, rootChange }
  action stepRootTicket = all { root.tNo < 2, rootTicket }
  action stepLearnCp = { nondet n = cps.keys().oneOf() learnCp(n) }
  action stepLearnRootChange = learnRootChange
  action stepLearnTicket = { nondet g = 1.to(2).oneOf() nondet n = 1.to(2).oneOf() learnTicket(g, n) }
  action stepRecvJoin = recvJoin

  // ------------------------------------------- an arbitrary state of IndInv
  // The store is drawn from the key slots (PSLOTS, GSLOTS in relay.qnt), one
  // object per occupied slot, instead of from all subsets of every possible
  // object; the slot bytes drawn are the relay's accounting.
  val ARRS = 1.to(MAX_ARR)

  action indInit = {
    nondet pBytes = setOfMaps(PSLOTS, Set(0).union(SIZES)).oneOf()
    nondet pDepth = setOfMaps(PSLOTS, 1.to(MAX_DEPTH)).oneOf()
    nondet pArr = setOfMaps(PSLOTS, ARRS).oneOf()
    nondet gBytes = setOfMaps(GSLOTS, 0.to(1)).oneOf()
    nondet gGen = setOfMaps(GSLOTS, 1.to(2)).oneOf()
    nondet gNo = setOfMaps(GSLOTS, 0.to(1)).oneOf()
    nondet gArr = setOfMaps(GSLOTS, ARRS).oneOf()
    nondet qBytes = setOfMaps(GSLOTS, 0.to(1)).oneOf()
    nondet qArr = setOfMaps(GSLOTS, ARRS).oneOf()
    nondet served = Set(false, true).oneOf()
    nondet cpNo = CPNOS.oneOf()
    nondet revAll = setOfMaps(CPNOS, DEVS.powerset()).oneOf()
    nondet rootGen = 1.to(2).oneOf()
    nondet tGen = 1.to(2).oneOf()
    nondet tNo = 1.to(2).oneOf()
    nondet hi = setOfMaps(KEYS, 0.to(MAX_NO)).oneOf()
    nondet dep = setOfMaps(KEYS, 0.to(MAX_DEPTH)).oneOf()
    nondet arr = 0.to(MAX_ARR).oneOf()
    nondet jl = 0.to(JOIN_MAX).oneOf()
    nondet jv = setOfMaps(1.to(JOIN_MAX), 1.to(MAX_EVENTS)).oneOf()
    nondet online = DEVS.powerset().oneOf()
    nondet rGen = 1.to(2).oneOf()
    nondet rTNo = 0.to(2).oneOf()
    nondet rCpNo = CPNOS.oneOf()
    nondet listed = Set(false, true).oneOf()
    nondet ev = 0.to(MAX_EVENTS).oneOf()
    nondet nj = 0.to(MAX_EVENTS).oneOf()
    nondet sn = TAGS.powerset().oneOf()
    val pubs = PSLOTS.filter(t => pBytes.get(t) > 0).map(t =>
      { kind: "pub", src: t._1, ch: t._2, reader: 0, no: t._3, gen: 0, depth: pDepth.get(t), size: pBytes.get(t),
        ok: true, arr: pArr.get(t) })
    val grants = GSLOTS.filter(t => gBytes.get(t) == 1).map(t =>
      { kind: "grant", src: t._1, ch: t._2, reader: t._3, no: gNo.get(t), gen: gGen.get(t), depth: 0, size: 0,
        ok: true, arr: gArr.get(t) })
    val reqs = GSLOTS.filter(t => qBytes.get(t) == 1).map(t =>
      { kind: "req", src: t._1, ch: t._2, reader: t._3, no: 1, gen: 0, depth: 0, size: 0, ok: true, arr: qArr.get(t) })
    val c = CPNOS.filter(k => k <= rCpNo).mapBy(k => revAll.get(k))
    val r = {
      served: served, cpNo: cpNo, cpMax: cpNo, revoked: revAll.get(cpNo), rootGen: rootGen, tGen: tGen, tNo: tNo,
      store: pubs.union(grants).union(reqs), bytes: { pub: pBytes, grant: gBytes, req: qBytes }, hi: hi, dep: dep, arr: arr,
      joins: range(0, JOIN_MAX).foldl(List(), (l, i) => if (i < jl) l.append(jv.get(i + 1)) else l),
      online: online,
    }
    val rt = { gen: rGen, tNo: rTNo, cpNo: rCpNo, listed: listed }
    all {
      indInvOf(r, c, rt, ev, nj, Set(), sn),
      relay' = r, cps' = c, root' = rt, events' = ev, nextJoin' = nj, broken' = Set(), seen' = sn,
    }
  }
}

// The size of tiny.
module tiny_ind {
  import inductive(I_N_DEV = 2, I_CHANS = Set(1), I_MAX_NO = 2, I_MAX_DEPTH = 1, I_SIZES = Set(1, 2),
                   I_SOURCE_BYTES = 2, I_BUS_BYTES = 3, I_JOIN_MAX = 1, I_MAX_ARR = 4, I_MAX_EVENTS = 3).*
}

// The size of small, for a long run (R-VER-3).
module small_ind {
  import inductive(I_N_DEV = 3, I_CHANS = Set(1, 2), I_MAX_NO = 3, I_MAX_DEPTH = 2, I_SIZES = Set(1, 2),
                   I_SOURCE_BYTES = 3, I_BUS_BYTES = 5, I_JOIN_MAX = 2, I_MAX_ARR = 8, I_MAX_EVENTS = 4).*
}
