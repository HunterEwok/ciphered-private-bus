// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 HunterEwok
//
// Relay of Ciphered Private Bus (verification level V2).
//
// Scope: one relay serving one bus; what it accepts, stores, evicts, serves
// and forgets. Publications with their retention depth, key grants, key
// requests, calls, quotas per source and per bus with the eviction rules of
// Appendix B, Section B.10, revocation of a device, removal of the relay from
// the checkpoint, tickets across a root change, and the buffer of join
// requests. Requirements: R-REL-2..8, R-JOIN-8, R-CH-12, B.10 rules;
// properties S14 (fair share), S15, L5.
//
// Abstractions:
// - Signatures are perfect: an object either carries a valid signature of its
//   signer or not (`ok`), and the relay can tell. The network delivers any
//   object, forged or not, at any time and any number of times.
// - Every device is a possible source and reader; devices are numbered, so
//   "the smaller identifier" of rule 4 is the smaller number.
// - Sizes are small units; a grant and a key request take one unit. Blobs,
//   padding and the clearing publication are not modelled; a blob counts as
//   part of its publication's size.
// - The relay's checkpoint is reduced to its number, the set of revoked
//   devices and whether it still lists the relay. The ticket is reduced to its
//   pair (gen, no); its limits are the constants BUS_BYTES and SOURCE_BYTES.
// - What the relay sends is not kept: properties of a send are checked by a
//   monitor when it happens. The order of what is served (grant first, then
//   publications by number) is a delivery property (R-REL-11) and is checked
//   by the simulator of the implementation, not here.
// - Calls and stream chunks are one kind: the relay forwards them and stores
//   nothing (R-REL-8, R-STR-7).
// - The property that a hostile relay cannot break S1..S14 (R-REL-11) is
//   checked in the other models, whose network is a pool that delivers
//   anything any number of times; this model checks the honest relay.
module relay {
  // ---------------------------------------------------------------- parameters
  const N_DEV: int          // devices 1..N_DEV
  const CHANS: Set[int]     // channel labels of each source
  const MAX_NO: int         // highest publication number per channel
  const MAX_DEPTH: int      // highest retention depth
  const SIZES: Set[int]     // possible sizes of a publication
  const SOURCE_BYTES: int   // per-source limit of the ticket
  const BUS_BYTES: int      // per-bus limit of the ticket
  const JOIN_MAX: int       // join requests the relay holds (R-JOIN-8)
  const MAX_ARR: int        // objects the relay may store over a run (its arrival counter)
  const MAX_EVENTS: int     // revocations, root changes, tickets, joins, removal of the relay
  const MUTANT: str         // "none", or the name of a deliberate defect (R-VER-2)

  // --------------------------------------------------------------------- types
  val DEVS = 1.to(N_DEV)
  val NOS = 1.to(MAX_NO)
  val DEPTHS = 0.to(MAX_DEPTH)

  // Key slots: publications are unique by (source, channel, number), grants
  // and key requests by (source, channel, reader), and a grant or request
  // never names its source as reader.
  val PSLOTS = tuples(DEVS, CHANS, NOS)
  val GSLOTS = tuples(DEVS, CHANS, DEVS).filter(t => t._1 != t._3)
  // The bytes the relay holds in each slot, 0 for an empty one. The relay
  // accounts by slot; each object is in the slot of its key.
  type Bytes = { pub: (int, int, int) -> int, grant: (int, int, int) -> int, req: (int, int, int) -> int }

  // One object as the relay sees it. Fields that a kind does not use are 0.
  // pub:   src, ch, no (publication number), depth, size
  // grant: src, ch, reader, gen (channel key generation), no (nonce of the
  //        request it answers, 0 for none)
  // req:   src and ch of the channel asked for, reader (the signer), no (nonce)
  // call:  src (sender), reader (target); also stands for replies and chunks
  type Obj = { kind: str, src: int, ch: int, reader: int, no: int, gen: int, depth: int, size: int, ok: bool, arr: int }

  type Relay = {
    served: bool,          // the latest checkpoint lists the relay
    cpNo: int,             // number of the latest checkpoint accepted
    cpMax: int,            // ghost: greatest checkpoint number ever accepted
    revoked: Set[int],     // devices revoked under that checkpoint
    rootGen: int,          // generation of the latest root change record
    tGen: int,             // pair (gen, no) of the ticket held
    tNo: int,
    store: Set[Obj],       // publications, grants and key requests
    bytes: Bytes,          // bytes held per key slot (the relay's accounting)
    hi: (int, int) -> int, // highest publication number seen per (source, channel)
    dep: (int, int) -> int,// depth of that publication: it governs retention
    arr: int,              // arrival counter (B.10 rule 5)
    joins: List[int],      // join requests, oldest first
    online: Set[int],      // connected devices
  }

  // ----------------------------------------------------------------- variables
  var relay: Relay
  var cps: int -> Set[int]   // ghost: every checkpoint the Root issued, by number
  var root: { gen: int, tNo: int, cpNo: int, listed: bool }
  var events: int
  var nextJoin: int          // ghost: number of join requests ever made
  // Monitor: properties of a single step are checked when it is taken, and
  // the name of a violated one is added here.
  var broken: Set[str]
  var seen: Set[str]         // ghost: behaviours that happened (witnesses)

  // ------------------------------------------------------------------ helpers
  pure def max2(a: int, b: int): int = if (a > b) a else b
  pure def payer(o: Obj): int = if (o.kind == "req") o.reader else o.src
  pure def sizeOf(o: Obj): int = if (o.kind == "pub") o.size else 1
  pure def atP(o: Obj, k: (int, int, int)): bool = o.kind == "pub" and o.src == k._1 and o.ch == k._2 and o.no == k._3
  pure def atG(o: Obj, k: (int, int, int)): bool = o.kind == "grant" and o.src == k._1 and o.ch == k._2 and o.reader == k._3
  pure def atQ(o: Obj, k: (int, int, int)): bool = o.kind == "req" and o.src == k._1 and o.ch == k._2 and o.reader == k._3
  val NO_BYTES: Bytes = { pub: PSLOTS.mapBy(k => 0), grant: GSLOTS.mapBy(k => 0), req: GSLOTS.mapBy(k => 0) }
  // `o` stored; `gone` deleted. Each slot is computed on its own.
  def withObj(m: Bytes, o: Obj): Bytes = {
    pub: PSLOTS.mapBy(k => if (atP(o, k)) o.size else m.pub.get(k)),
    grant: GSLOTS.mapBy(k => if (atG(o, k)) 1 else m.grant.get(k)),
    req: GSLOTS.mapBy(k => if (atQ(o, k)) 1 else m.req.get(k)),
  }
  def without(m: Bytes, gone: Set[Obj]): Bytes = {
    pub: PSLOTS.mapBy(k => if (gone.exists(x => atP(x, k))) 0 else m.pub.get(k)),
    grant: GSLOTS.mapBy(k => if (gone.exists(x => atG(x, k))) 0 else m.grant.get(k)),
    req: GSLOTS.mapBy(k => if (gone.exists(x => atQ(x, k))) 0 else m.req.get(k)),
  }
  // Slot by slot: `c` chooses between `x` and `y`.
  def pick(c: bool, x: Bytes, y: Bytes): Bytes = {
    pub: PSLOTS.mapBy(k => if (c) x.pub.get(k) else y.pub.get(k)),
    grant: GSLOTS.mapBy(k => if (c) x.grant.get(k) else y.grant.get(k)),
    req: GSLOTS.mapBy(k => if (c) x.req.get(k) else y.req.get(k)),
  }
  // The usage of device `d`: its publications and grants, and the key
  // requests it signed. A plain sum over its slots, with no condition on
  // whether a slot is occupied (an empty slot holds 0): such sums stay
  // linear for the solver, while a sum over the objects of a set grows
  // exponentially with the number of objects the set may hold. `d` is always
  // a constant (a member of DEVS in `usageOf`).
  def bytesOf(m: Bytes, d: int): int =
    tuples(CHANS, NOS).fold(0, (a, t) => a + m.pub.get((d, t._1, t._2)))
    + tuples(CHANS, DEVS).fold(0, (a, t) => if (t._2 == d) a else a + m.grant.get((d, t._1, t._2)) + m.req.get((t._2, t._1, d)))
  def usageOf(m: Bytes): int -> int = DEVS.mapBy(d => bytesOf(m, d))
  pure def total(st: Set[Obj]): int = st.fold(0, (a, o) => a + sizeOf(o))
  pure def pubsOf(st: Set[Obj], s: int): Set[Obj] = st.filter(o => o.kind == "pub" and o.src == s)
  pure def grantsOf(st: Set[Obj], s: int): Set[Obj] = st.filter(o => o.kind == "grant" and o.src == s)
  pure def hasGrant(st: Set[Obj], s: int, c: int, r: int): bool =
    st.exists(o => o.kind == "grant" and o.src == s and o.ch == c and o.reader == r)

  // Rule 1: a source over its limit loses its own publications, the oldest of
  // the same channel first, then the oldest by arrival in its other channels.
  // `keep` is the object being stored, which is not a candidate. A key request
  // is paid by its reader and belongs to no channel of the payer, so it passes
  // c = 0 and every publication of the payer is ordered by arrival only.
  // Each round removes the oldest candidates. The store is within the limits
  // before the new object arrives, every publication has a size of at least
  // 1, and an object larger than SOURCE_BYTES is refused (rule 3), so
  // SOURCE_BYTES rounds always suffice; a source still over its limit after
  // them has the object refused (`ownOver` in `admit`).
  // The order of rule 1: the same channel first, then the others, each by arrival.
  pure def ruleOneKey(o: Obj, s: int, c: int): int =
    if (MUTANT == "evict_other" or (o.ch == c and o.src == s)) o.arr else o.arr + MAX_ARR
  // Mutant "evict_other" may remove publications of other sources first,
  // which do not lower the usage of `s`, so it gets MAX_ARR rounds.
  val OWN_ROUNDS = if (MUTANT == "evict_other") MAX_ARR else SOURCE_BYTES
  def evictOwn(st0: Set[Obj], m0: Bytes, s: int, c: int, keep: Obj): { st: Set[Obj], m: Bytes } =
    range(0, OWN_ROUNDS).foldl({ st: st0, m: m0 }, (e, i) =>
      if (usageOf(e.m).get(s) <= SOURCE_BYTES) e
      else {
        val acc = e.st
        // Mutant "evict_other": rule 1 takes the oldest publication of any
        // source; mutant "evict_grant": grants are evicted like publications.
        val cand = acc.filter(o => (o.kind == "pub" or (o.kind == "grant" and MUTANT == "evict_grant")) and o != keep
          and (o.src == s or MUTANT == "evict_other"))
        val first = cand.fold(2 * MAX_ARR + 1, (m, o) => if (ruleOneKey(o, s, c) < m) ruleOneKey(o, s, c) else m)
        val gone = cand.filter(o => ruleOneKey(o, s, c) == first)
        { st: acc.exclude(gone), m: without(e.m, gone) }
      })

  // Rule 4: the bus over its limit. The victim is the source that occupies
  // most (the smaller number on a tie); if it has only grants left, the next
  // source by volume that has publications and occupies more than the
  // average. With no victim the new object is refused. Returns the store and
  // whether the object was refused; the fair share check is `unfair`.
  // Every quantity below depends on the store only through the usage of each
  // source, `u`, computed once per round from the slots (every payer is a
  // device, so the total is the sum of `u`).
  pure def sumOf(u: int -> int, devs: Set[int]): int = devs.fold(0, (a, x) => a + u.get(x))
  // "Above the average" is u(s) * n > sum, with n the number of sources that
  // occupy anything. Both comparisons here are written as sums over the
  // sources (u(s) * n - sum is the sum of u(s) - u(x) over those sources), so
  // that the arithmetic stays linear: a product of two variables is hard for
  // the SMT solver.
  pure def avgExceeded(u: int -> int, s: int, devs: Set[int]): bool =
    devs.fold(0, (a, x) => if (u.get(x) > 0) a + u.get(s) - u.get(x) else a) > 0
  // The source that occupies most among `cands`, the smaller number on a tie;
  // 0 if `cands` is empty.
  pure def most(u: int -> int, cands: Set[int]): int = cands.fold(0, (b, x) =>
    if (b == 0 or u.get(x) > u.get(b) or (u.get(x) == u.get(b) and x < b)) x else b)
  def victim(st: Set[Obj], u: int -> int, keep: Obj): int = {
    val busiest = most(u, DEVS)
    // Mutant "unfair": the victim is the source of the oldest publication.
    val oldest = st.filter(o => o.kind == "pub" and o != keep)
      .fold({ s: 0, a: MAX_ARR + 1 }, (m, o) => if (o.arr < m.a) { s: o.src, a: o.arr } else m).s
    val withPubs = DEVS.filter(x => pubsOf(st, x).exclude(Set(keep)) != Set() and avgExceeded(u, x, DEVS))
    val second = most(u, withPubs)
    if (MUTANT == "unfair") oldest
    else if (pubsOf(st, busiest).exclude(Set(keep)) != Set()) busiest
    else second
  }
  // The victim is within its fair share: u(v) * n <= BUS_BYTES, as a sum.
  def unfairOf(u: int -> int, v: int, s: int): bool =
    v != s and DEVS.fold(0, (a, x) => if (u.get(x) > 0) a + u.get(v) else a) <= BUS_BYTES
  // Each round removes one publication of the victim; for the reason given at
  // rule 1, SOURCE_BYTES rounds always suffice, and a bus still over its limit
  // after them has the object refused.
  // The slots `m` follow the store through every round.
  def evictBus(st: Set[Obj], m: Bytes, keep: Obj): { st: Set[Obj], m: Bytes, refused: bool, unfair: bool } = {
    val r = evictBusRounds(st, m, keep)
    { ...r, refused: r.refused or sumOf(usageOf(r.m), DEVS) > BUS_BYTES }
  }
  def evictBusRounds(st: Set[Obj], m: Bytes, keep: Obj): { st: Set[Obj], m: Bytes, refused: bool, unfair: bool } =
    range(0, SOURCE_BYTES).foldl({ st: st, m: m, refused: false, unfair: false }, (acc, i) => {
      val u = usageOf(acc.m)
      if (acc.refused or sumOf(u, DEVS) <= BUS_BYTES) acc
      else {
        val v = victim(acc.st, u, keep)
        if (v == 0) { ...acc, refused: true }
        else {
          val old = pubsOf(acc.st, v).exclude(Set(keep))
            .fold({ a: MAX_ARR + 1 }, (mm, o) => if (o.arr < mm.a) { a: o.arr } else mm).a
          val gone = acc.st.filter(o => o.kind == "pub" and o.src == v and o.arr == old)
          { st: acc.st.exclude(gone), m: without(acc.m, gone), refused: false,
            unfair: acc.unfair or unfairOf(u, v, payer(keep)) }
        }
      }
    })

  // Store `o` under the quota rules, from the store `st` with the slots `m`.
  // Returns whether `o` was refused, the store and slots if it is accepted,
  // and the step properties violated on the way.
  def admit(st: Set[Obj], m: Bytes, o: Obj): { st: Set[Obj], bytes: Bytes, refused: bool, bad: Set[str], tags: Set[str] } = {
    val s = payer(o)
    val st1 = st.union(Set(o))
    // Rule 2: grants are never evicted for publications; a source whose
    // grants alone exceed its limit has the new grant refused.
    // Mutant "evict_grant": grants are evicted like publications.
    val grantsOver = o.kind == "grant" and grantsOf(st1, s).size() > SOURCE_BYTES and MUTANT != "evict_grant"
    val st2 = st1
    // Rule 1. Mutant "over_quota": the per-source limit is not enforced.
    val m1 = withObj(m, o)
    val e1 = if (MUTANT == "over_quota") { st: st2, m: m1 } else evictOwn(st2, m1, s, if (o.kind == "req") 0 else o.ch, o)
    val st3 = e1.st
    val ownOver = usageOf(e1.m).get(s) > SOURCE_BYTES and MUTANT != "over_quota"
    val ruleOneLost = st2.filter(x => not(st3.contains(x)))
    val b = evictBus(st3, e1.m, o)
    // Rule 3: an object larger than the limit by itself is refused.
    val tooBig = sizeOf(o) > SOURCE_BYTES and MUTANT != "over_quota"
    val refused = tooBig or grantsOver or ownOver or b.refused
    val lost = st.filter(x => not(b.st.contains(x)))
    {
      st: b.st,
      bytes: b.m,
      refused: refused,
      bad: (if (not(refused) and b.unfair) Set("fairShare") else Set())
        .union(if (not(refused) and ruleOneLost.exists(x => payer(x) != s)) Set("evictsOnlyOwn") else Set())
        .union(if (not(refused) and lost.exists(x => x.kind == "grant")) Set("grantsKept") else Set()),
      tags: (if (refused) Set("refused") else Set())
        .union(if (not(refused) and lost.exists(x => x.kind == "pub" and x.src == s)) Set("ownEvicted") else Set())
        .union(if (not(refused) and lost.exists(x => x.kind == "pub" and x.src != s)) Set("busEvicted") else Set())
        .union(if (b.refused and not(tooBig or grantsOver or ownOver)) Set("noVictim") else Set()),
    }
  }

  // Who receives a publication now: connected readers holding a grant of its
  // channel. Mutant "serve_ungranted": every connected device.
  def receivers(st: Set[Obj], p: Obj): Set[int] =
    relay.online.filter(r => r != p.src and (hasGrant(st, p.src, p.ch, r) or MUTANT == "serve_ungranted"))

  // Step properties of sending `p` to each of `rs` (R-REL-5, R-REL-6).
  def sendProblems(st: Set[Obj], p: Obj, rs: Set[int]): Set[str] =
    (if (rs.exists(r => not(hasGrant(st, p.src, p.ch, r)) and r != p.src)) Set("servedOnlyGranted") else Set())
      .union(if (rs.exists(r => relay.revoked.contains(r))) Set("nothingForRevoked") else Set())

  // ---------------------------------------------------------------- actions
  action commitWith(r2: Relay, extra: Set[str], tags: Set[str]): bool = all {
    relay' = r2, cps' = cps, root' = root, events' = events, nextJoin' = nextJoin,
    broken' = broken.union(extra), seen' = seen.union(tags),
  }

  action init = all {
    relay' = {
      served: true, cpNo: 1, cpMax: 1, revoked: Set(), rootGen: 1, tGen: 1, tNo: 1, store: Set(), bytes: NO_BYTES,
      hi: tuples(DEVS, CHANS).mapBy(k => 0), dep: tuples(DEVS, CHANS).mapBy(k => 0), arr: 0, joins: List(), online: Set(),
    },
    cps' = Map(1 -> Set()),
    root' = { gen: 1, tNo: 1, cpNo: 1, listed: true },
    events' = 0,
    nextJoin' = 0,
    broken' = Set(),
    seen' = Set(),
  }

  // A forged object is refused (R-REL-2). Mutant "no_verify": it is not.
  def verified(o: Obj): bool = o.ok or MUTANT == "no_verify"

  // A publication arrives. Depth 0 is forwarded and not stored (R-CH-12);
  // otherwise the relay keeps the N latest of the channel (R-REL-3) within the
  // quotas (R-REL-4).
  action recvPub(o: Obj): bool = {
    val r = relay
    val key = (o.src, o.ch)
    val hi = r.hi.get(key)
    // Mutant "accept_revoked": nothing is refused for a revoked source.
    val refusedFrom = r.revoked.contains(o.src) and MUTANT != "accept_revoked"
    val held = r.store.exists(x => x.kind == "pub" and x.src == o.src and x.ch == o.ch and x.no == o.no)
    val chanPubs = r.store.filter(x => x.kind == "pub" and x.src == o.src and x.ch == o.ch)
    val newer = chanPubs.filter(x => x.no > o.no).size()
    val newest = o.no > hi
    val depth = if (newest) o.depth else r.dep.get(key)
    // Mutant "store_depth0": publications of depth 0 are stored like others.
    val retain = (o.depth > 0 or MUTANT == "store_depth0") and (newest or newer < depth) and not(held)
    val o2 = { ...o, arr: r.arr + 1 }
    // Retention: the depth of the newest governs; older ones beyond it go.
    // Mutant "retain_all": nothing is deleted for depth.
    // R-CH-10: the depth of the newest governs; when it falls, older ones
    // beyond it go at once (depth 0 clears the channel). Mutant
    // "retain_all": nothing is deleted for depth.
    val trimmed = r.store.filter(x => MUTANT == "retain_all" or not(x.kind == "pub" and x.src == o.src and x.ch == o.ch
      and chanPubs.filter(y => y.no > x.no).size() + (if ((newest or retain) and o.no > x.no) 1 else 0) >= depth))
    val trimmedBytes = without(r.bytes, r.store.exclude(trimmed))
    // `admit` matters only when the publication is retained.
    val a0 = admit(trimmed, trimmedBytes, o2)
    val a = { ...a0, refused: retain and a0.refused, bad: if (retain) a0.bad else Set(), tags: if (retain) a0.tags else Set() }
    val stored = if (not(retain)) trimmed else if (a.refused) r.store else a.st
    val bytes2 = pick(not(retain), trimmedBytes, pick(a.refused, r.bytes, a.bytes))
    val rs = if (retain and a.refused) Set() else receivers(stored, o)
    all {
      verified(o), r.served, not(refusedFrom), o.kind == "pub", r.arr < MAX_ARR,
      commitWith(
        { ...r, store: stored, bytes: bytes2,
          arr: if (retain and not(a.refused)) r.arr + 1 else r.arr,
          hi: if (newest and not(a.refused)) r.hi.put(key, o.no) else r.hi,
          dep: if (newest and not(a.refused)) r.dep.put(key, o.depth) else r.dep },
        a.bad.union(sendProblems(stored, o, rs))
          .union(if (not(o.ok)) Set("onlyVerified") else Set()),
        a.tags.union(if (o.depth == 0 and rs != Set()) Set("forwarded0") else Set())
          .union(if (rs != Set()) Set("servedPub") else Set())),
    }
  }

  // A key grant arrives: the latest per (source, channel, reader), a higher
  // generation replaces it (R-REL-3). It is forwarded to the reader if
  // connected, together with the retained publications, and then a key
  // request it answers is deleted.
  action recvGrant(o: Obj): bool = {
    val r = relay
    val old = r.store.filter(x => x.kind == "grant" and x.src == o.src and x.ch == o.ch and x.reader == o.reader)
    // Mutant "grant_downgrade": a grant replaces the held one whatever its generation.
    val replaces = old.forall(x => o.gen > x.gen) or MUTANT == "grant_downgrade"
    val refusedFor = (r.revoked.contains(o.src) or r.revoked.contains(o.reader)) and MUTANT != "accept_revoked"
    val o2 = { ...o, arr: r.arr + 1 }
    val a = admit(r.store.exclude(old), without(r.bytes, old), o2)
    val online = r.online.contains(o.reader)
    val answered = r.store.filter(x => x.kind == "req" and x.reader == o.reader and x.src == o.src
      and x.ch == o.ch and x.no == o.no and o.no > 0)
    val st = if (a.refused) r.store else if (online) a.st.exclude(answered) else a.st
    val pubs = st.filter(x => x.kind == "pub" and x.src == o.src and x.ch == o.ch)
    all {
      verified(o), r.served, not(refusedFor), o.kind == "grant", o.src != o.reader, replaces,
      r.arr < MAX_ARR,
      commitWith({ ...r, store: st, bytes: pick(a.refused, r.bytes, pick(online, without(a.bytes, answered), a.bytes)),
                   arr: if (a.refused) r.arr else r.arr + 1 },
        a.bad.union(if (not(o.ok)) Set("onlyVerified") else Set())
          .union(if (online and not(a.refused) and r.revoked.contains(o.reader)) Set("nothingForRevoked") else Set())
          .union(if (not(a.refused) and old.exists(x => x.gen >= o.gen)) Set("latestGrant") else Set()),
        a.tags.union(if (old != Set() and not(a.refused)) Set("grantReplaced") else Set())
          .union(if (online and pubs != Set() and not(a.refused)) Set("servedPub") else Set())),
    }
  }

  // A key request (R-CH-18): one per (reader, channel), a newer one replaces
  // it; it is charged to the reader. Mutant "two_requests": it is added.
  action recvReq(o: Obj): bool = {
    val r = relay
    val old = if (MUTANT == "two_requests") Set()
              else r.store.filter(x => x.kind == "req" and x.reader == o.reader and x.src == o.src and x.ch == o.ch)
    val refusedFrom = (r.revoked.contains(o.reader) or r.revoked.contains(o.src)) and MUTANT != "accept_revoked"
    val o2 = { ...o, arr: r.arr + 1 }
    val a = admit(r.store.exclude(old), without(r.bytes, old), o2)
    all {
      verified(o), r.served, not(refusedFrom), o.kind == "req", o.src != o.reader, r.arr < MAX_ARR,
      commitWith({ ...r, store: if (a.refused) r.store else a.st,
                   bytes: pick(a.refused, r.bytes, a.bytes),
                   arr: if (a.refused) r.arr else r.arr + 1 },
        a.bad.union(if (not(o.ok)) Set("onlyVerified") else Set()), a.tags),
    }
  }

  // A call, reply or stream chunk: forwarded to a connected target, or
  // refused with code 5; never stored (R-REL-8). Mutant "store_call": stored.
  action recvCall(o: Obj): bool = {
    val r = relay
    all {
      verified(o), r.served, o.kind == "call", o.src != o.reader, r.arr < MAX_ARR,
      not(r.revoked.contains(o.src)) or MUTANT == "accept_revoked",
      commitWith({ ...r, store: if (MUTANT == "store_call") r.store.union(Set({ ...o, arr: r.arr + 1 })) else r.store,
                   arr: if (MUTANT == "store_call") r.arr + 1 else r.arr },
        if (r.online.contains(o.reader) and r.revoked.contains(o.reader)) Set("nothingForRevoked") else Set(),
        if (r.online.contains(o.reader)) Set("callForwarded") else Set("callRefused")),
    }
  }

  // A device connects after its hello and is served the grants made to it
  // and the publications of those channels; key requests the grants answer
  // are deleted. A revoked device gets no hello (R-REL-1, R-REL-6).
  action connect(d: int): bool = {
    val r = relay
    // Mutant "accept_revoked": a revoked device is connected.
    val mine = r.store.filter(x => x.kind == "grant" and x.reader == d)
    val chans = mine.map(g => (g.src, g.ch))
    val answered = r.store.filter(x => x.kind == "req" and x.reader == d
      and mine.exists(g => g.src == x.src and g.ch == x.ch and g.no == x.no and x.no > 0))
    val given = r.store.filter(x => x.kind == "pub" and (chans.contains((x.src, x.ch)) or MUTANT == "serve_ungranted"))
    all {
      r.served, not(r.online.contains(d)),
      not(r.revoked.contains(d)) or MUTANT == "accept_revoked",
      commitWith({ ...r, online: r.online.union(Set(d)), store: r.store.exclude(answered),
                   bytes: without(r.bytes, answered) },
        given.fold(Set(), (acc, p) => acc.union(
          if (p.src != d and not(hasGrant(r.store, p.src, p.ch, d))) Set("servedOnlyGranted") else Set()))
          .union(if (r.revoked.contains(d) and (given != Set() or mine != Set())) Set("nothingForRevoked") else Set()),
        (if (given.exists(p => p.src != d)) Set("servedPub") else Set())
          .union(if (answered != Set()) Set("requestAnswered") else Set())),
    }
  }

  action disconnect(d: int): bool = all {
    relay.online.contains(d),
    commitWith({ ...relay, online: relay.online.exclude(Set(d)) }, Set(), Set()),
  }

  // ---------------------------------------------------------- Root and events
  action eventWith(cps2: int -> Set[int], root2: { gen: int, tNo: int, cpNo: int, listed: bool }, nj: int): bool = all {
    events < MAX_EVENTS,
    relay' = relay, cps' = cps2, root' = root2, events' = events + 1, nextJoin' = nj,
    broken' = broken, seen' = seen,
  }

  // The Root revokes a device: a new checkpoint without it.
  action rootRevoke(d: int): bool = all {
    root.listed, not(cps.get(root.cpNo).contains(d)),
    eventWith(cps.put(root.cpNo + 1, cps.get(root.cpNo).union(Set(d))), { ...root, cpNo: root.cpNo + 1 }, nextJoin),
  }
  // The Root removes the relay from the checkpoint (B.10 rule 4).
  action rootUnlist = all {
    root.listed,
    eventWith(cps.put(root.cpNo + 1, cps.get(root.cpNo)), { ...root, cpNo: root.cpNo + 1, listed: false }, nextJoin),
  }
  // A root change and a new ticket.
  action rootChange = eventWith(cps, { ...root, gen: root.gen + 1, tNo: 0 }, nextJoin)
  action rootTicket = eventWith(cps, { ...root, tNo: root.tNo + 1 }, nextJoin)

  // The relay accepts a checkpoint only with a greater number (R-REL-7). The
  // relay's latest checkpoint is the only one whose relay list counts, so a
  // checkpoint after `rootUnlist` removes it. Mutant "cp_rollback": any number.
  action learnCp(n: int): bool = {
    val r = relay
    val unlisted = not(root.listed) and n == root.cpNo
    val rev = cps.get(n)
    // Mutant "keep_revoked": what is stored for a revoked device stays.
    val purge = r.store.filter(x => MUTANT == "keep_revoked"
      or not(rev.contains(x.src) or (x.kind != "pub" and rev.contains(x.reader))))
    val cleared = unlisted and MUTANT != "keep_unserved"
    val bytes2 = pick(cleared, NO_BYTES, without(r.bytes, r.store.exclude(purge)))
    all {
      cps.keys().contains(n), n > r.cpNo or (MUTANT == "cp_rollback" and n != r.cpNo),
      commitWith(
        if (cleared) { ...r, cpNo: n, cpMax: max2(r.cpMax, n), revoked: rev, served: false, store: Set(), bytes: bytes2, online: Set(), joins: List() }
        else if (unlisted) { ...r, cpNo: n, cpMax: max2(r.cpMax, n), revoked: rev, served: false, store: purge, bytes: bytes2 }
        else { ...r, cpNo: n, cpMax: max2(r.cpMax, n), revoked: rev, store: purge, bytes: bytes2, online: r.online.exclude(rev) },
        Set(),
        (if (purge != r.store) Set("revokedPurged") else Set())
          .union(if (unlisted) Set("unlisted") else Set())),
    }
  }

  // The relay learns a root change record.
  action learnRootChange = all {
    relay.rootGen < root.gen,
    commitWith({ ...relay, rootGen: root.gen }, Set(), Set()),
  }

  // A ticket (B.10 rules 2 and 3): accepted only with a greater pair and of
  // the generation of the latest root change record. Mutant "old_ticket": a
  // ticket of the old generation is accepted after a root change. A relay
  // that is no longer listed takes no tickets.
  action learnTicket(g: int, n: int): bool = {
    val r = relay
    val greater = g > r.tGen or (g == r.tGen and n > r.tNo)
    all {
      r.served, g <= root.gen, (g < root.gen or n <= root.tNo), n >= 1,
      greater, g == r.rootGen or MUTANT == "old_ticket",
      commitWith({ ...r, tGen: g, tNo: n },
        if (g != r.rootGen) Set("ticketOfCurrentRoot") else Set(),
        if (g > 1) Set("newGenTicket") else Set()),
    }
  }

  // A join request (R-JOIN-8): kept in a buffer of JOIN_MAX, the oldest
  // evicted on overflow. Mutant "join_unbounded": nothing is evicted;
  // mutant "join_drop_new": the new request is dropped instead.
  action recvJoin = {
    val j = nextJoin + 1
    val l = relay.joins.append(j)
    val l2 = if (l.length() <= JOIN_MAX or MUTANT == "join_unbounded") l
             else if (MUTANT == "join_drop_new") relay.joins
             else l.slice(1, l.length())
    all {
      events < MAX_EVENTS, relay.served,
      relay' = { ...relay, joins: l2 }, cps' = cps, root' = root, events' = events + 1, nextJoin' = j,
      broken' = broken.union(if (not(l2.indices().exists(i => l2.nth(i) == j))) Set("newestJoinKept") else Set()),
      seen' = seen.union(if (l.length() > JOIN_MAX) Set("joinEvicted") else Set()),
    }
  }

  // ------------------------------------------------------------------- step
  val PUBS: Set[Obj] = tuples(DEVS, CHANS, NOS, DEPTHS, SIZES, Set(false, true)).map(t =>
    { kind: "pub", src: t._1, ch: t._2, reader: 0, no: t._3, gen: 0, depth: t._4, size: t._5, ok: t._6, arr: 0 })
  val GRANTS: Set[Obj] = tuples(DEVS, CHANS, DEVS, 1.to(2), 0.to(1), Set(false, true)).map(t =>
    { kind: "grant", src: t._1, ch: t._2, reader: t._3, no: t._5, gen: t._4, depth: 0, size: 0, ok: t._6, arr: 0 })
  val REQS: Set[Obj] = tuples(DEVS, CHANS, DEVS, 1.to(1), Set(false, true)).map(t =>
    { kind: "req", src: t._1, ch: t._2, reader: t._3, no: t._4, gen: 0, depth: 0, size: 0, ok: t._5, arr: 0 })
  val CALLS: Set[Obj] = tuples(DEVS, DEVS).map(t =>
    { kind: "call", src: t._1, ch: 0, reader: t._2, no: 0, gen: 0, depth: 0, size: 0, ok: true, arr: 0 })

  action step = any {
    nondet o = PUBS.oneOf() recvPub(o),
    nondet o = GRANTS.oneOf() recvGrant(o),
    nondet o = REQS.oneOf() recvReq(o),
    nondet o = CALLS.oneOf() recvCall(o),
    nondet d = DEVS.oneOf() connect(d),
    nondet d = DEVS.oneOf() disconnect(d),
    nondet d = DEVS.oneOf() rootRevoke(d),
    rootUnlist,
    all { root.gen < 2, rootChange },
    all { root.tNo < 2, rootTicket },
    nondet n = cps.keys().oneOf() learnCp(n),
    learnRootChange,
    nondet g = 1.to(2).oneOf() nondet n = 1.to(2).oneOf() learnTicket(g, n),
    recvJoin,
  }

  // ------------------------------------------------------------- invariants
  // R-REL-2: nothing unverified is stored.
  val onlyVerified = relay.store.forall(o => o.ok) and not(broken.contains("onlyVerified"))
  // R-REL-8, R-CH-12: calls, replies, chunks and publications of depth 0 are
  // never stored.
  val nothingTransient = relay.store.forall(o => o.kind != "call" and not(o.kind == "pub" and o.depth == 0))
  // R-REL-5, L5: a publication goes only to a reader with a grant of its
  // channel (checked at every send).
  val servedOnlyGranted = not(broken.contains("servedOnlyGranted"))
  // R-REL-6, S5: nothing is stored from or for a revoked device, and nothing
  // is sent to it.
  val revokedPurged = relay.store.forall(o =>
    not(relay.revoked.contains(o.src)) and (o.kind == "pub" or not(relay.revoked.contains(o.reader))))
    and not(broken.contains("nothingForRevoked"))
  // R-REL-4: no source exceeds its limit, and the bus does not exceed its own.
  // The slots hold exactly the stored objects (each object is in the slot of
  // its key, with its size), and the usage they give is within the limits:
  // per source, and for the bus as the sum over the sources (every object
  // has exactly one payer, a device).
  def bytesMatch(r: Relay): bool = and {
    r.store.forall(o => o.kind == "pub" or ((o.kind == "grant" or o.kind == "req") and o.src != o.reader)),
    PSLOTS.forall(k => (r.bytes.pub.get(k) > 0) == r.store.exists(o => atP(o, k))),
    PSLOTS.forall(k => r.store.forall(o => atP(o, k) implies r.bytes.pub.get(k) == o.size)),
    GSLOTS.forall(k => (r.bytes.grant.get(k) == 1) == r.store.exists(o => atG(o, k))),
    GSLOTS.forall(k => (r.bytes.req.get(k) == 1) == r.store.exists(o => atQ(o, k))),
  }
  val quotasHold = and {
    bytesMatch(relay),
    DEVS.forall(d => bytesOf(relay.bytes, d) <= SOURCE_BYTES),
    sumOf(usageOf(relay.bytes), DEVS) <= BUS_BYTES,
  }
  // S14, B.10: a source within its fair share never loses data because of
  // another source (checked at every eviction).
  val fairShare = not(broken.contains("fairShare"))
  // R-REL-4, B.10 rule 1: a source over its own limit evicts only its own
  // publications (checked at every eviction).
  val evictsOnlyOwn = not(broken.contains("evictsOnlyOwn"))
  // B.10 rule 2: a grant is never evicted to make room.
  val grantsKept = not(broken.contains("grantsKept"))
  // R-REL-3: a grant replaces the held one only with a higher generation
  // (checked at every replacement).
  val latestGrant = not(broken.contains("latestGrant"))
  // R-REL-3: one grant per (source, channel, reader), one key request per
  // (reader, channel).
  val oneGrantOneRequest = relay.store.forall(a => relay.store.forall(b =>
    (a.kind == b.kind and a.kind != "pub" and a.src == b.src and a.ch == b.ch and a.reader == b.reader) implies a == b))
  // R-REL-3, R-CH-11: a channel keeps at most as many publications as the
  // depth of its newest.
  val retentionHolds = relay.hi.keys().forall(k => relay.hi.get(k) > 0 implies
    relay.store.filter(o => o.kind == "pub" and (o.src, o.ch) == k).size() <= relay.dep.get(k))
  // R-JOIN-8: the buffer is bounded and keeps the newest request.
  val joinsBounded = relay.joins.length() <= JOIN_MAX and not(broken.contains("newestJoinKept"))
  // B.10 rules 2 and 3: the ticket is of the latest root generation the relay
  // knows when accepted.
  val ticketOfCurrentRoot = not(broken.contains("ticketOfCurrentRoot"))
  // B.10 rule 4: a relay no longer listed stores nothing.
  val unlistedEmpty = not(relay.served) implies (relay.store == Set() and relay.joins == List())
  // R-REL-7: the relay's checkpoint only moves forward: its revoked set
  // contains that of the newest checkpoint it ever accepted.
  val checkpointForward = cps.get(relay.cpMax).subseteq(relay.revoked)

  val safety = onlyVerified and nothingTransient and servedOnlyGranted and revokedPurged and quotasHold
    and fairShare and evictsOnlyOwn and grantsKept and latestGrant and oneGrantOneRequest and retentionHolds and joinsBounded
    and ticketOfCurrentRoot and unlistedEmpty and checkpointForward

  // ------------------------------------------------- non-vacuity witnesses
  // Each witness is expected to be VIOLATED: the behaviour is reachable.
  val witnessOwnEvicted = not(seen.contains("ownEvicted"))
  val witnessBusEvicted = not(seen.contains("busEvicted"))
  val witnessNoVictim = not(seen.contains("noVictim"))
  val witnessGrantReplaced = not(seen.contains("grantReplaced"))
  val witnessServedPub = not(seen.contains("servedPub"))
  val witnessForwarded0 = not(seen.contains("forwarded0"))
  val witnessRequestAnswered = not(seen.contains("requestAnswered"))
  val witnessRevokedPurged = not(seen.contains("revokedPurged"))
  val witnessUnlisted = not(seen.contains("unlisted"))
  val witnessJoinEvicted = not(seen.contains("joinEvicted"))
  val witnessNewGenTicket = not(seen.contains("newGenTicket"))
}
