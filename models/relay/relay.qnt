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
  pure def usage(st: Set[Obj], s: int): int = st.filter(o => payer(o) == s).fold(0, (a, o) => a + sizeOf(o))
  pure def total(st: Set[Obj]): int = st.fold(0, (a, o) => a + sizeOf(o))
  pure def pubsOf(st: Set[Obj], s: int): Set[Obj] = st.filter(o => o.kind == "pub" and o.src == s)
  pure def grantsOf(st: Set[Obj], s: int): Set[Obj] = st.filter(o => o.kind == "grant" and o.src == s)
  pure def hasGrant(st: Set[Obj], s: int, c: int, r: int): bool =
    st.exists(o => o.kind == "grant" and o.src == s and o.ch == c and o.reader == r)

  // Rule 1: a source over its limit loses its own publications, the oldest of
  // the same channel first, then the oldest by arrival in its other channels.
  // `keep` is the object being stored, which is not a candidate.
  def evictOwn(st: Set[Obj], s: int, c: int, keep: Obj): Set[Obj] =
    range(1, 2 * MAX_ARR + 2).foldl(st, (acc, key) =>
      if (usage(acc, s) <= SOURCE_BYTES) acc
      else {
        // Mutant "evict_other": rule 1 takes the oldest publication of any
        // source; mutant "evict_grant": grants are evicted like publications.
        val cand = acc.filter(o => (o.kind == "pub" or (o.kind == "grant" and MUTANT == "evict_grant")) and o != keep
          and (o.src == s or MUTANT == "evict_other")
          and (if (MUTANT == "evict_other" or (o.ch == c and o.src == s)) o.arr else o.arr + MAX_ARR) == key)
        acc.exclude(cand)
      })

  // Rule 4: the bus over its limit. The victim is the source that occupies
  // most (the smaller number on a tie); if it has only grants left, the next
  // source by volume that has publications and occupies more than the
  // average. With no victim the new object is refused. Returns the store and
  // whether the object was refused; the fair share check is `unfair`.
  pure def avgExceeded(st: Set[Obj], s: int, devs: Set[int]): bool = {
    val n = devs.filter(x => usage(st, x) > 0).size()
    usage(st, s) * n > total(st)
  }
  // The source that occupies most among `cands`, the smaller number on a tie;
  // 0 if `cands` is empty.
  pure def most(st: Set[Obj], cands: Set[int]): int = cands.fold(0, (b, x) =>
    if (b == 0 or usage(st, x) > usage(st, b) or (usage(st, x) == usage(st, b) and x < b)) x else b)
  def victim(st: Set[Obj], keep: Obj): int = {
    val busiest = most(st, DEVS)
    // Mutant "unfair": the victim is the source of the oldest publication.
    val oldest = st.filter(o => o.kind == "pub" and o != keep)
      .fold({ s: 0, a: MAX_ARR + 1 }, (m, o) => if (o.arr < m.a) { s: o.src, a: o.arr } else m).s
    val withPubs = DEVS.filter(x => pubsOf(st, x).exclude(Set(keep)) != Set() and avgExceeded(st, x, DEVS))
    val second = most(st, withPubs)
    if (MUTANT == "unfair") oldest
    else if (pubsOf(st, busiest).exclude(Set(keep)) != Set()) busiest
    else second
  }
  def unfairOf(st: Set[Obj], v: int, s: int): bool = {
    val n = DEVS.filter(x => usage(st, x) > 0).size()
    v != s and usage(st, v) * n <= BUS_BYTES
  }
  def evictBus(st: Set[Obj], keep: Obj): { st: Set[Obj], refused: bool, unfair: bool } =
    range(0, MAX_ARR + 1).foldl({ st: st, refused: false, unfair: false }, (acc, i) =>
      if (acc.refused or total(acc.st) <= BUS_BYTES) acc
      else {
        val v = victim(acc.st, keep)
        if (v == 0) { ...acc, refused: true }
        else {
          val old = pubsOf(acc.st, v).exclude(Set(keep))
            .fold({ a: MAX_ARR + 1 }, (m, o) => if (o.arr < m.a) { a: o.arr } else m).a
          { st: acc.st.filter(o => not(o.kind == "pub" and o.src == v and o.arr == old)),
            refused: false, unfair: acc.unfair or unfairOf(acc.st, v, payer(keep)) }
        }
      })

  // Store `o` under the quota rules. Returns the new store, whether `o` was
  // refused, and the step properties violated on the way.
  def admit(st: Set[Obj], o: Obj): { st: Set[Obj], refused: bool, bad: Set[str], tags: Set[str] } = {
    val s = payer(o)
    val st1 = st.union(Set(o))
    // Rule 2: grants are never evicted for publications; a source whose
    // grants alone exceed its limit has the new grant refused.
    // Mutant "evict_grant": grants are evicted like publications.
    val grantsOver = o.kind == "grant" and grantsOf(st1, s).size() > SOURCE_BYTES and MUTANT != "evict_grant"
    val st2 = st1
    // Rule 1. Mutant "over_quota": the per-source limit is not enforced.
    val st3 = if (MUTANT == "over_quota") st2 else evictOwn(st2, s, o.ch, o)
    val ownOver = usage(st3, s) > SOURCE_BYTES and MUTANT != "over_quota"
    val ruleOneLost = st2.filter(x => not(st3.contains(x)))
    val b = evictBus(st3, o)
    // Rule 3: an object larger than the limit by itself is refused.
    val tooBig = sizeOf(o) > SOURCE_BYTES and MUTANT != "over_quota"
    val refused = tooBig or grantsOver or ownOver or b.refused
    val lost = st.filter(x => not(b.st.contains(x)))
    {
      st: if (refused) st else b.st,
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
      served: true, cpNo: 1, cpMax: 1, revoked: Set(), rootGen: 1, tGen: 1, tNo: 1, store: Set(),
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
    val a = if (retain) admit(trimmed, o2) else { st: trimmed, refused: false, bad: Set(), tags: Set() }
    val stored = if (a.refused) r.store else a.st
    val rs = if (retain and a.refused) Set() else receivers(stored, o)
    all {
      verified(o), r.served, not(refusedFrom), o.kind == "pub", r.arr < MAX_ARR,
      commitWith(
        { ...r, store: stored, arr: if (retain and not(a.refused)) r.arr + 1 else r.arr,
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
    val a = admit(r.store.exclude(old), o2)
    val online = r.online.contains(o.reader)
    val answered = r.store.filter(x => x.kind == "req" and x.reader == o.reader and x.src == o.src
      and x.ch == o.ch and x.no == o.no and o.no > 0)
    val st = if (a.refused) r.store else if (online) a.st.exclude(answered) else a.st
    val pubs = st.filter(x => x.kind == "pub" and x.src == o.src and x.ch == o.ch)
    all {
      verified(o), r.served, not(refusedFor), o.kind == "grant", o.src != o.reader, replaces,
      r.arr < MAX_ARR,
      commitWith({ ...r, store: st, arr: if (a.refused) r.arr else r.arr + 1 },
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
    val a = admit(r.store.exclude(old), o2)
    all {
      verified(o), r.served, not(refusedFrom), o.kind == "req", o.src != o.reader, r.arr < MAX_ARR,
      commitWith({ ...r, store: if (a.refused) r.store else a.st, arr: if (a.refused) r.arr else r.arr + 1 },
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
      commitWith({ ...r, online: r.online.union(Set(d)), store: r.store.exclude(answered) },
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
    all {
      cps.keys().contains(n), n > r.cpNo or (MUTANT == "cp_rollback" and n != r.cpNo),
      commitWith(
        if (unlisted and MUTANT != "keep_unserved") { ...r, cpNo: n, cpMax: max2(r.cpMax, n), revoked: rev, served: false, store: Set(), online: Set() }
        else if (unlisted) { ...r, cpNo: n, cpMax: max2(r.cpMax, n), revoked: rev, served: false, store: purge }
        else { ...r, cpNo: n, cpMax: max2(r.cpMax, n), revoked: rev, store: purge, online: r.online.exclude(rev) },
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
  // ticket of the old generation is accepted after a root change.
  action learnTicket(g: int, n: int): bool = {
    val r = relay
    val greater = g > r.tGen or (g == r.tGen and n > r.tNo)
    all {
      g <= root.gen, (g < root.gen or n <= root.tNo), n >= 1,
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
  val quotasHold = DEVS.forall(s => usage(relay.store, s) <= SOURCE_BYTES) and total(relay.store) <= BUS_BYTES
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
  val unlistedEmpty = not(relay.served) implies relay.store == Set()
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
