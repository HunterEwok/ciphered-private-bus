// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 HunterEwok
//
// A state view of the enrollment model for exhaustive TLC runs (TLC option
// VIEW). TLC stores and expands one state per value of `viewOf`; module
// `bisim` below proves with Apalache that states with equal views are
// interchangeable for `safety`, so the reduced search finds a violation
// exactly when the full one does. Valid only for MUTANT = "none".
//
// The view drops only what can never influence `safety`:
// - the witness tags `seen`: no guard and no invariant of `safety` reads them;
// - join requests in `inbox` whose key is not an honest joiner's: the Root
//   admits a request only for the joiner in front of it (`r.key == j` in
//   rootAdmit), and no other action reads `inbox`, so such a request never
//   enables or changes a step. They are what makes the full search large:
//   the adversary and the compromised acceptor can file any subset of the
//   payloads signed by the adversary's key.
// Every other variable is kept as it is.
module viewdefs {
  const V_JOINERS: Set[str]

  type EPayload = { key: str, presence: str, name: str, tid: int }
  type ESession = { tid: int, joiner: str, acceptor: str }
  type ERequest = { key: str, presence: str, name: str, tid: int, signed: EPayload, acceptor: str }
  type EPassport = { key: str, presence: str, name: str }
  type View = {
    tid: int, sessions: Set[ESession], current: str -> int, sent: Set[{ p: EPayload, to: str }],
    inbox: Set[ERequest],
    passports: Set[EPassport], confirmed: Set[str], broken: Set[str],
  }

  // The requests the Root may still admit: those of an honest joiner's key.
  pure def liveInbox(ib: Set[ERequest]): Set[ERequest] = ib.filter(r => V_JOINERS.contains(r.key))

  pure def viewOf(t: int, ss: Set[ESession], cu: str -> int,
                  se: Set[{ p: EPayload, to: str }], ib: Set[ERequest], pp: Set[EPassport], co: Set[str],
                  b: Set[str]): View =
    { tid: t, sessions: ss, current: cu, sent: se, inbox: liveInbox(ib),
      passports: pp, confirmed: co, broken: b }
}

// The TLC instance: the constants of `tiny` in instances.qnt.
module tiny_view {
  import enrollment(JOINERS = Set("j1"), PRESENCE = Set("j1"), ACCEPTORS = Set("h"), MAX_TID = 4,
                    MUTANT = "none").* from "./enrollment"
  import viewdefs(V_JOINERS = Set("j1")).*
  val safetyView = viewOf(tid, sessions, current, sent, inbox, passports, confirmed,
                          broken)
}

// Proof that the view is exact for `safety` (R-VER-3), checked by Apalache on
// two copies A and B of the model:
//   O1. init implies Struct                             (initStruct, 0 steps, invariant structA)
//   O2. Struct, safety and one step imply Struct         (initSafe, stepX, 1 step, invariant structA)
//   O3. two Struct states with equal views agree on safety (initPair, 0 steps, invariant sameSafety)
//   O4. for two Struct states with equal views, A safe, every step of A is
//       answered by B with no step or one step, and the views are equal again
//       (initPair, matchX, 2 steps, invariant matched).
// Struct is the bounded types of the variables and unique transcripts; it
// does not include `safety` and leaves `broken` arbitrary. Why this suffices: take a shortest behaviour
// of the model that ends in a state violating `safety`. Every earlier state
// is safe, so by O1 and O2 it satisfies Struct. TLC with the view reaches a
// state of the same view as the initial state (it is the initial state). If
// TLC holds a state r with the view of the i-th state s, then r is reachable
// and safe (otherwise TLC has already reported a violation), so r satisfies
// Struct, and by O4 the step from s to the next state is answered from r by a
// state TLC also generates, with the same view as the next state. By
// induction TLC generates a state with the view of the last state, which
// violates `safety` by O3.
//
// B's answer: no step when A's step left the views equal (A filed a request
// of a key that is not an honest joiner's, or only added a witness tag);
// otherwise the same action with the same parameters. Every guard of that
// action reads only variables the view keeps (rootAdmit reads `inbox` only
// for its own request, whose key is the joiner's), so it holds in B, and the
// action changes the kept variables of A and B in the same way.
module bisim {
  const P_JOINERS: Set[str]
  const P_PRESENCE: Set[str]
  const P_ACCEPTORS: Set[str]
  const P_MAX_TID: int
  import enrollment(JOINERS = P_JOINERS, PRESENCE = P_PRESENCE, ACCEPTORS = P_ACCEPTORS,
                    MAX_TID = P_MAX_TID, MUTANT = "none") as A from "./enrollment"
  import enrollment(JOINERS = P_JOINERS, PRESENCE = P_PRESENCE, ACCEPTORS = P_ACCEPTORS,
                    MAX_TID = P_MAX_TID, MUTANT = "none") as B from "./enrollment"
  import viewdefs(V_JOINERS = P_JOINERS).*

  // ------------------------------------------------------------ bounded types
  pure val ADV = "adv"
  pure val BAD = "c"
  pure val SIDES = P_ACCEPTORS.union(Set(BAD))
  pure val KEYS = P_JOINERS.union(Set(ADV))
  pure val PRES = P_JOINERS.union(Set(ADV, "none"))
  pure val NAMES = KEYS
  pure def presOf(j: str): str = if (P_PRESENCE.contains(j)) j else "none"
  pure val TIDS = 1.to(P_MAX_TID)
  pure val SESSIONS: Set[ESession] = tuples(TIDS, KEYS, SIDES.union(Set(ADV)))
    .map(t => { tid: t._1, joiner: t._2, acceptor: t._3 })
  pure val SENT: Set[{ p: EPayload, to: str }] = tuples(P_JOINERS, TIDS, SIDES.union(Set(ADV)))
    .map(t => { p: { key: t._1, presence: presOf(t._1), name: t._1, tid: t._2 }, to: t._3 })
  pure val REQUESTS: Set[ERequest] = tuples(KEYS, PRES, NAMES, TIDS, SIDES)
    .map(t => { key: t._1, presence: t._2, name: t._3, tid: t._4,
                signed: { key: t._1, presence: t._2, name: t._3, tid: t._4 }, acceptor: t._5 })
  pure val PASSPORTS: Set[EPassport] = tuples(KEYS, PRES, NAMES).map(t => { key: t._1, presence: t._2, name: t._3 })
  pure val TAGS = Set("advPaired", "tampered", "admitted", "direct")
  pure val BROKEN = Set("intended", "asSigned", "bound")

  // ------------------------------------------------------------------ Struct
  // The values every reachable state takes: the sessions, sent payloads and kept requests the actions can build, and
  // sessions named uniquely by their transcript (which makes the other end of
  // a joiner's latest session, chosen in joinerSend, unique).
  pure def structOf(t: int, ss: Set[ESession], cu: str -> int,
                    se: Set[{ p: EPayload, to: str }], ib: Set[ERequest], pp: Set[EPassport], co: Set[str],
                    b: Set[str], sn: Set[str]): bool = and {
    0.to(P_MAX_TID).contains(t), ss.subseteq(SESSIONS), ss.forall(s => s.tid <= t),
    ss.forall(x => ss.forall(y => x.tid == y.tid implies x == y)),
    cu.keys() == P_JOINERS, P_JOINERS.forall(j => 0.to(P_MAX_TID).contains(cu.get(j))),
    se.subseteq(SENT), ib.subseteq(REQUESTS), pp.subseteq(PASSPORTS), co.subseteq(KEYS),
    b.subseteq(BROKEN), sn.subseteq(TAGS),
  }

  val structA = structOf(A::tid, A::sessions, A::current, A::sent, A::inbox,
                         A::passports, A::confirmed, A::broken, A::seen)
  val structB = structOf(B::tid, B::sessions, B::current, B::sent, B::inbox,
                         B::passports, B::confirmed, B::broken, B::seen)
  val viewA = viewOf(A::tid, A::sessions, A::current, A::sent, A::inbox,
                     A::passports, A::confirmed, A::broken)
  val viewB = viewOf(B::tid, B::sessions, B::current, B::sent, B::inbox,
                     B::passports, B::confirmed, B::broken)

  // ------------------------------------------------------------- bookkeeping
  pure val NO_PAYLOAD: EPayload = { key: "", presence: "", name: "", tid: 0 }
  pure val NO_SESSION: ESession = { tid: 0, joiner: "", acceptor: "" }
  pure val NO_REQUEST: ERequest = { key: "", presence: "", name: "", tid: 0, signed: NO_PAYLOAD, acceptor: "" }
  type Move = { kind: str, j: str, a: str, s: ESession, p: EPayload, r: ERequest, key: str,
                presence: str, name: str, t: int }
  pure val NO_MOVE: Move = { kind: "", j: "", a: "", s: NO_SESSION, p: NO_PAYLOAD, r: NO_REQUEST,
                             key: "", presence: "", name: "", t: 0 }
  var stage: int      // 0: before A's step, 1: after it, 2: after B's answer
  var mv: Move        // A's step, as B needs it
  var matchOk: bool   // B's answer was enabled

  action aStay = all {
    A::tid' = A::tid, A::sessions' = A::sessions, A::current' = A::current, A::sent' = A::sent,
    A::inbox' = A::inbox, A::passports' = A::passports,
    A::confirmed' = A::confirmed, A::broken' = A::broken, A::seen' = A::seen,
  }
  action bStay = all {
    B::tid' = B::tid, B::sessions' = B::sessions, B::current' = B::current, B::sent' = B::sent,
    B::inbox' = B::inbox, B::passports' = B::passports,
    B::confirmed' = B::confirmed, B::broken' = B::broken, B::seen' = B::seen,
  }

  // --------------------------------------------- an arbitrary state of Struct
  // Every variable is drawn from its whole bounded type (powersets and maps
  // into the bounded ranges, as indInit in inductive.qnt draws them) and then
  // filtered by Struct, so the draws reach every state of Struct.
  action drawA = {
    nondet t = 0.to(P_MAX_TID).oneOf()
    nondet ss = SESSIONS.powerset().oneOf()
    nondet cu = setOfMaps(P_JOINERS, 0.to(P_MAX_TID)).oneOf()
    nondet se = SENT.powerset().oneOf()
    nondet ib = REQUESTS.powerset().oneOf()
    nondet pp = PASSPORTS.powerset().oneOf()
    nondet co = KEYS.powerset().oneOf()
    nondet b = BROKEN.powerset().oneOf()
    nondet sn = TAGS.powerset().oneOf()
    all {
      structOf(t, ss, cu, se, ib, pp, co, b, sn),
      A::tid' = t, A::sessions' = ss, A::current' = cu,
      A::sent' = se, A::inbox' = ib, A::passports' = pp, A::confirmed' = co, A::broken' = b, A::seen' = sn,
    }
  }

  action drawB = {
    nondet t = 0.to(P_MAX_TID).oneOf()
    nondet ss = SESSIONS.powerset().oneOf()
    nondet cu = setOfMaps(P_JOINERS, 0.to(P_MAX_TID)).oneOf()
    nondet se = SENT.powerset().oneOf()
    nondet ib = REQUESTS.powerset().oneOf()
    nondet pp = PASSPORTS.powerset().oneOf()
    nondet co = KEYS.powerset().oneOf()
    nondet b = BROKEN.powerset().oneOf()
    nondet sn = TAGS.powerset().oneOf()
    all {
      structOf(t, ss, cu, se, ib, pp, co, b, sn),
      B::tid' = t, B::sessions' = ss, B::current' = cu,
      B::sent' = se, B::inbox' = ib, B::passports' = pp, B::confirmed' = co, B::broken' = b, B::seen' = sn,
    }
  }

  // ----------------------------------------------------------- initial states
  action initStruct = all { A::init, B::init, stage' = 0, mv' = NO_MOVE, matchOk' = true }
  action initSafe = all { drawA, B::init, stage' = 0, mv' = NO_MOVE, matchOk' = true }
  action initPair = all { drawA, drawB, stage' = 0, mv' = NO_MOVE, matchOk' = true }

  // Names run-inductive.ps1 uses for its first, cheap check (Apalache download).
  action modelInit = initStruct
  action modelStep = stepSend
  val IndInv = structA

  val sameSafety = (viewA == viewB) implies (A::safety iff B::safety)
  val matched = stage != 2 or (matchOk and viewA == viewB)
  // Non-vacuity: expected to be violated (a pair with equal views exists; B answers).
  val witnessPair = viewA != viewB
  val witnessAnswered = stage != 2

  // ------------------------------------------------- A's step, branch by branch
  // The branches of `step` in enrollment.qnt as inductive.qnt splits them
  // (badIssue is disabled for MUTANT = "none"). O2 runs stepX from initSafe;
  // O4 runs matchX from initPair.
  action pre = all { stage == 0, A::safety }
  action stepPairHonest = all { pre, bStay, stage' = 1, matchOk' = true,
    nondet j = P_JOINERS.oneOf() nondet a = SIDES.oneOf()
    all { A::pairHonest(j, a), mv' = { ...NO_MOVE, kind: "pairHonest", j: j, a: a } } }
  action stepAdvJoiner = all { pre, bStay, stage' = 1, matchOk' = true,
    nondet j = P_JOINERS.oneOf()
    all { A::advPairJoiner(j), mv' = { ...NO_MOVE, kind: "advJoiner", j: j } } }
  action stepAdvAcceptor = all { pre, bStay, stage' = 1, matchOk' = true,
    nondet a = P_ACCEPTORS.oneOf()
    all { A::advPairAcceptor(a), mv' = { ...NO_MOVE, kind: "advAcceptor", a: a } } }
  action stepSend = all { pre, bStay, stage' = 1, matchOk' = true,
    nondet j = P_JOINERS.oneOf()
    all { A::joinerSend(j), mv' = { ...NO_MOVE, kind: "send", j: j } } }
  action stepAdmit = all { pre, bStay, stage' = 1, matchOk' = true,
    nondet j = P_JOINERS.oneOf()
    all { A::inbox != Set(), nondet r = A::inbox.oneOf()
          all { A::rootAdmit(r, j), mv' = { ...NO_MOVE, kind: "admit", j: j, r: r } } } }
  action stepRequest = all { pre, bStay, stage' = 1, matchOk' = true,
    A::sessions != Set(),
    nondet s = A::sessions.oneOf()
    nondet p = A::sent.map(x => x.p).union(A::advPayloads).oneOf()
    all { A::acceptorRequest(s.acceptor, s, p), mv' = { ...NO_MOVE, kind: "request", s: s, p: p } } }
  action stepBadRequest = all { pre, bStay, stage' = 1, matchOk' = true,
    nondet key = KEYS.oneOf() nondet presence = PRES.oneOf() nondet name = NAMES.oneOf()
    nondet t = TIDS.oneOf() nondet p = A::advPayloads.oneOf()
    all { A::badRequest(key, presence, name, t, p),
          mv' = { ...NO_MOVE, kind: "badRequest", key: key, presence: presence, name: name, t: t, p: p } } }

  // --------------------------------------------------------------- B's answer
  // B does nothing when the views already agree; otherwise it takes the same
  // action as A with the same parameters. Each guard copies the guard of that
  // action in enrollment.qnt under MUTANT = "none", so that B's step is taken
  // exactly when the guard holds; matchOk records it.
  action bNone = all { bStay, matchOk' = false }
  action answer = {
    if (mv.kind == "pairHonest")
      if (B::tid < P_MAX_TID)
        all { B::pairHonest(mv.j, mv.a), matchOk' = true }
      else bNone
    else if (mv.kind == "advJoiner")
      if (B::tid < P_MAX_TID)
        all { B::advPairJoiner(mv.j), matchOk' = true }
      else bNone
    else if (mv.kind == "advAcceptor")
      if (B::tid < P_MAX_TID)
        all { B::advPairAcceptor(mv.a), matchOk' = true }
      else bNone
    else if (mv.kind == "send")
      // joinerSend picks the other end of the session named by the joiner's
      // latest transcript; Struct makes transcripts unique, so the choice is
      // the same in A and B (their sessions are equal).
      if (B::current.get(mv.j) != 0)
        all { B::joinerSend(mv.j), matchOk' = true }
      else bNone
    else if (mv.kind == "admit")
      if (B::inbox.contains(mv.r) and B::current.get(mv.j) != 0 and B::sigOk(mv.r) and mv.r.key == mv.j)
        all { B::rootAdmit(mv.r, mv.j), matchOk' = true }
      else bNone
    else if (mv.kind == "request")
      if (P_ACCEPTORS.contains(mv.s.acceptor) and B::sessions.contains(mv.s)
          and (B::sent.contains({ p: mv.p, to: mv.s.acceptor })
               or (mv.s.joiner == ADV and B::advPayloads.contains(mv.p)))
          and mv.p.tid == mv.s.tid)
        all { B::acceptorRequest(mv.s.acceptor, mv.s, mv.p), matchOk' = true }
      else bNone
    else if (mv.kind == "badRequest")
      if (B::advPayloads.contains(mv.p))
        all { B::badRequest(mv.key, mv.presence, mv.name, mv.t, mv.p), matchOk' = true }
      else bNone
    else bNone
  }
  action respond = all { stage == 1, aStay, stage' = 2, mv' = mv,
    if (viewA == viewB) all { bStay, matchOk' = true } else answer }
  action matchPairHonest = any { all { viewA == viewB, stepPairHonest }, respond }
  action matchAdvJoiner = any { all { viewA == viewB, stepAdvJoiner }, respond }
  action matchAdvAcceptor = any { all { viewA == viewB, stepAdvAcceptor }, respond }
  action matchSend = any { all { viewA == viewB, stepSend }, respond }
  action matchAdmit = any { all { viewA == viewB, stepAdmit }, respond }
  action matchRequest = any { all { viewA == viewB, stepRequest }, respond }
  action matchBadRequest = any { all { viewA == viewB, stepBadRequest }, respond }
}

// The proof instance: the constants of `tiny` in instances.qnt.
module tiny_bisim {
  import bisim(P_JOINERS = Set("j1"), P_PRESENCE = Set("j1"), P_ACCEPTORS = Set("h"), P_MAX_TID = 4).*
}
