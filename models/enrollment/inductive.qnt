// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 HunterEwok
//
// Inductive invariant of the enrollment model (R-VER-3). Apalache proves three
// obligations, so that `safety` holds in every reachable state:
//   1. init implies IndInv               (--init=modelInit --invariant=IndInv, 0 steps)
//   2. IndInv and one step imply IndInv   (--init=indInit --invariant=IndInv, 1 step)
//   3. IndInv implies safety              (--init=indInit --invariant=modelSafety, 0 steps)
// with --step=modelStep, or with --step=stepX for each branch X of the step.
// indInit picks an arbitrary state of the bounded types that satisfies IndInv.
module inductive {
  const I_JOINERS: Set[str]
  const I_PRESENCE: Set[str]
  const I_ACCEPTORS: Set[str]
  const I_LIMIT: int
  const I_MAX_TID: int
  const I_MUTANT: str
  import enrollment(JOINERS = I_JOINERS, PRESENCE = I_PRESENCE, ACCEPTORS = I_ACCEPTORS, LIMIT = I_LIMIT,
                    MAX_TID = I_MAX_TID, MUTANT = I_MUTANT).* from "./enrollment"

  // ------------------------------------------------------------ bounded types
  val TIDS = 1.to(MAX_TID)
  val TRIES = 0.to(LIMIT)
  val SESSIONS: Set[Session] = tuples(TIDS, JOINERS.union(Set(ADV)), SIDES.union(Set(ADV)))
    .map(t => { tid: t._1, joiner: t._2, acceptor: t._3 })
  // What honest joiners send: their own payload, to the other end of a session.
  val SENT: Set[{ p: Payload, to: str }] = tuples(JOINERS, TIDS, SIDES.union(Set(ADV)))
    .map(t => { p: { key: t._1, presence: presOf(t._1), name: t._1, tid: t._2 }, to: t._3 })
  // Requests the Root keeps: the signature covers exactly the shown fields.
  val REQUESTS: Set[Request] = tuples(KEYS, PRES, NAMES, TIDS, SIDES)
    .map(t => { key: t._1, presence: t._2, name: t._3, tid: t._4,
                signed: { key: t._1, presence: t._2, name: t._3, tid: t._4 }, acceptor: t._5 })
  val PASSPORTS: Set[Passport] = tuples(KEYS, PRES, NAMES).map(t => { key: t._1, presence: t._2, name: t._3 })
  val TAGS = Set("advPaired", "tampered", "admitted", "direct")

  // ------------------------------------------------------------------- parts
  // Sessions are named uniquely by their transcript, and a joiner's latest
  // session is one it ran.
  pure def sessionsOk(t: int, ss: Set[Session], cu: str -> int): bool = and {
    0.to(MAX_TID).contains(t), ss.subseteq(SESSIONS), ss.forall(s => s.tid <= t),
    ss.forall(a => ss.forall(b => a.tid == b.tid implies a == b)),
    cu.keys() == JOINERS,
    JOINERS.forall(j => 0.to(t).contains(cu.get(j))
      and (cu.get(j) != 0 implies ss.exists(s => s.tid == cu.get(j) and s.joiner == j))),
  }

  // Every payload a joiner sent went to the other end of its own session; the
  // Root keeps only requests the joiner's signature covers; a joiner's
  // request carries its own presence key and name, and one through an honest
  // acceptor comes from a session of that joiner with that acceptor.
  pure def requestsOk(ss: Set[Session], se: Set[{ p: Payload, to: str }], ib: Set[Request]): bool = and {
    se.subseteq(SENT),
    se.forall(x => ss.contains({ tid: x.p.tid, joiner: x.p.key, acceptor: x.to })),
    ib.subseteq(REQUESTS),
    ib.forall(r => JOINERS.contains(r.key) implies (r.presence == presOf(r.key) and r.name == r.key)),
    ib.forall(r => (JOINERS.contains(r.key) and ACCEPTORS.contains(r.acceptor))
                     implies ss.contains({ tid: r.tid, joiner: r.key, acceptor: r.acceptor })),
  }

  pure def indInvOf(t: int, ss: Set[Session], cu: str -> int, jt: str -> int, at: str -> (str -> int),
                    se: Set[{ p: Payload, to: str }], ib: Set[Request], pp: Set[Passport], co: Set[str],
                    b: Set[str], sn: Set[str]): bool = and {
    sessionsOk(t, ss, cu),
    jt.keys() == JOINERS, JOINERS.forall(j => TRIES.contains(jt.get(j))),
    at.keys() == ACCEPTORS,
    ACCEPTORS.forall(a => at.get(a).keys() == JOINERS and JOINERS.forall(j => TRIES.contains(at.get(a).get(j)))),
    requestsOk(ss, se, ib),
    pp.subseteq(PASSPORTS), co.subseteq(KEYS), pp.forall(p => co.contains(p.key)),
    b == Set(),
    sn.subseteq(TAGS),
  }

  val IndInv = indInvOf(tid, sessions, current, joinerTries, acceptorTries, sent, inbox, passports, confirmed,
                        broken, seen)

  // The model's own initial state, step, and safety, and the branches of the
  // step one by one (together they are exactly step in enrollment.qnt).
  action modelInit = init
  action modelStep = step
  val modelSafety = safety
  action stepPairHonest = { nondet j = JOINERS.oneOf() nondet a = SIDES.oneOf() pairHonest(j, a) }
  action stepAdvJoiner = {
    nondet j = JOINERS.oneOf()
    nondet success = Set(false, true).oneOf()
    advPairJoiner(j, success)
  }
  action stepAdvAcceptor = {
    nondet j = JOINERS.oneOf()
    nondet a = ACCEPTORS.oneOf()
    nondet success = Set(false, true).oneOf()
    advPairAcceptor(a, j, success)
  }
  action stepSend = { nondet j = JOINERS.oneOf() joinerSend(j) }
  action stepAdmit = { nondet j = JOINERS.oneOf() all { inbox != Set(), nondet r = inbox.oneOf() rootAdmit(r, j) } }
  action stepRequest = all {
    sessions != Set(),
    nondet s = sessions.oneOf()
    nondet p = sent.map(x => x.p).union(advPayloads).oneOf()
    acceptorRequest(s.acceptor, s, p),
  }
  action stepBadRequest = {
    nondet key = KEYS.oneOf()
    nondet presence = PRES.oneOf()
    nondet name = NAMES.oneOf()
    nondet t = TIDS.oneOf()
    nondet p = advPayloads.oneOf()
    badRequest(key, presence, name, t, p)
  }
  // Only the mutant acceptor_issues enables badIssue. Without it the branch
  // has no transition at all: checks.json lists it under disabledSteps, and
  // the proof checks that no state of IndInv enables it.
  action stepBadIssue = { nondet key = KEYS.oneOf() badIssue(key) }

  // ------------------------------------------- an arbitrary state of IndInv
  action indInit = {
    nondet t = 0.to(MAX_TID).oneOf()
    nondet ss = SESSIONS.powerset().oneOf()
    nondet cu = setOfMaps(JOINERS, 0.to(MAX_TID)).oneOf()
    nondet jt = setOfMaps(JOINERS, TRIES).oneOf()
    nondet at = setOfMaps(ACCEPTORS, setOfMaps(JOINERS, TRIES)).oneOf()
    nondet se = SENT.powerset().oneOf()
    nondet ib = REQUESTS.powerset().oneOf()
    nondet pp = PASSPORTS.powerset().oneOf()
    nondet co = KEYS.powerset().oneOf()
    nondet sn = TAGS.powerset().oneOf()
    all {
      indInvOf(t, ss, cu, jt, at, se, ib, pp, co, Set(), sn),
      tid' = t, sessions' = ss, current' = cu, joinerTries' = jt, acceptorTries' = at, sent' = se, inbox' = ib,
      passports' = pp, confirmed' = co, broken' = Set(), seen' = sn,
    }
  }
}

module tiny_ind {
  import inductive(I_JOINERS = Set("j1"), I_PRESENCE = Set("j1"), I_ACCEPTORS = Set("h"), I_LIMIT = 2,
                   I_MAX_TID = 4, I_MUTANT = "none").*
}

module small_ind {
  import inductive(I_JOINERS = Set("j1", "j2"), I_PRESENCE = Set("j1"), I_ACCEPTORS = Set("h", "root"),
                   I_LIMIT = 2, I_MAX_TID = 6, I_MUTANT = "none").*
}
