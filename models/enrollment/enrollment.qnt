// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 HunterEwok
//
// Device enrollment of Ciphered Private Bus (verification level V2).
//
// Scope: pairing of a joiner with an acceptor or with the Root by a code,
// with attempts counted on both sides; the joiner's signed payload; the join
// request; a compromised acceptor and a network adversary that pairs by
// guessing the code and relays payloads between sessions; and the Root's
// admission after the owner compares the key fingerprint. Requirements:
// R-JOIN-3..7, R-JOIN-9; property S4.
//
// Abstractions:
// - CPace, signatures, and sealing are perfect (Tamarin covers them). A
//   pairing session is named by its transcript (`tid`); only its two ends
//   know what was sent in it. A run against a side that does not know the
//   code is one password guess, and any such guess may succeed: the model
//   bounds the number of guesses, not their probability.
// - The fingerprint shows 64 bits of the key hash (R-JOIN-5); equal
//   fingerprints mean equal keys.
// - The owner enrolls the honest joiner in front of them and confirms a
//   request only after comparing fingerprints (R-JOIN-7). The joiner's
//   later check of the bus fingerprint is not modelled.
// - A compromised acceptor is a member; with the adversary it knows every
//   payload sent to either of them and may put anything in a request. The
//   Root itself is honest. Bus identity and the root key the joiner learns
//   (R-JOIN-2) belong to Tamarin and the membership model.
module enrollment {
  // ---------------------------------------------------------------- parameters
  const JOINERS: Set[str]          // honest joiners; a joiner's device key is named by the joiner
  const PRESENCE: Set[str]         // joiners that have a user-presence key
  const ACCEPTORS: Set[str]        // honest acceptors; "root" pairs directly (R-JOIN-9)
  const LIMIT: int                 // attempts per code on each side (R-JOIN-3)
  const MAX_TID: int               // pairing sessions in a run
  const MUTANT: str                // "none", or the name of a deliberate defect (R-VER-2)

  // --------------------------------------------------------------------- types
  val ADV = "adv"                  // the network adversary, and its device key
  val BAD = "c"                    // the compromised acceptor
  val SIDES = ACCEPTORS.union(Set(BAD))
  val KEYS = JOINERS.union(Set(ADV))
  // A presence key is named by its owner's device; "none" for no key.
  val PRES = JOINERS.union(Set(ADV, "none"))
  val NAMES = KEYS
  pure def presOf(j: str): str = if (PRESENCE.contains(j)) j else "none"

  // What a joiner signs: its key, presence key, name, and the transcript of
  // the pairing session (R-JOIN-4).
  type Payload = { key: str, presence: str, name: str, tid: int }
  type Session = { tid: int, joiner: str, acceptor: str }
  // A join request: the fields the Root shows and admits, and the payload
  // the joiner's signature actually covers.
  type Request = { key: str, presence: str, name: str, tid: int, signed: Payload, acceptor: str }
  type Passport = { key: str, presence: str, name: str }

  // ----------------------------------------------------------------- variables
  var tid: int                      // sessions so far
  var sessions: Set[Session]        // ghost: every pairing session that completed
  var current: str -> int           // each joiner's latest session, 0 for none
  var joinerTries: str -> int       // attempts the joiner made with its code
  var acceptorTries: str -> (str -> int)  // attempts an honest acceptor made with each joiner's code
  var sent: Set[{ p: Payload, to: str }]  // payloads sent inside sessions, with the receiving side
  var inbox: Set[Request]           // join requests that reached the Root
  var passports: Set[Passport]      // passports the Root issued
  var confirmed: Set[str]           // ghost: keys the owner confirmed
  var broken: Set[str]
  var seen: Set[str]

  // ------------------------------------------------------------------- helpers
  // Payloads the adversary and the compromised acceptor can provide: every
  // payload sent to either of them, and any payload signed by its own key.
  def advPayloads: Set[Payload] =
    sent.filter(s => s.to == ADV or s.to == BAD).map(s => s.p)
      .union(tuples(PRES, NAMES, 1.to(MAX_TID)).map(t => { key: ADV, presence: t._1, name: t._2, tid: t._3 }))

  // The joiner's signature verifies over the request (R-JOIN-4).
  pure def sigOk(r: Request): bool =
    r.signed.key == r.key and r.signed.tid == r.tid
      and ((r.signed.presence == r.presence and r.signed.name == r.name) or MUTANT == "sig_key_only")

  action commit(t: int, ss: Set[Session], cu: str -> int, jt: str -> int, at: str -> (str -> int),
                se: Set[{ p: Payload, to: str }], ib: Set[Request], pp: Set[Passport], co: Set[str],
                extra: Set[str], tags: Set[str]): bool = all {
    tid' = t, sessions' = ss, current' = cu, joinerTries' = jt, acceptorTries' = at, sent' = se, inbox' = ib,
    passports' = pp, confirmed' = co, broken' = broken.union(extra), seen' = seen.union(tags),
  }

  // -------------------------------------------------------------- initial state
  action init = all {
    tid' = 0,
    sessions' = Set(),
    current' = JOINERS.mapBy(j => 0),
    joinerTries' = JOINERS.mapBy(j => 0),
    acceptorTries' = ACCEPTORS.mapBy(a => JOINERS.mapBy(j => 0)),
    sent' = Set(),
    inbox' = Set(),
    passports' = Set(),
    confirmed' = Set(),
    broken' = Set(),
    seen' = Set(),
  }

  // ------------------------------------------------------------------- pairing
  // The joiner pairs with an acceptor, the compromised one, or the Root,
  // with its own code. Both honest sides count the attempt (R-JOIN-3).
  action pairHonest(j: str, a: str): bool = all {
    tid < MAX_TID,
    joinerTries.get(j) < LIMIT,
    // An if, not "or": TLC evaluates both sides of a disjunction in a step,
    // and the compromised acceptor has no counter.
    if (ACCEPTORS.contains(a)) acceptorTries.get(a).get(j) < LIMIT else true,
    val t = tid + 1
    commit(t, sessions.union(Set({ tid: t, joiner: j, acceptor: a })), current.set(j, t),
      joinerTries.setBy(j, n => n + 1),
      if (ACCEPTORS.contains(a)) acceptorTries.setBy(a, m => m.setBy(j, n => n + 1)) else acceptorTries,
      sent, inbox, passports, confirmed, Set(), Set()),
  }

  // The adversary plays an acceptor against a joiner without the code: one
  // guess, which may succeed.
  action advPairJoiner(j: str, success: bool): bool = all {
    tid < MAX_TID,
    joinerTries.get(j) < LIMIT or MUTANT == "joiner_no_count",
    val t = tid + 1
    val over = if (joinerTries.get(j) >= LIMIT) Set("guessLimit") else Set()
    commit(t, if (success) sessions.union(Set({ tid: t, joiner: j, acceptor: ADV })) else sessions,
      if (success) current.set(j, t) else current, joinerTries.setBy(j, n => n + 1), acceptorTries, sent, inbox,
      passports, confirmed, over, if (success) Set("advPaired") else Set()),
  }

  // The adversary plays a joiner against an honest acceptor or the Root with
  // a joiner's code: one guess, which may succeed.
  action advPairAcceptor(a: str, j: str, success: bool): bool = all {
    tid < MAX_TID,
    acceptorTries.get(a).get(j) < LIMIT or MUTANT == "acceptor_no_count",
    val t = tid + 1
    val over = if (acceptorTries.get(a).get(j) >= LIMIT) Set("guessLimit") else Set()
    commit(t, if (success) sessions.union(Set({ tid: t, joiner: ADV, acceptor: a })) else sessions, current,
      joinerTries, acceptorTries.setBy(a, m => m.setBy(j, n => n + 1)), sent, inbox, passports, confirmed, over,
      if (success) Set("advPaired") else Set()),
  }

  // The joiner signs its payload over the transcript of its latest session
  // and sends it to the other end.
  action joinerSend(j: str): bool = {
    val t = current.get(j)
    all {
      t != 0,
      val peer = sessions.filter(s => s.tid == t).map(s => s.acceptor)
      nondet dest = peer.oneOf()
      val p = { key: j, presence: presOf(j), name: j, tid: t }
      commit(tid, sessions, current, joinerTries, acceptorTries, sent.union(Set({ p: p, to: dest })), inbox, passports,
        confirmed, Set(), Set()),
    }
  }

  // ------------------------------------------------------------- join requests
  // An honest acceptor, or the Root pairing directly, turns a payload it
  // received in one of its sessions into a join request with that session's
  // transcript. The payload's signature must cover that transcript; the
  // mutant no_transcript_binding takes the transcript from the payload.
  action acceptorRequest(a: str, s: Session, p: Payload): bool = all {
    ACCEPTORS.contains(a),
    sessions.contains(s),
    s.acceptor == a,
    sent.contains({ p: p, to: a }) or (s.joiner == ADV and advPayloads.contains(p)),
    p.tid == s.tid or MUTANT == "no_transcript_binding",
    val t = if (MUTANT == "no_transcript_binding") p.tid else s.tid
    val r = { key: p.key, presence: p.presence, name: p.name, tid: t, signed: p, acceptor: a }
    commit(tid, sessions, current, joinerTries, acceptorTries, sent, inbox.union(Set(r)), passports, confirmed,
      Set(), Set()),
  }

  // The compromised acceptor submits any request with any signed payload it
  // knows. The Root verifies the joiner's signature on receipt and drops a
  // request it does not cover.
  action badRequest(key: str, presence: str, name: str, t: int, p: Payload): bool = all {
    advPayloads.contains(p),
    val r = { key: key, presence: presence, name: name, tid: t, signed: p, acceptor: BAD }
    commit(tid, sessions, current, joinerTries, acceptorTries, sent, if (sigOk(r)) inbox.union(Set(r)) else inbox,
      passports, confirmed, Set(), if (sigOk(r)) Set() else Set("tampered")),
  }

  // ------------------------------------------------------------------- the Root
  // The owner enrolls the joiner in front of them: the Root verifies the
  // joiner's signature, shows the fingerprint, and the owner confirms only if
  // it equals the one the joiner shows (R-JOIN-5, R-JOIN-7).
  action rootAdmit(r: Request, j: str): bool = all {
    inbox.contains(r),
    current.get(j) != 0,
    sigOk(r),
    r.key == j or MUTANT == "no_fingerprint_compare",
    val pp = { key: r.key, presence: r.presence, name: r.name }
    val bad = (if (r.key != j) Set("intended") else Set())
      .union(if (JOINERS.contains(r.key) and (r.presence != presOf(r.key) or r.name != r.key)) Set("asSigned") else Set())
      .union(if (JOINERS.contains(r.key) and ACCEPTORS.contains(r.acceptor)
                 and not(sessions.contains({ tid: r.tid, joiner: r.key, acceptor: r.acceptor }))) Set("bound")
             else Set())
    commit(tid, sessions, current, joinerTries, acceptorTries, sent, inbox, passports.union(Set(pp)),
      confirmed.union(Set(r.key)), bad,
      Set("admitted").union(if (r.acceptor == "root") Set("direct") else Set())),
  }

  // The mutant acceptor_issues lets the compromised acceptor issue a
  // passport itself (R-JOIN-6).
  action badIssue(key: str): bool = all {
    MUTANT == "acceptor_issues",
    commit(tid, sessions, current, joinerTries, acceptorTries, sent, inbox,
      passports.union(Set({ key: key, presence: "none", name: key })), confirmed, Set(), Set()),
  }

  // ---------------------------------------------------------------------- step
  action step = any {
    nondet j = JOINERS.oneOf()
    any {
      nondet a = SIDES.oneOf()
      pairHonest(j, a),
      nondet success = Set(false, true).oneOf()
      advPairJoiner(j, success),
      nondet a = ACCEPTORS.oneOf()
      nondet success = Set(false, true).oneOf()
      advPairAcceptor(a, j, success),
      joinerSend(j),
      all { inbox != Set(), nondet r = inbox.oneOf() rootAdmit(r, j) },
    },
    all {
      sessions != Set(),
      nondet s = sessions.oneOf()
      nondet p = sent.map(x => x.p).union(advPayloads).oneOf()
      acceptorRequest(s.acceptor, s, p),
    },
    nondet key = KEYS.oneOf()
    nondet presence = PRES.oneOf()
    nondet name = NAMES.oneOf()
    nondet t = 1.to(MAX_TID).oneOf()
    nondet p = advPayloads.oneOf()
    badRequest(key, presence, name, t, p),
    nondet key = KEYS.oneOf()
    badIssue(key),
  }

  // ---------------------------------------------------------------- invariants
  // S4, R-JOIN-5, R-JOIN-7: a passport goes only to the key of the device the
  // owner enrolls, so an acceptor cannot substitute its own key.
  val intended = not(broken.contains("intended"))
  // S4, R-JOIN-4: the passport of a joiner carries exactly the presence key
  // and name it signed.
  val asSigned = not(broken.contains("asSigned"))
  // S4, R-JOIN-4: a request through an honest acceptor admits a joiner only
  // from a session the joiner ran with that acceptor, not one relayed by a
  // man in the middle.
  val bound = not(broken.contains("bound"))
  // S4, R-JOIN-3: no side runs more than LIMIT attempts with one code.
  val guessLimit = not(broken.contains("guessLimit"))
  // S4, R-JOIN-6: every passport was confirmed by the owner on the Root.
  val rootOnly = passports.forall(p => confirmed.contains(p.key))

  val safety = intended and asSigned and bound and guessLimit and rootOnly

  // ------------------------------------------------- non-vacuity witnesses
  // Each witness is expected to be VIOLATED: the behaviour is reachable.
  val witnessAdmitted = not(seen.contains("admitted"))
  val witnessDirect = not(seen.contains("direct"))
  val witnessAdvPaired = not(seen.contains("advPaired"))
  val witnessTampered = not(seen.contains("tampered"))
  val witnessForgedRequest = not(inbox.exists(r => r.key == ADV))
}
