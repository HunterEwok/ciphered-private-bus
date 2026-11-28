// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 HunterEwok
//
// Device enrollment of Ciphered Private Bus (verification level V2).
//
// Scope: pairing of a joiner with an acceptor or with the Root by the code
// the joiner shows; the joiner's signed payload; the join request; a
// compromised acceptor and a network adversary that knows the joiner's code
// and relays payloads between sessions; and the Root's admission only for
// the key fingerprint it read from the joiner. Requirements: R-JOIN-3..7,
// R-JOIN-9; property S4.
//
// Abstractions:
// - CPace, signatures, and sealing are perfect (Tamarin covers them). A
//   pairing session is named by its transcript (`tid`); only its two ends
//   know what was sent in it.
// - The code carries a 128-bit secret, so it cannot be guessed (R-JOIN-3),
//   and runs are not counted. The adversary is still given every code, as
//   if it had seen the joiner's screen: it may pair with a joiner as an
//   acceptor and with an acceptor or the Root as a joiner at any time.
// - The key fingerprint is the SHA-256 of the joiner's device key
//   (R-JOIN-5); equal fingerprints mean equal keys.
// - The owner enrolls the honest joiner in front of them: the root device
//   reads the fingerprint from that joiner's code and admits a request only
//   for that key (R-JOIN-7). A mismatch only refuses, so it is no step here.
//   The local check of a non-root acceptor (abort code 5) is not modelled:
//   nothing relies on it. The joiner does not authenticate the bus, and its
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

  action commit(t: int, ss: Set[Session], cu: str -> int,
                se: Set[{ p: Payload, to: str }], ib: Set[Request], pp: Set[Passport], co: Set[str],
                extra: Set[str], tags: Set[str]): bool = all {
    tid' = t, sessions' = ss, current' = cu, sent' = se, inbox' = ib,
    passports' = pp, confirmed' = co, broken' = broken.union(extra), seen' = seen.union(tags),
  }

  // -------------------------------------------------------------- initial state
  action init = all {
    tid' = 0,
    sessions' = Set(),
    current' = JOINERS.mapBy(j => 0),
    sent' = Set(),
    inbox' = Set(),
    passports' = Set(),
    confirmed' = Set(),
    broken' = Set(),
    seen' = Set(),
  }

  // ------------------------------------------------------------------- pairing
  // The joiner pairs with an acceptor, the compromised one, or the Root,
  // which reads its code.
  action pairHonest(j: str, a: str): bool = all {
    tid < MAX_TID,
    val t = tid + 1
    commit(t, sessions.union(Set({ tid: t, joiner: j, acceptor: a })), current.set(j, t),
      sent, inbox, passports, confirmed, Set(), Set()),
  }

  // The adversary, knowing the joiner's code, plays an acceptor against it.
  action advPairJoiner(j: str): bool = all {
    tid < MAX_TID,
    val t = tid + 1
    commit(t, sessions.union(Set({ tid: t, joiner: j, acceptor: ADV })), current.set(j, t), sent, inbox,
      passports, confirmed, Set(), Set("advPaired")),
  }

  // The adversary plays a joiner against an honest acceptor or the Root with
  // a code it showed or one it knows; either way the session's joiner is the
  // adversary.
  action advPairAcceptor(a: str): bool = all {
    tid < MAX_TID,
    val t = tid + 1
    commit(t, sessions.union(Set({ tid: t, joiner: ADV, acceptor: a })), current, sent, inbox, passports,
      confirmed, Set(), Set("advPaired")),
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
      commit(tid, sessions, current, sent.union(Set({ p: p, to: dest })), inbox, passports,
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
    commit(tid, sessions, current, sent, inbox.union(Set(r)), passports, confirmed,
      Set(), Set()),
  }

  // The compromised acceptor submits any request with any signed payload it
  // knows. The Root verifies the joiner's signature on receipt and drops a
  // request it does not cover.
  action badRequest(key: str, presence: str, name: str, t: int, p: Payload): bool = all {
    advPayloads.contains(p),
    val r = { key: key, presence: presence, name: name, tid: t, signed: p, acceptor: BAD }
    commit(tid, sessions, current, sent, if (sigOk(r)) inbox.union(Set(r)) else inbox,
      passports, confirmed, Set(), if (sigOk(r)) Set() else Set("tampered")),
  }

  // ------------------------------------------------------------------- the Root
  // The owner enrolls the joiner in front of them: the Root verifies the
  // joiner's signature and admits only the key whose fingerprint it read
  // from that joiner's code (R-JOIN-5, R-JOIN-7).
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
    commit(tid, sessions, current, sent, inbox, passports.union(Set(pp)),
      confirmed.union(Set(r.key)), bad,
      Set("admitted").union(if (r.acceptor == "root") Set("direct") else Set())),
  }

  // The mutant acceptor_issues lets the compromised acceptor issue a
  // passport itself (R-JOIN-6).
  action badIssue(key: str): bool = all {
    MUTANT == "acceptor_issues",
    commit(tid, sessions, current, sent, inbox,
      passports.union(Set({ key: key, presence: "none", name: key })), confirmed, Set(), Set()),
  }

  // ---------------------------------------------------------------------- step
  action step = any {
    nondet j = JOINERS.oneOf()
    any {
      nondet a = SIDES.oneOf()
      pairHonest(j, a),
      advPairJoiner(j),
      joinerSend(j),
      all { inbox != Set(), nondet r = inbox.oneOf() rootAdmit(r, j) },
    },
    nondet a = ACCEPTORS.oneOf()
    advPairAcceptor(a),
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
  // S4, R-JOIN-6: every passport was confirmed by the owner on the Root.
  val rootOnly = passports.forall(p => confirmed.contains(p.key))

  val safety = intended and asSigned and bound and rootOnly

  // ------------------------------------------------- non-vacuity witnesses
  // Each witness is expected to be VIOLATED: the behaviour is reachable.
  val witnessAdmitted = not(seen.contains("admitted"))
  val witnessDirect = not(seen.contains("direct"))
  val witnessAdvPaired = not(seen.contains("advPaired"))
  val witnessTampered = not(seen.contains("tampered"))
  val witnessForgedRequest = not(inbox.exists(r => r.key == ADV))
}
