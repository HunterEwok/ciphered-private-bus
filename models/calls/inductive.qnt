// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 HunterEwok
//
// Inductive invariant of the calls model (R-VER-3). Apalache proves three
// obligations, so that `safety` holds in every reachable state:
//   1. init implies IndInv               (--init=modelInit --invariant=IndInv, 0 steps)
//   2. IndInv and one step imply IndInv   (--init=indInit --invariant=IndInv, 1 step)
//   3. IndInv implies safety              (--init=indInit --invariant=modelSafety, 0 steps)
// with --step=modelStep, or with --step=stepX for each branch X of the step.
// indInit picks an arbitrary state of the bounded types that satisfies IndInv.
module inductive {
  const I_COMMANDERS: Set[str]
  const I_OUTSIDERS: Set[str]
  const I_ROOT: str
  const I_PRESENCE: Set[str]
  const I_RIGHTS: str -> Set[int]
  const I_MAX_NONCE: int
  const I_MAX_EPOCH: int
  const I_MAX_CALLS: int
  const I_MAX_RESETS: int
  const I_MUTANT: str
  import calls(COMMANDERS = I_COMMANDERS, OUTSIDERS = I_OUTSIDERS, ROOT = I_ROOT, PRESENCE = I_PRESENCE,
               RIGHTS = I_RIGHTS, MAX_NONCE = I_MAX_NONCE, MAX_EPOCH = I_MAX_EPOCH, MAX_CALLS = I_MAX_CALLS,
               MAX_RESETS = I_MAX_RESETS, MUTANT = I_MUTANT).* from "./calls"

  // ------------------------------------------------------------ bounded types
  val IDS = 1.to(MAX_CALLS)
  val EPOCHS = 1.to(MAX_EPOCH)
  val EXECS: Set[Exec] = tuples(DEVICES, IDS).map(t => { cmd: t._1, id: t._2 })
  val CALLS: Set[Call] = tuples(DEVICES, IDS, Set(false, true), ACTIONS, KEYS, NONCES, EPOCHS)
    .map(t => { cmd: t._1, id: t._2, idem: t._3, act: t._4, key: t._5, nonce: t._6, epoch: t._7 })
  val REPLIES: Set[Reply] = tuples(DEVICES, IDS, 0.to(MAX_NONCE), Set(false, true))
    .map(t => { cmd: t._1, id: t._2, nextNonce: t._3, executed: t._4 })
  val ISSUES: Set[Issue] = tuples(DEVICES, 0.to(MAX_RESETS)).map(t => { cmd: t._1, era: t._2 })
  val TAGS = Set("executed", "noRight", "unknown", "staleNonce", "staleEpoch", "epochRetryExecuted",
                 "mismatchRetryExecuted", "done", "reset", "reboot")

  // ------------------------------------------------------------------- parts
  pure def exOf(x: Call): Exec = { cmd: x.cmd, id: x.id }

  // The target's counters and slots: every slot holds a nonce issued to its
  // device in the current era and not consumed.
  pure def targetOk(sl: str -> int, te: int, pp: str -> Set[int], nm: Set[str], is: int, it: int -> Issue, er: int,
                    co: Set[int], sh: Set[int]): bool = and {
    sl.keys() == DEVICES, EPOCHS.contains(te), pp.keys() == COMMANDERS, nm.subseteq(COMMANDERS),
    COMMANDERS.forall(c => pp.get(c).subseteq(ACTIONS)),
    0.to(MAX_NONCE).contains(is), 0.to(MAX_RESETS).contains(er), it.keys() == NONCES,
    NONCES.forall(n => if (n <= is) ISSUES.contains(it.get(n)) and it.get(n).era <= er
                       else it.get(n) == { cmd: "", era: -1 }),
    co.forall(n => 1 <= n and n <= is), sh.forall(n => 1 <= n and n <= is),
    DEVICES.forall(d => sl.get(d) == 0 or and {
      sl.get(d) <= is, it.get(sl.get(d)) == { cmd: d, era: er }, not(co.contains(sl.get(d))),
      nm.contains(d) or d == ROOT,
    }),
  }

  pure def agrees(x: Call, s: Call): bool = and {
    s != noCall, x.idem == s.idem, x.act == s.act, x.key == s.key, not(x.idem) implies x.nonce == s.nonce,
  }

  // Every body of a call agrees with its first body, and all bodies of a call
  // that is not idempotent carry one nonce; a call that was executed and is
  // not idempotent has consumed it.
  pure def callsOk(ca: Set[Call], re: Set[Reply], is: int, co: Set[int], ex: Set[Exec], inn: Exec -> Call,
                   cm: str -> Commander): bool = and {
    ca.subseteq(CALLS), re.subseteq(REPLIES), ex.subseteq(EXECS), inn.keys() == EXECS,
    ca.forall(x => x.nonce <= is),
    re.forall(r => r.nextNonce <= is),
    EXECS.forall(e => inn.get(e) == noCall or (CALLS.contains(inn.get(e)) and exOf(inn.get(e)) == e
                                              and ca.contains(inn.get(e)))),
    EXECS.forall(e => (inn.get(e) == noCall) iff (e.id >= cm.get(e.cmd).nextId)),
    ca.forall(x => agrees(x, inn.get(exOf(x)))),
    ex.forall(e => inn.get(e) != noCall and (not(inn.get(e).idem) implies co.contains(inn.get(e).nonce))),
  }

  // A commander's counters and its pending call.
  pure def cmdOk(c: str, k: Commander, te: int, is: int, ca: Set[Call], inn: Exec -> Call): bool = and {
    0.to(is).contains(k.nonce), 1 <= k.epoch, k.epoch <= te, 1 <= k.nextId, k.nextId <= MAX_CALLS + 1,
    if (k.pending.active) and {
      ca.contains(k.pending.call), k.pending.call.cmd == c, k.pending.call.id == k.nextId - 1,
      k.nonce == 0,
    } else k.pending == idle,
  }

  pure def indInvOf(sl: str -> int, te: int, pp: str -> Set[int], nm: Set[str], cm: str -> Commander, ca: Set[Call],
                    re: Set[Reply], sh: Set[int], is: int, it: int -> Issue, er: int, co: Set[int], ex: Set[Exec],
                    inn: Exec -> Call, b: Set[str], sn: Set[str]): bool = and {
    targetOk(sl, te, pp, nm, is, it, er, co, sh),
    cm.keys() == DEVICES,
    DEVICES.forall(c => cmdOk(c, cm.get(c), te, is, ca, inn)),
    callsOk(ca, re, is, co, ex, inn, cm),
    b == Set(),
    sn.subseteq(TAGS),
  }

  val IndInv = indInvOf(slots, tepoch, passport, named, cmds, calls, replies, shown, issued, issuedTo, era, consumed,
                        executed, intents, broken, seen)

  // The model's own initial state, step, and safety, and the branches of the
  // step one by one (together they are exactly step in calls.qnt).
  action modelInit = init
  action modelStep = step
  val modelSafety = safety
  action stepAnswer = { nondet c = DEVICES.oneOf() targetAnswer(c) }
  action stepLearn = { nondet c = DEVICES.oneOf() nondet n = shown.union(Set(0)).oneOf() cmdLearn(c, n) }
  action stepMismatch = { nondet c = DEVICES.oneOf() nondet n = shown.union(Set(0)).oneOf() cmdMismatch(c, n) }
  action stepStart = {
    nondet c = DEVICES.oneOf()
    nondet a = ACTIONS.oneOf()
    nondet idem = Set(false, true).oneOf()
    nondet key = KEYS.oneOf()
    cmdStart(c, a, idem, key)
  }
  action stepEpoch = { nondet c = DEVICES.oneOf() nondet e = EPOCHS.oneOf() cmdEpoch(c, e) }
  action stepReply = { nondet c = DEVICES.oneOf() all { replies != Set(), nondet r = replies.oneOf() cmdReply(c, r) } }
  action stepChange = { nondet c = DEVICES.oneOf() nondet rs = ACTIONS.powerset().oneOf() envChange(c, rs) }
  action stepCall = all { calls != Set(), nondet x = calls.oneOf() targetCall(x) }
  action stepReset = { nondet kind = Set("reset", "reboot").oneOf() targetReset(kind) }
  action stepRotate = targetRotate

  // ------------------------------------------- an arbitrary state of IndInv
  action indInit = {
    nondet sl = setOfMaps(DEVICES, 0.to(MAX_NONCE)).oneOf()
    nondet te = EPOCHS.oneOf()
    nondet pp = setOfMaps(COMMANDERS, ACTIONS.powerset()).oneOf()
    nondet nm = COMMANDERS.powerset().oneOf()
    nondet kn = setOfMaps(DEVICES, 0.to(MAX_NONCE)).oneOf()
    nondet ke = setOfMaps(DEVICES, EPOCHS).oneOf()
    nondet ki = setOfMaps(DEVICES, 1.to(MAX_CALLS + 1)).oneOf()
    nondet pa = setOfMaps(DEVICES, Set(false, true)).oneOf()
    nondet pc = setOfMaps(DEVICES, CALLS).oneOf()
    nondet pte = setOfMaps(DEVICES, Set(false, true)).oneOf()
    nondet ptm = setOfMaps(DEVICES, Set(false, true)).oneOf()
    nondet ca = CALLS.powerset().oneOf()
    nondet re = REPLIES.powerset().oneOf()
    nondet sh = NONCES.powerset().oneOf()
    nondet is = 0.to(MAX_NONCE).oneOf()
    nondet it = setOfMaps(NONCES, ISSUES.union(Set({ cmd: "", era: -1 }))).oneOf()
    nondet er = 0.to(MAX_RESETS).oneOf()
    nondet co = NONCES.powerset().oneOf()
    nondet ex = EXECS.powerset().oneOf()
    nondet inn = setOfMaps(EXECS, CALLS.union(Set(noCall))).oneOf()
    nondet sn = TAGS.powerset().oneOf()
    val cm = DEVICES.mapBy(d => { nonce: kn.get(d), epoch: ke.get(d), nextId: ki.get(d),
      pending: if (pa.get(d)) { active: true, call: pc.get(d), triedEpoch: pte.get(d), triedMismatch: ptm.get(d) }
               else idle })
    all {
      indInvOf(sl, te, pp, nm, cm, ca, re, sh, is, it, er, co, ex, inn, Set(), sn),
      slots' = sl, tepoch' = te, passport' = pp, named' = nm, cmds' = cm, calls' = ca, replies' = re, shown' = sh,
      issued' = is, issuedTo' = it, era' = er, consumed' = co, executed' = ex, intents' = inn,
      broken' = Set(), seen' = sn,
    }
  }
}

module tiny_ind {
  import inductive(I_COMMANDERS = Set("a"), I_OUTSIDERS = Set(), I_ROOT = "r", I_PRESENCE = Set("a"),
                   I_RIGHTS = Map("a" -> Set(1, 2)), I_MAX_NONCE = 3, I_MAX_EPOCH = 3, I_MAX_CALLS = 2,
                   I_MAX_RESETS = 1, I_MUTANT = "none").*
}

module small_ind {
  import inductive(I_COMMANDERS = Set("a", "b"), I_OUTSIDERS = Set("x"), I_ROOT = "r", I_PRESENCE = Set("b"),
                   I_RIGHTS = Map("a" -> Set(1), "b" -> Set(1, 2)), I_MAX_NONCE = 6, I_MAX_EPOCH = 3,
                   I_MAX_CALLS = 2, I_MAX_RESETS = 2, I_MUTANT = "none").*
}
