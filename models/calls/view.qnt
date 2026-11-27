// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 HunterEwok
//
// A state view of the calls model for exhaustive TLC runs (TLC option VIEW).
// TLC stores and expands one state per value of `viewOf`; `bisim.qnt` proves
// with Apalache that states with equal views are interchangeable for
// `safety`, so the reduced search finds a violation exactly when the full one
// does. Valid only for MUTANT = "none".
//
// The view drops what can no longer influence `safety`:
// - the witness tags `seen` and the ghost `intents`, which only feed `seen`;
// - call bodies whose nonce can never match a slot again or whose epoch is
//   already stale, replies that cannot end the pending call differently from a
//   refusal, and the history of nonces outside the current slots;
// - nonce values (only "the slot of this device", "none" and "another
//   value" matter), the action and key of a body beyond what the target
//   decides from them, and epochs at or above the last one a commander can
//   still learn;
// - every device that can never hold a slot again.
module viewdefs {
  const V_COMMANDERS: Set[str]
  const V_OUTSIDERS: Set[str]
  const V_ROOT: str
  const V_PRESENCE: Set[str]
  const V_MAX_NONCE: int
  const V_MAX_EPOCH: int
  const V_MAX_CALLS: int

  type VCall = { cmd: str, id: int, idem: bool, act: int, key: str, nonce: int, epoch: int }
  type VReply = { cmd: str, id: int, nextNonce: int, executed: bool }
  type VPending = { active: bool, call: VCall, triedEpoch: bool, triedMismatch: bool }
  type VCommander = { nonce: int, epoch: int, nextId: int, pending: VPending }
  type VIssue = { cmd: str, era: int }
  type VExec = { cmd: str, id: int }

  type CallView = { cmd: str, pend: bool, exec: bool, act: int, ep: int }
  type PendView = { tag: str, idem: bool, act: int, exec: bool, cur: bool, ep: int }
  type CmdView = { tag: str, nonce: int, epoch: int, nextId: int, pend: PendView }
  type View = {
    exhausted: bool, slotActive: str -> bool, tepoch: int, passport: str -> Set[int], liveNamed: Set[str],
    cmds: str -> CmdView, calls: Set[CallView], replies: Set[(str, int)], shown: Set[str], issued: int,
    issuedTo: str -> VIssue, era: int, consumed: Set[str], broken: Set[str],
  }

  pure val V_AUTO = 1
  pure val V_CONFIRM = 2
  pure val V_ACTIONS = Set(V_AUTO, V_CONFIRM)
  pure val V_DEVICES = V_COMMANDERS.union(V_OUTSIDERS).union(Set(V_ROOT))
  // The highest epoch a commander's knowledge still matters below: a body
  // sealed at this epoch or above is never stale (the target's epoch is at
  // most V_MAX_EPOCH, and a body is stale below its epoch minus one).
  pure val TOP_EPOCH = if (V_MAX_EPOCH <= 1) 1 else V_MAX_EPOCH - 1

  pure def vAllowed(nm: Set[str], c: str): bool = nm.contains(c) or c == V_ROOT
  pure def vRights(pp: str -> Set[int], nm: Set[str], c: str): Set[int] =
    if (c == V_ROOT) V_ACTIONS else if (nm.contains(c)) pp.get(c) else Set()
  pure def vKeyOk(x: VCall): bool =
    (x.key == "root" and x.cmd == V_ROOT)
      or (x.act == V_AUTO and x.key == "device")
      or (x.act == V_CONFIRM and x.key == "presence" and V_PRESENCE.contains(x.cmd))

  // A device that has no slot and can never get one: it is not entitled, or
  // the target has issued its last nonce.
  pure def devDead(sl: str -> int, nm: Set[str], is: int, d: str): bool =
    sl.get(d) == 0 and (not(vAllowed(nm, d)) or is == V_MAX_NONCE)
  // A nonce held by or sent to device d: none, its current slot, or a value
  // that never matches a slot again.
  pure def normNonce(sl: str -> int, d: str, n: int): int =
    if (n == 0) 0 else if (sl.get(d) != 0 and n == sl.get(d)) 1 else -1
  // The nonces in the open: the devices whose slot is in the open, and "" if
  // some other value is.
  pure def normShown(sl: str -> int, sh: Set[int]): Set[str] = {
    val live = V_DEVICES.filter(d => sl.get(d) != 0 and sh.contains(sl.get(d)))
    if (sh.size() > live.size()) live.union(Set("")) else live
  }
  pure def effEpoch(te: int, ep: int): int = if (ep < te - 1) 0 else if (ep >= TOP_EPOCH) TOP_EPOCH else ep
  pure def effCmdEpoch(ep: int): int = if (ep >= TOP_EPOCH) TOP_EPOCH else ep
  // What the target decides from a body's action and key: refused (0), an
  // automatic action (1), a confirmation-class action (2), or a root call (3).
  pure def liveAct(pp: str -> Set[int], nm: Set[str], x: VCall): int =
    if (not(vAllowed(nm, x.cmd) and vRights(pp, nm, x.cmd).contains(x.act) and vKeyOk(x))) 0
    else if (x.cmd == V_ROOT) 3
    else x.act
  pure def canRetryMismatch(k: VCommander): bool =
    k.pending.active and not(k.pending.triedMismatch) and k.pending.call.act != V_CONFIRM and k.pending.call.idem
  // A body the target can still execute.
  pure def liveCall(sl: str -> int, te: int, x: VCall): bool = x.nonce == sl.get(x.cmd) and x.epoch >= te - 1
  pure def callView(te: int, pp: str -> Set[int], nm: Set[str], cm: str -> VCommander, ex: Set[VExec], x: VCall): CallView = {
    val la = liveAct(pp, nm, x)
    val k = cm.get(x.cmd)
    { cmd: x.cmd, pend: k.pending.active and k.pending.call.id == x.id,
      exec: la != 0 and not(x.idem) and ex.contains({ cmd: x.cmd, id: x.id }), act: la, ep: effEpoch(te, x.epoch) }
  }

  pure val NO_PEND: PendView = { tag: "none", idem: false, act: 0, exec: false, cur: false, ep: 0 }
  pure def normPending(sl: str -> int, te: int, pp: str -> Set[int], nm: Set[str], ex: Set[VExec], d: str,
                       k: VCommander): PendView =
    if (not(k.pending.active)) NO_PEND
    else {
      val c = k.pending.call
      val cm = not(k.pending.triedMismatch) and c.act != V_CONFIRM and c.idem
      val ce = not(k.pending.triedEpoch) and c.act != V_CONFIRM and k.epoch < TOP_EPOCH
      val dn = normNonce(sl, d, c.nonce)
      val la = liveAct(pp, nm, c)
      if (not(cm) and not(ce)) { ...NO_PEND, tag: "done" }
      else if (not(cm) and ce and dn != 1) { ...NO_PEND, tag: "dead_ep" }
      else if (not(cm) and ce)
        { ...NO_PEND, tag: "ep", idem: c.idem, act: la,
          exec: not(c.idem) and la != 0 and ex.contains({ cmd: d, id: c.id }) }
      else if (cm and not(ce)) { ...NO_PEND, tag: "mm", act: la, ep: effEpoch(te, c.epoch) }
      else { ...NO_PEND, tag: "both", act: la, cur: dn == 1, ep: effEpoch(te, c.epoch) }
    }

  pure val DEAD_CMD: CmdView = { tag: "dead", nonce: 0, epoch: 0, nextId: 0, pend: NO_PEND }
  pure val NO_ISSUE: VIssue = { cmd: "", era: -1 }

  pure def viewOf(sl: str -> int, te: int, pp: str -> Set[int], nm: Set[str], cm: str -> VCommander, ca: Set[VCall],
                  re: Set[VReply], sh: Set[int], is: int, it: int -> VIssue, er: int, co: Set[int], ex: Set[VExec],
                  b: Set[str]): View = {
    val dead = V_DEVICES.mapBy(d => devDead(sl, nm, is, d))
    if (V_DEVICES.forall(d => dead.get(d)))
      { exhausted: true, slotActive: V_DEVICES.mapBy(d => false), tepoch: 0,
        passport: V_COMMANDERS.mapBy(c => Set()), liveNamed: Set(), cmds: V_DEVICES.mapBy(d => DEAD_CMD),
        calls: Set(), replies: Set(), shown: Set(), issued: 0, issuedTo: V_DEVICES.mapBy(d => NO_ISSUE), era: 0,
        consumed: Set(), broken: b }
    else {
      val liveNamed = nm.filter(c => not(dead.get(c)))
      val ns = normShown(sl, sh)
      val cmdsV = V_DEVICES.mapBy(d => {
        val k = cm.get(d)
        if (dead.get(d)) DEAD_CMD
        else if (k.nextId > V_MAX_CALLS and not(k.pending.active)) { ...DEAD_CMD, tag: "finished" }
        else { tag: "live", nonce: normNonce(sl, d, k.nonce), epoch: effCmdEpoch(k.epoch), nextId: k.nextId,
               pend: normPending(sl, te, pp, nm, ex, d, k) }
      })
      val repliesV = re.filter(r => {
        val k = cm.get(r.cmd)
        val dn = normNonce(sl, r.cmd, r.nextNonce)
        and {
          not(dead.get(r.cmd)), k.pending.active, k.nextId <= V_MAX_CALLS, r.id == k.pending.call.id, dn != 0,
          canRetryMismatch(k) or (if (dn == 1) not(ns.contains(r.cmd)) else ns.exclude(Set(r.cmd)) == Set()),
        }
      }).map(r => (r.cmd, normNonce(sl, r.cmd, r.nextNonce)))
      { exhausted: false, slotActive: V_DEVICES.mapBy(d => sl.get(d) != 0), tepoch: te,
        passport: V_COMMANDERS.mapBy(c => if (liveNamed.contains(c)) pp.get(c) else Set()), liveNamed: liveNamed,
        cmds: cmdsV, calls: ca.filter(x => liveCall(sl, te, x)).map(x => callView(te, pp, nm, cm, ex, x)),
        replies: repliesV, shown: ns, issued: is,
        issuedTo: V_DEVICES.mapBy(d => if (sl.get(d) == 0) NO_ISSUE else it.get(sl.get(d))), era: er,
        consumed: V_DEVICES.filter(d => co.contains(sl.get(d))), broken: b }
    }
  }
}

// The instance `tiny` of instances.qnt with its view, for TLC. The constants
// must stay those of `tiny`.
module tiny_view {
  import calls(COMMANDERS = Set("a"), OUTSIDERS = Set(), ROOT = "r", PRESENCE = Set("a"),
               RIGHTS = Map("a" -> Set(1, 2)), MAX_NONCE = 4, MAX_EPOCH = 3, MAX_CALLS = 2, MAX_RESETS = 1,
               MUTANT = "none").* from "./calls"
  import viewdefs(V_COMMANDERS = Set("a"), V_OUTSIDERS = Set(), V_ROOT = "r", V_PRESENCE = Set("a"),
                  V_MAX_NONCE = 4, V_MAX_EPOCH = 3, V_MAX_CALLS = 2).*
  val safetyView = viewOf(slots, tepoch, passport, named, cmds, calls, replies, shown, issued, issuedTo, era,
                          consumed, executed, broken)
}

// Proof that the view is exact for `safety` (R-VER-3), checked by Apalache on
// two copies A and B of the model:
//   O1. init implies Struct                             (initStruct, 0 steps, invariant structA)
//   O2. Struct, safety and one step imply Struct         (initSafe, stepX, 1 step, invariant structA)
//   O3. two Struct states with equal views agree on safety (initPair, 0 steps, invariant sameSafety)
//   O4. for two Struct states with equal views, A safe, every step of A is
//       answered by B with no step or one step, and the views are equal again
//       (initPair, matchX, 2 steps, invariant matched).
// Struct is a set of facts about the model's counters that does not include
// `safety`. Why this suffices: take a shortest behaviour of the model that
// ends in a state violating `safety`. Every earlier state is safe, so by O1
// and O2 it satisfies Struct. TLC with the view reaches a state of the same
// view as the initial state (it is the initial state). If TLC holds a state r
// with the view of the i-th state s, then r is reachable and safe (otherwise
// TLC has already reported a violation), so r satisfies Struct, and by O4 the
// step from s to the next state is answered from r by a state TLC also
// generates, with the same view as the next state. By induction TLC generates
// a state with the view of the last state, which violates `safety` by O3.
module bisim {
  const P_COMMANDERS: Set[str]
  const P_OUTSIDERS: Set[str]
  const P_ROOT: str
  const P_PRESENCE: Set[str]
  const P_RIGHTS: str -> Set[int]
  const P_MAX_NONCE: int
  const P_MAX_EPOCH: int
  const P_MAX_CALLS: int
  const P_MAX_RESETS: int
  import calls(COMMANDERS = P_COMMANDERS, OUTSIDERS = P_OUTSIDERS, ROOT = P_ROOT, PRESENCE = P_PRESENCE,
               RIGHTS = P_RIGHTS, MAX_NONCE = P_MAX_NONCE, MAX_EPOCH = P_MAX_EPOCH, MAX_CALLS = P_MAX_CALLS,
               MAX_RESETS = P_MAX_RESETS, MUTANT = "none") as A from "./calls"
  import calls(COMMANDERS = P_COMMANDERS, OUTSIDERS = P_OUTSIDERS, ROOT = P_ROOT, PRESENCE = P_PRESENCE,
               RIGHTS = P_RIGHTS, MAX_NONCE = P_MAX_NONCE, MAX_EPOCH = P_MAX_EPOCH, MAX_CALLS = P_MAX_CALLS,
               MAX_RESETS = P_MAX_RESETS, MUTANT = "none") as B from "./calls"
  import viewdefs(V_COMMANDERS = P_COMMANDERS, V_OUTSIDERS = P_OUTSIDERS, V_ROOT = P_ROOT, V_PRESENCE = P_PRESENCE,
                  V_MAX_NONCE = P_MAX_NONCE, V_MAX_EPOCH = P_MAX_EPOCH, V_MAX_CALLS = P_MAX_CALLS).*

  // ------------------------------------------------------------ bounded types
  pure val DEVS = V_DEVICES
  pure val NONCES = 1.to(P_MAX_NONCE)
  pure val IDS = 1.to(P_MAX_CALLS)
  pure val EPOCHS = 1.to(P_MAX_EPOCH)
  pure val KEYS = Set("device", "presence", "root")
  pure val EXECS: Set[VExec] = tuples(DEVS, IDS).map(t => { cmd: t._1, id: t._2 })
  pure val ISSUES: Set[VIssue] = tuples(DEVS, 0.to(P_MAX_RESETS)).map(t => { cmd: t._1, era: t._2 })
  pure val REPLIES: Set[VReply] = tuples(DEVS, IDS, 0.to(P_MAX_NONCE), Set(false, true))
    .map(t => { cmd: t._1, id: t._2, nextNonce: t._3, executed: t._4 })
  pure val NO_CALL: VCall = { cmd: "", id: 0, idem: false, act: V_AUTO, key: "device", nonce: 0, epoch: 0 }
  pure val IDLE: VPending = { active: false, call: NO_CALL, triedEpoch: false, triedMismatch: false }

  pure def isCall(x: VCall): bool = and {
    DEVS.contains(x.cmd), IDS.contains(x.id), V_ACTIONS.contains(x.act), KEYS.contains(x.key),
    NONCES.contains(x.nonce), EPOCHS.contains(x.epoch),
  }

  // ------------------------------------------------------------------ Struct
  pure def structOf(sl: str -> int, te: int, pp: str -> Set[int], nm: Set[str], cm: str -> VCommander,
                    ca: Set[VCall], re: Set[VReply], sh: Set[int], is: int, it: int -> VIssue, er: int, co: Set[int],
                    ex: Set[VExec], inn: VExec -> VCall): bool = and {
    sl.keys() == DEVS, EPOCHS.contains(te), pp.keys() == P_COMMANDERS, nm.subseteq(P_COMMANDERS),
    P_COMMANDERS.forall(c => pp.get(c).subseteq(V_ACTIONS)),
    0.to(P_MAX_NONCE).contains(is), 0.to(P_MAX_RESETS).contains(er), it.keys() == NONCES,
    NONCES.forall(n => if (n <= is) ISSUES.contains(it.get(n)) and it.get(n).era <= er
                       else it.get(n) == NO_ISSUE),
    co.forall(n => 1 <= n and n <= is), sh.forall(n => 1 <= n and n <= is),
    // A slot holds a nonce issued to its device in the current era and not consumed.
    DEVS.forall(d => sl.get(d) == 0 or and {
      sl.get(d) <= is, it.get(sl.get(d)) == { cmd: d, era: er }, not(co.contains(sl.get(d))),
    }),
    cm.keys() == DEVS,
    DEVS.forall(d => {
      val k = cm.get(d)
      and {
        0.to(is).contains(k.nonce), 1 <= k.epoch, k.epoch <= te, 1 <= k.nextId, k.nextId <= P_MAX_CALLS + 1,
        if (k.pending.active) and {
          ca.contains(k.pending.call), k.pending.call.cmd == d, k.pending.call.id == k.nextId - 1,
          k.pending.call.epoch == k.epoch, k.nonce == 0,
        } else k.pending == IDLE,
      }
    }),
    ca.forall(x => isCall(x) and x.nonce <= is and x.id < cm.get(x.cmd).nextId),
    ca.forall(x => ca.forall(y => (x.cmd == y.cmd and x.id == y.id)
                                  implies (x.idem == y.idem and x.act == y.act and x.key == y.key))),
    re.forall(r => REPLIES.contains(r) and r.nextNonce <= is and r.id < cm.get(r.cmd).nextId),
    ex.forall(e => EXECS.contains(e) and e.id < cm.get(e.cmd).nextId),
    inn.keys() == EXECS,
  }

  val structA = structOf(A::slots, A::tepoch, A::passport, A::named, A::cmds, A::calls, A::replies, A::shown,
                         A::issued, A::issuedTo, A::era, A::consumed, A::executed, A::intents)
  val structB = structOf(B::slots, B::tepoch, B::passport, B::named, B::cmds, B::calls, B::replies, B::shown,
                         B::issued, B::issuedTo, B::era, B::consumed, B::executed, B::intents)
  val viewA = viewOf(A::slots, A::tepoch, A::passport, A::named, A::cmds, A::calls, A::replies, A::shown,
                     A::issued, A::issuedTo, A::era, A::consumed, A::executed, A::broken)
  val viewB = viewOf(B::slots, B::tepoch, B::passport, B::named, B::cmds, B::calls, B::replies, B::shown,
                     B::issued, B::issuedTo, B::era, B::consumed, B::executed, B::broken)

  // ------------------------------------------------------------- bookkeeping
  type Move = { kind: str, c: str, a: int, idem: bool, key: str, e: int, rs: Set[int], xv: CallView, live: bool,
                dn: int, epTop: bool, over: bool }
  pure val NO_XV: CallView = { cmd: "", pend: false, exec: false, act: 0, ep: 0 }
  pure val NO_MOVE: Move = { kind: "", c: "", a: 0, idem: false, key: "", e: 0, rs: Set(), xv: NO_XV, live: false,
                             dn: 0, epTop: false, over: false }
  var stage: int      // 0: before A's step, 1: after it, 2: after B's answer
  var mv: Move        // A's step, as B needs it
  var matchOk: bool   // B's answer was enabled

  action aStay = all {
    A::slots' = A::slots, A::tepoch' = A::tepoch, A::passport' = A::passport, A::named' = A::named,
    A::cmds' = A::cmds, A::calls' = A::calls, A::replies' = A::replies, A::shown' = A::shown,
    A::issued' = A::issued, A::issuedTo' = A::issuedTo, A::era' = A::era, A::consumed' = A::consumed,
    A::executed' = A::executed, A::intents' = A::intents, A::broken' = A::broken, A::seen' = A::seen,
  }
  action bStay = all {
    B::slots' = B::slots, B::tepoch' = B::tepoch, B::passport' = B::passport, B::named' = B::named,
    B::cmds' = B::cmds, B::calls' = B::calls, B::replies' = B::replies, B::shown' = B::shown,
    B::issued' = B::issued, B::issuedTo' = B::issuedTo, B::era' = B::era, B::consumed' = B::consumed,
    B::executed' = B::executed, B::intents' = B::intents, B::broken' = B::broken, B::seen' = B::seen,
  }

  // --------------------------------------------- an arbitrary state of Struct
  // Drawn as indInit in inductive.qnt draws one: every body of a call shares
  // idem, act and key, which Struct requires, so these draw every state of
  // Struct (intents only feed the witness tags and are left arbitrary).
  pure def mkInn(ip: VExec -> bool, ii: VExec -> bool, ia: VExec -> int, ik: VExec -> str, ino: VExec -> int,
                 iep: VExec -> int): VExec -> VCall =
    EXECS.mapBy(e => if (ip.get(e))
      { cmd: e.cmd, id: e.id, idem: ii.get(e), act: ia.get(e), key: ik.get(e), nonce: ino.get(e), epoch: iep.get(e) }
      else NO_CALL)
  pure def mkCalls(ip: VExec -> bool, ii: VExec -> bool, ia: VExec -> int, ik: VExec -> str,
                   bodies: (VExec, int, int) -> bool): Set[VCall] =
    tuples(EXECS, NONCES, EPOCHS).filter(t => ip.get(t._1) and bodies.get(t))
      .map(t => { cmd: t._1.cmd, id: t._1.id, idem: ii.get(t._1), act: ia.get(t._1), key: ik.get(t._1),
                  nonce: t._2, epoch: t._3 })
  pure def mkCmds(kn: str -> int, ke: str -> int, ki: str -> int, pa: str -> bool, pn: str -> int, pe: str -> int,
                  pte: str -> bool, ptm: str -> bool, ii: VExec -> bool, ia: VExec -> int,
                  ik: VExec -> str): str -> VCommander =
    DEVS.mapBy(d => {
      val e = { cmd: d, id: if (ki.get(d) > 1) ki.get(d) - 1 else 1 }
      val pc = { cmd: d, id: ki.get(d) - 1, idem: ii.get(e), act: ia.get(e), key: ik.get(e), nonce: pn.get(d),
                 epoch: pe.get(d) }
      { nonce: kn.get(d), epoch: ke.get(d), nextId: ki.get(d),
        pending: if (pa.get(d)) { active: true, call: pc, triedEpoch: pte.get(d), triedMismatch: ptm.get(d) }
                 else IDLE }
    })

  action drawA = {
    nondet sl = setOfMaps(DEVS, 0.to(P_MAX_NONCE)).oneOf()
    nondet te = EPOCHS.oneOf()
    nondet pp = setOfMaps(P_COMMANDERS, V_ACTIONS.powerset()).oneOf()
    nondet nm = P_COMMANDERS.powerset().oneOf()
    nondet kn = setOfMaps(DEVS, 0.to(P_MAX_NONCE)).oneOf()
    nondet ke = setOfMaps(DEVS, EPOCHS).oneOf()
    nondet ki = setOfMaps(DEVS, 1.to(P_MAX_CALLS + 1)).oneOf()
    nondet pa = setOfMaps(DEVS, Set(false, true)).oneOf()
    nondet pn = setOfMaps(DEVS, NONCES).oneOf()
    nondet pe = setOfMaps(DEVS, EPOCHS).oneOf()
    nondet pte = setOfMaps(DEVS, Set(false, true)).oneOf()
    nondet ptm = setOfMaps(DEVS, Set(false, true)).oneOf()
    nondet re = REPLIES.powerset().oneOf()
    nondet sh = NONCES.powerset().oneOf()
    nondet is = 0.to(P_MAX_NONCE).oneOf()
    nondet it = setOfMaps(NONCES, ISSUES.union(Set(NO_ISSUE))).oneOf()
    nondet er = 0.to(P_MAX_RESETS).oneOf()
    nondet co = NONCES.powerset().oneOf()
    nondet ex = EXECS.powerset().oneOf()
    nondet ip = setOfMaps(EXECS, Set(false, true)).oneOf()
    nondet ii = setOfMaps(EXECS, Set(false, true)).oneOf()
    nondet ia = setOfMaps(EXECS, V_ACTIONS).oneOf()
    nondet ik = setOfMaps(EXECS, KEYS).oneOf()
    nondet ino = setOfMaps(EXECS, NONCES).oneOf()
    nondet iep = setOfMaps(EXECS, EPOCHS).oneOf()
    nondet bodies = setOfMaps(tuples(EXECS, NONCES, EPOCHS), Set(false, true)).oneOf()
    val inn = mkInn(ip, ii, ia, ik, ino, iep)
    val ca = mkCalls(ip, ii, ia, ik, bodies)
    val cm = mkCmds(kn, ke, ki, pa, pn, pe, pte, ptm, ii, ia, ik)
    all {
      structOf(sl, te, pp, nm, cm, ca, re, sh, is, it, er, co, ex, inn),
      A::slots' = sl, A::tepoch' = te, A::passport' = pp, A::named' = nm, A::cmds' = cm, A::calls' = ca,
      A::replies' = re, A::shown' = sh, A::issued' = is, A::issuedTo' = it, A::era' = er, A::consumed' = co,
      A::executed' = ex, A::intents' = inn, A::broken' = Set(), A::seen' = Set(),
    }
  }

  action drawB = {
    nondet sl = setOfMaps(DEVS, 0.to(P_MAX_NONCE)).oneOf()
    nondet te = EPOCHS.oneOf()
    nondet pp = setOfMaps(P_COMMANDERS, V_ACTIONS.powerset()).oneOf()
    nondet nm = P_COMMANDERS.powerset().oneOf()
    nondet kn = setOfMaps(DEVS, 0.to(P_MAX_NONCE)).oneOf()
    nondet ke = setOfMaps(DEVS, EPOCHS).oneOf()
    nondet ki = setOfMaps(DEVS, 1.to(P_MAX_CALLS + 1)).oneOf()
    nondet pa = setOfMaps(DEVS, Set(false, true)).oneOf()
    nondet pn = setOfMaps(DEVS, NONCES).oneOf()
    nondet pe = setOfMaps(DEVS, EPOCHS).oneOf()
    nondet pte = setOfMaps(DEVS, Set(false, true)).oneOf()
    nondet ptm = setOfMaps(DEVS, Set(false, true)).oneOf()
    nondet re = REPLIES.powerset().oneOf()
    nondet sh = NONCES.powerset().oneOf()
    nondet is = 0.to(P_MAX_NONCE).oneOf()
    nondet it = setOfMaps(NONCES, ISSUES.union(Set(NO_ISSUE))).oneOf()
    nondet er = 0.to(P_MAX_RESETS).oneOf()
    nondet co = NONCES.powerset().oneOf()
    nondet ex = EXECS.powerset().oneOf()
    nondet ip = setOfMaps(EXECS, Set(false, true)).oneOf()
    nondet ii = setOfMaps(EXECS, Set(false, true)).oneOf()
    nondet ia = setOfMaps(EXECS, V_ACTIONS).oneOf()
    nondet ik = setOfMaps(EXECS, KEYS).oneOf()
    nondet ino = setOfMaps(EXECS, NONCES).oneOf()
    nondet iep = setOfMaps(EXECS, EPOCHS).oneOf()
    nondet bodies = setOfMaps(tuples(EXECS, NONCES, EPOCHS), Set(false, true)).oneOf()
    val inn = mkInn(ip, ii, ia, ik, ino, iep)
    val ca = mkCalls(ip, ii, ia, ik, bodies)
    val cm = mkCmds(kn, ke, ki, pa, pn, pe, pte, ptm, ii, ia, ik)
    all {
      structOf(sl, te, pp, nm, cm, ca, re, sh, is, it, er, co, ex, inn),
      B::slots' = sl, B::tepoch' = te, B::passport' = pp, B::named' = nm, B::cmds' = cm, B::calls' = ca,
      B::replies' = re, B::shown' = sh, B::issued' = is, B::issuedTo' = it, B::era' = er, B::consumed' = co,
      B::executed' = ex, B::intents' = inn, B::broken' = Set(), B::seen' = Set(),
    }
  }

  // ----------------------------------------------------------- initial states
  action initStruct = all { A::init, B::init, stage' = 0, mv' = NO_MOVE, matchOk' = true }
  action initSafe = all { drawA, B::init, stage' = 0, mv' = NO_MOVE, matchOk' = true }
  action initPair = all { drawA, drawB, stage' = 0, mv' = NO_MOVE, matchOk' = true }

  // Names run-inductive.ps1 uses for its first, cheap check (Apalache download).
  action modelInit = initStruct
  action modelStep = stepRotate
  val IndInv = structA

  val sameSafety = (viewA == viewB) implies (A::safety iff B::safety)
  val matched = stage != 2 or (matchOk and viewA == viewB)
  // Non-vacuity: expected to be violated (a pair with equal views exists; B answers).
  val witnessPair = viewA != viewB
  val witnessAnswered = stage != 2

  // ------------------------------------------------- A's step, branch by branch
  // O2 runs stepX from initSafe; O4 runs matchX from initPair.
  action pre = all { stage == 0, A::safety }
  action stepAnswer = all { pre, bStay, stage' = 1, matchOk' = true,
    nondet c = DEVS.oneOf() all { A::targetAnswer(c), mv' = { ...NO_MOVE, kind: "answer", c: c } } }
  action stepLearn = all { pre, bStay, stage' = 1, matchOk' = true,
    nondet c = DEVS.oneOf() nondet n = A::shown.union(Set(0)).oneOf()
    all { A::cmdLearn(c, n), mv' = { ...NO_MOVE, kind: "learn", c: c, dn: normNonce(A::slots, c, n) } } }
  action stepMismatch = all { pre, bStay, stage' = 1, matchOk' = true,
    nondet c = DEVS.oneOf() nondet n = A::shown.union(Set(0)).oneOf()
    all { A::cmdMismatch(c, n), mv' = { ...NO_MOVE, kind: "mismatch", c: c, dn: normNonce(A::slots, c, n) } } }
  action stepStart = all { pre, bStay, stage' = 1, matchOk' = true,
    nondet c = DEVS.oneOf() nondet a = V_ACTIONS.oneOf() nondet idem = Set(false, true).oneOf()
    nondet key = KEYS.oneOf()
    all { A::cmdStart(c, a, idem, key), mv' = { ...NO_MOVE, kind: "start", c: c, a: a, idem: idem, key: key } } }
  action stepEpoch = all { pre, bStay, stage' = 1, matchOk' = true,
    nondet c = DEVS.oneOf() nondet e = EPOCHS.oneOf()
    all { A::cmdEpoch(c, e),
          mv' = { ...NO_MOVE, kind: "epoch", c: c, e: e, epTop: A::cmds.get(c).epoch >= TOP_EPOCH } } }
  action stepReply = all { pre, bStay, stage' = 1, matchOk' = true, A::replies != Set(),
    nondet c = DEVS.oneOf() nondet r = A::replies.oneOf()
    all { A::cmdReply(c, r),
          mv' = { ...NO_MOVE, kind: "reply", c: c, dn: normNonce(A::slots, c, r.nextNonce),
                  over: A::cmds.get(c).nextId > P_MAX_CALLS } } }
  action stepChange = all { pre, bStay, stage' = 1, matchOk' = true,
    nondet c = DEVS.oneOf() nondet rs = V_ACTIONS.powerset().oneOf()
    all { A::envChange(c, rs), mv' = { ...NO_MOVE, kind: "change", c: c, rs: rs } } }
  action stepCall = all { pre, bStay, stage' = 1, matchOk' = true, A::calls != Set(),
    nondet x = A::calls.oneOf()
    all { A::targetCall(x),
          mv' = { ...NO_MOVE, kind: "call", c: x.cmd, live: liveCall(A::slots, A::tepoch, x),
                  xv: callView(A::tepoch, A::passport, A::named, A::cmds, A::executed, x) } } }
  action stepReset = all { pre, bStay, stage' = 1, matchOk' = true,
    nondet kind = Set("reset", "reboot").oneOf()
    all { A::targetReset(kind), mv' = { ...NO_MOVE, kind: kind } } }
  action stepRotate = all { pre, bStay, stage' = 1, matchOk' = true, A::targetRotate,
    mv' = { ...NO_MOVE, kind: "rotate" } }

  // --------------------------------------------------------------- B's answer
  // B does nothing when the views already agree; otherwise it takes the step
  // given by the case analysis below. Each guard copies the guard of the
  // corresponding action of calls.qnt under MUTANT = "none", so that B's step
  // is taken exactly when the guard holds; matchOk records it.
  action bNone = all { bStay, matchOk' = false }
  action bAnswer(c: str): bool =
    if (vAllowed(B::named, c) and (B::slots.get(c) != 0 or B::issued < P_MAX_NONCE))
      all { B::targetAnswer(c), matchOk' = true }
    else bNone
  pure def nonceChoices(sl: str -> int, sh: Set[int], c: str, dn: int): Set[int] =
    sh.union(Set(0)).filter(m => normNonce(sl, c, m) == dn)
  action bMismatch(c: str, ms: Set[int]): bool =
    if (ms != Set() and B::cmds.get(c).pending.active)
      all { matchOk' = true, nondet m = ms.oneOf() B::cmdMismatch(c, m) }
    else bNone
  action answer = {
    val k = B::cmds.get(mv.c)
    if (mv.kind == "answer") bAnswer(mv.c)
    else if (mv.kind == "learn") {
      val ms = nonceChoices(B::slots, B::shown, mv.c, mv.dn)
      if (ms != Set() and not(k.pending.active)) all { matchOk' = true, nondet m = ms.oneOf() B::cmdLearn(mv.c, m) }
      else bNone
    }
    else if (mv.kind == "mismatch") bMismatch(mv.c, nonceChoices(B::slots, B::shown, mv.c, mv.dn))
    else if (mv.kind == "start")
      if (not(k.pending.active) and k.nonce != 0 and k.nextId <= P_MAX_CALLS)
        all { B::cmdStart(mv.c, mv.a, mv.idem, mv.key), matchOk' = true }
      else bNone
    else if (mv.kind == "epoch")
      if (not(mv.epTop))
        if (1 <= mv.e and mv.e <= B::tepoch and mv.e > k.epoch) all { B::cmdEpoch(mv.c, mv.e), matchOk' = true }
        else bNone
      else bMismatch(mv.c, Set(0))
    else if (mv.kind == "reply") {
      val rs = B::replies.filter(r => r.cmd == mv.c and r.id == k.pending.call.id
                                      and normNonce(B::slots, mv.c, r.nextNonce) == mv.dn)
      if (rs != Set() and k.pending.active) all { matchOk' = true, nondet r = rs.oneOf() B::cmdReply(mv.c, r) }
      else bMismatch(mv.c, if (mv.over) Set(0) else nonceChoices(B::slots, B::shown, mv.c, mv.dn))
    }
    else if (mv.kind == "change")
      if (B::named.contains(mv.c) and mv.rs.subseteq(B::passport.get(mv.c)) and mv.rs != B::passport.get(mv.c))
        all { B::envChange(mv.c, mv.rs), matchOk' = true }
      else bNone
    else if (mv.kind == "call")
      if (mv.live) {
        val xs = B::calls.filter(y => liveCall(B::slots, B::tepoch, y)
                                      and callView(B::tepoch, B::passport, B::named, B::cmds, B::executed, y) == mv.xv)
        if (xs != Set()) all { matchOk' = true, nondet y = xs.oneOf() B::targetCall(y) }
        else bNone
      } else bAnswer(mv.c)
    else if (mv.kind == "reset" or mv.kind == "reboot")
      if (B::era < P_MAX_RESETS) all { B::targetReset(mv.kind), matchOk' = true }
      else bNone
    else if (mv.kind == "rotate")
      if (B::tepoch < P_MAX_EPOCH) all { B::targetRotate, matchOk' = true }
      else bNone
    else bNone
  }
  action respond = all { stage == 1, aStay, stage' = 2, mv' = mv,
    if (viewA == viewB) all { bStay, matchOk' = true } else answer }
  action matchAnswer = any { all { viewA == viewB, stepAnswer }, respond }
  action matchLearn = any { all { viewA == viewB, stepLearn }, respond }
  action matchMismatch = any { all { viewA == viewB, stepMismatch }, respond }
  action matchStart = any { all { viewA == viewB, stepStart }, respond }
  action matchEpoch = any { all { viewA == viewB, stepEpoch }, respond }
  action matchReply = any { all { viewA == viewB, stepReply }, respond }
  action matchChange = any { all { viewA == viewB, stepChange }, respond }
  action matchCall = any { all { viewA == viewB, stepCall }, respond }
  action matchReset = any { all { viewA == viewB, stepReset }, respond }
  action matchRotate = any { all { viewA == viewB, stepRotate }, respond }
}

module tiny_bisim {
  import bisim(P_COMMANDERS = Set("a"), P_OUTSIDERS = Set(), P_ROOT = "r", P_PRESENCE = Set("a"),
               P_RIGHTS = Map("a" -> Set(1, 2)), P_MAX_NONCE = 4, P_MAX_EPOCH = 3, P_MAX_CALLS = 2,
               P_MAX_RESETS = 1).*
}
