// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 HunterEwok
//
// Call nonce slots of Ciphered Private Bus (verification level V2).
//
// Scope: one target and its commanders; nonce requests, calls, replies, the
// two open refusals ("nonce mismatch" and "stale key epoch") and the
// commander's automatic retries, the host events "reset nonces" and reboot,
// rotation of the target's sealing key epoch, and changes of the target's
// passport. Requirements: R-CALL-1, R-CALL-4..8, R-CALL-13, R-CORE-6;
// property S10.
//
// Abstractions:
// - Signatures and HPKE are perfect: nobody forges a call body, opens a
//   command or a reply, or forges a signed key claim. Nonces are fresh
//   values from a counter: a random 16-byte nonce is not guessed and does not
//   repeat by chance (Section 13.1). The value 0 stands for "no nonce".
// - The network is a pool of every call body and reply ever sent; an
//   adversary delivers any of them to the target or the commander at any
//   time, any number of times, or never. Nonce answers and refusals are
//   unsigned and travel in the open, so the adversary can show a commander
//   any nonce value that ever appeared on the wire, or junk, and can replay
//   any key claim the target ever signed.
// - A call names one action, automatic or confirmation-class; arguments,
//   streams, and result data are not modelled. The halt of a target is the
//   membership model's (R-MEM-10).
// - Processing is instantaneous. Slots live in RAM only, so a power loss
//   between erasing a nonce and executing the action loses the slot anyway;
//   the order of R-CALL-5 is a property of the implementation (storage
//   test), not of this model.
module calls {
  // ---------------------------------------------------------------- parameters
  const COMMANDERS: Set[str]      // devices named as commanders in the target's passport
  const OUTSIDERS: Set[str]       // devices not named there
  const ROOT: str                 // the root device named in the checkpoint
  const PRESENCE: Set[str]        // commanders that hold a user-presence key
  const RIGHTS: str -> Set[int]   // initial rights of each commander in the target's passport
  const MAX_NONCE: int            // nonces the target may issue
  const MAX_EPOCH: int            // highest sealing key epoch of the target
  const MAX_CALLS: int            // calls each commander may start
  const MAX_RESETS: int           // "reset nonces" events and reboots together
  const MUTANT: str               // "none", or the name of a deliberate defect (R-VER-2)

  // --------------------------------------------------------------------- types
  val AUTO = 1
  val CONFIRM = 2
  val ACTIONS = Set(AUTO, CONFIRM)
  val KEYS = Set("device", "presence", "root")
  val DEVICES = COMMANDERS.union(OUTSIDERS).union(Set(ROOT))
  val NONCES = 1.to(MAX_NONCE)

  // A signed call body; `id` names the commander's call (ghost). An
  // automatic retry is another body of the same call.
  type Call = { cmd: str, id: int, idem: bool, act: int, key: str, nonce: int, epoch: int }
  // A reply names the call by the hash of its body (R-CALL-10); a commander
  // takes a reply to any body of its pending call, so the model keeps only
  // the call it belongs to.
  type Reply = { cmd: str, id: int, nextNonce: int, executed: bool }
  type Pending = { active: bool, call: Call, triedEpoch: bool, triedMismatch: bool }
  type Commander = { nonce: int, epoch: int, nextId: int, pending: Pending }
  type Issue = { cmd: str, era: int }
  type Exec = { cmd: str, id: int }

  // ----------------------------------------------------------------- variables
  var slots: str -> int           // target: the nonce slot of each device, 0 for none (RAM)
  var tepoch: int                 // target: current sealing key epoch
  var passport: str -> Set[int]   // target's passport: rights of each named commander
  var named: Set[str]             // target's passport: the named commanders
  var cmds: str -> Commander      // commanders
  var calls: Set[Call]            // pool of call bodies
  var replies: Set[Reply]         // pool of replies
  var shown: Set[int]             // nonce values that appeared in the open
  var issued: int                 // ghost: nonces issued so far
  var issuedTo: int -> Issue      // ghost: to whom and in which era each nonce was issued
  var era: int                    // ghost: resets and reboots so far
  var consumed: Set[int]          // ghost: nonces consumed by a call
  var executed: Set[Exec]         // ghost: calls whose action was executed
  var intents: Exec -> Call       // ghost: the first body of each call, noCall before it starts
  // Monitor: properties of a single step are checked when it is taken, and
  // the name of a violated one is added here.
  var broken: Set[str]
  var seen: Set[str]              // ghost: behaviours reached, for the witnesses

  // ------------------------------------------------------------------- helpers
  pure val noCall: Call = { cmd: "", id: 0, idem: false, act: AUTO, key: "device", nonce: 0, epoch: 0 }
  pure val idle: Pending = { active: false, call: noCall, triedEpoch: false, triedMismatch: false }

  // R-CALL-7: slots only for named commanders and the root device.
  def allowed(c: str): bool = named.contains(c) or c == ROOT
  // R-CALL-4: the root key has the right to every action; any other key has
  // the rights the target's passport gives its device, and the root device
  // is no exception.
  def rightsOf(c: str, key: str): Set[int] = if (key == "root") ACTIONS else if (named.contains(c)) passport.get(c) else Set()

  // R-CALL-4: an automatic action is signed by the device key, a
  // confirmation-class action by the user-presence key; the root key signs
  // anything, and only from the root device.
  pure def keyOk(x: Call): bool =
    (x.key == "root" and x.cmd == ROOT)
      or (x.act == AUTO and x.key == "device")
      or (x.act == CONFIRM and x.key == "presence" and PRESENCE.contains(x.cmd))

  action commit(sl: str -> int, te: int, pp: str -> Set[int], nm: Set[str], cm: str -> Commander, ca: Set[Call],
                re: Set[Reply], sh: Set[int], is: int, it: int -> Issue, er: int, co: Set[int], ex: Set[Exec],
                extra: Set[str], tags: Set[str]): bool = all {
    slots' = sl, tepoch' = te, passport' = pp, named' = nm, cmds' = cm, calls' = ca, replies' = re, shown' = sh,
    issued' = is, issuedTo' = it, era' = er, consumed' = co, executed' = ex, intents' = intents,
    broken' = broken.union(extra), seen' = seen.union(tags),
  }

  // A commander's state changes; everything else stays.
  action setCmd(c: str, k: Commander, ca: Set[Call], tags: Set[str]): bool =
    commit(slots, tepoch, passport, named, cmds.set(c, k), ca, replies, shown, issued, issuedTo, era, consumed,
      executed, Set(), tags)

  // -------------------------------------------------------------- initial state
  action init = all {
    slots' = DEVICES.mapBy(d => 0),
    tepoch' = 1,
    passport' = COMMANDERS.mapBy(c => RIGHTS.get(c)),
    named' = COMMANDERS,
    cmds' = DEVICES.mapBy(d => { nonce: 0, epoch: 1, nextId: 1, pending: idle }),
    calls' = Set(),
    replies' = Set(),
    shown' = Set(),
    issued' = 0,
    issuedTo' = NONCES.mapBy(n => { cmd: "", era: -1 }),
    era' = 0,
    consumed' = Set(),
    executed' = Set(),
    intents' = tuples(DEVICES, 1.to(MAX_CALLS)).map(t => { cmd: t._1, id: t._2 }).mapBy(e => noCall),
    broken' = Set(),
    seen' = Set(),
  }

  // -------------------------------------------------------------------- target
  // A nonce request (R-CALL-1, R-CALL-7): the target answers with the current
  // value of the slot, creating it on the first request.
  action targetAnswer(c: str): bool = all {
    allowed(c) or MUTANT == "slot_for_anyone",
    if (slots.get(c) != 0)
      commit(slots, tepoch, passport, named, cmds, calls, replies, shown.union(Set(slots.get(c))), issued, issuedTo,
        era, consumed, executed, Set(), Set())
    else all {
      issued < MAX_NONCE,
      val n = issued + 1
      commit(slots.set(c, n), tepoch, passport, named, cmds, calls, replies, shown.union(Set(n)), n,
        issuedTo.set(n, { cmd: c, era: era }), era, consumed, executed,
        if (allowed(c)) Set() else Set("slotsKnown"), Set()),
    },
  }

  // A call arrives (R-CALL-4..6, R-CALL-13).
  action targetCall(x: Call): bool = {
    val cur = slots.get(x.cmd)
    if (cur == 0 or x.nonce != cur) {
      // "Nonce mismatch": nothing is executed, the slot does not change, and
      // the refusal carries the current nonce in the open. Without a slot it
      // is the answer to a nonce request: the slot is created first, for a
      // named commander or the root device only (R-CALL-6, R-CALL-7).
      val fresh = issued + 1
      val create = cur == 0 and allowed(x.cmd) and issued < MAX_NONCE
      val change = MUTANT == "mismatch_changes" and cur != 0 and issued < MAX_NONCE
      commit(if (change or create) slots.set(x.cmd, fresh) else slots, tepoch, passport, named, cmds, calls, replies,
        if (change or create) shown.union(Set(fresh)) else if (cur != 0) shown.union(Set(cur)) else shown,
        if (change or create) fresh else issued,
        if (change or create) issuedTo.set(fresh, { cmd: x.cmd, era: era }) else issuedTo, era, consumed, executed,
        if (change) Set("mismatchKeepsSlot") else Set(),
        if (x.nonce != 0 and issuedTo.get(x.nonce).era < era) Set("staleNonce") else Set())
    } else if (x.epoch < tepoch - 1) {
      // "Stale key epoch": the target cannot open the command; the nonce is
      // not consumed. The signed claim of the current epoch is in the open.
      commit(slots, tepoch, passport, named, cmds, calls, replies, shown, issued, issuedTo, era, consumed,
        executed, Set(), Set("staleEpoch"))
    } else {
      // The command is opened, the nonce is consumed, and the reply carries
      // the next nonce. The action runs only with the right and the key.
      // The mutant revoked_calls checks the passport the target started with;
      // the mutant root_device_all_rights gives every key of the root device
      // every right; the mutant root_key_any_device accepts the root key from
      // any device.
      val stale = MUTANT == "revoked_calls" and COMMANDERS.contains(x.cmd)
      val ok = (allowed(x.cmd) or stale)
        and ((if (stale) RIGHTS.get(x.cmd) else if (MUTANT == "root_device_all_rights" and x.cmd == ROOT) ACTIONS else rightsOf(x.cmd, x.key)).contains(x.act) or MUTANT == "no_right_check")
        and (keyOk(x) or (MUTANT == "presence_not_required" and x.key == "device")
             or (MUTANT == "root_key_any_device" and x.key == "root"))
      val keep = MUTANT == "no_erase"
      val nxt = if (keep) cur else if (issued < MAX_NONCE) issued + 1 else 0
      val fresh = not(keep) and nxt != 0
      val e = { cmd: x.cmd, id: x.id }
      val iss = issuedTo.get(x.nonce)
      val violations =
        if (not(ok)) Set() else
          (if (not(x.idem) and executed.contains(e)) Set("atMostOnce") else Set())
            .union(if (iss.cmd == x.cmd and iss.era == era and not(consumed.contains(x.nonce))) Set()
                   else Set("freshNonce"))
            .union(if (allowed(x.cmd) and rightsOf(x.cmd, x.key).contains(x.act) and keyOk(x)) Set()
                   else Set("permitted"))
      commit(slots.set(x.cmd, nxt), tepoch, passport, named, cmds, calls,
        replies.union(Set({ cmd: x.cmd, id: x.id, nextNonce: nxt, executed: ok })), shown, if (fresh) nxt else issued,
        if (fresh) issuedTo.set(nxt, { cmd: x.cmd, era: era }) else issuedTo, era, consumed.union(Set(x.nonce)),
        if (ok) executed.union(Set(e)) else executed, violations,
        if (not(ok)) Set("noRight")
        else Set("executed").union(if (x.epoch != intents.get(e).epoch) Set("epochRetryExecuted") else Set())
          .union(if (x.nonce != intents.get(e).nonce) Set("mismatchRetryExecuted") else Set()))
    }
  }

  // "Reset nonces" (R-CALL-8) and reboot (R-CORE-6) erase every slot.
  action targetReset(kind: str): bool = all {
    era < MAX_RESETS,
    val keep = (kind == "reset" and MUTANT == "reset_keeps_slots") or (kind == "reboot" and MUTANT == "reboot_keeps_slots")
    commit(if (keep) slots else DEVICES.mapBy(d => 0), tepoch, passport, named, cmds, calls, replies, shown, issued,
      issuedTo, era + 1, consumed, executed, Set(), Set(kind)),
  }

  // The target's sealing key moves to the next epoch.
  action targetRotate = all {
    tepoch < MAX_EPOCH,
    commit(slots, tepoch + 1, passport, named, cmds, calls, replies, shown, issued, issuedTo, era, consumed,
      executed, Set(), Set()),
  }

  // A new passport of the target: a commander loses a right or is no longer
  // named (revocation or change of rights, R-MEM-3). The slot of a device
  // that is no longer named is erased in the same event (R-CALL-7); the
  // mutant keep_revoked_slot keeps it.
  action envChange(c: str, rs: Set[int]): bool = all {
    named.contains(c),
    rs.subseteq(passport.get(c)),
    rs != passport.get(c),
    if (rs == Set())
      commit(if (MUTANT == "keep_revoked_slot") slots else slots.set(c, 0), tepoch, passport, named.exclude(Set(c)),
        cmds, calls, replies, shown, issued, issuedTo, era, consumed, executed, Set(), Set())
    else
      commit(slots, tepoch, passport.set(c, rs), named, cmds, calls, replies, shown, issued, issuedTo, era,
        consumed, executed, Set(), Set()),
  }

  // ----------------------------------------------------------------- commander
  // The commander takes a nonce from an answer, which the adversary may also
  // forge with any value seen in the open.
  action cmdLearn(c: str, n: int): bool = all {
    shown.contains(n) or n == 0,
    not(cmds.get(c).pending.active),
    setCmd(c, { ...cmds.get(c), nonce: n }, calls, Set()),
  }

  // Start a call with the nonce held. A device that is not entitled may
  // still send one; the target must refuse it.
  action cmdStart(c: str, action_: int, idem: bool, key: str): bool = {
    val k = cmds.get(c)
    all {
      not(k.pending.active),
      k.nonce != 0,
      k.nextId <= MAX_CALLS,
      val x = { cmd: c, id: k.nextId, idem: idem, act: action_, key: key, nonce: k.nonce, epoch: k.epoch }
      all {
        cmds' = cmds.set(c, { ...k, nonce: 0, nextId: k.nextId + 1,
                              pending: { active: true, call: x, triedEpoch: false, triedMismatch: false } }),
        calls' = calls.union(Set(x)),
        intents' = intents.set({ cmd: c, id: k.nextId }, x),
        slots' = slots, tepoch' = tepoch, passport' = passport, named' = named, replies' = replies,
        shown' = shown, issued' = issued, issuedTo' = issuedTo, era' = era, consumed' = consumed,
        executed' = executed, broken' = broken, seen' = seen,
      },
    }
  }

  // A reply to the pending call, or to an earlier body of it, ends the call.
  action cmdReply(c: str, r: Reply): bool = {
    val k = cmds.get(c)
    all {
      r.cmd == c,
      k.pending.active,
      r.id == k.pending.call.id,
      setCmd(c, { ...k, nonce: r.nextNonce, pending: idle }, calls, Set("done")),
    }
  }

  // A "nonce mismatch" refusal for the pending call, which the adversary may
  // forge with any value seen in the open (R-CALL-13). Only a call that the
  // application marked idempotent, and that is not confirmation-class, is
  // retried, once; otherwise the outcome is reported as unknown (L7).
  action cmdMismatch(c: str, n: int): bool = {
    val k = cmds.get(c)
    val p = k.pending
    all {
      shown.contains(n) or n == 0,
      p.active,
      val retry = n != 0 and (not(p.triedMismatch) or MUTANT == "retry_twice")
        and (p.call.act != CONFIRM or MUTANT == "retry_confirmation_mismatch")
        and (p.call.idem or MUTANT == "retry_on_mismatch")
      if (retry) {
        val x = { ...p.call, nonce: n }
        commit(slots, tepoch, passport, named, cmds.set(c, { ...k, nonce: 0, pending: { ...p, call: x, triedMismatch: true } }),
          calls.union(Set(x)), replies, shown, issued, issuedTo, era, consumed, executed,
          (if (p.call.act == CONFIRM) Set("noConfirmRetry") else Set())
            .union(if (p.triedMismatch) Set("oneRetryPerKind") else Set()), Set())
      } else
        setCmd(c, { ...k, nonce: n, pending: idle }, calls, Set("unknown")),
    }
  }

  // A signed claim of the target's key epoch, carried by a "stale key epoch"
  // refusal; the adversary may replay any claim the target ever signed. It is
  // accepted only with an epoch above the known one; then the pending call is
  // retried once with the same nonce and the new key, except a
  // confirmation-class call, which needs a new confirmation (R-CALL-13).
  action cmdEpoch(c: str, e: int): bool = {
    val k = cmds.get(c)
    val p = k.pending
    all {
      1 <= e, e <= tepoch,
      e > k.epoch or (MUTANT == "accept_any_epoch" and e != k.epoch),
      val bad = if (e <= k.epoch) Set("epochGrows") else Set()
      if (not(p.active))
        commit(slots, tepoch, passport, named, cmds.set(c, { ...k, epoch: e }), calls, replies, shown, issued,
          issuedTo, era, consumed, executed, bad, Set())
      else if ((not(p.triedEpoch) or MUTANT == "retry_twice") and (p.call.act != CONFIRM or MUTANT == "retry_confirmation")) {
        val x = { ...p.call, epoch: e }
        commit(slots, tepoch, passport, named,
          cmds.set(c, { ...k, epoch: e, pending: { ...p, call: x, triedEpoch: true } }), calls.union(Set(x)),
          replies, shown, issued, issuedTo, era, consumed, executed,
          bad.union(if (p.call.act == CONFIRM) Set("noConfirmRetry") else Set())
            .union(if (p.triedEpoch) Set("oneRetryPerKind") else Set()), Set())
      } else
        commit(slots, tepoch, passport, named, cmds.set(c, { ...k, epoch: e, pending: idle }), calls, replies,
          shown, issued, issuedTo, era, consumed, executed, bad, Set("unknown")),
    }
  }

  // ---------------------------------------------------------------------- step
  action step = any {
    nondet c = DEVICES.oneOf()
    any {
      targetAnswer(c),
      nondet n = shown.union(Set(0)).oneOf()
      any { cmdLearn(c, n), cmdMismatch(c, n) },
      nondet a = ACTIONS.oneOf()
      nondet idem = Set(false, true).oneOf()
      nondet key = KEYS.oneOf()
      cmdStart(c, a, idem, key),
      nondet e = 1.to(MAX_EPOCH).oneOf()
      cmdEpoch(c, e),
      all { replies != Set(), nondet r = replies.oneOf() cmdReply(c, r) },
      nondet rs = ACTIONS.powerset().oneOf()
      envChange(c, rs),
    },
    all { calls != Set(), nondet x = calls.oneOf() targetCall(x) },
    nondet kind = Set("reset", "reboot").oneOf()
    targetReset(kind),
    targetRotate,
  }

  // ---------------------------------------------------------------- invariants
  // S10, R-CALL-5: a call that is not idempotent is executed at most once,
  // also across automatic retries.
  val atMostOnce = not(broken.contains("atMostOnce"))
  // S10, R-CALL-1, R-CALL-8, R-CORE-6: an action runs only over a nonce the
  // target issued to this commander since the latest reset or reboot, and
  // not consumed before.
  val freshNonce = not(broken.contains("freshNonce"))
  // S10, R-CALL-4: only with the right under the target's current passport,
  // and with the key the action class requires.
  val permitted = not(broken.contains("permitted"))
  // S14, R-CALL-7: slots only for named commanders and the root device, also
  // after a commander stops being named.
  val slotsKnown = not(broken.contains("slotsKnown")) and DEVICES.forall(d => slots.get(d) != 0 implies allowed(d))
  // S14, R-CALL-6: a mismatch does not change the slot.
  val mismatchKeepsSlot = not(broken.contains("mismatchKeepsSlot"))
  // R-CALL-13: a confirmation-class call is never retried automatically,
  // after either open refusal.
  val noConfirmRetry = not(broken.contains("noConfirmRetry"))
  // R-CALL-13: per call, at most one automatic retry per kind of open refusal.
  val oneRetryPerKind = not(broken.contains("oneRetryPerKind"))
  // R-CALL-13: the key epoch a commander knows never goes back, so a replayed
  // old claim cannot make it seal to a retired key.
  val epochGrows = not(broken.contains("epochGrows"))

  val safety = atMostOnce and freshNonce and permitted and slotsKnown and mismatchKeepsSlot and noConfirmRetry
    and oneRetryPerKind and epochGrows

  // ------------------------------------------------- non-vacuity witnesses
  // Each witness is expected to be VIOLATED: the behaviour is reachable.
  val witnessExecuted = not(seen.contains("executed"))
  val witnessNoRight = not(seen.contains("noRight"))
  val witnessUnknown = not(seen.contains("unknown"))
  val witnessStaleNonce = not(seen.contains("staleNonce"))
  val witnessEpochRetryExecuted = not(seen.contains("epochRetryExecuted"))
  val witnessMismatchRetryExecuted = not(seen.contains("mismatchRetryExecuted"))
}
