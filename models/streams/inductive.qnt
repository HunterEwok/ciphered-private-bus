// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 HunterEwok
//
// Inductive invariant of the streams model (R-VER-3). Apalache proves three
// facts, each for all reachable states and not only up to a bound:
//   1. init implies IndInv               (--init=modelInit --invariant=IndInv, 0 steps)
//   2. IndInv and one step imply IndInv   (--init=indInit --invariant=IndInv, 1 step)
//   3. IndInv implies safety              (--init=indInit --invariant=modelSafety, 0 steps)
// with --step=modelStep. indInit picks an arbitrary state of the bounded
// types that satisfies IndInv, so fact 2 starts from every such state,
// reachable or not.
module inductive {
  const I_MAX_STREAMS: int
  const I_MAX_CALLS: int
  const I_MAX_NO: int
  const I_MAX_CREDIT: int
  const I_MAX_EVENTS: int
  import streams(MAX_STREAMS = I_MAX_STREAMS, MAX_CALLS = I_MAX_CALLS, MAX_NO = I_MAX_NO,
                 MAX_CREDIT = I_MAX_CREDIT, MAX_EVENTS = I_MAX_EVENTS, MUTANT = "none").* from "./streams"

  // ------------------------------------------------------------ bounded types
  val KS = 1.to(MAX_CALLS)
  val NOS = 1.to(MAX_NO)
  val CREDITS = 0.to(MAX_CREDIT)
  // Credit a side can have received or given in all: the initial credit and
  // one credit chunk per chunk number.
  val GMAX = MAX_CREDIT * (MAX_NO + 1)
  val DIRS = Set("c2t", "t2c")
  val KINDS = Set("data", "credit", "end")
  val TAGS = Set("tooMany", "staleDropped", "orderClose", "creditAdded", "orderedData", "creditClose",
                 "lossyGap", "resetClosed", "overrun")

  // Field checks. They replace c.in(CALLS) and the like: membership of a
  // record in a big set costs Apalache the size of that set per element.
  pure def isCall(c: Call): bool = and {
    1 <= c.k, c.k <= MAX_CALLS, MODES.contains(c.mode), 0 <= c.credit, c.credit <= MAX_CREDIT,
    c.mode == "lossy" implies c.credit == 0,
  }
  pure def isReply(r: Reply): bool = and {
    1 <= r.k, r.k <= MAX_CALLS, 0 <= r.sid, r.sid <= MAX_STREAMS, 0 <= r.credit, r.credit <= MAX_CREDIT,
    if (r.ok) r.sid >= 1 else (r.sid == 0 and r.credit == 0),
  }
  pure def isChunk(c: Chunk): bool = and {
    DIRS.contains(c.dir), 1 <= c.sid, c.sid <= MAX_STREAMS, 1 <= c.k, c.k <= MAX_CALLS,
    1 <= c.no, c.no <= MAX_NO, KINDS.contains(c.kind), 0 <= c.credit, c.credit <= MAX_CREDIT,
    if (c.kind == "credit") c.credit >= 1 else c.credit == 0,
  }

  val PSLOTS = tuples(DIRS, KS, NOS)
  pure def callOf(mo: int -> str, cr: int -> int, k: int): Call =
    { k: k, mode: mo.get(k), credit: if (mo.get(k) == "lossy") 0 else cr.get(k) }

  pure def csum(s: Set[Chunk]): int = s.fold(0, (a, c) => a + c.credit)
  pure def dirOf(p: str): str = if (p == "C") "c2t" else "t2c"
  pure def inDir(p: str): str = if (p == "C") "t2c" else "c2t"

  // ------------------------------------------------------------------- parts
  def callsOk(cs: Set[Call], nk: int): bool = and {
    cs.forall(c => c.k < nk),
    cs.forall(c1 => cs.forall(c2 => c1.k == c2.k implies c1 == c2)),
  }

  def repliesOk(rs: Set[Reply], cs: Set[Call], d: Set[int]): bool = and {
    rs.forall(r => d.contains(r.k) and cs.exists(c => c.k == r.k and (c.mode == "lossy" implies r.credit == 0))),
    rs.forall(r1 => rs.forall(r2 => r1.k == r2.k implies r1 == r2)),
  }

  // The reply that opened a side, and the call it answers.
  def opened(rs: Set[Reply], cs: Set[Call], sid: int, s: Side): bool =
    rs.exists(r => r.k == s.k and r.ok and r.sid == sid) and cs.exists(c => c.k == s.k and c.mode == s.mode)

  def sideOk(p: str, sid: int, s: Side, n: Node, ns: str -> Node, rs: Set[Reply], cs: Set[Call],
             pl: Set[Chunk]): bool = and {
    opened(rs, cs, sid, s),
    // R-KEY-9: every chunk this side sent has a number below its next one
    pl.forall(c => (c.dir == dirOf(p) and c.k == s.k) implies c.no < s.next),
    // the highest number taken is the number of a chunk of the peer
    s.high >= 1 implies pl.exists(c => c.dir == inDir(p) and c.k == s.k and c.no == s.high),
    if (s.mode == "ordered") and {
      s.recvCredit + s.recvd == s.granted,
      s.sendCredit + s.sent == s.got,
      // credit given: the initial credit and every credit chunk this side sent
      s.granted == (if (p == "T") rs.fold(0, (a, r) => if (r.k == s.k) r.credit else a)
                    else cs.fold(0, (a, c) => if (c.k == s.k) c.credit else a))
                   + csum(pl.filter(c => c.dir == dirOf(p) and c.k == s.k and c.kind == "credit")),
      // credit received: the initial credit and the credit chunks taken, which
      // are exactly the peer's credit chunks numbered up to the highest taken
      s.got == (if (p == "T") cs.fold(0, (a, c) => if (c.k == s.k) c.credit else a)
                else rs.fold(0, (a, r) => if (r.k == s.k) r.credit else a))
               + csum(pl.filter(c => c.dir == inDir(p) and c.k == s.k and c.kind == "credit" and c.no <= s.high)),
    } else and {
      s.sendCredit == 0, s.recvCredit == 0, s.got == 0, s.granted == 0,
    },
  }

  def nodeOk(p: str, ns: str -> Node, pe: int -> Call, d: Set[int], rs: Set[Reply], cs: Set[Call],
             pl: Set[Chunk], nk: int): bool = {
    val n = ns.get(p)
    and {
      n.streams.keys().subseteq(IDS),
      n.halted implies n.streams.keys() == Set(),
      n.peerRevoked implies n.streams.keys() == Set(),
      n.streams.keys().forall(i => sideOk(p, i, n.streams.get(i), n, ns, rs, cs, pl)),
      p == "T" implies n.streams.keys().forall(i => d.contains(n.streams.get(i).k)),
      p == "C" implies n.streams.keys().forall(i => not(pe.keys().contains(n.streams.get(i).k))),
    }
  }

  def poolOk(pl: Set[Chunk], pe: int -> Call, d: Set[int], rs: Set[Reply], cs: Set[Call]): bool = and {
    pl.forall(c => rs.exists(r => r.k == c.k and r.ok and r.sid == c.sid)),
    pl.forall(c => cs.exists(x => x.k == c.k and (c.kind == "credit" implies x.mode == "ordered"))),
    pl.forall(c => c.dir == "c2t" implies not(pe.keys().contains(c.k))),
    pl.forall(c1 => pl.forall(c2 => (c1.dir == c2.dir and c1.k == c2.k and c1.no == c2.no) implies c1 == c2)),
  }

  def indInvOf(ns: str -> Node, pe: int -> Call, d: Set[int], cs: Set[Call], rs: Set[Reply], pl: Set[Chunk],
               nk: int, ev: int, b: Set[str], s: Set[str]): bool = and {
    ns.keys() == PARTIES,
    1 <= nk, nk <= MAX_CALLS + 1, 0 <= ev, ev <= MAX_EVENTS,
    cs.forall(c => isCall(c)), rs.forall(r => isReply(r)), pl.forall(c => isChunk(c)), d.subseteq(KS),
    pe.keys().subseteq(KS),
    pe.keys().forall(k => cs.contains(pe.get(k)) and pe.get(k).k == k),
    d.forall(k => k < nk),
    callsOk(cs, nk),
    repliesOk(rs, cs, d),
    poolOk(pl, pe, d, rs, cs),
    PARTIES.forall(p => nodeOk(p, ns, pe, d, rs, cs, pl, nk)),
    b == Set(),
    s.subseteq(TAGS),
  }

  val IndInv = indInvOf(nodes, pending, done, calls, replies, pool, nextK, events, broken, seen)

  action modelInit = init
  action modelStep = step
  val modelSafety = safety

  // The branches of step, one by one. Together they are exactly step.
  action stepCall = commanderCall
  action stepOpen = all { calls != Set(), nondet c = calls.oneOf() targetOpen(c) }
  action stepReply = all { replies != Set(), nondet r = replies.oneOf() commanderReply(r) }
  action stepSend = { nondet p = PARTIES.oneOf() send(p) }
  action stepOverrun = { nondet p = PARTIES.oneOf() overrun(p) }
  action stepReceive = { nondet p = PARTIES.oneOf() all { pool != Set(), nondet ch = pool.oneOf() receive(p, ch) } }
  action stepReset = { nondet p = PARTIES.oneOf() resetNonces(p) }
  action stepHalt = { nondet p = PARTIES.oneOf() halt(p) }
  action stepRevoke = { nondet p = PARTIES.oneOf() learnRevoked(p) }
  action stepReboot = { nondet p = PARTIES.oneOf() reboot(p) }
  action stepLinkDown = linkDown

  // ------------------------------------------- an arbitrary state of IndInv
  action indInit = {
    nondet opens = setOfMaps(PARTIES, IDS.powerset()).oneOf()
    nondet fk = setOfMaps(PARTIES, setOfMaps(IDS, KS)).oneOf()
    nondet fmode = setOfMaps(PARTIES, setOfMaps(IDS, MODES)).oneOf()
    nondet fnext = setOfMaps(PARTIES, setOfMaps(IDS, 1.to(MAX_NO + 1))).oneOf()
    nondet fhigh = setOfMaps(PARTIES, setOfMaps(IDS, 0.to(MAX_NO))).oneOf()
    nondet fsc = setOfMaps(PARTIES, setOfMaps(IDS, 0.to(GMAX))).oneOf()
    nondet frc = setOfMaps(PARTIES, setOfMaps(IDS, CREDITS)).oneOf()
    nondet fidle = setOfMaps(PARTIES, setOfMaps(IDS, Set(false, true))).oneOf()
    nondet fgot = setOfMaps(PARTIES, setOfMaps(IDS, 0.to(GMAX))).oneOf()
    nondet fgr = setOfMaps(PARTIES, setOfMaps(IDS, 0.to(GMAX))).oneOf()
    nondet fsent = setOfMaps(PARTIES, setOfMaps(IDS, 0.to(MAX_NO))).oneOf()
    nondet frecvd = setOfMaps(PARTIES, setOfMaps(IDS, 0.to(MAX_NO))).oneOf()
    nondet halts = setOfMaps(PARTIES, Set(false, true)).oneOf()
    nondet revs = setOfMaps(PARTIES, Set(false, true)).oneOf()
    // Calls and replies are unique per call number and chunks per (direction,
    // call, number) (callsOk, repliesOk, poolOk), so each is drawn from one
    // slot per key instead of from all subsets of every possible record.
    nondet pk = KS.powerset().oneOf()
    nondet d = KS.powerset().oneOf()
    nondet cIn = setOfMaps(KS, Set(false, true)).oneOf()
    nondet cMode = setOfMaps(KS, MODES).oneOf()
    nondet cCr = setOfMaps(KS, CREDITS).oneOf()
    nondet rIn = setOfMaps(KS, Set(false, true)).oneOf()
    nondet rSid = setOfMaps(KS, 0.to(MAX_STREAMS)).oneOf()
    nondet rCr = setOfMaps(KS, CREDITS).oneOf()
    nondet rOk = setOfMaps(KS, Set(false, true)).oneOf()
    nondet pIn = setOfMaps(PSLOTS, Set(false, true)).oneOf()
    nondet pSid = setOfMaps(PSLOTS, IDS).oneOf()
    nondet pKind = setOfMaps(PSLOTS, KINDS).oneOf()
    nondet pCr = setOfMaps(PSLOTS, CREDITS).oneOf()
    val cs = KS.filter(k => cIn.get(k)).map(k => callOf(cMode, cCr, k))
    val rs = KS.filter(k => rIn.get(k)).map(k => { k: k, sid: rSid.get(k), credit: rCr.get(k), ok: rOk.get(k) })
    val pl = PSLOTS.filter(t => pIn.get(t))
      .map(t => { dir: t._1, sid: pSid.get(t), k: t._2, no: t._3, kind: pKind.get(t), credit: pCr.get(t) })
    nondet nk = 1.to(MAX_CALLS + 1).oneOf()
    nondet ev = 0.to(MAX_EVENTS).oneOf()
    nondet sn = TAGS.powerset().oneOf()
    val ns = PARTIES.mapBy(p => {
      streams: opens.get(p).mapBy(i => {
        k: fk.get(p).get(i), mode: fmode.get(p).get(i), next: fnext.get(p).get(i), high: fhigh.get(p).get(i),
        sendCredit: fsc.get(p).get(i), recvCredit: frc.get(p).get(i), idle: fidle.get(p).get(i),
        got: fgot.get(p).get(i), granted: fgr.get(p).get(i), sent: fsent.get(p).get(i), recvd: frecvd.get(p).get(i),
      }),
      halted: halts.get(p), peerRevoked: revs.get(p),
    })
    val pe = pk.mapBy(k => callOf(cMode, cCr, k))
    all {
      indInvOf(ns, pe, d, cs, rs, pl, nk, ev, Set(), sn),
      nodes' = ns, pending' = pe, done' = d, calls' = cs, replies' = rs, pool' = pl,
      nextK' = nk, events' = ev, broken' = Set(), seen' = sn,
    }
  }
}

// The size of tiny.
module tiny_ind {
  import inductive(I_MAX_STREAMS = 1, I_MAX_CALLS = 2, I_MAX_NO = 2, I_MAX_CREDIT = 1, I_MAX_EVENTS = 2).*
}

// The size of small, for a long run (R-VER-3).
module small_ind {
  import inductive(I_MAX_STREAMS = 2, I_MAX_CALLS = 3, I_MAX_NO = 3, I_MAX_CREDIT = 2, I_MAX_EVENTS = 3).*
}
