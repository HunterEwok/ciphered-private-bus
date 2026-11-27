// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 HunterEwok
//
// Inductive invariant of the external relay model (R-VER-3). Apalache proves
// three facts, each for all reachable states and not only up to a bound:
//   1. init implies IndInv               (--init=modelInit --invariant=IndInv, 0 steps)
//   2. IndInv and one step imply IndInv   (--init=indInit --invariant=IndInv, 1 step)
//   3. IndInv implies safety              (--init=indInit --invariant=modelSafety, 0 steps)
// with --step=modelStep. indInit picks an arbitrary state of the bounded
// types that satisfies IndInv, so fact 2 starts from every such state,
// reachable or not.
module inductive {
  const I_MEMBERS: Set[str]
  const I_FIRST: Set[str]
  const I_MAX_E: int
  const I_MAX_RD: int
  const I_MAX_GEN: int
  const I_MAX_EVENTS: int
  import extrelay(MEMBERS = I_MEMBERS, FIRST = I_FIRST, MAX_E = I_MAX_E, MAX_RD = I_MAX_RD, MAX_GEN = I_MAX_GEN,
                  MAX_EVENTS = I_MAX_EVENTS, MUTANT = "none").* from "./extrelay"

  // ------------------------------------------------------------ bounded types
  val GENS = 1.to(MAX_GEN)
  val RDS = 0.to(MAX_RD - 1)
  val ALIASES = tuples(GENS, RDS, 1.to(MAX_E)).map(t => { g: t._1, rd: t._2, e: t._3 })
  val ALIASES0 = ALIASES.union(Set(NONE))
  val ACCESSES = tuples(ALIASES, MEMBERS).map(p => { g: p._1.g, rd: p._1.rd, e: p._1.e, dev: p._2 })
  // A ticket number grows with each admission and once more on closing.
  val NOS = 1.to(MAX_EVENTS + 2)
  val CPNOS = 1.to(MAX_EVENTS + 1)
  val OWNERS = MEMBERS.union(Set("root"))
  val TAGS = Set("revoke", "unlist", "admit", "rootChange", "newRootDevice", "close", "returned", "bridgeFetched",
                 "upload")

  // (g1, rd1) is not before (g2, rd2): the root device of a checkpoint.
  pure def rdGE(g1: int, rd1: int, g2: int, rd2: int): bool = g1 > g2 or (g1 == g2 and rd1 >= rd2)
  pure def rdGT(g1: int, rd1: int, g2: int, rd2: int): bool = g1 > g2 or (g1 == g2 and rd1 > rd2)

  def indInvOf(r: Root, n: str -> Node, ac: Set[Access], fg: Set[Access], t: Alias -> Ticket, ls: Alias -> int,
               b: Set[Bridge], o: Set[Obj], ev: int, es: Alias -> Set[str], sc: Alias -> Alias, un: Set[Alias],
               tf: Set[str], bk: Set[str], sn: Set[str]): bool = {
    val c = cur(r)
    and {
      // the Root: every event is one checkpoint
      1 <= r.g, r.g <= MAX_GEN, 0 <= r.rd, r.rd < MAX_RD, 1 <= r.e, r.e <= MAX_E,
      r.valid.subseteq(r.admitted), r.admitted.subseteq(MEMBERS), FIRST.subseteq(r.admitted),
      0 <= ev, ev <= MAX_EVENTS, r.cpNo == ev + 1, 0 <= r.stage, r.stage <= 3,
      r.stolen == (r.rd > 0), ALIASES0.contains(r.prev), ALIASES0.contains(r.succ),
      // an epoch change in progress: the old alias is open, the new one is
      // the current alias, bridged from the old one at a listed relay
      r.stage != 0 implies and {
        r.succ == c, ALIASES.contains(r.prev), r.prev.rd == r.rd, later(c, r.prev),
        t.keys().contains(r.prev), not(t.get(r.prev).closed), es.get(c) == r.valid,
      },
      (r.stage == 1 or r.stage == 2) implies and {
        r.listed, sc.keys().contains(r.prev), sc.get(r.prev) == c, not(t.keys().contains(c)),
      },
      r.stage == 1 implies b.forall(x => x.a != r.prev),
      r.stage == 3 implies (if (r.listed) sc.keys().contains(r.prev) and sc.get(r.prev) == c
                            else un.contains(r.prev)),
      (r.listed and (r.stage == 0 or r.stage == 3)) implies (t.keys().contains(c) and not(t.get(c).closed)),
      not(r.listed) implies (not(t.keys().contains(c)) and r.stage != 1 and r.stage != 2),
      r.listed implies un == Set(),
      // tickets: the relay holds the latest one of each alias it knows
      t.keys().subseteq(ALIASES), ls.keys() == t.keys(),
      t.keys().forall(a => val tk = t.get(a) and {
        not(later(a, c)), NOS.contains(tk.no), tk.members.subseteq(MEMBERS),
        tk.no <= ev + 1 + (if (tk.closed) 1 else 0), tk.closed implies a != c, ls.get(a) == tk.no,
      }),
      // members at the start of each epoch; the current epoch's are valid
      es.keys().subseteq(ALIASES), es.keys().contains(c),
      es.keys().forall(a => not(later(a, c)) and es.get(a).subseteq(MEMBERS)),
      es.get(c).subseteq(r.valid),
      // bridged aliases, and aliases closed when the relay left the list
      sc.keys().subseteq(t.keys()), un.subseteq(t.keys()),
      sc.keys().forall(a => and {
        es.keys().contains(sc.get(a)), later(sc.get(a), a), not(later(sc.get(a), c)), not(un.contains(a)),
      }),
      // bridges: one bridging per alias, at the checkpoint of its new epoch
      b.forall(x => and {
        sc.keys().contains(x.a), x.next == sc.get(x.a), MEMBERS.contains(x.to), es.get(x.next).contains(x.to),
        t.get(x.a).members.contains(x.to), CPNOS.contains(x.cpNo), x.cpNo <= r.cpNo,
        rdGE(r.g, r.rd, x.next.g, x.next.rd), x.cpNo == r.cpNo implies (x.next.g == r.g and x.next.rd == r.rd),
      }),
      b.forall(x => b.forall(y => (x.a == y.a implies x.cpNo == y.cpNo)
        and (x.cpNo >= y.cpNo implies rdGE(x.next.g, x.next.rd, y.next.g, y.next.rd)))),
      // nodes: checkpoints the Root issued, relay access objects of their root
      // device, and only epochs up to the current one
      n.keys() == MEMBERS,
      MEMBERS.forall(d => val x = n.get(d) and {
        0 <= x.cpNo, x.cpNo <= r.cpNo, 1 <= x.cpGen, x.cpGen <= MAX_GEN, 0 <= x.cpRd, x.cpRd < MAX_RD,
        rdGE(r.g, r.rd, x.cpGen, x.cpRd), x.cpNo == r.cpNo implies (x.cpGen == r.g and x.cpRd == r.rd),
        x.keys.subseteq(ALIASES), x.keys.forall(a => not(later(a, c))), ALIASES0.contains(x.ra),
        x.ra != NONE implies (x.keys.contains(x.ra) and x.ra.g == x.cpGen and x.ra.rd == x.cpRd),
        x.keys.contains(c) implies r.valid.contains(d),
        x.cpNo == 0 implies (x.cpGen == 1 and x.cpRd == 0),
        b.forall(y => (x.cpNo >= y.cpNo implies rdGE(x.cpGen, x.cpRd, y.next.g, y.next.rd))
          and (x.cpNo <= y.cpNo implies rdGE(y.next.g, y.next.rd, x.cpGen, x.cpRd))),
      }),
      // relay access objects: those of the current epoch go to valid members;
      // forged ones are of a replaced root device
      ac.subseteq(ACCESSES), fg.subseteq(ac),
      ac.forall(x => not(later(aliasOf(x), c))),
      ac.forall(x => (aliasOf(x) == c and not(fg.contains(x))) implies r.valid.contains(x.dev)),
      fg.forall(x => x.rd < r.rd),
      // stored objects: under open aliases, from their true uploader
      o.forall(x => and {
        t.keys().contains(x.a), not(t.get(x.a).closed), OWNERS.contains(x.by), x.from == x.by,
        x.root == (x.by == "root"),
      }),
      // R-REL-19, strengthened to the bridged alias before its closing ticket
      sc.keys().forall(a => val nx = sc.get(a)
        (t.get(a).closed or (a == r.prev and (r.stage == 2 or r.stage == 3))) implies
          t.get(a).members.forall(d => val x = n.get(d)
            not(es.get(nx).contains(d)) or x.keys.exists(k => k == nx or later(k, nx))
            or rdGT(x.cpGen, x.cpRd, nx.g, nx.rd)
            or b.exists(y => y.a == a and y.to == d and y.next == nx))),
      tf.subseteq(MEMBERS), bk == Set(), sn.subseteq(TAGS),
    }
  }

  val IndInv = indInvOf(root, nodes, access, forged, tickets, lastSent, bridges, objs, events, epochStart, succ,
                        unlisted, tookForged, broken, seen)

  action modelInit = init
  action modelStep = step
  val modelSafety = safety

  // The branches of step, one by one. Together they are exactly step.
  action stepAdmit = { nondet d = MEMBERS.oneOf() rootAdmit(d) }
  action stepRevoke = { nondet d = MEMBERS.oneOf() rootRevoke(d) }
  action stepUnlist = rootUnlist
  action stepRootChange = rootChange
  action stepNewRootDevice = newRootDevice
  action stepBridges = rootBridges
  action stepRegister = rootRegister
  action stepClose = rootClose
  action stepForge = { nondet e = 1.to(MAX_E).oneOf() nondet d = MEMBERS.oneOf() adversaryForge(e, d) }
  action stepRelayTicket = all {
    tickets != Map(), nondet a = tickets.keys().oneOf() nondet no = 1.to(MAX_EVENTS + 1).oneOf()
    nondet m = tickets.get(a).members.powerset().oneOf() relayTicket(a, no, m),
  }
  action stepNodeCheckpoint = { nondet d = MEMBERS.oneOf() nodeCheckpoint(d) }
  action stepNodeAccess = { nondet d = MEMBERS.oneOf() nondet x = access.oneOf() nodeAccess(d, x) }
  action stepNodeBridge = all {
    bridges != Set(), nondet d = MEMBERS.oneOf() nondet b = bridges.oneOf() nodeBridge(d, b.to, b),
  }
  action stepNodeUpload = {
    nondet d = MEMBERS.oneOf() nondet as = MEMBERS.oneOf() nondet a = nodes.get(d).keys.union(Set(NONE)).oneOf()
    nondet ro = Set(false, true).oneOf() nodeUpload(d, as, a, ro)
  }

  // ------------------------------------------- an arbitrary state of IndInv
  // Maps are drawn total over ALIASES or MEMBERS and cut to a drawn domain;
  // bridges and stored objects are drawn as the pairs that name them, the
  // other fields following from the invariant (one bridging per alias, an
  // object names its uploader).
  action indInit = {
    nondet g = GENS.oneOf()
    nondet rd = RDS.oneOf()
    nondet e = 1.to(MAX_E).oneOf()
    nondet valid = MEMBERS.powerset().oneOf()
    nondet admitted = MEMBERS.powerset().oneOf()
    nondet listed = Set(false, true).oneOf()
    nondet stage = 0.to(3).oneOf()
    nondet prev = ALIASES0.oneOf()
    nondet rsucc = ALIASES0.oneOf()
    nondet ev = 0.to(MAX_EVENTS).oneOf()
    nondet nCp = setOfMaps(MEMBERS, 0.to(MAX_EVENTS + 1)).oneOf()
    nondet nGen = setOfMaps(MEMBERS, GENS).oneOf()
    nondet nRd = setOfMaps(MEMBERS, RDS).oneOf()
    nondet nRa = setOfMaps(MEMBERS, ALIASES0).oneOf()
    nondet nKeys = setOfMaps(MEMBERS, ALIASES.powerset()).oneOf()
    nondet ac = ACCESSES.powerset().oneOf()
    nondet fg = ACCESSES.powerset().oneOf()
    nondet tDom = ALIASES.powerset().oneOf()
    nondet tNo = setOfMaps(ALIASES, NOS).oneOf()
    nondet tMem = setOfMaps(ALIASES, MEMBERS.powerset()).oneOf()
    nondet tClosed = setOfMaps(ALIASES, Set(false, true)).oneOf()
    nondet bPairs = tuples(ALIASES, MEMBERS).powerset().oneOf()
    nondet bCp = setOfMaps(ALIASES, CPNOS).oneOf()
    nondet oPairs = tuples(ALIASES, OWNERS).powerset().oneOf()
    nondet esDom = ALIASES.powerset().oneOf()
    nondet esAll = setOfMaps(ALIASES, MEMBERS.powerset()).oneOf()
    nondet scDom = ALIASES.powerset().oneOf()
    nondet scAll = setOfMaps(ALIASES, ALIASES).oneOf()
    nondet un = ALIASES.powerset().oneOf()
    nondet tf = MEMBERS.powerset().oneOf()
    nondet sn = TAGS.powerset().oneOf()
    val r = { g: g, rd: rd, e: e, valid: valid, admitted: admitted, cpNo: ev + 1, listed: listed, stage: stage,
              prev: prev, succ: rsucc, stolen: rd > 0 }
    val n = MEMBERS.mapBy(d => { cpNo: nCp.get(d), cpGen: nGen.get(d), cpRd: nRd.get(d), ra: nRa.get(d),
                                 keys: nKeys.get(d) })
    val t = tDom.mapBy(a => { no: tNo.get(a), members: tMem.get(a), closed: tClosed.get(a) })
    val ls = tDom.mapBy(a => tNo.get(a))
    val b = bPairs.map(p => { a: p._1, to: p._2, next: scAll.get(p._1), cpNo: bCp.get(p._1) })
    val o = oPairs.map(p => { a: p._1, from: p._2, by: p._2, root: p._2 == "root" })
    val es = esDom.mapBy(a => esAll.get(a))
    val sc = scDom.mapBy(a => scAll.get(a))
    all {
      indInvOf(r, n, ac, fg, t, ls, b, o, ev, es, sc, un, tf, Set(), sn),
      root' = r, nodes' = n, access' = ac, forged' = fg, tickets' = t, lastSent' = ls, bridges' = b, objs' = o,
      events' = ev, epochStart' = es, succ' = sc, unlisted' = un, tookForged' = tf, broken' = Set(), seen' = sn,
    }
  }
}

// The size of tiny.
module tiny_ind {
  import inductive(I_MEMBERS = Set("a", "b"), I_FIRST = Set("a"), I_MAX_E = 2, I_MAX_RD = 2, I_MAX_GEN = 2,
                   I_MAX_EVENTS = 3).*
}

// The size of small, for a long run (R-VER-3).
module small_ind {
  import inductive(I_MEMBERS = Set("a", "b", "c"), I_FIRST = Set("a", "b"), I_MAX_E = 3, I_MAX_RD = 2, I_MAX_GEN = 2,
                   I_MAX_EVENTS = 4).*
}
