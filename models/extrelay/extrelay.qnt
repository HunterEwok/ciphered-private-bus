// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 HunterEwok
//
// External relays of Ciphered Private Bus (verification level V2).
//
// Scope: one external relay of one bus, the relay epochs of the root device,
// relay access objects, tickets, bridges under a closed alias, relay hello
// admission, Root-signed objects, and members that upload and read under
// their aliases. Requirements: R-REL-13, R-REL-15, R-REL-18, R-REL-19,
// R-REL-3 and R-REL-5 for aliases, R-REL-6 for external relays; Appendix B,
// Section B.10 (relay access, ticket rules 1..5, relay hello, `Relayed` field
// `from` and rule 1); properties S5, S14, S18.
//
// Abstractions:
// - Checkpoints are the honest sequence of the Root, as the membership model
//   proves it (models/membership): one number, the set of valid members,
//   the root device it names, the root generation, and whether this relay
//   is in the `relays` list. A node takes the Root's latest checkpoint at
//   any time, or stays behind. Equivocated checkpoints halt a node there and
//   are not repeated here.
// - A bus alias is named by (generation, root device, epoch): different
//   triples are unrelated strings for the relay (Appendix B, Section B.10,
//   derivations), which is the Tamarin relay link model's to prove. A node
//   knows the relay epoch secret of an alias exactly when it accepted a
//   relay access object of that epoch; it then computes every alias of the
//   epoch. Only the member a link seed was sealed to holds its link key, so
//   a relay hello proves the member, not only its alias, unless the relay
//   skips the tree check (mutant "hello_no_tree").
// - Relay access objects travel on member links and member relays, as a set
//   that the adversary delivers to their addressee at any time, any number
//   of times, or never; a bridge travels through the relay. A relay access
//   object is sealed to its addressee: no other node opens it.
// - The key of a replaced root device is stolen: the adversary signs relay
//   access objects of that root device with any epoch (the probe of
//   R-REL-13). The period secret and the root key are not stolen; tickets
//   are the Root's only.
// - What members store is one kind of data object per alias and uploader;
//   which grants and publications, and the quotas, are the relay model's
//   (models/relay), with aliases in place of devices and channel labels.
// - The root device holds its predecessor's relay state on a root change,
//   so it bridges and closes the old alias; a new root device after a lost
//   one does not (B.10 rule 5), and members reach it through member links.
//   The optional epoch change on the time event or at the owner's request is
//   not modelled: it is the same epoch change without a checkpoint.
module extrelay {
  // ---------------------------------------------------------------- parameters
  const MEMBERS: Set[str]  // devices that may be members; the root device is not among them
  const FIRST: Set[str]    // members at the start
  const MAX_E: int         // highest relay epoch, also of a forged relay access object
  const MAX_RD: int        // root devices: 0 .. MAX_RD - 1
  const MAX_GEN: int       // root generations: 1 .. MAX_GEN
  const MAX_EVENTS: int    // Root events (admit, revoke, unlist, root change, new root device)
  const MUTANT: str        // "none", or the name of a deliberate defect (R-VER-2)

  // --------------------------------------------------------------------- types
  // A bus alias at the relay: one per root generation, root device and epoch.
  type Alias = { g: int, rd: int, e: int }
  // A relay access object (t = 13), sealed to `dev`.
  type Access = { g: int, rd: int, e: int, dev: str }
  type Ticket = { no: int, members: Set[str], closed: bool }
  // A bridge under the closed alias `a`: the relay access object of `next`
  // for `to`, kept with the Root's checkpoint number `cpNo` at the time and,
  // after a root change, the root change record and checkpoint that let the
  // addressee verify it (R-REL-19).
  type Bridge = { a: Alias, to: str, next: Alias, cpNo: int }
  // A stored object: `from` is the alias it names as uploader, `by` the
  // member that uploaded it; "root" is the root device.
  type Obj = { a: Alias, from: str, by: str, root: bool }
  // `ra.e == 0`: no relay access object held.
  type Node = { cpNo: int, cpGen: int, cpRd: int, ra: Alias, keys: Set[Alias] }
  type Root = {
    g: int, rd: int, e: int, valid: Set[str], admitted: Set[str], cpNo: int, listed: bool,
    // epoch change at the relay: 0 none, 1 bridges due, 2 new ticket due,
    // 3 closing ticket due; `prev` the alias to close, `succ` the new one
    stage: int, prev: Alias, succ: Alias, stolen: bool,
  }

  pure val NONE: Alias = { g: 0, rd: 0, e: 0 }
  pure def aliasOf(x: Access): Alias = { g: x.g, rd: x.rd, e: x.e }
  pure def cur(r: Root): Alias = { g: r.g, rd: r.rd, e: r.e }

  // ----------------------------------------------------------------- variables
  var root: Root
  var nodes: str -> Node
  var access: Set[Access]       // relay access objects on member links (pool)
  var forged: Set[Access]       // ghost: those the stolen key signed
  var tickets: Alias -> Ticket  // what the relay holds
  var lastSent: Alias -> int    // the greatest ticket number the Root sent for each alias
  var bridges: Set[Bridge]
  var objs: Set[Obj]
  var events: int
  // ghost: the members of each epoch when it began, the alias each bridged
  // alias was bridged to, aliases closed because the relay left the list,
  // and nodes that took a forged object
  var epochStart: Alias -> Set[str]
  var succ: Alias -> Alias
  var unlisted: Set[Alias]
  var tookForged: Set[str]
  // Monitor: properties of a single step are checked when it is taken, and
  // the name of a violated one is added here.
  var broken: Set[str]
  var seen: Set[str]            // ghost: behaviours that happened (witnesses)

  // ------------------------------------------------------------------- helpers
  // B.10 relay access rule: of the generation and the root device of the
  // node's checkpoint, and from the same root device with an epoch not
  // smaller than the one held. Mutant "no_rd_check": the root device is not
  // checked; mutant "epoch_only_order": objects are ordered by epoch alone.
  pure def acceptable(n: Node, x: Access): bool =
    (x.g == n.cpGen or MUTANT == "epoch_only_order")
    and (x.rd == n.cpRd or MUTANT == "no_rd_check" or MUTANT == "epoch_only_order")
    and (n.ra.e == 0 or x.e >= n.ra.e
         or (MUTANT != "epoch_only_order" and (x.g != n.ra.g or x.rd != n.ra.rd)))

  // `x` is a later alias than `y`: a later generation, a later root device
  // of the same generation, or a later epoch of the same root device.
  pure def later(x: Alias, y: Alias): bool =
    x.g > y.g or (x.g == y.g and (x.rd > y.rd or (x.rd == y.rd and x.e > y.e)))

  pure def take(n: Node, x: Access): Node =
    { ...n, ra: aliasOf(x), keys: n.keys.union(Set(aliasOf(x))) }

  // The relay admits a hello of member `d` claiming the alias of `as` under
  // alias `a`: `d` computes the alias (it knows the epoch secret), the pair
  // of alias and link key is a leaf of the latest ticket's tree, and the
  // authentication is signed with the link key of `as`, which only `as`
  // holds. Mutant "hello_no_tree": the relay checks only that the alias is
  // listed, so any member that knows the secret can claim it.
  def admits(d: str, as: str, a: Alias): bool = all {
    nodes.get(d).keys.contains(a),
    tickets.keys().contains(a),
    tickets.get(a).members.contains(as),
    as == d or MUTANT == "hello_no_tree",
  }

  // --------------------------------------------------------------- transitions
  action commit(r2: Root, n2: str -> Node, ac2: Set[Access], t2: Alias -> Ticket, s2: Alias -> int,
                b2: Set[Bridge], o2: Set[Obj], es2: Alias -> Set[str], un2: Set[Alias],
                extra: Set[str], tags: Set[str]): bool = all {
    root' = r2, nodes' = n2, access' = ac2, tickets' = t2, lastSent' = s2, bridges' = b2, objs' = o2,
    epochStart' = es2, unlisted' = un2, succ' = succ,
    forged' = forged, events' = events, tookForged' = tookForged,
    broken' = broken.union(extra), seen' = seen.union(tags),
  }

  action init = {
    val a1 = { g: 1, rd: 0, e: 1 }
    val t1 = { no: 1, members: FIRST, closed: false }
    all {
      root' = { g: 1, rd: 0, e: 1, valid: FIRST, admitted: FIRST, cpNo: 1, listed: true,
                stage: 0, prev: NONE, succ: NONE, stolen: false },
      nodes' = MEMBERS.mapBy(d => if (FIRST.contains(d))
                 { cpNo: 1, cpGen: 1, cpRd: 0, ra: a1, keys: Set(a1) }
               else { cpNo: 0, cpGen: 1, cpRd: 0, ra: NONE, keys: Set() }),
      access' = FIRST.map(d => { g: 1, rd: 0, e: 1, dev: d }),
      forged' = Set(),
      tickets' = Map(a1 -> t1),
      lastSent' = Map(a1 -> 1),
      bridges' = Set(),
      objs' = Set({ a: a1, from: "root", by: "root", root: true }),
      events' = 0,
      epochStart' = Map(a1 -> FIRST),
      succ' = Map(),
      unlisted' = Set(),
      tookForged' = Set(),
      broken' = Set(),
      seen' = Set(),
    }
  }

  // A new checkpoint of the Root with members `v2`, the relay listed or not
  // (`l2`), the same root device. R-REL-13: a new epoch MUST begin when the
  // checkpoint clears a passport bit or changes the `relays` list; mutant
  // "no_new_epoch": not on a cleared bit. With a new epoch the root device
  // issues the relay access object of the new epoch to every valid member;
  // at a relay that stays listed it then bridges, registers and closes
  // (stages 1..3, B.10 rule 4), at a relay that leaves the list it only
  // closes (stage 3, no bridges; mutant "unlisted_bridges": it bridges).
  action checkpoint(v2: Set[str], l2: bool, cleared: bool, tag: str): bool = {
    val r = root
    val newEpoch = (cleared and MUTANT != "no_new_epoch") or l2 != r.listed
    val s = { g: r.g, rd: r.rd, e: r.e + 1 }
    all {
      r.stage == 0, events < MAX_EVENTS,
      not(newEpoch) or r.e < MAX_E,
      events' = events + 1,
      forged' = forged, tookForged' = tookForged,
      nodes' = nodes, objs' = objs, bridges' = bridges,
      if (newEpoch) all {
        root' = { ...r, e: r.e + 1, valid: v2, cpNo: r.cpNo + 1, listed: l2,
                  stage: if (not(r.listed)) 0 else if (l2 or MUTANT == "unlisted_bridges") 1 else 3,
                  prev: cur(r), succ: s },
        access' = access.union(v2.map(d => { g: s.g, rd: s.rd, e: s.e, dev: d })),
        epochStart' = epochStart.put(s, v2),
        unlisted' = if (r.listed and not(l2)) unlisted.union(Set(cur(r))) else unlisted,
        succ' = if (r.listed and l2) succ.put(cur(r), s) else succ,
        tickets' = tickets, lastSent' = lastSent,
      } else all {
        root' = { ...r, valid: v2, cpNo: r.cpNo + 1 },
        access' = access, epochStart' = epochStart, unlisted' = unlisted, succ' = succ,
        tickets' = tickets, lastSent' = lastSent,
      },
      broken' = broken.union(if (cleared and not(newEpoch)) Set("newEpochOnClear") else Set()),
      seen' = seen.union(Set(tag)),
    }
  }

  // Admission during the epoch: the member enters the tree with a ticket of
  // a greater number (B.10 rule 2) and gets the current relay access object.
  action rootAdmit(d: str): bool = {
    val r = root
    val a = cur(r)
    val t = { ...tickets.get(a), no: lastSent.get(a) + 1, members: tickets.get(a).members.union(Set(d)) }
    all {
      r.stage == 0, events < MAX_EVENTS, not(r.admitted.contains(d)),
      events' = events + 1,
      root' = { ...r, valid: r.valid.union(Set(d)), admitted: r.admitted.union(Set(d)), cpNo: r.cpNo + 1 },
      access' = access.union(Set({ g: a.g, rd: a.rd, e: a.e, dev: d })),
      tickets' = if (r.listed) tickets.put(a, t) else tickets,
      lastSent' = if (r.listed) lastSent.put(a, t.no) else lastSent,
      epochStart' = epochStart, succ' = succ,
      nodes' = nodes, objs' = objs, bridges' = bridges, unlisted' = unlisted,
      forged' = forged, tookForged' = tookForged, broken' = broken, seen' = seen.union(Set("admit")),
    }
  }

  action rootRevoke(d: str): bool = all {
    root.valid.contains(d),
    checkpoint(root.valid.exclude(Set(d)), root.listed, true, "revoke"),
  }

  action rootUnlist: bool = all { root.listed, checkpoint(root.valid, false, false, "unlist") }

  // A root change with the same root device, which keeps the relay state:
  // epoch 1 of the new generation, bridged and closed like any epoch change.
  action rootChange: bool = {
    val r = root
    val s = { g: r.g + 1, rd: r.rd, e: 1 }
    all {
      r.stage == 0, events < MAX_EVENTS, r.g < MAX_GEN,
      events' = events + 1,
      root' = { ...r, g: s.g, e: 1, cpNo: r.cpNo + 1, stage: if (r.listed) 1 else 0, prev: cur(r), succ: s },
      access' = access.union(r.valid.map(d => { g: s.g, rd: s.rd, e: 1, dev: d })),
      epochStart' = epochStart.put(s, r.valid),
      succ' = if (r.listed) succ.put(cur(r), s) else succ,
      nodes' = nodes, objs' = objs, bridges' = bridges, tickets' = tickets, lastSent' = lastSent,
      unlisted' = unlisted, forged' = forged, tookForged' = tookForged,
      broken' = broken, seen' = seen.union(Set("rootChange")),
    }
  }

  // A checkpoint that names a new root device, after the old one was lost
  // (R-MEM-17, B.10 rule 5): it starts epoch 1, registers its alias, and
  // does not bridge or close the old aliases. The old root device's key is
  // stolen.
  action newRootDevice: bool = {
    val r = root
    val s = { g: r.g, rd: r.rd + 1, e: 1 }
    val t = { no: 1, members: r.valid, closed: false }
    all {
      r.stage == 0, events < MAX_EVENTS, r.rd + 1 < MAX_RD,
      events' = events + 1,
      root' = { ...r, rd: s.rd, e: 1, cpNo: r.cpNo + 1, stolen: true },
      access' = access.union(r.valid.map(d => { g: s.g, rd: s.rd, e: 1, dev: d })),
      epochStart' = epochStart.put(s, r.valid), succ' = succ,
      tickets' = if (r.listed) tickets.put(s, t) else tickets,
      lastSent' = if (r.listed) lastSent.put(s, 1) else lastSent,
      objs' = if (r.listed) objs.union(Set({ a: s, from: "root", by: "root", root: true })) else objs,
      nodes' = nodes, bridges' = bridges, unlisted' = unlisted, forged' = forged,
      tookForged' = tookForged, broken' = broken, seen' = seen.union(Set("newRootDevice")),
    }
  }

  // Stage 1: under the old alias, a bridge for each member of the old tree
  // that stays valid (R-REL-19). Mutant "no_bridges": none; mutant
  // "bridge_to_revoked": also for the revoked.
  action rootBridges: bool = {
    val r = root
    val old = tickets.get(r.prev).members
    val dests = if (MUTANT == "bridge_to_revoked") old else old.intersect(r.valid)
    all {
      r.stage == 1,
      commit({ ...r, stage: if (r.listed) 2 else 3 }, nodes, access, tickets, lastSent,
             if (MUTANT == "no_bridges") bridges
             else bridges.union(dests.map(d => { a: r.prev, to: d, next: r.succ, cpNo: r.cpNo })),
             objs, epochStart, unlisted, Set(), Set()),
    }
  }

  // Stage 2: the ticket of the new alias, and the Root-signed objects under it.
  action rootRegister: bool = {
    val r = root
    val t = { no: 1, members: r.valid, closed: false }
    all {
      r.stage == 2,
      commit({ ...r, stage: 3 }, nodes, access, tickets.put(r.succ, t), lastSent.put(r.succ, 1),
             bridges, objs.union(Set({ a: r.succ, from: "root", by: "root", root: true })),
             epochStart, unlisted, Set(), Set()),
    }
  }

  // Stage 3: the closing ticket (B.10 rule 3). The relay deletes everything
  // under the alias except the bridges; mutant "keep_on_close": it keeps the
  // members' objects.
  action rootClose: bool = {
    val r = root
    val t = { ...tickets.get(r.prev), no: lastSent.get(r.prev) + 1, closed: true }
    all {
      r.stage == 3,
      commit({ ...r, stage: 0 }, nodes, access, tickets.put(r.prev, t), lastSent.put(r.prev, t.no),
             bridges,
             if (MUTANT == "keep_on_close") objs.filter(o => o.a != r.prev or not(o.root))
             else objs.filter(o => o.a != r.prev),
             epochStart, unlisted, Set(), Set("close")),
    }
  }

  // The stolen key of a replaced root device signs a relay access object of
  // its root device with any epoch, for any member.
  action adversaryForge(e: int, d: str): bool = {
    val x = { g: root.g, rd: root.rd - 1, e: e, dev: d }
    all {
      root.stolen,
      not(forged.contains(x)),
      access' = access.union(Set(x)), forged' = forged.union(Set(x)),
      root' = root, nodes' = nodes, tickets' = tickets, lastSent' = lastSent, bridges' = bridges, objs' = objs,
      events' = events, epochStart' = epochStart, succ' = succ, unlisted' = unlisted, tookForged' = tookForged,
      broken' = broken, seen' = seen,
    }
  }

  // An earlier ticket of alias `a` arrives again (B.10 rule 1): number `no`
  // below the one held, members of the alias then (members only join an
  // alias, so a subset of those held), not closing. The relay takes a ticket
  // only with a greater number, and never after a closing ticket. Mutant
  // "ticket_rollback": it takes the earlier one.
  action relayTicket(a: Alias, no: int, members: Set[str]): bool = {
    val held = tickets.get(a)
    val x = { no: no, members: members, closed: false }
    all {
      1 <= no, no < held.no, members.subseteq(held.members),
      (x.no > held.no and not(held.closed)) or MUTANT == "ticket_rollback",
      commit(root, nodes, access, tickets.put(a, x), lastSent, bridges, objs, epochStart, unlisted,
             Set(), Set()),
    }
  }

  // A node takes the Root's latest checkpoint. One that names another root
  // device or another generation makes it drop the relay access object it
  // holds (R-REL-13); mutant "epoch_only_order": it keeps it.
  action nodeCheckpoint(d: str): bool = {
    val n = nodes.get(d)
    val other = root.rd != n.cpRd or root.g != n.cpGen
    all {
      n.cpNo < root.cpNo,
      commit(root, nodes.set(d, { ...n, cpNo: root.cpNo, cpGen: root.g, cpRd: root.rd,
                                  ra: if (other and MUTANT != "epoch_only_order") NONE else n.ra }),
             access, tickets, lastSent, bridges, objs, epochStart, unlisted, Set(), Set()),
    }
  }

  // A node accepts a relay access object addressed to it, delivered on a
  // member link.
  action nodeAccess(d: str, x: Access): bool = {
    val n = nodes.get(d)
    all {
      x.dev == d, acceptable(n, x), n.ra != aliasOf(x),
      root' = root, nodes' = nodes.set(d, take(n, x)), access' = access, forged' = forged,
      tickets' = tickets, lastSent' = lastSent, bridges' = bridges, objs' = objs, events' = events,
      epochStart' = epochStart, succ' = succ, unlisted' = unlisted,
      tookForged' = if (forged.contains(x)) tookForged.union(Set(d)) else tookForged,
      broken' = broken,
      seen' = seen.union(if (tookForged.contains(d) and x.rd == root.rd and not(forged.contains(x)))
                           Set("returned") else Set()),
    }
  }

  // A node, after a relay hello under a closed alias, fetches the bridge
  // addressed to the alias it claims; the relay deletes it once served. The
  // relay access object inside opens only for its addressee. The node first
  // takes the checkpoint served with the bridge, if it is newer, so that a
  // node asleep through a root change can verify the relay access object of
  // the new generation; mutant "bridge_without_records": the bridge carries
  // no checkpoint or root change record.
  action nodeBridge(d: str, as: str, b: Bridge): bool = {
    val n0 = nodes.get(d)
    val newer = n0.cpNo < b.cpNo and MUTANT != "bridge_without_records"
    val other = b.next.rd != n0.cpRd or b.next.g != n0.cpGen
    val n = if (newer) { ...n0, cpNo: b.cpNo, cpGen: b.next.g, cpRd: b.next.rd, ra: if (other) NONE else n0.ra }
            else n0
    val x = { g: b.next.g, rd: b.next.rd, e: b.next.e, dev: b.to }
    all {
      b.to == as, admits(d, as, b.a), tickets.get(b.a).closed,
      commit(root,
             if (d != as) nodes else if (acceptable(n, x)) nodes.set(d, take(n, x)) else nodes.set(d, n),
             access, tickets, lastSent, bridges.exclude(Set(b)), objs, epochStart, unlisted,
             Set(), Set("bridgeFetched")),
    }
  }

  // A node uploads under an open alias as the alias it claims (R-REL-15,
  // R-REL-16; `Relayed` field `from` equals the alias of the link). A
  // Root-signed object is accepted only from the root device's alias
  // (R-REL-18); mutant "member_root_obj": also from a member.
  action nodeUpload(d: str, as: str, a: Alias, rootObj: bool): bool = all {
    admits(d, as, a), not(tickets.get(a).closed),
    not(rootObj) or MUTANT == "member_root_obj",
    commit(root, nodes, access, tickets, lastSent, bridges, objs.union(Set({ a: a, from: as, by: d, root: rootObj })),
           epochStart, unlisted, Set(), Set("upload")),
  }

  action step = any {
    nondet d = MEMBERS.oneOf() rootAdmit(d),
    nondet d = MEMBERS.oneOf() rootRevoke(d),
    rootUnlist,
    rootChange,
    newRootDevice,
    rootBridges,
    rootRegister,
    rootClose,
    nondet e = 1.to(MAX_E).oneOf() nondet d = MEMBERS.oneOf() adversaryForge(e, d),
    all { tickets != Map(), nondet a = tickets.keys().oneOf() nondet no = 1.to(MAX_EVENTS + 1).oneOf()
      nondet m = tickets.get(a).members.powerset().oneOf() relayTicket(a, no, m) },
    nondet d = MEMBERS.oneOf() nodeCheckpoint(d),
    nondet d = MEMBERS.oneOf() nondet x = access.oneOf() nodeAccess(d, x),
    all { bridges != Set(), nondet d = MEMBERS.oneOf() nondet b = bridges.oneOf() nodeBridge(d, b.to, b) },
    nondet d = MEMBERS.oneOf() nondet as = MEMBERS.oneOf() nondet a = nodes.get(d).keys.union(Set(NONE)).oneOf()
      nondet ro = Set(false, true).oneOf() nodeUpload(d, as, a, ro),
  }

  // ---------------------------------------------------------------- properties
  // S5, S18, R-REL-13, R-REL-19: a device that is not a valid member does not
  // know the relay epoch secret of the current epoch, whatever path it took:
  // relay access objects go to valid members only, a new epoch follows every
  // revocation, and bridges go to members that stay valid.
  val revokedNoCurrent = MEMBERS.forall(d =>
    root.valid.contains(d) or not(nodes.get(d).keys.contains(cur(root))))

  // R-REL-13: a node holds a relay access object only of the root device and
  // the generation of its checkpoint, so a replaced root device's key, with
  // any epoch, cannot keep it away from the new root device's relays.
  val accessOfNamedRoot = MEMBERS.forall(d => val n = nodes.get(d)
    n.ra.e == 0 or (n.ra.rd == n.cpRd and n.ra.g == n.cpGen))

  // R-REL-19: under a bridged alias that is closed, every member of its tree
  // that is a member of the epoch it was bridged to knows that epoch or a
  // later one, has a checkpoint of a later root device (whose access it
  // takes on its member links), or still has its bridge: no member of the
  // next epoch is stranded.
  val bridgeForEveryMember = succ.keys().forall(a => val nx = succ.get(a)
    not(tickets.get(a).closed) or tickets.get(a).members.forall(d => val n = nodes.get(d)
      not(epochStart.get(nx).contains(d)) or n.keys.exists(k => k == nx or later(k, nx))
      or later({ g: n.cpGen, rd: n.cpRd, e: 0 }, { ...nx, e: 0 })
      or bridges.exists(b => b.a == a and b.to == d and b.next == nx)))

  // R-REL-19: a revoked device receives no bridge, and an alias closed
  // because the relay left the list carries none.
  val bridgesOnlyToMembers = bridges.forall(b =>
    epochStart.keys().contains(b.next) and epochStart.get(b.next).contains(b.to) and not(unlisted.contains(b.a)))

  // B.10 rule 3, R-REL-6: a closed alias holds nothing but bridges.
  val closedHoldsOnlyBridges = objs.forall(o => not(tickets.keys().contains(o.a)) or not(tickets.get(o.a).closed))

  // R-REL-18: Root-signed objects come only from the root device.
  val rootObjectsFromRoot = objs.forall(o => not(o.root) or o.by == "root")

  // R-REL-15, `Relayed` field `from`: a stored object names its true uploader.
  val uploaderIsLinkAlias = objs.forall(o => o.from == o.by)

  // B.10 rules 1 and 3: the relay holds the ticket with the greatest number
  // the Root sent for each alias, so a closed alias stays closed.
  val ticketIsLatest = tickets.keys().forall(a => tickets.get(a).no == lastSent.get(a))

  // Every property checked on a step.
  val newEpochOnClear = not(broken.contains("newEpochOnClear"))

  val safety = revokedNoCurrent and accessOfNamedRoot and bridgeForEveryMember and bridgesOnlyToMembers
    and closedHoldsOnlyBridges and rootObjectsFromRoot and uploaderIsLinkAlias and ticketIsLatest
    and newEpochOnClear

  // ------------------------------------------------- non-vacuity witnesses
  // Each witness is expected to be VIOLATED: the violation shows that the
  // behaviour is reachable, so the safety checks above are not vacuous.
  val witnessBridgeFetched = not(seen.contains("bridgeFetched"))
  val witnessRevokedAndClosed = not(seen.contains("revoke") and seen.contains("close"))
  val witnessReturned = not(seen.contains("returned"))
  val witnessUnlisted = not(seen.contains("unlist") and seen.contains("close"))
  val witnessRootChangeBridged = not(MEMBERS.exists(d => nodes.get(d).ra.g == 2 and nodes.get(d).ra.e == 1
                                       and bridges.forall(b => b.to != d) and seen.contains("bridgeFetched")
                                       and seen.contains("rootChange")))
  val witnessAdmitted = not(seen.contains("admit") and seen.contains("upload"))
}
