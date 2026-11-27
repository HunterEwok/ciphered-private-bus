// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 HunterEwok
//
// Channel keys and retention of Ciphered Private Bus (verification level V2).
//
// Scope: one source and one channel; the channel key and its rotation, key
// grants, publication numbers reserved in blocks, the recipient's window and
// retention depth, the clearing publication, and reboots of the source and the
// readers. Requirements: R-CH-5..13, R-CORE-5, R-REL-11; properties
// S5, S12, S16 (grant side).
//
// Abstractions:
// - Signatures and the key commitment are perfect, and HPKE sealing works: a
//   reader can open exactly the grants made to it, and nobody can forge a
//   publication or a grant. The network and any relay are a pool of every
//   publication and grant ever made; any reader may receive any of them at any
//   time, any number of times. This is a relay that behaves arbitrarily
//   (R-REL-11) except that it cannot forge.
// - Membership is reduced to the set of devices that are valid readers under
//   the source's checkpoint: a device leaves it (revocation, or the
//   application removes it as a reader) or joins it once. A removed device
//   keeps running and keeps what it has (R-MEM-16).
// - A key is named by its generation and by a ghost identity `kid` that is new
//   for every key ever created, so two different keys with one generation are
//   visible.
// - Processing is instantaneous: a reader erases the previous key as soon as
//   it accepts the next one (R-CH-7 with no unprocessed publications left).
// - Data, blobs, padding, and channel 0 are not modelled; a publication is
//   either data or the clearing publication without data.
// - Key requests (R-CH-18), the source's own retained publications, and the
//   holder's resend on hello (R-CH-11) only speed up delivery; in the pool
//   every grant and publication is always available, so they add no
//   behaviour to the safety model.
module channels {
  // ---------------------------------------------------------------- parameters
  const DEVICES: Set[str]   // possible readers (the source is not one of them)
  const NO_READ: Set[str]   // devices whose passport has no read right
  const LATE: Set[str]      // devices that start outside the readers and may join once
  const MAX_GEN: int        // highest key generation
  const MAX_NO: int         // highest publication number
  const MAX_DEPTH: int      // highest retention depth
  const BLOCK: int          // publication numbers reserved per storage write (R-CH-8)
  const MUTANT: str         // "none", or the name of a deliberate defect (R-VER-2)

  // --------------------------------------------------------------------- types
  type Pub = { gen: int, kid: int, no: int, depth: int, empty: bool }
  type Grant = { gen: int, kid: int, reader: str }

  type Source = {
    gen: int,              // persisted: generation of the current key, 0 before the first
    kid: int,              // ghost identity of the current key
    keyOk: bool,           // the current key is held (it may not survive a reboot)
    granted: Set[str],     // readers granted the current key
    nextNo: int,           // next publication number to hand out
    reserved: int,         // persisted: upper bound of the reserved block of numbers
    mustRotate: bool,      // persisted: the key must be rotated before the next publication
  }

  type Reader = {
    gen: int,              // persisted: generation of the held key, 0 for none
    kid: int,              // ghost identity of the held key, 0 for none
    hiGen: int,            // persisted: highest accepted generation
    hiNo: int,             // persisted: highest accepted publication number
    floor: int,            // persisted: window floor; the window is [floor, hiNo]
    depth: int,            // persisted: depth of the latest accepted publication
    retained: Set[Pub],    // retained publications; refilled after a reboot
  }

  type Pool = { pubs: Set[Pub], grants: Set[Grant] }

  // ----------------------------------------------------------------- variables
  var source: Source
  var readers: str -> Reader
  var members: Set[str]      // valid readers under the source's checkpoint
  var gone: Set[str]         // ghost: devices that left the readers
  var joined: Set[str]       // ghost: late devices that joined
  var made: int               // ghost: number of keys ever created
  var pool: Pool
  // Monitor: properties of a single step are checked when it is taken, and
  // the name of a violated one is added here.
  var broken: Set[str]
  var seen: Set[str]         // ghost: behaviours reached, for the witnesses

  // ------------------------------------------------------------------- helpers
  pure def maxNo(s: Set[Pub]): int = s.fold(0, (m, p) => if (p.no > m) p.no else m)
  pure def minNo(s: Set[Pub], dflt: int): int = s.fold(dflt, (m, p) => if (p.no < m) p.no else m)

  // The n publications with the highest numbers (R-CH-11).
  pure def trim(s: Set[Pub], n: int): Set[Pub] =
    if (MUTANT == "no_trim") s else s.filter(p => s.filter(q => q.no > p.no).size() < n)

  pure def initSource: Source = {
    gen: 0, kid: 0, keyOk: false, granted: Set(), nextNo: 1, reserved: 0, mustRotate: false,
  }
  pure def initReader: Reader = { gen: 0, kid: 0, hiGen: 0, hiNo: 0, floor: 1, depth: 0, retained: Set() }

  // R-CH-5: the source must rotate before the next publication.
  def mustRotateNow: bool = not(source.keyOk) or source.mustRotate

  // R-CH-9: the floor rises only when publications leave the retained ones
  // because the depth is exceeded, or above a clearing publication, and then
  // above every publication that left; so one that left is never accepted
  // again. `out` are the publications that left the window in this step.
  pure def floorProblems(a: Reader, b: Reader, out: Set[Pub], clear: bool): Set[str] =
    if (b.floor >= a.floor and out.forall(q => q.no < b.floor)
        and (out != Set() or clear or b.floor == a.floor)) Set() else Set("windowFloor")

  // Properties of one transition of one reader.
  pure def readerProblems(a: Reader, b: Reader): Set[str] =
    // S12: the channel value is never replaced with an older one, also across
    // a reboot; generations never go back.
    (if (b.hiNo >= a.hiNo and b.hiGen >= a.hiGen) Set() else Set("freshness"))

  action commitWith(s2: Source, r2: str -> Reader, m2: Set[str], p2: Pool, extra: Set[str], tags: Set[str]): bool = all {
    source' = s2,
    readers' = r2,
    members' = m2,
    gone' = gone.union(members.exclude(m2)),
    joined' = joined.union(m2.exclude(members)),
    made' = made + (if (s2.kid != source.kid) 1 else 0),
    pool' = p2,
    broken' = broken.union(extra)
      .union(DEVICES.fold(Set(), (acc, d) => acc.union(readerProblems(readers.get(d), r2.get(d))))),
    seen' = seen.union(tags),
  }

  // -------------------------------------------------------------- initial state
  action init = all {
    source' = initSource,
    readers' = DEVICES.mapBy(d => initReader),
    members' = DEVICES.exclude(LATE),
    gone' = Set(),
    joined' = Set(),
    made' = 0,
    pool' = { pubs: Set(), grants: Set() },
    broken' = Set(),
    seen' = Set(),
  }

  // -------------------------------------------------------------- environment
  // A device leaves the readers: revoked under the source's checkpoint, or
  // removed by the application (R-CH-5). In the same event the source marks
  // the channel for rotation and persists the mark: after a reboot it no
  // longer knows whom it granted the key, so the mark cannot be recomputed.
  action envRemoveDevice(d: str): bool = all {
    members.contains(d),
    val mark = source.gen > 0 and MUTANT != "no_rotate_on_remove"
    commitWith({ ...source, mustRotate: source.mustRotate or mark }, readers, members.exclude(Set(d)), pool,
      Set(), Set()),
  }

  action envRemove = all { members != Set(), nondet d = members.oneOf() envRemoveDevice(d) }

  // A late device joins once (R-CH-6).
  action envJoin = {
    val cand = LATE.exclude(joined).exclude(gone)
    all {
      cand != Set(),
      nondet d = cand.oneOf()
      commitWith(source, readers, members.union(Set(d)), pool, Set(), Set()),
    }
  }

  // ------------------------------------------------------------------- source
  // A new channel key (R-CH-5, R-CH-8): the generation grows and is persisted
  // before anything is sent under it. Allowed at any time.
  action sourceRotate = all {
    source.gen < MAX_GEN,
    made < MAX_GEN,
    val g = source.gen + 1
    // R-CH-8: a generation is never used for two keys.
    val reused = pool.grants.exists(x => x.gen >= g) or pool.pubs.exists(x => x.gen >= g)
    commitWith({ ...source, gen: g, kid: made + 1, keyOk: true, granted: Set(), mustRotate: false },
      readers, members, pool, if (reused) Set("uniqueKeys") else Set(),
      if (source.mustRotate and source.granted.exists(r => not(members.contains(r)))) Set("rotateAfterRemove") else Set()),
  }

  // Grant the current key to a reader (R-CH-6, R-CH-13), also again.
  // While the rotation mark is set the marked key is granted to no one: the
  // grant waits for the new key (R-CH-5).
  action sourceGrantTo(d: str): bool = all {
    source.keyOk,
    not(source.mustRotate) or MUTANT == "grant_marked",
    val allowed = (members.contains(d) or MUTANT == "grant_removed") and (not(NO_READ.contains(d)) or MUTANT == "grant_no_read")
    all {
      allowed,
      // R-CH-13, S5: keys go only to valid readers with the read right.
      val bad = not(members.contains(d)) or NO_READ.contains(d)
      commitWith({ ...source, granted: source.granted.union(Set(d)) }, readers, members,
        { ...pool, grants: pool.grants.union(Set({ gen: source.gen, kid: source.kid, reader: d })) },
        (if (bad) Set("grantsToReaders") else Set()).union(if (source.mustRotate) Set("noMarkedGrant") else Set()),
        Set()),
    },
  }

  action sourceGrant = { nondet d = DEVICES.oneOf() sourceGrantTo(d) }

  // Publish under the current key (R-CH-8, R-CH-10, R-CH-11).
  action sourcePublishWith(depth: int, empty: bool): bool = all {
    not(mustRotateNow),
    source.nextNo <= MAX_NO,
    val no = source.nextNo
    // Reserve the next block before handing out a number beyond the last one.
    val reserved = if (no > source.reserved) no + BLOCK - 1 else source.reserved
    val p = { gen: source.gen, kid: source.kid, no: no, depth: depth, empty: empty }
    // R-CH-8: publication numbers increase strictly over the device key's life.
    val dup = pool.pubs.exists(q => q.no >= no)
    // R-CH-5, S5: nobody outside the readers holds the key a publication is made under.
    val leak = pool.grants.exists(x => x.kid == source.kid and not(members.contains(x.reader)))
    commitWith({ ...source, nextNo: no + 1, reserved: reserved }, readers, members,
      { ...pool, pubs: pool.pubs.union(Set(p)) },
      (if (dup) Set("uniqueNumbers") else Set()).union(if (leak) Set("rotateOnRemove") else Set()),
      if (empty and depth > 0) Set("clear") else Set()),
  }

  action sourcePublish = {
    nondet depth = 0.to(MAX_DEPTH).oneOf()
    nondet empty = Set(false, true).oneOf()
    sourcePublishWith(depth, empty)
  }

  // The host signals "rotate key epoch" (R-CH-5).
  action sourceEpoch = commitWith({ ...source, mustRotate: true }, readers, members, pool, Set(), Set())

  // Reboot of the source (R-CORE-5): the generation, the block bound, and the
  // rotation mark survive; the key itself may not; the memory is lost,
  // including the readers granted the key.
  action sourceReboot = {
    nondet keep = Set(false, true).oneOf()
    val start = if (MUTANT == "no_block_skip") source.reserved - BLOCK + 1 else source.reserved + 1
    val g = if (MUTANT == "gen_not_persisted" and source.gen > 0) source.gen - 1 else source.gen
    commitWith({ ...source, gen: g, keyOk: keep and source.keyOk, granted: Set(),
                 mustRotate: source.mustRotate and MUTANT != "mark_not_persisted",
                 nextNo: if (start < 1) 1 else start },
      readers, members, pool, Set(), Set())
  }

  // ------------------------------------------------------------------ readers
  action setReader(d: str, r: Reader, extra: Set[str], tags: Set[str]): bool =
    commitWith(source, readers.set(d, r), members, pool, extra, tags)

  // Receive a grant (R-CH-9, R-CH-13).
  action readerGrant(d: str, x: Grant): bool = {
    val r = readers.get(d)
    val accept = x.reader == d and not(NO_READ.contains(d))
      and (x.gen > r.hiGen or (x.gen == r.hiGen and x.kid == r.kid) or MUTANT == "accept_old_grant")
    if (accept)
      setReader(d, { ...r, gen: x.gen, kid: x.kid, hiGen: x.gen }, Set(), Set())
    else
      setReader(d, r, Set(), Set())
  }

  // Receive a publication (R-CH-9, R-CH-10, R-CH-11).
  action readerPub(d: str, p: Pub): bool = {
    val r = readers.get(d)
    val haveKey = (r.kid != 0 and p.kid == r.kid) or MUTANT == "accept_without_key"
    val isNew = p.no > r.hiNo
    // A publication of depth 0 has no window and is never accepted late.
    val inWindow = r.depth > 0 and (p.depth > 0 or MUTANT == "late_clear_kept")
      and r.floor <= p.no and p.no <= r.hiNo and not(r.retained.contains(p))
    if (not(haveKey) or not(isNew or inWindow))
      setReader(d, r, Set(), Set())
    else if (isNew) {
      val cleared = p.depth == 0 or p.empty
      val kept = if (cleared) (if (MUTANT == "empty_no_clear" and p.empty) r.retained else Set())
                 else trim(r.retained.union(Set(p)), p.depth)
      // The floor rises above what left the window (R-CH-9); the mutant
      // floor_stays computes it as before the fix.
      val out = r.retained.union(Set(p)).exclude(kept).exclude(if (cleared) Set(p) else Set())
      val r2 = { ...r, hiNo: p.no, depth: p.depth, retained: kept,
                 floor: if (cleared) p.no + 1
                        else if (MUTANT == "floor_stays") minNo(kept, p.no)
                        else if (out != Set()) minNo(kept, p.no) else r.floor }
      // Accepted only under a key the reader holds (R-CH-9).
      setReader(d, r2, (if (p.kid != r.kid) Set("acceptUnderHeldKey") else Set())
        .union(floorProblems(r, r2, if (cleared) r.retained else out, cleared)),
        Set("accept").union(if (p.depth < r.depth and not(cleared)) Set("shrink") else Set()))
    } else if (p.empty and MUTANT != "late_clear_kept") {
      // A late clearing publication clears everything up to its number, and
      // the floor moves above it, so nothing older refills the window
      // (R-CH-9, R-CH-10).
      val r2 = { ...r, retained: r.retained.filter(q => q.no > p.no), floor: p.no + 1 }
      setReader(d, r2, (if (p.kid != r.kid) Set("acceptUnderHeldKey") else Set())
        .union(floorProblems(r, r2, r.retained.filter(q => q.no <= p.no), true)), Set("lateClear"))
    } else {
      // A publication in the window that the reader does not hold: refill.
      // Only the depth of the latest publication governs (R-CH-10).
      val kept = trim(r.retained.union(Set(p)), r.depth)
      val out = r.retained.union(Set(p)).exclude(kept)
      val r2 = { ...r, retained: kept,
                 floor: if (MUTANT == "floor_stays") minNo(kept, r.floor)
                        else if (out != Set()) minNo(kept, r.hiNo) else r.floor,
                 hiNo: if (MUTANT == "refill_moves_high") p.no else r.hiNo }
      setReader(d, r2, (if (p.kid != r.kid) Set("acceptUnderHeldKey") else Set())
        .union(floorProblems(r, r2, out, false)), Set("refill"))
    }
  }

  // Reboot of a reader (R-CORE-5): the key and the numbers survive, the
  // retained publications do not.
  action readerReboot(d: str): bool = {
    val r = readers.get(d)
    setReader(d, { ...r, retained: Set(), hiNo: if (MUTANT == "high_not_persisted") 0 else r.hiNo }, Set(), Set())
  }

  // ---------------------------------------------------------------------- step
  action step = any {
    envRemove,
    envJoin,
    sourceRotate,
    sourceGrant,
    sourcePublish,
    sourceEpoch,
    sourceReboot,
    nondet d = DEVICES.oneOf()
    any {
      all { pool.grants != Set(), nondet x = pool.grants.oneOf() readerGrant(d, x) },
      all { pool.pubs != Set(), nondet p = pool.pubs.oneOf() readerPub(d, p) },
      readerReboot(d),
    },
  }

  // ---------------------------------------------------------------- invariants
  // Step properties (see the monitor above and the actions).
  val freshness = not(broken.contains("freshness"))                 // S12, R-CH-9
  val uniqueNumbers = not(broken.contains("uniqueNumbers"))         // R-CH-8
  val uniqueKeys = not(broken.contains("uniqueKeys"))               // R-CH-8
  val rotateOnRemove = not(broken.contains("rotateOnRemove"))       // R-CH-5, S5
  val grantsToReaders = not(broken.contains("grantsToReaders"))     // R-CH-13, S5
  val acceptUnderHeldKey = not(broken.contains("acceptUnderHeldKey")) // R-CH-9
  val noMarkedGrant = not(broken.contains("noMarkedGrant"))         // R-CH-5
  val windowFloor = not(broken.contains("windowFloor"))             // R-CH-9, S12

  // R-CH-10, R-CH-11, R-CH-12: a reader retains at most `depth`
  // publications, all of them in its window, with distinct numbers, and none
  // of them a clearing publication or one of depth 0.
  val retention = DEVICES.forall(d =>
    val r = readers.get(d)
    r.retained.size() <= r.depth
      and r.retained.forall(p => r.floor <= p.no and p.no <= r.hiNo)
      and r.retained.forall(p => r.retained.forall(q => p.no == q.no implies p == q))
      and r.retained.forall(p => not(p.empty) and p.depth > 0))

  // R-CH-13: a device without the read right never holds a channel key.
  val noReadNoKey = NO_READ.forall(d => readers.get(d).kid == 0)

  val safety = freshness and uniqueNumbers and uniqueKeys and rotateOnRemove and grantsToReaders
    and acceptUnderHeldKey and noMarkedGrant and windowFloor and retention and noReadNoKey

  // ------------------------------------------------- non-vacuity witnesses
  // Each witness is expected to be VIOLATED: the behaviour is reachable.
  val witnessAccept = not(seen.contains("accept"))
  val witnessRefill = not(seen.contains("refill"))
  val witnessLateClear = not(seen.contains("lateClear"))
  val witnessClear = not(seen.contains("clear"))
  val witnessShrink = not(seen.contains("shrink"))
  val witnessRotateAfterRemove = not(seen.contains("rotateAfterRemove"))
  val witnessRefillAfterReboot = not(DEVICES.exists(d =>
    readers.get(d).retained != Set() and readers.get(d).retained.forall(p => p.no < readers.get(d).hiNo)))
}
