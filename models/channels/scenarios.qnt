// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 HunterEwok
//
// Fixed scenarios for behaviours that random simulation rarely reaches: the
// correct model must reach them with safety intact, and each probe listed
// here must violate safety after the same steps (R-VER-2).

module scenarios {
  import channels(DEVICES = Set("a", "b"), NO_READ = Set(), LATE = Set(), MAX_GEN = 2, MAX_NO = 4,
                  MAX_DEPTH = 2, BLOCK = 2, MUTANT = "none").* from "./channels"

  val g1 = { gen: 1, kid: 1, reader: "a" }
  val p1 = { gen: 1, kid: 1, no: 1, depth: 2, empty: false }
  val p2 = { gen: 1, kid: 1, no: 2, depth: 2, empty: false }
  val p3 = { gen: 1, kid: 1, no: 3, depth: 1, empty: false }
  val p4 = { gen: 1, kid: 1, no: 4, depth: 2, empty: false }

  // A rebooted reader refills its window from older publications and keeps
  // its highest number (R-CH-9, S12).
  run refillAfterRebootTest =
    init
      .then(sourceRotate)
      .then(sourceGrantTo("a"))
      .then(sourceGrantTo("b"))
      .then(readerGrant("a", g1))
      .then(sourcePublishWith(2, false))
      .then(sourcePublishWith(2, false))
      .then(readerPub("a", p1))
      .then(readerPub("a", p2))
      .then(readerReboot("a"))
      .then(readerPub("a", p1))
      .expect(readers.get("a").retained == Set(p1) and readers.get("a").hiNo == 2 and safety)
      .then(readerPub("a", p2))
      .expect(readers.get("a").retained == Set(p1, p2) and safety)

  // A lower depth deletes the excess at once (R-CH-10).
  run shrinkTest =
    init
      .then(sourceRotate)
      .then(sourceGrantTo("a"))
      .then(sourceGrantTo("b"))
      .then(readerGrant("a", g1))
      .then(sourcePublishWith(2, false))
      .then(sourcePublishWith(2, false))
      .then(sourcePublishWith(1, false))
      .then(readerPub("a", p1))
      .then(readerPub("a", p2))
      .then(readerPub("a", p3))
      .expect(readers.get("a").retained == Set(p3) and readers.get("a").floor == 3 and safety)

  // The clearing publication empties the channel, and an older publication
  // no longer refills it (R-CH-10).
  run clearTest =
    init
      .then(sourceRotate)
      .then(sourceGrantTo("a"))
      .then(sourceGrantTo("b"))
      .then(readerGrant("a", g1))
      .then(sourcePublishWith(2, false))
      .then(sourcePublishWith(2, true))
      .then(readerPub("a", p1))
      .then(readerPub("a", { gen: 1, kid: 1, no: 2, depth: 2, empty: true }))
      .expect(readers.get("a").retained == Set() and safety)
      .then(readerPub("a", p1))
      .expect(readers.get("a").retained == Set() and safety)

  // A clearing publication that arrives late clears the window up to its
  // number and is not retained; a late publication of depth 0 is dropped
  // (R-CH-9, R-CH-10, R-CH-12).
  run lateClearTest =
    init
      .then(sourceRotate)
      .then(sourceGrantTo("a"))
      .then(sourceGrantTo("b"))
      .then(readerGrant("a", g1))
      .then(sourcePublishWith(2, false))
      .then(sourcePublishWith(2, true))
      .then(sourcePublishWith(0, false))
      .then(sourcePublishWith(2, false))
      .then(readerPub("a", p1))
      .then(readerPub("a", p4))
      .expect(readers.get("a").retained == Set(p1, p4) and safety)
      .then(readerPub("a", { gen: 1, kid: 1, no: 3, depth: 0, empty: false }))
      .expect(readers.get("a").retained == Set(p1, p4) and safety)
      .then(readerPub("a", { gen: 1, kid: 1, no: 2, depth: 2, empty: true }))
      .expect(readers.get("a").retained == Set(p4) and readers.get("a").floor == 3 and safety)
      .then(readerPub("a", p1))
      .expect(readers.get("a").retained == Set(p4) and safety)

  // While the rotation mark is set, the marked key is granted to no one
  // (R-CH-5).
  run noMarkedGrantTest =
    init
      .then(sourceRotate)
      .then(sourceEpoch)
      .then(sourceGrantTo("a"))
      .fail()

  // A new key is granted to every reader before the next publication (R-CH-5).
  run grantBeforePublishTest =
    init
      .then(sourceRotate)
      .then(sourceGrantTo("a"))
      .then(sourcePublishWith(1, false))
      .fail()

  // After a reader leaves, the source cannot publish under the old key, even
  // after a reboot that keeps the key (R-CH-5, R-CORE-5).
  run rotateAfterRemoveTest =
    init
      .then(sourceRotate)
      .then(sourceGrantTo("b"))
      .then(envRemoveDevice("b"))
      .then(sourceReboot)
      .expect(source.mustRotate)
      .then(sourcePublishWith(1, false))
      .fail()

  // Publications 1, 3, 2 at depth 2: publication 1 leaves the window when 2
  // arrives, the floor rises to 2, and after a reboot publication 1 is not
  // accepted again (R-CH-9, S12).
  val q3 = { gen: 1, kid: 1, no: 3, depth: 2, empty: false }
  run floorAfterEvictionTest =
    init
      .then(sourceRotate)
      .then(sourceGrantTo("a"))
      .then(sourceGrantTo("b"))
      .then(readerGrant("a", g1))
      .then(sourcePublishWith(2, false))
      .then(sourcePublishWith(2, false))
      .then(sourcePublishWith(2, false))
      .then(readerPub("a", p1))
      .then(readerPub("a", q3))
      .then(readerPub("a", p2))
      .expect(readers.get("a").retained == Set(p2, q3) and readers.get("a").floor == 2 and safety)
      .then(readerReboot("a"))
      .then(readerPub("a", p1))
      .expect(readers.get("a").retained == Set() and safety)
}

module scenarios_probe_refill_moves_high {
  import channels(DEVICES = Set("a", "b"), NO_READ = Set(), LATE = Set(), MAX_GEN = 2, MAX_NO = 4,
                  MAX_DEPTH = 2, BLOCK = 2, MUTANT = "refill_moves_high").* from "./channels"

  run refillMovesHighViolatesSafetyTest =
    init
      .then(sourceRotate)
      .then(sourceGrantTo("a"))
      .then(sourceGrantTo("b"))
      .then(readerGrant("a", { gen: 1, kid: 1, reader: "a" }))
      .then(sourcePublishWith(2, false))
      .then(sourcePublishWith(2, false))
      .then(readerPub("a", { gen: 1, kid: 1, no: 1, depth: 2, empty: false }))
      .then(readerPub("a", { gen: 1, kid: 1, no: 2, depth: 2, empty: false }))
      .then(readerReboot("a"))
      .then(readerPub("a", { gen: 1, kid: 1, no: 1, depth: 2, empty: false }))
      .expect(not(safety))
}

module scenarios_probe_no_trim {
  import channels(DEVICES = Set("a", "b"), NO_READ = Set(), LATE = Set(), MAX_GEN = 2, MAX_NO = 4,
                  MAX_DEPTH = 2, BLOCK = 2, MUTANT = "no_trim").* from "./channels"

  run noTrimViolatesSafetyTest =
    init
      .then(sourceRotate)
      .then(sourceGrantTo("a"))
      .then(sourceGrantTo("b"))
      .then(readerGrant("a", { gen: 1, kid: 1, reader: "a" }))
      .then(sourcePublishWith(1, false))
      .then(sourcePublishWith(1, false))
      .then(readerPub("a", { gen: 1, kid: 1, no: 1, depth: 1, empty: false }))
      .then(readerPub("a", { gen: 1, kid: 1, no: 2, depth: 1, empty: false }))
      .expect(not(safety))
}

module scenarios_probe_empty_no_clear {
  import channels(DEVICES = Set("a", "b"), NO_READ = Set(), LATE = Set(), MAX_GEN = 2, MAX_NO = 4,
                  MAX_DEPTH = 2, BLOCK = 2, MUTANT = "empty_no_clear").* from "./channels"

  run emptyNoClearViolatesSafetyTest =
    init
      .then(sourceRotate)
      .then(sourceGrantTo("a"))
      .then(sourceGrantTo("b"))
      .then(readerGrant("a", { gen: 1, kid: 1, reader: "a" }))
      .then(sourcePublishWith(2, false))
      .then(sourcePublishWith(2, true))
      .then(readerPub("a", { gen: 1, kid: 1, no: 1, depth: 2, empty: false }))
      .then(readerPub("a", { gen: 1, kid: 1, no: 2, depth: 2, empty: true }))
      .expect(not(safety))
}

module scenarios_probe_late_clear_kept {
  import channels(DEVICES = Set("a", "b"), NO_READ = Set(), LATE = Set(), MAX_GEN = 2, MAX_NO = 4,
                  MAX_DEPTH = 2, BLOCK = 2, MUTANT = "late_clear_kept").* from "./channels"

  run lateClearKeptViolatesSafetyTest =
    init
      .then(sourceRotate)
      .then(sourceGrantTo("a"))
      .then(sourceGrantTo("b"))
      .then(readerGrant("a", { gen: 1, kid: 1, reader: "a" }))
      .then(sourcePublishWith(2, false))
      .then(sourcePublishWith(2, true))
      .then(sourcePublishWith(2, false))
      .then(readerPub("a", { gen: 1, kid: 1, no: 1, depth: 2, empty: false }))
      .then(readerPub("a", { gen: 1, kid: 1, no: 3, depth: 2, empty: false }))
      .then(readerPub("a", { gen: 1, kid: 1, no: 2, depth: 2, empty: true }))
      .expect(not(safety))
}

module scenarios_probe_floor_stays {
  import channels(DEVICES = Set("a", "b"), NO_READ = Set(), LATE = Set(), MAX_GEN = 2, MAX_NO = 4,
                  MAX_DEPTH = 2, BLOCK = 2, MUTANT = "floor_stays").* from "./channels"

  val g1 = { gen: 1, kid: 1, reader: "a" }
  val p1 = { gen: 1, kid: 1, no: 1, depth: 2, empty: false }
  val p2 = { gen: 1, kid: 1, no: 2, depth: 2, empty: false }
  val q3 = { gen: 1, kid: 1, no: 3, depth: 2, empty: false }

  run floorStaysViolatesSafetyTest =
    init
      .then(sourceRotate)
      .then(sourceGrantTo("a"))
      .then(sourceGrantTo("b"))
      .then(readerGrant("a", g1))
      .then(sourcePublishWith(2, false))
      .then(sourcePublishWith(2, false))
      .then(sourcePublishWith(2, false))
      .then(readerPub("a", p1))
      .then(readerPub("a", q3))
      .then(readerPub("a", p2))
      .expect(not(safety))
}
