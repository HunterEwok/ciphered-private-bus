// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 HunterEwok

//! Interface tests of the simulator: scenarios an application sees at R-API-2.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::assert_is_empty,
    reason = "tests"
)]

use cpb_api::{
    Action, ActionSet, CallOutcome, Channel, DeviceId, ErrorMode, Event, FetchId, HostAnswer, HostRequestKind,
    InvokeOptions, LocalApi, MAX_APP_INFO, OwnerOperation, Permit, Readers, ResultCode, Rights, RuleCode,
};
use cpb_sim::{Config, DEFAULT_BLOB_SEGMENT, Faults, Sim};

const ROOT: DeviceId = DeviceId::from_u64(1);
const A: DeviceId = DeviceId::from_u64(2);
const B: DeviceId = DeviceId::from_u64(3);
const RELAY: DeviceId = DeviceId::from_u64(4);
const CH: Channel = Channel(16);

fn act(n: u8) -> Action {
    Action::new(n).unwrap()
}

fn config(mode: ErrorMode) -> Config {
    Config { mode: Some(mode), ..Config::default() }
}

/// Root, A and B, all linked to each other.
fn triangle(mode: ErrorMode) -> Sim {
    let mut sim = Sim::new(config(mode), ROOT);
    sim.admit(A, Rights::MEMBER, false, Vec::new());
    sim.admit(B, Rights::MEMBER, false, Vec::new());
    sim.link(ROOT, A);
    sim.link(ROOT, B);
    sim.link(A, B);
    sim.settle().unwrap();
    sim
}

fn publications(events: &[Event]) -> Vec<Vec<u8>> {
    events
        .iter()
        .filter_map(|e| match e {
            Event::Publication(p) => Some(p.data.clone()),
            _ => None,
        })
        .collect()
}

fn outcomes(events: &[Event]) -> Vec<CallOutcome> {
    events
        .iter()
        .filter_map(|e| match e {
            Event::CallFinished { outcome, .. } => Some(outcome.clone()),
            _ => None,
        })
        .collect()
}

#[test]
fn publish_subscribe_and_retention() {
    let mut sim = triangle(ErrorMode::Release);
    sim.node(B).unwrap().subscribe(A, CH).unwrap();
    for v in [b"1", b"2", b"3"] {
        sim.node(A).unwrap().publish(CH, v, 2).unwrap();
    }
    sim.settle().unwrap();
    assert_eq!(publications(&sim.drain_events(B)), vec![b"1".to_vec(), b"2".to_vec(), b"3".to_vec()]);
    let kept: Vec<u64> = sim.node(B).unwrap().read(A, CH).iter().map(|p| p.number).collect();
    assert_eq!(kept, vec![2, 3], "depth 2 keeps the two latest");
    // A clearing publication empties the channel at the reader.
    sim.node(A).unwrap().publish(CH, b"", 1).unwrap();
    sim.settle().unwrap();
    assert!(sim.drain_events(B).iter().any(|e| matches!(e, Event::Cleared { .. })));
    assert!(sim.node(B).unwrap().read(A, CH).is_empty());
}

#[test]
fn a_late_reader_gets_the_retained_value() {
    let mut sim = triangle(ErrorMode::Release);
    sim.node(A).unwrap().publish(CH, b"state", 1).unwrap();
    sim.settle().unwrap();
    sim.node(B).unwrap().subscribe(A, CH).unwrap();
    sim.settle().unwrap();
    assert_eq!(publications(&sim.drain_events(B)), vec![b"state".to_vec()]);
}

#[test]
fn a_rebooted_reader_refills_from_the_source() {
    let mut sim = triangle(ErrorMode::Release);
    sim.node(B).unwrap().subscribe(A, CH).unwrap();
    sim.node(A).unwrap().publish(CH, b"v1", 1).unwrap();
    sim.settle().unwrap();
    sim.reboot(B);
    assert!(sim.node(B).unwrap().read(A, CH).is_empty());
    sim.link(A, B);
    sim.settle().unwrap();
    assert_eq!(sim.node(B).unwrap().read(A, CH)[0].data, b"v1");
}

#[test]
fn a_revoked_device_gets_no_new_key_and_is_not_heard() {
    let mut sim = triangle(ErrorMode::Release);
    sim.node(B).unwrap().subscribe(A, CH).unwrap();
    sim.node(ROOT).unwrap().subscribe(A, CH).unwrap();
    sim.node(A).unwrap().subscribe(B, CH).unwrap();
    sim.node(A).unwrap().publish(CH, b"before", 1).unwrap();
    sim.settle().unwrap();
    sim.drain_events(B);
    assert!(sim.revoke(B));
    sim.settle().unwrap();
    // A rotates the key before its next publication; B is not granted it (R-CH-5).
    sim.node(A).unwrap().publish(CH, b"after", 1).unwrap();
    sim.settle().unwrap();
    assert!(publications(&sim.drain_events(B)).is_empty());
    assert_eq!(publications(&sim.drain_events(ROOT)).last().unwrap(), b"after");
    // B, cut off before the revocation, still considers itself a member (R-MEM-16), but
    // nobody who has seen the new checkpoint accepts it.
    assert!(publications(&sim.drain_events(A)).is_empty());
}

#[test]
fn a_revoked_device_that_does_not_know_it_is_not_heard() {
    let mut sim = triangle(ErrorMode::Debug);
    sim.node(A).unwrap().subscribe(B, CH).unwrap();
    sim.settle().unwrap();
    sim.unlink(ROOT, B);
    sim.unlink(A, B);
    assert!(sim.revoke(B));
    sim.settle().unwrap();
    // B comes back and publishes before it hears of its revocation.
    sim.link(A, B);
    sim.node(B).unwrap().publish(CH, b"from revoked", 1).unwrap();
    sim.settle().unwrap();
    let events = sim.drain_events(A);
    assert!(publications(&events).is_empty());
    assert!(events.iter().any(|e| matches!(e, Event::Rejected(r) if r.code() == RuleCode::MEM_NOT_MEMBER)));
    // Afterwards B knows: its own operations are refused.
    let e = sim.node(B).unwrap().publish(CH, b"again", 1).unwrap_err();
    assert_eq!(e.code(), RuleCode::PUB_NO_RIGHT);
}

#[test]
fn removing_a_reader_rotates_the_key() {
    let mut sim = triangle(ErrorMode::Release);
    sim.node(B).unwrap().subscribe(A, CH).unwrap();
    sim.node(ROOT).unwrap().subscribe(A, CH).unwrap();
    sim.node(A).unwrap().publish(CH, b"x", 1).unwrap();
    sim.settle().unwrap();
    sim.drain_events(B);
    sim.drain_events(ROOT);
    sim.node(A).unwrap().set_readers(CH, Readers::Only(vec![ROOT])).unwrap();
    sim.node(A).unwrap().publish(CH, b"y", 1).unwrap();
    sim.settle().unwrap();
    assert!(publications(&sim.drain_events(B)).is_empty());
    assert_eq!(publications(&sim.drain_events(ROOT)), vec![b"y".to_vec()]);
}

#[test]
fn interface_refusals_have_rule_codes() {
    let mut sim = triangle(ErrorMode::Release);
    let mut a = sim.node(A).unwrap();
    let e = a.publish(Channel(3), b"x", 1).unwrap_err();
    assert_eq!(e.code(), RuleCode::API_RESERVED_CHANNEL);
    let e = a.publish(CH, &[0u8; 4097], 1).unwrap_err();
    assert_eq!(e.code(), RuleCode::API_DATA_TOO_LARGE);
    let e = a.publish(CH, b"x", 17).unwrap_err();
    assert_eq!(e.code(), RuleCode::API_DEPTH_TOO_LARGE);
    let e = a.set_name(&"n".repeat(65)).unwrap_err();
    assert_eq!(e.code(), RuleCode::API_NAME_TOO_LONG);
    let e = a.invoke(B, act(1), b"", InvokeOptions { as_root: true, ..InvokeOptions::default() }).unwrap_err();
    assert_eq!(e.code(), RuleCode::API_NOT_ROOT);
}

/// What a node saw of its blob fetches: the segments (fetch, number, offset, bytes) and the
/// endings, in arrival order.
#[derive(Default)]
struct Fetched {
    segments: Vec<(FetchId, u32, u64, Vec<u8>)>,
    ended: Vec<(FetchId, Result<(), RuleCode>)>,
}

impl Fetched {
    fn bytes(&self, fetch: FetchId) -> Vec<u8> {
        self.segments.iter().filter(|s| s.0 == fetch).flat_map(|s| s.3.clone()).collect()
    }

    fn numbers(&self, fetch: FetchId) -> Vec<u32> {
        self.segments.iter().filter(|s| s.0 == fetch).map(|s| s.1).collect()
    }

    fn take(&mut self, events: Vec<Event>) -> bool {
        let mut any = false;
        for e in events {
            any = true;
            match e {
                Event::BlobSegment { fetch, segment, offset, data } => {
                    self.segments.push((fetch, segment, offset, data));
                }
                Event::BlobFetchFinished { fetch, result } => self.ended.push((fetch, result.map_err(|r| r.code()))),
                _ => {}
            }
        }
        any
    }
}

/// Runs the bus and takes the node's events until nothing more arrives. Taking a segment
/// lets its fetch ask for the next one.
fn fetch_until_quiet(sim: &mut Sim, at: DeviceId) -> Fetched {
    let mut f = Fetched::default();
    loop {
        sim.settle().unwrap();
        if !f.take(sim.drain_events(at)) {
            return f;
        }
    }
}

fn pattern(len: u32) -> Vec<u8> {
    (0..len).map(|i| u8::try_from(i % 251).unwrap()).collect()
}

fn publish_blob(sim: &mut Sim, from: DeviceId, ch: Channel, blob: &[u8]) -> u64 {
    let mut a = sim.node(from).unwrap();
    let w = a.begin_blob(ch, b"photo", 1).unwrap();
    for piece in blob.chunks(3_000) {
        a.write_blob(w, piece).unwrap();
    }
    a.finish_blob(w).unwrap()
}

#[test]
fn blobs_arrive_in_segments() {
    let mut sim = triangle(ErrorMode::Release);
    sim.node(B).unwrap().subscribe(A, CH).unwrap();
    let blob = pattern(10_000);
    let no = publish_blob(&mut sim, A, CH, &blob);
    sim.settle().unwrap();
    let info = sim.node(B).unwrap().read(A, CH)[0].blob.unwrap();
    assert_eq!((info.size, info.segments, info.segment_size), (10_000, 3, DEFAULT_BLOB_SEGMENT));
    sim.drain_events(B);

    // The same bytes published again are another blob with another hash.
    publish_blob(&mut sim, A, Channel(17), &blob);
    let again = sim.node(A).unwrap().read(A, Channel(17))[0].blob.unwrap();
    assert_ne!(again.hash, info.hash);
    assert_eq!(sim.node(A).unwrap().read(A, CH)[0].blob.unwrap().hash, info.hash);

    let whole = sim.node(B).unwrap().fetch_blob(A, CH, no, 0, info.segments).unwrap();
    let got = fetch_until_quiet(&mut sim, B);
    assert_eq!(got.numbers(whole), vec![0, 1, 2]);
    assert_eq!(got.bytes(whole), blob);
    assert_eq!(got.segments.iter().map(|s| s.2).collect::<Vec<_>>(), vec![0, 4042, 8084]);
    assert_eq!(got.ended, vec![(whole, Ok(()))]);

    // The source reads its own blob from host storage.
    let own = sim.node(A).unwrap().fetch_blob(A, CH, no, 0, 3).unwrap();
    let got = fetch_until_quiet(&mut sim, A);
    assert_eq!(got.bytes(own), blob);
}

#[test]
fn a_blob_fetch_takes_any_range_and_two_run_at_once() {
    let mut sim = triangle(ErrorMode::Release);
    sim.node(B).unwrap().subscribe(A, CH).unwrap();
    let blob = pattern(30_000);
    let no = publish_blob(&mut sim, A, CH, &blob);
    sim.settle().unwrap();
    sim.drain_events(B);
    let mut b = sim.node(B).unwrap();
    let middle = b.fetch_blob(A, CH, no, 2, 3).unwrap();
    let tail = b.fetch_blob(A, CH, no, 4, 4).unwrap();
    let got = fetch_until_quiet(&mut sim, B);
    assert_eq!(got.numbers(middle), vec![2, 3, 4]);
    assert_eq!(got.numbers(tail), vec![4, 5, 6, 7]);
    assert_eq!(got.bytes(middle), blob[2 * 4042..5 * 4042]);
    assert_eq!(got.bytes(tail), blob[4 * 4042..]);
    assert_eq!(got.ended.len(), 2);

    let mut b = sim.node(B).unwrap();
    assert_eq!(b.fetch_blob(A, CH, no, 0, 0).unwrap_err().code(), RuleCode::API_BAD_RANGE);
    assert_eq!(b.fetch_blob(A, CH, no, 7, 2).unwrap_err().code(), RuleCode::API_BAD_RANGE);
    assert_eq!(b.fetch_blob(A, CH, no + 1, 0, 1).unwrap_err().code(), RuleCode::API_UNKNOWN_ID);
}

#[test]
fn the_application_sets_the_pace_of_a_blob_fetch_and_can_cancel_it() {
    let mut sim = triangle(ErrorMode::Release);
    sim.node(B).unwrap().subscribe(A, CH).unwrap();
    let no = publish_blob(&mut sim, A, CH, &pattern(30_000));
    sim.settle().unwrap();
    sim.drain_events(B);
    let fetch = sim.node(B).unwrap().fetch_blob(A, CH, no, 0, 8).unwrap();
    // However long the bus runs, one segment waits for the application and no more.
    sim.settle().unwrap();
    sim.settle().unwrap();
    let first = sim.node(B).unwrap().poll_event();
    assert!(matches!(first, Some(Event::BlobSegment { segment: 0, .. })));
    assert!(sim.node(B).unwrap().poll_event().is_none());
    // Taking it asked for the next one.
    sim.settle().unwrap();
    sim.node(B).unwrap().cancel_fetch(fetch).unwrap();
    let got = fetch_until_quiet(&mut sim, B);
    assert!(got.segments.is_empty() && got.ended.is_empty());
    assert_eq!(sim.node(B).unwrap().cancel_fetch(fetch).unwrap_err().code(), RuleCode::API_UNKNOWN_ID);
}

#[test]
fn blob_fetch_ends_when_the_publication_leaves_retention() {
    let mut sim = triangle(ErrorMode::Release);
    sim.node(B).unwrap().subscribe(A, CH).unwrap();
    let no = publish_blob(&mut sim, A, CH, &pattern(9_000));
    sim.settle().unwrap();
    sim.drain_events(B);
    let fetch = sim.node(B).unwrap().fetch_blob(A, CH, no, 0, 3).unwrap();
    // A newer publication at depth 1 replaces it before the first segment is served.
    sim.node(A).unwrap().publish(CH, b"v2", 1).unwrap();
    let got = fetch_until_quiet(&mut sim, B);
    assert!(got.segments.is_empty());
    assert_eq!(got.ended, vec![(fetch, Err(RuleCode::BLOB_GONE))]);
}

#[test]
fn a_blob_fetch_survives_a_lost_link() {
    let mut sim = triangle(ErrorMode::Release);
    sim.node(B).unwrap().subscribe(A, CH).unwrap();
    let blob = pattern(12_000);
    let no = publish_blob(&mut sim, A, CH, &blob);
    sim.settle().unwrap();
    sim.drain_events(B);
    sim.unlink(A, B);
    sim.unlink(ROOT, B);
    let fetch = sim.node(B).unwrap().fetch_blob(A, CH, no, 0, 3).unwrap();
    let got = fetch_until_quiet(&mut sim, B);
    assert!(got.segments.is_empty() && got.ended.is_empty());
    sim.link(A, B);
    let got = fetch_until_quiet(&mut sim, B);
    assert_eq!(got.bytes(fetch), blob);
    assert_eq!(got.ended, vec![(fetch, Ok(()))]);
}

#[test]
fn blob_arguments_are_checked() {
    let mut sim = triangle(ErrorMode::Release);
    let mut a = sim.node(A).unwrap();
    assert_eq!(a.begin_blob(CH, b"", 0).unwrap_err().code(), RuleCode::API_BAD_BLOB);
    let w = a.begin_blob(CH, b"", 1).unwrap();
    assert_eq!(a.finish_blob(w).unwrap_err().code(), RuleCode::API_BAD_BLOB);
    assert_eq!(a.write_blob(w, b"x").unwrap_err().code(), RuleCode::API_UNKNOWN_ID);
    let w = a.begin_blob(CH, b"", 1).unwrap();
    a.abort_blob(w).unwrap();
    assert_eq!(a.finish_blob(w).unwrap_err().code(), RuleCode::API_UNKNOWN_ID);
    assert_eq!(a.fetch_blob(B, CH, 1, 0, 1).unwrap_err().code(), RuleCode::API_UNKNOWN_ID);
}

#[test]
fn node_info_reaches_every_member() {
    let mut sim = triangle(ErrorMode::Release);
    sim.node(A).unwrap().set_name("Kitchen sensor").unwrap();
    sim.node(A).unwrap().set_app_info(b"profile:on").unwrap();
    sim.settle().unwrap();
    for d in [ROOT, B] {
        let infos: Vec<(String, Vec<u8>)> = sim
            .drain_events(d)
            .into_iter()
            .filter_map(|e| match e {
                Event::NodeInfo { device, name, app } if device == A => Some((name, app)),
                _ => None,
            })
            .collect();
        assert_eq!(infos.last(), Some(&("Kitchen sensor".to_string(), b"profile:on".to_vec())), "at {d}");
    }
    let e = sim.node(A).unwrap().set_app_info(&vec![0u8; MAX_APP_INFO + 1]).unwrap_err();
    assert_eq!(e.code(), RuleCode::API_APP_INFO_TOO_LARGE);
    sim.node(A).unwrap().set_app_info(&vec![0u8; MAX_APP_INFO]).unwrap();
}

#[test]
fn membership_changes_are_announced() {
    let mut sim = triangle(ErrorMode::Release);
    sim.drain_events(A);
    let before = sim.node(A).unwrap().state();
    assert_eq!(before.root_device, ROOT);
    sim.admit(RELAY, Rights::READER, false, Vec::new());
    sim.settle().unwrap();
    let after = sim.node(A).unwrap().state();
    let announced: Vec<(u32, u32)> = sim
        .drain_events(A)
        .into_iter()
        .filter_map(|e| match e {
            Event::MembershipChanged { generation, checkpoint } => Some((generation, checkpoint)),
            _ => None,
        })
        .collect();
    assert!(!announced.is_empty());
    assert_eq!(announced.last(), Some(&(after.generation, after.checkpoint)));
    assert!(after.members.iter().any(|m| m.device == RELAY));
}

/// What B reads on A's channel after A adds it to the readers, with or without a new key first.
fn added_reader_sees(rotate_first: bool) -> Vec<Vec<u8>> {
    let mut sim = triangle(ErrorMode::Release);
    let mut a = sim.node(A).unwrap();
    a.set_readers(CH, Readers::Only(vec![ROOT])).unwrap();
    a.publish(CH, b"old", 4).unwrap();
    sim.settle().unwrap();
    let mut a = sim.node(A).unwrap();
    if rotate_first {
        a.rotate_channel_key(CH).unwrap();
    }
    a.set_readers(CH, Readers::Only(vec![ROOT, B])).unwrap();
    sim.node(B).unwrap().subscribe(A, CH).unwrap();
    sim.settle().unwrap();
    sim.node(A).unwrap().publish(CH, b"new", 4).unwrap();
    sim.settle().unwrap();
    sim.node(B).unwrap().read(A, CH).into_iter().map(|p| p.data).collect()
}

#[test]
fn a_new_key_hides_the_past_from_an_added_reader() {
    assert_eq!(added_reader_sees(false), vec![b"old".to_vec(), b"new".to_vec()]);
    assert_eq!(added_reader_sees(true), vec![b"new".to_vec()]);
    let mut sim = triangle(ErrorMode::Release);
    let e = sim.node(A).unwrap().rotate_channel_key(Channel(0)).unwrap_err();
    assert_eq!(e.code(), RuleCode::API_RESERVED_CHANNEL);
}

/// A commands B: action 1 automatic, action 2 confirmation-class.
fn command_setup() -> Sim {
    let mut sim = Sim::new(config(ErrorMode::Release), ROOT);
    sim.admit(A, Rights::MEMBER, true, Vec::new());
    let permit = Permit { commander: A, automatic: ActionSet::of(&[act(1)]), confirmation: ActionSet::of(&[act(2)]) };
    sim.admit(B, Rights::MEMBER, false, vec![permit]);
    sim.link(ROOT, A);
    sim.link(ROOT, B);
    sim.link(A, B);
    sim.settle().unwrap();
    let mut b = sim.node(B).unwrap();
    b.register_action(act(1));
    b.register_action(act(2));
    sim
}

fn serve(sim: &mut Sim, code: ResultCode) -> Vec<bool> {
    let mut confirmed = Vec::new();
    for e in sim.drain_events(B) {
        if let Event::IncomingCall { id, confirmed: c, .. } = e {
            confirmed.push(c);
            sim.node(B).unwrap().reply(id, code, b"ok").unwrap();
        }
    }
    sim.settle().unwrap();
    confirmed
}

#[test]
fn an_automatic_call_executes_and_replies() {
    let mut sim = command_setup();
    sim.node(A).unwrap().invoke(B, act(1), b"on", InvokeOptions::default()).unwrap();
    sim.settle().unwrap();
    assert_eq!(serve(&mut sim, ResultCode::DONE), vec![false]);
    assert_eq!(
        outcomes(&sim.drain_events(A)),
        vec![CallOutcome::Replied { code: ResultCode::DONE, data: b"ok".to_vec() }]
    );
    // The reply carried the next nonce: the second call takes one round trip.
    sim.node(A).unwrap().invoke(B, act(1), b"off", InvokeOptions::default()).unwrap();
    sim.settle().unwrap();
    assert_eq!(serve(&mut sim, ResultCode::DONE).len(), 1);
}

#[test]
fn a_call_without_a_right_is_refused() {
    let mut sim = command_setup();
    sim.node(A).unwrap().invoke(B, act(3), b"", InvokeOptions::default()).unwrap();
    sim.settle().unwrap();
    assert!(serve(&mut sim, ResultCode::DONE).is_empty());
    assert!(matches!(outcomes(&sim.drain_events(A))[..], [CallOutcome::Replied { code: ResultCode::NO_RIGHT, .. }]));
    // The root device gets a slot, but its device key has only the rights the target's
    // passport gives it (R-CALL-4, R-CALL-7).
    sim.node(ROOT).unwrap().invoke(B, act(1), b"", InvokeOptions::default()).unwrap();
    sim.settle().unwrap();
    assert!(matches!(outcomes(&sim.drain_events(ROOT))[..], [CallOutcome::Replied { code: ResultCode::NO_RIGHT, .. }]));
    // A device that is neither a commander nor the root device gets no nonce (R-CALL-7).
    let outsider = DeviceId::from_u64(9);
    sim.admit(outsider, Rights::MEMBER, false, Vec::new());
    sim.link(outsider, B);
    sim.settle().unwrap();
    sim.node(outsider).unwrap().invoke(B, act(1), b"", InvokeOptions::default()).unwrap();
    sim.settle().unwrap();
    assert!(outcomes(&sim.drain_events(outsider)).is_empty(), "the call waits for a nonce that never comes");
    assert!(sim.log().iter().any(|l| l.contains("call/no-slot")));
}

#[test]
fn a_confirmation_call_needs_the_user() {
    let mut sim = command_setup();
    sim.node(A).unwrap().invoke(B, act(2), b"unlock", InvokeOptions::default()).unwrap();
    sim.settle().unwrap();
    let req = sim
        .drain_events(A)
        .into_iter()
        .find_map(|e| match e {
            Event::HostRequest { id, kind: HostRequestKind::SignWithPresenceKey { .. } } => Some(id),
            _ => None,
        })
        .unwrap();
    sim.node(A).unwrap().answer_host(req, HostAnswer::Approve).unwrap();
    sim.settle().unwrap();
    assert_eq!(serve(&mut sim, ResultCode::DONE), vec![true]);
    assert!(matches!(outcomes(&sim.drain_events(A))[..], [CallOutcome::Replied { .. }]));

    // Declined by the user: the call is not sent.
    sim.node(A).unwrap().invoke(B, act(2), b"unlock", InvokeOptions::default()).unwrap();
    sim.settle().unwrap();
    let req = sim
        .drain_events(A)
        .into_iter()
        .find_map(|e| match e {
            Event::HostRequest { id, .. } => Some(id),
            _ => None,
        })
        .unwrap();
    sim.node(A).unwrap().answer_host(req, HostAnswer::Refuse).unwrap();
    sim.settle().unwrap();
    match &outcomes(&sim.drain_events(A))[..] {
        [CallOutcome::NotSent(r)] => assert_eq!(r.code(), RuleCode::CALL_NOT_CONFIRMED),
        other => panic!("{other:?}"),
    }
}

#[test]
fn after_a_target_reset_only_idempotent_calls_are_retried() {
    let mut sim = command_setup();
    sim.node(A).unwrap().invoke(B, act(1), b"", InvokeOptions::default()).unwrap();
    sim.settle().unwrap();
    serve(&mut sim, ResultCode::DONE);
    sim.drain_events(A);

    // The target forgets its slots; A still holds the old nonce.
    sim.reset_nonces(B);
    sim.node(A).unwrap().invoke(B, act(1), b"", InvokeOptions::default()).unwrap();
    sim.settle().unwrap();
    assert!(serve(&mut sim, ResultCode::DONE).is_empty());
    assert_eq!(outcomes(&sim.drain_events(A)), vec![CallOutcome::Unknown], "L7");

    sim.reset_nonces(B);
    let idem = InvokeOptions { idempotent: true, ..InvokeOptions::default() };
    sim.node(A).unwrap().invoke(B, act(1), b"", idem).unwrap();
    sim.settle().unwrap();
    assert_eq!(serve(&mut sim, ResultCode::DONE).len(), 1);
    assert!(matches!(outcomes(&sim.drain_events(A))[..], [CallOutcome::Replied { .. }]));
}

#[test]
fn a_commander_reset_avoids_the_unknown_outcome() {
    let mut sim = command_setup();
    sim.node(A).unwrap().invoke(B, act(1), b"", InvokeOptions::default()).unwrap();
    sim.settle().unwrap();
    serve(&mut sim, ResultCode::DONE);
    sim.drain_events(A);
    // Both sides raise "reset nonces" with the same period: A forgets its nonce and asks again.
    sim.reset_nonces(B);
    sim.reset_nonces(A);
    sim.node(A).unwrap().invoke(B, act(1), b"", InvokeOptions::default()).unwrap();
    sim.settle().unwrap();
    assert_eq!(serve(&mut sim, ResultCode::DONE).len(), 1);
    assert!(matches!(outcomes(&sim.drain_events(A))[..], [CallOutcome::Replied { .. }]));
}

#[test]
fn a_member_relay_forwards() {
    let mut sim = Sim::new(config(ErrorMode::Release), ROOT);
    sim.admit(A, Rights::MEMBER, false, Vec::new());
    sim.admit(B, Rights::MEMBER, false, Vec::new());
    sim.admit(RELAY, Rights { relay: true, ..Rights::default() }, false, Vec::new());
    for d in [A, B, RELAY] {
        sim.link(ROOT, d);
    }
    sim.settle().unwrap();
    sim.unlink(ROOT, A);
    sim.unlink(ROOT, B);
    sim.link(A, RELAY);
    sim.link(B, RELAY);
    sim.settle().unwrap();
    sim.node(B).unwrap().subscribe(A, CH).unwrap();
    sim.node(A).unwrap().publish(CH, b"via relay", 1).unwrap();
    sim.settle().unwrap();
    assert_eq!(publications(&sim.drain_events(B)), vec![b"via relay".to_vec()]);
    // The relay has no read right and holds no key.
    assert!(sim.node(RELAY).unwrap().read(A, CH).is_empty());
}

#[test]
fn debug_mode_shows_rejections_and_release_does_not() {
    for (mode, shown) in [(ErrorMode::Debug, true), (ErrorMode::Release, false)] {
        let mut sim = triangle(mode);
        sim.unlink(ROOT, B);
        sim.unlink(A, B);
        sim.revoke(B);
        sim.settle().unwrap();
        sim.link(A, B);
        sim.node(B).unwrap().publish(CH, b"x", 1).unwrap();
        sim.settle().unwrap();
        let rejected = sim
            .drain_events(A)
            .into_iter()
            .any(|e| matches!(e, Event::Rejected(r) if r.code() == RuleCode::MEM_NOT_MEMBER));
        assert_eq!(rejected, shown, "{mode:?}");
        assert!(sim.log().iter().any(|l| l.contains("mem/not-member")), "logged in both modes");
    }
}

#[test]
fn faults_are_recovered_and_runs_are_reproducible() {
    let run = |seed: u64| {
        let cfg = Config {
            seed,
            mode: Some(ErrorMode::Release),
            faults: Faults { loss_permille: 200, duplicate_permille: 100, reorder: true },
            ..Config::default()
        };
        let mut sim = Sim::new(cfg, ROOT);
        sim.admit(A, Rights::MEMBER, false, Vec::new());
        sim.admit(B, Rights::MEMBER, false, Vec::new());
        sim.link(ROOT, A);
        sim.link(ROOT, B);
        sim.link(A, B);
        sim.settle().unwrap();
        sim.node(B).unwrap().subscribe(A, CH).unwrap();
        for i in 0u8..10 {
            sim.node(A).unwrap().publish(CH, &[i], 4).unwrap();
            sim.settle().unwrap();
        }
        // Lost messages come back after the link is re-established (R-CH-11).
        for _ in 0..20 {
            if sim.node(B).unwrap().read(A, CH).last().map(|p| p.data.clone()) == Some(vec![9]) {
                break;
            }
            sim.unlink(A, B);
            sim.link(A, B);
            sim.node(B).unwrap().subscribe(A, CH).unwrap();
            sim.settle().unwrap();
        }
        let kept: Vec<u64> = sim.node(B).unwrap().read(A, CH).iter().map(|p| p.number).collect();
        (kept, sim.log().to_vec(), sim.steps())
    };
    let (kept, log1, steps1) = run(7);
    assert_eq!(kept.last(), Some(&10), "the latest value arrives despite loss");
    assert!(kept.windows(2).all(|w| w[0] < w[1]));
    let (_, log2, steps2) = run(7);
    assert_eq!((log1, steps1), (log2, steps2), "same seed, same run");
}

#[test]
fn owner_operations_need_the_root_key_confirmation() {
    let mut sim = command_setup();
    // Only the root device has them.
    let e = sim.node(A).unwrap().revoke(B).unwrap_err();
    assert_eq!(e.code(), RuleCode::API_NOT_ROOT);
    // The owner takes action 1 away from A: nothing changes until the host confirms.
    let permit = Permit { commander: A, automatic: ActionSet::EMPTY, confirmation: ActionSet::of(&[act(2)]) };
    let id = sim.node(ROOT).unwrap().change_member(B, Rights::MEMBER, false, vec![permit]).unwrap();
    let asked = sim.drain_events(ROOT).into_iter().any(|e| {
        matches!(e, Event::HostRequest { id: x, kind: HostRequestKind::SignMembership { device, operation: OwnerOperation::Change } } if x == id && device == B)
    });
    assert!(asked);
    let before = sim.node(B).unwrap().state().checkpoint;
    sim.node(ROOT).unwrap().answer_host(id, HostAnswer::Approve).unwrap();
    sim.settle().unwrap();
    assert!(sim.node(B).unwrap().state().checkpoint > before);
    sim.node(A).unwrap().invoke(B, act(1), b"", InvokeOptions::default()).unwrap();
    sim.settle().unwrap();
    assert!(matches!(outcomes(&sim.drain_events(A))[..], [CallOutcome::Replied { code: ResultCode::NO_RIGHT, .. }]));
    // A declined revocation leaves the member in place.
    let id = sim.node(ROOT).unwrap().revoke(B).unwrap();
    sim.node(ROOT).unwrap().answer_host(id, HostAnswer::Refuse).unwrap();
    sim.settle().unwrap();
    assert!(sim.node(A).unwrap().state().members.iter().any(|m| m.device == B));
}
