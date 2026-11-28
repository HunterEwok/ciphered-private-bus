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
    Action, ActionSet, CallKey, CallOutcome, Channel, DeviceId, ErrorMode, Event, FetchId, HostAnswer, HostRequestKind,
    InvokeOptions, JoinRequestId, KeyFingerprint, LocalApi, MAX_APP_INFO, MAX_APP_TAG, MAX_INITIAL_CREDIT, MAX_MESSAGE,
    OwnerOperation, Paired, PairingCode, Permit, Readers, ResultCode, Rights, RuleCode, StreamEnd, StreamId,
    StreamMode, StreamRequest,
};
use cpb_sim::{Config, DEFAULT_BLOB_SEGMENT, DEFAULT_STREAM_CHUNK, Faults, Profile, Sim};

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
    let before = sim.node(A).unwrap().state().unwrap();
    assert_eq!(before.root_device, Some(ROOT));
    sim.admit(RELAY, Rights::READER, false, Vec::new());
    sim.settle().unwrap();
    let after = sim.node(A).unwrap().state().unwrap();
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

#[test]
fn the_root_application_changes_one_right_and_keeps_the_permits() {
    let mut sim = command_setup();
    sim.settle().unwrap();
    // Read B as the bus shows it, change one right, write the rest back.
    let b = sim.node(ROOT).unwrap().state().unwrap().members.into_iter().find(|m| m.device == B).unwrap();
    assert_eq!(b.permits.len(), 1);
    assert_eq!(b.permits[0].commander, A);
    let a = sim.node(ROOT).unwrap().state().unwrap().members.into_iter().find(|m| m.device == A).unwrap();
    assert!(a.presence && !b.presence);
    let rights = Rights { relay: true, ..b.rights };
    let id = sim.node(ROOT).unwrap().change_member(B, rights, b.presence, b.permits.clone()).unwrap();
    sim.node(ROOT).unwrap().answer_host(id, HostAnswer::Approve).unwrap();
    sim.settle().unwrap();
    let after = sim.node(A).unwrap().state().unwrap().members.into_iter().find(|m| m.device == B).unwrap();
    assert!(after.rights.relay);
    assert_eq!(after.permits, b.permits);
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

fn serve(sim: &mut Sim, code: ResultCode) -> Vec<CallKey> {
    let mut keys = Vec::new();
    for e in sim.drain_events(B) {
        if let Event::IncomingCall { id, signed_by, .. } = e {
            keys.push(signed_by);
            sim.node(B).unwrap().reply(id, code, "", b"ok").unwrap();
        }
    }
    sim.settle().unwrap();
    keys
}

#[test]
fn an_automatic_call_executes_and_replies() {
    let mut sim = command_setup();
    sim.node(A).unwrap().invoke(B, act(1), b"on", InvokeOptions::default()).unwrap();
    sim.settle().unwrap();
    assert_eq!(serve(&mut sim, ResultCode::DONE), vec![CallKey::Device]);
    assert_eq!(
        outcomes(&sim.drain_events(A)),
        vec![CallOutcome::Replied {
            code: ResultCode::DONE,
            message: String::new(),
            data: b"ok".to_vec(),
            stream: None
        }]
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
    assert_eq!(serve(&mut sim, ResultCode::DONE), vec![CallKey::Presence]);
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
    let before = sim.node(B).unwrap().state().unwrap().checkpoint;
    sim.node(ROOT).unwrap().answer_host(id, HostAnswer::Approve).unwrap();
    sim.settle().unwrap();
    assert!(sim.node(B).unwrap().state().unwrap().checkpoint > before);
    sim.node(A).unwrap().invoke(B, act(1), b"", InvokeOptions::default()).unwrap();
    sim.settle().unwrap();
    assert!(matches!(outcomes(&sim.drain_events(A))[..], [CallOutcome::Replied { code: ResultCode::NO_RIGHT, .. }]));
    // A declined revocation leaves the member in place.
    let id = sim.node(ROOT).unwrap().revoke(B).unwrap();
    sim.node(ROOT).unwrap().answer_host(id, HostAnswer::Refuse).unwrap();
    sim.settle().unwrap();
    assert!(sim.node(A).unwrap().state().unwrap().members.iter().any(|m| m.device == B));
}

// ------------------------------------------------------------------------- streams

fn with_stream(mode: StreamMode, credit: u32) -> InvokeOptions {
    InvokeOptions { stream: Some(StreamRequest { mode, credit }), ..InvokeOptions::default() }
}

/// A calls action 1 of B and asks for a stream; B opens it. Returns both ends.
fn open_stream(sim: &mut Sim, mode: StreamMode, a_credit: u32, b_credit: u32) -> (StreamId, StreamId) {
    sim.node(A).unwrap().invoke(B, act(1), b"", with_stream(mode, a_credit)).unwrap();
    sim.settle().unwrap();
    let mut at_b = None;
    for e in sim.drain_events(B) {
        if let Event::IncomingCall { id, stream, .. } = e {
            assert_eq!(stream, Some(StreamRequest { mode, credit: a_credit }));
            at_b = Some(sim.node(B).unwrap().reply_with_stream(id, ResultCode::DONE, "", b"", b_credit).unwrap());
        }
    }
    sim.settle().unwrap();
    let at_a = sim.drain_events(A).into_iter().find_map(|e| match e {
        Event::CallFinished { outcome: CallOutcome::Replied { code: ResultCode::DONE, stream, .. }, .. } => stream,
        _ => None,
    });
    (at_a.expect("the reply opens the commander's side"), at_b.expect("the target opened its side"))
}

fn stream_data(events: &[Event], stream: StreamId) -> Vec<Vec<u8>> {
    events
        .iter()
        .filter_map(|e| match e {
            Event::StreamData { stream: s, data } if *s == stream => Some(data.clone()),
            _ => None,
        })
        .collect()
}

fn closed(events: &[Event], stream: StreamId) -> Option<StreamEnd> {
    events.iter().find_map(|e| match e {
        Event::StreamClosed { stream: s, reason } if *s == stream => Some(*reason),
        _ => None,
    })
}

#[test]
fn an_ordered_stream_carries_data_within_credit() {
    let mut sim = command_setup();
    let (sa, sb) = open_stream(&mut sim, StreamMode::Ordered, 8, 4);
    // A may send what B granted: four bytes.
    sim.node(A).unwrap().stream_write(sa, b"abcd").unwrap();
    let e = sim.node(A).unwrap().stream_write(sa, b"e").unwrap_err();
    assert_eq!(e.code(), RuleCode::STR_NO_CREDIT);
    sim.settle().unwrap();
    assert_eq!(stream_data(&sim.drain_events(B), sb), vec![b"abcd".to_vec()]);
    // B grants three more, and A learns it.
    sim.node(B).unwrap().stream_grant(sb, 3).unwrap();
    sim.settle().unwrap();
    assert!(sim.drain_events(A).contains(&Event::StreamCredit { stream: sa, added: 3 }));
    sim.node(A).unwrap().stream_write(sa, b"efg").unwrap();
    // The other direction has its own credit: eight bytes from A.
    sim.node(B).unwrap().stream_write(sb, b"12345678").unwrap();
    assert_eq!(sim.node(B).unwrap().stream_write(sb, b"9").unwrap_err().code(), RuleCode::STR_NO_CREDIT);
    sim.settle().unwrap();
    assert_eq!(stream_data(&sim.drain_events(B), sb), vec![b"efg".to_vec()]);
    assert_eq!(stream_data(&sim.drain_events(A), sa), vec![b"12345678".to_vec()]);
    // The "end" chunk closes both sides; the side that ended gets no event.
    sim.node(A).unwrap().stream_end(sa).unwrap();
    sim.settle().unwrap();
    assert_eq!(closed(&sim.drain_events(B), sb), Some(StreamEnd::Ended));
    assert!(sim.drain_events(A).is_empty());
    assert_eq!(sim.node(A).unwrap().stream_write(sa, b"x").unwrap_err().code(), RuleCode::API_UNKNOWN_ID);
    assert_eq!(sim.node(B).unwrap().stream_write(sb, b"x").unwrap_err().code(), RuleCode::API_UNKNOWN_ID);
}

#[test]
fn stream_operations_check_their_arguments() {
    let mut sim = command_setup();
    let mut a = sim.node(A).unwrap();
    // A lossy stream has no credit, and the initial credit is bounded.
    let e = a.invoke(B, act(1), b"", with_stream(StreamMode::Lossy, 1)).unwrap_err();
    assert_eq!(e.code(), RuleCode::API_BAD_STREAM);
    let e = a.invoke(B, act(1), b"", with_stream(StreamMode::Ordered, MAX_INITIAL_CREDIT + 1)).unwrap_err();
    assert_eq!(e.code(), RuleCode::API_BAD_STREAM);
    // A call that asked for no stream cannot be answered with one, and stays to be answered.
    a.invoke(B, act(1), b"", InvokeOptions::default()).unwrap();
    sim.settle().unwrap();
    for e in sim.drain_events(B) {
        if let Event::IncomingCall { id, stream, .. } = e {
            assert_eq!(stream, None);
            let mut b = sim.node(B).unwrap();
            assert_eq!(
                b.reply_with_stream(id, ResultCode::DONE, "", b"", 0).unwrap_err().code(),
                RuleCode::API_BAD_STREAM
            );
            b.reply(id, ResultCode::DONE, "", b"").unwrap();
        }
    }
    sim.settle().unwrap();
    assert!(matches!(outcomes(&sim.drain_events(A))[..], [CallOutcome::Replied { stream: None, .. }]));
    // The target may also answer a stream request with a plain reply: no stream opens.
    sim.node(A).unwrap().invoke(B, act(1), b"", with_stream(StreamMode::Ordered, 16)).unwrap();
    sim.settle().unwrap();
    serve(&mut sim, ResultCode::DECLINED);
    assert!(matches!(
        outcomes(&sim.drain_events(A))[..],
        [CallOutcome::Replied { code: ResultCode::DECLINED, stream: None, .. }]
    ));
    // Chunk sizes and kinds.
    let (sa, sb) = open_stream(&mut sim, StreamMode::Lossy, 0, 0);
    let mut a = sim.node(A).unwrap();
    assert_eq!(a.stream_write(sa, b"").unwrap_err().code(), RuleCode::API_BAD_STREAM);
    let big = vec![0u8; usize::try_from(DEFAULT_STREAM_CHUNK).unwrap() + 1];
    assert_eq!(a.stream_write(sa, &big).unwrap_err().code(), RuleCode::API_DATA_TOO_LARGE);
    assert_eq!(a.stream_grant(sa, 0).unwrap_err().code(), RuleCode::API_BAD_STREAM);
    assert_eq!(a.stream_grant(sa, 8).unwrap_err().code(), RuleCode::API_BAD_STREAM);
    assert_eq!(a.stream_end(StreamId(u64::MAX)).unwrap_err().code(), RuleCode::API_UNKNOWN_ID);
    // The refused operations sent nothing: the stream still works.
    a.stream_write(sa, &big[1..]).unwrap();
    sim.settle().unwrap();
    assert_eq!(stream_data(&sim.drain_events(B), sb).len(), 1);
}

#[test]
fn a_lossy_stream_drops_what_does_not_fit() {
    let profile = Profile { stream_buffer: 8, ..Profile::default() };
    let mut sim = Sim::new(Config { mode: Some(ErrorMode::Release), profile, ..Config::default() }, ROOT);
    sim.admit(A, Rights::MEMBER, false, Vec::new());
    let permit = Permit { commander: A, automatic: ActionSet::of(&[act(1)]), confirmation: ActionSet::EMPTY };
    sim.admit(B, Rights::MEMBER, false, vec![permit]);
    sim.link(A, B);
    sim.settle().unwrap();
    sim.node(B).unwrap().register_action(act(1));
    let (sa, sb) = open_stream(&mut sim, StreamMode::Lossy, 0, 0);
    // No credit: A sends as it likes. B holds eight bytes for its application and drops the
    // third chunk.
    for chunk in [b"aaaa", b"bbbb", b"cccc"] {
        sim.node(A).unwrap().stream_write(sa, chunk).unwrap();
    }
    sim.settle().unwrap();
    assert_eq!(stream_data(&sim.drain_events(B), sb), vec![b"aaaa".to_vec(), b"bbbb".to_vec()]);
    // The application took them, so there is room again; the stream stays open after a loss.
    sim.node(A).unwrap().stream_write(sa, b"dddd").unwrap();
    sim.settle().unwrap();
    assert_eq!(stream_data(&sim.drain_events(B), sb), vec![b"dddd".to_vec()]);
}

#[test]
fn opening_beyond_the_limit_keeps_existing_streams() {
    let profile = Profile { max_streams: 1, ..Profile::default() };
    let mut sim = Sim::new(Config { mode: Some(ErrorMode::Release), profile, ..Config::default() }, ROOT);
    sim.admit(A, Rights::MEMBER, false, Vec::new());
    let permit = Permit { commander: A, automatic: ActionSet::of(&[act(1)]), confirmation: ActionSet::EMPTY };
    sim.admit(B, Rights::MEMBER, false, vec![permit]);
    sim.link(ROOT, B);
    sim.link(A, B);
    sim.settle().unwrap();
    sim.node(B).unwrap().register_action(act(1));
    let (sa, sb) = open_stream(&mut sim, StreamMode::Ordered, 4, 4);
    // A is at its own limit: the call is not sent.
    let e = sim.node(A).unwrap().invoke(B, act(1), b"", with_stream(StreamMode::Ordered, 4)).unwrap_err();
    assert_eq!(e.code(), RuleCode::STR_TOO_MANY);
    // The root device has room and calls with the root key; B is at its limit and answers
    // with the result code (R-STR-6).
    let options = InvokeOptions { as_root: true, ..with_stream(StreamMode::Ordered, 4) };
    sim.node(ROOT).unwrap().invoke(B, act(1), b"", options).unwrap();
    sim.settle().unwrap();
    for e in sim.drain_events(ROOT) {
        if let Event::HostRequest { id, kind: HostRequestKind::SignWithRootKey { .. } } = e {
            sim.node(ROOT).unwrap().answer_host(id, HostAnswer::Approve).unwrap();
        }
    }
    sim.settle().unwrap();
    for e in sim.drain_events(B) {
        if let Event::IncomingCall { id, signed_by, .. } = e {
            assert_eq!(signed_by, CallKey::Root);
            let e = sim.node(B).unwrap().reply_with_stream(id, ResultCode::DONE, "", b"", 4).unwrap_err();
            assert_eq!(e.code(), RuleCode::STR_TOO_MANY);
        }
    }
    sim.settle().unwrap();
    assert!(matches!(
        outcomes(&sim.drain_events(ROOT))[..],
        [CallOutcome::Replied { code: ResultCode::TOO_MANY_STREAMS, stream: None, .. }]
    ));
    // The stream that was open is untouched.
    sim.node(A).unwrap().stream_write(sa, b"abcd").unwrap();
    sim.settle().unwrap();
    assert_eq!(stream_data(&sim.drain_events(B), sb), vec![b"abcd".to_vec()]);
}

#[test]
fn a_stream_closes_with_its_link() {
    let mut sim = command_setup();
    let (sa, sb) = open_stream(&mut sim, StreamMode::Ordered, 4, 4);
    sim.unlink(A, B);
    assert_eq!(closed(&sim.drain_events(A), sa), Some(StreamEnd::LinkDown));
    assert_eq!(closed(&sim.drain_events(B), sb), Some(StreamEnd::LinkDown));
    assert_eq!(sim.node(A).unwrap().stream_write(sa, b"x").unwrap_err().code(), RuleCode::API_UNKNOWN_ID);
}

#[test]
fn a_stream_runs_through_a_relay() {
    let mut sim = Sim::new(config(ErrorMode::Release), ROOT);
    sim.admit(A, Rights::MEMBER, false, Vec::new());
    let permit = Permit { commander: A, automatic: ActionSet::of(&[act(1)]), confirmation: ActionSet::EMPTY };
    sim.admit(B, Rights::MEMBER, false, vec![permit]);
    sim.admit(RELAY, Rights { relay: true, ..Rights::default() }, false, Vec::new());
    for d in [A, B, RELAY] {
        sim.link(ROOT, d);
    }
    sim.settle().unwrap();
    for d in [A, B, RELAY] {
        sim.unlink(ROOT, d);
    }
    sim.link(A, RELAY);
    sim.link(B, RELAY);
    sim.settle().unwrap();
    sim.node(B).unwrap().register_action(act(1));
    let (sa, sb) = open_stream(&mut sim, StreamMode::Ordered, 4, 4);
    sim.node(A).unwrap().stream_write(sa, b"abcd").unwrap();
    sim.settle().unwrap();
    assert_eq!(stream_data(&sim.drain_events(B), sb), vec![b"abcd".to_vec()]);
    // A loses its link to the relay and closes its side. B's link is up, so B learns
    // nothing yet: its side closes at the second quiet "reset nonces" (R-STR-5).
    sim.unlink(A, RELAY);
    assert_eq!(closed(&sim.drain_events(A), sa), Some(StreamEnd::LinkDown));
    assert!(sim.drain_events(B).is_empty());
    sim.reset_nonces(B);
    assert!(sim.drain_events(B).is_empty());
    sim.reset_nonces(B);
    assert_eq!(closed(&sim.drain_events(B), sb), Some(StreamEnd::Idle));
}

#[test]
fn a_relay_may_refuse_streams() {
    let mut sim =
        Sim::new(Config { mode: Some(ErrorMode::Release), relays_refuse_streams: true, ..Config::default() }, ROOT);
    sim.admit(A, Rights::MEMBER, false, Vec::new());
    let permit = Permit { commander: A, automatic: ActionSet::of(&[act(1)]), confirmation: ActionSet::EMPTY };
    sim.admit(B, Rights::MEMBER, false, vec![permit]);
    sim.admit(RELAY, Rights { relay: true, ..Rights::default() }, false, Vec::new());
    for d in [A, B, RELAY] {
        sim.link(ROOT, d);
    }
    sim.settle().unwrap();
    for d in [A, B, RELAY] {
        sim.unlink(ROOT, d);
    }
    sim.link(A, RELAY);
    sim.link(B, RELAY);
    sim.settle().unwrap();
    sim.node(B).unwrap().register_action(act(1));
    // The call and its reply pass: the relay refuses only stream chunks.
    let (sa, _) = open_stream(&mut sim, StreamMode::Ordered, 4, 4);
    sim.node(A).unwrap().stream_write(sa, b"abcd").unwrap();
    sim.settle().unwrap();
    // The refusal is a hint that the network can forge: the application is told, and the
    // stream stays open until the application ends it.
    assert_eq!(sim.drain_events(A), vec![Event::StreamRefused { stream: sa }]);
    assert!(sim.drain_events(B).is_empty());
    sim.node(A).unwrap().stream_end(sa).unwrap();
}

#[test]
fn reset_nonces_closes_only_an_idle_stream() {
    let mut sim = command_setup();
    let (sa, sb) = open_stream(&mut sim, StreamMode::Lossy, 0, 0);
    sim.reset_nonces(B);
    // Traffic since the previous reset keeps the stream.
    sim.node(A).unwrap().stream_write(sa, b"x").unwrap();
    sim.settle().unwrap();
    sim.reset_nonces(B);
    assert_eq!(closed(&sim.drain_events(B), sb), None);
    sim.reset_nonces(B);
    assert_eq!(closed(&sim.drain_events(B), sb), Some(StreamEnd::Idle));
    // A chunk for the stream B no longer has is dropped without an answer (R-STR-3).
    sim.node(A).unwrap().stream_write(sa, b"y").unwrap();
    sim.settle().unwrap();
    assert!(sim.drain_events(B).is_empty());
    assert!(sim.drain_events(A).is_empty());
}

#[test]
fn revocation_closes_the_streams_of_both_parties() {
    let mut sim = command_setup();
    let (sa, sb) = open_stream(&mut sim, StreamMode::Ordered, 4, 4);
    assert!(sim.revoke(A));
    sim.settle().unwrap();
    assert_eq!(closed(&sim.drain_events(B), sb), Some(StreamEnd::Revoked));
    assert_eq!(closed(&sim.drain_events(A), sa), Some(StreamEnd::Revoked));
}

#[test]
fn a_lost_chunk_closes_an_ordered_stream_and_not_a_lossy_one() {
    let mut sim = Sim::new(config(ErrorMode::Debug), ROOT);
    sim.admit(A, Rights::MEMBER, false, Vec::new());
    let permit = Permit { commander: A, automatic: ActionSet::of(&[act(1)]), confirmation: ActionSet::EMPTY };
    sim.admit(B, Rights::MEMBER, false, vec![permit]);
    sim.link(A, B);
    sim.settle().unwrap();
    sim.node(B).unwrap().register_action(act(1));
    let (oa, ob) = open_stream(&mut sim, StreamMode::Ordered, 8, 8);
    let (la, lb) = open_stream(&mut sim, StreamMode::Lossy, 0, 0);
    sim.drain_events(B);
    // The first chunk of each stream is lost on the link.
    sim.node(A).unwrap().stream_write(oa, b"1").unwrap();
    sim.node(A).unwrap().stream_write(la, b"1").unwrap();
    assert_eq!(sim.lose_in_flight(), 2);
    sim.node(A).unwrap().stream_write(oa, b"2").unwrap();
    sim.node(A).unwrap().stream_write(la, b"2").unwrap();
    sim.settle().unwrap();
    let events = sim.drain_events(B);
    // Ordered: the chunk is not the next one, so the stream closes (R-STR-3).
    assert_eq!(closed(&events, ob), Some(StreamEnd::OutOfOrder));
    assert!(stream_data(&events, ob).is_empty());
    assert!(events.iter().any(|e| matches!(e, Event::Rejected(r) if r.code() == RuleCode::STR_OUT_OF_ORDER)));
    // Lossy: the gap is not filled and the stream goes on.
    assert_eq!(closed(&events, lb), None);
    assert_eq!(stream_data(&events, lb), vec![b"2".to_vec()]);
}

#[test]
fn a_new_stream_replaces_a_stale_side() {
    let mut sim = command_setup();
    let (sa, sb) = open_stream(&mut sim, StreamMode::Ordered, 4, 4);
    // B closes its side after a quiet period; A is not told.
    sim.reset_nonces(B);
    sim.reset_nonces(B);
    assert_eq!(closed(&sim.drain_events(B), sb), Some(StreamEnd::Idle));
    // A's own "reset nonces" makes its next call start with a nonce request (R-CALL-8).
    sim.reset_nonces(A);
    // B numbers the next stream the same, so A's stale side is replaced by the new one.
    sim.node(A).unwrap().invoke(B, act(1), b"", with_stream(StreamMode::Ordered, 4)).unwrap();
    sim.settle().unwrap();
    let mut sb2 = None;
    for e in sim.drain_events(B) {
        if let Event::IncomingCall { id, .. } = e {
            sb2 = Some(sim.node(B).unwrap().reply_with_stream(id, ResultCode::DONE, "", b"", 4).unwrap());
        }
    }
    sim.settle().unwrap();
    let events = sim.drain_events(A);
    assert_eq!(closed(&events, sa), Some(StreamEnd::Replaced));
    let sa2 = events.iter().find_map(|e| match e {
        Event::CallFinished { outcome: CallOutcome::Replied { stream, .. }, .. } => *stream,
        _ => None,
    });
    let (sa2, sb2) = (sa2.unwrap(), sb2.unwrap());
    assert_ne!(sa2, sa);
    sim.node(A).unwrap().stream_write(sa2, b"new").unwrap();
    sim.settle().unwrap();
    assert_eq!(stream_data(&sim.drain_events(B), sb2), vec![b"new".to_vec()]);
}

#[test]
fn a_reboot_loses_the_streams_without_an_answer() {
    let mut sim = command_setup();
    let (sa, _) = open_stream(&mut sim, StreamMode::Ordered, 4, 4);
    // B reboots; its links drop, so A closes its side with the link.
    sim.reboot(B);
    assert_eq!(closed(&sim.drain_events(A), sa), Some(StreamEnd::LinkDown));
    assert!(sim.drain_events(B).iter().all(|e| !matches!(e, Event::StreamClosed { .. })));
}

#[test]
fn a_reply_carries_a_message_for_the_log() {
    let mut sim = command_setup();
    sim.node(A).unwrap().invoke(B, act(1), b"", InvokeOptions::default()).unwrap();
    sim.settle().unwrap();
    for e in sim.drain_events(B) {
        if let Event::IncomingCall { id, .. } = e {
            let mut b = sim.node(B).unwrap();
            let long = "x".repeat(MAX_MESSAGE + 1);
            let e = b.reply(id, ResultCode::BAD_ARGUMENTS, &long, b"").unwrap_err();
            assert_eq!(e.code(), RuleCode::API_MESSAGE_TOO_LONG);
            b.reply(id, ResultCode::BAD_ARGUMENTS, "level must be 0..100", b"").unwrap();
        }
    }
    sim.settle().unwrap();
    assert_eq!(
        outcomes(&sim.drain_events(A)),
        vec![CallOutcome::Replied {
            code: ResultCode::BAD_ARGUMENTS,
            message: String::from("level must be 0..100"),
            data: Vec::new(),
            stream: None,
        }]
    );
}

#[test]
fn the_root_signs_application_data_and_every_node_verifies_it() {
    let mut sim = triangle(ErrorMode::Release);
    let settings = b"version 3: A may read secrets";
    // Only the root device can ask, and the tag is 1 to 64 bytes.
    assert_eq!(sim.node(A).unwrap().sign_app_data("settings", settings).unwrap_err().code(), RuleCode::API_NOT_ROOT);
    assert_eq!(sim.node(ROOT).unwrap().sign_app_data("", settings).unwrap_err().code(), RuleCode::API_BAD_TAG);
    let long = "t".repeat(MAX_APP_TAG + 1);
    assert_eq!(sim.node(ROOT).unwrap().sign_app_data(&long, settings).unwrap_err().code(), RuleCode::API_BAD_TAG);
    // The owner declines: no signature.
    let id = sim.node(ROOT).unwrap().sign_app_data("settings", settings).unwrap();
    let asked = sim.drain_events(ROOT).into_iter().any(|e| {
        matches!(e, Event::HostRequest { id: x, kind: HostRequestKind::SignAppData { tag, size } }
            if x == id && tag == "settings" && size == 29)
    });
    assert!(asked);
    sim.node(ROOT).unwrap().answer_host(id, HostAnswer::Refuse).unwrap();
    assert_eq!(sim.drain_events(ROOT), vec![Event::AppDataSigned { request: id, signature: None }]);
    // The owner confirms: the signature arrives, and every node verifies it.
    let id = sim.node(ROOT).unwrap().sign_app_data("settings", settings).unwrap();
    sim.node(ROOT).unwrap().answer_host(id, HostAnswer::Approve).unwrap();
    let signature = sim
        .drain_events(ROOT)
        .into_iter()
        .find_map(|e| match e {
            Event::AppDataSigned { request, signature } if request == id => signature,
            _ => None,
        })
        .unwrap();
    for d in [ROOT, A, B] {
        let node = sim.node(d).unwrap();
        node.verify_app_data("settings", settings, &signature).unwrap();
        // Other data, another tag, or a changed signature do not verify.
        let e = node.verify_app_data("settings", b"version 3: B may read secrets", &signature).unwrap_err();
        assert_eq!(e.code(), RuleCode::MEM_APP_SIGNATURE);
        assert_eq!(
            node.verify_app_data("other", settings, &signature).unwrap_err().code(),
            RuleCode::MEM_APP_SIGNATURE
        );
        let mut bad = signature.clone();
        bad[0] ^= 1;
        assert_eq!(node.verify_app_data("settings", settings, &bad).unwrap_err().code(), RuleCode::MEM_APP_SIGNATURE);
    }
}

// ------------------------------------------------------------------ enrollment

const NEW: DeviceId = DeviceId::from_u64(9);

/// Root and an acceptor A, linked; NEW is not on the bus and is linked to `near`.
fn before_pairing(near: DeviceId) -> Sim {
    let mut sim = Sim::new(Config { mode: Some(ErrorMode::Debug), ..Config::default() }, ROOT);
    sim.admit(A, Rights { accept: true, ..Rights::MEMBER }, false, Vec::new());
    sim.link(ROOT, A);
    assert!(sim.add_device(NEW, true));
    sim.link(near, NEW);
    sim.settle().unwrap();
    sim.drain_events(ROOT);
    sim.drain_events(A);
    sim
}

fn pairing_results(events: &[Event]) -> Vec<Result<Paired, RuleCode>> {
    events
        .iter()
        .filter_map(|e| match e {
            Event::PairingFinished { result, .. } => Some(result.clone().map_err(|r| r.code())),
            _ => None,
        })
        .collect()
}

fn join_requests(events: &[Event]) -> Vec<(JoinRequestId, DeviceId, String, DeviceId, bool)> {
    events
        .iter()
        .filter_map(|e| match e {
            Event::JoinRequested { request, device, name, acceptor, presence } => {
                Some((*request, *device, name.clone(), *acceptor, *presence))
            }
            _ => None,
        })
        .collect()
}

fn is_member(sim: &mut Sim, at: DeviceId, d: DeviceId) -> bool {
    sim.node(at).unwrap().state().is_some_and(|s| s.members.iter().any(|m| m.device == d))
}

/// What the camera of the root device reads from the screen of a device.
fn scanned(sim: &mut Sim, d: DeviceId) -> KeyFingerprint {
    sim.node(d).unwrap().device_fingerprint()
}

/// The new device `d` presents a code and the acceptor `at` reads it; the exchange runs.
fn pair(sim: &mut Sim, d: DeviceId, at: DeviceId) -> PairingCode {
    let (_, code) = sim.node(d).unwrap().show_pairing_code().unwrap();
    sim.node(at).unwrap().enter_pairing_code(code).unwrap();
    sim.settle().unwrap();
    code
}

/// The owner reads the new device's code with the root device and confirms the admission.
fn admit(sim: &mut Sim, request: JoinRequestId, rights: Rights) {
    let presented = scanned(sim, NEW);
    let host = sim.node(ROOT).unwrap().admit(request, presented, rights, Vec::new()).unwrap();
    let asked = sim.drain_events(ROOT);
    assert!(asked.iter().any(|e| matches!(
        e,
        Event::HostRequest { id, kind: HostRequestKind::SignMembership { device, operation: OwnerOperation::Admit } }
            if *id == host && *device == NEW
    )));
    sim.node(ROOT).unwrap().answer_host(host, HostAnswer::Approve).unwrap();
    sim.settle().unwrap();
}

#[test]
fn a_device_joins_through_an_acceptor() {
    let mut sim = before_pairing(A);
    // Before pairing the device has no bus: no state, and bus operations are refused.
    assert!(sim.node(NEW).unwrap().state().is_none());
    assert_eq!(sim.node(NEW).unwrap().publish(CH, b"x", 1).unwrap_err().code(), RuleCode::API_NO_BUS);
    sim.node(NEW).unwrap().set_name("kitchen display").unwrap();

    // The new device presents a code with its device key; the acceptor reads it (R-JOIN-1).
    let code = pair(&mut sim, NEW, A);
    assert_eq!(code.device, sim.node(NEW).unwrap().device_fingerprint());
    let bus = sim.node(ROOT).unwrap().state().unwrap().bus;
    assert_eq!(pairing_results(&sim.drain_events(NEW)), vec![Ok(Paired::Joiner { bus })]);
    let at_acceptor = pairing_results(&sim.drain_events(A));
    assert_eq!(at_acceptor, vec![Ok(Paired::Acceptor { name: "kitchen display".into() })]);
    // Paired is not admitted: the device knows the bus and is not a member (R-JOIN-6).
    assert!(sim.node(NEW).unwrap().state().is_some());
    assert!(!is_member(&mut sim, NEW, NEW));
    assert!(!is_member(&mut sim, ROOT, NEW));

    // The Root shows the name and the acceptor (R-JOIN-5).
    let requests = join_requests(&sim.drain_events(ROOT));
    assert_eq!(requests.len(), 1);
    let (request, device, name, acceptor, presence) = requests[0].clone();
    assert_eq!((device, name.as_str(), acceptor, presence), (NEW, "kitchen display", A, true));

    admit(&mut sim, request, Rights::MEMBER);
    for at in [ROOT, A, NEW] {
        assert!(is_member(&mut sim, at, NEW), "at {at}");
    }
    let state = sim.node(NEW).unwrap().state().unwrap();
    assert_eq!(state.fingerprint, sim.node(ROOT).unwrap().state().unwrap().fingerprint);
    let me = state.members.into_iter().find(|m| m.device == NEW).unwrap();
    assert!(me.presence && me.rights == Rights::MEMBER);
    // The new member announces the name it proposed (R-CH-16).
    sim.node(A).unwrap().subscribe(NEW, Channel::NODE_INFO).unwrap();
    sim.settle().unwrap();
    assert!(sim.drain_events(A).iter().any(|e| matches!(
        e, Event::NodeInfo { device, name, .. } if *device == NEW && name == "kitchen display"
    )));
    // The request is answered: it cannot be used again.
    let presented = scanned(&mut sim, NEW);
    let again = sim.node(ROOT).unwrap().admit(request, presented, Rights::MEMBER, Vec::new());
    assert_eq!(again.unwrap_err().code(), RuleCode::API_UNKNOWN_ID);
}

/// Two devices paired through the acceptor; their requests wait at the Root.
fn two_requests() -> (Sim, JoinRequestId, JoinRequestId) {
    let mut sim = before_pairing(A);
    sim.add_device(B, false);
    sim.link(A, B);
    sim.settle().unwrap();
    for d in [NEW, B] {
        pair(&mut sim, d, A);
    }
    let requests = join_requests(&sim.drain_events(ROOT));
    assert_eq!(requests.iter().map(|r| r.1).collect::<Vec<_>>(), vec![NEW, B]);
    (sim, requests[0].0, requests[1].0)
}

#[test]
fn the_root_device_admits_only_the_device_whose_fingerprint_it_was_given() {
    let (mut sim, of_new, of_other) = two_requests();
    // The owner read the code of the new device, and the request names another device key:
    // this is what a request with a substituted key looks like to the Root (R-JOIN-7).
    let presented = scanned(&mut sim, NEW);
    let refused = sim.node(ROOT).unwrap().admit(of_other, presented, Rights::MEMBER, Vec::new());
    assert_eq!(refused.unwrap_err().code(), RuleCode::JOIN_FINGERPRINT);
    // Nothing was asked of the root key, and nobody was admitted.
    assert!(!sim.drain_events(ROOT).iter().any(|e| matches!(e, Event::HostRequest { .. })));
    sim.settle().unwrap();
    assert!(!is_member(&mut sim, ROOT, B) && !is_member(&mut sim, ROOT, NEW));
    // The refusal changed nothing: both requests still wait, and the right one is admitted.
    admit(&mut sim, of_new, Rights::MEMBER);
    assert!(is_member(&mut sim, ROOT, NEW) && !is_member(&mut sim, ROOT, B));
    sim.node(ROOT).unwrap().decline_join(of_other).unwrap();
}

#[test]
fn a_mistyped_fingerprint_admits_nobody() {
    let (mut sim, of_new, _) = two_requests();
    // Without a camera the owner types the text form; one wrong digit refuses (R-JOIN-7).
    let mut typed = sim.node(NEW).unwrap().device_fingerprint();
    assert_eq!(typed.to_string().len(), 79);
    typed.0[31] ^= 1;
    let refused = sim.node(ROOT).unwrap().admit(of_new, typed, Rights::MEMBER, Vec::new());
    assert_eq!(refused.unwrap_err().code(), RuleCode::JOIN_FINGERPRINT);
    assert!(!is_member(&mut sim, ROOT, NEW));
}

#[test]
fn the_acceptor_pairs_only_the_device_its_code_names() {
    let mut sim = before_pairing(A);
    sim.add_device(B, false);
    sim.settle().unwrap();
    // Someone saw the code of the new device and stands in for it with another device key:
    // the acceptor read the code of NEW and meets B, which knows the secret (R-JOIN-7).
    let (_, code) = sim.node(NEW).unwrap().show_pairing_code().unwrap();
    sim.unlink(A, NEW);
    let (_, of_b) = sim.node(B).unwrap().show_pairing_code().unwrap();
    sim.link(A, B);
    let seen = PairingCode { secret: of_b.secret, device: code.device };
    sim.node(A).unwrap().enter_pairing_code(seen).unwrap();
    sim.settle().unwrap();
    assert_eq!(pairing_results(&sim.drain_events(A)), vec![Err(RuleCode::JOIN_FINGERPRINT)]);
    assert!(join_requests(&sim.drain_events(ROOT)).is_empty());
}

#[test]
fn the_root_pairs_a_device_itself_with_one_reading_of_its_code() {
    let mut sim = before_pairing(ROOT);
    // The new device presents its code before the Root has read it (R-JOIN-9).
    let (_, code) = sim.node(NEW).unwrap().show_pairing_code().unwrap();
    sim.settle().unwrap();
    sim.node(ROOT).unwrap().enter_pairing_code(code).unwrap();
    sim.settle().unwrap();
    let requests = join_requests(&sim.drain_events(ROOT));
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].3, ROOT);
    // The one reading gave the root device both the secret and the fingerprint.
    let host = sim.node(ROOT).unwrap().admit(requests[0].0, code.device, Rights::READER, Vec::new()).unwrap();
    sim.node(ROOT).unwrap().answer_host(host, HostAnswer::Approve).unwrap();
    sim.settle().unwrap();
    assert!(is_member(&mut sim, NEW, NEW));
}

#[test]
fn a_declined_request_admits_nobody() {
    let mut sim = before_pairing(A);
    pair(&mut sim, NEW, A);
    let request = join_requests(&sim.drain_events(ROOT))[0].0;
    // Only the root device answers a request.
    assert_eq!(sim.node(A).unwrap().decline_join(request).unwrap_err().code(), RuleCode::API_NOT_ROOT);
    let presented = scanned(&mut sim, NEW);
    assert_eq!(
        sim.node(A).unwrap().admit(request, presented, Rights::MEMBER, Vec::new()).unwrap_err().code(),
        RuleCode::API_NOT_ROOT
    );
    // The owner starts to admit and declines at the root key: nothing is signed.
    let host = sim.node(ROOT).unwrap().admit(request, presented, Rights::MEMBER, Vec::new()).unwrap();
    sim.node(ROOT).unwrap().answer_host(host, HostAnswer::Refuse).unwrap();
    sim.settle().unwrap();
    assert!(!is_member(&mut sim, ROOT, NEW));
    sim.node(ROOT).unwrap().decline_join(request).unwrap();
    assert_eq!(sim.node(ROOT).unwrap().decline_join(request).unwrap_err().code(), RuleCode::API_UNKNOWN_ID);
    sim.settle().unwrap();
    assert!(!is_member(&mut sim, NEW, NEW));
}

#[test]
fn a_wrong_secret_fails_the_run_and_the_code_stays_good() {
    let mut sim = before_pairing(A);
    let (_, code) = sim.node(NEW).unwrap().show_pairing_code().unwrap();
    // Runs are not counted (R-JOIN-3): several wrong secrets do not spend the code.
    for k in 1..=4u8 {
        let mut guess = code;
        guess.secret[0] ^= k;
        sim.node(A).unwrap().enter_pairing_code(guess).unwrap();
        sim.settle().unwrap();
        assert_eq!(pairing_results(&sim.drain_events(A)), vec![Err(RuleCode::JOIN_WRONG_CODE)]);
        assert!(pairing_results(&sim.drain_events(NEW)).is_empty());
    }
    assert!(join_requests(&sim.drain_events(ROOT)).is_empty());
    sim.node(A).unwrap().enter_pairing_code(code).unwrap();
    sim.settle().unwrap();
    assert!(sim.node(NEW).unwrap().state().is_some());
    assert_eq!(join_requests(&sim.drain_events(ROOT)).len(), 1);
}

#[test]
fn a_replaced_code_is_dead() {
    let mut sim = before_pairing(A);
    // The application replaces the code, as it may every few seconds.
    let (pairing, old) = sim.node(NEW).unwrap().show_pairing_code().unwrap();
    sim.node(NEW).unwrap().cancel_pairing(pairing).unwrap();
    let (_, new) = sim.node(NEW).unwrap().show_pairing_code().unwrap();
    assert_ne!(old.secret, new.secret);
    assert_eq!(old.device, new.device);
    sim.node(A).unwrap().enter_pairing_code(old).unwrap();
    sim.settle().unwrap();
    assert_eq!(pairing_results(&sim.drain_events(A)), vec![Err(RuleCode::JOIN_WRONG_CODE)]);
    assert!(sim.node(NEW).unwrap().state().is_none());
}

#[test]
fn pairing_roles_and_rights_are_checked() {
    let mut sim = before_pairing(A);
    sim.admit(B, Rights::MEMBER, false, Vec::new());
    sim.settle().unwrap();
    // The joiner presents and a member reads; never the other way.
    assert_eq!(sim.node(A).unwrap().show_pairing_code().unwrap_err().code(), RuleCode::JOIN_ON_BUS);
    let (pairing, code) = sim.node(NEW).unwrap().show_pairing_code().unwrap();
    assert_eq!(sim.node(NEW).unwrap().enter_pairing_code(code).unwrap_err().code(), RuleCode::API_NO_BUS);
    // A member without the accept right does not pair (R-JOIN-4).
    assert_eq!(sim.node(B).unwrap().enter_pairing_code(code).unwrap_err().code(), RuleCode::JOIN_NO_RIGHT);
    // One pairing at a time.
    assert_eq!(sim.node(NEW).unwrap().show_pairing_code().unwrap_err().code(), RuleCode::JOIN_BUSY);
    sim.node(NEW).unwrap().cancel_pairing(pairing).unwrap();
    assert_eq!(sim.node(NEW).unwrap().cancel_pairing(pairing).unwrap_err().code(), RuleCode::API_UNKNOWN_ID);
    sim.node(NEW).unwrap().show_pairing_code().unwrap();
}

#[test]
fn a_relay_holds_join_requests_while_the_root_is_away() {
    let profile = Profile { join_buffer: 1, ..Profile::default() };
    let mut sim = Sim::new(Config { mode: Some(ErrorMode::Debug), profile, ..Config::default() }, ROOT);
    sim.admit(A, Rights { accept: true, ..Rights::MEMBER }, false, Vec::new());
    sim.admit(RELAY, Rights { relay: true, ..Rights::MEMBER }, false, Vec::new());
    sim.link(A, RELAY);
    sim.add_device(NEW, false);
    sim.add_device(B, false);
    sim.link(A, NEW);
    sim.link(A, B);
    sim.settle().unwrap();
    for d in [NEW, B] {
        pair(&mut sim, d, A);
        assert!(sim.node(d).unwrap().state().is_some(), "{d} paired");
    }
    // The Root comes back to the relay: of two requests the relay kept the newest (R-JOIN-8).
    sim.link(ROOT, RELAY);
    sim.settle().unwrap();
    let requests = join_requests(&sim.drain_events(ROOT));
    assert_eq!(requests.iter().map(|r| r.1).collect::<Vec<_>>(), vec![B]);
    assert!(sim.log().iter().any(|l| l.contains("evicted the oldest join request")));
}

#[test]
fn a_reboot_forgets_a_pairing_in_progress() {
    let mut sim = before_pairing(A);
    let (pairing, code) = sim.node(NEW).unwrap().show_pairing_code().unwrap();
    sim.reboot(NEW);
    assert_eq!(sim.node(NEW).unwrap().cancel_pairing(pairing).unwrap_err().code(), RuleCode::API_UNKNOWN_ID);
    sim.link(A, NEW);
    sim.node(A).unwrap().enter_pairing_code(code).unwrap();
    sim.settle().unwrap();
    // The code died with the reboot: the acceptor is still waiting, and nobody is paired.
    assert!(sim.node(NEW).unwrap().state().is_none());
    assert!(pairing_results(&sim.drain_events(A)).is_empty());
}
