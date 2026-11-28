// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 HunterEwok

//! The local application interface of **Ciphered Private Bus** (CPB), requirement R-API-2.
//!
//! An application talks to its node only through [`LocalApi`]. The simulator (`cpb-sim`) and
//! the application library of the core implement the same trait, so an application written
//! against the simulator moves to the core without changes to its own code.
//!
//! The interface is non-blocking and has no callbacks: every operation returns at once, and
//! everything the bus delivers later (publications, incoming calls, call outcomes, requests
//! for a user-presence or root signature) comes from [`LocalApi::poll_event`]. It needs no
//! async runtime and no operating system.
//!
//! The crate is at version 0.x: the shape may change until the format is frozen (R-FMT-15).

#![no_std]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

pub mod codes;
pub mod report;

pub use codes::{ErrorKind, RuleCode};
pub use report::{ErrorMode, Report};

/// Largest publication data, call arguments and call result, in bytes (Section 13.1).
pub const MAX_DATA: usize = 4096;
/// Largest device name, in bytes of UTF-8 (Section 13.1).
pub const MAX_NAME: usize = 64;
/// The first channel number an application may use; 0..15 belong to the bus (R-CH-16).
pub const FIRST_APP_CHANNEL: u16 = 16;
/// Highest action number (D5).
pub const MAX_ACTION: u8 = 64;
/// Largest application part of the node info, in bytes (R-CH-16, Appendix B, Section B.5).
///
/// The node info is publication data, so its encoding is at most [`MAX_DATA`] bytes. Without
/// the application part it takes at most 68 bytes, and the key and the byte string header of
/// the application part take 4 more: 4096 - 68 - 4 = 4024.
pub const MAX_APP_INFO: usize = 4024;
/// Largest data of one stream chunk, in bytes: a 16384-byte frame less the 46-byte chunk
/// header and the 16-byte authentication tag (Appendix B, Section B.7).
pub const MAX_STREAM_DATA: usize = 16384 - 46 - 16;
/// Largest initial credit of a stream, in bytes (Section 13.2).
pub const MAX_INITIAL_CREDIT: u32 = 1 << 20;
/// The default initial credit of a stream, in bytes: four default chunks (Section 13.2).
pub const DEFAULT_INITIAL_CREDIT: u32 = 16 << 10;
/// Largest message of a reply, in bytes of UTF-8 (Appendix B, Section B.6).
pub const MAX_MESSAGE: usize = 256;
/// Highest number of segments of a blob: the segment number is a 4-byte AEAD nonce
/// (Appendix B, Section B.5).
pub const MAX_BLOB_SEGMENTS: u32 = 0x7fff_ffff;

/// A device identifier: the first 16 bytes of the hash of its device key (Section 13.1).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DeviceId(pub [u8; 16]);

impl DeviceId {
    /// An identifier whose last eight bytes hold `n`; convenient in tests.
    #[must_use]
    pub const fn from_u64(n: u64) -> Self {
        let b = n.to_be_bytes();
        Self([0, 0, 0, 0, 0, 0, 0, 0, b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
    }
}

impl fmt::Debug for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl fmt::Display for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The first and last four bytes are enough to tell devices apart in a log.
        let [h0, h1, h2, h3, .., t0, t1, t2, t3] = self.0;
        write!(f, "dev:{h0:02x}{h1:02x}{h2:02x}{h3:02x}..{t0:02x}{t1:02x}{t2:02x}{t3:02x}")
    }
}

/// A channel number of a source device. Numbers below [`FIRST_APP_CHANNEL`] belong to the bus.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Channel(pub u16);

impl Channel {
    /// Channel 0, the node info (R-CH-16).
    pub const NODE_INFO: Self = Self(0);

    /// Whether an application may publish to this channel.
    #[must_use]
    pub const fn is_application(self) -> bool {
        self.0 >= FIRST_APP_CHANNEL
    }
}

/// An action number, 1..64 (R-CALL-3).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Action(u8);

impl Action {
    /// The action with number `n`, if `n` is in 1..64.
    #[must_use]
    pub const fn new(n: u8) -> Option<Self> {
        if n >= 1 && n <= MAX_ACTION { Some(Self(n)) } else { None }
    }

    /// The number of the action.
    #[must_use]
    pub const fn number(self) -> u8 {
        self.0
    }

    /// The bit of the action in an [`ActionSet`]: bit i - 1 for action i.
    fn bit(self) -> u64 {
        // `new` guarantees 1..=64, so the shift is 0..=63.
        1u64.wrapping_shl(u32::from(self.0.saturating_sub(1)))
    }
}

/// A set of actions, encoded as 8 bytes where bit i - 1 is action i (Section 6.1).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default, Debug)]
pub struct ActionSet(u64);

impl ActionSet {
    /// The empty set.
    pub const EMPTY: Self = Self(0);

    /// The set of the given actions.
    #[must_use]
    pub fn of(actions: &[Action]) -> Self {
        actions.iter().fold(Self::EMPTY, |s, a| s.with(*a))
    }

    /// The set with one more action.
    #[must_use]
    pub fn with(self, a: Action) -> Self {
        Self(self.0 | a.bit())
    }

    /// Whether the set contains the action.
    #[must_use]
    pub fn contains(self, a: Action) -> bool {
        self.0 & a.bit() != 0
    }

    /// The 8-byte encoding of Section 6.1.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 8] {
        self.0.to_le_bytes()
    }
}

/// Passport rights (Section 6.1).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default, Debug)]
#[allow(clippy::struct_excessive_bools, reason = "the four rights of the passport")]
pub struct Rights {
    /// Receives channel keys.
    pub read: bool,
    /// Its publications and grants are accepted.
    pub publish: bool,
    /// Serves as a member relay.
    pub relay: bool,
    /// Accepts join requests.
    pub accept: bool,
}

impl Rights {
    /// Read and publish, the rights of an ordinary device.
    pub const MEMBER: Self = Self { read: true, publish: true, relay: false, accept: false };
    /// Read only.
    pub const READER: Self = Self { read: true, publish: false, relay: false, accept: false };
}

/// A permit in a target's passport: which actions a commander may invoke (Section 6.1).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Permit {
    /// The commander device.
    pub commander: DeviceId,
    /// Actions executed on the commander's device key.
    pub automatic: ActionSet,
    /// Actions that require the commander's user-presence key (R-CALL-4).
    pub confirmation: ActionSet,
}

/// Who may read a channel (R-API-2).
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub enum Readers {
    /// Every valid member with the read right.
    #[default]
    AllMembers,
    /// Only the listed devices, and only while they are valid members with the read right.
    Only(Vec<DeviceId>),
}

/// What a publication says about its blob. The blob itself is fetched with
/// [`LocalApi::fetch_blob`] and arrives in segments (R-CH-15).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct BlobInfo {
    /// The length of the blob, in bytes.
    pub size: u64,
    /// The number of segments; [`Event::BlobSegment`] counts them from 0.
    pub segments: u32,
    /// Bytes per segment; the last segment may be shorter.
    pub segment_size: u32,
    /// The hash in the publication header: SHA-256 of the encrypted blob. The blob key is
    /// drawn anew for every publication, so the hash identifies this publication's blob, for
    /// example to skip a fetch already made, and says nothing about the content: the same
    /// bytes published twice have different hashes.
    pub hash: [u8; 32],
}

/// A publication delivered to or read by the application.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Publication {
    /// The source device.
    pub source: DeviceId,
    /// The channel of the source.
    pub channel: Channel,
    /// The publication number (R-CH-8).
    pub number: u64,
    /// The data, up to [`MAX_DATA`] bytes.
    pub data: Vec<u8>,
    /// The blob's size and segment count, if the publication has a blob.
    pub blob: Option<BlobInfo>,
}

/// A blob being written by [`LocalApi::begin_blob`].
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct BlobWriteId(pub u64);

/// A blob fetch started by [`LocalApi::fetch_blob`].
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct FetchId(pub u64);

/// A call made by this node, as returned by [`LocalApi::invoke`].
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct CallId(pub u64);

/// A call received by this node, to be answered with [`LocalApi::reply`].
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct IncomingId(pub u64);

/// A request from the core to the host, answered with [`LocalApi::answer_host`].
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct HostRequestId(pub u64);

/// A stream, as returned when a call or its reply opens one (R-STR-1).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct StreamId(pub u64);

/// The mode of a stream, named in the call (R-STR-3).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum StreamMode {
    /// Every chunk arrives, in order, and each side sends only within the credit the other
    /// side granted.
    Ordered,
    /// Chunks may be lost; a late chunk is dropped; there is no credit.
    Lossy,
}

/// A request to open a stream with a call.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct StreamRequest {
    /// The mode.
    pub mode: StreamMode,
    /// The commander's initial credit: how many bytes the target may send before the
    /// commander grants more, up to [`MAX_INITIAL_CREDIT`]. Zero in lossy mode.
    pub credit: u32,
}

/// Why a stream closed (R-STR-5).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum StreamEnd {
    /// The peer sent the "end" chunk.
    Ended,
    /// The peer opened another stream under the same number, so it had closed this one.
    Replaced,
    /// The link went down.
    LinkDown,
    /// No traffic between two "reset nonces" events.
    Idle,
    /// The node halted.
    Halted,
    /// The peer is no longer a valid member.
    Revoked,
    /// Ordered mode: a chunk arrived out of order (`str/out-of-order`).
    OutOfOrder,
    /// Ordered mode: the peer sent more than the credit it was granted (`str/over-credit`).
    OverCredit,
    /// The peer sent a chunk whose flags name no single meaning (R-STR-2).
    BadChunk,
}

/// The key that signed a call (R-CALL-4).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum CallKey {
    /// The commander's device key: an automatic action.
    Device,
    /// The commander's user-presence key: the user confirmed this call on the commander.
    Presence,
    /// The root key: the owner confirmed this call on the root device.
    Root,
}

/// A call result code (R-CALL-11): 0..255 belong to the bus, 256..65535 to the application.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct ResultCode(pub u16);

impl ResultCode {
    /// Executed.
    pub const DONE: Self = Self(0);
    /// Not permitted.
    pub const NO_RIGHT: Self = Self(1);
    /// Declined by the user.
    pub const DECLINED: Self = Self(2);
    /// Invalid arguments.
    pub const BAD_ARGUMENTS: Self = Self(3);
    /// Action not served.
    pub const NOT_SERVED: Self = Self(4);
    /// Too many streams.
    pub const TOO_MANY_STREAMS: Self = Self(5);
    /// The first code that belongs to the application.
    pub const FIRST_APPLICATION: Self = Self(256);

    /// Whether the application may reply with this code: an application code, or one of the
    /// bus codes that describe the application's own decision.
    #[must_use]
    pub const fn allowed_in_reply(self) -> bool {
        self.0 >= Self::FIRST_APPLICATION.0
            || self.0 == Self::DONE.0
            || self.0 == Self::DECLINED.0
            || self.0 == Self::BAD_ARGUMENTS.0
    }
}

/// How a call ended, as the commander sees it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum CallOutcome {
    /// The target replied.
    Replied {
        /// The result code.
        code: ResultCode,
        /// The target's message: text for a log, not data; empty if the target sent none.
        message: String,
        /// The result data.
        data: Vec<u8>,
        /// The stream the reply opened, if the call asked for one and the target agreed.
        stream: Option<StreamId>,
    },
    /// The outcome is unknown: the call may or may not have been executed (L7, R-CALL-13).
    Unknown,
    /// The call was not sent, for the reason given.
    NotSent(Report),
}

/// Options of a call.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
pub struct InvokeOptions {
    /// The action may be executed more than once with the same effect, so the core may retry it
    /// after a "nonce mismatch" refusal (R-CALL-13).
    pub idempotent: bool,
    /// Sign with the root key; only on the root device (R-CALL-4).
    pub as_root: bool,
    /// Ask the target to open a stream with its reply (R-STR-1).
    pub stream: Option<StreamRequest>,
}

/// What the core asks the host to do. The host answers after asking the user.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum HostRequestKind {
    /// Sign a confirmation-class call with the user-presence key (R-API-3).
    SignWithPresenceKey {
        /// The target of the call.
        target: DeviceId,
        /// The action.
        action: Action,
    },
    /// Sign a call with the root key.
    SignWithRootKey {
        /// The target of the call.
        target: DeviceId,
        /// The action.
        action: Action,
    },
    /// Sign membership records with the root key: an owner's operation on a device.
    SignMembership {
        /// The device the records concern.
        device: DeviceId,
        /// The operation.
        operation: OwnerOperation,
    },
}

/// An owner's operation on the root device (R-API-2).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum OwnerOperation {
    /// A new passport with other rights or permits, and a checkpoint that clears the old one.
    Change,
    /// A checkpoint that clears the device's passport.
    Revoke,
}

/// The host's answer to a request.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum HostAnswer {
    /// The user confirmed and the key signed.
    Approve,
    /// The user declined, or the key failed.
    Refuse,
}

/// Something the bus delivers to the application.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Event {
    /// A publication was accepted on a channel this node reads.
    Publication(Publication),
    /// A clearing publication emptied a channel (R-CH-10).
    Cleared {
        /// The source device.
        source: DeviceId,
        /// The channel.
        channel: Channel,
    },
    /// A member published its node info on channel 0 (R-CH-16).
    NodeInfo {
        /// The member.
        device: DeviceId,
        /// Its name.
        name: String,
        /// The application part, opaque to the core; empty if the member set none.
        app: Vec<u8>,
    },
    /// The node accepted a checkpoint or a passport: the members, their rights, or the root
    /// device may have changed. [`LocalApi::state`] gives the new picture.
    MembershipChanged {
        /// The root generation.
        generation: u32,
        /// The checkpoint number.
        checkpoint: u32,
    },
    /// A verified segment of a blob being fetched. The segments of one fetch arrive in
    /// order, and the core asks for the next one only after the application has taken this
    /// event, so the application sets the pace.
    BlobSegment {
        /// The fetch.
        fetch: FetchId,
        /// The segment number, from 0.
        segment: u32,
        /// The offset of the segment in the blob, in bytes.
        offset: u64,
        /// The segment's bytes.
        data: Vec<u8>,
    },
    /// A blob fetch ended: every requested segment was delivered, or the fetch stopped for
    /// the reason given and will not resume. A cancelled fetch raises no event.
    BlobFetchFinished {
        /// The fetch.
        fetch: FetchId,
        /// How it ended.
        result: Result<(), Report>,
    },
    /// A call to an action this node registered.
    IncomingCall {
        /// The handle for [`LocalApi::reply`].
        id: IncomingId,
        /// The commander device.
        commander: DeviceId,
        /// The action.
        action: Action,
        /// The key that signed the call. The target's passport decides which key an action
        /// needs; the root key has the right to every action.
        signed_by: CallKey,
        /// The arguments.
        args: Vec<u8>,
        /// The stream the commander asks for; [`LocalApi::reply_with_stream`] opens it.
        stream: Option<StreamRequest>,
    },
    /// Data arrived on a stream.
    StreamData {
        /// The stream.
        stream: StreamId,
        /// The bytes of one chunk.
        data: Vec<u8>,
    },
    /// The peer granted more credit: this side may send that many more bytes.
    StreamCredit {
        /// The stream.
        stream: StreamId,
        /// The bytes added.
        added: u32,
    },
    /// A relay on the stream's path reported that it does not serve streams (R-STR-7). The
    /// report is an unsigned hint that the network can forge, so the core changes nothing:
    /// the stream stays open, and the application decides whether to end it.
    StreamRefused {
        /// The stream.
        stream: StreamId,
    },
    /// A stream closed for a reason other than this side's own "end".
    StreamClosed {
        /// The stream.
        stream: StreamId,
        /// Why.
        reason: StreamEnd,
    },
    /// A call made by this node ended.
    CallFinished {
        /// The call.
        call: CallId,
        /// How it ended.
        outcome: CallOutcome,
    },
    /// The core needs a signature that only the user can authorise.
    HostRequest {
        /// The handle for [`LocalApi::answer_host`].
        id: HostRequestId,
        /// What is asked.
        kind: HostRequestKind,
    },
    /// The node halted (R-MEM-8, R-MEM-10).
    Halted,
    /// The node refused a message; shown in debug mode, logged in both (R-ERR-2).
    Rejected(Report),
}

/// A valid member as the node sees it: the public content of its passport (Section 6.1).
/// These are the values [`LocalApi::change_member`] takes, so a root application reads a
/// member, changes what it means to change, and writes the rest back as it was.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct Member {
    /// The device.
    pub device: DeviceId,
    /// Its rights.
    pub rights: Rights,
    /// Whether the passport names a user-presence key.
    pub presence: bool,
    /// Who may command this device, and with which actions.
    pub permits: Vec<Permit>,
}

/// A snapshot of the bus state without secrets and without side effects (R-API-2).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BusState {
    /// The bus identifier.
    pub bus: [u8; 32],
    /// This device.
    pub device: DeviceId,
    /// The root generation.
    pub generation: u32,
    /// The checkpoint number.
    pub checkpoint: u32,
    /// The root device named by the checkpoint. It changes with a root change and with a
    /// checkpoint that moves the root to another device (R-MEM-17).
    pub root_device: DeviceId,
    /// Whether the node is halted.
    pub halted: bool,
    /// Known valid members with their rights.
    pub members: Vec<Member>,
    /// Devices with a connected link.
    pub links: Vec<DeviceId>,
    /// Memory used by the node's state, in bytes, as estimated by the implementation.
    pub memory_used: usize,
}

/// The operations of R-API-2.
pub trait LocalApi {
    /// Publishes `data` on an own channel with retention `depth` (R-CH-10) and returns the
    /// publication number. Empty data at depth 1 or more clears the channel.
    ///
    /// # Errors
    /// `api/reserved-channel`, `api/data-too-large`, `api/depth-too-large`, `mem/halted`.
    fn publish(&mut self, channel: Channel, data: &[u8], depth: u16) -> Result<u64, Report>;

    /// Starts a publication with a blob (R-CH-15). The blob is passed in pieces of any size
    /// with [`LocalApi::write_blob`]; the core encrypts it segment by segment into host
    /// storage, so it never holds the whole blob in memory. [`LocalApi::finish_blob`]
    /// publishes it. A blob is served while its publication is retained, so `depth` is at
    /// least 1.
    ///
    /// # Errors
    /// `api/reserved-channel`, `api/data-too-large`, `api/depth-too-large`, `api/bad-blob`,
    /// `mem/halted`.
    fn begin_blob(&mut self, channel: Channel, data: &[u8], depth: u16) -> Result<BlobWriteId, Report>;

    /// Appends bytes to a blob being written.
    ///
    /// # Errors
    /// `api/unknown-id`, `api/data-too-large` past the largest blob.
    fn write_blob(&mut self, id: BlobWriteId, bytes: &[u8]) -> Result<(), Report>;

    /// Publishes a written blob and returns the publication number. The number is taken
    /// now, so publications made while the blob was written keep their order.
    ///
    /// # Errors
    /// `api/unknown-id`, `api/bad-blob` for an empty blob, `mem/halted`, and the errors of
    /// [`LocalApi::publish`].
    fn finish_blob(&mut self, id: BlobWriteId) -> Result<u64, Report>;

    /// Drops a blob being written.
    ///
    /// # Errors
    /// `api/unknown-id`.
    fn abort_blob(&mut self, id: BlobWriteId) -> Result<(), Report>;

    /// Fetches `count` segments of the blob of a retained publication, starting with segment
    /// `first`; [`BlobInfo`] gives the number of segments, so `(0, segments)` is the whole
    /// blob. The segments arrive as [`Event::BlobSegment`] and the end as
    /// [`Event::BlobFetchFinished`]. Several fetches may run at once, also on one blob. A
    /// fetch does not survive a reboot; the application starts another from the segment it
    /// needs next.
    ///
    /// # Errors
    /// `api/unknown-id` if the node holds no such publication with a blob, `api/bad-range`,
    /// `mem/halted`.
    fn fetch_blob(
        &mut self,
        source: DeviceId,
        channel: Channel,
        number: u64,
        first: u32,
        count: u32,
    ) -> Result<FetchId, Report>;

    /// Stops a fetch. No further event of that fetch is delivered.
    ///
    /// # Errors
    /// `api/unknown-id` if the fetch has ended.
    fn cancel_fetch(&mut self, fetch: FetchId) -> Result<(), Report>;

    /// The retained publications of a channel that this node holds, in number order; for an
    /// own channel, the source's retained publications. The node holds what arrived under a
    /// key it has: channels whose readers are all members grant the key without a request,
    /// while for a channel with a reader list the key may not have arrived before
    /// [`LocalApi::subscribe`].
    fn read(&self, source: DeviceId, channel: Channel) -> Vec<Publication>;

    /// Asks the source for the channel key if the node has none, delivers what is retained
    /// at once, and from then on delivers the channel's publications as events (R-CH-18).
    ///
    /// # Errors
    /// `mem/halted`.
    fn subscribe(&mut self, source: DeviceId, channel: Channel) -> Result<(), Report>;

    /// Sets who may read an own channel. Removing a reader rotates the key (R-CH-5).
    ///
    /// # Errors
    /// `api/reserved-channel`, `mem/halted`.
    fn set_readers(&mut self, channel: Channel, readers: Readers) -> Result<(), Report>;

    /// Marks an own channel for a new key: the current key is granted to no one from now on,
    /// and the source makes and grants a new one before its next publication or grant
    /// (R-CH-5). Called before [`LocalApi::set_readers`] adds a reader, it keeps that reader
    /// from the publications made under the old key (R-CH-6). Publications retained under the
    /// old key are not sent again under the new one.
    ///
    /// # Errors
    /// `api/reserved-channel`, `mem/halted`.
    fn rotate_channel_key(&mut self, channel: Channel) -> Result<(), Report>;

    /// Invokes an action on a target. The outcome arrives as [`Event::CallFinished`]. With
    /// [`InvokeOptions::stream`] the call asks the target to open a stream.
    ///
    /// # Errors
    /// `api/data-too-large`, `api/not-root`, `api/bad-stream` for credit in lossy mode,
    /// `str/too-many` at this node's own limit of streams, `mem/halted`.
    fn invoke(
        &mut self,
        target: DeviceId,
        action: Action,
        args: &[u8],
        options: InvokeOptions,
    ) -> Result<CallId, Report>;

    /// Replies to an incoming call. `message` is text for the commander's log, up to
    /// [`MAX_MESSAGE`] bytes, or empty (R-CALL-10).
    ///
    /// # Errors
    /// `api/unknown-id`, `api/bus-result`, `api/data-too-large`, `api/message-too-long`.
    fn reply(&mut self, call: IncomingId, code: ResultCode, message: &str, data: &[u8]) -> Result<(), Report>;

    /// Replies to an incoming call that asked for a stream and opens the stream. `credit` is
    /// how many bytes the commander may send before this side grants more; zero in lossy
    /// mode. At the limit of open streams the core replies "too many streams" itself and
    /// existing streams stay (R-STR-6).
    ///
    /// # Errors
    /// `api/unknown-id`, `api/bad-stream` if the call asked for no stream or the credit does
    /// not fit the mode, `str/too-many`, and the errors of [`LocalApi::reply`].
    fn reply_with_stream(
        &mut self,
        call: IncomingId,
        code: ResultCode,
        message: &str,
        data: &[u8],
        credit: u32,
    ) -> Result<StreamId, Report>;

    /// Sends one chunk of data, 1 to [`MAX_STREAM_DATA`] bytes or the profile's smaller
    /// limit. In ordered mode the data must fit the credit the peer granted; otherwise
    /// nothing is sent and the application waits for [`Event::StreamCredit`] (R-STR-4).
    ///
    /// # Errors
    /// `api/unknown-id` for a closed stream, `api/data-too-large`, `api/bad-stream` for
    /// empty data, `str/no-credit`.
    fn stream_write(&mut self, stream: StreamId, data: &[u8]) -> Result<(), Report>;

    /// Grants the peer credit for `bytes` more, in ordered mode (R-STR-4). The application
    /// grants what it is ready to receive, so the credit it has out bounds what the core
    /// holds for it.
    ///
    /// # Errors
    /// `api/unknown-id`, `api/bad-stream` for a lossy stream or zero bytes.
    fn stream_grant(&mut self, stream: StreamId, bytes: u32) -> Result<(), Report>;

    /// Ends a stream with the "end" chunk (R-STR-5).
    ///
    /// # Errors
    /// `api/unknown-id`.
    fn stream_end(&mut self, stream: StreamId) -> Result<(), Report>;

    /// Registers this node as the handler of an action; calls to other actions are answered
    /// "action not served".
    fn register_action(&mut self, action: Action);

    /// Sets the node name; the core publishes it on channel 0 (R-CH-16).
    ///
    /// # Errors
    /// `api/name-too-long`, `mem/halted`.
    fn set_name(&mut self, name: &str) -> Result<(), Report>;

    /// Sets the application part of the node info, opaque to the core; the core publishes
    /// it on channel 0 with the name (R-CH-16). Every valid member with the read right
    /// receives it and only the latest is kept, so it suits slowly changing state.
    ///
    /// # Errors
    /// `api/app-info-too-large`, `mem/halted`.
    fn set_app_info(&mut self, app: &[u8]) -> Result<(), Report>;

    /// A snapshot of the bus state.
    fn state(&self) -> BusState;

    /// The next event, if any.
    fn poll_event(&mut self) -> Option<Event>;

    /// Answers a host request.
    ///
    /// # Errors
    /// `api/unknown-id`.
    fn answer_host(&mut self, id: HostRequestId, answer: HostAnswer) -> Result<(), Report>;

    /// On the root device: changes a member's rights, user-presence key and permits (R-MEM-4).
    /// The records are signed after the host confirms the request returned here.
    ///
    /// # Errors
    /// `api/not-root`, `api/unknown-id` for a device that is not a member, `mem/halted`.
    fn change_member(
        &mut self,
        device: DeviceId,
        rights: Rights,
        presence: bool,
        permits: Vec<Permit>,
    ) -> Result<HostRequestId, Report>;

    /// On the root device: revokes a member (R-MEM-4). The checkpoint is signed after the host
    /// confirms the request returned here.
    ///
    /// # Errors
    /// `api/not-root`, `api/unknown-id` for a device that is not a member, `mem/halted`.
    fn revoke(&mut self, device: DeviceId) -> Result<HostRequestId, Report>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_codes_are_unique_and_parse() {
        for (i, a) in codes::ALL.iter().enumerate() {
            for b in codes::ALL.iter().skip(i.saturating_add(1)) {
                assert!(!(a.area() == b.area() && a.rule() == b.rule()), "duplicate {a}");
            }
            let text = alloc::format!("{a}");
            assert_eq!(RuleCode::parse(&text), Some(*a));
        }
    }

    #[test]
    fn modes_render() {
        let r = Report::new(RuleCode::CALL_NO_RIGHT, "action 3 from dev:1");
        assert_eq!(r.render(ErrorMode::Release), "The caller has no right to this action.");
        let d = r.render(ErrorMode::Debug);
        assert!(d.contains("call/no-right"));
        assert!(d.contains("R-CALL-4"));
        assert!(d.contains("refused"));
        assert!(d.contains("action 3 from dev:1"));
        assert_eq!(ErrorMode::resolve(Some("RELEASE")), ErrorMode::Release);
        assert_eq!(ErrorMode::resolve(Some("debug")), ErrorMode::Debug);
        assert_eq!(ErrorMode::resolve(Some("junk")), ErrorMode::for_build());
    }

    #[test]
    fn action_sets() {
        let a1 = Action::new(1).unwrap_or(Action(1));
        let a64 = Action::new(64).unwrap_or(Action(64));
        assert!(Action::new(0).is_none());
        assert!(Action::new(65).is_none());
        let s = ActionSet::of(&[a1, a64]);
        assert!(s.contains(a1) && s.contains(a64));
        assert_eq!(s.to_bytes(), [1, 0, 0, 0, 0, 0, 0, 0x80]);
    }
}
