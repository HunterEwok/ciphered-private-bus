// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 HunterEwok

//! One side of a stream: chunk numbers, the two modes, and credit.
//!
//! This is the `streams` Quint model (models/streams) written as Rust, with the same state
//! and the same transitions; the trace replay test checks that they agree. The model counts
//! data in units, one per chunk; here a chunk carries bytes and credit is counted in bytes
//! (R-STR-4), so a model unit is a chunk of one byte. The model's `k`, the number of the
//! call whose HPKE context keys the stream (R-STR-1), stands in for the stream keys: a chunk
//! opens only under the `k` of its own stream instance.

use std::collections::BTreeMap;

use cpb_api::StreamMode;

/// What a chunk carries. Exactly one of the three flags is set (R-STR-2).
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Kind {
    /// Data bytes.
    Data(Vec<u8>),
    /// Credit added to what the peer may send, in bytes.
    Credit(u32),
    /// The end of the stream.
    End,
}

/// A chunk as it travels, without its addressing.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Chunk {
    /// The stream instance: stands in for the key.
    pub k: u64,
    /// The chunk number of its direction, from 1.
    pub no: u32,
    /// What it carries.
    pub kind: Kind,
}

/// Why a side refused to send.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SendError {
    /// Ordered mode: the data exceeds the credit the peer granted (R-STR-4).
    NoCredit,
    /// The chunk numbers of this direction are used up (Section 13.1).
    Exhausted,
    /// Credit does not apply in lossy mode (R-STR-3).
    LossyCredit,
}

/// What a received chunk did.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Received {
    /// Data for the application.
    Data(Vec<u8>),
    /// The peer added credit: this side may send that many more bytes.
    Credit(u32),
    /// The peer ended the stream; the side is closed.
    End,
    /// Dropped without a state change: an old chunk in lossy mode.
    Dropped,
    /// Ordered mode: the chunk is not the next one, so the stream closes (R-STR-3).
    OutOfOrder,
    /// Ordered mode: the data exceeds the credit this side granted, so the stream closes
    /// (R-STR-4).
    OverCredit,
}

impl Received {
    /// Whether the side is closed after this chunk.
    #[must_use]
    pub const fn closes(&self) -> bool {
        matches!(self, Self::End | Self::OutOfOrder | Self::OverCredit)
    }
}

/// Highest chunk number of a direction (Section 13.1).
pub const MAX_CHUNK_NO: u32 = 0x7fff_ffff;

/// One side of an open stream.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Side {
    /// The stream instance.
    pub k: u64,
    /// The mode named in the call.
    pub mode: StreamMode,
    /// The number of the next chunk this side sends.
    pub next: u32,
    /// The highest chunk number accepted from the peer.
    pub high: u32,
    /// Bytes this side may still send.
    pub send_credit: u64,
    /// Bytes this side still lets the peer send.
    pub recv_credit: u64,
    /// No traffic since the last "reset nonces" (R-STR-5).
    pub idle: bool,
    /// Ghost: all credit received, the initial credit included.
    pub got: u64,
    /// Ghost: all credit given, the initial credit included.
    pub granted: u64,
    /// Ghost: data chunks sent.
    pub sent: u64,
    /// Ghost: data chunks received.
    pub recvd: u64,
}

impl Side {
    /// A side opened by a call or its reply (R-STR-1, R-STR-4).
    #[must_use]
    pub fn new(k: u64, mode: StreamMode, send_credit: u64, recv_credit: u64) -> Self {
        Self {
            k,
            mode,
            next: 1,
            high: 0,
            send_credit,
            recv_credit,
            idle: false,
            got: send_credit,
            granted: recv_credit,
            sent: 0,
            recvd: 0,
        }
    }

    /// Sends a chunk: it takes the next number whatever it carries (R-STR-2).
    ///
    /// # Errors
    /// The reason nothing was sent; the side is unchanged.
    pub fn send(&mut self, kind: Kind) -> Result<Chunk, SendError> {
        if self.next > MAX_CHUNK_NO {
            return Err(SendError::Exhausted);
        }
        match &kind {
            Kind::Data(d) => {
                let len = u64::try_from(d.len()).unwrap_or(u64::MAX);
                if self.mode == StreamMode::Ordered {
                    self.send_credit = self.send_credit.checked_sub(len).ok_or(SendError::NoCredit)?;
                }
                self.sent = self.sent.saturating_add(1);
            }
            Kind::Credit(add) => {
                if self.mode == StreamMode::Lossy {
                    return Err(SendError::LossyCredit);
                }
                self.recv_credit = self.recv_credit.saturating_add(u64::from(*add));
                self.granted = self.granted.saturating_add(u64::from(*add));
            }
            Kind::End => {}
        }
        let no = self.next;
        self.next = self.next.saturating_add(1);
        self.idle = false;
        Ok(Chunk { k: self.k, no, kind })
    }

    /// Receives a chunk of this stream instance from the peer (R-STR-3, R-STR-4). The
    /// caller has matched the stream and the key; it removes the side if the result closes.
    pub fn receive(&mut self, chunk: &Chunk) -> Received {
        match self.mode {
            StreamMode::Ordered => {
                if chunk.no != self.high.saturating_add(1) {
                    return Received::OutOfOrder;
                }
                self.high = chunk.no;
                self.idle = false;
                match &chunk.kind {
                    Kind::End => Received::End,
                    Kind::Credit(add) => {
                        self.send_credit = self.send_credit.saturating_add(u64::from(*add));
                        self.got = self.got.saturating_add(u64::from(*add));
                        Received::Credit(*add)
                    }
                    Kind::Data(d) => {
                        let len = u64::try_from(d.len()).unwrap_or(u64::MAX);
                        match self.recv_credit.checked_sub(len) {
                            Some(left) => {
                                self.recv_credit = left;
                                self.recvd = self.recvd.saturating_add(1);
                                Received::Data(d.clone())
                            }
                            None => Received::OverCredit,
                        }
                    }
                }
            }
            StreamMode::Lossy => {
                if chunk.no <= self.high {
                    return Received::Dropped;
                }
                self.high = chunk.no;
                self.idle = false;
                match &chunk.kind {
                    Kind::End => Received::End,
                    // A lossy stream has no credit; a credit chunk only takes its number.
                    Kind::Credit(_) => Received::Dropped,
                    Kind::Data(d) => {
                        self.recvd = self.recvd.saturating_add(1);
                        Received::Data(d.clone())
                    }
                }
            }
        }
    }

    /// "Reset nonces" (R-STR-5): a side without traffic since the previous such event
    /// closes; the others start a new period. Returns whether the side stays open.
    pub fn reset_period(&mut self) -> bool {
        if self.idle {
            return false;
        }
        self.idle = true;
        true
    }
}

/// The streams one party has with one peer in one role: the model's node.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct Table {
    /// Open streams by stream number.
    pub streams: BTreeMap<u32, Side>,
}

/// What a chunk did to a table.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Taken {
    /// No stream with this number and key: dropped, nothing changes, nothing is sent
    /// (R-STR-3).
    Unknown,
    /// The stream took the chunk; it is gone from the table if the result closes.
    Stream(Received),
}

impl Table {
    /// The target opens a stream under the smallest free number (R-STR-6). `room` says
    /// whether the node is below its limit of open streams; without room nothing changes.
    pub fn open(&mut self, side: Side, room: bool) -> Option<u32> {
        if !room {
            return None;
        }
        let sid = (1..=u32::MAX).find(|i| !self.streams.contains_key(i))?;
        self.streams.insert(sid, side);
        Some(sid)
    }

    /// The commander opens its side under the number the reply names. A stale side under
    /// that number, which the target closed without the commander noticing, is replaced and
    /// returned.
    pub fn open_as(&mut self, sid: u32, side: Side) -> Option<Side> {
        self.streams.insert(sid, side)
    }

    /// Sends a chunk on a stream; an "end" chunk closes this side.
    ///
    /// # Errors
    /// The reason nothing was sent; `None` if there is no such stream.
    pub fn send(&mut self, sid: u32, kind: Kind) -> Result<Chunk, Option<SendError>> {
        let side = self.streams.get_mut(&sid).ok_or(None)?;
        let end = kind == Kind::End;
        let chunk = side.send(kind).map_err(Some)?;
        if end {
            self.streams.remove(&sid);
        }
        Ok(chunk)
    }

    /// Receives a chunk the peer sent under stream number `sid` (R-STR-3).
    pub fn receive(&mut self, sid: u32, chunk: &Chunk) -> Taken {
        let Some(side) = self.streams.get_mut(&sid) else { return Taken::Unknown };
        if side.k != chunk.k {
            return Taken::Unknown;
        }
        let got = side.receive(chunk);
        if got.closes() {
            self.streams.remove(&sid);
        }
        Taken::Stream(got)
    }

    /// "Reset nonces" (R-STR-5): returns the numbers of the idle streams it closed.
    pub fn reset_period(&mut self) -> Vec<u32> {
        let closed: Vec<u32> = self.streams.iter().filter(|(_, s)| s.idle).map(|(i, _)| *i).collect();
        self.streams.retain(|_, s| s.reset_period());
        closed
    }

    /// Link down, halt, revocation of the peer, or reboot: every stream closes. Returns
    /// their numbers.
    pub fn close_all(&mut self) -> Vec<u32> {
        let closed = self.streams.keys().copied().collect();
        self.streams.clear();
        closed
    }
}
