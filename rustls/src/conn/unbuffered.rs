//! Unbuffered connection API

use alloc::vec::Vec;
use core::num::NonZeroUsize;
use core::{fmt, mem};
#[cfg(feature = "std")]
use std::error::Error as StdError;

use super::{UnbufferedConnectionCommon, hs_buffer_fast_is_active};
use crate::client::ClientConnectionData;
use crate::msgs::deframer::buffers::{BufferProgress, DeframerSliceBuffer};
use crate::msgs::deframer::DeframerIterImmut;
use crate::server::ServerConnectionData;
use crate::{ContentType, Error};

impl UnbufferedConnectionCommon<ClientConnectionData> {
    /// Processes the TLS records in `incoming_tls` buffer until a new [`UnbufferedStatus`] is
    /// reached.
    pub fn process_tls_records<'c, 'i>(
        &'c mut self,
        incoming_tls: &'i mut [u8],
    ) -> UnbufferedStatus<'c, 'i, ClientConnectionData> {
        self.process_tls_records_common(incoming_tls, |_| false, |_, _| unreachable!())
    }

    /// Decrypts TLS records from `src` into `dst` at the specified offset.
    ///
    /// This API allows decrypting from one buffer to another ("read A, write B"),
    /// enabling zero-copy patterns where multiple TLS records can be decrypted
    /// sequentially into the same destination buffer.
    pub fn decrypt_to<'c>(
        &'c mut self,
        incoming_tls: &[u8],
        outcoming_tls: &mut [u8],
    ) -> UnbufferedStatus<'c, 'c, ClientConnectionData> {
        self.process_tls_records_fast(incoming_tls, outcoming_tls)
    }

    /// Return the current inbound TLS record sequence number.
    ///
    /// This is intentionally exposed for kernel/DPDK-style external record
    /// scheduling.  Callers that decrypt records out of order must only commit
    /// a sequence after the candidate record authenticates and the application
    /// data has been accepted.
    pub fn dangerous_read_seq(&self) -> u64 {
        self.core.common_state.record_layer.read_seq()
    }

    /// Try decrypting exactly one complete TLS record with an explicit inbound
    /// record sequence number, without mutating the connection sequence state.
    ///
    /// `record` must include the 5-byte TLS record header.  `outgoing_tls`
    /// receives plaintext on success.  The return value is the plaintext
    /// payload length after TLS 1.3 inner-content unpadding.
    pub fn dangerous_try_decrypt_record_to_at(
        &mut self,
        record: &[u8],
        seq: u64,
        outgoing_tls: &mut [u8],
    ) -> Result<Option<usize>, Error> {
        self.try_decrypt_one_record_to_at(record, seq, outgoing_tls)
    }

    /// Try decrypting exactly one complete TLS 1.3 record with the speculative
    /// next inbound traffic key and an explicit record sequence number.
    ///
    /// This does not switch traffic-key epochs or change the record-layer read
    /// sequence.  [`Error::DecryptError`] specifically means AEAD authentication
    /// failed; framing, connection-state, and output-buffer errors remain
    /// distinguishable through their existing error variants.  After this
    /// returns application data successfully, the caller may explicitly commit
    /// that key and sequence with [`Self::dangerous_commit_next_inbound_key`].
    pub fn dangerous_try_decrypt_record_to_at_with_next_key(
        &mut self,
        record: &[u8],
        seq: u64,
        outgoing_tls: &mut [u8],
    ) -> Result<Option<usize>, Error> {
        self.try_decrypt_one_record_to_at_with_next_key(record, seq, outgoing_tls)
    }

    /// Commit the inbound TLS record sequence after an externally scheduled
    /// decrypt succeeds.
    pub fn dangerous_commit_read_seq(&mut self, next_seq: u64) {
        self.core
            .common_state
            .record_layer
            .commit_read_seq_after_decrypt(next_seq);
    }

    /// Commit a successfully authenticated speculative next inbound traffic
    /// key, then set the read sequence to `matched_seq + 1`.
    ///
    /// The commit fails without changing the key epoch or sequence unless the
    /// same speculative key previously authenticated `matched_seq`.  A
    /// successful commit also prepares the following inbound traffic key while
    /// keeping all traffic secrets internal to rustls.
    pub fn dangerous_commit_next_inbound_key(
        &mut self,
        matched_seq: u64,
    ) -> Result<(), Error> {
        let state = &mut self.core.state;
        let common = &mut self.core.common_state;
        match state {
            Ok(state) => state.commit_next_inbound_traffic_key(common, matched_seq),
            Err(error) => Err(error.clone()),
        }
    }
}

impl UnbufferedConnectionCommon<ServerConnectionData> {
    /// Processes the TLS records in `incoming_tls` buffer until a new [`UnbufferedStatus`] is
    /// reached.
    pub fn process_tls_records<'c, 'i>(
        &'c mut self,
        incoming_tls: &'i mut [u8],
    ) -> UnbufferedStatus<'c, 'i, ServerConnectionData> {
        self.process_tls_records_common(
            incoming_tls,
            |conn| conn.peek_early_data().is_some(),
            |conn, incoming_tls| ReadEarlyData::new(conn, incoming_tls).into(),
        )
    }
}

impl<Data> UnbufferedConnectionCommon<Data> {
    fn try_decrypt_one_record_to_at<'a>(
        &mut self,
        record: &[u8],
        seq: u64,
        outgoing_tls: &'a mut [u8],
    ) -> Result<Option<usize>, Error> {
        if !self
            .core
            .common_state
            .may_receive_application_data
            || hs_buffer_fast_is_active(&self.hs_buffer_fast)
        {
            return Ok(None);
        }
        let mut iter = DeframerIterImmut::new(record);
        let message = match iter.next().transpose()? {
            Some(message) => message,
            None => return Ok(None),
        };
        if iter.bytes_consumed() != record.len() {
            return Ok(None);
        }
        let decrypted = match self
            .core
            .common_state
            .record_layer
            .try_decrypt_incoming_to_at(message, seq, outgoing_tls)?
        {
            Some(decrypted) => decrypted,
            None => return Ok(None),
        };
        if decrypted.plaintext.typ != ContentType::ApplicationData {
            return Ok(None);
        }
        Ok(Some(decrypted.plaintext.payload.len()))
    }

    fn try_decrypt_one_record_to_at_with_next_key<'a>(
        &mut self,
        record: &[u8],
        seq: u64,
        outgoing_tls: &'a mut [u8],
    ) -> Result<Option<usize>, Error> {
        if !self
            .core
            .common_state
            .may_receive_application_data
            || hs_buffer_fast_is_active(&self.hs_buffer_fast)
        {
            return Ok(None);
        }
        let mut iter = DeframerIterImmut::new(record);
        let message = match iter.next().transpose()? {
            Some(message) => message,
            None => return Ok(None),
        };
        if iter.bytes_consumed() != record.len() {
            return Ok(None);
        }
        let plaintext = match self.core.state.as_mut() {
            Ok(state) => state.try_decrypt_with_next_inbound_traffic_key(
                &message,
                seq,
                outgoing_tls,
            )?,
            Err(error) => return Err(error.clone()),
        };
        if plaintext.typ != ContentType::ApplicationData {
            return Ok(None);
        }
        Ok(Some(plaintext.payload.len()))
    }

    fn process_tls_records_common<'c, 'i>(
        &'c mut self,
        incoming_tls: &'i mut [u8],
        mut early_data_available: impl FnMut(&mut Self) -> bool,
        early_data_state: impl FnOnce(&'c mut Self, &'i mut [u8]) -> ConnectionState<'c, 'i, Data>,
    ) -> UnbufferedStatus<'c, 'i, Data> {
        let mut buffer = DeframerSliceBuffer::new(incoming_tls);
        let mut buffer_progress = self.core.hs_deframer.progress();

        let (discard, state) = loop {
            if early_data_available(self) {
                break (
                    buffer.pending_discard(),
                    early_data_state(self, incoming_tls),
                );
            }

            if !self
                .core
                .common_state
                .received_plaintext
                .is_empty()
            {
                break (
                    buffer.pending_discard(),
                    ReadTraffic::new(self, incoming_tls).into(),
                );
            }

            if let Some(chunk) = self
                .core
                .common_state
                .sendable_tls
                .pop()
            {
                break (
                    buffer.pending_discard(),
                    EncodeTlsData::new(self, chunk).into(),
                );
            }

            let deframer_output = if self
                .core
                .common_state
                .has_received_close_notify
            {
                None
            } else {
                match self
                    .core
                    .deframe(None, buffer.filled_mut(), &mut buffer_progress)
                {
                    Err(err) => {
                        buffer.queue_discard(buffer_progress.take_discard());
                        return UnbufferedStatus {
                            discard: buffer.pending_discard(),
                            state: Err(err),
                        };
                    }
                    Ok(r) => r,
                }
            };

            if let Some(msg) = deframer_output {
                let mut state =
                    match mem::replace(&mut self.core.state, Err(Error::HandshakeNotComplete)) {
                        Ok(state) => state,
                        Err(e) => {
                            buffer.queue_discard(buffer_progress.take_discard());
                            self.core.state = Err(e.clone());
                            return UnbufferedStatus {
                                discard: buffer.pending_discard(),
                                state: Err(e),
                            };
                        }
                    };

                match self.core.process_msg(msg, state, None) {
                    Ok(new) => state = new,

                    Err(e) => {
                        buffer.queue_discard(buffer_progress.take_discard());
                        self.core.state = Err(e.clone());
                        return UnbufferedStatus {
                            discard: buffer.pending_discard(),
                            state: Err(e),
                        };
                    }
                }

                buffer.queue_discard(buffer_progress.take_discard());

                self.core.state = Ok(state);
            } else if self.wants_write {
                break (
                    buffer.pending_discard(),
                    TransmitTlsData { conn: self }.into(),
                );
            } else if self
                .core
                .common_state
                .has_received_close_notify
                && !self.emitted_peer_closed_state
            {
                self.emitted_peer_closed_state = true;
                break (buffer.pending_discard(), ConnectionState::PeerClosed);
            } else if self
                .core
                .common_state
                .has_received_close_notify
                && self
                    .core
                    .common_state
                    .has_sent_close_notify
            {
                break (buffer.pending_discard(), ConnectionState::Closed);
            } else if self
                .core
                .common_state
                .may_send_application_data
            {
                break (
                    buffer.pending_discard(),
                    ConnectionState::WriteTraffic(WriteTraffic { conn: self }),
                );
            } else {
                break (buffer.pending_discard(), ConnectionState::BlockedHandshake);
            }
        };

        UnbufferedStatus {
            discard,
            state: Ok(state),
        }
    }

    /// Process TLS records with zero-copy decryption.
    ///
    /// This is the fast path API:
    /// - `incoming_tls`: immutable input buffer containing encrypted TLS records
    /// - `outgoing_tls`: mutable output buffer for decrypted data
    ///
    /// Returns `FastReadLen(len)` for ApplicationData, indicating `len` bytes
    /// of decrypted data are available in `outgoing_tls`.
    pub fn process_tls_records_fast<'c>(
        &'c mut self,
        incoming_tls: &[u8],
        outgoing_tls: &mut [u8],
    ) -> UnbufferedStatus<'c, 'c, Data> {
        // Use fresh BufferProgress for immutable input - starts at 0 each call
        let mut buffer_progress = BufferProgress::new(0);

        let (discard, state) = loop {
            // Check for sendable TLS data
            if let Some(chunk) = self
                .core
                .common_state
                .sendable_tls
                .pop()
            {
                break (
                    buffer_progress.processed(),
                    EncodeTlsData::new(self, chunk).into(),
                );
            }

            // Get next message
            let deframer_output = if self
                .core
                .common_state
                .has_received_close_notify
            {
                None
            } else {
                match self.core.deframe_to(
                    None,
                    incoming_tls,
                    outgoing_tls,
                    &mut buffer_progress,
                    &mut self.hs_buffer_fast,
                ) {
                    Err(err) => {
                        return UnbufferedStatus {
                            discard: buffer_progress.processed(),
                            state: Err(err),
                        };
                    }
                    Ok(r) => r,
                }
            };

            if let Some(msg) = deframer_output {
                // ApplicationData fast path: return directly without state machine
                if msg.typ == ContentType::ApplicationData
                    && self
                        .core
                        .common_state
                        .may_receive_application_data
                {
                    break (
                        buffer_progress.processed(),
                        ConnectionState::FastReadLen(FastReadLen(msg.payload.len())),
                    );
                }

                // All other messages: go through state machine
                let mut state =
                    match mem::replace(&mut self.core.state, Err(Error::HandshakeNotComplete)) {
                        Ok(state) => state,
                        Err(e) => {
                            self.core.state = Err(e.clone());
                            return UnbufferedStatus {
                                discard: buffer_progress.processed(),
                                state: Err(e),
                            };
                        }
                    };

                match self.core.process_msg(msg, state, None) {
                    Ok(new) => state = new,
                    Err(e) => {
                        self.core.state = Err(e.clone());
                        return UnbufferedStatus {
                            discard: buffer_progress.processed(),
                            state: Err(e),
                        };
                    }
                }

                // For immutable input, discard equals processed after message handling
                // Don't call take_discard as it modifies processed offset
                self.core.state = Ok(state);
            } else if self.wants_write {
                // Return processed as discard - indicates how many bytes were consumed
                break (
                    buffer_progress.processed(),
                    TransmitTlsData { conn: self }.into(),
                );
            } else if self
                .core
                .common_state
                .has_received_close_notify
                && !self.emitted_peer_closed_state
            {
                self.emitted_peer_closed_state = true;
                break (buffer_progress.processed(), ConnectionState::PeerClosed);
            } else if self
                .core
                .common_state
                .has_received_close_notify
                && self
                    .core
                    .common_state
                    .has_sent_close_notify
            {
                break (buffer_progress.processed(), ConnectionState::Closed);
            } else if self
                .core
                .common_state
                .may_send_application_data
            {
                break (
                    buffer_progress.processed(),
                    ConnectionState::WriteTraffic(WriteTraffic { conn: self }),
                );
            } else {
                break (
                    buffer_progress.processed(),
                    ConnectionState::BlockedHandshake,
                );
            }
        };

        UnbufferedStatus {
            discard,
            state: Ok(state),
        }
    }
}

/// The current status of the `UnbufferedConnection*`
#[must_use]
#[derive(Debug)]
pub struct UnbufferedStatus<'c, 'i, Data> {
    /// Number of bytes to discard
    ///
    /// After the `state` field of this object has been handled, `discard` bytes must be
    /// removed from the *front* of the `incoming_tls` buffer that was passed to
    /// the [`UnbufferedConnectionCommon::process_tls_records`] call that returned this object.
    ///
    /// This discard operation MUST happen *before*
    /// [`UnbufferedConnectionCommon::process_tls_records`] is called again.
    pub discard: usize,

    /// The current state of the handshake process
    ///
    /// This value MUST be handled prior to calling
    /// [`UnbufferedConnectionCommon::process_tls_records`] again. See the documentation on the
    /// variants of [`ConnectionState`] for more details.
    pub state: Result<ConnectionState<'c, 'i, Data>, Error>,
}

/// The state of the [`UnbufferedConnectionCommon`] object
#[non_exhaustive] // for forwards compatibility; to support caller-side certificate verification
pub enum ConnectionState<'c, 'i, Data> {
    /// One, or more, application data records are available
    ///
    /// See [`ReadTraffic`] for more details on how to use the enclosed object to access
    /// the received data.
    ReadTraffic(ReadTraffic<'c, 'i, Data>),

    /// Application data has been decrypted directly to the output buffer.
    ///
    /// Use [`FastReadLen`] to get the length of available data.
    /// This is returned by [`process_tls_records_fast`].
    ///
    /// [`process_tls_records_fast`]: UnbufferedConnectionCommon::process_tls_records_fast
    FastReadLen(FastReadLen),
    /// Connection has been cleanly closed by the peer.
    ///
    /// This state is encountered at most once by each connection -- it is
    /// "edge" triggered, rather than "level" triggered.
    ///
    /// It delimits the data received from the peer, meaning you can be sure you
    /// have received all the data the peer sent.
    ///
    /// No further application data will be received from the peer, so no further
    /// `ReadTraffic` states will be produced.
    ///
    /// However, it is possible to _send_ further application data via `WriteTraffic`
    /// states, or close the connection cleanly by calling
    /// [`WriteTraffic::queue_close_notify()`].
    PeerClosed,

    /// Connection has been cleanly closed by both us and the peer.
    ///
    /// This is a terminal state.  No other states will be produced for this
    /// connection.
    Closed,

    /// One, or more, early (RTT-0) data records are available
    ReadEarlyData(ReadEarlyData<'c, 'i, Data>),

    /// A Handshake record is ready for encoding
    ///
    /// Call [`EncodeTlsData::encode`] on the enclosed object, providing an `outgoing_tls`
    /// buffer to store the encoding
    EncodeTlsData(EncodeTlsData<'c, Data>),

    /// Previously encoded handshake records need to be transmitted
    ///
    /// Transmit the contents of the `outgoing_tls` buffer that was passed to previous
    /// [`EncodeTlsData::encode`] calls to the peer.
    ///
    /// After transmitting the contents, call [`TransmitTlsData::done`] on the enclosed object.
    /// The transmitted contents MUST not be sent to the peer more than once so they SHOULD be
    /// discarded at this point.
    ///
    /// At some stages of the handshake process, it's possible to send application-data alongside
    /// handshake records. Call [`TransmitTlsData::may_encrypt_app_data`] on the enclosed
    /// object to probe if that's allowed.
    TransmitTlsData(TransmitTlsData<'c, Data>),

    /// More TLS data is needed to continue with the handshake
    ///
    /// Request more data from the peer and append the contents to the `incoming_tls` buffer that
    /// was passed to [`UnbufferedConnectionCommon::process_tls_records`].
    BlockedHandshake,

    /// The handshake process has been completed.
    ///
    /// [`WriteTraffic::encrypt`] can be called on the enclosed object to encrypt application
    /// data into an `outgoing_tls` buffer. Similarly, [`WriteTraffic::queue_close_notify`] can
    /// be used to encrypt a close_notify alert message into a buffer to signal the peer that the
    /// connection is being closed. Data written into `outgoing_buffer` by either method MAY be
    /// transmitted to the peer during this state.
    ///
    /// Once this state has been reached, data MAY be requested from the peer and appended to an
    /// `incoming_tls` buffer that will be passed to a future
    /// [`UnbufferedConnectionCommon::process_tls_records`] invocation. When enough data has been
    /// appended to `incoming_tls`, [`UnbufferedConnectionCommon::process_tls_records`] will yield
    /// the [`ConnectionState::ReadTraffic`] state.
    WriteTraffic(WriteTraffic<'c, Data>),
}

impl<'c, 'i, Data> From<ReadTraffic<'c, 'i, Data>> for ConnectionState<'c, 'i, Data> {
    fn from(v: ReadTraffic<'c, 'i, Data>) -> Self {
        Self::ReadTraffic(v)
    }
}

impl<'c, 'i, Data> From<ReadEarlyData<'c, 'i, Data>> for ConnectionState<'c, 'i, Data> {
    fn from(v: ReadEarlyData<'c, 'i, Data>) -> Self {
        Self::ReadEarlyData(v)
    }
}

impl<'c, Data> From<EncodeTlsData<'c, Data>> for ConnectionState<'c, '_, Data> {
    fn from(v: EncodeTlsData<'c, Data>) -> Self {
        Self::EncodeTlsData(v)
    }
}

impl<'c, Data> From<TransmitTlsData<'c, Data>> for ConnectionState<'c, '_, Data> {
    fn from(v: TransmitTlsData<'c, Data>) -> Self {
        Self::TransmitTlsData(v)
    }
}

impl<Data> fmt::Debug for ConnectionState<'_, '_, Data> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReadTraffic(..) => f.debug_tuple("ReadTraffic").finish(),

            Self::FastReadLen(..) => f.debug_tuple("FastReadLen").finish(),

            Self::PeerClosed => write!(f, "PeerClosed"),

            Self::Closed => write!(f, "Closed"),

            Self::ReadEarlyData(..) => f.debug_tuple("ReadEarlyData").finish(),

            Self::EncodeTlsData(..) => f.debug_tuple("EncodeTlsData").finish(),

            Self::TransmitTlsData(..) => f
                .debug_tuple("TransmitTlsData")
                .finish(),

            Self::BlockedHandshake => f
                .debug_tuple("BlockedHandshake")
                .finish(),

            Self::WriteTraffic(..) => f.debug_tuple("WriteTraffic").finish(),
        }
    }
}

/// Length of application data available in the output buffer from [`process_tls_records_fast`].
///
/// [`process_tls_records_fast`]: UnbufferedConnectionCommon::process_tls_records_fast
#[derive(Debug, Clone, Copy)]
pub struct FastReadLen(pub usize);
/// Application data is available
pub struct ReadTraffic<'c, 'i, Data> {
    conn: &'c mut UnbufferedConnectionCommon<Data>,
    // for forwards compatibility; to support in-place decryption in the future
    _incoming_tls: &'i mut [u8],

    // owner of the latest chunk obtained in `next_record`, as borrowed by
    // `AppDataRecord`
    chunk: Option<Vec<u8>>,
}

impl<'c, 'i, Data> ReadTraffic<'c, 'i, Data> {
    fn new(conn: &'c mut UnbufferedConnectionCommon<Data>, _incoming_tls: &'i mut [u8]) -> Self {
        Self {
            conn,
            _incoming_tls,
            chunk: None,
        }
    }

    /// Decrypts and returns the next available app-data record
    // TODO deprecate in favor of `Iterator` implementation, which requires in-place decryption
    pub fn next_record(&mut self) -> Option<Result<AppDataRecord<'_>, Error>> {
        self.chunk = self
            .conn
            .core
            .common_state
            .received_plaintext
            .pop();
        self.chunk.as_ref().map(|chunk| {
            Ok(AppDataRecord {
                discard: 0,
                payload: chunk,
            })
        })
    }

    /// Returns the payload size of the next app-data record *without* decrypting it
    ///
    /// Returns `None` if there are no more app-data records
    pub fn peek_len(&self) -> Option<NonZeroUsize> {
        self.conn
            .core
            .common_state
            .received_plaintext
            .peek()
            .and_then(|ch| NonZeroUsize::new(ch.len()))
    }
}

/// Early application-data is available.
pub struct ReadEarlyData<'c, 'i, Data> {
    conn: &'c mut UnbufferedConnectionCommon<Data>,

    // for forwards compatibility; to support in-place decryption in the future
    _incoming_tls: &'i mut [u8],

    // owner of the latest chunk obtained in `next_record`, as borrowed by
    // `AppDataRecord`
    chunk: Option<Vec<u8>>,
}

impl<'c, 'i> ReadEarlyData<'c, 'i, ServerConnectionData> {
    fn new(
        conn: &'c mut UnbufferedConnectionCommon<ServerConnectionData>,
        _incoming_tls: &'i mut [u8],
    ) -> Self {
        Self {
            conn,
            _incoming_tls,
            chunk: None,
        }
    }

    /// decrypts and returns the next available app-data record
    // TODO deprecate in favor of `Iterator` implementation, which requires in-place decryption
    pub fn next_record(&mut self) -> Option<Result<AppDataRecord<'_>, Error>> {
        self.chunk = self.conn.pop_early_data();
        self.chunk.as_ref().map(|chunk| {
            Ok(AppDataRecord {
                discard: 0,
                payload: chunk,
            })
        })
    }

    /// returns the payload size of the next app-data record *without* decrypting it
    ///
    /// returns `None` if there are no more app-data records
    pub fn peek_len(&self) -> Option<NonZeroUsize> {
        self.conn
            .peek_early_data()
            .and_then(|ch| NonZeroUsize::new(ch.len()))
    }
}

/// A decrypted application-data record
pub struct AppDataRecord<'i> {
    /// Number of additional bytes to discard
    ///
    /// This number MUST be added to the value of [`UnbufferedStatus::discard`] *prior* to the
    /// discard operation. See [`UnbufferedStatus::discard`] for more details
    pub discard: usize,

    /// The payload of the app-data record
    pub payload: &'i [u8],
}

/// Allows encrypting app-data
pub struct WriteTraffic<'c, Data> {
    conn: &'c mut UnbufferedConnectionCommon<Data>,
}

impl<Data> WriteTraffic<'_, Data> {
    /// Encrypts `application_data` into the `outgoing_tls` buffer
    ///
    /// Returns the number of bytes that were written into `outgoing_tls`, or an error if
    /// the provided buffer is too small. In the error case, `outgoing_tls` is not modified
    pub fn encrypt(
        &mut self,
        application_data: &[u8],
        outgoing_tls: &mut [u8],
    ) -> Result<usize, EncryptError> {
        self.conn
            .core
            .maybe_refresh_traffic_keys();
        self.conn
            .core
            .common_state
            .write_plaintext(application_data.into(), outgoing_tls)
    }

    /// Encrypts a close_notify warning alert in `outgoing_tls`
    ///
    /// Returns the number of bytes that were written into `outgoing_tls`, or an error if
    /// the provided buffer is too small. In the error case, `outgoing_tls` is not modified
    pub fn queue_close_notify(&mut self, outgoing_tls: &mut [u8]) -> Result<usize, EncryptError> {
        self.conn
            .core
            .common_state
            .eager_send_close_notify(outgoing_tls)
    }

    /// Arranges for a TLS1.3 `key_update` to be sent.
    ///
    /// This consumes the `WriteTraffic` state:  to actually send the message,
    /// call [`UnbufferedConnectionCommon::process_tls_records`] again which will
    /// return a `ConnectionState::EncodeTlsData` that emits the `key_update`
    /// message.
    ///
    /// See [`ConnectionCommon::refresh_traffic_keys()`] for full documentation,
    /// including why you might call this and in what circumstances it will fail.
    ///
    /// [`ConnectionCommon::refresh_traffic_keys()`]: crate::ConnectionCommon::refresh_traffic_keys
    pub fn refresh_traffic_keys(self) -> Result<(), Error> {
        self.conn.core.refresh_traffic_keys()
    }
}

/// A handshake record must be encoded
pub struct EncodeTlsData<'c, Data> {
    conn: &'c mut UnbufferedConnectionCommon<Data>,
    chunk: Option<Vec<u8>>,
}

impl<'c, Data> EncodeTlsData<'c, Data> {
    fn new(conn: &'c mut UnbufferedConnectionCommon<Data>, chunk: Vec<u8>) -> Self {
        Self {
            conn,
            chunk: Some(chunk),
        }
    }

    /// Encodes a handshake record into the `outgoing_tls` buffer
    ///
    /// Returns the number of bytes that were written into `outgoing_tls`, or an error if
    /// the provided buffer is too small. In the error case, `outgoing_tls` is not modified
    pub fn encode(&mut self, outgoing_tls: &mut [u8]) -> Result<usize, EncodeError> {
        let Some(chunk) = self.chunk.take() else {
            return Err(EncodeError::AlreadyEncoded);
        };

        let required_size = chunk.len();

        if required_size > outgoing_tls.len() {
            self.chunk = Some(chunk);
            Err(InsufficientSizeError { required_size }.into())
        } else {
            let written = chunk.len();
            outgoing_tls[..written].copy_from_slice(&chunk);

            self.conn.wants_write = true;

            Ok(written)
        }
    }
}

/// Previously encoded TLS data must be transmitted
pub struct TransmitTlsData<'c, Data> {
    pub(crate) conn: &'c mut UnbufferedConnectionCommon<Data>,
}

impl<Data> TransmitTlsData<'_, Data> {
    /// Signals that the previously encoded TLS data has been transmitted
    pub fn done(self) {
        self.conn.wants_write = false;
    }

    /// Returns an adapter that allows encrypting application data
    ///
    /// If allowed at this stage of the handshake process
    pub fn may_encrypt_app_data(&mut self) -> Option<WriteTraffic<'_, Data>> {
        if self
            .conn
            .core
            .common_state
            .may_send_application_data
        {
            Some(WriteTraffic { conn: self.conn })
        } else {
            None
        }
    }
}

/// Errors that may arise when encoding a handshake record
#[derive(Debug)]
pub enum EncodeError {
    /// Provided buffer was too small
    InsufficientSize(InsufficientSizeError),

    /// The handshake record has already been encoded; do not call `encode` again
    AlreadyEncoded,
}

impl From<InsufficientSizeError> for EncodeError {
    fn from(v: InsufficientSizeError) -> Self {
        Self::InsufficientSize(v)
    }
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InsufficientSize(InsufficientSizeError { required_size }) => write!(
                f,
                "cannot encode due to insufficient size, {required_size} bytes are required"
            ),
            Self::AlreadyEncoded => "cannot encode, data has already been encoded".fmt(f),
        }
    }
}

#[cfg(feature = "std")]
impl StdError for EncodeError {}

/// Errors that may arise when encrypting application data
#[derive(Debug)]
pub enum EncryptError {
    /// Provided buffer was too small
    InsufficientSize(InsufficientSizeError),

    /// Encrypter has been exhausted
    EncryptExhausted,
}

impl From<InsufficientSizeError> for EncryptError {
    fn from(v: InsufficientSizeError) -> Self {
        Self::InsufficientSize(v)
    }
}

impl fmt::Display for EncryptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InsufficientSize(InsufficientSizeError { required_size }) => write!(
                f,
                "cannot encrypt due to insufficient size, {required_size} bytes are required"
            ),
            Self::EncryptExhausted => f.write_str("encrypter has been exhausted"),
        }
    }
}

#[cfg(feature = "std")]
impl StdError for EncryptError {}

/// Provided buffer was too small
#[derive(Clone, Copy, Debug)]
pub struct InsufficientSizeError {
    /// buffer must be at least this size
    pub required_size: usize,
}
