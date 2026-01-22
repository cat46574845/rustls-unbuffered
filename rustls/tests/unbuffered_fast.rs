//! Tests for the zero-copy `process_tls_records_fast` API.
//!
//! These tests are exact copies of the original unbuffered.rs handshake tests,
//! but using `process_tls_records_fast` with an immutable input buffer and
//! an empty output buffer (&mut []).

#![allow(clippy::disallowed_types, clippy::duplicate_mod)]

use std::num::NonZeroUsize;

use rustls::client::{ClientConnectionData, EarlyDataError, UnbufferedClientConnection};
use rustls::server::{ServerConnectionData, UnbufferedServerConnection};
use rustls::unbuffered::{
    ConnectionState, EncodeError, EncryptError, InsufficientSizeError, UnbufferedConnectionCommon,
    UnbufferedStatus, WriteTraffic,
};
use rustls::version::TLS13;
use rustls::{CertificateError, ClientConfig, ServerConfig, SideData};

use super::*;

mod common;
use common::*;

const MAX_ITERATIONS: usize = 100;

// ============================================================================
// Handshake Tests using process_tls_records_fast
// ============================================================================

#[test]
fn fast_tls12_handshake() {
    let outcome = handshake(&rustls::version::TLS12);

    assert_eq!(
        outcome.client_transcript, TLS12_CLIENT_TRANSCRIPT,
        "client transcript mismatch"
    );
    assert_eq!(
        outcome.server_transcript, TLS12_SERVER_TRANSCRIPT,
        "server transcript mismatch"
    );
}

#[test]
fn fast_tls12_handshake_fragmented() {
    let outcome = handshake_config(&rustls::version::TLS12, |client, server| {
        client.max_fragment_size = Some(512);
        client.cert_decompressors = vec![];
        server.max_fragment_size = Some(512);
    });

    let mut expected_client = TLS12_CLIENT_TRANSCRIPT_FRAGMENTED.to_vec();
    let mut expected_server = TLS12_SERVER_TRANSCRIPT_FRAGMENTED.to_vec();
    if provider_is_aws_lc_rs() && cfg!(feature = "prefer-post-quantum") {
        // client hello is larger for X25519MLKEM768
        expected_client.splice(0..0, ["EncodeTlsData", "EncodeTlsData"]);
        expected_server.splice(0..0, ["BlockedHandshake", "BlockedHandshake"]);
    }
    assert_eq!(
        outcome.client_transcript, expected_client,
        "client transcript mismatch"
    );
    assert_eq!(
        outcome.server_transcript, expected_server,
        "server transcript mismatch"
    );
}

#[test]
fn fast_tls13_handshake() {
    let outcome = handshake(&rustls::version::TLS13);

    assert_eq!(
        outcome.client_transcript, TLS13_CLIENT_TRANSCRIPT,
        "client transcript mismatch"
    );
    assert_eq!(
        outcome.server_transcript, TLS13_SERVER_TRANSCRIPT,
        "server transcript mismatch"
    );
}

#[test]
fn fast_tls13_handshake_fragmented() {
    let outcome = handshake_config(&rustls::version::TLS13, |client, server| {
        client.max_fragment_size = Some(512);
        client.cert_decompressors = vec![];
        server.max_fragment_size = Some(512);
    });

    let mut expected_client = TLS13_CLIENT_TRANSCRIPT_FRAGMENTED.to_vec();
    let mut expected_server = TLS13_SERVER_TRANSCRIPT_FRAGMENTED.to_vec();

    if provider_is_aws_lc_rs() && cfg!(feature = "prefer-post-quantum") {
        // client hello is larger for X25519MLKEM768
        expected_client.splice(0..0, ["EncodeTlsData", "EncodeTlsData"]);
        expected_server.splice(0..0, ["BlockedHandshake", "BlockedHandshake"]);

        // and server flight
        expected_client.splice(4..4, ["BlockedHandshake", "BlockedHandshake"]);
        expected_server.splice(4..4, ["EncodeTlsData", "EncodeTlsData"]);
    }

    assert_eq!(
        outcome.client_transcript, expected_client,
        "client transcript mismatch"
    );
    assert_eq!(
        outcome.server_transcript, expected_server,
        "server transcript mismatch"
    );
}

#[test]
fn fast_tls13_packed_handshake() {
    // transcript requires selection of X25519
    if provider_is_fips() {
        return;
    }

    // regression test for https://github.com/rustls/rustls/issues/2040
    let client_config = ClientConfig::builder_with_provider(unsafe_plaintext_crypto_provider(
        provider::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .dangerous()
    .with_custom_certificate_verifier(std::sync::Arc::new(
        MockServerVerifier::rejects_certificate(CertificateError::UnknownIssuer.into()),
    ))
    .with_no_client_auth();

    let mut client = UnbufferedClientConnection::new(
        std::sync::Arc::new(client_config),
        server_name("localhost"),
    )
    .unwrap();

    // Use fast API with empty output buffer
    let mut out_buffer: [u8; 0] = [];

    let (_hello, _) = encode_tls_data(client.process_tls_records_fast(&[], &mut out_buffer));
    confirm_transmit_tls_data(client.process_tls_records_fast(&[], &mut out_buffer));

    let first_flight = include_bytes!("data/bug2040-message-1.bin");
    let (_ccs, discard) =
        encode_tls_data(client.process_tls_records_fast(first_flight, &mut out_buffer));
    assert_eq!(discard, first_flight.len());

    let second_flight = include_bytes!("data/bug2040-message-2.bin");
    let UnbufferedStatus { state, .. } =
        client.process_tls_records_fast(second_flight, &mut out_buffer);
    assert_eq!(
        state.unwrap_err(),
        rustls::Error::InvalidCertificate(CertificateError::UnknownIssuer)
    );
}

// ============================================================================
// Helper Functions (copied from unbuffered.rs with fast API)
// ============================================================================

fn handshake(version: &'static rustls::SupportedProtocolVersion) -> Outcome {
    handshake_config(version, |_, _| ())
}

fn handshake_config(
    version: &'static rustls::SupportedProtocolVersion,
    editor: impl Fn(&mut ClientConfig, &mut ServerConfig),
) -> Outcome {
    let provider = provider::default_provider();
    let mut server_config =
        make_server_config_with_versions(KeyType::Rsa2048, &[version], &provider);
    let mut client_config = make_client_config(KeyType::Rsa2048, &provider);
    editor(&mut client_config, &mut server_config);

    run(
        std::sync::Arc::new(client_config),
        &mut NO_ACTIONS.clone(),
        std::sync::Arc::new(server_config),
        &mut NO_ACTIONS.clone(),
    )
}

fn run(
    client_config: std::sync::Arc<ClientConfig>,
    client_actions: &mut Actions,
    server_config: std::sync::Arc<ServerConfig>,
    server_actions: &mut Actions,
) -> Outcome {
    let mut outcome = Outcome::default();
    let mut count = 0;
    let mut client_handshake_done = false;
    let mut server_handshake_done = false;

    let mut client =
        UnbufferedClientConnection::new(client_config.clone(), server_name("localhost")).unwrap();
    let mut server = UnbufferedServerConnection::new(server_config.clone()).unwrap();
    let mut buffers = BothBuffers::default();

    while !(client_handshake_done
        && server_handshake_done
        && client_actions.finished()
        && server_actions.finished())
    {
        match advance_client(
            &mut client,
            &mut buffers.client,
            *client_actions,
            &mut outcome.client_transcript,
        ) {
            State::EncodedTlsData => {}
            State::TransmitTlsData {
                sent_early_data,
                sent_app_data,
                sent_close_notify,
            } => {
                buffers.client_send();
                if sent_app_data {
                    client_actions.app_data_to_send = None;
                }

                if sent_early_data {
                    client_actions.early_data_to_send = None;
                }

                if sent_close_notify {
                    client_actions.send_close_notify = false;
                }
            }
            State::BlockedHandshake => buffers.server_send(),
            State::WriteTraffic {
                sent_app_data,
                sent_close_notify,
            } => {
                buffers.client_send();

                if sent_app_data {
                    client_actions.app_data_to_send = None;
                }

                if sent_close_notify {
                    client_actions.send_close_notify = false;
                }

                client_handshake_done = true;
            }
            State::ReceivedAppData { records } => {
                outcome
                    .client_received_app_data
                    .extend(records);
            }
            State::PeerClosed => {
                outcome.client_saw_peer_closed_state = true;
            }
            State::Closed => {}
            state => unreachable!("{state:?}"),
        }

        match advance_server(
            &mut server,
            &mut buffers.server,
            *server_actions,
            &mut outcome.server_transcript,
        ) {
            State::EncodedTlsData => {}
            State::TransmitTlsData {
                sent_app_data,
                sent_close_notify,
                ..
            } => {
                buffers.server_send();

                if sent_app_data {
                    server_actions.app_data_to_send = None;
                }

                if sent_close_notify {
                    server_actions.send_close_notify = false;
                }
            }
            State::BlockedHandshake => buffers.client_send(),
            State::WriteTraffic {
                sent_app_data,
                sent_close_notify,
            } => {
                buffers.server_send();

                if sent_app_data {
                    server_actions.app_data_to_send = None;
                }

                if sent_close_notify {
                    server_actions.send_close_notify = false;
                }

                server_handshake_done = true;
            }
            State::ReceivedEarlyData { records } => {
                outcome
                    .server_received_early_data
                    .extend(records);
            }
            State::ReceivedAppData { records } => {
                outcome
                    .server_received_app_data
                    .extend(records);
            }
            State::PeerClosed => {
                outcome.server_saw_peer_closed_state = true;
            }
            State::Closed => {}
        }

        count += 1;

        assert!(count <= MAX_ITERATIONS, "handshake was not completed");
    }

    println!("finished with:");
    println!(
        "  client: {:?} {:?} {:?}",
        client.protocol_version(),
        client.negotiated_cipher_suite(),
        client.handshake_kind()
    );
    println!(
        "  server: {:?} {:?} {:?}",
        server.protocol_version(),
        server.negotiated_cipher_suite(),
        server.handshake_kind()
    );

    outcome.server = Some(server);
    outcome.client = Some(client);
    outcome
}

// ============================================================================
// State and Buffer Types (copied from unbuffered.rs)
// ============================================================================

#[derive(Debug)]
enum State {
    Closed,
    PeerClosed,
    EncodedTlsData,
    TransmitTlsData {
        sent_app_data: bool,
        sent_close_notify: bool,
        sent_early_data: bool,
    },
    BlockedHandshake,
    ReceivedAppData {
        records: Vec<Vec<u8>>,
    },
    ReceivedEarlyData {
        records: Vec<Vec<u8>>,
    },
    WriteTraffic {
        sent_app_data: bool,
        sent_close_notify: bool,
    },
}

const NO_ACTIONS: Actions = Actions {
    app_data_to_send: None,
    early_data_to_send: None,
    send_close_notify: false,
};

#[derive(Clone, Copy, Debug)]
struct Actions<'a> {
    app_data_to_send: Option<&'a [u8]>,
    early_data_to_send: Option<&'a [u8]>,
    send_close_notify: bool,
}

impl Actions<'_> {
    fn finished(&self) -> bool {
        self.app_data_to_send.is_none()
            && self.early_data_to_send.is_none()
            && !self.send_close_notify
    }
}

#[derive(Default)]
struct Outcome {
    server: Option<UnbufferedServerConnection>,
    server_transcript: Vec<String>,
    server_received_early_data: Vec<Vec<u8>>,
    server_received_app_data: Vec<Vec<u8>>,
    server_saw_peer_closed_state: bool,
    client: Option<UnbufferedClientConnection>,
    client_transcript: Vec<String>,
    client_received_app_data: Vec<Vec<u8>>,
    client_saw_peer_closed_state: bool,
}

/// Uses process_tls_records_fast with immutable input and empty output buffer
fn advance_client(
    conn: &mut UnbufferedConnectionCommon<ClientConnectionData>,
    buffers: &mut Buffers,
    actions: Actions,
    transcript: &mut Vec<String>,
) -> State {
    // KEY DIFFERENCE: Use process_tls_records_fast with immutable input and empty output
    // Note: &mut [u8] auto-coerces to &[u8]
    let UnbufferedStatus { discard, state } =
        conn.process_tls_records_fast(buffers.incoming.filled(), &mut []);
    let state = state.unwrap();

    transcript.push(format!("{state:?}"));

    let state = match state {
        ConnectionState::TransmitTlsData(mut state) => {
            let mut sent_early_data = false;
            if let (Some(early_data), Some(mut state)) =
                (actions.early_data_to_send, state.may_encrypt_early_data())
            {
                write_with_buffer_size_checks(
                    |out_buf| state.encrypt(early_data, out_buf),
                    |e| {
                        println!("encrypt error: {e}");
                        match e {
                            EarlyDataError::Encrypt(EncryptError::InsufficientSize(ise)) => ise,
                            _ => unreachable!(),
                        }
                    },
                    &mut buffers.outgoing,
                );
                sent_early_data = true;
            }
            state.done();
            State::TransmitTlsData {
                sent_app_data: false,
                sent_close_notify: false,
                sent_early_data,
            }
        }

        state => handle_state(state, &mut buffers.outgoing, actions),
    };
    buffers.incoming.discard(discard);

    state
}

/// Server uses the old API (process_tls_records) since we're testing client zero-copy
fn advance_server(
    conn: &mut UnbufferedConnectionCommon<ServerConnectionData>,
    buffers: &mut Buffers,
    actions: Actions,
    transcript: &mut Vec<String>,
) -> State {
    let UnbufferedStatus { discard, state } = conn.process_tls_records(buffers.incoming.filled());
    let state = state.unwrap();

    transcript.push(format!("{state:?}"));

    let state = match state {
        ConnectionState::ReadEarlyData(mut state) => {
            let mut records = vec![];
            let mut peeked_len = state.peek_len();

            while let Some(res) = state.next_record() {
                let payload = res.unwrap().payload.to_vec();
                assert_eq!(NonZeroUsize::new(payload.len()), peeked_len);
                records.push(payload);
                peeked_len = state.peek_len();
            }

            assert_eq!(None, peeked_len);

            State::ReceivedEarlyData { records }
        }

        state => handle_state(state, &mut buffers.outgoing, actions),
    };
    buffers.incoming.discard(discard);

    state
}

fn handle_state<Data>(
    state: ConnectionState<'_, '_, Data>,
    outgoing: &mut Buffer,
    actions: Actions,
) -> State {
    match dbg!(state) {
        ConnectionState::EncodeTlsData(mut state) => {
            write_with_buffer_size_checks(
                |out_buf| state.encode(out_buf),
                |e| {
                    println!("encode error: {e}");
                    match e {
                        EncodeError::InsufficientSize(ise) => ise,
                        _ => unreachable!(),
                    }
                },
                outgoing,
            );

            assert!(matches!(
                state.encode(&mut []).unwrap_err(),
                EncodeError::AlreadyEncoded
            ));

            State::EncodedTlsData
        }

        ConnectionState::TransmitTlsData(mut state) => {
            let mut sent_app_data = false;
            if let (Some(app_data), Some(mut state)) =
                (actions.app_data_to_send, state.may_encrypt_app_data())
            {
                encrypt(&mut state, app_data, outgoing);
                sent_app_data = true;
            }

            let mut sent_close_notify = false;
            if let Some(mut state) = state.may_encrypt_app_data() {
                if actions.send_close_notify {
                    queue_close_notify(&mut state, outgoing);
                    sent_close_notify = true;
                }
            }

            // this should be called *after* the data has been transmitted but it's easier to
            // do it in reverse
            state.done();
            State::TransmitTlsData {
                sent_app_data,
                sent_early_data: false,
                sent_close_notify,
            }
        }

        ConnectionState::BlockedHandshake { .. } => State::BlockedHandshake,

        ConnectionState::WriteTraffic(mut state) => {
            let mut sent_app_data = false;
            if let Some(app_data) = actions.app_data_to_send {
                encrypt(&mut state, app_data, outgoing);
                sent_app_data = true;
            }

            let mut sent_close_notify = false;
            if actions.send_close_notify {
                queue_close_notify(&mut state, outgoing);
                sent_close_notify = true;
            }

            State::WriteTraffic {
                sent_app_data,
                sent_close_notify,
            }
        }

        ConnectionState::ReadTraffic(mut state) => {
            let mut records = vec![];
            let mut peeked_len = state.peek_len();

            while let Some(res) = state.next_record() {
                let payload = res.unwrap().payload.to_vec();
                assert_eq!(NonZeroUsize::new(payload.len()), peeked_len);
                records.push(payload);
                peeked_len = state.peek_len();
            }

            assert_eq!(None, peeked_len);

            State::ReceivedAppData { records }
        }

        ConnectionState::PeerClosed => State::PeerClosed,
        ConnectionState::Closed => State::Closed,

        _ => unreachable!(),
    }
}

fn queue_close_notify<Data>(state: &mut WriteTraffic<'_, Data>, outgoing: &mut Buffer) {
    write_with_buffer_size_checks(
        |out_buf| state.queue_close_notify(out_buf),
        map_encrypt_error,
        outgoing,
    );
}

fn encrypt<Data>(state: &mut WriteTraffic<'_, Data>, app_data: &[u8], outgoing: &mut Buffer) {
    write_with_buffer_size_checks(
        |out_buf| state.encrypt(app_data, out_buf),
        map_encrypt_error,
        outgoing,
    );
}

fn map_encrypt_error(e: EncryptError) -> InsufficientSizeError {
    match e {
        EncryptError::InsufficientSize(ise) => ise,
        _ => unreachable!(),
    }
}

fn write_with_buffer_size_checks<E: core::fmt::Debug>(
    mut try_write: impl FnMut(&mut [u8]) -> Result<usize, E>,
    map_err: impl FnOnce(E) -> InsufficientSizeError,
    outgoing: &mut Buffer,
) {
    let required_size = map_err(try_write(&mut []).unwrap_err()).required_size;
    let written = try_write(outgoing.unfilled()).unwrap();
    assert_eq!(required_size, written);
    outgoing.advance(written);
}

fn encode_tls_data<T: SideData>(status: UnbufferedStatus<'_, '_, T>) -> (Vec<u8>, usize) {
    match status {
        UnbufferedStatus {
            discard,
            state: Ok(ConnectionState::EncodeTlsData(mut etd)),
        } => {
            let mut buf = vec![0u8; 16384];
            let len = etd.encode(&mut buf).unwrap();
            buf.truncate(len);
            (buf, discard)
        }
        other => panic!("expected EncodeTlsData, got {:?}", other.state),
    }
}

fn confirm_transmit_tls_data<T: SideData>(status: UnbufferedStatus<'_, '_, T>) {
    match status {
        UnbufferedStatus {
            state: Ok(ConnectionState::TransmitTlsData(ttd)),
            ..
        } => {
            ttd.done();
        }
        other => panic!("expected TransmitTlsData, got {:?}", other.state),
    }
}

#[derive(Default)]
struct BothBuffers {
    client: Buffers,
    server: Buffers,
}

impl BothBuffers {
    fn client_send(&mut self) {
        let client_data = self.client.outgoing.filled();
        let num_bytes = client_data.len();
        if num_bytes == 0 {
            return;
        }
        self.server.incoming.append(client_data);
        self.client.outgoing.clear();
        eprintln!("client sent {num_bytes}B");
    }

    fn server_send(&mut self) {
        let server_data = self.server.outgoing.filled();
        let num_bytes = server_data.len();
        if num_bytes == 0 {
            return;
        }
        self.client.incoming.append(server_data);
        self.server.outgoing.clear();
        eprintln!("server sent {num_bytes}B");
    }
}

#[derive(Default)]
struct Buffers {
    incoming: Buffer,
    outgoing: Buffer,
}

struct Buffer {
    inner: Vec<u8>,
    used: usize,
}

impl Default for Buffer {
    fn default() -> Self {
        Self {
            inner: vec![0; 16 * 1024],
            used: 0,
        }
    }
}

impl Buffer {
    fn advance(&mut self, num_bytes: usize) {
        self.used += num_bytes;
    }

    fn append(&mut self, bytes: &[u8]) {
        let num_bytes = bytes.len();
        self.unfilled()[..num_bytes].copy_from_slice(bytes);
        self.advance(num_bytes)
    }

    fn clear(&mut self) {
        self.used = 0;
    }

    fn discard(&mut self, discard: usize) {
        if discard != 0 {
            assert!(discard <= self.used);

            self.inner
                .copy_within(discard..self.used, 0);
            self.used -= discard;
        }
    }

    fn filled(&mut self) -> &mut [u8] {
        &mut self.inner[..self.used]
    }

    fn unfilled(&mut self) -> &mut [u8] {
        &mut self.inner[self.used..]
    }
}

// ============================================================================
// Expected Transcripts (same as unbuffered.rs)
// ============================================================================

const TLS12_CLIENT_TRANSCRIPT: &[&str] = &[
    "EncodeTlsData",
    "TransmitTlsData",
    "BlockedHandshake",
    "EncodeTlsData",
    "EncodeTlsData",
    "EncodeTlsData",
    "TransmitTlsData",
    "BlockedHandshake",
    "BlockedHandshake",
    "WriteTraffic",
];

const TLS12_SERVER_TRANSCRIPT: &[&str] = &[
    "BlockedHandshake",
    "EncodeTlsData",
    "TransmitTlsData",
    "BlockedHandshake",
    "BlockedHandshake",
    "BlockedHandshake",
    "EncodeTlsData",
    "EncodeTlsData",
    "TransmitTlsData",
    "WriteTraffic",
];

const TLS12_CLIENT_TRANSCRIPT_FRAGMENTED: &[&str] = &[
    "EncodeTlsData",
    "TransmitTlsData",
    "BlockedHandshake",
    "BlockedHandshake",
    "BlockedHandshake",
    "BlockedHandshake",
    "BlockedHandshake",
    "BlockedHandshake",
    "EncodeTlsData",
    "EncodeTlsData",
    "EncodeTlsData",
    "TransmitTlsData",
    "BlockedHandshake",
    "BlockedHandshake",
    "WriteTraffic",
];

const TLS12_SERVER_TRANSCRIPT_FRAGMENTED: &[&str] = &[
    "BlockedHandshake",
    "EncodeTlsData",
    "EncodeTlsData",
    "EncodeTlsData",
    "EncodeTlsData",
    "EncodeTlsData",
    "EncodeTlsData",
    "TransmitTlsData",
    "BlockedHandshake",
    "BlockedHandshake",
    "BlockedHandshake",
    "EncodeTlsData",
    "EncodeTlsData",
    "TransmitTlsData",
    "WriteTraffic",
];

const TLS13_CLIENT_TRANSCRIPT: &[&str] = &[
    "EncodeTlsData",
    "TransmitTlsData",
    "BlockedHandshake",
    "EncodeTlsData",
    "TransmitTlsData",
    "EncodeTlsData",
    "TransmitTlsData",
    "WriteTraffic",
    "WriteTraffic",
];

const TLS13_SERVER_TRANSCRIPT: &[&str] = &[
    "BlockedHandshake",
    "EncodeTlsData",
    "EncodeTlsData",
    "EncodeTlsData",
    "TransmitTlsData",
    "BlockedHandshake",
    "EncodeTlsData",
    "TransmitTlsData",
    "WriteTraffic",
];

const TLS13_CLIENT_TRANSCRIPT_FRAGMENTED: &[&str] = &[
    "EncodeTlsData",
    "TransmitTlsData",
    "BlockedHandshake",
    "EncodeTlsData",
    "TransmitTlsData",
    "BlockedHandshake",
    "BlockedHandshake",
    "BlockedHandshake",
    "BlockedHandshake",
    "BlockedHandshake",
    "EncodeTlsData",
    "TransmitTlsData",
    "WriteTraffic",
    "WriteTraffic",
];

const TLS13_SERVER_TRANSCRIPT_FRAGMENTED: &[&str] = &[
    "BlockedHandshake",
    "EncodeTlsData",
    "EncodeTlsData",
    "EncodeTlsData",
    "EncodeTlsData",
    "EncodeTlsData",
    "EncodeTlsData",
    "EncodeTlsData",
    "EncodeTlsData",
    "TransmitTlsData",
    "BlockedHandshake",
    "EncodeTlsData",
    "TransmitTlsData",
    "WriteTraffic",
];
