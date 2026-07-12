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
    ConnectionState, DangerousBatchDecryptOutcome, DangerousDecryptOutcome, EncodeError, EncryptError, FastReadLen,
    InsufficientSizeError, UnbufferedConnectionCommon, UnbufferedStatus, WriteTraffic,
};
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

    // Use fast API with properly sized output buffer
    let mut out_buffer = [0u8; 16384 + 256];

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
// 應用數據傳輸測試 (Application Data Transfer Tests)
// 驗證零拷貝 API 能正確處理加密的應用數據
// ============================================================================

/// 測試客戶端向服務器發送應用數據
///
/// 驗證要點：
/// - 客戶端使用 process_tls_records_fast 完成握手
/// - 握手完成後，客戶端加密並發送應用數據
/// - 服務器正確接收並解密數據
#[test]
fn fast_app_data_client_to_server() {
    let provider = provider::default_provider();
    let expected: &[_] = b"hello";

    // 遍歷所有支持的 TLS 版本
    for version in rustls::ALL_VERSIONS {
        eprintln!("{version:?}");
        let server_config =
            make_server_config_with_versions(KeyType::Rsa2048, &[version], &provider);
        let client_config = make_client_config(KeyType::Rsa2048, &provider);

        // 設定客戶端動作：發送應用數據
        let mut client_actions = Actions {
            app_data_to_send: Some(expected),
            ..NO_ACTIONS
        };

        let outcome = run(
            std::sync::Arc::new(client_config),
            &mut client_actions,
            std::sync::Arc::new(server_config),
            &mut NO_ACTIONS.clone(),
        );

        // 驗證：客戶端的數據已被發送
        assert!(
            client_actions
                .app_data_to_send
                .is_none(),
            "客戶端數據應已發送"
        );

        // 驗證：服務器收到正確的數據
        assert_eq!(
            [expected],
            outcome
                .server_received_app_data
                .as_slice(),
            "服務器應收到 'hello'"
        );
    }
}

/// 測試服務器向客戶端發送應用數據
///
/// 驗證要點：
/// - 客戶端使用 process_tls_records_fast 接收數據
/// - 解密後的數據應與原始數據一致
#[test]
fn fast_app_data_server_to_client() {
    let provider = provider::default_provider();
    let expected: &[_] = b"hello";

    for version in rustls::ALL_VERSIONS {
        eprintln!("{version:?}");
        let server_config =
            make_server_config_with_versions(KeyType::Rsa2048, &[version], &provider);
        let client_config = make_client_config(KeyType::Rsa2048, &provider);

        // 設定服務器動作：發送應用數據
        let mut server_actions = Actions {
            app_data_to_send: Some(expected),
            ..NO_ACTIONS
        };

        let outcome = run(
            std::sync::Arc::new(client_config),
            &mut NO_ACTIONS.clone(),
            std::sync::Arc::new(server_config),
            &mut server_actions,
        );

        // 驗證：服務器的數據已被發送
        assert!(
            server_actions
                .app_data_to_send
                .is_none(),
            "服務器數據應已發送"
        );

        // 驗證：客戶端收到正確的數據
        assert_eq!(
            [expected],
            outcome
                .client_received_app_data
                .as_slice(),
            "客戶端應收到 'hello'"
        );
    }
}

// ============================================================================
// 連接關閉測試 (Connection Closure Tests)
// 驗證零拷貝 API 的 close_notify 處理
// ============================================================================

/// 測試客戶端發送 close_notify
///
/// 驗證要點：
/// - 客戶端發送 close_notify alert
/// - 服務器正確檢測到 PeerClosed 狀態
#[test]
fn fast_close_notify_client_to_server() {
    let provider = provider::default_provider();

    for version in rustls::ALL_VERSIONS {
        eprintln!("{version:?}");
        let server_config =
            make_server_config_with_versions(KeyType::Rsa2048, &[version], &provider);
        let client_config = make_client_config(KeyType::Rsa2048, &provider);

        // 設定客戶端動作：發送 close_notify
        let mut client_actions = Actions {
            send_close_notify: true,
            ..NO_ACTIONS
        };

        let outcome = run(
            std::sync::Arc::new(client_config),
            &mut client_actions,
            std::sync::Arc::new(server_config),
            &mut NO_ACTIONS.clone(),
        );

        // 驗證：close_notify 已發送
        assert!(!client_actions.send_close_notify, "close_notify 應已發送");

        // 驗證：服務器檢測到對端關閉
        assert!(
            outcome.server_saw_peer_closed_state,
            "服務器應檢測到 PeerClosed"
        );
    }
}

/// 測試服務器發送 close_notify
///
/// 驗證要點：
/// - 服務器發送 close_notify alert
/// - 客戶端通過零拷貝 API 正確檢測到 PeerClosed 狀態
#[test]
fn fast_close_notify_server_to_client() {
    let provider = provider::default_provider();

    for version in rustls::ALL_VERSIONS {
        eprintln!("{version:?}");
        let server_config =
            make_server_config_with_versions(KeyType::Rsa2048, &[version], &provider);
        let client_config = make_client_config(KeyType::Rsa2048, &provider);

        // 設定服務器動作：發送 close_notify
        let mut server_actions = Actions {
            send_close_notify: true,
            ..NO_ACTIONS
        };

        let outcome = run(
            std::sync::Arc::new(client_config),
            &mut NO_ACTIONS.clone(),
            std::sync::Arc::new(server_config),
            &mut server_actions,
        );

        // 驗證：close_notify 已發送
        assert!(!server_actions.send_close_notify, "close_notify 應已發送");

        // 驗證：客戶端檢測到對端關閉
        assert!(
            outcome.client_saw_peer_closed_state,
            "客戶端應檢測到 PeerClosed"
        );
    }
}

// ============================================================================
// 完整關閉流程測試 (Full Closure Tests)
// 驗證雙向關閉的完整流程
// ============================================================================

/// 測試完整的雙向關閉流程（使用零拷貝 API）
///
/// 流程：
/// 1. 服務器發送 "hello" + close_notify
/// 2. 客戶端接收數據，檢測 PeerClosed
/// 3. 客戶端回覆 "goodbye" + close_notify
/// 4. 服務器接收數據，檢測 PeerClosed
/// 5. 雙方進入 Closed 狀態
#[test]
fn fast_full_closure_server_to_client() {
    for version in rustls::ALL_VERSIONS {
        eprintln!("{version:?}");
        let mut outcome = handshake(version);
        let mut client = outcome.client.take().unwrap();
        let mut server = outcome.server.take().unwrap();

        let mut buf = Buffer::default();

        // 服務器發送消息後接著 close_notify
        write_traffic(
            server.process_tls_records(&mut []),
            |mut wt: WriteTraffic<_>| {
                encrypt(&mut wt, b"hello", &mut buf);
                queue_close_notify(&mut wt, &mut buf);
            },
        );

        // 客戶端使用零拷貝 API 接收消息
        let mut decrypt_buf = [0u8; 16384 + 256];
        let UnbufferedStatus { discard, state } =
            client.process_tls_records_fast(buf.filled(), &mut decrypt_buf);

        // 應該先收到 FastReadLen（應用數據）
        match state.unwrap() {
            ConnectionState::FastReadLen(FastReadLen(len)) => {
                assert_eq!(&decrypt_buf[..len], b"hello", "應收到 'hello'");
            }
            other => panic!("預期 FastReadLen，得到 {:?}", other),
        }
        buf.discard(discard);

        // 接著應該收到 PeerClosed
        let UnbufferedStatus { discard, state } =
            client.process_tls_records_fast(buf.filled(), &mut decrypt_buf);
        match state.unwrap() {
            ConnectionState::PeerClosed => {}
            other => panic!("預期 PeerClosed，得到 {:?}", other),
        }
        buf.discard(discard);
        assert_eq!(buf.used, 0, "緩衝區應已清空");

        // 客戶端回覆數據和 close_notify
        write_traffic(
            client.process_tls_records_fast(&[], &mut decrypt_buf),
            |mut wt| {
                encrypt(&mut wt, b"goodbye", &mut buf);
                queue_close_notify(&mut wt, &mut buf);
            },
        );

        // 服務器接收並驗證
        let (data, discard) = read_traffic(server.process_tls_records(buf.filled()), |mut rt| {
            assert_eq!(rt.peek_len(), NonZeroUsize::new(7));
            rt.next_record()
                .unwrap()
                .unwrap()
                .payload
                .to_vec()
        });
        assert_eq!(data, b"goodbye", "服務器應收到 'goodbye'");
        buf.discard(discard);

        // 服務器檢測 PeerClosed
        let discard = peer_closed(server.process_tls_records(buf.filled()));
        buf.discard(discard);
        assert_eq!(buf.used, 0);

        // 雙方進入 Closed 狀態
        closed(client.process_tls_records_fast(&[], &mut decrypt_buf));
        closed(server.process_tls_records(&mut []));
    }
}

// ============================================================================
// 錯誤處理測試 (Error Handling Tests)
// 驗證零拷貝 API 的錯誤處理
// ============================================================================

/// 測試服務器拒絕垃圾數據
///
/// 驗證要點：
/// - 發送無效 content type 的數據
/// - 服務器返回 InvalidContentType 錯誤
/// - 服務器發送 DecodeError alert
#[test]
fn fast_rejects_junk() {
    let mut server = UnbufferedServerConnection::new(std::sync::Arc::new(make_server_config(
        KeyType::Rsa2048,
        &provider::default_provider(),
    )))
    .unwrap();

    // 發送垃圾數據（無效的 content type 0xff）
    let junk_data = [0xff; 5];
    let mut decrypt_buf = [0u8; 16384 + 256];

    let UnbufferedStatus { discard, state } =
        server.process_tls_records_fast(&junk_data, &mut decrypt_buf);

    assert_eq!(discard, 0, "不應丟棄任何數據");
    assert_eq!(
        state.unwrap_err(),
        rustls::Error::InvalidMessage(rustls::InvalidMessage::InvalidContentType),
        "應返回 InvalidContentType 錯誤"
    );

    // 服務器應該編碼一個 alert 響應
    let (alert_data, _) = encode_tls_data(server.process_tls_records_fast(&[], &mut decrypt_buf));

    // 驗證 alert 格式：0x15 (alert), 0x03 0x03 (TLS 1.2), 0x00 0x02 (len), 0x02 (fatal), 0x32 (decode_error)
    assert_eq!(
        alert_data,
        &[
            0x15,
            0x03,
            0x03,
            0x00,
            0x02,
            0x02,
            u8::from(rustls::AlertDescription::DecodeError)
        ],
        "應發送 DecodeError alert"
    );

    confirm_transmit_tls_data(server.process_tls_records_fast(&[], &mut decrypt_buf));
}

/// 測試服務器收到錯誤的首個握手消息
///
/// 驗證要點：
/// - 發送無效的握手消息類型 (0xff)
/// - 服務器返回 InappropriateHandshakeMessage 錯誤
#[test]
fn fast_server_receives_incorrect_first_handshake_message() {
    let (_, mut server) = make_connection_pair(&rustls::version::TLS13);

    // 構造無效的握手消息：正確的 record header，但無效的握手類型 0xff
    let junk_buffer = [0x16, 0x3, 0x1, 0x0, 0x4, 0xff, 0x0, 0x0, 0x0];
    let mut decrypt_buf = [0u8; 16384 + 256];

    let UnbufferedStatus { discard, state } =
        server.process_tls_records_fast(&junk_buffer, &mut decrypt_buf);

    assert_eq!(discard, junk_buffer.len(), "應丟棄整個無效消息");

    // 驗證錯誤類型
    let err_str = format!("{state:?}");
    assert!(
        err_str.contains("InappropriateHandshakeMessage"),
        "應返回 InappropriateHandshakeMessage 錯誤，實際: {err_str}"
    );

    // 服務器應該編碼 alert 響應
    let UnbufferedStatus { discard, state } =
        server.process_tls_records_fast(&[], &mut decrypt_buf);
    assert_eq!(discard, 0);
    match state.unwrap() {
        ConnectionState::EncodeTlsData(mut inner) => {
            let mut alert_buffer = [0u8; 7];
            let wr = inner.encode(&mut alert_buffer).unwrap();
            assert_eq!(wr, 7);
            // 驗證 alert: 0x15 (alert), version, length, level=fatal(2), desc=unexpected_message(10)
            assert_eq!(alert_buffer[0], 0x15, "應是 alert record");
            assert_eq!(alert_buffer[5], 0x02, "應是 fatal level");
        }
        other => panic!("預期 EncodeTlsData，得到 {:?}", other),
    }
}

/// 測試服務器逐字節接收握手消息
///
/// 驗證要點：
/// - 每次只處理部分 ClientHello
/// - 在完整消息之前，始終返回 BlockedHandshake
/// - 完整消息到達後，返回 EncodeTlsData
#[test]
fn fast_server_receives_handshake_byte_by_byte() {
    let (mut client, mut server) = make_connection_pair(&rustls::version::TLS13);

    // 客戶端編碼 ClientHello
    let mut client_hello_buffer = vec![0u8; 2048];
    let mut decrypt_buf = [0u8; 16384 + 256];

    let UnbufferedStatus { discard, state } =
        client.process_tls_records_fast(&[], &mut decrypt_buf);
    assert_eq!(discard, 0);

    match state.unwrap() {
        ConnectionState::EncodeTlsData(mut inner) => {
            let wr = inner
                .encode(&mut client_hello_buffer)
                .expect("ClientHello 太大");
            client_hello_buffer.truncate(wr);
        }
        _ => panic!("預期第一個客戶端事件是 EncodeTlsData"),
    }

    println!("ClientHello 長度: {} bytes", client_hello_buffer.len());

    // 逐字節發送（實際上是逐前綴發送）
    for prefix in 0..client_hello_buffer.len() - 1 {
        let UnbufferedStatus { discard, state } =
            server.process_tls_records_fast(&client_hello_buffer[..prefix], &mut decrypt_buf);

        if prefix % 100 == 0 {
            println!("前綴 {prefix}: discard={discard}, state={state:?}");
        }

        assert!(
            matches!(state.unwrap(), ConnectionState::BlockedHandshake),
            "前綴 {prefix} 應該是 BlockedHandshake"
        );
    }

    // 完整發送後應該開始處理
    let UnbufferedStatus { discard, state } =
        server.process_tls_records_fast(&client_hello_buffer[..], &mut decrypt_buf);

    assert!(
        matches!(state.unwrap(), ConnectionState::EncodeTlsData(_)),
        "完整消息後應該是 EncodeTlsData"
    );
    assert_eq!(discard, client_hello_buffer.len(), "應丟棄完整消息");
}

// ============================================================================
// 早期數據測試 (Early Data / 0-RTT Tests)
// 驗證零拷貝 API 的 0-RTT 支持
// ============================================================================

/// 測試 TLS 1.3 早期數據 (0-RTT)
///
/// 流程：
/// 1. 第一次握手獲取 session ticket
/// 2. 第二次握手使用 0-RTT 發送 "hello" 早期數據
/// 3. 驗證服務器正確接收早期數據
///
/// 注意：早期數據由客戶端發送，服務器接收，因此這裡我們測試
/// 客戶端使用零拷貝 API 發送早期數據的能力。
#[test]
fn fast_early_data() {
    let provider = provider::default_provider();
    let expected: &[_] = b"hello";

    let mut server_config = make_server_config(KeyType::Rsa2048, &provider);
    server_config.max_early_data_size = 128;
    let server_config = std::sync::Arc::new(server_config);

    let mut client_config =
        make_client_config_with_versions(KeyType::Rsa2048, &[&rustls::version::TLS13], &provider);
    client_config.enable_early_data = true;
    let client_config = std::sync::Arc::new(client_config);

    // 第一次握手：獲取 session ticket 以便第二次能使用 0-RTT
    let first_outcome = run(
        client_config.clone(),
        &mut NO_ACTIONS.clone(),
        server_config.clone(),
        &mut NO_ACTIONS.clone(),
    );

    // 驗證收到 session tickets
    let tickets_received = first_outcome
        .client
        .as_ref()
        .unwrap()
        .tls13_tickets_received();
    assert!(
        tickets_received > 0,
        "應收到 session tickets，實際: {tickets_received}"
    );
    println!("收到 {tickets_received} 個 session tickets");

    // 第二次握手：使用 0-RTT 發送早期數據
    let mut client_actions = Actions {
        early_data_to_send: Some(expected),
        ..NO_ACTIONS
    };

    let outcome = run(
        client_config.clone(),
        &mut client_actions,
        server_config.clone(),
        &mut NO_ACTIONS.clone(),
    );

    // 驗證早期數據已發送
    assert!(
        client_actions
            .early_data_to_send
            .is_none(),
        "早期數據應已發送"
    );

    // 驗證服務器收到早期數據
    assert_eq!(
        [expected],
        outcome
            .server_received_early_data
            .as_slice(),
        "服務器應收到 'hello' 作為早期數據"
    );

    // 驗證 transcript 包含預期的狀態轉換
    assert!(
        outcome
            .server_transcript
            .contains(&"ReadEarlyData".to_string()),
        "服務器 transcript 應包含 ReadEarlyData，實際: {:?}",
        outcome.server_transcript
    );
}

// ============================================================================
// close_notify 語義測試 (Close Notify Semantics Tests)
// ============================================================================

/// 測試 queue_close_notify 的冪等性
///
/// 驗證要點：
/// - 第一次調用 queue_close_notify 成功並返回寫入字節數
/// - 第二次調用返回 0（因為已經排隊）
#[test]
fn fast_queue_close_notify_is_idempotent() {
    let outcome = handshake(&rustls::version::TLS13);
    let mut client = outcome.client.unwrap();

    let mut buf = Buffer::default();
    let mut decrypt_buf = [0u8; 16384 + 256];

    // 通過 WriteTraffic 調用 queue_close_notify
    match client
        .process_tls_records_fast(&[], &mut decrypt_buf)
        .state
        .unwrap()
    {
        ConnectionState::WriteTraffic(mut wt) => {
            // 第一次調用應該成功並返回非零字節數
            let first_len = wt
                .queue_close_notify(buf.unfilled())
                .unwrap();
            assert!(first_len > 0, "第一次調用應返回非零字節數");
            buf.advance(first_len);

            // 第二次調用應該返回 0（冪等性）
            let second_len = wt
                .queue_close_notify(buf.unfilled())
                .unwrap();
            assert_eq!(second_len, 0, "第二次調用應返回 0（冪等）");
        }
        other => panic!("預期 WriteTraffic，得到 {:?}", other),
    }
}

/// 測試 close_notify 後忽略垃圾數據
///
/// 驗證要點：
/// - 客戶端發送 close_notify 後附加垃圾數據
/// - 服務器正確識別 PeerClosed
/// - 後續垃圾數據被忽略（discard=0 表示沒有處理）
#[test]
fn fast_junk_after_close_notify_received() {
    for version in rustls::ALL_VERSIONS {
        eprintln!("{version:?}");
        let outcome = handshake(version);
        let mut client = outcome.client.unwrap();
        let mut server = outcome.server.unwrap();

        let mut buf = Buffer::default();
        let mut decrypt_buf = [0u8; 16384 + 256];

        // 客戶端準備 close_notify
        write_traffic(
            client.process_tls_records_fast(&[], &mut decrypt_buf),
            |mut wt| {
                queue_close_notify(&mut wt, &mut buf);
            },
        );

        // 在 close_notify 後附加垃圾數據
        let junk = [0xffu8; 64];
        buf.append(&junk);

        let len = buf.used;
        eprintln!("發送 {len} bytes（包含 close_notify + 垃圾）");

        // 服務器處理
        let UnbufferedStatus { discard, state } = server.process_tls_records(buf.filled());

        // 應該檢測到 PeerClosed
        match state.unwrap() {
            ConnectionState::PeerClosed => {}
            other => panic!("預期 PeerClosed，得到 {:?}", other),
        }
        buf.discard(discard);

        // close_notify 後的垃圾應被忽略
        let UnbufferedStatus { discard, state } = server.process_tls_records(buf.filled());
        assert_eq!(discard, 0, "垃圾數據應被忽略");

        // 狀態應該是 WriteTraffic（服務器可以發送數據）或 Closed
        match state.unwrap() {
            ConnectionState::WriteTraffic(_) | ConnectionState::Closed => {}
            other => panic!("預期 WriteTraffic 或 Closed，得到 {:?}", other),
        }
    }
}

// ============================================================================
// Key Refresh 測試 (Traffic Key Update Tests)
// ============================================================================

/// 測試 TLS 1.2 連接的 key refresh 應返回錯誤
///
/// 驗證要點：
/// - TLS 1.2 不支持 key update（因為沒有 KeyUpdate 消息）
/// - 調用 refresh_traffic_keys 應返回 HandshakeNotComplete 錯誤
#[test]
#[cfg(feature = "tls12")]
fn fast_refresh_traffic_keys_on_tls12_connection() {
    use rustls::version::TLS12;

    let outcome = handshake(&TLS12);
    let mut client = outcome.client.unwrap();
    let mut decrypt_buf = [0u8; 16384 + 256];

    // 獲取 WriteTraffic 狀態並嘗試 refresh
    match client
        .process_tls_records_fast(&[], &mut decrypt_buf)
        .state
        .unwrap()
    {
        ConnectionState::WriteTraffic(wt) => {
            // TLS 1.2 不支持 key update
            let result = wt.refresh_traffic_keys();
            assert!(
                matches!(result, Err(rustls::Error::HandshakeNotComplete)),
                "TLS 1.2 應返回 HandshakeNotComplete，實際: {:?}",
                result
            );
        }
        other => panic!("預期 WriteTraffic，得到 {:?}", other),
    }
}

/// 測試 TLS 1.3 手動 key refresh
///
/// 流程：
/// 1. 客戶端調用 refresh_traffic_keys()
/// 2. 編碼並傳輸 KeyUpdate 消息
/// 3. 服務器處理後發送 "hello"
/// 4. 客戶端接收並驗證
/// 5. 客戶端回覆 "world"，服務器接收成功
#[test]
fn fast_refresh_traffic_keys_manually() {
    let mut outcome = handshake(&rustls::version::TLS13);
    let mut client = outcome.client.take().unwrap();
    let mut server = outcome.server.take().unwrap();
    let mut decrypt_buf = [0u8; 16384 + 256];

    // 1. 客戶端調用 refresh_traffic_keys
    match client
        .process_tls_records_fast(&[], &mut decrypt_buf)
        .state
        .unwrap()
    {
        ConnectionState::WriteTraffic(wt) => {
            wt.refresh_traffic_keys()
                .expect("TLS 1.3 應支持 key refresh");
        }
        other => panic!("預期 WriteTraffic，得到 {:?}", other),
    }

    // 2. 編碼 KeyUpdate 消息
    let mut buffer = [0u8; 64];
    let used = match client
        .process_tls_records_fast(&[], &mut decrypt_buf)
        .state
        .unwrap()
    {
        ConnectionState::EncodeTlsData(mut etd) => {
            println!("編碼 KeyUpdate");
            etd.encode(&mut buffer)
                .expect("編碼失敗")
        }
        other => panic!("預期 EncodeTlsData，得到 {:?}", other),
    };

    // 確認 TransmitTlsData
    match client
        .process_tls_records_fast(&[], &mut decrypt_buf)
        .state
        .unwrap()
    {
        ConnectionState::TransmitTlsData(ttd) => {
            ttd.done();
        }
        other => panic!("預期 TransmitTlsData，得到 {:?}", other),
    }

    // 3. 服務器處理 KeyUpdate，然後加密 "hello"
    println!("服務器接收 KeyUpdate 並發送 hello");
    let used = match server.process_tls_records(&mut buffer[..used]) {
        UnbufferedStatus {
            discard: actual_used,
            state: Ok(ConnectionState::WriteTraffic(mut wt)),
        } => {
            assert_eq!(used, actual_used);
            wt.encrypt(b"hello", &mut buffer)
                .expect("加密失敗")
        }
        other => panic!("預期 WriteTraffic，得到 {:?}", other.state),
    };

    // 4. 客戶端接收 "hello"（使用零拷貝 API）
    println!("客戶端接收 hello");
    let UnbufferedStatus { discard, state } =
        client.process_tls_records_fast(&buffer[..used], &mut decrypt_buf);

    match state.unwrap() {
        ConnectionState::FastReadLen(FastReadLen(len)) => {
            assert_eq!(used, discard);
            let payload = &decrypt_buf[..len];
            assert_eq!(payload, b"hello", "客戶端應收到 'hello'");
        }
        other => panic!("預期 FastReadLen，得到 {:?}", other),
    }

    // 5. 客戶端回覆 "world"
    println!("客戶端發送 world");
    let used = match client
        .process_tls_records_fast(&[], &mut decrypt_buf)
        .state
        .unwrap()
    {
        ConnectionState::WriteTraffic(mut wt) => wt
            .encrypt(b"world", &mut buffer)
            .expect("加密失敗"),
        other => panic!("預期 WriteTraffic，得到 {:?}", other),
    };

    // 服務器接收 "world"
    match server.process_tls_records(&mut buffer[..used]) {
        UnbufferedStatus {
            discard: actual_used,
            state: Ok(ConnectionState::ReadTraffic(mut rt)),
        } => {
            assert_eq!(used, actual_used);
            let app_data = rt.next_record().unwrap().unwrap();
            assert_eq!(app_data.payload, b"world", "服務器應收到 'world'");
        }
        other => panic!("預期 ReadTraffic，得到 {:?}", other.state),
    }
}

#[test]
fn fast_current_inbound_key_sequence_range_finds_the_only_match() {
    let mut outcome = handshake(&rustls::version::TLS13);
    let mut client = outcome.client.take().unwrap();
    let mut server = outcome.server.take().unwrap();
    let mut client_out = [0u8; 16384 + 256];
    let mut server_out = [0u8; 16384 + 256];
    let expected_seq = client.dangerous_read_seq();
    let mut record = [0u8; 256];
    let record_len = encrypt_server_record(
        &mut server,
        &mut server_out,
        b"range-current",
        &mut record,
    );
    let outcome = client
        .dangerous_try_decrypt_record_to_sequence_range(
            &record[..record_len],
            expected_seq.saturating_sub(3),
            expected_seq + 5,
            &mut client_out,
        )
        .expect("current-key sequence range must execute");
    match outcome {
        DangerousBatchDecryptOutcome::AuthenticatedApplicationData {
            seq,
            plaintext_len,
        } => {
            assert_eq!(seq, expected_seq);
            assert_eq!(&client_out[..plaintext_len], b"range-current");
        }
        other => panic!("expected current-key range match, got {other:?}"),
    }
    assert_eq!(client.dangerous_read_seq(), expected_seq);
}

#[test]
fn fast_speculative_next_inbound_key_is_transactional_across_two_generations() {
    let mut outcome = handshake(&rustls::version::TLS13);
    let mut client = outcome.client.take().unwrap();
    let mut server = outcome.server.take().unwrap();
    let mut client_out = [0u8; 16384 + 256];
    let mut server_out = [0u8; 16384 + 256];
    let initial_read_seq = client.dangerous_read_seq();

    drop_server_key_update(&mut server, &mut server_out);

    let mut generation_one = [0u8; 256];
    let generation_one_len = encrypt_server_record(
        &mut server,
        &mut server_out,
        b"generation-one",
        &mut generation_one,
    );
    let generation_one = &generation_one[..generation_one_len];

    assert!(matches!(
        client.dangerous_try_decrypt_record_to_at(generation_one, 0, &mut client_out),
        Err(rustls::Error::DecryptError)
    ));
    assert_eq!(client.dangerous_read_seq(), initial_read_seq);

    assert!(matches!(
        client.dangerous_try_decrypt_record_to_at_with_next_key(
            generation_one,
            1,
            &mut client_out,
        ),
        Err(rustls::Error::DecryptError)
    ));
    assert_eq!(client.dangerous_read_seq(), initial_read_seq);
    assert!(client.dangerous_commit_next_inbound_key(1).is_err());
    assert_eq!(client.dangerous_read_seq(), initial_read_seq);

    let mut corrupted = generation_one.to_vec();
    let last = corrupted
        .last_mut()
        .expect("the encrypted TLS record contains an authentication tag");
    *last ^= 1;
    assert!(matches!(
        client.dangerous_try_decrypt_record_to_at_with_next_key(
            &corrupted,
            0,
            &mut client_out,
        ),
        Err(rustls::Error::DecryptError)
    ));
    assert_eq!(client.dangerous_read_seq(), initial_read_seq);
    assert!(client.dangerous_commit_next_inbound_key(0).is_err());
    assert_eq!(client.dangerous_read_seq(), initial_read_seq);

    let mut undersized = [0u8; 1];
    assert!(matches!(
        client.dangerous_try_decrypt_record_to_at_with_next_key(
            generation_one,
            0,
            &mut undersized,
        ),
        Err(rustls::Error::General(_))
    ));
    assert_eq!(client.dangerous_read_seq(), initial_read_seq);
    assert!(client.dangerous_commit_next_inbound_key(0).is_err());
    assert_eq!(client.dangerous_read_seq(), initial_read_seq);

    let batch_len = match client
        .dangerous_try_decrypt_record_to_sequence_range_with_next_key(
            generation_one,
            0,
            6,
            &mut client_out,
        )
        .expect("the next-key batch range must execute")
    {
        DangerousBatchDecryptOutcome::AuthenticatedApplicationData {
            seq,
            plaintext_len,
        } => {
            assert_eq!(seq, 0);
            plaintext_len
        }
        other => panic!("expected authenticated next-key batch record, got {other:?}"),
    };
    assert_eq!(&client_out[..batch_len], b"generation-one");
    assert_eq!(client.dangerous_read_seq(), initial_read_seq);

    let len = authenticated_application_data_len(
        client
            .dangerous_try_decrypt_record_to_at_with_next_key(
                generation_one,
                0,
                &mut client_out,
            )
            .expect("the first speculative traffic key must decrypt"),
    );
    assert_eq!(&client_out[..len], b"generation-one");
    assert_eq!(client.dangerous_read_seq(), initial_read_seq);
    assert!(matches!(
        client.dangerous_try_decrypt_record_to_at(generation_one, 0, &mut client_out),
        Err(rustls::Error::DecryptError)
    ));

    assert!(client
        .dangerous_commit_next_inbound_key(u64::MAX)
        .is_err());
    assert_eq!(client.dangerous_read_seq(), initial_read_seq);
    assert!(client.dangerous_commit_next_inbound_key(1).is_err());
    assert_eq!(client.dangerous_read_seq(), initial_read_seq);
    client
        .dangerous_commit_next_inbound_key(0)
        .expect("the authenticated first speculative key must commit");
    assert_eq!(client.dangerous_read_seq(), 1);

    let mut generation_one_current = [0u8; 256];
    let generation_one_current_len = encrypt_server_record(
        &mut server,
        &mut server_out,
        b"generation-one-current",
        &mut generation_one_current,
    );
    let len = authenticated_application_data_len(
        client
            .dangerous_try_decrypt_record_to_at(
                &generation_one_current[..generation_one_current_len],
                1,
                &mut client_out,
            )
            .expect("the committed first key must be current"),
    );
    assert_eq!(&client_out[..len], b"generation-one-current");
    client.dangerous_commit_read_seq(2);

    drop_server_key_update(&mut server, &mut server_out);

    let mut generation_two = [0u8; 256];
    let generation_two_len = encrypt_server_record(
        &mut server,
        &mut server_out,
        b"generation-two",
        &mut generation_two,
    );
    let generation_two = &generation_two[..generation_two_len];

    assert!(matches!(
        client.dangerous_try_decrypt_record_to_at(generation_two, 0, &mut client_out),
        Err(rustls::Error::DecryptError)
    ));
    assert_eq!(client.dangerous_read_seq(), 2);

    let len = authenticated_application_data_len(
        client
            .dangerous_try_decrypt_record_to_at_with_next_key(
                generation_two,
                0,
                &mut client_out,
            )
            .expect("the second speculative traffic key must decrypt"),
    );
    assert_eq!(&client_out[..len], b"generation-two");
    assert_eq!(client.dangerous_read_seq(), 2);
    client
        .dangerous_commit_next_inbound_key(0)
        .expect("the authenticated second speculative key must commit");
    assert_eq!(client.dangerous_read_seq(), 1);

    let mut generation_two_current = [0u8; 256];
    let generation_two_current_len = encrypt_server_record(
        &mut server,
        &mut server_out,
        b"generation-two-current",
        &mut generation_two_current,
    );
    let len = authenticated_application_data_len(
        client
            .dangerous_try_decrypt_record_to_at(
                &generation_two_current[..generation_two_current_len],
                1,
                &mut client_out,
            )
            .expect("the committed second key must be current"),
    );
    assert_eq!(&client_out[..len], b"generation-two-current");
}

#[test]
fn fast_standard_client_key_update_uses_prepared_inbound_chain() {
    let mut outcome = handshake(&rustls::version::TLS13);
    let mut client = outcome.client.take().unwrap();
    let mut server = outcome.server.take().unwrap();
    let mut client_out = [0u8; 16384 + 256];
    let mut server_out = [0u8; 16384 + 256];
    let mut key_update = [0u8; 256];
    let key_update_len = encode_server_key_update(
        &mut server,
        &mut server_out,
        &mut key_update,
    );
    let mut generation_one = [0u8; 256];
    let generation_one_len = encrypt_server_record(
        &mut server,
        &mut server_out,
        b"standard-generation-one",
        &mut generation_one,
    );

    process_client_key_update(
        &mut client,
        &key_update[..key_update_len],
        &mut client_out,
    );
    assert_eq!(client.dangerous_read_seq(), 0);
    let len = authenticated_application_data_len(
        client
            .dangerous_try_decrypt_record_to_at(
                &generation_one[..generation_one_len],
                0,
                &mut client_out,
            )
            .expect("the standard KeyUpdate must install the prepared inbound key"),
    );
    assert_eq!(&client_out[..len], b"standard-generation-one");
    client.dangerous_commit_read_seq(1);

    assert_following_speculative_generation(
        &mut client,
        &mut server,
        &mut client_out,
        &mut server_out,
        b"standard-generation-two",
    );
}

#[test]
fn fast_failed_speculative_trial_does_not_split_standard_key_update_chain() {
    let mut outcome = handshake(&rustls::version::TLS13);
    let mut client = outcome.client.take().unwrap();
    let mut server = outcome.server.take().unwrap();
    let mut client_out = [0u8; 16384 + 256];
    let mut server_out = [0u8; 16384 + 256];
    let initial_read_seq = client.dangerous_read_seq();
    let mut key_update = [0u8; 256];
    let key_update_len = encode_server_key_update(
        &mut server,
        &mut server_out,
        &mut key_update,
    );
    let mut generation_one = [0u8; 256];
    let generation_one_len = encrypt_server_record(
        &mut server,
        &mut server_out,
        b"failed-trial-generation-one",
        &mut generation_one,
    );

    assert!(matches!(
        client.dangerous_try_decrypt_record_to_at_with_next_key(
            &generation_one[..generation_one_len],
            1,
            &mut client_out,
        ),
        Err(rustls::Error::DecryptError)
    ));
    assert!(client.dangerous_commit_next_inbound_key(1).is_err());
    assert_eq!(client.dangerous_read_seq(), initial_read_seq);

    process_client_key_update(
        &mut client,
        &key_update[..key_update_len],
        &mut client_out,
    );
    let len = authenticated_application_data_len(
        client
            .dangerous_try_decrypt_record_to_at(
                &generation_one[..generation_one_len],
                0,
                &mut client_out,
            )
            .expect("a failed speculative trial must not poison standard KeyUpdate"),
    );
    assert_eq!(&client_out[..len], b"failed-trial-generation-one");
    client.dangerous_commit_read_seq(1);

    assert_following_speculative_generation(
        &mut client,
        &mut server,
        &mut client_out,
        &mut server_out,
        b"failed-trial-generation-two",
    );
}

#[test]
fn fast_uncommitted_speculative_success_is_consumed_by_standard_key_update() {
    let mut outcome = handshake(&rustls::version::TLS13);
    let mut client = outcome.client.take().unwrap();
    let mut server = outcome.server.take().unwrap();
    let mut client_out = [0u8; 16384 + 256];
    let mut server_out = [0u8; 16384 + 256];
    let initial_read_seq = client.dangerous_read_seq();
    let mut key_update = [0u8; 256];
    let key_update_len = encode_server_key_update(
        &mut server,
        &mut server_out,
        &mut key_update,
    );
    let mut generation_one = [0u8; 256];
    let generation_one_len = encrypt_server_record(
        &mut server,
        &mut server_out,
        b"uncommitted-generation-one",
        &mut generation_one,
    );

    let len = authenticated_application_data_len(
        client
            .dangerous_try_decrypt_record_to_at_with_next_key(
                &generation_one[..generation_one_len],
                0,
                &mut client_out,
            )
            .expect("the speculative next key must authenticate before standard KeyUpdate"),
    );
    assert_eq!(&client_out[..len], b"uncommitted-generation-one");
    assert_eq!(client.dangerous_read_seq(), initial_read_seq);

    process_client_key_update(
        &mut client,
        &key_update[..key_update_len],
        &mut client_out,
    );
    assert!(client.dangerous_commit_next_inbound_key(0).is_err());
    assert_eq!(client.dangerous_read_seq(), 0);
    let len = authenticated_application_data_len(
        client
            .dangerous_try_decrypt_record_to_at(
                &generation_one[..generation_one_len],
                0,
                &mut client_out,
            )
            .expect("standard KeyUpdate must consume the speculative key exactly once"),
    );
    assert_eq!(&client_out[..len], b"uncommitted-generation-one");
    client.dangerous_commit_read_seq(1);

    assert_following_speculative_generation(
        &mut client,
        &mut server,
        &mut client_out,
        &mut server_out,
        b"uncommitted-generation-two",
    );
}

#[test]
fn fast_current_key_update_and_next_key_app_data_share_one_tail_chain() {
    let mut outcome = handshake(&rustls::version::TLS13);
    let mut client = outcome.client.take().unwrap();
    let mut server = outcome.server.take().unwrap();
    let mut client_out = [0u8; 16384 + 256];
    let mut server_out = [0u8; 16384 + 256];
    let mut tail_packet = [0u8; 512];
    let current_seq = client.dangerous_read_seq();

    let key_update_len = encode_server_key_update(
        &mut server,
        &mut server_out,
        &mut tail_packet,
    );
    let next_app_len = encrypt_server_record(
        &mut server,
        &mut server_out,
        b"next-key-tail-app-data",
        &mut tail_packet[key_update_len..],
    );
    let tail_packet = &tail_packet[..key_update_len + next_app_len];
    let (current_key_update, next_key_app_data) = tail_packet.split_at(key_update_len);

    assert_eq!(
        client
            .dangerous_try_decrypt_record_to_at(tail_packet, current_seq, &mut client_out)
            .expect("a multi-record tail packet is a valid framing outcome"),
        DangerousDecryptOutcome::NoCompleteSingleRecord,
    );
    assert_eq!(
        client
            .dangerous_try_decrypt_record_to_at(current_key_update, current_seq, &mut client_out)
            .expect("the current-key KeyUpdate must authenticate"),
        DangerousDecryptOutcome::AuthenticatedOpaque,
    );
    client.dangerous_commit_read_seq(current_seq + 1);

    let len = authenticated_application_data_len(
        client
            .dangerous_try_decrypt_record_to_at_with_next_key(
                next_key_app_data,
                0,
                &mut client_out,
            )
            .expect("the next-key application record must authenticate"),
    );
    assert_eq!(&client_out[..len], b"next-key-tail-app-data");
    client
        .dangerous_commit_next_inbound_key(0)
        .expect("the opaque current record must not block next-key commit");
    assert_eq!(client.dangerous_read_seq(), 1);
}

#[test]
fn fast_authenticated_opaque_next_key_commits_and_prepares_following_generation() {
    let mut outcome = handshake(&rustls::version::TLS13);
    let mut client = outcome.client.take().unwrap();
    let mut server = outcome.server.take().unwrap();
    let mut client_out = [0u8; 16384 + 256];
    let mut server_out = [0u8; 16384 + 256];
    let initial_read_seq = client.dangerous_read_seq();

    drop_server_key_update(&mut server, &mut server_out);

    let mut next_key_update = [0u8; 256];
    let next_key_update_len = encode_server_key_update(
        &mut server,
        &mut server_out,
        &mut next_key_update,
    );
    assert_eq!(
        client
            .dangerous_try_decrypt_record_to_at_with_next_key(
                &next_key_update[..next_key_update_len],
                0,
                &mut client_out,
            )
            .expect("the next-key KeyUpdate must authenticate"),
        DangerousDecryptOutcome::AuthenticatedOpaque,
    );
    assert_eq!(client.dangerous_read_seq(), initial_read_seq);
    let mut corrupted = next_key_update[..next_key_update_len].to_vec();
    let last = corrupted
        .last_mut()
        .expect("the encrypted KeyUpdate contains an authentication tag");
    *last ^= 1;
    assert!(matches!(
        client.dangerous_try_decrypt_record_to_at_with_next_key(
            &corrupted,
            0,
            &mut client_out,
        ),
        Err(rustls::Error::DecryptError)
    ));
    assert_eq!(client.dangerous_read_seq(), initial_read_seq);
    client
        .dangerous_commit_next_inbound_key(0)
        .expect("a later authentication failure must preserve the opaque commit proof");
    assert_eq!(client.dangerous_read_seq(), 1);

    let mut following_generation = [0u8; 256];
    let following_generation_len = encrypt_server_record(
        &mut server,
        &mut server_out,
        b"following-generation",
        &mut following_generation,
    );
    let len = authenticated_application_data_len(
        client
            .dangerous_try_decrypt_record_to_at_with_next_key(
                &following_generation[..following_generation_len],
                0,
                &mut client_out,
            )
            .expect("the following speculative generation must authenticate"),
    );
    assert_eq!(&client_out[..len], b"following-generation");
    client
        .dangerous_commit_next_inbound_key(0)
        .expect("the following speculative generation must commit");
    assert_eq!(client.dangerous_read_seq(), 1);
}

fn authenticated_application_data_len(outcome: DangerousDecryptOutcome) -> usize {
    match outcome {
        DangerousDecryptOutcome::AuthenticatedApplicationData(len) => len,
        other => panic!("expected authenticated application data, got {other:?}"),
    }
}

fn process_client_key_update(
    client: &mut UnbufferedClientConnection,
    key_update: &[u8],
    scratch: &mut [u8],
) {
    let UnbufferedStatus { discard, state } =
        client.process_tls_records_fast(key_update, scratch);
    assert_eq!(discard, key_update.len());
    match state.expect("the standard client KeyUpdate must process") {
        ConnectionState::WriteTraffic(_) => {}
        other => panic!("expected WriteTraffic after server KeyUpdate, got {other:?}"),
    }
}

fn assert_following_speculative_generation(
    client: &mut UnbufferedClientConnection,
    server: &mut UnbufferedServerConnection,
    client_scratch: &mut [u8],
    server_scratch: &mut [u8],
    expected: &[u8],
) {
    drop_server_key_update(server, server_scratch);
    let mut following = [0u8; 256];
    let following_len = encrypt_server_record(
        server,
        server_scratch,
        expected,
        &mut following,
    );
    let len = authenticated_application_data_len(
        client
            .dangerous_try_decrypt_record_to_at_with_next_key(
                &following[..following_len],
                0,
                client_scratch,
            )
            .expect("the following speculative generation must remain prepared"),
    );
    assert_eq!(&client_scratch[..len], expected);
    client
        .dangerous_commit_next_inbound_key(0)
        .expect("the following speculative generation must commit");
    assert_eq!(client.dangerous_read_seq(), 1);
}

fn drop_server_key_update(
    server: &mut UnbufferedServerConnection,
    scratch: &mut [u8],
) {
    let mut discarded = [0u8; 256];
    let _ = encode_server_key_update(server, scratch, &mut discarded);
}

fn encode_server_key_update(
    server: &mut UnbufferedServerConnection,
    scratch: &mut [u8],
    record: &mut [u8],
) -> usize {
    match server
        .process_tls_records_fast(&[], scratch)
        .state
        .unwrap()
    {
        ConnectionState::WriteTraffic(write) => write
            .refresh_traffic_keys()
            .expect("TLS 1.3 server traffic keys must refresh"),
        other => panic!("expected WriteTraffic before key update, got {other:?}"),
    }

    let encoded = match server
        .process_tls_records_fast(&[], scratch)
        .state
        .unwrap()
    {
        ConnectionState::EncodeTlsData(mut encode) => encode
            .encode(scratch)
            .expect("the KeyUpdate record must encode"),
        other => panic!("expected EncodeTlsData for key update, got {other:?}"),
    };
    assert!(encoded > 0, "the KeyUpdate record must not be empty");
    record[..encoded].copy_from_slice(&scratch[..encoded]);

    match server
        .process_tls_records_fast(&[], scratch)
        .state
        .unwrap()
    {
        ConnectionState::TransmitTlsData(transmit) => transmit.done(),
        other => panic!("expected TransmitTlsData for key update, got {other:?}"),
    }
    encoded
}

fn encrypt_server_record(
    server: &mut UnbufferedServerConnection,
    scratch: &mut [u8],
    plaintext: &[u8],
    record: &mut [u8],
) -> usize {
    match server
        .process_tls_records_fast(&[], scratch)
        .state
        .unwrap()
    {
        ConnectionState::WriteTraffic(mut write) => write
            .encrypt(plaintext, record)
            .expect("the server application record must encrypt"),
        other => panic!("expected WriteTraffic before application record, got {other:?}"),
    }
}

// ============================================================================
// Kernel API 測試 (kTLS Secret Extraction Tests)
// 驗證零拷貝 API 的密鑰提取功能
// ============================================================================

/// 測試密鑰提取未啟用時返回錯誤
///
/// 驗證要點：
/// - 握手完成後，如果未啟用 enable_secret_extraction
/// - 調用 dangerous_into_kernel_connection 應返回錯誤
#[test]
fn fast_kernel_err_on_secret_extraction_not_enabled() {
    let outcome = handshake(&rustls::version::TLS13);
    let client = outcome.client.unwrap();
    let server = outcome.server.unwrap();

    // 未啟用密鑰提取，應該返回錯誤
    assert!(
        client
            .dangerous_into_kernel_connection()
            .is_err(),
        "客戶端未啟用密鑰提取，應返回錯誤"
    );
    assert!(
        server
            .dangerous_into_kernel_connection()
            .is_err(),
        "服務器未啟用密鑰提取，應返回錯誤"
    );
}

/// 測試握手未完成時密鑰提取返回錯誤
///
/// 驗證要點：
/// - 握手未完成時調用 dangerous_into_kernel_connection
/// - 應返回 HandshakeNotComplete 錯誤
#[test]
fn fast_kernel_err_on_handshake_not_complete() {
    let provider = provider::default_provider();
    let mut server_config = make_server_config(KeyType::Rsa2048, &provider);
    server_config.enable_secret_extraction = true;
    let server_config = std::sync::Arc::new(server_config);

    let mut client_config = make_client_config(KeyType::Rsa2048, &provider);
    client_config.enable_secret_extraction = true;
    let client_config = std::sync::Arc::new(client_config);

    let server = UnbufferedServerConnection::new(server_config).unwrap();
    let client = UnbufferedClientConnection::new(client_config, server_name("localhost")).unwrap();

    // 握手未完成，應該返回 HandshakeNotComplete 錯誤
    assert!(
        matches!(
            client.dangerous_into_kernel_connection(),
            Err(rustls::Error::HandshakeNotComplete)
        ),
        "客戶端握手未完成，應返回 HandshakeNotComplete"
    );
    assert!(
        matches!(
            server.dangerous_into_kernel_connection(),
            Err(rustls::Error::HandshakeNotComplete)
        ),
        "服務器握手未完成，應返回 HandshakeNotComplete"
    );
}

/// 測試初始流量密鑰匹配
///
/// 驗證要點：
/// - 握手完成後，客戶端的 TX 密鑰應與服務器的 RX 密鑰匹配
/// - 客戶端的 RX 密鑰應與服務器的 TX 密鑰匹配
#[test]
fn fast_kernel_initial_traffic_secrets_match() {
    let provider = provider::default_provider();
    let mut server_config = make_server_config(KeyType::Rsa2048, &provider);
    server_config.enable_secret_extraction = true;
    let server_config = std::sync::Arc::new(server_config);

    let mut client_config = make_client_config(KeyType::Rsa2048, &provider);
    client_config.enable_secret_extraction = true;
    let client_config = std::sync::Arc::new(client_config);

    // 使用 run 函數完成握手
    let mut outcome = run(
        client_config,
        &mut NO_ACTIONS.clone(),
        server_config,
        &mut NO_ACTIONS.clone(),
    );

    let client = outcome.client.take().unwrap();
    let server = outcome.server.take().unwrap();

    // 提取密鑰
    let (client_secrets, _) = client
        .dangerous_into_kernel_connection()
        .expect("客戶端密鑰提取失敗");
    let (server_secrets, _) = server
        .dangerous_into_kernel_connection()
        .expect("服務器密鑰提取失敗");

    // 驗證密鑰匹配
    assert_secrets_equal(client_secrets.tx, server_secrets.rx);
    assert_secrets_equal(server_secrets.tx, client_secrets.rx);
}

/// 測試 TLS 1.3 密鑰更新
///
/// 驗證要點：
/// - 握手完成後提取密鑰
/// - 調用 update_tx_secret 和 update_rx_secret
/// - 驗證更新後的密鑰仍然匹配
#[test]
fn fast_kernel_key_updates_tls13() {
    let provider = provider::default_provider();
    let mut server_config =
        make_server_config_with_versions(KeyType::Rsa2048, &[&rustls::version::TLS13], &provider);
    server_config.enable_secret_extraction = true;
    let server_config = std::sync::Arc::new(server_config);

    let mut client_config =
        make_client_config_with_versions(KeyType::Rsa2048, &[&rustls::version::TLS13], &provider);
    client_config.enable_secret_extraction = true;
    let client_config = std::sync::Arc::new(client_config);

    // 使用 run 函數完成握手
    let mut outcome = run(
        client_config,
        &mut NO_ACTIONS.clone(),
        server_config,
        &mut NO_ACTIONS.clone(),
    );

    let client = outcome.client.take().unwrap();
    let server = outcome.server.take().unwrap();

    // 提取 kernel connection
    let (_, mut client_kernel) = client
        .dangerous_into_kernel_connection()
        .expect("客戶端密鑰提取失敗");
    let (_, mut server_kernel) = server
        .dangerous_into_kernel_connection()
        .expect("服務器密鑰提取失敗");

    // 客戶端更新密鑰
    let new_client_tx = client_kernel
        .update_tx_secret()
        .expect("客戶端 TX 密鑰更新失敗");
    let new_client_rx = client_kernel
        .update_rx_secret()
        .expect("客戶端 RX 密鑰更新失敗");

    // 服務器更新密鑰
    let new_server_tx = server_kernel
        .update_tx_secret()
        .expect("服務器 TX 密鑰更新失敗");
    let new_server_rx = server_kernel
        .update_rx_secret()
        .expect("服務器 RX 密鑰更新失敗");

    // 驗證更新後的密鑰匹配
    assert_secrets_equal(new_client_tx, new_server_rx);
    assert_secrets_equal(new_server_tx, new_client_rx);
}

/// 測試 TLS 1.2 密鑰更新返回 None
///
/// 驗證要點：
/// - TLS 1.2 不支持密鑰更新
/// - update_tx_secret 和 update_rx_secret 應返回 None
#[test]
#[cfg(feature = "tls12")]
fn fast_kernel_key_updates_tls12() {
    use rustls::version::TLS12;

    let provider = provider::default_provider();
    let mut server_config =
        make_server_config_with_versions(KeyType::Rsa2048, &[&TLS12], &provider);
    server_config.enable_secret_extraction = true;
    let server_config = std::sync::Arc::new(server_config);

    let mut client_config =
        make_client_config_with_versions(KeyType::Rsa2048, &[&TLS12], &provider);
    client_config.enable_secret_extraction = true;
    let client_config = std::sync::Arc::new(client_config);

    // 使用 run 函數完成握手
    let mut outcome = run(
        client_config,
        &mut NO_ACTIONS.clone(),
        server_config,
        &mut NO_ACTIONS.clone(),
    );

    let client = outcome.client.take().unwrap();
    let server = outcome.server.take().unwrap();

    // 提取 kernel connection
    let (_, mut client_kernel) = client
        .dangerous_into_kernel_connection()
        .expect("客戶端密鑰提取失敗");
    let (_, mut server_kernel) = server
        .dangerous_into_kernel_connection()
        .expect("服務器密鑰提取失敗");

    // TLS 1.2 不支持密鑰更新，應返回 Err
    assert!(
        client_kernel
            .update_tx_secret()
            .is_err(),
        "TLS 1.2 客戶端 TX 密鑰更新應返回 Err"
    );
    assert!(
        client_kernel
            .update_rx_secret()
            .is_err(),
        "TLS 1.2 客戶端 RX 密鑰更新應返回 Err"
    );
    assert!(
        server_kernel
            .update_tx_secret()
            .is_err(),
        "TLS 1.2 服務器 TX 密鑰更新應返回 Err"
    );
    assert!(
        server_kernel
            .update_rx_secret()
            .is_err(),
        "TLS 1.2 服務器 RX 密鑰更新應返回 Err"
    );
}

/// 密鑰比較輔助函數
fn assert_secrets_equal(
    (l_seq, l_sec): (u64, rustls::ConnectionTrafficSecrets),
    (r_seq, r_sec): (u64, rustls::ConnectionTrafficSecrets),
) {
    assert_eq!(l_seq, r_seq, "序列號應相等");

    fn explode_secrets(s: &rustls::ConnectionTrafficSecrets) -> (&[u8], &[u8]) {
        match s {
            rustls::ConnectionTrafficSecrets::Aes128Gcm { key, iv } => (key.as_ref(), iv.as_ref()),
            rustls::ConnectionTrafficSecrets::Aes256Gcm { key, iv } => (key.as_ref(), iv.as_ref()),
            rustls::ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv } => {
                (key.as_ref(), iv.as_ref())
            }
            _ => panic!("未知密鑰類型"),
        }
    }

    assert_eq!(
        explode_secrets(&l_sec),
        explode_secrets(&r_sec),
        "密鑰內容應相等"
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

/// 使用 process_tls_records_fast 處理 TLS 記錄
///
/// 注意：零拷貝 API 對於 ApplicationData 返回 FastReadLen 狀態，
/// 解密後的數據直接在輸出緩衝區中，而不是通過 ReadTraffic 迭代器獲取。
fn advance_client(
    conn: &mut UnbufferedConnectionCommon<ClientConnectionData>,
    buffers: &mut Buffers,
    actions: Actions,
    transcript: &mut Vec<String>,
) -> State {
    // 輸出緩衝區用於解密，必須足夠大（至少 16384 + 256 bytes）
    let mut decrypt_buf = [0u8; 16384 + 256];
    let UnbufferedStatus { discard, state } =
        conn.process_tls_records_fast(buffers.incoming.filled(), &mut decrypt_buf);
    let state = state.unwrap();

    transcript.push(format!("{state:?}"));

    let state = match state {
        // 零拷貝專用狀態：FastReadLen 表示應用數據已解密到輸出緩衝區
        ConnectionState::FastReadLen(FastReadLen(len)) => {
            // 從輸出緩衝區提取解密的數據
            let records = vec![decrypt_buf[..len].to_vec()];
            State::ReceivedAppData { records }
        }

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

/// 從 WriteTraffic 狀態執行操作
fn write_traffic<T: SideData, R, F: FnMut(WriteTraffic<T>) -> R>(
    status: UnbufferedStatus<'_, '_, T>,
    mut f: F,
) -> R {
    let UnbufferedStatus { discard, state } = status;
    assert_eq!(discard, 0);
    match state.unwrap() {
        ConnectionState::WriteTraffic(state) => f(state),
        other => panic!("預期 WriteTraffic，得到 {other:?}"),
    }
}

/// 從 ReadTraffic 狀態讀取數據
fn read_traffic<T: SideData, R, F: FnMut(rustls::unbuffered::ReadTraffic<T>) -> R>(
    status: UnbufferedStatus<'_, '_, T>,
    mut f: F,
) -> (R, usize) {
    let UnbufferedStatus { discard, state } = status;
    match state.unwrap() {
        ConnectionState::ReadTraffic(state) => (f(state), discard),
        other => panic!("預期 ReadTraffic，得到 {other:?}"),
    }
}

/// 檢查 PeerClosed 狀態
fn peer_closed<T: SideData>(status: UnbufferedStatus<'_, '_, T>) -> usize {
    let UnbufferedStatus { discard, state } = status;
    match state.unwrap() {
        ConnectionState::PeerClosed => discard,
        other => panic!("預期 PeerClosed，得到 {other:?}"),
    }
}

/// 檢查 Closed 狀態
fn closed<T: SideData>(status: UnbufferedStatus<'_, '_, T>) -> usize {
    let UnbufferedStatus { discard, state } = status;
    match state.unwrap() {
        ConnectionState::Closed => discard,
        other => panic!("預期 Closed，得到 {other:?}"),
    }
}

/// 創建客戶端和服務器連接對
fn make_connection_pair(
    version: &'static rustls::SupportedProtocolVersion,
) -> (UnbufferedClientConnection, UnbufferedServerConnection) {
    let provider = provider::default_provider();
    let server_config = make_server_config(KeyType::Rsa2048, &provider);
    let client_config = make_client_config_with_versions(KeyType::Rsa2048, &[version], &provider);

    let client = UnbufferedClientConnection::new(
        std::sync::Arc::new(client_config),
        server_name("localhost"),
    )
    .unwrap();
    let server = UnbufferedServerConnection::new(std::sync::Arc::new(server_config)).unwrap();
    (client, server)
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
