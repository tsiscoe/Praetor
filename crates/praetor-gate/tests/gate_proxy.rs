use std::collections::BTreeMap;
use std::sync::Arc;

use praetor_core::nodes::{ClusterRoster, NodeSecretKey};
use praetor_gate::{GateConfig, GateState, build_signed_post_bytes, serve_gate_listener};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[tokio::test]
async fn vec01_gate_blocks_unauthenticated_post_and_csrf_while_forwarding_signed_wake() {
    // 1. Spin up mock loopback Python hub (`127.0.0.1:0`) returning `Access-Control-Allow-Origin: *`
    let upstream_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream");
    let upstream_addr = upstream_listener.local_addr().expect("upstream addr");

    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = upstream_listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let _ = sock.read(&mut buf).await;
                let body = b"{\"status\":\"ok\",\"conference\":{\"status\":\"ASSEMBLED\"}}";
                let resp = format!(
                    "HTTP/1.1 200 OK\r\n\
                     Content-Type: application/json\r\n\
                     Access-Control-Allow-Origin: *\r\n\
                     Content-Length: {}\r\n\
                     Connection: close\r\n\r\n",
                    body.len()
                );
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.write_all(body).await;
            });
        }
    });

    // 2. Build cluster roster & forensic output dir, then start `praetor-gate`
    let forensic_dir = TempDir::new().expect("tempdir");
    let alpha_sk = NodeSecretKey::generate();
    let mut pubkeys = BTreeMap::new();
    pubkeys.insert("node-alpha".into(), alpha_sk.verifying_key_hex());
    let roster = ClusterRoster::default_cluster(&pubkeys).expect("roster");

    let gate_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind gate");
    let gate_addr = gate_listener.local_addr().expect("gate addr");
    let state = GateState::new(GateConfig {
        local_node_id: "node-alpha".into(),
        roster: Arc::new(roster),
        upstream_addr,
        forensic_dir: Some(forensic_dir.path().to_path_buf()),
    });
    let state_ref = Arc::clone(&state);
    tokio::spawn(async move {
        let _ = serve_gate_listener(gate_listener, state_ref).await;
    });

    // Attack A: Unauthenticated POST /api/mesh/notify -> 401 + Sextant forensic capsule minted
    {
        let mut s = TcpStream::connect(gate_addr).await.expect("connect");
        let raw = "POST /api/mesh/notify HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 21\r\nConnection: close\r\n\r\n{\"type\":\"assemble\"}  ";
        s.write_all(raw.as_bytes()).await.expect("write");
        let mut resp = String::new();
        s.read_to_string(&mut resp).await.expect("read");
        assert!(resp.starts_with("HTTP/1.1 401 Unauthorized"), "got: {resp}");
    }

    // Attack B: Browser drive-by CSRF (`Origin: https://evil.example`) -> 403 Forbidden
    {
        let mut s = TcpStream::connect(gate_addr).await.expect("connect");
        let raw = "GET /api/mesh/presence HTTP/1.1\r\nHost: 127.0.0.1\r\nOrigin: https://evil.example\r\nConnection: close\r\n\r\n";
        s.write_all(raw.as_bytes()).await.expect("write");
        let mut resp = String::new();
        s.read_to_string(&mut resp).await.expect("read");
        assert!(resp.starts_with("HTTP/1.1 403 Forbidden"), "got: {resp}");
    }

    // Wait briefly for the background `.sext` spawn_blocking worker (`[SEC-04c]`) to flush
    // Note: Both Attack A and Attack B came from `127.0.0.1` within 60s, so per-IP cooldown caps disk writes to 1 `.sext` capsule!
    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    let sext_count = std::fs::read_dir(forensic_dir.path())
        .expect("readdir")
        .filter_map(Result::ok)
        .filter(|e| e.path().extension().and_then(|x| x.to_str()) == Some("sext"))
        .count();
    assert_eq!(sext_count, 1);
    assert_eq!(*state.blocked_attempts.lock().expect("lock"), 2);

    // Legitimate Wake: Valid Ed25519 X-Praetor-Envelope from NodeAlpha -> 200 OK AND wildcard CORS stripped
    {
        let body = br#"{"id":"comm-01","type":"assemble","to":"all","title":"Audit"}"#;
        let wire = build_signed_post_bytes(
            &alpha_sk,
            "node-alpha",
            "node-alpha",
            &gate_addr.to_string(),
            "/api/mesh/notify",
            body,
            60,
        )
        .expect("signed wire");

        let mut s = TcpStream::connect(gate_addr).await.expect("connect");
        s.write_all(&wire).await.expect("write");
        let mut resp = String::new();
        s.read_to_string(&mut resp).await.expect("read");
        assert!(resp.starts_with("HTTP/1.1 200 OK"), "got: {resp}");
        assert!(
            !resp
                .to_ascii_lowercase()
                .contains("access-control-allow-origin: *"),
            "wildcard CORS leaked: {resp}"
        );
        assert!(resp.contains("\"ASSEMBLED\""));
    }
}

#[tokio::test]
async fn sec04_blocks_smuggling_evil_options_worker_assemble_and_inherited_handle_hang() {
    // Upstream intentionally holds the socket open for 30s AFTER writing `Content-Length` bytes,
    // reproducing Windows `subprocess.Popen` handle inheritance (`WIN32-HANDLE-INHERIT`).
    let upstream_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream");
    let upstream_addr = upstream_listener.local_addr().expect("upstream addr");

    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = upstream_listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let _ = sock.read(&mut buf).await;
                let body = b"{\"status\":\"ok\",\"inherited_socket_held\":true}";
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
                    body.len()
                );
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.write_all(body).await;
                let _ = sock.flush().await;
                // Hold `sock` open for 30s without EOF!
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            });
        }
    });

    let alpha_sk = NodeSecretKey::generate();
    let gamma_sk = NodeSecretKey::generate();
    let mut pubkeys = BTreeMap::new();
    pubkeys.insert("node-alpha".into(), alpha_sk.verifying_key_hex());
    pubkeys.insert("node-gamma".into(), gamma_sk.verifying_key_hex());
    let roster = Arc::new(ClusterRoster::default_cluster(&pubkeys).expect("roster"));

    // Gate 1 (`local_node_id = "node-alpha"`) for parser, OPTIONS, and inherited-handle tests
    let gate_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind gate");
    let gate_addr = gate_listener.local_addr().expect("gate addr");
    let state = GateState::new(GateConfig {
        local_node_id: "node-alpha".into(),
        roster: Arc::clone(&roster),
        upstream_addr,
        forensic_dir: None,
    });
    tokio::spawn(serve_gate_listener(gate_listener, Arc::clone(&state)));

    // 1. `[SEC-04a]` Duplicate `Content-Length` smuggling attempt -> 400 Bad Request
    {
        let mut s = TcpStream::connect(gate_addr).await.expect("connect");
        let raw = "POST /api/mesh/notify HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{}";
        s.write_all(raw.as_bytes()).await.expect("write");
        let mut resp = String::new();
        s.read_to_string(&mut resp).await.expect("read");
        assert!(resp.starts_with("HTTP/1.1 400 Bad Request"), "got: {resp}");
    }

    // 2. `[SEC-04a]` Bare LF (`\n` without `\r\n`) or obs-fold header continuation -> 400 Bad Request
    {
        let mut s = TcpStream::connect(gate_addr).await.expect("connect");
        let raw = "GET /api/mesh/presence HTTP/1.1\r\nHost: 127.0.0.1\nX-Smuggled: 1\r\n\r\n";
        s.write_all(raw.as_bytes()).await.expect("write");
        let mut resp = String::new();
        s.read_to_string(&mut resp).await.expect("read");
        assert!(resp.starts_with("HTTP/1.1 400 Bad Request"), "got: {resp}");
    }

    // 3. `[SEC-04b]` `OPTIONS` preflight with untrusted `Origin: https://evil.example` -> 403 Forbidden
    {
        let mut s = TcpStream::connect(gate_addr).await.expect("connect");
        let raw = "OPTIONS /api/mesh/notify HTTP/1.1\r\nHost: 127.0.0.1\r\nOrigin: https://evil.example\r\n\r\n";
        s.write_all(raw.as_bytes()).await.expect("write");
        let mut resp = String::new();
        s.read_to_string(&mut resp).await.expect("read");
        assert!(resp.starts_with("HTTP/1.1 403 Forbidden"), "got: {resp}");
    }

    // 4. `WIN32-HANDLE-INHERIT`: Coordinator `node-alpha` POST finishes in < 1s even though upstream holds socket 30s!
    {
        let body = br#"{"id":"comm-02","type":"assemble","to":"all"}"#;
        let wire = build_signed_post_bytes(
            &alpha_sk,
            "node-alpha",
            "node-alpha",
            &gate_addr.to_string(),
            "/api/mesh/notify",
            body,
            60,
        )
        .expect("signed wire");

        let resp = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            let mut s = TcpStream::connect(gate_addr).await.expect("connect");
            s.write_all(&wire).await.expect("write");
            let mut buf = String::new();
            s.read_to_string(&mut buf).await.expect("read");
            buf
        })
        .await
        .expect("gate must close immediately on Content-Length without 30s hang");
        assert!(resp.starts_with("HTTP/1.1 200 OK"), "got: {resp}");
        assert!(resp.contains("\"inherited_socket_held\":true"));
    }

    // 5. `[SEC-01a-3]` Worker-only node `node-gamma` attempting `type: "assemble"` -> 403 Forbidden (RBAC)
    {
        let gamma_gate = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind node-gamma gate");
        let gamma_addr = gamma_gate.local_addr().expect("addr");
        let gamma_state = GateState::new(GateConfig {
            local_node_id: "node-gamma".into(),
            roster: Arc::clone(&roster),
            upstream_addr,
            forensic_dir: None,
        });
        tokio::spawn(serve_gate_listener(gamma_gate, gamma_state));

        let body = br#"{"id":"rogue-assemble","type":"assemble","to":"all"}"#;
        let wire = build_signed_post_bytes(
            &gamma_sk,
            "node-gamma",
            "node-gamma",
            &gamma_addr.to_string(),
            "/api/mesh/notify",
            body,
            60,
        )
        .expect("signed wire");

        let mut s = TcpStream::connect(gamma_addr).await.expect("connect");
        s.write_all(&wire).await.expect("write");
        let mut resp = String::new();
        s.read_to_string(&mut resp).await.expect("read");
        assert!(resp.starts_with("HTTP/1.1 403 Forbidden"), "got: {resp}");
        assert!(resp.contains("coordinator"));

        // `[G1]`: Worker node hiding `[ASSEMBLE]` inside `title` with harmless `type: "note"` ALSO blocked with 403!
        let stealth_body =
            br#"{"id":"stealth-1","type":"note","title":"[ASSEMBLE] escalate","to":"all"}"#;
        let stealth_wire = build_signed_post_bytes(
            &gamma_sk,
            "node-gamma",
            "node-gamma",
            &gamma_addr.to_string(),
            "/api/mesh/notify",
            stealth_body,
            60,
        )
        .expect("signed wire");
        let mut s2 = TcpStream::connect(gamma_addr).await.expect("connect");
        s2.write_all(&stealth_wire).await.expect("write");
        let mut resp2 = String::new();
        s2.read_to_string(&mut resp2).await.expect("read");
        assert!(resp2.starts_with("HTTP/1.1 403 Forbidden"), "got: {resp2}");
    }

    // 6. `[G3]` Upstream returning duplicate Content-Length is rejected with 502 Bad Gateway before forwarding body
    {
        let bad_upstream = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind bad upstream");
        let bad_addr = bad_upstream.local_addr().expect("addr");
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = bad_upstream.accept().await {
                let mut buf = [0u8; 1024];
                let _ = sock.read(&mut buf).await;
                let _ = sock
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 5\r\n\r\nhello",
                    )
                    .await;
            }
        });
        let g3_gate = TcpListener::bind("127.0.0.1:0").await.expect("bind g3");
        let g3_addr = g3_gate.local_addr().expect("addr");
        let g3_state = GateState::new(GateConfig {
            local_node_id: "node-alpha".into(),
            roster: Arc::clone(&roster),
            upstream_addr: bad_addr,
            forensic_dir: None,
        });
        tokio::spawn(serve_gate_listener(g3_gate, g3_state));

        let mut s = TcpStream::connect(g3_addr).await.expect("connect");
        s.write_all(b"GET /api/mesh/presence HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
            .await
            .expect("write");
        let mut resp = String::new();
        s.read_to_string(&mut resp).await.expect("read");
        assert!(resp.starts_with("HTTP/1.1 502 Bad Gateway"), "got: {resp}");
    }
}
