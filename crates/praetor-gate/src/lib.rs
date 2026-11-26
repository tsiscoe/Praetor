#![forbid(unsafe_code)]
//! **Praetor Gate** — Authenticated LAN Interceptor Proxy closing `VEC-01` across **NodeAlpha**,
//! **NodeBeta**, **NodeDelta**, and **NodeGamma**.
//!
//! Hardened under Wave-1 Security Audit (`[SEC-04a]`..`[SEC-04d]` + `WIN32-HANDLE-INHERIT`):
//! 1. **Zero-Smuggling Canonical HTTP/1.1 Parser (`[SEC-04a]`):** Rejects bare `\r`/`\n`, obs-fold,
//!    header-name whitespace, duplicate `Content-Length`/`Origin`/`Host`/`X-Praetor-Envelope`, and
//!    reconstructs canonical outbound headers from validated AST state (eliminating `raw_head`).
//! 2. **Origin-Gated `OPTIONS` Preflight (`[SEC-04b]`):** Runs `authorize_http_request` *before*
//!    answering `OPTIONS`, blocking untrusted CORS preflights and HTTP response splitting.
//! 3. **Non-Blocking Rate-Limited `.sext` Worker (`[SEC-04c]`):** Cooldown-throttles `.sext` disk
//!    captures per peer IP (`60s`), caps directory count (`<= 512`), and offloads `fsync`/`icacls`
//!    to a bounded background `spawn_blocking` queue so Tokio reactor threads never stall.
//! 4. **Bounded Concurrency, Timeouts & Exact `Content-Length` Relay (`[SEC-04d]`):** Caps active
//!    connections via `Semaphore(256)`, enforces connect/header/write timeouts, checks `coordinator`
//!    RBAC on conference wakes (`[SEC-01a-3]`), and closes upstream sockets immediately once
//!    `Content-Length` bytes arrive (defeating Windows child-process socket handle inheritance hangs).

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use praetor_core::envelope::{
    ENVELOPE_HEADER, ReplayWindow, WakeClaims, sign_wake_envelope, verify_wake_envelope,
};
use praetor_core::forensics::{IncidentEvidence, write_forensic_sextant_capsule};
use praetor_core::nodes::{ClusterRoster, NodeSecretKey};
use praetor_core::{PraetorError, PraetorResult};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, mpsc};
use uuid::Uuid;

/// Hard ceiling on HTTP header block (`16 KiB`).
pub const MAX_HTTP_HEADER_BYTES: usize = 16 * 1024;
/// Hard ceiling on HTTP request body (`256 KiB`).
pub const MAX_HTTP_BODY_BYTES: usize = 256 * 1024;
/// Maximum concurrent inbound TCP connections handled by `praetor-gate` (`[SEC-04d]` / `[G2]`).
pub const MAX_CONCURRENT_CONNECTIONS: usize = 192;
/// Maximum concurrent unauthenticated `GET`/SSE connections, reserving 128 permits for control traffic (`[G2]`).
pub const MAX_PUBLIC_GET_CONNECTIONS: usize = 64;
/// Idle upstream read timeout and hard stream lifetime for SSE responses (`[G2]`).
pub const SSE_IDLE_READ_TIMEOUT_SECS: u64 = 300;
pub const MAX_SSE_LIFETIME_SECS: u64 = 3600;
/// Maximum retained `gate-block-*.sext` files in `forensic_dir` (`[SEC-04c]`).
pub const MAX_GATE_FORENSIC_FILES: usize = 512;

/// Runtime configuration for a `praetor-gate` node listener.
#[derive(Clone)]
pub struct GateConfig {
    pub local_node_id: String,
    pub roster: Arc<ClusterRoster>,
    pub upstream_addr: SocketAddr,
    pub forensic_dir: Option<PathBuf>,
}

/// Shared state across concurrent TCP connections on `praetor-gate`.
pub struct GateState {
    pub cfg: GateConfig,
    pub replay: Mutex<ReplayWindow>,
    pub blocked_attempts: Mutex<u64>,
    pub forensic_dropped: AtomicU64,
    pub conn_semaphore: Arc<Semaphore>,
    pub public_get_semaphore: Arc<Semaphore>,
    forensic_cooldown: Mutex<BTreeMap<IpAddr, Instant>>,
    forensic_tx: mpsc::Sender<(IncidentEvidence, PathBuf)>,
}

impl GateState {
    pub fn new(cfg: GateConfig) -> Arc<Self> {
        let (tx, mut rx) = mpsc::channel::<(IncidentEvidence, PathBuf)>(32);
        let state = Arc::new(Self {
            cfg,
            replay: Mutex::new(ReplayWindow::new(65_536)),
            blocked_attempts: Mutex::new(0),
            forensic_dropped: AtomicU64::new(0),
            conn_semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS)),
            public_get_semaphore: Arc::new(Semaphore::new(MAX_PUBLIC_GET_CONNECTIONS)),
            forensic_cooldown: Mutex::new(BTreeMap::new()),
            forensic_tx: tx,
        });
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            let st_weak = Arc::downgrade(&state);
            handle.spawn(async move {
                while let Some((ev, ledger_path)) = rx.recv().await {
                    let write_res = tokio::task::spawn_blocking(move || {
                        if let Some(parent) = ledger_path.parent()
                            && gate_forensic_has_capacity(parent)
                        {
                            std::fs::create_dir_all(parent)?;
                            write_forensic_sextant_capsule(&ev, &ledger_path)?;
                            Ok::<bool, PraetorError>(true)
                        } else {
                            Ok(false)
                        }
                    })
                    .await;
                    if !matches!(write_res, Ok(Ok(true)))
                        && let Some(st) = st_weak.upgrade()
                    {
                        st.forensic_dropped.fetch_add(1, Ordering::Relaxed);
                    }
                }
            });
        }

        state
    }
}

fn gate_forensic_has_capacity(dir: &Path) -> bool {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return true;
    };
    let count = rd
        .filter_map(Result::ok)
        .filter(|e| e.path().extension().and_then(|x| x.to_str()) == Some("sext"))
        .take(MAX_GATE_FORENSIC_FILES + 1)
        .count();
    count < MAX_GATE_FORENSIC_FILES
}

/// Validated, smuggling-free HTTP/1.1 request AST (`[SEC-04a]` — `raw_head` eliminated).
#[derive(Debug, Clone)]
pub struct ParsedHttpRequest {
    pub method: String,
    pub path: String,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}

/// Inspect a parsed HTTP request against CSRF, `X-Praetor-Envelope`, and `coordinator` RBAC rules.
pub fn authorize_http_request(
    req: &ParsedHttpRequest,
    peer_ip: IpAddr,
    state: &GateState,
) -> Result<Option<WakeClaims>, (u16, String)> {
    let origin = req.headers.get("origin").map(String::as_str);
    if let Err(err) = state.cfg.roster.verify_origin(origin) {
        record_blocked_wake(state, peer_ip, &req.method, &req.path, &err.to_string());
        return Err((403, format!("CSRF blocked: {err}")));
    }

    if req.method.eq_ignore_ascii_case("OPTIONS") {
        return Ok(None);
    }

    // Allow local loopback non-browser presence heartbeats (`Watch-AgentChannel.py`)
    if peer_ip.is_loopback()
        && origin.is_none()
        && req.method.eq_ignore_ascii_case("POST")
        && req.path == "/api/mesh/presence"
    {
        return Ok(None);
    }

    // Only `GET` is unauthenticated read; `HEAD`, `POST`, `PUT`, `DELETE`, etc. require `X-Praetor-Envelope`
    let requires_envelope = !req.method.eq_ignore_ascii_case("GET");
    if !requires_envelope {
        return Ok(None);
    }

    let Some(raw_env) = req.headers.get(ENVELOPE_HEADER) else {
        let msg = format!(
            "missing required {ENVELOPE_HEADER} header from {peer_ip} on {} {}",
            req.method, req.path
        );
        record_blocked_wake(state, peer_ip, &req.method, &req.path, &msg);
        return Err((401, msg));
    };

    let mut replay_guard = state
        .replay
        .lock()
        .map_err(|_| (500, "replay mutex poisoned".to_string()))?;

    let claims = match verify_wake_envelope(
        raw_env,
        &state.cfg.roster,
        &state.cfg.local_node_id,
        peer_ip,
        &req.method,
        &req.path,
        &req.body,
        &mut replay_guard,
    ) {
        Ok(c) => c,
        Err(err) => {
            drop(replay_guard);
            let status = match err {
                PraetorError::UnauthorizedNodeIp { .. } | PraetorError::CrossOriginBlocked(_) => {
                    403
                }
                _ => 401,
            };
            let msg = format!("wake authorization denied: {err}");
            record_blocked_wake(state, peer_ip, &req.method, &req.path, &msg);
            return Err((status, msg));
        }
    };
    drop(replay_guard);

    // Enforce `coordinator` RBAC on `/api/mesh/conference` or `assemble`/`adjourn` signals (`[SEC-01a-3]`)
    if requires_coordinator_role(&req.path, &req.body) {
        let sender = state
            .cfg
            .roster
            .get_node(&claims.sender_node)
            .map_err(|e| (403, e.to_string()))?;
        if !sender.has_role("coordinator") {
            let msg = format!(
                "node '{}' lacks required 'coordinator' role for conference control",
                sender.node_id
            );
            record_blocked_wake(state, peer_ip, &req.method, &req.path, &msg);
            return Err((403, msg));
        }
    }

    Ok(Some(claims))
}

fn requires_coordinator_role(path: &str, body: &[u8]) -> bool {
    if path.starts_with("/api/mesh/conference") {
        return true;
    }
    if path.starts_with("/api/mesh")
        && let Ok(val) = serde_json::from_slice::<serde_json::Value>(body)
    {
        for key in ["type", "conference_signal", "action"] {
            let v = val
                .get(key)
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase();
            if matches!(v.as_str(), "assemble" | "adjourn") {
                return true;
            }
        }
        // Mirror Start-AgentHubServer.py `_detect_conference_signal` title/body triggers (`[G1]`)
        for key in ["title", "topic", "summary", "body", "excerpt"] {
            let v = val
                .get(key)
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_ascii_lowercase();
            if v.contains("[assemble]")
                || v.contains("[adjourn]")
                || (matches!(key, "title" | "topic") && v.contains("avengers assemble"))
            {
                return true;
            }
        }
    }
    false
}

fn record_blocked_wake(state: &GateState, peer_ip: IpAddr, method: &str, path: &str, reason: &str) {
    if let Ok(mut count) = state.blocked_attempts.lock() {
        *count += 1;
    }
    let Some(ref dir) = state.cfg.forensic_dir else {
        return;
    };

    // Per-IP 60s cooldown checked before enqueueing; cooldown only recorded AFTER `try_send` succeeds (`[G4]`)
    let now = Instant::now();
    let in_cooldown = if let Ok(mut map) = state.forensic_cooldown.lock() {
        if map.len() > 4096 {
            map.retain(|_, ts| now.duration_since(*ts) < Duration::from_secs(60));
        }
        matches!(map.get(&peer_ip), Some(prev) if now.duration_since(*prev) < Duration::from_secs(60))
    } else {
        state.forensic_dropped.fetch_add(1, Ordering::Relaxed);
        return;
    };

    if in_cooldown {
        return;
    }

    let id = Uuid::new_v4().simple().to_string();
    let ledger_path = dir.join(format!("gate-block-{}.sext", &id[..12]));
    let ev = IncidentEvidence {
        incident_id: id,
        host_node: state.cfg.local_node_id.clone(),
        detector: "praetor-gate".into(),
        vector_code: "VEC-01-UNAUTH-WAKE".into(),
        summary: format!("peer={peer_ip} {method} {path} -> {reason}"),
        offending_pid: None,
        terminated_pids: Vec::new(),
        restored_files: Vec::new(),
        revoked_signet_token_hash: None,
    };
    if state.forensic_tx.try_send((ev, ledger_path)).is_ok() {
        if let Ok(mut map) = state.forensic_cooldown.lock() {
            map.insert(peer_ip, now);
        }
    } else {
        state.forensic_dropped.fetch_add(1, Ordering::Relaxed);
    }
}

/// Bind `listener` and serve the authenticated reverse proxy under bounded concurrency (`[SEC-04d]`).
pub async fn serve_gate_listener(
    listener: TcpListener,
    state: Arc<GateState>,
) -> std::io::Result<()> {
    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let Ok(permit) = Arc::clone(&state.conn_semaphore).try_acquire_owned() else {
            drop(stream);
            continue;
        };
        let st = Arc::clone(&state);
        tokio::spawn(async move {
            let _permit = permit;
            let _ = handle_client_connection(stream, peer_addr.ip(), st).await;
        });
    }
}

/// Handle one inbound HTTP/1.1 connection with strict timeouts, CSRF gate, reserved control permits, and framing safety.
pub async fn handle_client_connection(
    mut client: TcpStream,
    peer_ip: IpAddr,
    state: Arc<GateState>,
) -> std::io::Result<()> {
    let parsed =
        match tokio::time::timeout(Duration::from_secs(10), read_http_request(&mut client)).await {
            Ok(Ok(req)) => req,
            Ok(Err((code, msg))) => {
                record_blocked_wake(&state, peer_ip, "INVALID", "/", &msg);
                return write_json_error(&mut client, code, &msg).await;
            }
            Err(_) => {
                return write_json_error(&mut client, 408, "request read timed out").await;
            }
        };

    // Reserve `128` connection permits strictly for authenticated/control traffic (`[G2]`)
    let _public_get_permit = if parsed.method.eq_ignore_ascii_case("GET") {
        let Ok(permit) = Arc::clone(&state.public_get_semaphore).try_acquire_owned() else {
            return write_json_error(
                &mut client,
                503,
                "public read/SSE capacity saturated; signed control channels reserved",
            )
            .await;
        };
        Some(permit)
    } else {
        None
    };

    // Authorize BEFORE `OPTIONS` so `verify_origin` strictly enforces `allowed_origins` (`[SEC-04b]`)
    let claims = match authorize_http_request(&parsed, peer_ip, &state) {
        Ok(c) => c,
        Err((code, reason)) => return write_json_error(&mut client, code, &reason).await,
    };

    if parsed.method.eq_ignore_ascii_case("OPTIONS") {
        let origin_hdr = parsed
            .headers
            .get("origin")
            .cloned()
            .unwrap_or_else(|| "http://127.0.0.1:8088".into());
        let resp = format!(
            "HTTP/1.1 204 No Content\r\n\
             Access-Control-Allow-Origin: {origin_hdr}\r\n\
             Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n\
             Access-Control-Allow-Headers: Content-Type, X-Praetor-Envelope\r\n\
             Vary: Origin\r\n\
             Connection: close\r\n\r\n"
        );
        let _ =
            tokio::time::timeout(Duration::from_secs(5), client.write_all(resp.as_bytes())).await;
        return Ok(());
    }

    let mut upstream = match tokio::time::timeout(
        Duration::from_secs(3),
        TcpStream::connect(state.cfg.upstream_addr),
    )
    .await
    {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            return write_json_error(
                &mut client,
                502,
                &format!("upstream loopback unreachable: {e}"),
            )
            .await;
        }
        Err(_) => {
            return write_json_error(&mut client, 504, "upstream loopback connect timeout").await;
        }
    };

    let verified_sender = claims.as_ref().map(|c| c.sender_node.as_str());
    let canonical_head = serialize_canonical_upstream_request(&parsed, verified_sender);
    tokio::time::timeout(Duration::from_secs(5), async {
        upstream.write_all(&canonical_head).await?;
        upstream.write_all(&parsed.body).await?;
        upstream.flush().await
    })
    .await
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "upstream write timeout"))??;

    // Read upstream response headers strictly up to `MAX_HTTP_HEADER_BYTES` (`[G3]`)
    let mut head_buf = Vec::with_capacity(2048);
    let mut chunk = [0u8; 4096];
    let header_end = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let n = upstream.read(&mut chunk).await?;
            if n == 0 {
                return Ok::<Option<usize>, std::io::Error>(None);
            }
            head_buf.extend_from_slice(&chunk[..n]);
            if let Some(pos) = find_header_terminator(&head_buf) {
                return Ok(Some(pos));
            }
            if head_buf.len() > MAX_HTTP_HEADER_BYTES {
                return Ok(None);
            }
        }
    })
    .await
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "upstream header timeout"))??;

    let Some(pos) = header_end else {
        return write_json_error(
            &mut client,
            502,
            "upstream returned truncated or oversized HTTP headers",
        )
        .await;
    };
    if pos > MAX_HTTP_HEADER_BYTES {
        return write_json_error(
            &mut client,
            502,
            "upstream HTTP headers exceed 16 KiB limit",
        )
        .await;
    }

    let resp_content_length = match parse_upstream_framing(&head_buf[..pos], &parsed.method) {
        Ok(len_opt) => len_opt,
        Err(reason) => return write_json_error(&mut client, 502, reason).await,
    };

    let sanitized_head = scrub_wildcard_cors(&head_buf[..pos + 4]);
    let initial_body = &head_buf[pos + 4..];

    tokio::time::timeout(Duration::from_secs(10), async {
        client.write_all(&sanitized_head).await?;
        if !initial_body.is_empty() {
            client.write_all(initial_body).await?;
        }
        client.flush().await
    })
    .await
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "client write timeout"))??;

    // If `Content-Length: N` is present, stop immediately once `N` body bytes are relayed!
    if let Some(expected_len) = resp_content_length {
        let mut delivered = initial_body.len();
        while delivered < expected_len {
            let to_read = (expected_len - delivered).min(chunk.len());
            let Ok(Ok(n)) = tokio::time::timeout(
                Duration::from_secs(10),
                upstream.read(&mut chunk[..to_read]),
            )
            .await
            else {
                break;
            };
            if n == 0 {
                break;
            }
            if tokio::time::timeout(Duration::from_secs(10), async {
                client.write_all(&chunk[..n]).await?;
                client.flush().await
            })
            .await
            .is_err()
            {
                break;
            }
            delivered += n;
        }
        return Ok(());
    }

    // Bounded streaming mode (for SSE `Content-Type: text/event-stream`): 300s idle timeout + 3600s max lifetime (`[G2]`)
    let stream_start = Instant::now();
    let max_lifetime = Duration::from_secs(MAX_SSE_LIFETIME_SECS);
    while stream_start.elapsed() < max_lifetime {
        let Ok(Ok(n)) = tokio::time::timeout(
            Duration::from_secs(SSE_IDLE_READ_TIMEOUT_SECS),
            upstream.read(&mut chunk),
        )
        .await
        else {
            break;
        };
        if n == 0 {
            break;
        }
        let write_res = tokio::time::timeout(Duration::from_secs(10), async {
            client.write_all(&chunk[..n]).await?;
            client.flush().await
        })
        .await;
        if !matches!(write_res, Ok(Ok(()))) {
            break;
        }
    }
    Ok(())
}

/// Strict RFC 9112 HTTP/1.1 request parser closing `[SEC-04a]` smuggling vectors.
pub async fn read_http_request(stream: &mut TcpStream) -> Result<ParsedHttpRequest, (u16, String)> {
    let mut buf = Vec::with_capacity(2048);
    let mut chunk = [0u8; 2048];
    let header_end = loop {
        let n = stream
            .read(&mut chunk)
            .await
            .map_err(|e| (400, format!("socket read failed: {e}")))?;
        if n == 0 {
            return Err((400, "unexpected EOF before HTTP headers completed".into()));
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = find_header_terminator(&buf) {
            if pos > MAX_HTTP_HEADER_BYTES {
                return Err((431, "HTTP headers exceed 16 KiB limit".into()));
            }
            break pos;
        }
        if buf.len() > MAX_HTTP_HEADER_BYTES {
            return Err((431, "HTTP headers exceed 16 KiB limit".into()));
        }
    };

    let head_str = std::str::from_utf8(&buf[..header_end])
        .map_err(|_| (400, "non-UTF-8 HTTP request headers".to_string()))?;
    let mut lines = head_str.split("\r\n");
    let req_line = lines
        .next()
        .ok_or_else(|| (400, "missing request line".to_string()))?;
    if req_line.contains(['\r', '\n']) {
        return Err((400, "bare CR/LF in request line rejected".into()));
    }
    let req_parts: Vec<&str> = req_line.split(' ').collect();
    if req_parts.len() != 3 || !matches!(req_parts[2], "HTTP/1.1" | "HTTP/1.0") {
        return Err((
            400,
            "malformed HTTP request line or unsupported HTTP version".into(),
        ));
    }

    let method = req_parts[0].to_string();
    let path = req_parts[1].to_string();
    if !method.bytes().all(|b| b.is_ascii_uppercase()) {
        return Err((400, "invalid HTTP method token".into()));
    }
    if !path.starts_with('/')
        || path.starts_with("//")
        || path.contains('\\')
        || path.contains("..")
        || path.bytes().any(|b| b <= 0x20 || b == 0x7f)
    {
        return Err((400, "invalid or non-normalized HTTP request target".into()));
    }

    let mut headers = BTreeMap::new();
    for line in lines {
        if line.is_empty() {
            return Err((400, "unexpected empty header line".into()));
        }
        if line.contains(['\r', '\n']) || line.starts_with([' ', '\t']) {
            return Err((
                400,
                "bare LF or obs-fold header continuation rejected".into(),
            ));
        }
        let Some((raw_k, raw_v)) = line.split_once(':') else {
            return Err((400, "malformed header line missing ':'".into()));
        };
        if raw_k.is_empty()
            || !raw_k
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
        {
            return Err((400, "invalid HTTP header field-name token".into()));
        }
        let k = raw_k.to_ascii_lowercase();
        let v = raw_v.trim().to_string();
        if v.bytes().any(|b| (b < 0x20 && b != b'\t') || b == 0x7f) {
            return Err((400, "control character in header value rejected".into()));
        }
        if headers.insert(k.clone(), v).is_some()
            && matches!(
                k.as_str(),
                "content-length" | "transfer-encoding" | "origin" | "host" | ENVELOPE_HEADER
            )
        {
            return Err((400, format!("duplicate '{k}' header rejected (CWE-444)")));
        }
    }

    if headers.contains_key("transfer-encoding") {
        return Err((
            411,
            "chunked Transfer-Encoding rejected; explicit Content-Length required".into(),
        ));
    }

    let content_len = match headers.get("content-length") {
        Some(v) => v
            .parse::<usize>()
            .map_err(|_| (400, "invalid Content-Length".to_string()))?,
        None => 0,
    };
    if content_len > MAX_HTTP_BODY_BYTES {
        return Err((413, "HTTP request body exceeds 256 KiB limit".into()));
    }

    let already_read_body = &buf[header_end + 4..];
    if already_read_body.len() > content_len {
        return Err((400, "pipelined extra trailing bytes rejected".into()));
    }

    let mut body = Vec::with_capacity(content_len);
    body.extend_from_slice(already_read_body);
    while body.len() < content_len {
        let remaining = content_len - body.len();
        let read_slice_len = remaining.min(chunk.len());
        let n = stream
            .read(&mut chunk[..read_slice_len])
            .await
            .map_err(|e| (400, format!("body read failed: {e}")))?;
        if n == 0 {
            return Err((400, "truncated HTTP body".into()));
        }
        body.extend_from_slice(&chunk[..n]);
    }

    Ok(ParsedHttpRequest {
        method,
        path,
        headers,
        body,
    })
}

fn find_header_terminator(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn parse_upstream_framing(
    raw_head: &[u8],
    req_method: &str,
) -> Result<Option<usize>, &'static str> {
    let head = std::str::from_utf8(raw_head).map_err(|_| "non-UTF-8 upstream HTTP headers")?;
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    let status_code = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or("malformed upstream HTTP status line")?;

    let mut content_len: Option<usize> = None;
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            let k_low = k.trim().to_ascii_lowercase();
            if k_low == "transfer-encoding" {
                return Err("upstream Transfer-Encoding unsupported by canonical proxy");
            }
            if k_low == "content-length" {
                let parsed = v
                    .trim()
                    .parse::<usize>()
                    .map_err(|_| "invalid upstream Content-Length")?;
                if let Some(prev) = content_len {
                    if prev != parsed {
                        return Err("conflicting duplicate upstream Content-Length headers");
                    }
                    return Err("duplicate upstream Content-Length header rejected");
                }
                content_len = Some(parsed);
            }
        }
    }

    if req_method.eq_ignore_ascii_case("HEAD")
        || (100..200).contains(&status_code)
        || matches!(status_code, 204 | 304)
    {
        return Ok(Some(0));
    }
    Ok(content_len)
}

fn serialize_canonical_upstream_request(
    req: &ParsedHttpRequest,
    verified_sender: Option<&str>,
) -> Vec<u8> {
    let mut out = format!("{} {} HTTP/1.1\r\n", req.method, req.path);
    for (k, v) in &req.headers {
        if matches!(
            k.as_str(),
            "connection" | "keep-alive" | "proxy-connection" | "x-praetor-verified-node"
        ) {
            continue;
        }
        out.push_str(k);
        out.push_str(": ");
        out.push_str(v);
        out.push_str("\r\n");
    }
    if let Some(sender) = verified_sender {
        out.push_str("x-praetor-verified-node: ");
        out.push_str(sender);
        out.push_str("\r\n");
    }
    out.push_str("Connection: close\r\n\r\n");
    out.into_bytes()
}

fn scrub_wildcard_cors(resp: &[u8]) -> Vec<u8> {
    let Some(pos) = find_header_terminator(resp) else {
        return resp.to_vec();
    };
    let head = String::from_utf8_lossy(&resp[..pos]);
    let body = &resp[pos + 4..];

    let mut out_head = String::with_capacity(head.len() + 32);
    for (idx, line) in head.split("\r\n").enumerate() {
        if idx > 0
            && line
                .to_ascii_lowercase()
                .starts_with("access-control-allow-origin:")
        {
            out_head.push_str("X-Praetor-Gate: enforced\r\n");
            continue;
        }
        out_head.push_str(line);
        out_head.push_str("\r\n");
    }
    out_head.push_str("\r\n");
    let mut combined = out_head.into_bytes();
    combined.extend_from_slice(body);
    combined
}

async fn write_json_error(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
) -> std::io::Result<()> {
    let status_text = match status {
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        408 => "Request Timeout",
        411 => "Length Required",
        413 => "Payload Too Large",
        431 => "Request Header Fields Too Large",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "Error",
    };
    let body = serde_json::to_vec(&serde_json::json!({
        "status": "blocked",
        "gate": "praetor-gate",
        "code": status,
        "error": reason,
    }))
    .unwrap_or_else(|_| b"{\"status\":\"blocked\"}".to_vec());

    let head = format!(
        "HTTP/1.1 {status} {status_text}\r\n\
         Content-Type: application/json; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         X-Praetor-Gate: blocked\r\n\
         Connection: close\r\n\r\n",
        body.len()
    );
    let _ = tokio::time::timeout(Duration::from_secs(5), async {
        stream.write_all(head.as_bytes()).await?;
        stream.write_all(&body).await?;
        stream.flush().await
    })
    .await;
    Ok(())
}

/// Helper for authorized CLI clients (`avengers.py` replacement) to construct a signed HTTP POST.
pub fn build_signed_post_bytes(
    secret: &NodeSecretKey,
    sender_node: &str,
    target_node: &str,
    host_header: &str,
    path: &str,
    json_body: &[u8],
    ttl_secs: i64,
) -> PraetorResult<Vec<u8>> {
    if host_header.contains(['\r', '\n']) || path.contains(['\r', '\n']) {
        return Err(PraetorError::EndpointMismatch);
    }
    let claims = WakeClaims::new(
        sender_node,
        target_node,
        "POST",
        path,
        json_body,
        ttl_secs,
        None,
    );
    let env = sign_wake_envelope(secret, &claims)?;
    let req = format!(
        "POST {path} HTTP/1.1\r\n\
         Host: {host_header}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         X-Praetor-Envelope: {env}\r\n\
         Connection: close\r\n\r\n",
        json_body.len()
    );
    let mut raw = req.into_bytes();
    raw.extend_from_slice(json_body);
    Ok(raw)
}
