//! Replay-bounded `Ed25519` + `BLAKE3` HTTP wake envelopes (`prae1.<base64url-claims>.<hex-sig>`).
//!
//! Hardened under Wave-1 Security Audit (`[SEC-01a-1]`..`[SEC-01a-3]`):
//! - Enforces `VerifyingKey::verify_strict` + weak torsion key rejection (`[SEC-01a-2]`).
//! - Eliminates `ReplayWindow` unexpired FIFO eviction and head-of-line expiry blocking (`[SEC-01a-1]`).
//! - Restricts loopback `127.0.0.1` IP-pinning strictly to `sender_node == local_node_id` (`[SEC-01a-3]`).

use std::collections::{HashSet, VecDeque};
use std::net::IpAddr;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use ed25519_dalek::{Signature, Signer};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::nodes::{ClusterRoster, NodeSecretKey};
use crate::{PraetorError, PraetorResult};

/// Wire prefix for Praetor v1 signed wake envelopes.
pub const ENVELOPE_PREFIX: &str = "prae1";
/// HTTP header carrying the signed wake envelope.
pub const ENVELOPE_HEADER: &str = "x-praetor-envelope";
/// Domain separator preventing cross-protocol Ed25519 signature reuse.
const SIGNING_DOMAIN: &[u8] = b"PRAETOR_WAKE_ENVELOPE_V1:";
/// Maximum allowed clock skew in seconds.
pub const MAX_CLOCK_SKEW_SECS: i64 = 30;
/// Maximum allowed envelope TTL in seconds (clamped to 120s to bound replay state).
pub const MAX_ENVELOPE_TTL_SECS: i64 = 120;

/// Claims signed inside an `X-Praetor-Envelope` token.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WakeClaims {
    pub nonce: String,
    pub sender_node: String,
    pub target_node: String,
    pub method: String,
    pub path: String,
    pub body_blake3_hex: String,
    pub signet_token_hash: Option<String>,
    pub issued_at_unix: i64,
    pub expires_at_unix: i64,
}

impl WakeClaims {
    /// Create a fresh set of wake claims binding `method`, `path`, and raw HTTP `body`.
    pub fn new(
        sender_node: impl Into<String>,
        target_node: impl Into<String>,
        method: impl Into<String>,
        path: impl Into<String>,
        body: &[u8],
        ttl_secs: i64,
        signet_token_hash: Option<String>,
    ) -> Self {
        let now = Utc::now().timestamp();
        let clamped_ttl = ttl_secs.clamp(5, MAX_ENVELOPE_TTL_SECS);
        Self {
            nonce: Uuid::new_v4().to_string(),
            sender_node: sender_node.into().to_ascii_lowercase(),
            target_node: target_node.into().to_ascii_lowercase(),
            method: method.into().to_ascii_uppercase(),
            path: path.into(),
            body_blake3_hex: compute_body_digest_hex(body),
            signet_token_hash,
            issued_at_unix: now,
            expires_at_unix: now + clamped_ttl,
        }
    }
}

/// Compute domain-separated `BLAKE3` hex digest over an HTTP body.
pub fn compute_body_digest_hex(body: &[u8]) -> String {
    let mut hasher = blake3::Hasher::new_derive_key("PRAETOR_HTTP_BODY_V1");
    hasher.update(&(body.len() as u64).to_le_bytes());
    hasher.update(body);
    hex::encode(hasher.finalize().as_bytes())
}

/// Mint a signed `prae1.<base64url-claims>.<hex-sig>` wake envelope.
pub fn sign_wake_envelope(secret: &NodeSecretKey, claims: &WakeClaims) -> PraetorResult<String> {
    let claims_json = serde_json::to_vec(claims)?;
    let encoded_claims = URL_SAFE_NO_PAD.encode(&claims_json);

    let mut msg = Vec::with_capacity(SIGNING_DOMAIN.len() + encoded_claims.len());
    msg.extend_from_slice(SIGNING_DOMAIN);
    msg.extend_from_slice(encoded_claims.as_bytes());

    let sig: Signature = secret.signing_key().sign(&msg);
    Ok(format!(
        "{ENVELOPE_PREFIX}.{encoded_claims}.{}",
        hex::encode(sig.to_bytes())
    ))
}

/// Bounded fail-closed nonce replay cache (`[SEC-01a-1]`).
#[derive(Debug)]
pub struct ReplayWindow {
    capacity: usize,
    order: VecDeque<(String, i64)>,
    seen: HashSet<String>,
}

impl ReplayWindow {
    pub fn new(capacity: usize) -> Self {
        let cap = capacity.max(64);
        Self {
            capacity: cap,
            order: VecDeque::with_capacity(cap.min(4096)),
            seen: HashSet::with_capacity(cap.min(4096)),
        }
    }

    /// Purge expired nonces and atomically check-and-insert `nonce`.
    /// Never evicts unexpired nonces (`[SEC-01a-1]`): performs a full expired sweep when full
    /// and fails closed if `capacity` is saturated by live unexpired nonces.
    pub fn check_and_record(
        &mut self,
        nonce: &str,
        expires_at_unix: i64,
        now_unix: i64,
    ) -> PraetorResult<()> {
        while let Some((_, exp)) = self.order.front() {
            if exp
                .checked_add(MAX_CLOCK_SKEW_SECS)
                .is_some_and(|deadline| deadline < now_unix)
            {
                if let Some((old_nonce, _)) = self.order.pop_front() {
                    self.seen.remove(&old_nonce);
                }
            } else {
                break;
            }
        }

        if self.seen.contains(nonce) {
            return Err(PraetorError::ReplayDetected(nonce.to_string()));
        }

        if self.order.len() >= self.capacity {
            // Full sweep to defeat head-of-line blocking from mixed TTLs (`[SEC-01a-1]`)
            let seen = &mut self.seen;
            self.order.retain(|(n, exp)| {
                let alive = exp
                    .checked_add(MAX_CLOCK_SKEW_SECS)
                    .is_some_and(|deadline| deadline >= now_unix);
                if !alive {
                    seen.remove(n);
                }
                alive
            });
            if self.order.len() >= self.capacity {
                return Err(PraetorError::ReplayDetected(
                    "replay window saturated with live nonces; failing closed".into(),
                ));
            }
        }

        let owned = nonce.to_string();
        self.seen.insert(owned.clone());
        self.order.push_back((owned, expires_at_unix));
        Ok(())
    }
}

/// Verify an incoming `X-Praetor-Envelope` against the cluster roster, peer IP, method, path,
/// raw request body, clock window, and replay cache.
#[allow(clippy::too_many_arguments)]
pub fn verify_wake_envelope(
    raw_envelope: &str,
    roster: &ClusterRoster,
    local_node_id: &str,
    peer_ip: IpAddr,
    method: &str,
    path: &str,
    body: &[u8],
    replay_window: &mut ReplayWindow,
) -> PraetorResult<WakeClaims> {
    verify_wake_envelope_at(
        raw_envelope,
        roster,
        local_node_id,
        peer_ip,
        method,
        path,
        body,
        replay_window,
        Utc::now().timestamp(),
    )
}

/// Deterministic timestamp variant of [`verify_wake_envelope`] for testing and offline replay audits.
#[allow(clippy::too_many_arguments)]
pub fn verify_wake_envelope_at(
    raw_envelope: &str,
    roster: &ClusterRoster,
    local_node_id: &str,
    peer_ip: IpAddr,
    method: &str,
    path: &str,
    body: &[u8],
    replay_window: &mut ReplayWindow,
    now_unix: i64,
) -> PraetorResult<WakeClaims> {
    let parts: Vec<&str> = raw_envelope.trim().split('.').collect();
    if parts.len() != 3 || parts[0] != ENVELOPE_PREFIX {
        return Err(PraetorError::MalformedEnvelope(
            "expected prae1.<claims>.<sig>".into(),
        ));
    }

    let encoded_claims = parts[1];
    let sig_hex = parts[2];

    if encoded_claims.len() > 16 * 1024 {
        return Err(PraetorError::MalformedEnvelope(
            "claims segment exceeds 16 KiB".into(),
        ));
    }

    let claims_bytes = URL_SAFE_NO_PAD
        .decode(encoded_claims)
        .map_err(|e| PraetorError::MalformedEnvelope(format!("base64url decode failed: {e}")))?;
    let claims: WakeClaims = serde_json::from_slice(&claims_bytes)
        .map_err(|e| PraetorError::MalformedEnvelope(format!("claims JSON invalid: {e}")))?;

    // 1. Lookup sender node and verify host-aware IP pinning (`[SEC-01a-3]`)
    let node = roster.get_node(&claims.sender_node)?;
    if !node.allows_ip_on_host(peer_ip, local_node_id) {
        return Err(PraetorError::UnauthorizedNodeIp {
            node: node.node_id.clone(),
            actual: peer_ip.to_string(),
        });
    }

    // 2. Strictly verify Ed25519 signature over domain + encoded_claims (`[SEC-01a-2]`)
    let sig_bytes = hex::decode(sig_hex)
        .map_err(|e| PraetorError::MalformedEnvelope(format!("signature hex invalid: {e}")))?;
    let sig_arr: [u8; 64] = sig_bytes.try_into().map_err(|_| {
        PraetorError::MalformedEnvelope("Ed25519 signature must be 64 bytes".into())
    })?;
    let signature = Signature::from_bytes(&sig_arr);

    let mut msg = Vec::with_capacity(SIGNING_DOMAIN.len() + encoded_claims.len());
    msg.extend_from_slice(SIGNING_DOMAIN);
    msg.extend_from_slice(encoded_claims.as_bytes());

    let verifying_key = node.verifying_key()?;
    verifying_key
        .verify_strict(&msg, &signature)
        .map_err(|_| PraetorError::SignatureInvalid(node.node_id.clone()))?;

    // 3. Verify clock window & max TTL (checked arithmetic defeats integer-boundary wrap)
    let ttl = claims.expires_at_unix.saturating_sub(claims.issued_at_unix);
    let max_issue_time = now_unix.saturating_add(MAX_CLOCK_SKEW_SECS);
    let max_expiry_time = claims.expires_at_unix.saturating_add(MAX_CLOCK_SKEW_SECS);
    if ttl <= 0
        || ttl > MAX_ENVELOPE_TTL_SECS
        || claims.issued_at_unix > max_issue_time
        || now_unix > max_expiry_time
    {
        return Err(PraetorError::EnvelopeExpired {
            issued: claims.issued_at_unix,
            expires: claims.expires_at_unix,
            now: now_unix,
        });
    }

    // 4. Verify target node, HTTP method, and path (`target_node` must match `local_node_id` or explicit `"all"`)
    let target_ok =
        claims.target_node == "all" || claims.target_node.eq_ignore_ascii_case(local_node_id);
    if !target_ok || !claims.method.eq_ignore_ascii_case(method) || claims.path != path {
        return Err(PraetorError::EndpointMismatch);
    }

    // 5. Constant-time body BLAKE3 digest comparison
    let actual_digest = compute_body_digest_hex(body);
    if actual_digest
        .as_bytes()
        .ct_eq(claims.body_blake3_hex.as_bytes())
        .unwrap_u8()
        != 1
    {
        return Err(PraetorError::BodyDigestMismatch);
    }

    // 6. Consume nonce in fail-closed replay cache
    replay_window.check_and_record(&claims.nonce, claims.expires_at_unix, now_unix)?;

    Ok(claims)
}
