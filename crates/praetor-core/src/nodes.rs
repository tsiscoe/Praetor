//! Canonical cluster node registry for **NodeAlpha**, **NodeBeta**, **NodeDelta**, and **NodeGamma**.

use std::collections::BTreeMap;
use std::net::IpAddr;

use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{PraetorError, PraetorResult};

/// Known AgentMesh / MeshBus physical cluster host profile.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClusterNode {
    /// Canonical lowercase node ID (`node-alpha`, `node-beta`, `node-delta`, `node-gamma`).
    pub node_id: String,
    /// Human-readable hostname.
    pub hostname: String,
    /// Authorized LAN / loopback IPv4 and IPv6 addresses permitted to present this node's key.
    pub allowed_ips: Vec<IpAddr>,
    /// 32-byte Ed25519 verifying key (hex-encoded in config).
    pub verifying_key_hex: String,
    /// Permitted operational roles (e.g., `coordinator`, `worker`, `auditor`).
    pub roles: Vec<String>,
}

impl ClusterNode {
    /// Decode the 32-byte RFC 8032 `VerifyingKey`, rejecting weak small-order torsion points (`[SEC-01a-2]`).
    pub fn verifying_key(&self) -> PraetorResult<VerifyingKey> {
        let bytes = hex::decode(self.verifying_key_hex.trim()).map_err(|e| {
            PraetorError::KeyError(format!("invalid hex pubkey for {}: {e}", self.node_id))
        })?;
        let arr: [u8; 32] = bytes.try_into().map_err(|_| {
            PraetorError::KeyError(format!("pubkey for {} must be 32 bytes", self.node_id))
        })?;
        let vk = VerifyingKey::from_bytes(&arr).map_err(|e| {
            PraetorError::KeyError(format!("invalid Ed25519 pubkey for {}: {e}", self.node_id))
        })?;
        if vk.is_weak() {
            return Err(PraetorError::KeyError(format!(
                "weak small-order Ed25519 torsion pubkey rejected for {}",
                self.node_id
            )));
        }
        Ok(vk)
    }

    /// Check whether `peer_ip` matches this node's pinned LAN address, permitting loopback (`127.0.0.1` / `::1`)
    /// **strictly when `self.node_id == local_node_id`** (`[SEC-01a-3]`).
    pub fn allows_ip_on_host(&self, peer_ip: IpAddr, local_node_id: &str) -> bool {
        let normalized = match peer_ip {
            IpAddr::V6(v6) => v6
                .to_ipv4_mapped()
                .map(IpAddr::V4)
                .unwrap_or(IpAddr::V6(v6)),
            other => other,
        };
        if normalized.is_loopback() {
            return self.node_id.eq_ignore_ascii_case(local_node_id)
                && self.allowed_ips.iter().any(IpAddr::is_loopback);
        }
        self.allowed_ips.contains(&normalized)
    }

    /// Check whether this node holds a given RBAC role (e.g., `"coordinator"`).
    pub fn has_role(&self, role: &str) -> bool {
        self.roles.iter().any(|r| r.eq_ignore_ascii_case(role))
    }
}

/// Zeroizing 32-byte `Ed25519` node signing key held strictly in RAM.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct NodeSecretKey {
    seed: [u8; 32],
}

impl NodeSecretKey {
    /// Mint a fresh node signing key from OS CSPRNG entropy.
    pub fn generate() -> Self {
        let sk = SigningKey::generate(&mut OsRng);
        Self {
            seed: sk.to_bytes(),
        }
    }

    /// Construct from raw 32-byte seed.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self { seed }
    }

    /// Parse from a 64-character hex seed string (zeroizing intermediate buffers).
    pub fn from_hex(hex_str: &str) -> PraetorResult<Self> {
        let mut raw = hex::decode(hex_str.trim())
            .map_err(|e| PraetorError::KeyError(format!("invalid node secret hex: {e}")))?;
        if raw.len() != 32 {
            raw.zeroize();
            return Err(PraetorError::KeyError(format!(
                "expected 32-byte Ed25519 seed, got {}",
                raw.len()
            )));
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&raw);
        raw.zeroize();
        Ok(Self { seed })
    }

    /// Export hex seed for initial provisioning into restricted node key files.
    pub fn to_hex_zeroizing(&self) -> zeroize::Zeroizing<String> {
        zeroize::Zeroizing::new(hex::encode(self.seed))
    }

    /// Derive the `ed25519_dalek::SigningKey`.
    pub fn signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.seed)
    }

    /// Return hex-encoded 32-byte verifying key.
    pub fn verifying_key_hex(&self) -> String {
        hex::encode(self.signing_key().verifying_key().to_bytes())
    }
}

/// Pinned cluster trust roster for **NodeAlpha**, **NodeBeta**, **NodeDelta**, and **NodeGamma**.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClusterRoster {
    pub nodes: BTreeMap<String, ClusterNode>,
    /// Strictly allowed HTTP `Origin` headers for browser cockpit requests (blocks `*` CSRF).
    pub allowed_origins: Vec<String>,
}

impl ClusterRoster {
    /// Construct the default AgentMesh / MeshBus dual-subnet topology (`10.244.76.172/24` + `10.244.97.181/24`)
    /// populated with supplied verifying keys per node.
    pub fn default_cluster(node_pubkeys: &BTreeMap<String, String>) -> PraetorResult<Self> {
        let parse_ips = |ips: &[&str]| -> PraetorResult<Vec<IpAddr>> {
            ips.iter()
                .map(|s| {
                    s.parse::<IpAddr>()
                        .map_err(|e| PraetorError::KeyError(format!("invalid IP '{s}': {e}")))
                })
                .collect()
        };

        let specs = [
            (
                "node-alpha",
                "NodeAlpha",
                &["127.0.0.1", "::1", "10.244.81.12", "10.244.250.181"][..],
                &["coordinator", "worker", "auditor"][..],
            ),
            (
                "node-beta",
                "NodeBeta",
                &["127.0.0.1", "::1", "10.244.229.100", "10.244.17.103"][..],
                &["coordinator", "worker", "auditor"][..],
            ),
            (
                "node-delta",
                "NodeDelta",
                &["127.0.0.1", "::1", "10.244.196.142"][..],
                &["coordinator", "worker"][..],
            ),
            (
                "node-gamma",
                "NodeGamma",
                &["127.0.0.1", "::1", "10.244.125.117", "10.244.202.213"][..],
                &["worker", "auditor"][..],
            ),
        ];

        let mut nodes = BTreeMap::new();
        for (id, host, ips, roles) in specs {
            if let Some(vk) = node_pubkeys.get(id) {
                let node = ClusterNode {
                    node_id: id.to_string(),
                    hostname: host.to_string(),
                    allowed_ips: parse_ips(ips)?,
                    verifying_key_hex: vk.clone(),
                    roles: roles.iter().map(|r| (*r).to_string()).collect(),
                };
                let _ = node.verifying_key()?;
                nodes.insert(id.to_string(), node);
            }
        }

        let allowed_origins = vec![
            "http://127.0.0.1:8088".into(),
            "http://localhost:8088".into(),
            "http://node-alpha:8088".into(),
            "http://node-alpha.internal:8088".into(),
            "http://node-beta:8088".into(),
            "http://node-delta:8088".into(),
            "http://node-gamma:8088".into(),
        ];

        Ok(Self {
            nodes,
            allowed_origins,
        })
    }

    /// Look up a registered node by ID (case-insensitive).
    pub fn get_node(&self, node_id: &str) -> PraetorResult<&ClusterNode> {
        let key = node_id.trim().to_ascii_lowercase();
        self.nodes.get(&key).ok_or(PraetorError::UnknownNode(key))
    }

    /// Verify whether an HTTP `Origin` header is permitted (`None` is allowed for CLI/daemon callers;
    /// any browser `Origin` must strictly match `allowed_origins`, closing `VEC-01` drive-by CSRF).
    pub fn verify_origin(&self, origin: Option<&str>) -> PraetorResult<()> {
        let Some(raw) = origin else {
            return Ok(());
        };
        let trimmed = raw.trim().to_ascii_lowercase();
        if trimmed.is_empty() {
            return Ok(());
        }
        if self
            .allowed_origins
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(&trimmed))
        {
            Ok(())
        } else {
            Err(PraetorError::CrossOriginBlocked(raw.to_string()))
        }
    }
}
