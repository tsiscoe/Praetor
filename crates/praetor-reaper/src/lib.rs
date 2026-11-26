#![forbid(unsafe_code)]
//! **Praetor Reaper** — Autonomous Counter-Agent Hunter, Canary Trap, Surgical Process-Tree
//! Evictor, Persistence Rollback Engine, and 3-Pane `Ratatui` v0.30 Defense Cockpit (`VEC-05`).
//!
//! Hardened under Wave-1 Security Audit (`[SEC-05-01]`, `[SEC-05-02]`):
//! 1. **Bounded Canary Timeouts & Capsule Ceiling (`[SEC-05-01]`):** 2-second read/write timeouts
//!    defeat slowloris canary hangs; `spawn_blocking` isolates `icacls` subprocess calls off Tokio
//!    workers; `MAX_FORENSIC_CAPSULES` (`512`) prevents disk/inode exhaustion.
//! 2. **Hit-and-Run PID & Partial-Rollback Resilience (`[SEC-05-02]`):** `ProcessNotFound` on an
//!    already-exited rogue PID no longer aborts Step 2 rollback or Step 3 `.sext` forensic sealing,
//!    and per-file restore errors are accumulated so every healable surface is restored first.

pub mod tui;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use praetor_core::PraetorResult;
use praetor_core::baseline::{BaselineAuditItem, BaselineVault, DriftStatus, SnapshotSealKey};
use praetor_core::forensics::{
    IncidentEvidence, SealedForensicReceipt, write_forensic_sextant_capsule,
};
use praetor_win32_cage::{CageError, EvictionReport, freeze_and_evict_tree};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use uuid::Uuid;

/// Hard cap on `.sext` forensic capsules per directory to prevent flood disk exhaustion (`[SEC-05-01]`).
pub const MAX_FORENSIC_CAPSULES: usize = 512;

/// Outcome of an autonomous `praetor-reaper` sweep across protected persistence & suspect PIDs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReaperSweepOutcome {
    pub audited_files: usize,
    pub tampered_files: Vec<String>,
    pub restored_files: Vec<String>,
    pub restore_errors: Vec<String>,
    #[serde(default)]
    pub eviction_error: Option<String>,
    pub eviction: Option<EvictionReport>,
    pub forensic_receipt: Option<SealedForensicReceipt>,
}

/// Seal a set of critical persistence paths into `vault` using `seal_key`.
pub fn arm_baselines(
    vault: &mut BaselineVault,
    seal_key: &SnapshotSealKey,
    paths: &[PathBuf],
) -> PraetorResult<usize> {
    for path in paths {
        vault.seal_path(path, seal_key)?;
    }
    Ok(paths.len())
}

/// Count existing `.sext` files in `forensic_dir` to enforce `MAX_FORENSIC_CAPSULES`.
pub fn forensic_dir_has_capacity(forensic_dir: &Path) -> bool {
    let Ok(rd) = std::fs::read_dir(forensic_dir) else {
        return true;
    };
    let count = rd
        .filter_map(Result::ok)
        .filter(|e| e.path().extension().and_then(|x| x.to_str()) == Some("sext"))
        .take(MAX_FORENSIC_CAPSULES + 1)
        .count();
    count < MAX_FORENSIC_CAPSULES
}

/// Execute a single deterministic counter-intrusion sweep (`[SEC-05-02]`):
/// - Tolerates `CageError::ProcessNotFound` when a hit-and-run process already exited.
/// - Restores every healable file even if one path encounters an OS lock/error.
/// - Always seals a `Sextant` forensic capsule before surfacing any residual restore errors.
pub fn execute_reaper_sweep(
    host_node: &str,
    vault: &BaselineVault,
    seal_key: &SnapshotSealKey,
    suspect_pid: Option<u32>,
    revoked_signet_token_hash: Option<String>,
    forensic_dir: &Path,
) -> PraetorResult<ReaperSweepOutcome> {
    let items: Vec<BaselineAuditItem> = vault.audit_all(seal_key)?;
    let mut tampered_paths: Vec<PathBuf> = Vec::new();

    for item in &items {
        if item.status != DriftStatus::Intact {
            tampered_paths.push(item.path.clone());
        }
    }

    if tampered_paths.is_empty() && suspect_pid.is_none() {
        return Ok(ReaperSweepOutcome {
            audited_files: items.len(),
            tampered_files: Vec::new(),
            restored_files: Vec::new(),
            restore_errors: Vec::new(),
            eviction_error: None,
            eviction: None,
            forensic_receipt: None,
        });
    }

    // Step 1: Attempt freeze & evict on suspect PID tree, continuing to file recovery even if eviction errors (`[R1]`)
    let mut eviction_error: Option<String> = None;
    let eviction = match suspect_pid {
        Some(pid) => match freeze_and_evict_tree(pid) {
            Ok(rep) => Some(rep),
            Err(CageError::ProcessNotFound(_)) => None,
            Err(other) => {
                eviction_error = Some(format!("process eviction error: {other}"));
                None
            }
        },
        None => None,
    };

    // Step 2: Best-effort atomic restoration across ALL tampered files (`[SEC-05-02]`, `[R1]`)
    let mut restored_files = Vec::with_capacity(tampered_paths.len());
    let mut restore_errors = Vec::new();
    for path in &tampered_paths {
        match vault.restore_path(path, seal_key) {
            Ok(()) => restored_files.push(path.to_string_lossy().into_owned()),
            Err(e) => restore_errors.push(format!("{}: {e}", path.display())),
        }
    }

    // Step 3: Seal finalized Sextant forensic ledger (bounded by MAX_FORENSIC_CAPSULES)
    std::fs::create_dir_all(forensic_dir)?;
    let terminated_pids = eviction
        .as_ref()
        .map(|ev| ev.terminated_pids.clone())
        .unwrap_or_default();
    let tampered_strings: Vec<String> = tampered_paths
        .iter()
        .map(|p| p.to_string_lossy().into_owned())
        .collect();

    let mut receipt_error: Option<String> = None;
    let receipt = if forensic_dir_has_capacity(forensic_dir) {
        let inc_id = Uuid::new_v4().simple().to_string();
        let ledger_path = forensic_dir.join(format!("reaper-evict-{}.sext", &inc_id[..12]));
        let evidence = IncidentEvidence {
            incident_id: inc_id,
            host_node: host_node.to_ascii_lowercase(),
            detector: "praetor-reaper".into(),
            vector_code: "VEC-05-ACTIVE-EVICTION".into(),
            summary: format!(
                "Evicted {} PID(s), restored {} surface(s), restore_errors={}, eviction_err={}",
                terminated_pids.len(),
                restored_files.len(),
                restore_errors.len(),
                eviction_error.as_deref().unwrap_or("none")
            ),
            offending_pid: suspect_pid,
            terminated_pids,
            restored_files: restored_files.clone(),
            revoked_signet_token_hash,
        };
        match write_forensic_sextant_capsule(&evidence, &ledger_path) {
            Ok(r) => Some(r),
            Err(e) => {
                receipt_error = Some(format!("forensic receipt sealing error: {e}"));
                None
            }
        }
    } else {
        None
    };

    if !restore_errors.is_empty() || eviction_error.is_some() || receipt_error.is_some() {
        let mut msgs = Vec::new();
        if let Some(ev_e) = eviction_error {
            msgs.push(ev_e);
        }
        if !restore_errors.is_empty() {
            msgs.push(format!("restore_errors=[{}]", restore_errors.join("; ")));
        }
        if let Some(rec_e) = receipt_error {
            msgs.push(rec_e);
        }
        return Err(praetor_core::PraetorError::BaselineTamper(format!(
            "reaper sweep completed with partial errors: {}",
            msgs.join("; ")
        )));
    }

    Ok(ReaperSweepOutcome {
        audited_files: items.len(),
        tampered_files: tampered_strings,
        restored_files,
        restore_errors,
        eviction_error: None,
        eviction,
        forensic_receipt: receipt,
    })
}

/// Listen for one probe on a borrowed loopback `&TcpListener` (`127.0.0.1:<port>` / `[::1]:<port>`),
/// enforcing strict loopback binding (`[R3]`), 2-second read/write timeouts (`[SEC-05-01]`), and `spawn_blocking` `.sext` sealing.
pub async fn capture_canary_probe_on_listener(
    listener: &TcpListener,
    host_node: &str,
    suspect_pid: Option<u32>,
    forensic_dir: &Path,
) -> PraetorResult<(SocketAddr, String, Option<SealedForensicReceipt>)> {
    let local_ip = listener.local_addr()?.ip();
    if !local_ip.is_loopback() {
        return Err(praetor_core::PraetorError::UnauthorizedNodeIp {
            node: host_node.to_string(),
            actual: format!("non-loopback canary listener bind refused: {local_ip}"),
        });
    }
    let (mut stream, peer_addr) = listener.accept().await?;
    let mut buf = [0u8; 2048];
    let n = match tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf)).await {
        Ok(Ok(bytes_read)) => bytes_read,
        Ok(Err(_)) | Err(_) => 0,
    };

    let sanitized_line = if n == 0 {
        "<tcp-connect-or-slowloris-timeout>".to_string()
    } else {
        let raw_req = String::from_utf8_lossy(&buf[..n]);
        let first_line = raw_req.lines().next().unwrap_or("");
        sextant_core::canonical::sanitize_terminal_text(first_line)
    };

    let decoy_resp = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 15\r\nConnection: close\r\n\r\n{\"status\":\"ok\"}";
    let _ = tokio::time::timeout(Duration::from_secs(2), async {
        let _ = stream.write_all(decoy_resp).await;
        let _ = stream.flush().await;
    })
    .await;

    let host_owned = host_node.to_ascii_lowercase();
    let dir_owned = forensic_dir.to_path_buf();
    let line_clone = sanitized_line.clone();

    let receipt_opt =
        tokio::task::spawn_blocking(move || -> PraetorResult<Option<SealedForensicReceipt>> {
            let terminated_pids = if let Some(pid) = suspect_pid {
                freeze_and_evict_tree(pid)
                    .map(|r| r.terminated_pids)
                    .unwrap_or_default()
            } else {
                Vec::new()
            };

            std::fs::create_dir_all(&dir_owned)?;
            if !forensic_dir_has_capacity(&dir_owned) {
                return Ok(None);
            }
            let inc_id = Uuid::new_v4().simple().to_string();
            let ledger_path = dir_owned.join(format!("canary-trip-{}.sext", &inc_id[..12]));
            let evidence = IncidentEvidence {
                incident_id: inc_id,
                host_node: host_owned,
                detector: "praetor-reaper-canary".into(),
                vector_code: "TAGGANT-LOOPBACK-TRIPWIRE".into(),
                summary: format!("Loopback canary hit from {peer_addr}: {line_clone}"),
                offending_pid: suspect_pid,
                terminated_pids,
                restored_files: Vec::new(),
                revoked_signet_token_hash: None,
            };
            Ok(Some(write_forensic_sextant_capsule(
                &evidence,
                &ledger_path,
            )?))
        })
        .await
        .map_err(|e| praetor_core::PraetorError::BaselineTamper(format!("join error: {e}")))??;

    Ok((peer_addr, sanitized_line, receipt_opt))
}

/// Owned-listener convenience wrapper around [`capture_canary_probe_on_listener`].
pub async fn capture_canary_probe_once(
    listener: TcpListener,
    host_node: &str,
    suspect_pid: Option<u32>,
    forensic_dir: &Path,
) -> PraetorResult<(SocketAddr, String, Option<SealedForensicReceipt>)> {
    capture_canary_probe_on_listener(&listener, host_node, suspect_pid, forensic_dir).await
}
