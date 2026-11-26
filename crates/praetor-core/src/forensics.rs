//! Cryptographic Forensic Eviction Capsules bridging `Praetor` -> `Sextant` (`v0.1.2`) + `SigNET`.
//!
//! Whenever `praetor-hook`, `praetor-gate`, or `praetor-reaper` intercepts or evicts an attacking
//! agent, it records a finalized, offline-verifiable `Sextant` binary ledger (`.sext`) signed by
//! an ephemeral `ZeroizeOnDrop` `SessionSigner`.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sextant_core::crypto::{AccumulatorState, RecordType, SessionSigner, verify_finalized_ledger};
use sextant_core::fleet::{SignetCapabilityReceipt, ingest_signet_receipt};
use sextant_core::wire::{read_ledger_from_path, write_ledger_to_path};

use crate::PraetorResult;

/// Structured incident evidence captured during agent interception or surgical eviction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentEvidence {
    pub incident_id: String,
    pub host_node: String,
    pub detector: String,
    pub vector_code: String,
    pub summary: String,
    pub offending_pid: Option<u32>,
    pub terminated_pids: Vec<u32>,
    pub restored_files: Vec<String>,
    pub revoked_signet_token_hash: Option<String>,
}

/// Summary receipt returned after sealing a finalized `Sextant` forensic capsule on disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedForensicReceipt {
    pub session_id: String,
    pub verifying_key_hex: String,
    pub final_accumulator_hex: String,
    pub total_nodes: usize,
    pub ledger_path: String,
}

/// Emit and immediately self-verify a finalized `Sextant` (`SEXT` v1) forensic capsule at `ledger_out`.
pub fn write_forensic_sextant_capsule(
    evidence: &IncidentEvidence,
    ledger_out: &Path,
) -> PraetorResult<SealedForensicReceipt> {
    let signer = SessionSigner::generate();
    let policy_bytes = serde_json::to_vec(&serde_json::json!({
        "engine": "praetor-counter-agent-fleet",
        "version": env!("CARGO_PKG_VERSION"),
        "host_node": evidence.host_node,
        "detector": evidence.detector,
    }))?;
    let policy_hash = *blake3::hash(&policy_bytes).as_bytes();

    let session_id = format!("praetor-incident-{}", evidence.incident_id);
    let mut ts_ns = current_timestamp_ns();
    let mut acc = AccumulatorState::with_signer(session_id.clone(), &policy_bytes, signer);

    // Step 1: SessionInit anchoring host & vector
    let init_args = serde_json::to_vec(&serde_json::json!({
        "host_node": evidence.host_node,
        "detector": evidence.detector,
        "vector_code": evidence.vector_code,
    }))?;
    acc.record_action(
        "praetor:session:init",
        &init_args,
        b"{\"status\":\"ARMED\"}",
        RecordType::SessionInit,
        ts_ns,
    )?;

    // Step 2: Optional SigNET token reference assertion (records audit reference; does not claim external revocation occurred)
    if let Some(ref tok_hash) = evidence.revoked_signet_token_hash {
        ts_ns += 1_000;
        let receipt = SignetCapabilityReceipt {
            tool_id: format!("evict:{}", evidence.vector_code),
            capability_token_digest: tok_hash.clone(),
            attenuation_depth: 0,
            merkle_receipt_root: hex::encode(policy_hash),
            decision: "REFERENCED_TOKEN".into(),
        };
        ingest_signet_receipt(&mut acc, &receipt, ts_ns)?;
    }

    // Step 3: Record observed outcome accurately without overstating unexecuted containment
    ts_ns += 1_000;
    let verdict_label = if !evidence.terminated_pids.is_empty() {
        "CONTAINED_AND_EVICTED"
    } else if !evidence.restored_files.is_empty() {
        "RESTORED_ONLY"
    } else {
        "OBSERVED_BLOCKED"
    };
    let evict_args = serde_json::to_vec(evidence)?;
    let evict_ret = serde_json::to_vec(&serde_json::json!({
        "evicted_count": evidence.terminated_pids.len(),
        "restored_count": evidence.restored_files.len(),
        "verdict": verdict_label,
    }))?;
    acc.record_action(
        "praetor:reaper:evict",
        &evict_args,
        &evict_ret,
        RecordType::ToolInvocation,
        ts_ns,
    )?;

    // Step 4: Terminal SessionFinalize (satisfies SEC-02 RequireFinalized)
    ts_ns += 1_000;
    let fin_node = acc.record_action(
        "praetor:session:finalize",
        b"{}",
        b"{\"sealed\":true}",
        RecordType::SessionFinalize,
        ts_ns,
    )?;

    let metadata = acc.metadata.clone();
    write_ledger_to_path(ledger_out, &metadata, acc.entries())?;
    sextant_core::canonical::enforce_owner_only_acl(ledger_out, false)?;

    // Round-trip verify with strict finalized ledger check (`SEC-02`)
    let (loaded_meta, loaded_entries) = read_ledger_from_path(ledger_out)?;
    let report = verify_finalized_ledger(&loaded_meta, &loaded_entries, true)?;

    Ok(SealedForensicReceipt {
        session_id,
        verifying_key_hex: hex::encode(metadata.verifying_key),
        final_accumulator_hex: hex::encode(fin_node.accumulated_hash),
        total_nodes: report.total_nodes,
        ledger_path: ledger_out.to_string_lossy().into_owned(),
    })
}

fn current_timestamp_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(1)
}
