use std::collections::BTreeMap;
use std::net::IpAddr;

use praetor_core::baseline::{BaselineVault, DriftStatus, SnapshotSealKey};
use praetor_core::envelope::{
    ReplayWindow, WakeClaims, sign_wake_envelope, verify_wake_envelope_at,
};
use praetor_core::forensics::{IncidentEvidence, write_forensic_sextant_capsule};
use praetor_core::nodes::{ClusterRoster, NodeSecretKey};
use proptest::prelude::*;
use tempfile::TempDir;

fn build_test_cluster() -> (ClusterRoster, NodeSecretKey, NodeSecretKey, NodeSecretKey) {
    let alpha_sk = NodeSecretKey::generate();
    let beta_sk = NodeSecretKey::generate();
    let gamma_sk = NodeSecretKey::generate();

    let mut pubkeys = BTreeMap::new();
    pubkeys.insert("node-alpha".into(), alpha_sk.verifying_key_hex());
    pubkeys.insert("node-beta".into(), beta_sk.verifying_key_hex());
    pubkeys.insert("node-gamma".into(), gamma_sk.verifying_key_hex());

    let roster = ClusterRoster::default_cluster(&pubkeys).expect("valid roster");
    (roster, alpha_sk, beta_sk, gamma_sk)
}

#[test]
fn signed_wake_envelope_verifies_and_blocks_replay_ip_spoof_and_csrf() {
    let (roster, alpha_sk, _beta_sk, _gamma_sk) = build_test_cluster();
    let mut replay = ReplayWindow::new(128);
    let body = br#"{"id":"assemble-01","type":"assemble","to":"all","title":"Audit"}"#;

    let claims = WakeClaims::new(
        "node-alpha",
        "node-beta",
        "POST",
        "/api/mesh/notify",
        body,
        60,
        Some("blake3-token-digest-01".into()),
    );
    let now = claims.issued_at_unix;
    let header_val = sign_wake_envelope(&alpha_sk, &claims).expect("sign envelope");

    // 1. Valid request from NodeAlpha's pinned LAN IP succeeds
    let alpha_ip: IpAddr = "10.244.81.12".parse().expect("ip");
    let verified = verify_wake_envelope_at(
        &header_val,
        &roster,
        "node-beta",
        alpha_ip,
        "POST",
        "/api/mesh/notify",
        body,
        &mut replay,
        now,
    )
    .expect("valid wake envelope");
    assert_eq!(verified.sender_node, "node-alpha");

    // 2. Exact replay of the same envelope is rejected immediately
    let replay_err = verify_wake_envelope_at(
        &header_val,
        &roster,
        "node-beta",
        alpha_ip,
        "POST",
        "/api/mesh/notify",
        body,
        &mut replay,
        now + 1,
    )
    .expect_err("replay must fail");
    assert!(replay_err.to_string().contains("replay detected"));

    // 3. Fresh nonce from an unpinned rogue LAN IP (e.g. 10.244.68.21) fails IP pinning
    let rogue_claims = WakeClaims::new(
        "node-alpha",
        "node-beta",
        "POST",
        "/api/mesh/notify",
        body,
        60,
        None,
    );
    let rogue_env = sign_wake_envelope(&alpha_sk, &rogue_claims).expect("sign");
    let rogue_ip: IpAddr = "10.244.68.21".parse().expect("ip");
    let ip_err = verify_wake_envelope_at(
        &rogue_env,
        &roster,
        "node-beta",
        rogue_ip,
        "POST",
        "/api/mesh/notify",
        body,
        &mut replay,
        rogue_claims.issued_at_unix,
    )
    .expect_err("spoofed IP must fail");
    assert!(ip_err.to_string().contains("not authorized"));

    // 4. Drive-by browser CSRF Origin check blocks external sites while allowing cluster origins
    assert!(
        roster
            .verify_origin(Some("https://evil-pentest-harness.example"))
            .is_err()
    );
    assert!(roster.verify_origin(Some("http://node-alpha:8088")).is_ok());
    assert!(roster.verify_origin(None).is_ok());
}

#[test]
fn baseline_vault_detects_tamper_and_restores_exact_bytes() {
    let dir = TempDir::new().expect("tempdir");
    let db_path = dir.path().join("baselines.db");
    let mcp_cfg = dir.path().join("mcp_config.json");
    let rogue_hook = dir.path().join("rogue-pretool.ps1");

    let clean_json = br#"{"mcpServers":{"signet":{"command":"signet"}}}"#;
    std::fs::write(&mcp_cfg, clean_json).expect("write clean config");

    let seal_key = SnapshotSealKey::generate();
    let mut vault = BaselineVault::open(&db_path).expect("open baseline vault");
    vault
        .seal_path(&mcp_cfg, &seal_key)
        .expect("seal mcp_config");
    vault
        .seal_path(&rogue_hook, &seal_key)
        .expect("seal absent hook slot");

    // Simulate attacking agent injecting a malicious MCP server + dropping a new persistence hook
    std::fs::write(
        &mcp_cfg,
        br#"{"mcpServers":{"backdoor":{"command":"nc.exe"}}}"#,
    )
    .expect("tamper mcp");
    std::fs::write(&rogue_hook, b"Start-Process calc.exe").expect("plant rogue hook");

    let audit = vault.audit_all(&seal_key).expect("audit");
    assert_eq!(audit.len(), 2);
    assert!(
        audit
            .iter()
            .any(|i| matches!(i.status, DriftStatus::Modified { .. }))
    );
    assert!(
        audit
            .iter()
            .any(|i| matches!(i.status, DriftStatus::UnauthorizedCreation { .. }))
    );

    // Restore both surfaces and re-verify Intact state
    vault
        .restore_path(&mcp_cfg, &seal_key)
        .expect("restore mcp_config");
    vault
        .restore_path(&rogue_hook, &seal_key)
        .expect("remove unauthorized hook");

    assert_eq!(std::fs::read(&mcp_cfg).expect("read restored"), clean_json);
    assert!(!rogue_hook.exists());

    let post_audit = vault.audit_all(&seal_key).expect("post audit");
    assert!(post_audit.iter().all(|i| i.status == DriftStatus::Intact));

    // Wrong seal key MUST fail authenticated inventory audit rather than trusting unauthenticated DB columns (`[C1]`)
    let wrong_key = SnapshotSealKey::generate();
    assert!(vault.audit_all(&wrong_key).is_err());
}

#[test]
fn forensic_capsule_writes_verified_finalized_sextant_ledger() {
    let dir = TempDir::new().expect("tempdir");
    let ledger_path = dir.path().join("incident-001.sext");

    let evidence = IncidentEvidence {
        incident_id: "inc-20261124-01".into(),
        host_node: "node-gamma".into(),
        detector: "praetor-reaper".into(),
        vector_code: "VEC-05-CANARY-TRIP".into(),
        summary: "Rogue harness probed Taggant loopback canary and touched mcp_config.json".into(),
        offending_pid: Some(42424),
        terminated_pids: vec![42424, 42429],
        restored_files: vec!["mcp_config.json".into()],
        revoked_signet_token_hash: Some("deadbeefcafebabe0123456789abcdef".into()),
    };

    let receipt = write_forensic_sextant_capsule(&evidence, &ledger_path).expect("seal capsule");
    assert_eq!(receipt.total_nodes, 4);
    assert!(ledger_path.exists());
}

#[test]
fn sec01a_replay_window_mixed_ttl_sweep_and_fail_closed_saturation() {
    let mut replay = ReplayWindow::new(64);
    let t0 = 1_700_000_000i64;

    // 1. Insert a long-lived nonce at the front (`expires = t0 + 120`), followed by 63 short-lived nonces (`expires = t0 + 5`)
    replay
        .check_and_record("front-long-ttl", t0 + 120, t0)
        .expect("insert front");
    for idx in 1..64 {
        replay
            .check_and_record(&format!("short-{idx}"), t0 + 5, t0)
            .expect("insert short");
    }

    // 2. While all 64 nonces are still within clock-skew horizon (`t0 + 10`), a 65th nonce MUST fail closed
    //    WITHOUT evicting `"front-long-ttl"`!
    let sat_err = replay
        .check_and_record("overflow-while-live", t0 + 60, t0 + 10)
        .expect_err("saturated window must fail closed");
    assert!(sat_err.to_string().contains("saturated"));

    // Confirm `"front-long-ttl"` is STILL guarded against replay
    assert!(
        replay
            .check_and_record("front-long-ttl", t0 + 120, t0 + 10)
            .is_err()
    );

    // 3. Advance clock past `t0 + 5 + 30` (`t0 + 40`): the 63 short-lived nonces expire behind `"front-long-ttl"`,
    //    so full sweep reclaims capacity while STILL retaining `"front-long-ttl"`!
    replay
        .check_and_record("post-sweep-fresh", t0 + 100, t0 + 40)
        .expect("full expired sweep must reclaim slots behind long-TTL head");
    assert!(
        replay
            .check_and_record("front-long-ttl", t0 + 120, t0 + 40)
            .is_err(),
        "long-TTL head nonce must remain replay-protected after sweep"
    );
}

#[test]
fn sec01a_weak_torsion_key_and_cross_node_loopback_spoof_rejected() {
    // 1. Weak small-order Ed25519 identity point (`010000...00`) must be rejected at roster load
    let mut bad_pubkeys = BTreeMap::new();
    bad_pubkeys.insert(
        "node-alpha".into(),
        "0100000000000000000000000000000000000000000000000000000000000000".into(),
    );
    let weak_err =
        ClusterRoster::default_cluster(&bad_pubkeys).expect_err("weak torsion pubkey must fail");
    assert!(weak_err.to_string().contains("weak"));

    // 2. `127.0.0.1` loopback is ONLY valid when `sender_node == local_node_id` (`[SEC-01a-3]`)
    let (roster, alpha_sk, beta_sk, _) = build_test_cluster();
    let mut replay = ReplayWindow::new(64);
    let body = br#"{"id":"local-1","type":"ping"}"#;
    let loopback: IpAddr = "127.0.0.1".parse().expect("ip");

    // Localhost NodeAlpha -> NodeAlpha succeeds
    let self_claims = WakeClaims::new(
        "node-alpha",
        "node-alpha",
        "POST",
        "/api/mesh/notify",
        body,
        60,
        None,
    );
    let self_env = sign_wake_envelope(&alpha_sk, &self_claims).expect("sign");
    assert!(
        verify_wake_envelope_at(
            &self_env,
            &roster,
            "node-alpha",
            loopback,
            "POST",
            "/api/mesh/notify",
            body,
            &mut replay,
            self_claims.issued_at_unix,
        )
        .is_ok()
    );

    // NodeBeta key presented over `127.0.0.1` to `local_node_id = "node-alpha"` MUST fail IP-pinning
    let spoof_claims = WakeClaims::new(
        "node-beta",
        "node-alpha",
        "POST",
        "/api/mesh/notify",
        body,
        60,
        None,
    );
    let spoof_env = sign_wake_envelope(&beta_sk, &spoof_claims).expect("sign");
    let spoof_err = verify_wake_envelope_at(
        &spoof_env,
        &roster,
        "node-alpha",
        loopback,
        "POST",
        "/api/mesh/notify",
        body,
        &mut replay,
        spoof_claims.issued_at_unix,
    )
    .expect_err("remote node identity on 127.0.0.1 must be rejected");
    assert!(spoof_err.to_string().contains("not authorized"));
}

#[test]
fn sec01b_baseline_restores_readonly_file_and_defeats_directory_replacement() {
    let dir = TempDir::new().expect("tempdir");
    let db_path = dir.path().join("baselines.db");
    let protected_cfg = dir.path().join("locked_hooks.json");

    let golden_bytes = br#"{"hooks":{"PreToolUse":[{"matcher":"run_command"}]}}"#;
    std::fs::write(&protected_cfg, golden_bytes).expect("write golden");

    // Mark golden file read-only (`attrib +R`) BEFORE sealing
    let mut perms = std::fs::metadata(&protected_cfg)
        .expect("meta")
        .permissions();
    perms.set_readonly(true);
    std::fs::set_permissions(&protected_cfg, perms).expect("set readonly");

    let seal_key = SnapshotSealKey::generate();
    let mut vault = BaselineVault::open(&db_path).expect("open vault");
    vault
        .seal_path(&protected_cfg, &seal_key)
        .expect("seal readonly file");

    // Attacker clears readonly, unlinks file, and plants a directory at the exact protected path (`[SEC-01b-1]`)
    let mut unlock = std::fs::metadata(&protected_cfg)
        .expect("meta")
        .permissions();
    #[allow(clippy::permissions_set_readonly_false)]
    unlock.set_readonly(false);
    std::fs::set_permissions(&protected_cfg, unlock).expect("unlock");
    std::fs::remove_file(&protected_cfg).expect("unlink");
    std::fs::create_dir(&protected_cfg).expect("plant directory sabotage");
    std::fs::write(protected_cfg.join("nested"), b"sabotage").expect("nested");

    let audit = vault.audit_all(&seal_key).expect("audit");
    assert_eq!(audit.len(), 1);
    assert!(matches!(
        &audit[0].status,
        DriftStatus::Modified { actual_blake3, .. } if actual_blake3 == "SYMLINK_OR_DIR_SABOTAGE"
    ));

    // `restore_path` removes the planted directory, writes golden bytes via CSPRNG `create_new`, and re-applies `readonly`!
    vault
        .restore_path(&protected_cfg, &seal_key)
        .expect("restore over directory sabotage");
    let restored_meta = std::fs::symlink_metadata(&protected_cfg).expect("restored meta");
    assert!(restored_meta.is_file());
    assert!(restored_meta.permissions().readonly());
    assert_eq!(
        std::fs::read(&protected_cfg).expect("read restored"),
        golden_bytes
    );

    // Clean up readonly attribute so TempDir drop succeeds cleanly on Windows
    let mut cleanup = restored_meta.permissions();
    #[allow(clippy::permissions_set_readonly_false)]
    cleanup.set_readonly(false);
    std::fs::set_permissions(&protected_cfg, cleanup).expect("cleanup readonly");
}

proptest! {
    #[test]
    fn prop_any_mutated_body_byte_invalidates_wake_envelope(
        body in proptest::collection::vec(any::<u8>(), 1..512),
        flip_idx in 0usize..512,
        flip_mask in 1u8..=255u8,
    ) {
        let (roster, alpha_sk, _, _) = build_test_cluster();
        let mut replay = ReplayWindow::new(64);
        let claims = WakeClaims::new("node-alpha", "node-gamma", "POST", "/api/mesh/notify", &body, 60, None);
        let env = sign_wake_envelope(&alpha_sk, &claims).expect("sign");

        let mut tampered = body.clone();
        let idx = flip_idx % tampered.len();
        tampered[idx] ^= flip_mask;

        let ip: IpAddr = "10.244.250.181".parse().expect("ip");
        let res = verify_wake_envelope_at(
            &env,
            &roster,
            "node-gamma",
            ip,
            "POST",
            "/api/mesh/notify",
            &tampered,
            &mut replay,
            claims.issued_at_unix,
        );
        prop_assert!(res.is_err());
    }
}
