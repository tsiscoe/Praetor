use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use praetor_core::baseline::{BaselineVault, DriftStatus, SnapshotSealKey};
use praetor_reaper::tui::{CockpitModel, render_cockpit};
use praetor_reaper::{arm_baselines, capture_canary_probe_once, execute_reaper_sweep};
use ratatui::{Terminal, backend::TestBackend};
use sextant_core::crypto::verify_finalized_ledger;
use sextant_core::wire::read_ledger_from_path;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[test]
fn vec05_reaper_evicts_rogue_process_restores_tampered_mcp_and_seals_sextant_proof() {
    let dir = TempDir::new().expect("tempdir");
    let db_path = dir.path().join("reaper.db");
    let forensic_dir = dir.path().join("forensics");
    let mcp_cfg = dir.path().join("mcp_config.json");
    let hook_file = dir.path().join("validate-tool-call.mjs");

    let golden_mcp = br#"{"mcpServers":{"mesh-bus":{"command":"python"}}}"#;
    let golden_hook = b"// verified golden hook\n";
    std::fs::write(&mcp_cfg, golden_mcp).expect("write mcp");
    std::fs::write(&hook_file, golden_hook).expect("write hook");

    let seal_key = SnapshotSealKey::generate();
    let mut vault = BaselineVault::open(&db_path).expect("open vault");
    arm_baselines(&mut vault, &seal_key, &[mcp_cfg.clone(), hook_file.clone()])
        .expect("arm baselines");

    let mut rogue_child = if cfg!(windows) {
        Command::new("ping")
            .args(["-n", "30", "127.0.0.1"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn rogue")
    } else {
        Command::new("sleep")
            .arg("30")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn rogue")
    };
    let rogue_pid = rogue_child.id();
    thread::sleep(Duration::from_millis(60));

    std::fs::write(
        &mcp_cfg,
        br#"{"mcpServers":{"evil":{"command":"powershell"}}}"#,
    )
    .expect("tamper mcp");
    std::fs::remove_file(&hook_file).expect("delete hook");

    let outcome = execute_reaper_sweep(
        "node-beta",
        &vault,
        &seal_key,
        Some(rogue_pid),
        Some("revoked-signet-hash-99".into()),
        &forensic_dir,
    )
    .expect("reaper sweep");

    let exit_status = rogue_child.wait().expect("wait rogue");
    assert!(!exit_status.success());
    assert!(
        outcome
            .eviction
            .as_ref()
            .expect("eviction report")
            .terminated_pids
            .contains(&rogue_pid)
    );

    assert_eq!(outcome.restored_files.len(), 2);
    assert_eq!(
        std::fs::read(&mcp_cfg).expect("read restored mcp"),
        golden_mcp
    );
    assert_eq!(
        std::fs::read(&hook_file).expect("read restored hook"),
        golden_hook
    );
    assert!(
        vault
            .audit_all(&seal_key)
            .expect("re-audit")
            .iter()
            .all(|i| i.status == DriftStatus::Intact)
    );

    let receipt = outcome.forensic_receipt.expect("forensic receipt");
    let (meta, entries) =
        read_ledger_from_path(std::path::Path::new(&receipt.ledger_path)).expect("read .sext");
    let verified = verify_finalized_ledger(&meta, &entries, true).expect("verify .sext");
    assert_eq!(verified.total_nodes, 4);
}

#[test]
fn sec05_02_hit_and_run_exited_pid_still_restores_readonly_file_and_seals_sextant() {
    let dir = TempDir::new().expect("tempdir");
    let db_path = dir.path().join("reaper_ro.db");
    let forensic_dir = dir.path().join("forensics_ro");
    let locked_file = dir.path().join("skills-meta-index.json");

    let golden = br#"{"status":"STERILE_LOCKED"}"#;
    std::fs::write(&locked_file, golden).expect("write");
    let mut perms = std::fs::metadata(&locked_file).expect("meta").permissions();
    perms.set_readonly(true);
    std::fs::set_permissions(&locked_file, perms).expect("set +R");

    let seal_key = SnapshotSealKey::generate();
    let mut vault = BaselineVault::open(&db_path).expect("open");
    arm_baselines(&mut vault, &seal_key, std::slice::from_ref(&locked_file)).expect("arm");

    // Simulate attacker clearing +R, corrupting file, and re-applying +R before exiting (`ProcessNotFound`)
    let mut p2 = std::fs::metadata(&locked_file).expect("meta").permissions();
    #[allow(clippy::permissions_set_readonly_false)]
    p2.set_readonly(false);
    std::fs::set_permissions(&locked_file, p2).expect("unset +R");
    std::fs::write(&locked_file, br#"{"status":"POISONED"}"#).expect("corrupt");
    let mut p3 = std::fs::metadata(&locked_file).expect("meta").permissions();
    p3.set_readonly(true);
    std::fs::set_permissions(&locked_file, p3).expect("re-set +R");

    // Pass non-existent hit-and-run PID `999_999_991`
    let outcome = execute_reaper_sweep(
        "node-alpha",
        &vault,
        &seal_key,
        Some(999_999_991),
        None,
        &forensic_dir,
    )
    .expect("hit-and-run sweep must not abort");

    assert!(outcome.eviction.is_none());
    assert_eq!(outcome.restored_files.len(), 1);
    assert_eq!(std::fs::read(&locked_file).expect("restored"), golden);
    assert!(
        std::fs::metadata(&locked_file)
            .expect("meta")
            .permissions()
            .readonly()
    );
    assert!(outcome.forensic_receipt.is_some());

    // Cleanup +R so TempDir drops cleanly on Windows
    let mut cleanup = std::fs::metadata(&locked_file).expect("meta").permissions();
    #[allow(clippy::permissions_set_readonly_false)]
    cleanup.set_readonly(false);
    let _ = std::fs::set_permissions(&locked_file, cleanup);
}

#[tokio::test]
async fn canary_trap_catches_loopback_probe_and_defeats_slowloris_hang() {
    let dir = TempDir::new().expect("tempdir");

    // 1. Standard HTTP probe
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind canary");
    let addr = listener.local_addr().expect("addr");
    let forensic_dir = dir.path().to_path_buf();

    let handle = tokio::spawn(async move {
        capture_canary_probe_once(listener, "node-gamma", None, &forensic_dir).await
    });

    let mut client = TcpStream::connect(addr).await.expect("connect canary");
    client
        .write_all(b"GET /v1/ping/sk-proj-canary123 HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
        .await
        .expect("probe");
    let mut decoy = String::new();
    client.read_to_string(&mut decoy).await.expect("read decoy");
    assert!(decoy.contains("200 OK"));

    let (_peer, req_line, receipt) = handle.await.expect("join").expect("canary result");
    assert!(req_line.contains("/v1/ping/sk-proj-canary123"));
    assert!(std::path::Path::new(&receipt.expect("receipt").ledger_path).exists());

    // 2. Slowloris 0-byte stall ([SEC-05-01]) completes within 2.5s instead of hanging forever
    let listener2 = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind canary 2");
    let addr2 = listener2.local_addr().expect("addr 2");
    let forensic_dir2 = dir.path().to_path_buf();
    let handle2 = tokio::spawn(async move {
        capture_canary_probe_once(listener2, "node-gamma", None, &forensic_dir2).await
    });
    let _stalled_client = TcpStream::connect(addr2).await.expect("connect stall");
    let (_peer2, req_line2, receipt2) = tokio::time::timeout(Duration::from_secs(5), handle2)
        .await
        .expect("slowloris must time out cleanly")
        .expect("join")
        .expect("canary result");
    assert_eq!(req_line2, "<tcp-connect-or-slowloris-timeout>");
    assert!(receipt2.is_some());
}

#[test]
fn cockpit_tui_renders_cleanly_on_test_backend_and_strips_escape_injection() {
    let backend = TestBackend::new(100, 24);
    let mut terminal = Terminal::new(backend).expect("test terminal");
    let mut model = CockpitModel::default();
    model
        .incident_feed
        .push("Evicted PID 9999 \x1b[31mFAKE_ANSI_INJECTION\x1b[0m".into());

    terminal
        .draw(|f| render_cockpit(&model, f))
        .expect("draw cockpit");

    let buf = terminal.backend().buffer();
    let mut rendered = String::new();
    for y in 0..buf.area.height {
        for x in 0..buf.area.width {
            rendered.push_str(buf[(x, y)].symbol());
        }
        rendered.push('\n');
    }
    assert!(rendered.contains(concat!("PRAETOR v", env!("CARGO_PKG_VERSION"))));
    assert!(rendered.contains("node-beta"));
    assert!(rendered.contains("node-gamma"));
    assert!(!rendered.contains('\x1b'));
}

#[tokio::test]
async fn r3_non_loopback_canary_listener_rejected_and_wrong_seal_key_fails_audit() {
    // Verify `capture_canary_probe_once` rejects non-loopback sockets (simulated via local LAN bind if available or 0.0.0.0)
    if let Ok(wild) = TcpListener::bind("0.0.0.0:0").await {
        let dir = TempDir::new().expect("tempdir");
        let err = capture_canary_probe_once(wild, "node-alpha", None, dir.path())
            .await
            .expect_err("non-loopback canary listener must be refused");
        assert!(
            err.to_string().contains("non-loopback") || err.to_string().contains("not authorized")
        );
    }

    // Verify `audit_all(&wrong_key)` rejects unauthenticated/wrong-key reads
    let dir = TempDir::new().expect("tempdir");
    let db_path = dir.path().join("auth_audit.db");
    let cfg = dir.path().join("cfg.json");
    std::fs::write(&cfg, b"{}").expect("write");
    let right_key = SnapshotSealKey::generate();
    let wrong_key = SnapshotSealKey::generate();
    let mut vault = BaselineVault::open(&db_path).expect("open");
    arm_baselines(&mut vault, &right_key, std::slice::from_ref(&cfg)).expect("arm");
    assert!(vault.audit_all(&wrong_key).is_err());
}
