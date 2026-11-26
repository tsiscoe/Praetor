use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use praetor_win32_cage::{
    CageError, KillOnCloseJob, ProcessEntry, collect_descendant_pids, freeze_and_evict_tree,
    snapshot_processes, validate_process_entry,
};

#[test]
fn collect_descendant_pids_handles_cycles_and_stale_parent_pid_creation_time() {
    let table = vec![
        // Recycled PID 100 created at t=5000
        ProcessEntry {
            pid: 100,
            parent_pid: 4,
            exe_name: "agent.exe".into(),
            creation_time_100ns: Some(5000),
            session_id: Some(1),
        },
        // Genuine child created at t=5100 (>= 5000) -> INCLUDED
        ProcessEntry {
            pid: 200,
            parent_pid: 100,
            exe_name: "cmd.exe".into(),
            creation_time_100ns: Some(5100),
            session_id: Some(1),
        },
        // Genuine grandchild created at t=5200 -> INCLUDED
        ProcessEntry {
            pid: 300,
            parent_pid: 200,
            exe_name: "pwsh.exe".into(),
            creation_time_100ns: Some(5200),
            session_id: Some(1),
        },
        // Stale th32ParentProcessID=100 from hours earlier (t=1000 < 5000) -> EXCLUDED ([SEC-02-01])
        ProcessEntry {
            pid: 888,
            parent_pid: 100,
            exe_name: "explorer.exe".into(),
            creation_time_100ns: Some(1000),
            session_id: Some(1),
        },
    ];
    let tree = collect_descendant_pids(100, &table);
    assert_eq!(tree, vec![100, 200, 300]);
}

#[test]
fn self_system_session0_and_fleet_binaries_are_strictly_protected() {
    let self_pid = std::process::id();
    assert!(matches!(
        freeze_and_evict_tree(self_pid),
        Err(CageError::ProtectedPid(p)) if p == self_pid
    ));
    assert!(matches!(
        freeze_and_evict_tree(0),
        Err(CageError::ProtectedPid(0))
    ));

    // Session 0 critical process rejected ([SEC-02-01])
    let csrss = ProcessEntry {
        pid: 612,
        parent_pid: 500,
        exe_name: "csrss.exe".into(),
        creation_time_100ns: Some(100),
        session_id: Some(0),
    };
    assert!(matches!(
        validate_process_entry(&csrss),
        Err(CageError::ProtectedPid(612))
    ));

    // Praetor guardian daemon in user session 1 also rejected ([SEC-02-01])
    let gate = ProcessEntry {
        pid: 9400,
        parent_pid: 1200,
        exe_name: r"C:\Workspaces\global_workspace\praetor\target\release\praetor-gate.exe".into(),
        creation_time_100ns: Some(900),
        session_id: Some(1),
    };
    assert!(matches!(
        validate_process_entry(&gate),
        Err(CageError::ProtectedPid(9400))
    ));
}

#[test]
fn freeze_and_evict_tree_terminates_live_spawned_child_process() {
    let mut child = if cfg!(windows) {
        Command::new("ping")
            .args(["-n", "30", "127.0.0.1"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn ping")
    } else {
        Command::new("sleep")
            .arg("30")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn sleep")
    };

    let pid = child.id();
    thread::sleep(Duration::from_millis(80));

    let report = freeze_and_evict_tree(pid).expect("evict child");
    assert!(report.discovered_tree_pids.contains(&pid));
    assert!(report.terminated_pids.contains(&pid));

    let status = child.wait().expect("wait exited child");
    assert!(!status.success());
}

#[test]
fn kill_on_close_job_terminates_assigned_child_on_drop() {
    let mut child = if cfg!(windows) {
        Command::new("ping")
            .args(["-n", "30", "127.0.0.1"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn ping")
    } else {
        Command::new("sleep")
            .arg("30")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn sleep")
    };

    let pid = child.id();
    {
        let job = KillOnCloseJob::create().expect("create job");
        job.assign_pid(pid).expect("assign pid to job");
        let snap = snapshot_processes().expect("snapshot");
        assert!(snap.iter().any(|p| p.pid == pid));
    }

    let status = child.wait().expect("child reaped by job drop");
    assert!(!status.success());
}
