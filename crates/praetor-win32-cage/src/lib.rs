//! **Praetor Win32 Cage** — The single, strictly isolated FFI boundary in the Praetor fleet.
//!
//! Hardened under Wave-1 Security Audit (`[SEC-02-01]`, `[SEC-02-02]`):
//! 1. **`KillOnCloseJob`**: Win32 Kernel Job Object configured with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`
//!    and **zero** `BREAKAWAY_OK` / `SILENT_BREAKAWAY_OK` flags.
//! 2. **CreationTime-Pinned Lineage (`[SEC-02-01]`)**: Defeats Windows NT stale `th32ParentProcessID`
//!    PID-reuse false positives by requiring `child.creation_time_100ns >= parent.creation_time_100ns`.
//! 3. **Critical System & Fleet Immunity (`[SEC-02-01]`)**: Blocks eviction of PID `0`, `1`/`4`,
//!    `std::process::id()`, Session `0` daemons, critical Windows subsystems (`csrss.exe`, `lsass.exe`,
//!    `wininit.exe`, `smss.exe`, `services.exe`, `winlogon.exe`, `dwm.exe`), and Praetor binaries.
//! 4. **Handle-First Convergence Freeze (`[SEC-02-02]`)**: Holds kernel `PROCESS_TERMINATE` handles
//!    verified against `GetProcessTimes` across up to 4 thread-freeze convergence passes so neither
//!    PID recycling nor fork-during-freeze watchdogs can escape.

use std::collections::{BTreeSet, HashMap, VecDeque};

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Protected Windows & Praetor fleet executable names (`[SEC-02-01]`).
pub const PROTECTED_EXES: &[&str] = &[
    "system",
    "registry",
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "services.exe",
    "lsass.exe",
    "winlogon.exe",
    "fontdrvhost.exe",
    "dwm.exe",
    "praetor-gate.exe",
    "praetor-reaper.exe",
    "praetor-hook.exe",
    "praetor-gate",
    "praetor-reaper",
    "praetor-hook",
];

#[derive(Debug, Error)]
pub enum CageError {
    #[error("refusing to evict protected PID {0} (system, Session 0, or guardian process)")]
    ProtectedPid(u32),

    #[error("Win32 kernel containment failure in {op}: OS error {code}")]
    Win32 { op: &'static str, code: u32 },

    #[error("process {0} not found or already exited")]
    ProcessNotFound(u32),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

pub type CageResult<T> = Result<T, CageError>;

/// Telemetry record from a process-tree freeze & surgical eviction operation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvictionReport {
    pub root_pid: u32,
    pub discovered_tree_pids: Vec<u32>,
    pub suspended_threads: usize,
    pub terminated_pids: Vec<u32>,
    #[serde(default)]
    pub failed_pids: Vec<u32>,
}

/// Snapshot entry of an active OS process for behavioral / lineage inspection.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProcessEntry {
    pub pid: u32,
    pub parent_pid: u32,
    pub exe_name: String,
    #[serde(default)]
    pub creation_time_100ns: Option<u64>,
    #[serde(default)]
    pub session_id: Option<u32>,
}

/// Verify that a `ProcessEntry` is not a protected OS subsystem, Session 0 service, or Praetor binary.
pub fn validate_process_entry(entry: &ProcessEntry) -> CageResult<()> {
    if entry.pid == 0 || entry.pid == 4 || entry.pid == std::process::id() {
        return Err(CageError::ProtectedPid(entry.pid));
    }
    if cfg!(not(windows)) && entry.pid == 1 {
        return Err(CageError::ProtectedPid(entry.pid));
    }
    if entry.session_id == Some(0) {
        return Err(CageError::ProtectedPid(entry.pid));
    }
    let exe_low = entry
        .exe_name
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(&entry.exe_name)
        .to_ascii_lowercase();
    if PROTECTED_EXES.contains(&exe_low.as_str()) {
        return Err(CageError::ProtectedPid(entry.pid));
    }
    Ok(())
}

/// Compute all descendant PIDs rooted at `root_pid` (inclusive) from a process table snapshot,
/// enforcing `child.creation_time_100ns >= parent.creation_time_100ns` (`[SEC-02-01]`).
pub fn collect_descendant_pids(root_pid: u32, snapshot: &[ProcessEntry]) -> Vec<u32> {
    let mut by_pid: HashMap<u32, &ProcessEntry> = HashMap::with_capacity(snapshot.len());
    for entry in snapshot {
        by_pid.insert(entry.pid, entry);
    }
    if !by_pid.contains_key(&root_pid) {
        return Vec::new();
    }

    let mut children_map: HashMap<u32, Vec<u32>> = HashMap::new();
    for entry in snapshot {
        if entry.pid == entry.parent_pid {
            continue;
        }
        if let Some(parent) = by_pid.get(&entry.parent_pid) {
            // Reject stale `th32ParentProcessID` edges or partially unauthenticated Windows timestamps (`[W1]`)
            let time_valid = match (parent.creation_time_100ns, entry.creation_time_100ns) {
                (Some(p_ct), Some(c_ct)) => c_ct >= p_ct,
                (None, None) => !cfg!(windows),
                _ => false,
            };
            if time_valid {
                children_map
                    .entry(entry.parent_pid)
                    .or_default()
                    .push(entry.pid);
            }
        }
    }

    let mut ordered = Vec::new();
    let mut visited = BTreeSet::new();
    let mut queue = VecDeque::new();
    visited.insert(root_pid);
    queue.push_back(root_pid);

    while let Some(curr) = queue.pop_front() {
        ordered.push(curr);
        if let Some(kids) = children_map.get(&curr) {
            for &kid in kids {
                if visited.insert(kid) {
                    queue.push_back(kid);
                }
            }
        }
    }
    ordered
}

#[cfg(windows)]
mod imp {
    use std::collections::{BTreeMap, BTreeSet, HashMap};
    use std::mem::{MaybeUninit, offset_of, size_of};
    use std::ptr::null;

    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_NO_MORE_FILES, FILETIME, GetLastError, HANDLE, INVALID_HANDLE_VALUE,
        WAIT_OBJECT_0,
    };
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
        TH32CS_SNAPPROCESS, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
    };
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
        SetInformationJobObject, TerminateJobObject,
    };
    use windows_sys::Win32::System::RemoteDesktop::ProcessIdToSessionId;
    use windows_sys::Win32::System::Threading::{
        GetProcessIdOfThread, GetProcessTimes, OpenProcess, OpenThread,
        PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SET_QUOTA, PROCESS_SYNCHRONIZE,
        PROCESS_TERMINATE, ResumeThread, SuspendThread, THREAD_QUERY_LIMITED_INFORMATION,
        THREAD_SUSPEND_RESUME, TerminateProcess, WaitForSingleObject,
    };

    use super::{
        CageError, CageResult, EvictionReport, ProcessEntry, collect_descendant_pids,
        validate_process_entry,
    };

    struct OwnedHandle(HANDLE);

    impl OwnedHandle {
        fn new(handle: HANDLE, op: &'static str) -> CageResult<Self> {
            if handle.is_null() || handle == INVALID_HANDLE_VALUE {
                // SAFETY: GetLastError reads thread-local Win32 error state with no pointer dereferences.
                let code = unsafe { GetLastError() };
                return Err(CageError::Win32 { op, code });
            }
            Ok(Self(handle))
        }

        fn raw(&self) -> HANDLE {
            self.0
        }
    }

    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
                // SAFETY: `self.0` was validated non-null and not INVALID_HANDLE_VALUE at construction,
                // and `OwnedHandle` has exclusive ownership of the kernel handle.
                unsafe {
                    let _ = CloseHandle(self.0);
                }
            }
        }
    }

    // SAFETY: Win32 kernel JobObject handles are thread-safe kernel object references that may be
    // moved across threads safely as long as CloseHandle occurs once on Drop.
    unsafe impl Send for KillOnCloseJob {}
    // SAFETY: TerminateJobObject and AssignProcessToJobObject are synchronized by the NT kernel.
    unsafe impl Sync for KillOnCloseJob {}

    /// Win32 Job Object enforcing `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` with breakaway disabled.
    pub struct KillOnCloseJob {
        handle: OwnedHandle,
    }

    impl KillOnCloseJob {
        /// Create an anonymous Win32 Job Object armed with `KILL_ON_JOB_CLOSE` and breakaway denied.
        pub fn create() -> CageResult<Self> {
            // SAFETY: Passing null security attributes and null name creates a fresh anonymous JobObject.
            let raw = unsafe { CreateJobObjectW(null(), null()) };
            let handle = OwnedHandle::new(raw, "CreateJobObjectW")?;

            // SAFETY: Zero-initializing POD Win32 struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION is valid.
            let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION =
                unsafe { MaybeUninit::zeroed().assume_init() };
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;

            // SAFETY: `handle.raw()` is a valid JobObject handle and `info` points to an initialized
            // `JOBOBJECT_EXTENDED_LIMIT_INFORMATION` of exact byte size.
            let ok = unsafe {
                SetInformationJobObject(
                    handle.raw(),
                    JobObjectExtendedLimitInformation,
                    (&raw const info).cast(),
                    size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                )
            };
            if ok == 0 {
                // SAFETY: Reads thread-local Win32 error code.
                let code = unsafe { GetLastError() };
                return Err(CageError::Win32 {
                    op: "SetInformationJobObject",
                    code,
                });
            }

            Ok(Self { handle })
        }

        /// Bind a spawned process PID into this `KillOnCloseJob` after handle-bound identity checks (`[W1]`).
        pub fn assign_pid(&self, pid: u32) -> CageResult<()> {
            if pid == 0 || pid == 4 || pid == std::process::id() {
                return Err(CageError::ProtectedPid(pid));
            }
            let snap = snapshot_processes()?;
            let entry = snap
                .iter()
                .find(|e| e.pid == pid)
                .ok_or(CageError::ProcessNotFound(pid))?;
            if entry.session_id.is_none() || entry.creation_time_100ns.is_none() {
                return Err(CageError::ProtectedPid(pid));
            }
            validate_process_entry(entry)?;

            // SAFETY: Opens a temporary kernel process handle with quota+terminate+query+sync rights.
            let proc_raw = unsafe {
                OpenProcess(
                    PROCESS_SET_QUOTA
                        | PROCESS_TERMINATE
                        | PROCESS_QUERY_LIMITED_INFORMATION
                        | PROCESS_SYNCHRONIZE,
                    0,
                    pid,
                )
            };
            let proc_handle = OwnedHandle::new(proc_raw, "OpenProcess(AssignJob)")?;

            // Revalidate exact process identity on the held handle before Job assignment (`[W1]`)
            let handle_ctime = query_creation_time_100ns(proc_handle.raw());
            if handle_ctime != entry.creation_time_100ns {
                return Err(CageError::ProcessNotFound(pid));
            }
            let mut session_id = 0u32;
            // SAFETY: Writes validated stack `u32` via Win32 `ProcessIdToSessionId`.
            if unsafe { ProcessIdToSessionId(pid, &raw mut session_id) } == 0 || session_id == 0 {
                return Err(CageError::ProtectedPid(pid));
            }

            // SAFETY: Both `self.handle.raw()` and `proc_handle.raw()` are live, validated kernel handles.
            let ok = unsafe { AssignProcessToJobObject(self.handle.raw(), proc_handle.raw()) };
            if ok == 0 {
                // SAFETY: Reads thread-local Win32 error code.
                let code = unsafe { GetLastError() };
                return Err(CageError::Win32 {
                    op: "AssignProcessToJobObject",
                    code,
                });
            }
            Ok(())
        }

        /// Immediately terminate every process and breakaway-blocked descendant inside the Job Object.
        pub fn terminate_all(&self, exit_code: u32) -> CageResult<()> {
            // SAFETY: `self.handle.raw()` is a valid JobObject handle owned by `self`.
            let ok = unsafe { TerminateJobObject(self.handle.raw(), exit_code) };
            if ok == 0 {
                // SAFETY: Reads thread-local Win32 error code.
                let code = unsafe { GetLastError() };
                return Err(CageError::Win32 {
                    op: "TerminateJobObject",
                    code,
                });
            }
            Ok(())
        }
    }

    impl Drop for KillOnCloseJob {
        fn drop(&mut self) {
            let _ = self.terminate_all(0xDEAD_C0DE);
        }
    }

    fn query_creation_time_100ns(handle: HANDLE) -> Option<u64> {
        let mut created = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        let mut exited = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        let mut kernel = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        let mut user = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        // SAFETY: `handle` has `PROCESS_QUERY_LIMITED_INFORMATION` and all four FILETIME pointers are valid stack locals.
        let ok = unsafe {
            GetProcessTimes(
                handle,
                &raw mut created,
                &raw mut exited,
                &raw mut kernel,
                &raw mut user,
            )
        };
        if ok != 0 {
            Some(((created.dwHighDateTime as u64) << 32) | (created.dwLowDateTime as u64))
        } else {
            None
        }
    }

    fn query_pid_metadata(pid: u32) -> (Option<u64>, Option<u32>) {
        let mut session_id = 0u32;
        // SAFETY: `ProcessIdToSessionId` writes a single `u32` into valid stack reference `&raw mut session_id`.
        let sess_opt = if unsafe { ProcessIdToSessionId(pid, &raw mut session_id) } != 0 {
            Some(session_id)
        } else {
            None
        };

        // SAFETY: Opens read-only limited metadata handle (`PROCESS_QUERY_LIMITED_INFORMATION`).
        let raw = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        let ctime_opt = if let Ok(h) = OwnedHandle::new(raw, "OpenProcess(Query)") {
            query_creation_time_100ns(h.raw())
        } else {
            None
        };
        (ctime_opt, sess_opt)
    }

    /// Enumerate all running processes on the Windows host with `CreationTime` and `SessionId`.
    pub fn snapshot_processes() -> CageResult<Vec<ProcessEntry>> {
        // SAFETY: Requests a read-only kernel snapshot of the active process table.
        let snap_raw = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
        let snap = OwnedHandle::new(snap_raw, "CreateToolhelp32Snapshot(Process)")?;

        // SAFETY: Zero-initializing PROCESSENTRY32W POD structure before setting dwSize.
        let mut entry: PROCESSENTRY32W = unsafe { MaybeUninit::zeroed().assume_init() };
        entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;
        let min_proc_bytes =
            (offset_of!(PROCESSENTRY32W, th32ParentProcessID) + size_of::<u32>()) as u32;

        let mut list = Vec::new();
        // SAFETY: `snap.raw()` is valid and `entry.dwSize` is initialized to the exact struct size.
        let mut has_item = unsafe { Process32FirstW(snap.raw(), &raw mut entry) };
        while has_item != 0 {
            if entry.dwSize >= min_proc_bytes {
                let nul_pos = entry
                    .szExeFile
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(entry.szExeFile.len());
                let exe_name = String::from_utf16_lossy(&entry.szExeFile[..nul_pos]);
                let pid = entry.th32ProcessID;
                let (creation_time_100ns, session_id) = if pid == 0 || pid == 4 {
                    (Some(0), Some(0))
                } else {
                    query_pid_metadata(pid)
                };
                list.push(ProcessEntry {
                    pid,
                    parent_pid: entry.th32ParentProcessID,
                    exe_name,
                    creation_time_100ns,
                    session_id,
                });
            }
            entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;
            // SAFETY: Iterates next process entry into the same properly sized `entry` struct.
            has_item = unsafe { Process32NextW(snap.raw(), &raw mut entry) };
        }
        // SAFETY: Reads thread-local Win32 error state after enumeration ends (`[W3]`).
        let last_err = unsafe { GetLastError() };
        if last_err != 0 && last_err != ERROR_NO_MORE_FILES {
            return Err(CageError::Win32 {
                op: "Process32NextW",
                code: last_err,
            });
        }
        Ok(list)
    }

    /// Suspend not-yet-suspended threads belonging to `target_set`, verifying `GetProcessIdOfThread`
    /// and retaining thread handles for clean `ResumeThread` rollback on partial eviction failure (`[W2]`, `[W3]`).
    fn suspend_new_threads(
        target_set: &BTreeSet<u32>,
        already_suspended_tids: &mut BTreeSet<u32>,
        retained_threads: &mut Vec<(u32, OwnedHandle)>,
    ) -> CageResult<usize> {
        // SAFETY: Requests a read-only kernel snapshot of active threads.
        let snap_raw = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
        let snap = OwnedHandle::new(snap_raw, "CreateToolhelp32Snapshot(Thread)")?;

        // SAFETY: Zero-initializing THREADENTRY32 POD structure before setting dwSize.
        let mut te: THREADENTRY32 = unsafe { MaybeUninit::zeroed().assume_init() };
        te.dwSize = size_of::<THREADENTRY32>() as u32;
        let min_thread_bytes =
            (offset_of!(THREADENTRY32, th32OwnerProcessID) + size_of::<u32>()) as u32;

        let mut newly_suspended = 0usize;
        // SAFETY: `snap.raw()` is valid and `te.dwSize` equals `size_of::<THREADENTRY32>()`.
        let mut has_thread = unsafe { Thread32First(snap.raw(), &raw mut te) };
        while has_thread != 0 {
            if te.dwSize >= min_thread_bytes
                && target_set.contains(&te.th32OwnerProcessID)
                && !already_suspended_tids.contains(&te.th32ThreadID)
            {
                // SAFETY: Opens target thread with suspend + query rights to verify owning PID (`[V2]`).
                let th_raw = unsafe {
                    OpenThread(
                        THREAD_SUSPEND_RESUME | THREAD_QUERY_LIMITED_INFORMATION,
                        0,
                        te.th32ThreadID,
                    )
                };
                if !th_raw.is_null() && th_raw != INVALID_HANDLE_VALUE {
                    let th = OwnedHandle(th_raw);
                    // SAFETY: `th.raw()` has `THREAD_QUERY_LIMITED_INFORMATION`.
                    let actual_owner = unsafe { GetProcessIdOfThread(th.raw()) };
                    if actual_owner == te.th32OwnerProcessID && actual_owner != 0 {
                        // SAFETY: `th.raw()` is verified to belong to `actual_owner`; `SuspendThread` returns `u32::MAX` on error.
                        let prev = unsafe { SuspendThread(th.raw()) };
                        if prev != u32::MAX {
                            already_suspended_tids.insert(te.th32ThreadID);
                            retained_threads.push((actual_owner, th));
                            newly_suspended += 1;
                        }
                    }
                }
            }
            te.dwSize = size_of::<THREADENTRY32>() as u32;
            // SAFETY: Advances to next thread record in snapshot.
            has_thread = unsafe { Thread32Next(snap.raw(), &raw mut te) };
        }
        // SAFETY: Reads thread-local Win32 error state after enumeration ends (`[W3]`).
        let last_err = unsafe { GetLastError() };
        if last_err != 0 && last_err != ERROR_NO_MORE_FILES {
            return Err(CageError::Win32 {
                op: "Thread32Next",
                code: last_err,
            });
        }
        Ok(newly_suspended)
    }

    fn resume_retained_threads(
        retained_threads: Vec<(u32, OwnedHandle)>,
        skip_pids: &BTreeSet<u32>,
    ) {
        for (owner_pid, th) in retained_threads {
            if !skip_pids.contains(&owner_pid) {
                // SAFETY: `th.raw()` is a valid `THREAD_SUSPEND_RESUME` handle suspended once by Praetor.
                unsafe {
                    let _ = ResumeThread(th.raw());
                }
            }
        }
    }

    /// Handle-first, multi-pass convergent freeze & eviction (`[W1]`, `[W2]`, `[SEC-02-01..02]`).
    pub fn freeze_and_evict_tree(root_pid: u32) -> CageResult<EvictionReport> {
        if root_pid == 0 || root_pid == 4 || root_pid == std::process::id() {
            return Err(CageError::ProtectedPid(root_pid));
        }

        let mut pinned_handles: BTreeMap<u32, OwnedHandle> = BTreeMap::new();
        let mut discovery_order: Vec<u32> = Vec::new();
        let mut suspended_tids: BTreeSet<u32> = BTreeSet::new();
        let mut retained_threads: Vec<(u32, OwnedHandle)> = Vec::new();
        let mut total_suspended_threads = 0usize;

        for pass in 0..4 {
            let snapshot = match snapshot_processes() {
                Ok(s) => s,
                Err(e) => {
                    resume_retained_threads(retained_threads, &BTreeSet::new());
                    return Err(e);
                }
            };
            let by_pid: HashMap<u32, &ProcessEntry> = snapshot.iter().map(|e| (e.pid, e)).collect();

            if pass == 0 && !by_pid.contains_key(&root_pid) {
                resume_retained_threads(retained_threads, &BTreeSet::new());
                return Err(CageError::ProcessNotFound(root_pid));
            }

            let tree_pids = collect_descendant_pids(root_pid, &snapshot);
            let mut new_pids_this_pass = 0usize;

            for &pid in &tree_pids {
                if let Some(entry) = by_pid.get(&pid) {
                    if let Err(e) = validate_process_entry(entry) {
                        resume_retained_threads(retained_threads, &BTreeSet::new());
                        return Err(e);
                    }
                    if entry.session_id.is_none() || entry.creation_time_100ns.is_none() {
                        continue;
                    }
                    if let std::collections::btree_map::Entry::Vacant(vacant) =
                        pinned_handles.entry(pid)
                    {
                        // SAFETY: Opens kernel handle pinning PID against kernel reuse while verifying CreationTime.
                        let raw = unsafe {
                            OpenProcess(
                                PROCESS_TERMINATE
                                    | PROCESS_QUERY_LIMITED_INFORMATION
                                    | PROCESS_SYNCHRONIZE,
                                0,
                                pid,
                            )
                        };
                        if let Ok(h) = OwnedHandle::new(raw, "OpenProcess(PinAndTerminate)") {
                            // Verify opened handle matches snapshot CreationTime (`[W1]` / `[SEC-02-02]`)
                            let handle_ctime = query_creation_time_100ns(h.raw());
                            if handle_ctime != entry.creation_time_100ns {
                                continue;
                            }
                            vacant.insert(h);
                            discovery_order.push(pid);
                            new_pids_this_pass += 1;
                        }
                    }
                }
            }

            let target_set: BTreeSet<u32> = pinned_handles.keys().copied().collect();
            if target_set.is_empty() {
                break;
            }
            match suspend_new_threads(&target_set, &mut suspended_tids, &mut retained_threads) {
                Ok(newly_suspended) => {
                    total_suspended_threads += newly_suspended;
                    if new_pids_this_pass == 0 && newly_suspended == 0 {
                        break;
                    }
                }
                Err(e) => {
                    resume_retained_threads(retained_threads, &BTreeSet::new());
                    return Err(e);
                }
            }
        }

        if discovery_order.is_empty() {
            resume_retained_threads(retained_threads, &BTreeSet::new());
            return Err(CageError::ProcessNotFound(root_pid));
        }

        // Terminate leaves-first and confirm actual OS process exit via `WaitForSingleObject(250ms)` (`[W2]`)
        let mut terminated_pids = Vec::with_capacity(discovery_order.len());
        let mut failed_pids = Vec::new();
        let mut terminated_set = BTreeSet::new();
        for &pid in discovery_order.iter().rev() {
            if let Some(handle) = pinned_handles.get(&pid) {
                // SAFETY: `handle.raw()` is a verified `PROCESS_TERMINATE | SYNCHRONIZE` handle.
                let ok = unsafe { TerminateProcess(handle.raw(), 0xDEAD_C0DE) };
                // SAFETY: Waits up to 250ms for the kernel object to become signaled (exited).
                let exited =
                    ok != 0 && unsafe { WaitForSingleObject(handle.raw(), 250) } == WAIT_OBJECT_0;
                if exited {
                    terminated_pids.push(pid);
                    terminated_set.insert(pid);
                } else {
                    failed_pids.push(pid);
                }
            } else {
                failed_pids.push(pid);
            }
        }

        // Resume any surviving threads on PIDs whose termination did not complete cleanly (`[W2]`)
        resume_retained_threads(retained_threads, &terminated_set);

        Ok(EvictionReport {
            root_pid,
            discovered_tree_pids: discovery_order,
            suspended_threads: total_suspended_threads,
            terminated_pids,
            failed_pids,
        })
    }
}

#[cfg(not(windows))]
mod imp {
    use std::collections::HashMap;
    use std::process::Command;

    use super::{
        CageError, CageResult, EvictionReport, ProcessEntry, collect_descendant_pids,
        validate_process_entry,
    };

    pub struct KillOnCloseJob {
        tracked_pids: std::sync::Mutex<Vec<u32>>,
    }

    impl KillOnCloseJob {
        pub fn create() -> CageResult<Self> {
            Ok(Self {
                tracked_pids: std::sync::Mutex::new(Vec::new()),
            })
        }

        pub fn assign_pid(&self, pid: u32) -> CageResult<()> {
            if pid == 0 || pid == 1 || pid == std::process::id() {
                return Err(CageError::ProtectedPid(pid));
            }
            if let Ok(mut guard) = self.tracked_pids.lock() {
                guard.push(pid);
            }
            Ok(())
        }

        pub fn terminate_all(&self, _exit_code: u32) -> CageResult<()> {
            if let Ok(guard) = self.tracked_pids.lock() {
                for &pid in guard.iter() {
                    let _ = Command::new("kill").args(["-9", &pid.to_string()]).status();
                }
            }
            Ok(())
        }
    }

    impl Drop for KillOnCloseJob {
        fn drop(&mut self) {
            let _ = self.terminate_all(1);
        }
    }

    pub fn snapshot_processes() -> CageResult<Vec<ProcessEntry>> {
        let out = Command::new("ps")
            .args(["-eo", "pid=,ppid=,comm="])
            .output()?;
        let text = String::from_utf8_lossy(&out.stdout);
        let mut entries = Vec::new();
        for line in text.lines() {
            let mut parts = line.split_whitespace();
            if let (Some(p), Some(pp), Some(comm)) = (parts.next(), parts.next(), parts.next())
                && let (Ok(pid), Ok(parent_pid)) = (p.parse::<u32>(), pp.parse::<u32>())
            {
                entries.push(ProcessEntry {
                    pid,
                    parent_pid,
                    exe_name: comm.to_string(),
                    creation_time_100ns: None,
                    session_id: None,
                });
            }
        }
        Ok(entries)
    }

    pub fn freeze_and_evict_tree(root_pid: u32) -> CageResult<EvictionReport> {
        if root_pid == 0 || root_pid == 1 || root_pid == std::process::id() {
            return Err(CageError::ProtectedPid(root_pid));
        }
        let snap = snapshot_processes()?;
        let by_pid: HashMap<u32, &ProcessEntry> = snap.iter().map(|e| (e.pid, e)).collect();
        let tree_pids = collect_descendant_pids(root_pid, &snap);
        if tree_pids.is_empty() {
            return Err(CageError::ProcessNotFound(root_pid));
        }
        for &pid in &tree_pids {
            if let Some(entry) = by_pid.get(&pid) {
                validate_process_entry(entry)?;
            }
        }
        for &pid in &tree_pids {
            let _ = Command::new("kill")
                .args(["-STOP", &pid.to_string()])
                .status();
        }
        let mut terminated = Vec::new();
        for &pid in tree_pids.iter().rev() {
            if Command::new("kill")
                .args(["-KILL", &pid.to_string()])
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
            {
                terminated.push(pid);
            }
        }
        Ok(EvictionReport {
            root_pid,
            discovered_tree_pids: tree_pids,
            suspended_threads: terminated.len(),
            terminated_pids: terminated,
            failed_pids: Vec::new(),
        })
    }
}

pub use imp::{KillOnCloseJob, freeze_and_evict_tree, snapshot_processes};
