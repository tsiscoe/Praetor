# Praetor (`praetor` v0.1.2)

**Pure-Rust Counter-Agent Interceptor, PreToolUse Firewall & Surgical Eviction Fleet** for **NodeAlpha**, **NodeBeta**, **NodeDelta**, and **NodeGamma**.

## Architecture & Hybrid Safety Invariant

| Crate | Binary | Safety Boundary | Threat Vectors Closed |
| :--- | :--- | :--- | :--- |
| `praetor-core` | *(lib)* | `#![forbid(unsafe_code)]` | `Ed25519` + IP-pinned cluster roster, `BLAKE3` HTTP body digests, replay nonce cache, `XChaCha20-Poly1305` golden persistence snapshots, and `Sextant` (`v0.1.2`) + `SigNET` (`v0.4.0`) forensic capsules. |
| `praetor-win32-cage` | *(lib)* | `#![deny(unsafe_op_in_unsafe_fn)]` + `undocumented_unsafe_blocks = "deny"` | Single ANSSI-documented Win32 FFI cage: `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` (breakaway disabled), two-phase `SuspendThread` + `TerminateProcess` tree eviction, and self/System PID guards. |
| `praetor-hook` | `praetor-hook` | `#![forbid(unsafe_code)]` | Closes `VEC-02` & `VEC-03`: fail-closed `256 KiB` JSON/duplicate-key (`CWE-436`) validator, PowerShell UTF-16LE `-EncodedCommand` recursive decoder, protected-file write shield, and `<UNTRUSTED_HANDOFF_DATA>` wrapper for `Inbox_Handoffs` / SMB handoffs. |
| `praetor-gate` | `praetor-gate` | `#![forbid(unsafe_code)]` | Closes `VEC-01`: zero-framework `tokio` HTTP/1.1 reverse proxy for `:8088`/`:8765`, stripping wildcard `Access-Control-Allow-Origin: *`, blocking browser drive-by CSRF, and enforcing `X-Praetor-Envelope` wakes. |
| `praetor-reaper` | `praetor-reaper` | `#![forbid(unsafe_code)]` | Closes `VEC-05`: `Taggant` loopback canary listener, autonomous persistence drift sweep, process-tree freeze & eviction, atomic snapshot restoration, and 3-pane `Ratatui` v0.30 cockpit. |

## Verification

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\Deploy-PraetorCluster.ps1 -Node node-alpha -DryRun
```
