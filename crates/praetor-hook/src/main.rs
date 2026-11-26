#![forbid(unsafe_code)]

use std::io;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use praetor_core::forensics::{IncidentEvidence, write_forensic_sextant_capsule};
use praetor_hook::{evaluate_hook_reader, wrap_handoff_directory};

#[derive(Parser)]
#[command(
    name = "praetor-hook",
    version,
    about = "Fail-closed PreToolUse AST firewall and untrusted handoff sanitizer"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Read PreToolUse JSON from stdin and evaluate fail-closed.
    ValidateTool {
        /// Output contract: `cli` (exit 0/2), `agent-ide` (`{"decision":"allow"|"deny"}`), `gemini-cli`, or `claude-code`.
        #[arg(long, default_value = "cli")]
        surface: String,
        /// Optional path to emit a signed Sextant (.sext) forensic capsule on block.
        #[arg(long)]
        forensic_out: Option<PathBuf>,
        /// Host node identifier for forensic tagging.
        #[arg(long, default_value = "node-alpha")]
        node: String,
    },
    /// Sanitize and wrap a handoff directory (`Inbox_Handoffs`) into non-instructional data envelopes.
    WrapHandoffs {
        #[arg(long)]
        dir: PathBuf,
    },
}

fn emit_surface_json(surface: &str, allowed: bool, rule_id: &str, reason: &str) -> ExitCode {
    let low = surface.trim().to_ascii_lowercase();
    let formatted_reason = format!("[praetor-hook:{rule_id}] {reason}");
    match low.as_str() {
        "agent-ide" => {
            let out = if allowed {
                serde_json::json!({ "decision": "allow" })
            } else {
                serde_json::json!({ "decision": "deny", "reason": formatted_reason })
            };
            println!("{out}");
            ExitCode::SUCCESS
        }
        "gemini-cli" => {
            if allowed {
                println!("{{}}");
            } else {
                println!(
                    "{}",
                    serde_json::json!({ "decision": "deny", "reason": formatted_reason })
                );
            }
            ExitCode::SUCCESS
        }
        "claude-code" => {
            if allowed {
                println!("{{}}");
            } else {
                println!(
                    "{}",
                    serde_json::json!({
                        "hookSpecificOutput": {
                            "hookEventName": "PreToolUse",
                            "permissionDecision": "deny",
                            "permissionDecisionReason": formatted_reason,
                        }
                    })
                );
            }
            ExitCode::SUCCESS
        }
        _ => {
            if allowed {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            }
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command.unwrap_or(Commands::ValidateTool {
        surface: "cli".into(),
        forensic_out: None,
        node: "node-alpha".into(),
    }) {
        Commands::ValidateTool {
            surface,
            forensic_out,
            node,
        } => {
            let verdict = evaluate_hook_reader(io::stdin().lock());
            if verdict.allowed {
                eprintln!(
                    "APPROVED by praetor-hook ({}, decoded_layers={}): {}",
                    verdict.rule_id, verdict.decoded_layers, verdict.reason
                );
                emit_surface_json(&surface, true, verdict.rule_id, &verdict.reason)
            } else {
                eprintln!(
                    "BLOCKED by praetor-hook [{}]: {}",
                    verdict.rule_id, verdict.reason
                );
                if let Some(ledger_path) = forensic_out {
                    let ev = IncidentEvidence {
                        incident_id: format!("hook-{}", verdict.rule_id.to_ascii_lowercase()),
                        host_node: node,
                        detector: "praetor-hook".into(),
                        vector_code: verdict.rule_id.into(),
                        summary: verdict.reason.clone(),
                        offending_pid: None,
                        terminated_pids: Vec::new(),
                        restored_files: Vec::new(),
                        revoked_signet_token_hash: None,
                    };
                    let _ = write_forensic_sextant_capsule(&ev, &ledger_path);
                }
                emit_surface_json(&surface, false, verdict.rule_id, &verdict.reason)
            }
        }
        Commands::WrapHandoffs { dir } => match wrap_handoff_directory(&dir) {
            Ok(bundle) => {
                print!("{bundle}");
                ExitCode::SUCCESS
            }
            Err(err) => {
                eprintln!("praetor-hook wrap-handoffs error: {err}");
                ExitCode::from(2)
            }
        },
    }
}
