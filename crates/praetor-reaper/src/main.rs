#![forbid(unsafe_code)]

use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use clap::{Parser, Subcommand};
use crossterm::event::{self, Event, KeyCode, KeyModifiers};
use praetor_core::baseline::{BaselineVault, DriftStatus, SnapshotSealKey};
use praetor_reaper::tui::{CockpitModel, CockpitMsg, render_cockpit, update_cockpit};
use praetor_reaper::{arm_baselines, capture_canary_probe_on_listener, execute_reaper_sweep};
use praetor_win32_cage::freeze_and_evict_tree;
use tokio::net::TcpListener;

#[derive(Parser)]
#[command(
    name = "praetor-reaper",
    version,
    about = "Autonomous Counter-Agent Hunter, Process-Tree Evictor, Persistence Rollback & TUI"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a 256-bit XChaCha20-Poly1305 baseline sealing key file (owner-only ACLs).
    Keygen {
        #[arg(long)]
        key_out: PathBuf,
    },
    /// Seal protected files (`mcp_config.json`, hooks, `skills-meta-index.json`) into the baseline vault.
    Arm {
        #[arg(long)]
        db: PathBuf,
        #[arg(long)]
        key_file: PathBuf,
        #[arg(long, required = true, num_args = 1..)]
        paths: Vec<PathBuf>,
    },
    /// Sweep sealed files, optionally freeze & evict a suspect PID tree, restore tampered files, and emit a Sextant capsule.
    Sweep {
        #[arg(long, default_value = "node-alpha")]
        node: String,
        #[arg(long)]
        db: PathBuf,
        #[arg(long)]
        key_file: PathBuf,
        #[arg(long)]
        evict_pid: Option<u32>,
        #[arg(long)]
        revoke_token_hash: Option<String>,
        #[arg(long)]
        forensic_dir: PathBuf,
    },
    /// Immediately freeze and terminate a rogue agent PID + all descendants without a baseline DB.
    EvictPid {
        #[arg(long)]
        pid: u32,
    },
    /// Arm a continuous loopback Taggant canary listener (`127.0.0.1:<port>`) and seal Sextant capsules on hit.
    WatchCanary {
        #[arg(long, default_value = "127.0.0.1:19470")]
        listen: SocketAddr,
        #[arg(long, default_value = "node-alpha")]
        node: String,
        #[arg(long)]
        forensic_dir: PathBuf,
        /// Exit after N alerts (0 = continuous standing tripwire).
        #[arg(long, default_value_t = 0)]
        max_alerts: usize,
    },
    /// Launch the 3-pane Ratatui v0.30 Counter-Agent Cockpit.
    Tui {
        #[arg(long, default_value = "node-alpha")]
        node: String,
        #[arg(long)]
        db: Option<PathBuf>,
        #[arg(long)]
        key_file: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Keygen { key_out } => {
            if let Some(parent) = key_out.parent()
                && !parent.as_os_str().is_empty()
            {
                fs::create_dir_all(parent)?;
                sextant_core::canonical::enforce_owner_only_acl(parent, true)?;
            }
            let key = SnapshotSealKey::generate();
            let hex_key = key.to_hex_zeroizing();
            fs::write(&key_out, hex_key.as_bytes())?;
            if let Err(err) = sextant_core::canonical::enforce_owner_only_acl(&key_out, false) {
                let _ = fs::remove_file(&key_out);
                return Err(err.into());
            }
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "status": "sealed_key_created",
                    "key_file": key_out,
                }))?
            );
            Ok(())
        }
        Commands::Arm {
            db,
            key_file,
            paths,
        } => {
            let key = SnapshotSealKey::from_hex(&fs::read_to_string(&key_file)?)?;
            let mut vault = BaselineVault::open(&db)?;
            let count = arm_baselines(&mut vault, &key, &paths)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "status": "armed",
                    "sealed_paths": count,
                    "db": db,
                }))?
            );
            Ok(())
        }
        Commands::Sweep {
            node,
            db,
            key_file,
            evict_pid,
            revoke_token_hash,
            forensic_dir,
        } => {
            let key = SnapshotSealKey::from_hex(&fs::read_to_string(&key_file)?)?;
            let vault = BaselineVault::open(&db)?;
            let outcome = execute_reaper_sweep(
                &node,
                &vault,
                &key,
                evict_pid,
                revoke_token_hash,
                &forensic_dir,
            )?;
            println!("{}", serde_json::to_string_pretty(&outcome)?);
            Ok(())
        }
        Commands::EvictPid { pid } => {
            let report = freeze_and_evict_tree(pid)?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            Ok(())
        }
        Commands::WatchCanary {
            listen,
            node,
            forensic_dir,
            max_alerts,
        } => {
            anyhow::ensure!(
                listen.ip().is_loopback(),
                "WatchCanary must bind strictly to a loopback address (got {listen})"
            );
            let listener = TcpListener::bind(listen).await?;
            println!("[praetor-reaper] Taggant loopback canary armed on http://{listen}");
            let mut count = 0usize;
            loop {
                let (peer, req_line, receipt) =
                    capture_canary_probe_on_listener(&listener, &node, None, &forensic_dir).await?;
                count += 1;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "alert": "CANARY_TRIPPED",
                        "alert_index": count,
                        "peer": peer,
                        "request": req_line,
                        "forensic_receipt": receipt,
                    }))?
                );
                if max_alerts > 0 && count >= max_alerts {
                    break;
                }
            }
            Ok(())
        }
        Commands::Tui { node, db, key_file } => {
            let mut model = CockpitModel {
                active_node: node,
                ..CockpitModel::default()
            };
            if let (Some(db_path), Some(kf_path)) = (db, key_file)
                && db_path.exists()
                && kf_path.exists()
                && let Ok(key) = SnapshotSealKey::from_hex(&fs::read_to_string(&kf_path)?)
                && let Ok(vault) = BaselineVault::open(&db_path)
                && let Ok(items) = vault.audit_all(&key)
            {
                model.protected_surfaces = items
                    .into_iter()
                    .map(|i| {
                        let st = match i.status {
                            DriftStatus::Intact => "[INTACT]",
                            DriftStatus::Modified { .. } => "[TAMPERED]",
                            DriftStatus::Deleted { .. } => "[DELETED]",
                            DriftStatus::UnauthorizedCreation { .. } => "[ROGUE_FILE]",
                        };
                        (i.path.to_string_lossy().into_owned(), st.to_string())
                    })
                    .collect();
            }

            let mut terminal = ratatui::init();
            let run_res = (|| -> Result<()> {
                while model.running {
                    terminal.draw(|f| render_cockpit(&model, f))?;
                    if event::poll(Duration::from_millis(200))?
                        && let Event::Key(key) = event::read()?
                        && (matches!(key.code, KeyCode::Char('q') | KeyCode::Esc)
                            || (key.modifiers.contains(KeyModifiers::CONTROL)
                                && key.code == KeyCode::Char('c')))
                    {
                        update_cockpit(&mut model, CockpitMsg::Quit);
                    }
                }
                Ok(())
            })();
            ratatui::restore();
            run_res
        }
    }
}
