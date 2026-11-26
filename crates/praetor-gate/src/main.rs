#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use praetor_core::envelope::{WakeClaims, sign_wake_envelope};
use praetor_core::nodes::{ClusterRoster, NodeSecretKey};
use praetor_gate::{GateConfig, GateState, build_signed_post_bytes, serve_gate_listener};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[derive(Parser)]
#[command(
    name = "praetor-gate",
    version,
    about = "Ed25519 LAN Reverse Proxy & CSRF/Wake Firewall for NodeAlpha, NodeBeta, NodeDelta, and NodeGamma"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a fresh Ed25519 node signing key file (owner-only ACLs) and print its public key.
    Keygen {
        #[arg(long)]
        node: String,
        #[arg(long)]
        secret_out: PathBuf,
    },
    /// Run the authenticated LAN proxy in front of a loopback hub (`127.0.0.1:18088`).
    Serve {
        #[arg(long, default_value = "node-alpha")]
        node: String,
        #[arg(long, default_value = "0.0.0.0:8088")]
        listen: SocketAddr,
        #[arg(long, default_value = "127.0.0.1:18088")]
        upstream: SocketAddr,
        #[arg(long)]
        roster_file: PathBuf,
        #[arg(long)]
        forensic_dir: Option<PathBuf>,
    },
    /// Dispatch a cryptographically signed wake POST (`ASSEMBLE` / `ADJOURN` / `NOTIFY`) to a peer gate.
    SendWake {
        #[arg(long)]
        sender_node: String,
        #[arg(long)]
        target_node: String,
        #[arg(long)]
        secret_file: PathBuf,
        #[arg(long)]
        peer_addr: SocketAddr,
        #[arg(long, default_value = "/api/mesh/notify")]
        path: String,
        #[arg(long)]
        json_body: String,
    },
    /// Initialize or update a `cluster_roster.json` file with `--peer <node_id>=<pubkey_hex>` pairs.
    InitRoster {
        #[arg(long)]
        roster_out: PathBuf,
        #[arg(long, required = true)]
        peer: Vec<String>,
    },
    /// Mint and print a standalone `prae1.<claims>.<sig>` token string for `X-Praetor-Envelope`.
    SignEnvelope {
        #[arg(long)]
        sender_node: String,
        #[arg(long, default_value = "all")]
        target_node: String,
        #[arg(long)]
        secret_file: PathBuf,
        #[arg(long, default_value = "POST")]
        method: String,
        #[arg(long, default_value = "/api/mesh/notify")]
        path: String,
        #[arg(long)]
        json_body: String,
        #[arg(long, default_value_t = 60)]
        ttl_secs: i64,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Keygen { node, secret_out } => {
            let sk = NodeSecretKey::generate();
            let vk_hex = sk.verifying_key_hex();
            if let Some(parent) = secret_out.parent()
                && !parent.as_os_str().is_empty()
            {
                fs::create_dir_all(parent)?;
                sextant_core::canonical::enforce_owner_only_acl(parent, true)?;
            }
            let hex_seed = sk.to_hex_zeroizing();
            fs::write(&secret_out, hex_seed.as_bytes())?;
            if let Err(err) = sextant_core::canonical::enforce_owner_only_acl(&secret_out, false) {
                let _ = fs::remove_file(&secret_out);
                return Err(err.into());
            }
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "node": node.to_ascii_lowercase(),
                    "verifying_key_hex": vk_hex,
                    "secret_file": secret_out,
                }))?
            );
            Ok(())
        }
        Commands::Serve {
            node,
            listen,
            upstream,
            roster_file,
            forensic_dir,
        } => {
            let raw = fs::read_to_string(&roster_file)
                .with_context(|| format!("failed reading roster {}", roster_file.display()))?;
            let roster: ClusterRoster =
                serde_json::from_str(&raw).context("invalid ClusterRoster JSON")?;
            let state = GateState::new(GateConfig {
                local_node_id: node.to_ascii_lowercase(),
                roster: Arc::new(roster),
                upstream_addr: upstream,
                forensic_dir,
            });
            let listener = TcpListener::bind(listen).await?;
            println!(
                "[praetor-gate] Armed on http://{listen} -> loopback http://{upstream} (node={node})"
            );
            serve_gate_listener(listener, state).await?;
            Ok(())
        }
        Commands::SendWake {
            sender_node,
            target_node,
            secret_file,
            peer_addr,
            path,
            json_body,
        } => {
            let hex_seed = fs::read_to_string(&secret_file)?;
            let sk = NodeSecretKey::from_hex(&hex_seed)?;
            let wire = build_signed_post_bytes(
                &sk,
                &sender_node,
                &target_node,
                &peer_addr.to_string(),
                &path,
                json_body.as_bytes(),
                60,
            )?;
            let mut stream = TcpStream::connect(peer_addr).await?;
            stream.write_all(&wire).await?;
            stream.flush().await?;
            let mut resp = Vec::new();
            stream.read_to_end(&mut resp).await?;
            print!("{}", String::from_utf8_lossy(&resp));
            Ok(())
        }
        Commands::InitRoster { roster_out, peer } => {
            let mut pubkeys = BTreeMap::new();
            if roster_out.exists()
                && let Ok(existing_raw) = fs::read_to_string(&roster_out)
                && let Ok(existing) = serde_json::from_str::<ClusterRoster>(&existing_raw)
            {
                for (k, node) in existing.nodes {
                    pubkeys.insert(k, node.verifying_key_hex);
                }
            }
            for item in peer {
                let (node_id, vk_hex) = item
                    .split_once('=')
                    .context("expected --peer <node_id>=<verifying_key_hex>")?;
                pubkeys.insert(
                    node_id.trim().to_ascii_lowercase(),
                    vk_hex.trim().to_string(),
                );
            }
            let roster = ClusterRoster::default_cluster(&pubkeys)?;
            if let Some(parent) = roster_out.parent()
                && !parent.as_os_str().is_empty()
            {
                fs::create_dir_all(parent)?;
            }
            fs::write(&roster_out, serde_json::to_string_pretty(&roster)? + "\n")?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "status": "roster_written",
                    "nodes": roster.nodes.keys().collect::<Vec<_>>(),
                    "roster_file": roster_out,
                }))?
            );
            Ok(())
        }
        Commands::SignEnvelope {
            sender_node,
            target_node,
            secret_file,
            method,
            path,
            json_body,
            ttl_secs,
        } => {
            let hex_seed = fs::read_to_string(&secret_file)?;
            let sk = NodeSecretKey::from_hex(&hex_seed)?;
            let claims = WakeClaims::new(
                sender_node,
                target_node,
                method,
                path,
                json_body.as_bytes(),
                ttl_secs,
                None,
            );
            let token = sign_wake_envelope(&sk, &claims)?;
            println!("{token}");
            Ok(())
        }
    }
}
