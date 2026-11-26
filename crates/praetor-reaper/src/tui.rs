//! 3-Pane `Ratatui` v0.30 Defense Cockpit (TEA Model -> Update -> View, `TestBackend`-verified).
//! Sanitizes all external strings via `sextant_core::canonical::sanitize_terminal_text` (`CWE-150`).

use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph},
};
use sextant_core::canonical::sanitize_terminal_text;

/// Immutable snapshot rendered by the 3-pane Praetor Reaper TUI.
#[derive(Debug, Clone)]
pub struct CockpitModel {
    pub active_node: String,
    pub cluster_nodes: Vec<(String, String, String)>,
    pub protected_surfaces: Vec<(String, String)>,
    pub incident_feed: Vec<String>,
    pub running: bool,
}

impl Default for CockpitModel {
    fn default() -> Self {
        Self {
            active_node: "node-alpha".into(),
            cluster_nodes: vec![
                (
                    "node-alpha".into(),
                    "10.244.81.12 / .2.2".into(),
                    "[ARMED]".into(),
                ),
                (
                    "node-beta".into(),
                    "10.244.229.100 / .2.41".into(),
                    "[ARMED]".into(),
                ),
                (
                    "node-delta".into(),
                    "10.244.196.142".into(),
                    "[STANDBY]".into(),
                ),
                (
                    "node-gamma".into(),
                    "10.244.125.117 / .2.47".into(),
                    "[ARMED]".into(),
                ),
            ],
            protected_surfaces: Vec::new(),
            incident_feed: Vec::new(),
            running: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CockpitMsg {
    Quit,
}

pub fn update_cockpit(model: &mut CockpitModel, msg: CockpitMsg) {
    match msg {
        CockpitMsg::Quit => model.running = false,
    }
}

/// Render the 3-pane Praetor Counter-Agent Cockpit into any `ratatui::Frame` (`Crossterm` or `TestBackend`).
pub fn render_cockpit(model: &CockpitModel, frame: &mut Frame) {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(8),
            Constraint::Length(7),
        ])
        .split(frame.area());

    let top_banner = Paragraph::new(Line::from(vec![
        Span::styled(
            concat!(" PRAETOR v", env!("CARGO_PKG_VERSION"), " "),
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        ),
        Span::raw(format!(
            "| Active Guardian Node: {} | Press 'q' to exit",
            sanitize_terminal_text(&model.active_node)
        )),
    ]))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Counter-Agent Fleet "),
    );
    frame.render_widget(top_banner, vertical[0]);

    let mid_panes = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(42), Constraint::Percentage(58)])
        .split(vertical[1]);

    // Pane 1: Cluster Perimeter Roster (NodeAlpha, NodeBeta, NodeDelta, NodeGamma)
    let node_items: Vec<ListItem> = model
        .cluster_nodes
        .iter()
        .map(|(name, ip, st)| {
            ListItem::new(format!(
                "{:<15} {:<22} {}",
                sanitize_terminal_text(name),
                sanitize_terminal_text(ip),
                sanitize_terminal_text(st)
            ))
        })
        .collect();
    let nodes_list = List::new(node_items).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Cluster Nodes (:8088 Gate) "),
    );
    frame.render_widget(nodes_list, mid_panes[0]);

    // Pane 2: Sealed Persistence Baselines
    let surface_items: Vec<ListItem> = if model.protected_surfaces.is_empty() {
        vec![ListItem::new(
            "No baselines loaded in current view (run `praetor-reaper arm`)",
        )]
    } else {
        model
            .protected_surfaces
            .iter()
            .map(|(path, status)| {
                ListItem::new(format!(
                    "{} -> {}",
                    sanitize_terminal_text(status),
                    sanitize_terminal_text(path)
                ))
            })
            .collect()
    };
    let surface_list = List::new(surface_items).block(
        Block::default()
            .borders(Borders::ALL)
            .title("BLAKE3 + XChaCha20 Persistence Baselines"),
    );
    frame.render_widget(surface_list, mid_panes[1]);

    // Pane 3: Sanitized Eviction & Sextant Forensic Stream
    let inc_items: Vec<ListItem> = if model.incident_feed.is_empty() {
        vec![ListItem::new(
            "[CLEAN] Zero rogue agent evictions or canary trips recorded in window.",
        )]
    } else {
        model
            .incident_feed
            .iter()
            .map(|line| ListItem::new(sanitize_terminal_text(line)))
            .collect()
    };
    let inc_list = List::new(inc_items).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Eviction & Sextant Forensic Capsules "),
    );
    frame.render_widget(inc_list, vertical[2]);
}
