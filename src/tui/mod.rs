//! Ratatui cockpit: findings table + status keys, native threat-model and
//! attack-chain graphs (Canvas/braille), all over the same in-process ledger.

mod graph;

use crate::artifacts::{norm_severity, Chain, ThreatModel};
use crate::config::TargetConfig;
use crate::ledger::{Ledger, LedgerFinding};
use anyhow::Result;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind};
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::symbols::Marker;
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::canvas::{Canvas, Line as CanvasLine};
use ratatui::widgets::{Block, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::{DefaultTerminal, Frame};
use std::time::Duration;

#[derive(PartialEq, Clone, Copy)]
enum RightTab {
    Threat,
    Chains,
}

enum Mode {
    Normal,
    EditNote(String),
}

struct App {
    target: TargetConfig,
    model: String,
    ledger: Ledger,
    tm: ThreatModel,
    chains: Vec<Chain>,
    sel: usize,
    filter: Option<String>,
    tab: RightTab,
    mode: Mode,
    status: String,
    quit: bool,
}

fn sev_color(sev: &str) -> Color {
    match norm_severity(sev).as_str() {
        "CRITICAL" => Color::LightRed,
        "HIGH" => Color::Red,
        "MEDIUM" => Color::Yellow,
        "LOW" => Color::Blue,
        _ => Color::Gray,
    }
}

fn status_color(s: &str) -> Color {
    match s {
        "confirmed" => Color::Green,
        "false_positive" => Color::Red,
        "accepted" => Color::Yellow,
        "fixed" => Color::Blue,
        "duplicate" => Color::DarkGray,
        _ => Color::Gray,
    }
}

impl App {
    fn load(target: &TargetConfig, model: &str) -> App {
        let ledger = Ledger::load(&target.target_dir, &target.name);
        let tm: ThreatModel = std::fs::read_to_string(target.target_dir.join("threat_model.json"))
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        let chains: Vec<Chain> = std::fs::read_to_string(target.target_dir.join("chains.json"))
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        App {
            target: target.clone(),
            model: model.to_string(),
            ledger,
            tm,
            chains,
            sel: 0,
            filter: None,
            tab: RightTab::Threat,
            mode: Mode::Normal,
            status: "↑↓ move · c/f/a/x triage · e note · / filter · Tab graph · r chains · g html · q quit".into(),
            quit: false,
        }
    }

    /// Finding ids in display order (severity desc, id asc), respecting the filter.
    fn ordered(&self) -> Vec<&LedgerFinding> {
        let mut v: Vec<&LedgerFinding> = self
            .ledger
            .findings
            .iter()
            .filter(|f| self.filter.as_ref().map(|s| &f.status == s).unwrap_or(true))
            .collect();
        v.sort_by(|a, b| {
            crate::artifacts::sev_rank(&b.severity)
                .cmp(&crate::artifacts::sev_rank(&a.severity))
                .then(a.id.cmp(&b.id))
        });
        v
    }

    fn cycle_filter(&mut self) {
        let order: [Option<&str>; 6] = [None, Some("confirmed"), Some("new"), Some("false_positive"), Some("accepted"), Some("fixed")];
        let cur = self.filter.as_deref();
        let idx = order.iter().position(|x| *x == cur).unwrap_or(0);
        self.filter = order[(idx + 1) % order.len()].map(|s| s.to_string());
        self.sel = 0;
        self.status = format!("filter: {}", self.filter.as_deref().unwrap_or("all"));
    }

    fn selected_id(&self) -> Option<String> {
        self.ordered().get(self.sel).map(|f| f.id.clone())
    }

    fn move_sel(&mut self, d: i32) {
        let n = self.ledger.findings.len();
        if n == 0 {
            return;
        }
        let new = (self.sel as i32 + d).clamp(0, n as i32 - 1);
        self.sel = new as usize;
    }

    fn set_status(&mut self, s: &str) -> Result<()> {
        if let Some(id) = self.selected_id() {
            self.ledger.set_status(&id, s, None)?;
            self.ledger.save(&self.target.target_dir)?;
            self.status = format!("{id} → {s}");
        }
        Ok(())
    }

    async fn regenerate_chains(&mut self) -> Result<()> {
        let cands: Vec<crate::stages::chain::ChainCandidate> = self
            .ledger
            .chainable("confirmed")
            .iter()
            .map(|f| crate::stages::chain::ChainCandidate {
                signature: f.signature.clone(),
                title: f.title.clone(),
                loc: f.loc(),
                severity: f.severity.clone(),
                premise: f.exploit_premise.clone(),
                description: f.description.clone(),
            })
            .collect();
        if cands.is_empty() {
            self.status = "no confirmed findings to chain".into();
            return Ok(());
        }
        self.status = "composing chains…".into();
        let (ctx, _) = crate::context::load_context(&self.target.context_dir());
        let (chains, _, _) =
            crate::stages::chain::run_chain(&self.target, &cands, &self.model, &ctx, None, None).await?;
        crate::stages::report::write_chains(&self.target.target_dir, &chains)?;
        self.chains = chains;
        self.tab = RightTab::Chains;
        self.status = format!("composed {} chain(s)", self.chains.len());
        Ok(())
    }

    fn open_html(&mut self) -> Result<()> {
        let tmm = crate::viz::threat_model_mermaid(&self.tm.components, &self.tm.flows, &self.tm.boundaries);
        let chm = crate::viz::chains_mermaid(&self.chains);
        let html = build_html(&self.target.name, &strip_fence(&tmm), &strip_fence(&chm));
        let path = self.target.target_dir.join("dashboard.html");
        crate::lock::write_atomic(&path, html.as_bytes())?;
        let _ = crate::ui::open_path(&path);
        self.status = format!("opened {}", path.display());
        Ok(())
    }
}

fn strip_fence(s: &str) -> String {
    s.lines().filter(|l| !l.trim_start().starts_with("```")).collect::<Vec<_>>().join("\n")
}

fn build_html(name: &str, tm: &str, chains: &str) -> String {
    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>cannon — {name}</title>\
<script type=\"module\">import mermaid from 'https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.esm.min.mjs';mermaid.initialize({{startOnLoad:true,theme:'dark'}});</script>\
<style>body{{font-family:ui-sans-serif,system-ui;background:#0b0f14;color:#d7dde3;margin:2rem}}h1,h2{{color:#f0a559}}.mermaid{{background:#0f141b;padding:1rem;border-radius:8px}}</style>\
</head><body><h1>{name} — security dashboard</h1>\
<h2>Threat model</h2><pre class=\"mermaid\">{tm}</pre>\
<h2>Attack chains</h2><pre class=\"mermaid\">{chains}</pre></body></html>"
    )
}

fn row_line(f: &LedgerFinding) -> Line<'static> {
    let title: String = f.title.chars().take(34).collect();
    Line::from(vec![
        Span::styled(format!("{:<6} ", f.id), Style::default().add_modifier(Modifier::BOLD)),
        Span::styled(format!("{:<8} ", f.severity), Style::default().fg(sev_color(&f.severity))),
        Span::styled(format!("{:<14} ", f.status), Style::default().fg(status_color(&f.status))),
        Span::raw(title),
        Span::styled(format!("  {}", f.loc()), Style::default().fg(Color::DarkGray)),
    ])
}

fn detail_text(f: &LedgerFinding, source_root: &std::path::Path) -> Text<'static> {
    let mut lines: Vec<Line> = Vec::new();
    lines.push(Line::from(vec![
        Span::styled(format!("{} ", f.id), Style::default().add_modifier(Modifier::BOLD)),
        Span::styled(f.severity.clone(), Style::default().fg(sev_color(&f.severity)).add_modifier(Modifier::BOLD)),
        Span::raw("  "),
        Span::styled(f.status.clone(), Style::default().fg(status_color(&f.status))),
        Span::styled(format!(" ({})", f.triaged_by), Style::default().fg(Color::DarkGray)),
    ]));
    lines.push(Line::from(format!("{}  ·  {}", f.loc(), f.cwe.clone().unwrap_or_else(|| "—".into()))));
    if let (Some(v), Some(c)) = (&f.verifier_verdict, f.verifier_confidence) {
        lines.push(Line::from(Span::styled(format!("verifier: {v} ({c:.2}) · ×{} rounds", f.corroboration), Style::default().fg(Color::DarkGray))));
    }
    if !f.note.is_empty() {
        lines.push(Line::from(Span::styled(format!("note: {}", f.note), Style::default().fg(Color::Cyan))));
    }
    lines.push(Line::from(""));
    for l in f.description.lines().take(4) {
        lines.push(Line::from(l.to_string()));
    }
    for l in source_snippet(source_root, f) {
        lines.push(l);
    }
    Text::from(lines)
}

fn source_snippet(source_root: &std::path::Path, f: &LedgerFinding) -> Vec<Line<'static>> {
    let line = match f.line {
        Some(l) if l > 0 => l,
        _ => return Vec::new(),
    };
    let text = match std::fs::read_to_string(source_root.join(&f.file)) {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };
    let src: Vec<&str> = text.lines().collect();
    let start = line.saturating_sub(2).max(1);
    let end = (line + 3).min(src.len() as u32);
    let mut out = vec![Line::from(Span::styled("── source ──", Style::default().fg(Color::DarkGray)))];
    for n in start..=end {
        if let Some(code) = src.get((n - 1) as usize) {
            let sink = n == line;
            let style = if sink {
                Style::default().fg(Color::LightRed).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::Gray)
            };
            let marker = if sink { "▶" } else { " " };
            let code: String = code.chars().take(76).collect();
            out.push(Line::from(Span::styled(format!("{marker}{n:>4} {code}"), style)));
        }
    }
    out
}

fn draw(f: &mut Frame, app: &App) {
    let area = f.area();
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);
    let left = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(6), Constraint::Length(12)])
        .split(cols[0]);
    let right = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(6), Constraint::Length(3)])
        .split(cols[1]);

    let ordered = app.ordered();

    // Findings list
    let items: Vec<ListItem> = ordered.iter().map(|f| ListItem::new(row_line(f))).collect();
    let filt = app.filter.as_deref().map(|s| format!(" · {s}")).unwrap_or_default();
    let title = format!(" findings · {} ({}){} ", app.target.name, ordered.len(), filt);
    let list = List::new(items)
        .block(Block::bordered().title(title))
        .highlight_symbol("▶ ")
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED));
    let mut state = ListState::default();
    if !ordered.is_empty() {
        state.select(Some(app.sel.min(ordered.len() - 1)));
    }
    f.render_stateful_widget(list, left[0], &mut state);

    // Detail
    let detail = match ordered.get(app.sel) {
        Some(fd) => detail_text(fd, &app.target.source_root),
        None => Text::from("No findings yet. Run `cannon fire` first."),
    };
    f.render_widget(
        Paragraph::new(detail).block(Block::bordered().title(" detail ")).wrap(Wrap { trim: true }),
        left[1],
    );

    // Graph pane
    let sel_file = ordered.get(app.sel).map(|fd| fd.file.clone());
    let (layout, gtitle) = match app.tab {
        RightTab::Threat => (graph::threat_layout(&app.tm, sel_file.as_deref()), " threat model  (Tab→chains) "),
        RightTab::Chains => (graph::chains_layout(&app.chains), " attack chains  (Tab→threat) "),
    };
    let canvas = Canvas::default()
        .block(Block::bordered().title(gtitle))
        .marker(Marker::Braille)
        .x_bounds([0.0, graph::W])
        .y_bounds([0.0, graph::H])
        .paint(move |ctx| {
            for e in &layout.edges {
                ctx.draw(&CanvasLine { x1: e.x1, y1: e.y1, x2: e.x2, y2: e.y2, color: e.color });
            }
            for n in &layout.nodes {
                let style = if n.highlight {
                    Style::default().fg(Color::Black).bg(n.color).add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(n.color)
                };
                ctx.print(n.x, n.y, Line::from(Span::styled(n.label.clone(), style)));
            }
            if let Some(msg) = &layout.empty_msg {
                ctx.print(4.0, graph::H / 2.0, Line::from(Span::styled(msg.clone(), Style::default().fg(Color::DarkGray))));
            }
        });
    f.render_widget(canvas, right[0]);

    // Status / input bar
    let bar = match &app.mode {
        Mode::EditNote(buf) => Paragraph::new(Line::from(vec![
            Span::styled("note> ", Style::default().fg(Color::Cyan)),
            Span::raw(buf.clone()),
            Span::styled("▏", Style::default().fg(Color::Cyan)),
        ]))
        .block(Block::bordered().title(" edit note (Enter save · Esc cancel) ")),
        Mode::Normal => Paragraph::new(Line::from(Span::styled(app.status.clone(), Style::default().fg(Color::DarkGray))))
            .block(Block::bordered()),
    };
    f.render_widget(bar, right[1]);
}

async fn handle_key(app: &mut App, code: KeyCode) -> Result<()> {
    // Edit-note mode is handled with short borrows so we never hold `&mut app.mode`
    // across other `app` accesses.
    if matches!(app.mode, Mode::EditNote(_)) {
        match code {
            KeyCode::Enter => {
                let note = if let Mode::EditNote(b) = &app.mode { b.clone() } else { String::new() };
                if let Some(id) = app.selected_id() {
                    app.ledger.set_note(&id, note);
                    app.ledger.save(&app.target.target_dir)?;
                    app.status = "note saved".into();
                }
                app.mode = Mode::Normal;
            }
            KeyCode::Esc => app.mode = Mode::Normal,
            KeyCode::Backspace => {
                if let Mode::EditNote(b) = &mut app.mode {
                    b.pop();
                }
            }
            KeyCode::Char(c) => {
                if let Mode::EditNote(b) = &mut app.mode {
                    b.push(c);
                }
            }
            _ => {}
        }
        return Ok(());
    }

    match code {
        KeyCode::Char('q') | KeyCode::Esc => app.quit = true,
        KeyCode::Down | KeyCode::Char('j') => app.move_sel(1),
        KeyCode::Up | KeyCode::Char('k') => app.move_sel(-1),
        KeyCode::Char('c') => app.set_status("confirmed")?,
        KeyCode::Char('f') => app.set_status("false_positive")?,
        KeyCode::Char('a') => app.set_status("accepted")?,
        KeyCode::Char('x') => app.set_status("fixed")?,
        KeyCode::Char('e') => {
            let note = app.ordered().get(app.sel).map(|fd| fd.note.clone());
            if let Some(n) = note {
                app.mode = Mode::EditNote(n);
            }
        }
        KeyCode::Char('/') => app.cycle_filter(),
        KeyCode::Tab => {
            app.tab = if app.tab == RightTab::Threat { RightTab::Chains } else { RightTab::Threat };
        }
        KeyCode::Char('r') => app.regenerate_chains().await?,
        KeyCode::Char('g') => app.open_html()?,
        _ => {}
    }
    Ok(())
}

pub async fn run(target: &TargetConfig, model: &str) -> Result<()> {
    let mut app = App::load(target, model);
    if app.ledger.findings.is_empty() {
        println!("No findings for '{}'. Run `cannon fire {}` first.", target.name, target.name);
        return Ok(());
    }
    let mut terminal = ratatui::init();
    let res = event_loop(&mut terminal, &mut app).await;
    ratatui::restore();
    res
}

async fn event_loop(terminal: &mut DefaultTerminal, app: &mut App) -> Result<()> {
    loop {
        {
            let app_ref: &App = app;
            terminal.draw(|f| draw(f, app_ref))?;
        }
        if event::poll(Duration::from_millis(250))? {
            if let Event::Key(k) = event::read()? {
                if k.kind == KeyEventKind::Press {
                    handle_key(app, k.code).await?;
                }
            }
        }
        if app.quit {
            break;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifacts::{ChainStep, Component, DataFlow};
    use crate::ledger::LedgerFinding;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    use std::path::PathBuf;

    fn sample_app() -> App {
        let target = TargetConfig {
            name: "t".into(),
            target_dir: PathBuf::from("."),
            source_root: PathBuf::from("."),
            detector: "static_review".into(),
            language: None,
            description: None,
            focus_areas: vec![],
            engagement_context: None,
            build_command: None,
            run_command: None,
            witness: None,
        };
        let tm = ThreatModel {
            narrative: String::new(),
            components: vec![
                Component { name: "Client".into(), trust: "untrusted-input".into(), description: String::new() },
                Component { name: "API".into(), trust: "trusted-core".into(), description: String::new() },
                Component { name: "DB".into(), trust: "datastore".into(), description: String::new() },
            ],
            flows: vec![
                DataFlow { src: "Client".into(), dst: "API".into(), label: "http".into() },
                DataFlow { src: "API".into(), dst: "DB".into(), label: "sql".into() },
            ],
            boundaries: vec![],
            focus_areas: vec![],
        };
        let chains = vec![Chain {
            title: "RCE".into(),
            premise: "unauth".into(),
            steps: vec![ChainStep { signature: "s".into(), title: "x".into(), action: "inject".into() }],
            impact: "rce".into(),
            severity: "CRITICAL".into(),
        }];
        let mut ledger = Ledger { target: "t".into(), findings: vec![], next_id: 2 };
        ledger.findings.push(LedgerFinding {
            id: "F-001".into(),
            signature: "app.py:3:89".into(),
            title: "SQL injection".into(),
            severity: "CRITICAL".into(),
            cwe: Some("CWE-89".into()),
            file: "app.py".into(),
            line: Some(30),
            category: String::new(),
            description: "interpolated query".into(),
            evidence: String::new(),
            exploit_premise: String::new(),
            recommendation: String::new(),
            status: "confirmed".into(),
            triaged_by: "auto".into(),
            note: String::new(),
            corroboration: 2,
            rounds: vec![],
            verifier_verdict: Some("REAL".into()),
            verifier_confidence: Some(0.9),
            first_seen: String::new(),
            last_seen: String::new(),
            provenance: vec![],
            sources: vec!["cannon".into()],
            access_level: Some("unauthenticated_remote".into()),
            preconditions: vec![],
            reachability: None,
            claimed_severity: None,
            taint_path: vec![],
            taint_status: None,
        });
        App {
            target,
            model: "m".into(),
            ledger,
            tm,
            chains,
            sel: 0,
            filter: None,
            tab: RightTab::Threat,
            mode: Mode::Normal,
            status: String::new(),
            quit: false,
        }
    }

    #[test]
    fn renders_both_tabs_without_panic() {
        let backend = TestBackend::new(120, 40);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = sample_app();
        terminal.draw(|f| draw(f, &app)).unwrap();
        app.tab = RightTab::Chains;
        terminal.draw(|f| draw(f, &app)).unwrap();
        app.mode = Mode::EditNote("typing".into());
        terminal.draw(|f| draw(f, &app)).unwrap();
    }
}
