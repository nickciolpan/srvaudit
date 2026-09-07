//! srvaudit — a terminal audit dashboard for a remote Linux server.
//!
//! One SSH connection, one shell script, five questions:
//! what is listening, what containers exist, what services run, where the disk
//! went, and what starts on its own.

mod app;
mod cli;
mod findings;
#[cfg(test)]
mod fixtures;
mod model;
mod parse;
mod probe;
mod report;
mod ssh;
mod ui;

use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use clap::Parser;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use tokio::sync::mpsc;

use crate::app::{App, Tab};
use crate::cli::{Cli, ReportFormat};
use crate::model::{Audit, ProbeStatus};
use crate::probe::CollectOptions;
use crate::ssh::Session;

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("srvaudit: {e:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<()> {
    let cli = Cli::parse();
    let opts = cli.collect_options();

    let (audit, session) = match &cli.from_json {
        Some(path) => {
            let text = std::fs::read_to_string(path)
                .with_context(|| format!("reading {}", path.display()))?;
            let audit: Audit = serde_json::from_str(&text)
                .with_context(|| format!("{} is not a srvaudit JSON export", path.display()))?;
            (audit, None)
        }
        None => {
            let session = Session::open(cli.ssh_target()?);
            eprintln!("srvaudit → {}", session.target.label());
            eprintln!("  · opening ssh connection (any passphrase or 2FA prompt appears here)");
            let audit = collect(&session, &opts, cli.timeout).await?;
            eprintln!("  · {}", summarise(&audit));
            (audit, Some(Arc::new(session)))
        }
    };

    let result = match cli.effective_report() {
        Some(format) => emit_report(&cli, &audit, format),
        None => {
            let source = match &cli.from_json {
                Some(p) => format!(
                    "replayed from {}",
                    p.file_name().unwrap_or(p.as_os_str()).to_string_lossy()
                ),
                None => String::new(),
            };
            let mut app = App::new(audit, source, session.is_some());
            tui(&mut app, session.clone(), opts, cli.timeout).await
        }
    };

    if let Some(s) = session {
        s.close().await;
    }
    result
}

// --------------------------------------------------------- collection ----

async fn collect(session: &Session, opts: &CollectOptions, timeout: u64) -> Result<Audit> {
    let specs = probe::specs(opts);
    let nonce = probe::nonce();
    let script = probe::build_script(opts, &specs, &nonce);

    let started = Instant::now();
    let run = session.run(&script, Duration::from_secs(timeout)).await?;
    let sections = probe::split_sections(&run.stdout, &nonce);

    if sections.is_empty() {
        let hint = run.stderr.trim();
        bail!(
            "no audit data came back from {}{}{}",
            session.target.label(),
            match run.code {
                Some(c) => format!(" (ssh exited {c})"),
                None => String::new(),
            },
            if hint.is_empty() {
                String::new()
            } else {
                format!("\n{hint}")
            }
        );
    }

    Ok(probe::assemble(
        &session.target.label(),
        &specs,
        &sections,
        started.elapsed().as_millis() as u64,
    ))
}

fn summarise(a: &Audit) -> String {
    let count = |s: ProbeStatus| a.probes.iter().filter(|p| p.status == s).count();
    let mut parts = vec![format!(
        "collected in {:.1}s — {} probes ok",
        a.duration_ms as f64 / 1000.0,
        count(ProbeStatus::Ok)
    )];
    for (status, word) in [
        (ProbeStatus::Denied, "denied"),
        (ProbeStatus::Unsupported, "unavailable"),
        (ProbeStatus::Failed, "failed"),
    ] {
        let n = count(status);
        if n > 0 {
            parts.push(format!("{n} {word}"));
        }
    }
    parts.push(format!("{} findings", a.findings.len()));
    parts.join(", ")
}

// ------------------------------------------------------------- report ----

fn emit_report(cli: &Cli, audit: &Audit, format: ReportFormat) -> Result<()> {
    let body = match format {
        ReportFormat::Text => report::text(audit),
        ReportFormat::Markdown => report::markdown(audit),
        ReportFormat::Json => report::json(audit),
    };
    match &cli.out {
        Some(path) => {
            std::fs::write(path, &body).with_context(|| format!("writing {}", path.display()))?;
            eprintln!("  · wrote {}", path.display());
        }
        None => println!("{body}"),
    }
    Ok(())
}

// ---------------------------------------------------------------- tui ----

enum Ev {
    Input(Event),
    Tick,
    Collected(Box<Result<Audit, String>>),
}

async fn tui(
    app: &mut App,
    session: Option<Arc<Session>>,
    opts: CollectOptions,
    timeout: u64,
) -> Result<()> {
    let (tx, mut rx) = mpsc::channel::<Ev>(64);

    let input_tx = tx.clone();
    std::thread::spawn(move || {
        loop {
            let ev = match event::poll(Duration::from_millis(150)) {
                Ok(true) => match event::read() {
                    Ok(e) => Ev::Input(e),
                    Err(_) => break,
                },
                Ok(false) => Ev::Tick,
                Err(_) => break,
            };
            if input_tx.blocking_send(ev).is_err() {
                break;
            }
        }
    });

    let mut terminal = ratatui::init();
    let outcome = loop {
        if let Err(e) = terminal.draw(|f| ui::draw(f, app)) {
            break Err(e.into());
        }
        let Some(ev) = rx.recv().await else {
            break Ok(());
        };
        match ev {
            Ev::Tick => app.spinner = app.spinner.wrapping_add(1),
            Ev::Input(Event::Key(key)) if key.kind != KeyEventKind::Release => {
                handle_key(app, key, &session, &opts, timeout, &tx);
            }
            Ev::Input(_) => {}
            Ev::Collected(result) => {
                app.busy = false;
                match *result {
                    Ok(audit) => {
                        app.status = format!("refreshed — {}", summarise(&audit));
                        app.audit = audit;
                    }
                    Err(e) => app.status = format!("refresh failed: {e}"),
                }
            }
        }
        if app.quit {
            break Ok(());
        }
    };
    ratatui::restore();
    outcome
}

fn handle_key(
    app: &mut App,
    key: KeyEvent,
    session: &Option<Arc<Session>>,
    opts: &CollectOptions,
    timeout: u64,
    tx: &mpsc::Sender<Ev>,
) {
    // Overlays and the filter box swallow keys before anything else sees them.
    if app.help_open {
        app.help_open = false;
        return;
    }
    if app.filter_editing {
        match key.code {
            KeyCode::Enter => app.filter_editing = false,
            KeyCode::Esc => {
                app.filter.clear();
                app.filter_editing = false;
            }
            KeyCode::Backspace => {
                app.filter.pop();
            }
            KeyCode::Char(c) => app.filter.push(c),
            _ => {}
        }
        return;
    }
    if app.detail_open {
        match key.code {
            KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') => {
                app.detail_open = false;
                app.detail_scroll = 0;
            }
            KeyCode::Down | KeyCode::Char('j') => {
                app.detail_scroll = app.detail_scroll.saturating_add(1)
            }
            KeyCode::Up | KeyCode::Char('k') => {
                app.detail_scroll = app.detail_scroll.saturating_sub(1)
            }
            KeyCode::PageDown => app.detail_scroll = app.detail_scroll.saturating_add(10),
            KeyCode::PageUp => app.detail_scroll = app.detail_scroll.saturating_sub(10),
            _ => {}
        }
        return;
    }

    let table = app.table();
    let len = table.rows.len();
    let columns = table.headers.len();

    match key.code {
        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => app.quit = true,
        KeyCode::Char('q') => app.quit = true,
        KeyCode::Esc => {
            if app.filter.is_empty() {
                app.quit = true;
            } else {
                app.filter.clear();
            }
        }
        KeyCode::Char('?') => app.help_open = true,

        KeyCode::Tab | KeyCode::Right | KeyCode::Char('l') => app.next_tab(1),
        KeyCode::BackTab | KeyCode::Left | KeyCode::Char('h') => app.next_tab(-1),
        KeyCode::Char(c @ '1'..='8') => {
            let i = c as usize - '1' as usize;
            if i < Tab::ALL.len() {
                app.set_tab(Tab::ALL[i]);
            }
        }

        KeyCode::Down | KeyCode::Char('j') => app.move_selection(1, len),
        KeyCode::Up | KeyCode::Char('k') => app.move_selection(-1, len),
        KeyCode::PageDown => app.move_selection(10, len),
        KeyCode::PageUp => app.move_selection(-10, len),
        KeyCode::Home | KeyCode::Char('g') => app.select_edge(false, len),
        KeyCode::End | KeyCode::Char('G') => app.select_edge(true, len),

        KeyCode::Enter => {
            if len > 0 {
                // On the Overview a finding is a signpost: jump to its evidence.
                if app.current_tab() == Tab::Overview
                    && let Some(tab) = app
                        .audit
                        .findings
                        .get(app.selected())
                        .and_then(|f| Tab::from_slug(&f.tab))
                        .filter(|t| *t != Tab::Overview)
                {
                    app.set_tab(tab);
                    app.status = format!("jumped to {}", tab.title());
                    return;
                }
                app.detail_open = true;
                app.detail_scroll = 0;
            }
        }

        KeyCode::Char('/') => {
            app.filter_editing = true;
            app.status.clear();
        }
        KeyCode::Char('s') => app.cycle_sort(columns),
        KeyCode::Char('S') => app.toggle_sort_direction(),

        KeyCode::Char('e') => match export(app) {
            Ok(msg) => app.status = msg,
            Err(e) => app.status = format!("export failed: {e:#}"),
        },

        KeyCode::Char('r') => match session {
            Some(s) if !app.busy => {
                app.busy = true;
                app.status = "re-running probes…".into();
                let (s, opts, tx) = (s.clone(), opts.clone(), tx.clone());
                tokio::spawn(async move {
                    let r = collect(&s, &opts, timeout)
                        .await
                        .map_err(|e| format!("{e:#}"));
                    let _ = tx.send(Ev::Collected(Box::new(r))).await;
                });
            }
            Some(_) => {}
            None => app.status = "this audit was loaded from a file — nothing to refresh".into(),
        },
        _ => {}
    }
}

fn export(app: &mut App) -> Result<String> {
    let stem = format!(
        "srvaudit-{}-{}",
        slug(&app.audit.target),
        chrono::Local::now().format("%Y%m%d-%H%M%S")
    );
    let json = format!("{stem}.json");
    let md = format!("{stem}.md");
    std::fs::write(&json, report::json(&app.audit)).with_context(|| format!("writing {json}"))?;
    std::fs::write(&md, report::markdown(&app.audit)).with_context(|| format!("writing {md}"))?;
    Ok(format!("wrote {json} and {md}"))
}

fn slug(s: &str) -> String {
    let out: String = s
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    out.trim_matches('-').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn export_names_are_filesystem_safe() {
        assert_eq!(
            slug("deploy@web-01.acme.io:2222"),
            "deploy-web-01-acme-io-2222"
        );
        assert_eq!(slug("///"), "");
    }

    #[test]
    fn summary_counts_every_probe_outcome() {
        let mut a = Audit {
            duration_ms: 2400,
            ..Default::default()
        };
        for (id, status) in [
            ("a", ProbeStatus::Ok),
            ("b", ProbeStatus::Ok),
            ("c", ProbeStatus::Denied),
            ("d", ProbeStatus::Unsupported),
        ] {
            a.probes.push(model::ProbeOutcome {
                id: id.into(),
                label: id.into(),
                command: id.into(),
                status,
                exit_code: 0,
                note: String::new(),
                raw: String::new(),
            });
        }
        let s = summarise(&a);
        assert!(s.contains("2.4s"));
        assert!(s.contains("2 probes ok"));
        assert!(s.contains("1 denied"));
        assert!(s.contains("1 unavailable"));
        assert!(!s.contains("failed"));
    }
}
