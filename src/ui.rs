//! All drawing. One generic table renderer plus a header, a footer and three
//! overlays; every tab reuses them through [`App::table`].

use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Flex, Layout, Margin, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{
    Block, BorderType, Borders, Cell, Clear, Padding, Paragraph, Row, Table, Tabs, Wrap,
};

use crate::app::{App, Tab, Tone};
use crate::model::{Severity, SudoAvailability};

// A small palette, chosen so the tool stays readable on light and dark
// terminals: everything is either a named ANSI colour the terminal themes
// itself, or plain default foreground.
const ACCENT: Color = Color::Cyan;
const BAD: Color = Color::Red;
const WARN: Color = Color::Yellow;
const GOOD: Color = Color::Green;
const MUTED: Color = Color::DarkGray;

fn tone_style(tone: Tone) -> Style {
    match tone {
        Tone::Normal => Style::default(),
        Tone::Good => Style::default().fg(GOOD),
        Tone::Warn => Style::default().fg(WARN),
        Tone::Bad => Style::default().fg(BAD).add_modifier(Modifier::BOLD),
        Tone::Dim => Style::default().fg(MUTED),
    }
}

pub fn draw(f: &mut Frame, app: &mut App) {
    let [header, body, footer] = Layout::vertical([
        Constraint::Length(5),
        Constraint::Min(3),
        Constraint::Length(1),
    ])
    .areas(f.area());

    draw_header(f, app, header);
    if app.current_tab() == Tab::Overview {
        let [tiles, list] =
            Layout::vertical([Constraint::Length(5), Constraint::Min(3)]).areas(body);
        draw_tiles(f, app, tiles);
        draw_table(f, app, list);
    } else {
        draw_table(f, app, body);
    }
    draw_footer(f, app, footer);

    if app.detail_open {
        draw_detail(f, app);
    }
    if app.help_open {
        draw_help(f);
    }
}

// ------------------------------------------------------------- header ----

fn draw_header(f: &mut Frame, app: &mut App, area: Rect) {
    let [title, tabs] =
        Layout::vertical([Constraint::Length(4), Constraint::Length(1)]).areas(area);

    let h = &app.audit.host;
    let name = if h.hostname.is_empty() {
        app.audit.target.clone()
    } else {
        h.hostname.clone()
    };

    let sudo_style = match h.sudo {
        SudoAvailability::Root | SudoAvailability::Passwordless => Style::default().fg(GOOD),
        SudoAvailability::NeedsPassword => Style::default().fg(WARN),
        SudoAvailability::NotRequested => Style::default().fg(MUTED),
    };

    let mut facts = vec![
        Span::styled(name, Style::default().fg(ACCENT).bold()),
        Span::raw("  "),
        Span::styled(
            if h.os.is_empty() { "—" } else { &h.os },
            Style::default().fg(MUTED),
        ),
    ];
    if !h.kernel.is_empty() {
        facts.push(Span::styled(
            format!("  {}", h.kernel),
            Style::default().fg(MUTED),
        ));
    }

    // The target may already carry a login name; the remote `id -un` is the
    // authoritative one, so keep that and drop the duplicate prefix.
    let where_ = app
        .audit
        .target
        .rsplit('@')
        .next()
        .unwrap_or(&app.audit.target);
    let mut second = vec![
        Span::styled(format!("{}@{where_}", h.user), Style::default().fg(MUTED)),
        Span::raw("  "),
        Span::styled(h.sudo.label(), sudo_style),
    ];
    for (label, value) in [
        ("up", h.uptime.as_str()),
        ("load", h.load.as_str()),
        ("cpus", h.cpus.as_str()),
    ] {
        if !value.is_empty() {
            second.push(Span::styled(
                format!("  {label} {value}"),
                Style::default().fg(MUTED),
            ));
        }
    }
    if !app.source.is_empty() {
        second.push(Span::styled(
            format!("  · {}", app.source),
            Style::default().fg(MUTED),
        ));
    }
    if app.busy {
        const SPIN: [&str; 8] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧"];
        second.push(Span::styled(
            format!("  {} collecting…", SPIN[app.spinner % SPIN.len()]),
            Style::default().fg(ACCENT),
        ));
    }

    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(MUTED))
        .padding(Padding::horizontal(1));
    f.render_widget(
        Paragraph::new(vec![Line::from(facts), Line::from(second)]).block(block),
        title,
    );

    let titles: Vec<Line> = Tab::ALL
        .iter()
        .enumerate()
        .map(|(i, t)| {
            Line::from(vec![
                Span::styled(format!("{} ", i + 1), Style::default().fg(MUTED)),
                Span::raw(t.title()),
            ])
        })
        .collect();
    f.render_widget(
        Tabs::new(titles)
            .select(app.tab)
            .divider(Span::styled("│", Style::default().fg(MUTED)))
            .highlight_style(Style::default().fg(ACCENT).bold()),
        tabs.inner(Margin::new(1, 0)),
    );
}

// -------------------------------------------------------------- tiles ----

fn draw_tiles(f: &mut Frame, app: &App, area: Rect) {
    let a = &app.audit;
    let worst = a.findings.first().map(|f| f.severity);
    let counts = |s: Severity| a.findings.iter().filter(|f| f.severity == s).count();

    let root_pct = a
        .filesystems
        .iter()
        .filter(|fs| !fs.is_pseudo())
        .filter_map(|fs| fs.use_pct.map(|p| (p, fs.mount.clone())))
        .max_by(|x, y| x.0.total_cmp(&y.0));

    let exposed = a
        .listeners
        .iter()
        .filter(|l| l.exposure == crate::model::Exposure::AllInterfaces)
        .count();

    let tiles = [
        Tile {
            label: "FINDINGS",
            value: format!("{}", a.findings.len()),
            note: format!(
                "{} high · {} med",
                counts(Severity::High),
                counts(Severity::Medium)
            ),
            color: match worst {
                Some(Severity::High) => BAD,
                Some(Severity::Medium) => WARN,
                Some(_) => ACCENT,
                None => GOOD,
            },
        },
        Tile {
            label: "LISTENING",
            value: format!("{}", a.listeners.len()),
            note: format!("{exposed} on all ifaces"),
            color: if exposed > 0 { WARN } else { GOOD },
        },
        Tile {
            label: "CONTAINERS",
            value: format!(
                "{}/{}",
                a.containers.iter().filter(|c| c.is_running()).count(),
                a.containers.len()
            ),
            note: "running / total".into(),
            color: ACCENT,
        },
        Tile {
            label: "SERVICES",
            value: format!("{}", a.services.len()),
            note: format!("{} enabled at boot", a.unit_files.len()),
            color: ACCENT,
        },
        Tile {
            label: "FULLEST DISK",
            value: root_pct
                .as_ref()
                .map(|(p, _)| format!("{p:.0}%"))
                .unwrap_or_else(|| "—".into()),
            note: root_pct
                .as_ref()
                .map(|(_, m)| m.clone())
                .unwrap_or_else(|| "not collected".into()),
            color: match root_pct.as_ref().map(|(p, _)| *p) {
                Some(p) if p >= 90.0 => BAD,
                Some(p) if p >= 80.0 => WARN,
                Some(_) => GOOD,
                None => MUTED,
            },
        },
        Tile {
            label: "SCHEDULED",
            value: format!("{}", a.cron.len() + a.timers.len()),
            note: format!("{} cron · {} timers", a.cron.len(), a.timers.len()),
            color: ACCENT,
        },
    ];

    let areas = Layout::horizontal([Constraint::Ratio(1, tiles.len() as u32); 6]).split(area);
    for (tile, rect) in tiles.iter().zip(areas.iter()) {
        f.render_widget(tile.widget(), *rect);
    }
}

struct Tile {
    label: &'static str,
    value: String,
    note: String,
    color: Color,
}

impl Tile {
    fn widget(&self) -> Paragraph<'_> {
        Paragraph::new(vec![
            Line::from(Span::styled(
                self.label,
                Style::default().fg(MUTED).add_modifier(Modifier::BOLD),
            )),
            Line::from(Span::styled(
                self.value.clone(),
                Style::default().fg(self.color).bold(),
            )),
            Line::from(Span::styled(self.note.clone(), Style::default().fg(MUTED))),
        ])
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(MUTED))
                .padding(Padding::horizontal(1)),
        )
    }
}

// -------------------------------------------------------------- table ----

fn draw_table(f: &mut Frame, app: &mut App, area: Rect) {
    let spec = app.table();
    let tab = app.current_tab();
    let total = spec.rows.len();

    // Keep the selection inside the filtered set.
    let selected = app.selected().min(total.saturating_sub(1));
    app.state()
        .select(if total == 0 { None } else { Some(selected) });

    let title = if app.filter.is_empty() {
        format!(" {} ({total}) ", tab.title())
    } else {
        format!(" {} ({total} matching “{}”) ", tab.title(), app.filter)
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(MUTED))
        .title(Span::styled(title, Style::default().fg(ACCENT)));

    if total == 0 {
        f.render_widget(
            Paragraph::new(Text::from(spec.empty.clone()))
                .style(Style::default().fg(MUTED))
                .wrap(Wrap { trim: true })
                .block(block.padding(Padding::uniform(1))),
            area,
        );
        return;
    }

    let header = Row::new(
        spec.headers
            .iter()
            .map(|h| Cell::from(Span::styled(*h, Style::default().fg(MUTED).bold()))),
    )
    .height(1);

    let rows: Vec<Row> = spec
        .rows
        .iter()
        .map(|r| {
            Row::new(
                r.cells
                    .iter()
                    .map(|c| Cell::from(Span::raw(c.clone())))
                    .collect::<Vec<_>>(),
            )
            .style(tone_style(r.tone))
        })
        .collect();

    let table = Table::new(rows, spec.widths.clone())
        .header(header)
        .column_spacing(1)
        .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED))
        .highlight_symbol("")
        .block(block);

    f.render_stateful_widget(table, area, app.state());
}

// ------------------------------------------------------------- footer ----

fn draw_footer(f: &mut Frame, app: &App, area: Rect) {
    if app.filter_editing {
        f.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(" filter ", Style::default().bg(ACCENT).fg(Color::Black)),
                Span::raw(" "),
                Span::raw(app.filter.clone()),
                Span::styled("▏", Style::default().fg(ACCENT)),
                Span::styled(
                    "   enter to apply · esc to clear",
                    Style::default().fg(MUTED),
                ),
            ])),
            area,
        );
        return;
    }

    let keys: &[(&str, &str)] = &[
        ("↹/1-8", "tab"),
        ("↑↓", "move"),
        ("⏎", "detail"),
        ("/", "filter"),
        ("s/S", "sort"),
        ("r", "refresh"),
        ("e", "export"),
        ("?", "help"),
        ("q", "quit"),
    ];
    let mut spans: Vec<Span> = Vec::new();
    for (k, v) in keys {
        // `r` cannot re-run an audit that was replayed from a file.
        let enabled = *k != "r" || app.live;
        spans.push(Span::styled(
            format!(" {k}"),
            if enabled {
                Style::default().fg(ACCENT).bold()
            } else {
                Style::default().fg(MUTED)
            },
        ));
        spans.push(Span::styled(format!(" {v} "), Style::default().fg(MUTED)));
    }
    if !app.status.is_empty() {
        spans.push(Span::styled(
            format!("  {}", app.status),
            Style::default().fg(GOOD),
        ));
    }
    f.render_widget(Paragraph::new(Line::from(spans)), area);
}

// ----------------------------------------------------------- overlays ----

fn popup(area: Rect, width_pct: u16, height_pct: u16) -> Rect {
    let [h] = Layout::horizontal([Constraint::Percentage(width_pct)])
        .flex(Flex::Center)
        .areas(area);
    let [v] = Layout::vertical([Constraint::Percentage(height_pct)])
        .flex(Flex::Center)
        .areas(h);
    v
}

fn draw_detail(f: &mut Frame, app: &mut App) {
    let spec = app.table();
    let Some(row) = spec.rows.get(app.selected()) else {
        return;
    };

    let mut lines: Vec<Line> = Vec::new();
    for (key, value) in &row.detail {
        if value.trim().is_empty() {
            continue;
        }
        lines.push(Line::from(Span::styled(
            key.to_uppercase(),
            Style::default().fg(MUTED).bold(),
        )));
        for l in value.lines() {
            lines.push(Line::from(Span::raw(l.to_string())));
        }
        lines.push(Line::raw(""));
    }

    let area = popup(f.area(), 78, 70);
    f.render_widget(Clear, area);
    f.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .scroll((app.detail_scroll, 0))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_type(BorderType::Rounded)
                    .border_style(Style::default().fg(ACCENT))
                    .padding(Padding::uniform(1))
                    .title(Span::styled(" detail ", Style::default().fg(ACCENT)))
                    .title_bottom(Span::styled(
                        " ↑↓ scroll · esc close ",
                        Style::default().fg(MUTED),
                    )),
            ),
        area,
    );
}

fn draw_help(f: &mut Frame) {
    const HELP: &[(&str, &str)] = &[
        ("1 – 8, ← →, tab", "switch tab"),
        ("↑ ↓ / j k", "move selection"),
        ("pgup / pgdn", "page"),
        ("g / G", "first / last row"),
        ("enter", "open the detail pane for the selected row"),
        ("/", "filter rows (matches hidden detail too)"),
        ("esc", "close overlay, or clear the filter"),
        ("s", "cycle the sort column"),
        ("S", "reverse the sort"),
        ("r", "re-run the audit over the same ssh connection"),
        ("e", "export audit.json and audit.md next to you"),
        ("?", "this help"),
        ("q", "quit"),
    ];

    let mut lines = vec![
        Line::from(Span::styled("srvaudit", Style::default().fg(ACCENT).bold())),
        Line::from(Span::styled(
            "what is listening · what is running · where the data is · what starts on its own",
            Style::default().fg(MUTED),
        )),
        Line::raw(""),
    ];
    for (k, v) in HELP {
        lines.push(Line::from(vec![
            Span::styled(format!("{k:<18}"), Style::default().fg(ACCENT)),
            Span::raw(*v),
        ]));
    }
    lines.push(Line::raw(""));
    lines.push(Line::from(Span::styled(
        "Colours: red = act on this · yellow = check it · grey = informational only.",
        Style::default().fg(MUTED),
    )));

    let area = popup(f.area(), 66, 66);
    f.render_widget(Clear, area);
    f.render_widget(
        Paragraph::new(lines).wrap(Wrap { trim: false }).block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(ACCENT))
                .padding(Padding::uniform(1))
                .title_alignment(Alignment::Center)
                .title(Span::styled(" keys ", Style::default().fg(ACCENT))),
        ),
        area,
    );
}

// -------------------------------------------------------------- tests ----

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::sample_audit;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    fn render_at(app: &mut App, w: u16, h: u16) -> String {
        let mut terminal = Terminal::new(TestBackend::new(w, h)).unwrap();
        terminal.draw(|f| draw(f, app)).unwrap();
        terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|c| c.symbol())
            .collect()
    }

    /// A panic here is the whole point: layout maths that underflows on a
    /// narrow terminal is the classic way a TUI dies in the field.
    #[test]
    fn every_tab_renders_at_every_plausible_size() {
        let mut app = App::new(sample_audit(), "ssh: web-01".into(), true);
        for (w, h) in [(200, 60), (120, 40), (80, 24), (40, 12), (20, 6), (8, 3)] {
            for i in 0..Tab::ALL.len() {
                app.tab = i;
                app.detail_open = false;
                app.help_open = false;
                render_at(&mut app, w, h);

                app.detail_open = true;
                render_at(&mut app, w, h);

                app.detail_open = false;
                app.help_open = true;
                render_at(&mut app, w, h);
            }
        }
    }

    #[test]
    fn overview_shows_the_host_and_the_tiles() {
        let mut app = App::new(sample_audit(), "ssh: web-01".into(), true);
        let screen = render_at(&mut app, 160, 44);
        assert!(screen.contains("web-01.fra.acme.internal"));
        assert!(screen.contains("FINDINGS"));
        assert!(screen.contains("FULLEST DISK"));
        assert!(screen.contains("Ubuntu 24.04.2 LTS"));
    }

    #[test]
    fn filter_state_is_visible_in_the_title_and_footer() {
        let mut app = App::new(sample_audit(), "x".into(), true);
        app.set_tab(Tab::Ports);
        app.filter = "nginx".into();
        assert!(render_at(&mut app, 160, 30).contains("matching"));

        app.filter_editing = true;
        assert!(render_at(&mut app, 160, 30).contains("enter to apply"));
    }

    #[test]
    fn an_empty_filtered_table_explains_itself_instead_of_going_blank() {
        let mut app = App::new(sample_audit(), "x".into(), true);
        app.set_tab(Tab::Ports);
        app.filter = "zzzz-no-such-thing".into();
        let screen = render_at(&mut app, 160, 30);
        assert!(screen.contains("0 matching"));
    }

    #[test]
    fn the_login_name_is_not_printed_twice() {
        let mut audit = sample_audit();
        audit.target = "nick@192.168.64.50".into();
        audit.host.user = "nick".into();
        let mut app = App::new(audit, String::new(), true);
        let screen = render_at(&mut app, 160, 30);
        assert!(screen.contains("nick@192.168.64.50"));
        assert!(!screen.contains("nick@nick@"));
    }

    #[test]
    fn busy_state_shows_the_spinner() {
        let mut app = App::new(sample_audit(), "x".into(), true);
        app.busy = true;
        assert!(render_at(&mut app, 160, 30).contains("collecting"));
    }
}
