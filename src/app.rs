//! Application state, and the view-model that turns an [`Audit`] into rows.
//!
//! Keeping every tab behind one `TableSpec` + `Vec<ViewRow>` shape means the
//! drawing code has a single table renderer, and filtering, sorting, selection
//! and the detail popup are written once instead of eight times.

use ratatui::layout::Constraint;
use ratatui::widgets::TableState;

use crate::findings;
use crate::model::*;
use crate::parse::format_bytes;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Overview,
    Ports,
    Containers,
    Services,
    Disks,
    Dirs,
    Schedules,
    Probes,
}

impl Tab {
    pub const ALL: [Tab; 8] = [
        Tab::Overview,
        Tab::Ports,
        Tab::Containers,
        Tab::Services,
        Tab::Disks,
        Tab::Dirs,
        Tab::Schedules,
        Tab::Probes,
    ];

    pub fn title(self) -> &'static str {
        match self {
            Tab::Overview => "Overview",
            Tab::Ports => "Ports",
            Tab::Containers => "Containers",
            Tab::Services => "Services",
            Tab::Disks => "Disks",
            Tab::Dirs => "Dirs",
            Tab::Schedules => "Schedules",
            Tab::Probes => "Probes",
        }
    }

    /// Slug used by [`Finding::tab`] so a finding can jump to its evidence.
    pub fn slug(self) -> &'static str {
        match self {
            Tab::Overview => "overview",
            Tab::Ports => "listeners",
            Tab::Containers => "containers",
            Tab::Services => "services",
            Tab::Disks => "storage",
            Tab::Dirs => "dirs",
            Tab::Schedules => "schedules",
            Tab::Probes => "probes",
        }
    }

    pub fn from_slug(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|t| t.slug() == s)
    }

    /// Probes whose failure makes this tab's emptiness meaningless.
    fn probe_ids(self) -> &'static [&'static str] {
        match self {
            Tab::Ports => &["listeners"],
            Tab::Containers => &["containers"],
            Tab::Services => &["services", "unitfiles"],
            Tab::Disks => &["df"],
            Tab::Dirs => &["du"],
            Tab::Schedules => &["cron", "timers"],
            _ => &[],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tone {
    Normal,
    Good,
    Warn,
    Bad,
    Dim,
}

#[derive(Debug, Clone)]
pub struct ViewRow {
    pub cells: Vec<String>,
    pub tone: Tone,
    /// Key/value pairs for the detail popup.
    pub detail: Vec<(String, String)>,
}

impl ViewRow {
    fn new(cells: Vec<String>, tone: Tone, detail: Vec<(&str, String)>) -> Self {
        Self {
            cells,
            tone,
            detail: detail
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect(),
        }
    }

    fn matches(&self, needle: &str) -> bool {
        self.cells.iter().any(|c| c.to_lowercase().contains(needle))
            || self
                .detail
                .iter()
                .any(|(_, v)| v.to_lowercase().contains(needle))
    }
}

pub struct TableSpec {
    pub headers: Vec<&'static str>,
    pub widths: Vec<Constraint>,
    pub rows: Vec<ViewRow>,
    /// Shown in place of the table when `rows` is empty.
    pub empty: String,
}

pub struct App {
    pub audit: Audit,
    pub tab: usize,
    states: Vec<TableState>,
    pub filter: String,
    pub filter_editing: bool,
    pub detail_open: bool,
    pub detail_scroll: u16,
    pub help_open: bool,
    pub status: String,
    pub busy: bool,
    pub spinner: usize,
    pub quit: bool,
    pub source: String,
    /// Whether `r` can actually re-run the audit.
    pub live: bool,
    sort_column: Vec<Option<usize>>,
    sort_desc: Vec<bool>,
}

impl App {
    pub fn new(audit: Audit, source: String, live: bool) -> Self {
        let n = Tab::ALL.len();
        let mut states = vec![TableState::default(); n];
        for s in &mut states {
            s.select(Some(0));
        }
        Self {
            audit,
            tab: 0,
            states,
            filter: String::new(),
            filter_editing: false,
            detail_open: false,
            detail_scroll: 0,
            help_open: false,
            status: String::new(),
            busy: false,
            spinner: 0,
            quit: false,
            source,
            live,
            sort_column: vec![None; n],
            sort_desc: vec![false; n],
        }
    }

    pub fn current_tab(&self) -> Tab {
        Tab::ALL[self.tab]
    }

    pub fn state(&mut self) -> &mut TableState {
        &mut self.states[self.tab]
    }

    pub fn selected(&self) -> usize {
        self.states[self.tab].selected().unwrap_or(0)
    }

    pub fn set_tab(&mut self, tab: Tab) {
        if let Some(i) = Tab::ALL.iter().position(|t| *t == tab) {
            self.tab = i;
            self.detail_open = false;
        }
    }

    pub fn next_tab(&mut self, delta: isize) {
        let n = Tab::ALL.len() as isize;
        self.tab = ((self.tab as isize + delta).rem_euclid(n)) as usize;
        self.detail_open = false;
    }

    pub fn move_selection(&mut self, delta: isize, len: usize) {
        if len == 0 {
            self.states[self.tab].select(None);
            return;
        }
        let cur = self.states[self.tab].selected().unwrap_or(0) as isize;
        let next = (cur + delta).clamp(0, len as isize - 1);
        self.states[self.tab].select(Some(next as usize));
        self.detail_scroll = 0;
    }

    pub fn select_edge(&mut self, last: bool, len: usize) {
        if len == 0 {
            return;
        }
        self.states[self.tab].select(Some(if last { len - 1 } else { 0 }));
        self.detail_scroll = 0;
    }

    pub fn cycle_sort(&mut self, columns: usize) {
        if columns == 0 {
            return;
        }
        let i = self.tab;
        self.sort_column[i] = match self.sort_column[i] {
            None => Some(0),
            Some(c) if c + 1 < columns => Some(c + 1),
            Some(_) => None,
        };
        self.status = match self.sort_column[i] {
            Some(c) => format!("sort: column {}", c + 1),
            None => "sort: natural order".into(),
        };
    }

    pub fn toggle_sort_direction(&mut self) {
        let i = self.tab;
        self.sort_desc[i] = !self.sort_desc[i];
        self.status = format!(
            "sort: {}",
            if self.sort_desc[i] {
                "descending"
            } else {
                "ascending"
            }
        );
    }

    /// Build the current tab's table, with filter and sort applied.
    pub fn table(&self) -> TableSpec {
        let mut spec = match self.current_tab() {
            Tab::Overview => self.findings_table(),
            Tab::Ports => self.ports_table(),
            Tab::Containers => self.containers_table(),
            Tab::Services => self.services_table(),
            Tab::Disks => self.disks_table(),
            Tab::Dirs => self.dirs_table(),
            Tab::Schedules => self.schedules_table(),
            Tab::Probes => self.probes_table(),
        };

        if !self.filter.is_empty() {
            let needle = self.filter.to_lowercase();
            spec.rows.retain(|r| r.matches(&needle));
        }
        if let Some(col) = self.sort_column[self.tab] {
            let desc = self.sort_desc[self.tab];
            spec.rows.sort_by(|a, b| {
                let x = a.cells.get(col).map(String::as_str).unwrap_or("");
                let y = b.cells.get(col).map(String::as_str).unwrap_or("");
                let ord = natural_cmp(x, y);
                if desc { ord.reverse() } else { ord }
            });
        }
        spec
    }

    /// The message to show when a tab is empty: "none" and "we could not look"
    /// are very different answers.
    fn empty_message(&self, tab: Tab) -> String {
        let blind: Vec<String> = tab
            .probe_ids()
            .iter()
            .filter_map(|id| self.audit.probe(id))
            .filter(|p| !p.status.looked())
            .map(|p| {
                let why = if p.note.is_empty() {
                    p.status.label().to_string()
                } else {
                    p.note.clone()
                };
                format!("{} — {why}", p.command)
            })
            .collect();
        if blind.is_empty() {
            "nothing here".to_string()
        } else {
            format!("unknown, not empty:\n{}", blind.join("\n"))
        }
    }

    // ------------------------------------------------------------ tabs ----

    fn findings_table(&self) -> TableSpec {
        let rows = self
            .audit
            .findings
            .iter()
            .map(|f| {
                ViewRow::new(
                    vec![
                        f.severity.label().to_string(),
                        f.title.clone(),
                        f.detail.clone(),
                    ],
                    match f.severity {
                        Severity::High => Tone::Bad,
                        Severity::Medium => Tone::Warn,
                        Severity::Low => Tone::Normal,
                        Severity::Info => Tone::Dim,
                    },
                    vec![
                        ("severity", f.severity.label().to_string()),
                        ("finding", f.title.clone()),
                        ("detail", f.detail.clone()),
                        ("evidence", format!("the {} tab", f.tab)),
                    ],
                )
            })
            .collect();
        TableSpec {
            headers: vec!["", "Finding", "Detail"],
            widths: vec![
                Constraint::Length(4),
                Constraint::Max(50),
                Constraint::Fill(1),
            ],
            rows,
            empty: "nothing stood out".into(),
        }
    }

    fn ports_table(&self) -> TableSpec {
        let mut listeners: Vec<&Listener> = self.audit.listeners.iter().collect();
        listeners.sort_by_key(|l| (l.port_num().unwrap_or(u16::MAX), l.proto.clone()));
        let rows = listeners
            .into_iter()
            .map(|l| {
                let tone = match (l.exposure, l.port_num()) {
                    (Exposure::AllInterfaces, Some(p)) if findings::is_sensitive_port(p) => {
                        Tone::Bad
                    }
                    (Exposure::AllInterfaces, _) => Tone::Warn,
                    (Exposure::Loopback, _) => Tone::Dim,
                    _ => Tone::Normal,
                };
                ViewRow::new(
                    vec![
                        l.proto.clone(),
                        l.port.clone(),
                        findings::port_name(l.port_num().unwrap_or(0))
                            .unwrap_or("—")
                            .to_string(),
                        l.addr.clone(),
                        l.exposure.label().to_string(),
                        l.process.clone().unwrap_or_else(|| "?".into()),
                        l.pid.map(|p| p.to_string()).unwrap_or_else(|| "-".into()),
                    ],
                    tone,
                    vec![
                        ("endpoint", format!("{} {}", l.proto, l.endpoint())),
                        ("state", l.state.clone()),
                        ("reachable from", exposure_sentence(l.exposure)),
                        (
                            "service",
                            findings::port_name(l.port_num().unwrap_or(0))
                                .unwrap_or("not a well-known port")
                                .to_string(),
                        ),
                        ("socket owners", l.users.clone()),
                    ],
                )
            })
            .collect();
        TableSpec {
            headers: vec![
                "Proto", "Port", "Service", "Address", "Exposure", "Process", "PID",
            ],
            widths: vec![
                Constraint::Length(5),
                Constraint::Length(6),
                Constraint::Max(20),
                Constraint::Max(22),
                Constraint::Length(9),
                Constraint::Fill(1),
                Constraint::Length(6),
            ],
            rows,
            empty: self.empty_message(Tab::Ports),
        }
    }

    fn containers_table(&self) -> TableSpec {
        let rows = self
            .audit
            .containers
            .iter()
            .map(|c| {
                let tone = match c.state.as_str() {
                    "running" => Tone::Good,
                    "restarting" | "dead" => Tone::Bad,
                    "exited" if c.exit_code().is_some_and(|e| e != 0) => Tone::Warn,
                    _ => Tone::Dim,
                };
                let ports = if c.ports.is_empty() {
                    "-".to_string()
                } else {
                    c.ports
                        .iter()
                        .map(|p| p.render())
                        .collect::<Vec<_>>()
                        .join(", ")
                };
                ViewRow::new(
                    vec![
                        c.name.clone(),
                        c.state.clone(),
                        c.image.clone(),
                        c.status.clone(),
                        ports.clone(),
                    ],
                    tone,
                    vec![
                        ("name", c.name.clone()),
                        ("id", c.id.clone()),
                        ("runtime", c.runtime.clone()),
                        ("image", c.image.clone()),
                        ("state", format!("{} — {}", c.state, c.status)),
                        ("created", c.created.clone()),
                        ("ports", ports),
                        (
                            "published on 0.0.0.0",
                            if c.ports.iter().any(|p| p.is_wide_open()) {
                                "yes — these bypass ufw/firewalld".into()
                            } else {
                                "no".to_string()
                            },
                        ),
                    ],
                )
            })
            .collect();
        TableSpec {
            headers: vec!["Name", "State", "Image", "Status", "Ports"],
            widths: vec![
                Constraint::Max(22),
                Constraint::Length(11),
                Constraint::Max(34),
                Constraint::Max(24),
                Constraint::Fill(1),
            ],
            rows,
            empty: self.empty_message(Tab::Containers),
        }
    }

    fn services_table(&self) -> TableSpec {
        let enabled: Vec<&str> = self
            .audit
            .unit_files
            .iter()
            .map(|u| u.unit.as_str())
            .collect();

        let mut rows: Vec<ViewRow> = self
            .audit
            .services
            .iter()
            .map(|s| {
                let boot = if enabled.contains(&s.unit.as_str()) {
                    "enabled"
                } else {
                    "-"
                };
                ViewRow::new(
                    vec![
                        s.unit.clone(),
                        s.active.clone(),
                        s.sub.clone(),
                        boot.to_string(),
                        s.description.clone(),
                    ],
                    if s.is_failed() {
                        Tone::Bad
                    } else {
                        Tone::Normal
                    },
                    vec![
                        ("unit", s.unit.clone()),
                        ("state", format!("{} / {} / {}", s.load, s.active, s.sub)),
                        ("starts at boot", boot.to_string()),
                        ("description", s.description.clone()),
                    ],
                )
            })
            .collect();

        // Units that are enabled but are neither running nor failed never show
        // up in list-units, and they are exactly the ones worth noticing.
        let listed: Vec<&str> = self
            .audit
            .services
            .iter()
            .map(|s| s.unit.as_str())
            .collect();
        for u in &self.audit.unit_files {
            // `getty@.service` is a template: it never runs under that name.
            if listed.contains(&u.unit.as_str()) || u.unit.contains("@.") {
                continue;
            }
            rows.push(ViewRow::new(
                vec![
                    u.unit.clone(),
                    "not active".into(),
                    "-".into(),
                    u.state.clone(),
                    String::new(),
                ],
                Tone::Dim,
                vec![
                    ("unit", u.unit.clone()),
                    (
                        "state",
                        "enabled at boot, but neither running, completed nor failed right now"
                            .into(),
                    ),
                    ("preset", u.preset.clone()),
                ],
            ));
        }
        rows.sort_by(|a, b| a.cells[0].cmp(&b.cells[0]));

        TableSpec {
            headers: vec!["Unit", "Active", "Sub", "Boot", "Description"],
            widths: vec![
                Constraint::Max(34),
                Constraint::Length(9),
                Constraint::Length(9),
                Constraint::Length(8),
                Constraint::Fill(1),
            ],
            rows,
            empty: self.empty_message(Tab::Services),
        }
    }

    fn disks_table(&self) -> TableSpec {
        // Real filesystems first: a screen that opens on eight tmpfs mounts
        // buries the one number you came to read.
        let mut ordered: Vec<&Filesystem> = self.audit.filesystems.iter().collect();
        ordered.sort_by_key(|fs| (fs.is_pseudo(), fs.mount.clone()));
        let rows = ordered
            .into_iter()
            .map(|fs| {
                let pct = fs.use_pct.unwrap_or(0.0);
                let tone = if fs.is_pseudo() {
                    Tone::Dim
                } else if pct >= 90.0 {
                    Tone::Bad
                } else if pct >= 80.0 {
                    Tone::Warn
                } else {
                    Tone::Normal
                };
                ViewRow::new(
                    vec![
                        fs.mount.clone(),
                        fs.size.clone(),
                        fs.used.clone(),
                        fs.avail.clone(),
                        format!("{pct:.0}%"),
                        bar(pct / 100.0, 12),
                        fs.inode_pct
                            .map(|p| format!("{p:.0}%"))
                            .unwrap_or_else(|| "-".into()),
                        fs.fstype.clone(),
                    ],
                    tone,
                    vec![
                        ("mount", fs.mount.clone()),
                        ("device", fs.source.clone()),
                        ("type", fs.fstype.clone()),
                        (
                            "space",
                            format!("{} used of {}, {} free", fs.used, fs.size, fs.avail),
                        ),
                        (
                            "inodes",
                            fs.inode_pct
                                .map(|p| format!("{p:.0}% used"))
                                .unwrap_or_else(|| "not collected".into()),
                        ),
                    ],
                )
            })
            .collect();
        TableSpec {
            headers: vec![
                "Mounted on",
                "Size",
                "Used",
                "Avail",
                "Use%",
                "",
                "Inode%",
                "Type",
            ],
            widths: vec![
                Constraint::Max(34),
                Constraint::Length(7),
                Constraint::Length(7),
                Constraint::Length(7),
                Constraint::Length(6),
                Constraint::Length(13),
                Constraint::Length(7),
                Constraint::Fill(1),
            ],
            rows,
            empty: self.empty_message(Tab::Disks),
        }
    }

    fn dirs_table(&self) -> TableSpec {
        let max = self
            .audit
            .dir_usage
            .iter()
            .map(|d| d.bytes)
            .max()
            .unwrap_or(1)
            .max(1);
        let rows = self
            .audit
            .dir_usage
            .iter()
            .map(|d| {
                ViewRow::new(
                    vec![
                        format_bytes(d.bytes),
                        bar(d.bytes as f32 / max as f32, 20),
                        d.path.clone(),
                    ],
                    if d.bytes * 2 >= max {
                        Tone::Warn
                    } else {
                        Tone::Normal
                    },
                    vec![
                        ("path", d.path.clone()),
                        ("size", format!("{} ({} bytes)", d.human, d.bytes)),
                    ],
                )
            })
            .collect();
        TableSpec {
            headers: vec!["Size", "", "Directory"],
            widths: vec![
                Constraint::Length(8),
                Constraint::Length(21),
                Constraint::Fill(1),
            ],
            rows,
            empty: self.empty_message(Tab::Dirs),
        }
    }

    fn schedules_table(&self) -> TableSpec {
        let mut rows: Vec<ViewRow> = self
            .audit
            .cron
            .iter()
            .map(|c| {
                let risky = findings::pipes_remote_script_to_shell(&c.command);
                ViewRow::new(
                    vec![
                        c.schedule.clone(),
                        c.user.clone(),
                        c.command.clone(),
                        c.source.clone(),
                    ],
                    if risky {
                        Tone::Bad
                    } else if c.schedule == "@reboot" {
                        Tone::Warn
                    } else {
                        Tone::Normal
                    },
                    vec![
                        ("when", c.schedule.clone()),
                        ("runs as", c.user.clone()),
                        ("command", c.command.clone()),
                        ("defined in", c.source.clone()),
                    ],
                )
            })
            .collect();

        rows.extend(self.audit.timers.iter().map(|t| {
            ViewRow::new(
                vec![
                    if t.left.is_empty() {
                        "not scheduled".to_string()
                    } else {
                        format!("in {}", t.left)
                    },
                    "systemd".into(),
                    format!("{} -> {}", t.unit, t.activates),
                    "systemd timer".into(),
                ],
                if t.left.is_empty() {
                    Tone::Dim
                } else {
                    Tone::Normal
                },
                vec![
                    ("timer", t.unit.clone()),
                    ("activates", t.activates.clone()),
                    ("next run", format!("{}  (in {})", t.next, t.left)),
                    ("last run", format!("{}  ({})", t.last, t.passed)),
                ],
            )
        }));

        TableSpec {
            headers: vec!["When", "As", "What runs", "Defined in"],
            widths: vec![
                Constraint::Max(28),
                Constraint::Length(10),
                Constraint::Fill(1),
                Constraint::Max(26),
            ],
            rows,
            empty: self.empty_message(Tab::Schedules),
        }
    }

    fn probes_table(&self) -> TableSpec {
        let rows = self
            .audit
            .probes
            .iter()
            .map(|p| {
                ViewRow::new(
                    vec![
                        p.status.label().to_string(),
                        p.label.clone(),
                        p.command.clone(),
                        if p.note.is_empty() {
                            format!("{} lines", p.raw.lines().count())
                        } else {
                            p.note.clone()
                        },
                    ],
                    match p.status {
                        ProbeStatus::Ok => Tone::Good,
                        ProbeStatus::Partial | ProbeStatus::Denied => Tone::Warn,
                        ProbeStatus::Failed => Tone::Bad,
                        _ => Tone::Dim,
                    },
                    vec![
                        ("command", p.command.clone()),
                        (
                            "result",
                            format!("{} (exit {})", p.status.label(), p.exit_code),
                        ),
                        ("output", p.raw.clone()),
                    ],
                )
            })
            .collect();
        TableSpec {
            headers: vec!["Status", "Probe", "Command", "Detail"],
            widths: vec![
                Constraint::Length(8),
                Constraint::Max(18),
                Constraint::Fill(1),
                Constraint::Max(30),
            ],
            rows,
            empty: "no probes ran".into(),
        }
    }
}

fn exposure_sentence(e: Exposure) -> String {
    match e {
        Exposure::Loopback => "this machine only".into(),
        Exposure::Interface => "one specific interface".into(),
        Exposure::AllInterfaces => "every interface — anything that can route here".into(),
    }
}

/// A proportional bar drawn with eighth-block characters.
pub fn bar(fraction: f32, width: usize) -> String {
    const EIGHTHS: [char; 8] = ['▏', '▎', '▍', '▌', '▋', '▊', '▉', '█'];
    let fraction = fraction.clamp(0.0, 1.0);
    let units = (fraction * width as f32 * 8.0).round() as usize;
    let full = units / 8;
    let rest = units % 8;
    let mut s: String = "█".repeat(full.min(width));
    if full < width && rest > 0 {
        s.push(EIGHTHS[rest - 1]);
    }
    s
}

/// Chunked natural ordering: digit runs compare as numbers, everything else
/// as text. `9%` before `80%`, `web-2` before `web-10`, `4.0K` before `12G`.
fn natural_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    use std::cmp::Ordering;

    let (a, b) = (a.to_lowercase(), b.to_lowercase());
    let mut x = a.chars().peekable();
    let mut y = b.chars().peekable();
    loop {
        match (x.peek().copied(), y.peek().copied()) {
            (None, None) => return Ordering::Equal,
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (Some(cx), Some(cy)) if cx.is_ascii_digit() && cy.is_ascii_digit() => {
                match take_number(&mut x).total_cmp(&take_number(&mut y)) {
                    Ordering::Equal => {}
                    other => return other,
                }
            }
            (Some(cx), Some(cy)) => {
                x.next();
                y.next();
                match cx.cmp(&cy) {
                    Ordering::Equal => {}
                    other => return other,
                }
            }
        }
    }
}

fn take_number(it: &mut std::iter::Peekable<std::str::Chars<'_>>) -> f64 {
    let mut buf = String::new();
    while let Some(&c) = it.peek() {
        if c.is_ascii_digit() || (c == '.' && !buf.contains('.')) {
            buf.push(c);
            it.next();
        } else {
            break;
        }
    }
    buf.trim_end_matches('.').parse().unwrap_or(0.0)
}

// -------------------------------------------------------------- tests ----

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::sample_audit;

    fn app() -> App {
        App::new(sample_audit(), "ssh: web-01".into(), true)
    }

    #[test]
    fn every_tab_builds_a_table() {
        let mut a = app();
        for (i, tab) in Tab::ALL.iter().enumerate() {
            a.tab = i;
            let t = a.table();
            assert_eq!(t.headers.len(), t.widths.len(), "{}", tab.title());
            for row in &t.rows {
                assert_eq!(row.cells.len(), t.headers.len(), "{}", tab.title());
            }
        }
    }

    #[test]
    fn enabled_but_not_running_units_are_listed() {
        let mut a = app();
        a.set_tab(Tab::Services);
        let t = a.table();
        let node = t
            .rows
            .iter()
            .find(|r| r.cells[0] == "node_exporter.service")
            .expect("enabled unit missing from the services tab");
        assert_eq!(node.cells[1], "not active");
        assert_eq!(node.tone, Tone::Dim);

        let nginx = t
            .rows
            .iter()
            .find(|r| r.cells[0] == "nginx.service")
            .unwrap();
        assert_eq!(nginx.cells[3], "enabled");
    }

    #[test]
    fn exposed_datastore_ports_are_toned_worse_than_web_ports() {
        let mut a = app();
        a.set_tab(Tab::Ports);
        let t = a.table();
        let redis = t.rows.iter().find(|r| r.cells[1] == "6379").unwrap();
        let http = t.rows.iter().find(|r| r.cells[1] == "80").unwrap();
        let pg = t.rows.iter().find(|r| r.cells[1] == "5432").unwrap();
        assert_eq!(redis.tone, Tone::Bad);
        assert_eq!(http.tone, Tone::Warn);
        assert_eq!(pg.tone, Tone::Dim, "loopback postgres is not exposed");
        assert_eq!(redis.cells[2], "Redis", "the port should be named");
        assert_eq!(http.cells[2], "HTTP");
    }

    #[test]
    fn filtering_narrows_rows_and_searches_detail_too() {
        let mut a = app();
        a.set_tab(Tab::Ports);
        let all = a.table().rows.len();
        a.filter = "nginx".into();
        let filtered = a.table().rows.len();
        assert!(filtered > 0 && filtered < all);

        // "sshd" only appears in the socket-owners detail on some rows.
        a.filter = "chronyd".into();
        assert_eq!(a.table().rows.len(), 1);
    }

    #[test]
    fn sorting_cycles_columns_and_reverses() {
        let mut a = app();
        a.set_tab(Tab::Dirs);
        a.cycle_sort(3); // by Size, ascending
        let asc: Vec<String> = a.table().rows.iter().map(|r| r.cells[0].clone()).collect();
        a.toggle_sort_direction();
        let desc: Vec<String> = a.table().rows.iter().map(|r| r.cells[0].clone()).collect();
        assert_eq!(asc.len(), desc.len());
        assert_eq!(asc.first(), desc.last());
        assert_ne!(asc.first(), desc.first());
    }

    #[test]
    fn natural_order_beats_lexicographic() {
        assert_eq!(natural_cmp("9%", "80%"), std::cmp::Ordering::Less);
        assert_eq!(natural_cmp("web-2", "web-10"), std::cmp::Ordering::Less);
        assert_eq!(natural_cmp("alpha", "beta"), std::cmp::Ordering::Less);
        assert_eq!(natural_cmp("4.0K", "12G"), std::cmp::Ordering::Less);
        assert_eq!(
            natural_cmp("nginx.service", "nginx.service"),
            std::cmp::Ordering::Equal
        );
    }

    #[test]
    fn an_empty_tab_says_whether_it_looked() {
        let mut audit = sample_audit();
        audit.containers.clear();
        audit.probes = vec![crate::fixtures::probe(
            "containers",
            "Containers",
            "docker ps -a",
            ProbeStatus::Denied,
        )];
        let mut a = App::new(audit, "x".into(), false);
        a.set_tab(Tab::Containers);
        let msg = a.table().empty;
        assert!(msg.contains("unknown, not empty"));
        assert!(msg.contains("permission denied"));

        // Ran fine and found nothing: that really is "nothing here".
        let mut audit = sample_audit();
        audit.containers.clear();
        audit.probes[0].status = ProbeStatus::Empty;
        let mut a = App::new(audit, "x".into(), false);
        a.set_tab(Tab::Containers);
        assert_eq!(a.table().empty, "nothing here");
    }

    #[test]
    fn findings_can_point_at_the_tab_holding_their_evidence() {
        let a = app();
        for f in &a.audit.findings {
            assert!(
                Tab::from_slug(&f.tab).is_some(),
                "finding {:?} points at unknown tab {:?}",
                f.title,
                f.tab
            );
        }
    }

    #[test]
    fn selection_stays_in_range() {
        let mut a = app();
        a.set_tab(Tab::Ports);
        a.move_selection(500, 9);
        assert_eq!(a.selected(), 8);
        a.move_selection(-500, 9);
        assert_eq!(a.selected(), 0);
        a.move_selection(1, 0);
        assert_eq!(a.state().selected(), None);
    }

    #[test]
    fn bars_stay_inside_their_width() {
        assert_eq!(bar(0.0, 10).chars().count(), 0);
        assert_eq!(bar(1.0, 10).chars().count(), 10);
        assert!(bar(2.0, 10).chars().count() <= 10);
        assert!(bar(0.5, 10).chars().count() <= 10);
    }
}
