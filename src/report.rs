//! Non-interactive renderings of an audit: plain text for a terminal, Markdown
//! for a ticket or a pull request, JSON for anything else.

use std::fmt::Write as _;

use crate::model::*;
use crate::parse::format_bytes;

pub fn json(a: &Audit) -> String {
    serde_json::to_string_pretty(a).unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"))
}

pub fn text(a: &Audit) -> String {
    render(a, Flavor::Text)
}

pub fn markdown(a: &Audit) -> String {
    render(a, Flavor::Markdown)
}

#[derive(Clone, Copy, PartialEq)]
enum Flavor {
    Text,
    Markdown,
}

impl Flavor {
    fn h1(self, s: &str) -> String {
        match self {
            Self::Markdown => format!("# {s}\n"),
            Self::Text => format!("{s}\n{}\n", "=".repeat(s.len())),
        }
    }
    fn h2(self, s: &str) -> String {
        match self {
            Self::Markdown => format!("\n## {s}\n"),
            Self::Text => format!("\n{s}\n{}\n", "-".repeat(s.len())),
        }
    }
    fn bullet(self, s: &str) -> String {
        match self {
            Self::Markdown => format!("- {s}\n"),
            Self::Text => format!("  * {s}\n"),
        }
    }
    fn code(self, s: &str) -> String {
        match self {
            Self::Markdown => format!("`{s}`"),
            Self::Text => s.to_string(),
        }
    }
}

fn render(a: &Audit, f: Flavor) -> String {
    let mut o = String::new();
    let host = if a.host.hostname.is_empty() {
        a.target.clone()
    } else {
        a.host.hostname.clone()
    };
    o.push_str(&f.h1(&format!("Server audit — {host}")));
    let _ = writeln!(
        o,
        "{}",
        [
            format!("target: {}", a.target),
            format!("collected: {}", a.collected_at),
            format!("as: {} ({})", a.host.user, a.host.sudo.label()),
        ]
        .join("  |  ")
    );

    section_host(a, f, &mut o);
    section_findings(a, f, &mut o);
    section_listeners(a, f, &mut o);
    section_containers(a, f, &mut o);
    section_services(a, f, &mut o);
    section_storage(a, f, &mut o);
    section_schedules(a, f, &mut o);
    section_probes(a, f, &mut o);
    o
}

/// A section whose probe did not succeed must say "unknown", never "none".
fn blind_note(a: &Audit, ids: &[&str], f: Flavor, o: &mut String) -> bool {
    let bad: Vec<&ProbeOutcome> = ids
        .iter()
        .filter_map(|id| a.probe(id))
        .filter(|p| !p.status.looked())
        .collect();
    if bad.is_empty() {
        return false;
    }
    for p in bad {
        o.push_str(&f.bullet(&format!(
            "not collected ({}): {}",
            p.status.label(),
            if p.note.is_empty() {
                p.command.clone()
            } else {
                p.note.clone()
            }
        )));
    }
    true
}

fn section_host(a: &Audit, f: Flavor, o: &mut String) {
    o.push_str(&f.h2("Host"));
    let h = &a.host;
    for (k, v) in [
        ("hostname", h.hostname.as_str()),
        ("os", h.os.as_str()),
        ("kernel", h.kernel.as_str()),
        ("arch", h.arch.as_str()),
        ("virt", h.virt.as_str()),
        ("uptime", h.uptime.as_str()),
        ("cpus", h.cpus.as_str()),
        ("load", h.load.as_str()),
    ] {
        if !v.is_empty() {
            o.push_str(&f.bullet(&format!("{k}: {v}")));
        }
    }
    if let (Some(t), Some(u)) = (h.mem_total_mb, h.mem_used_mb) {
        o.push_str(&f.bullet(&format!("memory: {u} MB used of {t} MB")));
    }
}

fn section_findings(a: &Audit, f: Flavor, o: &mut String) {
    o.push_str(&f.h2(&format!("Findings ({})", a.findings.len())));
    if a.findings.is_empty() {
        o.push_str(&f.bullet("nothing stood out"));
        return;
    }
    for finding in &a.findings {
        o.push_str(&f.bullet(&format!(
            "**{}** {} — {}",
            finding.severity.label(),
            finding.title,
            finding.detail
        )));
    }
}

fn section_listeners(a: &Audit, f: Flavor, o: &mut String) {
    o.push_str(&f.h2(&format!("Listening sockets ({})", a.listeners.len())));
    if blind_note(a, &["listeners"], f, o) {
        return;
    }
    let mut rows: Vec<&Listener> = a.listeners.iter().collect();
    rows.sort_by_key(|l| (l.port_num().unwrap_or(u16::MAX), l.proto.clone()));
    for l in rows {
        o.push_str(&f.bullet(&format!(
            "{:<4} {:<24} {:<6} {}",
            l.proto,
            f.code(&l.endpoint()),
            l.exposure.label(),
            l.process.as_deref().unwrap_or("?")
        )));
    }
}

fn section_containers(a: &Audit, f: Flavor, o: &mut String) {
    o.push_str(&f.h2(&format!("Containers ({})", a.containers.len())));
    if blind_note(a, &["containers"], f, o) {
        return;
    }
    for c in &a.containers {
        let ports = if c.ports.is_empty() {
            "-".to_string()
        } else {
            c.ports
                .iter()
                .map(|p| p.render())
                .collect::<Vec<_>>()
                .join(", ")
        };
        o.push_str(&f.bullet(&format!(
            "{} [{}] {} — {} — {}",
            c.name, c.state, c.image, c.status, ports
        )));
    }
}

fn section_services(a: &Audit, f: Flavor, o: &mut String) {
    o.push_str(&f.h2(&format!(
        "Services ({} running, completed or failed)",
        a.services.len()
    )));
    if !blind_note(a, &["services"], f, o) {
        for s in &a.services {
            o.push_str(&f.bullet(&format!(
                "{} [{}/{}] {}",
                s.unit, s.active, s.sub, s.description
            )));
        }
    }

    o.push_str(&f.h2(&format!("Enabled at boot ({})", a.unit_files.len())));
    if !blind_note(a, &["unitfiles"], f, o) {
        let active: Vec<&str> = a.services.iter().map(|s| s.unit.as_str()).collect();
        for u in &a.unit_files {
            // `getty@.service` is a template; it never runs under that name.
            let mark = if active.contains(&u.unit.as_str()) || u.unit.contains("@.") {
                ""
            } else {
                "  (inactive)"
            };
            o.push_str(&f.bullet(&format!("{}{mark}", u.unit)));
        }
    }
}

fn section_storage(a: &Audit, f: Flavor, o: &mut String) {
    o.push_str(&f.h2("Filesystems"));
    if !blind_note(a, &["df"], f, o) {
        for fs in &a.filesystems {
            let inodes = match fs.inode_pct {
                Some(p) => format!(", inodes {p:.0}%"),
                None => String::new(),
            };
            o.push_str(&f.bullet(&format!(
                "{:<28} {:>6} used of {:>6} ({}%{inodes}) on {} [{}]",
                fs.mount,
                fs.used,
                fs.size,
                fs.use_pct.map(|p| format!("{p:.0}")).unwrap_or("?".into()),
                fs.source,
                fs.fstype
            )));
        }
    }

    o.push_str(&f.h2("Largest directories"));
    if !blind_note(a, &["du"], f, o) {
        for d in a.dir_usage.iter().take(25) {
            o.push_str(&f.bullet(&format!("{:>7}  {}", format_bytes(d.bytes), d.path)));
        }
    }
}

fn section_schedules(a: &Audit, f: Flavor, o: &mut String) {
    o.push_str(&f.h2(&format!("Cron ({})", a.cron.len())));
    if !blind_note(a, &["cron"], f, o) {
        for c in &a.cron {
            o.push_str(&f.bullet(&format!(
                "{:<16} {:<10} {}   [{}]",
                c.schedule, c.user, c.command, c.source
            )));
        }
    }

    o.push_str(&f.h2(&format!("Systemd timers ({})", a.timers.len())));
    if !blind_note(a, &["timers"], f, o) {
        for t in &a.timers {
            o.push_str(&f.bullet(&format!(
                "{:<30} next in {}, last {} -> {}",
                t.unit,
                if t.left.is_empty() {
                    "never".to_string()
                } else {
                    format!("{} ({})", t.left, t.next)
                },
                t.passed,
                t.activates
            )));
        }
    }
}

fn section_probes(a: &Audit, f: Flavor, o: &mut String) {
    o.push_str(&f.h2("Probes"));
    for p in &a.probes {
        let note = if p.note.is_empty() {
            String::new()
        } else {
            format!(" — {}", p.note)
        };
        o.push_str(&f.bullet(&format!(
            "{:<8} {} ({}){note}",
            p.status.label(),
            f.code(&p.command),
            p.label
        )));
    }
}

// -------------------------------------------------------------- tests ----

#[cfg(test)]
mod tests {
    use super::*;

    fn audit() -> Audit {
        let mut a = crate::fixtures::sample_audit();
        a.containers.clear();
        a.probes = vec![crate::fixtures::probe(
            "containers",
            "Containers",
            "docker ps -a",
            ProbeStatus::Denied,
        )];
        a.findings = crate::findings::analyze(&a);
        a
    }

    #[test]
    fn markdown_covers_every_section() {
        let md = markdown(&audit());
        for heading in [
            "# Server audit",
            "## Host",
            "## Findings",
            "## Listening sockets",
            "## Containers",
            "## Services",
            "## Filesystems",
            "## Cron",
            "## Probes",
        ] {
            assert!(md.contains(heading), "missing {heading}");
        }
        assert!(md.contains("web-01.fra.acme.internal"));
    }

    #[test]
    fn a_denied_probe_reads_as_unknown_not_as_none() {
        let md = markdown(&audit());
        let containers = md.split("## Containers").nth(1).unwrap();
        assert!(containers.contains("not collected (denied)"));
    }

    /// A file written by an older build, or trimmed by hand, must still open:
    /// every field falls back to its default rather than failing the load.
    #[test]
    fn a_partial_audit_file_still_loads() {
        let minimal: Audit = serde_json::from_str(r#"{"target":"web-01"}"#).unwrap();
        assert_eq!(minimal.target, "web-01");
        assert!(minimal.listeners.is_empty());
        assert_eq!(minimal.schema, SCHEMA_VERSION);
        assert!(text(&minimal).contains("Server audit"));

        let no_host: Audit =
            serde_json::from_str(r#"{"target":"x","host":{},"probes":[]}"#).unwrap();
        assert_eq!(no_host.host.hostname, "");
        assert!(markdown(&no_host).contains("## Host"));
    }

    #[test]
    fn json_round_trips() {
        let a = audit();
        let restored: Audit = serde_json::from_str(&json(&a)).unwrap();
        assert_eq!(restored.target, a.target);
        assert_eq!(restored.listeners.len(), a.listeners.len());
        assert_eq!(restored.findings.len(), a.findings.len());
        assert_eq!(restored.schema, a.schema);
    }

    #[test]
    fn text_flavour_has_underlines_and_no_markdown_code_ticks() {
        let t = text(&audit());
        assert!(t.contains("-----"));
        assert!(!t.contains("`docker ps -a`"));
    }
}
