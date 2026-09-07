//! Parsers for the raw output of each remote command.
//!
//! Every parser is total: it skips lines it does not understand rather than
//! failing the whole audit, because one weird line on one distro should never
//! cost you the other five sections.

use crate::model::*;

/// Split a line into `n` leading whitespace-separated tokens plus a remainder.
/// Returns `None` when the line has fewer than `n` tokens.
fn head_tail(line: &str, n: usize) -> Option<(Vec<&str>, String)> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < n {
        return None;
    }
    let tail = parts[n..].join(" ");
    Some((parts[..n].to_vec(), tail))
}

fn is_header(line: &str, first_word: &str) -> bool {
    line.split_whitespace().next() == Some(first_word)
}

// ---------------------------------------------------------------- host ----

pub fn parse_host(raw: &str) -> HostInfo {
    let mut h = HostInfo::default();
    for line in raw.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim().to_string();
        match key.trim() {
            "HOSTNAME" => h.hostname = value,
            "OS" => h.os = value,
            "KERNEL" => h.kernel = value,
            "ARCH" => h.arch = value,
            // `uptime -p` already says "up 3 days"; the UI adds its own label.
            "UPTIME" => h.uptime = value.trim_start_matches("up ").to_string(),
            "CPUS" => h.cpus = value,
            "LOAD" => h.load = value,
            "MEMTOTAL" => h.mem_total_mb = value.parse().ok(),
            "MEMUSED" => h.mem_used_mb = value.parse().ok(),
            "USER" => h.user = value,
            "VIRT" => h.virt = value,
            "SUDO" => {
                h.sudo = match value.as_str() {
                    "root" => SudoAvailability::Root,
                    "passwordless" => SudoAvailability::Passwordless,
                    "needs-password" => SudoAvailability::NeedsPassword,
                    _ => SudoAvailability::NotRequested,
                }
            }
            _ => {}
        }
    }
    h
}

// ----------------------------------------------------------- listeners ----

/// Dispatch on the header line: `ss` prints `Netid`/`State`, `netstat` prints
/// `Proto`.
pub fn parse_listeners(raw: &str) -> Vec<Listener> {
    let looks_like_netstat = raw
        .lines()
        .any(|l| is_header(l, "Proto") && l.contains("Local Address"));
    if looks_like_netstat {
        parse_netstat(raw)
    } else {
        parse_ss(raw)
    }
}

pub fn parse_ss(raw: &str) -> Vec<Listener> {
    let mut out = Vec::new();
    for line in raw.lines() {
        let line = line.trim_end();
        if line.is_empty() || is_header(line, "Netid") || is_header(line, "State") {
            continue;
        }
        let Some((head, tail)) = head_tail(line, 6) else {
            continue;
        };
        let (proto, state, local) = (head[0], head[1], head[4]);
        if !matches!(proto, "tcp" | "udp" | "tcp6" | "udp6" | "raw" | "sctp") {
            continue;
        }
        let (addr, port) = split_endpoint(local);
        let (process, pid, users) = parse_ss_users(&tail);
        out.push(Listener {
            proto: proto.to_string(),
            state: state.to_string(),
            exposure: classify_exposure(&addr),
            addr,
            port,
            process,
            pid,
            users,
        });
    }
    out
}

pub fn parse_netstat(raw: &str) -> Vec<Listener> {
    let mut out = Vec::new();
    for line in raw.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 6 {
            continue;
        }
        let proto = parts[0];
        if !proto.starts_with("tcp") && !proto.starts_with("udp") {
            continue;
        }
        let is_udp = proto.starts_with("udp");
        // `netstat -l` omits the State column for UDP rows.
        let (state, program) = if is_udp {
            ("UNCONN".to_string(), parts[5..].join(" "))
        } else {
            (parts[5].to_string(), parts[6..].join(" "))
        };
        let (addr, port) = split_endpoint(parts[3]);
        let (process, pid) = parse_netstat_program(&program);
        out.push(Listener {
            proto: proto.to_string(),
            state,
            exposure: classify_exposure(&addr),
            addr,
            port,
            process,
            pid,
            users: program,
        });
    }
    out
}

/// Split `0.0.0.0:443`, `[::]:22`, `:::443` or `10.0.3.7%eth0:9100`.
fn split_endpoint(s: &str) -> (String, String) {
    match s.rsplit_once(':') {
        Some((addr, port)) => (addr.to_string(), port.to_string()),
        None => (s.to_string(), String::new()),
    }
}

fn classify_exposure(addr: &str) -> Exposure {
    let a = addr.trim_start_matches('[').trim_end_matches(']');
    let a = a.split('%').next().unwrap_or(a);
    match a {
        "0.0.0.0" | "::" | "*" | "" => Exposure::AllInterfaces,
        "::1" => Exposure::Loopback,
        _ if a.starts_with("127.") => Exposure::Loopback,
        _ => Exposure::Interface,
    }
}

/// Pull names and pids out of `users:(("nginx",pid=901,fd=6),("nginx",pid=900,fd=6))`.
fn parse_ss_users(s: &str) -> (Option<String>, Option<u32>, String) {
    let mut names: Vec<String> = Vec::new();
    let mut first_pid = None;
    let mut cursor = 0usize;

    while let Some(rel) = s[cursor..].find("(\"") {
        let name_start = cursor + rel + 2;
        let Some(rel_end) = s[name_start..].find('"') else {
            break;
        };
        let name_end = name_start + rel_end;
        let name = &s[name_start..name_end];

        // The pid for this entry lives before the closing paren of the entry.
        let entry_end = s[name_end..]
            .find(')')
            .map(|e| name_end + e)
            .unwrap_or(s.len());
        if let Some(p) = s[name_end..entry_end].find("pid=") {
            let ds = name_end + p + 4;
            let de = s[ds..]
                .find(|c: char| !c.is_ascii_digit())
                .map(|e| ds + e)
                .unwrap_or(s.len());
            if first_pid.is_none() {
                first_pid = s[ds..de].parse::<u32>().ok();
            }
        }

        if !name.is_empty() && !names.iter().any(|n| n == name) {
            names.push(name.to_string());
        }
        cursor = entry_end.max(name_end + 1);
    }

    let process = names.first().cloned();
    (process, first_pid, s.trim().to_string())
}

/// `801/sshd`, `901/nginx: master p`, or `-` when we lack permission.
fn parse_netstat_program(s: &str) -> (Option<String>, Option<u32>) {
    let s = s.trim();
    if s.is_empty() || s == "-" {
        return (None, None);
    }
    match s.split_once('/') {
        Some((pid, name)) => {
            let name = name.split(':').next().unwrap_or(name).trim();
            (
                (!name.is_empty()).then(|| name.to_string()),
                pid.trim().parse().ok(),
            )
        }
        None => (Some(s.to_string()), None),
    }
}

// ---------------------------------------------------------- containers ----

/// Parses the tab-separated `--format` output we ask docker/podman for.
pub fn parse_containers(raw: &str, runtime: &str) -> Vec<Container> {
    let mut out = Vec::new();
    for line in raw.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let f: Vec<&str> = line.split('\t').collect();
        if f.len() < 7 {
            continue;
        }
        let ports_raw = f[5].trim().to_string();
        out.push(Container {
            runtime: runtime.to_string(),
            id: f[0].trim().to_string(),
            image: f[1].trim().to_string(),
            name: f[2].trim().to_string(),
            state: f[3].trim().to_lowercase(),
            status: f[4].trim().to_string(),
            ports: parse_port_mappings(&ports_raw),
            ports_raw,
            created: f[6].trim().to_string(),
        });
    }
    out
}

/// `0.0.0.0:5432->5432/tcp, :::5432->5432/tcp` or bare `8080/tcp`.
pub fn parse_port_mappings(raw: &str) -> Vec<PortMapping> {
    let mut out = Vec::new();
    for chunk in raw.split(',') {
        let chunk = chunk.trim();
        if chunk.is_empty() {
            continue;
        }
        let (host, container) = match chunk.split_once("->") {
            Some((h, c)) => (Some(h.trim()), c.trim()),
            None => (None, chunk),
        };
        let (container_port, proto) = match container.rsplit_once('/') {
            Some((p, pr)) => (p.to_string(), pr.to_string()),
            None => (container.to_string(), "tcp".to_string()),
        };
        let (host_ip, host_port) = match host {
            Some(h) => {
                let (ip, port) = split_endpoint(h);
                (ip, port)
            }
            None => (String::new(), String::new()),
        };
        out.push(PortMapping {
            host_ip,
            host_port,
            container_port,
            proto,
        });
    }
    out
}

// ------------------------------------------------------------ systemd ----

pub fn parse_services(raw: &str) -> Vec<Service> {
    let mut out = Vec::new();
    for line in raw.lines() {
        // `--plain` drops the bullet, but be forgiving if someone drops it.
        let line = line.trim_start_matches(['●', '*', '\u{25cf}']).trim();
        if line.is_empty() || is_header(line, "UNIT") {
            continue;
        }
        let Some((head, desc)) = head_tail(line, 4) else {
            continue;
        };
        if !head[0].ends_with(".service") {
            continue;
        }
        out.push(Service {
            unit: head[0].to_string(),
            load: head[1].to_string(),
            active: head[2].to_string(),
            sub: head[3].to_string(),
            description: desc,
        });
    }
    out
}

pub fn parse_unit_files(raw: &str) -> Vec<UnitFile> {
    let mut out = Vec::new();
    for line in raw.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 || !parts[0].ends_with(".service") {
            continue;
        }
        out.push(UnitFile {
            unit: parts[0].to_string(),
            state: parts[1].to_string(),
            preset: parts.get(2).copied().unwrap_or("-").to_string(),
        });
    }
    out
}

/// `list-timers` has four space-containing columns before the unit name, and
/// systemd changed the format along the way: it used to print `5h left`, and
/// since v25x it prints a bare `2h 10min`. Splitting on the word "left" only
/// worked on the old one. Anchor on the timestamps instead — under `LC_ALL=C`
/// they are always `Www YYYY-MM-DD HH:MM:SS TZ` — and read the columns around
/// them.
pub fn parse_timers(raw: &str) -> Vec<Timer> {
    let mut out = Vec::new();
    for line in raw.lines() {
        let t: Vec<&str> = line.split_whitespace().collect();
        let Some(unit_idx) = t.iter().position(|x| x.ends_with(".timer")) else {
            continue;
        };
        let head = &t[..unit_idx];

        // Non-overlapping timestamp starts: at most NEXT and LAST.
        let mut stamps: Vec<usize> = Vec::new();
        for i in 0..head.len() {
            if timestamp_at(head, i) && stamps.last().is_none_or(|&p| i >= p + 4) {
                stamps.push(i);
            }
        }
        let (next_i, last_i) = match stamps.as_slice() {
            [a, b, ..] => (Some(*a), Some(*b)),
            // A single timestamp is NEXT if it leads, otherwise it is LAST.
            [a] if *a == 0 => (Some(0), None),
            [a] => (None, Some(*a)),
            [] => (None, None),
        };

        let stamp = |i: Option<usize>| match i {
            Some(i) => head[i..i + 4].join(" "),
            None => "-".to_string(),
        };
        let span = |from: usize, to: usize| {
            let (from, to) = (from.min(head.len()), to.min(head.len()));
            if from >= to {
                String::new()
            } else {
                gap_text(&head[from..to])
            }
        };

        out.push(Timer {
            unit: head_unit(t[unit_idx]),
            activates: t[unit_idx + 1..].join(" "),
            next: stamp(next_i),
            left: span(next_i.map_or(0, |i| i + 4), last_i.unwrap_or(head.len())),
            last: stamp(last_i),
            passed: span(last_i.map_or(head.len(), |i| i + 4), head.len()),
        });
    }
    out
}

fn head_unit(s: &str) -> String {
    s.to_string()
}

/// Four tokens starting at `i` that look like `Mon 2026-09-07 06:26:44 EDT`.
fn timestamp_at(t: &[&str], i: usize) -> bool {
    if i + 4 > t.len() {
        return false;
    }
    let weekday = t[i].len() == 3 && t[i].chars().all(|c| c.is_ascii_alphabetic());
    let date = t[i + 1].len() == 10
        && t[i + 1].as_bytes()[4] == b'-'
        && t[i + 1].as_bytes()[7] == b'-'
        && t[i + 1].chars().filter(char::is_ascii_digit).count() == 8;
    let clock =
        t[i + 2].len() == 8 && t[i + 2].as_bytes()[2] == b':' && t[i + 2].as_bytes()[5] == b':';
    let zone = !t[i + 3].is_empty()
        && t[i + 3]
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '-');
    weekday && date && clock && zone
}

/// Join a LEFT/PASSED column, dropping placeholders and the old `left` suffix
/// so both systemd generations read the same.
fn gap_text(tokens: &[&str]) -> String {
    tokens
        .iter()
        .filter(|t| !matches!(**t, "-" | "n/a" | "left" | "*"))
        .copied()
        .collect::<Vec<_>>()
        .join(" ")
}

// ------------------------------------------------------------ storage ----

pub fn parse_df(raw: &str) -> Vec<Filesystem> {
    // `df -T` is not POSIX; on busybox and friends we fall back to `df -hP`,
    // which has no Type column. Decide from the header rather than guessing.
    let has_type = raw
        .lines()
        .find(|l| is_header(l, "Filesystem"))
        .map(|h| h.split_whitespace().any(|t| t == "Type"))
        .unwrap_or(true);
    let lead = if has_type { 6 } else { 5 };

    let mut out = Vec::new();
    for line in raw.lines() {
        if is_header(line, "Filesystem") {
            continue;
        }
        let Some((head, mount)) = head_tail(line, lead) else {
            continue;
        };
        if mount.is_empty() {
            continue;
        }
        let mut col = head.iter().skip(1);
        let fstype = if has_type {
            col.next().copied().unwrap_or("-").to_string()
        } else {
            "-".to_string()
        };
        out.push(Filesystem {
            source: head[0].to_string(),
            fstype,
            size: col.next().copied().unwrap_or("-").to_string(),
            used: col.next().copied().unwrap_or("-").to_string(),
            avail: col.next().copied().unwrap_or("-").to_string(),
            use_pct: col.next().and_then(|v| parse_pct(v)),
            inode_pct: None,
            mount,
        });
    }
    out
}

/// Fold `df -iP` output into filesystems already parsed from `df -hPT`.
pub fn merge_inodes(filesystems: &mut [Filesystem], raw: &str) {
    for line in raw.lines() {
        if is_header(line, "Filesystem") {
            continue;
        }
        let Some((head, mount)) = head_tail(line, 5) else {
            continue;
        };
        let pct = parse_pct(head[4]);
        if let Some(fs) = filesystems.iter_mut().find(|f| f.mount == mount) {
            fs.inode_pct = pct;
        }
    }
}

fn parse_pct(s: &str) -> Option<f32> {
    s.trim().trim_end_matches('%').parse().ok()
}

pub fn parse_du(raw: &str) -> Vec<DirUsage> {
    let mut out = Vec::new();
    for line in raw.lines() {
        let (size, path) = match line.split_once('\t') {
            Some((s, p)) => (s.trim(), p.trim()),
            None => match head_tail(line, 1) {
                Some((head, tail)) if !tail.is_empty() => {
                    out.push(DirUsage {
                        bytes: human_to_bytes(head[0]).unwrap_or(0),
                        human: head[0].to_string(),
                        path: tail,
                    });
                    continue;
                }
                _ => continue,
            },
        };
        if path.is_empty() || path.contains('*') {
            continue;
        }
        out.push(DirUsage {
            bytes: human_to_bytes(size).unwrap_or(0),
            human: size.to_string(),
            path: path.to_string(),
        });
    }
    out.sort_by_key(|d| std::cmp::Reverse(d.bytes));
    out
}

/// `12G` / `1.5M` / `4.0K` / `0` -> bytes. `du -h` uses powers of 1024.
pub fn human_to_bytes(s: &str) -> Option<u64> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let (num, suffix) = match s.find(|c: char| c.is_ascii_alphabetic()) {
        Some(i) => (&s[..i], &s[i..]),
        None => (s, ""),
    };
    let value: f64 = num.parse().ok()?;
    let mult: f64 = match suffix.chars().next().map(|c| c.to_ascii_uppercase()) {
        None => 1.0,
        Some('B') => 1.0,
        Some('K') => 1024.0,
        Some('M') => 1024f64.powi(2),
        Some('G') => 1024f64.powi(3),
        Some('T') => 1024f64.powi(4),
        Some('P') => 1024f64.powi(5),
        Some(_) => return None,
    };
    Some((value * mult) as u64)
}

pub fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 6] = ["B", "K", "M", "G", "T", "P"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes}B")
    } else if value < 10.0 {
        format!("{value:.1}{}", UNITS[unit])
    } else {
        format!("{value:.0}{}", UNITS[unit])
    }
}

// --------------------------------------------------------- scheduling ----

/// Parses the `##SRC <source>` stream the cron probe emits.
pub fn parse_cron(raw: &str) -> Vec<CronEntry> {
    let mut out = Vec::new();
    let mut source = String::new();

    for line in raw.lines() {
        if let Some(rest) = line.strip_prefix("##SRC ") {
            source = rest.trim().to_string();
            continue;
        }
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || source.is_empty() {
            continue;
        }

        if let Some(dir) = source.strip_prefix("dir:") {
            // run-parts drop-ins: the filename *is* the job.
            if line.contains('/') || line.contains(' ') {
                continue;
            }
            out.push(CronEntry {
                source: dir.to_string(),
                schedule: format!("@{}", cadence_of(dir)),
                user: "root".into(),
                command: format!("{dir}/{line}"),
            });
            continue;
        }

        if is_env_assignment(line) {
            continue;
        }

        // /etc/crontab and /etc/cron.d/* carry a user column; user crontabs do not.
        let has_user_column = source.starts_with('/');
        let Some(entry) = parse_cron_line(line, has_user_column) else {
            continue;
        };
        let user = if has_user_column {
            entry.1
        } else {
            source.strip_prefix("crontab:").unwrap_or("?").to_string()
        };
        out.push(CronEntry {
            source: source.clone(),
            schedule: entry.0,
            user,
            command: entry.2,
        });
    }
    out
}

fn cadence_of(dir: &str) -> &'static str {
    match dir.rsplit('.').next().unwrap_or("") {
        "hourly" => "hourly",
        "weekly" => "weekly",
        "monthly" => "monthly",
        _ => "daily",
    }
}

fn is_env_assignment(line: &str) -> bool {
    let Some((lhs, _)) = line.split_once('=') else {
        return false;
    };
    !lhs.is_empty()
        && !lhs.contains(char::is_whitespace)
        && lhs.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        && lhs.chars().next().is_some_and(|c| !c.is_ascii_digit())
}

/// Returns `(schedule, user, command)`; `user` is empty when not applicable.
fn parse_cron_line(line: &str, has_user_column: bool) -> Option<(String, String, String)> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    let schedule_fields = if line.starts_with('@') { 1 } else { 5 };
    let min_fields = schedule_fields + usize::from(has_user_column) + 1;
    if parts.len() < min_fields {
        return None;
    }
    if schedule_fields == 5 && !parts[..5].iter().all(|f| looks_like_cron_field(f)) {
        return None;
    }
    let schedule = parts[..schedule_fields].join(" ");
    let mut idx = schedule_fields;
    let user = if has_user_column {
        idx += 1;
        parts[idx - 1].to_string()
    } else {
        String::new()
    };
    Some((schedule, user, parts[idx..].join(" ")))
}

fn looks_like_cron_field(f: &str) -> bool {
    !f.is_empty()
        && f.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '*' | '/' | ',' | '-'))
        && f.chars().any(|c| c == '*' || c.is_ascii_digit())
}

// -------------------------------------------------------------- tests ----

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ss_output() {
        let l = parse_ss(include_str!("../testdata/ss.txt"));
        assert_eq!(l.len(), 9);

        let pg = l.iter().find(|x| x.port == "5432").unwrap();
        assert_eq!(pg.process.as_deref(), Some("postgres"));
        assert_eq!(pg.pid, Some(1104));
        assert_eq!(pg.exposure, Exposure::Loopback);

        let http = l.iter().find(|x| x.port == "80").unwrap();
        assert_eq!(http.exposure, Exposure::AllInterfaces);
        assert_eq!(http.process.as_deref(), Some("nginx"));

        let ssh = l.iter().find(|x| x.port == "22").unwrap();
        assert_eq!(ssh.addr, "[::]");
        assert_eq!(ssh.exposure, Exposure::AllInterfaces);

        // No `users:(...)` at all: process must be unknown, not fabricated.
        let node = l.iter().find(|x| x.port == "9100").unwrap();
        assert_eq!(node.process, None);
        assert_eq!(node.addr, "10.0.3.7%eth0");
        assert_eq!(node.exposure, Exposure::Interface);

        assert_eq!(l.iter().filter(|x| x.proto == "udp").count(), 2);
    }

    #[test]
    fn netstat_fallback_including_stateless_udp_rows() {
        let l = parse_listeners(include_str!("../testdata/netstat.txt"));
        assert_eq!(l.len(), 4);

        let mysql = l.iter().find(|x| x.port == "3306").unwrap();
        assert_eq!(mysql.process.as_deref(), Some("mysqld"));
        assert_eq!(mysql.pid, Some(1201));
        assert_eq!(mysql.exposure, Exposure::Loopback);

        let tls = l.iter().find(|x| x.port == "443").unwrap();
        assert_eq!(tls.addr, "::");
        assert_eq!(tls.process.as_deref(), Some("nginx"));

        let udp = l.iter().find(|x| x.proto == "udp").unwrap();
        assert_eq!(udp.state, "UNCONN");
        assert_eq!(udp.process.as_deref(), Some("dhclient"));
    }

    #[test]
    fn docker_output() {
        let c = parse_containers(include_str!("../testdata/docker.txt"), "docker");
        assert_eq!(c.len(), 5);

        let pg = c.iter().find(|x| x.name == "pg-main").unwrap();
        assert!(pg.is_running());
        assert_eq!(pg.ports.len(), 2);
        assert!(pg.ports[0].is_wide_open());

        let cache = c.iter().find(|x| x.name == "cache").unwrap();
        assert!(!cache.ports[0].is_wide_open());

        let api = c.iter().find(|x| x.name == "api").unwrap();
        assert_eq!(api.state, "restarting");
        assert_eq!(api.ports[0].host_port, "");
        assert_eq!(api.ports[0].container_port, "8080");

        let once = c.iter().find(|x| x.name == "migrate-once").unwrap();
        assert_eq!(once.exit_code(), Some(137));
        assert!(once.ports.is_empty());
    }

    #[test]
    fn systemd_units() {
        let s = parse_services(include_str!("../testdata/services.txt"));
        assert_eq!(s.len(), 6);
        assert_eq!(s.iter().filter(|x| x.is_failed()).count(), 1);
        let nginx = s.iter().find(|x| x.unit == "nginx.service").unwrap();
        assert_eq!(
            nginx.description,
            "A high performance web server and a reverse proxy server"
        );

        let uf = parse_unit_files(include_str!("../testdata/unitfiles.txt"));
        assert_eq!(uf.len(), 5);
        assert_eq!(uf[0].preset, "enabled");
    }

    #[test]
    fn timers_old_systemd_format_with_the_word_left() {
        let t = parse_timers(include_str!("../testdata/timers.txt"));
        assert_eq!(t.len(), 3);
        assert_eq!(t[0].unit, "logrotate.timer");
        assert_eq!(t[0].activates, "logrotate.service");
        assert_eq!(t[0].next, "Mon 2026-09-08 00:00:00 UTC");
        assert_eq!(t[0].left, "7h", "the word `left` is stripped");
        assert_eq!(t[0].last, "Sun 2026-09-07 00:00:11 UTC");
        assert_eq!(t[0].passed, "16h ago");

        // `n/a  n/a  Sat …  1 day ago` — no next run, only a last one.
        assert_eq!(t[2].unit, "fstrim.timer");
        assert_eq!(t[2].next, "-");
        assert_eq!(t[2].left, "");
        assert_eq!(t[2].last, "Sat 2026-09-06 03:10:01 UTC");
        assert_eq!(t[2].passed, "1 day ago");
    }

    /// Captured from Debian 13 / systemd 257, which prints `2h 10min` with no
    /// "left" anywhere. The old parser folded all four columns into one string.
    #[test]
    fn timers_modern_systemd_format_without_it() {
        let t = parse_timers(include_str!("../testdata/timers-systemd257.txt"));
        assert_eq!(t.len(), 8);

        let first = &t[0];
        assert_eq!(first.unit, "apt-daily-upgrade.timer");
        assert_eq!(first.activates, "apt-daily-upgrade.service");
        assert_eq!(first.next, "Mon 2026-09-07 06:26:44 EDT");
        assert_eq!(first.left, "2h 10min");
        assert_eq!(first.last, "Mon 2026-09-07 01:21:56 EDT");
        assert_eq!(first.passed, "2h 54min ago");

        // A single-token LEFT, and a two-token one, must both survive.
        let daily = t.iter().find(|x| x.unit == "apt-daily.timer").unwrap();
        assert_eq!(daily.left, "11h");
        let man = t.iter().find(|x| x.unit == "man-db.timer").unwrap();
        assert_eq!(man.left, "1 day 5h");
        assert_eq!(man.next, "Tue 2026-09-08 09:56:40 EDT");
    }

    #[test]
    fn disk_usage() {
        let mut fs = parse_df(include_str!("../testdata/df.txt"));
        assert_eq!(fs.len(), 6);
        merge_inodes(&mut fs, include_str!("../testdata/inodes.txt"));

        let root = fs.iter().find(|f| f.mount == "/").unwrap();
        assert_eq!(root.use_pct, Some(96.0));
        assert_eq!(root.inode_pct, Some(94.0));
        assert!(!root.is_pseudo());

        assert!(fs.iter().find(|f| f.fstype == "tmpfs").unwrap().is_pseudo());
        assert!(
            fs.iter()
                .find(|f| f.source == "/dev/loop3")
                .unwrap()
                .is_pseudo()
        );
    }

    #[test]
    fn df_without_a_type_column() {
        let raw = "Filesystem      Size  Used Avail Use% Mounted on\n\
                   /dev/sda1       100G   91G  4.2G  96% /\n";
        let fs = parse_df(raw);
        assert_eq!(fs.len(), 1);
        assert_eq!(fs[0].fstype, "-");
        assert_eq!(fs[0].size, "100G");
        assert_eq!(fs[0].use_pct, Some(96.0));
        assert_eq!(fs[0].mount, "/");
    }

    #[test]
    fn du_sorts_biggest_first() {
        let d = parse_du(include_str!("../testdata/du.txt"));
        assert_eq!(d.len(), 6);
        assert_eq!(d[0].path, "/var/lib/postgresql");
        assert_eq!(d[1].path, "/var/lib/docker");
        assert_eq!(d[0].bytes, 118 * 1024 * 1024 * 1024);
        assert_eq!(d.last().unwrap().bytes, 0);
    }

    #[test]
    fn byte_helpers_round_trip() {
        assert_eq!(human_to_bytes("4.0K"), Some(4096));
        assert_eq!(human_to_bytes("0"), Some(0));
        assert_eq!(human_to_bytes("1.5M"), Some(1_572_864));
        assert_eq!(human_to_bytes("nope"), None);
        assert_eq!(format_bytes(0), "0B");
        assert_eq!(format_bytes(4096), "4.0K");
        assert_eq!(format_bytes(12 * 1024 * 1024 * 1024), "12G");
    }

    #[test]
    fn cron_from_every_source() {
        let c = parse_cron(include_str!("../testdata/cron.txt"));

        let health = c
            .iter()
            .find(|e| e.command.contains("health-check.sh"))
            .unwrap();
        assert_eq!(health.schedule, "*/5 * * * *");
        assert_eq!(health.user, "deploy");
        assert_eq!(health.source, "crontab:deploy");

        let reboot = c.iter().find(|e| e.schedule == "@reboot").unwrap();
        assert_eq!(reboot.command, "/opt/acme/bin/warm-cache");
        assert_eq!(reboot.user, "deploy");

        let hourly = c
            .iter()
            .find(|e| e.command.contains("cron.hourly"))
            .unwrap();
        assert_eq!(hourly.user, "root");
        assert_eq!(hourly.schedule, "17 * * * *");

        let certbot = c.iter().find(|e| e.command.contains("certbot")).unwrap();
        assert_eq!(certbot.user, "root");
        assert_eq!(certbot.source, "/etc/cron.d/certbot");

        // run-parts drop-ins become one entry per script.
        let daily: Vec<_> = c.iter().filter(|e| e.source == "/etc/cron.daily").collect();
        assert_eq!(daily.len(), 3);
        assert_eq!(daily[0].schedule, "@daily");
        assert_eq!(daily[0].command, "/etc/cron.daily/apt-compat");

        // `MAILTO=""` and `SHELL=/bin/sh` are settings, not jobs.
        assert!(!c.iter().any(|e| e.command.contains("MAILTO")));
        assert!(!c.iter().any(|e| e.schedule.starts_with("SHELL")));
    }

    #[test]
    fn cron_ignores_error_text() {
        let noise = "##SRC crontab:deploy\nno crontab for deploy\nsudo: a password is required\n";
        assert!(parse_cron(noise).is_empty());
    }

    #[test]
    fn host_facts() {
        let h = parse_host(include_str!("../testdata/host.txt"));
        assert_eq!(h.hostname, "web-01.fra.acme.internal");
        assert_eq!(h.os, "Ubuntu 24.04.2 LTS");
        assert_eq!(h.uptime, "3 weeks, 2 days, 4 hours");
        assert_eq!(h.mem_total_mb, Some(7844));
        assert_eq!(h.sudo, SudoAvailability::Passwordless);
        assert!(h.sudo.is_privileged());
    }
}
