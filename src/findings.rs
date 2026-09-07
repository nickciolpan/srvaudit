//! Turns the collected facts into a short list of things worth looking at.
//!
//! The bar for a finding is "a competent admin would want to see this on the
//! first screen". Anything chattier gets aggregated into one line, because a
//! findings list nobody reads is worse than no findings list.

use std::collections::BTreeSet;

use crate::model::*;

/// Ports where "listening on every interface" is usually a mistake.
const DATASTORE_PORTS: &[(u16, &str)] = &[
    (21, "FTP"),
    (23, "Telnet"),
    (139, "NetBIOS"),
    (445, "SMB"),
    (1433, "Microsoft SQL Server"),
    (2375, "Docker API (no TLS, no auth)"),
    (2379, "etcd client"),
    (2380, "etcd peer"),
    (3306, "MySQL/MariaDB"),
    (3389, "RDP"),
    (5432, "PostgreSQL"),
    (5672, "RabbitMQ (AMQP)"),
    (5900, "VNC"),
    (5984, "CouchDB"),
    (6379, "Redis"),
    (6443, "Kubernetes API"),
    (8086, "InfluxDB"),
    (9042, "Cassandra"),
    (9092, "Kafka"),
    (9200, "Elasticsearch"),
    (9300, "Elasticsearch transport"),
    (10250, "kubelet"),
    (11211, "Memcached"),
    (15672, "RabbitMQ management UI"),
    (27017, "MongoDB"),
    (27018, "MongoDB shard"),
];

/// Ports that are fine to expose inside a private network but rarely meant for
/// the public internet.
const INTERNAL_PORTS: &[(u16, &str)] = &[
    (2376, "Docker API (TLS)"),
    (3000, "Grafana / dev HTTP server"),
    (4444, "Selenium / misc"),
    (5601, "Kibana"),
    (8000, "app server"),
    (8080, "app server"),
    (8081, "app server"),
    (8443, "app server (TLS)"),
    (9000, "app server / MinIO"),
    (9090, "Prometheus"),
    (9100, "node_exporter"),
];

/// Ports whose whole point is to be reachable.
const EXPECTED_PUBLIC: &[u16] = &[22, 80, 443];

fn lookup(table: &[(u16, &'static str)], port: u16) -> Option<&'static str> {
    table
        .iter()
        .find(|(p, _)| *p == port)
        .map(|(_, name)| *name)
}

/// A port where "open to the world" is a finding rather than a design choice.
pub fn is_sensitive_port(port: u16) -> bool {
    lookup(DATASTORE_PORTS, port).is_some()
}

/// Human name for a well-known port, for the detail pane.
pub fn port_name(port: u16) -> Option<&'static str> {
    lookup(DATASTORE_PORTS, port)
        .or_else(|| lookup(INTERNAL_PORTS, port))
        .or(match port {
            22 => Some("SSH"),
            80 => Some("HTTP"),
            443 => Some("HTTPS"),
            25 => Some("SMTP"),
            53 => Some("DNS"),
            123 => Some("NTP"),
            _ => None,
        })
}

pub fn analyze(a: &Audit) -> Vec<Finding> {
    let mut f = Vec::new();
    exposed_listeners(a, &mut f);
    storage(a, &mut f);
    systemd(a, &mut f);
    containers(a, &mut f);
    scheduled_jobs(a, &mut f);
    pressure(a, &mut f);
    coverage(a, &mut f);
    f.sort_by(|x, y| x.severity.cmp(&y.severity).then(x.title.cmp(&y.title)));
    f
}

fn push(f: &mut Vec<Finding>, severity: Severity, tab: &str, title: String, detail: String) {
    f.push(Finding {
        severity,
        title,
        detail,
        tab: tab.to_string(),
    });
}

fn exposed_listeners(a: &Audit, f: &mut Vec<Finding>) {
    let mut unknown_wide: Vec<String> = Vec::new();

    // A service bound to both 0.0.0.0 and [::] is one service, not two
    // problems, so group by port and proto family before reporting.
    let mut grouped: std::collections::BTreeMap<(u16, String, String), Vec<String>> =
        std::collections::BTreeMap::new();
    for l in a
        .listeners
        .iter()
        .filter(|l| l.exposure == Exposure::AllInterfaces)
    {
        let Some(port) = l.port_num() else { continue };
        let family = l.proto.trim_end_matches('6').to_string();
        let who = l
            .process
            .clone()
            .unwrap_or_else(|| "unknown process".to_string());
        grouped
            .entry((port, family, who))
            .or_default()
            .push(l.endpoint());
    }

    for ((port, proto, who), mut endpoints) in grouped {
        endpoints.sort();
        endpoints.dedup();
        let where_ = format!("{proto} {}", endpoints.join(", "));

        if let Some(name) = lookup(DATASTORE_PORTS, port) {
            push(
                f,
                Severity::High,
                "listeners",
                format!("{name} is listening on every interface"),
                format!(
                    "{where_} ({who}). Anything that can route to this host can reach it. \
                     Bind it to 127.0.0.1 or a private address, or put a firewall in front of it."
                ),
            );
        } else if let Some(name) = lookup(INTERNAL_PORTS, port) {
            push(
                f,
                Severity::Medium,
                "listeners",
                format!("{name} is listening on every interface"),
                format!(
                    "{where_} ({who}). Fine on a private network, worth checking if this \
                     box has a public address."
                ),
            );
        } else if !EXPECTED_PUBLIC.contains(&port) {
            unknown_wide.push(format!("{port}/{proto} ({who})"));
        }
    }

    if !unknown_wide.is_empty() {
        unknown_wide.sort();
        unknown_wide.dedup();
        push(
            f,
            Severity::Low,
            "listeners",
            format!(
                "{} other port{} open on every interface",
                unknown_wide.len(),
                plural(unknown_wide.len())
            ),
            unknown_wide.join(", "),
        );
    }

    if a.listeners.iter().any(|l| l.process.is_none()) && !a.host.sudo.is_privileged() {
        push(
            f,
            Severity::Info,
            "listeners",
            "Some listeners have no process name".into(),
            "The kernel only reveals socket owners to root. Re-run with --sudo to see what is \
             behind these ports."
                .into(),
        );
    }
}

fn storage(a: &Audit, f: &mut Vec<Finding>) {
    for fs in a.filesystems.iter().filter(|fs| !fs.is_pseudo()) {
        if let Some(pct) = fs.use_pct {
            let severity = if pct >= 90.0 {
                Some(Severity::High)
            } else if pct >= 80.0 {
                Some(Severity::Medium)
            } else {
                None
            };
            if let Some(severity) = severity {
                push(
                    f,
                    severity,
                    "storage",
                    format!("{} is {:.0}% full", fs.mount, pct),
                    format!(
                        "{} of {} used on {} ({}), {} free.",
                        fs.used, fs.size, fs.source, fs.fstype, fs.avail
                    ),
                );
            }
        }
        if let Some(ipct) = fs.inode_pct
            && ipct >= 85.0
        {
            push(
                f,
                Severity::High,
                "storage",
                format!("{} has used {ipct:.0}% of its inodes", fs.mount),
                "Writes start failing with ENOSPC once inodes run out, even with free space on \
                 the disk. Usually a directory full of tiny files — sessions, mail spool, cache."
                    .into(),
            );
        }
    }
}

fn systemd(a: &Audit, f: &mut Vec<Finding>) {
    let failed: Vec<&str> = a
        .services
        .iter()
        .filter(|s| s.is_failed())
        .map(|s| s.unit.as_str())
        .collect();
    if !failed.is_empty() {
        push(
            f,
            Severity::Medium,
            "services",
            format!("{} service{} failed", failed.len(), plural(failed.len())),
            format!(
                "{}. Check with `systemctl status <unit>`.",
                failed.join(", ")
            ),
        );
    }
}

fn containers(a: &Audit, f: &mut Vec<Finding>) {
    for c in a.containers.iter().filter(|c| c.state == "restarting") {
        push(
            f,
            Severity::Medium,
            "containers",
            format!("Container {} is stuck restarting", c.name),
            format!(
                "{} — {}. Check `docker logs {}`.",
                c.image, c.status, c.name
            ),
        );
    }

    let crashed: Vec<String> = a
        .containers
        .iter()
        .filter(|c| c.state == "exited" && c.exit_code().is_some_and(|code| code != 0))
        .map(|c| format!("{} (exit {})", c.name, c.exit_code().unwrap_or(-1)))
        .collect();
    if !crashed.is_empty() {
        push(
            f,
            Severity::Low,
            "containers",
            format!(
                "{} container{} exited non-zero",
                crashed.len(),
                plural(crashed.len())
            ),
            format!(
                "{}. Harmless for one-shot jobs, worth a look for anything meant to stay up.",
                crashed.join(", ")
            ),
        );
    }

    let published: Vec<String> = a
        .containers
        .iter()
        .flat_map(|c| {
            c.ports
                .iter()
                .filter(|p| p.is_wide_open())
                .map(move |p| format!("{} {}", c.name, p.render()))
        })
        .collect();
    if !published.is_empty() {
        push(
            f,
            Severity::Medium,
            "containers",
            format!(
                "{} container port{} published on 0.0.0.0",
                published.len(),
                plural(published.len())
            ),
            format!(
                "{}. Docker inserts its own iptables rules ahead of the INPUT chain, so a ufw or \
                 firewalld rule will not block these. Publish to 127.0.0.1 instead where you can.",
                published.join(", ")
            ),
        );
    }
}

fn scheduled_jobs(a: &Audit, f: &mut Vec<Finding>) {
    for c in &a.cron {
        if pipes_remote_script_to_shell(&c.command) {
            push(
                f,
                Severity::High,
                "schedules",
                "A cron job pipes a downloaded script straight into a shell".into(),
                format!(
                    "{} as {}: {}  (from {}). Whoever controls that URL controls this machine on \
                     every run.",
                    c.schedule, c.user, c.command, c.source
                ),
            );
        }
    }

    let at_boot: Vec<&str> = a
        .cron
        .iter()
        .filter(|c| c.schedule == "@reboot")
        .map(|c| c.command.as_str())
        .collect();
    if !at_boot.is_empty() {
        push(
            f,
            Severity::Info,
            "schedules",
            format!(
                "{} job{} run at every boot",
                at_boot.len(),
                plural(at_boot.len())
            ),
            at_boot.join("; "),
        );
    }
}

/// `curl … | sh`, `wget -O- … | bash`, and the usual variations.
pub fn pipes_remote_script_to_shell(cmd: &str) -> bool {
    let lower = cmd.to_lowercase();
    let fetches = ["curl ", "wget "].iter().any(|c| lower.contains(c));
    if !fetches {
        return false;
    }
    lower.split('|').skip(1).any(|seg| {
        let head = seg.split_whitespace().next().unwrap_or("");
        let head = head.rsplit('/').next().unwrap_or(head);
        matches!(
            head,
            "sh" | "bash" | "zsh" | "dash" | "ksh" | "python" | "python3" | "perl"
        )
    })
}

fn pressure(a: &Audit, f: &mut Vec<Finding>) {
    if let (Some(total), Some(used)) = (a.host.mem_total_mb, a.host.mem_used_mb)
        && total > 0
    {
        let pct = used as f64 / total as f64 * 100.0;
        if pct >= 90.0 {
            push(
                f,
                Severity::Medium,
                "overview",
                format!("Memory is {pct:.0}% used"),
                format!("{used} MB of {total} MB in use (excluding reclaimable cache)."),
            );
        }
    }

    let cpus: f64 = a.host.cpus.trim().parse().unwrap_or(0.0);
    let load1: f64 = a
        .host
        .load
        .split_whitespace()
        .next()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0.0);
    if cpus > 0.0 && load1 > cpus * 2.0 {
        push(
            f,
            Severity::Medium,
            "overview",
            format!("Load average {load1:.2} on {cpus:.0} CPUs"),
            "The run queue is more than twice the core count; something is saturating this box."
                .into(),
        );
    }
}

fn coverage(a: &Audit, f: &mut Vec<Finding>) {
    let mut blind: BTreeSet<&str> = BTreeSet::new();
    let mut partial: BTreeSet<&str> = BTreeSet::new();
    for p in &a.probes {
        match p.status {
            ProbeStatus::Partial => {
                partial.insert(p.label.as_str());
            }
            ProbeStatus::Denied => {
                blind.insert(p.label.as_str());
            }
            ProbeStatus::Failed => {
                push(
                    f,
                    Severity::Low,
                    "probes",
                    format!("Probe failed: {}", p.label),
                    format!("`{}` exited {} — {}", p.command, p.exit_code, p.note),
                );
            }
            _ => {}
        }
    }

    if !blind.is_empty() {
        let hint = if a.host.sudo.is_privileged() {
            "Even with sudo these were refused."
        } else {
            "Re-run with --sudo for the full picture."
        };
        push(
            f,
            Severity::Info,
            "probes",
            format!("{} probe{} were denied", blind.len(), plural(blind.len())),
            format!(
                "{}. {hint} Treat those sections as unknown, not empty.",
                blind.into_iter().collect::<Vec<_>>().join(", ")
            ),
        );
    }

    if !partial.is_empty() {
        push(
            f,
            Severity::Info,
            "probes",
            format!(
                "{} probe{} could not read everything",
                partial.len(),
                plural(partial.len())
            ),
            format!(
                "{}. What came back is shown and is accurate as far as it goes; some paths were \
                 unreadable{}.",
                partial.into_iter().collect::<Vec<_>>().join(", "),
                if a.host.sudo.is_privileged() {
                    ""
                } else {
                    ", so re-run with --sudo for complete totals"
                }
            ),
        );
    }

    if a.host.sudo == SudoAvailability::NeedsPassword {
        push(
            f,
            Severity::Info,
            "overview",
            "sudo needs a password, so privileged probes were skipped".into(),
            "srvaudit only ever uses `sudo -n`, so it can never hang on a password prompt. Grant \
             NOPASSWD for the read-only commands, or run as root, to see the whole machine."
                .into(),
        );
    }
}

fn plural(n: usize) -> &'static str {
    if n == 1 { "" } else { "s" }
}

// -------------------------------------------------------------- tests ----

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse;

    use crate::fixtures::sample_audit as sample;

    fn titles(a: &Audit, s: Severity) -> Vec<&str> {
        a.findings
            .iter()
            .filter(|f| f.severity == s)
            .map(|f| f.title.as_str())
            .collect()
    }

    /// Regression: a service bound to both 0.0.0.0 and [::] was producing two
    /// identical findings.
    #[test]
    fn one_service_on_both_ip_families_is_one_finding() {
        let mut a = Audit {
            listeners: parse::parse_ss(
                "Netid State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n\
                 tcp   LISTEN 0      511          0.0.0.0:8080      0.0.0.0:*\n\
                 tcp   LISTEN 0      511             [::]:8080         [::]:*\n",
            ),
            ..Default::default()
        };
        a.findings = analyze(&a);
        let hits: Vec<&Finding> = a
            .findings
            .iter()
            .filter(|f| f.title.contains("listening on every interface"))
            .collect();
        assert_eq!(hits.len(), 1, "{:?}", a.findings);
        assert!(hits[0].detail.contains("0.0.0.0:8080"));
        assert!(hits[0].detail.contains("[::]:8080"));
    }

    #[test]
    fn flags_exposed_datastores_but_not_ssh_or_http() {
        let a = sample();
        let high = titles(&a, Severity::High);
        assert!(high.iter().any(|t| t.starts_with("Redis")));
        assert!(high.iter().any(|t| t.starts_with("Docker API (no TLS")));
        // 80 and 443 are on 0.0.0.0 too, and that is the entire point of them.
        assert!(!a.findings.iter().any(|f| f.title.contains("80/tcp")));
        // Postgres is on 127.0.0.1 here, so it must not be flagged.
        assert!(!high.iter().any(|t| t.starts_with("PostgreSQL")));
    }

    #[test]
    fn findings_are_sorted_most_severe_first() {
        let a = sample();
        let mut sorted = a.findings.clone();
        sorted.sort_by_key(|f| f.severity);
        let order: Vec<_> = a.findings.iter().map(|f| f.severity).collect();
        let expect: Vec<_> = sorted.iter().map(|f| f.severity).collect();
        assert_eq!(order, expect);
        assert_eq!(a.findings.first().map(|f| f.severity), Some(Severity::High));
    }

    #[test]
    fn full_disk_and_exhausted_inodes_both_surface() {
        let a = sample();
        let high = titles(&a, Severity::High);
        assert!(high.iter().any(|t| t == &"/ is 96% full"));
        assert!(high.iter().any(|t| t.contains("94% of its inodes")));
        // The 100%-full squashfs loop mount is not a real problem.
        assert!(!a.findings.iter().any(|f| f.title.contains("/snap/")));
    }

    #[test]
    fn curl_pipe_shell_cron_job_is_high() {
        let a = sample();
        assert!(
            titles(&a, Severity::High)
                .iter()
                .any(|t| t.contains("pipes a downloaded script"))
        );
    }

    #[test]
    fn shell_pipe_detection_is_specific() {
        assert!(pipes_remote_script_to_shell(
            "curl -sL https://x/y.sh | bash"
        ));
        assert!(pipes_remote_script_to_shell(
            "wget -qO- https://x | /bin/sh -s --"
        ));
        assert!(pipes_remote_script_to_shell("curl https://x | python3"));
        // Downloading is fine; piping into grep is fine.
        assert!(!pipes_remote_script_to_shell(
            "curl -s https://x/health | grep -q ok"
        ));
        assert!(!pipes_remote_script_to_shell(
            "/usr/local/bin/backup.sh | mail -s x root"
        ));
    }

    #[test]
    fn container_and_service_health_is_reported() {
        let a = sample();
        let med = titles(&a, Severity::Medium);
        assert!(med.iter().any(|t| t.contains("stuck restarting")));
        assert!(med.iter().any(|t| t.contains("service failed")));
        assert!(med.iter().any(|t| t.contains("published on 0.0.0.0")));
        assert!(
            titles(&a, Severity::Low)
                .iter()
                .any(|t| t.contains("exited non-zero"))
        );
    }

    #[test]
    fn a_clean_host_produces_no_alarms() {
        let mut a = Audit {
            host: parse::parse_host("SUDO=root\nCPUS=4\nLOAD=0.10 0.10 0.10\n"),
            listeners: parse::parse_ss(
                "Netid State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n\
                 tcp   LISTEN 0      128          0.0.0.0:22        0.0.0.0:*  users:((\"sshd\",pid=1,fd=3))\n",
            ),
            filesystems: parse::parse_df(
                "Filesystem Type Size Used Avail Use% Mounted on\n/dev/sda1 ext4 100G 10G 90G 10% /\n",
            ),
            ..Default::default()
        };
        a.findings = analyze(&a);
        assert!(a.findings.is_empty(), "unexpected: {:?}", a.findings);
    }
}
