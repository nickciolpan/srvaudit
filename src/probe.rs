//! Builds the one shell script we send to the server, and turns its output
//! back into an [`Audit`].
//!
//! Everything runs inside a single SSH session: one authentication, one
//! round trip, a consistent snapshot. Each probe is wrapped in `( ... )` so a
//! probe that decides to `exit` only ends its own subshell.

use std::collections::HashMap;

use crate::findings;
use crate::model::*;
use crate::parse;

#[derive(Debug, Clone)]
pub struct CollectOptions {
    /// Try `sudo -n` for the probes that see more as root.
    pub sudo: bool,
    /// Directories to measure with `du -sh <dir>/*`.
    pub du_paths: Vec<String>,
    /// Skip the `du` pass entirely — it is the one slow probe.
    pub skip_du: bool,
    /// Seconds to give `du` before giving up on it.
    pub du_timeout: u64,
}

impl Default for CollectOptions {
    fn default() -> Self {
        Self {
            sudo: false,
            du_paths: vec!["/var/lib".to_string()],
            skip_du: false,
            du_timeout: 45,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProbeSpec {
    pub id: &'static str,
    pub label: &'static str,
    /// Shown verbatim in the Probes tab so you can rerun it by hand.
    pub display: String,
    pub script: String,
    /// This command routinely exits non-zero while still returning most of the
    /// answer — `du` over a tree with a few root-only subdirectories, or `cat`
    /// across a directory of cron files where one is unreadable. Throwing that
    /// output away would lose real data over a partial permission problem.
    pub tolerates_partial: bool,
}

/// A per-run marker so a probe that happens to print `###SA...` cannot forge
/// a section boundary.
pub fn nonce() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{:x}", now ^ (std::process::id() as u128).rotate_left(17))
}

pub fn specs(opts: &CollectOptions) -> Vec<ProbeSpec> {
    let mut v = vec![
        ProbeSpec {
            id: "host",
            label: "Host facts",
            display: "uname / os-release / uptime / loadavg".into(),
            script: HOST.into(),
            tolerates_partial: false,
        },
        ProbeSpec {
            id: "listeners",
            label: "Listening sockets",
            display: "ss -tulnp".into(),
            script: LISTENERS.into(),
            tolerates_partial: false,
        },
        ProbeSpec {
            id: "containers",
            label: "Containers",
            display: "docker ps -a".into(),
            script: CONTAINERS.into(),
            tolerates_partial: false,
        },
        ProbeSpec {
            id: "services",
            label: "Running services",
            display: "systemctl list-units --type=service --state=running,failed,exited".into(),
            script: SERVICES.into(),
            tolerates_partial: false,
        },
        ProbeSpec {
            id: "unitfiles",
            label: "Enabled at boot",
            display: "systemctl list-unit-files --type=service --state=enabled".into(),
            script: UNIT_FILES.into(),
            tolerates_partial: false,
        },
        ProbeSpec {
            id: "timers",
            label: "Systemd timers",
            display: "systemctl list-timers --all".into(),
            script: TIMERS.into(),
            tolerates_partial: false,
        },
        ProbeSpec {
            id: "df",
            label: "Filesystems",
            display: "df -hPT".into(),
            script: DF.into(),
            tolerates_partial: false,
        },
        ProbeSpec {
            id: "inodes",
            label: "Inodes",
            display: "df -iP".into(),
            script: "df -iP".into(),
            tolerates_partial: false,
        },
    ];

    let globs = opts
        .du_paths
        .iter()
        .map(|p| format!("{}/*", p.trim_end_matches('/')))
        .collect::<Vec<_>>()
        .join(" ");
    let paths = shell_list(&opts.du_paths);
    v.push(ProbeSpec {
        id: "du",
        label: "Directory sizes",
        display: if opts.skip_du {
            format!("du -shx {globs}   (skipped: --no-du)")
        } else {
            format!("du -shx {globs}")
        },
        script: if opts.skip_du {
            "echo '##SKIPPED'".to_string()
        } else {
            format!(
                "for d in {paths}; do [ -d \"$d\" ] || continue; \
                 $SA_SUDO $SA_TO du -shx \"$d\"/* 2>/dev/null; done"
            )
        },
        tolerates_partial: true,
    });

    v.push(ProbeSpec {
        id: "cron",
        label: "Scheduled jobs",
        display: "crontab -l; cat /etc/crontab /etc/cron.d/*; ls /etc/cron.daily".into(),
        script: CRON.into(),
        tolerates_partial: true,
    });
    v
}

/// Single-quote each path for the remote shell.
fn shell_list(paths: &[String]) -> String {
    paths
        .iter()
        .map(|p| format!("'{}'", p.replace('\'', r"'\''")))
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn build_script(opts: &CollectOptions, specs: &[ProbeSpec], nonce: &str) -> String {
    let want_sudo = i32::from(opts.sudo);
    let mut s = format!(
        r#"LC_ALL=C
export LC_ALL
PATH="$PATH:/usr/sbin:/sbin:/usr/local/sbin:/usr/local/bin"
export PATH
SA_SUDO=
if [ "$(id -u)" = 0 ]; then
  SA_PRIV=root
elif [ {want_sudo} = 1 ] && command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then
  SA_SUDO="sudo -n"
  SA_PRIV=passwordless
elif [ {want_sudo} = 1 ]; then
  SA_PRIV=needs-password
else
  SA_PRIV=not-requested
fi
SA_TO=
if command -v timeout >/dev/null 2>&1; then SA_TO="timeout {du_timeout}"; fi
"#,
        du_timeout = opts.du_timeout
    );

    for spec in specs {
        s.push_str(&format!(
            "printf '\\n%s\\n' '###{nonce}:B:{id}'\n(\n{body}\n) 2>&1\nprintf '\\n%s %d\\n' '###{nonce}:E:{id}' $?\n",
            id = spec.id,
            body = spec.script,
        ));
    }
    s
}

/// Cut the combined stdout back into `(id -> (output, exit code))`.
pub fn split_sections(stdout: &str, nonce: &str) -> HashMap<String, (String, i32)> {
    let begin = format!("###{nonce}:B:");
    let end = format!("###{nonce}:E:");
    let mut out = HashMap::new();
    let mut current: Option<(String, Vec<&str>)> = None;

    for line in stdout.lines() {
        let trimmed = line.trim();
        if let Some(id) = trimmed.strip_prefix(&begin) {
            current = Some((id.trim().to_string(), Vec::new()));
        } else if let Some(rest) = trimmed.strip_prefix(&end) {
            let mut it = rest.split_whitespace();
            let id = it.next().unwrap_or("").to_string();
            let code = it.next().and_then(|c| c.parse().ok()).unwrap_or(-1);
            if let Some((open_id, lines)) = current.take() {
                let body = lines.join("\n").trim_matches('\n').to_string();
                out.insert(if open_id.is_empty() { id } else { open_id }, (body, code));
            }
        } else if let Some((_, lines)) = current.as_mut() {
            lines.push(line);
        }
    }
    out
}

fn classify(raw: &str, code: i32, tolerates_partial: bool) -> (ProbeStatus, String) {
    let lower = raw.to_lowercase();
    let first_error = raw
        .lines()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("")
        .trim()
        .to_string();

    if raw.trim() == "##SKIPPED" {
        return (ProbeStatus::Skipped, "skipped by --no-du".into());
    }
    if code == 0 {
        return if raw.trim().is_empty() {
            (ProbeStatus::Empty, String::new())
        } else {
            (ProbeStatus::Ok, String::new())
        };
    }
    if code == 127
        || lower.contains("command not found")
        || lower.contains("not found")
        || lower.contains("no such file or directory")
        || (lower.contains("cannot connect to the docker daemon")
            && !lower.contains("permission denied"))
    {
        return (ProbeStatus::Unsupported, first_error);
    }
    if lower.contains("permission denied")
        || lower.contains("operation not permitted")
        || lower.contains("must be root")
        || lower.contains("are you root")
        || lower.contains("sudo:")
        || lower.contains("access denied")
    {
        return (ProbeStatus::Denied, first_error);
    }
    // `du` exits 1 for a single unreadable subdirectory after correctly sizing
    // everything else. Keep the data and say the coverage is incomplete.
    if tolerates_partial && !raw.trim().is_empty() {
        return (
            ProbeStatus::Partial,
            format!("exited {code}; some paths were unreadable, the rest is shown"),
        );
    }
    (ProbeStatus::Failed, first_error)
}

/// Turn raw sections into a fully populated, analysed [`Audit`].
pub fn assemble(
    target: &str,
    specs: &[ProbeSpec],
    sections: &HashMap<String, (String, i32)>,
    duration_ms: u64,
) -> Audit {
    let mut audit = Audit {
        schema: SCHEMA_VERSION,
        target: target.to_string(),
        collected_at: chrono::Local::now().to_rfc3339(),
        duration_ms,
        ..Default::default()
    };

    for spec in specs {
        let (raw, code) = sections
            .get(spec.id)
            .cloned()
            .unwrap_or_else(|| (String::new(), -1));
        let (status, note) = if sections.contains_key(spec.id) {
            classify(&raw, code, spec.tolerates_partial)
        } else {
            (
                ProbeStatus::Failed,
                "probe produced no output section".to_string(),
            )
        };

        if status.has_data() {
            match spec.id {
                "host" => audit.host = parse::parse_host(&raw),
                "listeners" => audit.listeners = parse::parse_listeners(&raw),
                "containers" => {
                    let runtime = if raw.contains("##RUNTIME podman") {
                        "podman"
                    } else {
                        "docker"
                    };
                    let body: String = raw
                        .lines()
                        .filter(|l| !l.starts_with("##RUNTIME"))
                        .collect::<Vec<_>>()
                        .join("\n");
                    audit.containers = parse::parse_containers(&body, runtime);
                }
                "services" => audit.services = parse::parse_services(&raw),
                "unitfiles" => audit.unit_files = parse::parse_unit_files(&raw),
                "timers" => audit.timers = parse::parse_timers(&raw),
                "df" => audit.filesystems = parse::parse_df(&raw),
                "inodes" => parse::merge_inodes(&mut audit.filesystems, &raw),
                "du" => audit.dir_usage = parse::parse_du(&raw),
                "cron" => audit.cron = parse::parse_cron(&raw),
                _ => {}
            }
        }

        audit.probes.push(ProbeOutcome {
            id: spec.id.to_string(),
            label: spec.label.to_string(),
            command: spec.display.clone(),
            status,
            exit_code: code,
            note,
            raw,
        });
    }

    audit.findings = findings::analyze(&audit);
    audit
}

// ------------------------------------------------------ probe scripts ----

const HOST: &str = r#"echo "HOSTNAME=$(hostname -f 2>/dev/null || hostname 2>/dev/null)"
( . /etc/os-release 2>/dev/null; echo "OS=${PRETTY_NAME:-$(uname -o 2>/dev/null || echo Linux)}" )
echo "KERNEL=$(uname -r)"
echo "ARCH=$(uname -m)"
echo "UPTIME=$(uptime -p 2>/dev/null || uptime 2>/dev/null)"
echo "CPUS=$(nproc 2>/dev/null || grep -c '^processor' /proc/cpuinfo 2>/dev/null)"
echo "LOAD=$(cut -d' ' -f1-3 /proc/loadavg 2>/dev/null)"
awk '/^MemTotal:/{t=$2} /^MemAvailable:/{a=$2} END{if(t>0){printf "MEMTOTAL=%d\nMEMUSED=%d\n", t/1024, (t-a)/1024}}' /proc/meminfo 2>/dev/null
echo "USER=$(id -un)"
echo "VIRT=$(systemd-detect-virt 2>/dev/null || echo unknown)"
echo "SUDO=$SA_PRIV""#;

const LISTENERS: &str = r#"if command -v ss >/dev/null 2>&1; then
  $SA_SUDO ss -tulnp
elif command -v netstat >/dev/null 2>&1; then
  $SA_SUDO netstat -tulnp
else
  echo "srvaudit: neither ss nor netstat is installed" >&2
  exit 127
fi"#;

const CONTAINERS: &str = r###"FMT='{{.ID}}\t{{.Image}}\t{{.Names}}\t{{.State}}\t{{.Status}}\t{{.Ports}}\t{{.RunningFor}}'
if command -v docker >/dev/null 2>&1; then
  echo "##RUNTIME docker"
  $SA_SUDO docker ps -a --format "$FMT"
elif command -v podman >/dev/null 2>&1; then
  echo "##RUNTIME podman"
  $SA_SUDO podman ps -a --format "$FMT"
else
  echo "srvaudit: no docker or podman on this host" >&2
  exit 127
fi"###;

const SERVICES: &str = r#"if command -v systemctl >/dev/null 2>&1; then
  systemctl list-units --type=service --state=running,failed,exited --no-pager --no-legend --plain
else
  echo "srvaudit: systemctl not found (not a systemd host)" >&2
  exit 127
fi"#;

const UNIT_FILES: &str = r#"if command -v systemctl >/dev/null 2>&1; then
  systemctl list-unit-files --type=service --state=enabled --no-pager --no-legend
else
  echo "srvaudit: systemctl not found (not a systemd host)" >&2
  exit 127
fi"#;

const TIMERS: &str = r#"if command -v systemctl >/dev/null 2>&1; then
  systemctl list-timers --all --no-pager --no-legend
else
  echo "srvaudit: systemctl not found (not a systemd host)" >&2
  exit 127
fi"#;

const DF: &str = r#"df -hPT 2>/dev/null || df -hP"#;

const CRON: &str = r###"echo "##SRC crontab:$(id -un)"
crontab -l 2>&1
for f in /etc/crontab /etc/cron.d/*; do
  [ -f "$f" ] || continue
  echo "##SRC $f"
  $SA_SUDO cat "$f" 2>&1
done
for d in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do
  [ -d "$d" ] || continue
  echo "##SRC dir:$d"
  ls -1 "$d" 2>/dev/null
done
if [ -n "$SA_SUDO" ] || [ "$(id -u)" = 0 ]; then
  ME=$(id -un)
  for sp in /var/spool/cron/crontabs /var/spool/cron; do
    [ -d "$sp" ] || continue
    for u in $($SA_SUDO ls -1 "$sp" 2>/dev/null); do
      [ "$u" = "$ME" ] && continue
      [ -f "$sp/$u" ] || $SA_SUDO test -f "$sp/$u" || continue
      echo "##SRC crontab:$u"
      $SA_SUDO cat "$sp/$u" 2>/dev/null
    done
  done
fi"###;

// -------------------------------------------------------------- tests ----

#[cfg(test)]
mod tests {
    use super::*;

    fn wrap(nonce: &str, id: &str, body: &str, code: i32) -> String {
        format!("###{nonce}:B:{id}\n{body}\n###{nonce}:E:{id} {code}\n")
    }

    #[test]
    fn sections_round_trip() {
        let n = "abc123";
        let raw = format!(
            "noise before\n{}{}",
            wrap(n, "df", "Filesystem\n/dev/sda1", 0),
            wrap(n, "containers", "boom", 1)
        );
        let s = split_sections(&raw, n);
        assert_eq!(s.len(), 2);
        assert_eq!(s["df"].0, "Filesystem\n/dev/sda1");
        assert_eq!(s["df"].1, 0);
        assert_eq!(s["containers"], ("boom".to_string(), 1));
    }

    #[test]
    fn a_probe_cannot_forge_a_section_boundary() {
        let n = "abc123";
        // The probe prints a marker with the wrong nonce; it stays payload.
        let raw = wrap(n, "df", "###deadbeef:E:df 0\nreal line", 0);
        let s = split_sections(&raw, n);
        assert_eq!(s.len(), 1);
        assert!(s["df"].0.contains("real line"));
    }

    #[test]
    fn status_classification() {
        assert_eq!(classify("data", 0, false).0, ProbeStatus::Ok);
        assert_eq!(classify("   \n", 0, false).0, ProbeStatus::Empty);
        assert_eq!(
            classify("sh: 1: docker: not found", 127, false).0,
            ProbeStatus::Unsupported
        );
        assert_eq!(
            classify(
                "permission denied while trying to connect to the Docker daemon socket",
                1,
                false
            )
            .0,
            ProbeStatus::Denied
        );
        assert_eq!(
            classify(
                "Cannot connect to the Docker daemon at unix:///var/run/docker.sock.",
                1,
                false
            )
            .0,
            ProbeStatus::Unsupported
        );
        assert_eq!(classify("something odd", 3, false).0, ProbeStatus::Failed);
        assert_eq!(classify("##SKIPPED", 0, false).0, ProbeStatus::Skipped);
    }

    /// Regression: on a real Debian host `du -shx /var/lib/*` sized 23
    /// directories and exited 1 because a handful are root-only. The whole
    /// section was being discarded and reported as a failed probe.
    #[test]
    fn a_partly_readable_du_keeps_its_data() {
        let raw = include_str!("../testdata/du.txt");
        let (status, note) = classify(raw, 1, true);
        assert_eq!(status, ProbeStatus::Partial);
        assert!(note.contains("unreadable"));

        let specs = specs(&CollectOptions::default());
        let mut sections = HashMap::new();
        sections.insert("du".to_string(), (raw.to_string(), 1));
        let audit = assemble("web-01", &specs, &sections, 0);

        assert_eq!(audit.dir_usage.len(), 6, "parsed rows must survive exit 1");
        assert_eq!(audit.probe("du").unwrap().status, ProbeStatus::Partial);
        // ...and du must not be reported as a failure. (The other probes have
        // no section in this cut-down run, so they legitimately do.)
        assert!(
            !audit
                .findings
                .iter()
                .any(|f| f.title == "Probe failed: Directory sizes"),
            "{:?}",
            audit.findings
        );
        assert!(
            audit
                .findings
                .iter()
                .any(|f| f.title.contains("could not read everything"))
        );

        // With no output at all, exit 1 is still a plain failure.
        assert_eq!(classify("", 1, true).0, ProbeStatus::Failed);
    }

    #[test]
    fn generated_script_covers_every_probe_and_quotes_paths() {
        let opts = CollectOptions {
            du_paths: vec!["/var/lib".into(), "/srv/it's here".into()],
            ..Default::default()
        };
        let specs = specs(&opts);
        let script = build_script(&opts, &specs, "n0nce");
        for s in &specs {
            assert!(script.contains(&format!("###n0nce:B:{}", s.id)), "{}", s.id);
            assert!(script.contains(&format!("###n0nce:E:{}", s.id)), "{}", s.id);
        }
        assert!(script.contains(r"'/srv/it'\''s here'"));
        assert!(script.contains("sudo -n true"));
    }

    #[test]
    fn skipping_du_still_emits_the_probe() {
        let opts = CollectOptions {
            skip_du: true,
            ..Default::default()
        };
        let specs = specs(&opts);
        let du = specs.iter().find(|s| s.id == "du").unwrap();
        assert!(du.script.contains("##SKIPPED"));
    }

    /// The script only ever runs on a machine we cannot see, so at least prove
    /// it is syntactically valid POSIX sh and that every probe reports back.
    /// Most probes are "unsupported" on a Mac, which is exactly the path that
    /// has to degrade gracefully.
    #[test]
    fn the_generated_script_runs_under_a_real_sh() {
        use std::io::Write;
        use std::process::{Command, Stdio};

        // Point `du` at a directory we just made: fast and identical everywhere.
        let scratch = std::env::temp_dir().join(format!("srvaudit-sh-{}", std::process::id()));
        std::fs::create_dir_all(scratch.join("child")).unwrap();
        std::fs::write(scratch.join("child/f"), b"hello").unwrap();

        let opts = CollectOptions {
            du_paths: vec![scratch.display().to_string()],
            du_timeout: 10,
            ..Default::default()
        };
        let specs = specs(&opts);
        let nonce = nonce();
        let script = build_script(&opts, &specs, &nonce);

        let mut child = Command::new("sh")
            .arg("-s")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn sh");
        child
            .stdin
            .take()
            .unwrap()
            .write_all(script.as_bytes())
            .unwrap();
        let out = child.wait_with_output().unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);

        assert!(
            !stderr.contains("syntax error") && !stderr.contains("unexpected"),
            "shell rejected the script: {stderr}"
        );

        let sections = split_sections(&stdout, &nonce);
        for spec in &specs {
            assert!(sections.contains_key(spec.id), "no section for {}", spec.id);
        }

        // A probe that calls `exit` must not take the rest of the run with it.
        let audit = assemble("localhost", &specs, &sections, 0);
        assert_eq!(audit.probes.len(), specs.len());
        assert!(!audit.host.user.is_empty(), "id -un produced nothing");
        assert_eq!(audit.host.sudo, SudoAvailability::NotRequested);
        assert!(
            audit.probes.iter().any(|p| p.status == ProbeStatus::Ok),
            "every single probe failed, which cannot be right"
        );
        assert!(
            audit.dir_usage.iter().any(|d| d.path.ends_with("child")),
            "du did not measure the directory we made: {:?}",
            audit.dir_usage
        );
        std::fs::remove_dir_all(&scratch).ok();
    }

    #[test]
    fn assemble_marks_missing_sections_without_losing_the_rest() {
        let specs = specs(&CollectOptions::default());
        let mut sections = HashMap::new();
        sections.insert(
            "df".to_string(),
            (include_str!("../testdata/df.txt").to_string(), 0),
        );
        sections.insert(
            "inodes".to_string(),
            (include_str!("../testdata/inodes.txt").to_string(), 0),
        );
        let audit = assemble("web-01", &specs, &sections, 1234);

        assert_eq!(audit.filesystems.len(), 6);
        assert_eq!(
            audit
                .filesystems
                .iter()
                .find(|f| f.mount == "/")
                .unwrap()
                .inode_pct,
            Some(94.0)
        );
        assert_eq!(audit.probe("df").unwrap().status, ProbeStatus::Ok);
        assert_eq!(audit.probe("cron").unwrap().status, ProbeStatus::Failed);
        assert_eq!(
            audit.probe("containers").unwrap().status,
            ProbeStatus::Failed
        );
    }
}
