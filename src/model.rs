//! Data model for a single audit run.
//!
//! Everything here is `Serialize`/`Deserialize` so an audit can be written to
//! JSON, mailed around, and replayed later with `srvaudit --from-json`.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Audit {
    /// Schema version, so a future release can refuse to misread an old file.
    #[serde(default = "schema_version")]
    pub schema: u32,
    pub target: String,
    pub collected_at: String,
    pub duration_ms: u64,
    pub host: HostInfo,
    pub listeners: Vec<Listener>,
    pub containers: Vec<Container>,
    pub services: Vec<Service>,
    pub unit_files: Vec<UnitFile>,
    pub timers: Vec<Timer>,
    pub filesystems: Vec<Filesystem>,
    pub dir_usage: Vec<DirUsage>,
    pub cron: Vec<CronEntry>,
    pub probes: Vec<ProbeOutcome>,
    pub findings: Vec<Finding>,
}

pub const SCHEMA_VERSION: u32 = 1;
fn schema_version() -> u32 {
    SCHEMA_VERSION
}

impl Audit {
    pub fn probe(&self, id: &str) -> Option<&ProbeOutcome> {
        self.probes.iter().find(|p| p.id == id)
    }
}

// ---------------------------------------------------------------- host ----

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HostInfo {
    pub hostname: String,
    pub os: String,
    pub kernel: String,
    pub arch: String,
    pub uptime: String,
    pub cpus: String,
    pub load: String,
    pub mem_total_mb: Option<u64>,
    pub mem_used_mb: Option<u64>,
    pub user: String,
    pub virt: String,
    pub sudo: SudoAvailability,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum SudoAvailability {
    /// Already running as uid 0.
    Root,
    /// `sudo -n true` succeeded: privileged probes ran.
    Passwordless,
    /// sudo exists but wants a password, so privileged probes were skipped.
    NeedsPassword,
    /// `--sudo` was not requested.
    #[default]
    NotRequested,
}

impl SudoAvailability {
    pub fn label(self) -> &'static str {
        match self {
            Self::Root => "root",
            Self::Passwordless => "sudo",
            Self::NeedsPassword => "sudo (password needed)",
            Self::NotRequested => "unprivileged",
        }
    }

    /// Whether the audit saw the whole machine or only this user's slice.
    pub fn is_privileged(self) -> bool {
        matches!(self, Self::Root | Self::Passwordless)
    }
}

// ----------------------------------------------------------- listeners ----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Listener {
    pub proto: String,
    pub state: String,
    pub addr: String,
    pub port: String,
    pub process: Option<String>,
    pub pid: Option<u32>,
    /// Every `users:(("name",pid=N,fd=M))` entry, joined — sockets are often
    /// shared by a parent and its workers.
    pub users: String,
    pub exposure: Exposure,
}

impl Listener {
    pub fn endpoint(&self) -> String {
        format!("{}:{}", self.addr, self.port)
    }

    pub fn port_num(&self) -> Option<u16> {
        self.port.parse().ok()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Exposure {
    /// 127.0.0.0/8 or ::1 — only reachable from the machine itself.
    Loopback,
    /// Bound to one specific address.
    Interface,
    /// 0.0.0.0, ::, or * — reachable on every interface the box has.
    AllInterfaces,
}

impl Exposure {
    pub fn label(self) -> &'static str {
        match self {
            Self::Loopback => "local",
            Self::Interface => "iface",
            Self::AllInterfaces => "ALL",
        }
    }
}

// ---------------------------------------------------------- containers ----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Container {
    pub runtime: String,
    pub id: String,
    pub name: String,
    pub image: String,
    pub state: String,
    pub status: String,
    pub created: String,
    pub ports: Vec<PortMapping>,
    pub ports_raw: String,
}

impl Container {
    pub fn is_running(&self) -> bool {
        self.state.eq_ignore_ascii_case("running")
    }

    /// Exit code parsed out of a `Exited (137) 3 hours ago` status string.
    pub fn exit_code(&self) -> Option<i32> {
        let start = self.status.find('(')? + 1;
        let end = self.status[start..].find(')')? + start;
        self.status[start..end].trim().parse().ok()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortMapping {
    pub host_ip: String,
    pub host_port: String,
    pub container_port: String,
    pub proto: String,
}

impl PortMapping {
    /// Published on every interface — which on Docker also means it punched
    /// through the host firewall.
    pub fn is_wide_open(&self) -> bool {
        matches!(self.host_ip.as_str(), "0.0.0.0" | "::" | "*" | "[::]")
    }

    pub fn render(&self) -> String {
        if self.host_port.is_empty() {
            format!("{}/{}", self.container_port, self.proto)
        } else {
            format!(
                "{}:{}->{}/{}",
                self.host_ip, self.host_port, self.container_port, self.proto
            )
        }
    }
}

// ------------------------------------------------------------ systemd ----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Service {
    pub unit: String,
    pub load: String,
    pub active: String,
    pub sub: String,
    pub description: String,
}

impl Service {
    pub fn is_failed(&self) -> bool {
        self.active == "failed" || self.sub == "failed"
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnitFile {
    pub unit: String,
    pub state: String,
    pub preset: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Timer {
    pub unit: String,
    pub activates: String,
    /// Absolute next run, or `-` for a timer with none scheduled.
    pub next: String,
    /// Time until the next run: `2h 10min`.
    pub left: String,
    /// Absolute last run, or `-` if it has never fired.
    pub last: String,
    /// Time since the last run: `2h 54min ago`.
    pub passed: String,
}

// ------------------------------------------------------------ storage ----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Filesystem {
    pub source: String,
    pub fstype: String,
    pub size: String,
    pub used: String,
    pub avail: String,
    pub use_pct: Option<f32>,
    pub inode_pct: Option<f32>,
    pub mount: String,
}

impl Filesystem {
    /// Pseudo filesystems that say nothing about "will this box run out of
    /// disk", so findings ignore them.
    pub fn is_pseudo(&self) -> bool {
        matches!(
            self.fstype.as_str(),
            "tmpfs"
                | "devtmpfs"
                | "squashfs"
                | "overlay"
                | "efivarfs"
                | "ramfs"
                | "iso9660"
                | "autofs"
                | "fuse.snapfuse"
                | "devfs"
        ) || self.source.starts_with("/dev/loop")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirUsage {
    pub path: String,
    pub human: String,
    pub bytes: u64,
}

// --------------------------------------------------------- scheduling ----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CronEntry {
    /// Where it came from: `crontab:root`, `/etc/cron.d/certbot`, ...
    pub source: String,
    pub schedule: String,
    pub user: String,
    pub command: String,
}

// ------------------------------------------------------------- probes ----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeOutcome {
    pub id: String,
    pub label: String,
    pub command: String,
    pub status: ProbeStatus,
    pub exit_code: i32,
    pub note: String,
    pub raw: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProbeStatus {
    /// Ran, returned data.
    Ok,
    /// Returned usable data but exited non-zero — almost always a few
    /// unreadable paths. The data is kept; the gap is reported.
    Partial,
    /// Ran, returned nothing — a genuine "there are none".
    Empty,
    /// The tool isn't installed on this host.
    Unsupported,
    /// The tool is there but refused us; the answer is "unknown", not "none".
    Denied,
    /// Non-zero exit for some other reason.
    Failed,
    /// We chose not to run it.
    Skipped,
}

impl ProbeStatus {
    /// Whether the probe's output is worth parsing and displaying.
    pub fn has_data(self) -> bool {
        matches!(self, Self::Ok | Self::Partial)
    }

    /// Whether an empty section means "none" rather than "we could not look".
    pub fn looked(self) -> bool {
        matches!(self, Self::Ok | Self::Partial | Self::Empty)
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Partial => "partial",
            Self::Empty => "empty",
            Self::Unsupported => "n/a",
            Self::Denied => "denied",
            Self::Failed => "failed",
            Self::Skipped => "skipped",
        }
    }
}

// ----------------------------------------------------------- findings ----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub severity: Severity,
    pub title: String,
    pub detail: String,
    /// Which tab has the evidence, so the UI can offer to jump there.
    pub tab: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    pub fn label(self) -> &'static str {
        match self {
            Self::High => "HIGH",
            Self::Medium => "MED",
            Self::Low => "LOW",
            Self::Info => "INFO",
        }
    }
}
