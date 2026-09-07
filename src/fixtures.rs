//! One realistic audit, parsed from the captured command output in `testdata/`,
//! shared by the unit tests so they all describe the same imaginary server.

use crate::findings;
use crate::model::*;
use crate::parse;

/// `web-01`: a busy Ubuntu box with a full disk, an exposed Redis, an
/// unauthenticated Docker socket, a crash-looping container and a cron job that
/// curls a script into bash.
pub fn sample_audit() -> Audit {
    let mut a = Audit {
        schema: SCHEMA_VERSION,
        target: "web-01".into(),
        collected_at: "2026-09-07T10:00:00+02:00".into(),
        duration_ms: 2400,
        host: parse::parse_host(include_str!("../testdata/host.txt")),
        listeners: parse::parse_listeners(include_str!("../testdata/ss.txt")),
        containers: parse::parse_containers(include_str!("../testdata/docker.txt"), "docker"),
        services: parse::parse_services(include_str!("../testdata/services.txt")),
        unit_files: parse::parse_unit_files(include_str!("../testdata/unitfiles.txt")),
        timers: parse::parse_timers(include_str!("../testdata/timers.txt")),
        filesystems: parse::parse_df(include_str!("../testdata/df.txt")),
        dir_usage: parse::parse_du(include_str!("../testdata/du.txt")),
        cron: parse::parse_cron(include_str!("../testdata/cron.txt")),
        probes: vec![probe(
            "containers",
            "Containers",
            "docker ps -a",
            ProbeStatus::Ok,
        )],
        findings: Vec::new(),
    };
    parse::merge_inodes(&mut a.filesystems, include_str!("../testdata/inodes.txt"));
    a.findings = findings::analyze(&a);
    a
}

pub fn probe(id: &str, label: &str, command: &str, status: ProbeStatus) -> ProbeOutcome {
    ProbeOutcome {
        id: id.into(),
        label: label.into(),
        command: command.into(),
        status,
        exit_code: i32::from(status != ProbeStatus::Ok),
        note: match status {
            ProbeStatus::Denied => "permission denied".into(),
            _ => String::new(),
        },
        raw: match status {
            ProbeStatus::Ok => "raw output\nsecond line".into(),
            _ => String::new(),
        },
    }
}
