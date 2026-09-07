//! Command line surface.

use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, ValueEnum};

use crate::probe::CollectOptions;
use crate::ssh::SshTarget;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ReportFormat {
    /// Plain text for a terminal.
    Text,
    /// Markdown for a ticket or a pull request.
    Markdown,
    /// The full audit, replayable with --from-json.
    Json,
}

const AFTER_HELP: &str = "\
Examples:
  srvaudit web-01                       audit the ~/.ssh/config alias 'web-01'
  srvaudit deploy@10.0.0.7:2222 --sudo  escalate read-only probes with `sudo -n`
  srvaudit web-01 --report markdown     no TUI, print a report on stdout
  srvaudit web-01 --out audit.json      save the audit for later
  srvaudit --from-json audit.json       reopen a saved audit in the TUI

srvaudit never runs anything that writes to the server, and never prompts for a
sudo password: it only ever uses `sudo -n`, so it cannot hang on a prompt.";

#[derive(Debug, Parser)]
#[command(
    name = "srvaudit",
    version,
    about = "Terminal audit dashboard for a remote Linux server",
    long_about = "Answers four questions about a server over one SSH connection: what is \
                  listening, what is running, where the data is, and what starts automatically.",
    after_help = AFTER_HELP
)]
pub struct Cli {
    /// [user@]host[:port], or any alias from your ~/.ssh/config.
    #[arg(value_name = "TARGET", required_unless_present = "from_json")]
    pub target: Option<String>,

    /// SSH port (overrides one given in TARGET).
    #[arg(short = 'p', long, value_name = "PORT")]
    pub port: Option<u16>,

    /// Log in as this user.
    #[arg(short = 'u', long, value_name = "USER")]
    pub user: Option<String>,

    /// Private key to authenticate with.
    #[arg(short = 'i', long, value_name = "KEYFILE")]
    pub identity: Option<PathBuf>,

    /// Jump host, same syntax as `ssh -J`.
    #[arg(short = 'J', long, value_name = "[user@]host")]
    pub jump: Option<String>,

    /// Extra ssh option, repeatable — e.g. -o StrictHostKeyChecking=accept-new
    #[arg(short = 'o', long = "ssh-option", value_name = "KEY=VALUE")]
    pub ssh_option: Vec<String>,

    /// Run the privileged probes through `sudo -n` (never prompts).
    #[arg(long)]
    pub sudo: bool,

    /// Directory to measure with `du`, repeatable.
    #[arg(long = "du-path", value_name = "DIR", default_value = "/var/lib")]
    pub du_path: Vec<String>,

    /// Skip the `du` pass — it is the one probe that can be slow.
    #[arg(long)]
    pub no_du: bool,

    /// Give up on the whole collection after this many seconds.
    #[arg(long, value_name = "SECONDS", default_value_t = 120)]
    pub timeout: u64,

    /// Give up on `du` alone after this many seconds.
    #[arg(long, value_name = "SECONDS", default_value_t = 45)]
    pub du_timeout: u64,

    /// Print a report instead of opening the TUI.
    #[arg(long, value_name = "FORMAT", value_enum)]
    pub report: Option<ReportFormat>,

    /// Write the report to a file (format inferred from the extension).
    #[arg(long, value_name = "FILE")]
    pub out: Option<PathBuf>,

    /// Reopen a saved JSON audit instead of connecting to anything.
    #[arg(long, value_name = "FILE", conflicts_with_all = ["target", "sudo", "jump"])]
    pub from_json: Option<PathBuf>,
}

impl Cli {
    pub fn collect_options(&self) -> CollectOptions {
        CollectOptions {
            sudo: self.sudo,
            du_paths: self.du_path.clone(),
            skip_du: self.no_du,
            du_timeout: self.du_timeout,
        }
    }

    pub fn ssh_target(&self) -> Result<SshTarget> {
        let spec = self.target.as_deref().unwrap_or_default();
        let mut t = SshTarget::parse(spec)?;
        if let Some(p) = self.port {
            t.port = Some(p);
        }
        t.user = self.user.clone();
        t.identity = self.identity.clone();
        t.jump = self.jump.clone();
        t.options = self.ssh_option.clone();
        Ok(t)
    }

    /// `--out report.md` implies markdown even without `--report`.
    pub fn effective_report(&self) -> Option<ReportFormat> {
        if let Some(f) = self.report {
            return Some(f);
        }
        let ext = self
            .out
            .as_ref()?
            .extension()?
            .to_string_lossy()
            .to_lowercase();
        Some(match ext.as_str() {
            "json" => ReportFormat::Json,
            "md" | "markdown" => ReportFormat::Markdown,
            _ => ReportFormat::Text,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn clap_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn target_and_flags_combine() {
        let c = Cli::parse_from([
            "srvaudit",
            "deploy@web-01:2200",
            "-p",
            "2222",
            "-i",
            "/k/id",
            "-o",
            "StrictHostKeyChecking=accept-new",
            "--sudo",
        ]);
        let t = c.ssh_target().unwrap();
        assert_eq!(t.destination, "deploy@web-01");
        assert_eq!(t.port, Some(2222), "-p must win over the :port suffix");
        assert_eq!(t.options, vec!["StrictHostKeyChecking=accept-new"]);
        assert!(c.collect_options().sudo);
    }

    #[test]
    fn du_paths_replace_the_default() {
        let c = Cli::parse_from(["srvaudit", "h"]);
        assert_eq!(c.collect_options().du_paths, vec!["/var/lib"]);
        let c = Cli::parse_from(["srvaudit", "h", "--du-path", "/srv", "--du-path", "/opt"]);
        assert_eq!(c.collect_options().du_paths, vec!["/srv", "/opt"]);
    }

    #[test]
    fn report_format_can_come_from_the_output_extension() {
        assert_eq!(
            Cli::parse_from(["srvaudit", "h", "--out", "a.md"]).effective_report(),
            Some(ReportFormat::Markdown)
        );
        assert_eq!(
            Cli::parse_from(["srvaudit", "h", "--out", "a.json"]).effective_report(),
            Some(ReportFormat::Json)
        );
        assert_eq!(
            Cli::parse_from(["srvaudit", "h", "--report", "json", "--out", "a.md"])
                .effective_report(),
            Some(ReportFormat::Json),
            "an explicit --report wins"
        );
        assert_eq!(Cli::parse_from(["srvaudit", "h"]).effective_report(), None);
    }

    #[test]
    fn a_target_is_required_unless_replaying_a_file() {
        assert!(Cli::try_parse_from(["srvaudit"]).is_err());
        assert!(Cli::try_parse_from(["srvaudit", "--from-json", "a.json"]).is_ok());
        assert!(Cli::try_parse_from(["srvaudit", "h", "--from-json", "a.json"]).is_err());
    }
}
