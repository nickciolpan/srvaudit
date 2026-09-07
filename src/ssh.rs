//! Transport: the system `ssh` binary, driven over one multiplexed connection.
//!
//! Deliberately not a Rust SSH client. Going through OpenSSH means `~/.ssh/config`
//! aliases, `ProxyJump`, agent keys, certificates, FIDO tokens, 2FA prompts and
//! `known_hosts` all behave exactly as they do when you type `ssh` yourself —
//! none of which a reimplementation would get right for free.
//!
//! The first call opens a `ControlMaster` socket; refreshes reuse it, so you
//! authenticate once even if the audit is re-run from inside the TUI.

use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

#[derive(Debug, Clone, Default)]
pub struct SshTarget {
    /// `[user@]host` exactly as ssh wants it — may be an `~/.ssh/config` alias.
    pub destination: String,
    pub port: Option<u16>,
    pub user: Option<String>,
    pub identity: Option<PathBuf>,
    pub jump: Option<String>,
    /// Raw `-o Key=Value` pass-throughs.
    pub options: Vec<String>,
    pub connect_timeout: u64,
}

impl SshTarget {
    /// Accepts `host`, `user@host`, `host:2222`, `user@host:2222`, `[::1]:22`
    /// and any alias from the user's ssh config.
    pub fn parse(spec: &str) -> Result<Self> {
        let spec = spec.trim();
        if spec.is_empty() {
            bail!("empty target");
        }
        let (user, hostpart) = match spec.rsplit_once('@') {
            Some((u, h)) => (Some(u.to_string()), h),
            None => (None, spec),
        };
        let (host, port) = split_host_port(hostpart);
        if host.is_empty() {
            bail!("could not read a hostname out of {spec:?}");
        }
        let destination = match &user {
            Some(u) => format!("{u}@{host}"),
            None => host,
        };
        Ok(Self {
            destination,
            port,
            connect_timeout: 15,
            ..Default::default()
        })
    }

    /// What the user typed, for titles and export filenames.
    pub fn label(&self) -> String {
        match self.port {
            Some(p) => format!("{}:{p}", self.destination),
            None => self.destination.clone(),
        }
    }

    fn base_args(&self, control: Option<&PathBuf>) -> Vec<String> {
        let mut a: Vec<String> = vec![
            "-o".into(),
            format!("ConnectTimeout={}", self.connect_timeout),
        ];
        if let Some(path) = control {
            a.push("-o".into());
            a.push("ControlMaster=auto".into());
            a.push("-o".into());
            a.push(format!("ControlPath={}", path.display()));
            a.push("-o".into());
            a.push("ControlPersist=120".into());
        }
        if let Some(p) = self.port {
            a.push("-p".into());
            a.push(p.to_string());
        }
        if let Some(i) = &self.identity {
            a.push("-i".into());
            a.push(i.display().to_string());
            // An explicit key should be the only key we offer, otherwise the
            // agent can burn through the server's auth attempt budget first.
            a.push("-o".into());
            a.push("IdentitiesOnly=yes".into());
        }
        if let Some(j) = &self.jump {
            a.push("-J".into());
            a.push(j.clone());
        }
        if let Some(u) = &self.user {
            a.push("-l".into());
            a.push(u.clone());
        }
        for o in &self.options {
            a.push("-o".into());
            a.push(o.clone());
        }
        a
    }
}

/// `host:2222` -> `("host", 2222)`; leaves bare IPv6 literals alone.
fn split_host_port(s: &str) -> (String, Option<u16>) {
    if let Some(rest) = s.strip_prefix('[')
        && let Some((inner, tail)) = rest.split_once(']')
    {
        let port = tail.strip_prefix(':').and_then(|p| p.parse().ok());
        return (inner.to_string(), port);
    }
    if s.matches(':').count() == 1
        && let Some((h, p)) = s.rsplit_once(':')
        && let Ok(port) = p.parse::<u16>()
        && !h.is_empty()
    {
        return (h.to_string(), Some(port));
    }
    (s.to_string(), None)
}

#[derive(Debug)]
pub struct Run {
    pub stdout: String,
    pub stderr: String,
    pub code: Option<i32>,
}

/// A connection whose control socket is kept alive between runs.
#[derive(Debug)]
pub struct Session {
    pub target: SshTarget,
    control: Option<PathBuf>,
}

impl Session {
    pub fn open(target: SshTarget) -> Self {
        Self {
            control: control_socket().ok(),
            target,
        }
    }

    /// Feed `script` to a remote `sh` and collect everything it prints.
    pub async fn run(&self, script: &str, timeout: Duration) -> Result<Run> {
        let mut cmd = Command::new("ssh");
        cmd.args(self.target.base_args(self.control.as_ref()))
            .arg("-T")
            .arg(&self.target.destination)
            .arg("sh")
            .arg("-s")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        let mut child = cmd.spawn().context(
            "could not run `ssh` — it must be installed and on PATH (srvaudit drives OpenSSH \
             rather than reimplementing it)",
        )?;

        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| anyhow!("ssh stdin was not available"))?;
        stdin.write_all(script.as_bytes()).await?;
        stdin.shutdown().await?;
        drop(stdin);

        let wait = child.wait_with_output();
        tokio::pin!(wait);
        let out = tokio::select! {
            r = &mut wait => r.context("waiting for ssh")?,
            _ = tokio::time::sleep(timeout) => bail!(
                "the audit did not finish within {}s. `du` over a huge directory is the usual \
                 cause — try --no-du, a smaller --du-path, or a longer --timeout.",
                timeout.as_secs()
            ),
        };

        Ok(Run {
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
            code: out.status.code(),
        })
    }

    /// Tear down the multiplexed master; best effort, never fatal.
    pub async fn close(&self) {
        let Some(path) = &self.control else { return };
        let _ = Command::new("ssh")
            .args(self.target.base_args(None))
            .arg("-o")
            .arg(format!("ControlPath={}", path.display()))
            .arg("-O")
            .arg("exit")
            .arg(&self.target.destination)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await;
        if let Some(dir) = path.parent() {
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}

/// A private 0700 directory holding the control socket.
///
/// The name is unique per run and `create_dir` fails if it already exists, so
/// nobody can pre-place a socket we would then talk to. Unix domain socket
/// paths are capped near 104 bytes, so fall back to `/tmp` when the platform
/// temp dir is long (macOS `/var/folders/...` is).
fn control_socket() -> Result<PathBuf> {
    use std::os::unix::fs::DirBuilderExt;

    let unique = format!(
        ".srvaudit-{}-{:x}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0)
    );

    let mut candidates = vec![std::env::temp_dir().join(&unique)];
    candidates.push(PathBuf::from("/tmp").join(&unique));

    let mut last = None;
    for dir in candidates {
        if dir.join("cm").as_os_str().len() > 100 {
            continue;
        }
        match std::fs::DirBuilder::new().mode(0o700).create(&dir) {
            Ok(()) => return Ok(dir.join("cm")),
            Err(e) => last = Some(e),
        }
    }
    Err(anyhow!(
        "no usable directory for the ssh control socket: {}",
        last.map(|e| e.to_string())
            .unwrap_or_else(|| "path too long".into())
    ))
}

// -------------------------------------------------------------- tests ----

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_forms() {
        let t = SshTarget::parse("web-01").unwrap();
        assert_eq!(t.destination, "web-01");
        assert_eq!(t.port, None);

        let t = SshTarget::parse("deploy@web-01.acme.io").unwrap();
        assert_eq!(t.destination, "deploy@web-01.acme.io");

        let t = SshTarget::parse("deploy@10.0.0.7:2222").unwrap();
        assert_eq!(t.destination, "deploy@10.0.0.7");
        assert_eq!(t.port, Some(2222));
        assert_eq!(t.label(), "deploy@10.0.0.7:2222");

        let t = SshTarget::parse("[2001:db8::1]:22").unwrap();
        assert_eq!(t.destination, "2001:db8::1");
        assert_eq!(t.port, Some(22));

        // A bare IPv6 literal has many colons and no port.
        let t = SshTarget::parse("2001:db8::1").unwrap();
        assert_eq!(t.destination, "2001:db8::1");
        assert_eq!(t.port, None);

        assert!(SshTarget::parse("   ").is_err());
    }

    #[test]
    fn args_carry_every_option_through() {
        let t = SshTarget {
            destination: "web-01".into(),
            port: Some(2222),
            user: Some("audit".into()),
            identity: Some("/keys/id_ed25519".into()),
            jump: Some("bastion".into()),
            options: vec!["StrictHostKeyChecking=accept-new".into()],
            connect_timeout: 9,
        };
        let a = t.base_args(Some(&PathBuf::from("/tmp/x/cm"))).join(" ");
        assert!(a.contains("ConnectTimeout=9"));
        assert!(a.contains("ControlPath=/tmp/x/cm"));
        assert!(a.contains("-p 2222"));
        assert!(a.contains("-i /keys/id_ed25519"));
        assert!(a.contains("IdentitiesOnly=yes"));
        assert!(a.contains("-J bastion"));
        assert!(a.contains("-l audit"));
        assert!(a.contains("-o StrictHostKeyChecking=accept-new"));

        // Without a control path we must not emit multiplexing options.
        let plain = t.base_args(None).join(" ");
        assert!(!plain.contains("ControlMaster"));
    }

    #[test]
    fn control_socket_is_private_and_short_enough() {
        let sock = control_socket().unwrap();
        assert!(sock.as_os_str().len() <= 100);
        let dir = sock.parent().unwrap();
        let meta = std::fs::metadata(dir).unwrap();
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(meta.permissions().mode() & 0o777, 0o700);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
