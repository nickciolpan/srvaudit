<h1 align="center">srvaudit</h1>

<p align="center">
  A terminal audit dashboard for a remote Linux server.<br>
  <b>What is listening · what is running · where the data is · what starts on its own.</b>
</p>

<p align="center">
  <a href="https://github.com/nickciolpan/srvaudit/actions/workflows/ci.yml"><img src="https://github.com/nickciolpan/srvaudit/actions/workflows/ci.yml/badge.svg" alt="ci"></a>
  <a href="https://github.com/nickciolpan/srvaudit/releases/latest"><img src="https://img.shields.io/github/v/release/nickciolpan/srvaudit?color=%2300a3a3" alt="latest release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="MIT"></a>
  <img src="https://img.shields.io/badge/rust-2024%20edition-orange.svg" alt="rust 2024">
</p>

```console
$ srvaudit web-01 --sudo
```

```
╭──────────────────────────────────────────────────────────────────────────────────────────────╮
│ lab1  Debian GNU/Linux 13 (trixie)  6.12.101+deb13-arm64                                     │
│ nick@192.168.64.50  sudo  up 1 day, 2 hours  load 0.00 0.01 0.00  cpus 2                     │
╰──────────────────────────────────────────────────────────────────────────────────────────────╯
  1 Overview │ 2 Ports │ 3 Containers │ 4 Services │ 5 Disks │ 6 Dirs │ 7 Schedules │ 8 Probes
╭───────────────────╮╭───────────────────╮╭───────────────────╮╭───────────────────╮
│ FINDINGS          ││ LISTENING         ││ CONTAINERS        ││ FULLEST DISK      │
│ 5                 ││ 9                 ││ 3/5               ││ 96%               │
│ 2 high · 2 med    ││ 6 on all ifaces   ││ running / total   ││ /                 │
╰───────────────────╯╰───────────────────╯╰───────────────────╯╰───────────────────╯
╭ Overview (5) ────────────────────────────────────────────────────────────────────────────────╮
│HIGH / is 96% full                        91G of 100G used on /dev/sda1 (ext4), 4.2G free     │
│HIGH / has used 94% of its inodes         Writes fail with ENOSPC once inodes run out, even w │
│HIGH Redis is listening on every interfa  tcp 0.0.0.0:6379 (redis-server). Anything that can  │
│MED  4 container ports published on 0.0.  Docker inserts its own iptables rules ahead of INPU │
│MED  1 service failed                     unattended-upgrades.service                         │
╰──────────────────────────────────────────────────────────────────────────────────────────────╯
 ↹/1-8 tab  ↑↓ move  ⏎ detail  / filter  s/S sort  r refresh  e export  ? help  q quit
```

One SSH connection, one read-only shell script, about half a second.

---

## Install

**Homebrew** — macOS and Linux:

```sh
brew install nickciolpan/tap/srvaudit
```

**Linux / macOS one-liner** — downloads the release binary for your platform and
verifies its published checksum before installing:

```sh
curl -fsSL https://raw.githubusercontent.com/nickciolpan/srvaudit/main/install.sh | sh
```

Set `PREFIX=~/.local/bin` to choose where it lands, or `SRVAUDIT_VERSION=v0.1.0`
to pin a version.

**Prebuilt binaries** — [every release](https://github.com/nickciolpan/srvaudit/releases/latest)
ships `darwin-arm64`, `darwin-amd64`, `linux-amd64` and `linux-arm64` tarballs
with checksums. The Linux builds are statically linked against musl, so they run
on any distribution regardless of its glibc.

**From source** — needs Rust 1.85+ (2024 edition):

```sh
cargo install --git https://github.com/nickciolpan/srvaudit
```

The only runtime dependency is the `ssh` client, which you already have.

---

## Usage

```sh
srvaudit web-01                        # an ~/.ssh/config alias
srvaudit deploy@10.0.0.7:2222          # or the long form
srvaudit web-01 --sudo                 # see process names, other users' crontabs
srvaudit web-01 -J bastion             # through a jump host
srvaudit web-01 --report markdown      # no TUI, print a report
srvaudit web-01 --out audit.json       # save it
srvaudit --from-json audit.json        # reopen it later, offline
```

| Flag | |
| --- | --- |
| `--sudo` | run privileged probes through `sudo -n` |
| `--du-path DIR` | directory to measure, repeatable (default `/var/lib`) |
| `--no-du` | skip the `du` pass entirely |
| `--timeout` / `--du-timeout` | seconds before giving up (default 120 / 45) |
| `-p` `-u` `-i` `-J` `-o` | port, user, key, jump host, raw ssh options |
| `--report text\|markdown\|json` | print instead of opening the TUI |
| `--out FILE` | write the report; format inferred from the extension |
| `--from-json FILE` | replay a saved audit |

### Keys

| | |
| --- | --- |
| `1`–`8`, `tab`, `← →` | switch tab |
| `↑ ↓`, `j k`, `pgup/pgdn`, `g G` | move |
| `enter` | row detail — on the Overview, jump to the evidence |
| `/` | filter (matches hidden detail too) |
| `s` / `S` | cycle sort column / reverse |
| `r` | re-run over the same SSH connection |
| `e` | export JSON + Markdown |
| `?` `q` | help, quit |

---

## What it actually runs

Nothing that writes. These are the read-only commands you would type yourself,
sent as one script to one remote `sh`:

| Question | Command |
| --- | --- |
| What is listening? | `ss -tulnp` (falls back to `netstat -tulnp`) |
| What containers exist? | `docker ps -a` (falls back to `podman ps -a`) |
| What services run? | `systemctl list-units --type=service --state=running,failed,exited` |
| What starts at boot? | `systemctl list-unit-files --type=service --state=enabled` |
| What is scheduled? | `crontab -l`, `/etc/crontab`, `/etc/cron.d/*`, `/etc/cron.{hourly,daily,weekly,monthly}`, `systemctl list-timers` |
| How full is the disk? | `df -hPT` and `df -iP` |
| Where did the disk go? | `du -shx /var/lib/*` |
| Who am I here? | `uname`, `/etc/os-release`, `/proc/loadavg`, `/proc/meminfo`, `id -un` |

Beyond that checklist it also collects **UDP listeners**, **inode usage** (a full
inode table fails writes while `df -h` still looks fine), **failed** units
alongside running ones, **enabled-but-never-started** units, and **systemd
timers** — which are how modern distributions schedule the work cron used to do.

---

## Three decisions worth knowing about

**It drives OpenSSH rather than reimplementing SSH.** Your `~/.ssh/config`
aliases, `ProxyJump`, agent keys, certificates, FIDO tokens, 2FA prompts and
`known_hosts` all behave exactly as they do when you type `ssh` yourself. The
first connection opens a `ControlMaster` socket in a private `0700` directory,
so pressing `r` to refresh reuses it and does not authenticate again.

**It never prompts for a sudo password.** `--sudo` uses `sudo -n` only. If sudo
wants a password, the privileged probes are skipped and the Overview says so. An
audit tool that can hang forever on a hidden password prompt is worse than one
that tells you what it could not see.

**"Denied" is never rendered as "none".** Every probe records whether it
succeeded, was refused, found the tool missing, or came back *partial*. An empty
tab says either *nothing here* or *unknown, not empty: docker ps -a — permission
denied*. And a probe that returns most of an answer keeps it: `du -shx
/var/lib/*` exits 1 when a couple of subdirectories are root-only, having
correctly sized the other twenty — that is recorded as partial, with the data
intact and the gap reported, not thrown away as a failure. The Probes tab shows
every command, its exit code and its raw output, so you can check the tool's
homework.

---

## Findings

The Overview ranks what a competent admin would want to see first: datastores
and admin APIs bound to `0.0.0.0` (Postgres, Redis, Mongo, Elasticsearch, the
unauthenticated Docker API, kubelet, …), filesystems past 80% and 90%, inode
exhaustion, failed units, crash-looping containers, container ports published on
`0.0.0.0` (which bypass `ufw`/`firewalld`, because Docker writes its own iptables
chain ahead of `INPUT`), cron jobs that pipe a downloaded script straight into a
shell, and `@reboot` jobs. Ports 22, 80 and 443 on `0.0.0.0` are not findings —
that is what they are for.

Findings are heuristics on a point-in-time snapshot, not a compliance scan.
Everything is derived from output shown in the Probes tab; when a heuristic is
wrong, the evidence to see that is one keypress away.

---

## Development

```sh
cargo test      # 59 tests: parsers against captured real output, findings,
                # view-model, TUI rendering at six terminal sizes, and the
                # generated script executed by a real /bin/sh
cargo clippy --all-targets
```

`testdata/` holds captured output from `ss`, `netstat`, `docker`, `systemctl`,
`df`, `du` and the cron sources; the parsers are tested against it directly, so
a distro that formats a column differently gets fixed with a fixture and a test.
`timers.txt` and `timers-systemd257.txt` are the same command from two systemd
generations — the older prints `5h left`, the newer a bare `2h 10min` — and both
parse by anchoring on the timestamps rather than on the word "left".

Releases are cut by pushing a tag: `git tag v0.1.0 && git push origin v0.1.0`
builds all four targets, publishes them with checksums, and the Homebrew formula
in [nickciolpan/homebrew-tap](https://github.com/nickciolpan/homebrew-tap) points
at them.

## License

MIT © Nick Ciolpan
