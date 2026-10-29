# 🏺 Infrastructure Archaeologist

**Know what is safe to delete before you delete it.**

Infrastructure Archaeologist is a Linux CLI that discovers what is running on a
server, correlates the pieces, and answers one question with evidence:

> **“Can I delete this — and based on what?”**

It is designed for the moment when a service *looks* unused but may still be
holding a listener, a dependency, a scheduled job, or a live connection. The
tool never deletes anything for you. It collects evidence, records blind spots,
and produces a verdict plus a staged cleanup plan that you review and run by
hand.

> **Status:** v0.1.x early preview. Interfaces and schemas may change before a
> stable release. Linux only.

## Why this exists

“It looks unused” is not proof that something is unused. A typical server
contains invisible relationships:

- a process listens on a port that an nginx route still targets;
- a systemd unit is stopped but another active unit depends on it;
- a cron job runs once a month, outside a short observation window;
- a container still receives traffic through a proxy;
- a script is referenced by a timer but has not changed in months.

Infrastructure Archaeologist makes those relationships explicit. Every claim
is backed by an evidence row with a source and `raw_ref`; missing access becomes
a **blind spot**, never a guess.

## What it does

- **Discovers** processes, listeners, systemd units, Docker and Compose
  projects, nginx routes, cron jobs and timers, scripts, git repositories, and
  CI metadata.
- **Correlates** them into an evidence-backed dependency graph.
- **Observes** network activity over time to distinguish “idle now” from
  “unused across a full observation window.”
- **Issues deterministic verdicts:** `ACTIVE`, `LIKELY_ORPHANED`, `ORPHANED`,
  or `UNKNOWN`.
- **Explains** the blockers, signals, evidence coverage, and blind spots behind
  a verdict.
- **Generates** six-stage cleanup plans with matching rollback commands. It
  never executes those commands.
- **Exports** HTML, JSON, or Markdown reports and serves a local evidence
  dashboard.

## Requirements

- Linux for release binaries (`amd64` and `arm64`).
- Go `1.27.1` or newer when building from source; see `go.mod`.
- Root or equivalent read permissions for full coverage. Running without them
  is allowed: gaps are reported as blind spots.

The binary is self-contained; the release builds are static and use no runtime
database server.

## Install

### From a release

Download the archive for your architecture and `checksums.txt` from the
[releases page](https://github.com/phamminhkhoa2k4/arch/releases), then verify
and unpack. Replace `<version>` and `<arch>` with the values in the asset name
(for example, `0.1.0` and `amd64`):

```sh
# Verify only the archive you downloaded; checksums.txt covers every release asset.
grep "archaeologist_<version>_linux_<arch>.tar.gz$" checksums.txt | sha256sum -c -
tar -xzf archaeologist_<version>_linux_<arch>.tar.gz
./archaeologist --version
```

Install it system-wide if you want to call it from any directory:

```sh
sudo install -m 0755 archaeologist /usr/local/bin/archaeologist
```

### From source

```sh
git clone https://github.com/phamminhkhoa2k4/arch.git
cd arch
go build -o archaeologist ./cmd/archaeologist
sudo install -m 0755 archaeologist /usr/local/bin/archaeologist
```

## Quick start

Run the access check first. It tells you which sources are readable and which
gaps will become blind spots:

```sh
sudo ./archaeologist doctor
```

Scan the host into a local SQLite database. The scan is read-only; the tool
writes only its own database and output files:

```sh
sudo ./archaeologist scan --db scan.db
```

Ask the central question for one component:

```sh
sudo ./archaeologist delete-check --db scan.db nginx.service
```

See *why* that verdict was reached — dependencies, evidence, and blind spots:

```sh
sudo ./archaeologist explain --db scan.db nginx.service
```

If the verdict is `LIKELY_ORPHANED` or `ORPHANED`, generate a staged cleanup
plan:

```sh
sudo ./archaeologist plan --db scan.db nginx.service
```

Plans are written under `cleanup-plans/` by default; use `--out` to choose
another directory. The component reference can be a name or an identity key. If a name is
ambiguous, the command prints the matching identity keys so you can choose the
exact target.

## How verdicts work

Each scan builds an evidence graph from independent sources. The rule engine
then looks for hard blockers, measures evidence coverage, and checks whether
the observation window is long enough for the component’s schedule.

| State | Meaning |
|---|---|
| `ACTIVE` | Something still depends on or uses the component. Do not delete it. |
| `UNKNOWN` | The evidence is incomplete, the observation window is too short, or the component has no reliable signal either way. Do not treat this as safe. |
| `LIKELY_ORPHANED` | No blockers were found and coverage is strong, but the component has not met every condition for `ORPHANED`. Review the evidence carefully. |
| `ORPHANED` | No blockers, high coverage, and a sufficient observation window. A cleanup plan may be generated, but human review is still required. |

The default rules use a **14-day observation window**, **30 days** without
activity for staleness, and **90 days** without a deploy for the no-deploy
signal. These thresholds and the rule set can be overridden on `delete-check`
and `plan` with `--rules-file rules.yaml`; verdicts are recomputed from stored
evidence without rescanning.

### Blockers

A blocker always wins over a “looks unused” signal. Examples include:

- an active nginx route still proxying to the component;
- inbound traffic inside the observation window;
- another active unit or Compose service depending on it;
- a cron job or timer still referencing it;
- a running process or container using it.

Run `explain` to see the exact blocker text and the evidence behind it.

### Exit codes

`delete-check` is automation-friendly:

| Exit code | Meaning |
|---|---|
| `0` | `ACTIVE` with no broken-route finding. |
| `1` | Needs attention: `UNKNOWN`, `LIKELY_ORPHANED`, `ORPHANED`, or a broken-route finding. |
| `2` | Execution error (bad database, unknown component, invalid flags, and so on). |

## Observation mode

A single scan is a snapshot. To distinguish “not running right now” from “not
used during its schedule,” run the observation sampler and leave it running:

```sh
sudo ./archaeologist observe --db scan.db --interval 5s
```

The sampler reads the socket tables and records activity in the same database.
It is a foreground process; use `nohup`, a terminal multiplexer, or the
provided systemd service. To install the service (the one explicit host change
the tool can make):

```sh
sudo ./archaeologist observe install-service --db "$PWD/scan.db"
```

Use the absolute path of the database you scanned; the service starts in a
different working directory. The quick start above creates `scan.db` in the
current directory, so `$PWD/scan.db` points at it.

Remove it with:

```sh
sudo ./archaeologist observe uninstall-service
```

Observation is especially important for monthly jobs, timers, and low-traffic
services. The default window is 14 days.

## Cleanup plans

`plan` is available only for `LIKELY_ORPHANED` and `ORPHANED` components. It
writes a plan directory containing a Markdown document, a provenance manifest
and six scripts:

1. `Candidate`
2. `Quarantined`
3. `Observed`
4. `Archived`
5. `Removed`
6. `Verified`

Every mutating step includes a rollback marker. The tool never runs a step.
You review and execute each script yourself, then record progress:

```sh
./archaeologist plan status --db scan.db nginx.service
./archaeologist plan confirm --db scan.db nginx.service Quarantined
```

Confirmations are order-enforced and persisted in the plan state. Re-running
`plan` keeps confirmed stages and regenerates the plan files from the current
verdict.

### Provenance and `plan check`

The stage scripts pin the binary, database and rules file they were generated
from, so a plan built against one database cannot silently verify itself
against another. `plan.json` records the scan, rules hash, entity fingerprint
and a SHA-256 of every generated script.

Run `plan check` before executing anything:

```sh
./archaeologist plan check --db scan.db nginx.service
```

It fails with a non-zero exit code when:

- a stage script was edited after generation;
- a stage script is missing;
- the rules changed since the plan was generated;
- the scan the plan was built from no longer exists;
- the manifest was written by an unsupported version.

It warns, without failing, when the latest scan differs from the plan's scan or
the component's fingerprint has changed — both are worth reviewing before you
act. `plan check` reads files only; it never runs a stage script.

The `Verified` stage re-scans and separates three outcomes rather than hiding
them behind `|| true`: the component still resolves (fail), the component is
gone (pass), or the command could not run (fail).

## Reports and local UI

Generate a Markdown or JSON report on stdout:

```sh
./archaeologist report --db scan.db --format md > report.md
./archaeologist report --db scan.db --format json > report.json
```

HTML is the default and requires an output path:

```sh
./archaeologist report --db scan.db -o report.html
```

Start the local dashboard after a scan:

```sh
./archaeologist serve --db scan.db --addr localhost:8080
```

The dashboard shows components, the dependency graph, plan status, and the
evidence behind each verdict. It binds to localhost by default and has no
authentication; do not expose it to an untrusted network.

## JSON output and schemas

Machine-readable output is available from `scan`, `delete-check`, `explain`,
and `report`:

```sh
./archaeologist scan --format json --db scan.db
./archaeologist delete-check --format json --db scan.db nginx.service
```

The published contracts live in [`schema/`](schema/):

- [`scan.schema.json`](schema/scan.schema.json)
- [`delete-check.schema.json`](schema/delete-check.schema.json)
- [`explain.schema.json`](schema/explain.schema.json)
- [`report.schema.json`](schema/report.schema.json)

Schema conformance tests validate the CLI output, including a negative proof
that removing a required field is rejected.

## Optional LLM explanation

Verdicts and evidence are deterministic and never require a network. If you
want a plain-language explanation, opt in with `--explain` and configure an
OpenAI-compatible endpoint:

```sh
export ARCHAEOLOGIST_LLM_BASE_URL=https://openrouter.ai/api/v1
export ARCHAEOLOGIST_LLM_API_KEY=<your-key>
export ARCHAEOLOGIST_LLM_MODEL=<model-name>

sudo -E ./archaeologist delete-check --db scan.db --explain nginx.service
```

The evidence payload is redacted before it is sent. Without an endpoint or key,
the core scan, verdict, plan, report, and UI commands continue to work offline.
The model is never treated as authority: the deterministic verdict remains the
answer, and LLM text is labeled as an explanation, not evidence.

## Safety and permissions

The analysis path is read-only with respect to the scanned host. The tool writes
only:

- its SQLite database (`--db`);
- generated plan and report files;
- the optional observation systemd unit when you explicitly run
  `observe install-service`.

It does not stop services, edit nginx configs, remove containers, or execute
cleanup scripts. Those actions remain yours.

`doctor` probes the sources below and prints a remediation hint for every gap:

| Source | Needs | Without it |
|---|---|---|
| processes (`/proc`) | read `/proc` | no process inventory |
| process environment (`/proc/<pid>/environ`) | same UID or root | environment evidence is skipped |
| listeners (`/proc/net`, `/proc/<pid>/fd`) | root or `CAP_SYS_PTRACE` | listener-to-process mapping gaps |
| systemd (D-Bus) | `/run/dbus/system_bus_socket` | no live unit inventory |
| systemd files | read unit files | no ExecStart/script discovery |
| Docker (`/var/run/docker.sock`) | docker group or root | no containers/images |
| nginx configs | read `/etc/nginx` | no route inventory |
| cron files | read `/etc/crontab` and `/etc/cron.d` | no cron inventory |
| access logs | group `adm` or root | no request-based activity evidence |
| systemd journal | journal access | no journal-based evidence |
| git repositories | read repository files | no repository/CI correlation |

Blind spots are first-class output: they appear in text, JSON, reports, and the
dashboard. `UNKNOWN` is not an error to ignore; it is a request for more access
or observation.

## Maintenance

- Back up `scan.db` and `cleanup-plans/` before replacing the binary.
- Remove the observation service with
  `sudo ./archaeologist observe uninstall-service`.
- The database contains host evidence. Treat it as sensitive and remove it when
  it is no longer needed.

## Development

```sh
make build       # compile all packages
make test        # go test ./...
make check       # build + test + lint (requires golangci-lint)
make cross       # linux/amd64 and linux/arm64 compile check
make benchmark   # correlation-quality report on the golden fixture
```

The golden fixture and lab scripts live under [`lab/`](lab/). CI runs the build,
test, lint, and correlation benchmark jobs. Release tags follow `vMAJOR.MINOR.PATCH`;
GoReleaser produces the linux archives and `checksums.txt`.

## Project layout

```text
cmd/archaeologist/   CLI entrypoint
cmd/bench/           golden-fixture benchmark
internal/cli/        commands and output formatting
internal/collector/  process, systemd, Docker, nginx, cron, git collectors
internal/store/      SQLite schema, evidence, graph, verdict persistence
internal/verdict/    deterministic rule engine
internal/rules/      embedded rules and overrides
internal/report/     HTML, Markdown, and JSON export
internal/webui/      local dashboard
internal/systemd/    D-Bus, journal, and service-install helpers
schema/              published JSON Schemas
lab/                 golden fixture and lab assets
```

## Limitations

- Linux is the only supported target for the released binaries.
- `UNKNOWN` means the evidence is insufficient. It is not a soft “probably
  safe” state.
- A clean verdict is not a backup. Review every generated script and maintain
  independent backups before destructive work.
- The tool does not provide automatic deletion, real-time monitoring, or
  multi-host orchestration.
- `serve` is a local operator UI, not an authenticated multi-user service.
