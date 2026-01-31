# Clawprint

**Flight recorder and receipts for OpenClaw agent runs**

> "Show the Clawprint" / "Receipts for agent actions"

Clawprint is an audit, replay, and diff system for AI agent systems. It records every agent run (tool calls, outputs, metadata) in a tamper-evident ledger with offline replay capabilities, a cybersecurity-style web dashboard, and rich CLI analytics.

**Not a proxy/firewall** — Clawprint is purely an observer and recorder.

## Features

- **Out-of-process observer** — Connects to OpenClaw Gateway WebSocket without modifying core code
- **Tamper-evident ledger** — SHA-256 hash chain for every event with integrity verification
- **Secret redaction** — Automatic redaction of API keys, tokens, JWTs, AWS keys, GitHub PATs, and credentials
- **Offline replay** — Reconstruct agent runs with event breakdowns, agent run sections, and chat reconstruction
- **Web dashboard** — Dark-themed cybersecurity dashboard with filtered/paginated events, search, and bar charts
- **CLI analytics** — Colored output, event histograms, per-minute timeline, live recording spinner
- **Run diffing** — Compare two runs side-by-side with event kind breakdown
- **Cross-platform** — Runs on macOS, Linux, cloud VMs

## Quick Start

```bash
# Install
cargo install --path .

# Start recording (auto-discovers token from ~/.openclaw/openclaw.json)
clawprint record --gateway ws://127.0.0.1:18789 --out ./clawprints

# List recorded runs
clawprint list --out ./clawprints

# View in browser (cybersecurity dashboard)
clawprint view --run <run_id> --out ./clawprints --open

# Replay offline with rich transcript
clawprint replay --run <run_id> --out ./clawprints --offline

# Export transcript to file
clawprint replay --run <run_id> --out ./clawprints --offline --export transcript.md

# Verify hash chain integrity
clawprint verify --run <run_id> --out ./clawprints

# Show run statistics
clawprint stats --run <run_id> --out ./clawprints

# Compare two runs
clawprint diff --run-a <run_id_1> --run-b <run_id_2> --out ./clawprints
```

## Commands

| Command | Description |
|---------|-------------|
| `record` | Connect to gateway and record events in real-time with live progress spinner |
| `list` | List all recorded runs with duration, event count, and storage size |
| `view` | Launch web dashboard for browsing events interactively |
| `replay` | Reconstruct a run offline with agent run sections and chat output |
| `stats` | Show event type histogram, events-per-minute timeline, and agent run count |
| `verify` | Verify SHA-256 hash chain integrity for a recorded run |
| `diff` | Compare two runs with event kind breakdown |

## Web Dashboard

The `view` command launches a dark-themed cybersecurity dashboard at `http://127.0.0.1:8080`:

- **Dashboard page** — Summary cards (total runs, events, storage), clickable run list with status badges and integrity indicators
- **Run detail page** — Event breakdown bar chart, filter buttons per event kind, text search with debounce, paginated event list (50/page), collapsible JSON payloads, color-coded event cards

### API Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /api/runs` | List all runs with metadata and size |
| `GET /api/runs/:id/events` | Paginated events with `?kind=X&search=Y&page=N&per_page=50` |
| `GET /api/runs/:id/stats` | Event breakdown, timeline, agent run count |
| `GET /api/runs/:id/meta` | Run metadata |
| `GET /api/runs/:id/export` | Full event export as JSON |

## Storage Format

Each run is a self-contained "case file":

```
clawprints/
  runs/
    <run_id>/
      ledger.sqlite      # Events with SHA-256 hash chain (WAL mode, synchronous=FULL)
      artifacts/          # Compressed blobs (zstd)
        <hash_prefix>/<hash>.zst
      meta.json           # Run metadata + root hash
```

### SQLite Schema

Events are stored with sequential IDs, timestamps, event kind, JSON payload, span/parent IDs, and hash chain fields (`hash_prev`, `hash_self`). Artifacts are deduplicated by content hash and compressed with Zstandard.

## Event Types

| Kind | Description |
|------|-------------|
| `RUN_START` / `RUN_END` | Session boundaries |
| `AGENT_EVENT` | Raw gateway stream events (tool calls, results, agent lifecycle) |
| `TOOL_CALL` / `TOOL_RESULT` | Direct tool invocations and results |
| `OUTPUT_CHUNK` | Streamed assistant output (chat messages) |
| `PRESENCE` / `TICK` | Gateway heartbeat and event loop ticks |
| `SHUTDOWN` | Gateway shutdown signal |
| `CUSTOM` | Unknown/custom event types |

## Architecture

```
                                                        Storage
 OpenClaw       WebSocket        Clawprint             (SQLite + zstd)
 Gateway  <------------------>  Recorder  ---------->  ledger.sqlite
           (observer role)         |                   artifacts/
                                   |                   meta.json
                                   v
                              Web Viewer  <---  Browser
                              (Axum HTTP)       (Dashboard UI)
```

### Modules

| Module | Role |
|--------|------|
| `gateway` | WebSocket client for OpenClaw Gateway protocol v3 (req/res/event frames) |
| `record` | Recording session coordinator with live progress spinner |
| `storage` | SQLite ledger with hash chain, artifact store, filtered queries |
| `replay` | Offline replay with agent run grouping and chat reconstruction |
| `viewer` | Axum web server with dashboard UI and REST API |
| `redact` | Secret detection and redaction (regex-based, supports JWT/AWS/GitHub patterns) |

## Authentication

Clawprint auto-discovers the gateway auth token from `~/.openclaw/openclaw.json`:

```json
{
  "gateway": {
    "auth": {
      "token": "your-token-here"
    }
  }
}
```

Or pass it directly: `clawprint record --token <token>`

## Configuration

| Option | Default | Description |
|--------|---------|-------------|
| `--gateway` | `ws://127.0.0.1:18789` | Gateway WebSocket URL |
| `--out` | `./clawprints` | Output directory for recordings |
| `--token` | auto-discovered | Gateway auth token |
| `--no-redact` | `false` | Disable secret redaction |
| `--batch-size` | `100` | SQLite batch commit size |
| `--port` | `8080` | Web viewer port |
| `RUST_LOG` | `clawprint=info` | Log level (set to `clawprint=debug` for verbose output) |

## Integrity Verification

Every event includes a SHA-256 hash computed from its canonical form (excluding `hash_self`). Each event's `hash_prev` points to the previous event's `hash_self`, forming a tamper-evident chain. The `verify` command checks the entire chain and reports `VALID` or `TAMPERED`.

```bash
$ clawprint verify --run <run_id> --out ./clawprints
  Verifying hash chain for a1b2c3d4... VALID
  Events:    1234
  Root hash: 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
```

## Building

```bash
# Development
cargo build

# Release (optimized, LTO, stripped)
cargo build --release

# Run tests
cargo test

# Without web viewer feature
cargo build --no-default-features
```

## License

MIT
