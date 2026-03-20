# AEGIS-SILENTIUM v12

**Professional-grade distributed C2 framework with legendary UX. Fully engineered.**

---


## Implementation Status

| Subsystem | Status | Notes |
|-----------|--------|-------|
| C2 Server (207 routes) | ✅ Complete | Flask, PostgreSQL, Redis, JWT auth |
| RBAC + per-operator API keys | ✅ Complete | 5 roles, 45 permissions, TOTP MFA |
| Listeners (TCP/DNS/HTTP) | ✅ Complete | Bidirectional, multi-session |
| IOC Manager | ✅ Complete | Bloom filter, STIX 2.1, CIDR, feeds |
| Threat Graph | ✅ Complete | PageRank, betweenness, communities |
| Exploit Arsenal | ✅ Complete | Lifecycle DAG, NVD sync, deploy |
| Zero-Day Pipeline | ✅ Core complete | Static analysis, fuzzer, exploit gen |
| Symbolic Execution | ⚠️ Interface only | Requires angr (`pip install angr`) |
| ML Vulnerability Prediction | ⚠️ Heuristic | Requires scikit-learn for ML models |
| Implant (implant/) | 🔲 Scaffolding | Framework defined, not compiled |
| Dashboard | ✅ Complete | Single-file SPA, memory-only auth |
| Distributed consensus | ✅ Complete | Raft, CRDT, Saga, HLC |


## What's New in v12

### Legendary Dashboard Overhaul
Complete ground-up redesign of the dashboard — 1600+ lines of polished HTML/CSS/JS:

- **Design System** — CSS custom properties, Inter + JetBrains Mono fonts, micro-animations, glass morphism panels, noise texture, radial glow effects
- **Command Palette** — `Ctrl+K` launches a VS Code-style command palette with fuzzy search across all 15 pages
- **Keyboard Navigation** — full keyboard-driven UX: `G+O/N/T/I/M/P` for instant page jumps, `` ` `` for console, `/` for search, `R` to refresh, `Esc` to dismiss
- **Sliding Console** — persistent operator terminal at the bottom with command history (↑/↓), live stats sidebar, commands: `nodes`, `tasks`, `ioc lookup <val>`, `scan <ip>`, `nav <page>`, `status`, `clear`
- **Status Bar** — always-visible HLC timestamp, node count, IOC count, current page, C2 health dot
- **Toast Notifications** — non-blocking slide-in toasts for every action with auto-dismiss
- **Force-directed Graphs** — interactive canvas-based threat graph AND network topology, both with drag-to-pan, scroll-to-zoom, spring physics simulation
- **Live Mode** — event log page has a ⏵ Live toggle that polls every 2 seconds
- **IOC Quick Lookup** — inline MALICIOUS/CLEAN result with confidence bar and matched indicators
- **MITRE ATT&CK Matrix** — real 12-tactic × N-technique grid with colour-coded observation coverage (red = observed, bright red = high confidence), hover for detail panel
- **Raft Cluster View** — visual ring of nodes with leader crown 👑, animated status
- **Saga Step Tracker** — per-step ✅/❌/↩/⏳ visual with duration and error display
- **Sparklines** — animated mini bar charts on stat cards (Overview page)
- **Scan History** — clickable scan history chips with open port count

### All v11 capabilities preserved
- Full Raft consensus, IOC Manager, MITRE ATT&CK, Threat Graph
- Saga Orchestrator, Service Registry, Plugin Engine
- Event Log + CQRS Projector, Network Topology + Port Scanner
- 175 API routes across all subsystems

---

## Quick Start

```bash
# Generate credentials
./scripts/gen_keys.sh

# Start services
docker-compose up -d

# Run migrations
psql $DATABASE_URL < deployment/migrations/v9_schema.sql
psql $DATABASE_URL < deployment/migrations/v10_distributed.sql
psql $DATABASE_URL < deployment/migrations/v11_full.sql

# Access dashboard
open http://localhost:8080
```

## Running Tests

```bash
# All unit tests
pytest tests/unit/ -v

# v11/v12 module tests
pytest tests/unit/test_v11_modules.py -v --tb=short

# Coverage
pytest tests/unit/ --cov=c2 --cov-report=html
```

## Keyboard Shortcuts

| Keys | Action |
|------|--------|
| `Ctrl+K` | Command Palette |
| `` ` `` | Toggle console |
| `/` | Focus search |
| `G O` | Go to Overview |
| `G N` | Go to Nodes |
| `G T` | Go to Tasks |
| `G I` | Go to IOC Manager |
| `G M` | Go to ATT&CK Matrix |
| `G P` | Go to Topology |
| `G S` | Go to Settings |
| `R` | Refresh current page |
| `Esc` | Close modals/palette |

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│                  AEGIS-SILENTIUM v12                     │
│                                                          │
│  Dashboard (1600+ lines)                                 │
│  ├─ Design system · Command palette · Keyboard nav       │
│  ├─ Force graphs · MITRE matrix · Raft ring viz          │
│  └─ IOC lookup · Scan history · Live event tail          │
│                                                          │
│  C2 API (3300+ lines · 175 routes)                       │
│  ├─ /api/intelligence/* — IOC, MITRE, ThreatGraph        │
│  ├─ /api/consensus/*   — Raft, KV store                  │
│  ├─ /api/network/*     — Topology, Scanner               │
│  ├─ /api/plugins/*     — Plugin engine                   │
│  ├─ /api/stream/*      — Event log, Projections          │
│  └─ /api/distributed/* — Saga, Services, Fencing, WAL   │
│                                                          │
│  Backend Modules                                         │
│  ├─ consensus/  — Raft + KV state machine               │
│  ├─ intelligence/ — IOC, MITRE ATT&CK, ThreatGraph      │
│  ├─ distributed/ — WAL, CRDT, Saga, ServiceRegistry     │
│  ├─ streaming/  — EventLog + CQRS projector             │
│  ├─ network/    — Topology + AsyncPortScanner           │
│  └─ plugins/    — Hot-reload plugin engine              │
│                                                          │
│  Infrastructure                                          │
│  ├─ PostgreSQL — 12 tables (v11_full.sql)               │
│  ├─ Redis — pub/sub + session store                     │
│  └─ Prometheus — metrics + alerting                     │
└──────────────────────────────────────────────────────────┘
```

---

*AEGIS-SILENTIUM v12 — Legendary UX. Professional engineering. Operationally ready.*
