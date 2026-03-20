# AEGIS-SILENTIUM v12 Changelog

## v12.0.0 — Legendary UX Release

### Dashboard — Complete Ground-Up Redesign

**Visual Design System**
- CSS custom property design tokens (20+ color vars, typography, spacing, radius, transitions)
- Inter + JetBrains Mono font stack via Google Fonts
- Radial glow effects on stat cards hover, noise texture overlay
- Smooth page transition animations (opacity + translateY)
- 5px custom scrollbars throughout
- Mobile-responsive sidebar collapse at 1024px

**Navigation & UX**
- Command Palette (`Ctrl+K`) — VS Code-style fuzzy search over all pages and actions
- Full keyboard navigation: G+letter for instant page jumps, `` ` `` console, `/` search, `R` refresh, `Esc` dismiss
- Active nav highlight with left border accent, icon + label layout, badge counters
- Persistent status bar: HLC timestamp, node count, IOC count, current page, C2 health indicator

**Interactive Visualizations**
- Threat Graph: canvas-based force-directed graph with spring physics (90 iterations), drag-to-pan, scroll-to-zoom, color-coded by node kind, glow halos, edge arrows, node labels
- Network Topology: independent canvas with same physics, color-coded by role (DC=red, web=cyan, DB=amber, firewall=orange, router=purple, C2=green), latency labels on edges
- MITRE ATT&CK Matrix: real 12-tactic grid rendered from API data, color-coded cells (observed=red, high-confidence=bright red), click for detail panel
- Raft Cluster Ring: visual node display with leader crown emoji, term/commit/leader info

**Components**
- Sliding bottom console: operator terminal with command history (↑/↓ arrows), live stats sidebar, built-in commands (nodes, tasks, ioc lookup, scan, nav, status, clear)
- Toast notifications: slide-in from right, type-colored left border (success/error/warn/info), auto-dismiss 3.5s
- Modal system: animated scale-in, focus management, multi-button footer
- Timeline component: left-border events with colored dots
- Progress bars: gradient fills (cyan/green/red/amber)
- Sparklines: animated mini bar charts on overview stat cards
- Scan history: clickable chips with open-port count and timestamp

**Pages Enhanced**
- Overview: 6 stat cards with sparklines, live event timeline, system health + subsystem grid, recent nodes/tasks tables
- IOC Manager: Quick Lookup tool with MALICIOUS/CLEAN inline result + confidence bar, bulk import modal, type/severity/tag filters, full CRUD
- ATT&CK Matrix: rendered from live API data, tactic columns, clickable techniques → detail panel, observation recording modal, Navigator JSON export
- Saga: per-step progress bar, step-count breakdown, duration column, click for step-by-step modal
- Services: service cards with instance list, heartbeat/deregister buttons, discover action
- Consensus: Raft ring visualization, metrics panel, KV grid view with clickable keys
- Port Scanner: timing profiles, banner grab option, scan history chips, auto-topology integration
- Event Log: live mode toggle (2s polling), projections stats, payload preview column

### Backend — v12 Fixes
- Startup banner updated: `AEGIS-SILENTIUM v12.0 online`
- All module imports updated to relative paths (no `c2.` prefix)
- Distributed imports fixed: saga, service_registry, fencing v11

### Files Changed
- `dashboard/dashboard.html` — complete rewrite (1606 lines)
- `README.md` — full v12 documentation
- `docs/CHANGELOG_v12.md` — this file
- `c2/app.py` — startup banner v12
