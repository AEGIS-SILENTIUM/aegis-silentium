# AEGIS-SILENTIUM v11 Changelog

## v11.0.0

### New Modules
- `c2/consensus/raft.py` — Full Raft consensus (leader election, log replication, snapshots)
- `c2/consensus/state_machine.py` — CommandStateMachine, KVStateMachine (SET/DEL/CAS/INCR/MSET)
- `c2/intelligence/ioc_manager.py` — IOC database with TTL, CIDR, wildcard, bulk ops
- `c2/intelligence/mitre_attack.py` — ATT&CK Enterprise v14, Navigator export
- `c2/intelligence/threat_graph.py` — PageRank threat actor graph, Tarjan path, clustering
- `c2/plugins/engine.py` — Hot-reload plugin engine, 11 hooks, timeout guard
- `c2/streaming/event_log.py` — Append-only event log, segments, consumer groups
- `c2/streaming/projector.py` — CQRS materialized views, built-in NodeStatus/Campaign/Alert views
- `c2/network/topology.py` — Dijkstra routing, chokepoint analysis, D3/DOT export
- `c2/network/scanner.py` — Async port scanner, banner grab, auto topology integration
- `c2/distributed/saga.py` — Saga orchestrator with compensation and retry
- `c2/distributed/service_registry.py` — TTL service registry with LB and watchers

### Upgraded Modules
- `c2/distributed/fencing.py` — Multi-resource, full epoch history, grace window, persist hook
- `c2/distributed/wal.py` — CRC32 checksums, segment rotation, checkpoint protocol, compaction

### API
- 175 total routes (+57 new in v11)
- New route groups: `/api/intelligence/*`, `/api/consensus/*`, `/api/network/*`, `/api/plugins/*`, `/api/stream/*`, `/api/distributed/saga/*`, `/api/distributed/services/*`
- `/api/v11/system` — comprehensive all-subsystems status

### Dashboard
- 10 new panels: IOC Manager, MITRE ATT&CK, Threat Graph, Raft/KV, Sagas, Service Registry, Topology, Port Scanner, Plugins, Event Log
- 4740 total lines (from 4010)

### Database
- `deployment/migrations/v11_full.sql` — 12 new tables, materialized view, updated indexes

### Testing
- `tests/unit/test_v11_modules.py` — 87 new tests
- 153 total unit tests across all modules

### Infrastructure
- `requirements.txt` — added pyotp, sqlalchemy, httpx, aiohttp, apscheduler, tenacity, cachetools

### Startup
- Banner updated: `AEGIS-SILENTIUM v11.0 online`
- All v11 singletons initialized at startup with graceful fallback on import failure
- Event log writes to streaming subsystem on every `emit()` call
- Plugin hooks dispatched asynchronously on every event
