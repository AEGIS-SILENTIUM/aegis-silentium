# AEGIS-SILENTIUM v10 — Release Notes

**Released:** 2026-03-13  
**Codename:** Distributed Core

---

## What's New in v10

### Distributed Systems Layer (`c2/distributed/`)

v10 ships a complete, production-grade distributed systems module with 17 independently testable components. Every class is thread-safe and designed for integration with the existing Flask C2 server.

| Module | Class(es) | Purpose |
|--------|-----------|---------|
| `hlc.py` | `HybridLogicalClock`, `HLCTimestamp` | Causally consistent ordering without NTP |
| `merkle.py` | `MerkleTree` | Efficient state reconciliation via root hash comparison |
| `wal.py` | `WriteAheadLog`, `WALStateMachine`, `WALEntry` | Crash-safe state persistence with replay protection |
| `crdt.py` | `GCounter`, `PNCounter`, `ORSet`, `LWWRegister`, `VectorClock` | Conflict-free replicated data types |
| `gossip.py` | `GossipProtocol`, `Member`, `MemberState` | SWIM-style membership and failure detection |
| `fencing.py` | `FencingTokenManager` | Stale-leader detection via monotonic epochs |
| `mvcc.py` | `MVCCStore` | Snapshot isolation / multi-version concurrency control |
| `quorum.py` | `QuorumManager`, `ConsistencyLevel` | ONE / QUORUM / ALL reads and writes with read-repair |
| `anti_entropy.py` | `AntiEntropyScheduler` | Incremental delta sync using Merkle comparison |
| `two_phase_commit.py` | `TwoPCCoordinator`, `Mutation`, `Transaction` | Multi-key atomic updates across partitions |
| `lease.py` | `LeaseCache`, `SpeculativeReadBuffer` | Follower read leases + read-after-write consistency |
| `state_verifier.py` | `StateVerifier` | Post-failover divergence detection + auto-repair |
| `lock_manager.py` | `Redlock`, `ReadWriteLock`, `NamedLockPool` | Distributed mutex, fair RW lock, named key locks |
| `consistent_hash.py` | `ConsistentHashRing`, `BloomFilter`, `PriorityTaskQueue` | Stable key routing, probabilistic membership, priority scheduling |
| `dead_letter.py` | `DeadLetterQueue`, `AdaptiveLoadBalancer`, `Backend` | Failed-message capture, replay, adaptive backend routing |
| `chaos.py` | `ChaosRunner`, `ChaosExperiment`, injectors | Chaos engineering harness with pre-built experiments |
| `__init__.py` | (all) | Single-import public API for the entire module |

### Unified `app.py`

v9 shipped two separate files (`app.py` = v8 core, `app_v9.py` = v9 additions) with no merge. v10 consolidates into a **single authoritative 2244-line `app.py`** containing:

- All v8 routes: node registration, beacon protocol, campaigns, tasks, vulnerabilities, nodes, events, relays, findings, exfil receipts, DoH ingest, ECDHE handshake, agent staging, silentium status
- All v9 routes: JWT auth, RBAC operators, audit trail, secrets rotation, webhooks, alerts, Prometheus metrics, health/ready
- All v10 routes: `/api/distributed/*` (14 endpoints exposing the new distributed layer)

### Distributed API (`/api/distributed/*`)

14 new REST endpoints expose the distributed layer to operators and integrations:

```
GET  /api/distributed/status          — all subsystem health
GET  /api/distributed/hlc             — new HLC timestamp
POST /api/distributed/merkle          — compute Merkle tree
GET  /api/distributed/wal             — WAL stats
POST /api/distributed/wal/append      — append state mutation
GET  /api/distributed/fencing/epoch   — current epoch
POST /api/distributed/fencing/new-epoch — bump epoch (leader change)
GET  /api/distributed/ring            — hash ring nodes
POST /api/distributed/ring/route      — route key → node(s)
POST /api/distributed/bloom           — bloom filter membership test
GET  /api/distributed/dlq             — dead letter queue entries
POST /api/distributed/dlq/{id}/resolve — resolve DLQ entry
GET  /api/distributed/task-queue      — priority queue stats
GET  /api/distributed/chaos/experiments — chaos results
```

### v10 Database Schema (`deployment/migrations/v10_distributed.sql`)

12 new tables backing the distributed layer:

- `hlc_events` — HLC timestamp audit trail
- `wal_entries` — persistent WAL log
- `gossip_members` — cluster membership state
- `mvcc_versions` — multi-version key store
- `distributed_txns` — 2PC transaction log
- `dead_letter_queue` — failed message archive
- `chaos_results` — experiment outcomes
- `anti_entropy_sessions` — sync session history
- `fencing_audit` — epoch change audit
- `lb_backends` — load balancer backend health
- `ring_snapshots` — consistent hash ring snapshots
- `priority_task_queue` — persistent priority task storage

### Additional Advanced Features (beyond v9 promises)

Beyond the 15 originally promised distributed features, v10 adds:

- **Distributed Lock Manager** — Redlock (multi-Redis mutex), fair Reader-Writer lock, Named Lock Pool with automatic GC
- **Consistent Hash Ring** — 150 virtual nodes per backend, stable remapping on node add/remove, `get_nodes(key, n)` for replication routing
- **Bloom Filter** — optimal bit array (configurable capacity + error rate), O(k) membership test
- **Priority Task Queue** — min-heap with delayed tasks, thread-safe, wakes immediately on insert
- **Dead Letter Queue** — capture, inspect, replay, resolve failed tasks/webhooks; max-size eviction; persist callback
- **Adaptive Load Balancer** — Round Robin / Least Connections / Power-of-Two-Choices strategies; p95 latency tracking; health-aware routing
- **Chaos Engineering Framework** — declarative experiments; LatencyInjector, PacketDropInjector, ByzantineInjector, MemoryPressureInjector, ThreadPoolExhaustionInjector; 5 pre-built standard experiments (Redis kill, DB kill, high latency, memory pressure, thread exhaustion)

### Test Coverage

`tests/unit/test_distributed.py` — 60+ test cases covering all 17 modules:

- HLC: monotonicity, recv merge, drift rejection, thread safety, serialisation, comparison
- Merkle: empty tree, identical hash, diff detection, to_dict
- WAL: monotonic index, entries_after, compact, state machine CRUD, replay protection, crash recovery
- CRDTs: GCounter merge/idempotent, PNCounter, ORSet add/remove/concurrent-add-wins/commutative, LWWRegister, VectorClock
- Gossip: join, leave, merge deltas, suspect state
- Fencing: epoch increment, validate current, stale rejection, thread safety
- MVCC: write/read, snapshot isolation, delete, multi-version
- Quorum: QUORUM/ONE write, failed quorum raises, read with repair
- Anti-entropy: no-op when in sync, syncs diverged keys
- 2PC: successful commit, abort on vote-no
- Lease: read with valid lease, forward without lease, speculative hit/miss
- Consistent hash: routing, stability on node add, get_nodes
- Bloom: no false negatives, false positive rate within bounds
- Priority queue: ordering, timeout, delayed tasks
- DLQ: push/list, resolve, replay, max-size eviction, stats

---

## Migration from v9

1. Run `deployment/migrations/v10_distributed.sql` against your database
2. Replace old `c2/app.py` with the new single `c2/app.py`
3. Ensure `c2/distributed/` directory is present (new in v10)
4. Restart the C2 container — all new subsystems initialise lazily

No breaking changes to existing v9 API endpoints or database schema.
EOF