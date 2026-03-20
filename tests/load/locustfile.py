from __future__ import annotations
import logging
log = logging.getLogger(__name__)
"""
AEGIS-SILENTIUM — Load Test (Locust)
======================================
Simulates realistic operator workloads against the C2 API.

Usage
-----
    locust -f tests/load/locustfile.py \
        --host http://localhost:5000 \
        --users 20 --spawn-rate 5 --run-time 2m

User profiles
-------------
  DashboardUser  — passive viewer, polls stats/nodes/events (80% of users)
  OperatorUser   — active operator, creates tasks/payloads, posts chat (15%)
  NodeBeacon     — simulates a beacon check-in (5% — high frequency)
"""

import json
import os
import random
import time

try:
    from locust import HttpUser, TaskSet, between, task, events
except ImportError:
    raise SystemExit("Install locust: pip install locust")

_KEY = os.environ.get("OPERATOR_KEY", "aegis-operator-key-2026")
_OP  = os.environ.get("OPERATOR_HANDLE", "load_test_op")

_AUTH_HEADERS = {
    "X-Aegis-Key":       _KEY,
    "X-Aegis-Operator":  _OP,
    "Content-Type":      "application/json",
}

# ── Summary stats printed after run ──────────────────────────────────────────
_stats: dict = {"requests": 0, "errors": 0, "min_ms": 99999, "max_ms": 0}

@events.request.add_listener
def _on_req(request_type, name, response_time, response_length,
            exception, context, **kw):
    _stats["requests"] += 1
    if exception:
        _stats["errors"] += 1
    _stats["min_ms"] = min(_stats["min_ms"], response_time)
    _stats["max_ms"] = max(_stats["max_ms"], response_time)

# ── Dashboard / Read-only workload ────────────────────────────────────────────

class DashboardTaskSet(TaskSet):
    """Simulates an operator passively watching the dashboard."""

    @task(10)
    def health(self):
        self.client.get("/health", name="/health")

    @task(8)
    def api_stats(self):
        with self.client.get(
            "/api/stats",
            headers=_AUTH_HEADERS,
            name="/api/stats",
            catch_response=True,
        ) as r:
            if r.status_code not in (200, 401):
                r.failure(f"Unexpected {r.status_code}")

    @task(6)
    def list_listeners(self):
        self.client.get(
            "/api/listeners?page=1&per_page=50",
            headers=_AUTH_HEADERS,
            name="/api/listeners",
        )

    @task(4)
    def list_exploits(self):
        self.client.get(
            "/api/exploits?page=1&per_page=50",
            headers=_AUTH_HEADERS,
            name="/api/exploits",
        )

    @task(4)
    def list_payloads(self):
        self.client.get(
            "/api/payloads?page=1&per_page=50",
            headers=_AUTH_HEADERS,
            name="/api/payloads",
        )

    @task(3)
    def listeners_summary(self):
        self.client.get(
            "/api/listeners/summary",
            headers=_AUTH_HEADERS,
            name="/api/listeners/summary",
        )

    @task(3)
    def surv_summary(self):
        self.client.get(
            "/api/surveillance/summary",
            headers=_AUTH_HEADERS,
            name="/api/surveillance/summary",
        )

    @task(2)
    def chat_channels(self):
        self.client.get(
            "/api/chat/channels",
            headers=_AUTH_HEADERS,
            name="/api/chat/channels",
        )

    @task(2)
    def chat_messages(self):
        ch = random.choice(["general", "intel", "alerts"])
        self.client.get(
            f"/api/chat/messages?channel={ch}&limit=50",
            headers=_AUTH_HEADERS,
            name="/api/chat/messages",
        )

    @task(1)
    def metrics(self):
        self.client.get("/metrics", name="/metrics")


class DashboardUser(HttpUser):
    tasks       = [DashboardTaskSet]
    wait_time   = between(2, 8)   # 2–8s think time
    weight      = 8               # 80% of virtual users


# ── Active operator workload ──────────────────────────────────────────────────

class OperatorTaskSet(TaskSet):
    """Simulates an operator performing operational tasks."""

    @task(5)
    def read_listeners(self):
        self.client.get(
            "/api/listeners",
            headers=_AUTH_HEADERS,
            name="/api/listeners",
        )

    @task(3)
    def read_exploits_filtered(self):
        severity = random.choice(["CRITICAL", "HIGH", "MEDIUM"])
        self.client.get(
            f"/api/exploits?severity={severity}&per_page=25",
            headers=_AUTH_HEADERS,
            name="/api/exploits?severity=X",
        )

    @task(2)
    def payload_options(self):
        self.client.get(
            "/api/payloads/options",
            headers=_AUTH_HEADERS,
            name="/api/payloads/options",
        )

    @task(1)
    def post_chat(self):
        msg = random.choice([
            "Target engaged. Proceeding to phase 2.",
            "Listener online. Waiting for callback.",
            "Exploit staged on node-1.",
            "Surveillance module activated.",
            "Standing by.",
        ])
        self.client.post(
            "/api/chat/messages",
            json={"message": msg, "channel": "general"},
            headers=_AUTH_HEADERS,
            name="POST /api/chat/messages",
        )

    @task(1)
    def search_chat(self):
        q = random.choice(["target", "node", "listener", "exploit"])
        self.client.get(
            f"/api/chat/search?q={q}&limit=20",
            headers=_AUTH_HEADERS,
            name="/api/chat/search",
        )


class OperatorUser(HttpUser):
    tasks     = [OperatorTaskSet]
    wait_time = between(1, 5)
    weight    = 1


# ── Beacon simulation (node check-in) ────────────────────────────────────────

class BeaconTaskSet(TaskSet):
    """Simulates implanted nodes beaconing back to C2."""

    def on_start(self):
        self.node_id = f"load-test-node-{random.randint(1000, 9999)}"

    @task(10)
    def beacon_checkin(self):
        with self.client.post(
            "/api/beacon",
            json={
                "node_id":   self.node_id,
                "hostname":  f"WIN-{self.node_id[-4:]}",
                "os":        "Windows 11",
                "arch":      "x64",
                "username":  "SYSTEM",
                "pid":       random.randint(1000, 65535),
                "ip":        f"192.168.{random.randint(1,254)}.{random.randint(1,254)}",
                "ts":        time.time(),
            },
            headers={"X-Aegis-Key": _KEY, "Content-Type": "application/json"},
            name="POST /api/beacon",
            catch_response=True,
        ) as r:
            if r.status_code not in (200, 201, 404):
                r.failure(f"Unexpected status {r.status_code}")

    @task(2)
    def poll_tasks(self):
        self.client.get(
            f"/api/nodes/{self.node_id}/commands",
            headers={"X-Aegis-Key": _KEY},
            name="GET /api/nodes/{id}/commands",
        )


class NodeBeacon(HttpUser):
    tasks     = [BeaconTaskSet]
    wait_time = between(25, 35)  # Beacon interval ~30s
    weight    = 1


# ── Chaos scenario (optional, --tags chaos) ───────────────────────────────────

class ChaosDashboardUser(DashboardUser):
    """
    Same as DashboardUser but hammers the SSE stream simultaneously.
    Run with: locust -f locustfile.py --tags chaos
    """
    weight = 0  # disabled by default

    @task(1)
    def sse_connect_disconnect(self):
        """Open an SSE connection and disconnect after 2s (simulates browser refresh)."""
        with self.client.get(
            f"/stream?key={_KEY}",
            stream=True,
            timeout=3,
            name="/stream (SSE)",
            catch_response=True,
        ) as r:
            if r.status_code != 200:
                r.failure(f"SSE {r.status_code}")
            # Read just first chunk then abort
            try:
                next(r.iter_lines())
            except Exception as _exc:
                log.debug("%s: %s", __name__, _exc)
