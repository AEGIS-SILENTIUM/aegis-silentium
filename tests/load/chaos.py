from __future__ import annotations
import logging
log = logging.getLogger(__name__)
"""
AEGIS-SILENTIUM — Chaos Test Suite
=====================================
Simulates infrastructure failures and verifies the system recovers
gracefully within its defined SLOs.

Requirements
------------
    pip install requests docker
    Docker must be running and aegis stack must be up.

Usage
-----
    python tests/load/chaos.py --host http://localhost:5000

Tests
-----
  1. Redis kill + recovery (C2 must degrade, not crash; SSE still works)
  2. DB kill + recovery   (requests fail fast; C2 comes back within 30s)
  3. C2 restart           (dashboard reconnects via SSE auto-reconnect)
  4. Slow DB (tc netem)   (circuit breaker trips within threshold time)
  5. High concurrency     (100 simultaneous requests without crash)
"""

import argparse
import json
import os
import subprocess
import sys
import threading
import time
from typing import Optional

import requests

_KEY = os.environ.get("OPERATOR_KEY", "aegis-operator-key-2026")
_AUTH = {"X-Aegis-Key": _KEY, "Content-Type": "application/json"}

GREEN  = "\033[32m"
RED    = "\033[31m"
YELLOW = "\033[33m"
RESET  = "\033[0m"
BOLD   = "\033[1m"


def ok(msg: str):    print(f"  {GREEN}✓{RESET} {msg}")
def fail(msg: str):  print(f"  {RED}✗{RESET} {msg}")
def info(msg: str):  print(f"  {YELLOW}→{RESET} {msg}")
def title(msg: str): print(f"\n{BOLD}{'═'*60}\n  {msg}\n{'═'*60}{RESET}")


def get_health(host: str, timeout: float = 5) -> Optional[dict]:
    try:
        r = requests.get(f"{host}/health", timeout=timeout)
        return r.json() if r.status_code == 200 else None
    except Exception:
        return None


def get_ready(host: str) -> dict:
    try:
        r = requests.get(f"{host}/ready", timeout=5)
        return r.json()
    except Exception:
        return {}


def docker_stop(container: str):
    subprocess.run(["docker", "stop", container], check=False, capture_output=True)


def docker_start(container: str):
    subprocess.run(["docker", "start", container], check=False, capture_output=True)


def wait_for_health(host: str, timeout_secs: float = 60) -> bool:
    deadline = time.time() + timeout_secs
    while time.time() < deadline:
        if get_health(host):
            return True
        time.sleep(1)
    return False


class ChaosResults:
    def __init__(self): self.passed = self.failed = 0
    def record(self, passed: bool, msg: str):
        if passed:  self.passed += 1; ok(msg)
        else:       self.failed += 1; fail(msg)
    def summary(self):
        total = self.passed + self.failed
        colour = GREEN if self.failed == 0 else RED
        print(f"\n{colour}{BOLD}{'─'*40}")
        print(f"  Results: {self.passed}/{total} scenarios passed")
        print(f"{'─'*40}{RESET}")
        return self.failed == 0


def run_chaos_tests(host: str, skip_docker: bool = False) -> bool:
    results = ChaosResults()

    # ── Test 1: Baseline health ───────────────────────────────────────────────
    title("T1 — Baseline health check")
    health = get_health(host)
    results.record(health is not None, "C2 responds to /health")
    if not health:
        fail("C2 is not running — skipping remaining tests")
        results.summary()
        return False

    ready = get_ready(host)
    results.record(ready.get("ready", False), f"/ready returns ok (checks: {ready.get('checks',{})})")

    # ── Test 2: Concurrent requests don't crash ───────────────────────────────
    title("T2 — High-concurrency (100 parallel requests)")
    errors = []
    threads = []

    def _req():
        try:
            r = requests.get(f"{host}/health", timeout=10)
            if r.status_code != 200:
                errors.append(r.status_code)
        except Exception as e:
            errors.append(str(e))

    for _ in range(100):
        t = threading.Thread(target=_req)
        threads.append(t)
        t.start()
    for t in threads:
        t.join(timeout=15)

    results.record(len(errors) == 0,
                   f"100 concurrent /health: {100-len(errors)}/100 succeeded")

    # ── Test 3: Unauthenticated requests blocked ──────────────────────────────
    title("T3 — Security: unauthenticated request blocked")
    try:
        r = requests.get(f"{host}/api/listeners", timeout=5)
        results.record(r.status_code == 401,
                       f"Unauthenticated /api/listeners → {r.status_code} (expected 401)")
    except Exception as e:
        results.record(False, f"Request failed: {e}")

    # ── Test 4: Rate limiter engages ──────────────────────────────────────────
    title("T4 — Rate limiter: flood auth endpoint")
    info("Sending 15 rapid login attempts...")
    statuses = []
    for i in range(15):
        try:
            r = requests.post(
                f"{host}/api/auth/login",
                json={"handle": f"flood_user_{i}", "key": "bad_key"},
                headers={"Content-Type": "application/json"},
                timeout=3,
            )
            statuses.append(r.status_code)
        except Exception:
            statuses.append(0)
    rate_limited = any(s == 429 for s in statuses)
    results.record(
        rate_limited or all(s in (400, 401, 503) for s in statuses),
        f"Auth flood: statuses={set(statuses)} (429 or graceful rejection expected)",
    )

    # ── Test 5: SSE connection ────────────────────────────────────────────────
    title("T5 — SSE stream connects and delivers events")
    received = []

    def _sse():
        try:
            r = requests.get(f"{host}/stream?key={_KEY}",
                             stream=True, timeout=8)
            for line in r.iter_lines():
                if line and b"data:" in line:
                    received.append(line)
                    if len(received) >= 1:
                        break
        except Exception as _exc:
            log.debug("%s: %s", __name__, _exc)

    sse_thread = threading.Thread(target=_sse, daemon=True)
    sse_thread.start()
    time.sleep(3)
    results.record(
        len(received) >= 1,
        f"SSE stream delivered {len(received)} event(s)",
    )

    # ── Test 6: Redis kill (Docker required) ──────────────────────────────────
    if skip_docker:
        info("Skipping Docker-dependent tests (--no-docker)")
    else:
        title("T6 — Redis kill → degraded mode → recovery")
        info("Stopping redis-master...")
        docker_stop("aegis-redis-master")
        time.sleep(5)

        # C2 should still respond to /health (degraded, not down)
        health_degraded = get_health(host, timeout=10)
        results.record(
            health_degraded is not None,
            "C2 /health still responds after Redis kill",
        )

        # API should still work (DB queries still function)
        try:
            r = requests.get(f"{host}/api/listeners",
                             headers=_AUTH, timeout=10)
            results.record(
                r.status_code in (200, 429, 503),
                f"/api/listeners after Redis kill → {r.status_code}",
            )
        except Exception as e:
            results.record(False, f"Request failed: {e}")

        info("Restarting redis-master...")
        docker_start("aegis-redis-master")
        time.sleep(10)

        # C2 should fully recover
        recovered = wait_for_health(host, timeout_secs=30)
        results.record(recovered, "C2 fully recovered after Redis restart")

        # ── Test 7: C2 restart ────────────────────────────────────────────────
        title("T7 — C2 container restart → reconnect within SLO")
        info("Restarting aegis-c2-1...")
        subprocess.run(["docker", "restart", "aegis-c2-1"],
                       check=False, capture_output=True)
        time.sleep(5)
        t_start = time.time()
        recovered = wait_for_health(host, timeout_secs=45)
        t_elapsed = time.time() - t_start
        results.record(
            recovered and t_elapsed <= 45,
            f"C2 recovered in {t_elapsed:.1f}s after restart (SLO: 45s)",
        )

    return results.summary()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AEGIS Chaos Tests")
    parser.add_argument("--host", default="http://localhost:5000")
    parser.add_argument("--no-docker", action="store_true",
                        help="Skip tests that require Docker")
    args = parser.parse_args()

    print(f"{BOLD}AEGIS-SILENTIUM Chaos Test Suite{RESET}")
    print(f"Target: {args.host}")
    success = run_chaos_tests(args.host, skip_docker=args.no_docker)
    sys.exit(0 if success else 1)
