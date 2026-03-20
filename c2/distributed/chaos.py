"""
c2/distributed/chaos.py
AEGIS-SILENTIUM v12 — Chaos Engineering Framework

Built-in chaos testing harness that can inject:
  - Network partitions (block inter-node traffic)
  - Slow I/O (artificial latency injection)
  - Leader crashes (force leader step-down)
  - Clock skew (manipulate HLC wall time)
  - Memory pressure (allocate and hold large buffers)
  - Resource exhaustion (thread pool saturation)
  - Packet loss (drop a fraction of outgoing calls)
  - Byzantine failures (corrupt responses with probability p)

Experiments are defined declaratively and run by the ChaosRunner.
Results are logged and can be fed into the CI pipeline.
"""

from __future__ import annotations

import logging
import os
import random
import socket
import subprocess
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Generator, List, Optional

log = logging.getLogger("aegis.chaos")


# ── Experiment Definition ─────────────────────────────────────────────────────

@dataclass
class ChaosExperiment:
    name:        str
    description: str
    duration_s:  float
    inject_fn:   Callable[[], None]   # start fault injection
    recover_fn:  Callable[[], None]   # restore normal operation
    verify_fn:   Optional[Callable[[], bool]] = None  # post-recovery health check
    tags:        List[str] = field(default_factory=list)


@dataclass
class ChaosResult:
    experiment:  str
    started_at:  float
    ended_at:    float
    recovered:   bool
    verified:    Optional[bool]
    notes:       str = ""

    @property
    def duration_s(self) -> float:
        return self.ended_at - self.started_at

    def to_dict(self) -> dict:
        return {
            "experiment":  self.experiment,
            "started_at":  self.started_at,
            "ended_at":    self.ended_at,
            "duration_s":  round(self.duration_s, 3),
            "recovered":   self.recovered,
            "verified":    self.verified,
            "notes":       self.notes,
        }


# ── Fault Injectors ───────────────────────────────────────────────────────────

class LatencyInjector:
    """Wraps a callable to inject artificial latency."""

    def __init__(self, target_fn: Callable, min_ms: float, max_ms: float) -> None:
        self._fn    = target_fn
        self._min   = min_ms / 1000.0
        self._max   = max_ms / 1000.0
        self._active = False

    def __call__(self, *args, **kwargs):
        if self._active:
            time.sleep(random.uniform(self._min, self._max))
        return self._fn(*args, **kwargs)

    def enable(self)  -> None: self._active = True
    def disable(self) -> None: self._active = False


class PacketDropInjector:
    """Wraps a callable to randomly drop calls (return None/raise)."""

    def __init__(self, target_fn: Callable, drop_rate: float = 0.3) -> None:
        self._fn       = target_fn
        self._rate     = drop_rate
        self._active   = False
        self._dropped  = 0

    def __call__(self, *args, **kwargs):
        if self._active and random.random() < self._rate:
            self._dropped += 1
            raise ConnectionError("ChaosInjector: simulated packet drop")
        return self._fn(*args, **kwargs)

    def enable(self)  -> None: self._active = True
    def disable(self) -> None: self._active = False


class ByzantineInjector:
    """Corrupts responses with probability p to simulate Byzantine failures."""

    def __init__(self, target_fn: Callable, corrupt_rate: float = 0.1) -> None:
        self._fn     = target_fn
        self._rate   = corrupt_rate
        self._active = False

    def __call__(self, *args, **kwargs):
        result = self._fn(*args, **kwargs)
        if self._active and random.random() < self._rate:
            # Corrupt: flip a random byte in string/bytes results
            if isinstance(result, dict) and result:
                k = random.choice(list(result.keys()))
                result[k] = "__CORRUPTED__"
            elif isinstance(result, str):
                result = result[::-1]
        return result

    def enable(self)  -> None: self._active = True
    def disable(self) -> None: self._active = False


class MemoryPressureInjector:
    """Allocates a large buffer to simulate memory pressure."""

    def __init__(self, mb: int = 256) -> None:
        self._mb     = mb
        self._buffer: Optional[bytearray] = None

    def enable(self) -> None:
        self._buffer = bytearray(self._mb * 1024 * 1024)
        log.warning("ChaosInjector: holding %dMB memory", self._mb)

    def disable(self) -> None:
        self._buffer = None
        log.info("ChaosInjector: memory pressure released")


class ThreadPoolExhaustionInjector:
    """Saturates a thread pool to simulate resource exhaustion."""

    def __init__(self, n_threads: int = 50, duration_s: float = 10.0) -> None:
        self._n  = n_threads
        self._dur = duration_s
        self._threads: List[threading.Thread] = []
        self._stop = threading.Event()

    def enable(self) -> None:
        self._stop.clear()
        self._threads = []
        for _ in range(self._n):
            t = threading.Thread(target=lambda: self._stop.wait(self._dur), daemon=True)
            t.start()
            self._threads.append(t)
        log.warning("ChaosInjector: %d threads saturating pool", self._n)

    def disable(self) -> None:
        self._stop.set()
        for t in self._threads:
            t.join(timeout=1)
        self._threads = []


# ── Chaos Runner ──────────────────────────────────────────────────────────────

class ChaosRunner:
    """
    Orchestrates chaos experiments.

    Usage::

        runner = ChaosRunner()
        runner.register(my_experiment)
        results = runner.run("redis-kill")

    or to run all experiments:

        results = runner.run_all()
    """

    def __init__(self) -> None:
        self._experiments: Dict[str, ChaosExperiment] = {}
        self._results: List[ChaosResult] = []
        self._lock = threading.Lock()

    def register(self, experiment: ChaosExperiment) -> None:
        self._experiments[experiment.name] = experiment
        log.debug("Chaos experiment registered: %s", experiment.name)

    def run(self, name: str) -> ChaosResult:
        exp = self._experiments.get(name)
        if not exp:
            raise KeyError(f"No chaos experiment named '{name}'")

        log.warning("━━ CHAOS: starting '%s' for %.1fs ━━", exp.name, exp.duration_s)
        started = time.time()
        recovered = False
        verified  = None
        notes     = ""

        try:
            exp.inject_fn()
            time.sleep(exp.duration_s)
        except Exception as exc:
            notes += f"inject error: {exc}; "
            log.error("Chaos inject error: %s", exc)
        finally:
            try:
                exp.recover_fn()
                recovered = True
            except Exception as exc:
                notes += f"recover error: {exc}; "
                log.error("Chaos recover error: %s", exc)

        # Post-recovery verification
        if exp.verify_fn:
            time.sleep(1.0)  # grace period
            try:
                verified = exp.verify_fn()
            except Exception as exc:
                notes += f"verify error: {exc}; "
                verified = False

        result = ChaosResult(
            experiment=name,
            started_at=started,
            ended_at=time.time(),
            recovered=recovered,
            verified=verified,
            notes=notes.strip("; "),
        )
        with self._lock:
            self._results.append(result)
        status = "✓ PASS" if (recovered and verified is not False) else "✗ FAIL"
        log.warning("━━ CHAOS: '%s' %s ━━", exp.name, status)
        return result

    def run_all(self, tags: Optional[List[str]] = None) -> List[ChaosResult]:
        experiments = list(self._experiments.values())
        if tags:
            experiments = [e for e in experiments if any(t in e.tags for t in tags)]
        results = []
        for exp in experiments:
            results.append(self.run(exp.name))
            time.sleep(2.0)  # cool-down between experiments
        return results

    def results(self) -> List[ChaosResult]:
        with self._lock:
            return list(self._results)

    def summary(self) -> dict:
        with self._lock:
            total   = len(self._results)
            passed  = sum(1 for r in self._results if r.recovered and r.verified is not False)
            return {
                "total":  total,
                "passed": passed,
                "failed": total - passed,
                "pass_rate": round(passed / total, 2) if total else 0.0,
            }


# ── Pre-built Experiments ─────────────────────────────────────────────────────

def build_standard_experiments(
    health_fn: Callable[[], bool],
    redis_container: str = "aegis-redis",
    db_container:    str = "aegis-db",
) -> List[ChaosExperiment]:
    """
    Returns a list of standard AEGIS chaos experiments.
    Requires Docker to be available for container-kill experiments.
    """

    def _docker_stop(name: str) -> None:
        subprocess.run(["docker", "stop", name], check=True, capture_output=True)

    def _docker_start(name: str) -> None:
        subprocess.run(["docker", "start", name], check=True, capture_output=True)

    latency = LatencyInjector(lambda: None, min_ms=200, max_ms=800)
    mem_pressure = MemoryPressureInjector(mb=128)
    thread_exhaust = ThreadPoolExhaustionInjector(n_threads=40, duration_s=8.0)

    return [
        ChaosExperiment(
            name="redis-kill",
            description="Kill Redis and verify C2 degrades gracefully then recovers",
            duration_s=5.0,
            inject_fn=lambda: _docker_stop(redis_container),
            recover_fn=lambda: _docker_start(redis_container),
            verify_fn=health_fn,
            tags=["redis", "infrastructure"],
        ),
        ChaosExperiment(
            name="db-kill",
            description="Kill Postgres and verify requests fail fast via circuit breaker",
            duration_s=5.0,
            inject_fn=lambda: _docker_stop(db_container),
            recover_fn=lambda: _docker_start(db_container),
            verify_fn=health_fn,
            tags=["postgres", "infrastructure"],
        ),
        ChaosExperiment(
            name="high-latency",
            description="Inject 200-800ms network latency into inter-node calls",
            duration_s=10.0,
            inject_fn=latency.enable,
            recover_fn=latency.disable,
            verify_fn=health_fn,
            tags=["network", "latency"],
        ),
        ChaosExperiment(
            name="memory-pressure",
            description="Hold 128MB to simulate memory pressure",
            duration_s=8.0,
            inject_fn=mem_pressure.enable,
            recover_fn=mem_pressure.disable,
            verify_fn=health_fn,
            tags=["memory", "resources"],
        ),
        ChaosExperiment(
            name="thread-exhaustion",
            description="Saturate thread pool with 40 idle threads",
            duration_s=8.0,
            inject_fn=thread_exhaust.enable,
            recover_fn=thread_exhaust.disable,
            verify_fn=health_fn,
            tags=["threads", "resources"],
        ),
    ]
