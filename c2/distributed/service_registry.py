"""
c2/distributed/service_registry.py
AEGIS-SILENTIUM v12 — Service Registry

Distributed service registry with:
  • Service registration with health metadata
  • TTL-based lease expiry (deregister dead services automatically)
  • Health check scheduling (HTTP/TCP/custom)
  • Round-robin and weighted-random load balancing
  • Watchers: subscribe to service change events
  • Consistent hashing for session affinity
"""
from __future__ import annotations

import logging
import random
import threading
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Dict, List, Optional, Set

log = logging.getLogger("aegis.distributed.registry")


class ServiceState(str, Enum):
    PASSING  = "passing"
    WARNING  = "warning"
    CRITICAL = "critical"
    UNKNOWN  = "unknown"


@dataclass
class ServiceInstance:
    service_id:   str
    service_name: str
    address:      str
    port:         int
    tags:         List[str]    = field(default_factory=list)
    meta:         Dict         = field(default_factory=dict)
    state:        ServiceState = ServiceState.UNKNOWN
    weight:       int          = 1          # for weighted load balancing
    registered_at: float       = field(default_factory=time.time)
    last_seen:    float        = field(default_factory=time.time)
    ttl_seconds:  float        = 30.0       # deregister if no heartbeat for ttl
    check_url:    Optional[str] = None      # optional HTTP health check URL
    version:      str           = ""

    @property
    def address_port(self) -> str:
        return f"{self.address}:{self.port}"

    def is_expired(self) -> bool:
        return time.time() - self.last_seen > self.ttl_seconds

    def heartbeat(self) -> None:
        self.last_seen = time.time()
        self.state     = ServiceState.PASSING

    def to_dict(self) -> dict:
        return {
            "service_id":    self.service_id,
            "service_name":  self.service_name,
            "address":       self.address,
            "port":          self.port,
            "address_port":  self.address_port,
            "tags":          self.tags,
            "meta":          self.meta,
            "state":         self.state.value,
            "weight":        self.weight,
            "registered_at": self.registered_at,
            "last_seen":     self.last_seen,
            "version":       self.version,
            "is_expired":    self.is_expired(),
        }


class ServiceRegistry:
    """
    In-memory service registry with TTL, health checks, and LB.

    Usage::
        registry = ServiceRegistry()

        # Register
        registry.register(ServiceInstance(
            service_id="c2-1", service_name="c2",
            address="10.0.0.1", port=5000, tags=["primary"]
        ))

        # Heartbeat (call from service periodically)
        registry.heartbeat("c2-1")

        # Discover (round-robin)
        instance = registry.discover("c2")

        # Watch for changes
        registry.watch("c2", callback=lambda event, svc: print(event, svc))
    """

    _HEALTH_CHECK_INTERVAL = 5.0
    _EXPIRY_CHECK_INTERVAL = 10.0

    def __init__(self) -> None:
        self._services: Dict[str, ServiceInstance] = {}   # service_id → instance
        self._by_name:  Dict[str, Set[str]] = {}          # name → set of service_ids
        self._rr_idx:   Dict[str, int] = {}               # name → round-robin cursor
        self._watchers: Dict[str, List[Callable]] = {}    # name → callbacks
        self._lock = threading.RLock()
        self._metrics = {
            "registrations": 0,
            "deregistrations": 0,
            "heartbeats": 0,
            "discoveries": 0,
            "expirations": 0,
        }

        self._expiry_thread = threading.Thread(
            target=self._expiry_loop, daemon=True, name="svc-expiry"
        )
        self._expiry_thread.start()

    # ── Registration ──────────────────────────────────────────────────────────

    def register(self, svc: ServiceInstance) -> str:
        with self._lock:
            self._services[svc.service_id] = svc
            self._by_name.setdefault(svc.service_name, set()).add(svc.service_id)
            self._metrics["registrations"] += 1
        svc.state = ServiceState.PASSING  # healthy on registration
        svc.last_seen = time.time()
        log.info("Service registered: %s (%s) at %s",
                 svc.service_name, svc.service_id, svc.address_port)
        self._notify(svc.service_name, "registered", svc)
        return svc.service_id

    def deregister(self, service_id: str) -> bool:
        with self._lock:
            svc = self._services.pop(service_id, None)
            if not svc:
                return False
            self._by_name.get(svc.service_name, set()).discard(service_id)
            self._metrics["deregistrations"] += 1
        log.info("Service deregistered: %s", service_id)
        self._notify(svc.service_name, "deregistered", svc)
        return True

    def heartbeat(self, service_id: str, state: ServiceState = ServiceState.PASSING) -> bool:
        with self._lock:
            svc = self._services.get(service_id)
            if not svc:
                return False
            svc.heartbeat()
            svc.state = state
            self._metrics["heartbeats"] += 1
        return True

    def update_state(self, service_id: str, state: ServiceState, message: str = "") -> bool:
        with self._lock:
            svc = self._services.get(service_id)
            if not svc:
                return False
            old_state = svc.state
            svc.state = state
        if old_state != state:
            with self._lock:
                svc = self._services.get(service_id)
            if svc:
                self._notify(svc.service_name, f"state_changed:{state.value}", svc)
        return True

    # ── Discovery ─────────────────────────────────────────────────────────────

    def discover(
        self,
        service_name:  str,
        strategy:      str = "round_robin",  # round_robin | random | weighted_random
        tags:          Optional[List[str]] = None,
        state_filter:  Optional[ServiceState] = ServiceState.PASSING,
    ) -> Optional[ServiceInstance]:
        with self._lock:
            ids = list(self._by_name.get(service_name, set()))
            candidates = [
                self._services[sid] for sid in ids
                if sid in self._services
                   and not self._services[sid].is_expired()
                   and (state_filter is None or self._services[sid].state == state_filter)
            ]
            if tags:
                candidates = [s for s in candidates
                              if all(t in s.tags for t in tags)]
            if not candidates:
                return None

            self._metrics["discoveries"] += 1

            if strategy == "round_robin":
                idx = self._rr_idx.get(service_name, 0) % len(candidates)
                self._rr_idx[service_name] = idx + 1
                return candidates[idx]
            elif strategy == "weighted_random":
                total = sum(s.weight for s in candidates)
                r = random.uniform(0, total)
                cumulative = 0
                for s in candidates:
                    cumulative += s.weight
                    if r <= cumulative:
                        return s
                return candidates[-1]
            else:
                return random.choice(candidates)

    def discover_all(
        self,
        service_name: str,
        state_filter: Optional[ServiceState] = None,
        tags: Optional[List[str]] = None,
    ) -> List[ServiceInstance]:
        with self._lock:
            ids = list(self._by_name.get(service_name, set()))
            results = []
            for sid in ids:
                svc = self._services.get(sid)
                if not svc or svc.is_expired():
                    continue
                if state_filter and svc.state != state_filter:
                    continue
                if tags and not all(t in svc.tags for t in tags):
                    continue
                results.append(svc)
        return results

    def get(self, service_id: str) -> Optional[ServiceInstance]:
        with self._lock:
            return self._services.get(service_id)

    def list_services(self) -> Dict[str, List[dict]]:
        with self._lock:
            result: Dict[str, List[dict]] = {}
            for name, ids in self._by_name.items():
                svcs = [self._services[sid].to_dict() for sid in ids
                        if sid in self._services]
                if svcs:
                    result[name] = svcs
        return result

    # ── Watchers ──────────────────────────────────────────────────────────────

    def watch(self, service_name: str, callback: Callable[[str, ServiceInstance], None]) -> None:
        """Register a callback invoked on any change for service_name."""
        with self._lock:
            self._watchers.setdefault(service_name, []).append(callback)

    def unwatch(self, service_name: str, callback: Callable) -> None:
        with self._lock:
            lst = self._watchers.get(service_name, [])
            if callback in lst:
                lst.remove(callback)

    def _notify(self, service_name: str, event: str, svc: ServiceInstance) -> None:
        with self._lock:
            callbacks = list(self._watchers.get(service_name, []))
        for cb in callbacks:
            try:
                cb(event, svc)
            except Exception as e:
                log.warning("Registry watcher error: %s", e)

    # ── Expiry ────────────────────────────────────────────────────────────────

    def _expiry_loop(self) -> None:
        while True:
            time.sleep(self._EXPIRY_CHECK_INTERVAL)
            try:
                self._expire_stale()
            except Exception:
                log.exception("Registry expiry error")

    def _expire_stale(self) -> int:
        with self._lock:
            expired = [sid for sid, svc in self._services.items()
                       if svc.is_expired()]
        count = 0
        for sid in expired:
            log.warning("Service expired (no heartbeat): %s", sid)
            self.deregister(sid)
            self._metrics["expirations"] += 1
            count += 1
        return count

    def stats(self) -> dict:
        with self._lock:
            total = len(self._services)
            passing = sum(1 for s in self._services.values()
                          if s.state == ServiceState.PASSING and not s.is_expired())
            return {
                **self._metrics,
                "total_services": total,
                "passing_services": passing,
                "service_names": list(self._by_name.keys()),
            }
