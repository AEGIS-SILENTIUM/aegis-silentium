"""
c2/distributed/fencing.py
AEGIS-SILENTIUM v12 — Fencing Token Manager (Full Implementation)

Epoch-based fencing prevents zombie leaders from writing stale data.
Every write request must carry the current epoch; writes from leaders
with outdated epochs are rejected atomically.

Upgrades from v10
-----------------
  * Full epoch history with timestamps, reasons, and operator attribution
  * Lease-coupled fencing: epoch auto-expires when lease lapses
  * Per-resource fencing: different resources can have different epochs
  * Broadcast hook: notify peers when epoch changes
  * Persistence hook: epoch survives restarts (via persist_fn)
  * Epoch validation with grace window for in-flight requests
  * Metrics: epoch_changes, stale_rejections, grace_window_accepts
"""
from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

log = logging.getLogger("aegis.distributed.fencing")


class StaleEpochError(Exception):
    def __init__(self, provided: int, current: int, resource: str = "global") -> None:
        self.provided = provided
        self.current  = current
        self.resource = resource
        super().__init__(
            f"Stale epoch for resource '{resource}': provided={provided} "
            f"current={current}. Rejecting — possible zombie leader."
        )


class EpochExpiredError(Exception):
    pass


@dataclass
class EpochRecord:
    epoch:      int
    resource:   str
    reason:     str = ""
    operator:   str = ""
    node_id:    str = ""
    created_at: float = field(default_factory=time.time)
    expires_at: Optional[float] = None
    retired_at: Optional[float] = None

    def is_valid(self) -> bool:
        if self.retired_at:
            return False
        if self.expires_at and time.time() > self.expires_at:
            return False
        return True

    def to_dict(self) -> dict:
        return {
            "epoch": self.epoch, "resource": self.resource,
            "reason": self.reason, "operator": self.operator,
            "node_id": self.node_id, "created_at": self.created_at,
            "expires_at": self.expires_at, "retired_at": self.retired_at,
            "is_valid": self.is_valid(),
        }


class ResourceFencer:
    _GRACE_WINDOW = 0.05

    def __init__(self, resource: str, initial_epoch: int = 0,
                 broadcast_fn=None, persist_fn=None) -> None:
        self._resource  = resource
        self._broadcast = broadcast_fn
        self._persist   = persist_fn
        self._lock      = threading.RLock()
        self._history: List[EpochRecord] = []
        self._metrics   = {"epoch_changes": 0, "stale_rejections": 0,
                           "grace_accepts": 0, "expiry_rejections": 0}
        rec = EpochRecord(epoch=initial_epoch, resource=resource,
                          reason="bootstrap", operator="system")
        self._history.append(rec)
        self._current_record: EpochRecord = rec

    @property
    def current_epoch(self) -> int:
        with self._lock:
            return self._current_record.epoch

    def new_epoch(self, reason: str = "leader_election", operator: str = "system",
                  node_id: str = "", ttl_seconds: Optional[float] = None) -> int:
        with self._lock:
            old = self._current_record
            old.retired_at = time.time()
            new_epoch = old.epoch + 1
            expires_at = time.time() + ttl_seconds if ttl_seconds else None
            rec = EpochRecord(epoch=new_epoch, resource=self._resource,
                              reason=reason, operator=operator,
                              node_id=node_id, expires_at=expires_at)
            self._history.append(rec)
            self._current_record = rec
            self._metrics["epoch_changes"] += 1
        log.info("Epoch bumped resource=%s old=%d new=%d reason=%s",
                 self._resource, old.epoch, new_epoch, reason)
        if self._broadcast:
            try:
                self._broadcast(self._resource, new_epoch)
            except Exception as e:
                log.warning("Epoch broadcast error: %s", e)
        if self._persist:
            try:
                self._persist(rec)
            except Exception as e:
                log.warning("Epoch persist error: %s", e)
        return new_epoch

    def validate(self, epoch: int) -> None:
        with self._lock:
            current = self._current_record.epoch
            if not self._current_record.is_valid():
                self._metrics["expiry_rejections"] += 1
                raise EpochExpiredError(
                    f"Current epoch {current} expired for resource '{self._resource}'"
                )
            if epoch == current:
                return
            if epoch == current - 1 and self._history:
                if time.time() - self._current_record.created_at <= self._GRACE_WINDOW:
                    self._metrics["grace_accepts"] += 1
                    return
            self._metrics["stale_rejections"] += 1
            raise StaleEpochError(epoch, current, self._resource)

    def is_valid_epoch(self, epoch: int) -> bool:
        try:
            self.validate(epoch)
            return True
        except (StaleEpochError, EpochExpiredError):
            return False

    def retire_epoch(self, epoch: int, reason: str = "explicit") -> bool:
        with self._lock:
            if epoch != self._current_record.epoch:
                return False
            self._current_record.retired_at = time.time()
            return True

    def history(self, limit: int = 50) -> List[dict]:
        with self._lock:
            return [r.to_dict() for r in self._history[-limit:]]

    def stats(self) -> dict:
        with self._lock:
            return {"resource": self._resource,
                    "current_epoch": self._current_record.epoch,
                    "epoch_valid": self._current_record.is_valid(),
                    "history_length": len(self._history),
                    **self._metrics}


class FencingTokenManager:
    """Multi-resource fencing token manager."""

    _DEFAULT_RESOURCE = "global"

    def __init__(self, initial_epoch: int = 0, broadcast_fn=None, persist_fn=None) -> None:
        self._broadcast = broadcast_fn
        self._persist   = persist_fn
        self._fencers: Dict[str, ResourceFencer] = {}
        self._lock = threading.Lock()
        self._get_or_create(self._DEFAULT_RESOURCE, initial_epoch)

    def _get_or_create(self, resource: str, initial_epoch: int = 0) -> ResourceFencer:
        with self._lock:
            if resource not in self._fencers:
                self._fencers[resource] = ResourceFencer(
                    resource=resource, initial_epoch=initial_epoch,
                    broadcast_fn=self._broadcast, persist_fn=self._persist)
            return self._fencers[resource]

    def new_epoch(self, reason: str = "leader_election", operator: str = "system",
                  node_id: str = "", resource: str = None,
                  ttl_seconds: Optional[float] = None) -> int:
        resource = resource or self._DEFAULT_RESOURCE
        return self._get_or_create(resource).new_epoch(
            reason=reason, operator=operator, node_id=node_id, ttl_seconds=ttl_seconds)

    def validate(self, epoch: int, resource: str = None) -> None:
        self._get_or_create(resource or self._DEFAULT_RESOURCE).validate(epoch)

    def is_valid(self, epoch: int, resource: str = None) -> bool:
        return self._get_or_create(resource or self._DEFAULT_RESOURCE).is_valid_epoch(epoch)

    @property
    def current_epoch(self) -> int:
        return self._get_or_create(self._DEFAULT_RESOURCE).current_epoch

    def current_epoch_for(self, resource: str) -> int:
        return self._get_or_create(resource).current_epoch

    def retire_epoch(self, epoch: int, resource: str = None, reason: str = "explicit") -> bool:
        return self._get_or_create(resource or self._DEFAULT_RESOURCE).retire_epoch(epoch, reason)

    def history(self, limit: int = 50, *, resource: str = None) -> List[dict]:
        return self._get_or_create(resource or self._DEFAULT_RESOURCE).history(limit)

    def stats(self) -> dict:
        with self._lock:
            resources = list(self._fencers.keys())
        return {"resources": {r: self._fencers[r].stats() for r in resources},
                "resource_count": len(resources)}
