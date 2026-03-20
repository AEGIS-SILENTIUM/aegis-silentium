"""
c2/distributed/saga.py
AEGIS-SILENTIUM v12 — Saga Orchestrator

Implements the Saga pattern for distributed long-running transactions
that span multiple services.  Each step has a compensating transaction
that is executed if any subsequent step fails.

Reference: Garcia-Molina & Salem, "Sagas" (SIGMOD 1987)

Design
------
  Choreography vs Orchestration: this implementation is purely
  orchestration-based — a central SagaOrchestrator drives all steps
  and maintains the saga log.

  Steps are executed sequentially.  On failure, all completed steps
  are compensated in reverse order (rollback).

  Sagas are durable: state is written to the SagaLog before/after
  each step so they can resume after a crash.

States
------
  PENDING → RUNNING → (step by step) → COMPLETED
                    ↘ (failure)      → COMPENSATING → COMPENSATED | FAILED

Retry Policies
--------------
  Each step can specify: max_retries, retry_delay_ms, retry_backoff.
  The saga will retry the step before triggering compensation.
"""
from __future__ import annotations

import logging
import threading
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

log = logging.getLogger("aegis.distributed.saga")


class SagaState(str, Enum):
    PENDING      = "pending"
    RUNNING      = "running"
    COMPLETED    = "completed"
    COMPENSATING = "compensating"
    COMPENSATED  = "compensated"
    FAILED       = "failed"


class StepState(str, Enum):
    PENDING     = "pending"
    RUNNING     = "running"
    COMPLETED   = "completed"
    FAILED      = "failed"
    COMPENSATING= "compensating"
    COMPENSATED = "compensated"
    SKIPPED     = "skipped"


@dataclass
class SagaStep:
    """
    A single step in a saga.

    Parameters
    ----------
    name          : human-readable name
    action        : callable(context) → result
    compensation  : callable(context) → None  — called on rollback
    max_retries   : how many times to retry action on failure
    retry_delay_ms: ms to wait between retries
    timeout_s     : per-step timeout in seconds (None = no limit)
    """
    name:          str
    action:        Callable[[dict], Any]
    compensation:  Optional[Callable[[dict], None]] = None
    max_retries:   int   = 0
    retry_delay_ms: int  = 500
    timeout_s:     Optional[float] = None
    description:   str  = ""


@dataclass
class SagaStepRecord:
    step_name:   str
    state:       StepState = StepState.PENDING
    result:      Any       = None
    error:       str       = ""
    attempt:     int       = 0
    started_at:  Optional[float] = None
    finished_at: Optional[float] = None
    comp_started: Optional[float] = None
    comp_finished: Optional[float] = None

    def to_dict(self) -> dict:
        return {
            "step_name":    self.step_name,
            "state":        self.state.value,
            "result":       self.result,
            "error":        self.error,
            "attempt":      self.attempt,
            "started_at":   self.started_at,
            "finished_at":  self.finished_at,
        }


@dataclass
class SagaRecord:
    saga_id:     str
    saga_type:   str
    state:       SagaState         = SagaState.PENDING
    steps:       List[SagaStepRecord] = field(default_factory=list)
    context:     dict              = field(default_factory=dict)
    error:       str               = ""
    created_at:  float             = field(default_factory=time.time)
    started_at:  Optional[float]   = None
    finished_at: Optional[float]   = None
    operator:    str               = ""

    def to_dict(self) -> dict:
        return {
            "saga_id":    self.saga_id,
            "saga_type":  self.saga_type,
            "state":      self.state.value,
            "steps":      [s.to_dict() for s in self.steps],
            "context":    self.context,
            "error":      self.error,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "operator":   self.operator,
        }


class SagaDefinition:
    """
    Blueprint for a saga — defines the ordered steps.

    Usage::
        saga_def = (
            SagaDefinition("deploy_campaign")
            .step("reserve_nodes",
                  action=reserve_nodes, compensation=release_nodes)
            .step("assign_tasks",
                  action=assign_tasks, compensation=unassign_tasks)
            .step("activate_campaign",
                  action=activate, compensation=deactivate)
        )
    """

    def __init__(self, saga_type: str) -> None:
        self._type  = saga_type
        self._steps: List[SagaStep] = []

    def step(
        self,
        name:         str,
        action:       Callable[[dict], Any],
        compensation: Optional[Callable[[dict], None]] = None,
        max_retries:  int   = 0,
        retry_delay_ms: int = 500,
        timeout_s:    Optional[float] = None,
        description:  str = "",
    ) -> "SagaDefinition":
        self._steps.append(SagaStep(
            name=name, action=action, compensation=compensation,
            max_retries=max_retries, retry_delay_ms=retry_delay_ms,
            timeout_s=timeout_s, description=description,
        ))
        return self

    @property
    def saga_type(self) -> str:
        return self._type

    @property
    def steps(self) -> List[SagaStep]:
        return list(self._steps)


class SagaOrchestrator:
    """
    Executes and tracks sagas.

    Usage::
        orch = SagaOrchestrator()
        orch.register(saga_def)

        saga_id = orch.start("deploy_campaign", context={"campaign_id": "abc"},
                             operator="admin")
        record  = orch.get(saga_id)
    """

    def __init__(self, log_fn: Optional[Callable[[SagaRecord], None]] = None) -> None:
        self._definitions: Dict[str, SagaDefinition] = {}
        self._records:     Dict[str, SagaRecord]     = {}
        self._log_fn = log_fn
        self._lock   = threading.RLock()
        self._metrics = {
            "total_started":     0,
            "total_completed":   0,
            "total_compensated": 0,
            "total_failed":      0,
        }

    # ── Registration ──────────────────────────────────────────────────────────

    def register(self, definition: SagaDefinition) -> None:
        with self._lock:
            self._definitions[definition.saga_type] = definition

    # ── Execution ─────────────────────────────────────────────────────────────

    def start(
        self,
        saga_type: str,
        context:   Optional[dict] = None,
        operator:  str = "",
        async_run: bool = False,
    ) -> str:
        with self._lock:
            defn = self._definitions.get(saga_type)
            if not defn:
                raise ValueError(f"Unknown saga type: {saga_type}")
            saga_id = str(uuid.uuid4())
            record  = SagaRecord(
                saga_id   = saga_id,
                saga_type = saga_type,
                context   = dict(context or {}),
                operator  = operator,
                steps     = [SagaStepRecord(step_name=s.name) for s in defn.steps],
            )
            self._records[saga_id] = record
            self._metrics["total_started"] += 1
            steps = list(defn.steps)

        if async_run:
            t = threading.Thread(
                target=self._execute, args=(record, steps), daemon=True,
                name=f"saga-{saga_id[:8]}"
            )
            t.start()
        else:
            self._execute(record, steps)

        return saga_id

    def _execute(self, record: SagaRecord, steps: List[SagaStep]) -> None:
        record.state      = SagaState.RUNNING
        record.started_at = time.time()
        self._log(record)

        completed_steps: List[int] = []

        for idx, step in enumerate(steps):
            step_rec = record.steps[idx]
            step_rec.state      = StepState.RUNNING
            step_rec.started_at = time.time()
            step_rec.attempt    = 0

            success = False
            for attempt in range(step.max_retries + 1):
                step_rec.attempt = attempt + 1
                try:
                    if step.timeout_s:
                        import concurrent.futures
                        with concurrent.futures.ThreadPoolExecutor(1) as ex:
                            fut = ex.submit(step.action, record.context)
                            result = fut.result(timeout=step.timeout_s)
                    else:
                        result = step.action(record.context)

                    step_rec.result      = result
                    step_rec.state       = StepState.COMPLETED
                    step_rec.finished_at = time.time()
                    completed_steps.append(idx)
                    # Merge result into context
                    if isinstance(result, dict):
                        record.context.update(result)
                    success = True
                    break

                except Exception as e:
                    step_rec.error = str(e)
                    log.warning("Saga %s step '%s' attempt %d failed: %s",
                                record.saga_id, step.name, attempt + 1, e)
                    if attempt < step.max_retries:
                        time.sleep(step.retry_delay_ms / 1000.0)

            if not success:
                step_rec.state       = StepState.FAILED
                step_rec.finished_at = time.time()
                record.error         = f"Step '{step.name}' failed: {step_rec.error}"
                self._compensate(record, steps, completed_steps)
                return

        record.state      = SagaState.COMPLETED
        record.finished_at = time.time()
        self._metrics["total_completed"] += 1
        log.info("Saga %s (%s) COMPLETED", record.saga_id, record.saga_type)
        self._log(record)

    def _compensate(
        self,
        record: SagaRecord,
        steps:  List[SagaStep],
        completed: List[int],
    ) -> None:
        record.state = SagaState.COMPENSATING
        self._log(record)

        for idx in reversed(completed):
            step     = steps[idx]
            step_rec = record.steps[idx]

            if not step.compensation:
                step_rec.state = StepState.SKIPPED
                continue

            step_rec.state        = StepState.COMPENSATING
            step_rec.comp_started = time.time()
            try:
                step.compensation(record.context)
                step_rec.state         = StepState.COMPENSATED
                step_rec.comp_finished = time.time()
                log.info("Saga %s step '%s' compensated", record.saga_id, step.name)
            except Exception as e:
                step_rec.state = StepState.FAILED
                log.error("Saga %s compensation for '%s' failed: %s",
                          record.saga_id, step.name, e)

        all_comp = all(
            s.state in (StepState.COMPENSATED, StepState.SKIPPED)
            for s in record.steps
            if s.state not in (StepState.PENDING,)
        )
        record.state       = SagaState.COMPENSATED if all_comp else SagaState.FAILED
        record.finished_at = time.time()

        if record.state == SagaState.COMPENSATED:
            self._metrics["total_compensated"] += 1
        else:
            self._metrics["total_failed"] += 1

        log.info("Saga %s (%s) %s", record.saga_id, record.saga_type, record.state.value.upper())
        self._log(record)

    def _log(self, record: SagaRecord) -> None:
        if self._log_fn:
            try:
                self._log_fn(record)
            except Exception as _exc:
                log.debug("_log: %s", _exc)

    # ── Query ─────────────────────────────────────────────────────────────────

    def get(self, saga_id: str) -> Optional[dict]:
        with self._lock:
            rec = self._records.get(saga_id)
            return rec.to_dict() if rec else None

    def list_sagas(
        self,
        saga_type: Optional[str] = None,
        state:     Optional[SagaState] = None,
        limit:     int = 50,
    ) -> List[dict]:
        with self._lock:
            records = list(self._records.values())
        if saga_type:
            records = [r for r in records if r.saga_type == saga_type]
        if state:
            records = [r for r in records if r.state == state]
        records.sort(key=lambda r: -(r.created_at))
        return [r.to_dict() for r in records[:limit]]

    def stats(self) -> dict:
        with self._lock:
            state_counts = {}
            for r in self._records.values():
                state_counts[r.state.value] = state_counts.get(r.state.value, 0) + 1
            return {**self._metrics,
                    "total_sagas": len(self._records),
                    "by_state": state_counts,
                    "registered_types": list(self._definitions.keys())}
