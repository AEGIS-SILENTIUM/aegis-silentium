"""
c2/zeroday/analysis/dynamic/tracer.py
AEGIS-SILENTIUM v12 — Dynamic Analysis: Execution Tracer

Instruments target execution to collect:
  - Code coverage (basic block hit counts)
  - Memory access patterns (read/write addresses)
  - System call traces (syscall number, args, return)
  - Signal/crash events

Backend: subprocess with ASAN/UBSAN env, or strace/ptrace on Linux.
For full symbolic execution, use the symbolic/ subpackage (angr/Triton).
"""
from __future__ import annotations

import logging
import os
import re
import subprocess
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

log = logging.getLogger("aegis.zeroday.dynamic")


@dataclass
class TraceEvent:
    """A single event captured during dynamic execution."""
    event_type: str         # "syscall" | "signal" | "malloc" | "free" | "coverage"
    timestamp:  float       = field(default_factory=time.time)
    address:    Optional[int] = None
    data:       dict        = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "event_type": self.event_type,
            "timestamp":  self.timestamp,
            "address":    hex(self.address) if self.address else None,
            "data":       self.data,
        }


@dataclass
class DynamicTrace:
    """Collection of events from one execution."""
    target_path:   str
    input_data:    bytes
    exit_code:     int           = 0
    signal:        Optional[int] = None
    elapsed_ms:    float         = 0.0
    events:        List[TraceEvent] = field(default_factory=list)
    syscalls:      Dict[str, int]   = field(default_factory=dict)  # name → count
    coverage_pcs:  List[int]        = field(default_factory=list)
    asan_report:   str              = ""

    def add_event(self, event: TraceEvent) -> None:
        self.events.append(event)
        if event.event_type == "syscall":
            name = event.data.get("name", "unknown")
            self.syscalls[name] = self.syscalls.get(name, 0) + 1

    def to_dict(self) -> dict:
        return {
            "target":      self.target_path,
            "exit_code":   self.exit_code,
            "signal":      self.signal,
            "elapsed_ms":  self.elapsed_ms,
            "event_count": len(self.events),
            "syscall_count": len(self.syscalls),
            "coverage_edges": len(self.coverage_pcs),
            "has_crash":   self.signal is not None and self.signal > 0,
            "syscalls":    dict(sorted(self.syscalls.items(), key=lambda x: -x[1])[:20]),
        }


class ExecutionTracer:
    """
    Lightweight dynamic tracer using subprocess + ASAN/strace.

    For full dynamic instrumentation with code coverage, configure
    AFL_NO_FORKSRV=1 and compile target with -fsanitize=address,coverage.

    For syscall tracing on Linux, uses strace when available.
    """

    _ASAN_ENV = {
        "ASAN_OPTIONS": (
            "detect_leaks=0:abort_on_error=1:symbolize=1:"
            "handle_segv=0:handle_abort=0"
        ),
        "AFL_NO_FORKSRV": "1",
    }

    def __init__(
        self,
        target_path:  str,
        timeout_sec:  float = 5.0,
        stdin_mode:   bool  = False,
        use_strace:   bool  = False,
        use_asan:     bool  = True,
    ) -> None:
        self._target    = target_path
        self._timeout   = timeout_sec
        self._stdin     = stdin_mode
        self._strace    = use_strace and self._strace_available()
        self._asan      = use_asan

    @staticmethod
    def _strace_available() -> bool:
        try:
            subprocess.run(["strace", "--version"], capture_output=True, timeout=2)
            return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def trace(self, input_data: bytes) -> DynamicTrace:
        """Execute target with input_data and collect trace."""
        env = os.environ.copy()
        if self._asan:
            env.update(self._ASAN_ENV)

        cmd = [self._target]
        if self._strace:
            cmd = ["strace", "-e", "trace=all", "-o", "/dev/stderr"] + cmd

        t_start = time.time()
        try:
            if self._stdin:
                proc = subprocess.run(
                    cmd, input=input_data, capture_output=True,
                    timeout=self._timeout, env=env,
                )
            else:
                import tempfile
                with tempfile.NamedTemporaryFile(delete=False, suffix=".input") as tf:
                    tf.write(input_data)
                    tf_path = tf.name
                real_cmd = [tf_path if a == "@@" else a for a in cmd]
                proc = subprocess.run(
                    real_cmd, capture_output=True, timeout=self._timeout, env=env,
                )
                try:
                    os.unlink(tf_path)
                except OSError:
                    pass

            elapsed = (time.time() - t_start) * 1000
            signal_num = None
            if proc.returncode < 0:
                signal_num = -proc.returncode
            elif proc.returncode > 128:
                signal_num = proc.returncode - 128

            trace = DynamicTrace(
                target_path = self._target,
                input_data  = input_data,
                exit_code   = proc.returncode,
                signal      = signal_num,
                elapsed_ms  = elapsed,
                asan_report = proc.stderr.decode(errors="replace")[:4000],
            )

            # Parse strace output for syscalls
            if self._strace:
                self._parse_strace(proc.stderr.decode(errors="replace"), trace)

            return trace

        except subprocess.TimeoutExpired:
            elapsed = (time.time() - t_start) * 1000
            return DynamicTrace(
                target_path = self._target,
                input_data  = input_data,
                exit_code   = -1,
                signal      = None,
                elapsed_ms  = elapsed,
            )
        except Exception as _e:
            log.debug("trace execution error: %s", _e)
            return DynamicTrace(
                target_path = self._target,
                input_data  = input_data,
                exit_code   = -2,
            )

    @staticmethod
    def _parse_strace(strace_output: str, trace: DynamicTrace) -> None:
        """Parse strace output to extract syscall names and counts."""
        for line in strace_output.splitlines():
            m = re.match(r'([A-Za-z_][A-Za-z0-9_]*)[(]', line)
            if m:
                syscall = m.group(1)
                trace.syscalls[syscall] = trace.syscalls.get(syscall, 0) + 1


__all__ = ["ExecutionTracer", "DynamicTrace", "TraceEvent"]
