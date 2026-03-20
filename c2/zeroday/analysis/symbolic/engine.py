"""
c2/zeroday/analysis/symbolic/engine.py
AEGIS-SILENTIUM v12 — Symbolic Execution Engine Interface

Provides a common interface for symbolic execution backends.
Supported backends (when libraries available):
  - angr       (pip install angr)
  - Triton DSE (requires native build)
  - KLEE       (requires LLVM bitcode + Docker)

Without a backend, returns a structured result indicating unavailability
rather than crashing — the fuzzing engine handles the path without symbolic
assistance.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional

log = logging.getLogger("aegis.zeroday.symbolic")


@dataclass
class SymbolicResult:
    """Result from symbolic execution of a path."""
    path_id:         str
    satisfiable:     bool
    input_values:    Dict[str, bytes]   = field(default_factory=dict)
    constraints:     List[str]          = field(default_factory=list)
    reachable_vulns: List[str]          = field(default_factory=list)
    backend_used:    str                = "none"
    error:           Optional[str]      = None

    def to_dict(self) -> dict:
        return {
            "path_id":      self.path_id,
            "satisfiable":  self.satisfiable,
            "input_size":   sum(len(v) for v in self.input_values.values()),
            "constraints":  len(self.constraints),
            "reachable_vulns": self.reachable_vulns,
            "backend":      self.backend_used,
            "error":        self.error,
        }


class SymbolicEngine:
    """
    Abstract symbolic execution engine.
    Tries angr first, falls back to a no-op result with guidance.

    Usage::
        engine = SymbolicEngine()
        result = engine.explore(binary_path, target_addr=0x400100)
        if result.satisfiable:
            # Use result.input_values to trigger the path
    """

    def __init__(self) -> None:
        self._backend = self._detect_backend()
        if self._backend:
            log.info("Symbolic engine: using %s", self._backend)
        else:
            log.info("Symbolic engine: no backend available (install angr for full support)")

    @staticmethod
    def _detect_backend() -> Optional[str]:
        try:
            import angr  # noqa: F401
            return "angr"
        except ImportError:
            pass
        return None

    def explore(
        self,
        binary_path: str,
        target_addr: Optional[int] = None,
        avoid_addrs: Optional[List[int]] = None,
        timeout_sec: float = 60.0,
        input_size:  int   = 64,
    ) -> SymbolicResult:
        """
        Symbolically explore a binary to find inputs that reach target_addr.
        Returns a SymbolicResult with concrete input values when satisfiable.
        """
        import uuid
        path_id = str(uuid.uuid4())[:12]

        if self._backend == "angr":
            return self._explore_angr(
                path_id, binary_path, target_addr, avoid_addrs, timeout_sec, input_size
            )

        # No backend — return structured guidance
        return SymbolicResult(
            path_id      = path_id,
            satisfiable  = False,
            backend_used = "none",
            error        = (
                "No symbolic execution backend available. "
                "Install angr: pip install angr. "
                "The fuzzing engine will cover paths without symbolic assistance."
            ),
        )

    def _explore_angr(
        self,
        path_id:     str,
        binary_path: str,
        target_addr: Optional[int],
        avoid_addrs: Optional[List[int]],
        timeout_sec: float,
        input_size:  int,
    ) -> SymbolicResult:
        """Symbolic exploration via angr."""
        try:
            import angr, claripy  # type: ignore
            proj = angr.Project(binary_path, auto_load_libs=False)
            sym_input = claripy.BVS("input", input_size * 8)
            state = proj.factory.entry_state(
                stdin=angr.SimFileStream(name="stdin", content=sym_input, size=input_size)
            )
            simgr = proj.factory.simulation_manager(state)

            find_addrs = [target_addr] if target_addr else []
            avoid = avoid_addrs or []

            simgr.explore(find=find_addrs, avoid=avoid, timeout=timeout_sec)

            if simgr.found:
                found_state = simgr.found[0]
                concrete = found_state.solver.eval(sym_input, cast_to=bytes)
                return SymbolicResult(
                    path_id      = path_id,
                    satisfiable  = True,
                    input_values = {"stdin": concrete},
                    backend_used = "angr",
                )
            return SymbolicResult(
                path_id      = path_id,
                satisfiable  = False,
                backend_used = "angr",
            )
        except Exception as _e:
            log.debug("angr exploration error: %s", _e)
            return SymbolicResult(
                path_id      = path_id,
                satisfiable  = False,
                backend_used = "angr",
                error        = str(_e)[:200],
            )


__all__ = ["SymbolicEngine", "SymbolicResult"]
