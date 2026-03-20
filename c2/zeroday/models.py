"""
c2/zeroday/models.py
AEGIS-SILENTIUM v12 — Zero-Day Discovery Framework: Core Data Models

All data classes used across the pipeline: targets, findings, crashes,
exploit primitives, and campaign state.
"""
from __future__ import annotations

import hashlib
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


# ── Enumerations ──────────────────────────────────────────────────────────────

class TargetType(str, Enum):
    BINARY   = "binary"
    WEB      = "web"
    NETWORK  = "network"
    KERNEL   = "kernel"
    BROWSER  = "browser"

class TargetArch(str, Enum):
    X86     = "x86"
    X86_64  = "x86_64"
    ARM     = "arm"
    ARM64   = "aarch64"
    MIPS    = "mips"
    RISCV   = "riscv"
    UNKNOWN = "unknown"

class VulnClass(str, Enum):
    BUFFER_OVERFLOW   = "buffer_overflow"
    HEAP_OVERFLOW     = "heap_overflow"
    USE_AFTER_FREE    = "use_after_free"
    DOUBLE_FREE       = "double_free"
    FORMAT_STRING     = "format_string"
    INTEGER_OVERFLOW  = "integer_overflow"
    NULL_DEREF        = "null_deref"
    TYPE_CONFUSION    = "type_confusion"
    RACE_CONDITION    = "race_condition"
    INJECTION         = "injection"
    PATH_TRAVERSAL    = "path_traversal"
    MEMORY_CORRUPTION = "memory_corruption"
    INFO_LEAK         = "info_leak"
    LOGIC_BUG         = "logic_bug"
    UNKNOWN           = "unknown"

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"

class Exploitability(str, Enum):
    WEAPONIZED  = "weaponized"   # working exploit generated
    LIKELY      = "likely"       # primitives confirmed
    POSSIBLE    = "possible"     # crash confirmed, primitives unclear
    UNLIKELY    = "unlikely"     # crash but not exploitable
    UNKNOWN     = "unknown"

class CampaignStatus(str, Enum):
    PENDING   = "pending"
    RUNNING   = "running"
    PAUSED    = "paused"
    COMPLETED = "completed"
    FAILED    = "failed"


# ── Target ────────────────────────────────────────────────────────────────────

@dataclass
class Target:
    """Describes a target to be analysed / fuzzed."""
    target_id:   str              = field(default_factory=lambda: str(uuid.uuid4()))
    name:        str              = ""
    target_type: TargetType       = TargetType.BINARY
    arch:        TargetArch       = TargetArch.X86_64
    path:        str              = ""          # file path or URL
    args:        List[str]        = field(default_factory=list)
    env:         Dict[str, str]   = field(default_factory=dict)
    stdin_mode:  bool             = False       # feed input via stdin
    network_host: Optional[str]   = None
    network_port: Optional[int]   = None
    timeout_sec: float            = 5.0
    meta:        Dict[str, Any]   = field(default_factory=dict)
    sha256:      str              = ""          # binary hash if applicable
    created_at:  float            = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "target_id":    self.target_id,
            "name":         self.name,
            "target_type":  self.target_type.value,
            "arch":         self.arch.value,
            "path":         self.path,
            "args":         self.args,
            "stdin_mode":   self.stdin_mode,
            "network_host": self.network_host,
            "network_port": self.network_port,
            "timeout_sec":  self.timeout_sec,
            "sha256":       self.sha256,
            "meta":         self.meta,
            "created_at":   self.created_at,
        }


# ── Crash ─────────────────────────────────────────────────────────────────────

@dataclass
class Crash:
    """A crash event captured during fuzzing or testing."""
    crash_id:     str              = field(default_factory=lambda: str(uuid.uuid4()))
    target_id:    str              = ""
    campaign_id:  str              = ""
    input_data:   bytes            = field(default_factory=bytes)
    signal:       Optional[int]    = None       # SIGSEGV=11, SIGABRT=6, etc.
    exit_code:    Optional[int]    = None
    pc:           Optional[int]    = None       # crash program counter
    sp:           Optional[int]    = None       # stack pointer
    backtrace:    List[str]        = field(default_factory=list)
    asan_report:  str              = ""
    stderr_out:   str              = ""
    crash_hash:   str              = ""         # bucketing hash
    vuln_class:   VulnClass        = VulnClass.UNKNOWN
    is_unique:    bool             = True
    is_exploitable: bool           = False
    created_at:   float            = field(default_factory=time.time)

    def __post_init__(self) -> None:
        if not self.crash_hash and self.input_data:
            self.crash_hash = hashlib.sha256(self.input_data).hexdigest()[:16]

    def to_dict(self) -> dict:
        return {
            "crash_id":      self.crash_id,
            "target_id":     self.target_id,
            "campaign_id":   self.campaign_id,
            "input_size":    len(self.input_data),
            "input_b64":     __import__("base64").b64encode(self.input_data[:4096]).decode(),
            "signal":        self.signal,
            "exit_code":     self.exit_code,
            "pc":            hex(self.pc) if self.pc else None,
            "backtrace":     self.backtrace[:20],
            "crash_hash":    self.crash_hash,
            "vuln_class":    self.vuln_class.value,
            "is_unique":     self.is_unique,
            "is_exploitable": self.is_exploitable,
            "asan_report":   self.asan_report[:2000],
            "created_at":    self.created_at,
        }


# ── Finding / Vulnerability ───────────────────────────────────────────────────

@dataclass
class Finding:
    """A confirmed vulnerability finding."""
    finding_id:    str              = field(default_factory=lambda: str(uuid.uuid4()))
    target_id:     str              = ""
    campaign_id:   str              = ""
    title:         str              = ""
    vuln_class:    VulnClass        = VulnClass.UNKNOWN
    severity:      Severity         = Severity.MEDIUM
    exploitability: Exploitability  = Exploitability.UNKNOWN
    cvss_score:    float            = 0.0
    description:   str              = ""
    affected_component: str         = ""
    crash_ids:     List[str]        = field(default_factory=list)
    proof_of_concept: str           = ""        # PoC code / steps
    patch_diff:    str              = ""
    cve_id:        Optional[str]    = None
    references:    List[str]        = field(default_factory=list)
    tags:          List[str]        = field(default_factory=list)
    triage_notes:  str              = ""
    analyst:       str              = "automated"
    created_at:    float            = field(default_factory=time.time)
    confirmed_at:  Optional[float]  = None
    meta:          Dict[str, Any]   = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "finding_id":          self.finding_id,
            "target_id":           self.target_id,
            "campaign_id":         self.campaign_id,
            "title":               self.title,
            "vuln_class":          self.vuln_class.value,
            "severity":            self.severity.value,
            "exploitability":      self.exploitability.value,
            "cvss_score":          self.cvss_score,
            "description":         self.description,
            "affected_component":  self.affected_component,
            "crash_count":         len(self.crash_ids),
            "proof_of_concept":    self.proof_of_concept[:500],
            "cve_id":              self.cve_id,
            "references":          self.references,
            "tags":                self.tags,
            "analyst":             self.analyst,
            "created_at":          self.created_at,
            "confirmed_at":        self.confirmed_at,
            "meta":                self.meta,
        }


# ── Fuzzing Campaign ──────────────────────────────────────────────────────────

@dataclass
class FuzzCampaign:
    """Tracks state of a single fuzzing campaign."""
    campaign_id:     str              = field(default_factory=lambda: str(uuid.uuid4()))
    target_id:       str              = ""
    name:            str              = ""
    status:          CampaignStatus   = CampaignStatus.PENDING
    fuzzer:          str              = "custom"   # afl, libfuzzer, custom
    max_duration_s:  float            = 3600.0
    max_execs:       int              = 0          # 0 = unlimited
    corpus_dir:      str              = ""
    output_dir:      str              = ""
    total_execs:     int              = 0
    execs_per_sec:   float            = 0.0
    coverage_edges:  int              = 0
    unique_crashes:  int              = 0
    total_crashes:   int              = 0
    findings_count:  int              = 0
    started_at:      Optional[float]  = None
    ended_at:        Optional[float]  = None
    created_at:      float            = field(default_factory=time.time)
    config:          Dict[str, Any]   = field(default_factory=dict)

    @property
    def duration_s(self) -> float:
        if self.started_at is None:
            return 0.0
        end = self.ended_at or time.time()
        return end - self.started_at

    def to_dict(self) -> dict:
        return {
            "campaign_id":    self.campaign_id,
            "target_id":      self.target_id,
            "name":           self.name,
            "status":         self.status.value,
            "fuzzer":         self.fuzzer,
            "total_execs":    self.total_execs,
            "execs_per_sec":  round(self.execs_per_sec, 1),
            "coverage_edges": self.coverage_edges,
            "unique_crashes": self.unique_crashes,
            "findings_count": self.findings_count,
            "duration_s":     round(self.duration_s, 1),
            "started_at":     self.started_at,
            "ended_at":       self.ended_at,
            "created_at":     self.created_at,
        }


# ── Static analysis ───────────────────────────────────────────────────────────

@dataclass
class CFGNode:
    """A basic block in a Control Flow Graph."""
    addr:        int
    size:        int
    instructions: List[str]   = field(default_factory=list)
    successors:  List[int]    = field(default_factory=list)
    predecessors: List[int]   = field(default_factory=list)
    is_entry:    bool         = False
    is_exit:     bool         = False

    def to_dict(self) -> dict:
        return {
            "addr":  hex(self.addr),
            "size":  self.size,
            "insns": self.instructions[:10],
            "succs": [hex(s) for s in self.successors],
        }


@dataclass
class Function:
    """A recovered function from static analysis."""
    addr:        int
    name:        str           = ""
    size:        int           = 0
    num_blocks:  int           = 0
    cyclomatic:  int           = 1    # cyclomatic complexity
    calls:       List[int]     = field(default_factory=list)
    strings:     List[str]     = field(default_factory=list)
    is_exported: bool          = False
    danger_score: float        = 0.0  # 0-1, likelihood of vuln

    def to_dict(self) -> dict:
        return {
            "addr":         hex(self.addr),
            "name":         self.name or f"sub_{self.addr:x}",
            "size":         self.size,
            "num_blocks":   self.num_blocks,
            "cyclomatic":   self.cyclomatic,
            "num_calls":    len(self.calls),
            "is_exported":  self.is_exported,
            "danger_score": round(self.danger_score, 3),
        }


# ── Exploit primitives ────────────────────────────────────────────────────────

@dataclass
class ROPGadget:
    """A ROP gadget."""
    addr:         int
    instructions: List[str]
    pivot_sp:     bool = False  # stack pivot
    syscall:      bool = False
    pop_regs:     List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "addr":    hex(self.addr),
            "insns":   self.instructions,
            "pivot":   self.pivot_sp,
            "syscall": self.syscall,
            "pop_regs": self.pop_regs,
        }


@dataclass
class ExploitTemplate:
    """Generated exploit code template."""
    exploit_id:    str              = field(default_factory=lambda: str(uuid.uuid4()))
    finding_id:    str              = ""
    target_id:     str              = ""
    exploit_type:  str              = "generic"
    code:          str              = ""       # Python exploit code
    shellcode:     bytes            = field(default_factory=bytes)
    rop_chain:     List[int]        = field(default_factory=list)
    reliability:   float            = 0.0      # 0-1
    tested:        bool             = False
    notes:         str              = ""
    created_at:    float            = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "exploit_id":  self.exploit_id,
            "finding_id":  self.finding_id,
            "exploit_type": self.exploit_type,
            "reliability": round(self.reliability, 2),
            "tested":      self.tested,
            "code_len":    len(self.code),
            "notes":       self.notes,
            "created_at":  self.created_at,
        }


__all__ = [
    "Target", "TargetType", "TargetArch",
    "Crash", "Finding", "FuzzCampaign",
    "VulnClass", "Severity", "Exploitability", "CampaignStatus",
    "CFGNode", "Function", "ROPGadget", "ExploitTemplate",
]
