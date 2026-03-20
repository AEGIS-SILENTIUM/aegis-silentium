"""
c2/zeroday/orchestrator.py
AEGIS-SILENTIUM v12 — Zero-Day Discovery Orchestrator

Coordinates the full zero-day discovery pipeline:
  Phase 1 → Static Analysis  : parse binary, find dangerous patterns, score risk
  Phase 2 → Fuzzing Campaign : coverage-guided fuzzing with crash collection
  Phase 3 → Crash Triage     : deduplicate, classify, assess exploitability
  Phase 4 → Exploit Gen      : auto-generate ROP chains and exploit templates
  Phase 5 → Arsenal          : push confirmed findings to AEGIS exploit arsenal
  Phase 6 → Intelligence     : emit IOC/TTP data to AEGIS threat graph + IOC mgr

All phases are individually callable. The pipeline can run end-to-end
or be paused/resumed per-phase. Results stream back to the C2 operator
via the callback system.
"""
from __future__ import annotations

import logging
import os
import threading
import time
import uuid
from typing import Any, Callable, Dict, List, Optional

from zeroday.models import (
    Crash, Finding, FuzzCampaign, Target,
    CampaignStatus, Exploitability, Severity, VulnClass,
)
from zeroday.analysis.static.analyzer import StaticAnalyzer
from zeroday.fuzzing.engine import FuzzEngine
from zeroday.exploit.generator import ExploitGenerator

log = logging.getLogger("aegis.zeroday.orchestrator")

# CVSS approximation map
_VULN_CVSS: Dict[VulnClass, float] = {
    VulnClass.BUFFER_OVERFLOW:   8.8,
    VulnClass.HEAP_OVERFLOW:     9.0,
    VulnClass.USE_AFTER_FREE:    9.1,
    VulnClass.DOUBLE_FREE:       8.5,
    VulnClass.FORMAT_STRING:     9.3,
    VulnClass.INTEGER_OVERFLOW:  7.5,
    VulnClass.NULL_DEREF:        5.5,
    VulnClass.TYPE_CONFUSION:    9.0,
    VulnClass.RACE_CONDITION:    7.8,
    VulnClass.INJECTION:         9.8,
    VulnClass.PATH_TRAVERSAL:    7.5,
    VulnClass.MEMORY_CORRUPTION: 8.5,
    VulnClass.INFO_LEAK:         6.5,
    VulnClass.LOGIC_BUG:         6.0,
    VulnClass.UNKNOWN:           5.0,
}


class ZeroDayPipeline:
    """
    Full zero-day discovery pipeline orchestrator.

    Thread-safe. Multiple campaigns can run concurrently (one per target).
    Results are stored in-memory and optionally pushed to AEGIS subsystems
    via injected callback functions.

    Integration hooks:
      on_crash_fn(crash)          → called for every unique crash
      on_finding_fn(finding)      → called when a finding is confirmed
      arsenal_push_fn(data)       → push to AEGIS ExploitArsenal
      ioc_push_fn(ioc_list)       → push to AEGIS IOCManager
      audit_fn(kind, msg, meta)   → push to AEGIS audit log
    """

    def __init__(
        self,
        on_crash_fn:        Optional[Callable[[Crash], None]]    = None,
        on_finding_fn:      Optional[Callable[[Finding], None]]  = None,
        arsenal_push_fn:    Optional[Callable[[dict], None]]     = None,
        ioc_push_fn:        Optional[Callable[[list], None]]     = None,
        payload_push_fn:    Optional[Callable[[dict, str], None]]= None,
        session_deliver_fn: Optional[Callable[[str, bytes], bool]]= None,
        audit_fn:           Optional[Callable[..., None]]        = None,
    ) -> None:
        self._on_crash        = on_crash_fn
        self._on_finding      = on_finding_fn
        self._arsenal         = arsenal_push_fn
        self._ioc_push        = ioc_push_fn
        self._payload_push    = payload_push_fn     # fn(finding_dict, operator) → build_id
        self._session_deliver = session_deliver_fn  # fn(session_id, payload_bytes) → bool
        self._audit           = audit_fn

        # Active state
        self._targets:   Dict[str, Target]       = {}
        self._campaigns: Dict[str, FuzzCampaign] = {}
        self._findings:  Dict[str, Finding]      = {}
        self._crashes:   Dict[str, Crash]        = {}
        self._engines:   Dict[str, FuzzEngine]   = {}
        self._lock       = threading.RLock()

        self._static  = StaticAnalyzer()
        self._exploit = ExploitGenerator()

    # ── Target management ─────────────────────────────────────────────────────

    def register_target(self, target: Target) -> str:
        """Register a target binary/service for analysis."""
        with self._lock:
            self._targets[target.target_id] = target
        self._emit("target_registered", f"Target '{target.name}' registered",
                   {"target_id": target.target_id, "type": target.target_type.value})
        log.info("Target registered: %s (%s)", target.name, target.target_id[:8])
        return target.target_id

    def get_target(self, target_id: str) -> Optional[Target]:
        with self._lock:
            return self._targets.get(target_id)

    def list_targets(self) -> List[dict]:
        with self._lock:
            return [t.to_dict() for t in self._targets.values()]

    # ── Phase 1: Static Analysis ──────────────────────────────────────────────

    def run_static_analysis(self, target_id: str) -> dict:
        """Run full static analysis on a registered target."""
        target = self.get_target(target_id)
        if not target:
            raise ValueError(f"Target {target_id!r} not registered")

        self._emit("analysis_started", f"Static analysis: {target.name}",
                   {"target_id": target_id, "phase": "static"})

        result = self._static.analyse(target)

        # Auto-register vulnerable findings from static analysis
        for call in result.get("dangerous_calls", [])[:5]:
            if call["danger_score"] >= 0.8:
                finding = Finding(
                    target_id    = target_id,
                    title        = f"Dangerous function: {call['function']}",
                    vuln_class   = VulnClass(call["vuln_class"]) if call["vuln_class"] in [v.value for v in VulnClass] else VulnClass.UNKNOWN,
                    severity     = Severity.HIGH if call["danger_score"] >= 0.9 else Severity.MEDIUM,
                    exploitability = Exploitability.POSSIBLE,
                    description  = call["description"],
                    affected_component = call["function"],
                    cvss_score   = call["danger_score"] * 10,
                    analyst      = "static_analysis",
                )
                self._register_finding(finding)

        self._emit("analysis_complete", f"Static analysis done: {target.name}",
                   {"target_id": target_id, "risk_score": result.get("risk_score", 0)})
        log.info("Static analysis complete: %s  risk=%.2f",
                  target.name, result.get("risk_score", 0))
        return result

    # ── Phase 2: Fuzzing ──────────────────────────────────────────────────────

    def start_fuzzing(
        self,
        target_id:      str,
        max_duration_s: float = 3600.0,
        max_execs:      int   = 0,
        seed_dir:       Optional[str] = None,
        fuzzer_name:    str   = "custom",
    ) -> str:
        """Launch a new fuzzing campaign. Returns campaign_id."""
        target = self.get_target(target_id)
        if not target:
            raise ValueError(f"Target {target_id!r} not registered")

        campaign = FuzzCampaign(
            target_id      = target_id,
            name           = f"{target.name}-{time.strftime('%H%M%S')}",
            fuzzer         = fuzzer_name,
            max_duration_s = max_duration_s,
            max_execs      = max_execs,
        )
        engine = FuzzEngine(
            target      = target,
            campaign    = campaign,
            crash_cb    = self._handle_crash,
            seed_dir    = seed_dir,
        )

        with self._lock:
            self._campaigns[campaign.campaign_id] = campaign
            self._engines[campaign.campaign_id]   = engine

        engine.start()
        self._emit("campaign_started", f"Fuzzing started: {campaign.name}",
                   {"campaign_id": campaign.campaign_id, "target_id": target_id})
        log.info("Fuzzing campaign started: %s", campaign.campaign_id[:12])
        return campaign.campaign_id

    def stop_fuzzing(self, campaign_id: str) -> bool:
        with self._lock:
            engine = self._engines.get(campaign_id)
        if engine:
            engine.stop()
            self._emit("campaign_stopped", f"Campaign {campaign_id[:12]} stopped",
                       {"campaign_id": campaign_id})
            return True
        return False

    def pause_campaign(self, campaign_id: str) -> bool:
        with self._lock:
            engine = self._engines.get(campaign_id)
        if engine:
            engine.pause()
            return True
        return False

    def resume_campaign(self, campaign_id: str) -> bool:
        with self._lock:
            engine = self._engines.get(campaign_id)
        if engine:
            engine.resume()
            return True
        return False

    def get_campaign_stats(self, campaign_id: str) -> Optional[dict]:
        with self._lock:
            engine = self._engines.get(campaign_id)
            campaign = self._campaigns.get(campaign_id)
        if engine:
            return engine.stats()
        if campaign:
            return campaign.to_dict()
        return None

    def list_campaigns(self) -> List[dict]:
        with self._lock:
            return [c.to_dict() for c in self._campaigns.values()]

    # ── Phase 3: Crash handling ───────────────────────────────────────────────

    def _handle_crash(self, crash: Crash) -> None:
        """Called by FuzzEngine for each unique crash."""
        with self._lock:
            self._crashes[crash.crash_id] = crash

        log.info("New unique crash: %s  class=%s  exploitable=%s",
                  crash.crash_hash, crash.vuln_class.value, crash.is_exploitable)

        self._emit("crash_found",
                   f"Unique crash: {crash.crash_hash} ({crash.vuln_class.value})",
                   crash.to_dict())

        if self._on_crash:
            try:
                self._on_crash(crash)
            except Exception as _e:
                log.debug("on_crash callback error: %s", _e)

        # Auto-escalate exploitable crashes to findings
        if crash.is_exploitable:
            self._auto_triage_crash(crash)

    def _auto_triage_crash(self, crash: Crash) -> None:
        """Automatically create a Finding from a high-value crash."""
        severity   = Severity.CRITICAL if crash.vuln_class in (
            VulnClass.HEAP_OVERFLOW, VulnClass.USE_AFTER_FREE,
            VulnClass.FORMAT_STRING, VulnClass.BUFFER_OVERFLOW,
        ) else Severity.HIGH

        finding = Finding(
            target_id    = crash.target_id,
            campaign_id  = crash.campaign_id,
            title        = f"{crash.vuln_class.value.replace('_',' ').title()} in {crash.target_id[:16]}",
            vuln_class   = crash.vuln_class,
            severity     = severity,
            exploitability = Exploitability.POSSIBLE,
            description  = (
                f"Crash detected: signal={crash.signal}, "
                f"PC={hex(crash.pc) if crash.pc else 'unknown'}, "
                f"class={crash.vuln_class.value}"
            ),
            crash_ids    = [crash.crash_id],
            cvss_score   = _VULN_CVSS.get(crash.vuln_class, 7.5),
            confirmed_at = time.time(),
            analyst      = "auto_triage",
        )
        self._register_finding(finding)

    # ── Phase 4: Exploit Generation ───────────────────────────────────────────

    def generate_exploit(
        self,
        crash_id:    str,
        lhost:       str = "127.0.0.1",
        lport:       int = 4444,
    ) -> Optional[dict]:
        """Generate an exploit template for a crash."""
        with self._lock:
            crash = self._crashes.get(crash_id)
        if not crash:
            return None

        target = self.get_target(crash.target_id)
        binary_path  = target.path if target else None
        binary_info: Optional[dict] = None

        if binary_path and os.path.isfile(binary_path):
            try:
                from zeroday.analysis.static.analyzer import BinaryParser
                bi = BinaryParser().parse(binary_path)
                binary_info = bi.to_dict()
            except Exception as _e:
                log.debug("Binary parse for exploit gen: %s", _e)

        template = self._exploit.assess_and_generate(
            crash, binary_path, binary_info, lhost, lport
        )

        # Update finding with exploit template
        with self._lock:
            for finding in self._findings.values():
                if crash_id in finding.crash_ids:
                    finding.proof_of_concept = template.code[:500]
                    finding.exploitability   = (
                        Exploitability.WEAPONIZED
                        if template.reliability >= 0.6
                        else Exploitability.LIKELY
                    )
                    break

        self._emit("exploit_generated",
                   f"Exploit template: {template.exploit_type} (reliability={template.reliability:.0%})",
                   template.to_dict())

        # Auto-deliver shellcode to active sessions if session_deliver_fn is wired
        if (self._session_deliver and template.shellcode and
                template.reliability >= 0.4):
            with self._lock:
                # Find sessions for the target
                target = self._targets.get(crash.target_id)
            if target:
                log.info("ZeroDay: shellcode ready for delivery (%d bytes, reliability=%.0f%%)",
                          len(template.shellcode), template.reliability * 100)
                # Caller can use session_deliver_fn to send to specific session
                self._emit("exploit_ready_for_delivery",
                            f"Shellcode ready: {len(template.shellcode)} bytes",
                            {"exploit_id": template.exploit_id,
                             "shellcode_size": len(template.shellcode),
                             "reliability": template.reliability})

        return template.to_dict()

    # ── Phase 5: Arsenal integration ─────────────────────────────────────────

    def _register_finding(self, finding: Finding) -> str:
        """
        Register a finding and push to all connected AEGIS subsystems:
          1. Arsenal  — creates an exploit entry (available status)
          2. Payload  — auto-builds a payload from the finding (if payload_push_fn set)
          3. IOC push — registers target IPs/domains as threat IOCs
          4. Audit    — emits operator-visible event
          5. Callback — notifies on_finding_fn subscriber
        """
        with self._lock:
            self._findings[finding.finding_id] = finding

        log.info("Finding registered: %s  severity=%s",
                  finding.title[:50], finding.severity.value)
        self._emit("finding_registered", finding.title, finding.to_dict())

        # 1. Push to AEGIS arsenal
        arsenal_id = None
        if self._arsenal:
            try:
                self._arsenal({
                    "cve_id":      finding.cve_id,
                    "name":        finding.title,
                    "severity":    finding.severity.value.upper(),
                    "type":        self._map_vuln_to_exploit_type(finding.vuln_class),
                    "target":      self._guess_target(finding.target_id),
                    "description": finding.description,
                    "notes":       (
                        f"Auto-discovered by AEGIS ZeroDay pipeline. "
                        f"vuln={finding.vuln_class.value} "
                        f"cvss={finding.cvss_score:.1f} "
                        f"analyst={finding.analyst}"
                    ),
                    "reliability": int(min(100, (finding.cvss_score or 5.0) * 10)),
                    "cvss_score":  finding.cvss_score,
                })
            except Exception as _e:
                log.debug("Arsenal push error: %s", _e)

        # 2. Auto-build payload from finding (high-severity only)
        if (self._payload_push and
                finding.severity in (Severity.CRITICAL, Severity.HIGH) and
                finding.exploitability != Exploitability.UNKNOWN):
            try:
                self._payload_push(finding.to_dict(), "zeroday_pipeline")
                log.info("Payload build queued for finding %s", finding.finding_id[:8])
            except Exception as _e:
                log.debug("Payload push error: %s", _e)

        # 3. Push target as IOC if we have an IP/host
        if self._ioc_push:
            try:
                with self._lock:
                    target = self._targets.get(finding.target_id)
                if target and target.network_host:
                    self._ioc_push([{
                        "ioc_type": "ip-address",
                        "value":    target.network_host,
                        "source":   "zeroday_scanner",
                        "confidence": min(1.0, (finding.cvss_score or 5.0) / 10.0),
                        "tags":     ["zeroday", finding.vuln_class.value,
                                      finding.severity.value],
                        "description": f"Vulnerable host: {finding.title}",
                    }])
            except Exception as _e:
                log.debug("IOC push error: %s", _e)

        # 4. Notify callback
        if self._on_finding:
            try:
                self._on_finding(finding)
            except Exception as _e:
                log.debug("on_finding callback error: %s", _e)

        return finding.finding_id

    # ── Query ─────────────────────────────────────────────────────────────────

    def list_findings(self) -> List[dict]:
        with self._lock:
            return [f.to_dict() for f in self._findings.values()]

    def list_crashes(self, campaign_id: Optional[str] = None) -> List[dict]:
        with self._lock:
            crashes = list(self._crashes.values())
        if campaign_id:
            crashes = [c for c in crashes if c.campaign_id == campaign_id]
        return [c.to_dict() for c in crashes]

    def get_finding(self, finding_id: str) -> Optional[dict]:
        with self._lock:
            f = self._findings.get(finding_id)
        return f.to_dict() if f else None

    def dashboard_stats(self) -> dict:
        """Aggregate stats for the operator dashboard."""
        with self._lock:
            active_campaigns = [
                c for c in self._campaigns.values()
                if c.status == CampaignStatus.RUNNING
            ]
            total_crashes   = len(self._crashes)
            unique_crashes  = sum(1 for c in self._crashes.values() if c.is_unique)
            findings_by_sev = {}
            for f in self._findings.values():
                findings_by_sev[f.severity.value] = findings_by_sev.get(f.severity.value, 0) + 1

        total_execs = sum(
            self._campaigns[cid].total_execs
            for cid in self._campaigns
        )
        return {
            "active_campaigns":  len(active_campaigns),
            "total_campaigns":   len(self._campaigns),
            "total_targets":     len(self._targets),
            "total_findings":    len(self._findings),
            "findings_by_sev":   findings_by_sev,
            "total_crashes":     total_crashes,
            "unique_crashes":    unique_crashes,
            "total_execs":       total_execs,
            "active_execs_ps":   sum(c.execs_per_sec for c in active_campaigns),
            "active_coverage":   sum(c.coverage_edges for c in active_campaigns),
        }

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _emit(self, kind: str, msg: str, meta: dict) -> None:
        if self._audit:
            try:
                self._audit(kind, msg, meta)
            except Exception as _e:
                log.debug("audit emit error: %s", _e)

    @staticmethod
    def _map_vuln_to_exploit_type(vc: VulnClass) -> str:
        mapping = {
            VulnClass.BUFFER_OVERFLOW: "RCE",
            VulnClass.HEAP_OVERFLOW:   "RCE",
            VulnClass.USE_AFTER_FREE:  "RCE",
            VulnClass.FORMAT_STRING:   "RCE",
            VulnClass.INJECTION:       "RCE",
            VulnClass.INTEGER_OVERFLOW: "RCE",
            VulnClass.DOUBLE_FREE:     "LPE",
            VulnClass.RACE_CONDITION:  "LPE",
            VulnClass.NULL_DEREF:      "DoS",
            VulnClass.PATH_TRAVERSAL:  "Auth Bypass",
            VulnClass.INFO_LEAK:       "Auth Bypass",
        }
        return mapping.get(vc, "Custom")

    def _guess_target(self, target_id: str) -> str:
        with self._lock:
            t = self._targets.get(target_id)
        if t:
            name = (t.path or t.name).lower()
            if "windows" in name or ".exe" in name or ".dll" in name:
                return "Windows"
            if "android" in name or ".apk" in name:
                return "Android"
            if "ios" in name or "macos" in name:
                return "macOS"
        return "Linux"


# Module-level singleton pipeline
_pipeline: Optional[ZeroDayPipeline] = None
_pipeline_lock = threading.Lock()


def get_pipeline(**kwargs) -> ZeroDayPipeline:
    """Return the module-level pipeline singleton, creating it if needed."""
    global _pipeline
    with _pipeline_lock:
        if _pipeline is None:
            _pipeline = ZeroDayPipeline(**kwargs)
    return _pipeline


def init_pipeline(**kwargs) -> ZeroDayPipeline:
    """Initialise (or re-initialise) the pipeline with AEGIS integration hooks."""
    global _pipeline
    with _pipeline_lock:
        _pipeline = ZeroDayPipeline(**kwargs)
    return _pipeline


__all__ = ["ZeroDayPipeline", "get_pipeline", "init_pipeline"]
