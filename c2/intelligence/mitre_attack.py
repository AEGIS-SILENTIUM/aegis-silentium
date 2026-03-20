"""
c2/intelligence/mitre_attack.py
AEGIS-SILENTIUM v12 — MITRE ATT&CK Framework Integration

Maps observed TTPs (Tactics, Techniques, Procedures) to the MITRE ATT&CK
Enterprise matrix.  Tracks which techniques are observed per campaign/node.

Tactics (TA0001–TA0011):
  Initial Access, Execution, Persistence, Privilege Escalation, Defense
  Evasion, Credential Access, Discovery, Lateral Movement, Collection,
  Command and Control, Exfiltration, Impact

Features
--------
  • Full ATT&CK Enterprise technique registry (embedded subset)
  • Campaign-to-TTP mapping with confidence and evidence
  • Navigator-compatible JSON export
  • Technique relationship graph (sub-techniques, mitigations)
  • Detection coverage tracking
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

log = logging.getLogger("aegis.intelligence.mitre")


@dataclass
class Tactic:
    tactic_id:   str    # e.g. "TA0001"
    name:        str
    short_name:  str    # e.g. "initial-access"
    description: str = ""
    url:         str = ""

    def to_dict(self) -> dict:
        return {
            "tactic_id":  self.tactic_id,
            "name":       self.name,
            "short_name": self.short_name,
        }


@dataclass
class Technique:
    technique_id: str    # e.g. "T1059.001"
    name:         str
    tactic_ids:   List[str]
    description:  str         = ""
    platforms:    List[str]   = field(default_factory=list)
    data_sources: List[str]   = field(default_factory=list)
    is_subtechnique: bool     = False
    parent_id:    Optional[str] = None   # e.g. "T1059" for "T1059.001"
    url:          str         = ""
    detection:    str         = ""
    mitigation:   str         = ""

    def to_dict(self) -> dict:
        return {
            "technique_id":    self.technique_id,
            "name":            self.name,
            "tactic_ids":      self.tactic_ids,
            "description":     self.description,
            "platforms":       self.platforms,
            "is_subtechnique": self.is_subtechnique,
            "parent_id":       self.parent_id,
        }


@dataclass
class TTPObservation:
    obs_id:       str
    technique_id: str
    campaign_id:  Optional[str]
    node_id:      Optional[str]
    confidence:   float = 0.8
    evidence:     str   = ""
    observed_at:  float = field(default_factory=time.time)
    operator:     str   = ""
    tags:         List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "obs_id":       self.obs_id,
            "technique_id": self.technique_id,
            "campaign_id":  self.campaign_id,
            "node_id":      self.node_id,
            "confidence":   self.confidence,
            "evidence":     self.evidence,
            "observed_at":  self.observed_at,
            "operator":     self.operator,
            "tags":         self.tags,
        }


# ── ATT&CK Data (embedded subset — Enterprise v14) ────────────────────────────

_TACTICS: List[dict] = [
    {"id": "TA0001", "name": "Initial Access",         "short": "initial-access"},
    {"id": "TA0002", "name": "Execution",              "short": "execution"},
    {"id": "TA0003", "name": "Persistence",            "short": "persistence"},
    {"id": "TA0004", "name": "Privilege Escalation",   "short": "privilege-escalation"},
    {"id": "TA0005", "name": "Defense Evasion",        "short": "defense-evasion"},
    {"id": "TA0006", "name": "Credential Access",      "short": "credential-access"},
    {"id": "TA0007", "name": "Discovery",              "short": "discovery"},
    {"id": "TA0008", "name": "Lateral Movement",       "short": "lateral-movement"},
    {"id": "TA0009", "name": "Collection",             "short": "collection"},
    {"id": "TA0010", "name": "Exfiltration",           "short": "exfiltration"},
    {"id": "TA0011", "name": "Command and Control",    "short": "command-and-control"},
    {"id": "TA0040", "name": "Impact",                 "short": "impact"},
]

_TECHNIQUES: List[dict] = [
    # Initial Access
    {"id": "T1190", "name": "Exploit Public-Facing Application",
     "tactics": ["TA0001"], "platforms": ["Linux", "Windows", "macOS", "Network"]},
    {"id": "T1133", "name": "External Remote Services",
     "tactics": ["TA0001", "TA0003"], "platforms": ["Linux", "Windows", "macOS"]},
    {"id": "T1566",    "name": "Phishing",
     "tactics": ["TA0001"], "platforms": ["Linux", "Windows", "macOS"]},
    {"id": "T1566.001","name": "Spearphishing Attachment",
     "tactics": ["TA0001"], "is_sub": True, "parent": "T1566",
     "platforms": ["Linux", "Windows", "macOS"]},
    {"id": "T1566.002","name": "Spearphishing Link",
     "tactics": ["TA0001"], "is_sub": True, "parent": "T1566",
     "platforms": ["Linux", "Windows", "macOS"]},
    # Execution
    {"id": "T1059",    "name": "Command and Scripting Interpreter",
     "tactics": ["TA0002"], "platforms": ["Linux", "Windows", "macOS"]},
    {"id": "T1059.001","name": "PowerShell",
     "tactics": ["TA0002"], "is_sub": True, "parent": "T1059",
     "platforms": ["Windows"]},
    {"id": "T1059.003","name": "Windows Command Shell",
     "tactics": ["TA0002"], "is_sub": True, "parent": "T1059",
     "platforms": ["Windows"]},
    {"id": "T1059.004","name": "Unix Shell",
     "tactics": ["TA0002"], "is_sub": True, "parent": "T1059",
     "platforms": ["Linux", "macOS"]},
    {"id": "T1059.006","name": "Python",
     "tactics": ["TA0002"], "is_sub": True, "parent": "T1059",
     "platforms": ["Linux", "Windows", "macOS"]},
    {"id": "T1053",    "name": "Scheduled Task/Job",
     "tactics": ["TA0002", "TA0003", "TA0004"],
     "platforms": ["Linux", "Windows", "macOS"]},
    # Persistence
    {"id": "T1547",    "name": "Boot or Logon Autostart Execution",
     "tactics": ["TA0003", "TA0004"], "platforms": ["Linux", "Windows", "macOS"]},
    {"id": "T1547.001","name": "Registry Run Keys / Startup Folder",
     "tactics": ["TA0003", "TA0004"], "is_sub": True, "parent": "T1547",
     "platforms": ["Windows"]},
    {"id": "T1543",    "name": "Create or Modify System Process",
     "tactics": ["TA0003", "TA0004"], "platforms": ["Linux", "Windows", "macOS"]},
    {"id": "T1543.003","name": "Windows Service",
     "tactics": ["TA0003", "TA0004"], "is_sub": True, "parent": "T1543",
     "platforms": ["Windows"]},
    # Privilege Escalation
    {"id": "T1068",    "name": "Exploitation for Privilege Escalation",
     "tactics": ["TA0004"], "platforms": ["Linux", "Windows", "macOS"]},
    {"id": "T1078",    "name": "Valid Accounts",
     "tactics": ["TA0001", "TA0003", "TA0004", "TA0005"],
     "platforms": ["Linux", "Windows", "macOS", "Cloud"]},
    # Defense Evasion
    {"id": "T1055",    "name": "Process Injection",
     "tactics": ["TA0004", "TA0005"], "platforms": ["Linux", "Windows", "macOS"]},
    {"id": "T1055.001","name": "Dynamic-link Library Injection",
     "tactics": ["TA0004", "TA0005"], "is_sub": True, "parent": "T1055",
     "platforms": ["Windows"]},
    {"id": "T1027",    "name": "Obfuscated Files or Information",
     "tactics": ["TA0005"], "platforms": ["Linux", "Windows", "macOS"]},
    {"id": "T1070",    "name": "Indicator Removal",
     "tactics": ["TA0005"], "platforms": ["Linux", "Windows", "macOS", "Network"]},
    {"id": "T1070.004","name": "File Deletion",
     "tactics": ["TA0005"], "is_sub": True, "parent": "T1070",
     "platforms": ["Linux", "Windows", "macOS"]},
    # Credential Access
    {"id": "T1003",    "name": "OS Credential Dumping",
     "tactics": ["TA0006"], "platforms": ["Linux", "Windows", "macOS"]},
    {"id": "T1003.001","name": "LSASS Memory",
     "tactics": ["TA0006"], "is_sub": True, "parent": "T1003",
     "platforms": ["Windows"]},
    {"id": "T1110",    "name": "Brute Force",
     "tactics": ["TA0006"], "platforms": ["Linux", "Windows", "macOS", "Cloud"]},
    {"id": "T1552",    "name": "Unsecured Credentials",
     "tactics": ["TA0006"], "platforms": ["Linux", "Windows", "macOS", "Cloud"]},
    # Discovery
    {"id": "T1046",    "name": "Network Service Discovery",
     "tactics": ["TA0007"], "platforms": ["Linux", "Windows", "macOS", "Network"]},
    {"id": "T1082",    "name": "System Information Discovery",
     "tactics": ["TA0007"], "platforms": ["Linux", "Windows", "macOS"]},
    {"id": "T1083",    "name": "File and Directory Discovery",
     "tactics": ["TA0007"], "platforms": ["Linux", "Windows", "macOS"]},
    {"id": "T1057",    "name": "Process Discovery",
     "tactics": ["TA0007"], "platforms": ["Linux", "Windows", "macOS"]},
    {"id": "T1018",    "name": "Remote System Discovery",
     "tactics": ["TA0007"], "platforms": ["Linux", "Windows", "macOS"]},
    # Lateral Movement
    {"id": "T1021",    "name": "Remote Services",
     "tactics": ["TA0008"], "platforms": ["Linux", "Windows", "macOS"]},
    {"id": "T1021.001","name": "Remote Desktop Protocol",
     "tactics": ["TA0008"], "is_sub": True, "parent": "T1021",
     "platforms": ["Windows"]},
    {"id": "T1021.004","name": "SSH",
     "tactics": ["TA0008"], "is_sub": True, "parent": "T1021",
     "platforms": ["Linux", "macOS"]},
    {"id": "T1550",    "name": "Use Alternate Authentication Material",
     "tactics": ["TA0005", "TA0008"], "platforms": ["Windows"]},
    # Collection
    {"id": "T1005",    "name": "Data from Local System",
     "tactics": ["TA0009"], "platforms": ["Linux", "Windows", "macOS"]},
    {"id": "T1074",    "name": "Data Staged",
     "tactics": ["TA0009"], "platforms": ["Linux", "Windows", "macOS"]},
    {"id": "T1056",    "name": "Input Capture",
     "tactics": ["TA0006", "TA0009"], "platforms": ["Linux", "Windows", "macOS"]},
    # C2
    {"id": "T1071",    "name": "Application Layer Protocol",
     "tactics": ["TA0011"], "platforms": ["Linux", "Windows", "macOS", "Network"]},
    {"id": "T1071.001","name": "Web Protocols",
     "tactics": ["TA0011"], "is_sub": True, "parent": "T1071",
     "platforms": ["Linux", "Windows", "macOS"]},
    {"id": "T1071.004","name": "DNS",
     "tactics": ["TA0011"], "is_sub": True, "parent": "T1071",
     "platforms": ["Linux", "Windows", "macOS", "Network"]},
    {"id": "T1573",    "name": "Encrypted Channel",
     "tactics": ["TA0011"], "platforms": ["Linux", "Windows", "macOS", "Network"]},
    {"id": "T1573.002","name": "Asymmetric Cryptography",
     "tactics": ["TA0011"], "is_sub": True, "parent": "T1573",
     "platforms": ["Linux", "Windows", "macOS"]},
    {"id": "T1090",    "name": "Proxy",
     "tactics": ["TA0011"], "platforms": ["Linux", "Windows", "macOS", "Network"]},
    {"id": "T1090.003","name": "Multi-hop Proxy",
     "tactics": ["TA0011"], "is_sub": True, "parent": "T1090",
     "platforms": ["Linux", "Windows", "macOS"]},
    {"id": "T1132",    "name": "Data Encoding",
     "tactics": ["TA0011"], "platforms": ["Linux", "Windows", "macOS", "Network"]},
    # Exfiltration
    {"id": "T1041",    "name": "Exfiltration Over C2 Channel",
     "tactics": ["TA0010"], "platforms": ["Linux", "Windows", "macOS"]},
    {"id": "T1048",    "name": "Exfiltration Over Alternative Protocol",
     "tactics": ["TA0010"], "platforms": ["Linux", "Windows", "macOS", "Network"]},
    {"id": "T1048.003","name": "Exfiltration Over Unencrypted Protocol",
     "tactics": ["TA0010"], "is_sub": True, "parent": "T1048",
     "platforms": ["Linux", "Windows", "macOS", "Network"]},
    # Impact
    {"id": "T1486",    "name": "Data Encrypted for Impact",
     "tactics": ["TA0040"], "platforms": ["Linux", "Windows", "macOS"]},
    {"id": "T1489",    "name": "Service Stop",
     "tactics": ["TA0040"], "platforms": ["Linux", "Windows", "macOS", "Network"]},
    {"id": "T1561",    "name": "Disk Wipe",
     "tactics": ["TA0040"], "platforms": ["Linux", "Windows", "macOS"]},
]


class MITREMapper:
    """
    ATT&CK technique registry and TTP observation tracker.

    Usage::

        mapper = MITREMapper()
        mapper.observe(
            technique_id="T1059.001",
            campaign_id="campaign-123",
            node_id="node-abc",
            confidence=0.9,
            evidence="PowerShell encoded command in process log",
            operator="analyst1",
        )
        profile = mapper.campaign_profile("campaign-123")
    """

    def __init__(self) -> None:
        self._tactics: Dict[str, Tactic] = {}
        self._techniques: Dict[str, Technique] = {}
        self._observations: Dict[str, TTPObservation] = {}
        self._lock = threading.RLock()
        self._load_embedded()

    def _load_embedded(self) -> None:
        for t in _TACTICS:
            tactic = Tactic(tactic_id=t["id"], name=t["name"], short_name=t["short"])
            self._tactics[tactic.tactic_id] = tactic
        for t in _TECHNIQUES:
            tech = Technique(
                technique_id     = t["id"],
                name             = t["name"],
                tactic_ids       = list(t.get("tactics", [])),
                platforms        = list(t.get("platforms", [])),
                is_subtechnique  = t.get("is_sub", False),
                parent_id        = t.get("parent"),
            )
            self._techniques[tech.technique_id] = tech
        log.info("Loaded %d ATT&CK techniques, %d tactics",
                 len(self._techniques), len(self._tactics))

    # ── API ───────────────────────────────────────────────────────────────────

    def get_technique(self, technique_id: str) -> Optional[Technique]:
        return self._techniques.get(technique_id)

    def get_tactic(self, tactic_id: str) -> Optional[Tactic]:
        return self._tactics.get(tactic_id)

    def techniques_for_tactic(self, tactic_id: str) -> List[Technique]:
        return [t for t in self._techniques.values() if tactic_id in t.tactic_ids]

    def observe(
        self,
        technique_id: str,
        campaign_id:  Optional[str] = None,
        node_id:      Optional[str] = None,
        confidence:   float         = 0.8,
        evidence:     str           = "",
        operator:     str           = "",
        tags:         Optional[List[str]] = None,
    ) -> str:
        """Record a TTP observation. Returns obs_id."""
        import uuid
        obs = TTPObservation(
            obs_id       = str(uuid.uuid4()),
            technique_id = technique_id,
            campaign_id  = campaign_id,
            node_id      = node_id,
            confidence   = confidence,
            evidence     = evidence,
            operator     = operator,
            tags         = tags or [],
        )
        with self._lock:
            self._observations[obs.obs_id] = obs
        return obs.obs_id

    def campaign_profile(self, campaign_id: str) -> dict:
        """Build a full ATT&CK profile for a campaign."""
        with self._lock:
            obs = [o for o in self._observations.values()
                   if o.campaign_id == campaign_id]

        tactic_coverage: Dict[str, List[dict]] = {}
        seen_techniques: Set[str] = set()
        for o in obs:
            tech = self._techniques.get(o.technique_id)
            if not tech:
                continue
            seen_techniques.add(o.technique_id)
            for tactic_id in tech.tactic_ids:
                tac = self._tactics.get(tactic_id)
                if tac:
                    tactic_coverage.setdefault(tac.name, [])
                    if tech.technique_id not in [
                            t["technique_id"] for t in tactic_coverage[tac.name]]:
                        tactic_coverage[tac.name].append({
                            **tech.to_dict(),
                            "confidence": o.confidence,
                            "evidence":   o.evidence,
                        })

        return {
            "campaign_id":       campaign_id,
            "observation_count": len(obs),
            "technique_count":   len(seen_techniques),
            "tactic_coverage":   tactic_coverage,
            "techniques":        list(seen_techniques),
        }

    def navigator_export(self, campaign_id: Optional[str] = None) -> dict:
        """Export ATT&CK Navigator layer JSON."""
        with self._lock:
            obs = [o for o in self._observations.values()
                   if campaign_id is None or o.campaign_id == campaign_id]

        scores: Dict[str, float] = {}
        for o in obs:
            existing = scores.get(o.technique_id, 0)
            scores[o.technique_id] = max(existing, o.confidence)

        techniques_layer = []
        for tech_id, confidence in scores.items():
            techniques_layer.append({
                "techniqueID": tech_id,
                "score":       round(confidence * 100),
                "color":       self._confidence_color(confidence),
                "enabled":     True,
            })

        return {
            "name":          f"AEGIS-SILENTIUM — {campaign_id or 'All Campaigns'}",
            "versions":      {"attack": "14", "navigator": "4.9", "layer": "4.5"},
            "domain":        "enterprise-attack",
            "techniques":    techniques_layer,
            "gradient":      {"colors": ["#ffffff", "#ff6666"], "minValue": 0, "maxValue": 100},
        }

    def all_observations(self, limit: int = 200) -> List[dict]:
        with self._lock:
            obs = sorted(self._observations.values(),
                         key=lambda o: -o.observed_at)[:limit]
            return [o.to_dict() for o in obs]

    def stats(self) -> dict:
        with self._lock:
            return {
                "total_techniques":  len(self._techniques),
                "total_tactics":     len(self._tactics),
                "total_observations": len(self._observations),
                "unique_techniques_observed": len(
                    set(o.technique_id for o in self._observations.values())
                ),
            }

    @staticmethod
    def _confidence_color(confidence: float) -> str:
        if confidence >= 0.9:
            return "#ff0000"
        if confidence >= 0.7:
            return "#ff6600"
        if confidence >= 0.5:
            return "#ffcc00"
        return "#66aa00"
