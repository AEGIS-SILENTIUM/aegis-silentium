"""
AEGIS-Advanced C2 Campaign Manager
=====================================
Full campaign lifecycle: creation, target management, scope control,
progress tracking, reporting, import/export, prioritization,
team collaboration, campaign templates, and objective tracking.
"""
import os
import json
import uuid
import time
import re
import ipaddress
from typing import List, Dict, Optional, Tuple
from datetime import datetime, timezone


# ══════════════════════════════════════════════
# Campaign model
# ══════════════════════════════════════════════

class Campaign:
    """
    Represents a scan campaign: a named collection of targets
    with shared configuration, scope rules, and objectives.
    """

    def __init__(self, name: str,
                 description: str = "",
                 scope_domains: List[str] = None,
                 scope_ips: List[str] = None,
                 exclude_patterns: List[str] = None,
                 tags: List[str] = None,
                 priority: int = 5,
                 owner: str = "operator"):
        self.id               = str(uuid.uuid4())
        self.name             = name
        self.description      = description
        self.scope_domains    = scope_domains or []
        self.scope_ips        = scope_ips or []
        self.exclude_patterns = exclude_patterns or []
        self.tags             = tags or []
        self.priority         = priority
        self.owner            = owner
        self.created_at       = datetime.now(timezone.utc).isoformat()
        self.active           = True
        self.objectives: List[Dict] = []
        self.notes            = ""
        self._targets: List[Dict] = []
        self._completed_targets: List[str] = []

    def add_target(self, url: str, priority: int = None) -> Dict:
        """Add a target to this campaign."""
        if not self.is_in_scope(url):
            raise ValueError("Target {} is out of scope".format(url))
        t = {
            "url":      url,
            "priority": priority or self.priority,
            "added":    datetime.now(timezone.utc).isoformat(),
            "status":   "pending",
        }
        self._targets.append(t)
        return t

    def add_objective(self, title: str, description: str = "",
                       severity_threshold: str = "high") -> Dict:
        """Add a testing objective."""
        obj = {
            "id":          str(uuid.uuid4()),
            "title":       title,
            "description": description,
            "threshold":   severity_threshold,
            "achieved":    False,
        }
        self.objectives.append(obj)
        return obj

    def is_in_scope(self, target: str) -> bool:
        """
        Check if target is within campaign scope.
        Returns True if no scope defined (scan everything).
        """
        if not self.scope_domains and not self.scope_ips:
            # Check exclusions only
            return not self._is_excluded(target)

        # Extract domain/IP from target
        try:
            from urllib.parse import urlparse
            host = urlparse(target if "://" in target else "http://" + target).netloc
            host = host.split(":")[0]
        except Exception:
            host = target

        # Check domain scope
        for domain in self.scope_domains:
            if host == domain or host.endswith("." + domain):
                if not self._is_excluded(target):
                    return True

        # Check IP scope
        try:
            ip = ipaddress.ip_address(host)
            for cidr in self.scope_ips:
                if ip in ipaddress.ip_network(cidr, strict=False):
                    if not self._is_excluded(target):
                        return True
        except ValueError:
            pass

        return False

    def _is_excluded(self, target: str) -> bool:
        """Check if target matches any exclusion pattern."""
        for pattern in self.exclude_patterns:
            if re.search(pattern, target, re.IGNORECASE):
                return True
        return False

    def get_stats(self) -> Dict:
        """Return campaign statistics."""
        total     = len(self._targets)
        completed = len(self._completed_targets)
        pending   = sum(1 for t in self._targets if t["status"] == "pending")
        running   = sum(1 for t in self._targets if t["status"] == "running")
        return {
            "total":     total,
            "completed": completed,
            "pending":   pending,
            "running":   running,
            "progress":  (completed / total * 100) if total else 0,
        }

    def to_dict(self) -> Dict:
        return {
            "id":               self.id,
            "name":             self.name,
            "description":      self.description,
            "scope_domains":    self.scope_domains,
            "scope_ips":        self.scope_ips,
            "exclude_patterns": self.exclude_patterns,
            "tags":             self.tags,
            "priority":         self.priority,
            "owner":            self.owner,
            "created_at":       self.created_at,
            "active":           self.active,
            "objectives":       self.objectives,
            "notes":            self.notes,
            "stats":            self.get_stats(),
        }

    @classmethod
    def from_dict(cls, d: Dict) -> "Campaign":
        c = cls(d["name"], d.get("description", ""),
                 scope_domains=d.get("scope_domains", []),
                 scope_ips=d.get("scope_ips", []),
                 exclude_patterns=d.get("exclude_patterns", []),
                 tags=d.get("tags", []),
                 priority=d.get("priority", 5),
                 owner=d.get("owner", "operator"))
        c.id         = d.get("id", c.id)
        c.created_at = d.get("created_at", c.created_at)
        c.active     = d.get("active", True)
        c.objectives = d.get("objectives", [])
        c.notes      = d.get("notes", "")
        return c


# ══════════════════════════════════════════════
# Campaign templates
# ══════════════════════════════════════════════

CAMPAIGN_TEMPLATES = {
    "web_pentest": {
        "description": "Full web application penetration test",
        "tags": ["web", "pentest", "full"],
        "priority": 7,
        "objectives": [
            {"title": "SQL Injection", "threshold": "critical"},
            {"title": "XSS", "threshold": "high"},
            {"title": "Authentication Bypass", "threshold": "critical"},
            {"title": "SSRF / RCE", "threshold": "critical"},
            {"title": "Business Logic Flaws", "threshold": "high"},
        ],
    },
    "recon": {
        "description": "Passive and active reconnaissance",
        "tags": ["recon", "osint"],
        "priority": 3,
        "objectives": [
            {"title": "Subdomain Enumeration", "threshold": "info"},
            {"title": "Open Ports and Services", "threshold": "medium"},
            {"title": "Technology Fingerprinting", "threshold": "info"},
        ],
    },
    "api_security": {
        "description": "REST/GraphQL API security assessment",
        "tags": ["api", "rest", "graphql"],
        "priority": 6,
        "objectives": [
            {"title": "Authentication/Authorization", "threshold": "critical"},
            {"title": "Injection Attacks", "threshold": "high"},
            {"title": "Mass Assignment", "threshold": "high"},
            {"title": "Rate Limiting", "threshold": "medium"},
        ],
    },
    "bug_bounty": {
        "description": "Bug bounty program targeting",
        "tags": ["bounty"],
        "priority": 5,
        "objectives": [
            {"title": "High/Critical Vulns Only", "threshold": "high"},
        ],
    },
}


def create_from_template(name: str, template_key: str,
                           scope_domains: List[str] = None,
                           **kwargs) -> Campaign:
    """Create a campaign from a predefined template."""
    tmpl = CAMPAIGN_TEMPLATES.get(template_key, {})
    c = Campaign(
        name,
        description=tmpl.get("description", ""),
        scope_domains=scope_domains or [],
        tags=tmpl.get("tags", []),
        priority=tmpl.get("priority", 5),
        **kwargs
    )
    for obj in tmpl.get("objectives", []):
        c.add_objective(obj["title"], threshold=obj.get("threshold", "high"))
    return c


# ══════════════════════════════════════════════
# Campaign manager (in-memory registry)
# ══════════════════════════════════════════════

class CampaignManager:
    """
    Registry of campaigns. Used by C2 and scheduler
    for lifecycle management.
    """

    def __init__(self):
        self._campaigns: Dict[str, Campaign] = {}

    def create(self, name: str, **kwargs) -> Campaign:
        c = Campaign(name, **kwargs)
        self._campaigns[c.id] = c
        return c

    def get(self, campaign_id: str) -> Optional[Campaign]:
        return self._campaigns.get(campaign_id)

    def get_by_name(self, name: str) -> Optional[Campaign]:
        for c in self._campaigns.values():
            if c.name == name:
                return c
        return None

    def list(self, active_only: bool = False) -> List[Campaign]:
        result = list(self._campaigns.values())
        if active_only:
            result = [c for c in result if c.active]
        return sorted(result, key=lambda c: c.created_at, reverse=True)

    def close(self, campaign_id: str) -> bool:
        if campaign_id in self._campaigns:
            self._campaigns[campaign_id].active = False
            return True
        return False

    def delete(self, campaign_id: str) -> bool:
        return self._campaigns.pop(campaign_id, None) is not None

    def export_json(self, campaign_id: str) -> Optional[str]:
        c = self.get(campaign_id)
        if not c:
            return None
        return json.dumps(c.to_dict(), indent=2)

    def import_json(self, data: str) -> Campaign:
        d = json.loads(data)
        c = Campaign.from_dict(d)
        self._campaigns[c.id] = c
        return c

    def stats(self) -> Dict:
        campaigns = self.list()
        return {
            "total":    len(campaigns),
            "active":   sum(1 for c in campaigns if c.active),
            "closed":   sum(1 for c in campaigns if not c.active),
        }


# Module-level singleton
_manager = CampaignManager()

def get_manager() -> CampaignManager:
    return _manager


__all__ = [
    "Campaign", "CampaignManager", "get_manager",
    "CAMPAIGN_TEMPLATES", "create_from_template",
]
