"""
c2/zeroday/reporting/reporter.py
AEGIS-SILENTIUM v12 — Zero-Day Reporting Engine

Generates professional vulnerability reports in multiple formats:
  • JSON  — structured machine-readable output for integrations
  • Markdown — operator-readable report with CVSS scores and PoC steps
  • HTML  — fully rendered standalone report with severity colour coding
  • CSV   — spreadsheet-friendly finding summary

All formats include: finding metadata, crash analysis, exploit info,
recommended mitigations, CVSS v3 breakdown, and timeline.
"""
from __future__ import annotations

import csv
import html
import io
import json
import time
from typing import Any, Dict, List, Optional

from zeroday.models import Crash, Finding, FuzzCampaign, Severity, VulnClass


# ── Severity styling ──────────────────────────────────────────────────────────

_SEVERITY_COLOURS = {
    Severity.CRITICAL: "#dc2626",
    Severity.HIGH:     "#ea580c",
    Severity.MEDIUM:   "#ca8a04",
    Severity.LOW:      "#16a34a",
    Severity.INFO:     "#2563eb",
}

_SEVERITY_EMOJI = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH:     "🟠",
    Severity.MEDIUM:   "🟡",
    Severity.LOW:      "🟢",
    Severity.INFO:     "🔵",
}

# CVSS v3.1 attack vector descriptions
_VULN_MITIGATIONS: Dict[VulnClass, List[str]] = {
    VulnClass.BUFFER_OVERFLOW:  [
        "Replace unsafe string functions with bounded equivalents (strncpy, snprintf)",
        "Enable stack canaries (-fstack-protector-strong)",
        "Enable Address Space Layout Randomisation (ASLR)",
        "Enable NX/DEP on all memory regions",
        "Use safe integer arithmetic libraries",
    ],
    VulnClass.HEAP_OVERFLOW: [
        "Validate all length parameters before heap allocation",
        "Use safe allocator wrappers with guard pages",
        "Enable heap address randomisation",
        "Compile with -fsanitize=address during testing",
        "Review all malloc/realloc call sites for integer overflow",
    ],
    VulnClass.USE_AFTER_FREE: [
        "Zero or poison freed pointers immediately after free()",
        "Use smart pointer patterns (e.g., unique_ptr in C++)",
        "Enable temporal memory safety (MiraclePtr / PartitionAlloc)",
        "Run with ASAN/HWASAN in staging environments",
        "Audit all callback/event handler lifetimes",
    ],
    VulnClass.FORMAT_STRING: [
        "Never pass user-controlled data as the format string argument",
        "Use printf(\"%s\", user_data) not printf(user_data)",
        "Enable -Wformat-security compiler warning",
        "Apply static analysis tools (Coverity, CodeQL) to catch pattern",
    ],
    VulnClass.INJECTION: [
        "Use parameterised queries / prepared statements for SQL",
        "Validate and sanitise all user input before use in commands",
        "Apply allowlist input validation (not denylist)",
        "Run processes with minimal privilege (least privilege principle)",
        "Use execve() with array arguments rather than system()",
    ],
    VulnClass.INTEGER_OVERFLOW: [
        "Use safe integer arithmetic with overflow detection",
        "Validate all arithmetic results before using as sizes/indices",
        "Use compiler flags -ftrapv or -fsanitize=integer",
        "Consider using size_t / ptrdiff_t for memory arithmetic",
    ],
    VulnClass.DOUBLE_FREE: [
        "Set pointer to NULL immediately after free()",
        "Use reference counting or ownership tracking",
        "Enable ASAN/Valgrind in testing pipeline",
    ],
    VulnClass.RACE_CONDITION: [
        "Use proper mutex/lock protection for shared resources",
        "Prefer lock-free data structures where appropriate",
        "Enable ThreadSanitizer (TSAN) in CI pipeline",
        "Apply TOCTOU-safe system calls (O_CREAT|O_EXCL for files)",
    ],
    VulnClass.PATH_TRAVERSAL: [
        "Canonicalise and validate all file paths before use",
        "Use realpath() and verify the result is within allowed prefix",
        "Apply chroot/seccomp/namespaces to limit filesystem access",
    ],
}

_DEFAULT_MITIGATIONS = [
    "Apply the principle of least privilege",
    "Enable all available compiler security flags",
    "Implement comprehensive input validation",
    "Deploy with modern exploit mitigations enabled",
]


def _mitigations_for(vuln_class: VulnClass) -> List[str]:
    return _VULN_MITIGATIONS.get(vuln_class, _DEFAULT_MITIGATIONS)


class VulnerabilityReporter:
    """
    Generates professional vulnerability reports from AEGIS zero-day findings.
    """

    def generate_json(
        self,
        findings:  List[Finding],
        crashes:   List[Crash],
        campaigns: List[FuzzCampaign],
        target_name: str = "",
    ) -> str:
        """Full JSON report."""
        report = {
            "report_version":  "1.0",
            "generated_at":    time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "target":          target_name,
            "summary": {
                "total_findings":  len(findings),
                "critical":        sum(1 for f in findings if f.severity == Severity.CRITICAL),
                "high":            sum(1 for f in findings if f.severity == Severity.HIGH),
                "medium":          sum(1 for f in findings if f.severity == Severity.MEDIUM),
                "low":             sum(1 for f in findings if f.severity == Severity.LOW),
                "total_crashes":   len(crashes),
                "unique_crashes":  sum(1 for c in crashes if c.is_unique),
                "exploitable":     sum(1 for c in crashes if c.is_exploitable),
                "campaign_count":  len(campaigns),
                "total_execs":     sum(c.total_execs for c in campaigns),
            },
            "findings": [
                {
                    **f.to_dict(),
                    "mitigations": _mitigations_for(f.vuln_class),
                    "cvss_score":  f.cvss_score or _VULN_CVSS_DEFAULT.get(f.vuln_class, 7.5),
                }
                for f in sorted(findings, key=lambda x: -(x.cvss_score or 0))
            ],
            "crashes": [c.to_dict() for c in crashes if c.is_unique],
            "campaigns": [c.to_dict() for c in campaigns],
        }
        return json.dumps(report, indent=2, default=str)

    def generate_markdown(
        self,
        findings:  List[Finding],
        crashes:   List[Crash],
        campaigns: List[FuzzCampaign],
        target_name: str = "Target",
    ) -> str:
        """Generate a Markdown vulnerability report."""
        lines = [
            f"# Vulnerability Research Report: {target_name}",
            f"",
            f"**Generated:** {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime())}  ",
            f"**Tool:** AEGIS-SILENTIUM v12 Zero-Day Discovery Pipeline  ",
            f"",
            f"---",
            f"",
            f"## Executive Summary",
            f"",
        ]

        crit = sum(1 for f in findings if f.severity == Severity.CRITICAL)
        high = sum(1 for f in findings if f.severity == Severity.HIGH)
        med  = sum(1 for f in findings if f.severity == Severity.MEDIUM)
        low  = sum(1 for f in findings if f.severity == Severity.LOW)

        lines += [
            f"| Severity | Count |",
            f"|----------|-------|",
            f"| 🔴 Critical | {crit} |",
            f"| 🟠 High     | {high} |",
            f"| 🟡 Medium   | {med} |",
            f"| 🟢 Low      | {low} |",
            f"| **Total**   | **{len(findings)}** |",
            f"",
            f"### Fuzzing Statistics",
            f"",
        ]

        total_execs = sum(c.total_execs for c in campaigns)
        unique_cr   = sum(1 for c in crashes if c.is_unique)
        exploitable = sum(1 for c in crashes if c.is_exploitable)
        total_cov   = sum(c.coverage_edges for c in campaigns)

        lines += [
            f"- **Campaigns run:** {len(campaigns)}",
            f"- **Total executions:** {total_execs:,}",
            f"- **Unique crashes:** {unique_cr}",
            f"- **Exploitable crashes:** {exploitable}",
            f"- **Coverage edges:** {total_cov:,}",
            f"",
            f"---",
            f"",
            f"## Findings",
            f"",
        ]

        for i, finding in enumerate(
            sorted(findings, key=lambda x: -(x.cvss_score or 0)), 1
        ):
            sev_emoji = _SEVERITY_EMOJI.get(finding.severity, "⚪")
            cvss = finding.cvss_score or _VULN_CVSS_DEFAULT.get(finding.vuln_class, 7.5)
            lines += [
                f"### {i}. {sev_emoji} {finding.title}",
                f"",
                f"| Field | Value |",
                f"|-------|-------|",
                f"| **Finding ID** | `{finding.finding_id[:16]}...` |",
                f"| **Severity** | {finding.severity.value.upper()} |",
                f"| **CVSS v3.1** | {cvss:.1f} |",
                f"| **Vuln Class** | {finding.vuln_class.value.replace('_', ' ').title()} |",
                f"| **Exploitability** | {finding.exploitability.value.title()} |",
                f"| **Analyst** | {finding.analyst} |",
                f"| **Confirmed** | {time.strftime('%Y-%m-%d', time.gmtime(finding.confirmed_at)) if finding.confirmed_at else 'Pending'} |",
                f"",
                f"**Description:**  ",
                f"{finding.description}",
                f"",
            ]
            if finding.affected_component:
                lines += [f"**Affected Component:** `{finding.affected_component}`", f""]
            if finding.proof_of_concept:
                lines += [
                    f"**Proof of Concept:**",
                    f"```",
                    finding.proof_of_concept[:300],
                    f"```",
                    f"",
                ]
            mitigations = _mitigations_for(finding.vuln_class)
            lines += [f"**Recommended Mitigations:**", f""]
            for m in mitigations:
                lines.append(f"- {m}")
            lines += [f"", f"---", f""]

        # Crash appendix
        unique_crashes = [c for c in crashes if c.is_unique]
        if unique_crashes:
            lines += [f"## Appendix A — Unique Crashes", f""]
            lines += [
                f"| Hash | Signal | Vuln Class | Exploitable | Input Size |",
                f"|------|--------|------------|-------------|------------|",
            ]
            for c in unique_crashes[:30]:
                lines.append(
                    f"| `{c.crash_hash}` | {c.signal or 'n/a'} | "
                    f"{c.vuln_class.value} | {'✓' if c.is_exploitable else '✗'} | "
                    f"{len(c.input_data)} bytes |"
                )
            lines.append(f"")

        return "\n".join(lines)

    def generate_html(
        self,
        findings:  List[Finding],
        crashes:   List[Crash],
        campaigns: List[FuzzCampaign],
        target_name: str = "Target",
    ) -> str:
        """Generate a standalone HTML report."""
        md = self.generate_markdown(findings, crashes, campaigns, target_name)
        # Simple markdown → HTML conversion
        body = self._md_to_html(md)
        colour_legend = "".join(
            f'<span style="color:{c};font-weight:bold">{s.value.upper()}</span>&nbsp; '
            for s, c in _SEVERITY_COLOURS.items()
        )
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Vulnerability Report — {html.escape(target_name)}</title>
  <style>
    body {{ font-family: -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
            max-width: 1000px; margin: 40px auto; padding: 0 20px;
            background: #0f172a; color: #e2e8f0; }}
    h1   {{ color: #f8fafc; border-bottom: 2px solid #334155; padding-bottom: 10px; }}
    h2   {{ color: #94a3b8; margin-top: 30px; }}
    h3   {{ color: #e2e8f0; }}
    table{{ border-collapse: collapse; width: 100%; margin: 16px 0; }}
    th,td{{ border: 1px solid #334155; padding: 8px 12px; text-align: left; }}
    th   {{ background: #1e293b; color: #94a3b8; }}
    tr:hover {{ background: #1e293b; }}
    code, pre {{ background: #1e293b; padding: 3px 7px; border-radius: 4px;
                  font-family: 'JetBrains Mono',monospace; font-size: 0.85em; }}
    pre  {{ padding: 12px; overflow-x: auto; }}
    hr   {{ border: 0; border-top: 1px solid #334155; }}
    .critical {{ color: {_SEVERITY_COLOURS[Severity.CRITICAL]}; font-weight: bold; }}
    .high     {{ color: {_SEVERITY_COLOURS[Severity.HIGH]}; font-weight: bold; }}
    .medium   {{ color: {_SEVERITY_COLOURS[Severity.MEDIUM]}; font-weight: bold; }}
    .low      {{ color: {_SEVERITY_COLOURS[Severity.LOW]}; font-weight: bold; }}
    .banner   {{ background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
                  border: 1px solid #334155; border-radius: 8px;
                  padding: 16px 24px; margin-bottom: 24px; }}
  </style>
</head>
<body>
  <div class="banner">
    <strong>AEGIS-SILENTIUM v12</strong> — Zero-Day Discovery Report &nbsp;|&nbsp;
    {colour_legend}
  </div>
  {body}
</body>
</html>"""

    def generate_csv(
        self,
        findings: List[Finding],
    ) -> str:
        """Generate a CSV summary of findings."""
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=[
            "finding_id", "title", "severity", "cvss_score",
            "vuln_class", "exploitability", "affected_component",
            "analyst", "confirmed_at", "cve_id",
        ], extrasaction="ignore")
        writer.writeheader()
        for f in sorted(findings, key=lambda x: -(x.cvss_score or 0)):
            row = f.to_dict()
            row["confirmed_at"] = (
                time.strftime("%Y-%m-%d", time.gmtime(f.confirmed_at))
                if f.confirmed_at else ""
            )
            writer.writerow(row)
        return buf.getvalue()

    @staticmethod
    def _md_to_html(md: str) -> str:
        """Minimal markdown → HTML converter (handles headers, tables, code, bold)."""
        import re
        lines  = md.split("\n")
        output = []
        in_table = False
        in_code  = False
        code_buf = []

        for line in lines:
            # Code blocks
            if line.startswith("```"):
                if in_code:
                    output.append("<pre><code>" + html.escape("\n".join(code_buf)) + "</code></pre>")
                    code_buf = []; in_code = False
                else:
                    in_code = True
                continue
            if in_code:
                code_buf.append(line); continue

            # Headers
            h_match = re.match(r"^(#{1,4})\s+(.+)", line)
            if h_match:
                level = len(h_match.group(1))
                text  = html.escape(h_match.group(2))
                output.append(f"<h{level}>{text}</h{level}>")
                continue

            # Horizontal rule
            if re.match(r"^-{3,}$", line.strip()):
                output.append("<hr>"); continue

            # Table rows
            if "|" in line and line.strip().startswith("|"):
                cells = [c.strip() for c in line.strip().strip("|").split("|")]
                if all(re.match(r"^[-:]+$", c) for c in cells if c):
                    continue  # separator row
                if not in_table:
                    output.append("<table>"); in_table = True
                tag = "th" if not in_table else "td"
                row = "".join(
                    f"<{tag}>{html.escape(c)}</{tag}>" for c in cells
                )
                output.append(f"<tr>{row}</tr>")
                continue
            else:
                if in_table:
                    output.append("</table>"); in_table = False

            # Inline code
            line = re.sub(r"`([^`]+)`", r"<code>\1</code>", html.escape(line))
            # Bold
            line = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", line)
            # List items
            if re.match(r"^[\-\*] ", line):
                line = "<li>" + line[2:] + "</li>"
            elif line.strip():
                line = f"<p>{line}</p>"
            output.append(line)

        if in_table:
            output.append("</table>")
        return "\n".join(output)


# Default CVSS scores (used when finding has no explicit score)
_VULN_CVSS_DEFAULT: Dict[VulnClass, float] = {
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


__all__ = ["VulnerabilityReporter"]
