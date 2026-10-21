"""Text, Markdown, JSON, and SARIF 2.1.0 renderers."""

from __future__ import annotations

import json

from auditsift.models import SEVERITY_RANK, AuditReport, Finding, PhaseUsage
from auditsift.rules import CATALOG

_SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}
_SARIF_SCORE = {
    "critical": "9.0",
    "high": "8.0",
    "medium": "5.0",
    "low": "3.0",
    "info": "1.0",
}


def render(report: AuditReport, fmt: str) -> str:
    if fmt == "json":
        return render_json(report)
    if fmt == "sarif":
        return render_sarif_text(report)
    if fmt == "md":
        return render_markdown(report)
    return render_text(report)


def render_json(report: AuditReport) -> str:
    return json.dumps(report.to_dict(), indent=2) + "\n"


def render_sarif_text(report: AuditReport) -> str:
    return json.dumps(render_sarif(report), indent=2) + "\n"


def render_sarif(report: AuditReport) -> dict:
    rules = []
    seen: set[str] = set()
    for finding in report.findings:
        if finding.rule_id in seen:
            continue
        seen.add(finding.rule_id)
        info = CATALOG.get(finding.rule_id)
        title = info.title if info else finding.title
        summary = info.summary if info else finding.message
        severity = info.severity if info else finding.severity
        rules.append(
            {
                "id": finding.rule_id,
                "shortDescription": {"text": title},
                "fullDescription": {"text": summary},
                "help": {"text": summary},
                "defaultConfiguration": {"level": _SARIF_LEVEL.get(severity, "warning")},
                "properties": {
                    "security-severity": _SARIF_SCORE.get(severity, "5.0"),
                    "tags": ["security"],
                },
            }
        )
    results = []
    for finding in _sorted(report.findings):
        results.append(
            {
                "ruleId": finding.rule_id,
                "level": _SARIF_LEVEL.get(finding.severity, "warning"),
                "message": {"text": _sarif_message(finding)},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding.path},
                            "region": {
                                "startLine": finding.start_line,
                                "endLine": max(finding.end_line, finding.start_line),
                                "startColumn": 1,
                            },
                        }
                    }
                ],
                "partialFingerprints": {"auditsift/finding": finding.id},
            }
        )
    return {
        "$schema": ("https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"),
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "auditsift",
                        "version": report.version,
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }


def render_text(report: AuditReport) -> str:
    lines = [f"auditsift  {report.target}"]
    if report.diff:
        lines.append(f"diff  {report.diff}")
    lines.append(f"{len(report.findings)} findings kept, {len(report.rejected)} rejected")
    lines.append("")
    if not report.findings:
        lines.append("No findings.")
    for finding in _sorted(report.findings):
        loc = f"{finding.path}:{finding.start_line}"
        lines.append(f"{finding.severity:<9}{finding.rule_id:<12}{loc}  {finding.message}")
        if finding.impact:
            lines.append(f"          impact: {finding.impact}")
        if finding.fix:
            lines.append(f"          fix: {finding.fix}")
        if finding.evidence:
            lines.append(f"          evidence: {finding.evidence}")
    lines.append("")
    lines.append(format_cost(report.usage))
    if report.notes:
        lines.append("")
        lines.append("notes")
        for note in report.notes:
            lines.append(f"  {note}")
    lines.append("")
    return "\n".join(lines)


def render_markdown(report: AuditReport) -> str:
    lines = [
        "# auditsift report",
        "",
        f"Target: `{report.target}`",
        "",
        f"Diff: `{report.diff}`" if report.diff else "Diff: full tree",
        "",
        f"Findings kept: **{len(report.findings)}**. Rejected: **{len(report.rejected)}**.",
        "",
    ]
    if not report.findings:
        lines.append("No findings.")
        lines.append("")
    current = None
    for finding in _sorted(report.findings):
        if finding.severity != current:
            current = finding.severity
            lines.append(f"## {current}")
            lines.append("")
        lines.append(f"### {finding.rule_id} `{finding.path}:{finding.start_line}`")
        lines.append("")
        lines.append(finding.message)
        lines.append("")
        if finding.impact:
            lines.append(f"Impact: {finding.impact}")
            lines.append("")
        if finding.fix:
            lines.append(f"Fix: {finding.fix}")
            lines.append("")
        if finding.evidence:
            lines.append(f"Evidence: `{finding.evidence}`")
            lines.append("")
        lines.append("```")
        lines.append(finding.snippet)
        lines.append("```")
        lines.append("")
    if report.rejected:
        lines.append("## Rejected")
        lines.append("")
        for finding in report.rejected:
            reason = finding.reason or "rejected"
            lines.append(f"- {finding.rule_id} `{finding.path}:{finding.start_line}` — {reason}")
        lines.append("")
    lines.append("## Cost")
    lines.append("")
    lines.append("| phase | model | tokens in | tokens out | calls |")
    lines.append("| --- | --- | ---: | ---: | ---: |")
    for row in report.usage:
        lines.append(f"| {row.phase} | {row.model or 'local'} | {row.tokens_in} | {row.tokens_out} | {row.calls} |")
    lines.append("")
    if report.notes:
        lines.append("## Notes")
        lines.append("")
        for note in report.notes:
            lines.append(f"- {note}")
        lines.append("")
    return "\n".join(lines)


def format_cost(usage: list[PhaseUsage]) -> str:
    lines = ["cost estimate"]
    for row in usage:
        model = row.model or "local"
        lines.append(f"  {row.phase:<8} {model:<24} {row.tokens_in:6} in / {row.tokens_out:6} out  ({row.calls} calls)")
    return "\n".join(lines)


def write_bundle(report: AuditReport, directory) -> None:
    from pathlib import Path

    dest = Path(directory)
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "auditsift.json").write_text(render_json(report), encoding="utf-8")
    (dest / "auditsift.sarif").write_text(render_sarif_text(report), encoding="utf-8")
    (dest / "auditsift.md").write_text(render_markdown(report), encoding="utf-8")


def _sorted(findings: list[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda item: (
            -SEVERITY_RANK.get(item.severity, 0),
            item.path,
            item.start_line,
            item.rule_id,
        ),
    )


def _sarif_message(finding: Finding) -> str:
    parts = [finding.message]
    if finding.impact:
        parts.append("Impact: " + finding.impact)
    if finding.fix:
        parts.append("Fix: " + finding.fix)
    return " ".join(parts)
