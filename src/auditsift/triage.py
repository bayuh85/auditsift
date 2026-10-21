"""Ask one model what a candidate would let an attacker do, and how to fix it.

Triage sees the snippet and the rule. It does not see the verify verdict.
"""

from __future__ import annotations

import json

from auditsift.llm import LLMClient, LLMError, extract_json
from auditsift.models import Finding, PhaseUsage

SYSTEM = (
    "You are Auditsift's triage stage. You explain one static-analysis candidate. "
    "Reply with a single JSON object and no other text, using the keys "
    '"impact" and "fix". impact is two sentences on what an attacker could do '
    "if this code runs. fix is a concrete code change and names the safe API "
    "to use. Do not invent files that are not shown."
)

CODE_BEGIN = "-----8<-----"
CODE_END = "----->8-----"


def triage_findings(
    findings: list[Finding],
    client: LLMClient,
    model: str,
    max_calls: int,
) -> tuple[list[Finding], PhaseUsage, list[str]]:
    usage = PhaseUsage(phase="triage", model=model)
    notes: list[str] = []
    ordered = sorted(findings, key=lambda item: (-_rank(item.severity), item.path, item.start_line))
    limit = max(0, max_calls)
    skipped = 0
    for index, finding in enumerate(ordered):
        if index >= limit:
            skipped += 1
            continue
        user = _prompt(finding)
        try:
            completion = client.complete(model=model, system=SYSTEM, user=user)
        except LLMError as exc:
            notes.append(f"triage failed for {finding.id}: {exc}")
            continue
        usage.calls += 1
        usage.tokens_in += completion.tokens_in
        usage.tokens_out += completion.tokens_out
        _apply(finding, completion.text)
    if skipped:
        notes.append(f"triage skipped {skipped} candidates because the call budget was reached")
    return findings, usage, notes


def _prompt(finding: Finding) -> str:
    return (
        f"rule: {finding.rule_id}\n"
        f"severity: {finding.severity}\n"
        f"file: {finding.path}\n"
        f"line: {finding.start_line}\n"
        f"message: {finding.message}\n"
        f"code:\n{CODE_BEGIN}\n{finding.snippet}\n{CODE_END}\n"
    )


def _apply(finding: Finding, text: str) -> None:
    try:
        payload = extract_json(text)
    except json.JSONDecodeError:
        return
    impact = payload.get("impact")
    fix = payload.get("fix")
    if isinstance(impact, str) and impact.strip():
        finding.impact = impact.strip()
    if isinstance(fix, str) and fix.strip():
        finding.fix = fix.strip()


def _rank(severity: str) -> int:
    order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    return order.get(severity, 0)
