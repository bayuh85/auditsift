"""Second pass. The model must quote the code, and the quote has to be real.

Verify does not receive the triage write-up. A confirm whose evidence is not
a substring of the snippet is recorded as a rejection.
"""

from __future__ import annotations

import json

from auditsift.llm import LLMClient, LLMError, extract_json
from auditsift.models import Finding, PhaseUsage
from auditsift.triage import CODE_BEGIN, CODE_END

SYSTEM = (
    "You are Auditsift's verify stage. You did not see any earlier explanation. "
    "Decide whether the candidate is a real vulnerability in the code shown. "
    "Reply with one JSON object and no other text: "
    '{"verdict":"confirm" or "reject","evidence":"<exact characters copied from the code block>",'
    '"reason":"<one sentence>"}. '
    "Reject documentation, parameterized queries, and constants. "
    "evidence MUST be copied verbatim from the code block. "
    "If you cannot quote the vulnerable syntax, reject."
)

MIN_EVIDENCE = 6


def verify_findings(
    findings: list[Finding],
    client: LLMClient,
    model: str,
    max_calls: int,
) -> tuple[list[Finding], list[Finding], PhaseUsage, list[str]]:
    usage = PhaseUsage(phase="verify", model=model)
    notes: list[str] = []
    ordered = sorted(findings, key=lambda item: (-_rank(item.severity), item.path, item.start_line))
    limit = max(0, max_calls)
    kept: list[Finding] = []
    rejected: list[Finding] = []
    for index, finding in enumerate(ordered):
        if index >= limit:
            finding.verdict = "unverified"
            finding.reason = "not sent because the call budget was reached"
            kept.append(finding)
            continue
        user = _prompt(finding)
        try:
            completion = client.complete(model=model, system=SYSTEM, user=user)
        except LLMError as exc:
            finding.verdict = "unverified"
            finding.reason = f"verify call failed: {exc}"
            kept.append(finding)
            notes.append(f"verify failed for {finding.id}: {exc}")
            continue
        usage.calls += 1
        usage.tokens_in += completion.tokens_in
        usage.tokens_out += completion.tokens_out
        verdict, evidence, reason = _parse(completion.text)
        if verdict == "confirm" and evidence_in_snippet(evidence, finding.snippet):
            finding.verdict = "confirmed"
            finding.evidence = evidence
            finding.reason = reason
            kept.append(finding)
            continue
        finding.verdict = "rejected"
        finding.evidence = evidence or None
        if verdict == "confirm":
            finding.reason = "evidence quote was not present in the code"
        else:
            finding.reason = reason or "rejected"
        rejected.append(finding)
    notes.append(f"verify kept {len(kept)}, rejected {len(rejected)}")
    return kept, rejected, usage, notes


def evidence_in_snippet(evidence: str | None, snippet: str) -> bool:
    if not evidence:
        return False
    quote = evidence.strip()
    if quote.startswith("`") and quote.endswith("`") and len(quote) >= 2:
        quote = quote[1:-1]
    if len(quote.strip()) < MIN_EVIDENCE:
        return False
    return quote in snippet or quote.strip() in snippet


def _prompt(finding: Finding) -> str:
    return (
        f"rule: {finding.rule_id}\n"
        f"severity: {finding.severity}\n"
        f"file: {finding.path}\n"
        f"line: {finding.start_line}\n"
        f"scanner message: {finding.message}\n"
        f"code:\n{CODE_BEGIN}\n{finding.snippet}\n{CODE_END}\n"
    )


def _parse(text: str) -> tuple[str, str, str]:
    try:
        payload = extract_json(text)
    except json.JSONDecodeError:
        return "reject", "", "verify response was not JSON"
    verdict = str(payload.get("verdict") or "").strip().lower()
    if verdict in {"confirm", "confirmed"}:
        verdict = "confirm"
    elif verdict in {"reject", "rejected"}:
        verdict = "reject"
    else:
        verdict = "reject"
    evidence = payload.get("evidence")
    reason = payload.get("reason")
    return (
        verdict,
        evidence.strip() if isinstance(evidence, str) else "",
        reason.strip() if isinstance(reason, str) else "",
    )


def _rank(severity: str) -> int:
    order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    return order.get(severity, 0)
