"""Run map, scan, and the optional model phases as one report."""

from __future__ import annotations

from pathlib import Path

from auditsift import __version__
from auditsift.config import Settings, load_settings
from auditsift.diffutil import diff_changed_lines, filter_candidates, find_git_root
from auditsift.errors import AuditError
from auditsift.inventory import build_inventory
from auditsift.llm import LLMClient
from auditsift.models import SEVERITY_RANK, AuditReport, Finding, PhaseUsage, severity_at_least
from auditsift.rules import CATALOG, redact_snippet
from auditsift.scanner import scan_target
from auditsift.triage import triage_findings
from auditsift.verify import verify_findings


def audit(
    target: str | Path,
    *,
    diff: str | None = None,
    settings: Settings | None = None,
    use_llm: bool = True,
    offline: bool = False,
    max_llm: int = 40,
    client: LLMClient | None = None,
) -> AuditReport:
    raw = Path(target)
    root = raw.resolve()
    anchor = root if root.is_dir() else root.parent
    if not root.exists():
        raise AuditError(f"path not found: {target}")
    settings = settings if settings is not None else load_settings()
    inventory, _files, git_root = build_inventory(raw)
    notes: list[str] = []
    changed = None
    if diff:
        git_root = git_root or find_git_root(anchor)
        if git_root is None:
            raise AuditError("--diff requires a git checkout")
        changed = diff_changed_lines(git_root, diff)
    scanned = scan_target(raw)
    before = len(scanned)
    candidates = filter_candidates(scanned, changed) if changed is not None else scanned
    if diff:
        notes.append(f"diff {diff}: {len(candidates)} candidates on changed lines ({before} before the filter)")
    findings = [_to_finding(item) for item in candidates]
    usage = [PhaseUsage("map", None), PhaseUsage("scan", None)]
    rejected: list[Finding] = []
    run_llm = use_llm and not offline and bool(settings.api_key)
    if run_llm:
        active = client or LLMClient(settings)
        _findings, triage_usage, triage_notes = triage_findings(findings, active, settings.triage_model, max_llm)
        findings = _findings
        usage.append(triage_usage)
        notes.extend(triage_notes)
        findings, rejected, verify_usage, verify_notes = verify_findings(
            findings, active, settings.verify_model, max_llm
        )
        usage.append(verify_usage)
        notes.extend(verify_notes)
    else:
        usage.append(PhaseUsage("triage", None))
        usage.append(PhaseUsage("verify", None))
        if not use_llm:
            notes.append("triage and verify did not run")
        elif offline:
            notes.append("triage and verify skipped (--offline)")
        else:
            notes.append("triage and verify skipped (no API key). Set ATMOROUTER_API_KEY to enable them.")
    findings = _sort(findings)
    return AuditReport(
        target=raw.as_posix(),
        diff=diff,
        inventory=inventory,
        findings=findings,
        rejected=rejected,
        usage=usage,
        notes=notes,
        version=__version__,
    )


def exit_code_for(findings: list[Finding], fail_on: str | None) -> int:
    if not fail_on:
        return 0
    if fail_on not in SEVERITY_RANK:
        raise AuditError(f"unknown severity: {fail_on}")
    for finding in findings:
        if severity_at_least(finding.severity, fail_on):
            return 1
    return 0


def _to_finding(candidate) -> Finding:
    info = CATALOG[candidate.rule_id]
    candidate.snippet = redact_snippet(candidate.rule_id, candidate.snippet)
    return Finding.from_candidate(candidate, info.impact, info.fix)


def _sort(findings: list[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda item: (
            -SEVERITY_RANK.get(item.severity, 0),
            item.path,
            item.start_line,
            item.rule_id,
        ),
    )
