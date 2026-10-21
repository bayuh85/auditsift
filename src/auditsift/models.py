"""Records shared by the scanner, the model phases, and the report writers."""

from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass, field

SEVERITY_ORDER = ("info", "low", "medium", "high", "critical")
SEVERITY_RANK = {name: index for index, name in enumerate(SEVERITY_ORDER)}


def severity_at_least(severity: str, threshold: str) -> bool:
    return SEVERITY_RANK[severity] >= SEVERITY_RANK[threshold]


@dataclass
class Candidate:
    rule_id: str
    title: str
    severity: str
    path: str
    line: int
    end_line: int
    message: str
    snippet: str

    def finding_id(self) -> str:
        raw = f"{self.rule_id}:{self.path}:{self.line}"
        digest = hashlib.sha256(raw.encode()).hexdigest()[:10]
        return f"{self.rule_id}-{digest}"


@dataclass
class Finding:
    id: str
    rule_id: str
    title: str
    severity: str
    path: str
    start_line: int
    end_line: int
    message: str
    snippet: str
    impact: str | None = None
    fix: str | None = None
    evidence: str | None = None
    verdict: str = "unverified"
    reason: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_candidate(cls, candidate: Candidate, impact: str, fix: str) -> Finding:
        return cls(
            id=candidate.finding_id(),
            rule_id=candidate.rule_id,
            title=candidate.title,
            severity=candidate.severity,
            path=candidate.path,
            start_line=candidate.line,
            end_line=candidate.end_line,
            message=candidate.message,
            snippet=candidate.snippet,
            impact=impact,
            fix=fix,
        )

    @classmethod
    def from_dict(cls, data: dict) -> Finding:
        known = set(cls.__dataclass_fields__)
        return cls(**{key: value for key, value in data.items() if key in known})


@dataclass
class PhaseUsage:
    phase: str
    model: str | None
    tokens_in: int = 0
    tokens_out: int = 0
    calls: int = 0

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class AuditReport:
    target: str
    diff: str | None
    inventory: dict
    findings: list[Finding] = field(default_factory=list)
    rejected: list[Finding] = field(default_factory=list)
    usage: list[PhaseUsage] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    version: str = "0.1.0"

    def to_dict(self) -> dict:
        return {
            "tool": "auditsift",
            "version": self.version,
            "target": self.target,
            "diff": self.diff,
            "inventory": self.inventory,
            "findings": [item.to_dict() for item in self.findings],
            "rejected": [item.to_dict() for item in self.rejected],
            "usage": [item.to_dict() for item in self.usage],
            "notes": list(self.notes),
        }

    @classmethod
    def from_dict(cls, data: dict) -> AuditReport:
        return cls(
            target=data.get("target", ""),
            diff=data.get("diff"),
            inventory=data.get("inventory") or {},
            findings=[Finding.from_dict(item) for item in data.get("findings") or []],
            rejected=[Finding.from_dict(item) for item in data.get("rejected") or []],
            usage=[
                PhaseUsage(
                    phase=item.get("phase", ""),
                    model=item.get("model"),
                    tokens_in=int(item.get("tokens_in") or 0),
                    tokens_out=int(item.get("tokens_out") or 0),
                    calls=int(item.get("calls") or 0),
                )
                for item in data.get("usage") or []
            ],
            notes=list(data.get("notes") or []),
            version=data.get("version") or "0.1.0",
        )


def redact_secret(value: str) -> str:
    if len(value) <= 6:
        return "•••"
    return f"{value[:3]}…{value[-2:]}"


def is_placeholder(value: str) -> bool:
    """True when a literal is an obvious dummy rather than a live credential."""
    folded = value.strip().lower()
    if len(folded) < 8:
        return True
    if folded in {
        "changeme",
        "change-me",
        "password",
        "secret",
        "example",
        "placeholder",
        "your-key-here",
        "ar-your-key-here",
    }:
        return True
    markers = (
        "your-key",
        "your_key",
        "placeholder",
        "changeme",
        "example",
        "replace-me",
        "insert-",
        "todo",
    )
    if any(marker in folded for marker in markers):
        return True
    if folded.startswith("<") or folded.endswith(">"):
        return True
    if re.fullmatch(r"[x*#._-]+", folded):
        return True
    return False
