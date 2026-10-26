"""Adversarial corpus and CI regression harness.

The gap this closes: there is no CI for agent safety. A prompt edit or a tool
scope widening can silently grant an agent authority it never had, and nothing
fails the build. This module runs a corpus of labelled traces — each with an
expected verdict — and reports regressions.

A corpus entry is a trace plus the verdict it *should* produce. If a change to
an agent's manifest or prompt makes a previously-safe trace unsafe, the corpus
catches it before it ships.

Copyright (c) 2026 kk (kkdev9715). All Rights Reserved. Proprietary — see LICENSE.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from sentinel_trace.model import SchemaError, Trace
from sentinel_trace.replay import Assessment, replay
from sentinel_trace.schema import parse_trace

#: Verdict ordering, for "at least as bad as" comparisons. "any" means the
#: case asserts only that the trace runs without error (a smoke case).
_VERDICT_RANK = {"any": -1, "pass": 0, "warn": 1, "fail": 2}


@dataclass(slots=True)
class CorpusCase:
    """One labelled trace in the corpus."""

    name: str
    trace: Trace
    expected_verdict: str
    expected_min_risk: float = 0.0
    expected_max_risk: float = 100.0
    must_flag: tuple[str, ...] = ()  # violation kinds that must be present
    description: str = ""

    def __post_init__(self) -> None:
        if self.expected_verdict not in _VERDICT_RANK:
            raise SchemaError(
                f"case {self.name!r}: expected_verdict must be one of "
                f"{sorted(_VERDICT_RANK)}, got {self.expected_verdict!r}"
            )


@dataclass(slots=True)
class CaseResult:
    """Outcome of running one corpus case."""

    name: str
    passed: bool
    expected_verdict: str
    actual_verdict: str
    risk_score: float
    failures: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "passed": self.passed,
            "expected_verdict": self.expected_verdict,
            "actual_verdict": self.actual_verdict,
            "risk_score": self.risk_score,
            "failures": self.failures,
        }


@dataclass(slots=True)
class CorpusReport:
    """Aggregate result of a corpus run."""

    results: list[CaseResult]

    @property
    def total(self) -> int:
        return len(self.results)

    @property
    def passed(self) -> int:
        return sum(1 for r in self.results if r.passed)

    @property
    def failed(self) -> int:
        return self.total - self.passed

    @property
    def ok(self) -> bool:
        return self.failed == 0

    def to_dict(self) -> dict:
        return {
            "total": self.total,
            "passed": self.passed,
            "failed": self.failed,
            "ok": self.ok,
            "results": [r.to_dict() for r in self.results],
        }


def run_case(case: CorpusCase) -> CaseResult:
    """Run one corpus case and compare against its expectations."""
    assessment: Assessment = replay(case.trace)
    failures: list[str] = []

    if assessment.verdict != case.expected_verdict and case.expected_verdict != "any":
        failures.append(
            f"verdict {assessment.verdict!r} != expected {case.expected_verdict!r}"
        )
    if assessment.risk_score < case.expected_min_risk:
        failures.append(
            f"risk {assessment.risk_score} below expected minimum {case.expected_min_risk}"
        )
    if assessment.risk_score > case.expected_max_risk:
        failures.append(
            f"risk {assessment.risk_score} above expected maximum {case.expected_max_risk}"
        )

    present = {v.kind.value for v in assessment.violations}
    for kind in case.must_flag:
        if kind not in present:
            failures.append(f"expected violation {kind!r} was not flagged")

    return CaseResult(
        name=case.name,
        passed=not failures,
        expected_verdict=case.expected_verdict,
        actual_verdict=assessment.verdict,
        risk_score=assessment.risk_score,
        failures=failures,
    )


def run_corpus(cases: list[CorpusCase]) -> CorpusReport:
    """Run every case; a corpus with no cases is a failure, not a pass."""
    if not cases:
        raise SchemaError("corpus is empty — an empty corpus cannot gate a build")
    return CorpusReport(results=[run_case(c) for c in cases])


def load_corpus(directory: str | Path) -> list[CorpusCase]:
    """Load every ``*.json`` case from a directory.

    Each file is either a bare trace (expected verdict defaults to ``fail``
    only if it has violations, else ``pass``) or an object with a ``trace`` key
    plus expectations.
    """
    d = Path(directory)
    if not d.exists():
        raise SchemaError(f"no such corpus directory: {d}")
    cases: list[CorpusCase] = []
    for path in sorted(d.glob("*.json")):
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise SchemaError(f"{path.name}: invalid JSON at line {exc.lineno}") from exc

        if "trace" in doc and isinstance(doc["trace"], dict):
            trace = parse_trace(doc["trace"])
            expected = doc.get("expected_verdict")
            if expected is None:
                expected = "fail" if doc.get("expect_violations") else "pass"
            cases.append(
                CorpusCase(
                    name=doc.get("name", path.stem),
                    trace=trace,
                    expected_verdict=expected,
                    expected_min_risk=float(doc.get("expected_min_risk", 0.0)),
                    expected_max_risk=float(doc.get("expected_max_risk", 100.0)),
                    must_flag=tuple(doc.get("must_flag", ())),
                    description=doc.get("description", ""),
                )
            )
        else:
            # A bare trace file is a smoke case: it must run without error, but
            # no verdict is asserted. Labelling it "pass" would be a lie for a
            # malicious trace, and labelling it "fail" would be a lie for a
            # benign one — so we assert neither.
            trace = parse_trace(doc)
            cases.append(
                CorpusCase(
                    name=path.stem,
                    trace=trace,
                    expected_verdict="any",
                )
            )
    return cases
