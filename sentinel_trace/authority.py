"""Authority comparison: declared vs actual.

The central question of agent security is not "was there a prompt injection?"
— detection of that is unreliable — but "did the agent do something it was not
declared to be allowed to do?". That question is answerable from a trace plus a
manifest, and it does not depend on getting injection detection right.

Copyright (c) 2026 kk (kkdev9715). All Rights Reserved. Proprietary — see LICENSE.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from enum import Enum

from sentinel_trace.model import (
    AgentEvent,
    AuthorityManifest,
    EventKind,
    Trace,
    scope_severity,
)


class ViolationKind(str, Enum):
    """The ways an action can exceed declared authority."""

    UNDECLARED_TOOL = "undeclared_tool"
    UNDECLARED_SCOPE = "undeclared_scope"
    UNDECLARED_DATA_CLASS = "undeclared_data_class"
    MISSING_APPROVAL = "missing_approval"
    NO_MANIFEST = "no_manifest"
    BLAST_RADIUS_EXCEEDED = "blast_radius_exceeded"


#: How much each violation kind contributes to the authority-exceeded score.
VIOLATION_WEIGHT: dict[ViolationKind, float] = {
    ViolationKind.UNDECLARED_TOOL: 0.55,
    ViolationKind.UNDECLARED_SCOPE: 0.70,
    ViolationKind.UNDECLARED_DATA_CLASS: 0.60,
    ViolationKind.MISSING_APPROVAL: 0.75,
    # Acting with no declared authority at all is worse than using one
    # undeclared tool: nothing about the run can be verified. Calibrated up
    # from 0.50 after the corpus showed such a trace scoring "pass".
    ViolationKind.NO_MANIFEST: 0.85,
    ViolationKind.BLAST_RADIUS_EXCEEDED: 0.65,
}


@dataclass(slots=True)
class Violation:
    """One action that exceeded declared authority."""

    span_id: str
    agent_id: str
    kind: ViolationKind
    detail: str
    tool: str | None = None
    scopes: tuple[str, ...] = ()
    data_classes: tuple[str, ...] = ()
    weight: float = 0.0

    def to_dict(self) -> dict:
        return {
            "span_id": self.span_id,
            "agent_id": self.agent_id,
            "kind": self.kind.value,
            "detail": self.detail,
            "tool": self.tool,
            "scopes": list(self.scopes),
            "data_classes": list(self.data_classes),
            "weight": round(self.weight, 3),
        }


def _actionable(event: AgentEvent) -> bool:
    """Only events that *do* something can exceed authority."""
    return event.kind in (
        EventKind.TOOL_INVOKE,
        EventKind.MEMORY_WRITE,
        EventKind.AGENT_SPAWN,
    )


def check_event(
    event: AgentEvent,
    manifest: AuthorityManifest | None,
) -> list[Violation]:
    """Return every way ``event`` exceeds ``manifest`` (empty if compliant)."""
    if not _actionable(event):
        return []

    if manifest is None:
        return [
            Violation(
                span_id=event.span_id,
                agent_id=event.agent_id,
                kind=ViolationKind.NO_MANIFEST,
                detail=(
                    f"agent {event.agent_id!r} performed {event.kind.value} with no "
                    "declared authority manifest — nothing can be verified"
                ),
                tool=event.tool,
                weight=VIOLATION_WEIGHT[ViolationKind.NO_MANIFEST],
            )
        ]

    out: list[Violation] = []

    tool = event.tool
    if tool and not manifest.allows_tool(tool):
        out.append(
            Violation(
                span_id=event.span_id,
                agent_id=event.agent_id,
                kind=ViolationKind.UNDECLARED_TOOL,
                detail=f"tool {tool!r} is not in the declared tool set",
                tool=tool,
                weight=VIOLATION_WEIGHT[ViolationKind.UNDECLARED_TOOL],
            )
        )

    bad_scopes = tuple(s for s in event.scopes if not manifest.allows_scope(s))
    if bad_scopes:
        # Weight by the most dangerous undeclared scope, not the count: one
        # `money:transfer` matters more than five `read:public`.
        worst = max(scope_severity(s) for s in bad_scopes)
        out.append(
            Violation(
                span_id=event.span_id,
                agent_id=event.agent_id,
                kind=ViolationKind.UNDECLARED_SCOPE,
                detail=f"scope(s) not declared: {', '.join(bad_scopes)}",
                tool=tool,
                scopes=bad_scopes,
                weight=VIOLATION_WEIGHT[ViolationKind.UNDECLARED_SCOPE] * worst,
            )
        )

    bad_classes = tuple(
        d for d in event.data_classes if not manifest.allows_data_class(d)
    )
    if bad_classes:
        out.append(
            Violation(
                span_id=event.span_id,
                agent_id=event.agent_id,
                kind=ViolationKind.UNDECLARED_DATA_CLASS,
                detail=f"data class(es) not declared: {', '.join(bad_classes)}",
                tool=tool,
                data_classes=bad_classes,
                weight=VIOLATION_WEIGHT[ViolationKind.UNDECLARED_DATA_CLASS],
            )
        )

    if manifest.needs_approval(tool or "", event.scopes) and not event.approved:
        out.append(
            Violation(
                span_id=event.span_id,
                agent_id=event.agent_id,
                kind=ViolationKind.MISSING_APPROVAL,
                detail=(
                    f"action requires human approval but no approval.grant precedes it "
                    f"(tool={tool!r}, scopes={list(event.scopes)})"
                ),
                tool=tool,
                scopes=event.scopes,
                weight=VIOLATION_WEIGHT[ViolationKind.MISSING_APPROVAL],
            )
        )

    return out


def check_trace(trace: Trace) -> list[Violation]:
    """Check every actionable event in a trace against its agent's manifest."""
    out: list[Violation] = []
    for event in trace.ordered():
        manifest = trace.manifest_for(event.agent_id)
        out.extend(check_event(event, manifest))
    return out


def authority_score(violations: list[Violation]) -> float:
    """0-100 score for how far a trace exceeded declared authority.

    The worst violation dominates; additional violations add a *bounded* bonus.
    This is deliberate: a single catastrophic violation must never be diluted
    by being averaged against many trivial ones, which is the failure mode of
    a plain mean. The bonus saturates, so a hundred trivial violations cannot
    outrank one catastrophic violation by count alone.
    """
    if not violations:
        return 0.0
    weights = sorted((v.weight for v in violations), reverse=True)
    worst = weights[0]
    rest = sum(weights[1:])
    combined = worst + 0.30 * (1.0 - math.exp(-rest))
    return round(min(100.0, combined * 100.0), 2)
