"""Blast-radius scoring.

Authority violations say *what* was unauthorised. Blast radius says *how much
it would cost* if that action were malicious rather than merely out of policy.
The two are different questions and conflating them is why agent-security
dashboards are noisy: a read of a public page with an undeclared scope is a
policy bug, while an irreversible external write of credentials is an incident.

Copyright (c) 2026 kk (kkdev9715). All Rights Reserved. Proprietary — see LICENSE.
"""

from __future__ import annotations

from dataclasses import dataclass

from sentinel_trace.model import (
    AgentEvent,
    EventKind,
    Severity,
    data_class_sensitivity,
    scope_severity,
    severity_from_score,
)

#: Multiplier applied when an action is irreversible.
IRREVERSIBLE_MULTIPLIER = 1.35
#: Multiplier applied when an action reaches outside the trust boundary.
EXTERNAL_MULTIPLIER = 1.25
#: Multiplier applied when the action was influenced by untrusted content.
TAINTED_MULTIPLIER = 1.30
#: Volume at which the volume term saturates (log scale).
VOLUME_SATURATION = 10_000


@dataclass(slots=True)
class BlastRadius:
    """Scored impact of a single action."""

    span_id: str
    agent_id: str
    tool: str | None
    score: float
    severity: Severity
    factors: dict[str, float]
    rationale: str

    def to_dict(self) -> dict:
        return {
            "span_id": self.span_id,
            "agent_id": self.agent_id,
            "tool": self.tool,
            "score": round(self.score, 2),
            "severity": self.severity.value,
            "factors": {k: round(v, 3) for k, v in self.factors.items()},
            "rationale": self.rationale,
        }


def _volume_factor(volume: int) -> float:
    """Log-scaled volume term, 0-1, saturating at VOLUME_SATURATION."""
    import math

    if volume <= 1:
        return 0.0
    return min(1.0, math.log10(volume) / math.log10(VOLUME_SATURATION))


def score_action(event: AgentEvent, *, tainted: bool = False) -> BlastRadius:
    """Score the blast radius of one action, 0-100.

    The score is a weighted blend of four independent dimensions, so no single
    dimension can carry it: scope severity, data sensitivity, reach
    (external/irreversible), and volume.
    """
    scopes = event.scopes
    scope_term = max((scope_severity(s) for s in scopes), default=0.0)

    classes = event.data_classes
    data_term = max((data_class_sensitivity(d) for d in classes), default=0.0)

    reach_term = 0.0
    if event.external:
        reach_term += 0.6
    if not event.reversible:
        reach_term += 0.4
    reach_term = min(1.0, reach_term)

    volume_term = _volume_factor(event.volume)

    # Weights sum to 1.0. Scope and data dominate; reach and volume modulate.
    factors = {
        "scope": scope_term * 0.40,
        "data": data_term * 0.30,
        "reach": reach_term * 0.20,
        "volume": volume_term * 0.10,
    }
    base = sum(factors.values())

    multiplier = 1.0
    if not event.reversible:
        multiplier *= IRREVERSIBLE_MULTIPLIER
    if event.external:
        multiplier *= EXTERNAL_MULTIPLIER
    if tainted:
        multiplier *= TAINTED_MULTIPLIER

    score = min(100.0, base * multiplier * 100.0)

    bits = []
    if scopes:
        bits.append(f"scopes {', '.join(scopes)}")
    if classes:
        bits.append(f"data {', '.join(classes)}")
    if event.external:
        bits.append("reaches outside the trust boundary")
    if not event.reversible:
        bits.append("irreversible")
    if tainted:
        bits.append("influenced by untrusted content")
    if event.volume > 1:
        bits.append(f"volume {event.volume}")
    rationale = "; ".join(bits) if bits else "no elevated factors"

    return BlastRadius(
        span_id=event.span_id,
        agent_id=event.agent_id,
        tool=event.tool,
        score=score,
        severity=severity_from_score(score),
        factors=factors,
        rationale=rationale,
    )


def score_trace(
    events: list[AgentEvent],
    *,
    tainted_spans: frozenset[str] = frozenset(),
) -> list[BlastRadius]:
    """Score every actionable event, highest blast radius first."""
    actionable = [
        e
        for e in events
        if e.kind in (EventKind.TOOL_INVOKE, EventKind.MEMORY_WRITE, EventKind.AGENT_SPAWN)
    ]
    scored = [score_action(e, tainted=e.span_id in tainted_spans) for e in actionable]
    scored.sort(key=lambda b: b.score, reverse=True)
    return scored


def worst(radii: list[BlastRadius]) -> BlastRadius | None:
    """The single highest-blast-radius action, or None."""
    return radii[0] if radii else None
