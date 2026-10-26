"""Core domain model for agent execution security.

Sentinel Trace models an agent run as a trace of typed events, and an agent's
*declared* authority as a manifest. Security questions are then answered by
comparing the two: what did the agent actually do, and was it authorised to?

The event model is deliberately OpenTelemetry-shaped (span ids, parent links,
nanosecond timestamps, attribute bags) so that traces emitted by existing
collectors can be consumed without a bespoke exporter.

Copyright (c) 2026 kk (kkdev9715). All Rights Reserved. Proprietary — see LICENSE.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum

_ID_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
_SCOPE_RE = re.compile(r"^[a-z][a-z0-9_-]*:[a-z0-9_.*-]+$")


class SchemaError(ValueError):
    """Raised when a trace or manifest is structurally invalid."""


class EventKind(str, Enum):
    """The event vocabulary. Deliberately small and closed."""

    CONTENT_INGEST = "content.ingest"
    LLM_CALL = "llm.call"
    TOOL_INVOKE = "tool.invoke"
    MEMORY_READ = "memory.read"
    MEMORY_WRITE = "memory.write"
    AGENT_SPAWN = "agent.spawn"
    APPROVAL_REQUEST = "approval.request"
    APPROVAL_GRANT = "approval.grant"


class Trust(str, Enum):
    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# --------------------------------------------------------------------------
# Scope and data-class severity
# --------------------------------------------------------------------------

#: Base severity (0-1) of a capability scope. Unknown scopes fall back to a
#: prefix rule, then to a conservative default — an unrecognised scope is
#: treated as more dangerous than a known-benign one, never less.
SCOPE_SEVERITY: dict[str, float] = {
    "read:public": 0.10,
    "read:internal": 0.30,
    "read:confidential": 0.60,
    "read:secret": 0.90,
    "write:internal": 0.40,
    "write:external": 0.70,
    "write:production": 0.90,
    "exec:code": 0.80,
    "exec:shell": 0.90,
    "net:egress": 0.60,
    "money:transfer": 1.00,
    "identity:grant": 0.95,
    "delete:data": 0.90,
}

_SCOPE_PREFIX_SEVERITY: dict[str, float] = {
    "read": 0.40,
    "write": 0.60,
    "exec": 0.85,
    "net": 0.55,
    "money": 0.95,
    "identity": 0.90,
    "delete": 0.90,
}

#: Sensitivity (0-1) of a data class.
DATA_CLASS_SENSITIVITY: dict[str, float] = {
    "public": 0.05,
    "internal": 0.30,
    "confidential": 0.60,
    "pii": 0.80,
    "phi": 0.90,
    "secret": 0.95,
    "credentials": 1.00,
    "financial": 0.85,
}


def scope_severity(scope: str) -> float:
    """Severity of a capability scope, 0-1.

    Exact match first, then the namespace prefix, then a conservative default.
    """
    if scope in SCOPE_SEVERITY:
        return SCOPE_SEVERITY[scope]
    prefix = scope.split(":", 1)[0]
    if prefix in _SCOPE_PREFIX_SEVERITY:
        return _SCOPE_PREFIX_SEVERITY[prefix]
    return 0.50


def data_class_sensitivity(data_class: str) -> float:
    """Sensitivity of a data class, 0-1. Unknown classes default to 0.5."""
    return DATA_CLASS_SENSITIVITY.get(data_class, 0.50)


def severity_from_score(score: float) -> Severity:
    """Map a 0-100 score onto a severity band."""
    if score >= 80:
        return Severity.CRITICAL
    if score >= 60:
        return Severity.HIGH
    if score >= 35:
        return Severity.MEDIUM
    return Severity.LOW


# --------------------------------------------------------------------------
# Events
# --------------------------------------------------------------------------


@dataclass(slots=True)
class AgentEvent:
    """One span in an agent trace.

    ``consumes`` / ``produces`` are value identifiers. They are what make taint
    analysis possible: an event that consumes a value produced by an untrusted
    ingest is itself influenced by untrusted content, transitively.
    """

    span_id: str
    name: str
    kind: EventKind
    agent_id: str
    parent_span_id: str | None = None
    trace_id: str = ""
    start_time: float = 0.0
    end_time: float = 0.0
    attributes: dict = field(default_factory=dict)
    consumes: tuple[str, ...] = ()
    produces: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not _ID_RE.match(self.span_id):
            raise SchemaError(f"invalid span_id: {self.span_id!r}")
        if not _ID_RE.match(self.agent_id):
            raise SchemaError(f"invalid agent_id: {self.agent_id!r}")
        if self.parent_span_id is not None and not _ID_RE.match(self.parent_span_id):
            raise SchemaError(f"invalid parent_span_id: {self.parent_span_id!r}")
        if self.end_time and self.start_time and self.end_time < self.start_time:
            raise SchemaError(f"span {self.span_id}: end_time precedes start_time")

    # -- convenience accessors -------------------------------------------
    @property
    def tool(self) -> str | None:
        return self.attributes.get("tool")

    @property
    def scopes(self) -> tuple[str, ...]:
        return tuple(self.attributes.get("scopes", ()))

    @property
    def data_classes(self) -> tuple[str, ...]:
        return tuple(self.attributes.get("data_classes", ()))

    @property
    def approved(self) -> bool:
        return bool(self.attributes.get("approved", False))

    @property
    def external(self) -> bool:
        return bool(self.attributes.get("external", False))

    @property
    def reversible(self) -> bool:
        return bool(self.attributes.get("reversible", True))

    @property
    def volume(self) -> int:
        try:
            return max(1, int(self.attributes.get("volume", 1)))
        except (TypeError, ValueError):
            return 1

    @property
    def trust(self) -> Trust:
        raw = self.attributes.get("trust", Trust.TRUSTED.value)
        try:
            return Trust(raw)
        except ValueError:
            return Trust.TRUSTED

    @property
    def source(self) -> str:
        return str(self.attributes.get("source", "unknown"))

    def to_dict(self) -> dict:
        return {
            "span_id": self.span_id,
            "parent_span_id": self.parent_span_id,
            "trace_id": self.trace_id,
            "name": self.name,
            "kind": self.kind.value,
            "agent_id": self.agent_id,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "attributes": dict(self.attributes),
            "consumes": list(self.consumes),
            "produces": list(self.produces),
        }


# --------------------------------------------------------------------------
# Authority manifest
# --------------------------------------------------------------------------


@dataclass(slots=True)
class AuthorityManifest:
    """What an agent is *declared* to be allowed to do.

    This is the reference against which a trace is judged. It is intentionally
    declarative and small: a manifest that is hard to write is a manifest that
    will not be written.
    """

    agent_id: str
    tools: frozenset[str] = frozenset()
    scopes: frozenset[str] = frozenset()
    data_classes: frozenset[str] = frozenset()
    requires_approval: frozenset[str] = frozenset()
    max_blast_radius: float | None = None

    def __post_init__(self) -> None:
        if not _ID_RE.match(self.agent_id):
            raise SchemaError(f"invalid agent_id: {self.agent_id!r}")
        for s in self.scopes:
            if not _SCOPE_RE.match(s):
                raise SchemaError(f"invalid scope identifier: {s!r}")
        if self.max_blast_radius is not None and not (0 <= self.max_blast_radius <= 100):
            raise SchemaError("max_blast_radius must be within 0-100")

    def allows_tool(self, tool: str) -> bool:
        return tool in self.tools

    def allows_scope(self, scope: str) -> bool:
        """Exact match, or a wildcard grant such as ``read:*``."""
        if scope in self.scopes:
            return True
        namespace = scope.split(":", 1)[0]
        return f"{namespace}:*" in self.scopes

    def allows_data_class(self, data_class: str) -> bool:
        return data_class in self.data_classes

    def needs_approval(self, tool: str, scopes: tuple[str, ...]) -> bool:
        if tool in self.requires_approval:
            return True
        return any(s in self.requires_approval for s in scopes)

    def to_dict(self) -> dict:
        return {
            "agent_id": self.agent_id,
            "tools": sorted(self.tools),
            "scopes": sorted(self.scopes),
            "data_classes": sorted(self.data_classes),
            "requires_approval": sorted(self.requires_approval),
            "max_blast_radius": self.max_blast_radius,
        }


# --------------------------------------------------------------------------
# Trace
# --------------------------------------------------------------------------


@dataclass(slots=True)
class Trace:
    """A complete agent run: its events plus the manifests in force."""

    trace_id: str
    events: list[AgentEvent]
    manifests: dict[str, AuthorityManifest] = field(default_factory=dict)

    def __post_init__(self) -> None:
        seen: set[str] = set()
        for e in self.events:
            if e.span_id in seen:
                raise SchemaError(f"duplicate span_id: {e.span_id}")
            seen.add(e.span_id)
        for e in self.events:
            if e.parent_span_id and e.parent_span_id not in seen:
                raise SchemaError(
                    f"span {e.span_id} references unknown parent {e.parent_span_id}"
                )

    # -- accessors --------------------------------------------------------
    def by_id(self, span_id: str) -> AgentEvent:
        for e in self.events:
            if e.span_id == span_id:
                return e
        raise SchemaError(f"unknown span_id: {span_id}")

    def of_kind(self, kind: EventKind) -> list[AgentEvent]:
        return [e for e in self.events if e.kind is kind]

    def children(self, span_id: str) -> list[AgentEvent]:
        return [e for e in self.events if e.parent_span_id == span_id]

    def manifest_for(self, agent_id: str) -> AuthorityManifest | None:
        return self.manifests.get(agent_id)

    def agents(self) -> list[str]:
        return sorted({e.agent_id for e in self.events})

    def ordered(self) -> list[AgentEvent]:
        """Events in execution order (start time, then span id for stability)."""
        return sorted(self.events, key=lambda e: (e.start_time, e.span_id))

    def validate(self) -> list[str]:
        """Structural sanity checks; returns human-readable warnings."""
        issues: list[str] = []
        if not self.events:
            issues.append("trace has no events")
        for agent in self.agents():
            if agent not in self.manifests:
                issues.append(f"no authority manifest declared for agent {agent!r}")
        produced = {v for e in self.events for v in e.produces}
        for e in self.events:
            for v in e.consumes:
                if v not in produced:
                    issues.append(
                        f"span {e.span_id} consumes value {v!r} that no event produces"
                    )
        if not self.of_kind(EventKind.TOOL_INVOKE):
            issues.append("trace contains no tool invocations")
        return issues

    def to_dict(self) -> dict:
        return {
            "trace_id": self.trace_id,
            "manifests": {k: v.to_dict() for k, v in self.manifests.items()},
            "events": [e.to_dict() for e in self.ordered()],
        }
