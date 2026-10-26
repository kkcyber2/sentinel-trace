"""Trace parsing and validation.

Accepts a documented JSON form and a native OpenTelemetry-ish form, normalising
both into :class:`~sentinel_trace.model.Trace`. Validation is strict and
happens before any analysis: a security tool that silently accepts a malformed
trace will confidently report the wrong answer.

Copyright (c) 2026 kk (kkdev9715). All Rights Reserved. Proprietary — see LICENSE.
"""

from __future__ import annotations

import json
from pathlib import Path

from sentinel_trace.model import (
    AgentEvent,
    AuthorityManifest,
    EventKind,
    SchemaError,
    Trace,
)

#: Hard cap on trace size. A trace is attacker-influenced input; an unbounded
#: one is a denial-of-service vector.
MAX_EVENTS = 200_000
MAX_FILE_BYTES = 64 * 1024 * 1024


def _as_tuple(value: object, field_name: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    if isinstance(value, (list, tuple)):
        out = []
        for item in value:
            if not isinstance(item, str):
                raise SchemaError(f"{field_name} entries must be strings, got {type(item).__name__}")
            out.append(item)
        return tuple(out)
    raise SchemaError(f"{field_name} must be a string or list of strings")


def _normalize_event(raw: object, trace_id: str) -> AgentEvent:
    if not isinstance(raw, dict):
        raise SchemaError(f"event must be an object, got {type(raw).__name__}")

    # Accept both snake_case and OTel camelCase keys.
    span_id = raw.get("span_id") or raw.get("spanId")
    parent = raw.get("parent_span_id", raw.get("parentSpanId"))
    name = raw.get("name")
    kind_raw = raw.get("kind") or raw.get("name")
    agent_id = raw.get("agent_id") or raw.get("agentId")

    if not span_id:
        raise SchemaError("event is missing span_id")
    if not name:
        raise SchemaError(f"event {span_id} is missing name")
    if not agent_id:
        raise SchemaError(f"event {span_id} is missing agent_id")

    try:
        kind = EventKind(kind_raw)
    except ValueError as exc:
        accepted = ", ".join(k.value for k in EventKind)
        raise SchemaError(
            f"event {span_id}: unknown kind {kind_raw!r}; accepted: {accepted}"
        ) from exc

    start = raw.get("start_time", raw.get("startTimeUnixNano", 0.0))
    end = raw.get("end_time", raw.get("endTimeUnixNano", 0.0))
    try:
        start_f = float(start or 0.0)
        end_f = float(end or 0.0)
    except (TypeError, ValueError) as exc:
        raise SchemaError(f"event {span_id}: timestamps must be numeric") from exc

    attributes = raw.get("attributes", {})
    if not isinstance(attributes, dict):
        raise SchemaError(f"event {span_id}: attributes must be an object")

    return AgentEvent(
        span_id=str(span_id),
        name=str(name),
        kind=kind,
        agent_id=str(agent_id),
        parent_span_id=str(parent) if parent else None,
        trace_id=str(raw.get("trace_id") or raw.get("traceId") or trace_id),
        start_time=start_f,
        end_time=end_f,
        attributes=dict(attributes),
        consumes=_as_tuple(raw.get("consumes"), f"event {span_id}.consumes"),
        produces=_as_tuple(raw.get("produces"), f"event {span_id}.produces"),
    )


def parse_manifest(raw: object) -> AuthorityManifest:
    if not isinstance(raw, dict):
        raise SchemaError(f"manifest must be an object, got {type(raw).__name__}")
    agent_id = raw.get("agent_id") or raw.get("agentId")
    if not agent_id:
        raise SchemaError("manifest is missing agent_id")
    cap = raw.get("max_blast_radius")
    if cap is not None:
        try:
            cap = float(cap)
        except (TypeError, ValueError) as exc:
            raise SchemaError("max_blast_radius must be numeric") from exc
    return AuthorityManifest(
        agent_id=str(agent_id),
        tools=frozenset(_as_tuple(raw.get("tools"), "manifest.tools")),
        scopes=frozenset(_as_tuple(raw.get("scopes"), "manifest.scopes")),
        data_classes=frozenset(_as_tuple(raw.get("data_classes"), "manifest.data_classes")),
        requires_approval=frozenset(
            _as_tuple(raw.get("requires_approval"), "manifest.requires_approval")
        ),
        max_blast_radius=cap,
    )


def parse_trace(doc: object) -> Trace:
    """Parse a trace document into a :class:`Trace`."""
    if not isinstance(doc, dict):
        raise SchemaError(f"trace document must be an object, got {type(doc).__name__}")

    trace_id = str(doc.get("trace_id") or doc.get("traceId") or "trace")
    raw_events = doc.get("events")
    if raw_events is None:
        raise SchemaError("trace document is missing 'events'")
    if not isinstance(raw_events, list):
        raise SchemaError("'events' must be a list")
    if len(raw_events) > MAX_EVENTS:
        raise SchemaError(f"trace exceeds the {MAX_EVENTS} event cap")

    events = [_normalize_event(e, trace_id) for e in raw_events]

    manifests: dict[str, AuthorityManifest] = {}
    raw_manifests = doc.get("manifests", doc.get("agents", []))
    if isinstance(raw_manifests, dict):
        for key, value in raw_manifests.items():
            if isinstance(value, dict) and "agent_id" not in value:
                value = {**value, "agent_id": key}
            m = parse_manifest(value)
            manifests[m.agent_id] = m
    elif isinstance(raw_manifests, list):
        for value in raw_manifests:
            m = parse_manifest(value)
            manifests[m.agent_id] = m
    elif raw_manifests is not None:
        raise SchemaError("'manifests' must be an object or list")

    return Trace(trace_id=trace_id, events=events, manifests=manifests)


def load_trace(path: str | Path) -> Trace:
    """Load and parse a trace from a JSON file."""
    p = Path(path)
    if not p.exists():
        raise SchemaError(f"no such file: {p}")
    if p.stat().st_size > MAX_FILE_BYTES:
        raise SchemaError(f"file exceeds the {MAX_FILE_BYTES // (1024 * 1024)} MB cap")
    try:
        doc = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SchemaError(f"invalid JSON at line {exc.lineno}: {exc.msg}") from exc
    except OSError as exc:
        raise SchemaError(f"cannot read {p}: {exc}") from exc
    return parse_trace(doc)
