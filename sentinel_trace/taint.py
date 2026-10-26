"""Taint propagation and injection-path reconstruction.

An agent that reads an untrusted document and then calls a dangerous tool is
the canonical agent-hijack shape. This module computes, for every event, the
set of untrusted sources that could have influenced it — transitively, through
the values events produce and consume — and then reconstructs the shortest
influence path from an untrusted ingest to a dangerous action.

The propagation is a forward fixpoint over the value graph. It is deliberately
conservative: if a value *could* carry untrusted influence, it is marked as
carrying it. Under-approximating here would mean missing real hijacks.

Copyright (c) 2026 kk (kkdev9715). All Rights Reserved. Proprietary — see LICENSE.
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass

from sentinel_trace.model import AgentEvent, EventKind, Trace, Trust


@dataclass(slots=True)
class Influence:
    """Why an event is considered influenced by untrusted content."""

    span_id: str
    sources: tuple[str, ...]  # span ids of untrusted ingests
    via_values: tuple[str, ...]  # value identifiers that carried the taint

    def to_dict(self) -> dict:
        return {
            "span_id": self.span_id,
            "sources": list(self.sources),
            "via_values": list(self.via_values),
        }


@dataclass(slots=True)
class InjectionPath:
    """A reconstructed chain from untrusted content to a dangerous action."""

    source_span: str
    source_label: str
    sink_span: str
    sink_label: str
    hops: tuple[str, ...]  # span ids, source -> sink
    via_values: tuple[str, ...]

    @property
    def length(self) -> int:
        return len(self.hops)

    def to_dict(self) -> dict:
        return {
            "source_span": self.source_span,
            "source_label": self.source_label,
            "sink_span": self.sink_span,
            "sink_label": self.sink_label,
            "hops": list(self.hops),
            "via_values": list(self.via_values),
            "length": self.length,
        }


def untrusted_sources(trace: Trace) -> dict[str, str]:
    """Map span id -> human label for every untrusted content ingest."""
    out: dict[str, str] = {}
    for e in trace.events:
        if e.kind is EventKind.CONTENT_INGEST and e.trust is Trust.UNTRUSTED:
            out[e.span_id] = f"{e.source} ({e.name})"
    return out


def propagate(trace: Trace) -> dict[str, Influence]:
    """Compute untrusted influence for every event.

    Forward fixpoint: a value is tainted if any event that produces it is
    tainted; an event is tainted if any value it consumes is tainted, or if it
    is itself an untrusted ingest.
    """
    # value -> set of source span ids that tainted it
    value_taint: dict[str, set[str]] = defaultdict(set)
    # value -> set of values that carried the taint (for path reconstruction)
    value_via: dict[str, set[str]] = defaultdict(set)
    influences: dict[str, Influence] = {}

    sources = untrusted_sources(trace)

    # Seed: untrusted ingests taint everything they produce.
    for e in trace.ordered():
        if e.span_id in sources:
            for v in e.produces:
                value_taint[v].add(e.span_id)
                value_via[v].add(v)

    # Fixpoint over the ordered event list. Bounded by the number of events,
    # since each pass can only add taint, never remove it.
    changed = True
    passes = 0
    max_passes = len(trace.events) + 1
    while changed and passes < max_passes:
        changed = False
        passes += 1
        for e in trace.ordered():
            incoming: set[str] = set()
            via: set[str] = set()
            for v in e.consumes:
                if value_taint.get(v):
                    incoming |= value_taint[v]
                    via |= value_via[v] | {v}
            if e.span_id in sources:
                incoming.add(e.span_id)
            if not incoming:
                continue
            if e.span_id not in influences:
                influences[e.span_id] = Influence(
                    span_id=e.span_id,
                    sources=tuple(sorted(incoming)),
                    via_values=tuple(sorted(via)),
                )
                changed = True
            else:
                prev = influences[e.span_id]
                merged = set(prev.sources) | incoming
                if len(merged) != len(prev.sources):
                    influences[e.span_id] = Influence(
                        span_id=e.span_id,
                        sources=tuple(sorted(merged)),
                        via_values=tuple(sorted(set(prev.via_values) | via)),
                    )
                    changed = True
            # Propagate to produced values.
            for v in e.produces:
                before = len(value_taint[v])
                value_taint[v] |= incoming
                value_via[v] |= via | {v}
                if len(value_taint[v]) != before:
                    changed = True

    return influences


def _dangerous(event: AgentEvent) -> bool:
    """An action whose hijacking would matter."""
    if event.kind is not EventKind.TOOL_INVOKE:
        return False
    if event.external or not event.reversible:
        return True
    return any(
        s.startswith(("write:", "exec:", "money:", "identity:", "delete:"))
        for s in event.scopes
    )


def reconstruct_paths(trace: Trace, influences: dict[str, Influence]) -> list[InjectionPath]:
    """Shortest influence path from each untrusted source to each dangerous sink.

    BFS over the event graph, where an edge exists from event A to event B when
    B consumes a value A produces, or when B is a child span of A. Shortest
    paths are reported because the shortest chain is the most defensible
    explanation of how untrusted content reached a dangerous action.
    """
    producers: dict[str, list[str]] = defaultdict(list)
    for e in trace.events:
        for v in e.produces:
            producers[v].append(e.span_id)

    # adjacency: span -> list of (next_span, value)
    adj: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for e in trace.events:
        for v in e.consumes:
            for p in producers.get(v, ()):
                if p != e.span_id:
                    adj[p].append((e.span_id, v))
        if e.parent_span_id:
            adj[e.parent_span_id].append((e.span_id, ""))

    sources = untrusted_sources(trace)
    sinks = [e for e in trace.events if _dangerous(e) and e.span_id in influences]

    paths: list[InjectionPath] = []
    for sink in sinks:
        for src_id, src_label in sources.items():
            if src_id == sink.span_id:
                continue
            # BFS from source to this sink.
            prev: dict[str, tuple[str, str] | None] = {src_id: None}
            q: deque[str] = deque([src_id])
            found = False
            while q and not found:
                cur = q.popleft()
                for nxt, val in adj.get(cur, ()):
                    if nxt in prev:
                        continue
                    prev[nxt] = (cur, val)
                    if nxt == sink.span_id:
                        found = True
                        break
                    q.append(nxt)
            if not found:
                continue
            # Walk back.
            hops: list[str] = []
            values: list[str] = []
            node = sink.span_id
            while node is not None:
                hops.append(node)
                step = prev[node]
                if step is None:
                    break
                node, val = step
                if val:
                    values.append(val)
            hops.reverse()
            values.reverse()
            paths.append(
                InjectionPath(
                    source_span=src_id,
                    source_label=src_label,
                    sink_span=sink.span_id,
                    sink_label=f"{sink.tool or sink.name}",
                    hops=tuple(hops),
                    via_values=tuple(values),
                )
            )

    # Shortest first; then by sink danger (external/irreversible sinks first).
    paths.sort(key=lambda p: (p.length, p.sink_span))
    return paths


def tainted_actions(trace: Trace, influences: dict[str, Influence]) -> list[AgentEvent]:
    """Actionable events that carry untrusted influence."""
    return [
        e
        for e in trace.ordered()
        if e.span_id in influences
        and e.kind in (EventKind.TOOL_INVOKE, EventKind.MEMORY_WRITE, EventKind.AGENT_SPAWN)
    ]
