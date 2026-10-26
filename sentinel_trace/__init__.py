"""Sentinel Trace — agent execution security.

Authority replay, blast-radius scoring, and hijack-path reconstruction over
OpenTelemetry-compatible agent traces.

Copyright (c) 2026 kk (kkdev9715). All Rights Reserved. Proprietary — see LICENSE.
"""

from sentinel_trace.authority import (
    Violation,
    ViolationKind,
    authority_score,
    check_event,
    check_trace,
)
from sentinel_trace.blast import BlastRadius, score_action, score_trace, worst
from sentinel_trace.model import (
    AgentEvent,
    AuthorityManifest,
    EventKind,
    SchemaError,
    Severity,
    Trace,
    Trust,
)
from sentinel_trace.replay import Assessment, replay
from sentinel_trace.schema import load_trace, parse_trace
from sentinel_trace.taint import (
    Influence,
    InjectionPath,
    propagate,
    reconstruct_paths,
    tainted_actions,
    untrusted_sources,
)

__version__ = "0.1.0"
__author__ = "kk (kkdev9715)"

__all__ = [
    "AgentEvent",
    "Assessment",
    "AuthorityManifest",
    "BlastRadius",
    "EventKind",
    "Influence",
    "InjectionPath",
    "SchemaError",
    "Severity",
    "Trace",
    "Trust",
    "Violation",
    "ViolationKind",
    "authority_score",
    "check_event",
    "check_trace",
    "load_trace",
    "parse_trace",
    "propagate",
    "reconstruct_paths",
    "replay",
    "score_action",
    "score_trace",
    "tainted_actions",
    "untrusted_sources",
    "worst",
    "__version__",
    "__author__",
]
