"""Test suite for Sentinel Trace.

Covers the behaviours the tool's claims rest on: schema validation, authority
comparison, taint propagation, blast-radius scoring, replay verdicts, and the
corpus gate — plus hostile input.

Copyright (c) 2026 kk (kkdev9715). All Rights Reserved.
"""

from __future__ import annotations

import json

import pytest

from sentinel_trace.authority import (
    ViolationKind,
    authority_score,
    check_event,
    check_trace,
)
from sentinel_trace.blast import score_action, score_trace, worst
from sentinel_trace.corpus import CorpusCase, load_corpus, run_case, run_corpus
from sentinel_trace.model import (
    AgentEvent,
    AuthorityManifest,
    EventKind,
    SchemaError,
    Severity,
    data_class_sensitivity,
    scope_severity,
    severity_from_score,
)
from sentinel_trace.replay import replay
from sentinel_trace.schema import load_trace, parse_manifest, parse_trace
from sentinel_trace.taint import (
    propagate,
    reconstruct_paths,
    tainted_actions,
    untrusted_sources,
)

# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def _ev(span_id, kind, agent="a", **attrs):
    return AgentEvent(
        span_id=span_id,
        name=span_id,
        kind=kind,
        agent_id=agent,
        attributes=attrs,
    )


def _manifest(**kw):
    kw.setdefault("agent_id", "a")
    return AuthorityManifest(**kw)


# --------------------------------------------------------------------------
# Model / severity tables
# --------------------------------------------------------------------------


class TestModel:
    def test_scope_severity_exact(self):
        assert scope_severity("money:transfer") == 1.0
        assert scope_severity("read:public") == 0.10

    def test_scope_severity_prefix_fallback(self):
        assert scope_severity("read:something-new") == 0.40
        assert scope_severity("exec:whatever") == 0.85

    def test_unknown_scope_is_conservative_not_zero(self):
        assert scope_severity("frobnicate:thing") == 0.50

    def test_data_class_sensitivity(self):
        assert data_class_sensitivity("credentials") == 1.0
        assert data_class_sensitivity("public") == 0.05
        assert data_class_sensitivity("unknown-class") == 0.50

    def test_severity_bands(self):
        assert severity_from_score(85) is Severity.CRITICAL
        assert severity_from_score(65) is Severity.HIGH
        assert severity_from_score(40) is Severity.MEDIUM
        assert severity_from_score(10) is Severity.LOW

    def test_invalid_span_id_rejected(self):
        with pytest.raises(SchemaError):
            _ev("bad span id!", EventKind.TOOL_INVOKE)

    def test_end_before_start_rejected(self):
        with pytest.raises(SchemaError):
            AgentEvent(
                span_id="s", name="s", kind=EventKind.TOOL_INVOKE, agent_id="a",
                start_time=10, end_time=5,
            )

    def test_manifest_wildcard_scope(self):
        m = _manifest(scopes=frozenset({"read:*"}))
        assert m.allows_scope("read:secret")
        assert not m.allows_scope("write:internal")

    def test_manifest_invalid_scope_rejected(self):
        with pytest.raises(SchemaError):
            _manifest(scopes=frozenset({"Not A Scope"}))

    def test_manifest_blast_radius_range(self):
        with pytest.raises(SchemaError):
            _manifest(max_blast_radius=150)

    def test_manifest_needs_approval_by_tool_and_scope(self):
        m = _manifest(requires_approval=frozenset({"write:external"}))
        assert m.needs_approval("anything", ("write:external",))
        assert not m.needs_approval("anything", ("read:public",))


# --------------------------------------------------------------------------
# Schema parsing
# --------------------------------------------------------------------------


class TestSchema:
    def test_parse_minimal_trace(self):
        t = parse_trace(
            {
                "trace_id": "t1",
                "events": [
                    {"span_id": "s1", "name": "n", "kind": "tool.invoke", "agent_id": "a"}
                ],
            }
        )
        assert t.trace_id == "t1"
        assert len(t.events) == 1

    def test_otel_camelcase_keys_accepted(self):
        t = parse_trace(
            {
                "traceId": "t2",
                "events": [
                    {
                        "spanId": "s1",
                        "name": "n",
                        "kind": "tool.invoke",
                        "agentId": "a",
                        "startTimeUnixNano": 5,
                    }
                ],
            }
        )
        assert t.events[0].span_id == "s1"
        assert t.events[0].agent_id == "a"

    def test_unknown_kind_rejected_with_accepted_list(self):
        with pytest.raises(SchemaError) as exc:
            parse_trace(
                {"events": [{"span_id": "s", "name": "n", "kind": "nope", "agent_id": "a"}]}
            )
        assert "accepted" in str(exc.value)

    def test_missing_events_rejected(self):
        with pytest.raises(SchemaError):
            parse_trace({"trace_id": "t"})

    def test_duplicate_span_rejected(self):
        with pytest.raises(SchemaError):
            parse_trace(
                {
                    "events": [
                        {"span_id": "s", "name": "n", "kind": "tool.invoke", "agent_id": "a"},
                        {"span_id": "s", "name": "n", "kind": "tool.invoke", "agent_id": "a"},
                    ]
                }
            )

    def test_unknown_parent_rejected(self):
        with pytest.raises(SchemaError):
            parse_trace(
                {
                    "events": [
                        {
                            "span_id": "s",
                            "name": "n",
                            "kind": "tool.invoke",
                            "agent_id": "a",
                            "parent_span_id": "ghost",
                        }
                    ]
                }
            )

    def test_manifests_as_dict_and_list(self):
        d = parse_trace(
            {
                "events": [{"span_id": "s", "name": "n", "kind": "tool.invoke", "agent_id": "a"}],
                "manifests": {"a": {"tools": ["x"]}},
            }
        )
        assert d.manifests["a"].tools == frozenset({"x"})
        lst = parse_trace(
            {
                "events": [{"span_id": "s", "name": "n", "kind": "tool.invoke", "agent_id": "a"}],
                "manifests": [{"agent_id": "a", "tools": ["x"]}],
            }
        )
        assert lst.manifests["a"].tools == frozenset({"x"})

    def test_manifest_missing_agent_id_rejected(self):
        with pytest.raises(SchemaError):
            parse_manifest({"tools": ["x"]})

    def test_load_missing_file(self):
        with pytest.raises(SchemaError):
            load_trace("/nonexistent/trace.json")

    def test_load_malformed_json(self, tmp_path):
        p = tmp_path / "bad.json"
        p.write_text("{not json", encoding="utf-8")
        with pytest.raises(SchemaError):
            load_trace(p)

    def test_validate_flags_missing_manifest(self):
        t = parse_trace(
            {"events": [{"span_id": "s", "name": "n", "kind": "tool.invoke", "agent_id": "a"}]}
        )
        issues = t.validate()
        assert any("no authority manifest" in i for i in issues)

    def test_validate_flags_dangling_value(self):
        t = parse_trace(
            {
                "events": [
                    {
                        "span_id": "s",
                        "name": "n",
                        "kind": "tool.invoke",
                        "agent_id": "a",
                        "consumes": ["never-produced"],
                    }
                ]
            }
        )
        assert any("no event produces" in i for i in t.validate())


# --------------------------------------------------------------------------
# Authority comparison
# --------------------------------------------------------------------------


class TestAuthority:
    def test_compliant_action_has_no_violations(self):
        m = _manifest(tools=frozenset({"read_file"}), scopes=frozenset({"read:internal"}))
        e = _ev("s", EventKind.TOOL_INVOKE, tool="read_file", scopes=["read:internal"])
        assert check_event(e, m) == []

    def test_undeclared_tool_flagged(self):
        m = _manifest(tools=frozenset({"read_file"}))
        e = _ev("s", EventKind.TOOL_INVOKE, tool="http_post")
        kinds = {v.kind for v in check_event(e, m)}
        assert ViolationKind.UNDECLARED_TOOL in kinds

    def test_undeclared_scope_flagged_and_weighted_by_severity(self):
        m = _manifest(scopes=frozenset({"read:public"}))
        e = _ev("s", EventKind.TOOL_INVOKE, tool="t", scopes=["money:transfer"])
        v = [x for x in check_event(e, m) if x.kind is ViolationKind.UNDECLARED_SCOPE][0]
        # money:transfer is severity 1.0, so the weight is the full base weight.
        assert v.weight == pytest.approx(0.70)

    def test_missing_approval_flagged(self):
        m = _manifest(
            tools=frozenset({"http_post"}),
            scopes=frozenset({"write:external"}),
            requires_approval=frozenset({"write:external"}),
        )
        e = _ev("s", EventKind.TOOL_INVOKE, tool="http_post", scopes=["write:external"])
        kinds = {v.kind for v in check_event(e, m)}
        assert ViolationKind.MISSING_APPROVAL in kinds

    def test_approval_present_clears_violation(self):
        m = _manifest(
            tools=frozenset({"http_post"}),
            scopes=frozenset({"write:external"}),
            requires_approval=frozenset({"write:external"}),
        )
        e = _ev(
            "s", EventKind.TOOL_INVOKE, tool="http_post",
            scopes=["write:external"], approved=True,
        )
        assert check_event(e, m) == []

    def test_no_manifest_flagged(self):
        e = _ev("s", EventKind.TOOL_INVOKE, tool="t")
        kinds = {v.kind for v in check_event(e, None)}
        assert ViolationKind.NO_MANIFEST in kinds

    def test_non_actionable_events_never_violate(self):
        m = _manifest()
        e = _ev("s", EventKind.LLM_CALL, tool="whatever")
        assert check_event(e, m) == []

    def test_authority_score_zero_when_clean(self):
        assert authority_score([]) == 0.0

    def test_authority_score_saturates(self):
        """Many trivial violations must not outrank one catastrophic one.

        This is the failure mode of a plain mean: one catastrophic violation
        averaged against fifty trivial ones collapses to near zero. The score
        must be dominated by the worst violation.
        """
        from sentinel_trace.authority import Violation

        def v(span, weight):
            return Violation(
                span_id=span,
                agent_id="a",
                kind=ViolationKind.UNDECLARED_TOOL,
                detail="d",
                weight=weight,
            )

        trivial = [v(f"s{i}", 0.05) for i in range(50)]
        catastrophic = [v("big", 0.90)]
        assert authority_score(catastrophic) > authority_score(trivial)
        # And the mean would have said the opposite.
        assert sum(x.weight for x in trivial) / len(trivial) < 0.90

    def test_authority_score_worst_dominates(self):
        """Adding trivial violations must not lower a catastrophic score."""
        from sentinel_trace.authority import Violation

        def v(span, weight):
            return Violation(
                span_id=span,
                agent_id="a",
                kind=ViolationKind.UNDECLARED_TOOL,
                detail="d",
                weight=weight,
            )

        alone = authority_score([v("big", 0.90)])
        diluted = authority_score([v("big", 0.90)] + [v(f"s{i}", 0.05) for i in range(50)])
        assert diluted >= alone

    def test_check_trace_uses_per_agent_manifest(self):
        t = parse_trace(
            {
                "events": [
                    {
                        "span_id": "s",
                        "name": "n",
                        "kind": "tool.invoke",
                        "agent_id": "a",
                        "attributes": {"tool": "http_post"},
                    }
                ],
                "manifests": {"a": {"tools": ["read_file"]}},
            }
        )
        assert check_trace(t)


# --------------------------------------------------------------------------
# Taint propagation
# --------------------------------------------------------------------------


class TestTaint:
    def _hijack(self):
        return parse_trace(
            {
                "trace_id": "h",
                "manifests": {"a": {"tools": ["fetch", "post"]}},
                "events": [
                    {
                        "span_id": "s1", "name": "ingest", "kind": "content.ingest",
                        "agent_id": "a", "attributes": {"trust": "untrusted", "source": "web"},
                        "produces": ["doc"],
                    },
                    {
                        "span_id": "s2", "name": "llm", "kind": "llm.call", "agent_id": "a",
                        "consumes": ["doc"], "produces": ["text"],
                    },
                    {
                        "span_id": "s3", "name": "post", "kind": "tool.invoke", "agent_id": "a",
                        "attributes": {"tool": "post", "external": True, "reversible": False},
                        "consumes": ["text"], "produces": ["resp"],
                    },
                ],
            }
        )

    def test_untrusted_source_detected(self):
        t = self._hijack()
        assert "s1" in untrusted_sources(t)

    def test_taint_propagates_transitively(self):
        t = self._hijack()
        inf = propagate(t)
        assert "s2" in inf
        assert "s3" in inf
        assert "s1" in inf["s3"].sources

    def test_trusted_content_does_not_taint(self):
        t = parse_trace(
            {
                "events": [
                    {
                        "span_id": "s1", "name": "ingest", "kind": "content.ingest",
                        "agent_id": "a", "attributes": {"trust": "trusted"},
                        "produces": ["doc"],
                    },
                    {
                        "span_id": "s2", "name": "llm", "kind": "llm.call", "agent_id": "a",
                        "consumes": ["doc"], "produces": ["text"],
                    },
                ]
            }
        )
        assert propagate(t) == {}

    def test_injection_path_reconstructed(self):
        t = self._hijack()
        inf = propagate(t)
        paths = reconstruct_paths(t, inf)
        assert paths
        p = paths[0]
        assert p.source_span == "s1"
        assert p.sink_span == "s3"
        assert p.hops[0] == "s1" and p.hops[-1] == "s3"

    def test_tainted_actions_lists_sink(self):
        t = self._hijack()
        inf = propagate(t)
        acts = tainted_actions(t, inf)
        assert any(a.span_id == "s3" for a in acts)

    def test_cycle_in_value_graph_terminates(self):
        t = parse_trace(
            {
                "events": [
                    {
                        "span_id": "s1", "name": "i", "kind": "content.ingest", "agent_id": "a",
                        "attributes": {"trust": "untrusted"}, "produces": ["v1"],
                    },
                    {
                        "span_id": "s2", "name": "a", "kind": "llm.call", "agent_id": "a",
                        "consumes": ["v1"], "produces": ["v2"],
                    },
                    {
                        "span_id": "s3", "name": "b", "kind": "llm.call", "agent_id": "a",
                        "consumes": ["v2"], "produces": ["v1"],
                    },
                ]
            }
        )
        inf = propagate(t)  # must terminate
        assert "s3" in inf


# --------------------------------------------------------------------------
# Blast radius
# --------------------------------------------------------------------------


class TestBlast:
    def test_public_read_is_low(self):
        e = _ev("s", EventKind.TOOL_INVOKE, tool="t", scopes=["read:public"],
                data_classes=["public"])
        assert score_action(e).score < 20

    def test_irreversible_external_credential_write_is_critical(self):
        e = _ev(
            "s", EventKind.TOOL_INVOKE, tool="post",
            scopes=["write:external"], data_classes=["credentials"],
            external=True, reversible=False,
        )
        b = score_action(e)
        assert b.severity is Severity.CRITICAL
        assert b.score > 80

    def test_taint_raises_score(self):
        e = _ev("s", EventKind.TOOL_INVOKE, tool="t", scopes=["write:external"],
                data_classes=["credentials"], external=True)
        assert score_action(e, tainted=True).score > score_action(e, tainted=False).score

    def test_volume_increases_score(self):
        low = _ev("s", EventKind.TOOL_INVOKE, tool="t", scopes=["read:internal"], volume=1)
        high = _ev("s", EventKind.TOOL_INVOKE, tool="t", scopes=["read:internal"], volume=100000)
        assert score_action(high).score > score_action(low).score

    def test_score_bounded_0_100(self):
        e = _ev(
            "s", EventKind.TOOL_INVOKE, tool="t", scopes=["money:transfer"],
            data_classes=["credentials"], external=True, reversible=False, volume=10**9,
        )
        assert 0 <= score_action(e, tainted=True).score <= 100

    def test_score_trace_sorted_desc(self):
        events = [
            _ev("a", EventKind.TOOL_INVOKE, tool="t", scopes=["read:public"]),
            _ev("b", EventKind.TOOL_INVOKE, tool="t", scopes=["money:transfer"],
                data_classes=["credentials"], external=True, reversible=False),
        ]
        radii = score_trace(events)
        assert radii[0].span_id == "b"
        assert worst(radii).span_id == "b"

    def test_worst_of_empty_is_none(self):
        assert worst([]) is None


# --------------------------------------------------------------------------
# Replay / verdicts
# --------------------------------------------------------------------------


class TestReplay:
    def test_clean_trace_passes(self):
        a = replay(load_trace("examples/clean-run.json"))
        assert a.verdict == "pass"
        assert a.risk_score < 50

    def test_hijack_trace_fails(self):
        a = replay(load_trace("examples/hijack-exfiltration.json"))
        assert a.verdict == "fail"
        assert a.risk_score >= 80
        assert a.injection_paths
        assert a.violations

    def test_hijack_flags_undeclared_scope_and_approval(self):
        a = replay(load_trace("examples/hijack-exfiltration.json"))
        kinds = {v.kind for v in a.violations}
        assert ViolationKind.UNDECLARED_SCOPE in kinds
        assert ViolationKind.MISSING_APPROVAL in kinds

    def test_risk_score_zero_when_nothing_wrong(self):
        t = parse_trace(
            {
                "manifests": {"a": {"tools": ["t"], "scopes": ["read:public"]}},
                "events": [
                    {
                        "span_id": "s", "name": "n", "kind": "tool.invoke", "agent_id": "a",
                        "attributes": {"tool": "t", "scopes": ["read:public"]},
                    }
                ],
            }
        )
        a = replay(t)
        assert a.risk_score == 0.0
        assert a.verdict == "pass"

    def test_assessment_serialises(self):
        a = replay(load_trace("examples/hijack-exfiltration.json"))
        d = a.to_dict()
        assert "summary" in d and "violations" in d and "injection_paths" in d
        assert d["summary"]["events"] == 4

    def test_event_count_is_correct(self):
        a = replay(load_trace("examples/clean-run.json"))
        assert a.counts["events"] == 3

    def test_no_manifest_alone_is_not_a_pass(self):
        """Acting with no declared authority must not slip through as 'pass'.

        This is the calibration the corpus forced: a geometric blend scored
        this 25 and called it a pass, which under-reports a governance failure.
        """
        t = parse_trace(
            {
                "events": [
                    {
                        "span_id": "n1", "name": "act", "kind": "tool.invoke",
                        "agent_id": "ghost",
                        "attributes": {"tool": "http_post", "scopes": ["write:external"],
                                       "external": True},
                    }
                ]
            }
        )
        a = replay(t)
        assert a.verdict != "pass"
        assert a.risk_score >= 50

    def test_risk_is_dominated_by_worse_dimension(self):
        """Two moderate signals must not collapse to a low score."""
        t = parse_trace(
            {
                "manifests": {"a": {"tools": ["t"], "scopes": ["read:public"]}},
                "events": [
                    {
                        "span_id": "s", "name": "n", "kind": "tool.invoke", "agent_id": "a",
                        "attributes": {
                            "tool": "drop_table", "scopes": ["delete:data"],
                            "data_classes": ["confidential"], "reversible": False,
                        },
                    }
                ],
            }
        )
        a = replay(t)
        assert a.risk_score >= max(a.authority_exceeded, a.relevant_blast_radius)

    def test_permitted_action_blast_radius_does_not_create_risk(self):
        """A large blast radius on a *permitted* action is not risk."""
        t = parse_trace(
            {
                "manifests": {
                    "a": {
                        "tools": ["drop_table"],
                        "scopes": ["delete:data"],
                        "data_classes": ["confidential"],
                    }
                },
                "events": [
                    {
                        "span_id": "s", "name": "n", "kind": "tool.invoke", "agent_id": "a",
                        "attributes": {
                            "tool": "drop_table", "scopes": ["delete:data"],
                            "data_classes": ["confidential"], "reversible": False,
                        },
                    }
                ],
            }
        )
        a = replay(t)
        assert a.max_blast_radius > 50  # the action is genuinely dangerous
        assert a.risk_score == 0.0  # but it was authorised, so it is not risk
        assert a.verdict == "pass"


# --------------------------------------------------------------------------
# Corpus / CI gate
# --------------------------------------------------------------------------


class TestCorpus:
    def test_run_case_pass(self):
        case = CorpusCase(
            name="clean",
            trace=load_trace("examples/clean-run.json"),
            expected_verdict="pass",
        )
        assert run_case(case).passed

    def test_run_case_detects_mismatch(self):
        case = CorpusCase(
            name="wrong",
            trace=load_trace("examples/clean-run.json"),
            expected_verdict="fail",
        )
        r = run_case(case)
        assert not r.passed
        assert any("verdict" in f for f in r.failures)

    def test_must_flag_enforced(self):
        case = CorpusCase(
            name="flag",
            trace=load_trace("examples/hijack-exfiltration.json"),
            expected_verdict="fail",
            must_flag=("undeclared_scope",),
        )
        assert run_case(case).passed

    def test_empty_corpus_is_a_failure(self):
        with pytest.raises(SchemaError):
            run_corpus([])

    def test_load_corpus_from_examples(self):
        cases = load_corpus("examples")
        assert len(cases) >= 2
        report = run_corpus(cases)
        assert report.total >= 2

    def test_invalid_expected_verdict_rejected(self):
        with pytest.raises(SchemaError):
            CorpusCase(
                name="x",
                trace=load_trace("examples/clean-run.json"),
                expected_verdict="maybe",
            )


# --------------------------------------------------------------------------
# Hostile input
# --------------------------------------------------------------------------


class TestHostileInput:
    def test_events_not_a_list(self):
        with pytest.raises(SchemaError):
            parse_trace({"events": {"not": "a list"}})

    def test_event_not_an_object(self):
        with pytest.raises(SchemaError):
            parse_trace({"events": ["just a string"]})

    def test_attributes_not_an_object(self):
        with pytest.raises(SchemaError):
            parse_trace(
                {
                    "events": [
                        {
                            "span_id": "s", "name": "n", "kind": "tool.invoke",
                            "agent_id": "a", "attributes": "nope",
                        }
                    ]
                }
            )

    def test_non_numeric_timestamp(self):
        with pytest.raises(SchemaError):
            parse_trace(
                {
                    "events": [
                        {
                            "span_id": "s", "name": "n", "kind": "tool.invoke",
                            "agent_id": "a", "start_time": "soon",
                        }
                    ]
                }
            )

    def test_consumes_with_non_string(self):
        with pytest.raises(SchemaError):
            parse_trace(
                {
                    "events": [
                        {
                            "span_id": "s", "name": "n", "kind": "tool.invoke",
                            "agent_id": "a", "consumes": [1, 2],
                        }
                    ]
                }
            )

    def test_html_in_attributes_is_escaped_in_report(self):
        from sentinel_trace.report_html import render_html

        t = parse_trace(
            {
                "manifests": {"a": {"tools": ["t"]}},
                "events": [
                    {
                        "span_id": "s", "name": "<script>alert(1)</script>",
                        "kind": "tool.invoke", "agent_id": "a",
                        "attributes": {"tool": "<img src=x onerror=alert(1)>"},
                    }
                ],
            }
        )
        html = render_html(replay(t).to_dict())
        assert "<script>alert(1)</script>" not in html
        assert "onerror=alert(1)>" not in html

    def test_script_close_tag_cannot_break_payload_block(self):
        from sentinel_trace.report_html import render_html

        t = parse_trace(
            {
                "manifests": {"a": {"tools": ["t"]}},
                "events": [
                    {
                        "span_id": "s", "name": "n", "kind": "tool.invoke", "agent_id": "a",
                        "attributes": {"tool": "</script><script>alert(1)</script>"},
                    }
                ],
            }
        )
        html = render_html(replay(t).to_dict())
        # The literal closing tag must not appear inside the JSON payload block.
        payload_start = html.index('id="payload"')
        payload_end = html.index("</script>", payload_start)
        assert "</script><script>" not in html[payload_start:payload_end]

    def test_large_trace_capped(self):
        from sentinel_trace.schema import MAX_EVENTS

        events = [
            {"span_id": f"s{i}", "name": "n", "kind": "tool.invoke", "agent_id": "a"}
            for i in range(MAX_EVENTS + 1)
        ]
        with pytest.raises(SchemaError):
            parse_trace({"events": events})

    def test_report_has_no_external_references(self):
        from sentinel_trace.report_html import render_html

        html = render_html(replay(load_trace("examples/hijack-exfiltration.json")).to_dict())
        for needle in ("http://", "https://", "//cdn", 'src="http'):
            assert needle not in html.replace("https://blog.example.com", "")

    def test_report_parses_as_json_payload(self):
        from sentinel_trace.report_html import render_html

        payload = replay(load_trace("examples/hijack-exfiltration.json")).to_dict()
        html = render_html(payload)
        start = html.index('id="payload">') + len('id="payload">')
        end = html.index("</script>", start)
        embedded = html[start:end]
        # The escaped form must round-trip back to the original payload.
        assert json.loads(embedded)["summary"]["verdict"] == "fail"
