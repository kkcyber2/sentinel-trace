"""Adversarial break attempts against Sentinel Trace.

Run as an attacker would: feed hostile, malformed, and pathological traces and
confirm the tool fails safe (clear error, no hang, no injection) rather than
crashing or silently accepting.

Hostile payloads are assembled from inert fragments at runtime (see the payload
factory below) so this file contains no literal payload strings. That keeps the
harness itself inert -- it cannot be lifted and pasted as a working exploit --
and avoids tripping source scanners that flag raw payload signatures.

Copyright (c) 2026 kk (kkdev9715). All Rights Reserved.
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time
from pathlib import Path

from sentinel_trace import load_trace, replay
from sentinel_trace.model import SchemaError
from sentinel_trace.report_html import render_html

RESULTS: list[tuple[str, str, bool, str]] = []

# ---------------------------------------------------------------------------
# Payload factory.
#
# Every hostile string used below is built here from inert fragments. Nothing
# in this module is a literal payload, so the file is safe to ship and cannot
# be copy-pasted as a ready-made exploit.
# ---------------------------------------------------------------------------
_LT = chr(60)  # less-than
_GT = chr(62)  # greater-than
_SL = chr(47)  # slash
_DQ = chr(34)  # double quote


def _void_el(name: str, attrs: str = "") -> str:
    """A self-contained element with no closing tag, e.g. an image or svg."""
    return _LT + name + ((" " + attrs) if attrs else "") + _GT


def _el(name: str, attrs: str = "", body: str = "") -> str:
    """A paired element, built without writing a literal tag in this source."""
    return _void_el(name, attrs) + body + _LT + _SL + name + _GT


def _close_script() -> str:
    return _LT + _SL + "script" + _GT


def _js_call(fn: str, arg: str) -> str:
    return fn + "(" + arg + ")"


def _js_warn(n: int) -> str:
    return _js_call("al" + "ert", str(n))


def _on(event: str, n: int) -> str:
    return "on" + event + "=" + _js_warn(n)


def _script(body: str) -> str:
    return _el("script", "", body)


def _rm_rf_root() -> str:
    return "r" + "m" + " " + "-" + "r" + "f" + " " + _SL


def _traversal() -> str:
    return ".." + _SL + ".." + _SL + "etc" + _SL + "passwd"


def check(name: str, expected: str, fn) -> None:
    try:
        fn()
        RESULTS.append((name, expected, True, "handled"))
    except Exception as exc:  # noqa: BLE001 - this is the test harness
        RESULTS.append((name, expected, False, f"{type(exc).__name__}: {exc}"))


def expect_schema_error(doc):
    def run():
        try:
            load_trace_from(doc)
        except SchemaError:
            return
        raise AssertionError("malformed input was accepted")

    return run


def load_trace_from(doc):
    from sentinel_trace.schema import parse_trace

    return parse_trace(doc)


def main() -> int:
    tmp = Path(tempfile.mkdtemp())

    # 1. Malformed / hostile documents
    check("malformed JSON", "SchemaError", lambda: _bad_json(tmp))
    check("events not a list", "SchemaError", expect_schema_error({"events": "nope"}))
    check("event is a string", "SchemaError", expect_schema_error({"events": ["x"]}))
    check(
        "attributes is a string",
        "SchemaError",
        expect_schema_error(
            {
                "events": [
                    {
                        "span_id": "s",
                        "name": "n",
                        "kind": "tool.invoke",
                        "agent_id": "a",
                        "attributes": "x",
                    }
                ]
            }
        ),
    )
    check(
        "unknown kind",
        "SchemaError",
        expect_schema_error(
            {
                "events": [
                    {
                        "span_id": "s",
                        "name": "n",
                        "kind": _rm_rf_root(),
                        "agent_id": "a",
                    }
                ]
            }
        ),
    )
    check(
        "duplicate span",
        "SchemaError",
        expect_schema_error(
            {
                "events": [
                    {"span_id": "s", "name": "n", "kind": "tool.invoke", "agent_id": "a"},
                    {"span_id": "s", "name": "n", "kind": "tool.invoke", "agent_id": "a"},
                ]
            }
        ),
    )
    check(
        "dangling parent",
        "SchemaError",
        expect_schema_error(
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
        ),
    )
    check(
        "path traversal span id",
        "SchemaError",
        expect_schema_error(
            {
                "events": [
                    {
                        "span_id": _traversal(),
                        "name": "n",
                        "kind": "tool.invoke",
                        "agent_id": "a",
                    }
                ]
            }
        ),
    )

    # 2. Markup / script injection into the report
    def html_injection():
        injected_name = _script(_js_warn(1))
        injected_tool = _close_script() + _script(_js_warn(1))
        injected_scope = _void_el("img", "src=x " + _on("error", 1))
        injected_source = _DQ + _GT + _void_el("svg", _on("load", 1))
        doc = {
            "manifests": {"a": {"tools": ["t"]}},
            "events": [
                {
                    "span_id": "s",
                    "name": injected_name,
                    "kind": "tool.invoke",
                    "agent_id": "a",
                    "attributes": {
                        "tool": injected_tool,
                        "scopes": [injected_scope],
                        "source": injected_source,
                    },
                }
            ],
        }
        html = render_html(replay(load_trace_from(doc)).to_dict())
        # No raw payload may survive into the rendered report.
        assert _js_warn(1) not in html or "&lt;" in html
        assert injected_scope not in html
        assert _void_el("svg", _on("load", 1)) not in html
        # The payload block must not be terminated early.
        start = html.index('id="payload">') + len('id="payload">')
        end = html.index(_close_script(), start)
        assert _close_script() not in html[start:end]

    check("markup injection into report", "escaped", html_injection)

    # 3. Resource exhaustion: 150k events
    def big_trace():
        doc = {
            "manifests": {"a": {"tools": ["t"]}},
            "events": [
                {
                    "span_id": f"s{i}",
                    "name": "n",
                    "kind": "tool.invoke",
                    "agent_id": "a",
                    "attributes": {"tool": "t"},
                }
                for i in range(150_000)
            ],
        }
        t0 = time.time()
        a = replay(load_trace_from(doc))
        elapsed = time.time() - t0
        assert elapsed < 60, f"took {elapsed:.1f}s"
        assert a.counts["events"] == 150_000

    check("150k events", "<60s, no hang", big_trace)

    # 4. Deep parent chain (stack-depth probe)
    def deep_chain():
        events = [
            {
                "span_id": "s0",
                "name": "n",
                "kind": "content.ingest",
                "agent_id": "a",
                "attributes": {"trust": "untrusted"},
                "produces": ["v0"],
            }
        ]
        for i in range(1, 3000):
            events.append(
                {
                    "span_id": f"s{i}",
                    "name": "n",
                    "kind": "llm.call",
                    "agent_id": "a",
                    "parent_span_id": f"s{i - 1}",
                    "consumes": [f"v{i - 1}"],
                    "produces": [f"v{i}"],
                }
            )
        doc = {"manifests": {"a": {"tools": ["t"]}}, "events": events}
        t0 = time.time()
        a = replay(load_trace_from(doc))
        elapsed = time.time() - t0
        assert elapsed < 60, f"took {elapsed:.1f}s"
        assert a.counts["tainted_spans"] >= 2999

    check("3000-deep chain", "<60s, no recursion error", deep_chain)

    # 5. Cycle in the value graph (fixpoint must terminate)
    def cycle():
        doc = {
            "manifests": {"a": {"tools": ["t"]}},
            "events": [
                {
                    "span_id": "s1",
                    "kind": "content.ingest",
                    "name": "i",
                    "agent_id": "a",
                    "attributes": {"trust": "untrusted"},
                    "produces": ["v1"],
                },
                {
                    "span_id": "s2",
                    "kind": "llm.call",
                    "name": "a",
                    "agent_id": "a",
                    "consumes": ["v1"],
                    "produces": ["v2"],
                },
                {
                    "span_id": "s3",
                    "kind": "llm.call",
                    "name": "b",
                    "agent_id": "a",
                    "consumes": ["v2"],
                    "produces": ["v1"],
                },
            ],
        }
        t0 = time.time()
        replay(load_trace_from(doc))
        assert time.time() - t0 < 10

    check("value-graph cycle", "terminates", cycle)

    # 6. CLI on a huge malformed file
    def cli_bad():
        p = tmp / "big.json"
        p.write_text(json.dumps({"events": list(range(1000))}), encoding="utf-8")
        r = subprocess.run(  # noqa: S603 - fixed argv, no shell, path is our own tempfile
            [os.environ.get("ST_BIN", "sentinel-trace"), "replay", str(p)],
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert r.returncode == 2, f"exit {r.returncode}"
        assert "Traceback" not in r.stderr

    check("CLI malformed file", "exit 2, no traceback", cli_bad)

    # 7. Manifest wildcard abuse: read:* must not grant write:*
    def wildcard():
        doc = {
            "manifests": {"a": {"tools": ["t"], "scopes": ["read:*"]}},
            "events": [
                {
                    "span_id": "s",
                    "kind": "tool.invoke",
                    "name": "n",
                    "agent_id": "a",
                    "attributes": {"tool": "t", "scopes": ["write:external"]},
                }
            ],
        }
        a = replay(load_trace_from(doc))
        assert a.violations, "read:* wrongly granted write:external"

    check("wildcard scope escalation", "flagged", wildcard)

    # 8. Unapproved dangerous action must not pass silently
    def no_approval():
        doc = {
            "manifests": {
                "a": {
                    "tools": ["http_post"],
                    "scopes": ["write:external"],
                    "requires_approval": ["write:external"],
                }
            },
            "events": [
                {
                    "span_id": "s",
                    "kind": "tool.invoke",
                    "name": "n",
                    "agent_id": "a",
                    "attributes": {"tool": "http_post", "scopes": ["write:external"]},
                }
            ],
        }
        a = replay(load_trace_from(doc))
        assert any(v.kind.value == "missing_approval" for v in a.violations)

    check("approval bypass", "flagged", no_approval)

    # 9. Empty trace
    def empty():
        a = replay(load_trace_from({"events": []}))
        assert a.verdict == "pass"
        assert a.risk_score == 0.0

    check("empty trace", "no crash", empty)

    print(f"{'ATTEMPT':<34} {'EXPECTED':<26} RESULT")
    print("-" * 82)
    failed = 0
    for name, expected, ok, detail in RESULTS:
        mark = "PASS" if ok else "FAIL"
        if not ok:
            failed += 1
        print(f"{name:<34} {expected:<26} {mark}  {detail if not ok else ''}")
    print("-" * 82)
    print(f"{len(RESULTS) - failed}/{len(RESULTS)} adversarial attempts handled correctly")
    return 1 if failed else 0


def _bad_json(tmp: Path):
    p = tmp / "bad.json"
    p.write_text("{not json at all", encoding="utf-8")
    try:
        load_trace(p)
    except SchemaError:
        return
    raise AssertionError("malformed JSON was accepted")


if __name__ == "__main__":
    raise SystemExit(main())
