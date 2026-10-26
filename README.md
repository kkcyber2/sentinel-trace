# Sentinel Trace

**Agent execution security: authority replay, blast-radius scoring, and hijack-path reconstruction.**

Sentinel Trace answers the question that agent security actually turns on:

> *Given this execution trace, what could the agent have done — and was it authorised to?*

It does **not** try to detect prompt injection. Detection of injection is unreliable, and a
security control that depends on it fails silently. Instead, Sentinel Trace assumes detection
fails and asks a question that is answerable from evidence: did the agent exceed the authority
it was declared to have, and if so, how much damage could that have caused?

Author: **kk ([kkdev9715](https://github.com/kkcyber2))**
License: **Proprietary — All Rights Reserved.** See [LICENSE](LICENSE).

---

## Why this exists

Every serious agent incident reduces to the same shape: **the agent had a tool it did not need,
scoped wider than the task required, with no approval gate.** The trace of that incident exists
— but there is no tooling to *see* it, because:

- Agent traces are JSON blobs with no canonical schema. A tool call is not an EDR event.
- Prompt firewalls try to detect injection, which is a detection problem with a bad base rate.
- Nothing compares what an agent *did* against what it was *declared* to be allowed to do.
- There is no CI for agent safety: a prompt edit or a tool-scope widening can silently grant
  authority, and nothing fails the build.

Sentinel Trace closes that gap with four pieces:

1. **A declarative authority manifest per agent** — which tools, which scopes, which data
   classes, which actions require human approval.
2. **Trace replay against the manifest** — every action that exceeded declared authority,
   ranked by blast radius.
3. **Injection-path reconstruction** — walk back from a dangerous tool call through the
   untrusted content that influenced it, transitively.
4. **A corpus gate for CI** — a labelled set of traces; a change that widens authority fails
   the build.

---

## Install

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
```

Requires Python 3.10+. **Zero runtime dependencies** — the engine, the CLI, and the HTML report
are all standard library.

## Use

```bash
# Assess a trace
sentinel-trace replay examples/hijack-exfiltration.json

# Machine-readable plus a self-contained HTML report (no CDN, no network)
sentinel-trace replay examples/hijack-exfiltration.json --out r.json --html r.html

# Structural validation only
sentinel-trace validate examples/clean-run.json

# CI gate: run the adversarial corpus
sentinel-trace corpus corpus
```

Example output on the bundled hijack trace:

```
Sentinel Trace 0.1.0 — examples/hijack-exfiltration.json
  events            4
  violations        7
  tainted spans     4
  injection paths   1
  authority exceeded 100.0/100
  max blast radius  100.0/100
  risk score        100.0/100  [critical]
  verdict           FAIL

  top violations
   - undeclared_tool: tool 'read_file' is not in the declared tool set
   - undeclared_scope: scope(s) not declared: read:secret
   - undeclared_data_class: data class(es) not declared: credentials
   - undeclared_tool: tool 'http_post' is not in the declared tool set
   - undeclared_scope: scope(s) not declared: write:external, net:egress

  injection paths
   - https://blog.example.com/post (fetch untrusted page) -> http_post (4 hops)
```

Exit codes: `0` pass, `1` at or above the `--fail-on` verdict, `2` invalid input, `3` write
failure. `--fail-on never|warn|fail` controls the gate.

As a library:

```python
from sentinel_trace import load_trace, replay

assessment = replay(load_trace("examples/hijack-exfiltration.json"))
print(assessment.verdict, assessment.risk_score)
for v in assessment.violations:
    print(v.kind.value, v.detail)
for p in assessment.injection_paths:
    print(" -> ".join(p.hops))
```

---

## The model in one page

### Events

A trace is a list of typed spans. The vocabulary is deliberately small and closed:

| Kind | Meaning |
|---|---|
| `content.ingest` | Content enters the agent's context (a page, a file, a message) |
| `llm.call` | A model invocation |
| `tool.invoke` | A tool call — the only kind that can *do* something |
| `memory.read` / `memory.write` | Vector-store or scratchpad access |
| `agent.spawn` | A sub-agent is created |
| `approval.request` / `approval.grant` | Human-in-the-loop gate |

Each span carries `consumes` and `produces` — value identifiers. **These are what make taint
analysis possible**: an event that consumes a value produced by an untrusted ingest is itself
influenced by untrusted content, transitively.

The schema accepts both snake_case and OpenTelemetry camelCase keys (`spanId`, `parentSpanId`,
`startTimeUnixNano`), so traces from existing collectors are consumed without a bespoke
exporter.

### Authority manifests

```json
{
  "agent_id": "summariser",
  "tools": ["fetch_url", "summarise"],
  "scopes": ["read:public"],
  "data_classes": ["public"],
  "requires_approval": ["write:external", "net:egress"],
  "max_blast_radius": 40
}
```

Scopes are namespaced (`read:secret`, `write:external`, `money:transfer`, `delete:data`) and
support wildcards (`read:*`). A manifest that is hard to write is a manifest that will not be
written, so it is intentionally small.

### Violation kinds

| Kind | Meaning |
|---|---|
| `undeclared_tool` | Used a tool not in the declared set |
| `undeclared_scope` | Used a capability scope not declared |
| `undeclared_data_class` | Touched a data class not declared |
| `missing_approval` | Action required human approval; none preceded it |
| `no_manifest` | Agent acted with no declared authority at all |
| `blast_radius_exceeded` | Action exceeded the manifest's blast-radius ceiling |

### Taint propagation

A forward fixpoint over the value graph. A value is tainted if any event producing it is
tainted; an event is tainted if any value it consumes is tainted, or if it is itself an
untrusted ingest. The propagation is **deliberately conservative** — if a value *could* carry
untrusted influence, it is marked as carrying it. Under-approximating here would mean missing
real hijacks.

### Injection-path reconstruction

BFS over the event graph (value edges plus parent-child span edges), from each untrusted source
to each dangerous sink. **Shortest paths are reported**, because the shortest chain is the most
defensible explanation of how untrusted content reached a dangerous action.

### Blast radius

Four independent dimensions, weighted so no single one can carry the score:

| Dimension | Weight | Basis |
|---|---|---|
| Scope severity | 40% | Most dangerous scope used |
| Data sensitivity | 30% | Most sensitive data class touched |
| Reach | 20% | External and/or irreversible |
| Volume | 10% | Log-scaled, saturating at 10,000 |

Then multiplied: irreversible ×1.35, external ×1.25, tainted ×1.30.

### Risk score and verdict

```
risk = max(authority_exceeded, relevant_blast_radius)
     + 0.25 × min(authority_exceeded, relevant_blast_radius)
```

The worse dimension dominates; the other amplifies it by up to 25%. Verdict: `fail` ≥ 80,
`warn` ≥ 50, else `pass`.

**`relevant_blast_radius` is not `max_blast_radius`.** A large blast radius on a *permitted*,
untainted action is not risk — the agent was allowed to do it. Only actions that violated
authority or carried untrusted influence count. This distinction is the difference between a
tool that reports danger and a tool that reports *unauthorised* danger.

---

## The corpus gate

`corpus/` holds labelled traces. Each asserts an expected verdict, a risk range, and which
violation kinds must be flagged.

```bash
sentinel-trace corpus corpus
# corpus: 4/4 passed
```

Wire it into CI so a prompt or tool-scope change that widens authority fails the build:

```yaml
- run: sentinel-trace corpus corpus
```

An **empty corpus is a failure, not a pass** — a gate that cannot fail is not a gate.

---

## Repository layout

```
sentinel-trace/
├── sentinel_trace/
│   ├── model.py        typed domain model; scope/data severity tables
│   ├── schema.py       validation-first trace parsing (snake_case + OTel)
│   ├── authority.py    declared-vs-actual comparison; violation scoring
│   ├── taint.py        taint propagation; injection-path reconstruction
│   ├── blast.py        blast-radius scoring
│   ├── replay.py       orchestration; risk score and verdict
│   ├── corpus.py       adversarial corpus + CI gate
│   ├── report_html.py  dependency-free HTML report renderer
│   └── cli.py          replay / corpus / validate
├── tests/test_engine.py  72 tests
├── corpus/               labelled traces for the CI gate
├── examples/             illustrative traces
├── ARCHITECTURE.md
└── SECURITY_REPORT.md
```

---

## Honest limitations

Stated plainly, because a security tool that oversells itself is worse than a blunt one:

1. **It does not instrument agents.** You supply the trace. An OTel exporter for common agent
   frameworks is the obvious next build.
2. **It cannot see what was not traced.** If a tool call is not in the trace, it is invisible.
   Trace completeness bounds output quality.
3. **Taint is conservative, not precise.** It over-approximates influence. A value that merely
   *could* carry untrusted content is treated as carrying it, which can produce false positives
   on complex data flows.
4. **Manifests are manual.** Writing a good manifest for a complex agent is real work. The
   payoff is that the resulting verdicts are defensible.
5. **No semantic understanding of content.** It does not read the poisoned document; it tracks
   that the document influenced an action.
6. **Boolean authority.** A scope is declared or it is not. There is no partial or conditional
   grant beyond the approval gate.
7. **Not a runtime blocker.** It is an analysis and CI tool. It does not sit in the request path.

---

## Comparison

| Capability | Sentinel Trace | Lakera / prompt firewalls | LangSmith / Langfuse | OWASP Agentic guidance | Generic SIEM |
|---|---|---|---|---|---|
| Declarative authority manifest per agent | **Yes** | No | No | Concept only | No |
| Declared-vs-actual authority diff | **Yes** | No | No | No | No |
| Blast-radius scoring of actions | **Yes** | No | No | No | No |
| Transitive taint from untrusted content | **Yes** | Partial (per-prompt) | No | No | No |
| Injection-path reconstruction | **Yes** | No | No | No | No |
| CI gate on authority regression | **Yes** | No | No | No | No |
| Self-hosted, zero runtime deps | **Yes** | No | Partial | n/a | No |
| Air-gapped HTML report | **Yes** | No | No | n/a | No |
| Detects injection in the prompt | No | **Yes** | No | No | No |
| Runtime blocking | No | **Yes** | No | No | Partial |
| Full observability / tracing UI | No | No | **Yes** | No | **Yes** |
| Managed SaaS | No | **Yes** | **Yes** | n/a | **Yes** |

**Leads:** authority modelling, blast-radius scoring, transitive taint, injection-path
reconstruction, and the CI gate — none of which the adjacent categories do.
**Lags:** runtime blocking, prompt-level detection, observability breadth, and managed hosting.

Sentinel Trace is **complementary** to a prompt firewall, not a replacement: the firewall tries
to stop the injection, and Sentinel Trace proves what the agent was authorised to do when it
fails.

---

## License

Proprietary. **All Rights Reserved.** Copyright (c) 2026 kk (kkdev9715).

No use, copy, modification, distribution, or derivative work is permitted without prior written
permission from the copyright holder. Public visibility of this repository grants no license.
See [LICENSE](LICENSE) for the full terms.
