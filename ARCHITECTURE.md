# Sentinel Trace — Architecture

**Author:** kk (kkdev9715) · **Version:** 0.1.0 · **License:** Proprietary, All Rights Reserved

---

## 1. The design decision that shapes everything

Most agent-security tooling is built on **detection**: classify the prompt, score the content,
block the request. Sentinel Trace is built on **authority**: declare what the agent may do, then
prove from the trace whether it stayed inside that boundary.

This is not a stylistic preference. It follows from the base rate. Prompt injection is
adversarial and open-ended; a detector that is 95% accurate still fails on the 5% that matter,
and it fails *silently* — the agent proceeds, and nothing records that a boundary was crossed.
Authority comparison has no such failure mode: either the trace shows a tool call outside the
declared set or it does not. It is decidable from evidence.

The consequence is that Sentinel Trace is **complementary** to a prompt firewall. The firewall
tries to stop the injection. Sentinel Trace proves what the agent was authorised to do when the
firewall fails — and gives you a CI gate so the authority boundary cannot silently widen.

---

## 2. Pipeline

```
trace JSON ──► schema.parse_trace ──► Trace
                                        │
                    ┌───────────────────┼───────────────────┐
                    ▼                   ▼                   ▼
              authority.check_trace  taint.propagate   (manifests)
                    │                   │
                    │                   ▼
                    │            taint.reconstruct_paths
                    │                   │
                    └─────────┬─────────┘
                              ▼
                    blast.score_trace
                              │
                              ▼
                    replay.replay ──► Assessment ──► report_html / CLI
```

Each stage is independently testable and has no hidden coupling. `replay()` is the only
orchestrator; everything else is a pure function of its inputs.

---

## 3. Module responsibilities

### `model.py` — the domain

`AgentEvent`, `AuthorityManifest`, `Trace`, and the severity tables. The severity tables
(`SCOPE_SEVERITY`, `DATA_CLASS_SENSITIVITY`) are the tool's opinion about what matters, and they
are deliberately explicit and auditable rather than learned. An unknown scope falls back to its
namespace prefix, then to a conservative default of 0.50 — **an unrecognised scope is treated as
more dangerous than a known-benign one, never less.**

### `schema.py` — validation first

Parsing is strict and happens before any analysis. A security tool that silently accepts a
malformed trace will confidently report the wrong answer. The parser accepts both snake_case and
OpenTelemetry camelCase keys, so traces from existing collectors work unchanged. Hard caps:
200,000 events, 64 MB file — a trace is attacker-influenced input, and an unbounded one is a
denial-of-service vector.

### `authority.py` — declared vs actual

`check_event` compares one actionable event against one manifest and returns every way it
exceeded authority. Only `tool.invoke`, `memory.write`, and `agent.spawn` are actionable — an
`llm.call` cannot exceed authority because it does not *do* anything.

`authority_score` is the subtle part. It is **not** a mean and **not** a sum:

```
score = worst_violation + 0.30 × (1 − e^(−sum_of_rest))
```

A mean would let one catastrophic violation be diluted by fifty trivial ones — the exact failure
mode that makes security dashboards useless. A sum would let a long tail of trivia outrank a
single catastrophe. The worst violation dominates; the rest add a bounded bonus.

### `taint.py` — influence tracking

A forward fixpoint over the value graph. Seeded by untrusted `content.ingest` events; a value is
tainted if any producer is tainted, an event is tainted if any consumed value is tainted. The
loop is bounded by the event count, since each pass can only add taint, never remove it.

`reconstruct_paths` runs BFS over a graph whose edges are (a) value production→consumption and
(b) parent→child span. Shortest paths are reported because the shortest chain is the most
defensible explanation.

**The propagation is conservative by design.** If a value *could* carry untrusted influence, it
is marked as carrying it. Under-approximating would mean missing real hijacks, which is the
worse error for a security tool.

### `blast.py` — impact scoring

Four independent dimensions — scope severity (40%), data sensitivity (30%), reach (20%), volume
(10%) — then multipliers for irreversible (×1.35), external (×1.25), and tainted (×1.30). The
weighting means no single dimension can carry the score: a `read:public` on a public page is low
even if it is external, and a `money:transfer` is high even if it is internal.

### `replay.py` — orchestration and verdict

```
risk = max(authority_exceeded, relevant_blast_radius)
     + 0.25 × min(authority_exceeded, relevant_blast_radius)
```

**`relevant_blast_radius` is the key refinement.** It is the highest blast radius among actions
that *violated authority or carried untrusted influence* — not the highest overall. A large
blast radius on a permitted, untainted action is not risk; the agent was allowed to do it. This
is the difference between reporting danger and reporting *unauthorised* danger.

The formula was calibrated against the corpus. A geometric blend was tried first and rejected:
it collapsed two moderate signals (50, 50) to 25, so an agent acting with **no declared
authority** on an external write scored "pass". Under-reporting a governance failure is the
worse error for a gate, so the formula was changed and the decision locked in with a test.

### `corpus.py` — the CI gate

Labelled traces with expected verdicts, risk ranges, and required violation kinds. An **empty
corpus is a failure, not a pass** — a gate that cannot fail is not a gate. A bare trace file
with no expectations is treated as a smoke case (`expected_verdict: "any"`), because labelling
it "pass" would be a lie for a malicious trace and "fail" a lie for a benign one.

### `report_html.py` — the report

Self-contained: no CDN, no external fonts, no network requests. The payload is embedded as
escaped JSON (`<`, `>`, `&` escaped so a value containing `</script>` cannot terminate the block
early) and the DOM is built with `textContent` only. `innerHTML` is never used, so a trace
containing HTML cannot inject markup into the report.

---

## 4. What was deliberately not built

- **No runtime proxy.** Sitting in the request path makes the tool a availability risk and
  requires a latency budget it cannot meet. Analysis and CI are where the value is.
- **No ML.** Every score is a documented formula. A security tool whose verdicts cannot be
  explained to an auditor is a security tool that will not be trusted.
- **No agent instrumentation.** Emitting OTel spans from LangChain/LangGraph/CrewAI is a
  separate, larger build. The schema is OTel-shaped precisely so that build is additive.
- **No persistence.** Traces in, assessment out. Storage is a deployment concern.

---

## 5. Extension points

| Want to… | Do this |
|---|---|
| Add a scope or data class | Add an entry to the table in `model.py` |
| Add a violation kind | Add to `ViolationKind` and `VIOLATION_WEIGHT`, handle in `check_event` |
| Change the risk formula | Edit `Assessment.risk_score`; the corpus will tell you if you broke calibration |
| Add a corpus case | Drop a JSON file in `corpus/` with `expected_verdict` and `must_flag` |
| Emit from a new framework | Produce the documented JSON; no code change needed |

---

**Sentinel Trace** · Copyright (c) 2026 kk (kkdev9715) · All Rights Reserved · Proprietary
