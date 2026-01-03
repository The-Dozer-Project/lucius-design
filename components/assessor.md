# Assessor

## Role

Assessor is a **binary gatekeeper**, not an interpreter.

Its sole responsibility is to answer one question:

> Is this artifact worth escalating to a more expensive or invasive analysis stage?

Assessor does not score, enrich, classify, or act. It only decides whether escalation is warranted based on declared thresholds and accumulated evidence.

---

## Inputs

Assessor consumes **existing signals and hints** emitted by upstream components. It does not generate new information.

### Signals
- Typed, enumerated factual observations
- Emitted by components such as:
  - `lstran` (structural analysis)
  - `lyara` (pattern matching)
- Signals are authoritative observations, not interpretations

### Risk Hints
- Contextual bias indicators (e.g. `ActiveContent`, `ObfuscationLikely`)
- Influence escalation decisions but never assert maliciousness

### Component-Local Scores
- Optional, delineated subtotals such as:
  - `lstran_score`
  - `lyara_score`
- Scores are read-only inputs; Assessor does not compute or normalize them

---

## Decision Model

Assessor emits a **binary decision**:

- `allow_static_analysis = true`
- `allow_static_analysis = false`

The decision is accompanied by an explicit rationale describing:
- Which thresholds were evaluated
- Which signals or hints contributed
- Why escalation was allowed or denied

All rationale is forwarded to Notary for auditability.

---

## Threshold Semantics

Thresholds are:
- Explicit
- Monotonic
- Bound to declared operator intent

Valid threshold inputs include:
- Accumulated score ranges
- Presence of specific high-confidence signals
- Combinations of risk hints and corroborating evidence
- Explicit operator directives (e.g. “always escalate executables”)

Assessor does **not** perform fuzzy reasoning, confidence tuning, or interpretive judgment.

---

## Authority Boundaries

Assessor **may**:
- Read signals and risk hints
- Compare values against declared thresholds
- Emit a binary escalation decision
- Provide explicit reasoning for that decision

Assessor **may not**:
- Modify scores
- Invent signals
- Trigger actions
- Override operator intent
- Persist final outcomes

If Assessor begins to interpret meaning, it has exceeded its mandate.

---

## Failure Philosophy

Assessor is fail-soft but explicit:

- Missing inputs result in conservative decisions with annotations
- Partial data results in decisions with confidence caveats
- Internal errors deny escalation and are explicitly recorded

Assessor never silently blocks or silently escalates.

---

## Design Intent

Assessor exists to:
- Keep expensive analysis stages earned
- Prevent analysis sprawl
- Preserve determinism
- Make escalation explainable
- Maintain strict separation of responsibility

Assessor is intentionally simple to prevent it from evolving into a second interpretation engine.