# Philosophy

## Opinionated where it must be, configurable where it matters

Lucius is opinionated by design, but not prescriptive in outcomes.

The system enforces opinions only where they materially reduce risk, ambiguity, or operational drag. Examples include constrained rule semantics, bounded execution paths, and deliberate limits on certain forms of pattern matching or analysis that historically lead to brittle or misleading results.

Outside of those guardrails, Lucius is designed for maximal operator control. Sanitization, analysis depth, scoring thresholds, escalation criteria, and downstream handling are all explicitly configured by the user.

This balance is intentional:
- Opinionated design exists to preserve throughput, clarity, and safety
- Configuration exists to preserve agency, adaptability, and trust

Lucius does not attempt to encode "best practices." It encodes hard constraints and leaves judgment to the operator.

---

## Code as configuration

Lucius adopts the same code-as-configuration ethos as Ben.

Configuration is not treated as opaque text blobs or permissive string-based rules. Instead, Lucius favors typed, versioned, and compile-checked definitions wherever possible.

The guiding principle is simple:

> If it compiles, it runs. If it runs, it behaves deterministically.

This philosophy directly informs the design of Lucius' DSLs, including rule definition, metadata, classification hints, and analysis declarations. String configuration is minimized to reduce error surface area, ambiguity, and runtime surprises.

Where DSLs exist, they are first-class artifacts and are expected to evolve alongside the system. Lucius explicitly rejects "just write strings" approaches when they undermine correctness or operator confidence.

---

## Free and open, by necessity and not ideology

The "Light Scrub" portion of Lucius is free and open source. **Luxamen** is the closed source VM orchestration and detonation system.

This is not a philosophical stance about software freedom for its own sake. It is a practical requirement for the class of organizations Lucius is designed to serve.

Sanitization and forensic systems sit in a position of extreme trust. Operators must be able to inspect behavior, reason about failure modes, and verify invariants without relying on vendor assurances.

Opacity in this layer is a liability.

Open design enables:
- Auditable behavior
- Reproducible analysis
- Meaningful external critique
- Long-term trust in the system's guarantees

---

## Intent is durable; heuristics are tools

Lucius is intent-driven, not heuristic-driven.

Heuristics, signatures, statistical signals, and classifiers are treated as tools, not authorities. They inform decisions, but they do not define the system's purpose or bounds.

Declared intent-what the operator is trying to achieve, tolerate, or prevent-is treated as the most durable input. Heuristics operate within that intent, never in place of it.

This distinction matters because:
- Heuristics decay
- Adversaries adapt
- Intent remains stable across contexts

Lucius is designed to respect that hierarchy.

---

## Bounded autonomy, not blind refusal

Unlike Ben, Lucius cannot always refuse to act. It exists in adversarial contexts where novel or malformed inputs are expected and must be handled.

However, autonomy is explicitly bounded.

Lucius may:
- Execute analysis
- Enrich artifacts
- Escalate suspicion
- Route data for deeper inspection
- Emit declared signals to Ben

Lucius may not:
- Perform irreversible actions outside declared bounds
- Hide uncertainty
- Invent confidence where none exists

Every autonomous action is tied to:
- Declared intent
- Observable inputs
- Explicit reasoning
- Recorded outcomes

Autonomy exists to handle novelty; not to replace operator judgment.

---

## Operator intent is paramount, even when incomplete

Lucius does not assume that operators can specify every edge case in advance. That expectation is unrealistic in adversarial environments.

Instead, Lucius is designed to:
- Operate safely when intent is partial
- Defer when confidence is low
- Accumulate context across stages
- Surface uncertainty rather than masking it

When defaults exist, they are conservative and transparent. They are never treated as hidden policy.

Intent may be incomplete, but it is never ignored.

---

## Failure is explicit, recorded, and explainable

Lucius treats failure as a first-class outcome.

Failures, whether analytical, operational, or environmental are:
- Explicitly recorded
- Timestamped
- Contextualized
- Preserved for later reasoning

There is no silent dropping, no best-effort ambiguity, and no invisible recovery paths. Every artifact that enters Lucius leaves behind an auditable trail, even when rejected or discarded.

This is foundational to Lucius' role as a forensic system.

---

## No drift, only versioned change

Lucius rejects implicit drift.

All meaningful behavior is versioned:
- Rules
- DSLs
- Scoring logic
- Analysis pathways
- Thresholds

Behavior changes occur through explicit version transitions, never silent mutation. This allows operators to reason about historical outcomes, replay decisions, and understand why a result differed across time.

Drift is treated as a failure mode, not an inevitability.
