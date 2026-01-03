# Lucius Declarative Language (DSL)

## Overview

Lucius uses a **declarative, compile-time language contract** to express intent, evidence, scoring semantics, and escalation boundaries across the sanitization pipeline.

This is **not a single monolithic DSL**.  
Instead, Lucius defines a **shared semantic language** that is enforced by a family of **domain-specific declarative proc macros**, each scoped to a specific analysis domain.

The DSL defines *what can be expressed*.  
Each macro defines *where it can be expressed*.

This separation is intentional and foundational to Lucius’ safety, clarity, and extensibility.

---

## Design Goals

The Lucius DSL exists to:

- Minimize error-prone, stringly-typed configuration
- Enforce domain boundaries at compile time
- Preserve determinism and replayability
- Make operator intent explicit and durable
- Enable static reasoning about system behavior
- Remain extensible without becoming opaque

The language prioritizes **clarity over cleverness** and **explicitness over convenience**.

---

## Non-Goals

The Lucius DSL is **not**:

- A runtime scripting language
- Turing complete
- A policy engine with implicit behavior
- A generic configuration format
- A replacement for operator judgment
- A mechanism for hidden automation

Any future scripting or programmable behavior would exist as a **separate, explicit system** that consumes Lucius outputs rather than replacing the DSL.

---

## Macro Families

Lucius is implemented through multiple declarative proc macros, each enforcing a bounded subset of the DSL.

Each macro:
- Accepts only domain-appropriate constructs
- Rejects invalid constructs at compile time
- Produces typed, versioned artifacts
- Cannot express concerns outside its domain

### Current Macro Families

| Macro        | Domain Purpose |
|-------------|----------------|
| `lstran!`  | Structural analysis and artifact legibility |
| `lyara!`    | Pattern-based matching and signatures |
| `lstat!`    | Statistical signals and derived metrics |
| `lstatic!`  | Static analysis declarations |
| `lthreat!`  | External threat feed correlation |

Macros may evolve independently, but all remain bound to the same underlying language contract.

---

## Shared Language Contract

The following constructs form the **shared grammar** of the Lucius DSL.  
They are available only where permitted by the enclosing macro.

### Keywords

```
when
and
or
not
all(...)
any(...)
count
range
score
tag
enact
action
```

These keywords are **declarative only**.  
They describe intent and conditions, not procedural control flow.

Action do not perform work. They express authorization.

---

## Determinism and Idempotency

All DSL artifacts must satisfy:

- Deterministic evaluation
- Idempotent execution
- Replayability
- Versioned behavior

If the same artifact is evaluated twice under the same inputs, it must produce the same outputs.

---

## Failure Semantics

The DSL never hides uncertainty.

- Missing data is explicit
- Failed evaluation is recorded
- Partial results are preserved
- Confidence is never invented

Failure is a first-class outcome.

---

## Summary

The Lucius DSL is:

- Declarative
- Compile-time enforced
- Domain-bounded
- Intent-first
- Deterministic
- Auditable

It exists to make **complex adversarial handling legible**, not magical.
