# Lucius Declarative Language (DSL)

## Overview

Lucius uses a **declarative, compile-time enforced language contract** to express **conditions over observed facts** and **actions to take when those conditions hold**.

The Lucius DSL is **not a standalone programming language** and **not a scripting engine**.  
It is a **rule and intent language** designed to remain legible, auditable, and deterministic in adversarial environments.

Although originally developed for Lucius, this DSL is designed to be **shared across Ben components** (proxy, sidecars, detectors, orchestrator), with Lucius providing **additional domain-specific extensions**.

The DSL defines *what may be expressed*.  
Each consuming component defines *what actions are legal* and *how they execute*.

This separation is intentional and foundational.

---

## Design Goals

The Lucius DSL exists to:

- Express conditions over system facts in a uniform way
- Avoid stringly-typed, ad-hoc configuration
- Preserve determinism, replayability, and auditability
- Keep execution semantics explicit and bounded
- Allow extensibility without turning into a scripting language
- Remain reusable across multiple Ben components

The language prioritizes **clarity over cleverness** and **constraints over expressiveness**.

---

## Non-Goals

The Lucius DSL is **not**:

- A runtime scripting language
- Turing complete
- An expression language
- A metrics or telemetry system
- A general configuration format
- A place to embed arbitrary computation

All computation occurs **outside** the DSL, in explicitly defined providers and executors.

---

## Core Concept: Observations

### What Is an Observation?

An **observation** is a named, typed fact that the system promises to provide at evaluation time.

Examples:
- `cpu_utilization`
- `queue_depth`
- `retry_rate`
- `SuspiciousEntropy`

Observations are **not computed in the DSL**.  
They are **provided by the surrounding system** via observation providers.

Rules may reference observations, but never define how they are produced.

> **Rules compare observed facts.  
> Systems decide how those facts are obtained.**

---

### Observation Providers (Out of Scope for the DSL)

Observation providers:
- May be native (high-throughput, platform-specific)
- May be WASM-based (portable, sandboxed)
- Own all platform, cost, and computation concerns

The DSL only depends on observation *names* and *types*.

---

## Rules

A rule consists of:
- A **condition** over observations
- One or more **actions** to perform when the condition holds

Conceptually:
```
when 
then 
```

Rules are declarative.  
They describe *what must be true* and *what should happen*, not *how* it happens.

---

## Conditions

Conditions are **pure boolean expressions** over observations.

### Boolean Composition
```
and
or
not
all(…)
any(…)
```

These operators:
- Do not introduce control flow
- Do not mutate state
- Do not evaluate code

They only combine truth values.

---

### Comparisons

Conditions may compare observations using:
```
<  <=  >  >=  ==  !=
```
Both sides of a comparison are **observations or constants**.

Examples:
```
cpu_utilization > cpu_threshold
queue_depth >= 0.8
retry_rate != baseline_retry_rate
```
All comparison semantics are resolved at evaluation time by the consuming component.

---

### Temporal Guards

Conditions may include temporal persistence constraints such as:
```
for 2 cycles
```
These modifiers express **stability requirements**, not iteration or loops.

Temporal guards are part of the condition, not actions.

---

## Actions

### Actions Are Intent, Not Meaning

Actions express **what should happen when a condition holds**.

The DSL does **not** define what an action does.
That is the responsibility of the consuming component.

---

### Action Kinds

At the DSL level, actions are classified only by **execution timing**:

- **Immediate actions** - executed as soon as the rule fires
- **Deferred actions** - recorded for later execution or mediation

The DSL does not encode domain-specific action semantics.
Action kewyword
```
run
```

---

### Component Responsibilities
- #### Ben
    - **Proxy / Sidecar / Detector**
        - Support **immediate actions only**
        - Execute actions synchronously
        - Do not defer intent

- **Lucius**
  - Supports **deferred actions**
  - Records durable intent (plans)
  - May expose resulting state as observations

Deferred actions are **Lucius-specific** and are not universal.

---

## Action Arguments

Actions may accept arguments.

Arguments are restricted to:
- References to observations
- Literal constants

No expressions, arithmetic, or computation is permitted.

This preserves determinism and prevents hidden logic.

---

## Emit Actions

Actions accept no argument and are bound to explicit intent declared in Ben.
Emits only emit enum idents. They are not observations and they do not include arbitrary code.
Emits correlate to playbooks within the detectors and are declared within the ben configuration crate 
via a proc macro.

```

## Macro Families

Lucius is implemented through **domain-specific declarative proc macros**, each enforcing a bounded subset of the DSL.

Each macro:
- Accepts only domain-appropriate constructs
- Rejects invalid constructs at compile time
- Produces typed, versioned artifacts
- Cannot express concerns outside its domain

### Example Macro Families

| Macro       | Domain Purpose |
|------------|----------------|
| `lstran!`  | Structural analysis and artifact legibility |
| `lyara!`   | Pattern-based matching and signatures |
| `lstat!`   | Statistical signals and derived metrics |
| `lstatic!` | Static analysis declarations |
| `lthreat!` | External threat correlation |

All macros share the same **underlying language contract**, even as their allowed actions differ.

---

## Determinism and Replayability

All DSL artifacts must satisfy:

- Deterministic evaluation
- Idempotent execution
- Replayable behavior
- Explicit versioning

Evaluating the same artifact under the same observations must produce the same outcome.

---

## Failure Semantics

The DSL never hides uncertainty.

- Missing observations are explicit
- Failed evaluation is surfaced
- Partial truth is preserved
- Confidence is never fabricated

Failure is a first-class outcome, not an error to be concealed.

---

## Summary

The Lucius DSL is:

- Declarative
- Observation-driven
- Compile-time enforced
- Deterministic
- Component-agnostic
- Action-oriented
- Auditable by design

It exists to make **complex system behavior legible and constrained**,  
not clever, implicit, or magical.
