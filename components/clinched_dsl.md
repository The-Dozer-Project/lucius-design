# clinched DSL

## Overview

Lucius/Ben uses a **declarative, compile-time enforced language contract** to express **conditions over observed facts** and **actions to take when those conditions hold**.

The clinched DSL is **not a standalone programming language** and **not a scripting engine**.  
It is a **rule and intent language** designed to remain legible, auditable, and deterministic in adversarial environments.

Although originally developed for Lucius, this DSL is designed to be **shared across Ben components** (proxy, sidecars, detectors, orchestrator), with Lucius providing **additional domain-specific extensions**.

The DSL defines *what may be expressed*.  
Each consuming component defines *what actions are legal* and *how they execute*.

This separation is intentional and foundational.

---

## Design Goals

The clinched DSL exists to:

- Express conditions over system facts in a uniform way
- Avoid stringly-typed, ad-hoc configuration
- Preserve determinism, replayability, and auditability
- Keep execution semantics explicit and bounded
- Allow extensibility without turning into a scripting language
- Remain reusable across multiple Ben components

The language prioritizes **clarity over cleverness** and **constraints over expressiveness**.

---

## Non-Goals

The clinched DSL is **not**:

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
<  <=  >  >=  ==  != not
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
per 2 cycles
within 2 minutes
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

### Action Providers (Out of Scope for the DSL)

#### Action providers:
- Execute or mediate intent requests emitted by Lucius
- Are registered and configured outside the DSL
- Are owned by Ben or the system control plane
- May be native (low-latency, platform-specific)
- May be WASM-based (portable, sandboxed, policy-constrained)

#### The DSL:
- Does not define what an action does
- Does not bind actions to implementations
- Does not encode policy or side effects
- Expresses only timing intent (immediate vs deferred)

---

### Component Responsibilities
- #### Ben
    - **Proxy / Sidecar / Detector**
        - Support **immediate actions and deferred actions**
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
Emits only emit enum ident and associated artifact information. They are not observations and they do not include arbitrary code.
Emits correlate to playbooks within the detectors and are declared within the ben configuration crate 
via a proc macro.


---

## from - Data Source Selection

The ```from``` keyword **declares** which data substrate an operation is **allowed** to read from.

### ```from``` is used to **make** 
- data provenance explicit
- enforce component boundaries
- preserve determinism across the Lucius and Ben ecosystems.

### ```from``` **does not** 
- invoke functions
- perform computation
- access the environment.
It selects a predefined, read-only data source provided by the enclosing component.

### Core Semantics
- from selects exactly one data source
- The data source must be declared by the component
- The data source is read-only
- The data source is bounded and deterministic
- The meaning of from is component-scoped

### ```from``` never:
- executes code
- allocates unbounded state
- mutates artifacts
- accesses external systems
- allows inline arbitrary logic


---

## ```select``` - Facet Declaration

The ```select``` clause declares which facets of a substrate are of interest to an operation.

It is purely declarative.

```select``` does not:
- Perform matching
- Evaluate truth
- Apply logic
- Produce signals
- Imply presence or absence

It exists solely to scope what data is extracted or observed from a substrate chosen by from.

### Role in the DSL

Within an operation, the execution model is:
1.	from chooses a substrate
2.	select declares facets of interest
3.	Optional operators (like, measure, decode) define how extraction occurs
4.	Results are emitted as raw observations

All reasoning happens later.

### Forms of select

1. Block form (implicit all)
- Used when all listed facets are requested.
    ```rust
    from byte_stream select {
        valid_ratio
        replacement_count
        null_byte_ratio
        control_char_ratio
        line_break_density
    }
    ```
    ### Semantics:
    - All listed facets are extracted
    - No ordering or dependency is implied
    - No logic is evaluated

    This form is equivalent to “select all of these”.


2. Set form (```any```, ```all```, ```none```)
- Used when declaring interest in a set, not asserting truth.

    ```rust
    from export_table select any(
        "DllRegisterServer",
        "ServiceMain",
        "ReflectiveLoader"
    )
    ```

    ### Semantics:
    - Declares a set of items the operation should look for
    - Whether any/all/none are present is determined later
    - Presence is evaluated only in signals or clinch

    #### Allowed qualifiers:
    - ```any(...)``` - interest if at least one appears
    - ```all(...)``` - interest only if all appear
    - ```none(...)``` - interest in confirmed absence (still factual)

    These are selection qualifiers, not logical conditions.

### What ```select``` May Reference

#### ```select``` may reference:
- Lucius-provided facets
- e.g. valid_ratio, entropy, has_overlay
- Provider-defined observations
- surfaced by structural, static, or normalization components
- Literal identifiers
- strings, symbols, tokens, opcodes, etc.

#### ```select``` may not:
- Combine facets with boolean logic
- Compare values
- Reference signals
- Reference score, tags, or outcomes


### Relationship to Operators

```select``` is orthogonal to operators.

### Examples:
#### Facet extraction
```rust
from byte_stream select {
    valid_ratio
    null_byte_ratio
}
```

---

### Pattern operator ```like```

```like``` is akin to "match". ```like``` is purely to match from a data substrate.

```rust
from byte_stream like bytes {
    value  = { 25 50 44 46 }
    offset = 0
}
```

#### Measurement operator ```measure```

```measure``` is purely to measure from a data substrate.

```rust
from byte_stream measure entropy {
    window_size = 256
}
```

These may appear independently or together, but their roles never overlap.

### Design Invariant

```select``` scopes interest.
Operators extract.
when reasons.

Keeping ```select``` free of logic preserves determinism, prevents ambiguity, and allows operations to remain reusable across components (Lucius, Ben, future DSLs).


---

## meta
### Purpose: 
- Identity
- audit
- applicability.
-   Declares what this macro is
-   Provides versioning and provenance
-   Enables replay, diffing, and governance

### Properties:
-   No logic
-   No conditionals
-   No access to data
-   No behavioral impact

### Invariant:
>**meta** may never influence execution or reasoning.

---

## operations

### Purpose: 
Declare the bounded work this component is allowed to perform.
-   Defines what kinds of inspection or correlation are permitted
-   Establishes hard limits and scope
-   Surfaces raw, structured results

### Properties:
-   Deterministic
-   Bounded
-   Component-specific
-   No interpretation
-   No scoring
-   No intent

### Invariant:
>**operations** describe capability, not meaning.

---

## signals
### Purpose: 
Define facts derived from **operations**.
-   Typed, explicit observations
-   Boolean or bounded numeric
-   Namespaced and structured
-   Documented and auditable

### Properties:
-   Derived only from **operations**
-   Carry no verdict or authority
-   Stable inputs for downstream reasoning

### Invariant:

>**signals** are true or false, not good or bad.

---

## clinch

### Purpose: 
Express consequences of observed facts.
-   Accumulate score (where allowed)
-   Attach tags
-   Promote or combine **signals**
-   Request escalation or downstream intent

### Properties:
-   No new data extraction
-   No hidden execution
-   No back-edges
-   No environment access

### Invariant:
>**clinch** reasons over facts; it does not create them.



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

The Lucius/Ben DSL is:

- Declarative
- Observation-driven
- Compile-time enforced
- Deterministic
- Component-agnostic
- Action-oriented
- Auditable by design

It exists to make **complex system behavior legible and constrained**,  
not clever, implicit, or magical.
