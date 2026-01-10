# Lucius macros overview

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
**meta** may never influence execution or reasoning.

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
**operations** describe capability, not meaning.

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

**signals** are true or false, not good or bad.

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
**clinch** reasons over facts; it does not create them.