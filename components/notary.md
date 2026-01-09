## Notary - Component Overview

The Notary is the **recording and coordination backbone** of Lucius’ enrichment pipeline. It exists to ensure that every artifact moving through the system leaves behind an explicit, auditable trail, regardless of outcome.

---

### Purpose
The Notary is responsible for:
- Accreting metadata, signals, risk hints, and scores emitted by upstream components
- Recording the progression of an artifact through each stage
- Coordinating handoff between stages to prevent uncontrolled backpressure
- Ensuring that rejection, deferral, or completion is **explicitly logged**

The Notary is deliberately *boring*. Its value comes from consistency, not intelligence.

---

### What the Notary Does
- Acts as the central ledger for per-artifact enrichment state
- Records:
  - Which components ran
  - What they emitted
  - When decisions were made
- Passes artifacts forward in a controlled, sequential manner
- Handles artifact rejection as a **first-class recorded outcome**
- Provides the data foundation for final interpretation and forensic replay

---

### What the Notary Does Not Do
- Make policy decisions outside rejection
- Interpret risk or intent
- Assign meaning to signals or tags
- Execute actions
- Modify artifacts
- Apply heuristics or thresholds

The Notary only reasons about rejection.

---

### Rejection Handling
Rejection is treated as an **explicit system outcome**, not an error path.

When an artifact is rejected:
- The rejection reason is recorded
- The artifact still proceeds to finalization for persistence
- No silent drops or implicit loss occur

Rejection logic is implemented internally and intentionally **not configurable**. This avoids introducing a policy surface where consistency and correctness matter more than flexibility.

---

### Emit handling
Emits are explicitly declared in Ben. Emits are only bound to sending immediate signals to Ben concerning data that need
to have an action happen when crossing a certain threshold

When an emission happens:
- Emit is bounded to declared intent.
- Artifact proceeds to allow for information propagation.
- Emissions are explicity recorded

Notary emissions **do not** allow for arbitrary code nor are they observations.

```

### Authority Model
The Notary has **no authority** outside rejection.

It cannot:
- Escalate
- Downgrade
- Override
- Infer intent

Its authority is limited to bookkeeping and coordination.

---

### Failure Philosophy
- Failure is expected and recorded
- Partial progress is preserved via snapshots
- On restart, the Notary resumes from known-good state
- No artifact is lost without an auditable record

---

### Design Invariant
If an artifact passed through Lucius, the Notary can explain **exactly how and why** it moved, or stopped.

This makes Lucius defensible, debuggable, and trustworthy in adversarial environments.