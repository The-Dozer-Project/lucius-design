## lassess (Assessor) Macro - Summary

The Assessor macro defines **when an artifact is eligible for static analysis**. It does not interpret risk, assign severity, or take action. Its sole responsibility is to make a **yes / no escalation decision** based on signals and risk hints emitted by upstream components.

---

### Purpose
The Assessor exists to protect system throughput and determinism by ensuring that **static analysis is only performed when explicitly justified**. It prevents expensive analysis from running indiscriminately while remaining fully operator-controlled.

---

### Inputs
The Assessor consumes:
- **Signals** (enumerated, factual observations)
- **Risk hints** (enumerated contextual markers)
- Source attribution from:
  - Structural analysis (`lstran`)
  - YARA analysis (`lyara`)

All inputs are strongly typed and non-arbitrary.

---

### Decision Model
The Assessor evaluates:
- Hard allow rules (immediate escalation)
- Hard deny rules (explicit non-escalation)
- Conditional allow rules based on combinations or counts

If no allow conditions are met, the artifact continues through the pipeline without static analysis.

---

### What the Assessor Does
- Determines eligibility for static analysis
- Enforces operator-declared escalation boundaries
- Applies explicit, enumerable rules
- Preserves determinism and explainability

---

### What the Assessor Does Not Do
- Assign weights or scores
- Interpret intent or severity
- Execute actions
- Modify artifacts
- Infer authority or confidence

---

### Authority Model
The Assessor has **bounded authority**:
- It may escalate or decline escalation
- It may not invent certainty
- It may not override declared intent

All meaning is derived from upstream components.

---

### Failure Philosophy
- Missing data results in non-escalation
- Internal errors are recorded and halt processing
- The Assessor never escalates on uncertainty alone

---

### Design Invariant
The Assessor decides **eligibility**, not **meaning**.

This keeps the system fast, predictable, and auditable while preserving operator control over costly analysis paths.





### Example
```rust
lassess! {
    meta {
        name        = "default_static_gate"
        version     = "0.1.0"
        author      = "org-security"
        intent      = Investigative
        description = "Escalation gate for static analysis based on upstream signals"
    }

    // Structural analysis gating
    //
    // Answers: is this artifact structurally suspicious enough
    // to justify deeper inspection?

    lstran {
        // Hard deny: things we explicitly do not escalate
        deny when KnownBenignFormat

        // Hard allow: deception indicators
        allow when FormatMismatch
        allow when UnknownFormat

        // Conditional escalation
        allow when all(
            PdfHasJavascript,
            ActiveContent
        )
    }


    // YARA-based gating
    //
    // Pattern-derived indicators only. no interpretation
    lyara {
        // Hard allow: strong indicators
        allow when ShellcodePattern
        allow when KnownMalwareSignature

        // Weak signals require reinforcement
        allow when count(
            SuspiciousEntropy,
            PackedBinary,
            ObfuscationLikely
        ) >= 2
    }


    // Global decision logic
    //
    // If no allow rules fire, artifact continues the pipeline
    // without static analysis.
    decision {
        escalate when any(allow)
        otherwise continue
    }

    // Failure posture
    //
    // Assessor never invents certainty.
    failure {
        on_missing_signals = continue
        on_internal_error  = halt_and_record
    }
}