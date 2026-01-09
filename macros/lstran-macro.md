# `lstran!` - Lucius Structural Analysis DSL

This document describes the **`lstran!` macro** under the current Lucius / Ben-wide DSL model.

`lstran!` defines **structural analysis rules**: bounded, deterministic inspection that establishes
what an artifact *appears to be*, which *structural signals* it exhibits, and how downstream stages
*should route or interpret it* - without asserting final maliciousness or executing unbounded logic.

Structural analysis exists to **reduce ambiguity early**, **preserve throughput**, and **make uncertainty explicit**.

```rust

// lstran! - Lucius Structural Analysis Macro
//
// This macro defines *structural analysis intent*.
// It does not score, convict, or execute code.
// It observes structure, records facts, and emits signals
// to guide downstream stages.
//
// Mental model:
//   - The runtime produces observations (magic, probes, context)
//   - The DSL reads observations and triggers actions
//   - Actions update stage-owned state or emit signals
//   - No computation happens inside the DSL

lstran! {

    // ---------------------------------------------------------------------
    // META - Identity & Audit
    //
    // This describes the *rule artifact itself*, not the analyzed file.
    // Nothing here affects execution semantics.
    // ---------------------------------------------------------------------
    meta {
        name        = "lucius_structural_default"
        author      = "org-security"
        source      = "internal-policy"
        version     = "0.3.0"

        // Informational intent only (hot-path vs deep-path).
        // Enforcement is always done by bounds + rules.
        profile     = "hot-path"
    }

    // ---------------------------------------------------------------------
    // BOUNDS - Determinism Contract
    //
    // Hard ceilings enforced by the runtime.
    // These are non-negotiable and adversary-facing.
    // If exceeded, analysis continues conservatively.
    // ---------------------------------------------------------------------
    bounds {
        max_read_bytes        = 8.mib
        max_scan_bytes        = 256.kib
        max_container_depth   = 4
        max_container_members = 64
        max_member_read_bytes = 256.kib
        max_text_parse_bytes  = 512.kib

        // fail_soft means:
        //   - emit explicit signals
        //   - do NOT pretend certainty
        //   - allow downstream escalation
        fail_mode             = fail_soft
    }

    // ---------------------------------------------------------------------
    // MAGIC - Cheap Structural Observations
    //
    // Magic checks are NOT YARA.
    // They are:
    //   - extremely cheap
    //   - deterministic
    //   - presence/absence observations
    //
    // They answer: “could this be X?”
    // They do NOT answer: “is this malicious?”
    // ---------------------------------------------------------------------
    magic {
        pdf_magic = bytes {
            offset = 0
            value  = { 25 50 44 46 } // %PDF
        }

        mz_magic = bytes {
            offset = 0
            value  = { 4D 5A } // MZ
        }

        zip_magic = bytes {
            offset = 0
            value  = { 50 4B 03 04 } // PK..
        }

        // Heuristic hint only; bounded scan
        html_hint = ascii {
            any_of = ["<html", "<script", "<meta"]
            nocase = true
        }
    }

    // ---------------------------------------------------------------------
    // PARSE - Structural Probes (Configuration)
    //
    // Probes are owned by Lucius.
    // The DSL only supplies configuration overrides.
    //
    // There is at most ONE configuration per probe kind.
    // Unspecified fields use safe defaults.
    // ---------------------------------------------------------------------
    parse {
        pdf {
            // Feature detection only; no execution
            detect_features = [
                "has_javascript",
                "has_openaction",
                "has_embedded_files"
            ]

            // Optional override; otherwise default applies
            max_objects = 10_000
        }

        archive {
            formats = [zip, tar, gzip]

            // Normalize based on member layout (e.g. docx, jar)
            classify_by_members = true
        }
    }

    // ---------------------------------------------------------------------
    // CLASSIFY - Canonical Structural Mapping
    //
    // This block performs *non-controversial normalization*.
    // There is no logic, no negation, no judgment.
    //
    // If an observation is present, assign canonical structure.
    // This is bookkeeping, not reasoning.
    // ---------------------------------------------------------------------
    classify {

        // If PDF magic is present, we classify as PDF.
        // This is a fact mapping, not a heuristic.
        pdf_magic => {
            observed_type   = pdf
            yara_class      = document
            type_confidence = high
            tag += "type:pdf"
        }

        mz_magic => {
            observed_type   = pe
            yara_class      = binary
            type_confidence = high
            tag += "type:pe"
        }

        zip_magic => {
            observed_type   = archive_zip
            yara_class      = archive
            type_confidence = high
            tag += "type:zip"
        }
    }

    // ---------------------------------------------------------------------
    // CONDITIONS - Structural Reasoning Rules
    //
    // This is where *judgment* happens.
    // Conditions combine observations and structural state.
    //
    // Rules:
    //   - read observations
    //   - trigger immediate actions
    //   - emit signals, tags, and routing hints
    //
    // No rule performs computation.
    // ---------------------------------------------------------------------
    conditions {

        // -------------------------------------------------------------
        // Structural mismatches are signals, not verdicts
        // -------------------------------------------------------------
        when ctx.claimed_ext is_some and ctx.claimed_ext != observed_type {
            signal += ClaimedTypeMismatch {
                claimed  = ctx.claimed_ext,
                observed = observed_type
            }
            risk_hint += SpoofedExtension
            tag += "mismatch:claimed-vs-observed"
        }

        // -------------------------------------------------------------
        // Probe execution is explicit and bounded
        // -------------------------------------------------------------
        when observed_type == pdf {
            run pdf
        }

        when observed_type == archive_zip {
            run archive
        }

        when observed_type == zip_bomb {
            emit Zips::ItsABomb
        }

        // -------------------------------------------------------------
        // Probe outputs are observations (read-only)
        // -------------------------------------------------------------
        when parse.pdf.state == ok and parse.pdf.has_javascript {
            signal += PdfHasJavascript
            risk_hint += ActiveContent
            tag += "pdf:js"
        }

        when parse.pdf.state == ok and parse.pdf.has_embedded_files {
            signal += PdfHasEmbeddedFiles {
                count = parse.pdf.embedded_count
            }
            risk_hint += NestedPayload
            tag += "pdf:embedded"
        }

        when parse.archive.state == partial {
            signal += PartialParse { kind = archive }
            risk_hint += StructuralAnomaly
            tag += "archive:partial"
        }

        // -------------------------------------------------------------
        // Bounds exhaustion is explicit
        // -------------------------------------------------------------
        when ctx.bounds_exceeded {
            signal += BoundsExceeded {
                max_read_bytes = bounds.max_read_bytes,
                max_depth      = bounds.max_container_depth
            }
            risk_hint += AnalysisIncomplete
            tag += "bounds:exceeded"
        }

        // -------------------------------------------------------------
        // Routing hints (advisory only)
        // -------------------------------------------------------------
        when yara_class == document {
            signal += YaraProfileHint {
                profiles = ["doc_common", "pdf_common"]
            }
        }

        when any(
            risk_hint contains ActiveContent,
            risk_hint contains NestedPayload,
            risk_hint contains StructuralAnomaly,
            risk_hint contains AnalysisIncomplete
        ) {
            signal += StaticCandidateHint {
                reason = "structural-risk-hints"
            }
        }
    }
}

```

## Relationship to Other Components

Structural analysis feeds:

- **Notary** - accumulates signals and tags
- **Assessor** - decides deeper analysis eligibility
- **YARA (`lyara!`)** - selects rule profiles
- **Finalize** - produces human-readable summaries

`lstran!` exists to make downstream decisions **cheaper, clearer, and more honest**.```

---

## Summary

`lstran!` is the first truth-finding stage in Lucius.

It:
- Observes structure
- Applies bounded probes
- Emits explicit signals
- Preserves uncertainty
- Avoids premature conclusions

Structural analysis is not about being right.  
It is about being **explicit, bounded, and useful**.
