```rust
// -----------------------------------------------------------------------------
// lthreat! — Lucius Threat Intelligence Correlation DSL
//
// Purpose:
// - Correlate artifacts against external threat intelligence feeds
// - Translate feed responses into bounded, factual signals
// - Contribute weighted context without asserting truth
//
// lthreat does NOT:
// - Perform detection or classification
// - Decide maliciousness
// - Execute actions
// - Override local analysis
//
// Threat intelligence is treated as *context*, not authority.
// -----------------------------------------------------------------------------

lthreat! {

    // -------------------------------------------------------------------------
    // META
    //
    // Identity, audit, and policy ownership.
    // -------------------------------------------------------------------------
    meta {
        name        = "default_threat_corroboration"
        author      = "org-security"
        source      = "threat-intel-policy"
        version     = "0.5.0"

        description = "Correlates artifacts against internal and external threat feeds"
    }

    // -------------------------------------------------------------------------
    // OPERATIONS
    //
    // Operations define *how external intelligence is consulted*.
    //
    // They:
    // - Specify which feeds are queried
    // - Declare supported artifact identifiers
    // - Define bounded interaction rules
    // - Model failure explicitly
    //
    // Operations DO NOT:
    // - Assign meaning
    // - Normalize confidence
    // - Decide outcomes
    // -------------------------------------------------------------------------
    operations {

        // -------------------------------------------------------------
        // Internal high-confidence malware feed
        // -------------------------------------------------------------
        operation internal_malware_feed {
            provider = "org-threat-intel"
            url = "someorgprovider.com"
            hashes   = [ sha256, sha1 ]

            authority {
                confidence = 0.9
                scope      = internal
            }

            timeout = 250.ms
            max_hits = 1

            on_failure {
                behavior = record_and_continue
            }
        }

        // -------------------------------------------------------------
        // External reputation feed (lower trust)
        // -------------------------------------------------------------
        operation public_reputation_feed {
            provider = "public-reputation-api"
            url = "somerepprovider.org"
            hashes   = [ sha256 ]

            authority {
                confidence = 0.5
                scope      = external
            }

            timeout = 400.ms
            max_hits = 3

            on_failure {
                behavior = degrade_confidence
                penalty  = 0.1
            }
        }
    }

    // -------------------------------------------------------------------------
    // SIGNALS
    //
    // Signals are *facts derived from feed responses*.
    //
    // They:
    // - Represent corroboration, not certainty
    // - Are boolean or bounded numeric
    // - Carry no implicit verdict
    // -------------------------------------------------------------------------
    signals {

        family reputation {

            signal known_malware {
                description = "Artifact hash matched a known malware entry"
                derive from operation.internal_malware_feed
                    when match == true
            }

            signal suspected_malware {
                description = "Artifact matched a lower-confidence reputation source"
                derive from operation.public_reputation_feed
                    when match_count >= 1
            }

            signal corroborated_intel {
                description = "Artifact corroborated across multiple independent feeds"
                derive from any(
                    operation.internal_malware_feed,
                    operation.public_reputation_feed
                )
                    when distinct_sources >= 2
            }
        }

        family intel_quality {

            signal feed_failure {
                description = "One or more threat intelligence feeds failed to respond"
                derive from any(
                    operation.internal_malware_feed,
                    operation.public_reputation_feed
                )
                    when failure == true
            }
        }
    }

    // -------------------------------------------------------------------------
    // CLINCH
    //
    // Clinch:
    // - Accumulates score contributions
    // - Tags artifacts for auditability
    // - Requests escalation intent (never executes)
    //
    // Still:
    // - No verdicts
    // - No authority claims
    // -------------------------------------------------------------------------
    clinch {

        // -------------------------------------------------------------
        // High-confidence internal corroboration
        // -------------------------------------------------------------
        when signal.reputation.known_malware {
            score += 0.6
            tag   += "threat:intel-internal-match"
            emit Emission::KnownMalware
        }

        // -------------------------------------------------------------
        // Lower-confidence public corroboration
        // -------------------------------------------------------------
        when signal.reputation.suspected_malware {
            score += 0.3
            tag   += "threat:intel-public-match"
        }

        // -------------------------------------------------------------
        // Multi-source corroboration
        // -------------------------------------------------------------
        when signal.reputation.corroborated_intel {
            score += 0.4
            tag   += "threat:intel-corroborated"
        }

        // -------------------------------------------------------------
        // Feed degradation awareness
        // -------------------------------------------------------------
        when signal.intel_quality.feed_failure {
            tag += "threat:intel-partial"
        }

        // -------------------------------------------------------------
        // Escalation requests
        //
        // Threat intel *never escalates alone*.
        // -----------------------------------------------------------------
        when all(
            signal.reputation.corroborated_intel,
            score >= 0.6
        ) {
            run deferred Route::ToAssessor
        }
    }
}
```