```rust
// -----------------------------------------------------------------------------
// lyara! — Lucius YARA-style Pattern Correlation DSL
//
// Purpose:
// - Perform bounded pattern matching over artifacts
// - Correlate low-level matches into meaningful signals
// - Accumulate score within a constrained domain
// - Request downstream intent (emit / run deferred)
//
// lyara does NOT:
// - Execute actions
// - Perform structural parsing
// - Perform static analysis (imports, CFGs, etc.)
// - Decide final verdicts
//
// lyara operates on:
// - Byte streams
// - Normalized text streams
// - Outputs of structural normalization (lstran)
//
// Outputs:
// - Pattern-derived signals
// - Score contributions
// - Tags
// - Intent requests (mediated by Notary)
//
// This macro encodes *pattern correlation*, not authority.
// -----------------------------------------------------------------------------

lyara! {

    // -------------------------------------------------------------------------
    // META
    // -------------------------------------------------------------------------
    meta {
        name        = "pdf_active_content_patterns"
        author      = "org-security"
        source      = "internal-research"
        version     = "1.3.0"

        severity    = high
        base_weight = 0.15
    }

    // -------------------------------------------------------------------------
    // OPERATIONS
    //
    // Operations define *bounded pattern matching work*.
    //
    // They:
    // - Perform deterministic scanning
    // - Produce match counts or booleans
    // - Do NOT assign meaning
    //
    // Think: "What patterns may we look for?"
    // -------------------------------------------------------------------------
    operations {

        // -------------------------------------------------------------
        // Magic header checks
        // -------------------------------------------------------------
        operation pdf_magic {
            from byte_stream like bytes {
                value  = { 25 50 44 46 }   // %PDF
                offset = 0
            }
        }

        // -------------------------------------------------------------
        // Embedded JavaScript indicators
        // -------------------------------------------------------------
        operation embedded_javascript {
            from text_stream like ascii {
                any_of = [
                    "JavaScript",
                    "/JS",
                    "/OpenAction",
                    "/AA"
                ]
                nocase = true
            }
        }

        // -------------------------------------------------------------
        // Suspicious launch / auto-exec tokens
        // -------------------------------------------------------------
        operation launch_tokens {
            from text_stream like ascii {
                any_of = [
                    "/Launch",
                    "/OpenAction",
                    "cmd.exe",
                    "powershell"
                ]
                nocase = true
            }
        }

        // -------------------------------------------------------------
        // High-entropy byte windows (bounded)
        // -------------------------------------------------------------
        operation entropy_windows {
            from byte_stream measure entropy {
                window_size = 256
                range       = 7.6..8.0
            }
        }

        // -------------------------------------------------------------
        // Shellcode-like byte patterns
        // -------------------------------------------------------------
        operation shellcode_patterns {
            from byte_stream like bytes {
                patterns = any(
                    { 90 90 90 90 },                // NOP sled
                    { E8 ?? ?? ?? ?? },             // CALL rel
                    { 0F 05 }                       // syscall
                )
            }
        }

        // -------------------------------------------------------------
        // Known-bad hash lookup (bounded list)
        // -------------------------------------------------------------
        operation known_bad_hash {
            from hash_stream like hash {
                sha256 = [
                    "b1946ac92492d2347c6235b4d2611184",
                    "e3b0c44298fc1c149afbf4c8996fb924"
                ]
            }
        }
    }

    // -------------------------------------------------------------------------
    // SIGNALS
    //
    // Signals are *facts derived from pattern matches*.
    //
    // They:
    // - Are boolean or bounded numeric
    // - Represent observed conditions
    // - Do NOT imply verdicts
    // -------------------------------------------------------------------------
    signals {

        family pdf {

            signal magic_present {
                description = "Artifact matches PDF magic header"
                derive from operation.pdf_magic
                    when matched == true
            }

            signal active_content {
                description = "PDF contains active JavaScript indicators"
                derive from operation.embedded_javascript
                    when match_count >= 1
            }

            signal auto_exec_tokens {
                description = "PDF contains auto-execution or shell tokens"
                derive from operation.launch_tokens
                    when match_count >= 1
            }
        }

        family entropy {

            signal compressed_regions {
                description = "Multiple high-entropy regions detected"
                derive from operation.entropy_windows
                    when count >= 2
            }
        }

        family payload {

            signal shellcode_like {
                description = "Shellcode-style byte patterns detected"
                derive from operation.shellcode_patterns
                    when match_count >= 1
            }
        }

        family reputation {

            signal known_malware {
                description = "Artifact hash matches known malware feed"
                derive from operation.known_bad_hash
                    when matched == true
            }
        }
    }

    // -------------------------------------------------------------------------
    // CLINCH
    //
    // Clinch performs:
    // - Score accumulation
    // - Tagging
    // - Signal promotion
    // - Intent requests
    //
    // Still:
    // - No execution
    // - No verdicts
    // -------------------------------------------------------------------------
    clinch {

        // -------------------------------------------------------------
        // Structural contradiction
        // -------------------------------------------------------------
        when not signal.pdf.magic_present {
            score += 0.9
            tag   += "spoofed-extension"
        }

        // -------------------------------------------------------------
        // Active content
        // -------------------------------------------------------------
        when signal.pdf.active_content {
            score += 0.4
            tag   += "active-content"
            signal += PdfHasJavascript
        }

        when signal.pdf.auto_exec_tokens {
            score += 0.3
            tag   += "auto-exec"
        }

        // -------------------------------------------------------------
        // Obfuscation heuristics
        // -------------------------------------------------------------
        when signal.entropy.compressed_regions {
            score += 0.25
            tag   += "compressed-or-obfuscated"
        }

        // -------------------------------------------------------------
        // Payload indicators
        // -------------------------------------------------------------
        when signal.payload.shellcode_like {
            score += 0.6
            tag   += "shellcode-pattern"
            signal += ShellcodePatternDetected
        }

        // -------------------------------------------------------------
        // Reputation correlation
        // -------------------------------------------------------------
        when signal.reputation.known_malware {
            score += 1.0
            tag   += "known-malware"
        }

        // -------------------------------------------------------------
        // Intent requests (mediated)
        // -------------------------------------------------------------
        when score >= 0.5 {
            emit Emission::ExtractStrings
        }

        when score >= 0.7 {
            emit Emission::QuarantineRecommended
        }

        when score >= 0.85 {
            run deferred Route::RequestDeepScrub
        }
    }
}
```