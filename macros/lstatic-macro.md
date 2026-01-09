```rust
// -----------------------------------------------------------------------------
// lstatic! — Lucius Static Feature Extraction DSL
//
// Purpose:
// - Perform bounded, deterministic static feature extraction
// - Produce factual, typed observations
// - Provide clean inputs for downstream semantic interpretation
//
// lstatic does NOT:
// - Assign intent, severity, or verdicts
// - Execute actions
// - Perform policy decisions
//
// Outputs are *facts*, not conclusions.
// -----------------------------------------------------------------------------

lstatic! {

    // -------------------------------------------------------------------------
    // META
    // -------------------------------------------------------------------------
    meta {
        name        = "binary_static_feature_extraction"
        author      = "org-security"
        source      = "internal-policy"
        version     = "0.4.0"
        scope       = binary
    }

    // -------------------------------------------------------------------------
    // OPERATIONS
    //
    // Operations define *what is inspected* and *how narrowly*.
    //
    // They are:
    // - Bounded
    // - Deterministic
    // - Explicitly scoped
    //
    // Operations DO NOT infer meaning.
    // They only surface structured facts.
    // -------------------------------------------------------------------------
    operations {

        // -------------------------------------------------------------
        // Import inspection (explicit API focus)
        // -------------------------------------------------------------
        operation inspect_imports {
            from import_table select any(
                "WriteProcessMemory",
                "VirtualAllocEx",
                "CreateRemoteThread",
                "NtQueueApcThread"
            ),
            max_entries = 4096,
        }

        // -------------------------------------------------------------
        // Export inspection
        // -------------------------------------------------------------
        operation inspect_exports {
            from export_table select any(
                "DllRegisterServer",
                "DllUnregisterServer",
                "DllGetClassObject",
                "ServiceMain",
                "ReflectiveLoader",
                "Inject",
                "Execute",
                "Command",
                "Install",
                "Persist"
            ),
            max_entries = 2048,
        }

        // -------------------------------------------------------------
        // String extraction with semantic focus
        // -------------------------------------------------------------
        operation inspect_strings {
            encoding = ascii | utf8,
            min_len  = 4,
            max_len  = 256,
            max_bytes = 256.kib,
            from string_table select any(
                "http://",
                "https://",
                ".onion",
                "cmd.exe",
                "powershell"
            ),
        }

        // -------------------------------------------------------------
        // Section entropy measurement
        // -------------------------------------------------------------
        operation inspect_entropy {
            from sections select shannon_entropy
            per_section = true
        }

        // -------------------------------------------------------------
        // Opcode pattern scanning (no CFG)
        // -------------------------------------------------------------
        operation inspect_opcodes {
            from opcode_stream any(sled_nop, call_pop, syscall_stub),
            max_instructions = 1_000_000,
        }
    }

    // -------------------------------------------------------------------------
    // SIGNALS
    //
    // Signals are *facts derived from operations*.
    //
    // They:
    // - Are boolean or bounded numeric
    // - Carry no intent
    // - Do not imply maliciousness
    // -------------------------------------------------------------------------
    signals {

        family imports {

            signal memory_injection_primitives {
                description = "Observed import of memory injection–related APIs"
                derive from operation.inspect_imports
                    when match_count >= 1
            }
        }

        family binary {

            signal high_entropy {
                kind   = numeric
                bounds = 0.0..8.0

                derive from operation.inspect_entropy
                    when average >= 7.2
            }

            signal packed {
                description = "Entropy variance consistent with packing"
                derive from operation.inspect_entropy
                    when variance >= 1.5
            }
        }

        family network {

            signal hardcoded_endpoints {
                description = "Hardcoded network endpoints found in string table"
                derive from operation.inspect_strings
                    when match_count >= 1
            }
        }
    }

    // -------------------------------------------------------------------------
    // CLINCH
    //
    // Clinch exposes facts and requests routing.
    //
    // Still:
    // - No scoring
    // - No interpretation
    // - No execution
    // -------------------------------------------------------------------------
    clinch {

        when signal.imports.memory_injection_primitives {
            tag += "feature:memory-injection-api"
        }

        when signal.binary.packed {
            tag += "feature:packed-binary"
            emit BinaryEmit::PackedBinary
        }

        when signal.network.hardcoded_endpoints {
            tag += "feature:hardcoded-endpoints"
        }

        // Escalation is requested, never decided
        when any(
            signal.imports.memory_injection_primitives,
            signal.binary.packed
        ) {
            run deferred Route::ToAssessor
        }
    }
}
```