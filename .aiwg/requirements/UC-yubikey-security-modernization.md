# Use Cases: YubiKey Toolkit Security Modernization

**Research:** `@.aiwg/working/issue-planner/research-synthesis.md`

## UC-1: Generate and provision without persistent plaintext

An operator can run one-shot provisioning with transient secrets confined to a verified volatile workspace. Failure to establish that workspace stops the operation unless the operator explicitly selects a documented degraded mode.

## UC-2: Maintain a persistent seed pool safely

An operator who needs reusable pools stores them encrypted at rest. Consumption is logically atomic, interruption-safe, and does not claim that unlink/overwrite sanitizes flash, journals, snapshots, or backups.

## UC-3: Program a supported YubiKey without process disclosure

Generated PINs, PUKs, management keys, OTP keys, and passwords never appear in child argv, environment, logs, previews, or ordinary terminal output. The operator chooses an explicit secure recovery sink.

## UC-4: Receive an accurate provisioning result

Before mutation, the toolkit inventories model, firmware, applications, and tool compatibility. Each requested mutation is verified. Completion is reported as complete, partial, or failed with a redacted recovery record.

## UC-5: Derive independent unbiased credentials

Every application and purpose uses an independently labeled, versioned HKDF derivation. Restricted alphabets use deterministic rejection sampling, and known-answer tests protect compatibility.

## UC-6: Use external public randomness honestly

The OS CSPRNG is the required secret root. Public beacons are authenticated and freshness-checked before optional diversification, or omitted. Documentation assigns no unmeasured entropy to public or heuristic sources.

## UC-7: Verify portability and vendor compatibility

Maintainers can run a non-hardware test suite covering ShellCheck, Bash syntax/3.2 compatibility, deterministic crypto vectors, mocked ykman versions/output, failure injection, cleanup, and documentation claims.
