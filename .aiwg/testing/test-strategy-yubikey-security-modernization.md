# Test Strategy: YubiKey Toolkit Security Modernization

## Required automated layers

1. `bash -n` for every shell script.
2. ShellCheck with warnings treated according to a checked-in baseline and no error-level findings.
3. Bash 3.2 compatibility execution on the canonical macOS target and current Bash on Linux.
4. Unit tests for storage allocation/cleanup, seed-store transactions, entropy-file parsing, version parsing, rejection sampling, and known-answer HKDF vectors.
5. Mocked ykman integration tests covering supported floor/current output and success/failure after every mutation.
6. Leakage tests that inspect child argv, environment, stdout, and stderr for canary credentials.
7. Documentation checks for forbidden claims such as verified secure deletion or public sources adding secret entropy.

## Hardware gate

Destructive hardware-in-the-loop tests run only against explicitly designated sacrificial keys. Record model, firmware, product family, ykman version, requested applications, and postconditions. Never run this gate automatically on an arbitrary attached key.

## Exit criteria

- All non-hardware checks pass on Linux and macOS.
- Every injected failure yields no orphan workspace and an accurate outcome.
- No canary secret appears in observable process/output surfaces.
- Hardware matrix results are documented for each claimed supported family.
