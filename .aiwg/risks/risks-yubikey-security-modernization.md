# Risk Register: YubiKey Toolkit Security Modernization

| ID | Risk | Impact | Control / Evidence |
|---|---|---|---|
| R-01 | Plaintext workspaces survive exit or interruption | Critical | Parent-shell lifecycle state; idempotent signal cleanup; orphan tests |
| R-02 | Persistent seed replacement leaves recoverable old extents | Critical | Encrypted-at-rest pool; accurate sanitization language; interruption tests |
| R-03 | Credentials leak through process inspection or terminal capture | High | Public API/prompt adapter; argv and output canary tests |
| R-04 | Mid-sequence device failure leaves unknown state | High | Capability preflight, checkpoints, postconditions, recovery record |
| R-05 | Firmware/product differences select invalid policy | High | Strict doctor and fixture matrix; fail closed on ambiguity |
| R-06 | Credential reuse or biased mapping weakens separation | Medium | Independent labels; rejection sampling; KAT/property tests |
| R-07 | Public data is mistaken for secret entropy | Medium | CSPRNG-root design; beacon verification; corrected documentation |
| R-08 | Portability regressions escape review | High | Bash 3.2/current test matrix, ShellCheck gate, mocked integrations |
| R-09 | Destructive tests damage real credentials | High | Mock-first suite; explicit sacrificial-device HIL runbook only |
