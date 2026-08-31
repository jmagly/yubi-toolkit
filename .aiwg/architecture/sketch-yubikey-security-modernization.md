# Architecture Sketch: Secure Provisioning Pipeline

**Research:** `@.aiwg/working/issue-planner/research-synthesis.md`

```text
dependency doctor -> device capability preflight -> storage policy gate
       |                         |                         |
       +-------------------------+-------------------------+
                                 v
                    versioned derivation suite
                                 |
                                 v
                   secret-safe programming adapter
                                 |
                    checkpoint + postcondition per step
                                 |
                                 v
              complete | partial + recovery | failed
```

## Boundaries

- Shell remains the orchestration layer and Bash 3.2 is a compatibility target.
- Secret transport is isolated behind a programming adapter. Public Yubico APIs are preferred where the CLI cannot accept secrets without argv exposure.
- Ephemeral storage owns its lifecycle in the parent shell and installs cleanup before secret creation.
- Persistent pools are encrypted records; atomic replacement provides consistency, not physical sanitization.
- Public-beacon verification and provenance are separate from secret entropy generation.

## Invariants

1. No secret crosses an argv, exported-environment, log, or default-output boundary.
2. No plaintext transient file is created before the storage policy gate passes.
3. Seeds are consumed only after requested device postconditions succeed.
4. Every partial mutation produces an accurate redacted recovery state.
5. The CSPRNG is mandatory; optional-source compromise or absence cannot reduce its security.
6. Derivation changes require a suite-version change and known-answer vectors.
