# Security Screening: YubiKey Toolkit Modernization

## Assets

Seed pools, derived PIN/PUK/management keys, OTP secrets/static passwords, device application state, and recovery records.

## Trust boundaries

- Operator terminal -> shell orchestration
- Shell -> filesystem/tmpfs/swap
- Shell -> ykman CLI or Yubico API helper
- Host -> attached YubiKey applications
- Network -> public beacon services

## STRIDE summary

- **Spoofing:** wrong device or public-beacon endpoint; mitigate with serial/capability confirmation and verified beacon parameters.
- **Tampering:** altered pool or partial device mutation; mitigate with authenticated storage, checkpoints, and postconditions.
- **Repudiation:** ambiguous partial outcome; mitigate with redacted state records.
- **Information disclosure:** argv, terminal, disk, swap, logs; mitigate with secret-safe transport and storage gates.
- **Denial of service:** interrupted provisioning or unavailable optional sources; use resumable states and keep optional sources non-blocking.
- **Elevation of privilege:** root tmpfs mounting and broad filesystem trim; minimize privileged operations and remove per-file trim behavior.

## Gate result

Construction may proceed only in dependency waves. Issues covering R-01 through R-05 are release blockers; documentation alone cannot close them.
