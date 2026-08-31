# Research Synthesis: YubiKey Toolkit Security Modernization

**Date:** 2026-08-30
**Objective:** File and address detailed, researched issues from the repository audit.
**Phase:** Construction

## Evidence base

- [Best-practices stream](research-best-practices.md)
- [Current-state stream](research-current-state.md)
- [Vendor-documentation stream](research-vendor-docs.md)

The three independent streams converge on eight implementation slices. The most urgent defects are secret-lifecycle failures rather than weak primitives: command substitution loses tmpfs cleanup state, atomic seed-pool replacement unlinks plaintext without sanitizing it, and generated credentials appear in child-process arguments and terminal output.

## Consensus decisions

1. Make verified volatile storage the default for transient plaintext and fail closed unless an operator explicitly accepts persistent storage.
2. Stop presenting pathname overwrite, unlink, or filesystem trim as verified media sanitization.
3. Keep generated credentials out of argv, environment, logs, previews, and terminal scrollback; use supported public Yubico APIs or individually verified input channels.
4. Treat provisioning as a scoped, fault-tolerant state machine with capability preflight, postcondition checks, and accurate partial outcomes.
5. Make the OS CSPRNG the secret entropy root. Treat public beacons as optional authenticated public diversification and unassessed sensors as uncredited supplementary input.
6. Preserve HKDF domain separation, move the secret CSPRNG into IKM, independently derive FIDO and PIV credentials, and remove modulo bias with a versioned construction.
7. Establish executable compatibility gates for Bash 3.2, current Bash, OpenSSL 3, ykman's supported range, shell lint, mocked device calls, and cleanup fault injection.
8. Update all documentation and operator runbooks to match demonstrated guarantees and the current Yubico surface.

## Principal sources

- GNU Bash command substitution: https://www.gnu.org/s/bash/manual/html_node/Command-Substitution.html
- Linux tmpfs: https://www.kernel.org/doc/html/latest/filesystems/tmpfs.html
- NIST SP 800-88 Rev. 2: https://csrc.nist.gov/pubs/sp/800/88/r2/final
- NIST SP 800-90B: https://csrc.nist.gov/pubs/sp/800/90/b/final
- RFC 5869 HKDF: https://www.rfc-editor.org/info/rfc5869/
- YubiKey Manager releases: https://github.com/Yubico/yubikey-manager/releases
- Yubico PIV commands: https://docs.yubico.com/software/yubikey/tools/ykman/PIV_Commands.html
- Yubico OTP commands: https://docs.yubico.com/software/yubikey/tools/ykman/OTP_Commands.html
- Yubico FIDO commands: https://docs.yubico.com/software/yubikey/tools/ykman/FIDO_Commands.html
- YubiKey firmware 5.7 specifics: https://docs.yubico.com/hardware/yubikey/yk-tech-manual/yk5-firmware-5.7.html
- OpenSSL KDF CLI: https://docs.openssl.org/3.5/man1/openssl-kdf/
- drand verification: https://docs.drand.love/developer/examples/

## Dependencies and waves

- **Wave 1:** volatile workspace/cleanup; test harness and compatibility fixtures.
- **Wave 2:** persistent seed-store lifecycle; secret-safe device programming backend; dependency/capability doctor.
- **Wave 3:** credential derivation/policy; transactional provisioning; authenticated public-diversification handling.
- **Wave 4:** integrated documentation, threat model, recovery runbook, and complete verification matrix.

## Known constraints

- Hardware-in-the-loop destructive tests require dedicated sacrificial devices and remain a documented external gate.
- The currently installed ykman 5.5.1 proves environment state, not compatibility. The current upstream release is 5.9.2; the tested range must be established by fixtures and integration tests.
- No generic stdin contract is assumed for all ykman subcommands. Each channel must be vendor-documented or replaced with a public API call.
