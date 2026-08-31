# Vendor and Standards Research for YubiKey Toolkit Issues

**Research date:** 2026-08-30
**Scope:** YubiKey Manager 5.9.x, YubiKey firmware 5.7/5.8, PIV/OTP/FIDO credential handling, OpenSSL HKDF, entropy claims, and media sanitization.
**Source policy:** official Yubico, OpenSSL, drand, and NIST material only. All URLs below were retrieved successfully on the research date.

## Executive findings

1. The repository should declare and test a YubiKey Manager 5.x compatibility range, while recommending the current patched 5.9.2 release. The local audit environment has 5.5.1, but upstream's current release is 5.9.2 and 5.9.1 contains a Windows DLL-search-path security fix.
2. Hardware firmware cannot be treated as a simple upgradeable dependency. Provisioning must branch on detected model, firmware, application availability, and policy. Firmware 5.7 changes the default PIV management-key algorithm to AES-192; 5.8 adds CTAP 2.3 and several FIDO/OTP capabilities.
3. The current CLI invocation pattern puts every generated credential in process arguments. Yubico documents interactive prompts for several commands and exposes a public Python library/scripting interface. A non-interactive secure implementation should use the public API rather than secrets in `argv`.
4. The OpenSSL HKDF syntax is correctly using hex-encoded key, salt, and `info`, but the code's entropy narrative is not. NIST and drand beacon values are public; they may be authenticated public diversification inputs but cannot contribute secret min-entropy after publication.
5. The overwrite/unlink implementation is not a defensible general-purpose sanitization guarantee for SSDs, journaled filesystems, snapshots, or copy-on-write media. NIST SP 800-88 Rev. 2 requires a media- and threat-appropriate sanitization program. Sensitive transient state should be kept in verified volatile storage or protected by encryption whose keys can be destroyed.

## 1. YubiKey Manager version policy

### Official state

- Yubico's release history identifies **YubiKey Manager 5.9.2**, released 2026-06-30, as current. It fixes YubiKey 4 FIPS CLI PIN commands for FIDO. Version 5.9.1 restricts Windows DLL search paths under YSA-2026-01. Version 5.9.0 adds PIV and error-handling improvements. Version 5.8.0 requires Python 3.10+, adds OTP `--serial-usb-visible`, improves missing/disabled-FIDO errors, and fixes multi-device FIDO reset.
- Upstream follows semantic versioning and explicitly recommends dependency bounds of `>=5,<6`, rather than an unbounded `>=5`.
- The audit host reports `ykman 5.5.1`; the repository only checks whether `ykman` exists (`configure-yubi.sh:79-85`, `yubi.sh:163-172`) and README requirements do not name a supported version (`README.md:52-60`).

### Issue requirements and migration notes

- Add a machine-readable dependency doctor that parses `ykman --version`, rejects unsupported major versions, and reports the tested range and current recommendation.
- Treat **`>=5.5.1,<6` as a transitional compatibility range** because that is the oldest version evidenced in the current environment, not as a claim that every minor is already tested. Establish CI/mocked-command coverage for the floor and 5.9.2 before calling the range supported.
- Recommend 5.9.2 for new installations, especially on Windows because 5.9.1 includes YSA-2026-01. Do not silently require Python 3.10 merely because upstream 5.8+ does: packaged executables may bundle Python. Document Python 3.10+ only for pip/source installations.
- Do not parse human-readable command output without validation. `configure-yubi.sh:117-120` greps `Firmware version:` from `ykman info`; if the field is absent or changes, subsequent integer comparisons can fail or choose an unsafe branch. Validate a strict `MAJOR.MINOR.PATCH` result, fail closed, and record model/application capabilities.

## 2. Firmware 5.7/5.8 and PIV policy

### Official state

- Firmware 5.7 changes the factory PIV management key algorithm from TDES to **AES-192**, without changing the 24-byte default value. Firmware 5.4.x through 5.6.x still defaults to TDES but supports AES-128/192/256; standard 5.7+ devices default to AES-192 and permit those AES variants. FIPS 5.7 devices allow AES only.
- Firmware 5.7 adds RSA-3072, RSA-4096, Ed25519, and X25519 PIV support. Firmware 5.7.4 introduces relevant FIPS and PIN-policy behavior; some product families enforce PIN complexity and minimum length.
- Yubico says application PINs remain **separate and distinct**, even when device-wide PIN-complexity rules apply. Firmware 5.7 complexity can reject common or patterned values. This matters because the toolkit generates an 8-digit PIV PIN and then reuses it as the FIDO2 PIN.
- Firmware 5.8 adds CTAP 2.3, FIDO2 over CCID, PRF and related CTAP capabilities; OTP settings add serial-number visibility in the USB descriptor. These are capability-dependent, not baseline requirements for PIV/OTP provisioning.

### Repository divergence

- `configure-yubi.sh:116-132` selects AES-256 at firmware 5.4.2+, which is supported, but its comments and README frame this solely as a firmware threshold. It does not distinguish standard, FIPS, Enhanced PIN, Bio, or Security Key products.
- `configure-yubi.sh:359` says the factory management key is always TDES. This is false for firmware 5.7+, where the same bytes represent an AES-192 default key. If ykman auto-detection currently makes this work, the comment and tests must still reflect the correct authentication algorithm.
- `configure-yubi.sh:460-470` reuses the PIV PIN for FIDO and treats failure as a warning. `README.md:234,313` endorses that reuse. This conflicts with application separation and makes the workflow's later claim of being fully initialized (`configure-yubi.sh:528`) unverifiable.
- The random-to-character transforms use modulo mapping (`configure-yubi.sh:225-253`), which introduces bias. An 8-digit result can also land on a firmware blocklist. Derive independent PIV PIN, PIV PUK, and FIDO PIN values with distinct HKDF `info` labels, rejection sampling, and retry-on-policy-rejection.

### Issue requirements and migration notes

- Rename the operation from “full key initialization” to scoped **PIV + OTP + optional FIDO PIN provisioning**, unless OATH, OpenPGP, YubiHSM Auth, interfaces, configuration lock, and all other supported applications receive explicit policy.
- Add a capability inventory before mutation: model, firmware, transports, enabled applications, FIPS status/product family where available, PIN state, and current OTP/PIV state. Refuse unsupported or ambiguous devices rather than treating all YubiKeys alike.
- Make AES-256 an explicit project policy, while documenting Yubico's AES-192 default for 5.7+. For pre-5.4.2 devices, require an explicit legacy opt-in before TDES rather than silently weakening policy.
- Never attempt a FIDO reset automatically. It deletes FIDO/U2F credentials and requires physical interaction. Existing foreign PIN state must produce a clear, scoped partial-success result and recovery instructions.

## 3. Credential input and process exposure

### Official behavior

- Current PIV CLI options accept management key, PIN, PUK, and replacements as command-line text. The PIV guide shows these flags, while Yubico's PIV Tool setup guide explicitly warns that credentials supplied as arguments leave traces in command history and advises omitting values to prompt.
- The FIDO CLI similarly accepts current and new PIN as text flags. The OTP guide offers a secure prompt convention for access codes (`--access-code -`) and interactive prompts when some key arguments are omitted. Static-password and YubiOTP interfaces still need command-specific testing; a general pipe-to-CLI scheme must not be assumed safe.
- Yubico exposes a public Python library and `ykman script` facility. Upstream promises compatibility for public APIs within major version 5 and warns that underscore-prefixed APIs are private.

### Repository evidence

- Management key, PUK, and PIN are placed in `argv` at `configure-yubi.sh:359-396`.
- Yubico OTP AES keys/private IDs and static passwords are placed in `argv` at `configure-yubi.sh:410-423`.
- FIDO PIN values are placed in `argv` at `configure-yubi.sh:462-465`.
- Full PIV management key, PUK, and PIN are printed to the terminal at `configure-yubi.sh:526-540`; partial AES/private-ID material is printed earlier at `configure-yubi.sh:277-315`. `README.md:319` acknowledges `/proc/PID/cmdline` exposure instead of preventing it.

### Issue requirements and migration notes

- Replace shell argument transport with a small, pinned YubiKey Manager Python API helper (public APIs only) that reads a mode-0600 descriptor or framed stdin, retains secrets in memory for the shortest practical interval, and emits only structured non-secret results. Pin the Python dependency to `>=5.9.2,<6` for this helper and test upgrade compatibility.
- If any operation remains CLI-driven, use documented masked prompts or `-` prompt sentinels. Verify each command on both the oldest supported and latest tested ykman. Do not use shell tracing, environment variables, temporary command files containing secrets, or generic `echo secret | command` without a documented stdin contract.
- Remove all secret and partial-secret output. A partial key is still unnecessary disclosure and makes output unsafe for logs/screen recording. Provide an opt-in handoff to a secure destination, not terminal scrollback instructions.
- Add regression tests that inspect child process command lines and captured stdout/stderr to prove generated credentials never appear.

## 4. OTP-specific limits and semantics

- A YubiKey has two OTP slots. The CLI supports Yubico OTP, static password, challenge-response, and HOTP. Custom Yubico OTP credentials do not automatically belong to YubiCloud; `README.md:309` is directionally correct, but the phrase “replaces factory trust” should be expressed as a deployment choice with validator enrollment instructions.
- Static passwords are keyboard-layout encoded. The CLI defaults to MODHEX and limits generated static passwords to 38 characters; repository code forces US layout (`configure-yubi.sh:419-423`). The code must validate every character against the selected layout before touching a slot. Truncation (`configure-yubi.sh:286-301`) should be a preflight error unless explicitly accepted, because silent truncation changes the credential users believe they provisioned.
- OTP slot access codes are currently not configured. If overwrite protection is within policy, generate independent six-byte access codes, use the documented prompt form, store/recover them securely, and account for Yubico's warning that access-code-protected slots affect mode switching.

## 5. OpenSSL HKDF review

### Aligned implementation

- OpenSSL documents `openssl kdf` with `hexkey`, `hexsalt`, and `hexinfo`; `info` binds output to application/context. The toolkit uses those exact binary-safe forms at `configure-yubi.sh:208-222`, `bootstrap-entropy.sh:494-510`, `entropy-mix.sh:248-263`, and `init-yubi.sh:480-487`.
- OpenSSL 3.0 introduced the EVP KDF interface used by the CLI, so the repository's 3.x floor and LibreSSL rejection (`yubi-lib.sh:152-177`, `README.md:316`) are reasonable.

### Required hardening

- Check capability, not only major version: execute a small deterministic HKDF known-answer test during `doctor`/preflight. This catches provider configuration, command-output, and packaging differences.
- Assign a versioned derivation suite that specifies digest, input encoding, exact salt construction, `info`, output length, character encoding, and rejection-sampling rules. Current labels are useful domain separation, but FIDO needs its own label and future changes need an explicit version/migration story.
- Do not describe concatenated public beacons and heuristic sensor readings as measured entropy. HKDF safely combines inputs, but it cannot make known public input secret or certify unassessed min-entropy.

## 6. Entropy and beacon claims

### Standards and vendor evidence

- NIST SP 800-90B defines an entropy source around a noise source, conditioning, min-entropy assessment, and health tests. Hashing temperature, disk timing, mouse timing, or API responses does not by itself establish a validated entropy estimate.
- NIST explicitly warns that randomness beacon values are public and must not be used as secret keys or seeds for cryptographic key generation. NIST pulses are signed and hash-chained, but the repository merely downloads and hashes the JSON.
- drand describes its output as public randomness and states that client libraries should verify beacon signatures and chain parameters. The repository fetches `/public/latest` without signature or chain verification (`yubi-lib.sh:385-393`, `entropy-collect.sh:146-164`, `entropy-mix.sh:164-212`).

### Issue requirements and migration notes

- Reclassify NIST/drand inputs as **optional authenticated public diversification**, contributing zero secret min-entropy after publication. Update `README.md:11-29,238-244,318,338` and script messages accordingly.
- Either verify NIST signatures/hash-chain fields and drand signatures/chain hash with supported clients, or remove the sources. TLS and a per-block SHA-256 checksum only detect transit/storage corruption; they do not prove beacon authenticity or freshness.
- Make the OS CSPRNG (`openssl rand`, backed by the platform RNG) the root secret source. Treat human/sensor inputs as unquantified supplements. Do not claim “strong entropy” for keyboard timing (`README.md:335`) without a threat model and min-entropy assessment.
- Add freshness, round/timestamp, chain/network identifier, response-schema, and replay checks. Store provenance metadata separately from secret key material.

## 7. Media sanitization and transient-secret handling

### Standard

NIST SP 800-88 Rev. 2 (September 2025) supersedes Rev. 1. It defines sanitization as making target data access infeasible for a chosen effort level and requires techniques and controls appropriate to the media and data sensitivity. A portable shell overwrite cannot guarantee purge across flash translation layers, filesystem journals, snapshots, copy-on-write copies, remote storage, or backups.

### Repository evidence

- `yubi-lib.sh:207-220` acknowledges SSD, journal, and snapshot limitations but then `secure_delete()` performs overwrite, unlink, and optional whole-mount `fstrim` (`yubi-lib.sh:222-259`). README still calls this secure deletion and claims APFS auto-TRIM/encryption makes the gap small (`README.md:100,255-265`).
- `configure-yubi.sh:500` renames a filtered file over the original. That unlinks the old inode without overwriting it; later cleanup applies to the replacement, not the original seed-bearing inode.
- `init-yubi.sh:74` captures `secure_tmpfs_create` through command substitution. Because that executes in a subshell, global mount/state variables set by the helper do not propagate to the EXIT trap. The promised cleanup and unmount therefore cannot be relied upon.

### Issue requirements and migration notes

- Stop using “secure delete/wipe” for ordinary file overwrite. Call it best-effort clear and state the limits.
- Require verified volatile storage for plaintext one-shot workflows. Call the allocator in the current shell, return paths via globals, verify the filesystem type/mount identity, and test cleanup on success, error, INT, TERM, and KILL limitations.
- For persistent pools, use authenticated encryption at creation and rotate/destroy the encryption key when retiring data. Document that copies, backups, swap, hibernation, crash dumps, and snapshots are in scope for the operator's sanitization policy.
- Never issue `fstrim` against an inferred broad mount as a per-file erasure claim. It is a filesystem maintenance operation and does not prove a specific file's media blocks are purged.
- Replace the seed-consumption rewrite with an encrypted store or a RAM-resident decrypted working set. Atomic replacement can preserve logical consistency, but must not be presented as physical sanitization.

## 8. Proposed issue decomposition and acceptance evidence

1. **Dependency and capability doctor** — version-bound ykman/OpenSSL; strict firmware parsing; application/product inventory; fixture tests for 5.5.1 and 5.9.2 output.
2. **Secret-safe YubiKey programming backend** — public Yubico Python API; no secrets in process arguments, environment, logs, or terminal; process-table regression test.
3. **Credential-domain and policy separation** — independent PIV PIN/PUK/FIDO PIN labels; unbiased encoding; blocked-value retry; explicit legacy/FIPS handling.
4. **Transactional scoped provisioning** — preflight, mutation journal, per-application outcomes, partial-failure recovery, no automatic FIDO reset, accurate completion wording.
5. **Authenticated public-beacon handling** — signature/chain/freshness verification or removal; public-diversification terminology; OS CSPRNG as secret root.
6. **Secret storage and sanitization redesign** — verified volatile workspace, encrypted persistent pool, correct EXIT/signal cleanup, NIST-aligned documentation with no overwrite guarantees.
7. **Documentation and compatibility matrix** — tested ykman/OpenSSL/OS/firmware matrix, current vendor install guidance, firmware capability notes, threat model, and operator recovery runbook.

Each issue should require executable tests or captured fixtures as acceptance evidence. Documentation-only changes cannot close implementation findings involving process exposure, cleanup, firmware branching, or beacon verification.

## Official sources

1. Yubico, **YubiKey Manager releases / NEWS** (5.8.0–5.9.2 release notes): https://github.com/Yubico/yubikey-manager/blob/main/NEWS
2. Yubico, **YubiKey Manager repository — versioning and compatibility**: https://github.com/Yubico/yubikey-manager
3. Yubico, **YubiKey Manager CLI Guide — PIV Commands**: https://docs.yubico.com/software/yubikey/tools/ykman/PIV_Commands.html
4. Yubico, **YubiKey Manager CLI Guide — OTP Commands**: https://docs.yubico.com/software/yubikey/tools/ykman/OTP_Commands.html
5. Yubico, **YubiKey Manager CLI Guide — FIDO Commands**: https://docs.yubico.com/software/yubikey/tools/ykman/FIDO_Commands.html
6. Yubico, **YubiKey PIV Tool — setup and command-line trace warning**: https://docs.yubico.com/software/yubikey/tools/pivtool/piv-tool-setup.html
7. Yubico, **YubiKey Technical Manual — PIV specifics and defaults**: https://docs.yubico.com/hardware/yubikey/yk-tech-manual/yk5-apps-piv.html
8. Yubico, **YubiKey Technical Manual — firmware 5.7/5.6 specifics**: https://docs.yubico.com/hardware/yubikey/yk-tech-manual/yk5-firmware-5.7.html
9. Yubico, **YubiKey Technical Manual — firmware overview/capability matrices**: https://docs.yubico.com/hardware/yubikey/yk-tech-manual/yk5-firmware-overview.html
10. Yubico, **YubiKey Technical Manual — FIDO specifics (5.8 / CTAP 2.3)**: https://docs.yubico.com/hardware/yubikey/yk-tech-manual/yk5-apps-fido.html
11. OpenSSL, **openssl-kdf 3.5 manual**: https://docs.openssl.org/3.5/man1/openssl-kdf/
12. OpenSSL, **EVP_KDF manual**: https://docs.openssl.org/3.5/man3/EVP_KDF/
13. NIST, **SP 800-90B — Entropy Sources Used for Random Bit Generation**: https://csrc.nist.gov/pubs/sp/800/90/b/final
14. NIST, **Interoperable Randomness Beacons**: https://csrc.nist.gov/projects/interoperable-randomness-beacons/
15. NIST, **SP 800-88 Rev. 2 — Guidelines for Media Sanitization**: https://csrc.nist.gov/pubs/sp/800/88/r2/final
16. drand, **HTTP API**: https://docs.drand.love/developer/http-api/
17. drand, **verified client examples**: https://docs.drand.love/developer/examples/

## Confidence and limitations

- **High confidence:** release versions, documented CLI flags, PIV algorithm defaults, firmware capability differences, public-beacon status, HKDF parameter semantics, and SP 800-88/90B scope; these are supported directly by official primary sources.
- **Moderate confidence:** the exact transitional ykman floor. The current host proves 5.5.1 is installed, not that the full repository works correctly against it. The proposed floor remains provisional until fixtures/tests cover every used command.
- **Deliberately not claimed:** that every ykman credential can be safely streamed over stdin. Official command behavior differs by subcommand; the recommended public-API backend avoids relying on undocumented prompt automation.
