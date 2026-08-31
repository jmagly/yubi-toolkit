# Issue Plan: YubiKey Toolkit Security Modernization

**Mode:** Awaiting mandatory filing approval
**Provider:** Gitea (`roctinam/yubi-toolkit`)
**Phase:** Construction
**Objective:** File researched issues and complete them through `address-issues`.

Supporting corpus:

- `@.aiwg/working/issue-planner/research-synthesis.md`
- `@.aiwg/requirements/UC-yubikey-security-modernization.md`
- `@.aiwg/architecture/sketch-yubikey-security-modernization.md`
- `@.aiwg/risks/risks-yubikey-security-modernization.md`
- `@.aiwg/testing/test-strategy-yubikey-security-modernization.md`
- `@.aiwg/security/screening-yubikey-security-modernization.md`

## Wave 1

### I-01 — Fix volatile workspace ownership and fail-closed cleanup

**Labels:** `bug`, `security`, `P0-critical`, `phase:construction`, `area:security`

#### Summary

`init-yubi.sh` captures `secure_tmpfs_create` through command substitution. Bash executes it in a subshell, so parent-shell cleanup state is never updated and the EXIT trap can leave plaintext workspaces or mounted tmpfs instances behind. Redesign lifecycle ownership and make volatile storage a verified prerequisite.

#### Evidence

- `init-yubi.sh:74-75`; `yubi-lib.sh:289-334`
- GNU Bash command substitution: https://www.gnu.org/s/bash/manual/html_node/Command-Substitution.html
- Linux tmpfs and swap behavior: https://www.kernel.org/doc/html/latest/filesystems/tmpfs.html
- Research: `@.aiwg/working/issue-planner/research-best-practices.md#bp-01--make-ephemeral-workspace-ownership-and-cleanup-fail-closed`

#### Acceptance criteria

- [ ] Allocation mutates lifecycle state in the parent shell and installs cleanup before secret creation.
- [ ] The actual backing filesystem/mount is verified; implicit disk fallback is removed or requires an explicit warned override.
- [ ] Cleanup is idempotent and preserves the original exit status.
- [ ] Tests cover success, injected failure, EXIT, INT, TERM, HUP, mount failure, and no orphan directory/mount.
- [ ] Documentation describes tmpfs swap limitations and does not claim non-swappable memory.

### I-02 — Establish security and compatibility test infrastructure

**Labels:** `test`, `infra`, `P0-critical`, `phase:construction`, `area:infra`

#### Summary

Create a mock-first test pyramid that detects the existing top-level `local` crash and protects Bash 3.2 portability, storage cleanup, cryptographic vectors, ykman integration, secret leakage, and documentation invariants.

#### Evidence

- `bootstrap-entropy.sh:385` triggers ShellCheck SC2168 and fails when X11 succeeds.
- No repository test suite or CI workflow currently exists.
- ShellCheck SC2168: https://www.shellcheck.net/wiki/SC2168
- Bats: https://bats-core.readthedocs.io/
- Test strategy: `@.aiwg/testing/test-strategy-yubikey-security-modernization.md`

#### Acceptance criteria

- [ ] Fix the X11-success execution defect.
- [ ] Add repeatable `bash -n`, ShellCheck, and unit/integration test entry points.
- [ ] Add current-Bash Linux tests and a documented/executable Bash 3.2 macOS gate.
- [ ] Provide mocked ykman fixtures for the supported floor and current release.
- [ ] Add cleanup fault-injection and secret-canary helpers reusable by later issues.

## Wave 2

### I-03 — Redesign seed-pool storage, atomic consumption, and sanitization claims

**Labels:** `security`, `bug`, `P0-critical`, `phase:construction`, `area:data`
**Depends on:** I-01, I-02

#### Summary

Atomic replacement currently unlinks the original seed-bearing inode without sanitizing it, while the project describes overwrite/unlink/trim as secure deletion. Prevent plaintext persistence by default, introduce authenticated encryption for persistent pools, preserve logical atomicity, and align terminology with media-aware sanitization guidance.

#### Evidence

- `configure-yubi.sh:481-508`; `yubi-lib.sh:203-263`; `README.md:255-265`
- NIST SP 800-88 Rev. 2: https://csrc.nist.gov/pubs/sp/800/88/r2/final
- Research: `@.aiwg/working/issue-planner/research-best-practices.md#bp-02--replace-overwrite-based-secure-deletion-claims-with-storage-lifecycle-controls`

#### Acceptance criteria

- [ ] One-shot mode never stages plaintext on unverified persistent storage.
- [ ] Persistent pools use authenticated encryption with a documented key lifecycle and recovery model.
- [ ] Consumption is crash-consistent and seeds are committed as consumed only after provisioning postconditions pass.
- [ ] Pathname-level cleanup is named best-effort clear; automatic whole-mount `fstrim` is removed from it.
- [ ] Tests cover interruption boundaries, empty/non-empty pools, permissions, symlink defenses, and authentication failure.

### I-04 — Add a dependency doctor and strict YubiKey capability preflight

**Labels:** `feat`, `security`, `P1-high`, `phase:construction`, `area:infra`
**Depends on:** I-02

#### Summary

Replace presence-only dependency checks and fragile firmware parsing with a machine-readable doctor and device capability preflight. Establish and test a supported ykman range, OpenSSL HKDF capability, product/application availability, and fail-closed handling of unknown devices.

#### Evidence

- `yubi.sh:163-172`; `configure-yubi.sh:79-132`; `yubi-lib.sh:152-177`
- Host: ykman 5.5.1; current upstream: 5.9.2.
- Releases: https://github.com/Yubico/yubikey-manager/releases
- Firmware 5.7: https://docs.yubico.com/hardware/yubikey/yk-tech-manual/yk5-firmware-5.7.html
- OpenSSL KDF: https://docs.openssl.org/3.5/man1/openssl-kdf/

#### Acceptance criteria

- [ ] Doctor reports ykman/OpenSSL/Python/Bash versions and supported/tested status.
- [ ] Strict firmware parsing and application/product capability inventory precede mutation.
- [ ] Unknown major versions, malformed output, absent applications, and ambiguous product policy fail closed.
- [ ] A deterministic OpenSSL HKDF known-answer check verifies actual provider capability.
- [ ] Fixtures cover ykman 5.5.1, 5.9.2, firmware 5.4-5.8, FIPS, Bio/Security Key limitations, and malformed output.

### I-05 — Replace argv/terminal credential exposure with a secret-safe programming adapter

**Labels:** `security`, `refactor`, `P0-critical`, `phase:construction`, `area:security`
**Depends on:** I-02, I-04

#### Summary

All generated PINs, PUKs, management keys, OTP keys, and static passwords currently cross process-argument boundaries, and several are printed fully or partially. Introduce a reviewed adapter using supported public Yubico APIs or individually documented prompt channels and provide an explicit secure recovery sink.

#### Evidence

- `configure-yubi.sh:313-315,359-465,526-540`; `README.md:319`
- Yubico PIV setup trace warning: https://docs.yubico.com/software/yubikey/tools/pivtool/piv-tool-setup.html
- Current PIV/FIDO/OTP command surfaces:
  - https://docs.yubico.com/software/yubikey/tools/ykman/PIV_Commands.html
  - https://docs.yubico.com/software/yubikey/tools/ykman/FIDO_Commands.html
  - https://docs.yubico.com/software/yubikey/tools/ykman/OTP_Commands.html

#### Acceptance criteria

- [ ] No generated secret appears in child argv, exported environment, stdout, stderr, logs, debug output, or plan previews.
- [ ] Every secret input channel is vendor-documented for the tested version or implemented through a pinned public API.
- [ ] Static/OTP layout and length are validated before any device mutation; silent truncation is removed.
- [ ] Recovery output is opt-in to an operator-selected permission-restricted encrypted sink.
- [ ] Canary integration tests inspect process/output surfaces and prove non-disclosure on success and failure.

## Wave 3

### I-06 — Version credential derivation and separate application policies

**Labels:** `security`, `refactor`, `P1-high`, `phase:construction`, `area:security`
**Depends on:** I-02, I-04

#### Summary

Specify a versioned HKDF suite with the OS CSPRNG as secret IKM, independent purpose/application labels, deterministic rejection sampling, and known-answer vectors. Stop reusing the PIV PIN as the FIDO PIN and handle firmware PIN-policy rejection explicitly.

#### Evidence

- `configure-yubi.sh:205-268,460-470`; `bootstrap-entropy.sh:485-510`; `README.md:231-244`
- RFC 5869: https://www.rfc-editor.org/info/rfc5869/
- Yubico application/PIN policy: https://docs.yubico.com/hardware/yubikey/yk-tech-manual/yk5-firmware-5.7.html

#### Acceptance criteria

- [ ] A derivation specification defines suite version, framing, encoding, IKM, salt, info, and migration semantics.
- [ ] PIV PIN, PUK, management key, FIDO PIN, and each OTP purpose use distinct labels and independent outputs.
- [ ] Numeric/alphanumeric mapping uses deterministic rejection sampling with refill/counter rules.
- [ ] Known-answer and rejection-boundary tests cover every artifact.
- [ ] Legacy derivation remains explicitly readable/migratable or is rejected with clear guidance; no silent credential drift.

### I-07 — Implement transactional, scoped provisioning with recovery states

**Labels:** `security`, `refactor`, `P1-high`, `phase:construction`, `area:security`
**Depends on:** I-03, I-04, I-05, I-06

#### Summary

Replace the linear mutation sequence and inaccurate “fully initialized” result with an application-scoped state machine. Preflight all requested changes, checkpoint verified mutations, preserve seeds until completion, and emit complete/partial/failed outcomes with redacted recovery guidance.

#### Evidence

- `configure-yubi.sh:304-471,473-540`
- Yubico application surfaces: https://docs.yubico.com/software/yubikey/tools/ykman/intro.html
- PIV reset semantics: https://docs.yubico.com/software/yubikey/tools/ykman/PIV_Commands.html
- FIDO reset semantics: https://docs.yubico.com/software/yubikey/tools/ykman/FIDO_Commands.html

#### Acceptance criteria

- [ ] The requested scope is named accurately: PIV, OTP, and optional FIDO PIN—not all YubiKey applications.
- [ ] Preflight completes before mutation and reset operations are separate, scoped, and independently confirmed.
- [ ] Every mutation has a non-secret postcondition and durable redacted checkpoint/recovery state.
- [ ] Fault injection after every adapter call yields an accurate complete/partial/failed result and never prematurely consumes seeds.
- [ ] FIDO failure cannot result in a “fully initialized” success; no FIDO reset is automatic.

### I-08 — Reframe entropy sources and authenticate public-beacon diversification

**Labels:** `security`, `docs`, `P1-high`, `phase:construction`, `area:security`
**Depends on:** I-02, I-04, I-06

#### Summary

Make the platform CSPRNG the mandatory secret root, classify human/sensor inputs as unassessed supplements, and classify NIST/drand as public diversification. Verify signed beacon material with pinned parameters, schema/freshness/replay bounds, or remove it. Correct implementation messages and documentation.

#### Evidence

- `bootstrap-entropy.sh:403-510`; `yubi-lib.sh:337-393`; `README.md:11-29,236-265,317-338`
- NIST SP 800-90B: https://csrc.nist.gov/pubs/sp/800/90/b/final
- NIST beacons: https://csrc.nist.gov/projects/interoperable-randomness-beacons/
- drand API/verification:
  - https://docs.drand.love/developer/http-api/
  - https://docs.drand.love/developer/examples/

#### Acceptance criteria

- [ ] CSPRNG failure is fatal; optional public/sensor source failure cannot weaken required security.
- [ ] No unmeasured min-entropy claim is made for timing, thermal, mouse, image, or public API inputs.
- [ ] Retained beacons have signature/chain, schema, response-size, freshness, network, and replay validation; otherwise they are removed.
- [ ] Provenance is recorded separately from secret material.
- [ ] Tests cover invalid signatures, malformed/oversized responses, replay, timeout, unavailable X11, working X11, and CSPRNG failure.

## Wave 4 integrated closeout

Each issue owns its related documentation. The final `address-issues` verification must additionally reconcile README, help output, threat model, compatibility matrix, recovery runbook, and hardware-test procedure against the completed implementation. No issue closes on documentation-only evidence where an executable acceptance criterion exists.
