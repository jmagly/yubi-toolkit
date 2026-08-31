# Current-state research: YubiKey toolkit audit

**Prepared:** 2026-08-30
**Scope:** Current YubiKey provisioning tooling, shell engineering/testing, entropy handling, and sensitive temporary storage.
**Method:** Repository inspection plus retrieval of primary vendor/standards documentation. URLs below were retrieved on 2026-08-30. This note is issue-planning evidence, not an implementation change.

## Executive summary

The repository's core design—OpenSSL 3 HKDF, explicit target serials, per-purpose HKDF labels, restrictive permissions, and support for the current `ykman` CLI—is directionally sound. The implementation is nevertheless unsafe to describe as secure or complete today. Two concrete file-lifecycle bugs can retain seed material; provisioning puts secrets in process arguments and prints recovery credentials; public randomness beacons are treated as secret entropy without authenticity verification; character derivation is biased; the claimed Bash 3.2 support is neither tested nor currently credible; and the workflow configures only PIV, OTP, and optionally FIDO while reporting a fully initialized device.

The local environment further demonstrates version drift: `ykman --version` reports 5.5.1 while upstream's latest release is 5.9.2 (2026-06-30). Compatibility should be defined and tested, not inferred from command presence.

## Repository baseline

- There are nine shell entry/library files and no committed test directory, CI workflow, ShellCheck configuration, dependency lock/version policy, or mocked hardware interface.
- README claims Linux Bash 4+ and macOS Bash 3.2.57+ support (`README.md:52-62`, `README.md:96-101`), but the current workstation only verifies GNU Bash 5.2.21.
- ShellCheck 0.9.0 is installed locally, but there is no repository-enforced invocation. The current code contains a definite top-level `local` error at `bootstrap-entropy.sh:385`.
- Provisioning scope is PIV credentials (`configure-yubi.sh:330-402`), OTP slots (`configure-yubi.sh:404-432`), and a best-effort FIDO PIN (`configure-yubi.sh:454-474`). It does not reset, configure, or verify OATH, OpenPGP, YubiHSM Auth, Security Domain, interface state, configuration lock, or existing FIDO credentials.

## Findings for issue filing

### 1. Critical — tmpfs cleanup state is lost through command substitution

**Repository evidence**

- `init-yubi.sh:74` calls `WORKDIR=$(secure_tmpfs_create "init-yubi")`, then installs `secure_tmpfs_cleanup` as the EXIT trap at line 75.
- `secure_tmpfs_create` assigns global `SECURE_TMPFS_DIR` and `SECURE_TMPFS_MOUNTED` at `yubi-lib.sh:292-313`; because command substitution executes in a subshell, those assignments do not survive in the caller.
- Cleanup returns immediately when the parent shell's directory global is empty (`yubi-lib.sh:316-319`). A mounted tmpfs can remain mounted; a disk-backed directory can remain with mux/enriched seed material.
- README promises RAM-only operation and cleanup at `README.md:218-222` and `README.md:255-265`.

**Current practice and issue acceptance direction**

Keep state mutation in the calling shell: call the function directly, consume `SECURE_TMPFS_DIR`, and do not transport state through stdout. Add tests for success, command failure, SIGINT, and SIGTERM; each must prove that the exact directory is absent and any exact mount is gone. Avoid falling back silently to durable storage for high-sensitivity one-shot provisioning; require an explicit opt-in or an encrypted/OS-protected alternative.

NIST SP 800-88 Rev. 2 defines sanitization by the outcome—access to target data must be infeasible for the relevant effort—not by a fixed overwrite ritual [S3].

### 2. Critical — consumed seed replacement does not sanitize the original inode

**Repository evidence**

- `configure-yubi.sh:481-500` writes unconsumed lines to a new file and renames it over the pool. The old inode is merely unlinked by the rename; it is never passed to `secure_delete`.
- The later deletion at `configure-yubi.sh:505-509` applies to the replacement only when it is empty.
- `secure_delete` performs three random passes, a zero pass, unlink, and optional filesystem trim (`yubi-lib.sh:222-262`), while README describes this as secure deletion (`README.md:255-265`).

**Current practice and issue acceptance direction**

Stop asserting that application-level overwrite plus unlink guarantees sanitization on SSDs, copy-on-write/journaled filesystems, snapshots, or backups. Prefer never writing plaintext seeds to durable storage; otherwise use encrypted-at-rest pools with destroyable keys and document storage-level sanitization as an operator responsibility. Tests should establish dataflow and file lifecycle, not claim physical-media erasure from a unit test. Align terminology and threat claims with NIST SP 800-88 Rev. 2 [S3].

### 3. High — credentials are exposed in argv and terminal output

**Repository evidence**

- PIV management key, PUK, and PIN are supplied as command options at `configure-yubi.sh:359-401`.
- OTP AES/private IDs and static passwords are supplied as arguments at `configure-yubi.sh:404-432`.
- FIDO PIN is supplied as an argument at `configure-yubi.sh:462-467`.
- Derived PIN, PUK, and complete management key are printed at `configure-yubi.sh:532-538`; even the plan leaks partial secrets at `configure-yubi.sh:284-315`.
- README acknowledges `/proc/PID/cmdline` exposure at `README.md:319`, but acceptance of a known exposure is not a mitigation.

**Current practice and issue acceptance direction**

Yubico's PIV Tool guide explicitly advises omitting secret arguments so prompting keeps them out of command-line history [S7]. For robust automation, prefer a supported Yubico library/API or a controlled interactive/stdin mechanism that keeps secrets out of argv; verify actual `ykman` behavior for every command/version before choosing a transport. Never render full or partial cryptographic keys in normal output. Provide a secure recovery-output destination with exclusive creation and an explicit operator choice, or require operator-supplied independently managed credentials.

Yubico's current `ykman` PIV documentation confirms the relevant command options and supports generating/protecting a random management key on-device [S1]. That is a materially safer policy option than deriving and displaying it when recovery requirements allow.

### 4. High — tool/firmware capability policy is stale and under-specified

**Repository evidence**

- README requires only an unspecified “YubiKey Manager CLI” (`README.md:52-59`). Scripts check command presence but do not enforce or report a supported version range.
- Local `ykman` is 5.5.1; upstream latest is 5.9.2, released 2026-06-30 [S2].
- Firmware branching in `configure-yubi.sh:130-148` selects AES-256 for firmware >=5.4.2 and TDES otherwise. README presents AES-256 as the modern behavior (`README.md:312`).
- Completion says “fully initialized” (`configure-yubi.sh:528`) despite only touching a subset of applications.

**Current practice and issue acceptance direction**

Define a tested `ykman` support window (minimum plus current), add a doctor/preflight command, parse stable machine-readable output where available, and test a matrix against representative fixture outputs. Current Yubico documentation covers applications beyond PIV/OTP/FIDO—including OATH, OpenPGP, YubiHSM Auth, configuration lock, interfaces, and Security Domain [S4]. Either make application scope explicit (“PIV/OTP provisioning with optional FIDO PIN”) or implement an explicit per-application policy and post-provision verification.

YubiKey firmware 5.7 defaults the PIV management key to AES-192; AES-128/192/256 remain supported options, while 5.4–5.6 default to TDES [S9]. AES-256 is therefore a valid project policy, but not the current vendor default. Capability detection must also account for FIPS models and firmware-specific constraints.

### 5. High — no automated shell, portability, or hardware-contract tests

**Repository evidence**

- No `.github/workflows`, `.gitlab-ci.yml`, test directory, Bats files, Makefile/check target, or ShellCheck configuration is committed.
- `bootstrap-entropy.sh:385` executes `local mouse_hash` at script top level. Bash reports `local: can only be used in a function` if that X11 branch succeeds.
- README's Bash 3.2 promise (`README.md:56`, `README.md:101`) is contradicted by C-style array append syntax such as `dev1+=("$line")` (`init-yubi.sh:109-115`), which needs execution on an actual Bash 3.2 runner or container/image to validate rather than comments asserting compatibility.

**Current practice and issue acceptance direction**

Add a pinned ShellCheck gate and Bats tests. ShellCheck is designed for build/test integration and recommends pinning a version to avoid surprise new-warning failures [S5]. Bats is TAP-compliant and supports Bash 3.2+, making it suitable for the claimed compatibility floor [S6].

The test design should include: syntax and lint; Bash 3.2 and current Bash execution; mocked `ykman` 5.5/current command contracts; Linux/macOS branches; no-device/multiple-device handling; tmpfs cleanup under signals; failure injection after each irreversible provisioning step; secret non-disclosure in argv/logs; and post-provision verification. Hardware tests must be opt-in, use designated disposable keys, and never run in ordinary CI.

### 6. Medium — beacon data is public, unauthenticated, and overstated as entropy

**Repository evidence**

- NIST Beacon and drand HTTP responses are fetched and mixed as `EXT_NIST`/`EXT_DRAND` without signature or chain verification (`yubi-lib.sh:383-394`, `entropy-collect.sh:145-167`).
- README lists them as entropy sources (`README.md:11-29`), says accumulation is “stronger” (`README.md:168-171`), and says unpredictability survives if any source is genuinely random (`README.md:236-245`). Published beacon output is public, so it cannot add secret min-entropy after publication.
- Interactive keyboard, mouse, thermal, and disk-jitter data are also called entropy without a min-entropy model or continuous health tests.

**Current practice and issue acceptance direction**

Treat public beacons as optional public diversification/audit values, not secret entropy. Authenticate/verify signed beacon values and bind source identity, chain/round, retrieval time, and raw-response digest into the record. Make OS CSPRNG output the security foundation; characterize interactive/sensor inputs as supplemental and do not assign entropy credit without a defensible model.

NIST SP 800-90B requires entropy-source design, min-entropy assessment, and health testing rather than inferring entropy from varied-looking samples [S8]. The repository implements none of that validation. Claims should be narrowed accordingly.

### 7. Medium — biased credential alphabet mapping and cross-application PIN reuse

**Repository evidence**

- Numeric and alphanumeric derivation map each byte with `% 10` and `% 62` (`configure-yubi.sh:225-253`). Because 256 is divisible by neither 10 nor 62, output symbols are not equiprobable.
- FIDO is assigned the exact PIV PIN (`configure-yubi.sh:454-467`, `README.md:233-235`, `README.md:313`). This collapses two application credentials into one compromise domain.

**Current practice and issue acceptance direction**

Use rejection sampling (discard byte values above the largest multiple of the alphabet size) and expand HKDF output as needed. Derive PIV and FIDO PINs with separate, versioned info labels and expose policy switches only where hardware forces sharing. Yubico documents FIDO PIN length/configuration independently from PIV [S10]; the technical manual notes a shared PIN specifically for the YubiKey Bio Multi-protocol Edition, implying capability/model-aware handling rather than universal reuse [S11]. Add deterministic vectors, distribution/property tests, and model-specific fixtures.

### 8. Medium — provisioning lacks transaction semantics and truthful verification

**Repository evidence**

- Operations are sequential and irreversible: PIV management key, PUK, PIN, OTP slots, then FIDO (`configure-yubi.sh:330-474`). Failure after any step leaves partial configuration.
- Seed consumption happens only after the command sequence (`configure-yubi.sh:477-509`), but no durable transaction journal captures which device/applications changed.
- The script reports success without reading back and verifying PIV/OTP/FIDO state (`configure-yubi.sh:519-538`).

**Current practice and issue acceptance direction**

Introduce a staged plan and non-secret journal keyed by serial, firmware, application, action, and outcome. Define resumability and manual recovery for every failure boundary. After writes, query each application and verify all non-secret state (algorithm, slot mode, PIN-set status where observable, retries/policies, interfaces). Final wording must reflect exactly what was verified. Yubico's current CLI exposes application-specific `info` and management commands needed for capability-aware checks [S4].

## Suggested issue dependency order

1. Fix and test secure workspace lifecycle (Finding 1).
2. Redesign plaintext seed persistence/sanitization semantics (Finding 2).
3. Eliminate credential exposure and define recovery-output policy (Finding 3).
4. Add the test harness, CI gates, and mocked `ykman` contracts (Finding 5).
5. Add version/capability preflight and scoped provisioning semantics (Finding 4).
6. Add transaction journal, recovery, and read-back verification (Finding 8).
7. Correct entropy/beacon handling and documentation (Finding 6).
8. Replace biased mapping and separate application PIN derivation (Finding 7).

Findings 1–3 should block a security/reliability release. Findings 4–5 are enabling work for safely completing and proving the remaining changes.

## Sources

- **[S1]** Yubico, “PIV Commands — YubiKey Manager (ykman) CLI Guide,” current documentation. https://docs.yubico.com/software/yubikey/tools/ykman/PIV_Commands.html
- **[S2]** Yubico, “YubiKey Manager releases,” latest release 5.9.2 dated 2026-06-30. https://github.com/Yubico/yubikey-manager/releases
- **[S3]** NIST, *SP 800-88 Rev. 2: Guidelines for Media Sanitization*, final 2025-09-26. https://csrc.nist.gov/pubs/sp/800/88/r2/final (DOI: https://doi.org/10.6028/NIST.SP.800-88r2)
- **[S4]** Yubico, “YubiKey Manager (ykman) CLI User Guide,” current command/application index. https://docs.yubico.com/software/yubikey/tools/ykman/index.html
- **[S5]** ShellCheck project, “ShellCheck, a static analysis tool for shell scripts,” build/test integration and version-pinning guidance. https://github.com/koalaman/shellcheck
- **[S6]** bats-core, “Welcome to bats-core's documentation,” Bash 3.2+ support and TAP-compliant Bash testing. https://bats-core.readthedocs.io/en/stable/
- **[S7]** Yubico, “Set up PIV Tool,” guidance to omit secret command arguments and use prompting. https://docs.yubico.com/software/yubikey/tools/pivtool/piv-tool-setup.html
- **[S8]** NIST, *SP 800-90B: Recommendation for the Entropy Sources Used for Random Bit Generation*, including min-entropy and health-test requirements; 2025 errata notice. https://csrc.nist.gov/pubs/sp/800/90/b/final (DOI: https://doi.org/10.6028/NIST.SP.800-90B)
- **[S9]** Yubico, “5.7–5.6 Firmware Specifics,” PIV management-key algorithms and defaults. https://docs.yubico.com/hardware/yubikey/yk-tech-manual/yk5-firmware-5.7.html
- **[S10]** Yubico, “FIDO Commands — YubiKey Manager CLI Guide,” PIN and minimum-length controls. https://docs.yubico.com/software/yubikey/tools/ykman/FIDO_Commands.html
- **[S11]** Yubico, “FIDO Specifics — YubiKey Technical Manual,” firmware-dependent minimum PIN length and Bio Multi-protocol shared-PIN exception. https://docs.yubico.com/hardware/yubikey/yk-tech-manual/yk5-apps-fido.html

## Evidence limitations

- No YubiKey was mutated or queried beyond the installed `ykman` version; firmware/model behavior is based on retrieved Yubico documentation.
- The local ShellCheck version is 0.9.0, not current 0.11.0, so the top-level `local` defect is supported by Bash semantics and repository inspection rather than treating this workstation's lint set as exhaustive.
- No claim is made that a software-only test can prove physical storage sanitization. That outcome depends on media, filesystem, encryption, snapshots/backups, and operator controls.
