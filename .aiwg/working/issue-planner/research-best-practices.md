# Research brief: YubiKey toolkit security engineering practices

**Prepared:** 2026-08-30
**Scope:** Bash secret handling, ephemeral storage and deletion, provisioning failure handling, entropy/KDF design, and automated testing.
**Method:** Repository source was compared with current primary standards and vendor documentation. All URLs below were retrieved during this audit. This is issue-planning evidence, not a claim of formal NIST validation or FIPS compliance.

## Executive summary

The highest-priority defects are not cryptographic primitive choices; they are lifecycle failures around secrets. The tmpfs helper is called in command substitution, so the parent shell loses the helper's cleanup state. Seed-file replacement unlinks the inode containing consumed secrets without sanitizing it. Provisioning credentials are passed in process arguments and printed to the terminal. These behaviors conflict with the repository's security claims and with authoritative guidance.

The recommended design is: make a verified, fail-closed ephemeral workspace the prerequisite for provisioning; regard ordinary filesystem overwrite as deletion rather than guaranteed sanitization; keep secrets out of argv and logs; model provisioning as a resumable state machine with preflight, per-step verification, and a recovery record; rely on the operating system CSPRNG for secret entropy; treat public beacons only as authenticated public diversification; apply HKDF domain separation correctly; and enforce all invariants with shell lint, unit tests, mocked `ykman` integration tests, and hardware-in-the-loop tests kept outside ordinary CI.

## BP-01 — Make ephemeral workspace ownership and cleanup fail closed

**Repository evidence**

- `init-yubi.sh:74` assigns `WORKDIR=$(secure_tmpfs_create "init-yubi")`; `init-yubi.sh:75` installs the cleanup trap afterward.
- `yubi-lib.sh:289-290` stores lifecycle state in global variables, while `yubi-lib.sh:292-314` mutates those globals inside the function.
- `yubi-lib.sh:316-334` depends on those globals to unmount or erase the workspace.
- GNU Bash documents that command substitution executes in a subshell and that changes made there cannot affect the parent execution environment. Therefore the parent cleanup trap sees its original empty/false state.
- The helper silently falls back to disk at `yubi-lib.sh:309-311`, even for a workflow that handles provisioning seeds.

**Authoritative practice**

- Call the allocator in the current shell, then read its global/output variable; install traps before any secret is written. Preserve and re-raise termination status where appropriate, and make cleanup idempotent.
- Refuse to continue with secret generation/provisioning unless the user explicitly opts into a documented disk-backed mode. Verify the actual filesystem type/mount ID after creation instead of trusting only the return status of `mount`.
- Linux tmpfs stores files in virtual memory and loses them on unmount, but the kernel documentation explicitly warns that tmpfs pages may be swapped. Use `noswap` where the running kernel supports it, or require encrypted/disabled swap and document the residual memory/cold-boot threat. `mode=0700`, bounded size, no inherited broad permissions, and exclusive ownership are baseline controls.
- Do not claim “RAM-backed, never hits disk” without accounting for swap.

**Acceptance criteria for an issue**

1. `secure_tmpfs_create` is called without command substitution and returns its path through parent-shell state.
2. EXIT, INT, TERM, and HUP tests demonstrate cleanup after success and injected failures.
3. Tests assert no orphan mount and no work directory after exit.
4. The program fails closed when ephemeral storage cannot be established unless an explicit, prominently warned override is supplied.
5. Documentation distinguishes tmpfs from non-swappable or locked memory.

**Sources**

- GNU Bash, “Command Substitution”: https://www.gnu.org/s/bash/manual/html_node/Command-Substitution.html
- GNU Bash, “Command Execution Environment”: https://www.gnu.org/software/bash/manual/html_node/Command-Execution-Environment.html
- Linux kernel, “Tmpfs”: https://www.kernel.org/doc/html/latest/filesystems/tmpfs.html

## BP-02 — Replace overwrite-based “secure deletion” claims with storage-lifecycle controls

**Repository evidence**

- `yubi-lib.sh:212-218` describes four overwrite passes, sync, unlink, and filesystem-wide trim as “defense in depth”; implementation is at `yubi-lib.sh:222-263`.
- `configure-yubi.sh:481-500` writes retained lines to a new inode and renames that inode over the input. The original inode containing consumed lines is merely unlinked; `secure_delete` is never applied to it.
- `configure-yubi.sh:505-508` only overwrites the replacement file if it becomes empty.
- `README.md:259-265` claims disk fallback is securely overwritten and tmpfs avoids persistent storage. Those statements exceed what the implementation and storage stack can prove.

**Authoritative practice**

- NIST SP 800-88 Rev. 2 defines sanitization by making target data access infeasible for the applicable threat level and emphasizes a media-sanitization program and appropriate techniques. A userspace overwrite of a pathname cannot guarantee coverage of SSD remapping, copy-on-write extents, journals, snapshots, backups, controller caches, or the already-unlinked inode replaced by `rename`.
- Prevent plaintext persistence: keep working seeds only in verified ephemeral storage, or place the seed pool in an encrypted container whose independently generated data-encryption key can be destroyed. Treat ordinary unlink/overwrite as best-effort cleanup, never as verified media sanitization.
- `fstrim` acts on a filesystem/mount, not a single file, and is not proof that every physical copy of a secret is inaccessible. It should not be invoked automatically as a per-file deletion primitive.
- If persistent seed pools remain a supported feature, document the storage threat model, backups/snapshots behavior, recovery model, and the exact limit of deletion guarantees.

**Acceptance criteria for an issue**

1. No user-facing text says a normal file was “securely deleted” solely because it was overwritten/unlinked.
2. The seed-consumption algorithm never stages plaintext on an unverified persistent filesystem by default.
3. Persistent mode uses encryption-at-rest with a documented key lifecycle, or is explicitly classified as outside strong deletion guarantees.
4. Tests cover rename/replacement, interruption before/after commit, symlinks, snapshots being out of scope, and empty/non-empty pools.
5. Automatic filesystem-wide trim is removed from a pathname-level deletion helper or clearly separated as an administrator operation.

**Source**

- NIST SP 800-88 Rev. 2, “Guidelines for Media Sanitization” (September 2025): https://csrc.nist.gov/pubs/sp/800/88/r2/final

## BP-03 — Keep PINs, PUKs, management keys, OTP keys, and static passwords out of argv and output

**Repository evidence**

- `configure-yubi.sh:359-376` places both current and new management keys into a Bash array passed to `ykman`.
- `configure-yubi.sh:383-400` passes PUK and PIN values as CLI option arguments.
- `configure-yubi.sh:460-465` passes the FIDO PIN in argv.
- OTP/static programming functions are invoked with key/password variables at `configure-yubi.sh:440-447`; the invoked `ykman` processes likewise receive secret options.
- `configure-yubi.sh:313-315` prints partial credentials before confirmation. `configure-yubi.sh:532-540` prints the complete management key, PUK, and PIN and tells the user to clear scrollback afterward.

**Authoritative practice**

- Yubico's own PIV Tool setup guide warns that supplying keys and PINs as arguments leaves traces in command history and recommends omitting the value so the tool prompts for it. The same exposure class includes `/proc/<pid>/cmdline`, process listings, wrappers, audit systems, CI logs, and terminal capture.
- Prefer supported hidden interactive prompts or a Yubico library/API that accepts secrets in process memory rather than argv. If automation requires stdin, first prove from the exact supported tool/version that the relevant prompt reads a dedicated input stream and cannot be confused with confirmation input.
- Never show partial secrets: prefixes/suffixes still disclose information and make accidental recording likely. Output only identifiers, algorithm/length metadata, and success/failure state.
- Recovery credentials should be transferred to an explicit secure sink (for example, an operator-selected password-manager import or root-owned encrypted recovery bundle), never terminal scrollback. Avoid exported environment variables because `/proc` and child inheritance can expose them too.

**Acceptance criteria for an issue**

1. An integration test samples child-process argv and proves no generated secret appears.
2. Logs and captured stdout/stderr contain no full or partial secret values.
3. Interactive and automation modes use documented secret-input channels for every supported `ykman` version.
4. The recovery/export path is explicit, permission-restricted, and redacted by default.
5. Debug/error modes cannot dump command arrays or secret variables.

**Sources**

- Yubico PIV Tool, “Preparing a YubiKey for Real Use”: https://docs.yubico.com/software/yubikey/tools/pivtool/piv-tool-setup.html
- YubiKey Manager CLI, PIV commands and supported prompt/options surface: https://docs.yubico.com/software/yubikey/tools/ykman/PIV_Commands.html
- YubiKey Manager CLI, FIDO commands: https://docs.yubico.com/software/yubikey/tools/ykman/FIDO_Commands.html

## BP-04 — Model destructive provisioning as a recoverable state machine

**Repository evidence**

- `configure-yubi.sh:337-400` mutates management key, then PUK, then PIN. Later failures explicitly acknowledge that earlier mutations remain.
- `configure-yubi.sh:440-449` acknowledges that PIV and one OTP slot may already be changed when slot 2 fails.
- `configure-yubi.sh:468-471` permits FIDO setup failure as a warning, but `configure-yubi.sh:528` still declares the device “fully initialized.”
- `configure-yubi.sh:340-355` offers an in-flow destructive PIV reset after a management-key attempt fails.
- Verification at `configure-yubi.sh:515-518` prints application info, but does not verify all desired postconditions or credential usability.

**Authoritative practice**

- Hardware application mutations are not generally atomically rollbackable. Treat the workflow as a persisted state machine: inventory and validate capabilities first; display an application-scoped change plan; checkpoint after each verified mutation; on failure emit a redacted recovery record identifying completed, uncertain, and pending steps.
- Separate application resets from normal provisioning and require an application-specific confirmation that states precisely what is erased. Never imply a PIV reset also resets OTP/FIDO or vice versa.
- Verification must exercise desired postconditions: correct application availability, slot configuration, successful authentication with new credentials (without exposing them), and expected retry/minimum-PIN policies. A warning on a requested component means overall status is partial, not complete.
- Current `ykman` is designed to manage individual applications including FIDO, PIV, OTP, OATH, OpenPGP, YubiHSM Auth, configuration locks and interfaces. Define the toolkit's scope explicitly rather than using “fully initialized.”

**Acceptance criteria for an issue**

1. Preflight captures serial, firmware, enabled applications/transports, current non-secret state, and command compatibility before mutation.
2. Each mutation has a postcondition check and a checkpoint state.
3. Fault injection after every `ykman` call yields an accurate recovery plan and never consumes seed inputs prematurely.
4. Reset actions are separate, scoped, and independently confirmed.
5. Completion is `complete`, `partial`, or `failed`; “complete” requires every requested postcondition.

**Sources**

- YubiKey Manager CLI introduction and supported applications: https://docs.yubico.com/software/yubikey/tools/ykman/intro.html
- YubiKey Manager PIV command semantics, including reset-related retry behavior: https://docs.yubico.com/software/yubikey/tools/ykman/PIV_Commands.html
- YubiKey Manager FIDO command semantics and application reset: https://docs.yubico.com/software/yubikey/tools/ykman/FIDO_Commands.html

## BP-05 — Use the OS CSPRNG as the entropy root; classify beacons and sensor data honestly

**Repository evidence**

- `bootstrap-entropy.sh:443-444` describes keyboard, mouse, CPU RNG, thermal, jitter, and external APIs as things every seed “mixes.”
- `bootstrap-entropy.sh:453-483` obtains `openssl rand` output but also hashes sensor/public-source values.
- `bootstrap-entropy.sh:485-498` puts interactive data in HKDF IKM and puts the CSPRNG, system signals, and external values in the salt.
- `yubi-lib.sh:376-393` and `entropy-collect.sh:147-164` fetch raw NIST/drand HTTP responses without cryptographic beacon verification.
- `bootstrap-entropy.sh:385` uses `local` at script top level, which causes the X11-success path to fail before entropy generation.

**Authoritative practice**

- Make a platform CSPRNG (`getrandom`/OpenSSL RAND when correctly seeded) the required secret entropy source. Optional human/sensor inputs may be mixed as uncredited supplementary input, but must not be assigned unmeasured min-entropy or used to justify stronger claims.
- NIST SP 800-90B requires a defined noise source, entropy assessment, conditioning, and startup/continuous health testing for entropy-source claims. Hashing timing, thermal, mouse, or image data does not itself establish an entropy estimate.
- Public randomness beacons are public. They can provide freshness, auditability, or attacker-independent public diversification, but cannot increase secrecy after publication. drand specifically says signature verification is important and recommends client libraries that verify rounds. Pin the chain hash/public key and verify round signatures, or label fetched beacon material unauthenticated and do not rely on it for security.
- Network failure or attacker-controlled public salt must not reduce the security supplied by the local CSPRNG. External responses should have strict timeouts, size/schema bounds, TLS validation, and provenance.

**Acceptance criteria for an issue**

1. Documentation designates the CSPRNG as the entropy root and makes no quantitative claims for unassessed sensors.
2. A CSPRNG failure is fatal; optional-source failure only removes diversification.
3. drand (and any signed beacon used for authenticity) is cryptographically verified against pinned network parameters; malformed/replayed/oversized data is rejected.
4. Tests cover absent X11, working X11, bad beacon signatures, timeouts, duplicates/replays, empty responses, and CSPRNG failure.
5. The top-level `local` error is fixed and made a ShellCheck-blocking regression test.

**Sources**

- NIST SP 800-90B, entropy-source design and health testing: https://csrc.nist.gov/pubs/sp/800/90/b/final
- NIST Random Bit Generation project, conditioning guidance: https://csrc.nist.gov/projects/random-bit-generation/sp-800-90-updates
- drand HTTP API (verification importance): https://docs.drand.love/developer/http-api/
- drand client example with chain hash/public key verification: https://docs.drand.love/developer/examples/

## BP-06 — Use HKDF inputs for their specified roles and preserve domain separation

**Repository evidence**

- Credential derivation uses distinct labels and device serial salt at `configure-yubi.sh:205-222` and `configure-yubi.sh:259-268`; this is a sound domain-separation direction.
- Bootstrap generation places the strongest secret value, `openssl rand`, in `salt_hex` at `bootstrap-entropy.sh:453-454` and `bootstrap-entropy.sh:496-498`, while interactive input becomes IKM at `bootstrap-entropy.sh:485-494`.
- Public external inputs are also placed into salt, and the construction is described as producing stronger entropy without a formal input model.

**Authoritative practice**

- RFC 5869 defines IKM as input keying material, salt as optional non-secret random data independent of IKM, and `info` as context/application-specific data. It explicitly says extraction concentrates existing entropy; a KDF does not create entropy.
- Put the required high-entropy secret CSPRNG output in IKM. If supplementary secret inputs are retained, frame and concatenate them unambiguously into IKM. Use a non-secret, independent salt and versioned `info` containing purpose, algorithm, output length, application, and device identifier as appropriate.
- Continue distinct labels for PIV PIN, PUK, management key, OTP slot/key/private ID, and FIDO PIN. Do not reuse the PIV PIN for FIDO: derive it with a separate label and policy so compromise/retry behavior is separated across applications.
- Version the derivation format and publish deterministic known-answer vectors using non-secret fixtures before changing it, so recovery/reprovision behavior is intentional.

**Acceptance criteria for an issue**

1. A short design document defines IKM, salt, info, framing, encoding, versioning, and threat assumptions.
2. CSPRNG output is IKM; external public inputs never count as secret entropy.
3. Every credential/application has a unique, versioned `info` label; FIDO and PIV PINs differ.
4. Known-answer tests cover all derived artifacts and detect encoding/domain-label regressions.
5. Migration/recovery behavior for existing derivation version 1 is explicit.

**Source**

- IETF RFC 5869, “HMAC-based Extract-and-Expand Key Derivation Function”: https://www.rfc-editor.org/info/rfc5869/

## BP-07 — Remove modulo bias when mapping derived bytes to constrained alphabets

**Repository evidence**

- `configure-yubi.sh:225-235` maps each byte with `% 10`; because 256 is not divisible by 10, digits 0–5 have 26 preimages and 6–9 have 25.
- `configure-yubi.sh:239-251` maps each byte with `% 62`; because 256 is not divisible by 62, four characters have five preimages and the rest have four.
- The functions request exactly one byte per output character, leaving no bytes available for rejection sampling.

**Practice and actionable pattern**

- Use rejection sampling: for alphabet size `n`, accept byte values below `floor(256/n)*n`, then map accepted values modulo `n`; derive/refill enough HKDF output until the required length is produced.
- Alternatively derive a sufficiently large integer and perform a rigorously specified uniform reduction over the full credential space. Rejection sampling is easier to review and test in Bash.
- Preserve deterministic derivation by specifying the refill/counter protocol and adding known-answer and distribution/property tests. This finding is mathematically demonstrable from the code and does not depend on an external policy source.

**Acceptance criteria for an issue**

1. Both character mappers use a specified deterministic rejection algorithm.
2. Tests force rejection-boundary bytes and validate refill behavior.
3. Large-sample property tests use tolerances only as a supplemental check; exact boundary/unit tests remain authoritative.
4. Derivation version changes so existing recovery semantics are not silently altered.

## BP-08 — Establish a compatibility and security test pyramid

**Repository evidence**

- No files were found under `.github/workflows/`, `test/`, or `tests/` during this audit.
- `bootstrap-entropy.sh:385` contains a ShellCheck-detectable `local` outside a function.
- `yubi-lib.sh:274-275` pipes `find` into a loop, placing loop execution in a subshell in Bash; future stateful cleanup changes here would inherit the same class of defect.
- The scripts claim Bash/macOS portability while using arrays, substring syntax, platform tools, mounts, terminal input, network services, and version-sensitive `ykman` commands—each needs explicit coverage.

**Authoritative practice**

- Run `bash -n` and ShellCheck on every shell file as mandatory CI gates. ShellCheck's documented rules catch real execution/environment hazards, but lint complements rather than replaces behavior tests.
- Add a Bash test framework or a small explicit harness. Unit-test pure functions; run integration tests with a fake `ykman` executable that records argv/stdin and supports deterministic failures after every operation.
- Test the declared minimum Bash versions and OS tool variants in containers/VMs/runners. Because macOS ships an older Bash, either continually test the exact supported version or raise/document the minimum and remove incompatible claims.
- Separate tests into: no-hardware CI; privileged Linux namespace tests for tmpfs/mount cleanup; and opt-in hardware-in-the-loop tests on dedicated sacrificial keys. Never run destructive hardware tests on a developer's unspecified key.

**Minimum matrix and gates**

1. Syntax + ShellCheck with zero untriaged warnings.
2. Supported Bash minimum and current Bash on Linux; declared macOS Bash/runtime on macOS.
3. Mocked oldest-supported and current `ykman` command surfaces.
4. OpenSSL supported-minimum and current version, with HKDF known-answer vectors.
5. Signal/fault injection at every provisioning and file-commit boundary.
6. Security assertions: no secrets in argv/logs; restrictive permissions at creation; no leftover mounts/files; seed consumption only after verified provisioning.
7. Hardware tests selected by exact serial and guarded by a destructive-test environment flag plus interactive confirmation.

**Sources**

- ShellCheck documentation: https://www.shellcheck.net/wiki/
- GNU Bash execution environments (subshell behavior): https://www.gnu.org/software/bash/manual/html_node/Command-Execution-Environment.html
- YubiKey Manager CLI guide (current command surface): https://docs.yubico.com/software/yubikey/tools/ykman/intro.html

## Suggested issue dependency order

1. BP-08 foundational test harness and fake `ykman` (needed to change high-risk paths safely).
2. BP-01 tmpfs lifecycle and fail-closed workspace.
3. BP-03 secret transport/output removal.
4. BP-02 persistent seed-storage and deletion redesign.
5. BP-04 provisioning state machine, scoped resets, and verification.
6. BP-05 entropy-source model and authenticated beacon handling.
7. BP-06 HKDF construction/versioning and PIN separation.
8. BP-07 unbiased character mapping, released with the derivation-version change.

BP-01 through BP-04 should block claims that the toolkit securely provisions production keys. BP-05 through BP-07 are cryptographic design corrections and should be implemented behind deterministic test vectors and an explicit derivation-version migration.

## Full source inventory

- NIST, **SP 800-88 Rev. 2: Guidelines for Media Sanitization**, September 2025. https://csrc.nist.gov/pubs/sp/800/88/r2/final
- NIST, **SP 800-90B: Recommendation for the Entropy Sources Used for Random Bit Generation**, January 2018 (2025 errata noted by NIST). https://csrc.nist.gov/pubs/sp/800/90/b/final
- NIST, **Random Bit Generation / SP 800-90 updates**. https://csrc.nist.gov/projects/random-bit-generation/sp-800-90-updates
- IETF, **RFC 5869: HMAC-based Extract-and-Expand Key Derivation Function**, May 2010. https://www.rfc-editor.org/info/rfc5869/
- GNU, **Bash Reference Manual: Command Substitution**. https://www.gnu.org/s/bash/manual/html_node/Command-Substitution.html
- GNU, **Bash Reference Manual: Command Execution Environment**. https://www.gnu.org/software/bash/manual/html_node/Command-Execution-Environment.html
- Linux kernel, **Tmpfs documentation**. https://www.kernel.org/doc/html/latest/filesystems/tmpfs.html
- Yubico, **YubiKey Manager CLI Introduction**. https://docs.yubico.com/software/yubikey/tools/ykman/intro.html
- Yubico, **YubiKey Manager PIV Commands**. https://docs.yubico.com/software/yubikey/tools/ykman/PIV_Commands.html
- Yubico, **YubiKey Manager FIDO Commands**. https://docs.yubico.com/software/yubikey/tools/ykman/FIDO_Commands.html
- Yubico, **YubiKey PIV Tool: Preparing a YubiKey for Real Use**. https://docs.yubico.com/software/yubikey/tools/pivtool/piv-tool-setup.html
- drand, **HTTP API**. https://docs.drand.love/developer/http-api/
- drand, **Client examples and verification parameters**. https://docs.drand.love/developer/examples/
- ShellCheck, **Wiki/documentation**. https://www.shellcheck.net/wiki/

## Research limitations

- This brief did not execute destructive operations on a YubiKey.
- It did not claim certification or compliance; NIST publications are used as engineering references.
- The repository's tracker issues should quote/paraphrase the actionable content above and retain the cited URLs, but implementation must verify the exact installed/supported `ykman` CLI behavior rather than assume options are stable across releases.
