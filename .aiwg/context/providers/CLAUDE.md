# Provider-specific context from CLAUDE.md

Source attribution: migrated from `CLAUDE.md`; checksum `5a55afc99190290ff563e2ef2f787b6ad7836e0cb507176ddcac64197f73a254`.

# CLAUDE.md

This file provides guidance to Claude Code when working with this codebase.

## Repository Purpose

A bash toolkit for generating high-entropy cryptographic seeds and fully initializing YubiKeys with user-controlled secrets. Replaces all factory-programmed credentials (OTP AES keys, PIV PIN, PUK, management key) with entropy derived from multiple independent sources via HKDF-SHA512.

## Tech Stack

- **Language**: Bash (pure shell, no compiled components). Targets bash 3.2.57+ to support Apple's stock `/bin/bash` on macOS — avoid `declare -A`, `mapfile`, `${var,,}`, `${var^^}`, and other bash 4+ features.
- **Runtime**: OpenSSL 3.x via `openssl kdf` (LibreSSL does not have this subcommand), Python 3 (keyboard/mouse capture)
- **Platforms**: Linux (GNU coreutils, sysfs, lm-sensors, X11) and macOS (BSD coreutils, sysctl/ioreg, Quartz). Runtime-branched via `_IS_MACOS` flag set in `yubi-lib.sh`. **Both must keep working** — avoid Linux-only or Mac-only paths without the branch.
- **Hardware**: YubiKey Manager CLI (`ykman`), X11 (Linux only — mouse entropy; falls back to keyboard otherwise)
- **Dependencies**: `curl`, `openssl 3.x`, `ykman`, `python3`. Optional: `lm-sensors` (Linux only — `system_thermal_entropy()` handles macOS via sysctl/ioreg).
- **macOS install**: `brew install openssl@3 ykman` (Apple's bash 3.2 + system python3/curl are sufficient). `yubi-lib.sh` auto-prepends `/opt/homebrew/opt/openssl@3/bin` to PATH on Darwin so `openssl` resolves to brew OpenSSL 3.x rather than `/usr/bin/openssl` (LibreSSL).

## Scripts

| Script | Purpose |
|--------|---------|
| `yubi.sh` | Unified entry point — all commands route through here |
| `yubi-lib.sh` | Shared library (logging, secure delete, tmpfs, entropy file I/O) |
| `bootstrap-entropy.sh` | Interactive seed generation from multiple entropy sources |
| `entropy-mix.sh` | Batch HKDF-SHA512 enrichment of password lists |
| `entropy-collect.sh` | Standalone external entropy collection for air-gapped workflows |
| `entropy-verify.sh` | Entropy file integrity validation and reporting |
| `yubi-mux.sh` | 2-device password collection and random pairing |
| `configure-yubi.sh` | YubiKey programmer (PIV + OTP slots) |
| `init-yubi.sh` | End-to-end pipeline (collect -> mux -> enrich -> program) |

## Usage

```bash
# Generate seeds (no YubiKeys needed)
./yubi.sh bootstrap [count]

# Program a YubiKey from seed pool
./yubi.sh configure <otp|static|mixed> [serial]

# Full pipeline: 2 source keys -> program target
./yubi.sh init <otp|static|mixed> [serial]

# Air-gapped workflow
./yubi.sh entropy-collect [--append file]  # On networked machine
./yubi.sh entropy-verify <file>            # Validate collected entropy
./yubi.sh bootstrap 15 --entropy-file <file>  # On air-gapped machine
./yubi.sh bootstrap 15 --no-external       # Skip APIs entirely

# Info commands
./yubi.sh list          # Connected YubiKeys
./yubi.sh info [serial] # Key details
./yubi.sh status        # Seed pool status
./yubi.sh purge         # Securely delete exhausted seed files
```

## Architecture

- **Single directory**: All scripts live at project root, no subdirectories for source code
- **Shared library**: `yubi-lib.sh` is sourced by all other scripts for common functions (logging, secure delete, entropy file format, external API calls)
- **Portability layer**: `yubi-lib.sh` exposes wrappers used in place of platform-specific commands. **Use these instead of calling `stat`/`date`/`df` directly:** `now_ns`, `file_size`, `file_perms`, `file_mtime`, `df_target`, `iso_to_epoch`, `system_thermal_entropy`. These hide GNU-vs-BSD coreutils differences and `date +%s%N` (which doesn't exist on macOS).
- **Seed storage**: `~/.yubikey-seeds/` (mode 700) with timestamped seed files
- **Entropy files**: Portable `YUBI-ENTROPY-V1` text format for air-gapped external entropy transfer
- **Secure workspace**: `init` mode uses tmpfs (RAM, Linux root only) — sensitive data never touches disk. Falls back to disk-backed + secure_delete on macOS or unprivileged Linux.
- **Entropy mixing**: HKDF with user entropy as IKM, system entropy as salt, unique per-seed labels for domain separation
- **External entropy dispatcher**: `get_external_entropy()` in yubi-lib.sh handles three modes: live API fetch, file-based loading (`--entropy-file`), or disabled (`--no-external`)

## Security Conventions

- All scripts set `umask 077` and `ulimit -c 0` (no core dumps)
- Sensitive files get 3-pass random overwrite + zero + sync + unlink + fstrim
- HKDF salt binding uses YubiKey serial number for device-specific derivation
- Password input uses `read -rs` with masked preview (first/last 5 chars)
- External APIs (random.org, NIST Beacon, drand) use retry+degrade — never block on failure

## Development Notes

- No test framework — this is a security-sensitive interactive toolkit
- Scripts are executable (`chmod +x *.sh`)
- OpenSSL 3.x is required (1.x lacks `openssl kdf` command; LibreSSL also lacks it — relevant on macOS)
- `ykman` passes credentials as CLI arguments — known `/proc` visibility limitation
- **Cross-platform changes must be tested on both Linux and macOS.** Mutsu (macOS 26.4.1, ARM64, bash 3.2.57) is the canonical Mac test target; access via `ssh mutsu-agent`. Use `bash -n <script>` to syntax-check on bash 3.2 before declaring done.
- When adding new commands or features, prefer the portability wrappers (`now_ns`, `file_size`, etc.) over direct `stat`/`date` calls. If you must add a platform-specific path, branch on `_IS_MACOS` and ensure both branches are exercised.

---

## Team Directives & Standards

<!-- PRESERVED SECTION - Content maintained across regeneration -->

<!-- Add team directives, conventions, or project-specific notes here -->
<!-- Use <!-- PRESERVE --> markers for content that must be kept across regeneration -->

<!-- /PRESERVED SECTION -->

---

## AIWG Framework Integration

### Installed Frameworks

| Framework | Version | Installed |
|-----------|---------|-----------|
| sdlc-complete | 1.0.0 | 2026-03-09 |
| forensics-complete | 1.0.0 | 2026-03-09 |
| media-curator | 1.0.0 | 2026-03-09 |
| media-marketing-kit | 1.0.0 | 2026-03-09 |
| research-complete | 1.0.0 | 2026-03-09 |

### Available Assets

- **162 agents** in `.claude/agents/`
- **167 commands** in `.claude/commands/`
- **Rules**: See `.claude/rules/RULES-INDEX.md` for enforcement rules

### Orchestration

The SDLC framework provides full lifecycle orchestration via `/orchestrate-project` and phase-specific flow commands. Use `/project-status` to check current state. Rules are indexed in `.claude/rules/RULES-INDEX.md` — scan summaries and load full rules only when relevant.

---

<!--
  USER NOTES
  Add team directives, conventions, or project-specific notes above in the preserved section.
  Content in preserved sections is maintained during regeneration.
  Use <!-- PRESERVE --> markers for content that must be kept.
-->
