# CLAUDE.md

This file provides guidance to Claude Code when working with this codebase.

## Repository Purpose

A bash toolkit for generating high-entropy cryptographic seeds and fully initializing YubiKeys with user-controlled secrets. Replaces all factory-programmed credentials (OTP AES keys, PIV PIN, PUK, management key) with entropy derived from multiple independent sources via HKDF-SHA512.

## Tech Stack

- **Language**: Bash (pure shell, no compiled components)
- **Runtime**: bash 4.0+, OpenSSL 3.x (HKDF support), Python 3 (keyboard/mouse capture)
- **Hardware**: YubiKey Manager CLI (`ykman`), X11 (mouse entropy)
- **Dependencies**: `curl`, `lm-sensors`, `openssl`, `ykman`, `python3`

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
- **Seed storage**: `~/.yubikey-seeds/` (mode 700) with timestamped seed files
- **Entropy files**: Portable `YUBI-ENTROPY-V1` text format for air-gapped external entropy transfer
- **Secure workspace**: `init` mode uses tmpfs (RAM) — sensitive data never touches disk
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
- OpenSSL 3.x is required (1.x lacks `openssl kdf` command)
- `ykman` passes credentials as CLI arguments — known `/proc` visibility limitation

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
