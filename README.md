# YubiKey Entropy Toolkit

A bash toolkit for generating high-entropy cryptographic seeds and fully initializing YubiKeys with user-controlled secrets. Replaces all factory-programmed credentials (OTP AES keys, PIV PIN, PUK, management key) with entropy derived from multiple independent sources.

## Why?

YubiKeys ship with factory-programmed secrets. While Yubico's manufacturing process is trusted, replacing factory credentials with your own entropy removes the factory line as a potential attack vector. This toolkit makes that process repeatable, auditable, and secure.

## Entropy Sources

Every seed is mixed from **all available sources** via HKDF-SHA512:

| Source | Type | Description |
|--------|------|-------------|
| Keyboard timing | Interactive | Nanosecond inter-keystroke intervals (2 rounds, 50 chars each) |
| Mouse movement | Interactive | X11 cursor position sampling (80 samples at 50ms) |
| CPU RDRAND | Local | `/dev/urandom` — fresh per seed |
| Thermal sensors | Local | sysfs thermal zones + lm-sensors (baseline + fresh per seed) |
| Disk I/O jitter | Local | Timing variance of urandom reads (baseline + fresh per seed) |
| random.org | External | Atmospheric noise integers |
| NIST Beacon | External | Randomness beacon pulse |
| drand | External | Distributed randomness beacon |
| YubiKey passwords | Hardware | Compound passwords from 2 source YubiKeys (mux mode) |
| Extra file | Optional | User-supplied data mixed in per seed |

External APIs use retry+degrade — if a source fails after 3 attempts, the system continues without it. No single source compromise can weaken the output.

## Quick Start

```bash
# Clone and make executable
git clone https://github.com/jmagly/yubi-toolkit.git
cd yubi-toolkit
chmod +x *.sh

# Generate seeds from scratch (no existing keys needed)
./yubi.sh bootstrap

# Initialize a YubiKey with generated seeds
./yubi.sh configure otp           # auto-detect single key
./yubi.sh configure otp 35276256  # specify serial

# Or do everything in one shot (requires 2 source keys)
./yubi.sh init otp
```

## Requirements

- `bash` 4.0+
- `openssl` (with HKDF support — OpenSSL 3.x)
- `ykman` (YubiKey Manager CLI) — `sudo apt install yubikey-manager`
- `curl`
- `sensors` (lm-sensors) — `sudo apt install lm-sensors`
- `python3` (for keyboard timing and mouse capture)
- X11 display (for mouse entropy; falls back to extra keyboard round)

## Commands

### Seed Generation

| Command | Description |
|---------|-------------|
| `yubi.sh bootstrap [count]` | Generate seeds from scratch (default: 15) |
| `yubi.sh bootstrap [count] <file>` | Generate seeds with extra entropy from file |
| `yubi.sh bootstrap [count] --mux` | Generate seeds with 2-device password muxing |
| `yubi.sh mux` | Pair passwords from 2 existing YubiKeys |
| `yubi.sh enrich` | Enrich latest seed file with additional entropy |

### Key Programming

| Command | Description |
|---------|-------------|
| `yubi.sh configure <mode> [serial]` | Program a YubiKey from seed pool |
| `yubi.sh init <mode> [serial]` | Full pipeline: 2 source keys -> program target |

### Info

| Command | Description |
|---------|-------------|
| `yubi.sh list` | Show connected YubiKeys |
| `yubi.sh info [serial]` | Detailed info for a specific key |
| `yubi.sh status` | Show seed pool status |
| `yubi.sh purge` | Securely delete empty/exhausted seed files |

### OTP Modes

| Mode | Slot 1 | Slot 2 |
|------|--------|--------|
| `otp` | Yubico OTP | Yubico OTP |
| `static` | Static password | Static password |
| `mixed` | Yubico OTP | Static password |

## Architecture

### Two Paths

| Path | Seeds Persist? | Use Case |
|------|---------------|----------|
| `bootstrap` -> `configure` | Yes, in `~/.yubikey-seeds/` | Build a pool, program multiple keys over time |
| `init` | No, RAM only | One-shot: 2 source keys -> 1 programmed key |

### What Gets Programmed

Each YubiKey initialization consumes **5 seeds** from the pool:

| Credential | Derivation |
|------------|------------|
| OTP Slot 1 | HKDF -> 16-byte AES key + 6-byte private ID |
| OTP Slot 2 | HKDF -> 16-byte AES key + 6-byte private ID |
| PIV PIN | HKDF -> 8 numeric digits |
| PIV PUK | HKDF -> 8 alphanumeric chars |
| PIV Management Key | HKDF -> 24-byte TDES key |

### Entropy Mixing

All entropy combination uses HKDF (HMAC-based Key Derivation Function):

- **IKM** (Input Key Material): User-controlled entropy (passwords, keyboard timing, mouse movement)
- **Salt**: System entropy (CPU RNG, thermal, jitter, external APIs)
- **Info**: Unique per-seed label for domain separation

This ensures that even if some entropy sources are compromised, the output remains unpredictable as long as any single source provides genuine randomness.

### Mux Process

When combining passwords from 2 YubiKeys:

1. Collect N passwords from device 1, N from device 2
2. Fisher-Yates shuffle both arrays independently
3. Random concatenation order per pair (D1+D2 or D2+D1)
4. Each compound password is cryptographically independent

### Secure Deletion

Sensitive files are handled with defense-in-depth:

- **RAM workspace** (`tmpfs`): `init` mode keeps all working files in RAM — never touches disk
- **Disk files**: 3-pass random overwrite + zero pass + `sync` + unlink + `fstrim` (SSD)
- **Consumed seeds**: Removed from pool file atomically after successful programming
- **Empty pool files**: Auto-detected and securely wiped by `purge`

Note: `shred` alone is insufficient on SSD/NVMe due to FTL wear leveling and filesystem journaling. The multi-pass approach provides defense in depth, and `tmpfs` avoids the problem entirely for ephemeral data.

### Password Input Security

All password entry uses silent terminal input (`read -rs`). After entry, a masked preview is displayed showing only the first 5 and last 5 characters:

```
  [D1 #1] vvccb...jneld
  [D1 #2] krtgh...pqwmx
```

## File Structure

```
~/.yubikey-seeds/           # Managed seed directory (mode 700)
  bootstrap-20260308-143022.txt   # Timestamped seed files
  enriched-20260308-144500.txt    # Enriched seeds
  mux-20260308-150000.txt         # Muxed compound passwords
```

All file management is automatic — you never need to specify paths.

## Scripts

| Script | Purpose |
|--------|---------|
| `yubi.sh` | Unified entry point — all commands go through here |
| `yubi-lib.sh` | Shared library (logging, secure delete, tmpfs workspace) |
| `bootstrap-entropy.sh` | Interactive seed generation for new users |
| `entropy-mix.sh` | Batch HKDF-SHA512 enrichment of password lists |
| `yubi-mux.sh` | 2-device password collection and random pairing |
| `configure-yubi.sh` | YubiKey programmer (PIV + OTP slots) |
| `init-yubi.sh` | End-to-end pipeline (collect -> mux -> enrich -> program) |

## Security Considerations

- **OTP slots programmed with custom keys will NOT validate against YubiCloud.** This is intentional — you're replacing Yubico's trust chain with your own.
- **Record your PIN, PUK, and management key immediately** after programming. They cannot be recovered, only reset to factory defaults.
- **PIV auto-reset**: If a key was previously initialized, `configure` will offer to reset PIV to factory defaults before reprogramming.
- **No secrets are logged or stored** beyond the seed pool files, which are mode 600.

## License

MIT License. See [LICENSE](LICENSE).
