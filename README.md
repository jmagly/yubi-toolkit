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
| CPU RDRAND | Local | `/dev/urandom` -- fresh per seed |
| Thermal sensors | Local | Linux: sysfs thermal zones + lm-sensors. macOS: sysctl + vm_stat + ioreg power state. (baseline + fresh per seed on both) |
| Disk I/O jitter | Local | Timing variance of urandom reads (baseline + fresh per seed) |
| random.org | External | Atmospheric noise integers |
| NIST Beacon | External | Randomness beacon pulse |
| drand | External | Distributed randomness beacon |
| YubiKey passwords | Hardware | Compound passwords from 2 source YubiKeys (mux mode) |
| Image files | Optional | SHA-256 hashes of user-supplied image files (`--image-dir`) |
| Extra file | Optional | User-supplied data mixed in per seed |

External APIs use retry+degrade -- if a source fails after 3 attempts, the system continues without it. No single source compromise can weaken the output.

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

The toolkit runs on **Linux** and **macOS** (Apple Silicon and Intel). Pick your platform below for install instructions.

## Requirements

| Component | Linux | macOS |
|-----------|-------|-------|
| `bash` | 4.0+ (default on modern distros) | 3.2.57+ (Apple's stock `/bin/bash` works -- no upgrade needed) |
| `openssl` | 3.x (`openssl kdf` subcommand required) | 3.x via Homebrew (Apple's `/usr/bin/openssl` is LibreSSL and won't work) |
| `ykman` | YubiKey Manager CLI | YubiKey Manager CLI |
| `curl` | yes | yes (preinstalled) |
| `python3` | for keyboard timing and mouse capture | for keyboard timing (preinstalled) |
| Thermal sensors | `lm-sensors` (optional, sysfs always works) | not needed -- uses `sysctl`/`ioreg` automatically |
| Mouse capture | X11 display (auto-falls back to extra keyboard round if unavailable) | not currently supported -- always falls back to keyboard |

The scripts auto-detect the platform at runtime. There are no platform-specific scripts to choose between.

### Install dependencies (Debian/Ubuntu)

```bash
sudo apt install yubikey-manager openssl curl lm-sensors python3
```

### Install dependencies (Fedora/RHEL)

```bash
sudo dnf install yubikey-manager openssl curl lm_sensors python3
```

### Install dependencies (Arch Linux)

```bash
sudo pacman -S yubikey-manager openssl curl lm_sensors python
```

### Install dependencies (macOS)

You need [Homebrew](https://brew.sh) installed first. Then:

```bash
brew install openssl@3 ykman
```

That's it. `bash`, `python3`, and `curl` ship with macOS. The toolkit automatically prepends `/opt/homebrew/opt/openssl@3/bin` (and `/usr/local/opt/openssl@3/bin` on Intel Macs) to `PATH` when sourced, so `openssl` resolves to Homebrew's OpenSSL 3.x rather than Apple's LibreSSL.

If you see `LibreSSL detected` when running any command, your `PATH` is overriding the toolkit's bootstrap. Either run scripts from a fresh terminal or explicitly install: `brew install openssl@3`.

#### macOS notes

- **No `lm-sensors` needed** -- the toolkit collects equivalent system entropy from `sysctl`, `vm_stat`, and `ioreg` automatically.
- **No X11 mouse capture** -- macOS uses Quartz, not X11. The toolkit automatically falls back to an extra keyboard entropy round, which provides strong entropy via nanosecond keystroke timing.
- **No `tmpfs`** -- the `init` command's secure RAM workspace falls back to a disk-backed directory that is securely overwritten on cleanup. APFS encrypts data at rest, so the security gap is small.
- **Apple's bash 3.2 works** -- you do not need to `brew install bash`. The toolkit avoids bash 4-only features.

## Commands

### Seed Generation

| Command | Description |
|---------|-------------|
| `yubi.sh bootstrap [count]` | Generate seeds from scratch (default: 15) |
| `yubi.sh bootstrap [count] <file>` | Generate seeds with extra entropy from file |
| `yubi.sh bootstrap [count] --mux` | Generate seeds with 2-device password muxing |
| `yubi.sh bootstrap [count] --image-dir <path>` | Generate seeds with image file hashes as entropy |
| `yubi.sh mux` | Pair passwords from 2 existing YubiKeys |
| `yubi.sh enrich [file]` | Enrich latest (or specified) seed file with additional entropy |

### Entropy Collection (Air-Gapped Workflows)

| Command | Description |
|---------|-------------|
| `yubi.sh entropy-collect [file]` | Collect external entropy to a portable file |
| `yubi.sh entropy-collect --append <file>` | Append new entropy to existing file |
| `yubi.sh entropy-verify <file>` | Validate integrity and report contents of entropy file |

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

### Air-Gapped Flags

The `bootstrap`, `enrich`, and `init` commands support these flags for air-gapped operation:

| Flag | Description |
|------|-------------|
| `--no-external` | Skip all external API calls; use local entropy only |
| `--entropy-file <path>` | Use pre-collected entropy file instead of live API calls |
| `--image-dir <path>` | Hash image files as additional entropy (bootstrap only) |

### OTP Modes

| Mode | Slot 1 | Slot 2 |
|------|--------|--------|
| `otp` | Yubico OTP | Yubico OTP |
| `static` | Static password | Static password |
| `mixed` | Yubico OTP | Static password |

## Air-Gapped YubiKey Provisioning

For high-security environments where the provisioning machine must not have network access, the toolkit supports a split workflow:

### 1. Collect entropy on a networked machine

```bash
# One-shot: grab entropy from all external sources
./yubi.sh entropy-collect

# Or accumulate entropy over time (stronger -- spans multiple time windows)
./yubi.sh entropy-collect --append ~/entropy-data/pool.bin
./yubi.sh entropy-collect --append ~/entropy-data/pool.bin  # again later
./yubi.sh entropy-collect --append ~/entropy-data/pool.bin  # days later

# Collect from specific sources only
./yubi.sh entropy-collect --sources random.org,drand

# Cron-friendly (minimal output)
./yubi.sh entropy-collect --append ~/entropy-data/pool.bin --quiet
```

### 2. Transfer via sneakernet

```bash
# Verify the file before copying
./yubi.sh entropy-verify ~/entropy-data/pool.bin

# Copy to removable media
cp ~/entropy-data/pool.bin /media/usb/
```

### 3. Provision on air-gapped machine

```bash
# Generate seeds using pre-collected external entropy
./yubi.sh bootstrap 15 --entropy-file /media/usb/pool.bin

# Or run the full pipeline air-gapped
./yubi.sh init otp --entropy-file /media/usb/pool.bin

# Enrich existing seeds with pre-collected entropy
./yubi.sh enrich --entropy-file /media/usb/pool.bin

# Or skip external entropy entirely (local sources only)
./yubi.sh bootstrap 15 --no-external
```

### Entropy File Format

Collected entropy files use a text-based format (`YUBI-ENTROPY-V1`) that is:
- Inspectable with standard tools (`cat`, `grep`, `head`)
- Integrity-checked via SHA-256 hash per block
- Appendable -- multiple collection runs accumulate blocks
- Source-tagged -- each block records its origin (random.org, NIST, drand) and timestamp

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
| PIV Management Key | HKDF -> 32-byte AES256 (firmware 5.4.2+) or 24-byte TDES |
| FIDO2 PIN | Same as PIV PIN (separate application, operationally simpler) |

### Entropy Mixing

All entropy combination uses HKDF (HMAC-based Key Derivation Function):

- **IKM** (Input Key Material): User-controlled entropy (passwords, keyboard timing, mouse movement)
- **Salt**: System entropy (CPU RNG, thermal, jitter, external APIs or pre-collected file)
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

- **RAM workspace** (`tmpfs`): `init` mode keeps all working files in RAM -- never touches disk (Linux, root only). On macOS and unprivileged Linux, falls back to a disk-backed directory that is securely overwritten on cleanup.
- **Disk files**: 3-pass random overwrite + zero pass + `sync` + unlink + `fstrim` (SSD, Linux root). On macOS, APFS auto-TRIMs and encrypts at rest, so `fstrim` is a no-op.
- **Consumed seeds**: Removed from pool file atomically after successful programming
- **Empty pool files**: Auto-detected and securely wiped by `purge`
- **Entropy files**: Created with mode 600 (owner-only read/write)

Note: `shred` alone is insufficient on SSD/NVMe due to FTL wear leveling and filesystem journaling. The multi-pass approach provides defense in depth, and `tmpfs` (where available) avoids the problem entirely for ephemeral data.

### Password Input Security

All password entry uses silent terminal input (`read -rs`). After entry, a masked preview is displayed showing only the first 5 and last 5 characters:

```
  [D1 #1] vvccb...jneld
  [D1 #2] krtgh...pqwmx
```

## File Structure

```
~/.yubikey-seeds/                       # Managed seed directory (mode 700)
  bootstrap-20260308-143022.txt         # Timestamped seed files
  enriched-20260308-144500.txt          # Enriched seeds
  mux-20260308-150000.txt              # Muxed compound passwords
```

Entropy collection files are stored wherever you specify (not in the seed directory):

```
~/entropy-data/pool.bin                 # Portable entropy file (YUBI-ENTROPY-V1)
```

All seed file management is automatic -- you never need to specify paths.

## Scripts

| Script | Purpose |
|--------|---------|
| `yubi.sh` | Unified entry point -- all commands go through here |
| `yubi-lib.sh` | Shared library (logging, secure delete, tmpfs, entropy file I/O) |
| `bootstrap-entropy.sh` | Interactive seed generation for new users |
| `entropy-mix.sh` | Batch HKDF-SHA512 enrichment of password lists |
| `entropy-collect.sh` | Standalone external entropy collection for air-gapped workflows |
| `entropy-verify.sh` | Entropy file integrity validation and reporting |
| `yubi-mux.sh` | 2-device password collection and random pairing |
| `configure-yubi.sh` | YubiKey programmer (PIV + OTP slots) |
| `init-yubi.sh` | End-to-end pipeline (collect -> mux -> enrich -> program) |

## Security Considerations

- **OTP slots programmed with custom keys will NOT validate against YubiCloud.** This is intentional -- you're replacing Yubico's trust chain with your own. You must operate your own OTP validation server (e.g., [yubikey-val](https://developers.yubico.com/yubikey-val/)).
- **Record your PIN, PUK, and management key immediately** after programming. They cannot be recovered, only reset to factory defaults. Clear terminal scrollback after recording.
- **PIV auto-reset**: If a key was previously initialized, `configure` will offer to reset PIV to factory defaults before reprogramming.
- **AES256 management key**: Automatically used on firmware 5.4.2+ (NIST deprecated TDES post-2023). Falls back to TDES on older keys.
- **FIDO2 PIN**: Set automatically during initialization using the same PIN as PIV.
- **Process hardening**: All scripts set `umask 077` (files never group/world-readable) and `ulimit -c 0` (no core dumps containing secrets).
- **HKDF salt binding**: Credential derivation uses the YubiKey serial number as HKDF salt, binding derived credentials to the specific target device.
- **OpenSSL 3.x required**: The `openssl kdf` command used for HKDF is not available in OpenSSL 1.x (Ubuntu 20.04 and earlier). Scripts check this at startup.
- **Entropy files are sensitive**: A collected entropy file reduces unpredictability if leaked alongside derived seeds. Treat them with the same care as seed files. Files are created mode 600 by default.
- **External entropy is supplementary**: On an air-gapped machine, local sources (CPU RNG, thermal, jitter, keyboard, mouse) remain the primary entropy. Pre-collected external entropy improves the salt but is not required.
- **Known limitation**: `ykman` receives credentials as CLI arguments, briefly visible in `/proc/PID/cmdline`. Run on a trusted single-user system.

## Troubleshooting

### "LibreSSL detected" (macOS)
Your `openssl` is resolving to Apple's `/usr/bin/openssl` (LibreSSL), which lacks the `kdf` subcommand. Install Homebrew OpenSSL: `brew install openssl@3`. The toolkit auto-prepends the brew path when scripts are sourced, so this typically resolves itself once `openssl@3` is installed. If you have a custom `PATH` that overrides this, ensure `/opt/homebrew/opt/openssl@3/bin` (Apple Silicon) or `/usr/local/opt/openssl@3/bin` (Intel) appears before `/usr/bin`.

### "OpenSSL 3.0+ required" (Linux)
Your system has OpenSSL 1.x. Upgrade to a newer OS (Ubuntu 22.04+) or install OpenSSL 3.x manually. The `openssl kdf` subcommand is required for HKDF and does not exist in 1.x.

### "No YubiKeys detected"
Ensure `ykman` is installed and your YubiKey is inserted. Try `ykman list` to verify. If using USB-C, try a different port.

On macOS, you may need to grant USB device access to your terminal app the first time you use ykman. If `ykman list` hangs, unplug and replug the key.

### Mouse entropy falls back to keyboard
This happens when no X11 display is available -- always the case on macOS (which uses Quartz, not X11), and on headless Linux, Wayland-only sessions, or SSH sessions. The toolkit automatically collects an extra keyboard entropy round instead. The security impact is minimal -- keyboard timing provides strong entropy via nanosecond inter-keystroke intervals.

### External API failures
All external sources (random.org, NIST Beacon, drand) degrade gracefully. If all three fail, seeds are generated from local entropy only. For environments without network access, use `--no-external` or the air-gapped workflow with `--entropy-file`.

### Entropy file validation fails
Run `yubi.sh entropy-verify <file>` for diagnostics. Common causes: file was truncated during transfer, or modified after collection (SHA-256 mismatch).

### "command not found: now_ns" or similar (macOS)
You ran one of the helper scripts (e.g. `bootstrap-entropy.sh`) directly without sourcing through `yubi.sh`, AND your `bash` is exiting before `yubi-lib.sh` is fully loaded. Always invoke commands via `./yubi.sh <subcommand>` -- the unified entry point sources the library correctly.

## License

MIT License. See [LICENSE](LICENSE).
