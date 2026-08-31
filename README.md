# YubiKey Entropy Toolkit

A Bash toolkit for generating CSPRNG-rooted credential seeds and provisioning a named YubiKey application scope with operator-controlled values.

## Why?

YubiKeys ship with factory-programmed secrets. While Yubico's manufacturing process is trusted, replacing factory credentials with your own entropy removes the factory line as a potential attack vector. This toolkit makes that process repeatable, auditable, and secure.

## Entropy Sources

Every seed has one mandatory security root: the platform/OpenSSL CSPRNG. A
CSPRNG read or shape failure is fatal. Other inputs are supplements with no
claimed or estimated min-entropy:

| Source | Classification | Description |
|--------|------|-------------|
| OpenSSL/platform CSPRNG | Mandatory secret root | Fresh 256-bit output per seed |
| Keyboard and mouse timing | Unassessed supplement | No min-entropy claim |
| Thermal and I/O timing | Unassessed supplement | No min-entropy claim |
| YubiKey passwords | Unassessed supplement | Operator-controlled input |
| Image and extra files | Unassessed supplement | Content hashes/input data |
| Public beacons/APIs | Disabled | Unverified NIST, drand, and random.org paths were removed |

Public beacon values are public diversification, not secret entropy. They are
not used because the former implementation did not verify signatures and chain
parameters. Pool-adjacent provenance records this policy separately from seed
material.

## Quick Start

```bash
# Clone and make executable
git clone https://github.com/jmagly/yubi-toolkit.git
cd yubi-toolkit
chmod +x *.sh

# Generate seeds from scratch (no existing keys needed)
./yubi.sh bootstrap

# Initialize a YubiKey with generated seeds
./yubi.sh doctor --json           # verify tools and device support first
./yubi.sh configure otp --derivation-profile v2
./yubi.sh configure otp 35276256 --derivation-profile v2

# Or do everything in one shot (requires 2 source keys)
./yubi.sh init otp
```

The toolkit runs on **Linux** and **macOS** (Apple Silicon and Intel). Pick your platform below for install instructions.

## Requirements

| Component | Linux | macOS |
|-----------|-------|-------|
| `bash` | 3.2.57+ (4.x/5.x are also tested) | 3.2.57+ (Apple's stock `/bin/bash` works -- no upgrade needed) |
| `openssl` | 3.x (`openssl kdf` subcommand required) | 3.x via Homebrew (Apple's `/usr/bin/openssl` is LibreSSL and won't work) |
| `ykman` | YubiKey Manager 5 (`>=5.5.1,<6`); 5.9.2 recommended | YubiKey Manager 5 (`>=5.5.1,<6`); 5.9.2 recommended |
| `age` | encrypted seed pools and recovery output | encrypted seed pools and recovery output |
| `curl` | yes | yes (preinstalled) |
| `python3` | for keyboard timing and mouse capture | for keyboard timing (preinstalled) |
| Thermal sensors | `lm-sensors` (optional, sysfs always works) | not needed -- uses `sysctl`/`ioreg` automatically |
| Mouse capture | X11 display (auto-falls back to extra keyboard round if unavailable) | not currently supported -- always falls back to keyboard |

The scripts auto-detect the platform at runtime. There are no platform-specific scripts to choose between.

### Install dependencies (Debian/Ubuntu)

```bash
sudo apt install yubikey-manager openssl curl lm-sensors python3 age
```

### Install dependencies (Fedora/RHEL)

```bash
sudo dnf install yubikey-manager openssl curl lm_sensors python3 age
```

### Install dependencies (Arch Linux)

```bash
sudo pacman -S yubikey-manager openssl curl lm_sensors python age
```

### Install dependencies (macOS)

You need [Homebrew](https://brew.sh) installed first. Then:

```bash
brew install openssl@3 ykman age
```

`bash`, `python3`, and `curl` ship with macOS. The toolkit automatically prepends `/opt/homebrew/opt/openssl@3/bin` (and `/usr/local/opt/openssl@3/bin` on Intel Macs) to `PATH` when sourced, so `openssl` resolves to Homebrew's OpenSSL 3.x rather than Apple's LibreSSL.

Before programming a key, install the bounded Yubico Python API dependency in
an isolated environment. The repository constraint stays within Yubico's
public API-compatible major version:

```bash
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -r requirements-programmer.in
```

If you see `LibreSSL detected` when running any command, your `PATH` is overriding the toolkit's bootstrap. Either run scripts from a fresh terminal or explicitly install: `brew install openssl@3`.

#### macOS notes

- **No `lm-sensors` needed** -- the toolkit collects equivalent system entropy from `sysctl`, `vm_stat`, and `ioreg` automatically.
- **No X11 mouse capture** -- macOS uses Quartz, not X11. The toolkit records another unassessed keyboard-timing supplement instead.
- **No native `tmpfs`** -- `init` fails closed on macOS unless you explicitly pass `--allow-disk-workspace`. That override permits plaintext temporary files on persistent storage; deletion cannot guarantee sanitization of APFS snapshots, journals, or flash blocks.
- **Apple's bash 3.2 works** -- you do not need to `brew install bash`. The toolkit avoids bash 4-only features.

## Commands

### Seed Generation

| Command | Description |
|---------|-------------|
| `yubi.sh bootstrap [count]` | Generate seeds from scratch (default: 15) |
| `yubi.sh bootstrap [count] <file>` | Legacy positional form; external beacon files are rejected |
| `yubi.sh bootstrap [count] --mux` | Generate seeds with 2-device password muxing |
| `yubi.sh bootstrap [count] --image-dir <path>` | Generate seeds with image file hashes as entropy |
| `yubi.sh mux` | Pair passwords from 2 existing YubiKeys |
| `yubi.sh enrich [file]` | Enrich latest (or specified) seed file with additional entropy |

### Entropy Collection (Air-Gapped Workflows)

| Command | Description |
|---------|-------------|
| `yubi.sh entropy-collect` | Removed; exits because unverified public inputs are forbidden |
| `yubi.sh entropy-verify <file>` | Validate integrity and report contents of entropy file |

### Key Programming

| Command | Description |
|---------|-------------|
| `yubi.sh configure <mode> [serial] --derivation-profile v2` | Program from a pool with an explicit derivation profile |
| `yubi.sh init <mode> [serial]` | Full pipeline: 2 source keys -> program target |

### Info

| Command | Description |
|---------|-------------|
| `yubi.sh list` | Show connected YubiKeys |
| `yubi.sh info [serial]` | Detailed info for a specific key |
| `yubi.sh status` | Show seed pool status |
| `yubi.sh doctor [serial]` | Machine-readable dependency and device support report (`--json`) |
| `yubi.sh reset <piv\|fido2> [serial]` | Reset exactly one named application after an independent typed confirmation |
| `yubi.sh purge` | Remove empty/exhausted encrypted pool files |

### Air-Gapped Flags

The `bootstrap`, `enrich`, and `init` commands support these flags for air-gapped operation:

| Flag | Description |
|------|-------------|
| `--no-external` | Compatibility no-op; live external sources are disabled |
| `--entropy-file <path>` | Rejected: legacy unverified beacon files are provenance-only |
| `--image-dir <path>` | Hash image files as additional entropy (bootstrap only) |

### OTP Modes

| Mode | Slot 1 | Slot 2 |
|------|--------|--------|
| `otp` | Yubico OTP | Yubico OTP |
| `static` | Static password | Static password |
| `mixed` | Yubico OTP | Static password |

## Offline operation

Seed generation and provisioning make no network requests. The deprecated
`entropy-collect` command fails closed, and legacy `--entropy-file` inputs are
not mixed because their public-beacon signatures were never verified. Operators
may archive those files as provenance, but they are not credential material.

Each encrypted pool receives a separate mode-600 `.provenance.json` record
identifying the platform CSPRNG as the secret root, human/sensor/image inputs as
unassessed supplements, and public diversification as disabled.

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
| FIDO2 PIN | Independent HKDF purpose -> 8 numeric digits |

### Entropy Mixing

All entropy combination uses HKDF (HMAC-based Key Derivation Function):

- **IKM** (Input Key Material): mandatory fresh CSPRNG output plus supplements
- **Salt**: domain-separated sensor/timing supplements
- **Info**: Unique per-seed label for domain separation

Security depends on the mandatory CSPRNG, not on an unmeasured assumption about any supplement.

Credential expansion uses the versioned `YUBI-CRED-V2` suite, independent
application/purpose labels, and unbiased rejection sampling. Persistent-pool
configuration has no implicit profile: select `v2`, or select `legacy-v1` only
for an intentional migration. See [the derivation specification](docs/derivation-v2.md).

Provisioning scope is PIV plus both OTP slots, with FIDO2 PIN included only
when `--with-fido-pin` is supplied. It does not initialize OATH, OpenPGP,
YubiHSM Auth, or every YubiKey application. PIV and FIDO2 resets are separate
`reset` operations with application-specific typed confirmation; provisioning
never performs either reset automatically.

### Mux Process

When combining passwords from 2 YubiKeys:

1. Collect N passwords from device 1, N from device 2
2. Fisher-Yates shuffle both arrays independently
3. Random concatenation order per pair (D1+D2 or D2+D1)
4. Each compound password is cryptographically independent

### Seed storage and removal

Persistent seed pools use the authenticated [age](https://age-encryption.org/)
file format. Install `age`, create an identity on separate protected storage,
and place only its public recipient in the managed directory:

```bash
age-keygen -o /protected/location/yubi-seed-identity.txt
mkdir -p ~/.yubikey-seeds && chmod 700 ~/.yubikey-seeds
age-keygen -y /protected/location/yubi-seed-identity.txt > ~/.yubikey-seeds/recipient
chmod 600 ~/.yubikey-seeds/recipient
export YUBI_SEED_IDENTITY=/protected/location/yubi-seed-identity.txt
```

Back up the identity separately: losing it makes every pool unrecoverable.
Do not store the identity beside the ciphertext. An age plugin identity may be
used when the installed age version supports that plugin.

Provisioning uses the public Yubico Python API, pinned in
`requirements-programmer.in`. Install that bounded dependency in the runtime
environment before programming:

```bash
python3 -m pip install -r requirements-programmer.in
```

Generated values are not printed. To retain the PIV recovery values, explicitly
select an encrypted destination and recipient:

```bash
./yubi.sh configure mixed 12345678 \
  --recovery-file /protected/recovery/yubikey-12345678.age \
  --recovery-recipient age1example...
```

The recovery file is created mode 600 and replaced atomically. Without these
two options, recovery values are intentionally discarded after programming.

- **Volatile workspace** (`tmpfs`): `init` uses a verified Linux tmpfs, including `/dev/shm` for unprivileged users. tmpfs pages can be swapped; disable or encrypt swap when the threat model forbids disk exposure. Persistent fallback requires the explicit `--allow-disk-workspace` risk override.
- **Persistent pools**: Authenticated ciphertext, mode 600, replaced atomically only after successful programming
- **Interrupted programming**: The active ciphertext is first moved to a `.pending` quarantine. A failure leaves it unavailable for reuse; `status` reports the recovery state.
- **Empty pool files**: Removed by `purge`
- **Entropy files**: Created with mode 600 (owner-only read/write)

Deletion does not guarantee sanitization on flash, copy-on-write, journaled,
snapshotted, or network storage. The design avoids persistent plaintext instead
of claiming that overwrite or TRIM can reliably erase it.

### Password Input Security

All password entry uses silent terminal input (`read -rs`). After entry, a masked preview is displayed showing only the first 5 and last 5 characters:

```text
  [D1 #1] vvccb...jneld
  [D1 #2] krtgh...pqwmx
```

## File Structure

```text
~/.yubikey-seeds/                       # Managed seed directory (mode 700)
  recipient                             # Public age recipient only
  bootstrap-20260308-143022.age         # Authenticated encrypted pool
  enriched-20260308-144500.age          # Authenticated encrypted pool
  mux-20260308-150000.age               # Authenticated encrypted pool
```

Legacy entropy collection files may be retained wherever you previously stored
them, but they are provenance-only and are not accepted as credential input:

```text
~/entropy-data/pool.bin                 # Portable entropy file (YUBI-ENTROPY-V1)
```

All seed file management is automatic -- you never need to specify paths.

## Scripts

| Script | Purpose |
|--------|---------|
| `yubi.sh` | Unified entry point -- all commands go through here |
| `yubi-lib.sh` | Shared library (logging, age pools, tmpfs, entropy file I/O) |
| `bootstrap-entropy.sh` | Interactive seed generation for new users |
| `entropy-mix.sh` | Batch HKDF-SHA512 enrichment of password lists |
| `entropy-collect.sh` | Fail-closed compatibility stub for the removed beacon collector |
| `entropy-verify.sh` | Entropy file integrity validation and reporting |
| `yubi-mux.sh` | 2-device password collection and random pairing |
| `configure-yubi.sh` | YubiKey programmer (PIV + OTP slots) |
| `init-yubi.sh` | End-to-end pipeline (collect -> mux -> enrich -> program) |

## Supported tool and device policy

Run `./yubi.sh doctor --json [serial]` before provisioning or in automation.
The current tested policy is:

- Bash 3.2, 4.x, or 5.x and Python 3
- OpenSSL 3.x with a passing deterministic HKDF-SHA256 known-answer test
- YubiKey Manager (`ykman`) `>=5.5.1,<6`; 5.5.1 and 5.9.2 fixtures are covered,
  and 5.9.2 is recommended for new installations
- YubiKey 5 family firmware 5.4.x through 5.8.x with OTP, CCID, Yubico
  OTP, PIV, and FIDO2 enabled

The compatibility range is a bounded transitional policy, not a claim that
every minor release has received hardware-in-the-loop validation. Unknown
major versions and products are intentionally rejected until fixtures
and hardware verification establish support. FIDO-only Security Key and
YubiKey Bio products cannot satisfy the OTP/PIV provisioning profile.

## Development and tests

Run the non-hardware verification suite before submitting changes:

```bash
./tests/run.sh
```

The suite includes syntax and ShellCheck gates, lifecycle tests, and mocked
YubiKey Manager fixtures. See [`tests/README.md`](tests/README.md) for the
macOS Bash 3.2 gate and hardware-test boundary.

## Security Considerations

- **OTP slots programmed with custom keys will NOT validate against YubiCloud.** This is intentional -- you're replacing Yubico's trust chain with your own. You must operate your own OTP validation server (e.g., [yubikey-val](https://developers.yubico.com/yubikey-val/)).
- **Recovery output is opt-in**: use `--recovery-file` with an age recipient when invoking the configuration script. Generated values are never printed; without an encrypted recovery sink they are not retained.
- **Application resets are separate**: provisioning never resets PIV or FIDO2 automatically.
- **AES256 management key**: Automatically used on firmware 5.4.2+ (NIST deprecated TDES post-2023). Falls back to TDES on older keys.
- **FIDO2 PIN**: Optional and independently derived from the PIV PIN.
- **Process hardening**: All scripts set `umask 077` (files never group/world-readable) and `ulimit -c 0` (no core dumps containing secrets).
- **HKDF salt binding**: Credential derivation uses the YubiKey serial number as HKDF salt, binding derived credentials to the specific target device.
- **OpenSSL 3.x required**: The `openssl kdf` command used for HKDF is not available in OpenSSL 1.x (Ubuntu 20.04 and earlier). Scripts check this at startup.
- **Entropy trust**: the platform CSPRNG is the mandatory secret root. Timing, thermal, mouse, image, and human inputs are unassessed supplements with no min-entropy claim.
- **Programming transport**: generated values are passed to the pinned public Yubico Python API through a mode-0600 descriptor on stdin. They are not placed in process arguments or exported environment variables.

## Troubleshooting

### "LibreSSL detected" (macOS)

Your `openssl` is resolving to Apple's `/usr/bin/openssl` (LibreSSL), which lacks the `kdf` subcommand. Install Homebrew OpenSSL: `brew install openssl@3`. The toolkit auto-prepends the brew path when scripts are sourced, so this typically resolves itself once `openssl@3` is installed. If you have a custom `PATH` that overrides this, ensure `/opt/homebrew/opt/openssl@3/bin` (Apple Silicon) or `/usr/local/opt/openssl@3/bin` (Intel) appears before `/usr/bin`.

### "OpenSSL 3.0+ required" (Linux)

Your system has OpenSSL 1.x. Upgrade to a newer OS (Ubuntu 22.04+) or install OpenSSL 3.x manually. The `openssl kdf` subcommand is required for HKDF and does not exist in 1.x.

### "No YubiKeys detected"

Ensure `ykman` is installed and your YubiKey is inserted. Try `ykman list` to verify. If using USB-C, try a different port.

On macOS, you may need to grant USB device access to your terminal app the first time you use ykman. If `ykman list` hangs, unplug and replug the key.

### Mouse entropy falls back to keyboard

This happens when no X11 display is available -- always the case on macOS (which uses Quartz, not X11), and on headless Linux, Wayland-only sessions, or SSH sessions. The toolkit collects another keyboard sample, but makes no entropy estimate for either input; the CSPRNG remains the security root.

### External API inputs are rejected

Live NIST, drand, and random.org paths were removed because the previous code did not authenticate them. Legacy external files are not mixed. This cannot weaken generated values because public inputs were never a required secret source.

### Entropy file validation fails

Run `yubi.sh entropy-verify <file>` for diagnostics. Common causes: file was truncated during transfer, or modified after collection (SHA-256 mismatch).

### "command not found: now_ns" or similar (macOS)

You ran one of the helper scripts (e.g. `bootstrap-entropy.sh`) directly without sourcing through `yubi.sh`, AND your `bash` is exiting before `yubi-lib.sh` is fully loaded. Always invoke commands via `./yubi.sh <subcommand>` -- the unified entry point sources the library correctly.

## License

MIT License. See [LICENSE](LICENSE).
