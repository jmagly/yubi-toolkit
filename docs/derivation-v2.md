# YUBI-CRED-V2 credential derivation

`YUBI-CRED-V2` is the current credential suite. Its input key material is one
32-byte CSPRNG-backed seed from the authenticated pool, decoded from base64.
The target YubiKey serial binds every output to a device.

## HKDF framing

HKDF uses SHA-256. Text fields are UTF-8/ASCII and decimal-length-prefixed.

- Salt: `12:YUBI-CRED-V2|serial:<length>:<serial>`
- Info: `suite:12:YUBI-CRED-V2|purpose:<length>:<purpose>|counter:8:<8-hex-digits>`
- IKM: the decoded 32-byte seed
- Output: raw HKDF output bytes, rendered as lowercase hex only for binary keys

The counter begins at zero. Binary keys use counter zero. Text derivation asks
for 64 bytes per counter and increments the counter for each refill.

## Independent purposes

- `piv/pin`, `piv/puk`, `piv/management-key/<algorithm>`
- `fido2/pin`
- `otp/slot1/aes-key`, `otp/slot1/private-id`, `otp/slot1/static-password`
- `otp/slot2/aes-key`, `otp/slot2/private-id`, `otp/slot2/static-password`

PIV and FIDO PINs are independently derived and must not be assumed equal.

## Unbiased text mapping

For an alphabet of size `n`, accept a byte only when it is below
`floor(256/n) * n`; map accepted bytes with modulo `n`. Rejected bytes are
discarded. When a 64-byte block is exhausted, derive the next counter block.
Numeric values use `0123456789`; alphanumeric values use lowercase, uppercase,
then digits in that exact order.

## Derivation profiles

Persistent-pool provisioning requires an explicit `--derivation-profile v2`
or `--derivation-profile legacy-v1`. There is no implicit default.
`legacy-v1` exists only to reproduce an already-established credential set.
New provisioning selects v2. Recovery ciphertext records the selected profile.

Known-answer and rejection-boundary vectors are executable in
`tests/test-credential-derivation.sh`.
