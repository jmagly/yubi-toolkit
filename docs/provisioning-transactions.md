# Provisioning transaction and recovery states

Provisioning changes only the requested application scope: PIV and both OTP
slots, plus an optional FIDO2 PIN. Other YubiKey applications are unchanged.

The order is fixed:

1. Validate the complete descriptor and uniquely select the target (`preflight`).
2. Mutate PIV and verify non-default PIN, PUK, and management-key metadata.
3. Mutate both OTP slots and verify that both are configured.
4. When requested, set the FIDO2 PIN and verify the CTAP `clientPin` state.
5. Mark the transaction complete, then and only then commit seed consumption.

After each adapter return, a mode-600 redacted JSON state file is atomically
replaced. It contains serial, scope, phase, completed applications, outcome,
and non-sensitive guidance. It never contains derived values or pool material.

- `failed`: no mutation postcondition completed.
- `partial`: at least one application completed, but final commit did not.
- `complete`: every requested postcondition passed; seed consumption may commit.

A persistent pool is moved to `.pending` before this workflow. Any failed or
partial outcome leaves that ciphertext quarantined and unavailable for reuse.
Use the encrypted recovery record and redacted state to reconcile the device;
do not rename or reuse the pending pool based on guesswork. FIDO2 failure never
triggers a reset and never produces a complete outcome.

Reset is intentionally outside this state machine. `yubi.sh reset piv` and
`yubi.sh reset fido2` are separate, application-scoped, typed-confirmation
operations because their recovery and physical-presence semantics differ.
