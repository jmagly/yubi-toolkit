# Test suite

Run all non-destructive tests with:

```bash
./tests/run.sh
```

The runner checks Bash syntax, applies ShellCheck's error gate, and executes all
`tests/test-*.sh` files. `tests/bin/ykman` is a non-hardware mock; fixtures pin
representative output from the transitional 5.5.1 environment and current
5.9.2 tooling. No test in this directory may mutate an attached YubiKey.

## macOS Bash 3.2 gate

The same command must pass under Apple's `/bin/bash` 3.2 on the canonical macOS
target before release:

```bash
/bin/bash ./tests/run.sh
```

The suite executes the shared shuffle helper and rejects known Bash 4+
constructs such as namerefs and associative arrays.

ShellCheck may be installed with Homebrew. GNU `timeout` is optional on macOS;
the focused interrupt test reports an explicit skip when it is unavailable,
while HUP and TERM cleanup still run.

Destructive hardware-in-the-loop coverage belongs in a separately authorized
runbook using designated sacrificial devices; it must never run in ordinary CI.
