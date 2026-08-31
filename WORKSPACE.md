# WORKSPACE.md
<!-- aiwg-managed -->
<!-- Generated structure by AIWG; operator content is protected by markers. -->

<!-- AIWG:workspace-context:start -->

## AIWG Context Graph

This file is the canonical provider-neutral home for project and operator context.
Provider startup files are generated adapters: they direct the harness here first,
then to AIWG.md for framework discovery and routing.

### Precedence

1. Provider, system, and organization instructions retain their native authority.
2. Root WORKSPACE.md supplies shared project/operator context.
3. AIWG.md supplies generated framework/discovery context.
4. Narrower linked files and provider-native subtree instructions govern their declared scope.

### Ownership

- Edit project-neutral notes only inside the protected Project Context section below.
- Keep detailed policies, runbooks, hooks, and quickrefs in linked files.
- Keep provider-only directives in `.aiwg/context/providers/`.
- Never store secrets, tokens, credentials, or machine-local sensitive values here.

### Linked Context

- [AIWG framework context](./AIWG.md)
- [AIWG project configuration](.aiwg/aiwg.config)
- [Project-local quickref](.aiwg/quickref.json) (when configured)

<!-- AIWG:workspace-context:end -->

<!-- AIWG:workspace-operator:start -->

## Project Context

This repository is a security-sensitive Bash toolkit for CSPRNG-rooted seed
generation and scoped YubiKey provisioning. The supported entry point is
`./yubi.sh`; helper scripts share portability and secret-handling primitives
from `yubi-lib.sh`.

- Preserve compatibility with Bash 3.2 on macOS as well as current Bash on
  Linux. Avoid associative arrays, namerefs, `mapfile`, and case-conversion
  expansions.
- Keep Linux and macOS paths explicit and use the portability wrappers in
  `yubi-lib.sh` instead of direct GNU-only `stat`, `date`, or `df` behavior.
- Treat attached hardware as out of scope for ordinary tests. Run
  `./tests/run.sh`; destructive hardware validation requires separate operator
  authorization and designated test devices.
- Never place generated credentials in argv, environment variables, logs, or
  terminal output. Persistent seed pools and optional recovery output remain
  authenticated ciphertext.
- Run `./yubi.sh doctor --json [serial]` before provisioning. Unknown tool
  majors, products, firmware, or ambiguous application capabilities fail
  closed.
- The current operational and security guidance lives in [README.md](README.md),
  with derivation and transaction details under [docs/](docs/).

<!-- AIWG:workspace-operator:end -->
