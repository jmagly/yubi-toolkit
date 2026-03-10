---
description: Build or rebuild the SDLC artifact index for agent-navigable discovery
category: documentation-tracking
argument-hint: [--force] [--verbose] [--interactive] [--guidance "text"]
allowed-tools: Read, Write, Glob, Grep, Bash
model: sonnet
---

# Build Artifact Index

## Task

Build or refresh the artifact index that powers `aiwg index query`, `aiwg index deps`, and `aiwg index stats`. This is the entry point for ensuring agents can discover and navigate project artifacts efficiently.

## Behavior

### Primary: Use `aiwg index build`

```bash
# Standard rebuild (incremental)
aiwg index build

# Full rebuild (ignore cache)
aiwg index build --force

# With progress output
aiwg index build --verbose
```

Report what changed: new artifacts indexed, updated, unchanged, and removed counts.

### Fallback: Manual Digest Generation

If `aiwg index build` is not available (CLI not installed), fall back to manual scanning:

1. Walk `.aiwg/` for all artifact files
2. Extract titles and short summaries from frontmatter/headings
3. Write digest files to `.aiwg/working/digests/`
4. Generate or update `_index.yaml` with paths, summaries, and timestamps

### Post-Build Verification

After building, verify the index is healthy:

```bash
aiwg index stats --json
```

Report total artifacts indexed, coverage by phase, and any orphaned artifacts.

## When to Run

- After creating new SDLC artifacts
- After modifying existing artifact references
- At the start of a new SDLC phase
- When `aiwg index query` returns stale results

## References

- @agentic/code/frameworks/sdlc-complete/rules/artifact-discovery.md — Agent protocol rules
- @agentic/code/frameworks/sdlc-complete/skills/artifact-lookup/SKILL.md — Query skill
- @src/artifacts/cli.ts — CLI implementation
