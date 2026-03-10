# cleanup-audit

Identify dead code, unused exports, orphaned files, stale manifest entries, and unused dependencies in a codebase. Produces a structured report with confidence-rated findings.

## Triggers

- "find dead code"
- "what files are not imported anywhere?"
- "show me unused exports"
- "audit dependencies"
- "find orphaned files"
- "cleanup audit"
- "/cleanup-audit"
- "/cleanup-audit --scope src/"

## Purpose

As codebases grow, dead code accumulates: unused exports, orphaned files, stale configurations, and unreferenced artifacts. This skill systematically identifies them and produces an actionable report — without deleting anything automatically.

## Behavior

When triggered:

1. **Determine scope** — default: entire project; can be narrowed via `--scope <path>`
2. **Select categories** — default: all; can filter via `--type <exports|files|deps|manifests>`
3. **Run analysis** for each enabled category
4. **Produce report** — structured markdown with confidence ratings
5. **Optionally output JSON** — via `--json` for machine processing

### Analysis Steps

#### Unused Exports
```bash
# For each .ts/.js file, find exports and check for imports
# Build: export_map[file:symbol] -> imported_by[]
# Report: entries where imported_by is empty
```

1. Glob all source files (`src/**/*.{ts,js,mjs}`)
2. Extract all `export` statements (named, default, re-exports)
3. For each export, grep the entire codebase for imports of that symbol
4. Report exports with zero imports (excluding index/barrel re-exports)

#### Orphaned Files
1. Build import graph from all source files
2. Identify entry points (bin scripts, main exports, test files)
3. Walk the graph from entry points
4. Report files not reachable from any entry point

#### Unused Dependencies
1. Read `package.json` dependencies and devDependencies
2. Grep `src/` for imports of each dependency
3. Grep `test/` and `tools/` for devDependency imports
4. Report packages with zero import matches

#### Stale Manifest Entries
1. Find all `manifest.json` files
2. For each file entry in manifest, verify it exists on disk
3. Report missing entries

## Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `--scope <path>` | `.` | Limit analysis to directory |
| `--type <category>` | all | `exports`, `files`, `deps`, `manifests` |
| `--json` | false | Output machine-readable JSON |
| `--fix` | false | Interactive removal (confirm each item) |
| `--dry-run` | false | Show what `--fix` would do without acting |

## Output Format

```markdown
## Dead Code Analysis Report

**Scope**: {scope}
**Files scanned**: {count}

### High Confidence
| Category | Location | Reason | Lines |
|----------|----------|--------|-------|

### Medium Confidence
| Category | Location | Reason | Lines |
|----------|----------|--------|-------|

### Low Confidence
| Category | Location | Reason | Lines |
|----------|----------|--------|-------|

### Summary
- Removable lines: ~{count}
- Removable files: {count}
- Unused dependencies: {count}
```

## Safety

- Never auto-delete without `--fix` flag AND per-item confirmation
- Manifest-listed files are considered alive
- Entry points (bin, main, test) are never flagged as orphaned
- Dynamic imports are flagged as LOW confidence, not auto-removable
- Files with associated test files get MEDIUM confidence at most

## Error Handling

- If a manifest cannot be parsed: warn and skip that manifest
- If import analysis hits a circular dependency: note it and continue
- If `package.json` is missing: skip dependency audit

## References

- @agentic/code/frameworks/sdlc-complete/agents/dead-code-analyzer.md
- @agentic/code/frameworks/sdlc-complete/rules/agent-friendly-code.md
- @agentic/code/frameworks/sdlc-complete/rules/anti-laziness.md
