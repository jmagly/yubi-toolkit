# doc-sync

Synchronize documentation and code to eliminate drift through parallel audit and automated fixes.

## Triggers

- "align docs to code"
- "align code to docs"
- "sync documentation"
- "doc audit"
- "check doc drift"
- "are docs up to date"
- "find stale documentation"
- "reconcile docs and code"
- "documentation out of date"
- "docs don't match code"

## Purpose

This skill detects documentation-code drift and orchestrates parallel auditors to identify, report, and fix inconsistencies. It supports three sync directions: code-to-docs (code is truth), docs-to-code (docs are truth), and full bidirectional reconciliation.

## Behavior

When triggered, this skill:

1. **Detects direction from phrasing**:
   - "align docs to code" / "sync docs" → `code-to-docs`
   - "align code to docs" / "code doesn't match docs" → `docs-to-code`
   - "reconcile" / "full sync" → `full`
   - Ambiguous → default to `code-to-docs`

2. **Detects scope from context**:
   - Path mentions → `--scope <path>`
   - "just the CLI reference" → `--scope docs/cli-reference.md`
   - "since last sync" / "recent changes" → `--incremental`
   - No scope → full project

3. **Invokes doc-sync command**:
   - Maps detected parameters to command switches
   - Defaults to `--dry-run` on first invocation (safe default)
   - Asks for confirmation before applying fixes

4. **Reports findings**:
   - Summary of drift items found
   - Classification: auto-fixable vs human-required
   - Offers to apply fixes

## Natural Language Routing Examples

### Simple audit
```
User: "Are the docs up to date?"
→ /doc-sync code-to-docs --dry-run
```

### Targeted sync
```
User: "The CLI reference doesn't match the actual commands"
→ /doc-sync code-to-docs --scope docs/cli-reference.md
```

### Full reconciliation
```
User: "Reconcile all docs and code"
→ /doc-sync full --verbose
```

### Incremental check
```
User: "Check if recent code changes broke any docs"
→ /doc-sync code-to-docs --incremental --dry-run
```

### Code fix generation
```
User: "The docs say we support X but code doesn't implement it"
→ /doc-sync docs-to-code --scope <detected-path>
```

## Integration

This skill uses:
- `parallel-dispatch`: For launching domain-specific auditors
- `mention-validate`: For checking @-mention resolution
- `claims-validator`: For verifying numeric claims
- `check-traceability`: For bidirectional link verification
- `ralph`: For iterative refinement of complex fixes

## Output Location

- Audit reports: `.aiwg/reports/doc-sync-audit-{date}.md`
- Sync state: `.aiwg/.last-doc-sync`

## References

- Command: @agentic/code/frameworks/sdlc-complete/commands/doc-sync.md
- CLI reference: @docs/cli-reference.md
