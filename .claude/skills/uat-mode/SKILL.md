---
name: uat-mode
description: Detect requests for UAT generation, execution, or reporting and invoke the appropriate UAT command
version: 1.0.0
triggers:
  - "run UAT"
  - "generate UAT plan"
  - "test the MCP tools"
  - "acceptance test this server"
  - "UAT the MCP connections"
  - "run acceptance tests"
  - "generate test plan for MCP"
  - "test MCP coverage"
  - "MCP acceptance testing"
  - "validate MCP tools"
  - "run UAT report"
  - "show UAT results"
  - "UAT coverage"
---

# UAT Mode

Detects requests related to User Acceptance Testing of MCP tool surfaces and routes to the appropriate UAT command.

## Triggers

| Pattern | Confidence | Routes To |
|---------|-----------|-----------|
| "run UAT", "execute UAT", "run acceptance tests" | High | `/uat-execute` |
| "generate UAT plan", "create test plan for MCP" | High | `/uat-generate` |
| "test the MCP tools", "validate MCP tools" | High | `/uat-generate` (if no plan exists) or `/uat-execute` |
| "acceptance test this server" | High | `/uat-generate` then `/uat-execute` |
| "UAT report", "show UAT results", "UAT coverage" | High | `/uat-report` |
| "test coverage for tools" | Medium | `/uat-report` (if results exist) or `/uat-generate` |
| "how are the MCP tools doing" | Medium | `/uat-report` (if results exist) |
| "run tests" (generic) | Low | Don't suggest — too ambiguous |

## Detection Logic

### High Confidence (Auto-Suggest)

Trigger contains explicit UAT terminology or MCP testing intent:
- Contains "UAT" in any case
- Contains "acceptance test" + "MCP" or "tool" or "server"
- Contains "test" + "MCP tools" or "MCP connections"

### Medium Confidence (Suggest with Alternatives)

Trigger is about testing tools but not explicitly UAT:
- "validate the tools"
- "check MCP coverage"
- "test the server"

### Low Confidence (Don't Suggest)

Too generic to confidently route:
- "run tests" (could be unit tests)
- "check coverage" (could be code coverage)
- "test this" (too vague)

## Behavior

### When No UAT Plan Exists

1. Inform user no plan exists
2. Offer to generate one: "I'll generate a UAT plan first. Run `/uat-generate`?"
3. If user agrees, invoke `/uat-generate`
4. After generation, offer to execute: "Plan ready. Execute it?"

### When UAT Plan Exists But No Results

1. Show existing plan summary (phases, test count)
2. Offer to execute: "Found existing plan. Execute it?"
3. If user agrees, invoke `/uat-execute`

### When Results Exist

1. Show latest results summary (pass/fail counts)
2. Offer options:
   - View full report: `/uat-report`
   - Re-run tests: `/uat-execute`
   - Generate new plan: `/uat-generate`

### Full Pipeline Request

When user says "acceptance test this server" or similar:
1. Generate plan: `/uat-generate`
2. Human reviews plan
3. Execute plan: `/uat-execute`
4. Generate report: `/uat-report`

## Response Templates

### Plan Generated
```
UAT plan generated with {N} tests across {M} phases.
Review the plan at: {path}

Ready to execute? Use `/uat-execute {path}` or just say "run the UAT".
```

### Execution Complete
```
UAT execution complete:
  Passed: {pass}/{total} ({percentage}%)
  Failed: {fail}
  Issues filed: {count}

View full report with `/uat-report` or say "show UAT results".
```

### No MCP Servers
```
No MCP servers detected. UAT-MCP requires at least one connected MCP server.
Check your MCP configuration and try again.
```

## Integration Notes

- **Priority**: High (when UAT keywords detected)
- **Exclusivity**: Full (takes over the interaction when triggered)
- **Fallback**: If UAT addon not installed, suggest `aiwg use uat-mcp`

## Related

- Commands: `/uat-generate`, `/uat-execute`, `/uat-report`
- Agents: `uat-planner`, `uat-executor`
- Issue: #380
