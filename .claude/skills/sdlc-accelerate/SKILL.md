# sdlc-accelerate

End-to-end SDLC ramp-up from idea to construction-ready in a single orchestrated pipeline.

## Triggers

- "set up project"
- "take me to construction"
- "bootstrap SDLC"
- "ramp up project"
- "accelerate project"
- "full SDLC setup"
- "prepare project for development"
- "get this project construction-ready"
- "I have an idea for"
- "new project setup"
- "start from scratch"

## Purpose

This skill eliminates the 7+ command ramp-up that new users face when going from idea to construction-ready. It orchestrates the full SDLC pipeline (intake → inception → elaboration → construction prep) with focused gate questions at each transition, producing a Construction Ready Brief at completion.

## Behavior

When triggered, this skill:

1. **Detects entry mode**:
   - New idea description → `sdlc-accelerate "<description>"`
   - Existing codebase mentioned → `sdlc-accelerate --from-codebase <path>`
   - Project already started → `sdlc-accelerate --resume`
   - Preview request → `sdlc-accelerate --dry-run "<description>"`

2. **Extracts project description**:
   - Pull key phrases from user message
   - Identify technology mentions, domain context
   - Detect if user wants interactive or automated flow

3. **Invokes sdlc-accelerate command**:
   - Maps natural language to appropriate switches
   - Defaults to interactive for new users (asks at gates)
   - Uses `--auto` if user says "just do it" or "auto"

4. **Guides through gates**:
   - Presents focused questions (not full gate reports)
   - Captures decisions for state tracking
   - Allows skip with waiver for non-critical items

## Natural Language Routing Examples

### New project from idea
```
User: "I have an idea for a customer portal with real-time chat"
→ /sdlc-accelerate "Customer portal with real-time chat"
```

### From existing code
```
User: "Set up SDLC for this codebase"
→ /sdlc-accelerate --from-codebase . "Existing project SDLC setup"
```

### Resume
```
User: "Continue setting up the project"
→ /sdlc-accelerate --resume
```

### Preview
```
User: "What would it take to get this project construction-ready?"
→ /sdlc-accelerate --dry-run "Current project assessment"
```

### Automated flow
```
User: "Bootstrap SDLC for this project, just auto-approve everything"
→ /sdlc-accelerate --auto "Project from context"
```

## Integration

This skill delegates to:
- `intake-wizard` / `intake-from-codebase`: Initial project intake
- `flow-concept-to-inception`: Phase transition
- `flow-gate-check`: Gate evaluation
- `flow-inception-to-elaboration`: Phase transition
- `flow-elaboration-to-construction`: Phase transition
- `project-status`: Phase detection for resume

## Output Location

- State file: `.aiwg/reports/accelerate-state.json`
- Construction brief: `.aiwg/reports/construction-ready-brief.md`
- Gate reports: `.aiwg/gates/`

## References

- Command: @agentic/code/frameworks/sdlc-complete/commands/sdlc-accelerate.md
- State schema: @agentic/code/frameworks/sdlc-complete/schemas/flows/accelerate-state.yaml
- Brief template: @agentic/code/frameworks/sdlc-complete/templates/management/construction-ready-brief-template.md
