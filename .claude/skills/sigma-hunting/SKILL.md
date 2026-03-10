---
name: sigma-hunting
description: "Apply Sigma rules against log sources for threat hunting; convert rules to Elasticsearch, Splunk, and grep queries"
tools: Bash, Read, Write, Glob, Grep
---

# sigma-hunting

Applies Sigma detection rules against collected log sources to identify threat activity. Supports the bundled forensics-complete Sigma rule library and custom rules. Converts Sigma rules to backend-specific queries for Elasticsearch, Splunk, and grep, enabling hunting across both real-time platforms and offline log files.

## Triggers

- "sigma hunt"
- "threat hunt"
- "sigma rules"
- "apply sigma rules"
- "hunt for <technique>"

## Purpose

Sigma provides a vendor-neutral rule format for expressing detection logic. Writing backend-specific queries for every log source and SIEM is time-consuming and error-prone. This skill translates Sigma rules to the appropriate query format for the available tooling, applies them against collected logs, and reports matches with ATT&CK technique context.

## Behavior

When triggered, this skill:

1. **Identify available rule sources**:
   - Bundled rules: `agentic/code/frameworks/forensics-complete/sigma/`
   - Custom rules: `.aiwg/forensics/sigma/custom/`
   - Check for sigma-cli or pySigma installation: `sigma --version 2>/dev/null`
   - If sigma-cli is unavailable, use built-in grep-based conversion for simple rules

2. **Identify target log sources and backends**:
   - Detect available log sources: journald, flat files, Elasticsearch index, Splunk index
   - Match Sigma `logsource` categories to available sources:
     - `category: process_creation` → syslog, auditd logs, or EDR telemetry
     - `category: network_connection` → firewall logs, VPC flow logs, Zeek conn.log
     - `category: webserver` → nginx/Apache access logs
     - `product: linux` → auth.log, syslog, journal
     - `product: windows` → Windows Event Log exports (.evtx or JSON)

3. **Select applicable rules**:
   - Filter rule library by `logsource` compatibility with available sources
   - If a specific MITRE technique is requested (e.g., "hunt for T1059"), filter by `tags: attack.t1059*`
   - Apply severity filter: default to `medium`, `high`, `critical` rules only
   - List selected rules and their ATT&CK technique mappings before execution

4. **Convert rules to grep (offline log files)**:
   - Parse Sigma YAML detection field
   - Convert `selection` keywords to extended grep patterns:
     ```bash
     grep -Ei 'pattern1|pattern2' /var/log/auth.log
     ```
   - Handle `condition: selection and not filter` by piping through a second grep with `-v`
   - Note: grep conversion handles keyword-only rules; complex field-mapped rules require sigma-cli

5. **Convert rules via sigma-cli (when available)**:
   - Elasticsearch backend:
     ```bash
     sigma convert -t elasticsearch -f lucene rules/sigma/linux/ > hunt-queries.txt
     ```
   - Splunk backend:
     ```bash
     sigma convert -t splunk rules/sigma/linux/ > hunt-spl.txt
     ```
   - Execute converted queries against the target index or log source

6. **Execute hunts and collect matches**:
   - Run each rule against the target log source
   - Record: rule name, ATT&CK technique, match count, first and last match timestamp, sample matching lines
   - Group results by ATT&CK tactic for reporting

7. **Triage matches**:
   - Flag rules with zero matches (coverage gap) vs rules with matches (hits)
   - For each hit: extract relevant fields (source IP, username, process name, command line)
   - Cross-reference extracted values with IOC list from `ioc-extraction` skill

8. **Apply custom rules**:
   - Load any `.yml` files from `.aiwg/forensics/sigma/custom/`
   - Validate YAML structure and required Sigma fields before execution
   - Report custom rule coverage alongside bundled rule results

9. **Write hunt report**:
   - Save to `.aiwg/forensics/findings/<hostname>-sigma-hunt.md`
   - Include: rules applied, hits per rule, ATT&CK tactic coverage map, sample evidence per hit, coverage gaps

## Usage Examples

### Example 1 — Full hunt against local logs
```
sigma hunt
```

### Example 2 — Hunt for specific technique
```
hunt for T1078
```

### Example 3 — Convert rules for Elasticsearch
```
sigma rules --backend elasticsearch --output hunt-queries.txt
```

## Output Locations

- Hunt report: `.aiwg/forensics/findings/<hostname>-sigma-hunt.md`
- Converted queries: `.aiwg/forensics/sigma/converted/`
- Rule hit evidence: `.aiwg/forensics/evidence/sigma-hits.txt`

## Configuration

```yaml
sigma_hunting:
  bundled_rules_path: agentic/code/frameworks/forensics-complete/sigma/
  custom_rules_path: .aiwg/forensics/sigma/custom/
  default_severity_filter:
    - medium
    - high
    - critical
  default_backend: grep
  available_backends:
    - grep
    - elasticsearch
    - splunk
  sigma_cli_path: sigma
```
