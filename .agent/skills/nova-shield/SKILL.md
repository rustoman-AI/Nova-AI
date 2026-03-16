---
name: nova-shield
description: Security gate for all agent actions using Amazon Nova
---

# Nova Shield

This skill intercepts every action that can modify the system to ensure robust, AI-powered security via Amazon Nova.

Protected actions:
- `run_command` (terminal commands)
- `write_to_file`, `replace_file_content`, `multi_replace_file_content`
- `git_commit`
- Dependency installation

Workflow:
1. Agent plans an action.
2. Nova Shield sends the `intent` + `payload` to the internal Nova scanner (via the `nova_client` wrapper).
3. Scanner evaluates the payload using Amazon Nova 2 Lite and returns a risk classification.

Risk policy:

- **LOW:** Action is allowed.
- **MEDIUM:** Warn the developer, but optionally allow execution.
- **HIGH:**
    - Block action immediately.
    - Generate a Vulnerability Report.
    - Ask for developer confirmation via `notify_user` before proceeding.

Implementation rule:
All subagents MUST call `security_gate(intent, payload)` before executing any system-changing action context. If running purely as an LLM prompt, the agent MUST evaluate the action against the Nova Shield rules before committing to the tool call.

### Vulnerability Report Template (for HIGH risk)
```markdown
# 🚨 Security Blocked Action

**Intent:** `[Action Type, e.g., terminal_command]`
**Payload:**
\`\`\`
[Payload, e.g., rm -rf /]
\`\`\`
**Risk Level:** HIGH

**Analysis (Nova):**
[Detailed explanation of the vulnerability or risk]

**Action:** Blocked until developer approval.
```
