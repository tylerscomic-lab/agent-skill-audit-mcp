# Agent Skill & Config Security Audit

Security scanner for AI agent skills and config files (SKILL.md, CLAUDE.md, AGENTS.md, .mcp.json, settings.json). Finds hidden Unicode instructions, prompt injection, exfiltration commands and over-broad permissions before you install a skill.

## Scan a skill before you install it
Agent skills and instruction files are read straight into your agent's context, and some ship scripts it can run. Research on public skill registries has found prompt injection and credential-stealing payloads in a large share of them. Installing a third-party skill is closer to adding a dependency than opening a document, and nothing scans them. This does.

## What it catches
- **Hidden Unicode instructions**: invisible "tag" characters that render as blank but that models can read, plus zero-width and bidi control characters. The hidden message is decoded for you.
- **Prompt injection**: "ignore previous instructions", "do not tell the user", fake system messages, approval bypasses.
- **Download-and-execute and obfuscation**: `curl | bash`, base64-decode-and-run, large encoded blobs.
- **Exfiltration shapes**: network commands that reference env vars or credential files, request-catcher and tunnel hosts, sensitive paths like `~/.ssh` and `.aws/credentials`.
- **Over-broad permissions**: unrestricted `Bash` in allowed-tools, `Bash(*)` pre-approvals, bypassed permissions.
- **Risky agent configs**: unpinned `@latest` MCP servers, inline secrets, plaintext remote servers, hooks that make network calls, API base-URL overrides, auto-trusted project MCP servers.

## Tools
- `audit_skill_file`: scan SKILL.md, CLAUDE.md, AGENTS.md, .cursorrules or a bundled script.
- `audit_agent_config`: audit .mcp.json or .claude/settings.json.
- `reveal_hidden_text`: find and decode invisible characters in any text, and return a cleaned copy.

Static analysis only. Nothing in your input is executed or fetched. A clean result is not a guarantee, so read bundled scripts too.

## Use it

Hosted on [MCPize](https://mcpize.com/mcp/agent-skill-audit-mcp) with a free tier (10 calls a day). Remote MCP endpoint (streamable HTTP, API key from MCPize):

```
https://agent-skill-audit-mcp.mcpize.run/mcp
```

Or run it yourself:

```bash
npm install
node server.js   # listens on :8080, MCP at /mcp
```

MIT licensed.
