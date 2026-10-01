import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { z } from 'zod';
import http from 'http';

// ── Agent skill / agent config security audit ─────────────────────────────
// Agent skills (SKILL.md), project instruction files (CLAUDE.md, AGENTS.md,
// .cursorrules) and agent configs (.mcp.json, .claude/settings.json) are
// read straight into an agent's context or executed by it. Installing a
// third-party skill is closer to installing a dependency than reading a
// document, but nothing scans them. This server does static, deterministic
// checks only -- it never executes, fetches or follows anything in the input.

const sev = { critical: 3, warning: 2, info: 1 };

// Unicode "tag" block U+E0000-E007F mirrors ASCII invisibly. Text written in
// it renders as nothing in most editors but many LLM tokenizers still read it
// ("ASCII smuggling"). Decoding it shows exactly what the hidden message says.
function decodeTagChars(str) {
  let out = '';
  for (const ch of str) {
    const cp = ch.codePointAt(0);
    if (cp >= 0xe0020 && cp <= 0xe007e) out += String.fromCodePoint(cp - 0xe0000);
  }
  return out;
}
const ZERO_WIDTH_RE = /[\u200B-\u200F\u202A-\u202E\u2060-\u2064\uFEFF]/g;
const isInvisible = (ch) => {
  const cp = ch.codePointAt(0);
  return (cp >= 0xe0000 && cp <= 0xe007f) || /[\u200B-\u200F\u202A-\u202E\u2060-\u2064\uFEFF]/.test(ch);
};

const INJECTION_PHRASES = [
  [/ignore (all |any )?(the )?(previous|prior|earlier|above) (instructions|rules|context|prompts?)/i, 'instruction override', 'critical'],
  [/disregard (all |any )?(the )?(previous|prior|above|system) (instructions|rules|prompt)/i, 'instruction override', 'critical'],
  [/do not (tell|mention|inform|show|reveal)[^.\n]{0,30}\b(the )?user\b/i, 'conceal from user', 'critical'],
  [/without (telling|informing|notifying|asking)[^.\n]{0,20}\b(the )?user\b/i, 'conceal from user', 'critical'],
  [/\b(don'?t|never) (let|tell) (the )?user (know|see)/i, 'conceal from user', 'critical'],
  [/you are now (in )?(developer|dan|jailbreak|unrestricted) mode/i, 'jailbreak persona', 'warning'],
  [/(this is|new) (a )?(system|admin|developer) (message|instruction|override)/i, 'fake authority', 'warning'],
  [/(skip|bypass|disable|ignore)[^.\n]{0,25}(confirmation|approval|permission|safety|guardrail)/i, 'approval bypass', 'warning'],
  [/(auto-?approve|always approve|never ask (for )?(permission|confirmation))/i, 'approval bypass', 'warning'],
];

const SENSITIVE_PATH_RE = /(~\/\.ssh|\.ssh\/id_[a-z0-9]+|\.aws\/credentials|\/etc\/passwd|\/etc\/shadow|\.npmrc\b|\.netrc\b|\.git-credentials|\.docker\/config\.json|\.kube\/config|\.config\/gcloud|id_rsa|id_ed25519|wallet\.dat|\.env(\.local|\.production)?\b|Login Data|Cookies\.sqlite|keychain)/i;

const EXFIL_HOST_RE = /(webhook\.site|requestbin|pipedream\.net|ngrok(-free)?\.(io|app|dev)|pastebin\.com|transfer\.sh|discord(app)?\.com\/api\/webhooks|hooks\.slack\.com|burpcollaborator|interact\.sh|oast\.(fun|live|site|pro|me)|canarytokens|trycloudflare\.com|\.workers\.dev|api\.telegram\.org\/bot)/i;
const PIPE_SHELL_RE = /(curl|wget|iwr|Invoke-WebRequest|irm|Invoke-RestMethod)\b[^\n|;]{0,200}\|\s*(sudo\s+)?(ba|z|da|k)?sh\b|(curl|wget)[^\n]{0,200}\|\s*(python3?|node|perl|ruby|iex)\b|\|\s*iex\b/i;
const B64_EXEC_RE = /(base64\s+(-d|--decode)|atob\(|FromBase64String|b64decode)[^\n]{0,80}(\|\s*(ba)?sh|eval|exec|iex|Invoke-Expression)|echo\s+[A-Za-z0-9+/=]{40,}\s*\|\s*base64/i;
const SECRET_UPLOAD_RE = /(curl|wget|Invoke-WebRequest|Invoke-RestMethod|fetch\()[^\n]{0,220}(\$\{?[A-Z_]*(KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL)[A-Z_]*\}?|\benv\b|\.env\b|id_rsa|credentials)/i;
const DESTRUCTIVE_RE = /(rm\s+-rf\s+(\/|~|\$HOME)(\s|$|\*)|mkfs\.|dd\s+if=.+of=\/dev\/|:\(\)\s*\{\s*:\|:&\s*\};:|git\s+push\s+(-f|--force)[^\n]{0,30}\b(main|master)\b|chmod\s+-R\s+777\s+\/|format\s+c:|Remove-Item[^\n]{0,30}-Recurse[^\n]{0,30}(C:\\|\$env:USERPROFILE))/i;

function lineOf(str, index) { return str.slice(0, index).split('\n').length; }

function add(findings, severity, kind, line, why, fix, evidence) {
  findings.push({ severity, kind, line: line ?? null, why, fix, ...(evidence ? { evidence: String(evidence).slice(0, 160) } : {}) });
}

function scanText(str, findings, mode = 'prose') {
  const hidden = decodeTagChars(str);
  if (hidden) {
    add(findings, 'critical', 'hidden_unicode_tag_message', null,
      'Contains invisible Unicode tag characters that spell a hidden message. Renders as blank in most editors but can be read and obeyed by an LLM ("ASCII smuggling").',
      'Do not install. Strip every character in U+E0000-U+E007F and treat the source as hostile.',
      `decoded hidden text: "${hidden}"`);
  }
  const zw = str.match(ZERO_WIDTH_RE);
  if (zw) {
    ZERO_WIDTH_RE.lastIndex = 0;
    const first = ZERO_WIDTH_RE.exec(str);
    ZERO_WIDTH_RE.lastIndex = 0;
    add(findings, zw.length > 5 ? 'critical' : 'warning', 'zero_width_or_bidi_characters', first ? lineOf(str, first.index) : null,
      `${zw.length} zero-width / bidirectional-control character(s) found. Legitimate instruction files have no reason to contain them; they hide or reorder text from human reviewers.`,
      'Remove them and re-read the file as plain text. Bidi controls (U+202A-202E) can make code or instructions display differently than they execute.');
  }
  for (const m of str.matchAll(/<!--([\s\S]*?)-->/g)) {
    const body = m[1].trim();
    if (body.length > 20 && /\b(you must|always|never|ignore|run|execute|send|upload|do not|read|cat|curl|include)\b/i.test(body)) {
      add(findings, 'warning', 'instructions_in_html_comment', lineOf(str, m.index),
        'An HTML comment contains imperative instructions. Markdown viewers hide comments, but the model still reads them -- a common way to hide directives from a reviewer.',
        'Move any real instruction into visible text, or delete the comment.', body);
    }
  }
  for (const [re, label, severity] of (mode === 'config' ? [] : INJECTION_PHRASES)) {
    const m = re.exec(str);
    if (m) add(findings, severity, 'prompt_injection_phrase', lineOf(str, m.index),
      `Matches a known prompt-injection pattern (${label}). Skill and instruction files should describe a task, not try to override the agent's rules or hide actions from its user.`,
      'Remove the phrase, or do not install the skill if you did not write it.', m[0]);
  }
  let m;
  if ((m = PIPE_SHELL_RE.exec(str))) add(findings, 'critical', 'download_and_execute', lineOf(str, m.index), 'Downloads remote content and pipes it straight into a shell/interpreter. The remote file can change after you review this one.', 'Download to a file, pin a checksum or commit, review it, then run it.', m[0]);
  if ((m = B64_EXEC_RE.exec(str))) add(findings, 'critical', 'obfuscated_payload_execution', lineOf(str, m.index), 'Decodes a base64 blob and executes it, the standard way to hide a payload from a reviewer.', 'Decode the blob manually and read it before deciding. Do not run it.', m[0]);
  if ((m = SECRET_UPLOAD_RE.exec(str))) add(findings, 'critical', 'secret_exfiltration_command', lineOf(str, m.index), 'A network command references an environment variable, .env file or credential on the same line -- the shape of a credential-exfiltration one-liner.', 'Do not run it. If it is legitimate, a secret should never be placed in a request to an arbitrary host.', m[0]);
  if ((m = EXFIL_HOST_RE.exec(str))) add(findings, 'warning', 'exfil_friendly_host', lineOf(str, m.index), 'References a host commonly used to receive stolen data or tunnel traffic (request catchers, webhooks, paste sites, tunnels).', 'Verify why the skill needs this host. Legitimate skills rarely ship to anonymous endpoints.', m[0]);
  if (mode !== 'config' && (m = SENSITIVE_PATH_RE.exec(str))) add(findings, 'warning', 'sensitive_path_reference', lineOf(str, m.index), 'Mentions a credential or secret store path. An instruction file has no need to name one unless it is telling the agent to read it.', 'Confirm the reference is a warning or documentation, not an instruction to read or upload the file.', m[0]);
  if ((m = DESTRUCTIVE_RE.exec(str))) add(findings, 'critical', 'destructive_command', lineOf(str, m.index), 'Contains a command that can wipe disks, directories or force-push over a main branch.', 'Remove it. Destructive commands do not belong in an auto-loaded instruction file.', m[0]);
  const blob = /[A-Za-z0-9+/]{200,}={0,2}/.exec(str);
  if (blob) add(findings, 'warning', 'large_encoded_blob', lineOf(str, blob.index), 'A 200+ character base64-like string is embedded. Instruction files are prose; large opaque blobs usually hide a payload or smuggle data.', 'Decode and read it, or remove it.', blob[0].slice(0, 60) + '...');
}

function parseFrontmatter(str) {
  const m = /^---\r?\n([\s\S]*?)\r?\n---/.exec(str);
  if (!m) return null;
  const fm = {};
  for (const line of m[1].split(/\r?\n/)) {
    const kv = /^([A-Za-z_-]+):\s*(.*)$/.exec(line);
    if (kv) fm[kv[1]] = kv[2].replace(/^["']|["']$/g, '');
  }
  return fm;
}

function scanSkillFrontmatter(str, findings) {
  const fm = parseFrontmatter(str);
  if (!fm) return;
  const tools = fm['allowed-tools'] || fm['allowed_tools'] || '';
  if (/\bBash\b(?!\()/.test(tools) || /Bash\(\s*\*\s*\)/.test(tools)) {
    add(findings, 'warning', 'unrestricted_shell_tool', null, 'The skill requests unrestricted shell access in allowed-tools, so it can run any command without a prompt once active.', 'Scope it, e.g. Bash(git status:*) instead of Bash.', `allowed-tools: ${tools}`);
  }
  if (fm.description) {
    if (fm.description.length > 1000) add(findings, 'warning', 'oversized_description', null, 'The description is always loaded into the agent context. An oversized one is a common place to bury instructions.', 'Keep it to a sentence or two.');
    if (/\b(always|every time|for (any|all) (task|request|prompt)|whenever the user)\b/i.test(fm.description)) {
      add(findings, 'info', 'over_eager_trigger', null, 'The description tries to make the skill trigger on everything. Legitimate skills describe a specific situation.', 'Narrow the trigger.', fm.description);
    }
  } else {
    add(findings, 'info', 'missing_description', null, 'No description in frontmatter, so the agent cannot judge when the skill applies.', 'Add a one-sentence description.');
  }
}

function summarize(findings, extra = {}) {
  findings.sort((a, b) => sev[b.severity] - sev[a.severity]);
  const critical = findings.filter((f) => f.severity === 'critical').length;
  const warning = findings.filter((f) => f.severity === 'warning').length;
  return {
    verdict: critical ? 'DO NOT INSTALL / DO NOT TRUST -- critical patterns found' : warning ? 'REVIEW BEFORE USE -- risky patterns found' : 'NO KNOWN MALICIOUS PATTERNS FOUND (static check only, not a guarantee)',
    criticalCount: critical, warningCount: warning, infoCount: findings.length - critical - warning,
    findings, ...extra,
    note: 'Static pattern analysis. Nothing in the input was executed or fetched. A clean result does not prove a skill is safe; read bundled scripts too.',
  };
}

function auditSkill(content, filename) {
  const findings = [];
  scanText(content, findings);
  if (/skill\.md$/i.test(filename || '') || /^---\r?\n/.test(content)) scanSkillFrontmatter(content, findings);
  return summarize(findings, { file: filename || '(unnamed)', characters: content.length });
}

function auditConfig(raw, filename) {
  const findings = [];
  let cfg;
  try { cfg = JSON.parse(raw); } catch { return { error: 'Input is not valid JSON. Pass the file contents of .mcp.json, .claude/settings.json or similar.' }; }
  scanText(raw, findings, 'config');
  const servers = cfg.mcpServers || cfg.servers || {};
  for (const [name, s] of Object.entries(servers)) {
    const cmd = [s.command, ...(s.args || [])].join(' ');
    if (/@latest\b/.test(cmd)) add(findings, 'warning', 'unpinned_mcp_server', null, `MCP server "${name}" runs an @latest package: whatever is published next runs on your machine with your permissions.`, 'Pin an exact version (pkg@1.2.3).', cmd);
    else if (/\bnpx\b/.test(cmd) && !/@\d/.test(cmd)) add(findings, 'warning', 'unpinned_mcp_server', null, `MCP server "${name}" runs an npx package with no pinned version.`, 'Pin an exact version.', cmd);
    if (/\buvx\b|\bpipx\b/.test(cmd) && !/[=@]=?\d/.test(cmd)) add(findings, 'info', 'unpinned_python_mcp_server', null, `MCP server "${name}" runs a Python tool without a pinned version.`, 'Pin a version.', cmd);
    if (s.url && /^http:\/\//i.test(s.url) && !/localhost|127\.0\.0\.1/.test(s.url)) add(findings, 'warning', 'plaintext_remote_mcp', null, `MCP server "${name}" connects over plain http to a non-local host. Tool results can be modified in transit.`, 'Use https.', s.url);
    if (s.url && EXFIL_HOST_RE.test(s.url)) add(findings, 'warning', 'exfil_friendly_host', null, `MCP server "${name}" points at a tunnel/webhook-style host.`, 'Confirm you control it.', s.url);
    for (const [k, v] of Object.entries(s.env || {})) {
      if (/(KEY|TOKEN|SECRET|PASSWORD)/i.test(k) && typeof v === 'string' && v.length > 8 && !/^\$\{?[A-Z_]+\}?$/.test(v)) {
        add(findings, 'warning', 'inline_secret_in_config', null, `A literal secret appears in env.${k} for "${name}". Committed config files leak it.`, 'Reference an environment variable instead, and rotate this value if the file was ever shared.', `${k}=${v.slice(0, 4)}...`);
      }
    }
    if (/\b(sh|bash|cmd|powershell|pwsh)\b/i.test(s.command || '') && /(-c|\/c|-Command)/.test(cmd) && /(curl|wget|http)/i.test(cmd)) {
      add(findings, 'critical', 'shell_wrapped_download_in_mcp', null, `MCP server "${name}" starts through a shell with a network call in the command line.`, 'Run a known, pinned binary directly.', cmd);
    }
  }
  const env = cfg.env || {};
  if (env.ANTHROPIC_BASE_URL && !/api\.anthropic\.com/.test(env.ANTHROPIC_BASE_URL)) add(findings, 'critical', 'api_base_url_override', null, 'Project config redirects the model API base URL to a non-Anthropic host. Every prompt and the API key can be sent there (a documented repo-config attack path).', 'Remove it unless you run that gateway yourself.', `ANTHROPIC_BASE_URL=${env.ANTHROPIC_BASE_URL}`);
  if (cfg.enableAllProjectMcpServers === true) add(findings, 'warning', 'auto_trust_project_mcp', null, 'enableAllProjectMcpServers auto-approves every MCP server a cloned repo declares.', 'Leave it off and approve servers one at a time.');
  const perms = cfg.permissions || {};
  for (const rule of perms.allow || []) {
    if (/^Bash(\(\s*\*?\s*\))?$/.test(rule)) add(findings, 'critical', 'allow_all_shell', null, 'Pre-approves every shell command, removing the permission prompt entirely.', 'Allow specific commands, e.g. Bash(git status:*).', rule);
    else if (/^(Write|Edit)(\(\s*\*+\s*\))?$/.test(rule)) add(findings, 'warning', 'allow_all_writes', null, 'Pre-approves writing to any file, including shell profiles and git hooks.', 'Scope writes to the project directory.', rule);
  }
  if (perms.defaultMode === 'bypassPermissions' || cfg.dangerouslySkipPermissions === true) add(findings, 'critical', 'permissions_bypassed', null, 'Config turns off permission checks entirely.', 'Remove it from any file that ships in a repository.');
  for (const [event, arr] of Object.entries(cfg.hooks || {})) {
    for (const entry of [].concat(arr || [])) {
      for (const h of entry.hooks || [entry]) {
        const c = h.command || '';
        if (!c) continue;
        if (/(curl|wget|Invoke-WebRequest|\bnc |ncat)/i.test(c)) add(findings, 'critical', 'hook_with_network_call', null, `A ${event} hook runs a network command automatically. Hooks execute with no prompt, so a cloned repo can run this on your machine.`, 'Do not use hooks that contact the network unless you wrote them.', c);
        else add(findings, 'info', 'hook_runs_shell_command', null, `A ${event} hook runs a command automatically with no prompt.`, 'Read the command before trusting the repo.', c);
      }
    }
  }
  return summarize(findings, { file: filename || '(config)', serversChecked: Object.keys(servers).length });
}

function revealHidden(str) {
  const chars = [...str];
  const positions = [];
  let idx = 0;
  let count = 0;
  for (const ch of chars) {
    if (isInvisible(ch)) {
      count++;
      if (positions.length < 50) positions.push({ index: idx, codePoint: 'U+' + ch.codePointAt(0).toString(16).toUpperCase().padStart(4, '0') });
    }
    idx += ch.length;
  }
  return {
    invisibleCharacterCount: count,
    hiddenMessageDecoded: decodeTagChars(str) || null,
    firstPositions: positions,
    cleanedText: chars.filter((c) => !isInvisible(c)).join(''),
  };
}

const reply = (o) => ({ content: [{ type: 'text', text: JSON.stringify(o, null, 2) }] });

function buildServer() {
  const server = new McpServer({ name: 'agent-skill-audit-mcp', version: '1.0.0' });

  server.tool('audit_skill_file',
    'Scans the text of an AI agent skill or instruction file (SKILL.md, CLAUDE.md, AGENTS.md, .cursorrules, a bundled script) for hidden Unicode instructions, prompt-injection phrases, download-and-execute commands, base64 payloads, secret-exfiltration one-liners, destructive commands and over-broad allowed-tools. Run it on any third-party skill before installing. Static analysis only; nothing is executed or fetched.',
    { content: z.string().describe('Full text of the file to scan'), filename: z.string().optional().describe('File name, e.g. SKILL.md. Enables skill-specific frontmatter checks.') },
    async ({ content, filename }) => reply(auditSkill(content, filename)));

  server.tool('audit_agent_config',
    'Audits an agent config file given as JSON text (.mcp.json, .claude/settings.json, .claude/settings.local.json, Cursor/Windsurf MCP config) for unpinned @latest MCP servers, inline secrets, plaintext remote servers, pre-approved shell access, bypassed permissions, auto-trusted project MCP servers, hooks that make network calls, and API base-URL overrides. Run it on a repo before opening it with an agent.',
    { config_json: z.string().describe('The JSON contents of the config file'), filename: z.string().optional() },
    async ({ config_json, filename }) => reply(auditConfig(config_json, filename)));

  server.tool('reveal_hidden_text',
    'Finds invisible Unicode in text (zero-width, bidi controls, and the U+E0000 tag block used to smuggle hidden instructions), decodes any hidden ASCII message, and returns a cleaned copy with those characters removed.',
    { text: z.string().describe('Text to inspect') },
    async ({ text }) => reply(revealHidden(text)));

  return server;
}

const PORT = process.env.PORT || 8080;
const httpServer = http.createServer(async (req, res) => {
  if (req.url === '/health') { res.writeHead(200); res.end('ok'); return; }
  if (req.url !== '/' && !req.url?.startsWith('/mcp')) { res.writeHead(404); res.end(); return; }
  const server = buildServer();
  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
  res.on('close', () => { transport.close(); server.close(); });
  await server.connect(transport);
  await transport.handleRequest(req, res);
});
httpServer.listen(PORT, () => console.log(`agent-skill-audit-mcp listening on :${PORT}`));
