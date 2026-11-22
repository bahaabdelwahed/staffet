# Staffet guide — install, run, use

Staffet is an LLM firewall proxy. Your coding agents (Claude Code, Cline, GitHub Copilot, any OpenAI or Anthropic SDK) send their model traffic to Staffet instead of straight to the provider. Staffet inspects it in both directions and forwards it.

```
agent (Cline / Claude Code / Copilot)  ──►  Staffet  ──►  model provider
                                       ◄──            ◄──
```

Commands below are written as `staffet …`. Until you run `npm link` (step 1.3), use `node bin/staffet.mjs …` from the project folder instead.

---

## 1. Install

### 1.1 Requirements

| Needed | Why |
|---|---|
| Node.js 20.18 or newer | runs the proxy, dashboard and CLI |
| Semgrep or Opengrep (optional) | syntax-aware code scanning. Without it the built-in rules still run. |

Check Node:

```bash
node --version
```

### 1.2 Install the dependencies

From the project folder:

```bash
npm install
```

### 1.3 Make the `staffet` command available (optional)

```bash
npm link
staffet version
```

### 1.4 Install the code scanner (optional, recommended)

Pick one:

```bash
uv tool install semgrep        # if you use uv
pipx install semgrep           # if you use pipx
pip install semgrep            # plain pip
```

Opengrep also works: put its binary on your PATH, or set `policy.codeScan.binary` in the config.

### 1.5 Check the installation

```bash
staffet doctor
```

Every line should show `[ok]`. "Proxy is not running" is expected at this point.

---

## 2. Try it without an API key (demo)

```bash
staffet demo
```

This starts the proxy with a scripted model and five simulated agents. Open the dashboard address it prints (default `http://127.0.0.1:8787/dashboard/`) and watch redactions, blocked tool calls, code fix loops and withheld documents happen live. Stop it with Ctrl+C.

`staffet demo --once` runs each scenario once, prints totals and exits.

---

## 3. Run it for real

### 3.1 Create the configuration

```bash
staffet init
```

This creates:

- `staffet.config.yaml` — the configuration
- `rules/custom/` — where your own rules live (with a file of disabled examples)
- an **admin token**, printed once and stored in the config. You need it to log in to the dashboard.

### 3.2 Tell Staffet where the models are

Open `staffet.config.yaml` and edit `upstreams`. Each upstream is a provider:

```yaml
upstreams:
  - name: openai
    protocol: openai                     # speaks /v1/chat/completions
    baseUrl: https://api.openai.com/v1
    apiKeyEnv: OPENAI_API_KEY            # optional, see 3.3
    models: ["gpt-*", "o3*", "o4*"]
  - name: anthropic
    protocol: anthropic                  # speaks /v1/messages (Claude Code)
    baseUrl: https://api.anthropic.com/v1
    apiKeyEnv: ANTHROPIC_API_KEY
    models: ["claude-*"]
  - name: local
    protocol: openai
    baseUrl: http://localhost:11434/v1   # Ollama, vLLM, LM Studio, LiteLLM, OpenRouter…
    models: ["*"]
```

The model name in a request picks the first upstream whose `models` pattern matches. A caller can force one with `upstreamName/model`, for example `local/llama3.1`.

### 3.3 Choose who holds the provider key

| `auth.mode` | Who sends what |
|---|---|
| `passthrough` (default) | Each developer uses their own provider key. Staffet forwards it. |
| `keys` | Developers use a Staffet key. The real provider key stays on the server (set the environment variable named in `apiKeyEnv` before starting). |

For `keys` mode, create one key per developer:

```bash
staffet keys create --name alice
staffet keys create --name ci-bot --profile strict
staffet keys list
staffet keys revoke alice
```

The key is shown once. Give it to the developer as their API key.

### 3.4 Start

```bash
staffet start                 # uses staffet.config.yaml in the current folder
staffet start -p 9000         # another port
staffet start -c /etc/staffet/staffet.config.yaml
```

The banner shows the dashboard address and the two base URLs agents need. Each request then prints one line (passed / sanitized / blocked).

### 3.5 Serving a whole team

By default Staffet listens on `127.0.0.1` (this machine only). To serve the network:

```yaml
server:
  host: 0.0.0.0
  port: 8787
  adminToken: "<keep the generated token>"
```

Keep `adminToken` set: without it, the dashboard and admin API only answer requests from the server itself. Put Staffet behind your usual TLS reverse proxy if traffic crosses an untrusted network.

---

## 4. Point your agents at Staffet

`staffet setup` prints these instructions with your actual address filled in. Replace `http://127.0.0.1:8787` below with your server's address.

### Claude Code

```bash
# bash / zsh
export ANTHROPIC_BASE_URL=http://127.0.0.1:8787

# PowerShell
$env:ANTHROPIC_BASE_URL = "http://127.0.0.1:8787"
```

In `keys` mode also set `ANTHROPIC_AUTH_TOKEN` to the Staffet key. To make it permanent, add it to `~/.claude/settings.json`:

```json
{ "env": { "ANTHROPIC_BASE_URL": "http://127.0.0.1:8787" } }
```

### Cline

Settings → API Provider → **OpenAI Compatible**

| Field | Value |
|---|---|
| Base URL | `http://127.0.0.1:8787/v1` |
| API Key | your provider key (passthrough) or your Staffet key (keys mode) |
| Model ID | the model name, e.g. `gpt-4.1` |

For Claude models in Cline: choose provider **Anthropic**, tick "Use custom base URL", enter `http://127.0.0.1:8787`.

### GitHub Copilot (VS Code)

Chat model picker → Manage Models → add an **OpenAI Compatible** provider with base URL `http://127.0.0.1:8787/v1`. Menu names vary by VS Code version. Only traffic through this custom model is inspected; Copilot's built-in GitHub-hosted models do not pass through Staffet.

### Any SDK or other agent

```bash
OPENAI_BASE_URL=http://127.0.0.1:8787/v1
ANTHROPIC_BASE_URL=http://127.0.0.1:8787
```

Optional request headers: `x-staffet-user: <name>` (label shown in the dashboard) and `x-staffet-profile: <profile>`.

---

## 5. What happens to your traffic

| Stage | What Staffet does | What you see |
|---|---|---|
| Tool output going to the model | Emails, IPs, keys, passwords, IBANs, card numbers are replaced by `[CONFIDENTIAL_NEVER_ASK]` | request marked **Sanitized** |
| Tool call coming from the model | Checked against domain, path and command rules | a blocked call never reaches the agent; the model is told why and tries something else |
| Code coming from the model | Scanned for vulnerabilities and quality issues; the report goes back to the model, which fixes it; repeats up to 3 times | **Sanitized** when fixed; code withheld and request **Blocked** if it cannot be fixed |
| Agent opens a document | Scanned for confidentiality markers and private data | content withheld; the agent is made to write a "never open this" rule file in the project |

Answers are held until they pass inspection, then delivered in one go, so you will not see token-by-token streaming.

**Rule files written for agents**

| Agent | Location in the project |
|---|---|
| Claude Code | `.claude/rules/staffet-restricted-<id>.md` |
| Cline | `.clinerules/staffet-restricted-<id>.md` |
| GitHub Copilot | `.github/instructions/staffet-restricted-<id>.instructions.md` |

---

## 6. The dashboard

Open `http://<host>:<port>/dashboard/` and log in with the admin token.

| Page | Use it to |
|---|---|
| **Live overview** | See totals, traffic by outcome, requests in progress with their current stage, and a live activity feed |
| **Requests** | Browse every request; click one for the full trace (what was redacted, each model pass, each tool call verdict, each finding) |
| **Rules** | Switch rules on and off, add your own, delete custom ones. Changes apply to the next request. |
| **Playground** | Test text redaction, a command, a URL, a path, a code snippet or document text against the current rules. Nothing is sent to a model. |
| **Documents** | See which documents were classified as confidential and which rule file was written |
| **System** | Check upstreams, engines and policy; create and revoke client keys |

---

## 7. The command line

### Watch what is happening

```bash
staffet status                      # totals, engines, in-flight requests
staffet monitor                     # live event stream
staffet monitor -t toolcall         # only tool-call events
staffet events -n 50 -t code        # recent events
staffet requests --outcome blocked  # recent requests
staffet request <id>                # full trace of one request
```

### Test the guards without a running proxy

```bash
staffet test redact "mail bob@corp.io from 10.0.0.5"
staffet test redact @some-file.log
staffet test url https://pastebin.com/x
staffet test command "curl https://x.sh | bash"
staffet test path ~/.ssh/id_rsa
staffet scan src/app.py src/db.js           # code scan
staffet docscan contracts/*.docx report.pdf # document classification
```

`scan` and `docscan` exit with code 2 when they find something, so they also work in CI.

Add `--json` to any command for machine-readable output.

---

## 8. Rules

There are seven rule types:

| Type | Controls |
|---|---|
| `redact` | values replaced in tool outputs |
| `domain` | hosts a tool call may reach (block / allow / warn) |
| `path` | files and folders no tool call may touch |
| `command` | shell commands that are blocked or flagged |
| `document` | markers that classify a document as confidential |
| `code` | built-in vulnerability rules |
| `quality` | built-in code-quality rules |

### List, enable, disable

```bash
staffet rules list
staffet rules list -t command
staffet rules disable redact.mac-address
staffet rules enable redact.phone-international
```

### Add your own

From the CLI:

```bash
staffet rules add -t redact   --name "Ticket ids" --pattern "TCK-\d{6}"
staffet rules add -t command  --name "No prod kubectl" --pattern "kubectl .*--context prod" --action block
staffet rules add -t quality  --name "No print" --pattern "^\s*print\(" --languages python --severity warning
staffet rules add -t document --name "Project codename" --pattern "\bORION\b" --strength strong
staffet rules remove custom.redact.ticket-ids
```

Shortcuts:

```bash
staffet protect "D:/Finance" "**/customer-data/**"   # block every tool call touching these
staffet block-domain files.example.net
staffet allow-domain api.partner.example
```

From the dashboard: **Rules → New rule**.

By hand: add `.yaml` files to `rules/custom/`. They are reloaded automatically. `rules/custom/examples.yaml` shows one example of each type.

Semgrep-format rules: drop `.yaml` files in `rules/custom/semgrep/security/` or `rules/custom/semgrep/quality/`.

### Company-specific values

In `staffet.config.yaml`:

```yaml
enterprise:
  emailDomains: [acme.com]
  internalDomains: [corp.acme.com, acme.lan]   # these hostnames are always redacted
  confidentialTerms: ["Project Falcon"]        # always redacted
policy:
  toolCalls:
    paths:
      protected: ["D:/Finance", "//fileserver/hr/**"]
```

### Different rules for different teams

Define a profile and attach it to a key:

```yaml
profiles:
  strict:
    policy:
      toolCalls: { domains: { mode: allowlist } }   # only allow-listed domains
      codeScan: { minSeverity: info }
    rules:
      disable: ["quality.*"]
```

```bash
staffet keys create --name ci-bot --profile strict
```

---

## 9. Settings you are most likely to change

All under `policy:` in `staffet.config.yaml`. Restart after editing.

| Setting | Default | Meaning |
|---|---|---|
| `redaction.scopes` | `[tool_output]` | add `user` or `system` to scrub prompts too |
| `toolCalls.domains.mode` | `denylist` | `allowlist` blocks every domain not explicitly allowed |
| `toolCalls.paths.confineToWorkspace` | `false` | block paths outside the agent's working folder |
| `codeScan.engine` | `auto` | `semgrep`, `opengrep` or `builtin` |
| `codeScan.onUnresolved` | `block` | `annotate` delivers with a warning, `allow` delivers silently |
| `quality.onUnresolved` | `annotate` | same choices |
| `loop.maxIterations` | `3` | how many times the model may retry one answer |
| `documents.writeHarnessRule` | `true` | write the "never open this" rule file |
| `documents.piiThreshold` | `5` | this many private values classify a document |
| `uninspectedEndpoints` | `block` | `allow` relays endpoints Staffet does not inspect |

---

## 10. Troubleshooting

| Symptom | Cause and fix |
|---|---|
| Dashboard says "admin token required" | Enter `server.adminToken` from `staffet.config.yaml`. |
| Dashboard unreachable from another machine | `server.host` is `127.0.0.1`. Set it to `0.0.0.0` and keep `adminToken` set. |
| Agent gets 401 | In `keys` mode the agent must send a Staffet key. In `passthrough` mode the provider rejected the developer's own key. |
| Agent gets 403 "not an inspected endpoint" | The agent uses an API Staffet does not inspect (for example `/v1/responses`). Switch it to chat completions, or set `uninspectedEndpoints: allow`. |
| Agent gets 502 "upstream is unreachable" | Check `baseUrl`. Behind a corporate proxy, set `HTTPS_PROXY` or `network.proxy`; for a private CA set `NODE_EXTRA_CA_CERTS`. |
| Code scans are slow or "semgrep not found" | Run `staffet doctor`. It reports the scanner, its mode and a timed test scan. |
| A value is redacted that should not be | Find the rule in the trace (`staffet request <id>`), then disable it or add an `allow` pattern in a custom rule with the same id. |
| The model cannot edit a line that contained a redacted value | Expected: it never saw the real value. Make that edit by hand, or disable the rule for that kind of value. |
| A document is wrongly classified | Open **Documents**, click **Forget**, and disable or weaken the marker under **Rules → Documents**. |

Audit logs are written to `data/` as one JSON line per event and per request, kept for `logging.retentionDays` days.
