# Greybox — MCP / AI Agent Security Self-Check Toolkit (v2)

You deploy AI agents or MCP servers. Before you trust them with data and tools, run this self-check. It is a **passive, read-only** look at the *deployment and permission layer* — the part the model layer can't see: leaks, over-granted tools, unsafe defaults, session handling, CORS, error disclosure.

**v2 = 双映射。** 同一份扫描结果，映射到两套官方清单：
- **OWASP MCP Security Cheat Sheet（12 类，MCP 专项，官方控制项）** — 主参考
- **OWASP Agentic AI Top 10（ASI01–ASI10，2025-12）** — 与 Cheat Sheet 有重叠，做交叉

两套都标注「toolkit 能测项 / 测不到（Untested）/ 官方控制项」，诚实划清"被动观察"的边界。

## What's included
1. **A copy of our zero-dependency audit scanner** (open-source, linked inside). Runs locally with nothing but the Python standard library — no `pip install`, no telemetry.
2. **The OWASP MCP Security Cheat Sheet (12 risks) self-check mapping.**
3. **The OWASP Agentic AI Top 10 (ASI01–ASI10) cross-mapping.**
4. **A fill-in report template** you can hand to a boss, a customer, or your future self.

## Scope — read this first
- This is a **self-service tool. It is not a security certification and not a substitute for a qualified professional.**
- All observations are passive protocol-layer checks (initialize / tools/list / one error probe). We do **not** execute tools, read business data, or change configuration.
- An item we cannot test is marked **Untested** — it is never reported as "Pass."
- The scanner's own rules map to the Cheat Sheet; the boundaries below are deliberate, not gaps we overlooked.

## How to use it
1. Get the scanner from the linked repo.
2. Run it only against a target you **own or are authorized** to test (an authorization gate is built in — it refuses to run without a declared authorization).
3. Walk the two tables below. For each row, mark **Pass / Fail / Untested** with one line of evidence.
4. Fill the report template at the bottom. Done — you have a defensible snapshot.

---

## Part A — OWASP MCP Security Cheat Sheet: 12 risks → passive-observable subset

For each of the 12 official risks, what our **passive protocol-layer** scanner can actually observe, what it **cannot**, and the **official control** the Cheat Sheet recommends.

| # | Cheat Sheet risk | Passively observable here (scanner domain) | **Not observable — mark Untested** | Official control (best practice) |
|---|---|---|---|---|
| 1 | **Tool Poisoning** | C1/C2: directive-style text & injected paths in tool descriptions | semantic-level poisoning the regex won't catch | Review & sign tool descriptions; add injection-pattern scanning to CI; forbid imperative sentences / file paths in descriptions |
| 2 | **Rug Pull** | C2: abnormally long / directive descriptions in a *single snapshot* | cross-time comparison (needs a stored baseline you re-scan against) | Pin tool definitions with cryptographic hashes; alert on any change |
| 3 | **Tool Shadowing / cross-origin escalation** | B3: dangerous-capability tools & write-ratio exposed | cross-server behavior at runtime | Strict JSON Schema, `additionalProperties:false`, per-tool patterns |
| 4 | **Confused Deputy** | A2: whether session is enforced (structural signal) | identity/privilege delegation chain (invisible inside protocol) | Enforce auth on all remote endpoints; OAuth 2.0 + PKCE; bind session ids to user context |
| 5 | **Data Exfiltration via legitimate channels** | D1/D3/H1: credentials / connection strings surfaced in headers, instructions, error bodies | live data-flow at runtime | Sanitize inputs & outputs; never pass raw shell / file paths; allow-list fetched URLs |
| 6 | **Excessive Permissions / over-scoped tokens** | B2: write-tool ratio > 30% → FAIL | actual OAuth scope granularity the server requests | Least-privilege, per-server credentials, short-lived tokens |
| 7 | **Supply Chain** | B1: tool count & names (unvetted server signal) | package version pinning / publisher trust | Pin dependencies; verify publisher; sandbox untrusted servers |
| 8 | **Message Tampering / Replay** | F1: session-id predictability (two-handshake sampling) | middleware / transport-level tampering | TLS for remote; pin/verify server identity; non-deterministic session ids; rate limits |
| 9 | **Sandbox Escape** | **not observable** — local process / filesystem layer | *(entirely)* — mark Untested | Run local MCP servers in containers/chroot; disable unneeded network; allow-list read dirs |
| 10 | **Credential / Secret Management** | D/H: only if a secret leaks into an error response | how secrets are stored server-side | Secret-management framework; scoped tokens; don't log secrets |

> **Bottom line of Part A:** the scanner covers the *observable subset* of risks 1–8; risks 9–10 (and the semantic depth of several others) are **outside a passive protocol probe** and must stay **Untested** — never "Pass."

---

## Part B — OWASP Agentic AI Top 10 (ASI01–ASI10) cross-mapping

| # | Risk (OWASP Agentic AI Top 10) | What to check — passively | Red flag |
|---|---|---|---|
| **ASI01** Agent Goal Hijack | Does content the agent *retrieves* get treated as instructions? | Agent obeys hidden directives from retrieved content; no data/command trust boundary |
| **ASI02** Tool Misuse & Exploitation | Which tools are exposed? Are parameters bounded? | Over-broad tool schema; no parameter validation; "send/delete/exec" with no guardrails |
| **ASI03** Identity & Privilege Abuse | What identity does the agent run as? Least-privilege enforced? | Agent inherits admin creds; no RBAC; "shadow agent" reusing legit creds |
| **ASI04** Agentic Supply Chain | Which MCP servers/plugins loaded? Trusted source? Pinned? | Unvetted servers; unpinned deps; unknown publishers auto-loading |
| **ASI05** Unexpected Code Execution | Does the agent generate/run code or shell? Sandboxed? | Unsandboxed execution; hidden commands in generated scripts |
| **ASI06** Memory & Context Poisoning | Is long-term memory / RAG writable by untrusted input? | Memory writable by external content; no session isolation |
| **ASI07** Insecure Inter-Agent Comm | How do cooperating agents authenticate to each other? | No auth between agents; spoofable / replayable messages |
| **ASI08** Cascading Failures | Does one failure propagate across the chain? | No circuit breaker; untested failure modes; no fallback |
| **ASI09** Human-Agent Trust Exploitation | Do users over-trust agent output? Human gate on high-impact actions? | No confirmation on destructive/external actions; blind auto-approval |
| **ASI10** Rogue Agents | Can a compromised agent act outside scope while looking legit? | No scope enforcement; no audit logging of tool calls / decisions |

---

## Red-flag quick checklist
- [ ] Agent reads external content and acts on it with no trust boundary
- [ ] Any tool with write / exec / send capability and no parameter bounds
- [ ] Agent identity broader than the task actually needs
- [ ] MCP servers or plugins loaded without source verification
- [ ] No logging of tool calls and decisions
- [ ] No human gate on high-impact (destructive / external) actions

If you tick even two of these, your agent is operating beyond what you can currently prove is safe. That is the exact gap this toolkit is built to make visible.

---

## Report Template (copy, fill, send)

```
TARGET
  Name / URL: ___________________________
  Type:  [ ] AI agent   [ ] MCP server   [ ] both
  Date: __________   Author: __________
  Authorization:  [ ] owner   [ ] written permission ref: _______

RESULTS — Cheat Sheet 12 (Pass / Fail / Untested + one line of evidence each)
  Tool Poisoning:          ___  note:
  Rug Pull:                ___  note:
  Tool Shadowing:          ___  note:
  Confused Deputy:         ___  note:
  Data Exfiltration:       ___  note:
  Excessive Permissions:   ___  note:
  Supply Chain:            ___  note:
  Msg Tamper/Replay:       ___  note:
  Sandbox Escape:          ___  note:   (Untested unless you ran a live box)
  Credential Management:   ___  note:

CROSS — ASI01–ASI10
  ASI01 Agent Goal Hijack: ___
  ASI02 Tool Misuse:       ___
  ASI03 Identity/Privilege:___
  ASI04 Supply Chain:      ___
  ASI05 Unexpected Exec:   ___
  ASI06 Memory Poison:     ___
  ASI07 Inter-Agent Comm:  ___
  ASI08 Cascading Failures:___
  ASI09 Human-Agent Trust: ___
  ASI10 Rogue Agents:      ___

OVERALL POSTURE (one paragraph):
  ________________________________________________________

TOP 3 FIXES (in priority order):
  1. ______________________________________________________
  2. ______________________________________________________
  3. ______________________________________________________

LIMITATION NOTE (required): This is a self-service passive snapshot.
It is not a security certification. Untested items are not "passes."
```

> Greybox — honest, automated, self-serve security checks for the agent deployment layer. Reproducible from the public repository.
