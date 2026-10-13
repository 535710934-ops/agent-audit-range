# agent-audit-range

**8 组对照靶场 + 25 项一键回归**，用于验证 AI agent / MCP Server 安全审计流程。

不是又一个扫描器。攻击 payload 那一侧已经很挤了 —— promptfoo 有 155 个插件，
garak、DeepTeam、Giskard、PyRIT、AgentDojo 各有覆盖。**缺的不是 payload，缺的是
判定、归因、以及说清楚哪些东西根本测不了。**

这个仓库开源的是**靶场与工具**。审计方法论本身不开源。

---

## Executive Summary (English)

**What this is:** a benchmark range and toolchain for auditing AI-agent / MCP-server
security — built around paired targets (deliberately vulnerable + hardened) so every
check is validated both ways: the vulnerable side must be caught, the hardened side
must stay clean.

**What's inside:**

- **10 target pairs** on localhost only — 8 pairs use a simplified range protocol
  (ports 9001–9016) for fast regression; 2 pairs speak **real MCP** (JSON-RPC 2.0 /
  Streamable HTTP, ports 9017–9018) with seeded flaws that mirror the 2025–2026
  wild: tool-description injection, unscoped SQL/shell tools, stack traces in errors,
  predictable session IDs, missing auth, confirmation-free writes.
- **18 audit tools** (`tools/`) — zero-dependency Python stdlib: multi-turn escalation,
  credential/session leakage, capability grant abuse, cross-server combo chains,
  deployment leaks, semantic-rewrite blind-spot quantification (with held-out sets).
- **A remote MCP scanner** (`toolkit/`) — passive, 6 domains / 16 checks mapped to
  OWASP for LLM Top 10, never calls the target's tools, and refuses to run against
  targets without a declared authorization (self / CTF / bounty / written).
- **`SKIPPED` is never folded into `PASS`.** Unreachable ≠ secure — the most
  dangerous failure mode is "couldn't test" being read as "no problem".

**Verified:** bidirectional self-check 9/9; full run catches 6 flaws on the vulnerable
target with zero false positives on the hardened one. A clean `git clone` reproduces
all of it with four commands and no third-party dependencies.

**What this is not:** a scanner marketing page. Payload generation is a crowded space
(promptfoo, garak, PyRIT, AgentDojo…). This project works the other side of the
problem: verdicts, attribution, and honest disclosure of what cannot be tested.

> The audit methodology itself is not open-sourced. Targets and tools are.

### If you run agents / MCP servers and just want to check your own

You probably already know there are free MCP scanners (mcp-scan, mcpaudit,
mcpscan…). This is not another one of those. The difference, in one line:

- **Passive + authorization-gated + redacted** — it only reads the protocol
  layer, refuses to run without a declared authorization, and ships a report
  you can hand to a boss or a client. No dynamic fuzzing that pokes your real
  tools, no "it said clean" where it actually couldn't reach the target.
- **Honest coverage**: mapped to the OWASP MCP Security Cheat Sheet and the
  Agentic AI Top 10, with anything it can't test marked **Untested**, never Pass.

If you just want to self-check your own servers, start with the **free
snapshot audit** above, or grab the self-serve toolkit from the
[landing page](https://535710934-ops.github.io/agent-audit-range/).

---

## 免费快检 · Free Snapshot Audit

**中文**：你在维护一个 AI agent / MCP 相关的项目？可以申请一次**免费的被动安全快检**（48 小时内交付）：

- **交付物**：一份脱敏 HTML 报告——部署层泄漏、工具权限面、错误信息暴露、会话管理、CORS 等协议层观察，逐项映射 OWASP LLM Top 10。长什么样：[`reports/sample-report-snapshot.html`](reports/sample-report-snapshot.html)
- **怎么申请**：邮件至 `535710934@qq.com`（标题 `[Audit Request] + 项目名`），写明：① 仓库/部署地址 ② 确认这是你拥有或维护的项目（self）③ 你最担心的一个点
- **边界（先说清）**：被动协议层观察——不执行你的工具、不进内网、不改代码；需要额外输入才能测的项如实记作「未测」，绝不记作「通过」；不构成安全结论或合规认证
- **成本**：¥0，不需要任何回报承诺。这套东西靠深度审计与月度复扫维持运转

**English**: Maintaining an AI-agent / MCP project? Request a **free passive snapshot audit** (48h turnaround): email `535710934@qq.com` with the subject `[Audit Request] <project name>`, including ① repo/deployment URL, ② confirmation that you own or maintain it (`self`), ③ the one thing that worries you most. You get a sanitized HTML report of protocol-layer observations (leaks, tool-permission surface, error handling, sessions, CORS) mapped to OWASP LLM Top 10 — sample: [`reports/sample-report-snapshot.html`](reports/sample-report-snapshot.html). Passive only: no tool execution, no internal access, no code changes; untestable items are marked **untested**, never "passed". Not a security verdict, not a compliance certification.

---

## 快速开始

```bash
# 1. 起靶场（前台常驻，Ctrl+C 全停）
python tools/start_targets.py

# 2. 另开一个终端，跑全量回归
python tools/run_all.py
```

零第三方依赖，Python 3.8+。预期输出：

```
[主任务 18 项]  ...全部 OK
[回归核对 7 项] ...全部 OK
汇总  检查项判定: FAIL=25 HIT=2 INFO=12 PASS=34 SKIPPED=4 WARN=7
      任务: ERR 0 | BROKEN 0 | FAIL 0 | 合计 25 | 约 26s
```

`ERR 0 / BROKEN 0 / FAIL 0` 是**任务**维度（进程崩了 / 判定器没看见东西 / 工具报错）；
`FAIL=25` 是**检查项**维度（靶场确实有缺陷）。这两个不要混 ——
详见下方「三种状态枚举」。

只做存活检查、不起服务：`python tools/start_targets.py --check`

---

## 靶场：8 组漏洞版 / 安全版对照

| 端口 | 类型 | 漏洞版植入的缺陷 | 安全版 |
|---|---|---|---|
| 9001 / 9002 | MCP Server | 无认证暴露工具清单、`/health` 泄漏堆栈与连接串、工具描述内嵌注入载荷、任意 SQL / 命令执行、退款无鉴权 | 全部修复 |
| 9003 / 9004 | 多租户 | 列表未按租户过滤、跨租户 BOLA、越权功能调用 | 按租户隔离 |
| 9005 / 9006 | 服务主体 | 平台级共享密钥 scope 过宽、可跨实例调用 | 最小 scope |
| 9007 / 9008 | 外联与部署泄漏 | 调试端点、`/memory/`、`/prospects.csv`、`.env` 可读 | 已收敛 |
| 9009–9012 | 组合链 | git-mcp + shell-mcp 跨服务器组合 = 任意代码执行 | 路径白名单 |
| 9013 / 9014 | 多轮升级 | 第 3 轮被打穿且上下文失忆 | 始终拒绝 |
| 9015 / 9016 | 供应链 | 任意 URL 拉取 → 写入仓库 | 域名白名单 + 阻断 metadata 端点 |

**每一组都有阴性对照。** 只看漏洞版命中率是没有意义的 ——
一个把所有东西都判成 FAIL 的检查器也能拿 100%。
必须同时看安全版是不是 0 误报。

---

## 真实 MCP 协议靶场与 toolkit/（2026-10 新增）

上面 8 组走的是**靶场简化协议**（`GET /mcp` 直返工具清单），用于回归自测。
`toolkit/` 与 `targets/mcp_proto_*` 说的是**真 MCP**（JSON-RPC 2.0，Streamable HTTP：
`initialize → notifications/initialized → tools/list`），面向「有授权的真实目标」设计：

| 文件 | 作用 |
|---|---|
| `targets/mcp_proto_vuln/` :9017 | 真协议漏洞靶场：9 类缺陷（工具描述间接注入、生产库直连 SQL、shell 执行、错误泄栈、可预测 session id、无认证、写工具零确认…） |
| `targets/mcp_proto_safe/` :9018 | 同协议阴性对照（Bearer 认证 + 随机 session + 最小错误面） |
| `toolkit/mcp_client.py` | 真 MCP 客户端：零依赖标准库，握手 / session 捕获回传 / 工具枚举调用 / JSON 与 SSE 双模式 |
| `toolkit/audit_remote.py` | 被动扫描器：六域 16 项，**只看协议层不调用目标工具**，每项带 OWASP LLM 映射 + 授权 gate + `--selfcheck` 双向自检 |
| `toolkit/run_all.py` | 批量编排 + 脱敏 HTML 报告 + 预期对照 |

**三条硬约束（写进代码）**：① 每个目标必须带授权声明（self / ctf / bounty / written），缺失即退出码 2 拒绝执行；② SKIPPED 永不折算 PASS——扫不到 ≠ 没问题；③ 脱敏只作用于公开产物，JSON 原件保留完整供授权方自查。

```bash
python targets/mcp_proto_vuln/server.py &   # :9017
python targets/mcp_proto_safe/server.py &   # :9018
python toolkit/audit_remote.py --selfcheck  # 双向自检：9/9
python toolkit/run_all.py --targets toolkit/targets.local.json
# 预期：漏洞版 6 FAIL；安全版 14 PASS + 1 SKIPPED，零误报
```

`toolkit/promptfoo/` 是开源扫描器 promptfoo（0.124.1）的接入验证配置，
含对两个靶场的真机跑通记录与踩坑笔记（`toolkit/promptfoo/README.md`）。

---

## 三种状态枚举（不可互换）

这是本仓库最重要的约定，也是最容易搞混的地方：

| 场景 | 枚举 | 说明 |
|---|---|---|
| 部署 / MCP 配置检查 | `FAIL` / `PASS` / `WARN` / `SKIPPED` / `INFO` | — |
| 人工探测载荷 | `REFUSED` / `PARTIAL` / `BREACH` / `SKIPPED` | **没有 PASS** —— 载荷没成功不等于系统安全 |
| 越权差分 | `FAIL` / `PASS` / `WARN` / `SKIPPED` | — |

两条硬性纪律：

- **`ERR ≠ 404，PASS ≠ SKIPPED`**。进程崩了、端点不可达 → 记 ERR 或 SKIPPED，
  绝不计入 PASS。一份全是绿的报告，通常说明判定器根本没看见被测对象。
- **运行时探针必须区分「策略拒绝」与「网络异常」**。显式 403 → PASS（数据通道不存在）；
  超时 / 连接失败 / 5xx → SKIPPED（**不是被拒绝，是没测成**）。
  把一次网络抖动当安全证明，是这个领域最常见也最危险的自欺。

---

## ⚠ 我们证明不了什么（请务必读完）

**靶场是我自己造的，缺陷分布必然对我的方法论友好。**

靶场只能证明**工具能工作**，不能证明**方法论能覆盖真实分布**。
这是两件事，而且第二件才是真正重要的那件。

做真实分布对齐用的是 11 个公开 CVE / 厂商披露事件。在那里：

| 事件 | CVSS | 能直接命中的检查项 |
|---|---|---|
| Flowise CVE-2025-59434 | 9.6 | 1 / 16 |
| ServiceNow CVE-2025-12420 | 9.3 | 1 / 16 |
| EchoLeak CVE-2025-32711 | 9.3 | 0 / 16 |

**覆盖面广 ≠ 命中率高。** 高严重度事件恰恰集中在方法论结构性地看不见的地方。

11 个事件的完整事实清单（CVE 编号、攻击链、来源、为什么通用扫描器抓不到）
见 [`docs/public-incidents.md`](docs/public-incidents.md)。

### 三个结构性缺口

| # | 缺口 | 为什么扫不出来 |
|---|---|---|
| G1 | 外联白名单的生命周期 | EchoLeak 走的是 CSP 白名单里的**合法**域名；ForcedLeak 用的是一个被 5 美元买回的**过期**域名。每一项配置都是对的 |
| G2 | 非人主体的授权粒度 | 凭据合法、scope 合法、endpoint 合法、请求合法 —— BOLA/BFLA 全部放行，报告一片绿 |
| G3 | 跨组件组合爆炸半径 | 单个 server 审不出「在这里写 + 在那里执行 = shell」 |

### 已量化但无解的一个盲区

提示注入检测：字面 payload 检出率 100%，**语义改写后 0%**。

我写过一个语义角色匹配器，在训练集上做到 75%；
然后在**训练完成后才写**的留出集上测一次 —— **0%**。
那 75% 全是过拟合。这个数字被写进了工具输出，没有藏起来。

（教训：**不能在同一份自造语料上既调参又报告效果。** 必须有留出集，且以留出集为准。）

### 完全未覆盖

多模态通道、向量库投毒、长上下文衰减、写事务回滚、训练数据泄漏重放、
真实 LLM 上的越狱成功率（需要 API key 实测，本仓库不含）。

多模态这一条不是我一个人说的 —— **promptfoo 与 garak 两家独立工具都有专门 probe**，
详见 [`docs/public-incidents.md`](docs/public-incidents.md) 之外的说明：
两份攻击面清单的交叉结果记在方法论里（不开源），已确认的新增盲区有
ANSI 转义（**已补**，见 `check_control_chars.py`）、包幻觉、训练数据泄漏重放。

### 关于「和 garak / promptfoo 的关系」

两份清单我都读过（garak 的 probe 清单从源码目录直接读，**不需要安装** ——
`pip install garak` 在本机跑了 4 小时 58 分钟后因下载中断失败，但目的不依赖安装）。

结论是：**它们主要在 LLM 侧（越狱、毒性、幻觉、训练数据泄漏），
本仓库主要在部署 / 配置 / 授权侧。重叠面积很小。**

这解释了「扫描器已经很多」和「高严重度事件仍然抓不到」为什么能同时成立 ——
不是工具不行，是**层面不同**。

---

## 公开证据链（时间戳可核验）

这条线做的事，都留了带时间戳、可回溯的公开记录（commit / 署名文章 / 第三方审计闭环 / 自助工具包）。不堆内容，只留能核的：

| 时间 | 事实 | 可核验来源 |
|---|---|---|
| 2026-10-13 | 自助 $19 数字产品上线（被动 MCP / Agent 自查工具包，OWASP Cheat Sheet + ASI 双映射） | `creem.io/payment/prod_5OGGTcdFsQ7kJmmZjD6VEd` |
| 2026-10-13 | 真实 server 上修掉 `Accept` 头 406（靶场全绿 ≠ 没 bug，真 server 一碰即挂） | 本仓库 commit `3030b25` |
| 2026-10-13 | 一篇英文痛点长文：修 406 的真实经过 + 为什么「绿 ≠ 测到」 | `dev.to/535710934ops/my-scanner-passed-every-local-test-then-406d-on-a-real-mcp-server-that-gap-is-the-point-5971` |

完整逐条证据链见 [`docs/EVIDENCE-LOG.md`](docs/EVIDENCE-LOG.md)。

---

## 目录

```
targets/          10 组对照靶场（9001–9016 靶场简化协议 + 9017/9018 真 MCP 协议）
tools/
  start_targets.py      一键起全部 16 个靶场
  run_all.py            一键跑 25 项回归，输出 runs/summary.json
  audit_mcp.py          MCP Server 配置面审计（A1–F2）
  audit_tenant.py       跨身份越权差分
  audit_egress.py       外联通道 + 跨服务器组合链
  check_service_principal.py  非人主体 / 平台级凭证
  scan_deploy_leak.py   部署层泄漏
  probe_combo.py        组合链运行时探针（真的走一遍链）
  probe_multiturn.py    多轮渐进升级（几轮被打穿）
  check_semantic_rewrite.py  语义改写盲区量化（含留出集）
  check_control_chars.py     控制字符 / ANSI 转义（含上下文判定）
  check_coverage*.py    漏报核对
toolkit/           真 MCP 对外扫描工具链（客户端 / 被动扫描器 / 编排器 / promptfoo 验证）
runs/              运行产物（gitignored）
```

---

## 引用

本仓库中的 CVE 编号、CVSS 分值与日期均取自公开来源，**未经独立验证**，
引用前请复核厂商公告。案例映射基于公开报道推断，**未在隔离环境复现** ——
复现涉及第三方系统，明确不做。

---

## License

MIT · 见 [LICENSE](LICENSE)

靶场中的缺陷是**故意植入**的，仅用于在本地隔离环境验证审计流程。
不要把这些 server 暴露到任何非本机网络。
