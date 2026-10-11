#!/usr/bin/env python3
"""
MCP Server 被动安全扫描器
==========================

**定位**：只读协议元数据，不执行目标任何工具、不发任何写请求、不产生副作用。
所谓「被动」在这里有严格含义：**只发 initialize / notifications/initialized /
tools/list / ping，外加一次「调用一个不存在的工具名」探错误处理**。最后这项
唯一可能被误解，但它调用的是 `__nonexistent_probe__`，任何实现都只会返回
JSON-RPC error，不可能产生业务副作用。

**它与 tools/audit_mcp.py 的区别**（不是替代关系）：
  audit_mcp.py   假设 GET /mcp 直接返回清单 → 只能扫自家靶场的简化协议
  本文件         真 MCP JSON-RPC → 可以扫任何说真话的 MCP server

八个检查域（对齐 OWASP LLM Top 10 2025 + MCP 特有风险）：

  A 认证与授权     无凭据即可握手/枚举？session 是否强制？
  B 工具面         工具总数、写占比、危险工具（执行/SQL/外发/资金）
  C 间接提示注入   工具描述里是否藏指令（tool poisoning 的主战场）
  D 信息泄漏       Server/X-Powered-By、serverInfo、instructions、错误泄栈
  E 传输与 CORS     http 明文？CORS 是否 * 全开？
  F 会话管理       session id 可预测性（两次握手取样）
  G 输入面         inputSchema 是否有类型约束（无约束 = 任意参数）
  H 错误处理       探测未知工具，看是否回栈 / 连接串 / 工具清单

**最关键的一条纪律**：任何"连不上 / 没返回"都必须记 **SKIPPED**，绝不能记 PASS。
一个扫不到的目标和一個没有缺陷的目标，在 JSON 里长得一模一样 ——
把它们混为一谈，就是"扫了 100 个 server 得出 0 漏洞"这类结论的来源。

用法：
    python toolkit/audit_remote.py --url http://127.0.0.1:9017/mcp
    python toolkit/audit_remote.py --targets toolkit/targets.local.json
"""

import argparse
import io
import json
import os
import re
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from mcp_client import MCPClient, MCPError   # noqa: E402

# ============================================================ 知识库

OWASP = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM06": "Excessive Agency",
    "LLM08": "Vector and Embedding Weaknesses",
    "LLM10": "Unbounded Consumption",
}

# 高危工具：按"能力"而非"名字"归类。名字会变，能力不会。
DANGEROUS_CAPABILITY = {
    "exec_shell":     (r"\b(run_?shell|exec_?shell|execute_?(cmd|command)|"
                       r"bash|system_command|run_?command|eval_?code)\b",
                       "任意命令执行"),
    "exec_query":     (r"\b(execute_?(query|sql)|run_?sql|raw_?sql|"
                       r"query_?db|sql_?query)\b", "任意 SQL 执行"),
    "send_external":  (r"\b(send_?(email|mail|message|webhook|sms)|"
                       r"post_?to_?(slack|webhook))\b", "对外发信/外发数据"),
    "move_money":     (r"\b(transfer_?funds?|wire_?transfer|payout|"
                       r"refund|issue_?payment)\b", "资金操作"),
    "deploy":         (r"\b(deploy|release|publish)_?(service|app|prod|"
                       r"version)?\b", "生产部署"),
    "file_read":      (r"\b(read_?file|get_?file|cat_?file|download_?file|"
                       r"read_?path)\b", "任意文件读取"),
    "manage_perm":    (r"\b(add_?(user|member)|grant_?role|create_?api_?key|"
                       r"set_?policy|update_?permission)\b", "权限变更"),
}

WRITE_KW = ("create", "update", "delete", "send", "execute", "run", "write",
            "refund", "transfer", "deploy", "add", "set", "post", "put")

# 间接注入指令特征。分两类：
#   A 类 = 明确祈使（"忽略之前的指令"）—— 几乎可直接判定
#   B 类 = 隐蔽动作（"读 ~/.ssh/id_rsa"）—— 单看可能合理，结合 A 类加权
INJECT_DIRECTIVE = re.compile(
    r"(ignore\s+(all\s+)?(the\s+)?previous|"
    r"disregard\s+(all\s+)?(the\s+)?(above|prior)|"
    r"forget\s+(everything|all)\s+(above|before)|"
    r"<\s*(IMPORTANT|SYSTEM|CRITICAL)\s*>|"
    r"\[?\s*(INST|SYSTEM)\s*\]?\s*:|"
    r"do\s+not\s+(tell|mention|inform|reveal)|"
    r"without\s+(telling|informing|notifying)|"
    r"never\s+reveal|hide\s+this|secretly|"
    r"do\s+not\s+log|skip\s+(the\s+)?(logging|audit))", re.I)

INJECT_ACTION = re.compile(
    r"(~/\.ssh|id_rsa|\.aws/credentials|\.env\b|/etc/passwd|"
    r"\.git/config|\.npmrc|\.netrc|"
    r"api[_-]?key|secret[_-]?key|access[_-]?token|password|"
    r"exfiltrat|curl\s+http|base64\s+-d)", re.I)

SECRET_IN_TEXT = re.compile(
    r"(postgres(?:ql)?://[^:\s]+:[^@\s]+@|mysql://[^:\s]+:[^@\s]+@|"
    r"mongodb(?:\+srv)?://[^:\s]+:[^@\s]+@|"
    r"AKIA[0-9A-Z]{16}|"
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----|"
    r"gh[pousr]_[A-Za-z0-9]{20,}|"
    r"sk-[A-Za-z0-9]{20,})")

TRACE_PAT = re.compile(r"(Traceback \(most recent call last\)|"
                       r'File "[^"]+", line \d+|'
                       r'^\s+at [\w.$]+ \(|'
                       r"\.py\", line \d+)")

VERSION_LEAK_HDRS = ("server", "x-powered-by", "x-aspnet-version",
                      "x-runtime-version", "x-generator")


def _c(cid, title, domain, status, detail, severity="info",
       owasp=None, evidence=None, remediation=None):
    """构造一条检查项。status: PASS / FAIL / WARN / SKIPPED"""
    d = {"id": cid, "title": title, "domain": domain,
         "status": status, "severity": severity, "detail": detail}
    if owasp:
        d["owasp"] = owasp
    if evidence:
        d["evidence"] = evidence
    if remediation:
        d["remediation"] = remediation
    return d


# ============================================================ 主扫描

def scan(url, token=None, timeout=10, verbose=False, allow_call=False):
    """扫一个目标。返回 dict。**任何失败路径都记 SKIPPED，不记 PASS。**"""
    t0 = time.time()
    res = {
        "url": url, "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
        "reachable": False, "checks": [], "meta": {}, "errors": [],
    }
    checks = res["checks"]

    # ---------------- 连接 ----------------
    c = MCPClient(url, token=token, timeout=timeout, verbose=verbose)
    try:
        c.handshake()
        res["reachable"] = True
    except MCPError as e:
        res["errors"].append("握手失败: %s" % e)
        checks.append(_c("A0", "连通性与协议握手", "认证与授权", "SKIPPED",
                         "无法完成 MCP 握手 —— **本目标未被评估**，不等于无缺陷",
                         severity="unknown"))
        res["secs"] = round(time.time() - t0, 1)
        return res

    res["meta"] = {
        "protocol_version": c.protocol_version,
        "server_info": c.server_info,
        "capabilities": c.capabilities,
        "session_id": c.session_id,
        "instructions": c.instructions,
    }

    # ---------------- 工具清单 ----------------
    try:
        tools = c.list_tools()
    except MCPError as e:
        res["errors"].append("tools/list 失败: %s" % e)
        checks.append(_c("B0", "工具清单枚举", "工具面", "SKIPPED",
                         "无法枚举工具：%s —— 工具面各项均未评估" % e,
                         severity="unknown"))
        tools = []
        res["secs"] = round(time.time() - t0, 1)
        return res

    names = [t.get("name", "") for t in tools]
    res["meta"]["tool_names"] = names
    res["meta"]["tool_count"] = len(tools)

    # ---------------- A 认证与授权 ----------------
    # A1：本次是带 token 还是没带 token
    if token:
        checks.append(_c("A1", "认证凭据", "认证与授权", "PASS",
                         "扫描时提供了凭据；**本次不能评估「无凭据是否可访问」**，"
                         "该结论需要另跑一次不带 token 的对照",
                         severity="info"))
    else:
        checks.append(_c("A1", "认证凭据", "认证与授权", "PASS",
                         "未提供凭据即可完成握手", severity="info",
                         owasp="LLM06"))

    # A2：session 是否强制（不强制 = 任何客户端可另起会话）
    if c.session_id:
        checks.append(_c("A2", "会话标识下发", "认证与授权", "PASS",
                         "服务端下发了 Mcp-Session-Id", severity="info"))
    else:
        checks.append(_c("A2", "会话标识下发", "认证与授权", "WARN",
                         "握手后未下发 Mcp-Session-Id —— 服务端可能无会话概念，"
                         "或要求通过别处（如 cookie / URL）传递",
                         severity="medium", owasp="LLM06",
                         remediation="下发不可预测的 session id 并在后续请求强制校验"))

    # ---------------- B 工具面 ----------------
    if not tools:
        checks.append(_c("B1", "工具清单", "工具面", "WARN",
                         "tools/list 返回空清单（真的是 0 工具？还是格式不符？）",
                         severity="low", owasp="LLM06"))
    else:
        checks.append(_c("B1", "工具清单", "工具面", "PASS",
                         "可枚举 %d 个工具" % len(tools), severity="info",
                         owasp="LLM06"))

    # B2：写工具占比（经验阈值 30%）
    writes = [n for n in names
              if any(k in n.lower() for k in WRITE_KW)]
    ratio = len(writes) / float(len(names)) if names else 0.0
    if names and ratio > 0.30:
        checks.append(_c("B2", "写工具占比", "工具面", "FAIL",
                         "写工具 %d/%d = %.0f%%，超过 30%% 经验阈值。"
                         "写工具越多，提示注入的后果越严重（一次注入即可改数据）"
                         % (len(writes), len(names), ratio * 100),
                         severity="high", owasp="LLM06",
                         evidence="写工具: %s" % ", ".join(writes[:12]),
                         remediation="按工具粒度授权；高危写操作要求人工/二次确认；"
                                     "把只读工具与写工具拆到不同 server"))
    else:
        checks.append(_c("B2", "写工具占比", "工具面", "PASS",
                         "写工具 %d/%d = %.0f%%" % (len(writes), len(names),
                                                ratio * 100),
                         severity="info", owasp="LLM06"))

    # B3：危险能力工具（按能力归类，不看名字）
    found_cap = []
    for n in names:
        nl = n.lower()
        for cap, (pat, label) in DANGEROUS_CAPABILITY.items():
            if re.search(pat, nl):
                found_cap.append((n, cap, label))
    if found_cap:
        uniq = {}
        for n, cap, label in found_cap:
            uniq.setdefault(cap, (n, label))
        ev = "; ".join("%s → %s" % (n, lab) for cap, (n, lab) in uniq.items())
        checks.append(_c("B3", "高危能力工具", "工具面", "FAIL",
                         "发现具备高危能力的工具：%s。"
                         "注意：工具**存在**不等于可被外部滥用，但它是攻击面，"
                         "其参数校验与授权强度必须单独验证" % ev,
                         severity="high", owasp="LLM06", evidence=ev,
                         remediation="对执行/外发/资金类工具加独立授权、"
                                     "参数白名单与调用审计；尽量不暴露给模型"))
    else:
        checks.append(_c("B3", "高危能力工具", "工具面", "PASS",
                         "未发现执行/SQL/外发/资金/部署类工具",
                         severity="info", owasp="LLM06"))

    # ---------------- C 间接提示注入 ----------------
    # ⚠ 必须用 finditer().group(0) 而不是 findall()。
    #   正则里每个分支都带捕获组（为了可读性），findall() 返回的是
    #   **元组列表**而非字符串列表 → ",".join() 直接抛
    #   "expected str instance, tuple found"。
    #   这是 re 的经典陷阱：findall 的返回形状取决于有没有捕获组。
    def _hits(rx, text):
        return [m.group(0) for m in rx.finditer(text or "")]

    inj_hits = []
    for t in tools:
        desc = t.get("description") or ""
        if not desc:
            continue
        dirs = _hits(INJECT_DIRECTIVE, desc)
        acts = _hits(INJECT_ACTION, desc)
        if dirs or acts:
            inj_hits.append({"tool": t.get("name"),
                             "directive": dirs[:4], "action": acts[:4],
                             "excerpt": desc[:180]})
    if inj_hits:
        sev = "critical" if any(h["directive"] for h in inj_hits) else "high"
        checks.append(_c("C1", "工具描述注入载荷", "间接提示注入", "FAIL",
                         "%d 个工具的描述中含指令式文本。这是 MCP 投毒（tool "
                         "poisoning）的主战场：LLM 把 description 当系统指令读，"
                         "攻击者无需攻破模型，只需改一行描述"
                         % len(inj_hits),
                         severity=sev, owasp="LLM01",
                         evidence="; ".join(
                             "%s[%s]" % (h["tool"],
                                         ",".join(h["directive"] or
                                                  h["action"]))
                             for h in inj_hits[:6]),
                         remediation="对工具描述做评审与签名；CI 中加入注入特征"
                                     "扫描；描述里禁止出现祈使句与文件路径"))
    else:
        checks.append(_c("C1", "工具描述注入载荷", "间接提示注入", "PASS",
                         "%d 个工具描述未见指令式文本" % len(tools),
                         severity="info", owasp="LLM01"))

    # C2：描述长度异常（藏载荷的常见形态）
    longs = [(t.get("name"), len(t.get("description") or ""))
             for t in tools if len(t.get("description") or "") > 800]
    if longs:
        checks.append(_c("C2", "工具描述长度", "间接提示注入", "WARN",
                         "%d 个工具描述超 800 字符 —— 异常长的描述是藏指令的"
                         "常见形态（本项只提示长度，不做内容判定）"
                         % len(longs), severity="low", owasp="LLM01",
                         evidence="; ".join("%s(%d)" % x for x in longs[:6])))
    else:
        checks.append(_c("C2", "工具描述长度", "间接提示注入", "PASS",
                         "工具描述长度均在合理范围", severity="info",
                         owasp="LLM01"))

    # ---------------- D 信息泄漏 ----------------
    hdrs = c.raw_headers or {}
    # ⚠ 第一版只要看到 Server 头就判 WARN，结果安全版返回 `Server: orders-mcp`
    #   也被判 WARN —— **规则过宽的误报**。
    #   判据应是"是否泄露**可定位实现的版本信息**"，而不是"有没有这个头"。
    #   一个不含版本的服务名头（orders-mcp）不是指纹；python/3.11.6 是。
    VERSIONISH = re.compile(
        r"(\d+\.\d+)|(python|ruby|node|php|java|dotnet|asp\.net|nginx|"
        r"apache|iis|express|django|flask|spring|mcp-sdk|langchain|"
        r"llamaindex|autogen|openai-sdk)", re.I)

    ver_hdrs, benign_hdrs = {}, {}
    for k, v in hdrs.items():
        if k.lower() not in VERSION_LEAK_HDRS:
            continue
        (ver_hdrs if VERSIONISH.search(str(v)) else benign_hdrs)[k] = v

    if ver_hdrs:
        checks.append(_c("D1", "实现指纹头", "信息泄漏", "WARN",
                         "响应头泄露实现与版本：%s。版本号让攻击者直接查"
                         "已知漏洞（CVE 匹配成本趋近于零）"
                         % ", ".join("%s: %s" % kv for kv in ver_hdrs.items()),
                         severity="medium", owasp="LLM02",
                         evidence=str(ver_hdrs),
                         remediation="移除 Server / X-Powered-By；"
                                     "对外统一网关，隐藏后端指纹"))
    else:
        extra = ("（另有非版本型头 %s，不构成指纹）"
                 % ", ".join(benign_hdrs) if benign_hdrs else "")
        checks.append(_c("D1", "实现指纹头", "信息泄漏", "PASS",
                         "未见泄露版本的指纹响应头%s" % extra,
                         severity="info", owasp="LLM02"))

    # D2：serverInfo 泄露
    # spec 必填 name+version —— 它们本身不是泄漏（D2 曾把 spec 必填的
    # version 一律判 WARN，对阴性对照误报，已修正判据）
    si = c.server_info or {}
    extra_si = {k: v for k, v in si.items() if k not in ("name", "version")}
    ver = str(si.get("version") or "")
    # 版本串带内部元数据才算泄漏：build 号 / rc 标记 / 内部代号 / 疑似 commit hash
    leaky = re.search(r"(\+|build|rc\d|internal|dev|[0-9a-f]{10,})", ver, re.I)
    if extra_si or leaky:
        checks.append(_c("D2", "serverInfo 泄露", "信息泄漏", "WARN",
                         "serverInfo 暴露内部元数据：%s"
                         % json.dumps(si, ensure_ascii=False)[:160],
                         severity="medium", owasp="LLM02",
                         evidence=json.dumps(si, ensure_ascii=False)[:200],
                         remediation="version 用通用串（如 1.0.0）；"
                                     "build 号 / 内部代号 / 提交哈希不外发"))
    else:
        checks.append(_c("D2", "serverInfo 泄露", "信息泄漏", "PASS",
                         "serverInfo 仅含 spec 必填字段，无内部元数据",
                         severity="info", owasp="LLM02"))

    # D3：instructions 字段（常被用来塞内部提示/联系方式）
    if c.instructions:
        checks.append(_c("D3", "instructions 字段", "信息泄漏", "WARN",
                         "服务端下发 instructions（%d 字符）。该字段是规范"
                         "定义的合法位置，也因此成为藏提示的合理外衣；"
                         "其中可能含内部系统提示或不应外泄的联系方式"
                         % len(c.instructions),
                         severity="low", owasp="LLM07",
                         evidence=str(c.instructions)[:180],
                         remediation="instructions 不应包含密钥、内部地址，"
                                     "或「禁止告知用户」类指令"))
    else:
        checks.append(_c("D3", "instructions 字段", "信息泄漏", "PASS",
                         "未下发 instructions", severity="info", owasp="LLM07"))

    # ---------------- E 传输与 CORS ----------------
    if url.lower().startswith("https://"):
        checks.append(_c("E1", "传输加密", "传输与 CORS", "PASS",
                         "HTTPS", severity="info", owasp="LLM02"))
    elif url.lower().startswith("http://"):
        is_local = re.search(r"://(127\.0\.0\.1|localhost|\[::1\]|0\.0\.0\.0)",
                             url)
        if is_local:
            checks.append(_c("E1", "传输加密", "传输与 CORS", "SKIPPED",
                             "http 明文，但目标是本地回环 —— 本机靶场不适用",
                             severity="unknown"))
        else:
            checks.append(_c("E1", "传输加密", "传输与 CORS", "FAIL",
                             "非回环地址使用 http 明文，凭据与工具返回值"
                             "均可被中间人读取", severity="high",
                             owasp="LLM02",
                             remediation="强制 https；token 只走 header 不走 URL"))
    else:
        checks.append(_c("E1", "传输加密", "传输与 CORS", "SKIPPED",
                         "URL scheme 异常，无法判定", severity="unknown"))

    acao = hdrs.get("access-control-allow-origin")
    if acao == "*":
        checks.append(_c("E2", "CORS 策略", "传输与 CORS", "FAIL",
                         "Access-Control-Allow-Origin: * —— 任意站点的"
                         "浏览器脚本可直连此 MCP 端点。结合本机已登录态"
                         "（cookie / 本地 token）可形成侧信道",
                         severity="high", owasp="LLM02",
                         remediation="收紧到明确的信任域；带凭据的接口"
                                     "禁止 ACAO:*"))
    else:
        checks.append(_c("E2", "CORS 策略", "传输与 CORS", "PASS",
                         "CORS 未全开（%s）" % (acao or "未返回该头"),
                         severity="info", owasp="LLM02"))

    # ---------------- F 会话可预测性 ----------------
    # 取样两次：可预测的 id 会在结构上重复（自增/时间戳/短随机）
    try:
        c2 = MCPClient(url, token=token, timeout=timeout)
        c2.handshake()
        sid2 = c2.session_id
    except MCPError as e:
        sid2 = None
        res["errors"].append("二次握手失败: %s" % e)

    s1 = c.session_id
    if not s1 or not sid2:
        checks.append(_c("F1", "会话随机性", "会话管理", "SKIPPED",
                         "两次握手未都拿到 session，无法评估随机性",
                         severity="unknown"))
    else:
        def _shape(s):
            # 把数字段折叠成 #，保留结构 —— 结构相同即高度可疑
            return re.sub(r"\d", "#", s)
        same_shape = _shape(s1) == _shape(sid2)
        entropy_ok = len(sid2) >= 24
        if same_shape and not entropy_ok:
            checks.append(_c("F1", "会话随机性", "会话管理", "FAIL",
                             "两次握手 session 结构完全相同且长度偏短"
                             "（%d 字符）：形态 %s。说明 session 由自增/时间戳"
                             "等可预测成分构成，会话可被枚举或推断"
                             % (len(sid2), _shape(sid2)[:40]),
                             severity="high", owasp="LLM06",
                             evidence="s1=%s  s2=%s" % (s1, sid2),
                             remediation="使用密码学安全随机（≥128 bit）生成"
                                         "session；不把 session 写进日志"))
        elif not entropy_ok:
            checks.append(_c("F1", "会话随机性", "会话管理", "WARN",
                             "session 长度仅 %d 字符，随机性偏弱" % len(sid2),
                             severity="medium", owasp="LLM06"))
        else:
            checks.append(_c("F1", "会话随机性", "会话管理", "PASS",
                             "两次握手 session 结构不同且长度充足（%d 字符）"
                             % len(sid2), severity="info", owasp="LLM06"))

    # ---------------- G 输入面 ----------------
    # ⚠ 第二版修正：第一版判据是「properties 为空即缺陷」，结果把
    #   `list_orders` 这种**合法的无参工具**误报成 WARN。
    #   无参工具的 properties 本就该是 {} —— 它靠 additionalProperties:false
    #   表达"不接受任何参数"，而不是靠 properties 非空。
    #   ⇒ 判据必须是"**是否声明了参数约束**"，不是"参数是否非空"。
    #     这与 D1 是同一类错误：规则过宽 → 误报 → 阴性对照被污染。
    unconstrained, untyped = [], []
    for t in tools:
        sch = t.get("inputSchema") or {}
        props = sch.get("properties")
        if sch.get("additionalProperties") is False:
            continue                      # 显式拒绝额外参数 → 有约束
        if props:
            untyped.append(t.get("name"))   # 有参数但无类型信息
        else:
            unconstrained.append(t.get("name"))

    loose = [n for n in unconstrained + untyped if n]
    if tools and loose:
        detail = []
        if unconstrained:
            detail.append("%d 个既无参数也无 additionalProperties:false"
                          % len(unconstrained))
        if untyped:
            detail.append("%d 个有参数但缺类型约束" % len(untyped))
        checks.append(_c("G1", "输入 schema 约束", "输入面", "WARN",
                         "%s。无约束的入参等于把底层能力整个暴露给模型，"
                         "且模型给的参数一律不可信"
                         % "；".join(detail),
                         severity="medium", owasp="LLM06",
                         evidence=", ".join(str(x) for x in loose[:10]),
                         remediation="为每个工具声明严格 JSON Schema"
                                     "（含类型/范围/枚举）；无参工具显式写 "
                                     "additionalProperties:false；"
                                     "服务端仍须独立校验，不信任 schema"))
    else:
        checks.append(_c("G1", "输入 schema 约束", "输入面", "PASS",
                         "工具均声明了参数约束"
                         + ("（无参工具以 additionalProperties:false 表达）"
                            if tools else ""),
                         severity="info", owasp="LLM06"))

    # ---------------- H 错误处理 ----------------
    # ⚠⚠ 这一段是第一版最危险的缺陷，且**双向自检直接把它抓出来了**。
    #   原写法：probe 失败 → ed=None → blob="" → 无任何泄漏特征 → 判 PASS。
    #   即"**取不到错误响应**"被当成"**错误响应很干净**"。
    #   这是纪律 3 最恶劣的一种形态：不是把 FAIL 当 PASS，而是把
    #   UNKNOWN 当 PASS —— 它会系统性地虚高安全评分。
    #   正确做法：拿不到响应就没有结论，记 SKIPPED。
    st, _eh, ed = c.probe_error()
    if not ed:
        detail = ("未能取得错误响应（HTTP=%s）—— **本项未评估**，"
                  "既不能判定有泄漏，也不能判定无泄漏"
                  % ("无" if st is None else st))
        checks.append(_c("H1", "错误响应信息泄漏", "错误处理", "SKIPPED",
                         detail, severity="unknown", owasp="LLM02",
                         evidence=str((res["errors"] or ["probe 无响应"])[-1])
                        [:180]))
    else:
        blob = json.dumps(ed, ensure_ascii=False) if ed else ""
        leaks = []
        if TRACE_PAT.search(blob):
            leaks.append("调用栈")
        sec = _hits(SECRET_IN_TEXT, blob)
        if sec:
            leaks.append("疑似凭据/连接串")
        # 未知工具错误里回列全部可用工具 = 枚举辅助
        listed = re.search(r"(available|可用|supported)\s*[:：]?\s*[\w, _-]{10,}",
                           blob, re.I)
        if listed:
            leaks.append("可用工具清单")
        if leaks:
            checks.append(_c("H1", "错误响应信息泄漏", "错误处理", "FAIL",
                             "对不存在工具的响应泄露了：%s。错误信息是攻击者"
                             "免费的信息源（栈给版本、连接串给内网、"
                             "工具清单给攻击面）" % "、".join(leaks),
                             severity="high", owasp="LLM02",
                             evidence=blob[:220],
                             remediation="对外错误只回 code + 通用 message；"
                                         "细节写服务端日志并做脱敏"))
        else:
            checks.append(_c("H1", "错误响应信息泄漏", "错误处理", "PASS",
                             "错误响应未泄露栈/凭据/工具清单", severity="info",
                             owasp="LLM02"))

    # ---------------- 汇总 ----------------
    res["summary"] = {}
    for x in checks:
        res["summary"][x["status"]] = \
            res["summary"].get(x["status"], 0) + 1
    res["secs"] = round(time.time() - t0, 1)
    return res


def _selfcheck():
    """阳性 / 阴性双向自检。

    **只测漏洞版是不够的。** 只对着坏靶场跑，任何"总是报 FAIL"的工具都能满分
    —— 它可能只是在猜。这里要求两条同时成立：

      · vuln 版：关键项必须 FAIL（检出能力）
      · safe 版：关键项必须 PASS（不误报能力）

    safe 版若也报出 FAIL，说明要么规则过宽，要么靶场没修干净 —— 两种都得查。
    """
    try:
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
    except Exception:
        pass

    vuln = scan("http://127.0.0.1:9017/mcp")
    safe = scan("http://127.0.0.1:9018/mcp", token="safe-token-9f2c41")

    # 期望（id → vuln 侧状态, safe 侧状态）
    EXPECT = {
        "C1": ("FAIL", "PASS"),    # 工具描述注入载荷
        "B3": ("FAIL", "PASS"),    # 高危能力工具
        "B2": ("FAIL", "PASS"),    # 写工具占比
        "D1": ("WARN", "PASS"),    # 实现指纹头
        "D3": ("WARN", "PASS"),    # instructions
        "E2": ("FAIL", "PASS"),    # CORS 全开
        "F1": ("FAIL", "PASS"),    # session 可预测
        "H1": ("FAIL", "PASS"),    # 错误泄栈
        "G1": ("WARN", "PASS"),    # 输入 schema 约束
    }

    def pick(res, cid):
        for x in res["checks"]:
            if x["id"] == cid:
                return x["status"]
        return "MISSING"

    print("=" * 70)
    print("扫描器双向自检（阳性 vuln :9017 / 阴性 safe :9018）")
    print("=" * 70)
    ok = 0
    bad = []
    for cid, (want_v, want_s) in sorted(EXPECT.items()):
        gv, gs = pick(vuln, cid), pick(safe, cid)
        hit_v = (gv == want_v)
        hit_s = (gs == want_s)
        flag = "✓" if (hit_v and hit_s) else "✗"
        if hit_v and hit_s:
            ok += 1
        else:
            bad.append(cid)
        print("  %s %-4s  vuln=%-8s(期望%-4s)  safe=%-8s(期望%s)"
              % (flag, cid, gv, want_v, gs, want_s))
    print("-" * 70)
    print("  vuln 侧判定: %s" % (json.dumps(vuln.get("summary", {}),
                                          ensure_ascii=False)))
    print("  safe 侧判定: %s" % (json.dumps(safe.get("summary", {}),
                                          ensure_ascii=False)))
    print("-" * 70)
    print("双向自检: %d/%d 通过%s"
          % (ok, len(EXPECT),
             "" if not bad else "   未通过: %s" % ", ".join(bad)))
    if bad:
        print("⚠ 双向条件未同时成立 —— 不要对外声称检出率，先查规则或靶场。")
    return 0 if ok == len(EXPECT) else 1


# ============================================================ 授权 gate

# ⚠ 这是整个工具**最重要的 40 行**。
#
# 一个"输入 URL 就能扫"的 MCP 扫描器，落到错误的人手里就是攻击工具；
# 落到公开仓库里就是法律风险。而"加个 flag 强制勾选 I-UNDERSTAND"这种
# 授权形同虚设 —— 它拦不住任何人，只制造了"我有授权"的错觉。
#
# 所以这里要求的是**可核查的授权依据**：每条授权都要写清来源，
# 且 self / ctf / bounty-program 三类之外不接受"我自己的"这种空口声明。
# 拿不到授权的目标，正确做法是**不扫**，而不是"先扫了再说"。
AUTH_KINDS = {
    "self":       "你自己拥有或控制的 server",
    "ctf":        "公开 CTF / 靶场平台（明确邀请测试）",
    "bounty":     "在有效赏金计划范围内（有 program policy URL）",
    "written":    "书面授权（合同 / 邮件 / 工单，需填 reference）",
}


def check_authorization(entry):
    """校验一条目标的授权声明。返回 (ok: bool, reason: str)。"""
    auth = entry.get("authorization") or {}
    kind = (auth.get("kind") or "").strip()
    if kind not in AUTH_KINDS:
        return False, ("authorization.kind 必须是 %s 之一；"
                       "当前=%r" % (list(AUTH_KINDS), kind))
    if kind in ("bounty", "written") and not (auth.get("reference") or "").strip():
        return False, ("kind=%s 必须提供 reference（赏金计划 URL / "
                       "授权单号），否则无法核查" % kind)
    if not (entry.get("url") or "").strip():
        return False, "缺少 url"
    return True, ""


def load_targets(path):
    """读目标清单。**任何一条缺授权 → 整体拒绝执行**（不是跳过那一条）。"""
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    targets = data.get("targets") if isinstance(data, dict) else data
    if not targets:
        raise ValueError("目标清单为空")

    bad = []
    for i, t in enumerate(targets):
        ok, why = check_authorization(t)
        if not ok:
            bad.append("[%d] %s → %s" % (i, t.get("name", "?"), why))
    if bad:
        raise PermissionError(
            "授权校验未通过，拒绝执行。\n  - " + "\n  - ".join(bad) +
            "\n\n若这些目标确实归你所有，请为每条补上 authorization 字段；"
            "没有授权依据的目标，正确做法是不扫。")
    return targets


# ============================================================ 输出

def print_human(res):
    print("=" * 74)
    print("目标 %s" % res["url"])
    print("  协议 %s | 工具 %s | 耗时 %ss"
          % (res["meta"].get("protocol_version", "-"),
             res["meta"].get("tool_count", "-"), res.get("secs", "-")))
    print("-" * 74)
    for x in res["checks"]:
        mark = {"PASS": "ok  ", "FAIL": "FAIL", "WARN": "warn",
                "SKIPPED": "skip"}[x["status"]]
        print("  [%-4s] %-18s %-12s %s"
              % (mark, x["id"], x["domain"], x["title"]))
        print("         %s" % x["detail"])
        if x.get("evidence"):
            print("         证据: %s" % str(x["evidence"])[:150])
    s = res.get("summary") or {}
    print("-" * 74)
    print("  " + "  ".join("%s=%d" % (k, v) for k, v in sorted(s.items())))
    if res["errors"]:
        print("  错误: " + " | ".join(res["errors"][:3]))
    print("=" * 74)


def main():
    ap = argparse.ArgumentParser(
        description="MCP Server 被动安全扫描器（只读，不执行目标工具）")
    ap.add_argument("--url", help="单个目标 URL（不推荐：请用 --targets 留授权痕迹）")
    ap.add_argument("--token", help="Bearer token（若目标需要）")
    ap.add_argument("--targets", help="目标清单 JSON（批量，需带 authorization）")
    ap.add_argument("--timeout", type=int, default=10)
    ap.add_argument("--json", help="结果写入 JSON 文件")
    ap.add_argument("--verbose", action="store_true")
    a = ap.parse_args()

    results = []
    if a.targets:
        try:
            targets = load_targets(a.targets)
        except (PermissionError, ValueError) as e:
            print("✗ %s" % e, file=sys.stderr)
            return 2
        for t in targets:
            r = scan(t["url"], token=t.get("token") or a.token,
                     timeout=a.timeout, verbose=a.verbose)
            r["name"] = t.get("name")
            r["authorization"] = t.get("authorization")
            print_human(r)
            results.append(r)
    elif a.url:
        results.append(scan(a.url, token=a.token, timeout=a.timeout,
                             verbose=a.verbose))
        print_human(results[-1])
    else:
        ap.print_help()
        return 2

    if a.json:
        os.makedirs(os.path.dirname(os.path.abspath(a.json)), exist_ok=True)
        with open(a.json, "w", encoding="utf-8") as f:
            json.dump(results, f, ensure_ascii=False, indent=2, default=str)
        print("JSON 已写入: %s" % a.json)
    return 0


if __name__ == "__main__":
    if "--selfcheck" in sys.argv:
        sys.exit(_selfcheck())
    sys.exit(main())
