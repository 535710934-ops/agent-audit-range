#!/usr/bin/env python3
"""
MCP Server 安全审计器
=====================

针对 MCP (Model Context Protocol) Server 的静态+运行时安全检查。

设计原则（来自 Day 1 沉淀的纪律）：
  1. 覆盖度是一等公民 —— 每个检查项都报PASS / FAIL / **SKIPPED(不可达)**
  2. ERR ≠ 通过 —— 无法检查的项绝不算「安全」
  3. 只做被动/只读检测 —— 不利用、不破坏、不写入业务数据

六大检查域（对齐 OWASP LLM Top 10 + MCP 特有风险）：
  A. 认证方式     —— 长效API key? OAuth 2.1 + PKCE?  token 有作用域吗
  B. 权限面       —— 读工具 vs 写工具的权限差异
  C. 写操作安全   —— 幂等性、确认步骤、审计日志
  D. 提示注入     —— 工具描述/返回值是否可被注入指令
  E. 速率限制     —— 有无限流 = 可被刷
  F. 信息泄漏     —— 错误信息、启动日志、版本披露

用法：
    python audit_mcp.py --url http://127.0.0.1:9000/mcp
    python audit_mcp.py --url http://127.0.0.1:9000/mcp --repo /path/to/repo
    python audit_mcp.py --url ... --json out.json --html out.html
"""

import argparse
import json
import re
import sys
import time
import urllib.error
import urllib.request

UA = "MCPAudit/1.0 (passive-check)"

# OWASP LLM Top 10 (2025) 编号
OWASP = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM03": "Supply Chain",
    "LLM04": "Data and Model Poisoning",
    "LLM05": "Improper Output Handling",
    "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage",
    "LLM08": "Vector and Embedding Weaknesses",
    "LLM09": "Misinformation",
    "LLM10": "Unbounded Consumption",
}


# ============================================================ 工具函数

def req(url, method="GET", timeout=8, headers=None):
    """返回 (status, text, err) —— status=None 表示网络受阻。"""
    h = {"User-Agent": UA}
    if headers:
        h.update(headers)
    r = urllib.request.Request(url, method=method, headers=h)
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            return resp.status, resp.read(16384).decode("utf-8", "replace"), None
    except urllib.error.HTTPError as e:
        try:
            body = e.read(2048).decode("utf-8", "replace")
        except Exception:
            body = ""
        return e.code, body, None
    except Exception as e:
        return None, "", "%s: %s" % (type(e).__name__, str(e)[:120])


def probe(url, method="GET", timeout=8):
    """先做healthcheck，避免把网络失败误报成「无问题」。"""
    status, text, err = req(url, method, timeout)
    reachable = status is not None
    return status, text, err, reachable


# ============================================================ 检查域 A：认证

def check_auth(url):
    """探测认证机制。仅做无凭据的被动探测，不尝试任何凭据。"""
    checks = []

    # A1: 无认证访问 —— 不带任何凭据能否拿到工具列表
    status, text, err, ok = probe(url)
    if not ok:
        checks.append({
            "id": "A1", "domain": "认证方式",
            "owasp": None, "severity": "INFO",
            "title": "无认证探测",
            "status": "SKIPPED",
            "detail": "端点不可达，无法检查：%s" % err,
        })
        return checks, []

    unauth_ok = (status == 200)
    if unauth_ok:
        a1_status, a1_sev = "FAIL", "HIGH"
        a1_detail = ("HTTP 200 —— 无需任何认证即可获取完整工具清单"
                     "（严重：任何人都能枚举并调用你的全部工具）")
    elif status in (401, 403):
        a1_status, a1_sev = "PASS", "PASS"
        a1_detail = "HTTP %d —— 无凭据请求被正确拒绝，认证生效" % status
    elif status == 404:
        a1_status, a1_sev = "SKIPPED", "MEDIUM"
        a1_detail = ("HTTP 404 —— 主端点不存在，无法验证认证机制。"
                     "**此项未覆盖**，不可达≠安全")
    else:
        a1_status, a1_sev = "WARN", "MEDIUM"
        a1_detail = "HTTP %d —— 预期 401/403，实际返回其他状态，认证机制需人工确认" % status

    checks.append({
        "id": "A1", "domain": "认证方式",
        "owasp": "LLM06", "severity": a1_sev,
        "title": "无凭据访问工具列表",
        "status": a1_status,
        "detail": a1_detail,
    })

    # A2: OAuth 2.1 + PKCE 支持检测
    #远程 MCP server 按规范必须支持 OAuth 2.1 with PKCE
    oauth_hints = []
    low = (text or "").lower()
    if "authorization" in low:
        oauth_hints.append("响应含 Authorization 提示")
    if "oauth" in low or "bearer" in low:
        oauth_hints.append("响应提及 OAuth/Bearer")
    if "pkce" in low or "code_challenge" in low:
        oauth_hints.append("响应提及 PKCE")
    if "www-authenticate" in low:
        oauth_hints.append("含 WWW-Authenticate 头语义")

    checks.append({
        "id": "A2", "domain": "认证方式",
        "owasp": "LLM06", "severity": "MEDIUM",
        "title": "OAuth 2.1 / PKCE 迹象",
        "status": "INFO",
        "detail": "；".join(oauth_hints) if oauth_hints
                  else "响应中无 OAuth 迹象（不等于不支持，需查源码/文档确认）",
    })

    # A3: 长效API key 风险 —— 行业 88% 的 server 靠长效 key
    findings = []
    if a1_status == "FAIL":
        findings.append(
            "【行业背景】对 5,200 个开源 MCP server 的分析显示："
            "88% 需要凭据，但仅约 8.5% 使用 OAuth。"
            "其余依赖长效 API key —— 企业安全团队通常不会批准这种设计。"
        )
    return checks, findings


# ============================================================ 检查域 B/C：权限与写操作

def check_agency(tool_defs):
    """基于工具清单做过度自主权（LLM06）分析。"""
    checks = []
    if not tool_defs:
        return checks

    WRITE_KW = ("write", "create", "update", "delete", "insert", "post",
                "put", "patch", "remove", "send", "execute", "run",
                "order", "refund", "transfer", "deploy", "modify")
    READ_KW = ("get", "list", "read", "search", "fetch", "query", "view", "describe")

    writes, reads = [], []
    for t in tool_defs:
        # 兼容工具清单的两种形态：字符串 或 dict
        name = t if isinstance(t, str) else str(t.get("name", ""))
        n = name.lower()
        if any(k in n for k in WRITE_KW):
            writes.append(name)
        elif any(k in n for k in READ_KW):
            reads.append(name)

    ratio = len(writes) / max(len(reads) + len(writes), 1)

    checks.append({
        "id": "B1", "domain": "权限面",
        "owasp": "LLM06",
        "severity": "HIGH" if ratio > 0.5 else ("MEDIUM" if writes else "PASS"),
        "title": "写工具占比",
        "status": "FAIL" if ratio > 0.5 else ("WARN" if writes else "PASS"),
        "detail": "读工具 %d 个 / 写工具 %d 个（写占比 %.0f%%）%s" % (
            len(reads), len(writes), ratio * 100,
            "　→ 写能力占比过半，提示注入可直接造成业务动作" if ratio > 0.5 else ""),
        "tools_written": writes,
    })

    # C1: 危险工具点名
    DANGEROUS = {
        "execute": "可执行任意命令",
        "run": "可执行任意代码",
        "eval": "可执行动态代码",
        "refund": "涉及资金",
        "transfer": "涉及资金转移",
        "delete": "可删除数据",
        "deploy": "可触发部署",
    }
    hit = []
    for t in tool_defs:
        name = t if isinstance(t, str) else str(t.get("name", ""))
        n = name.lower()
        for kw, desc in DANGEROUS.items():
            if kw in n:
                hit.append("%s（%s）" % (name, desc))
    checks.append({
        "id": "C1", "domain": "写操作安全",
        "owasp": "LLM06",
        "severity": "HIGH" if hit else "PASS",
        "title": "高危工具暴露",
        "status": "FAIL" if hit else "PASS",
        "detail": "；".join(hit) if hit else "未发现执行/资金/删除类高危工具",
    })

    return checks


IDEMPOTENCY_PATTERNS_DESC = [
    "声明了幂等性", "存在幂等键字段", "有去重/请求ID机制",
    "使用冲突忽略/upsert", "有唯一约束",
]

CONFIRM_PATTERNS_DESC = [
    "有确认参数", "有试运行/预览", "有审批步骤", "有二次验证",
]

AUDIT_PATTERNS_DESC = [
    "有审计日志", "有日志记录", "记录调用者身份", "有链路追踪ID",
]

DANGEROUS_SRC = [
    (r"(?i)def\s+\w*(refund|transfer|pay|charge|withdraw)", "资金操作函数"),
    (r"(?i)def\s+\w*(delete|remove|destroy|drop)", "删除操作函数"),
    (r"(?i)def\s+\w*(create|insert|add|update|modify)", "写操作函数"),
    (r"(?i)subprocess|os\.system|eval\(|exec\(", "命令/代码执行"),
    (r"(?i)execute\(|executemany\(|raw\s*\(", "原生SQL 执行"),
]

# 否定语境词：与机制关键词同行出现时，不视为「具备该能力」
NEGATION = [
    r"\bno\b", r"\bnot\b", r"\bwithout\b", r"\bnever\b", r"\bmissing\b",
    r"\bdisable[ds]?\b", r"\bTODO\b", r"\bFIXME\b",
    r"无需", r"不需", r"没有", r"缺少", r"尚未",
]


COMMENT_PREFIX = re.compile(r"(^\s*#)|(^\s*//)|(^\s*/\*)|(^\s*\*)")

# 核心机制关键词（用于判定该行是否真的实现了这个机制）
CORE_KW = {
    "声明了幂等性": r"idempoten",
    "存在幂等键字段": r"idempotency[_-]?key",
    "有去重/请求ID机制": r"request[_-]?id|dedup",
    "使用冲突忽略/upsert": r"on[ _]conflict|upsert",
    "有唯一约束": r"if[ _]exists\(|unique",
    "有确认参数": r"\bconfirm\b",
    "有试运行/预览": r"dry[_-]?run|preview",
    "有审批步骤": r"approval|approve",
    "有二次验证": r"two[_-]?step|verify[_-]?first",
    "有审计日志": r"audit[_-]?log|auditlog",
    "有日志记录": r"logger?\.(info|warn|error)|logging\.",
    "记录调用者身份": r"user[_-]?id|session[_-]?id|subject|actor",
    "有链路追踪ID": r"trace[_-]?id|correlation[_-]?id",
}


def _strip_comment(line):
    """去掉行内注释，避免注释里的关键词造成误判。"""
    s = line
    for mark in ("#", "//"):
        idx = s.find(mark)
        if idx != -1:
            s = s[:idx]
    return s


def scan_source_lines(repo_path, exts=(".py", ".ts", ".js", ".go", ".java")):
    """产出 (去注释后的有效代码行, 相对路径) 列表。"""
    import os
    out = []
    if not repo_path or not os.path.isdir(repo_path):
        return out
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs
                   if d not in (".git", "node_modules", "__pycache__",
                                ".venv", "venv", "dist", "build")]
        for fn in files:
            if not fn.endswith(exts):
                continue
            fp = os.path.join(root, fn)
            try:
                with open(fp, encoding="utf-8", errors="replace") as fh:
                    raw = fh.readlines()
            except Exception:
                continue
            rel = os.path.relpath(fp, repo_path)
            for line in raw:
                if COMMENT_PREFIX.match(line):
                    continue
                code = _strip_comment(line)
                if code.strip():
                    out.append((code, rel))
    return out


def scan_capability(repo_path, desc_labels):
    """在有效代码行中检测能力。

    关键：**逐行做否定语境判定** —— 注释行直接排除；
    同一行若含否定词（如 no/without/无需/缺少），不视为具备该能力。

    返回 (有效命中描述集合, 被否定的描述集合, 扫描行数)
    """
    lines = scan_source_lines(repo_path)
    ok_set, neg_set = set(), set()
    for code, _rel in lines:
        for desc in desc_labels:
            kw = CORE_KW.get(desc)
            if not kw or not re.search(kw, code, re.I):
                continue
            negated = any(re.search(neg, code, re.I) for neg in NEGATION)
            (neg_set if negated else ok_set).add(desc)
    return ok_set, neg_set, len(lines)


def _scan_source(repo_path, patterns, exts=(".py", ".ts", ".js", ".go", ".java")):
    """在源码目录中扫描，返回 (命中文件列表, 扫描文件数)。"""
    import os
    hits, n = [], 0
    if not repo_path or not os.path.isdir(repo_path):
        return hits, 0
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs
                   if d not in (".git", "node_modules", "__pycache__",
                                ".venv", "venv", "dist", "build")]
        for fn in files:
            if not fn.endswith(exts):
                continue
            fp = os.path.join(root, fn)
            try:
                with open(fp, encoding="utf-8", errors="replace") as fh:
                    src = fh.read()
            except Exception:
                continue
            n += 1
            for pat, desc in patterns:
                if re.search(pat, src):
                    hits.append((desc, os.path.relpath(fp, repo_path)))
    return hits, n


def check_write_safety(repo_path):
    """源码级检查：幂等性、确认步骤、审计日志。"""
    checks = []

    if not repo_path:
        # 【纪律 4】查不了 = SKIPPED，绝不能伪装成「已检查」
        return [
            {"id": "C2", "domain": "写操作安全", "owasp": "LLM06",
             "severity": "MEDIUM", "title": "源码级写操作审计",
             "status": "SKIPPED",
             "detail": "未提供 --repo，**未做任何源码检查**。"
                       "不可达≠安全——此项完全未覆盖"},
            {"id": "C3", "domain": "写操作安全", "owasp": "LLM06",
             "severity": "MEDIUM", "title": "写操作幂等性",
             "status": "SKIPPED",
             "detail": "未提供 --repo，**未做幂等性检查**"},
            {"id": "C4", "domain": "写操作安全", "owasp": "LLM02",
             "severity": "MEDIUM", "title": "审计日志与可追责性",
             "status": "SKIPPED",
             "detail": "未提供 --repo，**未做审计日志检查**"},
        ]

    import os
    if not os.path.isdir(repo_path):
        return [{"id": "C2", "domain": "写操作安全", "owasp": "LLM06",
                 "severity": "MEDIUM", "title": "源码级写操作审计",
                 "status": "SKIPPED",
                 "detail": "--repo 路径不存在：%s（未做任何检查）" % repo_path}]

    # C2 —— 写操作定位
    danger, nfile = _scan_source(repo_path, DANGEROUS_SRC)
    kinds = sorted(set(d for d, _ in danger))
    checks.append({
        "id": "C2", "domain": "写操作安全", "owasp": "LLM06",
        "severity": "MEDIUM" if danger else "PASS",
        "title": "写操作/执行点定位",
        "status": "INFO",
        "detail": "已扫描 %d 个源文件，命中 %d 处：%s"
                  % (nfile, len(danger), "、".join(kinds) if kinds else "无"),
    })

    # C3 —— 幂等性（行级判定，排除注释与否定语境）
    idem_ok, idem_neg, nlines = scan_capability(
        repo_path, [d for d in IDEMPOTENCY_PATTERNS_DESC])

    if not idem_ok:
        c3_status, c3_sev = "FAIL", "HIGH"
        extra = ("（命中但处于否定语境，已排除：%s）" % "、".join(sorted(idem_neg))
                 if idem_neg else "")
        c3_detail = ("已扫描 %d 行有效代码，未发现任何幂等机制"
                     "（幂等键/去重/upsert/唯一约束）%s"
                     "　→ **重试或重放会造成重复执行**" % (nlines, extra))
    else:
        c3_status, c3_sev = "PASS", "PASS"
        c3_detail = "发现幂等机制：%s" % "、".join(sorted(idem_ok))

    checks.append({
        "id": "C3", "domain": "写操作安全", "owasp": "LLM06",
        "severity": c3_sev, "title": "写操作幂等性",
        "status": c3_status, "detail": c3_detail,
        "note": "静态分析仅基于关键词，无法判断逻辑正确性；"
                "键存在但实现有误仍会导致重复执行",
    })

    # C4 —— 确认步骤
    conf_ok, conf_neg, _ = scan_capability(
        repo_path, [d for d in CONFIRM_PATTERNS_DESC])
    if not conf_ok:
        c4_status, c4_sev = "WARN", "MEDIUM"
        extra = ("（否定语境已排除：%s）" % "、".join(sorted(conf_neg)) if conf_neg else "")
        c4_detail = ("已扫描 %d 行有效代码，未发现 confirm / dry_run / preview / approval%s"
                     "　→ 提示注入可直接触发不可逆动作" % (nlines, extra))
    else:
        c4_status, c4_sev = "PASS", "PASS"
        c4_detail = "发现确认机制：%s" % "、".join(sorted(conf_ok))

    checks.append({
        "id": "C4", "domain": "写操作安全", "owasp": "LLM06",
        "severity": c4_sev, "title": "危险操作前的确认/试运行",
        "status": c4_status, "detail": c4_detail,
    })

    # C5 —— 审计日志与可追责性
    aud_ok, aud_neg, _ = scan_capability(
        repo_path, [d for d in AUDIT_PATTERNS_DESC])
    has_log = any(("审计" in k or "日志" in k) for k in aud_ok)
    has_who = any("调用者身份" in k for k in aud_ok)

    if not has_log:
        c5_status, c5_sev = "FAIL", "HIGH"
        c5_detail = "已扫描 %d 行有效代码，未发现审计日志或日志记录　→ **动作无法追责**" % nlines
    elif not has_who:
        c5_status, c5_sev = "WARN", "MEDIUM"
        c5_detail = ("有日志记录，但未发现调用者身份字段"
                     "（user_id / session_id / subject / actor）"
                     "　→ **无法定位是谁做的**")
    else:
        c5_status, c5_sev = "PASS", "PASS"
        c5_detail = "日志与调用者身份均已记录：%s" % "、".join(sorted(aud_ok))

    checks.append({
        "id": "C5", "domain": "写操作安全", "owasp": "LLM02",
        "severity": c5_sev, "title": "审计日志与可追责性",
        "status": c5_status, "detail": c5_detail,
    })

    return checks


# ============================================================ 检查域 D：提示注入

# 零宽/不可见字符 —— 攻击者用来打断关键词绕过检测
ZERO_WIDTH = {c: None for c in (
    0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF,   # 零宽
    0x00AD, 0x180E,                          # 软连字符 / 蒙古元音分隔符
)}


def normalize_for_detection(text):
    """检测前的文本归一化 —— 反制「同形字/零宽字符绕过」。

    promptfoo 有 ascii-smuggling / special-token-injection 两个插件
    专门打这一点：如果检测器不做归一化，攻击者用零宽字符打断关键词
    就能让检测规则失效（ig\\u200bnore previous）。

    处理：NFKC 归一 + 剥离零宽字符 + 剥离方向控制符 + 转小写。
    """
    if not text:
        return ""
    import unicodedata
    s = unicodedata.normalize("NFKC", text)
    s = s.translate(ZERO_WIDTH)
    # 剥离其余不可见/格式字符（保留 \n \t 等正常空白）
    s = "".join(ch for ch in s
                if ch in "\n\r\t" or not unicodedata.category(ch).startswith("C"))
    return s.lower()


def check_injection_surface(tool_defs, tool_meta_text):
    """LLM01：检查工具描述是否可被注入指令。"""
    checks = []

    # D1: 工具描述里是否含外部可控内容
    INJ_PATTERNS = [
        (r"ignore\s+(all\s+)?previous", "「ignore previous instructions」类注入"),
        (r"you\s+are\s+now", "角色重设指令"),
        (r"</?\s*important\s*>", "伪造强调标签 <important>"),
        (r"\bsystem\s*[:=]", "伪造 system 角色标记"),
        (r"disregard|forget\s+(everything|all)", "「disregard/forget」类指令"),
        (r"do\s+not\s+(mention|tell|inform)", "「不要提及」类隐蔽指令"),
        (r"(read|include|send|upload|exfiltrate).{0,40}"
         r"(\.ssh|id_rsa|\.env|password|credential|api[_-]?key|token)", "指示窃取凭据"),
        (r"(before|after)\s+(responding|answering)", "注入边界伪装（伪装成流程约束）"),
    ]

    suspicious = []
    if tool_meta_text:
        # 归一化后再匹配 —— 否则零宽字符可让所有规则失效
        norm = normalize_for_detection(tool_meta_text)
        for pat, desc in INJ_PATTERNS:
            if re.search(pat, norm):
                suspicious.append(desc)

    # 附加：检测零宽字符本身的存在（说明有人在藏东西）
    if tool_meta_text:
        zw = sum(tool_meta_text.count(chr(c)) for c in
                 (0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF))
        if zw:
            suspicious.append("元数据含 %d 个零宽字符（疑似刻意隐藏指令）" % zw)

    # 【纪律 4】没有描述可查 → SKIPPED，绝不能报 PASS
    if not tool_meta_text:
        d1_status, d1_sev = "SKIPPED", "MEDIUM"
        d1_detail = ("**未获取到任何工具描述，此项未覆盖**。"
                     "不可达≠安全——请用 --tools 提供清单，"
                     "或确认目标是否公开 /mcp 或 /mcp/descriptions")
    elif suspicious:
        d1_status, d1_sev = "FAIL", "HIGH"
        d1_detail = "工具元数据中发现注入载荷特征：%s" % "；".join(suspicious)
    else:
        d1_status, d1_sev = "PASS", "PASS"
        d1_detail = ("已检查 %d 项注入特征（含 Unicode 归一化后比对），"
                     "工具描述中未见明显注入串" % len(INJ_PATTERNS))

    # 【纪律 7】PASS 必须同时声明检测能力局限
    if d1_status == "PASS":
        d1_detail += ("\n⚠ 检测局限：本次仅覆盖已知模式与归一化后文本，"
                      "语义改写或新型注入载荷不在检测范围内。"
                      "本项 PASS ≠ 不存在注入")

    checks.append({
        "id": "D1", "domain": "提示注入",
        "owasp": "LLM01",
        "severity": d1_sev,
        "title": "工具元数据注入痕迹",
        "status": d1_status,
        "detail": d1_detail,
    })

    # D2: 工具数量 —— 工具越多，注入面越大
    n = len(tool_defs) if tool_defs else 0
    if not tool_defs:
        d2_status, d2_sev, d2_detail = "SKIPPED", "MEDIUM", "未获取工具清单"
    elif n > 20:
        d2_status, d2_sev = "WARN", "MEDIUM"
        d2_detail = "共 %d 个工具　→ 注入面较大，需重点验证工具边界" % n
    else:
        d2_status, d2_sev = "PASS", "PASS"
        d2_detail = "共 %d 个工具，注入面可控" % n

    checks.append({
        "id": "D2", "domain": "提示注入",
        "owasp": "LLM01", "severity": d2_sev,
        "title": "工具数量（注入面）", "status": d2_status, "detail": d2_detail,
    })

    return checks


# ============================================================ 检查域 E/F

def check_rate_limit(url):
    """仅观察，不做压力测试。"""
    return [{
        "id": "E1", "domain": "速率限制",
        "owasp": "LLM10", "severity": "MEDIUM",
        "title": "速率限制 / 无限成本风险",
        "status": "INFO",
        "detail": "需查源码确认是否有限流；单次探测无法判定。"
                "**未做压力测试**（超出被动检测范围）",
    }]


def check_info_leak(url, status, text):
    """LLM02：错误信息与版本披露。

    ⚠ 多端点采样 —— 只查主端点会漏掉其他路径上的泄漏。
    常见泄漏点：/health /metrics / 错误响应。
    采样偏差是审计工具最常见的致命缺陷：用一个端点的结论
    推断整个服务的安全性。
    """
    checks = []

    # 从主 URL 推导基址
    base = url.rstrip("/")
    for suf in ("/mcp", "/sse", "/message"):
        if base.endswith(suf):
            base = base[: -len(suf)]
            break

    endpoints = [("主端点", base + "/mcp")]
    for p in ("/health", "/healthz", "/ready", "/status", "/metrics"):
        endpoints.append(("健康/指标", base + p))
    # ⚠ 调试/管理端点 —— Day 4 补入。
    #   上一版只查 /health /metrics，漏掉了 /debug 这类
    #   **更容易泄漏且更常被忘记关闭**的路径。
    #   （promptfoo 插件 `debug-access` 交叉验证发现的盲区）
    for p in ("/debug/vars", "/debug", "/actuator", "/actuator/env",
              "/_debug", "/api/debug", "/server-status", "/.env", "/config"):
        endpoints.append(("调试/管理", base + p))

    patterns = [
        (r"(?i)traceback \(most recent call last\)", "Python traceback 泄露"),
        (r"(?i)at [\w.]+ \(.*:\d+:\d+\)", "含代码位置信息"),
        (r"(?i)(node|python|go|rust|java)\s+v?\d+\.\d+", "含运行时版本号"),
        (r"(?i)(/home/[\w/]+|/Users/[\w/]+|[A-Z]:\\\\)", "含服务器绝对路径"),
        (r"(?i)(postgresql|mysql|mongodb|redis)://[^\s\"']+", "含数据库连接串"),
        (r"(?i)api[_-]?key|secret[_-]?key", "含密钥字段名"),
        (r"(?i)(hunter2|passw[o0]rd\s*=\s*[^\s\"']{3,})", "含疑似明文口令"),
    ]

    leaks = []
    probed, blocked = [], []
    for label, ep in endpoints:
        st, tx, er, ok = probe(ep)
        if not ok:
            blocked.append((label, ep, er))
            continue
        probed.append("%s(%s)" % (label, st))
        # ⚠ 不限制 status —— **错误响应体（4xx/5xx）是泄漏最严重的地方**
        if not tx:
            continue
        for pat, desc in patterns:
            if re.search(pat, tx):
                leaks.append("%s ← %s [HTTP %s]" % (desc, ep, st))

    checks.append({
        "id": "F1", "domain": "信息泄漏",
        "owasp": "LLM02", "severity": "HIGH" if leaks else "PASS",
        "title": "错误响应信息泄漏（多端点采样）",
        "status": "FAIL" if leaks else "PASS",
        "detail": "；".join(leaks) if leaks else
                  "已探测 %d 个端点，未发现明显栈/路径/凭据泄漏" % len(probed),
        "probed": probed,
        "blocked": blocked,
    })

    # F2 —— 显式报出采样覆盖度（覆盖缺口必须可见）
    checks.append({
        "id": "F2", "domain": "信息泄漏",
        "owasp": "LLM02", "severity": "MEDIUM",
        "title": "端点采样覆盖度",
        "status": "WARN" if blocked else "PASS",
        "detail": ("已探测 %d/%d 个端点；**未探测 %d 个**：%s"
                   % (len(probed), len(endpoints), len(blocked),
                      ", ".join(b[1] for b in blocked)))
                if blocked else
                ("全部 %d 个端点均完成探测：%s"
                 % (len(probed), ", ".join(probed))),
    })

    return checks
    return checks


# ============================================================ 汇总与输出

SEV_CN = {"HIGH": "严重", "MEDIUM": "中", "PASS": "通过", "WARN": "注意", "INFO": "提示"}


def summarize(checks):
    c = {"HIGH": 0, "MEDIUM": 0, "PASS": 0, "WARN": 0, "INFO": 0, "SKIPPED": 0}
    for x in checks:
        c[x["status"]] = c.get(x["status"], 0) + 1
    return c


def render_text(res):
    L = []
    checks = res["checks"]
    s = res["summary"]

    L.append("=" * 70)
    L.append("MCP Server 安全审计报告")
    L.append("=" * 70)
    L.append("目标   : %s" % res["target"])
    L.append("时间   : %s" % res["timestamp"])
    L.append("可达性 : %s" % ("可达" if res["reachable"] else "**不可达**"))
    L.append("")
    L.append("检查结果统计：")
    L.append("  严重FAIL  : %d" % s.get("FAIL", 0))
    L.append("  警告         : %d" % s.get("WARN", 0))
    L.append("  通过         : %d" % s.get("PASS", 0))
    L.append("  提示         : %d" % s.get("INFO", 0))
    L.append("  ⚠ 跳过(不可达): %d" % s.get("SKIPPED", 0))
    L.append("")

    if not res["reachable"]:
        L.append("⚠ 端点不可达，以下结论仅基于可达的检查项。")
        L.append("  不可达 ≠ 安全。")
        L.append("")

    by_domain = {}
    for c in checks:
        by_domain.setdefault(c["domain"], []).append(c)

    for dom, items in by_domain.items():
        L.append("-" * 70)
        L.append("【%s】" % dom)
        for it in items:
            mark = "✗" if it["status"] == "FAIL" else (
                "!" if it["status"] in ("WARN", "SKIPPED") else "·")
            ow_key = it.get("owasp")
            ow = " (%s)" % OWASP.get(ow_key, ow_key) if ow_key else ""
            L.append("  %s [%s] %s%s" % (mark, it["id"], it["title"], ow))
            L.append("      状态: %s" % SEV_CN.get(it["status"], it["status"]))
            if it["detail"]:
                L.append("      %s" % it["detail"])
            if it.get("tools_written"):
                L.append("      写工具: %s" % ", ".join(
                    t if isinstance(t, str) else str(t.get("name", t))
                    for t in it["tools_written"]))
            L.append("")

    if res.get("notes"):
        L.append("=" * 70)
        L.append("行业背景")
        L.append("=" * 70)
        for n in res["notes"]:
            L.append("  · %s" % n)
        L.append("")

    L.append("=" * 70)
    L.append("实测边界")
    L.append("=" * 70)
    for lim in res["limitations"]:
        L.append("  - %s" % lim)
    return "\n".join(L)


def render_html(res):
    checks = res["checks"]
    s = res["summary"]

    ICON = {"FAIL": ("✗", "#c0392b"), "WARN": ("!", "#d68910"),
            "PASS": ("✓", "#27ae60"), "INFO": ("·", "#888"),
            "SKIPPED": ("⚠", "#8e44ad")}

    by_domain = {}
    for c in checks:
        by_domain.setdefault(c["domain"], []).append(c)

    sections = []
    for dom, items in by_domain.items():
        rows = []
        for it in items:
            ic, col = ICON.get(it["status"], ("?", "#888"))
            ow = OWASP.get(it.get("owasp"), "")
            ow_html = '<span class="ow">%s</span>' % ow if ow else ""
            tools = ""
            if it.get("tools_written"):
                tools = '<div class="tools">写工具：%s</div>' % "、".join(
                    t if isinstance(t, str) else str(t.get("name", t))
                    for t in it["tools_written"])
            rows.append(f"""<tr>
      <td class="id">{it['id']}</td>
      <td><span class="st" style="background:{col}">{ic} {it['status']}</span></td>
      <td><b>{it['title']}</b> {ow_html}{tools}<div class="detail">{it['detail']}</div></td>
    </tr>""")
        sections.append(f"""  <h2>{dom}</h2>
  <table><thead><tr><th style="width:52px">ID</th><th style="width:96px">状态</th><th>说明</th></tr></thead>
  <tbody>
{chr(10).join(rows)}
  </tbody></table>""")

    notes = ""
    if res.get("notes"):
        notes = "<div class='box'><h3>行业背景</h3><ul>" + \
                "".join("<li>%s</li>" % n for n in res["notes"]) + "</ul></div>"

    html = f"""<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8">
<title>MCP Server 安全审计报告 · {res['target']}</title><style>
 body{{font-family:-apple-system,"Segoe UI","Microsoft YaHei",sans-serif;background:#f7f8fa;
      color:#1a1a1a;margin:0;padding:32px;line-height:1.6}}
 .wrap{{max-width:1080px;margin:0 auto}}
 h1{{font-size:24px;margin:0 0 4px}}
 .sub{{color:#666;font-size:13px;margin-bottom:22px}}
 .kpi{{display:flex;gap:10px;margin-bottom:22px;flex-wrap:wrap}}
 .kpi div{{background:#fff;border:1px solid #e3e6ea;border-radius:8px;padding:13px 18px;
           flex:1;min-width:88px;text-align:center}}
 .kpi .n{{font-size:24px;font-weight:700}}
 .kpi .l{{font-size:11px;color:#888}}
 table{{width:100%;border-collapse:collapse;background:#fff;border:1px solid #e3e6ea;
        border-radius:8px;overflow:hidden;margin-bottom:8px}}
 th,td{{padding:9px 12px;text-align:left;border-bottom:1px solid #eef0f2;font-size:13px;
       vertical-align:top}}
 th{{background:#fafbfc;font-weight:600;color:#555}}
 .id{{color:#999;font-family:Consolas,monospace;font-size:12px}}
 .st{{color:#fff;padding:2px 7px;border-radius:4px;font-size:11px;font-weight:600;
     display:inline-block}}
 .ow{{color:#1a5fb4;font-size:11px;background:#eaf1fb;padding:1px 6px;border-radius:3px}}
 .detail{{color:#666;font-size:12.5px;margin-top:4px}}
 .tools{{color:#c0392b;font-size:12px;margin-top:3px}}
 .box{{background:#fff;border:1px solid #e3e6ea;border-radius:8px;padding:16px 20px;
       margin-bottom:18px;border-left:4px solid #d68910}}
 .box h3{{margin:0 0 8px;font-size:15px}}
 .box ul{{margin:6px 0;padding-left:20px;color:#555;font-size:13px}}
 h2{{font-size:16px;margin:24px 0 8px}}
 code{{background:#f0f2f5;padding:2px 6px;border-radius:4px;font-size:12px}}
 .foot{{margin-top:24px;padding-top:14px;border-top:1px solid #e3e6ea;font-size:12px;color:#999}}
</style></head><body><div class="wrap">
<h1>MCP Server 安全审计报告</h1>
<div class="sub">目标 <code>{res['target']}</code> · {res['timestamp']} · 被动/只读检测</div>
<div class="kpi">
 <div><div class="n" style="color:#c0392b">{s.get('FAIL',0)}</div><div class="l">FAIL 严重</div></div>
 <div><div class="n" style="color:#d68910">{s.get('WARN',0)}</div><div class="l">WARN 警告</div></div>
 <div><div class="n" style="color:#27ae60">{s.get('PASS',0)}</div><div class="l">PASS 通过</div></div>
 <div><div class="n" style="color:#8e44ad">{s.get('SKIPPED',0)}</div><div class="l">SKIPPED 跳过</div></div>
 <div><div class="n">{s.get('INFO',0)}</div><div class="l">INFO 提示</div></div>
</div>
{notes}
{chr(10).join(sections)}
<div class="box"><h3>实测边界</h3><ul>
{chr(10).join("  <li>%s</li>" % l for l in res['limitations'])}
</ul></div>
<div class="foot">本报告不含任何主动利用、压力测试或破坏性操作。</div>
</div></body></html>"""
    return html


# ============================================================ main

def main():
    ap = argparse.ArgumentParser(description="MCP Server 安全审计器（被动检测）")
    ap.add_argument("--url", required=True, help="MCP 端点 URL")
    ap.add_argument("--repo", help="源码目录（可选，启用源码级检查）")
    ap.add_argument("--tools", help="工具清单 JSON（可选）")
    ap.add_argument("--json", help="输出 JSON")
    ap.add_argument("--html", help="输出 HTML")
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args()

    url = a.url if a.url.startswith(("http://", "https://")) else "https://" + a.url

    # 载入工具清单：优先直接向目标拉取，其次用本地文件
    tool_defs, meta_text = [], ""
    source = ""

    # (1) 自动拉取：从 /mcp 与 /mcp/descriptions 抓工具描述
    base = url.rstrip("/")
    for suf in ("/mcp", "/sse", "/message"):
        if base.endswith(suf):
            base = base[: -len(suf)]
            break

    fetched_any = False
    for path in ("/mcp", "/mcp/descriptions"):
        st, tx, er, ok = probe(base + path)
        if ok and st == 200 and tx:
            try:
                raw = json.loads(tx)
                items = raw.get("tools") if isinstance(raw, dict) else raw
                if items:
                    tool_defs.extend(items)
                    meta_text += json.dumps(items, ensure_ascii=False) + "\n"
                    fetched_any = True
            except Exception:
                meta_text += tx[:4000] + "\n"
                fetched_any = True

    if fetched_any:
        source = "已自动从目标拉取"
        # 去重
        seen, uniq = set(), []
        for t in tool_defs:
            k = (t if isinstance(t, str) else str(t.get("name", id(t))))
            if k not in seen:
                seen.add(k)
                uniq.append(t)
        tool_defs = uniq
    elif a.tools:
        try:
            with open(a.tools, encoding="utf-8") as fh:
                raw = json.load(fh)
            tool_defs = raw.get("tools", []) if isinstance(raw, dict) else raw
            meta_text = json.dumps(raw, ensure_ascii=False)
            source = "使用本地清单: %s" % a.tools
        except Exception as e:
            source = "本地清单读取失败: %s" % e
    else:
        source = "**未获取到工具清单**（自动拉取失败且未提供 --tools）"

    print("审计目标: %s" % url)
    status, text, err, reachable = probe(url)
    if reachable:
        reach_line = "可达 (HTTP %s)" % status
    else:
        reach_line = "**不可达** — %s" % err
    print("可达性  : %s" % reach_line)
    print("工具清单: %s（%d 个工具）" % (source, len(tool_defs)))
    print()

    checks, notes = [], []
    c_a, n_a = check_auth(url); checks += c_a; notes += n_a
    checks += check_agency(tool_defs)
    checks += check_write_safety(a.repo)
    checks += check_injection_surface(tool_defs, meta_text)
    checks += check_rate_limit(url)
    checks += check_info_leak(url, status, text)

    res = {
        "target": url,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "reachable": reachable,
        "http_status": status,
        "checks": checks,
        "summary": summarize(checks),
        "notes": notes,
        "limitations": [
            "未做压力测试 / 速率限制验证（超出被动范围）",
            "未尝试任何凭据或绕过认证",
            "未验证工具内部逻辑（仅从名称与描述推断）",
            "未检测间接提示注入的实际可利用性（需真实 agent 交互）",
            "幂等性与确认步骤需读源码，本工具仅能标注为待人工核查",
        ],
    }

    print(render_text(res))

    if a.json:
        with open(a.json, "w", encoding="utf-8") as fh:
            json.dump(res, fh, ensure_ascii=False, indent=2)
        print("\nJSON 已写入: %s" % a.json)
    if a.html:
        with open(a.html, "w", encoding="utf-8") as fh:
            fh.write(render_html(res))
        print("HTML 已写入: %s" % a.html)

    return 1 if res["summary"].get("FAIL") else 0


if __name__ == "__main__":
    sys.exit(main())