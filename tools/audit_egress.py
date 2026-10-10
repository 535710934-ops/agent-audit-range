#!/usr/bin/env python3
"""
audit_egress.py —— 外联白名单盘点（G1）+ agent 可自改配置面（G1b）
=================================================================
Day6 新增。对应Day 5 对齐发现的 **G1 类缺口**。

【为什么这是一个独立检查，而不是加进F1 或 G2】
EchoLeak（CVE-2025-32711）与ForcedLeak（Salesforce Agentforce）两个
CVSS 9.x 案例的共同点是：
  **外发通道不是漏洞 —— 它是被正确授权的白名单。**
  - EchoLeak：CSP 允许域 + SharePoint EmbedService / Teams 代理
  - ForcedLeak：CSP 白名单里一个**已过期域名**被攻击者以 5 美元买回
⇒ 白名单本身是攻击面，而且是**唯一不会被任何扫描判为 FAIL 的攻击面**：
   它的每一项在配置层面都是「正确」的。

⇒ 本检查盘点三件事：
  G1a  外联白名单有哪些 —— 并标注哪些域看起来闲置/已过期
  G1b  agent 可自改的配置面 —— agent 能改自己的安全设置（YOLO mode）
  G1c  敏感数据是否会以 URL/图片参数形式流出（外发形态检查）

【G1b 的真实案例】
CVE-2025-53773（GitHub Copilot / VS Code "YOLO mode", CVSS 7.8）：
  注入 → 写入 .vscode/settings.json 的 chat.tools.autoApprove:true
       → 所有工具确认框消失 → 任意命令执行
⇒ **agent 能改自己的权限配置**，这是「能力授予」问题，不是文本检测问题。
   纯提示注入检测（D1）对此完全无效。
"""

import json
import os
import re
import sys
import time
import urllib.error
import urllib.request

UA = "egress-auditor/1.0"

# ============================================================ 配置面

# agent 可自改的安全相关配置路径（来自 CVE-2025-53773 等真实案例）
SELF_MODIFY_PATHS = [
    "/.vscode/settings.json",
    "/.vscode/tasks.json",
    "/.vscode/launch.json",
    "/.cursor/rules",
    "/.cursorrules",
    "/.claude/settings.json",
    "/.claude/CLAUDE.md",
    "/.codex/config.toml",
    "/.mcp.json",
    "/.cursor/mcp.json",
    "/.config/mcp/config.json",
    "/CLAUDE.md",
    "/AGENTS.md",
]

# 这些键值若出现在配置里，等于关掉了人工确认
AUTO_APPROVE_KEYS = [
    "autoApprove", "auto_approve", "yolo", "yoloMode",
    "autoConfirm", "skipConfirmation", "alwaysAllow",
    "trustAllTools", "disableSecurity", "bypassPermissions",
    "always_allow", "requireConfirmation",
    "chat.tools.autoApprove", "tools.autoApprove",
    "allowedCommands", "permissions.allow",
]

# 外联白名单/出站配置
EGRESS_PATHS = [
    "/csp.json", "/content-security-policy.json", "/csp.txt",
    "/.well-known/csp-report", "/security/csp",
    "/config/csp", "/admin/csp",
    "/.env", "/config.json", "/config.yaml", "/app.config.json",
    "/manifest.json", "/assetlinks.json",
    "/proxy.json", "/allowed-origins.json", "/cors.json",
]

# 敏感数据外发的高危参数形态
EXFIL_PATTERNS = [
    (r"(?i)[?&](data|payload|content|body|q|query|text|doc|file|msg|message|"
     r"inbox|csv|export|dump)\s*=", "URL 参数携带数据（数据经查询串外发）"),
    (r"(?i)!\[[^\]]*\]\((https?://[^)]*)\)", "Markdown 图片语法外联（渲染即触发）"),
    (r"(?i)!\[[^\]]*\]\[[^\]]*\]\[[^\]]*\]:\s*https?://",
     "Markdown 引用式图片语法外联（CVE-2025-32711 EchoLeak 同款手法）"),
    (r"(?i)(atob|btoa|base64|utf-?8\.TextEncoder)\s*\(", "编码函数（编码后外发）"),
    (r"(?i)fetch\s*\(\s*['\"]https?://[^'\"]*['\"]", "前端直连外部域"),
    (r"(?i)(XMLHttpRequest|sendBeacon|WebSocket)\s*\(", "跨域外发 API"),
    (r"(?i)window\.open\s*\(|location\.href\s*=\s*['\"]https?://", "页面跳转外联"),
]


def req(url, method="GET", timeout=8):
    r = urllib.request.Request(url, headers={"User-Agent": UA}, method=method)
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            return resp.status, resp.read(65536).decode("utf-8", "replace"), None
    except urllib.error.HTTPError as e:
        # 错误响应体同样要读 —— 配置类泄漏常在 403/404 里
        return e.code, e.read(8192).decode("utf-8", "replace"), None
    except Exception as e:
        return None, "", "%s: %s" % (type(e).__name__, str(e)[:100])


def derive_base(url):
    b = url.rstrip("/")
    for suf in ("/mcp", "/sse", "/message"):
        if b.endswith(suf):
            b = b[: -len(suf)]
            break
    return b


# ============================================================ G1a 白名单盘点


def check_egress_whitelist(base, deep=False):
    """盘点外联白名单，并标注**闲置/可疑**条目。

    ⚠ 关键区分：本检查**不判 PASS/FAIL**来表达「白名单是否安全」，
       因为配置里的每一项在语法上都是正确的。
       本检查回答的是**盘点 + 分诊**：客户至少要知道自己的出站面有多大。
    """
    paths = list(EGRESS_PATHS)
    if deep:
        paths += ["/.env.production", "/.env.local", "/settings/egress.json"]

    found, blocked, guarded = [], [], []
    for p in paths:
        st, tx, err = req(base + p)
        if err:
            blocked.append("%s(受阻)" % p)
            continue
        if st == 200 and tx.strip():
            found.append((p, tx))
        elif st in (401, 403):
            guarded.append("%s(%s)" % (p, st))
        else:
            guarded.append("%s(%s)" % (p, st))

    # 从内容里提取域名
    domains, csp_rules, suspicious = [], [], []
    IDLE_HINT = re.compile(r"(?i)(example\.(com|org)|test|localhost|"
                           r"staging|dev\.|old|legacy|backup|deprecated)")
    for p, tx in found:
        for m in re.finditer(r"(?i)https?://([a-z0-9.\-]+)", tx):
            d = m.group(1).lower()
            if d not in domains:
                domains.append(d)
            if IDLE_HINT.search(d):
                suspicious.append("%s ← %s" % (d, p))
        # CSP 里的指令
        for m in re.finditer(r"(?i)(img-src|script-src|connect-src|"
                             r"frame-src|media-src|form-action)\s+([^\"';\n]+)",
                             tx):
            csp_rules.append("%s %s" % (m.group(1), m.group(2)[:120]))

    return {
        "id": "G1a", "title": "外联白名单盘点（CSP / 出站配置）",
        "status": "WARN" if found else "PASS",
        "severity": "MEDIUM",
        "detail": ("发现 %d 个可读出站配置：%s" % (len(found), "、".join(p for p, _ in found)))
                  + ("；提取到 %d 个外联域：%s" % (len(domains), "、".join(domains[:8])))
                  + ("；**%d 个域看起来已过期/闲置，需人工确认是否仍需放行**：%s"
                     % (len(set(suspicious)), "、".join(sorted(set(suspicious))[:5])))
                  if (found and (domains or csp_rules)) else
                  ("已探测 %d 个出站配置端点，未发现可读的白名单配置"
                   % len(paths)),
        "note": "⚠ 本项**不对「白名单是否安全」下 PASS/FAIL 结论** —— "
                "配置里每一项在语法上都是正确的，"
                "风险来自**哪些域还在白名单里**（如过期域名被他人注册），"
                "只能靠人工分诊。",
        "probed": len(paths), "guarded": guarded[:6],
        "domains": domains, "csp": csp_rules[:8],
    }


# ============================================================ G1b 自改配置面


def check_self_modify(base):
    """agent 能否改自己的安全配置。

    这是**能力授予**问题，不是文本检测问题 ——
    纯提示注入检测（D1）对 CVE-2025-53773 这类完全无效。
    """
    exposed, guarded, blocked, critical = [], [], [], []
    for p in SELF_MODIFY_PATHS:
        st, tx, err = req(base + p)
        if err:
            blocked.append(p)
            continue
        if st == 200 and tx.strip():
            exposed.append(p)
            low = tx.lower()
            hits = [k for k in AUTO_APPROVE_KEYS if k.lower() in low]
            # 是否为已关闭确认的**危险状态**
            if any(re.search(re.escape(k.lower()) + r"\s*\"?\s*[:=]\s*"
                             r"(true|\[)", low) for k in hits):
                critical.append("%s ← %s" % (p, "、".join(hits[:3])))
        elif st in (401, 403):
            guarded.append("%s(%s)" % (p, st))
        else:
            guarded.append("%s(%s)" % (p, st))

    if critical:
        status, sev = "FAIL", "HIGH"
        detail = ("**发现已关闭人工确认的 agent 权限配置**：%s。"
                  "攻击者只需一次间接注入即可获得任意命令执行"
                  "（CVE-2025-53773 YOLO mode 同款链路）" % "；".join(critical))
    elif exposed:
        status, sev = "WARN", "MEDIUM"
        detail = ("%d 个 agent 自改配置路径可读：%s。"
                  "**这些配置未被加固**，agent 若被注入成功即可提权改写自身权限。"
                  % (len(exposed), "、".join(exposed[:6])))
    else:
        status, sev = "PASS", "HIGH"
        detail = "已探测 %d 个 agent 自改配置路径，未发现可读项" % len(SELF_MODIFY_PATHS)

    return {
        "id": "G1b", "title": "agent 可自改配置面（提权面）",
        "status": status, "severity": sev, "detail": detail,
        "exposed": exposed, "critical": critical,
    }


# ============================================================ G1c 外发形态


def check_exfil_shapes(base):
    """敏感数据是否会以 URL/图片参数形式流出。

    形态检查而非内容检查 —— 即便系统没被攻破，
    只要**具备**这种外发能力，一旦被注入就会成为通道。
    """
    samples, hits = [], []
    scan_eps = ["/mcp", "/health", "/", "/index.html", "/api/config"]
    for ep in scan_eps:
        st, tx, err = req(base + ep)
        if err or not tx:
            continue
        samples.append(ep)
        for pat, desc in EXFIL_PATTERNS:
            if re.search(pat, tx):
                hits.append("%s ← %s" % (desc, ep))

    if hits:
        status, sev = "WARN", "MEDIUM"
        detail = ("在 %d 个可读端点发现 %d 处外发形态：%s。"
                  "**这些形态本身不是漏洞** —— 但一旦发生间接注入，"
                  "它们就是现成的数据外发通道（EchoLeak / ForcedLeak 同款）。"
                  % (len(samples), len(hits), "；".join(sorted(set(hits))[:4])))
    elif samples:
        status, sev = "PASS", "MEDIUM"
        detail = "已探测 %d 个端点，未发现 URL 参数带数据 / 编码外发等形态" % len(samples)
    else:
        status, sev = "SKIPPED", "MEDIUM"
        detail = "全部端点受阻，**未测不等于无风险**"

    return {
        "id": "G1c", "title": "数据外发形态（URL/图片/编码）",
        "status": status, "severity": sev, "detail": detail,
        "probed": len(samples),
    }


# ============================================== G3s 跨服务器组合链（**静态**版）
#
# ⚠ 命名修正（Day 13）：原 ID 就叫 "G3"，与 check_service_principal.py 的
#   G3「硬编码平台级/共享密钥」**完全撞号** —— 两个不同的检查共用一个 ID，
#   合并台账里 G3 会变成歧义项（我自己的统计脚本就已经把它们混成一个了）。
#
#   现改为 G3s，与 G3r（组合链运行时探针）配对：
#     G3s = 静态能力盘点（只能报 WARN/PASS/SKIPPED）
#     G3r = 实际走一遍调用链（可报 FAIL/PASS/SKIPPED）
#   G3（不带后缀）专属 check_service_principal.py 的硬编码密钥检查。


def check_combo_chains(servers, repo=None):
    """G3s：单服务器审计看不到的**组合爆炸半径**（静态版）。

    真实案例（Anthropic mcp-server-git CVE-2025-68143/68144/68145）：
      单个 server git_init 无路径校验 看似只是「参数校验缺失」，
      但与 Filesystem server 组合后：
      git写 .git/config 的 clean filter → git_add 触发执行 → RCE

    ⇒ **每个单组件审计都可能显示 PASS，组合起来却是 RCE。**

    本检查做两件事：
      1) 列出已知的**危险能力组合**（写入任意路径 / 执行命令 / 网络出口）
      2) 判定当前服务器集合里是否**同时存在**其中两种以上

    ⚠ 诚实边界：静态能力清单**无法证明组合一定可利用**。
       本检查报 WARN 而非 FAIL，并在报告里写明需人工构造验证。
    """
    if not servers:
        # ⚠ 返回单dict（与其他三个检查一致）
        return {
            "id": "G3s", "title": "跨服务器组合链（爆炸半径）",
            "status": "SKIPPED", "severity": "HIGH",
            "detail": "未提供 --servers 清单，**本项未测**。"
                      "单服务器视角看不到组合爆炸，"
                      "这是本方法论当前的结构性局限。"}

    # 危险能力分类
    DANGER_CAPS = {
        "arbitrary_write": (r"(?i)(write_file|create_file|write\(|writeFile|"
                            r"save_file|put_file|edit_file|apply_patch|"
                            r"git_add|git_checkout|deploy|upload)",
                            "可写入任意路径"),
        "command_exec": (r"(?i)(run_command|"
                        # ⚠ `exec` 与 `execute_` 都必须带负向断言，且**两者都要**。
                        #   只给 execute_ 加断言不够：execute_query 里 `exec` 是子串，
                        #   会先命中 `exec` 分支。Day 8 实测：单侧断言时
                        #   execute_query / exec_sql 全部仍被误判为命令执行。
                        r"exec(?![\w]*(?:query|sql)\b)|"
                        r"shell|bash|subprocess|run_script|eval|terminal|"
                        r"git_diff|--output|"
                        r"execute_(?![\w]*(?:query|sql)\b))",
                         "可执行命令"),
        "net_egress": (r"(?i)(fetch|http_request|webhook|send_email|"
                      r"slack|discord|http\.client|requests\.)",
                       "具备网络出口"),
        "repo_write": (r"(?i)(git_init|git_commit|git_push|create_branch)",
                       "可改仓库内容"),
        "vcs_meta": (r"(?i)(git_)", "可操作 git 内部文件"),
    }

    inventory = []
    for s in servers:
        name = s.get("name") or s.get("url", "?")
        text = " ".join(s.get("tools") or []) + " " + name
        caps = []
        for cap, (pat, desc) in DANGER_CAPS.items():
            if re.search(pat, text):
                caps.append(cap)
        inventory.append({"name": name, "caps": caps, "desc": caps})

    all_caps = set()
    for it in inventory:
        all_caps |= set(it["caps"])

    # 已知危险组合（参考 CVE-2025-68143/68144/68145）
    DANGEROUS_COMBOS = [
        ({"repo_write", "vcs_meta", "command_exec"},
         "仓库写入 + git 内部文件操作 + 命令执行",
         "可写 .git/config 的 clean filter → git_add 触发任意命令执行 "
         "（CVE-2025-68144/68145 组合链）"),
        ({"arbitrary_write", "command_exec"},
         "任意路径写入 + 命令执行",
         "写脚本/配置 → 执行 → RCE"),
        ({"arbitrary_write", "net_egress"},
         "任意路径写入 + 网络出口",
         "写 .env/凭据文件 + 外联 → 数据外泄"),
        ({"net_egress", "repo_write"},
         "网络出口 + 仓库写入",
         "读远程内容 → 写入仓库 → 供应链投毒（CVE-2025-53773YOLO mode 形态）"),
    ]

    hits, rows = [], []
    # ⚠ 判定必须分「单服务器内」与「跨服务器」两种情形（Day 8 修复的真实漏报）。
    #   原实现只判 `need <= set(it["caps"])`（全部能力在**同一台**服务器上），
    #   而本检查项的名字就叫「跨服务器组合链」—— 组合恰恰是**跨服务器**发生的。
    #   原实现等于用相反的规则把要检的东西过滤掉了：
    #   CVE-2025-68143/68144/68145 正是 git-mcp 持有 repo_write+vcs_meta、
    #   另一个 server 持有 command_exec，跨 server 串联才成立。
    for need, label, why in DANGEROUS_COMBOS:
        # 情形一：能力集中在单台服务器（爆炸半径最小，最确定）
        single = [it["name"] for it in inventory
                  if need <= set(it["caps"])]
        if single:
            hits.append((label, why, single, "单台服务器内即成立"))
            continue
        # 情形二：能力分散在多台服务器（跨 server 组合链，本检查项的主目标）
        have = set()
        owners = {}
        for cap in need:
            for it in inventory:
                if cap in it["caps"]:
                    have.add(cap)
                    owners.setdefault(cap, []).append(it["name"])
        if need <= have:
            spread = sorted({n for ns in owners.values() for n in ns})
            detail = "；".join("%s ← %s" % (c, "/".join(owners[c]))
                              for c in sorted(need))
            hits.append((label, why, spread,
                         "**跨 %d 台服务器组合**（%s）" % (len(spread), detail)))

    lines = ["已审计 %d 个 MCP 服务器，危险能力分布：%s"
             % (len(inventory),
                "；".join("%s[%s]" % (it["name"],
                                     ",".join(it["caps"]) or "无危险能力")
                          for it in inventory))]
    if hits:
        status, sev = "WARN", "HIGH"
        lines.append("")
        lines.append("**发现 %d 组潜在危险能力组合：**" % len(hits))
        for label, why, present, mode in hits:
            lines.append("  · **%s** —— %s" % (label, why))
            lines.append("    涉及服务器：%s" % "、".join(present))
            lines.append("    成立方式：%s" % mode)
        lines.append("")
        lines.append("⚠ **本项不能证明组合一定可利用** —— 静态能力清单看不到"
                     "参数流向与运行时校验。必须实际构造调用链验证后才能定性。"
                     "跨服务器组合尤其如此：各 server 之间未必有可用的数据传递通道。")
    else:
        status, sev = "PASS", "HIGH"
        lines.append("未发现已知危险能力组合")

    return {
        "id": "G3s", "title": "跨服务器组合链（爆炸半径）",
        "status": status, "severity": sev,
        "detail": "\n".join(lines).replace("\n", "\n       "),
        "inventory": inventory,
    }


# ============================================================ 渲染

SEV_CN = {"HIGH": "严重", "MEDIUM": "中", "PASS": "通过", "WARN": "注意",
          "SKIPPED": "未测", "INFO": "提示"}


def wrap(s, w=64):
    out, cur = [], ""
    for ch in str(s):
        if len(cur) >= w:
            out.append(cur)
            cur = ""
        cur += ch
    if cur:
        out.append(cur)
    return out or [""]


def render_text(checks, base):
    L = ["=" * 70,
         "外联白名单 & agent 提权面审计（G1 类 · Day 6新增）",
         "目标: %s" % base,
         "=" * 70]
    for c in checks:
        mark = {"FAIL": "[FAIL]", "PASS": "[ OK ]", "WARN": "[WARN]",
                "SKIPPED": "[SKIP]", "INFO": "[INFO]"}.get(c["status"], "[?]")
        L.append("")
        L.append("%s %s  %s" % (mark, c["id"], c["title"]))
        L.append("       状态: %s   严重度: %s"
                 % (c["status"], SEV_CN.get(c["severity"], "-")))
        for x in wrap(c["detail"]):
            L.append("       " + x)
        if c.get("note"):
            for x in wrap(c["note"]):
                L.append("       · " + x)
    L.append("")
    L.append("-" * 70)
    cnt = {}
    for c in checks:
        cnt[c["status"]] = cnt.get(c["status"], 0) + 1
    L.append("合计: FAIL %d | PASS %d | WARN %d | SKIPPED %d"
             % (cnt.get("FAIL", 0), cnt.get("PASS", 0),
                cnt.get("WARN", 0), cnt.get("SKIPPED", 0)))
    L.append("=" * 70)
    return "\n".join(L)


def main():
    import argparse
    ap = argparse.ArgumentParser(
        description="外联白名单/agent 提权面/组合链审计")
    ap.add_argument("url", help="目标站点或 MCP 端点")
    ap.add_argument("--deep", action="store_true", help="扩大出站配置探测面")
    ap.add_argument("--servers", help="MCP 服务器清单 JSON，"
                                       '形如 [{"name":"git","tools":["git_add",...]}]')
    ap.add_argument("--json", help="输出 JSON 到指定路径（供多靶场聚合）")
    args = ap.parse_args()

    base = derive_base(args.url)
    # ⚠ 三个检查函数返回的是**单个 dict**，不是 list ——
    #   渲染层按 list 迭代，直接 append 会得到 dict 的 list 而崩。
    checks = [
        check_egress_whitelist(base, deep=args.deep),
        check_self_modify(base),
        check_exfil_shapes(base),
    ]

    if args.servers:
        try:
            servers = json.loads(args.servers)
        except Exception as e:
            print("!! --servers JSON 解析失败: %s" % e, file=sys.stderr)
            servers = []
        checks.append(check_combo_chains(servers))
    else:
        checks.append(check_combo_chains([]))

    if args.json:
        # ⚠ 必须剥掉 render 前不可序列化的字段（inventory 里都是原生类型，
        #   但保守起见用 default=str 兜住自定义对象）。
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump({"target": base, "checks": checks},
                      f, ensure_ascii=False, indent=2, default=str)
        print("JSON 已写入: %s" % args.json)

    print(render_text(checks, base))
    return 1 if any(c["status"] == "FAIL" for c in checks) else 0


if __name__ == "__main__":
    sys.exit(main())