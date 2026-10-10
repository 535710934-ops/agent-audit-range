#!/usr/bin/env python3
"""
check_service_principal.py —— 非人主体与平台级凭证审计（G2 类检查）
========================================================================
Day 5 新增。

【为什么这是最优先的一项】
三个 CVSS 9.x 的真实越权事件（Flowise 9.6 / ServiceNow 9.3 / Salesloft）
的共性不是「接口没校验」，而是**授权主体从具体用户被替换成平台级凭证**：
  - Flowise:  agent 运行时环境（$vars）越过 workspace 边界
  - ServiceNow: 全局共享静态密钥 `servicenowexternalagent`（所有实例相同）
  - Salesloft: 第三方应用 OAuth token，凭token 即授权，无 MFA

⇒ 在这三种情况下，B01/B02/B03 **全部会 PASS**：
   凭据合法、scope 合法、endpoint 合法、请求合法。
   本检查是对那一类「全绿但危险」场景的唯一补救。

【五项检查】
  G1  令牌共享性 —— 同一token 能否在多个「租户/环境」上通用
  G2  无MFA 直连 —— bearer token 能否直接当 API key 用
  G3  静态共享密钥探测 —— 已知常见默认/示例密钥
  G4  授权粒度 —— token能触及多少个对象（枚举放大）
  G5  actor 归属 —— 审计记录里是否只有非人主体

⚠ 三态判定，且**「测不了」必须显式报出** —— 本项多数场景需要
  真实多环境凭据，探测不到就报 SKIPPED，绝不报 PASS（纪律 3/9）。
"""

import json
import re
import urllib.error
import urllib.request

UA = "principal-auditor/1.0"

# 已知公开的默认/示例/硬编码密钥片段。
# 来源：真实 CVE 披露 + 各厂商公开文档。
# ⚠ 这些是**片段**而非完整密钥 —— 真实密钥通常以这些为前缀/包含这些。
KNOWN_STATIC_KEY_PATTERNS = [
    (r"servicenowexternalagent", "ServiceNow Now Assist 全局共享外部代理密钥",
     "CVE-2025-12420"),
    (r"(?i)^(sk|pk)-test-[A-Za-z0-9]{8,}", "OpenAI 测试密钥（sk-test- / pk-test-）", ""),
    (r"(?i)AKIA[0-9A-Z]{16}", "AWS Access Key ID（应为环境变量注入而非硬编码）", ""),
    (r"(?i)(sk_live|rk_live|pk_live)_[A-Za-z0-9]{10,}", "Stripe 正式密钥", ""),
    (r"(?i)gh[pousr]_[A-Za-z0-9]{20,}", "GitHub token（应为环境变量注入）", ""),
    (r"(?i)xox[baprs]-[A-Za-z0-9-]{10,}", "Slack token", ""),
    (r"(?i)(postgres|mysql|mongodb)://[^\s\"']{8,}", "数据库连接串", ""),
]

# 这些路径/字段名用于发现「非人主体」线索
SERVICE_PRINCIPAL_HINTS = [
    "service_account", "serviceaccount", "sa_", "svc_", "api_key", "apikey",
    "app_key", "client_secret", "integration", "integration_key", "bot_token",
    "machine_to_machine", "m2m", "connected_app", "system_user",
]


def _extract_stmt(txt, start, limit=2000):
    """从 start 处起做括号配平，提取一条完整语句（支持跨多行书写）。

    用于避免「按换行截断」把多行字典切断——实测踩过该坑。
    """
    depth = 1          # 调用本身已消耗一个左括号
    i = start
    end = min(len(txt), start + limit)
    while i < end:
        ch = txt[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return txt[start:i + 1]
        i += 1
    return txt[start:end]


def req(url, method="GET", headers=None, body=None, timeout=8):
    data = None
    h = {"User-Agent": UA}
    if headers:
        h.update(headers)
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        h["Content-Type"] = "application/json"
    r = urllib.request.Request(url, data=data, headers=h, method=method)
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            raw = resp.read()
            return resp.status, raw.decode("utf-8", "replace"), None
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace"), None
    except Exception as e:
        return None, "", "%s: %s" % (type(e).__name__, str(e)[:100])


class PrincipalAuditor(object):
    def __init__(self, url, token=None, tokens=None, source_dir=None, timeout=8):
        self.url = url.rstrip("/")
        if self.url.endswith("/mcp"):
            self.url = self.url[:-4]
        self.tokens = tokens or ([token] if token else [])
        self.source_dir = source_dir
        self.timeout = timeout

    # ---------- G1 令牌共享性 ----------
    def g1_token_shared(self):
        """**同一token 在多个端点是否通用** —— 服务账号的典型特征。

        需要多个环境 URL；若只给了一个 → SKIPPED（不猜）。
        """
        checks = []
        # 允许 --peer 参数形式：url1,url2,...
        peers = [u for u in getattr(self, "peer_urls", []) if u]
        if not peers:
            return [{
                "id": "G1", "title": "令牌共享性（跨环境通用）",
                "status": "SKIPPED", "severity": "HIGH",
                "detail": "未提供对照环境 URL，无法验证令牌是否跨环境通用。"
                          "**本项未测。** 服务账号/共享密钥的核心特征，"
                          "建议用两个环境复测。",
            }]
        if not self.tokens:
            return [{
                "id": "G1", "title": "令牌共享性（跨环境通用）",
                "status": "SKIPPED", "severity": "HIGH",
                "detail": "未提供 token，无法验证。**本项未测。**",
            }]

        tok = self.tokens[0]
        hdr = {"Authorization": "Bearer " + tok}
        results = []
        seen = set()
        for u in [self.url] + peers:
            # ⚠ 排除指向**同一主机**的"对照环境"——
            #   同一服务上的两个路径当然都通，那是必然结果，
            #   拿它判定"全局共享密钥"毫无意义（实测踩过这个误报）。
            host = re.sub(r"^https?://", "", u).rstrip("/")
            if host in seen:
                continue
            seen.add(host)
            st, _, err = req(u + "/mcp", headers=hdr, timeout=self.timeout)
            results.append((u, st, err))

        if len(results) < 2:
            return [{
                "id": "G1", "title": "令牌共享性（跨环境通用）",
                "status": "SKIPPED", "severity": "HIGH",
                "detail": "去重后仅有 %d 个不同主机，**不足以判定令牌是否跨环境通用**。"
                          "需要指向另一套部署（不同主机）的 --peer。"
                          "同一主机上的多个路径不算对照环境。" % len(results),
            }]
        ok_count = sum(1 for _, st, _ in results if st == 200)
        blocked = [u for u, st, e in results if st is None]
        if blocked:
            return [{
                "id": "G1", "title": "令牌共享性（跨环境通用）",
                "status": "SKIPPED", "severity": "HIGH",
                "detail": "网络受阻 %d/%d 个环境，**受阻不等于安全**：%s"
                          % (len(blocked), len(results),
                             "、".join(blocked))}]
        if ok_count == len(results) and len(results) > 1:
            return [{
                "id": "G1", "title": "令牌共享性（跨环境通用）",
                "status": "FAIL", "severity": "HIGH",
                "detail": "同一 token 在 %d/%d 个环境全部通过认证（HTTP 200）—— "
                          "疑似全局共享密钥而非租户级凭据"
                          "（参见 CVE-2025-12420：所有实例共用同一外部代理密钥）"
                          % (ok_count, len(results))}]
        return [{
            "id": "G1", "title": "令牌共享性（跨环境通用）",
            "status": "PASS", "severity": "HIGH",
            "detail": "同一 token 在 %d 个环境中 %d 个可用，未见全局共享特征"
                      % (len(results), ok_count)}]

    # ---------- G2 无 MFA 直连 ----------
    def g2_bearer_as_api_key(self):
        """bearer token 能否**直接**当 API key 用于管理面/数据面。

        这是 Salesloft UNC6395 的核心形态：凭 token 即授权，无 MFA、无用户交互。
        """
        if not self.tokens:
            return [{
                "id": "G2", "title": "凭 token 直连（无 MFA / 无用户交互）",
                "status": "SKIPPED", "severity": "HIGH",
                "detail": "未提供 token，**本项未测**。"}]
        tok = self.tokens[0]
        hdr = {"Authorization": "Bearer " + tok}
        paths = ["/api/v1/query", "/api/v1/export", "/admin", "/api/admin",
                 "/api/v1/bulk", "/graphql"]
        leaked, denied, blocked = [], [], []
        for p in paths:
            st, tx, err = req(self.url + p, headers=hdr, timeout=self.timeout)
            if err:
                blocked.append(p)
                continue
            if st == 200:
                leaked.append("%s → 200 未要求二次认证（%s）"
                              % (p, tx[:120].replace("\n", " ")))
            elif st in (401, 403):
                denied.append("%s(%s)" % (p, st))
            else:
                denied.append("%s(%s)" % (p, st))
        if leaked:
            return [{
                "id": "G2", "title": "凭 token 直连（无 MFA / 无用户交互）",
                "status": "FAIL", "severity": "HIGH",
                "detail": "；".join(leaked)}]
        if blocked and not denied:
            return [{
                "id": "G2", "title": "凭 token 直连（无 MFA / 无用户交互）",
                "status": "SKIPPED", "severity": "HIGH",
                "detail": "全部探测受阻，**未测不等于安全**"}]
        return [{
            "id": "G2", "title": "凭 token 直连（无 MFA / 无用户交互）",
            "status": "PASS", "severity": "HIGH",
            "detail": "已探测 %d 个敏感端点，bearer token 直连均被拒：%s"
                      % (len(denied), "、".join(denied[:5]))}]

    # ---------- G3 静态/硬编码密钥 ----------
    def g3_static_key(self):
        """扫描源码与常见配置位置里的硬编码平台级密钥。

        与部署层扫描器不同：这里查的是**平台级/高权限**密钥
        （能提权、能读全租户），而非任意 secret 字段。
        """
        checks = []
        if not self.source_dir or not os.path.isdir(self.source_dir):
            return [{
                "id": "G3", "title": "硬编码平台级/共享密钥",
                "status": "SKIPPED", "severity": "HIGH",
                "detail": "未提供 --repo 源码目录，**本项未测**。"}]
        hits, scanned = [], 0
        for root, _d, files in os.walk(self.source_dir):
            for fn in files:
                if not fn.endswith((".py", ".js", ".ts", ".go", ".java",
                                    ".json", ".yaml", ".yml", ".env", ".toml",
                                    ".ini", ".cfg", ".properties", ".xml")):
                    continue
                p = os.path.join(root, fn)
                try:
                    txt = open(p, "r", encoding="utf-8", errors="replace").read()
                except Exception:
                    continue
                scanned += 1
                for pat, desc, cve in KNOWN_STATIC_KEY_PATTERNS:
                    for m in re.finditer(pat, txt):
                        line_no = txt[:m.start()].count("\n") + 1
                        s = m.group(0)
                        masked = s[:6] + "***" + s[-2:] if len(s) > 10 else "***"
                        hits.append("%s:%d %s（值已掩码：%s）%s"
                                    % (os.path.relpath(p, self.source_dir),
                                       line_no, desc, masked,
                                       " [%s]" % cve if cve else ""))
        if hits:
            return [{
                "id": "G3", "title": "硬编码平台级/共享密钥",
                "status": "FAIL", "severity": "HIGH",
                "detail": "扫描 %d 个文件，发现 %d 处：%s"
                          % (scanned, len(hits), "；".join(hits[:5]))}]
        return [{
            "id": "G3", "title": "硬编码平台级/共享密钥",
            "status": "PASS", "severity": "HIGH",
            "detail": "扫描 %d 个文件，未命中已知平台级密钥模式。"
                      "⚠ 检测局限：只覆盖已知厂商格式，"
                      "自研系统的共享密钥**不在检测范围内**。" % scanned}]

    # ---------- G4 授权粒度 / 枚举放大 ----------
    def g4_grant_scope(self):
        """一个 token 能触及多少对象 —— 衡量越权半径。

        参照 Flowise CVE-2025-59434：单个免费账号读出 514 个全局变量。
        """
        if not self.tokens:
            return [{
                "id": "G4", "title": "授权粒度（单凭证越权半径）",
                "status": "SKIPPED", "severity": "HIGH",
                "detail": "未提供 token，**本项未测**。"}]
        tok = self.tokens[0]
        hdr = {"Authorization": "Bearer " + tok}
        st, tx, err = req(self.url + "/mcp", headers=hdr, timeout=self.timeout)
        if err:
            return [{
                "id": "G4", "title": "授权粒度（单凭证越权半径）",
                "status": "SKIPPED", "severity": "HIGH",
                "detail": "探测受阻：%s" % err}]
        if st != 200:
            return [{
                "id": "G4", "title": "授权粒度（单凭证越权半径）",
                "status": "PASS", "severity": "HIGH",
                "detail": "令牌不可用（HTTP %s），无越权半径可言" % st}]
        try:
            obj = json.loads(tx)
        except Exception:
            return [{
                "id": "G4", "title": "授权粒度（单凭证越权半径）",
                "status": "INFO", "severity": "MEDIUM",
                "detail": "响应非 JSON，无法量化工具/资源面（长度 %d）" % len(tx)}]
        tools = obj.get("tools") or []
        w = [t.get("name") for t in tools
             if re.search(r"(?i)(write|create|update|delete|drop|grant|"
                          r"execute|run|admin|deploy|transfer)", t.get("name") or "")]
        if len(tools) >= 10 or len(w) >= 5:
            return [{
                "id": "G4", "title": "授权粒度（单凭证越权半径）",
                "status": "FAIL", "severity": "MEDIUM",
                "detail": "单凭证可见工具 %d 个，其中写/管理类 %d 个：%s。"
                          "**agent 越权半径由其权限决定而非攻击者技能**"
                          "（参见 CVE-2025-12420 agentic amplification）"
                          % (len(tools), len(w), "、".join(w[:8]))}]
        return [{
            "id": "G4", "title": "授权粒度（单凭证越权半径）",
            "status": "PASS", "severity": "MEDIUM",
            "detail": "单凭证可见工具 %d 个（写/管理类 %d 个），未见过宽授权"
                      % (len(tools), len(w))}]

    # ---------- G5 actor 归属 ----------
    def g5_actor_attribution(self):
        """审计记录里是否只有**非人主体** —— 这类攻击唯一稳定的检出信号。

        Salesloft UNC6395 中，所有调用挂在 "Drift" 这个 App 身份下，
        无真实用户主体可追溯；ServiceNow 中动作记在被冒用用户名下。
        """
        checks = [{
            "id": "G5", "title": "审计记录 actor 归属（非人主体）",
            "status": "SKIPPED", "severity": "HIGH",
            "detail": "需源码或日志访问权（--repo / --log）才能判定。"
                      "**本项未测。** 这是平台级凭证类攻击"
                      "唯一稳定的检出信号，强烈建议实测。"}]
        # 若能从源码读审计结构则自动判定
        if not self.source_dir or not os.path.isdir(self.source_dir):
            return checks
        actor_f, trace_f = 0, 0
        scanned = 0
        # ⚠ 必须**行级**判定：只看文件里有没有 actor 字样会误判——
        #   实测踩过：漏洞版审计记录确实没写 actor，但工具返回体里恰好有
        #   {"user_id": ...}，被当成「已记录 actor」而误报 WARN。
        #   正确做法：找审计写入语句（append / audit_log.push 之类），
        #   只在**同一行/同一字典字面量**内查 actor 与 trace_id。
        AUDIT_WRITE = re.compile(
            r"(?i)(_?audit\w*\.append|audit_log\.\w+|logger\.\w+|log\.\w+)"
            r"\s*\(")
        ACTOR_RE = re.compile(
            r"(?i)[\"']\s*(actor|user_id|principal|subject|"
            r"on_behalf_of|caller)[\"']\s*:")
        TRACE_RE = re.compile(
            r"(?i)[\"']\s*(trace_id|request_id|correlation_id|span_id|"
            r"req_id)[\"']\s*:")

        for root, _d, files in os.walk(self.source_dir):
            for fn in files:
                if not fn.endswith((".py", ".js", ".ts", ".go")):
                    continue
                p = os.path.join(root, fn)
                try:
                    txt = open(p, "r", encoding="utf-8", errors="replace").read()
                except Exception:
                    continue
                if not AUDIT_WRITE.search(txt):
                    continue
                scanned += 1
                # 逐条审计写入语句，在其覆盖范围内查 actor/trace
                for m in AUDIT_WRITE.finditer(txt):
                    # ⚠ **不能用换行截断**：审计字典常跨多行书写
                    #   （实测踩过：干净版的 _audit.append({...}) 写了 4 行，
                    #   按 \n 截断后trace_id 被切掉→ 误报 WARN）。
                    #   正确做法：从写入点起做**括号配平**，取到语句真正结束。
                    stmt = _extract_stmt(txt, m.end())
                    if ACTOR_RE.search(stmt):
                        actor_f += 1
                    if TRACE_RE.search(stmt):
                        trace_f += 1
        if not scanned:
            checks[0] = {
                "id": "G5", "title": "审计记录 actor 归属（非人主体）",
                "status": "SKIPPED", "severity": "HIGH",
                "detail": "在 %s 下未找到审计写入语句（*.append/logger.*），"
                          "**本项未测**。平台级凭证类攻击"
                          "（如 Salesloft UNC6395）完全无法归因。"
                          % self.source_dir}
            return checks
        if actor_f == 0:
            checks[0] = {
                "id": "G5", "title": "审计记录 actor 归属（非人主体）",
                "status": "FAIL", "severity": "HIGH",
                "detail": "发现 %d 处审计写入语句，**无一处记录 actor/用户主体**。"
                          "平台级凭证类攻击（如 Salesloft UNC6395）"
                          "将完全无法归因——这是该类攻击唯一的稳定信号。"
                          % scanned}
        elif trace_f == 0:
            checks[0] = {
                "id": "G5", "title": "审计记录 actor 归属（非人主体）",
                "status": "WARN", "severity": "MEDIUM",
                "detail": "审计写入中已记录 actor（%d 处）但**缺 trace_id/request_id**，"
                          "无法把一次攻击的多个调用串成链。" % actor_f}
        else:
            checks[0] = {
                "id": "G5", "title": "审计记录 actor 归属（非人主体）",
                "status": "PASS", "severity": "HIGH",
                "detail": "审计写入含 actor（%d 处）与 trace_id（%d 处），"
                          "具备归因与串联能力" % (actor_f, trace_f)}
        return checks

    def run(self, peer_urls=None):
        self.peer_urls = peer_urls or []
        out = []
        out.extend(self.g1_token_shared())
        out.extend(self.g2_bearer_as_api_key())
        out.extend(self.g3_static_key())
        out.extend(self.g4_grant_scope())
        out.extend(self.g5_actor_attribution())
        return out


import os  # noqa: E402  (放在后面避免上方 docstring 解析问题)


# ============================================================ 输出

SEV_CN = {"HIGH": "严重", "MEDIUM": "中", "PASS": "通过", "WARN": "注意",
          "INFO": "提示"}


def render_text(checks):
    L = ["=" * 68,
         "非人主体与平台级凭证审计（G2 类 · Day 5 新增）",
         "=" * 68]
    for c in checks:
        mark = {"FAIL": "[FAIL]", "PASS": "[ OK ]", "WARN": "[WARN]",
                "SKIPPED": "[SKIP]", "INFO": "[INFO]"}.get(c["status"], "[?]")
        L.append("")
        L.append("%s %s  %s" % (mark, c["id"], c["title"]))
        L.append("       状态: %s   严重度: %s"
                 % (c["status"], SEV_CN.get(c["severity"], "-")))
        line, cur = [], ""
        for ch in str(c["detail"]):
            if len(cur) >= 62:
                line.append(cur)
                cur = ""
            cur += ch
        if cur:
            line.append(cur)
        for x in line or [""]:
            L.append("       " + x)
    L.append("")
    L.append("-" * 68)
    cnt = {}
    for c in checks:
        cnt[c["status"]] = cnt.get(c["status"], 0) + 1
    L.append("合计: FAIL %d | PASS %d | WARN %d | SKIPPED %d | INFO %d"
             % (cnt.get("FAIL", 0), cnt.get("PASS", 0), cnt.get("WARN", 0),
                cnt.get("SKIPPED", 0), cnt.get("INFO", 0)))
    L.append("提醒：SKIPPED 不等于安全。受阻的探测不构成任何结论。")
    L.append("=" * 68)
    return "\n".join(L)


def main():
    import argparse
    ap = argparse.ArgumentParser(
        description="非人主体与平台级凭证审计（G2 类）")
    ap.add_argument("url")
    ap.add_argument("--token", action="append", default=[],
                    help="可重复：用于验证令牌共享性")
    ap.add_argument("--peer", action="append", default=[],
                    help="对照环境 URL，用于验证跨环境通用")
    ap.add_argument("--repo", help="源码目录（用于硬编码密钥与 actor 归属）")
    ap.add_argument("--json", help="输出 JSON 到指定路径（供多靶场聚合）")
    args = ap.parse_args()

    au = PrincipalAuditor(args.url, tokens=args.token,
                          source_dir=args.repo)
    checks = au.run(peer_urls=args.peer)

    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump({"target": args.url, "checks": checks},
                      f, ensure_ascii=False, indent=2, default=str)
        print("JSON 已写入: %s" % args.json)

    print(render_text(checks))
    return 1 if any(c["status"] == "FAIL" for c in checks) else 0


if __name__ == "__main__":
    import sys
    sys.exit(main())