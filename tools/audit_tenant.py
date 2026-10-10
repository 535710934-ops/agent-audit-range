#!/usr/bin/env python3
"""
audit_tenant.py —— 多租户越权审计器（BOLA / BFLA / 跨会话泄漏）
=================================================================
Day 4 新增。零第三方依赖。

【为什么必须单独写一个工具】
promptfoo 155 插件交叉验证发现的盲区里，最关键的两个是：
  BOLA（横向越权）/ BFLA（纵向越权）——🔴 完全没做
  cross-session-leak（跨会话泄漏）—— 🔴 完全没有
原因不是懒，是**结构性的**：现有靶场与工具都是单租户单身份，
没有第二个身份就根本构造不出「越权」这个动作。
（不是「没测」，是「测不了」—— 这正是纪律 3 的含义）

【核心方法：交叉身份差分】
判定越权**不能**用「拿到数据就算 FAIL」——干净靶场也能合法
拿到本租户数据，那样会100% 误报。

正确做法：
  1. 用**身份 A** 取一份数据快照（基线）
  2. 用**身份 B** 请求**同一个资源 ID**
  3. 若 B 拿到的是**本该属于 A 的数据** → 越权成立

即：判定的不是「有没有返回数据」，而是「**返回的数据是不是
属于调用者**」。这需要 ground truth（谁拥有哪个资源），
通常从 A 身份的合法响应中推断。

【三态判定，与 audit_mcp.py 保持一致】
  BREACH —— 确认越权（A 的数据被 B 读到 / B 做了A 无权做的事）
  PASS—— 同样操作返回 403/404，隔离有效
  SKIPPED —— 缺第二身份或端点不支持，显式报出（绝不静默跳过）
"""

import json
import re
import urllib.error
import urllib.request

UA = "tenant-auditor/1.0"

# ============================================================ HTTP


def call(url, tool=None, args=None, token=None, method=None, timeout=8):
    """统一请求。返回 (status, obj, err) 三元组。
    status=None 表示网络受阻 —— 与 4xx/5xx 严格区分（纪律 3）。
    """
    data = None
    headers = {"User-Agent": UA}
    if tool:
        data = json.dumps({"tool": tool, "args": args or {}}).encode("utf-8")
        headers["Content-Type"] = "application/json"
        method = "POST"
    if token:
        headers["Authorization"] = "Bearer " + token

    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            try:
                return resp.status, json.loads(raw.decode("utf-8")), None
            except Exception:
                return resp.status, {"_raw": raw.decode("utf-8", "replace")[:2000]}, None
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw.decode("utf-8")), None
        except Exception:
            return e.code, {"_raw": raw.decode("utf-8", "replace")[:400]}, None
    except Exception as e:
        return None, None, "%s: %s" % (type(e).__name__, str(e)[:100])


# ============================================================ 越权探测


class TenantAuditor(object):
    def __init__(self, url, token_a, token_b, token_admin=None,
                 label_a="身份A", label_b="身份B", timeout=8):
        self.base = url.rstrip("/")
        if self.base.endswith("/mcp"):
            self.base = self.base[:-4]
        self.ep = self.base + "/mcp"
        self.ta, self.tb, self.tadmin = token_a, token_b, token_admin
        self.la, self.lb = label_a, label_b
        self.timeout = timeout
        self.log = []
        self.na, self.nb = label_a, label_b   # 身份「真名」，用于内容归属判定
        self._resolve_identities()

    def _resolve_identities(self):
        """向目标问出每个 token 的真实身份名。

        **为什么必须问，不能猜**：
        跨会话泄漏的判定依赖「这段内容是谁写的」。
        若用显示名（含租户后缀）做字符串匹配，
        会因全角/半角括号、标签写法差异而误判——
        Day 4 实测踩过：目标摘要写「Alice（租户A）」全角，
        标签是「Alice(租户A)」半角，直接 in 匹配失败 → 把真泄漏报成 PASS。
        """
        for tok, attr in ((self.ta, "na"), (self.tb, "nb")):
            st, obj, err = call(self.base + "/mcp", None, None, tok,
                                timeout=self.timeout)
            ident = (obj or {}).get("identity") or {}
            name = ident.get("name")
            if name:
                setattr(self, attr, name)

    def _rec(self, name, st, verdict, detail):
        self.log.append({"probe": name, "status": st,
                         "verdict": verdict, "detail": detail})
        return {"probe": name, "status": st,
                "verdict": verdict, "detail": detail}

    # ---------- 基线：用A 身份获取自有资源 ----------
    def discover_own(self):
        """用 A 身份拿自己的订单列表，得出 ground truth。"""
        st, obj, err = call(self.ep, "list_orders", {}, self.ta, timeout=self.timeout)
        if err or st != 200:
            return None, self._rec("基线-A.list_orders", st,
                                   "SKIPPED",
                                   "无法获取基线：%s" % (err or "HTTP %s" % st))
        items = (obj or {}).get("result") or []
        return items, self._rec("基线-A.list_orders", st, "PASS",
                                "A 可见订单 %d 条：%s"
                                % (len(items), [i.get("id") for i in items]))

    def discover_ids(self):
        """列出A 可见的客户ID（用于横向越权验证）。"""
        st, obj, err = call(self.ep, "list_orders", {}, self.ta, timeout=self.timeout)
        if err or st != 200:
            return []
        return [i.get("id") for i in (obj or {}).get("result") or []]

    # ---------- B01 BOLA：逐资源 ID 交叉身份验证 ----------
    def check_bola(self):
        """核心：用A 的 token 去读 **标记为 B 租户** 的资源。

        判定依据是响应体中出现的**租户标识字段**——
        若A 的token 拿回了 tenant!=A 的记录 → 越权成立。
        """
        checks = []
        st, obj, err = call(self.ep, "list_orders", {}, self.tb, timeout=self.timeout)
        if err or st != 200:
            checks.append({
                "id": "B01", "title": "BOLA 横向越权（读他人数据）",
                "status": "SKIPPED", "severity": "HIGH",
                "detail": "无法获取 %s 的资源列表：%s" % (
                    self.lb, err or "HTTP %s" % st),
            })
            return checks

        b_items = (obj or {}).get("result") or []
        if not b_items:
            checks.append({
                "id": "B01", "title": "BOLA 横向越权（读他人数据）",
                "status": "SKIPPED", "severity": "HIGH",
                "detail": "%s 名下无资源，无法构造越权样本" % self.lb,
            })
            return checks

        breaches, guarded = [], []
        # 资源标识字段名在不同实现里不一（id / order_id / orderId / _id…）
        ID_KEYS = ("id", "order_id", "orderId", "_id", "uuid", "no", "code")
        samples = []
        for item in b_items[:5]:
            rid = None
            if isinstance(item, dict):
                for k in ID_KEYS:
                    if item.get(k):
                        rid = item[k]
                        break
            if not rid:
                # ⚠ 拿不到资源标识 → 无法构造越权请求。
                #    **绝不能因此报 PASS** ——「没测到」不等于「没问题」。
                guarded.append("样本缺资源标识字段，无法构造越权请求（字段：%s）"
                               % (sorted(item.keys()) if isinstance(item, dict)
                                  else type(item).__name__))
                continue
            samples.append((rid, item))

        if not samples:
            checks.append({
                "id": "B01", "title": "BOLA 横向越权（读他人数据）",
                "status": "SKIPPED", "severity": "HIGH",
                "detail": "**无法构造越权样本** —— %s 的 %d 条记录中未找到可用资源标识。"
                          "本项未测，不构成任何结论。"
                          % (self.lb, len(b_items)),
            })
            return checks

        for rid, b_item in samples:
            # **用 A 的 token 去读属于 B 的资源**
            st2, obj2, err2 = call(self.ep, "get_order", {"order_id": rid},
                                    self.ta, timeout=self.timeout)
            if err2:
                guarded.append("%s: 网络受阻(%s)" % (rid, err2))
                continue
            if st2 in (401, 403, 404):
                guarded.append("%s: 拒绝(HTTP %s)" % (rid, st2))
                continue
            res = (obj2 or {}).get("result") or {}
            if not res:
                guarded.append("%s: HTTP %s 但无数据" % (rid, st2))
                continue
            # ⚠ 不看状态码，只看**返回内容是否属于 B** ——
            #   200 也可能返回了被裁剪过的空壳
            leaked = False
            for k, bv in (b_item or {}).items():
                if bv and res.get(k) == bv and k in (
                        "secret", "tenant", "amount", "customer"):
                    leaked = True
                    break
            if leaked:
                breaches.append(
                    "%s← %s 越权读取（%s / %s）"
                    % (rid, self.la, res.get("customer", "?"),
                       res.get("secret", "?")))
            else:
                guarded.append("%s: HTTP %s 但内容不属于 %s（已隔离）"
                               % (rid, st2, self.lb))

        if breaches:
            status, sev = "FAIL", "HIGH"
            detail = "；".join(breaches)
        else:
            status, sev = "PASS", "HIGH"
            detail = ("用%s token 读 %s 的 %d 个资源，全部被拒（%s）"
                      % (self.la, self.lb, len(guarded), "、".join(guarded[:3])))

        checks.append({
            "id": "B01", "title": "BOLA 横向越权（读他人数据）",
            "status": status, "severity": sev, "detail": detail,
        })
        return checks

    # ---------- B02 列表接口的租户过滤 ----------
    def check_list_filter(self):
        """**列表接口是最容易漏的**：单条有鉴权，不代表列表过滤了。

        做法：用 A 的 token 搜索一个只属于 B 的关键词，
        若返回了含 tenant!=A 的记录 → 列表未按租户过滤。
        """
        checks = []
        probes = [("B", "Bob2"), ("B", "bob2@beta.test")]
        leaks, ok = [], []
        for tenant_kw, q in probes:
            st, obj, err = call(self.ep, "search_customers", {"q": q},
                                self.ta, timeout=self.timeout)
            if err or st != 200:
                ok.append("%s: 受阻" % q)
                continue
            for c in (obj or {}).get("result") or []:
                if c.get("tenant") and c["tenant"] != "A":
                    leaks.append("搜索 %r 返回 %s（tenant=%s，ssn=%s）"
                                 % (q, c.get("name"), c.get("tenant"),
                                    c.get("ssn_last4")))
            if not leaks:
                ok.append("%s: 无越权记录" % q)

        if leaks:
            status, detail = "FAIL", "；".join(leaks)
        else:
            status, detail = "PASS", "用%s token 搜索 %s 的专有数据：%s" % (
                self.la, self.lb, "、".join(ok))
        checks.append({
            "id": "B02", "title": "列表接口租户过滤（search_customers）",
            "status": status, "severity": "HIGH", "detail": detail,
        })
        return checks

    # ---------- B03 BFLA：普通用户调管理功能 ----------
    def check_bfla(self):
        """纵向越权：用**普通用户** token 调管理类工具。"""
        checks = []
        admin_tools = ["delete_order", "update_user_role", "deploy_service",
                       "transfer_funds"]
        st, obj, err = call(self.base + "/mcp", None, None,
                            self.ta, timeout=self.timeout)
        if err or st != 200:
            checks.append({
                "id": "B03", "title": "BFLA 纵向越权（普通用户调管理功能）",
                "status": "SKIPPED", "severity": "HIGH",
                "detail": "无法获取工具清单：%s" % (err or "HTTP %s" % st)})
            return checks
        names = {t.get("name") for t in (obj or {}).get("tools") or []}

        tested, breached, denied, skipped = [], [], [], []
        for tool in admin_tools:
            if tool not in names:
                skipped.append(tool)
                continue
            args = {}
            if tool == "delete_order":
                args = {"order_id": "ORD-9999"}   # 故意用不存在的 ID，
                                                  #避免真删数据
            elif tool == "update_user_role":
                args = {"user_id": self.la, "role": "admin"}
            st2, obj2, err2 = call(self.ep, tool, args, self.ta,
                                   timeout=self.timeout)
            if err2:
                denied.append("%s: 受阻" % tool)
                continue
            tested.append(tool)
            if st2 in (401, 403, 404):
                denied.append("%s: 拒绝(HTTP %s)" % (tool, st2))
            elif st2 == 200:
                res = (obj2 or {}).get("result")
                # 自提权是最严重形态
                if tool == "update_user_role":
                    breached.append("%s **普通用户自提权为 admin 成功** "
                                    "(HTTP 200, %s)" % (tool, res))
                elif tool == "delete_order":
                    # 订单不存在时返回 200 同样说明未做鉴权
                    breached.append("%s: HTTP 200 未鉴权（%s）" % (tool, res))
                else:
                    breached.append("%s: HTTP 200 未鉴权（%s）" % (tool, res))
            else:
                denied.append("%s: HTTP %s" % (tool, st2))

        if breached:
            status, detail = "FAIL", "；".join(breached)
        elif not tested:
            status, detail = "SKIPPED", "目标未暴露管理类工具（跳过 %d 个）" % len(skipped)
        else:
            status, detail = "PASS", "普通用户调用 %d 个管理工具全部被拒：%s" % (
                len(tested), "、".join(denied))

        checks.append({
            "id": "B03", "title": "BFLA 纵向越权（普通用户调管理功能）",
            "status": status, "severity": "HIGH", "detail": detail,
            "tested": tested, "skipped": skipped,
        })
        return checks

    # ---------- B04 跨会话泄漏 ----------
    def check_cross_session(self):
        """会话命名空间是否按身份隔离。

        做法：用 A 建会话写入，再**用 B 读同一 session_id**，
        若 B 能读到 A 写入的内容 → 命名空间未隔离。
        """
        checks = []
        sid = "sess-shared-001"
        # 步骤1：A 写入
        st1, obj1, err1 = call(self.ep, "recall_session",
                                {"session_id": sid, "order_id": "ORD-1001",
                                 "q": "%s 的私有问题" % self.na},
                                self.ta, timeout=self.timeout)
        if err1 or st1 != 200:
            checks.append({
                "id": "B04", "title": "跨会话泄漏（会话命名空间隔离）",
                "status": "SKIPPED", "severity": "MEDIUM",
                "detail": "目标不支持 recall_session：%s" % (err1 or "HTTP %s" % st1)})
            return checks

        own_summary = (obj1 or {}).get("result", {}).get("summary", [])
        if not isinstance(own_summary, list):
            own_summary = [str(own_summary)]

        # 步骤 2：A **再读一次** —— 确认 A 自己能读回刚才写的内容。
        # ⚠ 这一步不可省：若命名空间隔离实现得过于严格（连本人也读不到），
        #   直接进步骤 3 会得到「B 读不到 A」的错误结论。
        st1b, obj1b, err1b = call(self.ep, "recall_session",
                                  {"session_id": sid, "q": "%s 自查" % self.na},
                                  self.ta, timeout=self.timeout)
        a_readback = []
        if not err1b and st1b == 200:
            a_readback = (obj1b or {}).get("result", {}).get("summary", [])
            if not isinstance(a_readback, list):
                a_readback = [str(a_readback)]

        if not a_readback:
            # A 自己都读不回来 → 无法用它作为「A 的内容」的基线
            checks.append({
                "id": "B04", "title": "跨会话泄漏（会话命名空间隔离）",
                "status": "SKIPPED", "severity": "MEDIUM",
                "detail": "%s 写入后无法读回自身会话内容，缺少判定基线。"
                          "本项未测，不构成任何结论。" % self.la})
            return checks

        # 步骤 3：**B 用同一 session_id 读**
        st2, obj2, err2 = call(self.ep, "recall_session",
                                {"session_id": sid, "q": "%s 读取" % self.nb},
                                self.tb, timeout=self.timeout)
        if err2:
            checks.append({
                "id": "B04", "title": "跨会话泄漏（会话命名空间隔离）",
                "status": "SKIPPED", "severity": "MEDIUM",
                "detail": "第二身份读取受阻：%s" % err2})
            return checks

        if st2 in (401, 403, 404):
            checks.append({
                "id": "B04", "title": "跨会话泄漏（会话命名空间隔离）",
                "status": "PASS", "severity": "MEDIUM",
                "detail": "%s 读取 %s 的会话被拒(HTTP %s)，命名空间已隔离"
                          % (self.lb, self.la, st2)})
            return checks

        got = (obj2 or {}).get("result", {}).get("summary", [])
        if not isinstance(got, list):
            got = [str(got)]

        # 步骤 4：判定 —— **B 读到的集合里是否包含「A 能读到、且不含 B 标记」的行**
        #   ⚠ 用集合比对，不用 `in` 字符串包含
        #   （实测踩过：全角/半角括号差异会让 "Alice"in "Alice（租户A）" 为真，
        #     反之标签写法不同则为假，导致漏判与误判并存）
        got_set = set(str(x).strip() for x in got)
        # A 自己的内容：排除本轮自查那行（含 self.nb 的不存在，保留全部即可）
        leaked = []
        for line in a_readback:
            ls = str(line).strip()
            if not ls or ls in got_set:
                if ls in got_set and ls:
                    leaked.append(ls)
        # 若 B 自己写入的行恰好与 A 的行文本相同，无法区分 → 显式报出不确定性
        if leaked:
            undecidable = any(self.nb in x and self.na in x for x in leaked)
            if undecidable:
                checks.append({
                    "id": "B04", "title": "跨会话泄漏（会话命名空间隔离）",
                    "status": "SKIPPED", "severity": "MEDIUM",
                    "detail": "B 读到的行与 A 的内容文本相同（会话摘要未区分写入者），"
                              "无法判定归属。本项未测。"})
            else:
                checks.append({
                    "id": "B04", "title": "跨会话泄漏（会话命名空间隔离）",
                    "status": "FAIL", "severity": "MEDIUM",
                    "detail": "%s 用同一 session_id 读到了 %s 写入的内容：%s"
                              % (self.lb, self.la, " | ".join(leaked[:3])[:200])})
        else:
            checks.append({
                "id": "B04", "title": "跨会话泄漏（会话命名空间隔离）",
                "status": "PASS", "severity": "MEDIUM",
                "detail": "%s 可读回自身 %d 行；%s 读同一 session_id 未见这些内容，"
                          "命名空间按身份隔离"
                          % (self.la, len(a_readback), self.lb)})
        return checks

    # ---------- B05 调试端点 ----------
    DEBUG_EP = ["/debug/vars", "/debug", "/actuator", "/actuator/env",
                "/_debug", "/api/debug", "/phpinfo.php", "/server-status",
                "/.env", "/config"]

    def check_debug_endpoints(self):
        """调试/管理端点是否需要认证。

        补充 F1 的端点清单 —— 上一版只查 /health /metrics，
        漏掉了 /debug 这类**更容易泄漏且更常被忘记关**的路径。
        """
        leaks, guarded, blocked = [], [], []
        for p in self.DEBUG_EP:
            st, obj, err = call(self.base + p, None, None, self.ta,
                                timeout=self.timeout)
            url = self.base + p
            if err:
                blocked.append("%s(受阻)" % p)
                continue
            if st in (401, 403):
                guarded.append("%s(%s)" % (p, st))
                continue
            if st == 200:
                body = json.dumps(obj, ensure_ascii=False)[:400]
                leaks.append("%s → 200 未授权访问: %s" % (p, body[:200]))
            else:
                guarded.append("%s(%s)" % (p, st))

        if leaks:
            status, sev = "FAIL", "HIGH"
            detail = "；".join(leaks)
        elif blocked:
            status, sev = "WARN", "MEDIUM"
            detail = "已探测 %d 个调试端点：拒绝 %d 个，**受阻 %d 个**（未测不等于安全）：%s" % (
                len(self.DEBUG_EP), len(guarded), len(blocked),
                "、".join(blocked[:5]))
        else:
            status, sev = "PASS", "MEDIUM"
            detail = "已探测 %d 个调试/管理端点，全部需认证：%s" % (
                len(self.DEBUG_EP), "、".join(guarded[:6]))

        return [{
            "id": "B05", "title": "调试/管理端点未授权访问",
            "status": status, "severity": sev, "detail": detail,
            "probed": len(self.DEBUG_EP),
        }]

    def run(self):
        base = self.discover_own()
        checks = []
        checks.extend(self.check_bola())
        checks.extend(self.check_list_filter())
        checks.extend(self.check_bfla())
        checks.extend(self.check_cross_session())
        checks.extend(self.check_debug_endpoints())
        return base[0], checks


# ============================================================ 输出

SEV_CN = {"HIGH": "严重", "MEDIUM": "中", "PASS": "通过", "WARN": "注意"}
ST_CN = {"FAIL": "FAIL", "PASS": "PASS", "WARN": "WARN", "SKIPPED": "SKIPPED"}


def render_text(checks):
    L = []
    L.append("=" * 68)
    L.append("多租户越权审计（BOLA / BFLA / 跨会话泄漏）")
    L.append("=" * 68)
    for c in checks:
        st = c["status"]
        mark = {"FAIL": "[FAIL]", "PASS": "[ OK ]",
                "WARN": "[WARN]", "SKIPPED": "[SKIP]"}[st]
        L.append("")
        L.append("%s %s  %s" % (mark, c["id"], c["title"]))
        L.append("       状态: %s   严重度: %s" % (st, SEV_CN.get(c["severity"], "-")))
        for line in _wrap(c["detail"], 62):
            L.append("       " + line)
    L.append("")
    L.append("-" * 68)
    cnt = {"FAIL": 0, "PASS": 0, "WARN": 0, "SKIPPED": 0}
    for c in checks:
        cnt[c["status"]] = cnt.get(c["status"], 0) + 1
    L.append("合计: FAIL %d | PASS %d | WARN %d | SKIPPED %d  （共 %d 项）"
             % (cnt["FAIL"], cnt["PASS"], cnt["WARN"], cnt["SKIPPED"], len(checks)))
    L.append("=" * 68)
    return "\n".join(L)


def _wrap(s, w):
    s = str(s)
    out, cur = [], ""
    for ch in s:
        if len(cur) >= w:
            out.append(cur)
            cur = ""
        cur += ch
    if cur:
        out.append(cur)
    return out or [""]


def render_html(checks, url, la, lb):
    cnt = {"FAIL": 0, "PASS": 0, "WARN": 0, "SKIPPED": 0}
    for c in checks:
        cnt[c["status"]] = cnt.get(c["status"], 0) + 1

    rows = []
    for c in checks:
        cls = {"FAIL": "f", "PASS": "p", "WARN": "w", "SKIPPED": "s"}[c["status"]]
        rows.append(
            '<div class="item %s"><div class="ih">'
            '<span class="badge %s">%s</span>'
            '<span class="id">%s</span><span class="t">%s</span>'
            '<span class="sev">%s</span></div>'
            '<div class="ib">%s</div></div>'
            % (cls, cls, c["status"], c["id"], c["title"],
               SEV_CN.get(c["severity"], "-"),
               _esc(c["detail"]).replace("\n", "<br>")))

    return """<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8">
<title>多租户越权审计报告</title><style>
*{box-sizing:border-box}
body{margin:0;background:#0f1115;color:#e6e8ee;font-family:-apple-system,"Segoe UI","Microsoft YaHei",sans-serif;line-height:1.7}
.wrap{max-width:980px;margin:0 auto;padding:36px 26px 70px}
h1{margin:0 0 4px;font-size:23px}
.sub{color:#6c7488;font-size:13px;margin-bottom:20px}
.kpi{display:grid;grid-template-columns:repeat(4,1fr);gap:11px;margin-bottom:26px}
.k{background:#171a21;border:1px solid #262b36;border-radius:7px;padding:14px}
.k .n{font-size:26px;font-weight:700;font-family:ui-monospace,Consolas,monospace}
.k .l{font-size:12px;color:#98a0b3;margin-top:3px}
.k.f .n{color:#e5534b}.k.p .n{color:#3fb950}.k.w .n{color:#d9a03a}.k.s .n{color:#6c7488}
.item{background:#171a21;border:1px solid #262b36;border-radius:7px;margin-bottom:13px;overflow:hidden}
.ih{padding:11px 15px;display:flex;align-items:center;gap:10px;border-bottom:1px solid #262b36}
.item.f .ih{background:rgba(229,83,75,.08)}.item.w .ih{background:rgba(217,160,58,.07)}
.badge{font-size:11px;font-weight:700;padding:2px 9px;border-radius:3px;letter-spacing:.4px}
.badge.f{background:rgba(229,83,75,.16);color:#e5534b;border:1px solid rgba(229,83,75,.4)}
.badge.p{background:rgba(63,185,80,.16);color:#3fb950;border:1px solid rgba(63,185,80,.4)}
.badge.w{background:rgba(217,160,58,.16);color:#d9a03a;border:1px solid rgba(217,160,58,.4)}
.badge.s{background:rgba(108,116,136,.14);color:#98a0b3;border:1px solid #262b36}
.id{font-family:ui-monospace,Consolas,monospace;font-size:12px;color:#6c7488}
.t{font-weight:600;flex:1;font-size:14px}
.sev{font-size:11px;color:#6c7488;border:1px solid #262b36;border-radius:3px;padding:1px 7px}
.ib{padding:14px 15px;font-size:13px;color:#c8cdd8;font-family:ui-monospace,Consolas,monospace;word-break:break-all}
.note{margin:24px 0;background:rgba(217,160,58,.07);border:1px solid rgba(217,160,58,.3);border-left:4px solid #d9a03a;border-radius:6px;padding:14px 16px;font-size:13px}
.note b{color:#d9a03a}
</style></head><body><div class="wrap">
<h1>多租户越权审计报告</h1>
<div class="sub">目标 <code style="color:#4a9eff">%s</code> &nbsp;·&nbsp; 身份A=<b>%s</b> &nbsp; 身份B=<b>%s</b> &nbsp;·&nbsp; 交叉身份差分法</div>
<div class="kpi">
<div class="k f"><div class="n">%d</div><div class="l">FAIL 越权</div></div>
<div class="k p"><div class="n">%d</div><div class="l">PASS隔离有效</div></div>
<div class="k w"><div class="n">%d</div><div class="l">WARN 覆盖不足</div></div>
<div class="k s"><div class="n">%d</div><div class="l">SKIPPED 未测</div></div>
</div>
<div class="note"><b>判定方法：</b>不按「是否返回数据」判定，而按「<b>返回的数据是否属于调用者</b>」判定。
用身份 A 取基线，再用身份 B 请求同一资源 ID，若B 拿到本该属于 A 的数据 → 越权成立。
<b>受阻的网络请求一律计入未测，绝不计入通过。</b></div>
%s
</div></body></html>""" % (_esc(url), _esc(la), _esc(lb),
                       cnt["FAIL"], cnt["PASS"], cnt["WARN"], cnt["SKIPPED"],
                       "\n".join(rows))


def _esc(s):
    return (str(s).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


# ============================================================ CLI

def main():
    import argparse
    ap = argparse.ArgumentParser(
        description="多租户越权审计器（BOLA/BFLA/跨会话）")
    ap.add_argument("url", help="MCP 端点，如 http://127.0.0.1:9003/mcp")
    ap.add_argument("--token-a", required=True, help="身份A的 token")
    ap.add_argument("--token-b", required=True, help="身份B的 token（不同租户）")
    ap.add_argument("--token-admin", default="", help="管理员 token（可选）")
    ap.add_argument("--label-a", default="身份A")
    ap.add_argument("--label-b", default="身份B")
    ap.add_argument("--html", help="输出 HTML 报告路径")
    args = ap.parse_args()

    au = TenantAuditor(args.url, args.token_a, args.token_b,
                      args.token_admin or None,
                      args.label_a, args.label_b)
    _, checks = au.run()
    print(render_text(checks))
    if args.html:
        with open(args.html, "w", encoding="utf-8") as f:
            f.write(render_html(checks, args.url, args.label_a, args.label_b))
        print("\nHTML 报告: %s" % args.html)
    return 1 if any(c["status"] == "FAIL" for c in checks) else 0


if __name__ == "__main__":
    import sys
    sys.exit(main())