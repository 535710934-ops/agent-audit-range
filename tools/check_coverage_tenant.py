# -*- coding: utf-8 -*-
"""
Day 4 漏报核对表 —— 越权类检查覆盖率
===================================
沿用 Day 2 的做法：把靶场植入的缺陷与审计器实际检出逐一对照。
首轮若覆盖率 <100%，逐项归因修复，直到双向对照都成立。

判据比 Day 2 更严：**要求状态码与内容双向吻合**，
不接受「检查项存在」这种过松的判定。
"""
import io
import os
import subprocess
import sys

PY = sys.executable
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def run(url, a, b, la, lb):
    #⚠ 子进程会继承父进程环境里的代理变量 → 本机预设代理不通会导致全部超时，
    #    输出为空被误判成「检查项缺失」。必须在子进程环境中清除。
    env = dict(os.environ)
    for k in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy",
              "ALL_PROXY", "all_proxy"):
        env.pop(k, None)
    p = subprocess.run(
        [PY, os.path.join(ROOT, "tools", "audit_tenant.py"), url,
         "--token-a", a, "--token-b", b, "--label-a", la, "--label-b", lb],
        capture_output=True, text=True, timeout=90, env=env)
    if not p.stdout.strip():
        raise SystemExit("子进程无输出，请排查：\nSTDOUT:%s\nSTDERR:%s"
                         % (p.stdout[:300], p.stderr[:300]))
    return p.stdout


def parse(out):
    """从文本报告解析 {检查项ID: (status, detail)}

    ⚠⚠ 两版解析器bug（均导致**假通过**，比漏报更危险）：

    v1 手工 split：把「状态: FAIL 严重度:」当正文，状态被覆盖成"状态:"。
    v2 正则漏了 PASS 的实际写法 `[ OK ]`（OK ≠ PASS），**所有 PASS 项解析不到**。
    v3 正则漏了 `[` 之后的前导空格（只能吃标记后的空格），
       于是 `[ OK ]` 不匹配而 `[FAIL]` 匹配 —— 症状是「只看得见失败的项」。

    三版全部表现为「反向对照 0 FAIL」这个**看似完美的假通过**。
    ⇒ 沉淀：**判定通过前必须先断言判定器确实看见了预期数量的项。**
    本函数末尾强制做数量断言，解析不到就抛出，而不是安静地返回空 dict。
    """
    import re
    res = {}
    # ⚠ 实际输出里 PASS 的标记是 `[ OK ]`。
    #   v3 bug：`\[(FAIL|...)\s*\]` 漏掉了 `[` **之后**的前导空格 ——
    #   而 `\s*` 只能吃掉标记**之后**的空格。两种写法混用时
    #   `[ OK ]` 匹配失败、[FAIL] 成功，症状是「只看得见失败的项」。
    #   正解：`\[\s*(...)\s*\]` 前后都要留\s*。
    pat = re.compile(r"^\[\s*(FAIL|PASS|WARN|SKIP|OK)\s*\]\s+"
                     r"(B\d{2})\s+(.*)$")
    norm = {"FAIL": "FAIL", "PASS": "PASS", "WARN": "WARN",
            "SKIP": "SKIPPED", "OK": "PASS"}
    cur = None
    buf = []
    for line in out.splitlines():
        s = line.strip()
        m = pat.match(s)
        if m:
            if cur:
                res[cur] = (cur_st, " ".join(buf).strip())
            cur_st, cur, _ = norm[m.group(1)], m.group(2), m.group(3)
            buf = []
        elif cur is not None and s and not s.startswith("状态:"):
            buf.append(s)
    if cur:
        res[cur] = (cur_st, " ".join(buf).strip())

    # —— 防假通过断言 ——
    if len(res) < 5:
        raise SystemExit(
            "解析器只认出 %d 个检查项（预期 ≥5）。报告输出：\n%s\n"
            "判定器没看见东西时，「0 个 FAIL」是假通过，必须修判定器而非改结论。"
            % (len(res), out[:600]))
    return res


# ===== 靶场植入的 6 类缺陷（T1–T6）+ 调试端点 =====
# 每条 = (缺陷ID, 期望被哪项检查抓到, 必须出现的证据关键词)
PLANTED = [
    ("T1", "B01", "越权读取", "BOLA get_order 未校验订单归属"),
    ("T2", "B02", "tenant=B", "search_customers 未按租户过滤"),
    ("T3", "B03", "delete_order", "delete_order 无角色校验"),
    ("T4", "B03", "提权", "update_user_role 普通用户自提权"),
    ("T5", "B04", "读到了", "会话命名空间未按身份隔离"),
    ("T6", "B02", "tenant=B", "list_invoices IDOR（B01 路径外）"),
]

A = "alice-token-aaa111"
B = "bob-token-bbb222"

print("=" * 72)
print("Day 4 漏报核对表 · 越权类检查")
print("=" * 72)

# ---------------- 阳性对照 ----------------
print("\n【阳性对照】漏洞版靶场 (9003) —— 应当全部命中")
vuln = parse(run("http://127.0.0.1:9003/mcp", A, B, "Alice", "Bob"))
hit = 0
for pid, cid, kw, desc in PLANTED:
    st, detail = vuln.get(cid, ("<缺检查项>", ""))
    ok = (st == "FAIL") and (kw in detail)
    print("  %s %-4s → %-4s  %-34s [%s]" %
          ("PASS" if ok else "MISS", pid, cid, desc, st))
    if not ok and st == "FAIL":
        print("       ↳ 状态对但证据关键词 '%s' 未出现在报告里" % kw)
    hit += 1 if ok else 0
cov = hit / float(len(PLANTED)) * 100

# B05 调试端点单列
st5, d5 = vuln.get("B05", ("<缺>", ""))
ok5 = st5 == "FAIL" and "/debug/vars" in d5
print("  %s T7  → B05  调试端点未授权%s"
      % ("PASS" if ok5 else "MISS", " [%s]" % st5))
hit += 1 if ok5 else 0
total = len(PLANTED) + 1
cov = hit / float(total) * 100

print("\n  覆盖率: %d/%d = %.0f%%" % (hit, total, cov))

# ---------------- 反向对照 ----------------
print("\n【反向对照】干净版靶场 (9004) —— 必须 0 FAIL（误报即不可交付）")
safe = parse(run("http://127.0.0.1:9004/mcp", A, B, "Alice", "Bob"))
fp = [(cid, st) for cid, (st, _) in safe.items() if st == "FAIL"]
if fp:
    print("  FAIL 检出 %d 处误报：%s" % (len(fp), fp))
    for cid, _ in fp:
        print("       ↳ %s: %s" % (cid, safe[cid][1][:150]))
else:
    print("  PASS 5 项全部判PASS / 未误报")
n_skip = len([1 for _, (st, _) in safe.items() if st == "SKIPPED"])
n_pass = len([1 for _, (st, _) in safe.items() if st == "PASS"])
print("  明细: PASS %d | FAIL %d | SKIPPED %d" % (n_pass, len(fp), n_skip))

# ---------------- 结论 ----------------
print("\n" + "=" * 72)
if cov == 100 and not fp:
    print("结论：双向对照通过 —— 覆盖率 100%，无误报。可交付。")
    sys.exit(0)
elif cov == 100:
    print("结论：覆盖率 100% 但存在误报 —— 反向对照未过，**不可交付**。")
    sys.exit(1)
else:
    print("结论：覆盖率 %.0f%% < 100%% —— 存在漏报，需归因修复。" % cov)
    sys.exit(1)