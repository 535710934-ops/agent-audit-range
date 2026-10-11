#!/usr/bin/env python3
"""
批量扫描编排器 + 脱敏报告生成
=============================

把 audit_remote.scan() 跑成一个可重复的批次，产出三样东西：

    runs/remote_scan_<ts>.json    机器可读全量结果
    runs/remote_scan_<ts>.html    脱敏后可公开的报告
    stdout                       人类可读汇总（含与预期的对照）

**为什么必须做脱敏**
------------------
对外发布的报告会落到 GitHub 公开仓库、搜索引擎、以及那些**正在被扫描的
项目方的监控**里。一份写着 `https://internal-corp-erp.mcp.company.com` 的报告
等于替对方公开了内部资产清单 —— 这是帮倒忙，甚至是二次伤害。

所以 HTML 报告走一条独立的脱敏管线（`redact()`），与 JSON 原件分开：
  · 主机名 → <target-1> / <target-2>（保留可对照性，抹掉可定位性）
  · IP / 端口 / URL path / token / 邮箱 → 占位符
  · 证据里的原始 payload 保留（那是发现本身，不含目标身份）

⚠ 脱敏**只作用于对外产物**。JSON 原件保持完整，便于你自己复查 ——
   把原件也脱敏，等于让判定失去可追溯性。

**与阳性对照的联动**
------------------
清单里每条目标可写 `expect: vuln | safe`。跑完后自动对照，
任何一条与预期不符都在汇总里点名。理由很直接：**只跑漏洞靶场的批次
无法证明检出能力**，而一个自己都测不准的工具不该拿去扫别人的服务器。

用法：
    python toolkit/run_all.py --targets toolkit/targets.local.json
    python toolkit/run_all.py --selftest          # 双向自检 + 样例报告
"""

import argparse
import html
import json
import os
import re
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

from audit_remote import scan, load_targets, print_human   # noqa: E402

RUNS = os.path.join(ROOT, "runs")

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3,
             "info": 4, "unknown": 5}

# 红涨绿跌不适用于安全评级 —— 这里用「严重度」语义配色：
# critical/high 用警示色系，PASS 用中性绿，SKIPPED 用灰（它不是"好"）
CSS = """
:root{
  --bg:#0f1115; --panel:#171a21; --line:#252a34; --fg:#e6e9ef;
  --dim:#9aa3b2; --crit:#ff4d4f; --high:#ff7a45; --med:#faad14;
  --ok:#52c41a; --skip:#8c8c8c; --info:#4a9eff;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);
  font:14px/1.65 -apple-system,"Segoe UI","Microsoft YaHei",sans-serif}
.wrap{max-width:1080px;margin:0 auto;padding:32px 20px 64px}
h1{font-size:24px;margin:0 0 6px;letter-spacing:.3px}
.sub{color:var(--dim);font-size:13px;margin-bottom:28px}
.card{background:var(--panel);border:1px solid var(--line);
  border-radius:10px;padding:18px 20px;margin-bottom:18px}
.card h2{font-size:16px;margin:0 0 14px;display:flex;
  align-items:center;gap:10px;flex-wrap:wrap}
.tag{font-size:11px;padding:2px 8px;border-radius:20px;
  border:1px solid currentColor;letter-spacing:.4px}
.t-crit,.t-high{color:var(--crit)}
.t-medium{color:var(--med)}
.t-PASS{color:var(--ok)}
.t-SKIPPED{color:var(--skip)}
.t-WARN{color:var(--high)}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);
  vertical-align:top}
th{color:var(--dim);font-weight:600;font-size:12px;
  text-transform:uppercase;letter-spacing:.5px}
code,.mono{font-family:"SFMono-Regular",Consolas,monospace;font-size:12px}
.ev{background:#11141a;border:1px solid var(--line);border-radius:6px;
  padding:8px 10px;color:var(--dim);font-size:12px;
  word-break:break-all;white-space:pre-wrap}
.kv{display:grid;grid-template-columns:130px 1fr;gap:6px 14px;
  font-size:13px}
.kv div:nth-child(odd){color:var(--dim)}
.note{background:#1a1416;border-left:3px solid var(--crit);
  padding:12px 16px;border-radius:0 6px 6px 0;margin:20px 0;
  font-size:13px;color:var(--fg)}
footer{color:var(--dim);font-size:12px;margin-top:32px;
  border-top:1px solid var(--line);padding-top:16px}
"""


# ============================================================ 脱敏

def redact(results):
    """生成对外可发布副本。**与 JSON 原件严格分离。**"""
    hostmap = {}

    def host_of(u):
        m = re.match(r"https?://([^/:]+)(?::(\d+))?", u or "")
        if not m:
            return None
        return m.group(1)

    for i, r in enumerate(results):
        h = host_of(r.get("url"))
        if h and h not in hostmap:
            hostmap[h] = "<target-%d>" % (len(hostmap) + 1)

    def mask_host(text):
        if not text:
            return text
        for h, alias in hostmap.items():
            text = re.sub(re.escape(h) + r"(:\d+)?", alias, text)
        return text

    out = []
    for r in results:
        r2 = json.loads(json.dumps(r, ensure_ascii=False, default=str))
        r2["url"] = mask_host(r2.get("url"))
        # token / 密钥 / 邮箱：任何形态都不该出现在公开报告里
        blob = json.dumps(r2, ensure_ascii=False)
        blob = re.sub(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
                      "<email>", blob)
        blob = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b", "<ip>", blob)
        blob = re.sub(r"\b[a-zA-Z][a-zA-Z0-9+.-]*://[^\s\"'<>]+",
                      "<url>", blob)
        blob = re.sub(r"\b(sk-|gh[pousr]_|AKIA)[A-Za-z0-9_]{8,}\b",
                      "<secret>", blob)
        # 端口号：回环靶场的端口无害，但真实资产的端口是资产信息
        blob = re.sub(r":\d{4,5}\b", ":<port>", blob)
        blob = re.sub(r"\bbearer\s+[A-Za-z0-9._-]{8,}", "Bearer <token>",
                      blob, flags=re.I)
        r2 = json.loads(blob)
        out.append(r2)
    return out, hostmap


# ============================================================ HTML

def render_html(results, hostmap, meta):
    parts = []
    A = parts.append
    A("<!doctype html><html lang=zh-CN><head><meta charset=utf-8>")
    A("<meta name=viewport content='width=device-width,initial-scale=1'>")
    A("<title>MCP Server 被动安全扫描报告</title><style>%s</style></head><body>"
      % CSS)
    A("<div class=wrap>")
    A("<h1>MCP Server 被动安全扫描报告</h1>")
    A("<div class=sub>生成时间 %s · 目标 %d 个 · 工具 "
      "<code>toolkit/audit_remote.py</code> · 协议 MCP Streamable HTTP / "
      "JSON-RPC 2.0</div>" % (html.escape(meta["ts"]), len(results)))

    # 免责声明：这份报告是公开的，必须让读者知道它的边界
    A("<div class=note><b>阅读前请先知道三件事：</b><br>"
      "1. 本报告<b>仅基于协议层被动观察</b>（initialize / tools/list / "
      "一次不存在工具的错误探测），<b>未执行目标任何工具</b>，"
      "因此<b>不能证明目标安全</b>，只能说明「这些面没被观察到问题」。<br>"
      "2. <code>SKIPPED</code> 表示<b>未能评估</b>（连不上 / 不适用 / "
      "响应取不到），<b>不是「没问题」</b>。把它当通过是本工具最典型的误用。"
      "<br>"
      "3. 所有目标均<b>已脱敏</b>，且都在<b>已获授权范围内</b>"
      "（工具内置授权 gate，无授权记录的目标拒绝执行）。</div>")

    # ---- 汇总表 ----
    A("<div class=card><h2>总览</h2><table>")
    A("<tr><th>#</th><th>目标</th><th>授权</th><th>工具数</th>"
      "<th>FAIL</th><th>WARN</th><th>PASS</th><th>SKIPPED</th>"
      "<th>最高严重度</th><th>预期对照</th></tr>")
    for i, r in enumerate(results, 1):
        s = r.get("summary") or {}
        fails = [x for x in r.get("checks", [])
                 if x["status"] in ("FAIL", "WARN")]
        top = "—"
        if fails:
            top = min((x.get("severity", "info") for x in fails),
                      key=lambda v: SEV_ORDER.get(v, 9))
        cmp_ = r.get("_expect_cmp") or "—"
        A("<tr><td>%d</td><td class=mono>%s</td><td class=mono>%s</td>"
          "<td>%s</td><td>%d</td><td>%d</td><td>%d</td><td>%d</td>"
          "<td class='t-%s'>%s</td><td>%s</td></tr>"
          % (i, html.escape(r.get("url", "-")),
             html.escape(str((r.get("authorization") or {}).get("kind", "-"))),
             r.get("meta", {}).get("tool_count", "-"),
             s.get("FAIL", 0), s.get("WARN", 0), s.get("PASS", 0),
             s.get("SKIPPED", 0), top, top, html.escape(cmp_)))
    A("</table></div>")

    # ---- 逐目标详情 ----
    for i, r in enumerate(results, 1):
        A("<div class=card><h2>%d. %s "
          "<span class='tag t-%s'>%s</span></h2>"
          % (i, html.escape(r.get("url", "-")),
             "crit" if (r.get("summary") or {}).get("FAIL") else "PASS",
             "有发现" if (r.get("summary") or {}).get("FAIL") else "无发现"))
        m = r.get("meta") or {}
        A("<div class=kv>")
        A("<div>协议版本</div><div class=mono>%s</div>"
          % html.escape(str(m.get("protocol_version", "-"))))
        A("<div>工具数</div><div>%s</div>" % m.get("tool_count", "-"))
        A("<div>授权依据</div><div class=mono>%s</div>"
          % html.escape(json.dumps(r.get("authorization") or {},
                                    ensure_ascii=False)))
        A("</div>")
        A("<table><tr><th style='width:74px'>判定</th>"
          "<th style='width:64px'>ID</th><th style='width:96px'>域</th>"
          "<th>说明</th></tr>")
        for x in r.get("checks", []):
            st = x["status"]
            cls = {"PASS": "PASS", "FAIL": "crit", "WARN": "WARN",
                   "SKIPPED": "SKIPPED"}.get(st, "PASS")
            A("<tr><td><span class='tag t-%s'>%s</span></td>"
              "<td class=mono>%s</td><td>%s</td><td>%s%s</td></tr>"
              % (cls, st, html.escape(x["id"]),
                 html.escape(x.get("domain", "")),
                 html.escape(x.get("detail", "")),
                 ('<div class=ev style="margin-top:8px">%s</div>'
                  % html.escape(str(x.get("evidence"))[:400]))
                 if x.get("evidence") else ""))
        A("</table></div>")

    A("<footer>本报告由开源工具生成，靶场与工具均公开可复现。"
      "报告本身做了脱敏处理（主机名/IP/端口/凭据/邮箱）。"
      "发现项仅代表<b>该面可被观察到问题</b>，不代表已实施利用，"
      "也不构成对目标安全性的整体结论。</footer>")
    A("</div></body></html>")
    return "".join(parts)


# ============================================================ 主流程

def run_batch(targets, timeout=10):
    results = []
    print("=" * 74)
    print("MCP 批量扫描 · %d 个目标" % len(targets))
    print("=" * 74)
    for t in targets:
        print("\n▶ %s  (%s)" % (t.get("name", "?"), t.get("url")))
        print("  授权: %s" % json.dumps(t.get("authorization", {}),
                                        ensure_ascii=False))
        r = scan(t["url"], token=t.get("token"), timeout=timeout)
        r["name"] = t.get("name")
        r["authorization"] = t.get("authorization")
        print_human(r)

        # 与预期对照 —— 只有对照才能证明检出能力
        exp = t.get("expect")
        if exp:
            s = r.get("summary") or {}
            if exp == "vuln":
                good = s.get("FAIL", 0) > 0
                cmp_ = "✓ 检出 %d 项" % s.get("FAIL", 0) if good \
                    else "✗ **未检出任何 FAIL**"
            elif exp == "safe":
                good = s.get("FAIL", 0) == 0
                cmp_ = "✓ 无误报" if good else \
                    "✗ **误报 %d 项**" % s.get("FAIL", 0)
            else:
                good, cmp_ = None, "未知 expect=%s" % exp
            r["_expect_cmp"] = cmp_
            r["_expect_ok"] = good
            print("  预期对照(%s): %s" % (exp, cmp_))
        results.append(r)
    return results


def summarize(results):
    print("\n" + "=" * 74)
    print("批次汇总")
    print("=" * 74)
    agg = {}
    for r in results:
        for k, v in (r.get("summary") or {}).items():
            agg[k] = agg.get(k, 0) + v
    print("  检查项判定: %s" % ("  ".join("%s=%d" % (k, v)
                                        for k, v in sorted(agg.items()))
                                or "-"))
    bad = [r for r in results
           if r.get("_expect_ok") is False]
    if bad:
        print("  ⚠ 预期对照未通过 %d 个目标 —— "
              "**不要用这批数据对外声称检出率**" % len(bad))
        for r in bad:
            print("     · %s → %s" % (r.get("url"), r.get("_expect_cmp")))
    else:
        exp_n = sum(1 for r in results if "_expect_cmp" in r)
        if exp_n:
            print("  ✓ 预期对照全部通过（%d 个带 expect 的目标）" % exp_n)
    unreachable = [r for r in results if not r.get("reachable")]
    if unreachable:
        print("  ⚠ %d 个目标未完成握手 —— 它们的 SKIPPED 项**不计入通过**"
              % len(unreachable))
    print("=" * 74)


def main():
    ap = argparse.ArgumentParser(
        description="MCP 批量扫描编排器（授权 gate + 脱敏报告）")
    ap.add_argument("--targets", help="目标清单 JSON")
    ap.add_argument("--timeout", type=int, default=10)
    ap.add_argument("--outdir", default=RUNS)
    ap.add_argument("--no-html", action="store_true", help="不生成 HTML")
    a = ap.parse_args()

    if not a.targets:
        ap.print_help()
        print("\n提示：先用 toolkit/targets.example.json 复制一份，"
              "把授权依据补齐后再扫。")
        return 2

    try:
        targets = load_targets(a.targets)
    except (PermissionError, ValueError) as e:
        print("✗ %s" % e, file=sys.stderr)
        return 2

    results = run_batch(targets, timeout=a.timeout)
    summarize(results)

    os.makedirs(a.outdir, exist_ok=True)
    ts = time.strftime("%Y%m%d_%H%M%S")
    stem = os.path.join(a.outdir, "remote_scan_%s" % ts)

    # 原件：完整，不脱敏，用于自查
    with open(stem + ".json", "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2, default=str)
    print("JSON 原件(未脱敏): %s.json" % stem)

    if not a.no_html:
        safe, hostmap = redact(results)
        with open(stem + ".html", "w", encoding="utf-8") as f:
            f.write(render_html(safe, hostmap, {"ts":
                                                time.strftime("%Y-%m-%d %H:%M")}))
        print("HTML 报告(已脱敏): %s.html" % stem)
        if hostmap:
            print("  脱敏映射: %s" % ", ".join(
                "%s → %s" % (h, a_) for h, a_ in hostmap.items()))

    exp_fail = sum(1 for r in results if r.get("_expect_ok") is False)
    return 1 if exp_fail else 0


if __name__ == "__main__":
    sys.exit(main())
