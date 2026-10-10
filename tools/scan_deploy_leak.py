#!/usr/bin/env python3
"""
部署层泄漏扫描器 (Deployment Leak Scanner)
==========================================

用途：检测公开 AI 项目站点上可被直接访问的敏感文件/路径。

原理：对目标站点发起 HEAD/GET 请求，检查是否返回 200 且含可利用内容。
纯被动检测 —— 不利用、不下载发现的敏感内容、不做任何破坏性操作。

合规红线：
  ✓ 只测公开可访问路径
  ✓ 发现敏感内容只报「存在性 + 路径」，不下载全文
  ✓ 单目标请求间隔 >= 200ms（礼貌爬取）
  ✗ 不做认证绕过、不做目录爆破、不做利用

用法：
  python scan_deploy_leak.py --url https://example.com
  python scan_deploy_leak.py --url https://example.com --deep
"""

import argparse
import json
import sys
import time
from urllib.parse import urljoin

import urllib.request
import urllib.error

# ---------------------------------------------------------------- 配置

# 高危：泄漏内部指令 / 密钥 / 记忆文件
HIGH_RISK_PATHS = [
    "/CLAUDE.md",
    "/AGENTS.md",
    "/.claude/CLAUDE.md",
    "/.codex/AGENTS.md",
    "/GEMINI.md",
    "/.cursorrules",
    "/.env",
    "/.env.local",
    "/.env.production",
    "/.env.development",
    "/config.json",
    "/config.yaml",
    # —— Day 6 补入：agent 可自改的权限配置 ——
    #  CVE-2025-53773（GitHub Copilot "YOLO mode"）正是通过写
    #  /.vscode/settings.json 的 chat.tools.autoApprove 关闭人工确认，
    #  再执行任意命令。这类配置是**提权面**，不是普通文件。
    "/.vscode/settings.json",
    "/.vscode/tasks.json",
    "/.vscode/launch.json",
    "/.mcp.json",
    "/.cursor/mcp.json",
    "/.claude/settings.json",
    "/.codex/config.toml",
]

# 中危：内部记录 / 状态文件
MEDIUM_RISK_PATHS = [
    "/memory/",
    "/memory/notes.md",
    "/notes/",
    "/data/",
    "/data/queue.json",
    "/prospects.csv",
    "/leads.csv",
    "/.git/config",
    "/package.json",
    "/requirements.txt",
    "/docker-compose.yml",
    "/Dockerfile",
]

# 特征串：命中即判定为「真泄漏」（而非 404 页面）
SIGNATURES = {
    "system-prompt": ["system prompt", "you are", "your role is", "instructions:"],
    "secrets": ["api_key", "apikey", "secret", "token", "password", "bearer "],
    "credentials-file": ["AKIA", "sk-", "ghp_", "-----BEGIN"],
    "memory-file": ["prospect", "lead", "queue", "todo", "follow-up", "跟进"],
    "internal-path": ["src/", "import ", "def ", "function ", "localhost:"],
}

# 白名单标记：命中这些说明是正常公开页面，不算泄漏
BENIGN_MARKERS = [
    "404", "not found", "page not found", "does not exist",
    "cannot be found", "index of /", "directory listing",
]

UA = "Mozilla/5.0 (compatible; DeployLeakAudit/1.0; passive-check)"
DELAY = 0.25  # 秒


# ---------------------------------------------------------------- 工具函数

def _get(url, timeout=10):
    """只取前 8KB —— 足以判定内容类型，且避免下载敏感全文。

    返回 (status, text, err)：
      status=200 且 body 非空 → 疑似泄漏
      status=其他 HTTP 码      → 确认不可达
      status=None            → **网络受阻**（ERR），与404 严格区分
    """
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(8192)
            return resp.status, body.decode("utf-8", errors="replace"), None
    except urllib.error.HTTPError as e:
        return e.code, "", None
    except Exception as e:
        # 网络层失败：DNS 拒绝 / 超时 / TLS 失败 / 被策略拦截
        return None, "", "%s: %s" % (type(e).__name__, str(e)[:120])


def _classify(text):
    """返回命中的特征标签列表。"""
    low = text.lower()
    hits = []
    for tag, needles in SIGNATURES.items():
        if any(n in low for n in needles):
            hits.append(tag)
    return hits


def _is_benign(text, status):
    """白名单：404 页面不算泄漏。"""
    if status == 404:
        return True
    low = text.lower()
    return any(m in low for m in BENIGN_MARKERS)


def _truncate(text, n=180):
    t = " ".join(text.split())
    return t[:n] + ("..." if len(t) > n else "")


# ---------------------------------------------------------------- 扫描主逻辑

def scan_base(url, paths, verbose=False):
    """扫描一组路径。

    三类结果严格区分：
      findings     → 可疑泄漏
      unreachable  → 确认不可达（404/403等）
      blocked      → 网络受阻（ERR），**覆盖度缺口**，必须报出
    """
    findings = []
    unreachable = []
    blocked = []
    total = len(paths)

    for i, p in enumerate(paths, 1):
        target = urljoin(url.rstrip("/") + "/", p.lstrip("/"))
        status, body, err = _get(target)

        # —— 类别 1：网络受阻（这不是"干净"，是"没测到"）
        if status is None:
            blocked.append({"path": p, "url": target, "error": err})
            if verbose:
                print(f"  [?] BLOCK  {p}  ({err})")
            if i < total:
                time.sleep(DELAY)
            continue

        # —— 类别 2：非200，但**错误响应体本身可能泄漏信息**
        # 关键：不能只查200。错误页/错误 JSON 常直接吐出栈、路径、连接串。
        if status != 200:
            err_leaks = []
            if body:
                for tag, needles in SIGNATURES.items():
                    if any(n in body.lower() for n in needles):
                        err_leaks.append(tag)
            if err_leaks:
                findings.append({
                    "path": p,
                    "url": target,
                    "status": status,
                    "severity": "HIGH",
                    "signatures": ["error-body-leak"] + err_leaks,
                    "bytes_sampled": len(body),
                    "evidence": _truncate(body),
                })
                if verbose:
                    print(f"  [!] HIGH   {p}  ({status}, **错误响应体泄漏** {err_leaks})")
            else:
                unreachable.append({"path": p, "url": target, "status": status})
                if verbose:
                    print(f"  [ ] ok     {p}  ({status})")
            if i < total:
                time.sleep(DELAY)
            continue

        # —— 类别 3：200，检查是否为 benign 404 页
        if not body or _is_benign(body, status):
            unreachable.append({"path": p, "url": target, "status": status})
            if verbose:
                print(f"  [ ] ok     {p}  ({status}, benign)")
            if i < total:
                time.sleep(DELAY)
            continue

        # —— 类别 4：200 + 有实质内容 → 可疑泄漏
        tags = _classify(body)
        severity = "HIGH" if tags else "MEDIUM"
        findings.append({
            "path": p,
            "url": target,
            "status": status,
            "severity": severity,
            "signatures": tags,
            "bytes_sampled": len(body),
            "evidence": _truncate(body),
        })
        if verbose:
            print(f"  [!] {severity:6s} {p}  ({status}, tags={tags or 'none'})")

        if i < total:
            time.sleep(DELAY)

    return findings, unreachable, blocked


def scan_dir_listing(url, verbose=False):
    """检查目录列表暴露。"""
    status, body, err = _get(url)
    if status == 200 and "index of" in body.lower():
        if verbose:
            print(f"  [!] HIGHdirectory listing at {url}")
        return [{
            "path": "/", "url": url, "status": status,
            "severity": "HIGH", "signatures": ["dir-listing"],
            "bytes_sampled": len(body), "evidence": _truncate(body),
        }], [], []
    return [], [], []


# ---------------------------------------------------------------- 输出

SEV_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


def render_text(result, show_evidence=True):
    L = []
    f = result["findings"]
    blocked = result["blocked"]
    unreachable = result["unreachable"]
    highs = [x for x in f if x["severity"] == "HIGH"]

    L.append("=" * 68)
    L.append("部署层泄漏扫描报告")
    L.append("=" * 68)
    L.append(f"目标      : {result['target']}")
    L.append(f"时间      : {result['timestamp']}")
    L.append(f"扫描路径  : {result['paths_scanned']}")
    L.append(f"  ├ 可疑泄漏 : {len(f)}")
    L.append(f"  ├ 确认不可达: {len(unreachable)}")
    L.append(f"  └ ⚠ 网络受阻: {len(blocked)}")
    L.append("")

    # —— 覆盖度警示：必须放在结论之前
    if blocked:
        cov = 100.0 * len(blocked) / max(result["paths_scanned"], 1)
        L.append("!!!" + "!" * 65)
        L.append(f"⚠ 覆盖度警告：{len(blocked)}/{result['paths_scanned']} 条路径未能完成扫描")
        L.append(f"实际有效覆盖率：{100 - cov:.1f}%")
        L.append("")
        L.append("以下路径因网络层失败**未被验证**，不能算作「安全」：")
        for b in blocked[:8]:
            L.append(f"  × {b['path']}  — {b['error']}")
        if len(blocked) > 8:
            L.append(f"  ... 另有 {len(blocked)-8} 条")
        L.append("")
        L.append("原因通常为：目标不可达 / DNS 失败 / TLS 问题 / 网络策略拦截。")
        L.append("→ 本报告结论仅覆盖已成功扫描的路径，其余部分**结论未知**。")
        L.append("!" * 68)
        L.append("")

    L.append(f"发现{len(f)} 条泄漏" + (f"，其中高危 {len(highs)} 条" if highs else ""))
    L.append("")

    if not f:
        L.append("在已完成扫描的路径中，未发现可访问的敏感文件。")
    else:
        for x in sorted(f, key=lambda v: SEV_ORDER.get(v["severity"], 9)):
            L.append("-" * 68)
            L.append(f"[{x['severity']}] {x['path']}")
            L.append(f"  URL      : {x['url']}")
            L.append(f"  状态码   : {x['status']}")
            L.append(f"  特征命中 : {', '.join(x['signatures']) if x['signatures'] else '无（仅确认可访问）'}")
            if show_evidence:
                L.append(f"  内容采样 : {x['evidence']}")
            L.append("")

    L.append("=" * 68)
    L.append("修复建议")
    L.append("=" * 68)
    L.append("核心原则：用「白名单」而非「黑名单」。")
    L.append("")
    L.append("❌ 黑名单：逐个把敏感文件加进 ignore → 会漏掉你没想到的")
    L.append("✅ 白名单：默认全部拒绝，只显式放开确实需要的文件")
    L.append("")
    L.append("Vercel / .vercelignore：")
    L.append("  *")
    L.append("  !index.html")
    L.append("  !agent-setup.html")
    L.append("")
    L.append("已泄露过的文件必须在 git 历史中清除，删掉当前文件不算修复。")

    L.append("")
    L.append("=" * 68)
    L.append("实测边界（必读）")
    L.append("=" * 68)
    for lim in result["limitations"]:
        L.append(f"  - {lim}")
    L.append("")
    L.append("本工具不验证业务逻辑安全、API 鉴权强度、模型安全性。")
    L.append("「未发现泄漏」仅代表固定路径清单在此刻不可达，不等于系统安全。")
    return "\n".join(L)


def render_html(result):
    f = result["findings"]
    blocked = result["blocked"]
    unreachable = result["unreachable"]
    highs = [x for x in f if x["severity"] == "HIGH"]
    total = result["paths_scanned"]
    covered = total - len(blocked)
    cov_pct = 100.0 * covered / max(total, 1)

    rows = []
    for x in sorted(f, key=lambda v: SEV_ORDER.get(v["severity"], 9)):
        color = "#c0392b" if x["severity"] == "HIGH" else "#d68910"
        rows.append(f"""    <tr><td><span class="badge" style="background:{color}">{x['severity']}</span></td>
      <td><code>{x['path']}</code></td>
      <td><a href="{x['url']}" target="_blank">{x['url']}</a></td>
      <td class="tags">{', '.join(x['signatures']) or '—'}</td></tr>""")

    # 覆盖度区块：有缺口就置顶警示
    if blocked:
        cov_block = f"""
  <div class="box bad">
    <h3>⚠ 覆盖度警告：{len(blocked)}/{total} 条路径未能完成扫描</h3>
    <p class="big">有效覆盖率<b>{cov_pct:.1f}%</b>（{covered}/{total}）</p>
    <p>以下路径因网络层失败<b>未被验证</b>，<b>不能算作「安全」</b>：</p>
    <table class="blk">
      <thead><tr><th>路径</th><th>失败原因</th></tr></thead>
      <tbody>{chr(10).join(f'    <tr><td><code>{b["path"]}</code></td><td class="err">{b["error"]}</td></tr>' for b in blocked[:15])}</tbody>
    </table>
    <p style="margin-top:10px">常见原因：目标不可达 / DNS 失败 / TLS 问题 / 网络策略拦截。<br>
    <b>→ 本报告结论仅覆盖已成功扫描的 {covered} 条路径，其余结论未知。</b></p>
  </div>"""
    else:
        cov_block = f"""
  <div class="box ok">
    <h3>扫描覆盖度：{covered}/{total}（{cov_pct:.1f}%）— 全部路径完成</h3>
  </div>"""

    if not f:
        body = f"""
  {cov_block}
  <div class="box ok">
    <h3>在已完成的 {covered} 条路径扫描中，未发现可访问的敏感文件</h3>
  </div>"""
    else:
        body = f"""
  {cov_block}
  <div class="box {'bad' if highs else 'warn'}">
    <h3>发现 {len(f)} 条泄漏{f"，其中高危 {len(highs)} 条" if highs else ""}</h3>
    <p>{'严重 — 存在信息泄漏，建议立即处理' if highs else '中 — 建议纳入整改计划'}</p>
  </div>
  <table>
    <thead><tr><th>严重度</th><th>路径</th><th>URL</th><th>特征命中</th></tr></thead>
    <tbody>
{chr(10).join(rows)}
    </tbody>
  </table>"""

    html = f"""<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<title>部署层泄漏扫描报告 · {result['target']}</title>
<style>
 body {{ font-family:-apple-system,"Segoe UI","Microsoft YaHei",sans-serif;
        background:#f7f8fa; color:#1a1a1a; margin:0; padding:32px; line-height:1.6 }}
 .wrap {{ max-width:1080px; margin:0 auto }}
 h1 {{ font-size:24px; margin:0 0 4px }}
 .sub {{ color:#666; font-size:13px; margin-bottom:22px }}
 .kpi {{ display:flex; gap:12px; margin-bottom:22px; flex-wrap:wrap }}
 .kpi div {{ background:#fff; border:1px solid #e3e6ea; border-radius:8px; padding:14px 20px;
             flex:1; min-width:110px }}
 .kpi .n {{ font-size:26px; font-weight:700 }}
 .kpi .l {{ font-size:12px; color:#888 }}
 table {{ width:100%; border-collapse:collapse; background:#fff;
          border:1px solid #e3e6ea; border-radius:8px; overflow:hidden; margin-bottom:18px }}
 th,td {{ padding:10px 12px; text-align:left; border-bottom:1px solid #eef0f2; font-size:13px }}
 th {{ background:#fafbfc; font-weight:600; color:#555 }}
 code {{ background:#f0f2f5; padding:2px 6px; border-radius:4px; font-size:12px }}
 a {{ color:#1a5fb4; text-decoration:none; word-break:break-all }}
 .badge {{ color:#fff; padding:2px 8px; border-radius:4px; font-size:11px; font-weight:600 }}
 .tags {{ color:#666; font-size:12px }}
 .err {{ color:#c0392b; font-size:12px; font-family:Consolas,monospace }}
 .box {{ background:#fff; border:1px solid #e3e6ea; border-radius:8px;
         padding:18px 22px; margin-bottom:20px }}
 .box.bad {{ border-left:4px solid #c0392b }}
 .box.warn {{ border-left:4px solid #d68910 }}
 .box.ok {{ border-left:4px solid #27ae60 }}
 .box h3 {{ margin:0 0 8px; font-size:16px }}
 .big {{ font-size:15px; margin:6px 0 }}
 .big b {{ font-size:22px; color:#c0392b; margin:0 4px }}
 .blk {{ margin:10px 0; font-size:12.5px }}
 pre {{ background:#1e1e2e; color:#e6e6e6; padding:14px 16px; border-radius:6px;
        font-size:12.5px; overflow-x:auto; line-height:1.7 }}
 h2 {{ font-size:17px; margin:26px 0 10px }}
 .foot {{ margin-top:26px; padding-top:16px; border-top:1px solid #e3e6ea;
          font-size:12px; color:#999 }}
</style></head><body><div class="wrap">
  <h1>部署层泄漏扫描报告</h1>
  <div class="sub">目标 <code>{result['target']}</code> · {result['timestamp']} · 被动检测，未做任何利用</div>
  <div class="kpi">
    <div><div class="n">{total}</div><div class="l">扫描路径</div></div>
    <div><div class="n" style="color:{'#c0392b' if cov_pct<100 else '#27ae60'}">{cov_pct:.0f}%</div><div class="l">有效覆盖率</div></div>
    <div><div class="n">{len(f)}</div><div class="l">发现泄漏</div></div>
    <div><div class="n" style="color:#c0392b">{len(highs)}</div><div class="l">高危</div></div>
  </div>
  {body}
  <h2>修复建议</h2>
  <div class="box">
    <p><b>核心原则：用「白名单」，不用「黑名单」。</b></p>
    <p>❌ 黑名单逐个忽略敏感文件 → 会漏掉你没想到的<br>
       ✅ 白名单默认全拒绝 → 只显式放开确实需要的</p>
    <pre># Vercel / .vercelignore
*
!index.html
!agent-setup.html

# Nginx / location
location ~ /\\. {{ deny all; return 404; }}</pre>
    <p style="color:#c0392b;margin-top:12px"><b>注意：</b>
       已经泄露过的文件必须在 git 历史中清除，删掉当前文件不算修复。</p>
  </div>
  <h2>实测边界</h2>
  <div class="box warn">
    <ul>{"".join(f"<li>{l}</li>" for l in result["limitations"])}</ul>
    <p><b>本工具不验证业务逻辑安全、API 鉴权强度、模型安全性。</b><br>
    「未发现泄漏」仅代表固定路径清单在此刻不可达，不等于系统安全。</p>
  </div>
  <div class="foot">本报告仅覆盖固定路径清单的被动可达性检查，
  不含目录爆破、认证绕过、业务逻辑测试或任何主动利用。</div>
</div></body></html>"""
    return html


# ---------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser(description="部署层泄漏扫描器（被动检测）")
    ap.add_argument("--url", required=True, help="目标站点根 URL")
    ap.add_argument("--deep", action="store_true", help="同时检查中危路径")
    ap.add_argument("--json", help="输出 JSON 到指定路径")
    ap.add_argument("--html", help="输出 HTML 报告路径")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    if not args.url.startswith(("http://", "https://")):
        url = "https://" + args.url
    else:
        url = args.url

    paths = list(HIGH_RISK_PATHS)
    if args.deep:
        paths += MEDIUM_RISK_PATHS

    print(f"扫描目标: {url}")
    print(f"路径数量: {len(paths)}\n")

    findings, unreachable, blocked = scan_base(url, paths, verbose=args.verbose)
    dl_f, dl_u, dl_b = scan_dir_listing(url, verbose=args.verbose)
    findings += dl_f
    unreachable += dl_u
    blocked += dl_b

    total_paths = len(paths) + 1
    covered = total_paths - len(blocked)

    result = {
        "target": url,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "paths_scanned": total_paths,
        "paths_covered": covered,
        "coverage_pct": round(100.0 * covered / max(total_paths, 1), 1),
        "findings": findings,
        "unreachable": unreachable,
        "blocked": blocked,
        "method": "passive-path-probe",
        "limitations": [
            "只检查固定路径清单，不做目录爆破",
            "不做认证绕过或凭据组合猜测",
            "仅采样响应前 8KB，未下载发现的敏感内容全文",
            "未覆盖：子域名枚举、API 端点鉴权强度、业务逻辑漏洞",
            "单次快照结果，配置变更后需重扫",
        ],
    }

    print()
    print(render_text(result))

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(result, fh, ensure_ascii=False, indent=2)
        print(f"\nJSON 已写入: {args.json}")

    if args.html:
        with open(args.html, "w", encoding="utf-8") as fh:
            fh.write(render_html(result))
        print(f"HTML 已写入: {args.html}")

    # 退出码：0=有发现 1=无发现 2=覆盖度不足（有缺口）
    if blocked:
        return 2
    return 0 if findings else 1


if __name__ == "__main__":
    sys.exit(main())