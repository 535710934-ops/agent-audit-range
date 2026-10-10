#!/usr/bin/env python3
"""
一键全量回归（Day 9 · P2）
===========================
把分散的手工调用固化成一条命令：

    python run_all.py            # 跑全部
    python run_all.py --quick    # 只跑回归核对（快）

设计约束（沿用方法论 v2.2 的纪律）：
  - 纪律 3：进程失败 / 端点不可达 → 记 ERR，与 FAIL/PASS/SKIPPED 分开统计，
            **绝不计入 PASS**。
  - 纪律 9：每个工具的解析结果都有**数量断言** —— 只认出 0 项直接判该工具 BROKEN。
  - 纪律 12：工具名与判定语义一致（本文件只做聚合与编排，不做判定）。

输出：
  runs/summary.json         机器可读总表
  stdout                    人类可读汇总

⚠ 本脚本**不启动靶场**。靶场需先各自起好（run_in_background，不能用 & 后台）。
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PY = sys.executable

# 干净的 subprocess 环境：必须剥掉代理变量，否则全部超时（Day 4 踩过）
_ENV = dict(os.environ)
for k in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy",
          "ALL_PROXY", "all_proxy"):
    _ENV.pop(k, None)

T = {
    "A": "alice-token-aaa111",
    "B": "bob-token-bbb222",
    "ADMIN": "admin-token-ccc333",
    "SVC": "servicenowexternalagent",
}

COMBO_SERVERS = json.dumps([
    {"name": "git-mcp", "tools": ["git_init", "git_commit", "git_push",
                                  "create_branch"]},
    {"name": "shell-exec", "tools": ["run_script", "execute_command"]},
    {"name": "http-fetch", "tools": ["http_request", "send_email"]},
    {"name": "db-mcp", "tools": ["execute_query"]},
])
COMBO_SAFE = json.dumps([
    {"name": "notes", "tools": ["read_note", "list_note"]},
    {"name": "calc", "tools": ["add", "subtract"]},
    {"name": "db", "tools": ["execute_query", "select_rows"]},
])

# (任务名, 工具, 参数列表, 靶场标签, 解析器, 最少项数)
#
# parser 取值（纪律 9：判定器必须先证明看见了被测对象）：
#   checks   JSON["checks"] 每项 .status 是判定状态枚举
#   single   JSON 本身就是一个检查项（probe_combo）
#   hits     JSON["findings"] 每项算一次命中；**零命中是合法 PASS，不是 BROKEN**
#   stdout   无 --json 输出，回落解析 "[FAIL]/[ OK ]/[SKIP]" 前缀（audit_tenant）
#
# ⚠ 为什么必须显式声明 parser，不能统一按 .status 读：
#   scan_deploy_leak 的 findings[].status 是 **HTTP 状态码**（200/404），
#   不是判定状态。Day 9 实测：统一读取会数出 "200 2 次" 这种荒谬结果。
#   **同名字段在不同工具里语义不同** —— 与纪律 12 同族。
JOBS = [
    ("F-MCP-9001", "audit_mcp.py",
     ["--url", "http://127.0.0.1:9001/mcp", "--repo",
      os.path.join(ROOT, "targets", "vulnsite_mcp")], "9001", "checks", 1),
    ("F-MCP-9002", "audit_mcp.py",
     ["--url", "http://127.0.0.1:9002/mcp", "--repo",
      os.path.join(ROOT, "targets", "cleansite_mcp")], "9002", "checks", 1),
    ("F-MCP-9003", "audit_mcp.py",
     ["--url", "http://127.0.0.1:9003/mcp", "--repo",
      os.path.join(ROOT, "targets", "multitenant_mcp")], "9003", "checks", 1),
    ("F-MCP-9005", "audit_mcp.py",
     ["--url", "http://127.0.0.1:9005/mcp", "--repo",
      os.path.join(ROOT, "targets", "service_principal_mcp")], "9005",
     "checks", 1),
    ("B-TENANT-9003", "audit_tenant.py",
     ["http://127.0.0.1:9003/mcp", "--token-a", T["A"], "--token-b", T["B"],
      "--token-admin", T["ADMIN"], "--label-a", "Alice", "--label-b", "Bob"],
     "9003", "stdout", 5),
    ("B-TENANT-9004", "audit_tenant.py",
     ["http://127.0.0.1:9004/mcp", "--token-a", T["A"], "--token-b", T["B"],
      "--token-admin", T["ADMIN"], "--label-a", "Alice", "--label-b", "Bob"],
     "9004", "stdout", 5),
    ("G-SVC-9005", "check_service_principal.py",
     ["http://127.0.0.1:9005/mcp", "--token", T["A"], "--token", T["SVC"],
      "--peer", "http://127.0.0.1:9006/mcp", "--repo",
      os.path.join(ROOT, "targets", "service_principal_mcp")], "9005",
     "checks", 1),
    ("G-SVC-9006", "check_service_principal.py",
     ["http://127.0.0.1:9006/mcp", "--token", T["A"], "--token", T["SVC"],
      "--peer", "http://127.0.0.1:9005/mcp", "--repo",
      os.path.join(ROOT, "targets", "service_principal_safe")], "9006",
     "checks", 1),
    ("G-EGRESS-9007", "audit_egress.py",
     ["http://127.0.0.1:9007", "--deep", "--servers", COMBO_SERVERS], "9007",
     "checks", 1),
    ("G-EGRESS-9008", "audit_egress.py",
     ["http://127.0.0.1:9008", "--deep", "--servers", COMBO_SAFE], "9008",
     "checks", 1),
    ("G3r-COMBO-9009", "probe_combo.py",
     ["--git", "http://127.0.0.1:9009/mcp",
      "--exec", "http://127.0.0.1:9010/mcp"], "9009", "single", 1),
    ("G3r-COMBO-9011", "probe_combo.py",
     ["--git", "http://127.0.0.1:9011/mcp",
      "--exec", "http://127.0.0.1:9012/mcp"], "9011", "single", 1),
    ("DEPLOY-9007", "scan_deploy_leak.py",
     ["--url", "http://127.0.0.1:9007"], "9007", "hits", 0),
    ("DEPLOY-9008", "scan_deploy_leak.py",
     ["--url", "http://127.0.0.1:9008"], "9008", "hits", 0),
    ("MT-9013", "probe_multiturn.py",
     ["http://127.0.0.1:9013/chat", "--rounds", "5"], "9013", "single", 1),
    ("MT-9014", "probe_multiturn.py",
     ["http://127.0.0.1:9014/chat", "--rounds", "5"], "9014", "single", 1),
    # 链二：供应链投毒（读远程 → 写仓库 → 内容落地），不需要命令执行权限
    ("G3r-SUPPLY-9015", "probe_combo.py",
     ["--chain", "supply", "--fetch", "http://127.0.0.1:9015/mcp",
      "--git", "http://127.0.0.1:9009/mcp"], "9015", "single", 1),
    ("G3r-SUPPLY-9016", "probe_combo.py",
     ["--chain", "supply", "--fetch", "http://127.0.0.1:9016/mcp",
      "--git", "http://127.0.0.1:9011/mcp"], "9016", "single", 1),
]

REGRESSION = [
    ("REG-Day2-MCP", "check_coverage.py", []),
    ("REG-Day3-CASEBOOK", "test_casebook.py", []),
    ("REG-Day4-TENANT", "check_coverage_tenant.py", []),
    # 语义改写漏检率实测（盲区量化，非靶场任务）
    ("REG-Day9-SEMANTIC", "check_semantic_rewrite.py", []),
    # 控制字符 / ANSI 转义（garak 交叉验证暴露的盲区，Day 10 补）
    ("REG-Day10-CTRL", "check_control_chars.py", []),
]


# ⚠ 存活检查必须**强制禁用代理**：环境里若设了 http_proxy（本机实测就是），
#   urlopen 会去问一个不通的代理 → 超时 → 靶场明明在线却被判「未启动」，
#   然后 18 个任务全记 ERR。与 start_targets.py 同一处修复。
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def alive(port, timeout=3):
    """存活预检。

    ⚠ 不能只判 200 —— 9001 的 /health **故意返回 500**（植入的堆栈泄漏），
      而 urllib 对 4xx/5xx 会抛 HTTPError，直接被当成「未启动」。
      这正是纪律 3 的活样本：**HTTP 500 不等于服务不在。**
    """
    try:
        with _OPENER.open(
                "http://127.0.0.1:%d/health" % port, timeout=timeout) as r:
            return True
    except urllib.error.HTTPError:
        return True          # 收到响应就说明服务在，只是这个端点报错
    except Exception:
        return False


def run(name, tool, args, parser="checks", expect_min=1):
    """跑一个工具，返回结构化结果。"""
    out_dir = os.path.join(ROOT, "runs")
    os.makedirs(out_dir, exist_ok=True)
    jf = os.path.join(out_dir, "batch_%s.json" % name)
    # audit_tenant 无 --json 接口（只有 --html），只能解析 stdout
    cmd = [PY, os.path.join(HERE, tool)] + args
    if parser != "stdout":
        cmd += ["--json", jf]
    elif os.path.exists(jf):
        os.remove(jf)          # 防读到上一轮残留
    t0 = time.time()
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=300,
                           env=_ENV, cwd=HERE)
        code, out, err = p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return {"name": name, "tool": tool, "status": "ERR",
                "detail": "超时 300s", "checks": {}, "secs": 300}
    except Exception as e:
        return {"name": name, "tool": tool, "status": "ERR",
                "detail": "%s: %s" % (type(e).__name__, str(e)[:150]),
                "checks": {}, "secs": 0}

    checks = {}
    seen = 0          # 判定器实际"看见"的对象数

    if parser == "stdout":
        # audit_tenant 输出形如 "[FAIL] B01 ..." / "[ OK ] B01 ..." / "[SKIP] ..."
        for line in (out or "").splitlines():
            s = line.strip()
            for tag, st in (("[FAIL]", "FAIL"), ("[ OK ]", "PASS"),
                            ("[WARN]", "WARN"), ("[SKIP]", "SKIPPED")):
                if s.startswith(tag):
                    checks[st] = checks.get(st, 0) + 1
                    seen += 1
                    break
    elif os.path.isfile(jf):
        try:
            d = json.load(open(jf, encoding="utf-8"))
            if parser == "single":
                items = [d]
            elif parser == "hits":
                # findings 每项是一次命中；零命中合法（干净靶场），不算 BROKEN
                items = d.get("findings") or []
                seen = len(items)
                checks["HIT"] = len(items)
                return {"name": name, "tool": tool,
                        "status": "OK", "checks": checks, "total": len(items),
                        "exit": code, "secs": round(time.time() - t0, 1),
                        "coverage": d.get("coverage_pct"),
                        "stderr_tail": (err or "").strip()[-200:]}
            else:
                items = d.get("checks") or []
            for it in items:
                if isinstance(it, dict) and it.get("status"):
                    st = str(it["status"]).upper()
                    checks[st] = checks.get(st, 0) + 1
                    seen += 1
        except Exception as e:
            return {"name": name, "tool": tool, "status": "ERR",
                    "detail": "JSON 解析失败 %s" % str(e)[:120],
                    "checks": {}, "secs": 0}

    total = sum(checks.values())
    # 纪律 9：判定器没看见东西 → BROKEN（不是通过）
    # 但 hits 型允许 0（见上方早退）；checks 型看见 0 项一定是坏的
    status = "OK" if seen >= expect_min else "BROKEN"
    return {"name": name, "tool": tool, "status": status, "checks": checks,
            "total": total, "exit": code, "secs": round(time.time() - t0, 1),
            "stderr_tail": (err or "").strip()[-200:]}


def main():
    ap = argparse.ArgumentParser(description="Agent 安全审计 · 一键全量回归")
    ap.add_argument("--quick", action="store_true", help="只跑回归核对")
    a = ap.parse_args()

    t0 = time.time()
    results = []

    print("=" * 74)
    print("Agent 安全审计 · 全量回归")
    print("=" * 74)

    # ---------- 靶场存活预检 ----------
    ports = sorted({t[3] for t in JOBS})
    print("\n[存活预检]")
    down = []
    for p in ports:
        ok = alive(int(p))
        print("  %s : %s" % (p, "在线" if ok else "**未启动**"))
        if not ok:
            down.append(p)
    if down:
        print("\n⚠ 以下靶场未启动：%s —— 对应任务将记 ERR，"
              "**绝不计入 PASS**（纪律 3）" % "、".join(down))

    # ---------- 主任务 ----------
    if not a.quick:
        print("\n[主任务 %d 项]" % len(JOBS))
        for name, tool, args, port, parser, expect_min in JOBS:
            if port in down:
                results.append({"name": name, "tool": tool, "status": "ERR",
                                "detail": "靶场 %s 未启动" % port,
                                "checks": {}, "target": port})
                print("  %-18s %s" % (name, "ERR  靶场未启动"))
                continue
            r = run(name, tool, args, parser, expect_min)
            r["target"] = port
            results.append(r)
            # ⚠ 键必须 str()：hits 型会把 int 混进来，sorted 会抛 TypeError
            #   （Day 9 实测：HTTP 状态码 200 被当成判定状态时崩在汇总这行）
            tally = " ".join("%s%d" % (str(k), v) for k, v in
                             sorted(r["checks"].items(), key=lambda x: str(x[0])))
            if r.get("coverage") is not None:
                tally += "  cov=%s%%" % r["coverage"]
            print("  %-18s %-7s %s  (%.1fs)"
                  % (name, r["status"], tally or "-", r.get("secs", 0)))

    # ---------- 生成回归依赖 ----------
    # check_coverage.py 的输入是 audit_mcp 的 JSON 输出。
    # 原实现把这条路径硬编码成本机绝对路径，开源后必然崩溃（且崩溃前
    # exit 0 恒真 —— 假通过）。现在改成相对仓库根 + 缺失时在此处生成。
    dep = os.path.join(ROOT, "reports", "mcp-vulnsite.json")
    os.makedirs(os.path.dirname(dep), exist_ok=True)
    src = os.path.join(ROOT, "runs", "batch_F-MCP-9001.json")
    if os.path.isfile(src):
        shutil.copyfile(src, dep)
    elif "9001" not in down:
        try:
            subprocess.run([PY, os.path.join(HERE, "audit_mcp.py"),
                            "--url", "http://127.0.0.1:9001/mcp", "--repo",
                            os.path.join(ROOT, "targets", "vulnsite_mcp"),
                            "--json", dep], capture_output=True, text=True,
                           timeout=180, env=_ENV, cwd=HERE)
        except Exception:
            pass                     # 生成不了就让 check_coverage 自己记 SKIPPED
    print("\n[依赖] %s %s" % (os.path.relpath(dep, ROOT),
                             "已就绪" if os.path.isfile(dep) else "**缺失**"))

    # ---------- 回归核对 ----------
    print("\n[回归核对 %d 项]" % len(REGRESSION))
    for name, tool, args in REGRESSION:
        cmd = [PY, os.path.join(HERE, tool)] + args
        try:
            p = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=300, env=_ENV, cwd=HERE)
            ok = (p.returncode == 0)
            tail = [l for l in p.stdout.strip().splitlines()
                    if l.strip()][-1:] or [""]
            print("  %-18s %-7s %s" % (name, "OK" if ok else "FAIL",
                                       tail[0][:54]))
            results.append({"name": name, "tool": tool,
                            "status": "OK" if ok else "FAIL",
                            "checks": {}, "kind": "regression",
                            "last_line": tail[0]})
        except Exception as e:
            print("  %-18s %-7s %s" % (name, "ERR", str(e)[:60]))
            results.append({"name": name, "tool": tool, "status": "ERR",
                            "checks": {}, "kind": "regression"})

    # ---------- 汇总 ----------
    agg = {}
    for r in results:
        if r.get("kind") == "regression":
            continue
        for k, v in r.get("checks", {}).items():
            agg[k] = agg.get(k, 0) + v
    n_err = sum(1 for r in results if r["status"] == "ERR")
    n_broken = sum(1 for r in results if r["status"] == "BROKEN")
    n_fail = sum(1 for r in results if r["status"] == "FAIL")

    print("\n" + "=" * 74)
    print("汇总  检查项判定: %s" % (" ".join("%s=%d" % (str(k), v)
                                            for k, v in sorted(
                                                agg.items(),
                                                key=lambda x: str(x[0])))
                                    or "-"))
    print("      任务: ERR %d | BROKEN %d | FAIL %d | 合计 %d | %.1fs"
          % (n_err, n_broken, n_fail, len(results), time.time() - t0))
    print("=" * 74)

    out = os.path.join(ROOT, "runs", "summary.json")
    # ⚠ 不能依赖 run() 里的 makedirs：--quick 不跑主任务，全新克隆下 runs/
    #   不存在，写 summary 会 FileNotFoundError（2026-10-10 在开源副本上实测）。
    os.makedirs(os.path.dirname(out), exist_ok=True)
    json.dump({"ts": time.strftime("%Y-%m-%d %H:%M:%S"),
               "aggregate": agg, "n_err": n_err, "n_broken": n_broken,
               "n_fail": n_fail, "results": results},
              open(out, "w", encoding="utf-8"),
              ensure_ascii=False, indent=2, default=str)
    print("JSON 已写入: %s" % out)

    return 1 if (n_err or n_broken or n_fail) else 0


if __name__ == "__main__":
    sys.exit(main())
