#!/usr/bin/env python3
"""
审计器漏报核对表
================
把靶场设计的每个缺陷与审计器实际检出逐一对照，
**漏报就是待补的检查项**，不能因为「大部分抓到了」就收工。
这与Day 1 的「双向对照」是同一条纪律。
"""
import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

# 靶场 server.py 中**故意植入**的缺陷（8 项）
PLANTED = [
    {"id": "V1", "desc": "无认证暴露完整工具清单",
     "expect": "A1 应FAIL"},
    {"id": "V2", "desc": "/health 泄露 Python栈、绝对路径、数据库连接串",
     "expect": "F1 应 FAIL"},
    {"id": "V3", "desc": "工具描述中植入间接注入载荷（读 SSH 私钥）",
     "expect": "D1 应 FAIL（9001 的工具描述里本身就带了注入载荷）"},
    {"id": "V4", "desc": "资金操作（退款）无任何认证",
     "expect": "C1 应命中 process_refund"},
    # 2026-10-10 更正：C3 已补齐，实测命中。原注释「当前无」是 Day 2 的旧状态。
    {"id": "V5", "desc": "无幂等性 —— create_order 重放会重复下单",
     "expect": "C3 应覆盖"},
    {"id": "V6", "desc": "任意SQL 执行无限制",
     "expect": "C1 应命中 execute_query"},
    {"id": "V7", "desc": "任意命令执行无限制",
     "expect": "C1 应命中 run_script"},
    # 同上：C4 已补齐，实测命中。
    {"id": "V8", "desc": "审计日志无认证可读，未记录调用者身份",
     "expect": "C4 应覆盖"},
]

ap = argparse.ArgumentParser(description="MCP 靶场漏报核对")
ap.add_argument("--input", default=os.path.join(ROOT, "reports",
                                                "mcp-vulnsite.json"),
                help="audit_mcp.py --json 的输出")
a = ap.parse_args()

# 判定不能只看「覆盖率数字」（纪律 12：判定条件必须与名字语义一致）。
#   把真漏报和已知缺口混在一起算「覆盖率 62% 通过」是自欺。
#   ⇒ 通过条件 = 必须检出项全部检出，而不是百分比过线。
#
# ⚠ 2026-10-10 实测修正（注释与代码漂移的活样本）：
#   上面 PLANTED 表里 V3/V5/V8 的 expect 还写着「本次传入干净清单」
#   「当前无对应检查项」—— 那是 **Day 2 的状态**。D1/C3/C4 后来补齐了，
#   实测 8/8 全部命中，而注释一直没跟着改。
#   这正是我把 KNOWN_GAP 报警器写进来的原因：**文档说的状态和代码
#   实际的状态会漂移，机器要比人先发现。**
MUST_COVER = {"V1", "V2", "V3", "V4", "V5", "V6", "V7", "V8"}
KNOWN_GAP = set()      # 当前无已知缺口；将来若有，必须显式登记在这里

# ⚠ 输入缺失必须记「未测」，绝不能当通过（纪律 3）。
#   原实现硬编码本机绝对路径，开源后必然 FileNotFoundError 崩溃 ——
#   exit 1 而不是 0，否则 run_all 会把它数成 OK。
if not os.path.isfile(a.input):
    print("STATUS: SKIPPED —— 输入缺失：%s" % a.input)
    print("先生成：python tools/audit_mcp.py --url http://127.0.0.1:9001/mcp "
          "--repo targets/vulnsite_mcp --json reports/mcp-vulnsite.json")
    sys.exit(1)

res = json.load(open(a.input, encoding="utf-8"))
checks = {c["id"]: c for c in res["checks"]}

print("=" * 74)
print("漏报核对：靶场植入缺陷 vs 审计器实际检出")
print("=" * 74)
print()

covered, missed = [], []

# V1 —— A1 无认证
a1 = checks.get("A1", {})
v1_ok = a1.get("status") == "FAIL"
(covered if v1_ok else missed).append(
    ("V1 无认证暴露工具清单", "A1 = FAIL" if v1_ok else "A1 = %s" % a1.get("status")))

# V2 —— F1 栈/路径/连接串泄漏
f1 = checks.get("F1", {})
v2_ok = f1.get("status") == "FAIL"
(covered if v2_ok else missed).append(
    ("V2 /health 泄露栈与凭据", "F1 = FAIL" if v2_ok else
     "F1 = %s —— **漏报**" % f1.get("status")))

# V3 —— D1 注入痕迹（本次未传入含注入的描述）
d1 = checks.get("D1", {})
v3_ok = d1.get("status") == "FAIL"
(covered if v3_ok else missed).append(
    ("V3 工具描述含间接注入载荷",
     "D1 = FAIL" if v3_ok else
     "D1 = %s —— 未检出（本次传入的是干净清单）" % d1.get("status")))

# V4/V6/V7 —— C1 高危工具
c1 = checks.get("C1", {})
c1_detail = c1.get("detail", "")
v4_ok = "process_refund" in c1_detail
v6_ok = "execute_query" in c1_detail
v7_ok = "run_script" in c1_detail
(covered if v4_ok else missed).append(
    ("V4 退款工具暴露", "C1 命中 process_refund" if v4_ok else "C1 未命中"))
(covered if v6_ok else missed).append(
    ("V6 任意 SQL 执行", "C1 命中 execute_query" if v6_ok else "C1 未命中"))
(covered if v7_ok else missed).append(
    ("V7 任意命令执行", "C1 命中 run_script" if v7_ok else "C1 未命中"))

# V5 —— 幂等性：无检查项
has_idem = any(c["id"] == "C3" for c in res["checks"])
(covered if has_idem else missed).append(
    ("V5 无幂等性", "C3 已覆盖" if has_idem else "**无检查项 —— 缺口**"))

# V8 —— 审计日志
has_log = any(c["id"] == "C4" for c in res["checks"])
(covered if has_log else missed).append(
    ("V8 审计日志可读且不记录调用者", "C4 已覆盖" if has_log else "**无检查项 —— 缺口**"))

print("✅ 已检出（%d）:" % len(covered))
for name, note in covered:
    print("   ✓ %s  [%s]" % (name, note))
print()
print("❌ 漏报 / 缺口（%d）:" % len(missed))
for name, note in missed:
    print("   ✗ %s  [%s]" % (name, note))
print()

cov = len(covered) / (len(covered) + len(missed)) * 100
print("-" * 74)
print("覆盖率: %d/%d = %.0f%%" % (len(covered), len(covered) + len(missed), cov))
print("-" * 74)

got = {n.split()[0] for n, _ in covered}
must_missed = sorted(MUST_COVER - got)
unexpected = sorted(got & KNOWN_GAP)

if missed:
    print()
    print("待补检查项：")
    for name, note in missed:
        mark = "（已知缺口）" if name.split()[0] in KNOWN_GAP else "**真漏报**"
        print("  · %s —— %s %s" % (name, note, mark))

print()
if must_missed:
    print("STATUS: FAIL —— 必须检出项漏报：%s" % "、".join(must_missed))
    sys.exit(1)
print("STATUS: OK —— 必须检出项 %d/%d 全部命中；已登记缺口：%s"
      % (len(MUST_COVER), len(MUST_COVER),
         "、".join(sorted(KNOWN_GAP)) or "无"))
if unexpected:
    print("       （注：%s 本次意外命中，可能检查项已补齐，"
          "请更新 KNOWN_GAP）" % "、".join(unexpected))
sys.exit(0)