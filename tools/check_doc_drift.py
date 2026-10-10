#!/usr/bin/env python3
"""
文档漂移 / 检查项撞号 自动检查器
=================================

**为什么会有这个文件**：同类错误已经发生过四次，我把它写进方法论 §4.0
当成「交付前必查项」，然后立刻在另一份文档里又犯了八次。

> 手工清单挡不住重复错误。会重复的东西要交给机器。

**它做四件事**：

A. 从源码**推导**四项事实（不硬编码，避免自己变成新的漂移源）
     · 方法论版本     ← 变更记录最后一行
     · 纪律条数       ← §4 表格行数
     · 回归任务数     ← 直接 import run_all.py 的 JOBS + REGRESSION
     · 检查项清单     ← 扫 tools/*.py 里的 "id"/"title" 字面量
B. 校验**检查项 ID 全局唯一**（同一 ID 对应两个不同 title = 撞号）
C. 扫对外文档，找出与上述事实不符的数字
D. 输出 STATUS: OK / FAIL，并退出 0 / 1

用法:
    python tools/check_doc_drift.py

⚠ 它不能保证文档**正确**，只能保证文档之间**一致**。
   数字对不对，仍然要人判断。
"""

import io
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
METH = os.path.join(ROOT, "methodology", "agent-security-audit-methodology.md")

try:
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
except Exception:
    pass


# ---------------------------------------------------------------- A. 推导事实

def derive_version(text):
    """变更记录里最后一个版本号。"""
    hits = re.findall(r"\|\s*\*\*(v\d+\.\d+)\*\*\s*\|", text)
    return hits[-1] if hits else None


def derive_disciplines(text):
    """§4 纪律表格的行数。

    只数形如 `| 12 | ... |` 的行，且必须落在「执行纪律」标题之后。
    """
    m = re.search(r"##\s*4\.\s*\S*执行纪律", text)
    if not m:
        return None
    seg = text[m.end(): m.end() + 6000]
    n = 0
    for line in seg.splitlines():
        if re.match(r"^\|\s*\d+\s*\|", line.strip()):
            n += 1
        elif line.strip().startswith("### ") and n:
            break            # 进入第一个子章节就停
    return n


def derive_regression():
    """直接 import run_all —— 它本来就是 Python，别用正则去数。"""
    sys.path.insert(0, HERE)
    try:
        import run_all
        return len(getattr(run_all, "JOBS", [])) + len(
            getattr(run_all, "REGRESSION", []))
    except Exception as e:
        print("  ⚠ 无法导入 run_all.py（%s）—— 回归任务数记为未推导" % e)
        return None


def derive_checks():
    """扫 tools/*.py 里的检查项 ID 与标题。

    返回 (id -> set(titles))。同一 ID 出现多个 title 就是撞号。
    """
    found = {}
    pat_id = re.compile(r'"id"\s*:\s*"([^"]+)"')
    pat_title = re.compile(r'"title"\s*:\s*"([^"]*)"')
    for fn in sorted(os.listdir(HERE)):
        if not fn.endswith(".py") or fn.startswith("check_doc_drift"):
            continue
        src = io.open(os.path.join(HERE, fn), encoding="utf-8",
                      errors="replace").read()
        for line in src.splitlines():
            m = pat_id.search(line)
            if not m:
                continue
            cid = m.group(1)
            # 只收「检查项」形态的 ID：字母+数字（A1 / G3s / MT / B01），
            # 排除 url / path 之类恰好也叫 id 的字段
            if not re.match(r"^[A-Za-z]{1,3}\d{0,2}[a-z]?$", cid):
                continue
            t = pat_title.search(line)
            found.setdefault(cid, set()).add(
                (t.group(1) if t else "（无 title）", fn))
    return found


# ---------------------------------------------------------------- C. 扫文档

# 默认只扫仓库内的对外文档（README / docs/）。
# 仓库外的交付文档（落地页、内容草稿等在另一个工作区）用 --docs 显式传入 ——
# ⚠ 别用相对路径去拼跨盘符目录：第一版就是这么写的，
#   `os.path.join(ROOT, "..", "..", ...)` 在 D 盘的目标上永远指向 C 盘，
#   结果「扫描对外文档 0 份」还显示 ✓ —— 一个查漂移的检查器自己漏扫了，
#   而且报的是通过。这正是纪律 3 的又一个活样本：
#   **没扫到 ≠ 没问题。**
DEFAULT_DIRS = [
    (os.path.join(ROOT, "docs"), (".md",)),
]
DEFAULT_FILES = [
    os.path.join(ROOT, "README.md"),
]
EXCLUDE = {"agent-security-audit-methodology.md"}

# ---------------------------------------------------------------- 豁免清单
#
# ⚠ 第一版没有这个清单，结果把**历史文档**当成漂移报了 30 多处假阳性：
#   「方法论 v2.1 全流程验证报告 · Day 8」里写 v2.1 / 12 条纪律 ——
#   那是**当时的真实状态**，改它等于伪造历史。
#
#   这是纪律 12（判定条件必须与名字语义一致）的又一活样本：
#   这个检查器的名字叫「文档漂移」，它判的却是「数字不等于当前值」。
#   历史记录里的旧数字不是漂移，是记录。
#
# ⇒ 豁免必须**显式登记 + 写明理由**，不能静默跳过。
#   静默跳过会让检查器慢慢变成摆设，而且没人知道它放过了什么。

HISTORICAL = [
    # (文件名包含, 豁免理由)
    ("_Day8", "Day 8 的历史报告，v2.1 / 12 条纪律是当时的真实状态"),
    ("_Day9", "Day 9 的历史报告，v2.2 / 14 条纪律是当时的真实状态"),
    ("Day9收尾", "Day 9 收尾报告，同上"),
    ("审计报告模板", "报告模板，自带模板版本号；v1.0 是待填占位字段"),
    ("审计报告样例", "脱敏样例报告，快照性质"),
    ("SCR指标", "另一项目（筹码扫描）的产出，与本方法论版本无关"),
    ("情绪周期", "另一项目（筹码扫描）的产出，与本方法论版本无关"),
    ("投资市场心理", "读书笔记类产出，与本方法论版本无关"),
    ("Python重型依赖", "环境调研笔记，不涉及方法论版本"),
    ("AI-Agent安全审计服务_30天执行规划", "Day 1 制定的原始规划，历史文件"),
    ("day1-执行记录", "历史执行记录"),
    ("day4-执行记录", "历史执行记录"),
    ("day5-执行记录", "历史执行记录"),
    ("day6-执行记录", "历史执行记录"),
]


def is_historical(name):
    for frag, why in HISTORICAL:
        if frag in name:
            return why
    return None

PATTERNS = [
    # (名字, 正则, 期望值来源 key)
    ("版本号", re.compile(r"v(\d+\.\d+)"), "version"),
    ("纪律条数", re.compile(r"(\d+)\s*条(?:执行)?纪律"), "disciplines"),
    # ⚠ 中间要允许「一键」这类修饰词：第一版写成 (\d+)\s*项(?:自动化)?回归，
    #   于是落地页的「24 项一键回归」**没被匹配到** —— 一个查漂移的检查器
    #   漏了自己该查的东西（纪律 9：先证明判定器看见了被测对象）。
    ("回归项数", re.compile(r"(\d+)\s*项[^，。；：\s]{0,6}回归"), "regression"),
]


def collect_docs(extra=None):
    out = []
    for d, exts in DEFAULT_DIRS + list(extra or []):
        d = os.path.normpath(d)
        if not os.path.isdir(d):
            continue
        for fn in sorted(os.listdir(d)):
            if fn in EXCLUDE:
                continue
            if fn.lower().endswith(exts):
                out.append(os.path.join(d, fn))
    for f in DEFAULT_FILES:
        if os.path.isfile(f):
            out.append(f)
    return out


def main():
    import argparse
    ap = argparse.ArgumentParser(description="文档漂移 / 检查项撞号 自动检查")
    ap.add_argument("--docs", action="append",
                    help="额外要扫的目录（可重复）。仓库外的交付文档用这个传。")
    a = ap.parse_args()

    print("=" * 72)
    print("文档漂移 / 检查项撞号 · 自动检查")
    print("=" * 72)

    if not os.path.isfile(METH):
        print("STATUS: SKIPPED —— 找不到方法论文件：%s" % METH)
        return 1

    meth = io.open(METH, encoding="utf-8").read()
    version = derive_version(meth)
    disciplines = derive_disciplines(meth)
    regression = derive_regression()
    checks = derive_checks()

    print("\n[A] 从源码推导的事实")
    print("-" * 72)
    print("  方法论版本     : %s" % (version or "**推导失败**"))
    print("  纪律条数       : %s" % (disciplines or "**推导失败**"))
    print("  回归任务数     : %s" % (regression or "**推导失败**"))
    print("  检查项 ID 数   : %d" % len(checks))
    if not (version and disciplines and regression):
        print("\nSTATUS: FAIL —— 事实推导不完整，后面的比对没有意义。")
        return 1

    # ---------------- B. 撞号 ----------------
    print("\n[B] 检查项 ID 唯一性")
    print("-" * 72)
    # ⚠ 只比对**真实标题**，忽略「无 title」的条目：
    #   第一版把「无 title」也算成一个独立标题，于是 G3r（同一文件里一处带
    #   标题、一处不带）被误报成撞号。空值不是证据 —— 这是纪律 9 的变体。
    collisions = {}
    for k, v in checks.items():
        titles = {t for t, _ in v if t != "（无 title）"}
        if len(titles) > 1:
            collisions[k] = v
    if collisions:
        for cid, v in sorted(collisions.items()):
            print("  ✗ ID「%s」对应 %d 个不同标题：" % (cid, len(v)))
            for t, fn in sorted(v):
                print("      · %-40s (%s)" % (t[:40], fn))
        print()
        print("  ⇒ 合并台账里这个 ID 是歧义项。统计脚本会把它当成一个。")
    else:
        print("  ✓ 全部 %d 个 ID 唯一，无撞号。" % len(checks))

    # ---------------- C. 文档扫描 ----------------
    canon = {"version": version, "disciplines": disciplines,
             "regression": regression}
    extra = [(d, (".md", ".html")) for d in (a.docs or [])]
    docs = collect_docs(extra)
    print("\n[C] 扫描对外文档 %d 份" % len(docs))
    print("-" * 72)
    if not docs:
        print("  ⚠ **一份都没扫到** —— 这不是通过，是没测成。")
        print("    检查 --docs 指向的目录是否存在（跨盘符时相对路径拼不出去）。")
        print()
        print("STATUS: SKIPPED —— 文档扫描未执行，不构成『文档一致』的结论。")
        return 1

    exempted = []
    problems = []
    for path in docs:
        try:
            txt = io.open(path, encoding="utf-8", errors="replace").read()
        except Exception:
            continue
        name = os.path.basename(path)
        why = is_historical(name)
        if why:
            exempted.append((name, why))
            continue
        for lineno, line in enumerate(txt.splitlines(), 1):
            for label, pat, key in PATTERNS:
                for m in pat.finditer(line):
                    got = m.group(1)
                    want = str(canon[key])
                    if got == want:
                        continue
                    # 版本号形态不同（v2.5 vs 2.5），统一比较
                    if key == "version" and ("v" + got) == want:
                        continue
                    ctx = line.strip()
                    if len(ctx) > 76:
                        ctx = ctx[:73] + "..."
                    problems.append((name, lineno, label, got, want, ctx))

    if exempted:
        print("  已豁免历史文档 %d 份（理由必须写明，见 HISTORICAL 清单）：" % len(exempted))
        for n, w in exempted:
            print("    · %-42s %s" % (n[:42], w))
        print()

    if not problems:
        print("  ✓ 未发现与事实不符的数字。")
    else:
        cur = None
        for name, lineno, label, got, want, ctx in problems:
            if name != cur:
                print("\n  %s" % name)
                cur = name
            print("    L%-4d %s：写了 %s，应为 %s" % (lineno, label, got, want))
            print("           %s" % ctx)

    # ---------------- 结论 ----------------
    print()
    print("=" * 72)
    n = len(problems) + len(collisions)
    if n == 0:
        print("STATUS: OK —— 文档一致，检查项 ID 无撞号。")
        return 0
    print("STATUS: FAIL —— %d 处漂移 + %d 处撞号。"
          % (len(problems), len(collisions)))
    print()
    print("  ⚠ 这个检查器只能保证**文档之间一致**，不能保证数字本身是对的。")
    print("    数字对不对，仍要人判断。")
    return 1


if __name__ == "__main__":
    sys.exit(main())
