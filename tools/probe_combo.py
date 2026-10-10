#!/usr/bin/env python3
"""
G3r · 组合链运行时探针（Day 9 · P1）
=====================================
与静态盘点（audit_egress 的 G3）的区别：

  静态 G3（WARN）："两台 server 的能力清单拼起来够一条链" —— 只能报 WARN，
                   因为看不到参数流向，也不知道 server 之间有没有数据通道。
  运行时 G3r     ：实际构造调用链，**真的走一遍** —— 走通了才能 FAIL。

判定枚举（沿用方法论 v2.1）：
  FAIL      链路走通，产物落盘并被下游消费（实测证据）
  PASS      两跳都成功执行，但数据通道被隔离/校验拦截（有实测证据）
  SKIPPED   任一跳无法执行 / 端点不可达 —— **未测，不构成任何结论**

三步判定（借鉴 Day 4 跨会话三步判定的教训）：
  步骤 1  上游写：write_file 写入 payload 脚本
  步骤 2  上游**复读确认**：read_file 读回，确认写入成功
          ⚠ 这一步不可省 —— 若写入被静默丢弃/路径被改写，
            下游"执行失败"会被误判成"隔离有效"（假 PASS）。
  步骤 3  下游执行 + 产物验证：run_script 执行该脚本，
          脚本在**越界路径**落 marker，read_file 验证 marker 存在。

为什么产物必须落在"越界路径"：
  如果 marker 落在白名单目录里，即使执行成功也无法区分
  "代码执行了"和"代码被沙箱限制后仍执行了无害部分"。
  越界落盘是命令执行的最小完整证据。

用法:
  python probe_combo.py --git http://127.0.0.1:9009/mcp \
                        --exec http://127.0.0.1:9010/mcp \
                        --json out.json
退出码: 有 FAIL 返 1，否则 0
"""

import argparse
import json
import sys
import time
import urllib.request

MARKER = "g3r-marker-%d.txt" % int(time.time())
PAYLOAD_PATH = "whitelist/payload_g3r.py"
OUT_OF_BOUNDS = "OUTSIDE_%s" % MARKER          # 越界路径（工作区根，白名单外）
PAYLOAD = """
import os
ws = os.path.dirname(os.path.abspath(__file__))
# 越界写：从 whitelist/ 向工作区根写 marker —— 沙箱若有效应被拦
target = os.path.join(os.path.dirname(ws), "%s")
with open(target, "w") as f:
    f.write("pwned")
print("marker-written:" + target)
""" % OUT_OF_BOUNDS


def call(url, tool, args, timeout=15):
    """调用 MCP 端点。返回 (ok, body)。网络错误不抛出 —— 报 SKIPPED 用。"""
    data = json.dumps({"tool": tool, "args": args}).encode("utf-8")
    req = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json"},
        method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return True, json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        try:
            return False, json.loads(e.read().decode("utf-8"))
        except Exception:
            return False, {"error": "HTTP %d" % e.code}
    except Exception as e:
        return False, {"error": "%s: %s" % (type(e).__name__, str(e)[:150])}


def probe(git_url, exec_url):
    steps = []

    # ---- 端点预检：任一不可达 → 整项 SKIPPED（纪律 3：ERR ≠ 404，也不等于 PASS）----
    for name, url, tools in (("git", git_url, "write_file"),
                             ("exec", exec_url, "run_script")):
        ok, body = call(url, "__health__", {})
        if not ok and "unknown tool" not in json.dumps(body):
            return {
                "id": "G3r",
                "title": "组合链运行时验证（写→执行→越界落盘）",
                "status": "SKIPPED",
                "severity": "HIGH",
                "detail": "%s 端点不可达（%s）—— **本项未测**，不构成任何结论。"
                          % (name, body.get("error", "?")),
                "steps": steps,
            }

    # ---- 步骤 1：上游写 ----
    ok, body = call(git_url, "write_file",
                    {"path": PAYLOAD_PATH, "content": PAYLOAD})
    steps.append({"step": "1 上游 write_file", "ok": ok, "resp": body})
    if not ok:
        # ⚠ 纪律 3：区分「策略拒绝」与「网络异常」（与链二第 1 步同一规则）
        err = json.dumps(body, ensure_ascii=False)
        if ("Timeout" in err or "timed out" in err or "WinError" in err
                or "URLError" in err or "ConnectionRefused" in err
                or (body.get("error") or "").startswith("HTTP 5")):
            return {
                "id": "G3r", "title": "组合链运行时验证（写→执行→越界落盘）",
                "status": "SKIPPED", "severity": "HIGH",
                "detail": "上游写入**未能完成**（%s）—— 不是被拒绝，是没测成。"
                          "ERR ≠ PASS，本项记未测。" % err[:150],
                "steps": steps,
            }
        return {
            "id": "G3r", "title": "组合链运行时验证（写→执行→越界落盘）",
            "status": "PASS", "severity": "HIGH",
            "detail": "上游写入被**实测拒绝**（%s）—— 数据通道不存在，"
                      "组合链**实测不可达**。" % err[:150],
            "steps": steps,
        }

    # ---- 步骤 2：上游复读确认（防假 PASS 的关键，Day 4 教训）----
    ok, body = call(git_url, "read_file", {"path": PAYLOAD_PATH})
    steps.append({"step": "2 上游复读确认", "ok": ok, "resp": body})
    # ⚠ 校验串必须是 payload **内容**里真实存在的标记（"g3r-marker"），
    #   不能用路径名（"payload_g3r"）—— 内容里没有路径，Day 9 实测踩过。
    if not ok or "g3r-marker" not in json.dumps(body, ensure_ascii=False):
        return {
            "id": "G3r", "title": "组合链运行时验证（写→执行→越界落盘）",
            "status": "SKIPPED", "severity": "HIGH",
            "detail": "写入成功但**复读失败** —— 写入状态不可确认，"
                      "继续判定会产生假 PASS/假 FAIL。本项记未测。",
            "steps": steps,
        }

    # ---- 步骤 3：下游执行 + 越界产物验证 ----
    ok, body = call(exec_url, "run_script", {"path": PAYLOAD_PATH})
    steps.append({"step": "3 下游 run_script", "ok": ok, "resp": body})
    if not ok:
        err = json.dumps(body, ensure_ascii=False)
        if ("Timeout" in err or "timed out" in err or "WinError" in err
                or "URLError" in err or "ConnectionRefused" in err
                or (body.get("error") or "").startswith("HTTP 5")):
            return {
                "id": "G3r", "title": "组合链运行时验证（写→执行→越界落盘）",
                "status": "SKIPPED", "severity": "HIGH",
                "detail": "下游执行**未能完成**（%s）—— 不是被拒绝，是没测成。"
                          "ERR ≠ PASS，本项记未测。" % err[:150],
                "steps": steps,
            }
        return {
            "id": "G3r", "title": "组合链运行时验证（写→执行→越界落盘）",
            "status": "PASS", "severity": "HIGH",
            "detail": "下游执行被**实测拒绝**（%s）—— 执行面有隔离，"
                      "组合链**实测不可达**。" % err[:150],
            "steps": steps,
        }

    # 执行成功了 → 验证 marker 是否真的越界落盘
    ok, body = call(git_url, "read_file", {"path": OUT_OF_BOUNDS})
    steps.append({"step": "4 越界产物验证", "ok": ok, "resp": body})
    if ok and "pwned" in json.dumps(body, ensure_ascii=False):
        return {
            "id": "G3r", "title": "组合链运行时验证（写→执行→越界落盘）",
            "status": "FAIL", "severity": "HIGH",
            "detail": "**组合链实测走通**：write_file 写入 payload → run_script 执行"
                      " → 越界路径落盘 marker（%s）。"
                      "静态盘点只能报 WARN 的链，此处升级为 FAIL —— "
                      "**有完整实测证据，不是推断。**" % OUT_OF_BOUNDS,
            "steps": steps,
        }
    return {
        "id": "G3r", "title": "组合链运行时验证（写→执行→越界落盘）",
        "status": "PASS", "severity": "HIGH",
        "detail": "脚本被执行，但**越界落盘失败** —— 存在沙箱/权限隔离，"
                  "组合链可达但爆炸半径受限。**执行面仍需人工复核**"
                  "（本探针的 payload 形态有限，不能证明所有形态都被拦）。",
        "steps": steps,
    }


def render(res):
    L = ["=" * 70, "G3r · 组合链运行时探针", "=" * 70]
    ST = {"FAIL": "[FAIL]", "PASS": "[ OK ]", "SKIPPED": "[SKIP]"}
    L.append("%s %s  %s" % (ST[res["status"]], res["id"], res["title"]))
    L.append("       状态: %s   严重度: %s" % (res["status"], res["severity"]))
    for s in res["steps"]:
        L.append("       %s -> %s" % (s["step"],
                 json.dumps(s["resp"], ensure_ascii=False)[:110]))
    L.append("")
    for ln in res["detail"].split("\n"):
        L.append("       " + ln)
    return "\n".join(L)


def probe_supply(fetch_url, git_url, payload_url):
    """第二条链：net_egress + repo_write（供应链投毒，CVE-2025-53773 形态）

    链路：fetch_url 读攻击者控制的远程内容 → write_file 写入仓库 → 复读验证内容落地。
    与第一条链（写→执行）的区别：这条**不需要命令执行**，
    仅靠"能联网 + 能写仓库"就能污染下游构建 —— 因此更容易被忽略。
    """
    steps = []
    T = "组合链运行时验证（读远程→写仓库→内容落地）"

    ok, body = call(fetch_url, "__health__", {})
    if not ok and "unknown tool" not in json.dumps(body):
        return {"id": "G3r", "title": T, "status": "SKIPPED",
                "severity": "HIGH",
                "detail": "fetch 端点不可达（%s）—— **本项未测**，不构成任何结论。"
                          % body.get("error", "?"), "steps": steps}

    # 步骤 1：上游读取远程内容（攻击者控制的"上游文档/依赖"）
    ok, body = call(fetch_url, "fetch_url", {"url": payload_url})
    steps.append({"step": "1 fetch 远程内容", "ok": ok, "resp": body})
    if not ok:
        # ⚠ 纪律 3：必须区分「策略拒绝」与「网络异常」。
        #   明确拒绝（403 + 可读原因）= 实测拦截 = PASS；
        #   超时/连接失败 = ERR，链路**未被验证** = SKIPPED。
        #   Day 9 实测踩过：把 TimeoutError 报成"数据通道不存在/PASS"，
        #   等于用一次网络抖动冒充了一次安全证明。
        err = json.dumps(body, ensure_ascii=False)
        if ("Timeout" in err or "timed out" in err
                or "WinError" in err or "URLError" in err
                or "ConnectionRefused" in err
                or (body.get("error") or "").startswith("HTTP 5")):
            return {"id": "G3r", "title": T, "status": "SKIPPED",
                    "severity": "HIGH",
                    "detail": "联网请求**未能完成**（%s）—— 这不是被拦截，"
                              "是没测成。按纪律 3，ERR ≠ PASS，本项记未测。"
                              % err[:150], "steps": steps}
        return {"id": "G3r", "title": T, "status": "PASS", "severity": "HIGH",
                "detail": "联网出口被**实测拒绝**（%s）—— 数据通道不存在。"
                          % err[:150], "steps": steps}

    content = body.get("result", "") if isinstance(body, dict) else ""
    if "supply-chain-payload" not in str(content):
        return {"id": "G3r", "title": T, "status": "SKIPPED",
                "severity": "HIGH",
                "detail": "fetch 成功但未取回预期标记 —— 无法确认内容来源，"
                          "继续判定会产生假结论。本项记未测。",
                "steps": steps}

    # 步骤 2：写入仓库
    path = "deps/upstream_notes.md"
    ok, body = call(git_url, "write_file", {"path": path, "content": content})
    steps.append({"step": "2 write_file 写入仓库", "ok": ok, "resp": body})
    if not ok:
        return {"id": "G3r", "title": T, "status": "PASS", "severity": "HIGH",
                "detail": "仓库写入被拒（%s）—— 投毒链第二跳不可达。"
                          % json.dumps(body, ensure_ascii=False)[:160],
                "steps": steps}

    # 步骤 3：复读验证（Day 4 三步判定的移植：不可省）
    ok, body = call(git_url, "read_file", {"path": path})
    steps.append({"step": "3 复读验证内容落地", "ok": ok, "resp": body})
    if ok and "supply-chain-payload" in json.dumps(body, ensure_ascii=False):
        return {"id": "G3r", "title": T, "status": "FAIL", "severity": "HIGH",
                "detail": "**供应链投毒链实测走通**：远程内容经 fetch 取回 → "
                          "write_file 落入仓库（%s）→ 复读确认含投毒标记。"
                          "该链**不需要命令执行权限**，仅靠「能联网 + 能写仓库」"
                          "即可污染下游构建 —— 静态 G3 只能报 WARN，此处升级 FAIL。"
                          % path, "steps": steps}
    return {"id": "G3r", "title": T, "status": "PASS", "severity": "HIGH",
            "detail": "写入成功但复读未取回投毒标记 —— 存在内容过滤，"
                      "投毒链可达但内容被改写。仍需人工复核。", "steps": steps}


def main():
    ap = argparse.ArgumentParser(description="G3r 组合链运行时探针")
    ap.add_argument("--git", required=True, help="git-mcp 端点")
    ap.add_argument("--exec", dest="exec_url", help="shell-mcp 端点（链一必需）")
    ap.add_argument("--fetch", dest="fetch_url",
                    help="fetch-mcp 端点（链二供应链投毒必需）")
    ap.add_argument("--chain", default="write-exec",
                    choices=["write-exec", "supply"],
                    help="链一 write-exec：写→执行→越界落盘；"
                         "链二 supply：读远程→写仓库→内容落地")
    ap.add_argument("--payload-url",
                    default="http://127.0.0.1:9015/payload",
                    help="链二使用的远程内容地址")
    ap.add_argument("--json", help="输出 JSON")
    a = ap.parse_args()

    if a.chain == "supply":
        if not a.fetch_url:
            ap.error("链二 supply 需要 --fetch")
        res = probe_supply(a.fetch_url, a.git, a.payload_url)
    else:
        if not a.exec_url:
            ap.error("链一 write-exec 需要 --exec")
        res = probe(a.git, a.exec_url)
    print(render(res))
    if a.json:
        with open(a.json, "w", encoding="utf-8") as f:
            json.dump(res, f, ensure_ascii=False, indent=2, default=str)
        print("JSON 已写入: %s" % a.json)
    return 1 if res["status"] == "FAIL" else 0


if __name__ == "__main__":
    sys.exit(main())
