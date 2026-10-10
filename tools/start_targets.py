#!/usr/bin/env python3
"""
一键启动全部靶场（Day 10 · 开源可用性）
=======================================
为什么要有这个脚本：

  run_all.py 的注释写着「本脚本不启动靶场」。对作者本人无所谓 ——
  他知道要开 16 个终端。但对拿到这个仓库的人是**无解的**：
  22 项回归全部会记 ERR，然后他会以为工具是坏的。

  ⇒ **可运行性是开源交付的一部分。** 没有启动器的靶场仓库等于没交付。

用法
----
    python tools/start_targets.py            # 起全部 16 个，前台常驻，Ctrl+C 全停
    python tools/start_targets.py --check    # 只做存活检查，不启动
    python tools/start_targets.py --ports 9001,9009,9010   # 只起部分

设计要点
--------
  1. **前台常驻**：不用 `&` 后台。本环境实测 `&` 起的进程会被回收
     （Day 9 踩过：起完就断，run_all 全线 ERR）。常驻父进程 + Ctrl+C 全停最稳。
  2. **剥代理变量**：子进程必须清 HTTP_PROXY/HTTPS_PROXY 等 6 个，否则全超时。
  3. **存活判定不能只看 200**：9001 的 /health **故意返回 500**（植入的堆栈泄漏），
     urllib 会抛 HTTPError。收到任何响应都算在线 —— 纪律 3 的活样本。
  4. 工作区目录（ws_vuln / ws_safe）自动建在 `runs/` 下，不污染 targets/。
"""
import argparse
import os
import subprocess
import sys
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PY = sys.executable

# 子进程必须剥掉的代理变量
_ENV = dict(os.environ)
for k in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy",
          "ALL_PROXY", "all_proxy"):
    _ENV.pop(k, None)

WS_VULN = os.path.join(ROOT, "runs", "ws_vuln")
WS_SAFE = os.path.join(ROOT, "runs", "ws_safe")

# (端口, 脚本相对 ROOT 的路径, 额外参数)
T = lambda script, *args: [os.path.join(ROOT, "targets", *script.split("/"))] + list(args)

TARGETS = [
    (9001, T("vulnsite_mcp/server.py"),        "MCP 漏洞站（无认证 / 注入载荷 / 任意执行）"),
    (9002, T("cleansite_mcp/server.py"),       "MCP 干净站（阴性对照）"),
    (9003, T("multitenant_mcp/server.py"),     "多租户漏洞版"),
    (9004, T("multitenant_safe/server.py"),    "多租户安全版（阴性对照）"),
    (9005, T("service_principal_mcp/server.py"), "服务主体漏洞版（平台级密钥）"),
    (9006, T("service_principal_safe/server.py"), "服务主体安全版（阴性对照）"),
    (9007, T("egress_vulnsite/server.py"),     "外联漏洞站（含部署泄漏路径）"),
    (9008, T("egress_safesite/server.py"),     "外联安全站（阴性对照）"),
    (9009, T("combo_vuln/server_git.py", "9009", "vuln", WS_VULN), "git-mcp 漏洞版"),
    (9010, T("combo_vuln/server_exec.py", "9010", "vuln", WS_VULN), "shell-mcp 漏洞版"),
    (9011, T("combo_vuln/server_git.py", "9011", "safe", WS_SAFE), "git-mcp 安全版（阴性对照）"),
    (9012, T("combo_vuln/server_exec.py", "9012", "safe", WS_SAFE), "shell-mcp 安全版（阴性对照）"),
    (9013, T("multiturn/server.py", "9013", "vuln"), "多轮升级模拟器 漏洞版"),
    (9014, T("multiturn/server.py", "9014", "safe"), "多轮升级模拟器 安全版（阴性对照）"),
    (9015, T("combo_supply/server_fetch.py", "9015", "vuln"), "fetch-mcp 漏洞版"),
    (9016, T("combo_supply/server_fetch.py", "9016", "safe"), "fetch-mcp 安全版（阴性对照）"),
]


# ⚠ 存活检查必须**强制禁用代理**。
#   子进程我们剥了代理变量，但父进程没有 —— 环境里若设了
#   http_proxy=127.0.0.1:56345（本机实测就是这么设的），urlopen 会去问代理，
#   代理不通 → 超时 → 判定「未响应」，而靶场其实早就监听上了。
#   症状极具误导性：日志里明明写着「监听 :9001」，check 却报离线。
#   ⇒ 用空 ProxyHandler 的 opener，与环境变量彻底解耦。
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def alive(port, timeout=1.5):
    """⚠ 收到响应就算在线 —— 9001 故意返回 500，不能当成「没起来」。"""
    try:
        _OPENER.open("http://127.0.0.1:%d/health" % port,
                     timeout=timeout).read()
        return True
    except urllib.error.HTTPError:
        return True          # 500 也是「服务在」，只是这个端点故意报错
    except Exception:
        return False


def wait_up(port, secs=12):
    deadline = time.time() + secs
    while time.time() < deadline:
        if alive(port):
            return True
        time.sleep(0.3)
    return False


def main():
    ap = argparse.ArgumentParser(description="一键启动 agent 安全审计靶场")
    ap.add_argument("--check", action="store_true", help="只检查存活，不启动")
    ap.add_argument("--ports", help="只起指定端口，逗号分隔")
    a = ap.parse_args()

    want = None
    if a.ports:
        want = {int(p) for p in a.ports.split(",") if p.strip()}

    if a.check:
        up = [p for p, _, _ in TARGETS if (want is None or p in want) and alive(p)]
        for p, cmd, desc in TARGETS:
            if want is not None and p not in want:
                continue
            print("  %-5s %s  %s" % (p, "在线  " if alive(p) else "**离线**", desc))
        print("\n%d/%d 在线" % (len(up), len([1 for p, _, _ in TARGETS
                                              if want is None or p in want])))
        return 0 if len(up) == len([1 for p, _, _ in TARGETS
                                    if want is None or p in want]) else 1

    for d in (WS_VULN, WS_SAFE):
        os.makedirs(d, exist_ok=True)

    procs = []
    print("=" * 74)
    print("启动靶场（Ctrl+C 全部停止）")
    print("=" * 74)
    try:
        for port, cmd, desc in TARGETS:
            if want is not None and port not in want:
                continue
            if alive(port):
                print("  %-5s 已在线，跳过   %s" % (port, desc))
                continue
            # ⚠ 不能把 stdout/stderr 丢进 DEVNULL。
            #   起不来时必须能看到原因（端口占用 / ImportError / 路径错），
            #   否则用户只看到「未响应」，无从下手 —— 这跟纪律 3 是同一条：
            #   **不能把失败藏起来。**
            log_dir = os.path.join(ROOT, "runs", "logs")
            os.makedirs(log_dir, exist_ok=True)
            lf = open(os.path.join(log_dir, "target-%d.log" % port), "w",
                      encoding="utf-8")
            # ⚠ 必须加 -u：stdout 重定向到文件时 Python 用块缓冲，
            #   进程一崩，缓冲区里的 ImportError / WinError 10048 就全丢了，
            #   日志留下 0 字节，用户只看到「未响应」四个字。
            try:
                p = subprocess.Popen([PY, "-u"] + cmd, env=_ENV, cwd=ROOT,
                                     stdout=lf, stderr=subprocess.STDOUT)
                procs.append((port, p, lf))
            except Exception as e:
                print("  %-5s **启动失败** %s —— %s" % (port, desc, e))
                lf.close()
                continue
            # 进程秒退就没必要等满 12s —— 直接读日志，别让用户干等
            time.sleep(0.4)
            if p.poll() is not None:
                ok = False
            else:
                ok = wait_up(port)
            print("  %-5s %s  %s" % (port, "已启动" if ok else "**未响应**", desc))
            if not ok:
                try:
                    lf.flush()
                    tail = open(lf.name, encoding="utf-8").read().strip()
                    for line in tail.splitlines()[-4:]:
                        print("         └ %s" % line[:100])
                    print("         完整日志：%s" % os.path.relpath(lf.name, ROOT))
                except Exception:
                    pass
        print("\n全部就绪。另开一个终端跑：python tools/run_all.py")
        print("停止：回到本窗口按 Ctrl+C\n")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n停止中…")
    finally:
        for item in procs:
            try:
                item[1].terminate()
            except Exception:
                pass
        for item in procs:
            try:
                item[1].wait(timeout=5)
            except Exception:
                try:
                    item[1].kill()
                except Exception:
                    pass
        for item in procs:
            try:
                item[2].close()
            except Exception:
                pass
        print("已停止 %d 个靶场。日志：runs/logs/" % len(procs))
    return 0


if __name__ == "__main__":
    sys.exit(main())
