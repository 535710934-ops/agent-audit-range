#!/usr/bin/env python3
"""
组合链靶场 · shell-mcp 服务器
==============================
模拟 MCP 生态里的脚本执行服务器。

漏洞模式（与 combo_safe 配对，端口差 2）：
  V1  run_script 可执行工作区**任意**脚本（无白名单）
  V2  可执行 .git/hooks/ 里的内容（组合链第二跳的关键）

安全模式（combo_safe）：
  S1  仅可执行 /whitelist/ 目录下的脚本
  S2  拒绝路径穿越

用法: python server_exec.py <port> <vuln|safe> <workspace>
端口约定：漏洞对 9010，安全对 9012
"""

import json
import os
import subprocess
import sys
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 9010
MODE = sys.argv[2] if len(sys.argv) > 2 else "vuln"
WORKSPACE = os.path.abspath(sys.argv[3]) if len(sys.argv) > 3 else os.getcwd()

os.makedirs(WORKSPACE, exist_ok=True)
AUDIT = []

TOOLS = [
    {"name": "run_script", "description": "Execute a script in the workspace (run_command/execute_command)"},
]


def _resolve(path):
    p = (path or "").lstrip("/\\")
    full = os.path.abspath(os.path.join(WORKSPACE, p))
    if MODE == "safe":
        if not full.startswith(WORKSPACE):
            return None, "path traversal denied"
        # S1：只允许白名单目录
        if not full.startswith(os.path.join(WORKSPACE, "whitelist")):
            return None, "execution restricted to /whitelist/"
    return full, None


class Handler(BaseHTTPRequestHandler):
    def _json(self, code, obj):
        b = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        p = self.path.split("?")[0]
        if p == "/health":
            self._json(200, {"ok": True, "mode": MODE})
            return
        if p == "/mcp":
            self._json(200, {"tools": TOOLS})
            return
        self._json(404, {"error": "not found"})

    def do_POST(self):
        p = self.path.split("?")[0]
        ln = int(self.headers.get("Content-Length", 0))
        try:
            data = json.loads(self.rfile.read(ln) or b"{}")
        except Exception:
            data = {}
        if p not in ("/mcp", "/call"):
            self._json(404, {"error": "not found"})
            return

        tool = data.get("tool", "")
        args = data.get("args", {}) or {}
        tid = str(uuid.uuid4())[:8]
        AUDIT.append({"tool": tool, "args": args, "trace": tid})

        if tool == "run_script":
            full, err = _resolve(args.get("path", ""))
            if err:
                self._json(403, {"error": err, "trace": tid})
                return
            if not os.path.isfile(full):
                self._json(404, {"error": "no such script", "trace": tid})
                return
            # 真实执行：脚本内只允许写 marker 与打印（我们自己的脚本可控）
            try:
                r = subprocess.run(
                    [sys.executable, full],
                    capture_output=True, text=True, timeout=10,
                    cwd=WORKSPACE,
                    env={k: v for k, v in os.environ.items()
                         if "proxy" not in k.lower()})
                self._json(200, {"result": {"stdout": r.stdout[-2000:],
                                            "stderr": r.stderr[-500:],
                                            "code": r.returncode},
                                 "trace": tid})
            except Exception as e:
                self._json(500, {"error": str(e)[:200], "trace": tid})
            return

        self._json(404, {"error": "unknown tool", "hint": "available: run_script"})

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    print("shell-mcp [%s] listening http://127.0.0.1:%d  workspace=%s"
          % (MODE, PORT, WORKSPACE))
    HTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
