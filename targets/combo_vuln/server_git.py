#!/usr/bin/env python3
"""
组合链靶场 · git-mcp 服务器
============================
模拟 MCP 生态里的 git 服务器。

漏洞模式（与 combo_safe 配对，端口差 2）：
  V1  write_file 可写**任意路径**（含 .git/hooks/、工作区任意位置）
  V2  read_file 可读任意路径（用于探测验证）
  V3  无内容白名单、无路径前缀校验

安全模式（combo_safe）：
  S1  write_file 限制在 /safe-writes/ 前缀内
  S2  路径穿越（../）被拒绝
  S3  read_file 同样限制

用法: python server.py <port> <vuln|safe> <workspace>
端口约定：漏洞对 9009，安全对 9011
"""

import json
import os
import sys
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 9009
MODE = sys.argv[2] if len(sys.argv) > 2 else "vuln"
WORKSPACE = os.path.abspath(sys.argv[3]) if len(sys.argv) > 3 else os.getcwd()

os.makedirs(WORKSPACE, exist_ok=True)
AUDIT = []

TOOLS = [
    {"name": "write_file", "description": "Write content to a file in the repo workspace"},
    {"name": "read_file", "description": "Read a file from the repo workspace"},
    {"name": "git_commit", "description": "Commit staged changes (git_init/git_commit/git_push/create_branch)"},
]


def _resolve(path):
    """解析请求路径。

    漏洞模式：任意路径，仅做工作区相对化。
    安全模式：强制 /safe-writes/ 前缀 + 拒绝穿越。
    """
    p = (path or "").lstrip("/\\")
    full = os.path.abspath(os.path.join(WORKSPACE, p))
    if MODE == "safe":
        # S2：拒绝路径穿越
        if not full.startswith(WORKSPACE):
            return None, "path traversal denied"
        # S1：强制写入隔离目录
        if not full.startswith(os.path.join(WORKSPACE, "safe-writes")):
            return None, "writes restricted to /safe-writes/"
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
            self._json(200, {"ok": True, "mode": MODE, "workspace": "workspace"})
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

        if tool == "write_file":
            full, err = _resolve(args.get("path", ""))
            if err:
                self._json(403, {"error": err})
                return
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with open(full, "w", encoding="utf-8", errors="replace") as f:
                f.write(str(args.get("content", "")))
            self._json(200, {"result": "written", "path": args.get("path"),
                             "trace": tid})
            return

        if tool == "read_file":
            full, err = _resolve(args.get("path", ""))
            if err:
                self._json(403, {"error": err})
                return
            if not os.path.isfile(full):
                self._json(404, {"error": "no such file"})
                return
            with open(full, "r", encoding="utf-8", errors="replace") as f:
                self._json(200, {"result": f.read(4000), "trace": tid})
            return

        if tool == "git_commit":
            # 只更新内部状态，不真正跑 git —— 关键是 write_file 才是写入口
            self._json(200, {"result": "committed", "trace": tid})
            return

        self._json(404, {"error": "unknown tool",
                         "hint": "available: write_file, read_file, git_commit"})

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    print("git-mcp [%s] listening http://127.0.0.1:%d  workspace=%s"
          % (MODE, PORT, WORKSPACE))
    HTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
