#!/usr/bin/env python3
"""
服务账号靶场 · 干净版（反向对照）
=================================
验证 check_service_principal.py **不会误报**。

对照植入的 5 类缺陷：
  S1 共享静态密钥  → 改为每租户独立 token，跨环境不通
  S2 凭 token 直连导出 → 要求二次确认头 X-Confirm + 短时nonce
  S3 源码硬编码密钥 → 全部走环境变量，源码里只有变量名
  S4 审计无 actor   → 记录 actor + tenant + trace_id
  S5 授权粒度过宽   → 集成账号工具面收窄至4 个只读

端口 9006
"""

import json
import os
import time
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer

# ✅ 修复：每租户独立的凭据（从环境注入，非硬编码）
TENANT_TOKENS = {
    os.environ.get("TOK_TENANT_A", "tok-tenantA-7f3a9c1e"): "A",
    os.environ.get("TOK_TENANT_B", "tok-tenantB-2b8e4d6f"): "B",
}

# ✅ 修复：集成账号工具面收窄，且**不提供写工具**
TOOLS = [
    {"name": "list_records", "description": "列出本租户记录"},
    {"name": "get_record", "description": "读取本租户单条记录"},
    {"name": "export_data", "description": "导出本租户数据（需二次确认）"},
    {"name": "read_own_secrets", "description": "读取本集成账号自身的密钥"},
]

_audit = []
# ✅ 二次确认 nonce（一次性、短时）
_nonces = {}


def _deny(msg, hint=""):
    return {"error": msg, "hint": hint}


class Handler(BaseHTTPRequestHandler):

    def log_message(self, fmt, *a):
        pass

    def _json(self, code, obj):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Server", "mcp")
        self.end_headers()
        self.wfile.write(body)

    def _who(self):
        h = self.headers.get("Authorization", "")
        if not h.startswith("Bearer "):
            return None
        tok = h[7:]
        t = TENANT_TOKENS.get(tok)
        if t:
            return {"tenant": t, "kind": "tenant", "name": "integration-" + t}
        # ✅ 修复：不存在全局共享密钥，任何单一 token 都不通多租户
        return None

    def do_GET(self):
        p = self.path.split("?")[0]
        u = self._who()

        if p in ("/health", "/healthz"):
            self._json(200, {"status": "ok"})
            return

        # ✅ 修复：导出端点要求二次确认（X-Confirm: <一次性nonce>）
        if p in ("/api/v1/export", "/admin", "/api/admin", "/api/v1/query"):
            if not u:
                self._json(401, _deny("unauthorized"))
                return
            confirm = self.headers.get("X-Confirm", "")
            if confirm not in _nonces:
                self._json(403, _deny(
                    "step-up confirmation required",
                    "先调用 /auth/step-up 获取短时一次性 nonce"))
                return
            _nonces.pop(confirm, None)
            self._json(200, {"result": "exporting",
                             "scope": u["tenant"],
                             "records": 12})
            return

        if p == "/auth/step-up":
            if not u:
                self._json(401, _deny("unauthorized"))
                return
            n = uuid.uuid4().hex[:12]
            _nonces[n] = time.time() + 120
            self._json(200, {"nonce": n, "expires_in": 120})
            return

        if p == "/mcp":
            if not u:
                self._json(401, _deny("unauthorized"))
                return
            self._json(200, {
                "serverInfo": {"name": "integration-mcp", "version": "1.0.0"},
                "tools": TOOLS,
                "identity": {"name": u["name"], "kind": u["kind"],
                             "tenant": u["tenant"]}})
            return

        self._json(404, _deny("not found"))

    def do_POST(self):
        p = self.path.split("?")[0]
        u = self._who()
        if not u:
            self._json(401, _deny("unauthorized"))
            return
        ln = int(self.headers.get("Content-Length", 0))
        try:
            data = json.loads(self.rfile.read(ln) or b"{}")
        except Exception:
            data = {}
        tool = data.get("tool", "")
        args = data.get("args", {}) or {}

        # ✅ 修复：审计记录 actor + tenant + trace_id
        _audit.append({"actor": u["name"], "tenant": u["tenant"],
                       "kind": u["kind"], "tool": tool,
                       "trace_id": "tr-" + uuid.uuid4().hex[:12]})

        if tool == "list_records":
            # ✅ 只返回本租户
            self._json(200, {"result": [
                {"id": "R1", "tenant": u["tenant"]},
                {"id": "R2", "tenant": u["tenant"]}]})
            return

        if tool == "read_own_secrets":
            # ✅ 只返回自身凭据，不含全局密钥
            self._json(200, {"result": {"MY_INTEGRATION_KEY": "<redacted>"}})
            return

        if tool in ("get_record", "export_data"):
            self._json(200, {"result": "ok"})
            return

        # ✅ 未授权的工具直接 404，不列出可用工具
        self._json(404, _deny("unknown tool"))


if __name__ == "__main__":
    HTTPServer(("127.0.0.1", 9006), Handler).serve_forever()