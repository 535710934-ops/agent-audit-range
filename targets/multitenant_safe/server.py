#!/usr/bin/env python3
"""
多租户越权靶场 · 干净版（反向对照）
=================================
验证 audit_tenant.py **不会误报**。

与漏洞版的全部差异（对应 6 类缺陷）：
  T1 get_order       → 校验 order["tenant"] == me["tenant"]
  T2 search_customers→ 按 tenant 过滤后再搜
  T3 delete_order    → 校验角色 admin + 租户归属
  T4 update_user_role→ 校验角色 admin，且不能改自己
  T5 recall_session  → 会话按 (tenant, session_id) 命名空间隔离
  T6 list_invoices   → 先按 tenant 过滤，再分页
  /debug/vars        → 401
  /health            → 不含 db 连接串
  审计日志            → 记录 actor + tenant + trace_id

端口 9004
"""

import json
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer

TOKEN_ROLE = {
    "alice-token-aaa111": {"tenant": "A", "role": "user", "name": "Alice"},
    "bob-token-bbb222": {"tenant": "B", "role": "user", "name": "Bob"},
    "admin-token-ccc333": {"tenant": "A", "role": "admin", "name": "Admin"},
}

TOOLS = [
    {"name": "get_order", "description": "获取订单详情"},
    {"name": "list_orders", "description": "列出本租户订单"},
    {"name": "search_customers", "description": "搜索本租户客户"},
    {"name": "list_invoices", "description": "分页列出本租户发票"},
    {"name": "delete_order", "description": "删除订单（需管理员）"},
    {"name": "update_user_role", "description": "修改用户角色（需管理员）"},
]

ORDERS = {
    "ORD-1001": {"tenant": "A", "customer": "Acme Corp", "amount": 12500.00, "secret": "A-ONLY-NOTE"},
    "ORD-1002": {"tenant": "B", "customer": "Beta LLC", "amount": 890.50, "secret": "B-ONLY-NOTE"},
    "ORD-2001": {"tenant": "B", "customer": "Beta LLC", "amount": 45000.00, "secret": "B-BIG-DEAL"},
}

CUSTOMERS = [
    {"id": "C-A01", "tenant": "A", "name": "Alice", "email": "alice@acme.test", "ssn_last4": "1111"},
    {"id": "C-B01", "tenant": "B", "name": "Bob", "email": "bob@beta.test", "ssn_last4": "2222"},
    {"id": "C-B02", "tenant": "B", "name": "Bob2", "email": "bob2@beta.test", "ssn_last4": "3333"},
]

INVOICES = [
    {"id": "INV-A1", "tenant": "A", "amount": 100},
    {"id": "INV-B1", "tenant": "B", "amount": 200},
    {"id": "INV-B2", "tenant": "B", "amount": 300},
    {"id": "INV-B3", "tenant": "B", "amount": 400},
]

# T5 修复：会话命名空间包含 tenant
SESSIONS = {}
_audit = []


def _deny(code, msg, hint=""):
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
        return TOKEN_ROLE.get(h[7:])

    def do_GET(self):
        p = self.path.split("?")[0]

        if p in ("/health", "/healthz"):
            # 不含 db / 版本 / 路径
            self._json(200, {"status": "ok"})
            return
        if p in ("/debug/vars", "/debug", "/actuator"):
            self._json(401, _deny("unauthorized", ""))
            return
        if p == "/mcp":
            u = self._who()
            if not u:
                self._json(401, _deny("unauthorized", ""))
                return
            self._json(200, {"serverInfo": {"name": "tenant-mcp", "version": "0.1.0"},
                             "tools": TOOLS,
                             "identity": {"name": u["name"], "role": u["role"]}})
            return
        self._json(404, _deny("not found", ""))

    def do_POST(self):
        p = self.path.split("?")[0]
        u = self._who()
        if not u:
            self._json(401, _deny("unauthorized", ""))
            return

        ln = int(self.headers.get("Content-Length", 0))
        try:
            data = json.loads(self.rfile.read(ln) or b"{}")
        except Exception:
            data = {}

        if p not in ("/mcp", "/call"):
            self._json(404, _deny("not found", ""))
            return

        tool = data.get("tool", "")
        args = data.get("args", {}) or {}
        tid = str(uuid.uuid4())[:8]
        # 审计日志记录 actor + tenant + trace_id —— 可追责
        _audit.append({"actor": u["name"], "tenant": u["tenant"],
                       "role": u["role"], "tool": tool, "trace": tid})

        me = u["tenant"]

        if tool == "get_order":
            o = ORDERS.get(args.get("order_id", ""))
            if not o:
                self._json(404, _deny("order not found", ""))
                return
            if o["tenant"] != me:
                # 统一 404 —— 不暴露「存在但无权」
                self._json(404, _deny("order not found", ""))
                return
            self._json(200, {"result": o})
            return

        if tool == "search_customers":
            q = (args.get("q", "") or "").lower()
            rs = [c for c in CUSTOMERS if c["tenant"] == me and
                  (q in c["name"].lower() or q in c["email"].lower())]
            self._json(200, {"result": rs})
            return

        if tool == "list_invoices":
            mine = [i for i in INVOICES if i["tenant"] == me]
            off = int(args.get("offset", 0))
            self._json(200, {"result": mine[off:off + 2], "total": len(mine)})
            return

        if tool == "list_orders":
            rs = [dict(o, id=k) for k, o in ORDERS.items() if o["tenant"] == me]
            self._json(200, {"result": rs})
            return

        if tool == "delete_order":
            if u["role"] != "admin":
                self._json(403, _deny("forbidden", "admin role required"))
                return
            o = ORDERS.get(args.get("order_id", ""))
            if not o or o["tenant"] != me:
                self._json(404, _deny("order not found", ""))
                return
            del ORDERS[args["order_id"]]
            self._json(200, {"result": "deleted"})
            return

        if tool == "update_user_role":
            if u["role"] != "admin":
                self._json(403, _deny("forbidden", "admin role required"))
                return
            if args.get("user_id") == u["name"]:
                self._json(403, _deny("forbidden", "cannot escalate own role"))
                return
            self._json(200, {"result": "ok", "target": args.get("user_id")})
            return

        if tool == "recall_session":
            sid = "%s:%s" % (me, args.get("session_id", ""))
            sess = SESSIONS.setdefault(sid, {"summary": []})
            sess["summary"].append("用户 %s 询问订单 %s"
                                   % (u["name"], args.get("order_id", "")))
            self._json(200, {"result": {"summary": sess["summary"]}})
            return

        self._json(404, _deny("unknown tool", ""))


if __name__ == "__main__":
    HTTPServer(("127.0.0.1", 9004), Handler).serve_forever()