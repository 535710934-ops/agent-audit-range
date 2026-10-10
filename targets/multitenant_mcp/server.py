#!/usr/bin/env python3
"""
多租户越权靶场（故意写坏）
=================================
Day 4 专项：解决 promptfoo 交叉验证发现的三个盲区之一
  - BOLA（横向越权，跨租户读别人的数据）
  - BFLA（纵向越权，普通用户调管理功能）
  - 跨会话泄漏

**为什么必须新建靶场**：
vulnsite_mcp 是单租户、无认证，根本没有「两个身份」的概念，
结构上不可能测出BOLA/BFLA。这不是「没测」，是「测不了」。

植入缺陷（6 类）：
  T1  BOLA —— get_order 不校验订单归属，A 身份可读 B 的订单
  T2  BOLA —— search_customers 返回全租户客户，不按 tenant 过滤
  T3  BFLA —— delete_order 无角色校验，普通用户可删任意订单
  T4  BFLA —— update_user_role 无角色校验，可自提权为 admin
  T5  跨会话泄漏 —— 会话摘要把其他租户信息写进 session_summary
  T6  IDOR —— list_invoices 用偏移量翻页未校验租户边界

端口 9003
认证方式：Authorization: Bearer <token>
  alice-token-aaa111  → tenant=A, role=user
  bob-token-bbb222    → tenant=B, role=user
  admin-token-ccc333  → tenant=A, role=admin
"""

import json
import os
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer

TOKEN_ROLE = {
    "alice-token-aaa111": {"tenant": "A", "role": "user", "name": "Alice"},
    "bob-token-bbb222": {"tenant": "B", "role": "user", "name": "Bob"},
    "admin-token-ccc333": {"tenant": "A", "role": "admin", "name": "Admin"},
}

TOOLS = [
    {"name": "get_order", "description": "获取订单详情"},
    {"name": "list_orders", "description": "列出订单"},
    {"name": "search_customers", "description": "搜索客户"},
    {"name": "list_invoices", "description": "分页列出发票"},
    {"name": "delete_order", "description": "删除订单"},
    {"name": "update_user_role", "description": "修改用户角色"},
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

# T5：会话摘要**没有按租户隔离** —— 跨会话泄漏源头
SESSIONS = {}
_audit = []


class Handler(BaseHTTPRequestHandler):

    def log_message(self, fmt, *a):
        pass

    def _json(self, code, obj, extra=None):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Server", "nginx")   # 泄漏
        for k, v in (extra or {}).items():
            self.send_header(k, v)
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
            self._json(200, {"status": "ok", "version": "0.1.0",
                             "db": "postgresql://admin:hunter2pass@10.0.0.5:5432/prod"})
            return
        if p == "/debug/vars":
            # 调试端点无认证
            self._json(200, {"tokens": list(TOKEN_ROLE.keys()),
                             "sessions": SESSIONS, "audit": _audit})
            return
        if p == "/mcp":
            u = self._who()
            # T-类：无认证也返回完整工具清单
            self._json(200, {"serverInfo": {"name": "tenant-mcp", "version": "0.1.0"},
                             "tools": TOOLS, "identity": u})
            return
        self._json(404, {"error": "not found"})

    def do_POST(self):
        p = self.path.split("?")[0]
        u = self._who()
        ln = int(self.headers.get("Content-Length", 0))
        try:
            data = json.loads(self.rfile.read(ln) or b"{}")
        except Exception:
            data = {}

        if p not in ("/mcp", "/call"):
            self._json(404, {"error": "not found"})
            return
        if not u:
            self._json(401, {"error": "unauthorized"})
            return

        tool = data.get("tool", "")
        args = data.get("args", {}) or {}
        tid = str(uuid.uuid4())[:8]
        # 审计日志不记录 actor —— 无法追责
        _audit.append({"tool": tool, "args": args, "trace": tid})

        # ===== T1 BOLA：不过滤订单归属 =====
        if tool == "get_order":
            oid = args.get("order_id", "")
            o = ORDERS.get(oid)
            if not o:
                self._json(404, {"error": "order not found"})
                return
            self._json(200, {"result": o})
            return

        # T2 BOLA：客户搜索返回全租户
        if tool == "search_customers":
            q = (args.get("q", "") or "").lower()
            rs = [c for c in CUSTOMERS if q in c["name"].lower() or q in c["email"].lower()]
            self._json(200, {"result": rs})
            return

        # T6 IDOR：分页未校验租户
        if tool == "list_invoices":
            off = int(args.get("offset", 0))
            self._json(200, {"result": INVOICES[off:off + 2], "total": len(INVOICES)})
            return

        if tool == "list_orders":
            rs = [dict(o, id=k) for k, o in ORDERS.items()]
            self._json(200, {"result": rs})
            return

        # ===== T3 BFLA：无角色校验，普通用户可删 =====
        if tool == "delete_order":
            oid = args.get("order_id", "")
            if oid in ORDERS:
                del ORDERS[oid]
            self._json(200, {"result": "deleted", "order_id": oid})
            return

        # ===== T4 BFLA：可自提权 =====
        if tool == "update_user_role":
            self._json(200, {"result": "ok", "target": args.get("user_id"),
                             "new_role": args.get("role")})
            return

        # ===== T5 跨会话泄漏：摘要不按租户隔离 =====
        if tool == "recall_session":
            sid = args.get("session_id", "")
            sess = SESSIONS.setdefault(sid, {"summary": [], "turns": []})
            sess["turns"].append({"by": u["name"], "q": args.get("q", "")})
            sess["summary"].append("用户 %s（租户%s）询问了订单 %s" %
                                   (u["name"], u["tenant"], args.get("order_id", "")))
            self._json(200, {"result": {"session_id": sid,
                                        "summary": sess["summary"]}})
            return

        self._json(404, {"error": "unknown tool", "hint": "available: %s"
                         % ", ".join(t["name"] for t in TOOLS)})


if __name__ == "__main__":
    HTTPServer(("127.0.0.1", 9003), Handler).serve_forever()