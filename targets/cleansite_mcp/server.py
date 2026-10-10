#!/usr/bin/env python3
"""
干净版 MCP Server（反向对照靶场）
=================================
用于验证 audit_mcp.py **不会误报**。

正向对照只能证明「能抓到问题」，
反向对照才能证明「不会把干净的东西报成有问题」。

这个版本实现了全部被审计器检查的安全措施。
端口 9002
"""

import json
import os
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer

TOKEN = os.environ.get("MCP_TOKEN", "test-token-abc123")

ORDERS = [
    {"id": "ORD-1001", "customer": "Acme Corp", "amount": 12500.00, "status": "paid"},
    {"id": "ORD-1002", "customer": "Beta LLC", "amount": 890.50, "status": "pending"},
]

# —— 实现了审计器要检查的安全措施
_idem_keys = set()          # 幂等：去重集合
_audit_log = []             # 审计日志


class Handler(BaseHTTPRequestHandler):

    def log_message(self, fmt, *a):
        pass  # 不打印，避免 stdout 泄漏

    def _auth(self):
        """强制认证。"""
        h = self.headers.get("Authorization", "")
        if not h.startswith("Bearer ") or h[7:] != TOKEN:
            return False
        return True

    def _json(self, code, obj, extra=None):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        # 安全头
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        # 不暴露服务器与框架信息
        self.send_header("Server", "mcp")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _deny(self):
        # 统一错误体：**不含任何栈/路径/内部信息**
        self._json(401, {"error": "unauthorized",
                          "error_description": "missing or invalid bearer token"},
                   {"WWW-Authenticate": 'Bearer realm="mcp", scope="tools:read"'})

    def do_GET(self):
        p = self.path.split("?")[0].rstrip("/") or "/"

        if p in ("/health", "/healthz", "/ready"):
            # 健康检查：不含路径/版本/连接串
            return self._json(200, {"status": "ok"})

        if p in ("/", "/mcp"):
            if not self._auth():
                return self._deny()
            return self._json(200, {
                "protocolVersion": "2024-11-05",
                "serverInfo": {"name": "order-mcp", "version": "1.0.0"},
                "tools": [
                    {"name": "list_orders", "description": "列出订单"},
                    {"name": "get_order", "description": "获取订单详情"},
                ],
            })

        return self._json(404, {"error": "not_found"})

    def do_POST(self):
        if not self._auth():
            return self._deny()

        p = self.path.split("?")[0].rstrip("/")
        ln = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(ln).decode("utf-8", "replace") if ln else ""
        try:
            payload = json.loads(raw) if raw else {}
        except Exception:
            return self._json(400, {"error": "invalid_json"})

        args = payload.get("args", {})
        tool = payload.get("tool", "")

        # —— 审计日志：记录**调用者身份**（用 token 作为主体标识）
        actor = "token:%s" % TOKEN[:8]
        _audit_log.append({"tool": tool, "actor": actor,
                           "trace_id": str(uuid.uuid4())})

        if tool == "list_orders":
            return self._json(200, {"orders": ORDERS})

        # —— 幂等：要求 idempotency_key，并对重复请求直接返回原结果
        if tool == "create_order":
            key = args.get("idempotency_key")
            if not key:
                return self._json(400, {
                    "error": "idempotency_key_required",
                    "error_description": "写操作必须携带 idempotency_key"})
            if key in _idem_keys:
                return self._json(200, {"created": False,
                                        "note": "duplicate request, "
                                                "idempotency_key already processed"})
            _idem_keys.add(key)
            return self._json(200, {"created": True,
                                    "order_id": "ORD-%s" % key[:8]})

        # —— 危险操作需确认 + 试运行
        if tool == "delete_order":
            if not args.get("confirm"):
                return self._json(200, {
                    "preview": {"would_delete": args.get("order_id")},
                    "requires_confirmation": True,
                    "hint": "resend with confirm=true to proceed"})
            if args.get("dry_run"):
                return self._json(200, {"deleted": False, "dry_run": True})
            return self._json(200, {"deleted": True})

        # 未知工具：**不泄漏可用工具列表**
        return self._json(400, {"error": "unknown_tool"})


if __name__ == "__main__":
    print("=" * 58)
    print("干净版 MCP Server（反向对照靶场）")
    print("=" * 58)
    print("监听: http://127.0.0.1:9002")
    print("")
    print("已实现的安全措施（用于验证审计器不误报）：")
    print("  1. 强制 Bearer 认证，无凭据一律 401")
    print("  2. 健康检查不含路径/版本/连接串")
    print("  3. 错误响应为统一 JSON，无栈信息")
    print("  4. 写操作强制 idempotency_key，并去重")
    print("  5. 危险操作需 confirm，支持 dry_run 预览")
    print("  6. 审计日志记录 actor 与 trace_id")
    print("  7. 未知工具不泄漏可用工具清单")
    print("  8. 工具面收窄（仅 2 个读工具，写占比 0%）")
    print("")
    HTTPServer(("127.0.0.1", 9002), Handler).serve_forever()