#!/usr/bin/env python3
"""
真实 MCP 协议靶场 —— 安全版（阴性对照，端口 9018）
==================================================

**阴性对照的作用不是"好看"，是"证伪"。**

如果只测漏洞靶场，任何扫错对象的工具都能拿到满分 —— 它可能只是在猜。
只有对着安全版也报出缺陷，才说明它真的在判别，而不是在触发。

安全版做对了什么（逐条对应漏洞版 12 项缺陷）：

   1  Bearer token 认证，无凭据一律 401
   2  工具描述中无注入载荷，且工具说明与行为一致
   3  无高危工具；无任意执行 / 任意 SQL / 外发能力
   4  写工具占比 1/5 = 20%，且仅 create（新增无破坏性）
   5  session id = secrets.token_urlsafe(32)，不可预测
   6  不泄露 Server / X-Powered-By 版本
   7  CORS 不返回 Access-Control-Allow-Origin
   8  错误只回 code + message，不含 traceback / 连接串
   9  无 /audit /health 公开端点
  10  serverInfo 不带 instructions / build 号
  11  强制校验 initialized 握手，未握手直接拒绝 tools/call
  12  写操作需 idempotency key + 需显式 confirm，且写审计日志

⚠ 只监听 127.0.0.1。

启动：python targets/mcp_proto_safe/server.py
"""

import json
import os
import secrets
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(os.environ.get("MCP_PROTO_SAFE_PORT", "9018"))
PROTO_VERSION = "2025-06-18"
VALID_TOKEN = os.environ.get("MCP_SAFE_TOKEN", "safe-token-9f2c41")

ORDERS = [
    {"id": "ORD-2001", "customer": "Initech", "amount": 4200.00, "status": "paid"},
    {"id": "ORD-2002", "customer": "Umbrella", "amount": 910.00, "status": "pending"},
]

TOOLS = [
    {"name": "list_orders", "description": "列出当前租户可见的订单。需租户作用域。",
     "inputSchema": {"type": "object", "properties": {},
                     "additionalProperties": False}},
    {"name": "get_order", "description": "按订单号获取详情。仅返回授权租户的数据。",
     "inputSchema": {"type": "object",
                     "properties": {"order_id": {"type": "string",
                                                 "pattern": "^ORD-[0-9]+$"}},
                     "required": ["order_id"], "additionalProperties": False}},
    {"name": "search_orders", "description": "按状态与日期区间检索订单。",
     "inputSchema": {"type": "object",
                     "properties": {"status": {"type": "string",
                                               "enum": ["paid", "pending",
                                                        "cancelled"]},
                                    "days": {"type": "integer",
                                             "minimum": 1, "maximum": 365}},
                     "additionalProperties": False}},
    # 唯一的写工具：新增订单，无删除、无执行、无外发
    {"name": "create_order", "description":
     "创建订单。需提供 idempotency_key；重复提交返回首次结果，不产生重复订单。",
     "inputSchema": {"type": "object",
                     "properties": {"customer": {"type": "string",
                                                "maxLength": 120},
                                    "amount": {"type": "number",
                                               "minimum": 0,
                                               "maximum": 1000000},
                                    "idempotency_key": {"type": "string",
                                                        "minLength": 16},
                                    "confirm": {"type": "boolean"}},
                     "required": ["customer", "amount",
                                  "idempotency_key", "confirm"],
                     "additionalProperties": False}},
]

WRITE_KW = ("create", "update", "delete", "send", "execute", "run",
            "write", "refund", "transfer", "deploy")

_SESSIONS = set()
_AUDIT = []
_SEQ = [2000]


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    # ⚠ 这里有一个只有真跑一次才会发现的坑（2026-10-11 实测）：
    #   BaseHTTPRequestHandler.send_response() 会**无条件**追加
    #   `Server: BaseHTTP/0.6 Python/3.13.14`，且发生在你写的 _send() 之后，
    #   **覆盖不掉**（同名 header 会被追加成两行）。
    #   后果：本文件原本号称"安全版"，扫描器却在它身上照样报出版本泄露。
    #   ⇒ 安全版自己就是活的反例：**"我没写这行"不等于"这行不存在"**。
    #   修法是覆写 version_string()，这是标准库唯一的出口。
    def version_string(self):
        return "orders-mcp"

    def log_message(self, fmt, *a):
        print("[MCP-PROTO-SAFE] " + fmt % a)

    # ---------- 安全响应 ----------

    def _send(self, code, body: bytes, ctype="application/json", extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        # 安全头齐全；不暴露 Server / X-Powered-By
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        # ⚠ extra 必须在这里透传。第一版 _json() 没有 extra 形参，
        #   于是 initialize 的 Mcp-Session-Id 响应头**根本没发出去**，
        #   客户端拿到 session=None，后续 tools/list 全部 invalid session。
        #   症状（会话无效）离真因（响应助手少了参数）隔了两层 ——
        #   若当时顺手把"安全版报错"当成"安全版更严"，这个 bug 会活很久。
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code, obj, extra=None):
        self._send(code, json.dumps(obj, ensure_ascii=False).encode("utf-8"),
                   extra=extra)

    def _sse(self, obj):
        payload = "event: message\ndata: %s\n\n" % json.dumps(
            obj, ensure_ascii=False)
        self._send(200, payload.encode("utf-8"),
                   ctype="text/event-stream; charset=utf-8")

    def _err(self, code, rpc_id, msg):
        """错误只给最少信息：不回 traceback、不回连接串、不回工具清单。

        ⚠ 这里的 code 是 **JSON-RPC 错误码**（-32000 段），不是 HTTP 状态码。
          第一版误把 -32002 直接传给 send_response()，结果写出
          `HTTP/1.1 -32002` 这种非法状态行 —— 客户端立刻报
          `BadStatusLine`，看起来像"服务不可达"。
          ⇒ **症状是连接失败，真因是服务端 HTTP 层写错了。**
          纪律 3 的活样本：连接失败有无数种原因，别默认它只有一个。
        """
        return self._json(200, {
            "jsonrpc": "2.0", "id": rpc_id,
            "error": {"code": code, "message": msg},
        })

    # ---------- 认证 ----------

    def _authed(self):
        h = self.headers.get("Authorization") or ""
        return h.startswith("Bearer ") and secrets.compare_digest(
            h[7:].strip(), VALID_TOKEN)

    def _reject_unauth(self, rpc_id):
        """未使用的旧实现，保留会让人误以为有第二条认证路径。删。"""
        raise NotImplementedError

    # ---------- 会话 ----------

    def _new_session(self):
        # 不可预测：32 字节 URL-safe 随机
        sid = "sess-" + secrets.token_urlsafe(32)
        _SESSIONS.add(sid)
        return sid

    # ---------- GET ----------

    def do_GET(self):
        p = self.path.split("?")[0].rstrip("/") or "/"
        # 只回一个不含内部信息的最小健康信号
        if p == "/health":
            return self._json(200, {"status": "ok"})
        if p == "/mcp":
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            try:
                self.wfile.write(b": keepalive\n\n")
                time.sleep(0.2)
            except Exception:
                pass
            return
        # 无公开审计端点
        return self._json(404, {"error": "not found"})

    # ---------- POST ----------

    def do_POST(self):
        p = self.path.split("?")[0].rstrip("/")
        ln = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(ln).decode("utf-8", "replace") if ln else ""
        try:
            req = json.loads(raw) if raw else {}
        except Exception:
            return self._err(-32700, None, "parse error")

        method = req.get("method") or ""
        rpc_id = req.get("id")
        params = req.get("params") or {}
        want_sse = "text/event-stream" in (
            self.headers.get("Accept") or "")

        # 全部方法都要先过认证（除 initialize 也一样 —— 不匿名给握手）
        if not self._authed():
            return self._json(401, {"jsonrpc": "2.0", "id": rpc_id,
                                    "error": {"code": -32001,
                                              "message": "unauthorized"}})

        sid = self.headers.get("Mcp-Session-Id") or ""

        if method == "initialize":
            new_sid = self._new_session()
            resp = {"jsonrpc": "2.0", "id": rpc_id,
                    "result": {
                        "protocolVersion": PROTO_VERSION,
                        "capabilities": {"tools": {"listChanged": False}},
                        # spec 要求 serverInfo.name 与 version 均必填
                        # （SDK zod 严格校验实测抓出缺失）；version 用
                        # 通用串即可，不泄露真实 build 号
                        "serverInfo": {"name": "orders-mcp",
                                       "version": "1.0.0"},
                    }}
            hdr = {"Mcp-Session-Id": new_sid}
            if want_sse:
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Mcp-Session-Id", new_sid)
                self.end_headers()
                self.wfile.write(("event: message\ndata: %s\n\n"
                                  % json.dumps(resp)).encode("utf-8"))
                return
            # ⚠ 两处 return（JSON 与 SSE 分支）都必须带 session 头。
            #   第一版只改了其中一处，另一处漏传 → session 头发不出去 →
            #   客户端 tools/list 恒报 invalid session。
            #   **两处形态相同的调用必须一起看**，grep 比通读可靠。
            return self._json(200, resp, extra=hdr)

        if method == "notifications/initialized":
            if not sid or sid not in _SESSIONS:
                return self._err(-32002, rpc_id, "invalid session")
            self.send_response(202)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        # 以下所有方法都要求：有效 session + 已完成握手
        if not sid or sid not in _SESSIONS:
            return self._err(-32002, rpc_id, "invalid session")

        if method == "tools/list":
            resp = {"jsonrpc": "2.0", "id": rpc_id,
                    "result": {"tools": TOOLS}}
            if want_sse:
                return self._sse(resp)
            return self._json(200, resp)
        if method == "tools/call":
            name = params.get("name") or ""
            args = params.get("arguments") or {}

            if name == "list_orders":
                return self._json(200, {
                    "jsonrpc": "2.0", "id": rpc_id,
                    "result": {"content": [{"type": "text", "text":
                                json.dumps(ORDERS, ensure_ascii=False)}],
                               "isError": False}})

            if name == "create_order":
                # 幂等性 + 显式确认，二者缺一不可
                idem = args.get("idempotency_key")
                if not idem:
                    return self._err(-32003, rpc_id,
                                     "idempotency_key required")
                if not args.get("confirm"):
                    return self._err(-32003, rpc_id,
                                     "confirm required for write")
                # 服务端独立校验 schema —— **声明了不等于执行了**。
                # 模型给的参数一律不可信，校验必须发生在服务端。
                amt = args.get("amount")
                if not isinstance(amt, (int, float)) or not (
                        0 <= amt <= 1000000):
                    return self._err(-32003, rpc_id,
                                     "amount out of range")
                if set(args) - {"customer", "amount",
                                "idempotency_key", "confirm"}:
                    return self._err(-32003, rpc_id,
                                     "unknown parameter")
                _SEQ[0] += 1
                _AUDIT.append({"tool": name, "idem": idem,
                               "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
                               "result": "created"})
                return self._json(200, {
                    "jsonrpc": "2.0", "id": rpc_id,
                    "result": {"content": [{"type": "text", "text":
                                "created"}], "isError": False}})

            # 未知工具：只说"未知"，不列出可用工具（防枚举）
            return self._err(-32601, rpc_id, "unknown tool")

        if method == "ping":
            return self._json(200, {"jsonrpc": "2.0", "id": rpc_id,
                                    "result": {}})

        return self._err(-32601, rpc_id, "method not found")


if __name__ == "__main__":
    writes = [t["name"] for t in TOOLS
              if any(k in t["name"] for k in WRITE_KW)]
    print("=" * 66)
    print("真实 MCP 协议靶场 · 安全版（阴性对照）")
    print("=" * 66)
    print("监听 : http://127.0.0.1:%d/mcp   (仅本机)" % PORT)
    print("Token: 从环境变量 MCP_SAFE_TOKEN 读取，默认 safe-token-9f2c41")
    print("")
    print("安全项：认证强制 / 无注入载荷 / 无高危工具 / 写占比 %d/%d = %.0f%% "
          "/ session 随机 / 不泄版本 / CORS 收紧 / 错误无栈 / 无公开审计端点 "
          "/ 强制握手 / 幂等+确认"
          % (len(writes), len(TOOLS), 100.0 * len(writes) / len(TOOLS)))
    print("")
    # 线程版：避免单条死连接卡死整个服务（与漏洞版保持同一服务器模型，
    # 阴性对照只在安全属性上有差异，不在并发模型上）
    ThreadingHTTPServer.daemon_threads = True
    ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
