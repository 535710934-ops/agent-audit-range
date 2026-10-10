#!/usr/bin/env python3
"""
服务账号/ 平台级凭证靶场（Day 5 · G2 类专项）
=============================================
为什么必须新建：Day 5 真实案例对齐发现，现有靶场全是**具体用户**身份
（alice/bob/admin），而 CVSS 9.x 的真实越权事件里，越权主体全是**非人主体**：
  - 全局共享静态密钥（ServiceNow CVE-2025-12420）
  - 第三方应用 OAuth token（Salesloft UNC6395）
  - agent 运行时环境变量（Flowise CVE-2025-59434）

本靶场植入 4 类 G2 缺陷：
  S1  全局共享静态密钥 —— 两个环境用同一个 key 都能通过
  S2  凭 token 直连导出接口，无 MFA / 无用户交互
  S3  源码硬编码平台级密钥（AWS AKIA / GitHub token / DB 连接串）
  S4  审计日志只记工具名，**不记 actor**，且全局无 trace_id
  S5  单凭证可见 12 个工具（8 写），授权粒度过宽

端口 9005
"""

import json
import os
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer

# ⚠ **全局共享静态密钥** —— 所有部署实例相同。参照 CVE-2025-12420
SHARED_STATIC_KEY = "servicenowexternalagent"

# 对照用的租户级 token（正常应是每租户独立）
TOKEN_ROLE = {
    SHARED_STATIC_KEY: {"tenant": "*", "role": "integration",
                        "name": "external-agent", "kind": "shared"},
    "acme-user-token-1": {"tenant": "A", "role": "user", "name": "AcmeUser",
                          "kind": "tenant"},
    "globex-user-token-1": {"tenant": "B", "role": "user",
                            "name": "GlobexUser", "kind": "tenant"},
}

TOOLS = [
    {"name": "list_records", "description": "列出记录"},
    {"name": "get_record", "description": "读取单条记录"},
    {"name": "create_record", "description": "创建记录"},
    {"name": "update_record", "description": "更新记录"},
    {"name": "delete_record", "description": "删除记录"},
    {"name": "create_user", "description": "创建用户并分配角色"},
    {"name": "assign_role", "description": "为用户分配角色（含 admin）"},
    {"name": "run_job", "description": "执行后台任务"},
    {"name": "export_data", "description": "批量导出数据"},
    {"name": "deploy", "description": "部署变更到生产"},
    {"name": "read_secrets", "description": "读取系统密钥"},
    {"name": "grant_access", "description": "授予访问权限"},
]

# 模拟全租户数据 —— 参照 Flowise 的514 个全局变量
GLOBAL_SECRETS = {
    "AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY",
    "GITHUB_TOKEN": "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345",
    "STRIPE_SECRET_KEY": "sk_live_abcdefghijklmnopqrstuvwx",
    "SLACK_BOT_TOKEN": "xoxb-123456789012-abcdefghijklmnop",
}

# ⚠ S4：审计日志**只有工具名**，没有 actor、没有 trace_id
_audit = []


class Handler(BaseHTTPRequestHandler):

    def log_message(self, fmt, *a):
        pass

    def _json(self, code, obj):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Server", "nginx")
        self.end_headers()
        self.wfile.write(body)

    def _who(self):
        h = self.headers.get("Authorization", "")
        if not h.startswith("Bearer "):
            return None
        return TOKEN_ROLE.get(h[7:])

    def do_GET(self):
        p = self.path.split("?")[0]
        u = self._who()

        if p in ("/health", "/healthz"):
            self._json(200, {"status": "ok"})
            return

        # ⚠ S2：导出/管理端点**凭 token 直连**，无 MFA、无二次确认
        if p in ("/api/v1/export", "/admin", "/api/admin", "/api/v1/query"):
            if not u:
                self._json(401, {"error": "unauthorized"})
                return
            self._json(200, {"result": "exporting",
                             "scope": "ALL_TENANTS",
                             "records": 1_487_000,
                             "note": "凭 bearer token 即授权，无 MFA"})
            return

        if p == "/api/v1/graphql":
            self._json(401, {"error": "unauthorized"})
            return

        if p == "/mcp":
            if not u:
                self._json(401, {"error": "unauthorized"})
                return
            self._json(200, {
                "serverInfo": {"name": "integration-mcp", "version": "1.0.0"},
                "tools": TOOLS,
                "identity": {"name": u["name"], "role": u["role"],
                             "kind": u["kind"], "tenant": u["tenant"]}})
            return

        self._json(404, {"error": "not found"})

    def do_POST(self):
        p = self.path.split("?")[0]
        u = self._who()
        if not u:
            self._json(401, {"error": "unauthorized"})
            return
        ln = int(self.headers.get("Content-Length", 0))
        try:
            data = json.loads(self.rfile.read(ln) or b"{}")
        except Exception:
            data = {}

        tool = data.get("tool", "")
        args = data.get("args", {}) or {}

        # ⚠ S4：审计只记工具名+参数 —— 无 actor、无 trace_id
        _audit.append({"tool": tool, "args": args})

        if tool == "list_records":
            self._json(200, {"result": [
                {"id": "R1", "tenant": "A"},
                {"id": "R2", "tenant": "B"},
                {"id": "R3", "tenant": "B"},
                {"id": "R4", "tenant": "C"}]})
            return

        if tool == "read_secrets":
            # ⚠ S3 表现面：集成账号可读全平台密钥
            self._json(200, {"result": GLOBAL_SECRETS})
            return

        if tool == "assign_role":
            self._json(200, {"result": "ok",
                             "target": args.get("user_id"),
                             "role": args.get("role")})
            return

        if tool == "create_user":
            self._json(200, {"result": "created",
                             "user_id": "u-" + uuid.uuid4().hex[:8]})
            return

        if tool in ("get_record", "create_record", "update_record",
                    "delete_record", "run_job", "export_data", "deploy",
                    "grant_access"):
            self._json(200, {"result": "ok", "tool": tool})
            return

        self._json(404, {"error": "unknown tool"})


if __name__ == "__main__":
    HTTPServer(("127.0.0.1", 9005), Handler).serve_forever()