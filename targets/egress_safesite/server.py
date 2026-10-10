#!/usr/bin/env python3
"""
外联白名单靶场 · 干净版（反向对照）
====================================
验证 audit_egress.py **不会误报**。

对照植入的 5 项缺陷：
  E1 CSP 白名单 → 全部收敛到自有CDN，无闲置/占位域名
  E2 /.vscode/settings.json 等 → 404（不部署到web 可达路径）
  E3 autoApprove → 显式 false，且配置本身不暴露
  E4 外发形态   → 页面无 URL 参数带数据、无编码外发、无外链图片
  E5 /csp.json   → 401

端口 9008
"""

import json
from http.server import BaseHTTPRequestHandler, HTTPServer

# ✅ 修复 E1：仅自有 CDN，无闲置/占位域名
CSP = {
    "img-src": ["'self'", "https://cdn.ourcompany.com"],
    "connect-src": ["'self'"],
    "script-src": ["'self'", "https://cdn.ourcompany.com"],
}

# ✅ 修复 E4：无外发形态 —— 无 URL 参数带数据、无外链图片、无编码外发
CLEAN_PAGE = """<!DOCTYPE html>
<html><head><meta charset="utf-8">
<title>Dashboard</title>
</head><body>
<h1>运营看板</h1>
<p>最新一期简报已发布。</p>
<!-- 图片走自有CDN，且不带任何数据参数 -->
<img src="/static/thumb.png" alt="chart">
<script>
  document.addEventListener('DOMContentLoaded', function(){
    // 仅向同源接口取数据，不做任何编码外发
    fetch('/api/widgets', {credentials:'same-origin'})
      .then(function(r){ return r.json(); })
      .then(function(d){ render(d); });
  });
</script>
</body></html>
"""

# ✅ 修复 E2/E3：agent 自改配置**不放�� web 可达路径**
#   且 autoApprove 显式为 false
VSCODE_SETTINGS_LOCAL = {
    "editor.formatOnSave": True,
    "chat.tools.autoApprove": False,      # 显式关闭
    "chat.agent.autoRun": False,
}


class Handler(BaseHTTPRequestHandler):

    def log_message(self, fmt, *a):
        pass

    def _json(self, code, obj):
        body = json.dumps(obj, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Server", "mcp")
        self.end_headers()
        self.wfile.write(body)

    def _raw(self, code, text):
        data = text.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Content-Security-Policy",
                         "img-src 'self' https://cdn.ourcompany.com; "
                         "script-src 'self'; connect-src 'self'")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Server", "mcp")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        p = self.path.split("?")[0]

        # ✅ 修复 E5：出站配置需认证，不公开
        if p in ("/csp.json", "/manifest.json", "/content-security-policy.json"):
            self._json(401, {"error": "unauthorized"})
            return

        # ✅ 修复 E2/E3：这些配置不在 web 可达路径上
        if p in ("/.vscode/settings.json", "/.mcp.json",
                 "/.cursor/mcp.json", "/.claude/settings.json"):
            self._json(404, {"error": "not found"})
            return

        if p in ("/", "/index.html", "/dashboard"):
            self._raw(200, CLEAN_PAGE)
            return

        if p in ("/health", "/healthz"):
            self._json(200, {"status": "ok"})
            return

        if p == "/api/widgets":
            self._json(200, {"widgets": []})
            return

        if p == "/mcp":
            # ✅ 修复 G3 组合面：工具面收窄，**不含写文件/执行命令/git 类**
            self._json(200, {"serverInfo": {"name": "dashboard-mcp",
                                            "version": "1.0.0"},
                             "tools": [
                                 {"name": "list_docs", "description": "列出文档"},
                                 {"name": "get_doc", "description": "读取文档"},
                                 {"name": "query_docs", "description": "检索文档"},
                             ]})
            return

        self._json(404, {"error": "not found"})


if __name__ == "__main__":
    HTTPServer(("127.0.0.1", 9008), Handler).serve_forever()