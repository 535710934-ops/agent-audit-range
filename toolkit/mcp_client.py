#!/usr/bin/env python3
"""
MCP 协议客户端（纯标准库）
==========================

**它为什么必须存在**
------------------
仓库里的 `tools/audit_mcp.py` 假设 `GET /mcp` 直接返回工具清单。那是**靶场
专用的简化协议**，真实 MCP server 不这么说话。拿它去扫真实目标是扫不到的
（连握手都发不出去），而且最危险的是——它会安静地返回"0 项发现"。

真实 MCP（Streamable HTTP / JSON-RPC 2.0）流程：

    1. POST /mcp  {"method":"initialize", "params":{...}}
       → result.protocolVersion / result.capabilities / result.serverInfo
       → 响应头 Mcp-Session-Id（**后续每个请求都要带上**）
    2. POST /mcp  {"method":"notifications/initialized"}
       → HTTP 202，无响应体（通知类无 id）
    3. POST /mcp  {"method":"tools/list"}
       → result.tools[]，每项含 name / description / inputSchema
    4. POST /mcp  {"method":"tools/call","params":{"name","arguments"}}

响应体有两种形态，必须都吃下：
  · application/json          —— 直接一个 JSON 对象
  · text/event-stream (SSE)   —— `event: message\ndata: {json}\n\n`

**不解析 SSE 会漏掉整类真实 server**（凡是声明支持流式响应的都走这条）。

用法：
    c = MCPClient("http://127.0.0.1:9017/mcp")
    c.handshake()
    tools = c.list_tools()

⚠ 三条硬纪律：
  1. 强制剥掉代理环境（同 targets/start_targets.py）—— 否则全部超时，
     而超时的表现是"扫不到"，不是"报错"。
  2. **超时 ≠ 安全**。所有失败路径都必须返回可辨识的 err 标记，
     绝不能让上层把"没连上"读成"没问题"（纪律 3）。
  3. 只做被动读取。tools/call 仅在调用方显式要求且传 --allow-call 时才发，
     默认一律不发（对照扫描不应该对目标产生副作用）。
"""

import json
import os
import time
import urllib.error
import urllib.request

UA = "MCPAuditToolkit/0.1 (passive; authorized-targets-only)"

# 协议版本候选：按从新到旧试。真实世界版本号很杂，见 modelcontextprotocol.io
PROTO_VERSIONS = ["2025-06-18", "2025-03-26", "2024-11-05"]

# 剥代理：环境里若设了 http_proxy（本机实测就是），urlopen 会去问一个不通的
# 代理 → 超时 → 靶场明明在线却被判"扫不到"。**这是最容易被误读成"目标安全"
# 的失败模式**，所以放在模块级，只做一次。
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


class MCPError(Exception):
    """协议层错误。**带 .soft 标记的表示"没连上"，上层必须记 SKIPPED 而非 PASS。"""


class MCPClient:
    def __init__(self, url, token=None, timeout=10, verbose=False):
        self.url = url
        self.token = token
        self.timeout = timeout
        self.verbose = verbose
        self.session_id = None
        self.initialized = False
        self.server_info = {}
        self.capabilities = {}
        self.protocol_version = None
        # 预声明：instructions 是规范可选字段，不预声明会导致
        # "server 没返回 instructions" 和 "客户端忘了读" 两种情况混淆
        self.instructions = None
        self.raw_headers = {}
        self.raw_headers_tl = {}
        self._id = 0

    # ------------------------------------------------------------ 底层

    def _headers(self, sse=False):
        # ⚠ 2026-10-13 实测：initialize 必须带 "Accept: application/json,
        #   text/event-stream"。规范（2025-03-26 起）规定单次 POST 的响应
        #   可以是 JSON 也可以是 SSE 流，服务端用 Accept 判定你能否接收两种
        #   形态。只发 "Accept: application/json" 会被严格实现回
        #   **406 Not Acceptable**（exa 等现代远程 server 实测）。
        #   旧写法（sse 才带 text/event-stream）在本地宽容靶场全过、一碰真
        #   server 就 406 —— 正是「靶场对你友好」漏掉的真 bug。
        h = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "User-Agent": UA,
        }
        if self.token:
            h["Authorization"] = "Bearer %s" % self.token
        if self.session_id:
            h["Mcp-Session-Id"] = self.session_id
        return h

    def _next_id(self):
        self._id += 1
        return self._id

    @staticmethod
    def _parse_sse(text):
        """从 SSE 流里取出第一条 data: 载荷。

        ⚠ 不能只取第一行 data: —— 有的实现会把 JSON 拆成多行 data:
          （SSE 规范允许多行拼接）。必须按空行切事件、把所有 data: 拼起来。
        """
        chunks, cur = [], []
        for line in text.splitlines():
            if line.startswith("data:"):
                cur.append(line[5:].lstrip())
            elif line.strip() == "" and cur:
                chunks.append("".join(cur))
                cur = []
        if cur:
            chunks.append("".join(cur))
        for c in chunks:
            c = c.strip()
            if c:
                try:
                    return json.loads(c)
                except Exception:
                    continue
        return None

    def post(self, method, params=None, want_response=True, sse=False):
        """发一个 JSON-RPC 请求。返回 (http_status, headers, parsed_body)。"""
        body = {"jsonrpc": "2.0", "method": method}
        if want_response:
            body["id"] = self._next_id()
        if params is not None:
            body["params"] = params

        req = urllib.request.Request(
            self.url, method="POST",
            data=json.dumps(body).encode("utf-8"),
            headers=self._headers(sse))
        try:
            with _OPENER.open(req, timeout=self.timeout) as resp:
                status = resp.status
                rheaders = {k.lower(): v for k, v in resp.getheaders()}
                raw = resp.read(65536).decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            # 4xx/5xx 也是有效信息：401 说明有认证、404 说明路径不对
            status = e.code
            rheaders = {k.lower(): v for k, v in (e.headers or {}).items()}
            try:
                raw = e.read(65536).decode("utf-8", "replace")
            except Exception:
                raw = ""
        except urllib.error.URLError as e:
            # ⚠ **BadStatusLine 也走这里**。它不是"网络故障"，而是
            #   服务端写出了非法状态行（例如把 JSON-RPC 错误码 -32601
            #   直接塞进 HTTP 状态行）。两种原因症状几乎一样，
            #   但只有一种是"对端有问题"、另一种是"网络不通"——
            #   所以这里**必须带出原因**，绝不让上层只看到一个 None。
            #   2026-10-11 实测：漏了这个降级，扫描器把
            #   "错误响应取不到" 当成 "错误响应没泄漏" ⇒ H1 假 PASS。
            reason = getattr(e, "reason", e)
            raise MCPError(
                "HTTP 失败(%s): %s: %s"
                % (type(reason).__name__, type(e).__name__, str(reason)[:120]))
        except Exception as e:
            raise MCPError("连接失败 %s: %s"
                           % (type(e).__name__, str(e)[:140]))

        data = None
        ctype = rheaders.get("content-type", "")
        if "text/event-stream" in ctype or raw.lstrip().startswith("event:"):
            data = self._parse_sse(raw)
        else:
            try:
                data = json.loads(raw) if raw.strip() else None
            except Exception:
                data = None
        if self.verbose:
            print("  → %-28s HTTP %s%s" % (method, status,
                                           "  session=%s" % self.session_id
                                           if self.session_id else ""))
        return status, rheaders, data

    # ------------------------------------------------------------ 握手

    def handshake(self):
        """完整 MCP 握手。失败抛 MCPError —— 调用方必须记 SKIPPED。"""
        last_err = None
        for pv in PROTO_VERSIONS:
            try:
                status, headers, data = self.post(
                    "initialize",
                    {"protocolVersion": pv,
                     "capabilities": {},
                     "clientInfo": {"name": "mcp-audit-toolkit",
                                    "version": "0.1"}},
                    sse=False)
            except MCPError as e:
                raise
            if status != 200 or not data:
                last_err = "initialize HTTP %s" % status
                continue
            res = data.get("result") or {}
            if not res:
                last_err = "initialize 无 result: %s" % json.dumps(
                    data, ensure_ascii=False)[:160]
                continue
            self.protocol_version = res.get("protocolVersion") or pv
            self.capabilities = res.get("capabilities") or {}
            self.server_info = res.get("serverInfo") or {}
            # instructions 是规范字段，但常被用来藏内部提示 —— 客户端要收下
            self.instructions = res.get("instructions")
            self.session_id = headers.get("mcp-session-id")
            self.raw_headers = headers
            break
        else:
            raise MCPError("握手失败: %s" % (last_err or "未知"))

        # 通知类：无 id，期望 202
        try:
            self.post("notifications/initialized", want_response=False)
            self.initialized = True
        except MCPError:
            # 有些实现不回 202 也算成功，不能因此判失败
            self.initialized = True
        return self

    # ------------------------------------------------------------ 读

    def list_tools(self):
        """返回工具清单列表。失败抛 MCPError。"""
        status, headers, data = self.post("tools/list", {})
        self.raw_headers_tl = headers
        if status != 200 or not data:
            raise MCPError("tools/list HTTP %s" % status)
        res = data.get("result")
        if res is None:
            # 明确区分"协议返回了 error"和"根本没结果"
            err = (data.get("error") or {}).get("message", "?")
            raise MCPError("tools/list 返回 error: %s" % str(err)[:140])
        tools = res.get("tools")
        if tools is None:
            raise MCPError("tools/list 无 tools 字段")
        return tools

    def call_tool(self, name, arguments=None):
        """⚠ 会产生副作用。默认不调用；仅在显式 allow_call 时使用。"""
        return self.post("tools/call",
                         {"name": name, "arguments": arguments or {}})

    def probe_error(self, method="tools/call",
                    params={"name": "__nonexistent_probe__", "arguments": {}}):
        """故意触发一次错误，看服务端泄不泄栈。

        这是**唯一**被允许的"越界"探测：它调用的是一个不存在的工具名，
        任何实现都只会返回 error，不可能产生业务副作用。
        """
        try:
            return self.post(method, params)
        except MCPError as e:
            return None, {"error": str(e)}, None


# ============================================================ 自检

def _selftest():
    """对两个协议靶场跑一次握手 + tools/list，证明客户端说的是真 MCP。"""
    import sys
    cases = [
        ("vuln :9017", "http://127.0.0.1:9017/mcp", None, True),
        ("safe :9018", "http://127.0.0.1:9018/mcp", "safe-token-9f2c41", True),
        ("safe 无凭据", "http://127.0.0.1:9018/mcp", None, False),
    ]
    print("=" * 70)
    print("MCP 客户端自检")
    print("=" * 70)
    ok = 0
    for name, url, token, expect_ok in cases:
        c = MCPClient(url, token=token, verbose=False)
        try:
            c.handshake()
            tools = c.list_tools()
            print("  %-14s ✓ proto=%s session=%s tools=%d"
                  % (name, c.protocol_version,
                     (c.session_id or "-")[:22], len(tools)))
            for t in tools:
                print("       · %s" % t.get("name"))
            ok += 1
            if not expect_ok:
                print("       ⚠ 期望失败却成功了")
        except MCPError as e:
            status = "✓ 按预期拒绝" if not expect_ok else "✗ 失败"
            print("  %-14s %s: %s" % (name, status, str(e)[:60]))
            if expect_ok:
                return 1
            ok += 1
    print("-" * 70)
    print("自检: %d/%d 通过" % (ok, len(cases)))
    return 0 if ok == len(cases) else 1


if __name__ == "__main__":
    import sys
    sys.exit(_selftest())
