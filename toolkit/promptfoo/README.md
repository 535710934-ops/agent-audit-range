# toolkit/promptfoo —— promptfoo 真机接入验证（2026-10-11）

promptfoo 0.124.1 通过 MCP provider 直连本仓库两个真协议靶场，端到端跑通。
这是「开源扫描器适配层」的第一块真机地基：**没跑通的不写文档，跑通的才写**。

## 环境

- promptfoo 0.124.1（npm，装于 node 托管工作区，npmmirror 源）
- 靶场：`targets/mcp_proto_vuln` :9017（无认证）/ `targets/mcp_proto_safe` :9018（Bearer）
- 全部零 LLM 依赖：断言不需要任何 API key

## 运行

```bash
# 1. 起靶场
python targets/mcp_proto_vuln/server.py   # :9017
python targets/mcp_proto_safe/server.py   # :9018

# 2. 跑 eval（node 侧，入口是 dist/src/entrypoint.js）
node node_modules/promptfoo/dist/src/entrypoint.js eval \
  --config toolkit/promptfoo/promptfooconfig.yaml \
  --output  toolkit/promptfoo/out.json

node node_modules/promptfoo/dist/src/entrypoint.js eval \
  --config toolkit/promptfoo/promptfooconfig.safe.yaml \
  --output toolkit/promptfoo/out_safe.json
```

## 验证结论（全部实测）

| 项 | 结果 |
|---|---|
| 漏洞版 :9017 `list_orders` 调用 | ✅ 真协议往返，返回订单数据 |
| 安全版 :9018 带 Bearer 认证 | ✅ headers 透传生效，握手+枚举+调用全通 |
| 安全版 `create_order`（合法载荷） | ✅ 返回 created |
| 未知工具 `__nonexistent_probe__` | ✅ registry 级报错（符合预期） |
| 授权声明 | ⚠️ promptfoo 配置本身无授权概念，授权 gate 在 run_all/audit_remote 层；本目录配置仅限 self 靶场 |

## 踩坑记录（按发现顺序，都是花时间换来的）

1. **`enabled: true` 必填**。`MCPClient.initialize()` 开头就是
   `if (!this.config.enabled) return;`——不写它，连接静默不建立，
   所有测例报 `Tool X not found in any connected MCP server`，
   且初始化失败被 `.catch(() => void 0)` 吞掉，无任何报错。
   正确格式：`servers` 必须是**数组**，每项含 `name` + `url`（+ 可选 `headers`）。
2. **prompt JSON 是工具调用**：`{"tool": "名称", "args": {...}}`。
   非 JSON 文本会报 "Invalid JSON in prompt"。
3. **单线程靶场会被死连接卡死**。promptfoo 的 SDK 保持 keep-alive；
   前台强杀后留下的半开连接能把单线程 `HTTPServer` 整体挂死。
   两个靶场已改 `ThreadingHTTPServer`（与真实服务器并发模型一致）。
4. **`serverInfo.version` 必填**。MCP spec + SDK zod 严格校验；
   安全版原先只发 name，SDK 直接拒绝握手。已补 `"version": "1.0.0"`
   （通用串，不泄露真实 build 号——当初"防泄漏"防过头变成了不合 spec）。
   注意：自研 `mcp_client.py` 没这个校验，所以 9/9 自检没抓到；
   **官方 SDK 的严格校验恰好是最好的第三方一致性探针**。
5. **provider 返回 JSON-RPC 错误时，promptfoo 把测例直接判 error，
   断言不执行**。负路径（如缺 amount 被拒）无法在 promptfoo 配置里
   断言——错误语义验证归 `audit_remote.py` 管，这里只做正例演示。
6. 漏洞版有工具**声明了但未实现**（get_order 等），调用时落进
   "unknown tool | available: 全清单"兜底——这正是真实服务器常见的不一致，
   也是扫描器 H1（错误泄工具清单）要抓的模式。靶场保留不改。

## 与 audit_remote.py 的分工

- `audit_remote.py`：被动协议层审计（六域 16 项，不调用工具）——**主审计工具**。
- promptfoo 适配：主动工具调用层（能按工具面构造正/负用例）——补充能力，
  用于对授权目标做工具级行为验证；不含授权 gate，只配合 run_all 使用。
