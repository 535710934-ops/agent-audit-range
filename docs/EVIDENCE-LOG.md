# EVIDENCE LOG（公开证据链 · 带时间戳）

> 用途：让"持续判断流 / 先发位置"这块护城河**可被外人核验**。每行 = 一件带时间戳、可回溯的公开事实。
> 维护：周五史料官自动化抓取本仓库 commit + 公开平台数据后追加；人工补"我改了主意"必填一句真看法。
> 纪律：只记**已公开/已推送**的事实，未推的草稿不进；数字与仓库一致；不夸大。

## 2026-10-13

| 时间 | 事实 | 可核验来源 |
|---|---|---|
| 11:15 | 落地页 $19 产品卡 + 免责定调上线（commit 47c1511） | github.com/535710934-ops/agent-audit-range @47c1511 |
| 15:00 | Creem 产品上线：Greybox — MCP / AI Agent Security Self-Check Toolkit，$19 one-time | creem.io/payment/prod_5OGGTcdFsQ7kJmmZjD6VEd |
| 15:01 | 落地页回填 Creem 支付链接（commit 95c168b） | 仓库 @95c168b |
| 16:0x | 出海收款闭环：Payout 账户（Paysway，Wang Longjun）通过验证，Grebox 商店待身份审绿 | Creem 后台 |
| 16:12 | 仓库推 2 commit：P0 买家差异化段 + 扫描器 OWASP Cheat Sheet 映射注释（6b6a8b4）；双映射 Self-Check-Toolkit-v2 进 docs + 落地页 $19 卡改双映射（86a5d4d） | 仓库 @6b6a8b4 / @86a5d4d |

### 本周我改了主意（必填一句真看法）

- 把"投 awesome-mcp PR 当长尾搜索位"降级为低优先级——理由是：专门那个列表已手动维护停滞，活跃那个按 star 自动收录、投 PR 不生效。**我原以为投 PR 白拿搜索位，后来发现它看指标不看投稿，收回。**
- 把 P0 引流主力从"安全 newsletter / 渠道厂商"挪到"DEV.to 痛点长文（独立开发者自查 MCP 偷 key）"——FreeBuf 0 转化 + 同层免费竞品（mcp-scan / mcpaudit / mcpscan / MCP-Scanner）都在，说明安全圈 C 端不是采购方，**独立开发者才是 $19 工具的真实买家。**

### 行业信号（本周外部）

- 同层竞品活跃：`@agentdefenders/mcp-scan`（11 客户端配置 + 投毒检测）、`mcpaudit`（Morendais，动态 fuzzing + CI SARIF）、`mcpscan`（GitHub Actions）、MCP-Scanner（eSentire，ACM 2026 论文）——全是免费开源、进 CI、绑 GitHub。我方差异 = 署名判断 + 合规映射产物 + 被动/授权/脱敏安全姿态。

---
_更新约定：每周追加一行"改了主意"，无真实改动则写"本周无立场变化"，不硬凑。_
