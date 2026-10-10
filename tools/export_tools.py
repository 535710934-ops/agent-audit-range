import json, re

src = open(r"C:/Users/Administrator/agent-audit/targets/vulnsite_mcp/server.py",
           encoding="utf-8").read()
m = re.search(r"TOOLS = (\[.*?\n\])", src, re.S)
ns = {}
exec("TOOLS = " + m.group(1), ns)
tools = ns["TOOLS"]

out = r"C:/Users/Administrator/agent-audit/targets/vulnsite_mcp/tools.json"
json.dump({"tools": tools}, open(out, "w", encoding="utf-8"), ensure_ascii=False, indent=2)

WRITE_KW = ("create", "update", "delete", "send", "execute", "run",
            "refund", "transfer", "deploy")
READ_KW = ("list", "get", "search")

writes = [t["name"] for t in tools if any(k in t["name"] for k in WRITE_KW)]
reads = [t["name"] for t in tools if any(k in t["name"] for k in READ_KW)]

print("工具总数:", len(tools))
print("写工具(%d):" % len(writes), writes)
print("读工具(%d):" % len(reads), reads)
print("写占比: %.0f%%" % (100.0 * len(writes) / len(tools)))
print("已导出 ->", out)