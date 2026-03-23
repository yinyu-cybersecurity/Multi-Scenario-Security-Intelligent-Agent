import asyncio
import json
from typing import List, Dict, Any
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from tool_framework import CTFTool
from llm_client import llm_client
from config import config


class MCPClientTool(CTFTool):
    """MCP 客户端工具的中间层基类"""

    def __init__(self, command: str, args: List[str], tool_name_in_mcp: str):
        # 例如启动 fetch server: command="npx", args=["-y", "@modelcontextprotocol/fetch"]
        self.server_params = StdioServerParameters(
            command=command,
            args=args,
            env=None
        )
        self.tool_name_in_mcp = tool_name_in_mcp  # Server 内部注册的工具名，比如 "fetch"

    async def _call_mcp_tool_async(self, arguments: dict) -> dict:
        """核心逻辑：连接 MCP Server 并调用特定工具"""
        try:
            # 1. 通过 stdio 启动并连接外部的 MCP Server
            async with stdio_client(self.server_params) as (read, write):
                async with ClientSession(read, write) as session:
                    # 2. 初始化连接
                    await session.initialize()

                    # 3. 调用指定的 MCP Tool
                    result = await session.call_tool(self.tool_name_in_mcp, arguments)

                    # 4. 解析结果 (MCP 标准返回的是 content 列表)
                    if result.content:
                        return {"success": True, "output": result.content[0].text}
                    return {"success": True, "output": "No content returned"}

        except Exception as e:
            return {"success": False, "error": str(e)}

    def execute(self, target: str, params: Dict) -> Dict:
        # 因为我们的基类 execute 是同步的，而 mcp 库是纯异步的，
        # 所以我们需要在这里用 asyncio.run 包装一下

        # 将 target 包装进 arguments 中传递给 MCP Server
        mcp_args = {"url": target, **params}

        # 同步阻塞等待异步结果
        raw_res = asyncio.run(self._call_mcp_tool_async(mcp_args))
        
        if not raw_res.get("success"):
            return raw_res

        output = raw_res.get("output", "")
        
        # 🚨 [核心修改] 使用 AI 智能分析网页抓取结果，提取漏洞线索
        analysis_prompt = f"""
分析以下网页抓取结果 (工具: {self.name()})，寻找潜在的漏洞线索（如 SQL 语法错误、敏感文件、目录遍历迹象等）。
剔除无关的 UI 文案，仅保留关键信息。

### 抓取内容 (前 4000 字符):
{output[:4000]}

### 输出要求 (JSON):
{{
  "vulnerable": true/false, // 是否发现了漏洞迹象（含报错信息证据）
  "critical_findings": ["发现的关键信息、敏感字段、报错指纹等"],
  "tactical_guidance": "战术指引（下一步建议）",
  "summary": "简要总结"
}}
"""
        try:
            analysis_text = llm_client.call_chat_completion(
                model=config.ANALYST_MODEL,
                messages=[{"role": "user", "content": analysis_prompt}],
                temperature=0.1,
                json_mode=True
            )
            
            if "```json" in analysis_text:
                analysis_text = analysis_text.split("```json")[1].split("```")[0]
            elif "```" in analysis_text:
                analysis_text = analysis_text.split("```")[1].split("```")[0]
                
            analysis_data = json.loads(analysis_text)
            
            # 保留原始输出用于日志归档
            analysis_data["raw_output"] = output
            analysis_data["success"] = True
            return analysis_data
            
        except Exception as e:
            return {
                "success": True, 
                "vulnerable": False,
                "summary": "抓取成功，但 AI 分析失败",
                "raw_output": output
            }