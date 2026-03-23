# tools/mcp_tool_fetch.py
from typing import Any, Dict, List
from tools.mcp_tool_base import MCPClientTool

class MCPFetchTool(MCPClientTool):
    def __init__(self):
        # 核心修改：使用 uvx 启动官方的 Python 版 fetch server
        super().__init__(
            command="uvx",
            args=["mcp-server-fetch"],
            tool_name_in_mcp="fetch"
        )

    def name(self) -> str:
        return "mcp_fetch"

    def description(self) -> str:
        return "利用标准 MCP 协议抓取网页并将其转换为干净的 Markdown 格式。"

    def supported_vulns(self) -> List[str]:
        return ["info_gathering", "recon"]

    def check_available(self) -> bool:
        # 核心修改：检查系统里有没有装 uvx
        import shutil
        return shutil.which("uvx") is not None
# 👇 这是为你补上的核心方法，有了它就不再是抽象类了
    def expected_params(self) -> Dict[str, Dict[str, Any]]:
        return {
            "url": {
                "type": "str",
                "description": "要抓取内容的网页 URL",
                "required": False, # 在你的 mcp_tool_base 里，默认会把 target 填进去，所以这里是 False
                "default": None
            }
        }