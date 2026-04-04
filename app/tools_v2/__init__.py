# Tools V2系统
#
# MCP架构 - 所有工具通过MCP服务器注册

from .mcp.client import (
    MCPClient,
    get_mcp_client,
    ensure_mcp_tools_registered,
)

__all__ = [
    # MCP客户端
    "MCPClient",
    "get_mcp_client",
    "ensure_mcp_tools_registered",
]