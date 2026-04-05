"""MCP客户端 - 极简实现"""

import asyncio
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


class MCPConnectionManager:
    """连接管理器"""

    def __init__(self, server_params: StdioServerParameters):
        self._server_params = server_params
        self._task: Optional[asyncio.Task] = None
        self._session: Optional[ClientSession] = None
        self._ready = asyncio.Event()
        self._stop = asyncio.Event()

    async def start(self) -> ClientSession:
        self._task = asyncio.create_task(self._run())
        await self._ready.wait()
        return self._session

    async def stop(self):
        self._stop.set()
        if self._task:
            self._task.cancel()

    async def _run(self):
        try:
            async with stdio_client(self._server_params) as (read, write):
                self._session = ClientSession(read, write)
                await self._session.__aenter__()
                self._ready.set()
                await self._stop.wait()
        finally:
            if self._session:
                await self._session.__aexit__(None, None, None)


class MCPConnector:
    """MCP连接器"""

    def __init__(self, command: str, args: List[str], env: Dict[str, str]):
        self._params = StdioServerParameters(command=command, args=args, env=env)
        self._manager: Optional[MCPConnectionManager] = None
        self._tools: List[Dict] = []

    async def connect(self) -> Dict[str, Any]:
        self._manager = MCPConnectionManager(self._params)
        session = await self._manager.start()

        result = await session.initialize()
        if result.capabilities.tools:
            tools_result = await session.list_tools()
            self._tools = [t.model_dump() for t in tools_result.tools]

        return {"server_info": getattr(result, "serverInfo", {}), "tools": len(self._tools)}

    async def disconnect(self):
        if self._manager:
            await self._manager.stop()

    async def call_tool(self, name: str, arguments: Dict) -> Any:
        if not self._manager or not self._manager._session:
            raise RuntimeError("Not connected")

        result = await self._manager._session.call_tool(name, arguments)
        if result.content:
            return "\n".join(c.text for c in result.content if hasattr(c, "text"))
        return result.model_dump()

    def get_tools(self) -> List[Dict]:
        return self._tools


class MCPSession:
    """MCP会话"""

    def __init__(self, name: str, connector: MCPConnector):
        self.name = name
        self._connector = connector
        self._initialized = False

    async def initialize(self) -> bool:
        if self._initialized:
            return True
        await self._connector.connect()
        self._initialized = True
        return True

    async def close(self):
        await self._connector.disconnect()
        self._initialized = False

    async def call_tool(self, name: str, arguments: Dict) -> Any:
        if not self._initialized:
            await self.initialize()
        return await self._connector.call_tool(name, arguments)

    def get_tool_schemas(self) -> List[Dict]:
        tools = self._connector.get_tools()
        return [
            {
                "name": f"{self.name}__{t['name']}",
                "description": t.get("description", ""),
                "parameters": t.get("inputSchema", {}),
            }
            for t in tools
        ]


class MCPClient:
    """MCP客户端"""

    def __init__(self, config_path: Optional[str] = None):
        self._sessions: Dict[str, MCPSession] = {}
        self._config: Dict[str, Dict] = {}

        if config_path:
            self._load_config(config_path)

    def _load_config(self, path: str):
        config_file = Path(path)
        if not config_file.exists():
            return

        data = json.loads(config_file.read_text())
        servers = data.get("mcp_servers", {})

        for name, cfg in servers.items():
            self._config[name] = {
                "command": cfg.get("command", ""),
                "args": cfg.get("args", []),
                "env": cfg.get("env", {}),
            }

    async def create_session(self, name: str) -> MCPSession:
        if name in self._sessions:
            return self._sessions[name]

        cfg = self._config.get(name)
        if not cfg:
            raise ValueError(f"No config for server: {name}")

        connector = MCPConnector(
            command=cfg["command"],
            args=cfg["args"],
            env=cfg["env"],
        )
        session = MCPSession(name, connector)
        await session.initialize()

        self._sessions[name] = session
        return session

    async def close_all(self):
        for session in self._sessions.values():
            await session.close()
        self._sessions.clear()

    async def call_tool(self, server: str, tool: str, args: Dict) -> Any:
        session = await self.create_session(server)
        return await session.call_tool(tool, args)

    def get_all_tool_schemas(self) -> List[Dict]:
        schemas = []
        for name, session in self._sessions.items():
            schemas.extend(session.get_tool_schemas())
        return schemas


# 全局客户端
_client: Optional[MCPClient] = None


def get_mcp_client() -> MCPClient:
    global _client
    if _client is None:
        config_path = str(Path(__file__).parent.parent.parent.parent / "settings.json")
        _client = MCPClient(config_path)
    return _client


async def ensure_mcp_tools_registered():
    """连接所有MCP服务器"""
    client = get_mcp_client()

    for server_name in list(client._config.keys()):
        try:
            await client.create_session(server_name)
            print(f"[OK] Connected: {server_name}")
        except Exception as e:
            print(f"[FAIL] {server_name}: {e}")


__all__ = ["MCPClient", "get_mcp_client", "ensure_mcp_tools_registered"]