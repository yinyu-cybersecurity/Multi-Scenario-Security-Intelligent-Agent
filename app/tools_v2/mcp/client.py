"""
MCP 客户端 - 企业级标准

对齐 Claude Code MCP 实现:
- 多传输支持: stdio (本地工具) + StreamableHTTP (比赛MCP直连)
- 连接健康检查 + 自动重连
- 连接池管理
- 工具 schema 缓存
"""

import asyncio
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from app.logger import get_logger

logger = get_logger("MCP")


# ============================================================================
# 连接管理器 - stdio 传输
# ============================================================================

class MCPConnectionManager:
    """管理单个 stdio MCP 服务器的生命周期"""

    def __init__(self, server_params: StdioServerParameters):
        self._server_params = server_params
        self._task: Optional[asyncio.Task] = None
        self._session: Optional[ClientSession] = None
        self._ready = asyncio.Event()
        self._stop = asyncio.Event()
        self._connected = False

    @property
    def is_connected(self) -> bool:
        return self._connected and self._session is not None

    async def start(self) -> ClientSession:
        self._stop.clear()
        self._ready.clear()
        self._task = asyncio.create_task(self._run())
        try:
            await asyncio.wait_for(self._ready.wait(), timeout=30)
        except asyncio.TimeoutError:
            if self._task:
                self._task.cancel()
            raise RuntimeError("MCP server startup timeout (30s)")
        return self._session

    async def stop(self):
        self._connected = False
        self._stop.set()
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):
                pass

    async def _run(self):
        try:
            async with stdio_client(self._server_params) as (read, write):
                self._session = ClientSession(read, write)
                await self._session.__aenter__()
                self._connected = True
                self._ready.set()
                await self._stop.wait()
        except Exception as e:
            logger.error(f"[MCP] Connection error: {e}")
            self._ready.set()  # 解除等待
        finally:
            self._connected = False
            if self._session:
                try:
                    await self._session.__aexit__(None, None, None)
                except Exception:
                    pass
                self._session = None


# ============================================================================
# StreamableHTTP 连接 (比赛MCP直连)
# ============================================================================

class MCPHttpConnection:
    """通过 StreamableHTTP 连接比赛 MCP 服务器"""

    def __init__(self, url: str, token: str):
        self._url = url
        self._token = token
        self._session: Optional[ClientSession] = None
        self._connected = False
        self._ctx = None
        self._ctx_manager = None

    @property
    def is_connected(self) -> bool:
        return self._connected and self._session is not None

    async def connect(self) -> ClientSession:
        """连接到比赛 MCP 服务器"""
        try:
            from mcp.client.streamable_http import streamablehttp_client
        except ImportError:
            raise ImportError(
                "streamablehttp_client not available. "
                "Upgrade mcp package: pip install mcp>=1.8.0"
            )

        headers = {"Authorization": f"Bearer {self._token}"}
        self._ctx_manager = streamablehttp_client(self._url, headers=headers)
        read, write, _ = await self._ctx_manager.__aenter__()

        self._session = ClientSession(read, write)
        await self._session.__aenter__()
        self._connected = True
        return self._session

    async def disconnect(self):
        self._connected = False
        if self._session:
            try:
                await self._session.__aexit__(None, None, None)
            except Exception:
                pass
            self._session = None
        if self._ctx_manager:
            try:
                await self._ctx_manager.__aexit__(None, None, None)
            except Exception:
                pass
            self._ctx_manager = None


# ============================================================================
# MCP Connector - 统一抽象
# ============================================================================

class MCPConnector:
    """MCP连接器 - 支持 stdio 和 HTTP 两种传输"""

    def __init__(
        self,
        command: str = "",
        args: List[str] = None,
        env: Dict[str, str] = None,
        http_url: str = "",
        http_token: str = "",
    ):
        self._stdio_params = None
        self._http_conn = None
        self._manager: Optional[MCPConnectionManager] = None
        self._tools: List[Dict] = []
        self._session: Optional[ClientSession] = None

        if http_url:
            self._http_conn = MCPHttpConnection(http_url, http_token)
        elif command:
            merged_env = {**os.environ, **(env or {})}
            self._stdio_params = StdioServerParameters(
                command=command,
                args=args or [],
                env=merged_env,
            )

    async def connect(self) -> Dict[str, Any]:
        """建立连接并获取工具列表"""
        if self._http_conn:
            self._session = await self._http_conn.connect()
        elif self._stdio_params:
            self._manager = MCPConnectionManager(self._stdio_params)
            self._session = await self._manager.start()
        else:
            raise RuntimeError("No connection params configured")

        # 初始化并获取工具
        result = await self._session.initialize()
        if result.capabilities and result.capabilities.tools:
            tools_result = await self._session.list_tools()
            self._tools = [t.model_dump() for t in tools_result.tools]

        info = getattr(result, "serverInfo", {})
        return {"server_info": info, "tools": len(self._tools)}

    async def disconnect(self):
        if self._http_conn:
            await self._http_conn.disconnect()
        if self._manager:
            await self._manager.stop()
        self._session = None

    @property
    def is_connected(self) -> bool:
        if self._http_conn:
            return self._http_conn.is_connected
        if self._manager:
            return self._manager.is_connected
        return False

    async def call_tool(self, name: str, arguments: Dict) -> Any:
        if not self._session:
            raise RuntimeError("Not connected")
        result = await self._session.call_tool(name, arguments)
        if result.content:
            return "\n".join(c.text for c in result.content if hasattr(c, "text"))
        return result.model_dump()

    def get_tools(self) -> List[Dict]:
        return self._tools


# ============================================================================
# MCP Session - 单服务器会话 + 自动重连
# ============================================================================

class MCPSession:
    """单个 MCP 服务器的会话管理"""

    def __init__(self, name: str, connector: MCPConnector, max_reconnects: int = 3):
        self.name = name
        self._connector = connector
        self._initialized = False
        self._max_reconnects = max_reconnects
        self._reconnect_count = 0

    async def initialize(self) -> bool:
        if self._initialized and self._connector.is_connected:
            return True
        info = await self._connector.connect()
        self._initialized = True
        self._reconnect_count = 0
        logger.info(f"[MCP] {self.name} connected: {info['tools']} tools")
        return True

    async def close(self):
        await self._connector.disconnect()
        self._initialized = False

    async def call_tool(self, name: str, arguments: Dict) -> Any:
        """调用工具，失败时自动重连一次"""
        try:
            if not self._initialized or not self._connector.is_connected:
                await self.initialize()
            return await self._connector.call_tool(name, arguments)
        except Exception as e:
            if self._reconnect_count < self._max_reconnects:
                self._reconnect_count += 1
                logger.warning(f"[MCP] {self.name} call failed, reconnecting ({self._reconnect_count})...")
                self._initialized = False
                try:
                    await self._connector.disconnect()
                except Exception:
                    pass
                await self.initialize()
                return await self._connector.call_tool(name, arguments)
            raise

    def get_tool_schemas(self) -> List[Dict]:
        """获取此服务器的工具 schema（带 server__tool 前缀）"""
        tools = self._connector.get_tools()
        return [
            {
                "name": f"{self.name}__{t['name']}",
                "description": t.get("description", ""),
                "parameters": t.get("inputSchema", {}),
            }
            for t in tools
        ]


# ============================================================================
# MCP Client - 多服务器管理
# ============================================================================

class MCPClient:
    """
    MCP 客户端 - 管理所有 MCP 服务器连接

    支持:
    - stdio 本地服务器（kali_server.py）
    - StreamableHTTP 远程服务器（比赛MCP直连）
    - 连接自动重连
    """

    def __init__(self, config_path: Optional[str] = None):
        self._sessions: Dict[str, MCPSession] = {}
        self._config: Dict[str, Dict] = {}

        if config_path:
            self._load_config(config_path)

    def _load_config(self, path: str):
        config_file = Path(path)
        if not config_file.exists():
            return

        data = json.loads(config_file.read_text(encoding="utf-8"))

        # 标准 MCP 服务器（stdio）
        for name, cfg in data.get("mcp_servers", {}).items():
            env = {}
            for k, v in cfg.get("env", {}).items():
                # 解析环境变量引用
                if isinstance(v, str) and v.startswith("${") and v.endswith("}"):
                    env[k] = os.environ.get(v[2:-1], "")
                else:
                    env[k] = v
            self._config[name] = {
                "command": cfg.get("command", ""),
                "args": cfg.get("args", []),
                "env": env,
            }

        # 比赛 MCP 直连（如果配置了）
        comp = data.get("competition", {})
        mcp_url = comp.get("mcp_url", "")
        if isinstance(mcp_url, str) and mcp_url.startswith("${"):
            mcp_url = os.environ.get(mcp_url[2:-1], "")

        token = comp.get("agent_token", "")
        if isinstance(token, str) and token.startswith("${"):
            token = os.environ.get(token[2:-1], "")

        # 也从环境变量直接获取
        if not mcp_url:
            mcp_url = os.environ.get("COMPETITION_MCP_URL", "")
        if not token:
            token = os.environ.get("COMPETITION_AGENT_TOKEN", "")

        if mcp_url and token:
            self._config["competition"] = {
                "http_url": mcp_url,
                "http_token": token,
            }

    def add_http_server(self, name: str, url: str, token: str):
        """动态添加 HTTP MCP 服务器"""
        self._config[name] = {
            "http_url": url,
            "http_token": token,
        }

    async def create_session(self, name: str) -> MCPSession:
        """创建或获取 MCP 会话"""
        if name in self._sessions:
            session = self._sessions[name]
            if session._connector.is_connected:
                return session

        cfg = self._config.get(name)
        if not cfg:
            raise ValueError(f"No config for MCP server: {name}")

        # 根据配置类型创建不同的连接器
        if "http_url" in cfg:
            connector = MCPConnector(
                http_url=cfg["http_url"],
                http_token=cfg["http_token"],
            )
        else:
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
        """关闭所有连接"""
        for session in self._sessions.values():
            try:
                await session.close()
            except Exception as e:
                logger.warning(f"[MCP] Error closing {session.name}: {e}")
        self._sessions.clear()

    async def call_tool(self, server: str, tool: str, args: Dict) -> Any:
        """调用指定服务器的工具"""
        session = await self.create_session(server)
        return await session.call_tool(tool, args)

    def get_all_tool_schemas(self) -> List[Dict]:
        """获取所有已连接服务器的工具 schema"""
        schemas = []
        for session in self._sessions.values():
            schemas.extend(session.get_tool_schemas())
        return schemas

    def get_server_names(self) -> List[str]:
        """获取所有已配置的服务器名称"""
        return list(self._config.keys())

    def get_connected_servers(self) -> List[str]:
        """获取所有已连接的服务器名称"""
        return [name for name, s in self._sessions.items() if s._connector.is_connected]


# ============================================================================
# 全局客户端
# ============================================================================

_client: Optional[MCPClient] = None


def get_mcp_client() -> MCPClient:
    """获取全局 MCP 客户端单例"""
    global _client
    if _client is None:
        config_path = str(Path(__file__).parent.parent.parent.parent / "settings.json")
        _client = MCPClient(config_path)
    return _client


async def ensure_mcp_tools_registered():
    """连接所有已配置的 MCP 服务器"""
    client = get_mcp_client()
    connected = 0
    failed = 0

    for server_name in list(client._config.keys()):
        try:
            await client.create_session(server_name)
            connected += 1
        except Exception as e:
            logger.error(f"[MCP] Failed to connect {server_name}: {e}")
            failed += 1

    logger.info(f"[MCP] Servers: {connected} connected, {failed} failed")
    return connected > 0


__all__ = [
    "MCPClient",
    "MCPSession",
    "MCPConnector",
    "get_mcp_client",
    "ensure_mcp_tools_registered",
]
