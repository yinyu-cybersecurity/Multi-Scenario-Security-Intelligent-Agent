"""MCP客户端 - Claude Code模式极简实现

架构: Client → Session → Connector → ConnectionManager → SDK
"""
import asyncio
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


# 前向声明避免循环导入
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from app.tools_v2.tool_factory import ParamSchema


class MCPConnectionManager:
    """连接管理器 - 在独立task中管理async context，避免cancel scope错误"""

    def __init__(self, server_params: StdioServerParameters):
        self._server_params = server_params
        self._task: Optional[asyncio.Task] = None
        self._session: Optional[ClientSession] = None
        self._ready = asyncio.Event()
        self._stop = asyncio.Event()

    async def start(self) -> ClientSession:
        """启动连接"""
        self._task = asyncio.create_task(self._run())
        await self._ready.wait()
        return self._session

    async def stop(self):
        """停止连接"""
        self._stop.set()
        if self._task:
            # 不等待任务完成，避免cancel scope错误
            self._task.cancel()

    async def _run(self):
        """在独立task中运行stdio_client"""
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
    """连接器 - 包装ClientSession，提供工具调用接口"""

    def __init__(self, command: str, args: List[str], env: Dict[str, str]):
        self._params = StdioServerParameters(command=command, args=args, env=env)
        self._manager: Optional[MCPConnectionManager] = None
        self._tools: List[Dict] = []

    async def connect(self) -> Dict[str, Any]:
        """连接并初始化"""
        self._manager = MCPConnectionManager(self._params)
        session = await self._manager.start()

        # 初始化会话
        result = await session.initialize()
        if result.capabilities.tools:
            tools_result = await session.list_tools()
            self._tools = [t.model_dump() for t in tools_result.tools]

        return {"server_info": getattr(result, "serverInfo", {}), "tools": len(self._tools)}

    async def disconnect(self):
        """断开连接"""
        if self._manager:
            await self._manager.stop()

    async def call_tool(self, name: str, arguments: Dict) -> Any:
        """调用工具"""
        if not self._manager or not self._manager._session:
            raise RuntimeError("Not connected")

        result = await self._manager._session.call_tool(name, arguments)
        # 提取文本内容
        if result.content:
            return "\n".join(
                c.text for c in result.content if hasattr(c, "text")
            )
        return result.model_dump()

    def get_tools(self) -> List[Dict]:
        """获取工具schema列表"""
        return self._tools


class MCPSession:
    """会话 - 管理单个MCP服务器连接和工具"""

    def __init__(self, name: str, connector: MCPConnector):
        self.name = name
        self._connector = connector
        self._initialized = False

    async def initialize(self) -> bool:
        """初始化会话"""
        if self._initialized:
            return True

        info = await self._connector.connect()
        self._initialized = True
        return True

    async def close(self):
        """关闭会话"""
        await self._connector.disconnect()
        self._initialized = False

    async def call_tool(self, name: str, arguments: Dict) -> Any:
        """调用工具"""
        if not self._initialized:
            await self.initialize()
        return await self._connector.call_tool(name, arguments)

    def get_tool_schemas(self) -> List[Dict]:
        """获取工具schema（用于注册到框架）"""
        tools = self._connector.get_tools()
        return [
            {
                "name": f"{self.name}__{t['name']}",  # 加服务器前缀避免冲突
                "description": t.get("description", ""),
                "parameters": t.get("inputSchema", {}),
            }
            for t in tools
        ]


class MCPClient:
    """客户端 - 管理多个MCP服务器配置"""

    def __init__(self, config_path: Optional[str] = None):
        self._sessions: Dict[str, MCPSession] = {}
        self._config: Dict[str, Dict] = {}

        if config_path:
            self._load_config(config_path)

    def _load_config(self, path: str):
        """加载配置文件"""
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
        """创建会话"""
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
        """关闭所有会话"""
        for session in self._sessions.values():
            await session.close()
        self._sessions.clear()

    async def call_tool(self, server: str, tool: str, args: Dict) -> Any:
        """调用指定服务器的工具"""
        session = await self.create_session(server)
        return await session.call_tool(tool, args)

    def get_all_tool_schemas(self) -> List[Dict]:
        """获取所有服务器的工具schema"""
        schemas = []
        for name, session in self._sessions.items():
            schemas.extend(session.get_tool_schemas())
        return schemas


# 全局客户端实例
_client: Optional[MCPClient] = None


def get_mcp_client() -> MCPClient:
    """获取全局MCP客户端"""
    global _client
    if _client is None:
        config_path = str(Path(__file__).parent.parent.parent.parent / "settings.json")
        _client = MCPClient(config_path)
    return _client


async def ensure_mcp_tools_registered():
    """将MCP工具注册到框架工具注册表

    遵循Claude Code模式：
    1. 启动时连接所有MCP服务器
    2. 获取工具schema
    3. 包装为框架的CTFToolV2
    4. 注册到全局registry
    """
    from app.tools_v2.tool_factory import (
        get_tool_registry_v2,
        CTFToolV2,
        ToolSchema,
        ParamSchema,
        ParamType,
    )
    from app.agents.base import ToolPermission

    client = get_mcp_client()
    registry = get_tool_registry_v2()

    # 连接所有配置的MCP服务器
    servers_to_connect = list(client._config.keys())

    for server_name in servers_to_connect:
        if server_name not in client._config:
            continue

        try:
            session = await client.create_session(server_name)
            tools = session._connector.get_tools()

            for mcp_tool in tools:
                # 转换schema
                tool_name = f"{server_name}__{mcp_tool['name']}"
                param_schema = _convert_mcp_schema(mcp_tool.get("inputSchema", {}))

                # 创建CTFToolV2
                schema = ToolSchema(
                    name=tool_name,
                    description=mcp_tool.get("description", ""),
                    parameters=param_schema,
                    timeout=300,
                    is_read_only=True,
                    is_concurrency_safe=True,
                )

                # 创建handler - 捕获session和tool_name
                async def make_handler(sess, tool):
                    async def handler(params, ctx):
                        return await sess.call_tool(tool, params)
                    return handler

                tool = CTFToolV2(
                    schema=schema,
                    handler=await make_handler(session, mcp_tool["name"]),
                    permissions=[ToolPermission.READ],
                )

                registry.register(tool)
                print(f"[OK] Registered MCP tool: {tool_name}")

        except Exception as e:
            print(f"[FAIL] Failed to connect MCP server {server_name}: {e}")


def _convert_mcp_schema(input_schema: Dict) -> "List[ParamSchema]":
    """转换MCP schema为框架ParamSchema

    MCP使用JSON Schema，框架使用ParamSchema列表
    """
    from app.tools_v2.tool_factory import ParamSchema, ParamType

    params = []
    properties = input_schema.get("properties", {})
    required = set(input_schema.get("required", []))

    type_map = {
        "string": ParamType.STRING,
        "integer": ParamType.INTEGER,
        "number": ParamType.NUMBER,
        "boolean": ParamType.BOOLEAN,
        "array": ParamType.ARRAY,
        "object": ParamType.OBJECT,
    }

    for name, prop in properties.items():
        param_type = type_map.get(prop.get("type", "string"), ParamType.STRING)

        # 检查format
        if prop.get("format") == "uri":
            param_type = ParamType.URI
        elif prop.get("format") == "path":
            param_type = ParamType.PATH

        params.append(ParamSchema(
            name=name,
            type=param_type,
            required=name in required,
            description=prop.get("description", ""),
        ))

    return params