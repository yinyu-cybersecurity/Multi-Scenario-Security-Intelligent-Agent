"""
简化工具系统测试
"""

import pytest
import asyncio

from app.tools_v2.tools import (
    TOOL_SCHEMAS,
    list_tools,
    get_tool_schema,
    get_all_schemas,
    execute_tool,
)


class TestToolSchemas:
    """测试工具Schema定义"""

    def test_list_tools(self):
        """测试列出工具"""
        tools = list_tools()
        assert "nmap" in tools
        assert "nuclei" in tools
        assert "httpx" in tools
        assert "fscan" in tools
        assert "sqlmap" in tools

    def test_get_tool_schema(self):
        """测试获取Schema"""
        schema = get_tool_schema("nmap")
        assert schema is not None
        assert schema["name"] == "nmap"
        assert "inputSchema" in schema
        assert "target" in schema["inputSchema"]["properties"]
        assert "target" in schema["inputSchema"]["required"]

    def test_all_schemas_valid(self):
        """测试所有Schema有效"""
        schemas = get_all_schemas()
        assert len(schemas) == 5

        for schema in schemas:
            assert "name" in schema
            assert "description" in schema
            assert "inputSchema" in schema
            assert "type" in schema["inputSchema"]
            assert "properties" in schema["inputSchema"]

    def test_nmap_schema_parameters(self):
        """测试nmap参数"""
        schema = get_tool_schema("nmap")
        props = schema["inputSchema"]["properties"]

        # target参数
        assert props["target"]["type"] == "string"
        assert "target" in schema["inputSchema"]["required"]

        # ports参数（可选）
        assert props["ports"]["default"] == "1-1000"

        # scan_type枚举
        assert props["scan_type"]["enum"] == ["quick", "full", "service"]

    def test_sqlmap_schema_parameters(self):
        """测试sqlmap参数"""
        schema = get_tool_schema("sqlmap")
        props = schema["inputSchema"]["properties"]

        assert props["level"]["minimum"] == 1
        assert props["level"]["maximum"] == 5
        assert props["action"]["enum"] == ["detect", "dbs", "tables", "dump"]


class TestToolExecution:
    """测试工具执行"""

    @pytest.mark.asyncio
    async def test_execute_unknown_tool(self):
        """测试执行未知工具"""
        result = await execute_tool("unknown", {})
        assert result["success"] == False
        assert "未知工具" in result["error"]

    @pytest.mark.asyncio
    async def test_nmap_not_installed(self):
        """测试nmap未安装情况"""
        # 如果nmap已安装会实际执行
        result = await execute_tool("nmap", {"target": "127.0.0.1"})
        # 只验证返回格式正确
        assert "success" in result


class TestSchemaCompatibility:
    """测试与buildTool的兼容性"""

    def test_register_tools_function(self):
        """测试注册函数"""
        from app.tools_v2.tools import register_tools
        from app.tools_v2.tool_factory import ToolRegistryV2

        registry = ToolRegistryV2()
        register_tools(registry)

        tools = registry.list_tools()
        assert "nmap" in tools
        assert "nuclei" in tools

    def test_tool_schema_dict_format(self):
        """测试Schema字典格式"""
        from app.tools_v2.tools import register_tools
        from app.tools_v2.tool_factory import ToolRegistryV2

        registry = ToolRegistryV2()
        register_tools(registry)

        nmap = registry.get_tool("nmap")
        assert nmap is not None

        schema = nmap.get_schema_dict()
        assert schema["name"] == "nmap"
        assert "parameters" in schema