"""
工具V2测试
"""

import pytest
from unittest.mock import patch, AsyncMock

from app.tools_v2.tool_factory import get_tool_registry_v2
from app.tools_v2.tools import register_all_tools


class TestToolRegistration:
    """测试工具注册"""

    def test_register_all_tools(self):
        """测试注册所有工具"""
        registry = get_tool_registry_v2()

        # 清空注册表
        registry._tools.clear()

        # 注册工具
        register_all_tools()

        # 验证工具已注册
        tools = registry.list_tools()
        assert "nmap" in tools
        assert "nuclei" in tools
        assert "httpx" in tools
        assert "fscan" in tools
        assert "sqlmap" in tools

    def test_tool_schema(self):
        """测试工具Schema"""
        registry = get_tool_registry_v2()
        registry._tools.clear()
        register_all_tools()

        nmap = registry.get_tool("nmap")
        assert nmap is not None

        schema = nmap.get_schema_dict()
        assert schema["name"] == "nmap"
        assert "parameters" in schema
        assert "target" in schema["parameters"]["properties"]

    def test_tool_schema_validation(self):
        """测试参数验证"""
        registry = get_tool_registry_v2()
        registry._tools.clear()
        register_all_tools()

        nmap = registry.get_tool("nmap")

        # 测试缺少必填参数
        from app.tools_v2.tool_factory import ValidationResult
        result = nmap.validator.validate({}, nmap.schema.parameters)
        assert not result.valid
        assert any("target" in e for e in result.errors)


class TestToolSchemas:
    """测试各工具Schema"""

    def test_nmap_schema(self):
        """测试nmap Schema"""
        registry = get_tool_registry_v2()
        nmap = registry.get_tool("nmap")

        schema = nmap.get_schema_dict()
        params = schema["parameters"]["properties"]

        assert "target" in params
        assert "ports" in params
        assert "scan_type" in params
        assert params["scan_type"].get("enum") == ["quick", "full", "service"]

    def test_nuclei_schema(self):
        """测试nuclei Schema"""
        registry = get_tool_registry_v2()
        nuclei = registry.get_tool("nuclei")

        schema = nuclei.get_schema_dict()
        params = schema["parameters"]["properties"]

        assert "target" in params
        assert "severity" in params
        assert params["severity"].get("enum") == ["critical", "high", "medium", "low", "info"]

    def test_sqlmap_schema(self):
        """测试sqlmap Schema"""
        registry = get_tool_registry_v2()
        sqlmap = registry.get_tool("sqlmap")

        schema = sqlmap.get_schema_dict()
        params = schema["parameters"]["properties"]

        assert "target_url" in params
        assert "level" in params
        assert params["level"].get("minimum") == 1
        assert params["level"].get("maximum") == 5
        assert "action" in params
        assert params["action"].get("enum") == ["detect", "dbs", "tables", "dump", "shell"]