# tests/test_tool_framework.py
"""
工具框架测试

测试内容:
- ToolRegistry 注册和查询
- NetworkScanTool 基类
- 工具执行
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'app'))


class TestToolRegistry:
    """ToolRegistry 测试类"""

    def test_registry_import(self):
        """测试 ToolRegistry 可导入"""
        from tool_framework import ToolRegistry
        assert ToolRegistry is not None

    def test_registry_has_tools(self):
        """测试工具已注册"""
        from tool_framework import ToolRegistry
        import tools  # 触发自动注册

        all_tools = ToolRegistry.get_all_tools()
        assert len(all_tools) > 0, "没有工具被注册"

    def test_get_tool_names(self):
        """测试获取工具名称列表"""
        from tool_framework import ToolRegistry
        import tools

        names = ToolRegistry.get_tool_names()
        assert len(names) > 0
        assert isinstance(names, list)

    def test_get_tool_by_name(self):
        """测试根据名称获取工具"""
        from tool_framework import ToolRegistry
        import tools

        # sqlmap 应该存在
        tool = ToolRegistry.get_tool_by_name('sqlmap')
        assert tool is not None, "sqlmap 工具不存在"
        assert tool.name() == 'sqlmap'

    def test_tool_exists(self):
        """测试工具存在检查"""
        from tool_framework import ToolRegistry
        import tools

        assert ToolRegistry.tool_exists('sqlmap') is True
        assert ToolRegistry.tool_exists('notexist123') is False

    def test_get_statistics(self):
        """测试统计信息"""
        from tool_framework import ToolRegistry
        import tools

        stats = ToolRegistry.get_statistics()
        assert 'total_tools' in stats
        assert 'vuln_types' in stats
        assert stats['total_tools'] > 0

    def test_get_tools_by_vuln_type(self):
        """测试根据漏洞类型获取工具"""
        from tool_framework import ToolRegistry
        import tools

        tools_list = ToolRegistry.get_tools('SQL Injection')
        assert len(tools_list) > 0, "SQL Injection 类型没有工具"


class TestNetworkScanTool:
    """NetworkScanTool 测试类"""

    def test_base_class_import(self):
        """测试 NetworkScanTool 可导入"""
        from tool_framework import NetworkScanTool
        assert NetworkScanTool is not None

    def test_validate_target_ip(self):
        """测试 IP 验证"""
        from tool_framework import NetworkScanTool

        # 创建具体测试子类
        class TestNetworkTool(NetworkScanTool):
            def name(self): return 'test'
            def description(self): return 'test tool'
            def supported_vulns(self): return ['test']
            def execute(self, target, params): return {'success': True}
            def check_available(self): return True
            def expected_params(self): return {}

        tool = TestNetworkTool('test')
        # 有效 IP
        valid, msg = tool.validate_target('192.168.1.1')
        assert valid is True

        # 无效格式（特殊字符）
        valid, msg = tool.validate_target('not!valid@host')
        assert valid is False

        # 空目标
        valid, msg = tool.validate_target('')
        assert valid is False

    def test_validate_target_cidr(self):
        """测试 CIDR 验证"""
        from tool_framework import NetworkScanTool

        class TestNetworkTool(NetworkScanTool):
            def name(self): return 'test'
            def description(self): return 'test tool'
            def supported_vulns(self): return ['test']
            def execute(self, target, params): return {'success': True}
            def check_available(self): return True
            def expected_params(self): return {}

        tool = TestNetworkTool('test')
        valid, msg = tool.validate_target('192.168.1.0/24')
        assert valid is True

    def test_validate_target_hostname(self):
        """测试主机名验证"""
        from tool_framework import NetworkScanTool

        class TestNetworkTool(NetworkScanTool):
            def name(self): return 'test'
            def description(self): return 'test tool'
            def supported_vulns(self): return ['test']
            def execute(self, target, params): return {'success': True}
            def check_available(self): return True
            def expected_params(self): return {}

        tool = TestNetworkTool('test')
        valid, msg = tool.validate_target('example.com')
        assert valid is True

    def test_validate_target_injection(self):
        """测试命令注入防护"""
        from tool_framework import NetworkScanTool

        class TestNetworkTool(NetworkScanTool):
            def name(self): return 'test'
            def description(self): return 'test tool'
            def supported_vulns(self): return ['test']
            def execute(self, target, params): return {'success': True}
            def check_available(self): return True
            def expected_params(self): return {}

        tool = TestNetworkTool('test')
        # 尝试命令注入
        valid, msg = tool.validate_target('192.168.1.1; rm -rf /')
        assert valid is False

        valid, msg = tool.validate_target('$(whoami)')
        assert valid is False

    def test_validate_ports(self):
        """测试端口验证"""
        from tool_framework import NetworkScanTool

        class TestNetworkTool(NetworkScanTool):
            def name(self): return 'test'
            def description(self): return 'test tool'
            def supported_vulns(self): return ['test']
            def execute(self, target, params): return {'success': True}
            def check_available(self): return True
            def expected_params(self): return {}

        tool = TestNetworkTool('test')
        # 有效端口
        valid, msg = tool.validate_ports('80,443,8080')
        assert valid is True

        # 端口范围
        valid, msg = tool.validate_ports('1-1000')
        assert valid is True

        # 无效端口
        valid, msg = tool.validate_ports('99999')
        assert valid is False


class TestNmapTool:
    """NmapTool 测试类"""

    def test_nmap_inherits_network_scan_tool(self):
        """测试 NmapTool 继承 NetworkScanTool"""
        from tool_framework import NetworkScanTool
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'tools'))
        from nmap_tool import NmapTool

        assert issubclass(NmapTool, NetworkScanTool)

    def test_nmap_has_required_methods(self):
        """测试 NmapTool 有必需方法"""
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'tools'))
        from nmap_tool import NmapTool

        tool = NmapTool()
        assert hasattr(tool, 'name')
        assert hasattr(tool, 'description')
        assert hasattr(tool, 'execute')


class TestFscanTool:
    """FscanTool 测试类"""

    def test_fscan_inherits_network_scan_tool(self):
        """测试 FscanTool 继承 NetworkScanTool"""
        from tool_framework import NetworkScanTool
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'tools'))
        from fscan_tool import FscanTool

        assert issubclass(FscanTool, NetworkScanTool)

    def test_fscan_has_required_methods(self):
        """测试 FscanTool 有必需方法"""
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'tools'))
        from fscan_tool import FscanTool

        tool = FscanTool()
        assert hasattr(tool, 'name')
        assert hasattr(tool, 'description')
        assert hasattr(tool, 'execute')


if __name__ == '__main__':
    pytest.main([__file__, '-v'])