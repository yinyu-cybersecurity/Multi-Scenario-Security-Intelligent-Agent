# tests/test_state_types.py
"""
状态类型测试

测试内容:
- 状态类型定义完整性
- 规约器功能正确性
- 向后兼容性
"""

import pytest
import sys
import os

# 添加 app 目录到路径
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'app'))


class TestStateTypes:
    """状态类型测试类"""

    def test_base_state_import(self):
        """测试 BaseCTFState 可导入"""
        from state_types.base import BaseCTFState
        assert BaseCTFState is not None

    def test_web_state_import(self):
        """测试 WebCTFState 可导入"""
        from state_types.web import WebCTFState
        assert WebCTFState is not None

    def test_internal_state_import(self):
        """测试 InternalNetworkState 可导入"""
        from state_types.internal_network import InternalNetworkState
        assert InternalNetworkState is not None

    def test_crypto_state_import(self):
        """测试 CryptoCTFState 可导入"""
        from state_types.crypto import CryptoCTFState
        assert CryptoCTFState is not None

    def test_pwn_state_import(self):
        """测试 PwnCTFState 可导入"""
        from state_types.pwn import PwnCTFState
        assert PwnCTFState is not None

    def test_reverse_state_import(self):
        """测试 ReverseCTFState 可导入"""
        from state_types.reverse import ReverseCTFState
        assert ReverseCTFState is not None

    def test_misc_state_import(self):
        """测试 MiscCTFState 可导入"""
        from state_types.misc import MiscCTFState
        assert MiscCTFState is not None

    def test_base_state_required_fields(self):
        """测试 BaseCTFState 必需字段"""
        from state_types.base import BaseCTFState
        required_fields = [
            'task_name', 'target_url', 'execution_steps',
            'current_mode', 'found_flag', 'start_time'
        ]
        for field in required_fields:
            assert field in BaseCTFState.__annotations__, f"Missing field: {field}"

    def test_state_v2_backward_compatible(self):
        """测试 CTFStateV2 向后兼容"""
        from state_v2 import CTFState, CTFStateV2
        assert CTFState is CTFStateV2


class TestReducers:
    """规约器测试类"""

    def test_cap_list_reducer_basic(self):
        """测试 cap_list_reducer 基本功能"""
        from state_types.reducers import cap_list_reducer
        # 新签名: cap_list_reducer(x, y)，固定上限为 20
        result = cap_list_reducer([1, 2], [3, 4])
        assert result == [1, 2, 3, 4]

    def test_cap_list_reducer_cap(self):
        """测试 cap_list_reducer 上限功能"""
        from state_types.reducers import cap_list_reducer
        # 上限固定为 20，测试超过 20 的情况
        long_list = list(range(15))
        new_items = list(range(15, 25))  # 总共 25 项
        result = cap_list_reducer(long_list, new_items)
        assert len(result) == 20
        # 保留最后 20 个
        assert result == list(range(5, 25))

    def test_cap_candidates_reducer_dedup(self):
        """测试 cap_candidates_reducer 去重功能"""
        from state_types.reducers import cap_candidates_reducer
        existing = [
            {'type': 'sqli', 'location': 'param:id', 'confidence': 0.5}
        ]
        new = [
            {'type': 'sqli', 'location': 'param:id', 'confidence': 0.8},  # 重复，应更新
            {'type': 'xss', 'location': 'param:name', 'confidence': 0.7}   # 新增
        ]
        result = cap_candidates_reducer(existing, new)
        assert len(result) == 2  # 去重后应剩2条

    def test_dedupe_list_reducer(self):
        """测试 dedupe_list_reducer 功能"""
        from state_types.reducers import dedupe_list_reducer
        result = dedupe_list_reducer(['a', 'b'], ['b', 'c'])
        assert 'a' in result
        assert 'b' in result
        assert 'c' in result
        assert len(result) == 3

    def test_merge_dict_reducer(self):
        """测试 merge_dict_reducer 功能"""
        from state_types.reducers import merge_dict_reducer
        result = merge_dict_reducer({'a': 1}, {'b': 2})
        assert result == {'a': 1, 'b': 2}


class TestModuleRegistry:
    """模块注册测试类"""

    def test_module_registry_import(self):
        """测试 ModuleRegistry 可导入"""
        from module_registry import ModuleRegistry
        assert ModuleRegistry is not None

    def test_module_registry_is_available(self):
        """测试 is_available 方法"""
        from module_registry import ModuleRegistry
        # internal_network 模块应该可用
        assert ModuleRegistry.is_available('internal_network')

    def test_module_registry_get_available_modules(self):
        """测试 get_available_modules 方法"""
        from module_registry import ModuleRegistry
        modules = ModuleRegistry.get_available_modules()
        assert isinstance(modules, list)
        assert len(modules) > 0


class TestToolFramework:
    """工具框架测试类"""

    def test_tool_registry_import(self):
        """测试 ToolRegistry 可导入"""
        from tool_framework import ToolRegistry
        assert ToolRegistry is not None

    def test_network_scan_tool_import(self):
        """测试 NetworkScanTool 可导入"""
        from tool_framework import NetworkScanTool
        assert NetworkScanTool is not None

    def test_tool_registration(self):
        """测试工具注册"""
        from tool_framework import ToolRegistry
        import tools  # 触发自动注册

        # 检查是否有工具注册
        assert len(ToolRegistry._tools) > 0


if __name__ == '__main__':
    pytest.main([__file__, '-v'])