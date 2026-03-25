#!/usr/bin/env python3
"""
CTF-Agent 系统验证脚本

验证内容:
1. 核心模块导入
2. 工具系统注册
3. LLM 连接测试
4. 图节点构建
5. 状态定义验证
"""

import sys
import os

# 设置路径
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'app'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'tools'))

def test_core_modules():
    """测试核心模块导入"""
    print("\n=== 1. 核心模块导入测试 ===")
    errors = []

    modules = [
        ('state', 'CTFState'),
        ('config', 'config'),
        ('llm_client', 'llm_client'),
        ('tool_framework', 'ToolRegistry'),
        ('module_registry', 'ModuleRegistry'),
        ('self_correction', 'SelfCorrectionManager'),
        ('prompts', 'PromptRegistry'),
    ]

    for module_name, attr_name in modules:
        try:
            module = __import__(module_name)
            getattr(module, attr_name)
            print(f'[OK] {module_name}.{attr_name}')
        except Exception as e:
            print(f'[FAIL] {module_name}.{attr_name}: {e}')
            errors.append(module_name)

    return len(errors) == 0


def test_tool_system():
    """测试工具系统"""
    print("\n=== 2. 工具系统测试 ===")

    try:
        from tool_framework import ToolRegistry
        import tools  # 触发自动注册

        all_tools = ToolRegistry.get_all_tools()
        print(f'[OK] 已注册工具: {len(all_tools)} 个')

        # 检查关键工具
        critical_tools = ['sqlmap', 'nmap', 'fscan', 'nuclei']
        for tool_name in critical_tools:
            if ToolRegistry.tool_exists(tool_name):
                print(f'[OK] {tool_name} 存在')
            else:
                print(f'[WARN] {tool_name} 不存在')

        return True
    except Exception as e:
        print(f'[FAIL] 工具系统错误: {e}')
        return False


def test_llm_connection():
    """测试 LLM 连接"""
    print("\n=== 3. LLM 连接测试 ===")

    try:
        from llm_client import llm_client
        from config import config

        print(f'API Base: {config.LLM_BASE_URL}')
        print(f'Model: {config.ANALYST_MODEL}')

        # 简单测试
        response = llm_client.call_chat_completion(
            model=config.ANALYST_MODEL,
            messages=[{'role': 'user', 'content': 'Reply with: OK'}],
            temperature=0.1,
            max_tokens=10
        )

        if response:
            print(f'[OK] LLM 响应正常')
            return True
        else:
            print('[FAIL] LLM 无响应')
            return False

    except Exception as e:
        print(f'[FAIL] LLM 连接失败: {e}')
        return False


def test_graph_nodes():
    """测试图节点"""
    print("\n=== 4. 图节点测试 ===")

    try:
        from ctf_agent_graph import (
            recon_node,
            analyst_node,
            attacker_node,
            verifier_node,
            explorer_node,
            mode_manager_node,
            challenge_type_detector_node,
        )
        print('[OK] 主要节点导入成功')

        from evolution import evolution_node
        from strategy_filter import strategy_filter_node
        from innovator_agent import innovator_node
        print('[OK] 辅助节点导入成功')

        # 内网节点
        from internal_network.nodes import (
            internal_recon_node,
            lateral_move_node,
            privilege_escalation_node,
            credential_gather_node,
        )
        print('[OK] 内网节点导入成功')

        return True
    except Exception as e:
        print(f'[FAIL] 节点导入失败: {e}')
        return False


def test_state_definition():
    """测试状态定义"""
    print("\n=== 5. 状态定义测试 ===")

    try:
        from state import CTFState, CTFStateV2
        from state_types.reducers import (
            cap_list_reducer,
            cap_candidates_reducer,
            visited_urls_reducer,
        )

        # 测试 reducer
        result = cap_list_reducer([1, 2], [3, 4])
        print(f'[OK] cap_list_reducer: {result}')

        result = visited_urls_reducer(['a'], ['b', 'c'])
        print(f'[OK] visited_urls_reducer: {result}')

        # 测试状态兼容性
        assert CTFState is CTFStateV2
        print('[OK] CTFState 向后兼容')

        return True
    except Exception as e:
        print(f'[FAIL] 状态定义错误: {e}')
        return False


def test_config():
    """测试配置"""
    print("\n=== 6. 配置测试 ===")

    try:
        from config import config

        critical_fields = [
            'LLM_API_KEY',
            'LLM_BASE_URL',
            'ANALYST_MODEL',
            'MAX_TOTAL_ROUNDS',
            'TASK_TIMEOUT',
        ]

        for field in critical_fields:
            value = getattr(config, field, None)
            if value:
                if 'KEY' in field:
                    print(f'[OK] {field}: ***')
                else:
                    print(f'[OK] {field}: {value}')
            else:
                print(f'[WARN] {field}: 未设置')

        return True
    except Exception as e:
        print(f'[FAIL] 配置错误: {e}')
        return False


def main():
    """主函数"""
    print("=" * 50)
    print("CTF-Agent 系统验证")
    print("=" * 50)

    results = []

    results.append(('核心模块', test_core_modules()))
    results.append(('工具系统', test_tool_system()))
    results.append(('LLM连接', test_llm_connection()))
    results.append(('图节点', test_graph_nodes()))
    results.append(('状态定义', test_state_definition()))
    results.append(('配置检查', test_config()))

    print("\n" + "=" * 50)
    print("验证结果汇总")
    print("=" * 50)

    all_passed = True
    for name, passed in results:
        status = 'PASS' if passed else 'FAIL'
        print(f'{name}: {status}')
        if not passed:
            all_passed = False

    print("\n" + "=" * 50)
    if all_passed:
        print("所有验证通过！系统就绪。")
    else:
        print("部分验证失败，请检查上述错误。")
    print("=" * 50)

    return 0 if all_passed else 1


if __name__ == '__main__':
    sys.exit(main())