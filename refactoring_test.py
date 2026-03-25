#!/usr/bin/env python
"""
重构验证脚本 - 自动化测试

用于验证重构过程中每个阶段的正确性
"""

import sys
import os
import time
import json
import subprocess
from datetime import datetime

# 添加路径
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'app'))

# 测试结果记录
results = {
    "timestamp": "",
    "phase": "",
    "tests": [],
    "passed": 0,
    "failed": 0,
    "warnings": 0
}


def test(name: str, condition: bool, detail: str = "") -> bool:
    """记录测试结果"""
    status = "PASS" if condition else "FAIL"
    results["tests"].append({
        "name": name,
        "status": status,
        "detail": detail
    })

    if condition:
        results["passed"] += 1
        print(f"[PASS] {name}")
    else:
        results["failed"] += 1
        print(f"[FAIL] {name}: {detail}")

    return condition


def warn(name: str, detail: str):
    """记录警告"""
    results["warnings"] += 1
    results["tests"].append({
        "name": name,
        "status": "WARN",
        "detail": detail
    })
    print(f"[WARN] {name}: {detail}")


def run_phase_tests(phase: str):
    """运行指定阶段的测试"""
    global results
    results = {
        "timestamp": datetime.now().isoformat(),
        "phase": phase,
        "tests": [],
        "passed": 0,
        "failed": 0,
        "warnings": 0
    }

    print(f"\n{'='*60}")
    print(f"Phase: {phase}")
    print(f"{'='*60}\n")

    if phase == "phase0":
        test_phase0()
    elif phase == "phase1":
        test_phase1()
    elif phase == "phase2":
        test_phase2()
    elif phase == "phase3a":
        test_phase3a()
    elif phase == "phase3b":
        test_phase3b()
    elif phase == "phase3c":
        test_phase3c()
    elif phase == "phase3d":
        test_phase3d()
    elif phase == "full":
        test_full()
    else:
        print(f"Unknown phase: {phase}")
        return

    # 输出摘要
    print(f"\n{'='*60}")
    print(f"Summary: {results['passed']} passed, {results['failed']} failed, {results['warnings']} warnings")
    print(f"{'='*60}")

    # 保存结果
    save_results(phase)

    return results["failed"] == 0


def test_phase0():
    """Phase 0: 准备工作验证"""
    print("--- Module Imports ---")

    # 核心模块导入
    try:
        from state import CTFState, VulnerabilityCandidate
        test("state module import", True)
    except Exception as e:
        test("state module import", False, str(e))

    try:
        from config import config
        test("config module import", True)
    except Exception as e:
        test("config module import", False, str(e))

    try:
        from llm_client import llm_client
        test("llm_client module import", True)
    except Exception as e:
        test("llm_client module import", False, str(e))

    try:
        from tool_framework import ToolRegistry, CommandLineTool, NetworkScanTool
        test("tool_framework module import", True)
    except Exception as e:
        test("tool_framework module import", False, str(e))

    try:
        from self_correction import SelfCorrectionManager
        test("self_correction module import", True)
    except Exception as e:
        test("self_correction module import", False, str(e))

    # 新模块导入
    try:
        from task_persistence import TaskPersistenceManager
        test("task_persistence module import", True)
    except Exception as e:
        test("task_persistence module import", False, str(e))

    try:
        from attack_strategy_evaluator import AttackStrategyEvaluator
        test("attack_strategy_evaluator module import", True)
    except Exception as e:
        test("attack_strategy_evaluator module import", False, str(e))

    # 配置常量检查
    print("\n--- Config Constants ---")
    try:
        from config import config
        test("MAX_VISITED_URLS defined", hasattr(config, 'MAX_VISITED_URLS'))
        test("MAX_VULN_CANDIDATES defined", hasattr(config, 'MAX_VULN_CANDIDATES'))
        test("MAX_CONTEXT_TOKENS defined", hasattr(config, 'MAX_CONTEXT_TOKENS'))
        test("TOOL_TIMEOUT_DEFAULT defined", hasattr(config, 'TOOL_TIMEOUT_DEFAULT'))
        test("LLM_RETRY_COUNT defined", hasattr(config, 'LLM_RETRY_COUNT'))
    except Exception as e:
        test("config constants check", False, str(e))


def test_phase1():
    """Phase 1: 代码规范验证"""
    print("--- Code Style Checks ---")

    # 检查类型提示
    from state import CTFState
    annotations = CTFState.__annotations__
    test("CTFState has annotations", len(annotations) > 50)

    # 检查是否有未导入的类型
    try:
        from typing import get_type_hints
        hints = get_type_hints(CTFState)
        test("CTFState type hints valid", True)
    except Exception as e:
        test("CTFState type hints valid", False, str(e))

    # 检查 config 类型提示
    from config import Config
    test("Config is dataclass", hasattr(Config, '__dataclass_fields__'))


def test_phase2():
    """Phase 2: 模块注册机制验证"""
    print("--- Module Registry ---")

    try:
        from module_registry import ModuleRegistry
        test("module_registry import", True)
    except Exception as e:
        test("module_registry import", False, str(e))
        return

    # 检查注册方法
    test("ModuleRegistry.register exists", hasattr(ModuleRegistry, 'register'))
    test("ModuleRegistry.get_node exists", hasattr(ModuleRegistry, 'get_node'))
    test("ModuleRegistry.is_available exists", hasattr(ModuleRegistry, 'is_available'))

    # 测试模块注册
    try:
        # 检查已注册模块
        modules = ['internal_network', 'crypto', 'pwn', 'reverse', 'misc']
        for mod in modules:
            available = ModuleRegistry.is_available(mod)
            if available:
                test(f"{mod} module available", True)
            else:
                warn(f"{mod} module", "not available (may not be installed)")
    except Exception as e:
        test("module availability check", False, str(e))


def test_phase3a():
    """Phase 3a: state_types 目录结构验证"""
    print("--- State Types Directory Structure ---")

    import os
    state_dir = os.path.join(os.path.dirname(__file__), 'app', 'state_types')

    test("state_types directory exists", os.path.isdir(state_dir))

    expected_files = ['__init__.py', 'base.py', 'reducers.py']
    for f in expected_files:
        path = os.path.join(state_dir, f)
        test(f"{f} exists", os.path.isfile(path))


def test_phase3b():
    """Phase 3b: reducers 迁移验证"""
    print("--- Reducers Migration ---")

    try:
        from state_types.reducers import cap_list_reducer, cap_candidates_reducer
        test("reducers module import", True)

        # 测试 reducer 功能
        result = cap_list_reducer([1, 2], [3, 4], cap=5)
        test("cap_list_reducer works", result == [1, 2, 3, 4])

        result = cap_list_reducer(list(range(10)), [11, 12], cap=10)
        test("cap_list_reducer caps correctly", len(result) == 10)

    except Exception as e:
        test("reducers migration", False, str(e))


def test_phase3c():
    """Phase 3c: 场景状态类验证"""
    print("--- Scene State Classes ---")

    try:
        from state_types.base import BaseCTFState
        test("BaseCTFState import", True)
    except Exception as e:
        test("BaseCTFState import", False, str(e))

    try:
        from state_types.web import WebCTFState
        test("WebCTFState import", True)
    except Exception as e:
        test("WebCTFState import", False, str(e))

    try:
        from state_types.internal_network import InternalNetworkState
        test("InternalNetworkState import", True)
    except Exception as e:
        test("InternalNetworkState import", False, str(e))


def test_phase3d():
    """Phase 3d: 统一导出接口验证"""
    print("--- Unified Export Interface ---")

    try:
        from state import CTFState
        test("CTFState still importable from state", True)

        # 检查向后兼容
        annotations = CTFState.__annotations__
        required_fields = ['target_url', 'execution_steps', 'found_flag', 'current_mode']
        for field in required_fields:
            test(f"CTFState has {field}", field in annotations)

    except Exception as e:
        test("unified export interface", False, str(e))


def test_full():
    """完整测试套件"""
    test_phase0()
    test_phase1()
    test_phase2()
    test_phase3a()
    test_phase3b()
    test_phase3c()
    test_phase3d()

    # API 测试
    print("\n--- API Endpoints ---")
    try:
        from web.api import app
        test("Flask app importable", True)

        with app.test_client() as client:
            response = client.get('/api/health')
            test("/api/health endpoint", response.status_code == 200)
    except Exception as e:
        test("API tests", False, str(e))


def save_results(phase: str):
    """保存测试结果"""
    log_dir = os.path.join(os.path.dirname(__file__), 'logs')
    os.makedirs(log_dir, exist_ok=True)

    filename = f"test_results_{phase}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    filepath = os.path.join(log_dir, filename)

    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    print(f"\nResults saved to: {filepath}")


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python refactoring_test.py <phase>")
        print("Phases: phase0, phase1, phase2, phase3a, phase3b, phase3c, phase3d, full")
        sys.exit(1)

    phase = sys.argv[1]
    success = run_phase_tests(phase)
    sys.exit(0 if success else 1)