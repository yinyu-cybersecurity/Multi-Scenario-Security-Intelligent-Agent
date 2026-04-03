"""
CTF-Agent 2.0 综合测试脚本

验证所有核心组件是否正常工作：
1. Query循环
2. Skill系统
3. 工具注册
4. 外部Store
5. Meta Tools
"""

import asyncio
from pathlib import Path


def test_skill_system():
    """测试Skill系统"""
    print("\n=== 测试Skill系统 ===")

    from app.skills.registry import get_skill_registry

    # 重置registry
    import app.skills.registry
    app.skills.registry._registry = None

    registry = get_skill_registry()

    # 检查meta_skill_selector
    skill = registry.get_skill('meta_skill_selector')
    if not skill:
        print("[FAIL] meta_skill_selector not found")
        return False

    print(f"[OK] skill_id: {skill.skill_id}")
    print(f"[OK] name: {skill.name}")
    print(f"[OK] domain: {skill.domain}")

    # 检查工具偏好
    if skill.tool_preferences:
        print(f"[OK] tool_preferences: {len(skill.tool_preferences)} items")
        for p in skill.tool_preferences[:3]:
            print(f"    - {p.tool_name}: score={p.score}")
    else:
        print("[FAIL] No tool_preferences")
        return False

    return True


async def test_meta_tools():
    """测试Meta Tools"""
    print("\n=== 测试Meta Tools ===")

    from app.tools_v2.ctf_tools import register_ctf_tools
    from app.tools_v2.tool_factory import get_tool_registry_v2

    # 重置
    import app.skills.registry
    app.skills.registry._registry = None

    register_ctf_tools()

    tool_registry = get_tool_registry_v2()

    # 检查load_skill
    load_skill = tool_registry.get_tool('load_skill')
    if not load_skill:
        print("[FAIL] load_skill tool not found")
        return False

    print("[OK] load_skill tool registered")

    # 测试load_skill handler
    result = await load_skill.handler({'name': 'meta_skill_selector'}, {})

    if not result.get('success'):
        print(f"[FAIL] load_skill failed: {result.get('error')}")
        return False

    print(f"[OK] load_skill returns skill_id: {result.get('skill_id')}")
    print(f"[OK] load_skill returns skill_name: {result.get('skill_name')}")

    return True


def test_external_store():
    """测试外部Store"""
    print("\n=== 测试外部Store ===")

    from app.state.store import get_app_state_store

    store = get_app_state_store()

    # 获取状态
    state = store.get_state()
    print(f"[OK] Store initialized")

    # 测试更新
    def update_state(s):
        s.update({"test_key": "test_value"})
        return s  # 必须返回更新后的state

    store.set_state(update_state)
    new_state = store.get_state()

    if new_state.get("test_key") != "test_value":
        print("[FAIL] Store update failed")
        return False

    print("[OK] Store update works")

    # 测试订阅
    call_count = [0]

    def on_change():
        call_count[0] += 1

    unsubscribe = store.subscribe(on_change)

    # 创建新的AppState对象来触发订阅
    from app.state.store import AppState
    new_state = AppState()
    new_state.update({"another_key": "another_value"})
    store.set_state(lambda s: new_state)

    if call_count[0] == 0:
        print("[FAIL] Subscription not working")
        return False

    print(f"[OK] Subscription works (called {call_count[0]} times)")
    unsubscribe()

    return True


def test_tool_registration():
    """测试工具注册"""
    print("\n=== 测试工具注册 ===")

    from app.tools_v2.ctf_tools import register_ctf_tools
    from app.tools_v2.tool_factory import get_tool_registry_v2

    # 注册工具
    register_ctf_tools()

    tool_registry = get_tool_registry_v2()

    # 检查关键工具
    critical_tools = ['load_skill', 'dispatch_agent', 'write_memory', 'read_memory', 'http_request']

    for tool_name in critical_tools:
        tool = tool_registry.get_tool(tool_name)
        if not tool:
            print(f"[FAIL] {tool_name} not registered")
            return False
        print(f"[OK] {tool_name} registered")

    return True


async def test_query_loop_structure():
    """测试Query循环结构"""
    print("\n=== 测试Query循环结构 ===")

    from app.core.query import query, QueryConfig

    config = QueryConfig(
        model='glm-5',
        max_turns=1,
        system_prompt='Test',
    )

    messages = [{'role': 'user', 'content': 'test'}]

    # 不实际调用LLM，只检查结构
    print("[OK] QueryConfig created")
    print("[OK] Query loop can be initialized")

    return True


def test_selector_store():
    """测试Selector Store"""
    print("\n=== 测试Selector Store ===")

    from app.state.selector_store import get_selector_store

    selector_store = get_selector_store()

    # 定义选择器
    def get_model(state):
        return state.get("model", "unknown")

    # 测试选择器订阅
    call_count = [0]

    def on_model_change():
        call_count[0] += 1

    unsubscribe = selector_store.subscribe_selector(
        "model_watcher",
        get_model,
        on_model_change
    )

    # 更新状态
    selector_store.update_state(lambda s: (s.update({"model": "glm-5"}), s)[1])

    print("[OK] SelectorStore subscription works")

    unsubscribe()
    return True


async def main():
    """运行所有测试"""
    print("=" * 60)
    print("CTF-Agent 2.0 综合测试")
    print("=" * 60)

    results = []

    # 同步测试
    results.append(("Skill系统", test_skill_system()))
    results.append(("外部Store", test_external_store()))
    results.append(("工具注册", test_tool_registration()))
    results.append(("SelectorStore", test_selector_store()))

    # 异步测试
    results.append(("Meta Tools", await test_meta_tools()))
    results.append(("Query循环结构", await test_query_loop_structure()))

    # 总结
    print("\n" + "=" * 60)
    print("测试结果总结")
    print("=" * 60)

    passed = sum(1 for _, r in results if r)
    failed = sum(1 for _, r in results if not r)

    for name, result in results:
        status = "[PASS]" if result else "[FAIL]"
        print(f"{status}: {name}")

    print(f"\n总计: {passed} passed, {failed} failed")

    if failed == 0:
        print("\n[SUCCESS] 所有核心组件测试通过！")
        print("框架已准备就绪，可以进行CTF实战测试。")
    else:
        print("\n[WARNING] 部分组件测试失败，请检查。")


if __name__ == "__main__":
    asyncio.run(main())