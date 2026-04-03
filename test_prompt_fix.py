"""
测试系统提示词修复

验证:
1. 系统提示词包含Plan-Execute-Verify循环
2. 强制先调用load_skill
3. 禁止求助用户
"""

import sys


def test_plan_execute_verify_cycle():
    """测试Plan-Execute-Verify循环是否存在"""
    from app.prompts.ctf_system_prompt import CTF_SYSTEM_PROMPT

    # 检查关键阶段
    assert "Phase 1: PLAN" in CTF_SYSTEM_PROMPT, "缺少PLAN阶段"
    assert "Phase 2: EXECUTE" in CTF_SYSTEM_PROMPT, "缺少EXECUTE阶段"
    assert "Phase 3: VERIFY" in CTF_SYSTEM_PROMPT, "缺少VERIFY阶段"

    # 检查强制要求
    assert "Before calling ANY tool, you MUST" in CTF_SYSTEM_PROMPT, "缺少强制规划要求"

    print("[OK] Plan-Execute-Verify循环存在")


def test_skill_system_integration():
    """测试Skill系统集成要求"""
    from app.prompts.ctf_system_prompt import CTF_SYSTEM_PROMPT

    # 检查Skill调用要求
    assert "load_skill" in CTF_SYSTEM_PROMPT, "缺少load_skill工具"
    assert "meta_skill_selector" in CTF_SYSTEM_PROMPT, "缺少meta_skill_selector要求"
    assert "MANDATORY FIRST STEP" in CTF_SYSTEM_PROMPT or "mandatory" in CTF_SYSTEM_PROMPT.lower(), "缺少强制要求"

    print("[OK] Skill系统集成要求存在")


def test_no_user_help():
    """测试禁止求助用户"""
    from app.prompts.ctf_system_prompt import CTF_SYSTEM_PROMPT

    # 检查是否移除了NEED_INPUT
    assert "[NEED_INPUT]" not in CTF_SYSTEM_PROMPT, "仍然允许求助用户"

    # 检查自我debug要求
    assert "DO NOT ask for help" in CTF_SYSTEM_PROMPT or "self-debug" in CTF_SYSTEM_PROMPT.lower() or "self correct" in CTF_SYSTEM_PROMPT.lower(), "缺少自我纠错要求"

    print("[OK] 禁止求助用户，强制自我纠错")


def test_minimal_tool_chain():
    """测试最小工具链原则"""
    from app.prompts.ctf_system_prompt import CTF_SYSTEM_PROMPT

    # 检查工具选择指南
    assert "Tool Selection Guide" in CTF_SYSTEM_PROMPT or "MINIMAL tools" in CTF_SYSTEM_PROMPT, "缺少工具选择指南"

    # 检查禁止重型工具
    assert "DO NOT use heavy tools" in CTF_SYSTEM_PROMPT or "don't" in CTF_SYSTEM_PROMPT.lower(), "缺少重型工具警告"

    print("[OK] 最小工具链原则存在")


def test_output_formats():
    """测试输出格式要求"""
    from app.prompts.ctf_system_prompt import CTF_SYSTEM_PROMPT

    # 检查规划输出格式
    assert "[PLAN]" in CTF_SYSTEM_PROMPT, "缺少规划输出格式"
    assert "[/PLAN]" in CTF_SYSTEM_PROMPT, "缺少规划结束标记"

    # 检查执行输出格式
    assert "[EXECUTE]" in CTF_SYSTEM_PROMPT, "缺少执行输出格式"

    # 检查完成标记
    assert "[TASK_COMPLETE]" in CTF_SYSTEM_PROMPT, "缺少完成标记"

    print("[OK] 输出格式要求存在")


if __name__ == "__main__":
    print("=" * 60)
    print("系统提示词修复验证")
    print("=" * 60)

    tests = [
        ("Plan-Execute-Verify循环", test_plan_execute_verify_cycle),
        ("Skill系统集成", test_skill_system_integration),
        ("禁止求助用户", test_no_user_help),
        ("最小工具链", test_minimal_tool_chain),
        ("输出格式", test_output_formats),
    ]

    results = []
    for name, test_func in tests:
        try:
            test_func()
            results.append((name, True, None))
        except AssertionError as e:
            results.append((name, False, str(e)))
        except Exception as e:
            results.append((name, False, f"异常: {e}"))

    print("\n" + "=" * 60)
    print("测试结果")
    print("=" * 60)

    passed = sum(1 for _, r, _ in results if r)
    failed = len(results) - passed

    for name, result, error in results:
        status = "[PASS]" if result else "[FAIL]"
        print(f"{status}: {name}")
        if error:
            print(f"    错误: {error}")

    print(f"\n总计: {passed}/{len(results)} passed")

    if failed > 0:
        sys.exit(1)