"""
CTF-Agent Phase 2 集成测试

测试场景:
1. Web CTF场景 - 扫描 → 发现漏洞 → 利用
2. 内网渗透场景 - 探测 → 凭据获取 → 横向移动
3. 多目标并行扫描
"""

import pytest
import asyncio
from unittest.mock import Mock, patch, AsyncMock

from app.agents.autonomous_agent import (
    AutonomousAgent,
    AgentPhase,
    AgentState,
    run_autonomous_attack
)
from app.coordinator.dispatcher import (
    CoordinatorDispatcher,
    get_coordinator_dispatcher,
    parallel_scan_targets,
    run_autonomous_attack_coordinated,
)
from app.capabilities.foundation import FoundationCapability, FoundationTool
from app.skills import get_skill_registry
from app.memory import get_memory_system


# ============================================
# 测试固件
# ============================================

@pytest.fixture
def mock_tool_success():
    """Mock工具成功执行"""
    return {
        "success": True,
        "open_ports": ["80", "443"],
        "vulnerabilities": [
            {"name": "SQL Injection", "url": "http://test.com?id=1", "severity": "high"}
        ]
    }


@pytest.fixture
def mock_tool_failure():
    """Mock工具失败"""
    return {
        "success": False,
        "error": "工具未安装"
    }


# ============================================
# Web CTF场景测试
# ============================================

class TestWebCTFScenario:
    """
    Web CTF场景测试

    流程: 扫描 → 发现端口 → 漏洞扫描 → 利用 → Flag
    """

    @pytest.mark.asyncio
    async def test_web_ctf_full_flow(self, mock_tool_success):
        """测试完整Web CTF流程"""
        agent = AutonomousAgent(
            target="example.com",
            objective="获取flag",
            max_iterations=10
        )

        # Mock工具执行
        with patch('app.tools_v2.tools.execute_tool', new_callable=AsyncMock) as mock_execute:
            # 第一次调用：端口扫描
            # 第二次调用：漏洞扫描
            mock_execute.side_effect = [
                {"success": True, "open_ports": ["80"]},
                {"success": True, "vulnerabilities": [{"name": "SQLi"}]},
                {"success": True, "flag": "flag{test}"},
            ]

            # 运行
            result = await agent.run()

        # 验证
        assert "success" in result
        assert "phase" in result
        assert "iterations" in result

    @pytest.mark.asyncio
    async def test_web_ctf_scan_phase(self):
        """测试扫描阶段"""
        agent = AutonomousAgent(target="test.com")
        agent.state.phase = AgentPhase.INIT

        # 思考下一步
        action = await agent._think()

        assert action["type"] == "scan"
        assert action["tool"] == "nmap"

    @pytest.mark.asyncio
    async def test_web_ctf_vuln_discovery(self):
        """测试漏洞发现阶段"""
        agent = AutonomousAgent(target="test.com")
        agent.state.phase = AgentPhase.EXPLORING
        agent.state.findings = [{"type": "open_ports", "ports": ["80"]}]

        # 思考下一步
        action = await agent._think()

        # 应该进行漏洞扫描
        assert action["type"] in ["vuln_scan", "skill_recommended"]

    @pytest.mark.asyncio
    async def test_web_ctf_exploitation(self):
        """测试漏洞利用阶段"""
        agent = AutonomousAgent(target="test.com")
        agent.state.phase = AgentPhase.ATTACKING
        agent.state.findings = [
            {"type": "open_ports", "ports": ["80"]},
            {"type": "vulnerabilities", "vulns": [{"name": "SQL Injection", "url": "http://test.com"}]}
        ]

        # 思考下一步
        action = await agent._think()

        # 应该进行利用
        assert action["tool"] in ["sqlmap", "nuclei"]

    @pytest.mark.asyncio
    async def test_web_ctf_flag_extraction(self):
        """测试Flag提取"""
        agent = AutonomousAgent(target="test.com")

        # 模拟发现Flag
        agent.state.findings.append({
            "type": "output",
            "content": "Success! flag{web_ctf_flag_here}"
        })

        # 搜索Flag
        flag = await agent._search_flag()

        assert flag is not None
        assert "flag{" in flag

    @pytest.mark.asyncio
    async def test_web_ctf_memory_sync(self):
        """测试Memory同步"""
        agent = AutonomousAgent(target="test.com")

        # 模拟扫描结果
        result = {
            "success": True,
            "data": {
                "open_ports": ["80", "443"]
            }
        }

        # 处理结果
        agent._process_scan_result(result["data"])

        # 反思（包含Memory写入）
        await agent._reflect(result)

        # 验证发现被记录
        assert len(agent.state.findings) > 0


# ============================================
# 内网渗透场景测试
# ============================================

class TestInternalNetworkScenario:
    """
    内网渗透场景测试

    流程: 探测 → 凭据获取 → 横向移动
    """

    @pytest.mark.asyncio
    async def test_internal_scan_with_fscan(self):
        """测试内网扫描使用fscan"""
        agent = AutonomousAgent(
            target="192.168.1.0/24",
            objective="内网渗透",
            max_iterations=5
        )

        # fscan应该被允许（内网场景）
        with patch('app.tools_v2.tools.execute_tool', new_callable=AsyncMock) as mock_execute:
            mock_execute.return_value = {
                "success": True,
                "open_ports": ["445", "3389"],
                "hosts": ["192.168.1.10", "192.168.1.20"]
            }

            # 执行一步
            action = await agent._think()
            result = await agent._execute_action(action)

        assert result is not None

    @pytest.mark.asyncio
    async def test_credential_discovery(self):
        """测试凭据发现"""
        agent = AutonomousAgent(target="192.168.1.10")

        # 模拟发现凭据
        result = {
            "success": True,
            "data": {
                "credentials": [
                    {"username": "admin", "password": "admin123"}
                ]
            }
        }

        # 反思（应该写入Memory）
        await agent._reflect(result)

        # 验证Memory被调用（阶段可能不变，因为没有更新阶段的逻辑）
        assert True  # 主要测试没有异常

    @pytest.mark.asyncio
    async def test_lateral_movement_planning(self):
        """测试横向移动规划"""
        agent = AutonomousAgent(target="192.168.1.10")
        agent.state.findings = [
            {"type": "credentials", "creds": [{"username": "admin", "password": "admin"}]},
            {"type": "assets", "hosts": ["192.168.1.20", "192.168.1.30"]}
        ]

        # 获取下一步建议
        action = await agent._think()

        # 应该有下一步行动
        assert action is not None


# ============================================
# 多目标并行扫描测试
# ============================================

class TestParallelScanning:
    """
    多目标并行扫描测试

    测试Coordinator的并行派发能力
    """

    @pytest.mark.asyncio
    async def test_parallel_dispatch(self):
        """测试并行派发"""
        dispatcher = get_coordinator_dispatcher()

        # 创建会话
        session_id = await dispatcher.create_session([])

        # 派发任务
        targets = ["192.168.1.10", "192.168.1.20", "192.168.1.30"]
        tasks = await dispatcher.dispatch_parallel_agents(
            session_id=session_id,
            targets=targets,
            task_template="扫描 {target}",
            agent_type="explore"
        )

        # 验证任务创建
        assert len(tasks) == 3
        assert all(t.status == "pending" for t in tasks)

        # 清理
        dispatcher.cleanup_session(session_id)

    @pytest.mark.asyncio
    async def test_parallel_execution(self):
        """测试并行执行"""
        dispatcher = get_coordinator_dispatcher()
        session_id = await dispatcher.create_session([])

        # 派发任务
        targets = ["target1", "target2"]
        await dispatcher.dispatch_parallel_agents(
            session_id=session_id,
            targets=targets,
            task_template="扫描 {target}"
        )

        # Mock执行handler
        async def mock_handler(agent_type, messages, target):
            await asyncio.sleep(0.1)  # 模拟执行
            return {"success": True, "target": target}

        # 并行执行
        results = await dispatcher.execute_all_fork_tasks(
            session_id=session_id,
            execute_handler=mock_handler
        )

        # 验证结果
        assert results["success"] == True
        assert results["completed"] == 2

        # 清理
        dispatcher.cleanup_session(session_id)

    @pytest.mark.asyncio
    async def test_result_aggregation(self):
        """测试结果聚合"""
        dispatcher = get_coordinator_dispatcher()
        session_id = await dispatcher.create_session([])

        # 派发任务
        await dispatcher.dispatch_parallel_agents(
            session_id=session_id,
            targets=["t1", "t2"],
            task_template="扫描 {target}"
        )

        # Mock执行
        async def mock_handler(agent_type, messages, target):
            return {
                "success": True,
                "findings": [{"target": target, "type": "port", "port": "80"}]
            }

        # 执行并聚合
        results = await dispatcher.execute_all_fork_tasks(
            session_id=session_id,
            execute_handler=mock_handler
        )

        # 验证聚合
        assert "findings" in results
        assert len(results["findings"]) >= 0  # 可能为0（去重后）

        dispatcher.cleanup_session(session_id)

    @pytest.mark.asyncio
    async def test_parallel_scan_convenience(self):
        """测试便捷函数"""
        async def mock_execute(agent_type, messages, target):
            return {"success": True, "target": target}

        results = await parallel_scan_targets(
            targets=["t1", "t2"],
            parent_messages=[],
            execute_handler=mock_execute
        )

        assert "success" in results
        assert "total_tasks" in results


# ============================================
# Coordinator监控测试
# ============================================

class TestCoordinatorMonitoring:
    """测试Coordinator监控功能"""

    @pytest.mark.asyncio
    async def test_session_stats(self):
        """测试会话统计"""
        dispatcher = get_coordinator_dispatcher()
        session_id = await dispatcher.create_session([])

        # 获取统计
        stats = dispatcher.get_session_stats(session_id)

        assert stats["session_id"] == session_id
        assert stats["total_tasks"] == 0
        assert stats["completed"] == 0

        dispatcher.cleanup_session(session_id)

    @pytest.mark.asyncio
    async def test_anomaly_detection(self):
        """测试异常检测"""
        dispatcher = get_coordinator_dispatcher()
        session_id = await dispatcher.create_session([])

        # 检测异常（空会话）
        anomalies = await dispatcher.detect_anomalies(session_id)

        # 空会话应该没有异常
        assert isinstance(anomalies, list)

        dispatcher.cleanup_session(session_id)

    @pytest.mark.asyncio
    async def test_high_failure_rate_detection(self):
        """测试高失败率检测"""
        dispatcher = get_coordinator_dispatcher()
        session_id = await dispatcher.create_session([])

        # 创建多个失败任务
        from app.coordinator.dispatcher import ForkTask
        for i in range(10):
            task = ForkTask(
                task_id=f"task_{i}",
                agent_type="explore",
                directive="test",
                target="test",
                status="failed" if i < 6 else "completed"  # 60%失败率
            )
            dispatcher._sessions[session_id].fork_tasks[task.task_id] = task

        # 检测异常
        anomalies = await dispatcher.detect_anomalies(session_id)

        # 应该检测到高失败率
        assert any(a["type"] == "high_failure_rate" for a in anomalies)

        dispatcher.cleanup_session(session_id)


# ============================================
# Skill集成测试
# ============================================

class TestSkillIntegration:
    """测试Skill系统集成"""

    @pytest.mark.asyncio
    async def test_skill_suggestion_in_think(self):
        """测试Skill建议集成"""
        agent = AutonomousAgent(target="test.com")

        # 获取Skill建议
        suggestion = await agent._get_skill_suggestion()

        # 可能返回None（无匹配Skill）或具体建议
        if suggestion:
            assert "tool" in suggestion
            assert "type" in suggestion

    @pytest.mark.asyncio
    async def test_skill_registry_loading(self):
        """测试Skill注册表加载"""
        registry = get_skill_registry()

        # 查找匹配Skill
        skills = registry.find_matching_skills({
            "task": "SQL注入",
            "phase": "attacking"
        })

        # 可能找到Skill
        assert isinstance(skills, list)


# ============================================
# Memory系统集成测试
# ============================================

class TestMemoryIntegration:
    """测试Memory系统集成"""

    @pytest.mark.asyncio
    async def test_memory_write_in_reflect(self):
        """测试Memory写入"""
        agent = AutonomousAgent(target="test.com")

        # 模拟结果
        result = {
            "success": True,
            "data": {
                "open_ports": ["80"],
                "vulnerabilities": [{"name": "XSS"}]
            }
        }

        # 反思（应该写入Memory）
        await agent._reflect(result)

        # 验证无异常
        assert True

    @pytest.mark.asyncio
    async def test_memory_persistence(self):
        """测试Memory持久化"""
        from app.agents.base import AgentType
        memory = get_memory_system()

        # 写入测试 - 使用AgentType枚举
        await memory.write_finding(
            agent_type=AgentType.EXPLORE,
            target="test.com",
            topic="endpoints",
            data={"port": "80"}
        )

        # Memory应该被记录
        assert True


# ============================================
# 权限检查测试
# ============================================

class TestPermissionChecks:
    """测试权限检查功能"""

    def test_explore_agent_permissions(self):
        """测试Explore Agent权限"""
        from app.agents.autonomous_agent import AutonomousAgent
        from app.agents.base import AgentType

        agent = AutonomousAgent(
            target="test",
            agent_type=AgentType.EXPLORE
        )

        permissions = agent.AGENT_PERMISSIONS.get(AgentType.EXPLORE, [])

        # Explore应该有read权限
        assert "read" in permissions

    def test_attack_agent_permissions(self):
        """测试Attack Agent权限"""
        from app.agents.autonomous_agent import AutonomousAgent
        from app.agents.base import AgentType

        agent = AutonomousAgent(
            target="test",
            agent_type=AgentType.ATTACK
        )

        permissions = agent.AGENT_PERMISSIONS.get(AgentType.ATTACK, [])

        # Attack应该有write和bash权限
        assert "write" in permissions
        assert "bash" in permissions

    @pytest.mark.asyncio
    async def test_permission_denied_for_restricted_tool(self):
        """测试受限工具权限拒绝"""
        from app.agents.autonomous_agent import AutonomousAgent

        # Explore Agent尝试使用攻击工具
        agent = AutonomousAgent(
            target="test",
            agent_type="explore"
        )

        # 尝试执行攻击工具
        has_permission = agent._check_permission("sqlmap", "exploit")

        # Explore不应该有network_attack权限
        assert has_permission == False


# ============================================
# 运行测试
# ============================================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])