"""
自主Agent测试
"""

import pytest
import asyncio

from app.agents.autonomous_agent import (
    AutonomousAgent,
    AgentPhase,
    AgentState,
    run_autonomous_attack,
)


class TestAgentState:
    """测试Agent状态"""

    def test_initial_state(self):
        """测试初始状态"""
        state = AgentState(target="127.0.0.1")
        assert state.phase == AgentPhase.INIT
        assert state.target == "127.0.0.1"
        assert state.current_iteration == 0
        assert state.flag_found == False

    def test_should_stop_max_iterations(self):
        """测试最大迭代停止"""
        state = AgentState(target="test", max_iterations=5)
        state.current_iteration = 5
        assert state.current_iteration >= state.max_iterations


class TestAutonomousAgent:
    """测试自主Agent"""

    def test_agent_creation(self):
        """测试创建Agent"""
        agent = AutonomousAgent(
            target="192.168.1.1",
            objective="获取flag"
        )

        assert agent.target == "192.168.1.1"
        assert agent.objective == "获取flag"
        assert agent.state.phase == AgentPhase.INIT

    def test_should_stop_on_completed(self):
        """测试完成状态停止"""
        agent = AutonomousAgent(target="test")
        agent.state.phase = AgentPhase.COMPLETED
        assert agent._should_stop() == True

    def test_should_stop_on_flag(self):
        """测试发现flag停止"""
        agent = AutonomousAgent(target="test")
        agent.state.flag_found = True
        assert agent._should_stop() == True

    def test_has_web_service(self):
        """测试Web服务检测"""
        agent = AutonomousAgent(target="test")

        # 无发现
        assert agent._has_web_service() == False

        # 有Web端口
        agent.state.findings.append({
            "type": "open_ports",
            "ports": ["80", "443"]
        })
        assert agent._has_web_service() == True

    def test_get_web_url(self):
        """测试获取Web URL"""
        agent = AutonomousAgent(target="example.com")

        # HTTP
        agent.state.findings = [{"type": "open_ports", "ports": ["80"]}]
        assert agent._get_web_url() == "http://example.com"

        # HTTPS
        agent.state.findings = [{"type": "open_ports", "ports": ["443"]}]
        assert agent._get_web_url() == "https://example.com"

    def test_process_scan_result(self):
        """测试处理扫描结果"""
        agent = AutonomousAgent(target="test")

        agent._process_scan_result({
            "open_ports": ["80", "22", "443"]
        })

        assert len(agent.state.findings) == 1
        assert agent.state.phase == AgentPhase.EXPLORING

    def test_process_vuln_result(self):
        """测试处理漏洞结果"""
        agent = AutonomousAgent(target="test")

        agent._process_vuln_result({
            "vulnerabilities": [{"name": "SQL Injection"}]
        })

        assert len(agent.state.findings) == 1
        assert agent.state.phase == AgentPhase.ATTACKING

    def test_search_flag(self):
        """测试flag搜索"""
        import asyncio

        agent = AutonomousAgent(target="test")

        # 无flag
        result = asyncio.run(agent._search_flag())
        assert result is None

        # 有flag
        agent.state.findings.append({
            "type": "output",
            "content": "flag{test_flag_here}"
        })
        result = asyncio.run(agent._search_flag())
        assert result == "flag{test_flag_here}"

    def test_build_result(self):
        """测试构建结果"""
        agent = AutonomousAgent(target="test")
        agent.state.flag_found = True
        agent.state.flag = "flag{test}"
        agent.state.current_iteration = 10

        result = agent._build_result()

        assert result["success"] == True
        assert result["flag"] == "flag{test}"
        assert result["iterations"] == 10
        assert result["phase"] == "completed"


class TestAgentPhases:
    """测试Agent阶段转换"""

    def test_phase_init_to_exploring(self):
        """测试INIT到EXPLORING"""
        agent = AutonomousAgent(target="test")
        assert agent.state.phase == AgentPhase.INIT

        agent._process_scan_result({"open_ports": ["80"]})
        assert agent.state.phase == AgentPhase.EXPLORING

    def test_phase_exploring_to_attacking(self):
        """测试EXPLORING到ATTACKING"""
        agent = AutonomousAgent(target="test")
        agent.state.phase = AgentPhase.EXPLORING

        agent._process_vuln_result({"vulnerabilities": [{"name": "XSS"}]})
        assert agent.state.phase == AgentPhase.ATTACKING

    def test_phase_to_completed(self):
        """测试到COMPLETED"""
        agent = AutonomousAgent(target="test")
        agent.state.flag_found = True

        result = agent._build_result()
        assert result["phase"] == "completed"


class TestConvenienceFunction:
    """测试便捷函数"""

    @pytest.mark.asyncio
    async def test_run_autonomous_attack(self):
        """测试便捷函数"""
        # 注意：这会实际执行，可能会失败（工具未安装）
        result = await run_autonomous_attack(
            target="127.0.0.1",
            objective="测试",
            max_iterations=1  # 只执行1步
        )

        # 验证返回格式
        assert "success" in result
        assert "phase" in result
        assert "iterations" in result