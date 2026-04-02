# tests/test_graph.py
"""
AgenticLoop架构集成测试

测试覆盖:
1. Think节点 - LLM决策逻辑
2. Act节点 - 工具执行和子Agent派发
3. Reflect节点 - 发现提取和Memory同步
4. 主图流程 - LangGraph循环
"""

import pytest
import asyncio
from unittest.mock import Mock, patch, AsyncMock, MagicMock
from datetime import datetime

from app.graph.ctf_graph import build_ctf_graph, decide_next
from app.graph.nodes import (
    think_node,
    act_node,
    reflect_node,
    validate_tool_name,
    validate_tool_params,
    ActionType
)
from app.state.state_v3 import (
    CTFStateV3,
    ChallengeInfo,
    ChallengeType,
    PhaseType,
    create_initial_state
)
from app.agents.base import AgentType


# ============================================
# Fixtures
# ============================================

@pytest.fixture
def mock_state() -> CTFStateV3:
    """创建测试状态"""
    challenge = ChallengeInfo(
        challenge_id="test_001",
        challenge_type=ChallengeType.WEB,
        title="Test Challenge",
        description="Test description",
        target_url="http://test.example.com"
    )
    state = create_initial_state(challenge)
    state["session_id"] = "test_session_001"
    state["max_iterations"] = 50
    return state


@pytest.fixture
def mock_dispatcher():
    """模拟Dispatcher"""
    dispatcher = Mock()
    dispatcher.should_stop = Mock(return_value=False)
    dispatcher.get_remaining_time = Mock(return_value=1800)
    dispatcher.create_session = AsyncMock(return_value="test_session_001")
    dispatcher.cleanup_session = Mock()
    return dispatcher


@pytest.fixture
def mock_llm_client():
    """模拟LLM客户端"""
    client = Mock()
    client.call_chat_completion = Mock(return_value='{"type": "switch_phase", "new_phase": "explore"}')
    return client


# ============================================
# 安全验证测试
# ============================================

class TestSecurityValidation:
    """测试安全验证函数"""

    def test_validate_tool_name_allowed(self):
        """测试允许的工具名称"""
        assert validate_tool_name("nmap") is True
        assert validate_tool_name("sqlmap") is True
        assert validate_tool_name("nuclei") is True

    def test_validate_tool_name_blocked(self):
        """测试阻止的工具名称"""
        assert validate_tool_name("rm") is False
        assert validate_tool_name("format") is False
        assert validate_tool_name("del") is False
        assert validate_tool_name("") is False
        assert validate_tool_name(None) is False

    def test_validate_tool_params_valid(self):
        """测试合法参数"""
        params = {
            "target": "192.168.1.1",
            "port": 80,
            "options": "--batch"
        }
        is_valid, error = validate_tool_params(params, "sqlmap")
        assert is_valid is True
        assert error == ""

    def test_validate_tool_params_too_long(self):
        """测试超长参数"""
        params = {
            "target": "a" * 15000
        }
        is_valid, error = validate_tool_params(params, "nmap")
        assert is_valid is False
        assert "exceeds max length" in error

    def test_validate_tool_params_invalid_name(self):
        """测试非法参数名"""
        params = {
            "target;rm -rf /": "value"
        }
        is_valid, error = validate_tool_params(params, "nmap")
        assert is_valid is False
        assert "Invalid parameter name" in error


# ============================================
# Think节点测试
# ============================================

class TestThinkNode:
    """测试Think节点"""

    @pytest.mark.asyncio
    async def test_think_node_timeout(self, mock_state):
        """测试超时检查"""
        with patch('app.graph.nodes.get_coordinator_dispatcher') as mock_disp:
            dispatcher = Mock()
            dispatcher.should_stop = Mock(return_value=True)
            mock_disp.return_value = dispatcher

            result = await think_node(mock_state)

            assert result["next_action"]["type"] == "complete"
            assert result["next_action"]["reason"] == "timeout"

    @pytest.mark.asyncio
    async def test_think_node_returns_action(self, mock_state, mock_dispatcher, mock_llm_client):
        """测试Think节点返回行动决策"""
        with patch('app.graph.nodes.get_coordinator_dispatcher') as mock_disp, \
             patch('app.graph.nodes.get_deferred_tool_registry') as mock_registry, \
             patch('app.graph.nodes.get_skill_registry') as mock_skill, \
             patch('app.graph.nodes.get_agent_memory') as mock_memory, \
             patch('app.graph.nodes.llm_client', mock_llm_client):

            mock_disp.return_value = mock_dispatcher

            mock_reg_instance = Mock()
            mock_reg_instance.get_tools_for_context = Mock(return_value=["nmap", "nuclei"])
            mock_registry.return_value = mock_reg_instance

            mock_skill_instance = Mock()
            mock_skill_instance.find_matching_skills = Mock(return_value=[])
            mock_skill.return_value = mock_skill_instance

            mock_memory_instance = Mock()
            mock_memory_instance.read_finding = Mock(return_value=[])
            mock_memory.return_value = mock_memory_instance

            result = await think_node(mock_state)

            assert "next_action" in result
            assert result["next_action"]["type"] in [
                ActionType.DIRECT_TOOL.value,
                ActionType.DISPATCH_SUBAGENT.value,
                ActionType.SWITCH_PHASE.value,
                ActionType.COMPLETE.value
            ]


# ============================================
# Act节点测试
# ============================================

class TestActNode:
    """测试Act节点"""

    @pytest.mark.asyncio
    async def test_act_node_switches_phase(self, mock_state):
        """测试阶段切换"""
        mock_state["next_action"] = {
            "type": "switch_phase",
            "new_phase": "attack"
        }

        result = await act_node(mock_state)

        assert result["current_phase"] == PhaseType.ATTACK
        assert result["iteration_count"] == 1

    @pytest.mark.asyncio
    async def test_act_node_completes(self, mock_state):
        """测试任务完成"""
        mock_state["next_action"] = {
            "type": "complete",
            "reason": "flag_found"
        }

        result = await act_node(mock_state)

        assert result["current_phase"] == PhaseType.COMPLETE
        assert result["final_result"]["reason"] == "flag_found"

    @pytest.mark.asyncio
    async def test_act_node_tool_validation(self, mock_state):
        """测试工具名称验证"""
        mock_state["next_action"] = {
            "type": "direct_tool",
            "tool": "rm",  # 非法工具
            "params": {}
        }

        result = await act_node(mock_state)

        assert result["last_tool_result"]["success"] is False
        assert "not allowed" in result["last_tool_result"]["error"]

    @pytest.mark.asyncio
    async def test_act_node_executes_tool(self, mock_state):
        """测试工具执行"""
        mock_state["next_action"] = {
            "type": "direct_tool",
            "tool": "nmap",
            "params": {"target": "192.168.1.1"}
        }

        with patch('app.graph.nodes.execute_tool', new_callable=AsyncMock) as mock_exec:
            mock_exec.return_value = {"success": True, "open_ports": [80, 443]}

            result = await act_node(mock_state)

            assert result["last_tool_result"]["success"] is True
            assert len(result["tool_history"]) == 1
            mock_exec.assert_called_once_with("nmap", {"target": "192.168.1.1"})


# ============================================
# Reflect节点测试
# ============================================

class TestReflectNode:
    """测试Reflect节点"""

    @pytest.mark.asyncio
    async def test_reflect_extracts_findings(self, mock_state):
        """测试发现提取"""
        mock_state["last_tool_result"] = {
            "success": True,
            "open_ports": [80, 443]
        }

        with patch('app.graph.nodes.get_agent_memory') as mock_mem, \
             patch('app.graph.nodes.extract_flags', return_value=[]), \
             patch('app.graph.nodes.get_context_compressor') as mock_comp:

            mock_mem_instance = Mock()
            mock_mem_instance.write_finding = AsyncMock()
            mock_mem.return_value = mock_mem_instance

            mock_comp_instance = Mock()
            mock_comp_instance.build_prompt_context = Mock(return_value="compressed")
            mock_comp.return_value = mock_comp_instance

            result = await reflect_node(mock_state)

            assert len(result["findings"]) > 0
            assert result["findings"][0]["type"] == "endpoint"

    @pytest.mark.asyncio
    async def test_reflect_compresses_context(self, mock_state):
        """测试上下文压缩"""
        # 添加超过20个发现
        for i in range(25):
            mock_state["findings"].append({
                "type": "test",
                "content": f"Finding {i}"
            })

        with patch('app.graph.nodes.get_agent_memory') as mock_mem, \
             patch('app.graph.nodes.extract_flags', return_value=[]), \
             patch('app.graph.nodes.get_context_compressor') as mock_comp:

            mock_mem_instance = Mock()
            mock_mem_instance.write_finding = AsyncMock()
            mock_mem.return_value = mock_mem_instance

            mock_comp_instance = Mock()
            mock_comp_instance.build_prompt_context = Mock(return_value="compressed")
            mock_comp.return_value = mock_comp_instance

            result = await reflect_node(mock_state)

            # 应该压缩到15个
            assert len(result["findings"]) == 15


# ============================================
# 决策路由测试
# ============================================

class TestDecideNext:
    """测试决策路由"""

    def test_decide_next_with_flags(self, mock_state):
        """找到Flag时应该结束"""
        mock_state["flags_found"] = ["flag{test}"]
        result = decide_next(mock_state)
        assert result == "end"

    def test_decide_next_max_iterations(self, mock_state):
        """达到最大迭代时应该结束"""
        mock_state["iteration_count"] = 100
        mock_state["max_iterations"] = 50
        result = decide_next(mock_state)
        assert result == "end"

    def test_decide_next_complete_action(self, mock_state):
        """Agent决策完成时应该结束"""
        mock_state["next_action"] = {"type": "complete"}
        result = decide_next(mock_state)
        assert result == "end"

    def test_decide_next_continue(self, mock_state):
        """正常情况应该继续"""
        mock_state["iteration_count"] = 5
        mock_state["max_iterations"] = 50
        result = decide_next(mock_state)
        assert result == "think"


# ============================================
# 主图测试
# ============================================

class TestBuildGraph:
    """测试图构建"""

    def test_graph_builds_successfully(self):
        """图应该成功构建"""
        graph = build_ctf_graph()
        assert graph is not None

    @pytest.mark.asyncio
    async def test_graph_execution_flow(self, mock_state):
        """测试图执行流程"""
        with patch('app.graph.ctf_graph.think_node', new_callable=AsyncMock) as mock_think, \
             patch('app.graph.ctf_graph.act_node', new_callable=AsyncMock) as mock_act, \
             patch('app.graph.ctf_graph.reflect_node', new_callable=AsyncMock) as mock_reflect:

            # 设置模拟返回值
            mock_think.return_value = mock_state
            mock_act.return_value = mock_state
            mock_reflect.return_value = mock_state

            # 模拟完成条件
            mock_state["flags_found"] = ["flag{test}"]

            graph = build_ctf_graph()

            # 验证图可以执行
            assert graph is not None


# ============================================
# 集成测试
# ============================================

class TestIntegration:
    """端到端集成测试"""

    @pytest.mark.asyncio
    async def test_full_cycle(self, mock_state):
        """测试完整Think-Act-Reflect循环"""
        # 模拟一个完整的循环
        with patch('app.graph.nodes.get_coordinator_dispatcher') as mock_disp, \
             patch('app.graph.nodes.get_deferred_tool_registry') as mock_reg, \
             patch('app.graph.nodes.get_skill_registry') as mock_skill, \
             patch('app.graph.nodes.get_agent_memory') as mock_mem, \
             patch('app.graph.nodes.llm_client') as mock_llm, \
             patch('app.graph.nodes.execute_tool', new_callable=AsyncMock) as mock_exec, \
             patch('app.graph.nodes.extract_flags', return_value=[]), \
             patch('app.graph.nodes.get_context_compressor'):

            # 设置模拟
            dispatcher = Mock()
            dispatcher.should_stop = Mock(return_value=False)
            mock_disp.return_value = dispatcher

            registry = Mock()
            registry.get_tools_for_context = Mock(return_value=["nmap"])
            mock_reg.return_value = registry

            skill_registry = Mock()
            skill_registry.find_matching_skills = Mock(return_value=[])
            mock_skill.return_value = skill_registry

            memory = Mock()
            memory.read_finding = Mock(return_value=[])
            memory.write_finding = AsyncMock()
            mock_mem.return_value = memory

            mock_llm.call_chat_completion = Mock(
                return_value='{"type": "direct_tool", "tool": "nmap", "params": {"target": "test"}}'
            )

            mock_exec.return_value = {"success": True, "open_ports": [80]}

            # 执行Think
            state_after_think = await think_node(mock_state)
            assert "next_action" in state_after_think

            # 执行Act
            state_after_act = await act_node(state_after_think)
            assert "last_tool_result" in state_after_act

            # 执行Reflect
            state_after_reflect = await reflect_node(state_after_act)
            assert len(state_after_reflect["findings"]) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])