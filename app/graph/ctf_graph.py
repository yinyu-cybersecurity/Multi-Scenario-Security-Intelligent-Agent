# app/graph/ctf_graph.py
"""
LangGraph主图构建

AgenticLoop架构:
Think → Act → Reflect → Decide → [Continue/End]

核心特点:
1. 动态调度 - Agent自主决策
2. 超时熔断 - 唯一硬性停止条件
3. 状态持久化 - MemorySaver支持断点续传
"""

from typing import Literal

from langgraph.graph import StateGraph, END
from langgraph.checkpoint.memory import MemorySaver

from app.state.state_v3 import CTFStateV3, PhaseType
from app.graph.nodes import think_node, act_node, reflect_node


def decide_next(state: CTFStateV3) -> Literal["think", "end"]:
    """
    决策路由：继续循环还是结束

    结束条件:
    1. 找到Flag
    2. 超时
    3. 达到最大迭代
    4. Agent决策完成
    """
    from app.coordinator.dispatcher import get_coordinator_dispatcher

    # 1. 找到Flag
    if state.get("flags_found"):
        return "end"

    # 2. 达到最大迭代
    if state["iteration_count"] >= state["max_iterations"]:
        return "end"

    # 3. Agent决策完成
    action = state.get("next_action", {})
    if action.get("type") == "complete":
        return "end"

    # 4. 阶段完成
    if state.get("current_phase") == PhaseType.COMPLETE:
        return "end"

    # 5. 检查超时（通过dispatcher）
    try:
        dispatcher = get_coordinator_dispatcher()
        if dispatcher.should_stop(state["session_id"]):
            return "end"
    except Exception:
        pass

    # 继续循环
    return "think"


def build_ctf_graph():
    """
    构建AgenticLoop主图

    结构:
    Entry → Think → Act → Reflect → Decide → [Think/END]

    Returns:
        编译后的LangGraph图
    """
    # 创建状态图
    graph = StateGraph(CTFStateV3)

    # =========================================
    # 添加核心节点
    # =========================================
    graph.add_node("think", think_node)
    graph.add_node("act", act_node)
    graph.add_node("reflect", reflect_node)

    # =========================================
    # 设置入口
    # =========================================
    graph.set_entry_point("think")

    # =========================================
    # 添加边
    # =========================================
    # Think → Act
    graph.add_edge("think", "act")

    # Act → Reflect
    graph.add_edge("act", "reflect")

    # Reflect → Decide (条件路由)
    graph.add_conditional_edges(
        "reflect",
        decide_next,
        {
            "think": "think",  # 继续循环
            "end": END         # 结束
        }
    )

    # =========================================
    # 编译图（带状态持久化）
    # =========================================
    checkpointer = MemorySaver()
    compiled_graph = graph.compile(checkpointer=checkpointer)

    return compiled_graph