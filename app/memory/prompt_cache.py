# Prompt Cache共享管理器
#
# 借鉴Claude Code的Fork子Agent机制
# 实现Prompt Cache共享，避免重复传输大Token上下文

import uuid
from typing import List, Dict, Any, Optional, Callable
from dataclasses import dataclass, field
import copy


# 占位符 - 用于Prompt Cache命中
FORK_PLACEHOLDER_RESULT = "[Previous tool result preserved for cache]"


@dataclass
class Message:
    """消息类型"""
    role: str  # user, assistant, tool_result
    content: List[Dict]
    uuid: str = field(default_factory=lambda: str(uuid.uuid4()))

    def to_api_format(self) -> Dict:
        """转换为API格式"""
        return {
            "role": self.role,
            "content": self.content
        }


@dataclass
class ToolUseBlock:
    """工具使用块"""
    id: str
    name: str
    input: Dict[str, Any]

    def to_dict(self) -> Dict:
        return {
            "type": "tool_use",
            "id": self.id,
            "name": self.name,
            "input": self.input
        }


@dataclass
class ToolResultBlock:
    """工具结果块"""
    tool_use_id: str
    content: str
    is_error: bool = False

    def to_dict(self) -> Dict:
        return {
            "type": "tool_result",
            "tool_use_id": self.tool_use_id,
            "content": self.content,
            "is_error": self.is_error
        }


class PromptCacheManager:
    """
    Prompt Cache共享管理器

    核心原理（借鉴Claude Code buildForkedMessages）:
    1. 克隆父Agent完整消息历史
    2. 为tool_use创建占位结果（让API命中缓存）
    3. 子Agent继承上下文，只传输增量

    应用场景:
    - 并行扫描多个内网主机（共享攻击方法论）
    - Web CTF多路径探索（共享目标架构分析）
    - 攻击链中共享前置发现
    """

    def __init__(self):
        self._cache_stats = {
            "forks_created": 0,
            "cache_hits": 0,
            "tokens_saved": 0
        }

    def build_forked_messages(
        self,
        directive: str,
        parent_messages: List[Message],
        agent_type: str = "explore"
    ) -> List[Message]:
        """
        构建Fork子Agent的消息

        Args:
            directive: 子Agent任务指令
            parent_messages: 父Agent完整消息历史
            agent_type: 子Agent类型

        Returns:
            子Agent的消息列表，可命中Prompt Cache
        """
        if not parent_messages:
            return [self._create_user_message(directive)]

        # 1. 找到最后一个assistant消息
        last_assistant = None
        for msg in reversed(parent_messages):
            if msg.role == "assistant":
                last_assistant = msg
                break

        if not last_assistant:
            return [self._create_user_message(directive)]

        # 2. 克隆assistant消息（关键：保持内容引用以命中缓存）
        forked_assistant = Message(
            role="assistant",
            content=copy.deepcopy(last_assistant.content),
            uuid=str(uuid.uuid4())
        )

        # 3. 为所有tool_use创建占位结果（Prompt Cache关键）
        tool_result_blocks = []
        for block in forked_assistant.content:
            if isinstance(block, dict) and block.get("type") == "tool_use":
                tool_result_blocks.append({
                    "type": "tool_result",
                    "tool_use_id": block["id"],
                    "content": FORK_PLACEHOLDER_RESULT
                })

        # 4. 构建用户消息（包含占位结果 + 新指令）
        user_content = tool_result_blocks + [{
            "type": "text",
            "text": self._format_directive(directive, agent_type)
        }]

        forked_user = Message(
            role="user",
            content=user_content
        )

        self._cache_stats["forks_created"] += 1

        return [forked_assistant, forked_user]

    def fork_parallel_agents(
        self,
        targets: List[str],
        task_template: str,
        parent_messages: List[Message],
        agent_type: str = "explore"
    ) -> List[Dict]:
        """
        并行派发多个Fork子Agent

        Args:
            targets: 目标列表
            task_template: 任务模板，使用 {target} 占位
            parent_messages: 父Agent消息
            agent_type: 子Agent类型

        Returns:
            多个并行Agent任务配置
        """
        tasks = []

        for target in targets:
            directive = task_template.format(target=target)
            forked_messages = self.build_forked_messages(
                directive=directive,
                parent_messages=parent_messages,
                agent_type=agent_type
            )

            tasks.append({
                "agent_type": agent_type,
                "model": "glm-5",  # 使用成本优化模型
                "messages": forked_messages,
                "inherit_cache": True,
                "target": target,
                "is_fork": True
            })

        # 估算节省的Token
        self._cache_stats["tokens_saved"] += self._estimate_saved_tokens(
            parent_messages, len(targets)
        )

        return tasks

    def build_cache_hit_messages(
        self,
        tool_uses: List[ToolUseBlock],
        context_summary: str
    ) -> List[Message]:
        """
        构建可命中缓存的消息

        用于工具调用结果需要保持缓存命中的场景

        Args:
            tool_uses: 工具使用列表
            context_summary: 上下文摘要

        Returns:
            消息列表
        """
        # Assistant消息（包含工具调用）
        assistant_content = [block.to_dict() for block in tool_uses]

        assistant_msg = Message(
            role="assistant",
            content=assistant_content
        )

        # 用户消息（占位结果 + 新指令）
        user_content = []
        for tool_use in tool_uses:
            user_content.append({
                "type": "tool_result",
                "tool_use_id": tool_use.id,
                "content": FORK_PLACEHOLDER_RESULT
            })

        user_content.append({
            "type": "text",
            "text": context_summary
        })

        user_msg = Message(
            role="user",
            content=user_content
        )

        return [assistant_msg, user_msg]

    def _create_user_message(self, text: str) -> Message:
        """创建用户消息"""
        return Message(
            role="user",
            content=[{"type": "text", "text": text}]
        )

    def _format_directive(self, directive: str, agent_type: str) -> str:
        """格式化指令"""
        return f"""
[子任务派发]
类型: {agent_type}
任务: {directive}

请基于共享上下文执行上述任务。
"""

    def _estimate_saved_tokens(
        self,
        messages: List[Message],
        num_forks: int
    ) -> int:
        """估算节省的Token数"""
        if not messages:
            return 0

        # 粗略估算：每条消息平均500 tokens
        base_tokens = len(messages) * 500

        # Fork时只需传输增量，节省 (num_forks - 1) * base_tokens
        return base_tokens * (num_forks - 1)

    def get_cache_stats(self) -> Dict:
        """获取缓存统计"""
        return self._cache_stats.copy()


class ForkSubagentManager:
    """
    Fork子Agent管理器

    封装Fork创建、执行、结果聚合
    """

    def __init__(self, cache_manager: PromptCacheManager = None):
        self.cache_manager = cache_manager or PromptCacheManager()
        self._active_forks: Dict[str, Dict] = {}

    def create_fork(
        self,
        fork_id: str,
        directive: str,
        parent_messages: List[Message],
        agent_type: str = "explore"
    ) -> Dict:
        """
        创建Fork任务

        Args:
            fork_id: Fork标识
            directive: 任务指令
            parent_messages: 父Agent消息
            agent_type: Agent类型

        Returns:
            Fork任务配置
        """
        forked_messages = self.cache_manager.build_forked_messages(
            directive=directive,
            parent_messages=parent_messages,
            agent_type=agent_type
        )

        fork_task = {
            "fork_id": fork_id,
            "agent_type": agent_type,
            "messages": forked_messages,
            "status": "pending",
            "result": None
        }

        self._active_forks[fork_id] = fork_task
        return fork_task

    def create_parallel_forks(
        self,
        targets: List[str],
        task_template: str,
        parent_messages: List[Message],
        agent_type: str = "explore"
    ) -> List[Dict]:
        """
        创建并行Fork任务

        Args:
            targets: 目标列表
            task_template: 任务模板
            parent_messages: 父Agent消息
            agent_type: Agent类型

        Returns:
            并行Fork任务列表
        """
        return self.cache_manager.fork_parallel_agents(
            targets=targets,
            task_template=task_template,
            parent_messages=parent_messages,
            agent_type=agent_type
        )

    def get_fork(self, fork_id: str) -> Optional[Dict]:
        """获取Fork任务"""
        return self._active_forks.get(fork_id)

    def update_fork_result(self, fork_id: str, result: Any):
        """更新Fork结果"""
        if fork_id in self._active_forks:
            self._active_forks[fork_id]["result"] = result
            self._active_forks[fork_id]["status"] = "completed"

    def aggregate_results(self, fork_ids: List[str]) -> Dict:
        """
        聚合多个Fork的结果

        Args:
            fork_ids: Fork ID列表

        Returns:
            聚合结果
        """
        results = []
        errors = []

        for fork_id in fork_ids:
            fork = self._active_forks.get(fork_id)
            if fork:
                if fork["status"] == "completed":
                    results.append(fork["result"])
                elif fork["status"] == "failed":
                    errors.append({
                        "fork_id": fork_id,
                        "error": fork.get("error")
                    })

        return {
            "total": len(fork_ids),
            "completed": len(results),
            "failed": len(errors),
            "results": results,
            "errors": errors
        }

    def cleanup_forks(self, fork_ids: List[str] = None):
        """清理Fork任务"""
        if fork_ids:
            for fork_id in fork_ids:
                self._active_forks.pop(fork_id, None)
        else:
            self._active_forks.clear()


# ============================================
# 便捷函数
# ============================================

_cache_manager: Optional[PromptCacheManager] = None
_fork_manager: Optional[ForkSubagentManager] = None


def get_cache_manager() -> PromptCacheManager:
    """获取缓存管理器单例"""
    global _cache_manager
    if _cache_manager is None:
        _cache_manager = PromptCacheManager()
    return _cache_manager


def get_fork_manager() -> ForkSubagentManager:
    """获取Fork管理器单例"""
    global _fork_manager
    if _fork_manager is None:
        _fork_manager = ForkSubagentManager(get_cache_manager())
    return _fork_manager


def fork_parallel_scan(
    targets: List[str],
    parent_messages: List[Message]
) -> List[Dict]:
    """
    便捷函数：并行Fork扫描任务

    示例:
        tasks = fork_parallel_scan(
            targets=["192.168.1.10", "192.168.1.20"],
            parent_messages=current_messages
        )
    """
    manager = get_fork_manager()
    return manager.create_parallel_forks(
        targets=targets,
        task_template="扫描目标 {target}，发现开放端口和服务",
        parent_messages=parent_messages,
        agent_type="explore"
    )