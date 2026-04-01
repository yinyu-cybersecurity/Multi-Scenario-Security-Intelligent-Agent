# Coordinator调度器
#
# 借鉴Claude Code的多Agent协调机制
# 实现并行派发、结果聚合、Memory同步
#
# 核心职责:
# 1. 并行派发多个Fork子Agent
# 2. Memory系统同步Agent发现
# 3. 结果聚合与冲突解决
# 4. **超时熔断管理（唯一停止条件）**
# 5. 异常检测与处理

from typing import Dict, Any, List, Optional, Callable
from dataclasses import dataclass, field
from enum import Enum
import asyncio
from datetime import datetime
import uuid
import time

from app.agents.base import AgentType, AGENT_REGISTRY
from app.memory.prompt_cache import PromptCacheManager, ForkSubagentManager
from app.memory.agent_memory import AgentMemorySystem
from app.state.selector_store import SelectorStore, get_selector_store
from app.state.state_v3 import (
    CTFStateV3,
    PhaseType,
    create_initial_state,
    get_state_slice_for_agent,
)


# ============================================
# 超时熔断配置
# ============================================

class TaskType(Enum):
    """任务类型"""
    CTF_CHALLENGE = "ctf_challenge"           # CTF 单题目 - 30分钟
    CTF_MULTI_FLAG = "ctf_multi_flag"          # CTF 多flag题目 - 60分钟
    PENETRATION_FULL = "penetration_full"       # 完整渗透（外网打点+内网） - 2小时
    PENETRATION_INTERNAL = "penetration_internal"  # 纯内网渗透（已有入口） - 60分钟
    EXTERNAL_ATTACK = "external_attack"         # 外网打点 - 30分钟
    VULNERABILITY_SCAN = "vuln_scan"           # 漏洞扫描 - 30分钟
    CODE_AUDIT = "code_audit"                  # 代码审计 - 60分钟
    RESEARCH = "research"                      # 安全研究 - 2小时
    OTHER = "other"                            # 其他任务 - 助手决策


# 任务超时配置（秒）
TASK_TIMEOUTS = {
    TaskType.CTF_CHALLENGE: 30 * 60,           # CTF单题: 30 分钟
    TaskType.CTF_MULTI_FLAG: 60 * 60,          # CTF多flag: 60 分钟
    TaskType.PENETRATION_FULL: 120 * 60,       # 完整渗透: 2 小时（外网+内网）
    TaskType.PENETRATION_INTERNAL: 60 * 60,    # 纯内网: 60 分钟
    TaskType.EXTERNAL_ATTACK: 30 * 60,         # 外网打点: 30 分钟
    TaskType.VULNERABILITY_SCAN: 30 * 60,      # 扫描: 30 分钟
    TaskType.CODE_AUDIT: 60 * 60,              # 审计: 60 分钟
    TaskType.RESEARCH: 120 * 60,               # 研究: 2 小时
    TaskType.OTHER: 90 * 60,                   # 其他: 90 分钟
}


@dataclass
class TimeoutState:
    """超时状态"""
    task_type: TaskType
    start_time: float
    timeout_seconds: int
    task_description: str = ""

    @property
    def remaining_seconds(self) -> float:
        """剩余时间（秒）"""
        elapsed = time.time() - self.start_time
        return max(0, self.timeout_seconds - elapsed)

    @property
    def elapsed_seconds(self) -> float:
        """已用时间（秒）"""
        return time.time() - self.start_time

    @property
    def is_timeout(self) -> bool:
        """是否已超时 - 这是唯一停止条件"""
        return self.remaining_seconds <= 0

    @property
    def progress_ratio(self) -> float:
        """进度比例（0.0 ~ 1.0）"""
        return min(1.0, self.elapsed_seconds / self.timeout_seconds)

    def format_remaining(self) -> str:
        """格式化剩余时间"""
        remaining = self.remaining_seconds
        if remaining <= 0:
            return "已超时"

        hours = int(remaining // 3600)
        minutes = int((remaining % 3600) // 60)
        secs = int(remaining % 60)

        if hours > 0:
            return f"{hours}小时{minutes}分{secs}秒"
        elif minutes > 0:
            return f"{minutes}分{secs}秒"
        else:
            return f"{secs}秒"


@dataclass
class ForkTask:
    """Fork任务定义"""
    task_id: str
    agent_type: AgentType
    directive: str
    target: str
    status: str = "pending"  # pending, running, completed, failed
    result: Optional[Dict] = None
    error: Optional[str] = None
    started_at: float = field(default_factory=lambda: datetime.now().timestamp())
    completed_at: Optional[float] = None


@dataclass
class CoordinatorSession:
    """Coordinator会话"""
    session_id: str
    parent_messages: List[Dict]
    fork_tasks: Dict[str, ForkTask] = field(default_factory=dict)
    memory_writes: List[Dict] = field(default_factory=list)
    aggregated_findings: List[Dict] = field(default_factory=list)
    timeout_state: Optional[TimeoutState] = None  # 超时状态


class CoordinatorDispatcher:
    """
    Coordinator调度器

    借鉴Claude Code的Coordinator Agent设计:
    - 并行派发多个Fork子Agent
    - Memory系统同步Agent发现
    - 结果聚合与冲突解决
    - Prompt Cache共享优化

    核心功能:
    1. dispatch_parallel_agents - 并行派发
    2. aggregate_results - 结果聚合
    3. sync_memory_updates - Memory同步
    4. resolve_conflicts - 冲突解决
    """

    def __init__(
        self,
        cache_manager: PromptCacheManager = None,
        memory_system: AgentMemorySystem = None,
        selector_store: SelectorStore = None
    ):
        self.cache_manager = cache_manager or PromptCacheManager()
        self.memory_system = memory_system or AgentMemorySystem()
        self.selector_store = selector_store or get_selector_store()

        self._sessions: Dict[str, CoordinatorSession] = {}
        self._max_concurrent = AGENT_REGISTRY.get(
            AgentType.COORDINATOR
        ).max_concurrent_tasks if AgentType.COORDINATOR in AGENT_REGISTRY else 8

    # =========================================================================
    # 超时熔断管理（核心功能 - 唯一停止条件）
    # =========================================================================

    async def classify_task_with_llm(
        self,
        task_description: str,
        context: Dict = None
    ) -> TaskType:
        """
        使用LLM智能判断任务类型

        完全由AI决定任务类型，考虑：
        - 多flag场景
        - 外网打点+内网渗透组合
        - 任务复杂度

        Args:
            task_description: 任务描述
            context: 额外上下文信息

        Returns:
            任务类型
        """
        from app.llm_client import get_llm_client

        prompt = f"""你是一个渗透测试任务分类器。根据任务描述，判断任务类型。

任务描述: {task_description}

可选类型:
1. ctf_challenge - CTF单题目，单个flag
2. ctf_multi_flag - CTF多flag题目（如part1/part2、多阶段）
3. penetration_full - 完整渗透（外网打点+内网渗透）
4. penetration_internal - 纯内网渗透（已有入口）
5. external_attack - 仅外网打点
6. vuln_scan - 漏洞扫描
7. code_audit - 代码审计
8. research - 安全研究
9. other - 其他

请只返回类型名称（如 penetration_full），不要解释。"""

        try:
            llm = get_llm_client()
            response = await llm.ainvoke(prompt, model="glm-5", max_tokens=30)

            # 解析响应
            result = response.strip().lower()

            # 映射到TaskType
            type_mapping = {
                "ctf_challenge": TaskType.CTF_CHALLENGE,
                "ctf_multi_flag": TaskType.CTF_MULTI_FLAG,
                "penetration_full": TaskType.PENETRATION_FULL,
                "penetration_internal": TaskType.PENETRATION_INTERNAL,
                "external_attack": TaskType.EXTERNAL_ATTACK,
                "vuln_scan": TaskType.VULNERABILITY_SCAN,
                "code_audit": TaskType.CODE_AUDIT,
                "research": TaskType.RESEARCH,
                "other": TaskType.OTHER,
            }

            for key, task_type in type_mapping.items():
                if key in result:
                    print(f"🤖 LLM分类: {task_type.value}")
                    return task_type

            # LLM返回无法识别，默认OTHER
            print(f"⚠️ LLM返回无法识别: {result}")
            return TaskType.OTHER

        except Exception as e:
            print(f"⚠️ LLM分类失败: {e}")
            return TaskType.OTHER

    async def start_timeout(
        self,
        session_id: str,
        task_description: str,
        task_type: Optional[TaskType] = None,
        timeout_override: Optional[int] = None
    ) -> TimeoutState:
        """
        开始任务超时计时

        这是唯一能启动超时的方法！

        Args:
            session_id: 会话ID
            task_description: 任务描述
            task_type: 任务类型（可选，默认用LLM自动识别）
            timeout_override: 自定义超时时间（秒）

        Returns:
            超时状态
        """
        session = self._sessions.get(session_id)
        if not session:
            raise ValueError(f"Session {session_id} not found")

        # LLM智能分类任务类型
        if not task_type:
            task_type = await self.classify_task_with_llm(task_description)

        # 获取超时时间
        timeout = timeout_override or TASK_TIMEOUTS.get(task_type, 90 * 60)

        # 创建超时状态
        session.timeout_state = TimeoutState(
            task_type=task_type,
            start_time=time.time(),
            timeout_seconds=timeout,
            task_description=task_description
        )

        print(f"\n⏱️ 任务开始")
        print(f"   类型: {task_type.value}")
        print(f"   描述: {task_description[:60]}...")
        print(f"   超时: {timeout // 60} 分钟")
        print(f"   截止: {datetime.fromtimestamp(session.timeout_state.start_time + timeout).strftime('%H:%M:%S')}")

        return session.timeout_state

    def should_stop(self, session_id: str) -> bool:
        """
        判断是否应该停止

        这是唯一停止条件！

        Args:
            session_id: 会话ID

        Returns:
            是否应该停止
        """
        session = self._sessions.get(session_id)
        if not session or not session.timeout_state:
            return False

        if session.timeout_state.is_timeout:
            print(f"\n⏰ 任务超时！已运行 {session.timeout_state.elapsed_seconds:.0f} 秒")
            return True

        return False

    def get_remaining_time(self, session_id: str) -> float:
        """获取剩余时间（秒）"""
        session = self._sessions.get(session_id)
        if not session or not session.timeout_state:
            return float('inf')
        return session.timeout_state.remaining_seconds

    def get_timeout_status(self, session_id: str) -> Dict[str, Any]:
        """获取超时状态"""
        session = self._sessions.get(session_id)
        if not session or not session.timeout_state:
            return {"status": "no_timeout"}

        ts = session.timeout_state
        return {
            "status": "timeout" if ts.is_timeout else "running",
            "task_type": ts.task_type.value,
            "elapsed_seconds": ts.elapsed_seconds,
            "remaining_seconds": ts.remaining_seconds,
            "remaining_formatted": ts.format_remaining(),
            "progress_ratio": ts.progress_ratio,
            "is_timeout": ts.is_timeout
        }

    def check_time_warning(self, session_id: str, threshold: float = 0.8) -> bool:
        """
        检查时间警告（当进度超过阈值）

        Args:
            session_id: 会话ID
            threshold: 阈值比例（默认 0.8 = 80%）

        Returns:
            是否达到警告阈值
        """
        session = self._sessions.get(session_id)
        if not session or not session.timeout_state:
            return False

        if session.timeout_state.progress_ratio >= threshold:
            remaining = session.timeout_state.format_remaining()
            print(f"⚠️ 时间警告: 已用 {threshold*100:.0f}%，剩余 {remaining}")
            return True

        return False

    # =========================================================================
    # 会话管理
    # =========================================================================

    async def create_session(
        self,
        parent_messages: List[Dict],
        task_description: str = "",
        task_type: Optional[TaskType] = None,
        timeout_override: Optional[int] = None
    ) -> str:
        """
        创建Coordinator会话

        Args:
            parent_messages: 父Agent消息历史
            task_description: 任务描述（用于自动分类超时）
            task_type: 任务类型（可选）
            timeout_override: 自定义超时时间（秒）

        Returns:
            session_id
        """
        session_id = str(uuid.uuid4())

        session = CoordinatorSession(
            session_id=session_id,
            parent_messages=parent_messages
        )

        self._sessions[session_id] = session

        # 如果提供了任务描述，自动启动超时计时
        if task_description:
            await self.start_timeout(session_id, task_description, task_type, timeout_override)

        return session_id

    async def dispatch_parallel_agents(
        self,
        session_id: str,
        targets: List[str],
        task_template: str,
        agent_type: AgentType = AgentType.EXPLORE,
        model: str = "glm-5"
    ) -> List[ForkTask]:
        """
        并行派发多个Fork子Agent

        借鉴Claude Code的并行是超能力原则:
        - 独立任务同时派发
        - Prompt Cache共享上下文
        - 节省Token传输开销

        Args:
            session_id: Coordinator会话ID
            targets: 目标列表
            task_template: 任务模板（使用{target}占位）
            agent_type: 子Agent类型
            model: 模型选择

        Returns:
            ForkTask列表
        """
        session = self._sessions.get(session_id)
        if not session:
            raise ValueError(f"Session {session_id} not found")

        # 使用Prompt Cache管理器创建并行Fork
        fork_manager = ForkSubagentManager(self.cache_manager)

        fork_tasks = fork_manager.create_parallel_forks(
            targets=targets,
            task_template=task_template,
            parent_messages=session.parent_messages,
            agent_type=agent_type
        )

        # 创建ForkTask记录
        tasks = []
        for fork_task_config in fork_tasks:
            task_id = str(uuid.uuid4())

            fork_task = ForkTask(
                task_id=task_id,
                agent_type=agent_type,
                directive=fork_task_config.get("directive", ""),
                target=fork_task_config.get("target", ""),
                status="pending"
            )

            session.fork_tasks[task_id] = fork_task
            tasks.append(fork_task)

        return tasks

    async def execute_fork_task(
        self,
        session_id: str,
        task_id: str,
        execute_handler: Callable
    ) -> Dict:
        """
        执行单个Fork任务

        Args:
            session_id: 会话ID
            task_id: 任务ID
            execute_handler: 执行Handler（调用Agent的函数）

        Returns:
            执行结果
        """
        session = self._sessions.get(session_id)
        if not session:
            return {"success": False, "error": "Session not found"}

        fork_task = session.fork_tasks.get(task_id)
        if not fork_task:
            return {"success": False, "error": "Task not found"}

        # 更新状态
        fork_task.status = "running"

        try:
            # 获取Fork消息（带Prompt Cache）
            fork_messages = self.cache_manager.build_forked_messages(
                directive=fork_task.directive,
                parent_messages=session.parent_messages,
                agent_type=fork_task.agent_type
            )

            # 执行Agent
            result = await execute_handler(
                agent_type=fork_task.agent_type,
                messages=fork_messages,
                target=fork_task.target
            )

            # 更新任务状态
            fork_task.status = "completed"
            fork_task.result = result
            fork_task.completed_at = datetime.now().timestamp()

            # 写入Memory
            await self._write_fork_result_to_memory(
                session_id,
                fork_task,
                result
            )

            return {"success": True, "result": result}

        except Exception as e:
            fork_task.status = "failed"
            fork_task.error = str(e)
            fork_task.completed_at = datetime.now().timestamp()

            return {"success": False, "error": str(e)}

    async def execute_all_fork_tasks(
        self,
        session_id: str,
        execute_handler: Callable,
        max_concurrent: int = None
    ) -> Dict:
        """
        并行执行所有Fork任务

        借鉴Claude Code的并行执行机制:
        - 使用asyncio.gather并行
        - 控制并发数量（Semaphore）
        - 独立任务互不阻塞
        - **超时熔断检查（唯一停止条件）**

        Args:
            session_id: 会话ID
            execute_handler: 执行Handler
            max_concurrent: 最大并发数

        Returns:
            聚合结果
        """
        session = self._sessions.get(session_id)
        if not session:
            return {"success": False, "error": "Session not found"}

        # 检查是否已超时
        if self.should_stop(session_id):
            return self.build_timeout_result(session_id)

        # 确定并发数
        concurrent_limit = max_concurrent or self._max_concurrent

        # 创建并发控制
        semaphore = asyncio.Semaphore(concurrent_limit)

        # 执行函数（带并发控制和超时检查）
        async def execute_with_limit(task_id: str):
            # 在每次执行前检查超时
            if self.should_stop(session_id):
                return {"success": False, "error": "Timeout", "task_id": task_id}

            async with semaphore:
                result = await self.execute_fork_task(
                    session_id,
                    task_id,
                    execute_handler
                )

                # 执行后检查超时
                if self.should_stop(session_id):
                    return {"success": False, "error": "Timeout", "task_id": task_id}

                return result

        # 获取所有待执行任务
        pending_tasks = [
            task_id for task_id, task in session.fork_tasks.items()
            if task.status == "pending"
        ]

        # 并行执行
        results = await asyncio.gather(
            *[execute_with_limit(task_id) for task_id in pending_tasks],
            return_exceptions=True
        )

        # 最终超时检查
        if self.should_stop(session_id):
            return self.build_timeout_result(session_id)

        # 聚合结果
        return await self.aggregate_results(session_id)

    async def aggregate_results(
        self,
        session_id: str
    ) -> Dict:
        """
        聚合所有Fork结果

        借鉴Claude Code的结果聚合机制:
        - 合并发现
        - 解决冲突
        - 提取关键信息

        Args:
            session_id: 会话ID

        Returns:
            聚合结果
        """
        session = self._sessions.get(session_id)
        if not session:
            return {"success": False, "error": "Session not found"}

        completed_tasks = [
            task for task in session.fork_tasks.values()
            if task.status == "completed"
        ]

        failed_tasks = [
            task for task in session.fork_tasks.values()
            if task.status == "failed"
        ]

        # 提取发现
        all_findings = []
        for task in completed_tasks:
            if task.result and "findings" in task.result:
                all_findings.extend(task.result["findings"])

        # 去重和合并
        unique_findings = self._deduplicate_findings(all_findings)

        # 解决冲突
        resolved_findings = await self._resolve_conflicts(unique_findings)

        # 更新会话
        session.aggregated_findings = resolved_findings

        # 获取缓存统计
        cache_stats = self.cache_manager.get_cache_stats()

        return {
            "success": True,
            "total_tasks": len(session.fork_tasks),
            "completed": len(completed_tasks),
            "failed": len(failed_tasks),
            "findings": resolved_findings,
            "cache_stats": cache_stats,
            "memory_updates": session.memory_writes
        }

    async def sync_memory_updates(
        self,
        session_id: str,
        target: str
    ) -> Dict:
        """
        同步Memory更新

        将所有Fork Agent的发现写入Memory系统

        Args:
            session_id: 会话ID
            target: 目标标识

        Returns:
            同步结果
        """
        session = self._sessions.get(session_id)
        if not session:
            return {"success": False, "error": "Session not found"}

        # 写入聚合发现
        for finding in session.aggregated_findings:
            topic = finding.get("topic", "findings")
            data = finding.get("data", {})

            # 根据发现类型选择写入方式
            finding_type = finding.get("type", "general")

            if finding_type == "endpoint":
                await self.memory_system.write_finding(
                    AgentType.EXPLORE,
                    target,
                    "endpoints",
                    data
                )
            elif finding_type == "vuln":
                await self.memory_system.write_finding(
                    AgentType.EXPLORE,
                    target,
                    "vulns",
                    data
                )
            elif finding_type == "credential":
                await self.memory_system.write_finding(
                    AgentType.ATTACK,
                    target,
                    "credentials",
                    data
                )
            elif finding_type == "flag":
                await self.memory_system.write_finding(
                    AgentType.VERIFY,
                    target,
                    "flags",
                    data
                )
            else:
                await self.memory_system.write_finding(
                    AgentType.COORDINATOR,
                    target,
                    topic,
                    data
                )

        return {
            "success": True,
            "synced_count": len(session.aggregated_findings)
        }

    async def _write_fork_result_to_memory(
        self,
        session_id: str,
        fork_task: ForkTask,
        result: Dict
    ):
        """将Fork结果写入Memory"""
        session = self._sessions.get(session_id)
        if not session:
            return

        # 记录Memory写入
        memory_write = {
            "task_id": fork_task.task_id,
            "agent_type": fork_task.agent_type,
            "target": fork_task.target,
            "result": result,
            "timestamp": datetime.now().timestamp()
        }

        session.memory_writes.append(memory_write)

    def _deduplicate_findings(
        self,
        findings: List[Dict]
    ) -> List[Dict]:
        """
        发现去重

        基于内容哈希去重
        """
        unique = []
        seen_hashes = set()

        for finding in findings:
            # 计算内容哈希
            import json
            content_hash = json.dumps(finding, sort_keys=True)

            if content_hash not in seen_hashes:
                seen_hashes.add(content_hash)
                unique.append(finding)

        return unique

    async def _resolve_conflicts(
        self,
        findings: List[Dict]
    ) -> List[Dict]:
        """
        冲突解决

        处理不同Agent的矛盾发现
        """
        # 简化实现：基于置信度选择
        resolved = []

        # 按主题分组
        grouped = {}
        for finding in findings:
            topic = finding.get("topic", "general")
            if topic not in grouped:
                grouped[topic] = []
            grouped[topic].append(finding)

        # 每个主题选择高置信度发现
        for topic, topic_findings in grouped.items():
            # 按置信度排序
            sorted_findings = sorted(
                topic_findings,
                key=lambda f: f.get("confidence", 0),
                reverse=True
            )

            # 选择高置信度
            resolved.extend(sorted_findings[:3])  # 每个主题最多3个

        return resolved

    def get_session_stats(self, session_id: str) -> Dict:
        """获取会话统计"""
        session = self._sessions.get(session_id)
        if not session:
            return {}

        stats = {
            "session_id": session_id,
            "total_tasks": len(session.fork_tasks),
            "completed": sum(1 for t in session.fork_tasks.values() if t.status == "completed"),
            "running": sum(1 for t in session.fork_tasks.values() if t.status == "running"),
            "failed": sum(1 for t in session.fork_tasks.values() if t.status == "failed"),
            "pending": sum(1 for t in session.fork_tasks.values() if t.status == "pending"),
            "memory_writes": len(session.memory_writes),
            "aggregated_findings": len(session.aggregated_findings),
        }

        # 添加超时状态
        if session.timeout_state:
            stats["timeout"] = self.get_timeout_status(session_id)

        return stats

    def build_timeout_result(self, session_id: str) -> Dict:
        """
        构建超时结果

        当任务超时时，返回此结果作为最终输出

        Args:
            session_id: 会话ID

        Returns:
            超时结果字典
        """
        session = self._sessions.get(session_id)
        if not session:
            return {"success": False, "error": "Session not found", "reason": "timeout"}

        ts = session.timeout_state

        return {
            "success": False,
            "reason": "timeout",
            "message": f"任务超时，已运行 {ts.elapsed_seconds:.0f} 秒",
            "task_type": ts.task_type.value if ts else "unknown",
            "elapsed_seconds": ts.elapsed_seconds if ts else 0,
            "findings": session.aggregated_findings,
            "completed_tasks": sum(1 for t in session.fork_tasks.values() if t.status == "completed"),
            "total_tasks": len(session.fork_tasks)
        }

    async def monitor_agent_execution(
        self,
        session_id: str,
        agent_id: str,
        check_interval: float = 1.0
    ) -> Dict:
        """
        监控Agent执行状态

        实现实时状态监控，检测异常情况

        Args:
            session_id: 会话ID
            agent_id: Agent ID
            check_interval: 检查间隔（秒）

        Returns:
            监控结果
        """
        session = self._sessions.get(session_id)
        if not session:
            return {"success": False, "error": "Session not found"}

        # 监控指标
        metrics = {
            "start_time": datetime.now().timestamp(),
            "iterations": 0,
            "tool_calls": 0,
            "errors": 0,
            "findings": 0,
        }

        # 异常检测阈值
        thresholds = {
            "max_iterations": 100,
            "max_errors": 5,
            "max_duration": 3600,  # 1小时
            "stuck_threshold": 60,  # 60秒无进展视为卡住
        }

        last_progress_time = datetime.now().timestamp()

        while True:
            await asyncio.sleep(check_interval)

            # 检查任务状态
            task = session.fork_tasks.get(agent_id)
            if not task:
                break

            if task.status in ["completed", "failed"]:
                break

            # 更新指标
            metrics["iterations"] += 1

            # 检测异常
            anomalies = []

            # 1. 无限循环检测
            if metrics["iterations"] >= thresholds["max_iterations"]:
                anomalies.append({
                    "type": "infinite_loop",
                    "message": f"超过最大迭代次数 {thresholds['max_iterations']}"
                })

            # 2. 错误率检测
            if metrics["errors"] >= thresholds["max_errors"]:
                anomalies.append({
                    "type": "high_error_rate",
                    "message": f"错误次数过多: {metrics['errors']}"
                })

            # 3. 执行时间检测
            duration = datetime.now().timestamp() - metrics["start_time"]
            if duration >= thresholds["max_duration"]:
                anomalies.append({
                    "type": "timeout",
                    "message": f"执行时间超过限制: {duration:.1f}秒"
                })

            # 4. 进展检测
            current_findings = len(session.aggregated_findings)
            if current_findings > metrics["findings"]:
                metrics["findings"] = current_findings
                last_progress_time = datetime.now().timestamp()
            else:
                stuck_duration = datetime.now().timestamp() - last_progress_time
                if stuck_duration >= thresholds["stuck_threshold"]:
                    anomalies.append({
                        "type": "stuck",
                        "message": f"无进展时间过长: {stuck_duration:.1f}秒"
                    })

            # 发现异常时中断
            if anomalies:
                return {
                    "success": False,
                    "anomalies": anomalies,
                    "metrics": metrics,
                    "action": "terminate"
                }

        # 正常结束
        metrics["end_time"] = datetime.now().timestamp()
        metrics["duration"] = metrics["end_time"] - metrics["start_time"]

        return {
            "success": True,
            "metrics": metrics,
            "action": "completed"
        }

    async def detect_anomalies(self, session_id: str) -> List[Dict]:
        """
        检测会话异常

        扫描整个会话，发现潜在问题

        Args:
            session_id: 会话ID

        Returns:
            异常列表
        """
        session = self._sessions.get(session_id)
        if not session:
            return [{"type": "session_not_found"}]

        anomalies = []

        # 1. 任务失败率
        total = len(session.fork_tasks)
        failed = sum(1 for t in session.fork_tasks.values() if t.status == "failed")
        if total > 0 and failed / total > 0.5:
            anomalies.append({
                "type": "high_failure_rate",
                "severity": "high",
                "message": f"任务失败率过高: {failed}/{total} ({failed/total*100:.1f}%)"
            })

        # 2. 资源泄漏检测
        running = sum(1 for t in session.fork_tasks.values() if t.status == "running")
        if running > self._max_concurrent:
            anomalies.append({
                "type": "resource_leak",
                "severity": "medium",
                "message": f"运行任务数超过并发限制: {running} > {self._max_concurrent}"
            })

        # 3. Memory写入冲突
        if len(session.memory_writes) > 100:
            anomalies.append({
                "type": "memory_bloat",
                "severity": "low",
                "message": f"Memory写入过多: {len(session.memory_writes)}"
            })

        # 4. 结果冲突
        finding_topics = {}
        for finding in session.aggregated_findings:
            topic = finding.get("topic", "general")
            if topic not in finding_topics:
                finding_topics[topic] = []
            finding_topics[topic].append(finding)

        for topic, findings in finding_topics.items():
            if len(findings) > 10:
                anomalies.append({
                    "type": "finding_flood",
                    "severity": "low",
                    "message": f"主题 '{topic}' 发现过多: {len(findings)}"
                })

        return anomalies

    def cleanup_session(self, session_id: str):
        """清理会话"""
        self._sessions.pop(session_id, None)


# ============================================
# 便捷函数
# ============================================

_dispatcher: Optional[CoordinatorDispatcher] = None


def get_coordinator_dispatcher() -> CoordinatorDispatcher:
    """获取Coordinator调度器单例"""
    global _dispatcher
    if _dispatcher is None:
        _dispatcher = CoordinatorDispatcher()
    return _dispatcher


async def run_autonomous_attack_coordinated(
    target: str,
    objective: str = "",
    max_iterations: int = 50,
    enable_monitoring: bool = True
) -> Dict:
    """
    使用AutonomousAgent执行自主攻击

    简化入口：输入目标地址，自动完成攻击

    集成功能:
    - 状态监控
    - 异常检测
    - Memory同步

    Args:
        target: 目标地址
        objective: 攻击目标描述
        max_iterations: 最大迭代次数
        enable_monitoring: 是否启用监控

    Returns:
        攻击结果
    """
    from app.agents.autonomous_agent import AutonomousAgent

    agent = AutonomousAgent(
        target=target,
        objective=objective,
        max_iterations=max_iterations
    )

    # 创建监控任务
    monitor_task = None
    if enable_monitoring:
        # 获取或创建dispatcher用于监控
        dispatcher = get_coordinator_dispatcher()
        session_id = await dispatcher.create_session([])

        # 异步启动监控
        async def monitor():
            return await dispatcher.monitor_agent_execution(
                session_id,
                "autonomous_agent",
                check_interval=2.0
            )

        monitor_task = asyncio.create_task(monitor())

    try:
        # 执行攻击
        result = await agent.run()

        # 同步到Memory
        if result.get("success"):
            memory = AgentMemorySystem()
            await memory.write_finding(
                AgentType.COORDINATOR,
                target,
                "attack_result",
                result
            )

        # 检查监控结果
        if monitor_task:
            try:
                monitor_result = await asyncio.wait_for(
                    monitor_task,
                    timeout=1.0
                )
                result["monitoring"] = monitor_result
            except asyncio.TimeoutError:
                pass

        return result

    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "target": target
        }
    finally:
        # 清理监控任务
        if monitor_task and not monitor_task.done():
            monitor_task.cancel()


async def parallel_scan_targets(
    targets: List[str],
    parent_messages: List[Dict],
    execute_handler: Callable,
    model: str = "glm-5"
) -> Dict:
    """
    便捷函数：并行扫描多个目标

    示例:
        results = await parallel_scan_targets(
            targets=["192.168.1.10", "192.168.1.20", "192.168.1.30"],
            parent_messages=current_messages,
            execute_handler=run_explore_agent
        )

    Args:
        targets: 目标列表
        parent_messages: 父Agent消息
        execute_handler: Agent执行函数
        model: 模型选择

    Returns:
        聚合结果
    """
    dispatcher = get_coordinator_dispatcher()

    # 创建会话
    session_id = await dispatcher.create_session(parent_messages)

    # 派发并行任务
    tasks = await dispatcher.dispatch_parallel_agents(
        session_id=session_id,
        targets=targets,
        task_template="扫描目标 {target}，发现开放端口和服务",
        agent_type=AgentType.EXPLORE,
        model=model
    )

    # 并行执行
    results = await dispatcher.execute_all_fork_tasks(
        session_id=session_id,
        execute_handler=execute_handler
    )

    # 同步Memory
    if results.get("success"):
        await dispatcher.sync_memory_updates(
            session_id=session_id,
            target="multi_target"
        )

    # 清理
    dispatcher.cleanup_session(session_id)

    return results