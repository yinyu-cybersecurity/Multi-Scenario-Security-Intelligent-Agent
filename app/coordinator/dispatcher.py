# Coordinator调度器
#
# 借鉴Claude Code的多Agent协调机制
# 实现并行派发、结果聚合、Memory同步

from typing import Dict, Any, List, Optional, Callable
from dataclasses import dataclass, field
import asyncio
from datetime import datetime
import uuid

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

    async def create_session(
        self,
        parent_messages: List[Dict]
    ) -> str:
        """
        创建Coordinator会话

        Args:
            parent_messages: 父Agent消息历史

        Returns:
            session_id
        """
        session_id = str(uuid.uuid4())

        session = CoordinatorSession(
            session_id=session_id,
            parent_messages=parent_messages
        )

        self._sessions[session_id] = session

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

        # 确定并发数
        concurrent_limit = max_concurrent or self._max_concurrent

        # 创建并发控制
        semaphore = asyncio.Semaphore(concurrent_limit)

        # 执行函数（带并发控制）
        async def execute_with_limit(task_id: str):
            async with semaphore:
                return await self.execute_fork_task(
                    session_id,
                    task_id,
                    execute_handler
                )

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

        return {
            "session_id": session_id,
            "total_tasks": len(session.fork_tasks),
            "completed": sum(1 for t in session.fork_tasks.values() if t.status == "completed"),
            "running": sum(1 for t in session.fork_tasks.values() if t.status == "running"),
            "failed": sum(1 for t in session.fork_tasks.values() if t.status == "failed"),
            "pending": sum(1 for t in session.fork_tasks.values() if t.status == "pending"),
            "memory_writes": len(session.memory_writes),
            "aggregated_findings": len(session.aggregated_findings),
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