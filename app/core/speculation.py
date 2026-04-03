"""
推测执行系统 - Speculation Executor

Claude Code的推测执行设计:
- 在用户确认前预先执行可能的操作
- 缓存执行结果，用户确认后立即返回
- 失败的推测静默丢弃
- 节省用户等待时间

典型场景:
1. AI准备修改文件时，推测用户可能接受，提前读取和分析
2. AI准备运行测试时，推测用户可能确认，提前准备测试环境
3. AI准备执行工具时，推测可能的参数组合，提前验证
"""

import asyncio
from typing import Dict, Any, List, Optional, Callable
from dataclasses import dataclass, field
from enum import Enum
import time
import hashlib


class SpeculationStatus(Enum):
    """推测状态"""
    PENDING = "pending"          # 等待确认
    RUNNING = "running"          # 正在执行
    COMPLETED = "completed"      # 已完成
    FAILED = "failed"           # 执行失败
    CANCELLED = "cancelled"      # 已取消


@dataclass
class SpeculativeResult:
    """推测执行结果"""
    speculation_id: str
    action: Dict[str, Any]
    status: SpeculationStatus
    result: Optional[Any] = None
    error: Optional[str] = None
    start_time: float = field(default_factory=time.time)
    end_time: Optional[float] = None
    cached: bool = False  # 是否命中缓存

    @property
    def duration(self) -> float:
        if self.end_time:
            return self.end_time - self.start_time
        return time.time() - self.start_time


class SpeculationExecutor:
    """
    推测执行器

    Claude Code的Speculation机制实现:
    1. 接受多个可能的下一步操作
    2. 并发执行所有推测
    3. 缓存成功的结果
    4. 用户确认后立即返回缓存结果
    5. 失败的推测静默丢弃

    使用场景:
    ```python
    # AI决定下一步可能的操作
    possible_actions = [
        {"type": "scan", "tool": "nmap", "params": {...}},
        {"type": "exploit", "tool": "sqlmap", "params": {...}},
    ]

    # 推测执行
    speculator = SpeculationExecutor()
    spec_id = await speculator.speculate(possible_actions)

    # 用户确认后获取结果
    if user_confirmed:
        result = await speculator.get_result(spec_id, action_id)
    ```
    """

    def __init__(self, max_concurrent: int = 3):
        """
        初始化推测执行器

        Args:
            max_concurrent: 最大并发推测数
        """
        self.max_concurrent = max_concurrent
        self._speculations: Dict[str, SpeculativeResult] = {}
        self._cache: Dict[str, Any] = {}  # 结果缓存
        self._semaphore = asyncio.Semaphore(max_concurrent)

    async def speculate(
        self,
        possible_actions: List[Dict[str, Any]],
        executor: Callable,
        context: Dict[str, Any] = None
    ) -> str:
        """
        推测执行多个可能的操作

        Claude Code模式:
        1. 并发启动所有推测
        2. 成功的结果缓存
        3. 失败的静默丢弃
        4. 返回推测ID供后续查询

        Args:
            possible_actions: 可能的操作列表
            executor: 执行函数 (async Callable)
            context: 执行上下文

        Returns:
            推测ID
        """
        # 生成推测ID
        spec_id = self._generate_speculation_id(possible_actions)

        # 如果已经在缓存中，直接返回
        if spec_id in self._speculations:
            existing = self._speculations[spec_id]
            if existing.status == SpeculationStatus.COMPLETED:
                existing.cached = True
                return spec_id

        # 创建推测记录
        self._speculations[spec_id] = SpeculativeResult(
            speculation_id=spec_id,
            action={"actions": possible_actions},
            status=SpeculationStatus.PENDING
        )

        # 并发执行所有推测
        asyncio.create_task(
            self._execute_speculations(spec_id, possible_actions, executor, context)
        )

        return spec_id

    async def _execute_speculations(
        self,
        spec_id: str,
        actions: List[Dict[str, Any]],
        executor: Callable,
        context: Dict[str, Any]
    ):
        """
        并发执行推测

        Args:
            spec_id: 推测ID
            actions: 操作列表
            executor: 执行函数
            context: 执行上下文
        """
        speculation = self._speculations.get(spec_id)
        if not speculation:
            return

        speculation.status = SpeculationStatus.RUNNING

        # 并发执行所有操作
        tasks = []
        for action in actions:
            task = asyncio.create_task(
                self._execute_single(spec_id, action, executor, context)
            )
            tasks.append(task)

        # 等待所有推测完成
        try:
            results = await asyncio.gather(*tasks, return_exceptions=True)

            # 收集成功结果
            successful_results = {}
            for i, result in enumerate(results):
                action_id = self._get_action_id(actions[i])
                if isinstance(result, Exception):
                    # 失败的推测，记录但不中断
                    speculation.error = str(result)
                else:
                    successful_results[action_id] = result

            # 缓存成功结果
            if successful_results:
                self._cache[spec_id] = successful_results
                speculation.status = SpeculationStatus.COMPLETED
                speculation.result = successful_results
            else:
                speculation.status = SpeculationStatus.FAILED

        except Exception as e:
            speculation.status = SpeculationStatus.FAILED
            speculation.error = str(e)

        finally:
            speculation.end_time = time.time()

    async def _execute_single(
        self,
        spec_id: str,
        action: Dict[str, Any],
        executor: Callable,
        context: Dict[str, Any]
    ) -> Any:
        """
        执行单个推测

        Args:
            spec_id: 推测ID
            action: 操作定义
            executor: 执行函数
            context: 执行上下文

        Returns:
            执行结果
        """
        async with self._semaphore:
            try:
                result = await executor(action, context)
                return result
            except Exception as e:
                # 推测失败，静默处理
                print(f"[Speculation] Action {action.get('type')} failed: {e}")
                raise

    async def get_result(
        self,
        spec_id: str,
        action_id: str = None,
        wait: bool = True,
        timeout: float = 30.0
    ) -> Optional[Any]:
        """
        获取推测结果

        Claude Code模式:
        1. 如果推测完成，返回缓存结果
        2. 如果还在执行，可选择等待或返回None
        3. 如果失败，返回None

        Args:
            spec_id: 推测ID
            action_id: 操作ID（可选，不指定则返回所有结果）
            wait: 是否等待完成
            timeout: 等待超时

        Returns:
            执行结果或None
        """
        speculation = self._speculations.get(spec_id)
        if not speculation:
            return None

        # 如果还在执行，等待
        if speculation.status == SpeculationStatus.RUNNING:
            if wait:
                start = time.time()
                while speculation.status == SpeculationStatus.RUNNING:
                    if time.time() - start > timeout:
                        return None
                    await asyncio.sleep(0.1)
            else:
                return None

        # 返回结果
        if speculation.status == SpeculationStatus.COMPLETED:
            if action_id:
                return speculation.result.get(action_id)
            else:
                return speculation.result

        return None

    async def cancel(self, spec_id: str):
        """
        取消推测

        Args:
            spec_id: 推测ID
        """
        speculation = self._speculations.get(spec_id)
        if speculation:
            speculation.status = SpeculationStatus.CANCELLED
            speculation.end_time = time.time()

    def get_status(self, spec_id: str) -> Optional[SpeculationStatus]:
        """获取推测状态"""
        speculation = self._speculations.get(spec_id)
        return speculation.status if speculation else None

    def clear_cache(self):
        """清空缓存"""
        self._cache.clear()
        self._speculations.clear()

    def _generate_speculation_id(self, actions: List[Dict]) -> str:
        """生成推测ID"""
        # 基于操作内容生成唯一ID
        content = str(sorted([str(a) for a in actions]))
        hash_val = hashlib.md5(content.encode()).hexdigest()[:8]
        return f"spec_{hash_val}_{int(time.time())}"

    def _get_action_id(self, action: Dict) -> str:
        """获取操作ID"""
        return action.get("id", f"{action.get('type', 'unknown')}_{action.get('tool', 'unknown')}")


# 全局推测执行器
_speculator: Optional[SpeculationExecutor] = None


def get_speculation_executor() -> SpeculationExecutor:
    """获取全局推测执行器"""
    global _speculator
    if _speculator is None:
        _speculator = SpeculationExecutor()
    return _speculator


__all__ = [
    "SpeculationExecutor",
    "SpeculationStatus",
    "SpeculativeResult",
    "get_speculation_executor",
]