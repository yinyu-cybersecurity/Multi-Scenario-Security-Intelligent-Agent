# app/core/time_manager.py

"""
时间管理器 - 唯一熔断条件

设计原则:
1. 超时是唯一硬性停止条件
2. 不同任务类型有不同超时时间
3. AI动态规划任务时间分配
4. 时间信息提供给AI让其自主决策
"""

from dataclasses import dataclass
from enum import Enum
from typing import Optional, Dict
import time


class TaskType(Enum):
    """任务类型 - 对应不同超时时间"""
    CTF_SINGLE_FLAG = "ctf_single"        # CTF单题目 - 30分钟
    CTF_MULTI_FLAG = "ctf_multi"          # CTF多flag - 60分钟
    EXTERNAL_ATTACK = "external_attack"   # 外网打点 - 60分钟
    INTERNAL_PENETRATION = "internal"     # 内网渗透 - 120分钟
    FULL_PENETRATION = "full_pentest"     # 外网+内网 - 180分钟
    CODE_AUDIT = "code_audit"             # 代码审计 - 60分钟
    RESEARCH = "research"                 # 安全研究 - 120分钟


# 时间配置（秒）- 只有总超时，AI自主分配
TIMEOUT_CONFIGS: Dict[TaskType, int] = {
    TaskType.CTF_SINGLE_FLAG: 30 * 60,       # 30分钟
    TaskType.CTF_MULTI_FLAG: 60 * 60,        # 60分钟
    TaskType.EXTERNAL_ATTACK: 60 * 60,       # 60分钟
    TaskType.INTERNAL_PENETRATION: 120 * 60, # 120分钟
    TaskType.FULL_PENETRATION: 180 * 60,     # 180分钟（外网+内网）
    TaskType.CODE_AUDIT: 60 * 60,            # 60分钟
    TaskType.RESEARCH: 120 * 60,             # 120分钟
}


@dataclass
class TimeBudget:
    """时间预算"""
    total_seconds: int
    start_time: float
    task_type: TaskType

    @property
    def elapsed_seconds(self) -> float:
        return time.time() - self.start_time

    @property
    def remaining_seconds(self) -> float:
        return max(0, self.total_seconds - self.elapsed_seconds)

    @property
    def progress_ratio(self) -> float:
        return min(1.0, self.elapsed_seconds / self.total_seconds)

    @property
    def is_timeout(self) -> bool:
        """唯一熔断条件"""
        return self.remaining_seconds <= 0

    def get_status_prompt(self) -> str:
        """生成时间状态提示给AI"""
        remaining = self.remaining_seconds
        progress = self.progress_ratio * 100

        if remaining <= 0:
            return "警告: **TIMEOUT**: 时间预算耗尽，必须立即结束。"

        if self.progress_ratio >= 0.8:
            return f"警告: **TIME WARNING**: 剩余 {remaining/60:.0f} 分钟 ({progress:.0f}% 已用)。优先核心目标。"
        elif self.progress_ratio >= 0.5:
            return f"提示: **TIME UPDATE**: 剩余 {remaining/60:.0f} 分钟 ({progress:.0f}% 已用)。"
        else:
            return f"时间状态: 剩余 {remaining/60:.0f} 分钟 ({progress:.0f}% 已用)"


class TimeManager:
    """
    时间管理器

    参考Claude Code的Memory设计:
    - 时间信息写入Memory，AI可以读取
    - AI根据时间自主决策任务优先级
    - 唯一停止条件：超时
    """

    def __init__(self):
        self._active_budgets: Dict[str, TimeBudget] = {}

    def create_budget(
        self,
        session_id: str,
        task_type: TaskType,
        custom_timeout: Optional[int] = None,
    ) -> TimeBudget:
        """创建时间预算"""
        timeout = custom_timeout or TIMEOUT_CONFIGS.get(task_type, 30 * 60)

        budget = TimeBudget(
            total_seconds=timeout,
            start_time=time.time(),
            task_type=task_type,
        )

        self._active_budgets[session_id] = budget
        return budget

    def get_budget(self, session_id: str) -> Optional[TimeBudget]:
        return self._active_budgets.get(session_id)

    def should_stop(self, session_id: str) -> bool:
        """唯一熔断条件检查"""
        budget = self.get_budget(session_id)
        if not budget:
            return False
        return budget.is_timeout

    def get_time_prompt(self, session_id: str) -> str:
        """获取时间提示注入到System Prompt"""
        budget = self.get_budget(session_id)
        if not budget:
            return ""
        return budget.get_status_prompt()


# 时间管理提示词（简化版）
TIME_MANAGEMENT_PROMPT = """
## 时间管理

你有本次任务的时间预算。系统会在时间即将耗尽时发出警告。

你自主决定如何分配时间。请高效执行，优先高价值活动。
"""


__all__ = [
    "TaskType",
    "TIMEOUT_CONFIGS",
    "TimeBudget",
    "TimeManager",
    "TIME_MANAGEMENT_PROMPT",
]