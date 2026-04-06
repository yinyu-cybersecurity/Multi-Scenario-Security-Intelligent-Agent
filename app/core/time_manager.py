# app/core/time_manager.py

"""
时间管理器 - 唯一熔断条件

设计原则:
1. 超时是唯一硬性停止条件
2. 时间信息提供给 AI 让其自主决策
3. 不同阶段给出不同级别的时间提示
"""

from dataclasses import dataclass
from typing import Optional, Dict
import time


@dataclass
class TimeBudget:
    """时间预算"""
    total_seconds: int
    start_time: float = None

    def __post_init__(self):
        if self.start_time is None:
            self.start_time = time.time()

    @property
    def elapsed_seconds(self) -> float:
        return time.time() - self.start_time

    @property
    def remaining_seconds(self) -> float:
        return max(0, self.total_seconds - self.elapsed_seconds)

    @property
    def progress_ratio(self) -> float:
        """已用时间比例 (0.0 ~ 1.0)"""
        return min(1.0, self.elapsed_seconds / self.total_seconds)

    @property
    def remaining_ratio(self) -> float:
        """剩余时间比例 (1.0 ~ 0.0)"""
        return max(0.0, 1.0 - self.progress_ratio)

    @property
    def is_timeout(self) -> bool:
        """唯一熔断条件"""
        return self.remaining_seconds <= 0

    def get_status(self) -> str:
        """简洁的时间状态"""
        r = self.remaining_seconds
        if r <= 0:
            return "TIMEOUT"
        elif r < 60:
            return f"{int(r)}s"
        else:
            return f"{r/60:.0f}min"


__all__ = ["TimeBudget"]
