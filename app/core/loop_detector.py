# app/core/loop_detector.py

"""
循环检测器 - 检测AI是否陷入重复调用循环

这是唯一合理的代码层面干预。原因：
- 相同工具+相同参数 = 相同输出（数学确定性）
- AI可能因为各种原因陷入循环
- 框架提供反馈而非阻止，AI仍可决定下一步
"""

from collections import Counter
from typing import List


class LoopDetector:
    """检测AI是否陷入重复调用循环 - 唯一合理的代码层干预"""

    def __init__(self, window: int = 5):
        self._history: List[str] = []
        self._window = window

    def record(self, tool_name: str, args_hash: str) -> bool:
        key = f"{tool_name}:{args_hash}"
        self._history.append(key)

        if len(self._history) < 3:
            return False

        recent = self._history[-self._window:]
        counts = Counter(recent)
        return counts.most_common(1)[0][1] >= 3

    def get_warning(self) -> str:
        recent = self._history[-self._window:]
        most_common = Counter(recent).most_common(1)[0]
        return (
            f"[LOOP_DETECTED] 你在最近{self._window}次调用中重复了 "
            f"{most_common[0].split(':')[0]} {most_common[1]}次，且参数相同。"
            f"相同输入必然产生相同输出。请分析之前的结果并换一种方法。"
        )


__all__ = ["LoopDetector"]