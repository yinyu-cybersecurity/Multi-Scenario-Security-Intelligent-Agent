# app/core/loop_detector.py

"""
循环检测器 - 检测 AI 是否陷入重复调用循环

设计原则:
- 相同工具 + 相同参数 = 相同输出（数学确定性）
- 框架提供反馈而非阻止，AI 仍可自主决定下一步
- 智能区分: 真循环 vs 合理的重复调用（如定期 list_challenges）
"""

from collections import Counter, deque
from typing import List, Set


class LoopDetector:
    """检测 AI 循环调用 - 唯一合理的代码层干预"""

    def __init__(self, window: int = 8, threshold: int = 3):
        self._history: deque = deque(maxlen=100)  # 完整历史
        self._window = window
        self._threshold = threshold
        # 某些工具的重复调用是合理的（如比赛模式下定期检查状态）
        self._exempt_tools: Set[str] = {"list_challenges"}
        self._loop_count = 0  # 累计循环次数

    def record(self, tool_name: str, args_hash: str) -> bool:
        """
        记录工具调用，返回是否检测到循环

        Returns:
            True: 检测到循环（调用者应注入警告）
            False: 正常调用
        """
        key = f"{tool_name}:{args_hash}"
        self._history.append(key)

        # 历史太短，不判断
        if len(self._history) < self._threshold:
            return False

        # 豁免工具
        bare_tool = tool_name.split("__")[-1] if "__" in tool_name else tool_name
        if bare_tool in self._exempt_tools:
            return False

        # 检查窗口内的重复
        recent = list(self._history)[-self._window:]
        counts = Counter(recent)
        most_common_key, most_common_count = counts.most_common(1)[0]

        if most_common_count >= self._threshold:
            self._loop_count += 1
            return True

        return False

    def get_warning(self) -> str:
        """生成循环警告消息"""
        recent = list(self._history)[-self._window:]
        counts = Counter(recent)
        most_common_key, count = counts.most_common(1)[0]
        tool_name = most_common_key.split(":")[0]

        # 根据循环次数升级警告强度
        if self._loop_count >= 5:
            return (
                f"[LOOP_CRITICAL] You have repeated {tool_name} {count} times with identical arguments. "
                f"This is the {self._loop_count}th loop detection. "
                f"STOP this approach immediately. The same input ALWAYS produces the same output. "
                f"You MUST: 1) Analyze previous results 2) Try a completely different tool or technique 3) If stuck, use search_skills for new ideas."
            )
        elif self._loop_count >= 3:
            return (
                f"[LOOP_WARNING] Repeated {tool_name} {count}x with same args (loop #{self._loop_count}). "
                f"Same input = same output. Change your approach: different parameters, different tool, or different attack vector."
            )
        else:
            return (
                f"[LOOP_DETECTED] {tool_name} called {count}x with identical args in last {self._window} calls. "
                f"Same input always produces same output. Analyze previous results and try a different approach."
            )

    @property
    def loop_count(self) -> int:
        return self._loop_count

    def get_recent_pattern(self) -> str:
        """获取最近最频繁的循环模式描述"""
        if not self._history:
            return "无循环"
        recent = list(self._history)[-self._window:]
        counts = Counter(recent)
        most_common_key, count = counts.most_common(1)[0]
        tool = most_common_key.split(":")[0]
        args_hash = most_common_key.split(":")[-1] if ":" in most_common_key else "?"
        return f"{tool} 重复 {count} 次 (args_hash: {args_hash})"

    def reset(self):
        """重置（用于切换题目时）"""
        self._history.clear()
        self._loop_count = 0


__all__ = ["LoopDetector"]
