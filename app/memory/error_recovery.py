"""
错误恢复系统 - Error Recovery Engine

Claude Code的错误恢复设计:
- 错误直接返回给AI，无降级处理
- AI自主决定如何处理错误
- 支持重试、忽略、回退等策略
- 记录错误历史供AI学习

核心原则:
1. 错误是信息，不是失败
2. AI可以看到完整错误信息
3. AI自主决定下一步行动
4. 系统提供错误上下文，不隐藏
"""

import asyncio
import time
from typing import Dict, Any, List, Optional, Callable
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime


class ErrorType(Enum):
    """错误类型"""
    LLM_ERROR = "llm_error"           # LLM调用错误
    TOOL_ERROR = "tool_error"         # 工具执行错误
    TIMEOUT_ERROR = "timeout_error"   # 超时错误
    NETWORK_ERROR = "network_error"   # 网络错误
    PERMISSION_ERROR = "permission_error"  # 权限错误
    VALIDATION_ERROR = "validation_error"  # 验证错误
    UNKNOWN_ERROR = "unknown_error"   # 未知错误


class ErrorSeverity(Enum):
    """错误严重程度"""
    LOW = "low"           # 可忽略
    MEDIUM = "medium"     # 需要处理
    HIGH = "high"         # 严重影响
    CRITICAL = "critical" # 致命错误


class RecoveryStrategy(Enum):
    """恢复策略"""
    RETRY = "retry"           # 重试
    IGNORE = "ignore"         # 忽略
    FALLBACK = "fallback"     # 回退
    ABORT = "abort"           # 中止
    ASK_USER = "ask_user"     # 询问用户
    SELF_CORRECT = "self_correct"  # AI自我纠正


@dataclass
class ErrorRecord:
    """错误记录"""
    error_id: str
    error_type: ErrorType
    severity: ErrorSeverity
    message: str
    context: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    traceback: Optional[str] = None
    attempt_count: int = 0
    recovery_attempted: bool = False
    recovery_successful: bool = False


class ErrorRecoveryEngine:
    """
    错误恢复引擎

    Claude Code模式:
    - 记录错误并返回给AI
    - 不自动降级或隐藏错误
    - AI决定恢复策略
    - 提供错误上下文帮助AI决策

    使用方式:
    ```python
    recovery = ErrorRecoveryEngine()

    try:
        result = await risky_operation()
    except Exception as e:
        # 记录错误
        record = recovery.record_error(e, context={...})

        # 获取恢复建议给AI
        suggestions = recovery.get_recovery_suggestions(record)

        # AI决定如何处理
        # ...
    ```
    """

    def __init__(self, max_history: int = 100):
        """
        初始化错误恢复引擎

        Args:
            max_history: 最大历史记录数
        """
        self.max_history = max_history
        self._error_history: List[ErrorRecord] = []
        self._error_counter = 0

    def record_error(
        self,
        error: Exception,
        error_type: ErrorType = None,
        severity: ErrorSeverity = None,
        context: Dict[str, Any] = None
    ) -> ErrorRecord:
        """
        记录错误

        Claude Code模式: 错误是信息，记录下来供AI参考

        Args:
            error: 异常对象
            error_type: 错误类型（自动推断）
            severity: 严重程度（自动推断）
            context: 错误上下文

        Returns:
            错误记录
        """
        # 自动推断错误类型
        if error_type is None:
            error_type = self._infer_error_type(error)

        # 自动推断严重程度
        if severity is None:
            severity = self._infer_severity(error, error_type)

        # 生成错误ID
        self._error_counter += 1
        error_id = f"err_{int(time.time())}_{self._error_counter}"

        # 获取traceback
        import traceback
        tb_str = "".join(traceback.format_exception(type(error), error, error.__traceback__))

        # 创建记录
        record = ErrorRecord(
            error_id=error_id,
            error_type=error_type,
            severity=severity,
            message=str(error),
            context=context or {},
            traceback=tb_str
        )

        # 添加到历史
        self._error_history.append(record)

        # 限制历史大小
        if len(self._error_history) > self.max_history:
            self._error_history = self._error_history[-self.max_history:]

        return record

    def get_recovery_suggestions(
        self,
        record: ErrorRecord,
        available_actions: List[str] = None
    ) -> List[Dict[str, Any]]:
        """
        获取恢复建议

        Claude Code模式: 提供建议给AI，AI决定如何处理

        Args:
            record: 错误记录
            available_actions: 可用的行动列表

        Returns:
            恢复建议列表
        """
        suggestions = []

        # 根据错误类型提供建议
        if record.error_type == ErrorType.LLM_ERROR:
            suggestions.append({
                "strategy": RecoveryStrategy.RETRY,
                "reason": "LLM调用可能因临时问题失败，可重试",
                "params": {"delay": 2, "max_attempts": 3}
            })
            suggestions.append({
                "strategy": RecoveryStrategy.SELF_CORRECT,
                "reason": "可能需要调整prompt或参数",
                "params": {}
            })

        elif record.error_type == ErrorType.TOOL_ERROR:
            suggestions.append({
                "strategy": RecoveryStrategy.SELF_CORRECT,
                "reason": "工具执行失败，检查参数或尝试其他工具",
                "params": {}
            })
            suggestions.append({
                "strategy": RecoveryStrategy.FALLBACK,
                "reason": "尝试使用替代工具或方法",
                "params": {}
            })

        elif record.error_type == ErrorType.TIMEOUT_ERROR:
            suggestions.append({
                "strategy": RecoveryStrategy.RETRY,
                "reason": "超时可能是临时的，可重试",
                "params": {"delay": 5, "max_attempts": 2}
            })
            suggestions.append({
                "strategy": RecoveryStrategy.IGNORE,
                "reason": "如果非关键操作，可以跳过",
                "params": {}
            })

        elif record.error_type == ErrorType.NETWORK_ERROR:
            suggestions.append({
                "strategy": RecoveryStrategy.RETRY,
                "reason": "网络问题通常是临时的",
                "params": {"delay": 3, "max_attempts": 3}
            })
            suggestions.append({
                "strategy": RecoveryStrategy.ABORT,
                "reason": "如果网络持续不可用，中止当前操作",
                "params": {}
            })

        elif record.error_type == ErrorType.PERMISSION_ERROR:
            suggestions.append({
                "strategy": RecoveryStrategy.ASK_USER,
                "reason": "权限问题需要用户确认或提供凭据",
                "params": {}
            })
            suggestions.append({
                "strategy": RecoveryStrategy.FALLBACK,
                "reason": "尝试不需要该权限的方法",
                "params": {}
            })

        else:
            suggestions.append({
                "strategy": RecoveryStrategy.SELF_CORRECT,
                "reason": "检查错误详情，决定下一步",
                "params": {}
            })

        return suggestions

    def format_error_for_ai(self, record: ErrorRecord) -> str:
        """
        格式化错误信息给AI

        Claude Code模式: AI需要看到完整错误信息来做决策

        Args:
            record: 错误记录

        Returns:
            格式化的错误信息
        """
        lines = [
            f"## Error Report: {record.error_id}",
            "",
            f"**Type**: {record.error_type.value}",
            f"**Severity**: {record.severity.value}",
            f"**Time**: {datetime.fromtimestamp(record.timestamp).isoformat()}",
            "",
            "### Message",
            f"```\n{record.message}\n```",
            "",
            "### Context",
        ]

        for key, value in record.context.items():
            lines.append(f"- {key}: {value}")

        if record.traceback:
            lines.extend([
                "",
                "### Traceback",
                f"```\n{record.traceback[:1000]}\n```"  # 限制长度
            ])

        suggestions = self.get_recovery_suggestions(record)
        if suggestions:
            lines.extend([
                "",
                "### Recovery Suggestions",
            ])
            for i, s in enumerate(suggestions, 1):
                lines.append(f"{i}. **{s['strategy'].value}**: {s['reason']}")

        return "\n".join(lines)

    async def execute_with_retry(
        self,
        operation: Callable,
        max_attempts: int = 3,
        delay: float = 1.0,
        backoff: float = 2.0,
        context: Dict[str, Any] = None
    ) -> Any:
        """
        带重试的执行

        Claude Code模式: 提供重试能力，但AI决定是否使用

        Args:
            operation: 要执行的异步函数
            max_attempts: 最大尝试次数
            delay: 初始延迟
            backoff: 退避因子
            context: 执行上下文

        Returns:
            操作结果

        Raises:
            最后一次错误
        """
        last_error = None
        current_delay = delay

        for attempt in range(max_attempts):
            try:
                return await operation()
            except Exception as e:
                last_error = e

                # 记录错误
                record = self.record_error(
                    e,
                    context={
                        **(context or {}),
                        "attempt": attempt + 1,
                        "max_attempts": max_attempts
                    }
                )

                # 如果不是最后一次，等待后重试
                if attempt < max_attempts - 1:
                    await asyncio.sleep(current_delay)
                    current_delay *= backoff

        # 所有尝试都失败，抛出最后的错误
        raise last_error

    def get_error_history(
        self,
        error_type: ErrorType = None,
        severity: ErrorSeverity = None,
        limit: int = 10
    ) -> List[ErrorRecord]:
        """
        获取错误历史

        Args:
            error_type: 过滤错误类型
            severity: 过滤严重程度
            limit: 返回数量限制

        Returns:
            错误记录列表
        """
        filtered = self._error_history

        if error_type:
            filtered = [r for r in filtered if r.error_type == error_type]

        if severity:
            filtered = [r for r in filtered if r.severity == severity]

        return filtered[-limit:]

    def clear_history(self):
        """清空错误历史"""
        self._error_history.clear()

    def _infer_error_type(self, error: Exception) -> ErrorType:
        """推断错误类型"""
        error_name = type(error).__name__.lower()

        if "timeout" in error_name:
            return ErrorType.TIMEOUT_ERROR
        elif "network" in error_name or "connection" in error_name:
            return ErrorType.NETWORK_ERROR
        elif "permission" in error_name or "auth" in error_name:
            return ErrorType.PERMISSION_ERROR
        elif "validation" in error_name or "value" in error_name:
            return ErrorType.VALIDATION_ERROR
        elif "llm" in error_name or "api" in error_name:
            return ErrorType.LLM_ERROR
        else:
            return ErrorType.UNKNOWN_ERROR

    def _infer_severity(
        self,
        error: Exception,
        error_type: ErrorType
    ) -> ErrorSeverity:
        """推断错误严重程度"""
        # 超时和网络错误通常是临时的
        if error_type in [ErrorType.TIMEOUT_ERROR, ErrorType.NETWORK_ERROR]:
            return ErrorSeverity.MEDIUM

        # 权限错误需要处理
        if error_type == ErrorType.PERMISSION_ERROR:
            return ErrorSeverity.HIGH

        # LLM错误可能需要重试
        if error_type == ErrorType.LLM_ERROR:
            return ErrorSeverity.MEDIUM

        # 验证错误通常是参数问题
        if error_type == ErrorType.VALIDATION_ERROR:
            return ErrorSeverity.LOW

        # 其他未知错误
        return ErrorSeverity.MEDIUM


# 全局错误恢复引擎
_error_recovery: Optional[ErrorRecoveryEngine] = None


def get_error_recovery() -> ErrorRecoveryEngine:
    """获取全局错误恢复引擎"""
    global _error_recovery
    if _error_recovery is None:
        _error_recovery = ErrorRecoveryEngine()
    return _error_recovery


__all__ = [
    "ErrorRecoveryEngine",
    "ErrorRecord",
    "ErrorType",
    "ErrorSeverity",
    "RecoveryStrategy",
    "get_error_recovery",
]