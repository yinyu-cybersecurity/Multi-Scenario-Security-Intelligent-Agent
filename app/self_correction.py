"""
自我纠错系统 - Self Correction Manager

Claude Code的错误恢复设计:
- 错误直接返回给AI
- AI自主决定恢复策略
- 记录错误历史供学习

兼容层：为topology等模块提供API
"""

from typing import Dict, List, Any

from app.memory.error_recovery import (
    ErrorType,
    ErrorSeverity,
    RecoveryStrategy,
    ErrorRecoveryEngine,
    ErrorRecord,
)


class SelfCorrectionManager:
    """
    自我纠错管理器

    兼容层：封装ErrorRecoveryEngine
    """

    def __init__(self):
        self._engine = ErrorRecoveryEngine()

    def record_error(
        self,
        error_type: ErrorType,
        message: str,
        context: Dict = None,
        severity: ErrorSeverity = ErrorSeverity.MEDIUM
    ) -> str:
        """记录错误"""
        return self._engine.record_error(
            error_type=error_type,
            message=message,
            context=context or {},
            severity=severity
        )

    def get_recovery_suggestions(self, error_id: str) -> List[Dict]:
        """获取恢复建议"""
        return self._engine.get_recovery_suggestions(error_id)

    def get_error_history(self, limit: int = 10) -> List[ErrorRecord]:
        """获取错误历史"""
        return self._engine.get_error_history(limit)


# 全局实例
self_correction_manager = SelfCorrectionManager()


__all__ = [
    "SelfCorrectionManager",
    "self_correction_manager",
    "ErrorType",
    "ErrorSeverity",
    "RecoveryStrategy",
]