# self_correction.py
"""
自我纠错机制模块

提供:
- 系统健康检查
- 自动状态恢复
- 错误链追踪
- 优雅关闭机制
"""
import time
import traceback
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, field
from enum import Enum
from state import CTFState


class ErrorSeverity(Enum):
    """错误严重程度"""
    LOW = 1       # 可自动恢复
    MEDIUM = 2    # 需要重试
    HIGH = 3      # 需要模式切换
    CRITICAL = 4  # 需要人工介入


@dataclass
class ErrorRecord:
    """错误记录"""
    timestamp: float
    node: str
    error_type: str
    error_message: str
    severity: ErrorSeverity
    stack_trace: str = ""
    recovery_action: str = ""
    recovered: bool = False


@dataclass
class HealthStatus:
    """系统健康状态"""
    is_healthy: bool = True
    last_check_time: float = 0.0
    consecutive_failures: int = 0
    total_errors: int = 0
    active_retries: int = 0
    recommendations: List[str] = field(default_factory=list)


class SelfCorrectionManager:
    """自我纠错管理器"""

    def __init__(self):
        self.error_history: List[ErrorRecord] = []
        self.max_history_size = 100
        self.health_status = HealthStatus()
        self.recovery_handlers: Dict[str, Callable] = {}
        self._register_default_handlers()

    def _register_default_handlers(self):
        """注册默认恢复处理器"""
        self.recovery_handlers = {
            "LLM_TIMEOUT": self._handle_llm_timeout,
            "TOOL_FAILURE": self._handle_tool_failure,
            "STATE_CORRUPTION": self._handle_state_corruption,
            "DEAD_LOOP": self._handle_dead_loop,
            "PERMISSION_DENIED": self._handle_permission_denied,
        }

    def record_error(
        self,
        node: str,
        error_type: str,
        error_message: str,
        severity: ErrorSeverity = ErrorSeverity.MEDIUM
    ) -> ErrorRecord:
        """
        记录错误并触发恢复机制

        Args:
            node: 发生错误的节点
            error_type: 错误类型
            error_message: 错误消息
            severity: 严重程度

        Returns:
            错误记录
        """
        record = ErrorRecord(
            timestamp=time.time(),
            node=node,
            error_type=error_type,
            error_message=error_message,
            severity=severity,
            stack_trace=traceback.format_exc()
        )

        self.error_history.append(record)
        if len(self.error_history) > self.max_history_size:
            self.error_history = self.error_history[-self.max_history_size:]

        self.health_status.total_errors += 1
        self.health_status.consecutive_failures += 1

        # 更新健康状态
        self._update_health_status(severity)

        # 尝试自动恢复
        if severity.value <= ErrorSeverity.MEDIUM.value:
            record.recovery_action = self._attempt_recovery(record)

        print(f"[SelfCorrection] 记录错误: {error_type}@{node} (严重度: {severity.name})")
        return record

    def _update_health_status(self, severity: ErrorSeverity):
        """更新系统健康状态"""
        if severity.value >= ErrorSeverity.HIGH.value:
            self.health_status.is_healthy = False

        if self.health_status.consecutive_failures > 5:
            self.health_status.is_healthy = False
            self.health_status.recommendations.append(
                "连续失败次数过多，建议重置状态或人工介入"
            )

    def _attempt_recovery(self, record: ErrorRecord) -> str:
        """尝试自动恢复"""
        handler = self.recovery_handlers.get(record.error_type)
        if handler:
            try:
                action = handler(record)
                record.recovered = True
                return action
            except Exception as e:
                return f"恢复失败: {str(e)}"
        return "无可用恢复处理器"

    def _handle_llm_timeout(self, record: ErrorRecord) -> str:
        """处理LLM超时"""
        return "切换到备用模型或减少请求频率"

    def _handle_tool_failure(self, record: ErrorRecord) -> str:
        """处理工具执行失败"""
        return "标记工具为不可用，尝试替代工具"

    def _handle_state_corruption(self, record: ErrorRecord) -> str:
        """处理状态损坏"""
        return "重置损坏的状态字段"

    def _handle_dead_loop(self, record: ErrorRecord) -> str:
        """处理死循环"""
        return "强制切换模式或节点"

    def _handle_permission_denied(self, record: ErrorRecord) -> str:
        """处理权限拒绝"""
        return "尝试提权或绕过方法"

    def check_health(self, state: CTFState) -> HealthStatus:
        """
        检查系统健康状态

        Args:
            state: 当前状态

        Returns:
            健康状态报告
        """
        self.health_status.last_check_time = time.time()
        self.health_status.recommendations = []

        # 检查关键状态字段
        if not state.get("target_url"):
            self.health_status.recommendations.append("目标URL缺失")

        # 检查执行步数
        steps = state.get("execution_steps", 0)
        max_steps = 500  # 假设最大步数
        if steps > max_steps * 0.8:
            self.health_status.recommendations.append(
                f"执行步数过高 ({steps}/{max_steps})"
            )

        # 检查失败分
        failure_score = state.get("failure_weighted_score", 0)
        if failure_score > 10:
            self.health_status.recommendations.append(
                f"失败分过高 ({failure_score})"
            )

        # 检查最近的错误
        recent_errors = [
            e for e in self.error_history
            if time.time() - e.timestamp < 300  # 最近5分钟
        ]
        if len(recent_errors) > 10:
            self.health_status.recommendations.append(
                f"最近错误频繁 ({len(recent_errors)}次/5min)"
            )

        # 如果没有问题，标记为健康
        if not self.health_status.recommendations:
            self.health_status.is_healthy = True
            self.health_status.consecutive_failures = 0

        return self.health_status

    def suggest_recovery_action(self, state: CTFState) -> Optional[str]:
        """
        根据当前状态建议恢复动作

        Args:
            state: 当前状态

        Returns:
            建议的恢复动作，None表示无需恢复
        """
        health = self.check_health(state)

        if health.is_healthy:
            return None

        # 优先级排序的建议
        if health.consecutive_failures > 5:
            return "reset_state"  # 重置状态

        failure_score = state.get("failure_weighted_score", 0)
        if failure_score > 15:
            return "mode_switch:innovate"  # 创新模式（替代原HITL）

        if failure_score > 10:
            return "mode_switch:innovate"  # 创新模式

        if failure_score > 5:
            return "mode_switch:explore"  # 探索模式

        return "retry"  # 重试当前操作

    def reset_state_fields(self, state: CTFState, fields: List[str] = None) -> Dict:
        """
        重置指定状态字段

        Args:
            state: 当前状态
            fields: 要重置的字段列表，None表示重置默认字段

        Returns:
            重置后的状态更新
        """
        default_reset_fields = [
            "failure_weighted_score",
            "exploration_rounds",
            "rule_miss_count",
        ]

        fields_to_reset = fields or default_reset_fields
        updates = {}

        for field in fields_to_reset:
            if field in state:
                # 根据字段类型设置默认值
                if isinstance(state.get(field), (int, float)):
                    updates[field] = 0
                elif isinstance(state.get(field), str):
                    updates[field] = ""
                elif isinstance(state.get(field), list):
                    updates[field] = []
                elif isinstance(state.get(field), dict):
                    updates[field] = {}

        print(f"[SelfCorrection] 重置状态字段: {list(updates.keys())}")
        self.health_status.consecutive_failures = 0
        self.health_status.is_healthy = True

        return updates

    def get_error_summary(self, last_n: int = 10) -> str:
        """获取最近的错误摘要"""
        recent = self.error_history[-last_n:] if self.error_history else []
        if not recent:
            return "无最近错误"

        lines = []
        for e in recent:
            lines.append(
                f"  [{e.severity.name}] {e.node}: {e.error_type} - {e.error_message[:50]}"
            )
        return "\n".join(lines)


# 全局自我纠错管理器实例
self_correction_manager = SelfCorrectionManager()


def with_self_correction(node_name: str):
    """
    装饰器：为节点添加自我纠错能力

    用法:
        @with_self_correction("attacker")
        def attacker_node(state: CTFState) -> Dict:
            ...
    """
    def decorator(func):
        def wrapper(state: CTFState) -> Dict:
            try:
                result = func(state)
                # 成功执行，重置连续失败计数
                self_correction_manager.health_status.consecutive_failures = 0
                return result
            except Exception as e:
                # 记录错误
                self_correction_manager.record_error(
                    node=node_name,
                    error_type="EXECUTION_ERROR",
                    error_message=str(e),
                    severity=ErrorSeverity.MEDIUM
                )

                # 尝试获取恢复建议
                recovery = self_correction_manager.suggest_recovery_action(state)

                # 返回包含错误信息的结果
                return {
                    "error": str(e),
                    "recovery_suggestion": recovery,
                    "failure_weighted_score": state.get("failure_weighted_score", 0) + 1.0
                }
        return wrapper
    return decorator