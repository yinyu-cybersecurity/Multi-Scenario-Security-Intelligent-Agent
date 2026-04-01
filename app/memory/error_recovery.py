"""
CTF-Agent 错误恢复机制

借鉴Claude Code的自主恢复设计:
1. 错误分类与分级处理
2. 自动重试策略（指数退避）
3. 状态回滚与继续执行
4. 错误知识库积累
"""

from typing import Dict, Any, List, Optional, Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import json
import hashlib


class ErrorType(Enum):
    """错误类型分类"""
    # 执行错误
    TOOL_EXECUTION = "tool_execution"        # 工具执行失败
    TIMEOUT = "timeout"                      # 超时
    RESOURCE_LIMIT = "resource_limit"        # 资源限制（内存/Token）
    NETWORK = "network"                      # 网络错误

    # 决策错误
    INVALID_INPUT = "invalid_input"          # 无效输入
    PERMISSION_DENIED = "permission_denied"  # 权限不足
    STRATEGY_FAILED = "strategy_failed"      # 策略失败

    # 系统错误
    LLM_ERROR = "llm_error"                  # LLM调用失败
    MCP_ERROR = "mcp_error"                  # MCP工具调用失败
    INTERNAL = "internal"                    # 内部逻辑错误

    # 外部错误
    TARGET_DOWN = "target_down"              # 目标不可达
    SERVICE_UNAVAILABLE = "service_unavailable"  # 服务不可用


class ErrorSeverity(Enum):
    """错误严重性"""
    CRITICAL = "critical"    # 需立即中断
    HIGH = "high"            # 需人工介入
    MEDIUM = "medium"        # 可自动恢复
    LOW = "low"              # 可忽略继续


@dataclass
class ErrorRecord:
    """错误记录"""
    error_id: str
    error_type: ErrorType
    severity: ErrorSeverity
    message: str
    context: Dict[str, Any]              # 错误上下文
    timestamp: datetime
    agent_type: str
    node_name: str
    retry_count: int = 0
    max_retries: int = 3
    recovered: bool = False
    recovery_strategy: Optional[str] = None
    lesson_learned: Optional[str] = None  # 从错误中学到的教训


@dataclass
class RecoveryStrategy:
    """恢复策略"""
    strategy_id: str
    error_type: ErrorType
    action: Callable                      # 恢复动作
    preconditions: List[str]              # 前置条件
    success_rate: float = 0.0             # 成功率统计
    avg_recovery_time: float = 0.0        # 平均恢复时间


class ErrorRecoveryEngine:
    """错误恢复引擎"""

    def __init__(self):
        self.error_history: List[ErrorRecord] = []
        self.recovery_strategies: Dict[str, RecoveryStrategy] = {}
        self.error_knowledge: Dict[str, List[str]] = {}  # 错误ID -> 教训列表
        self.max_global_retries: int = 5
        self.backoff_factor: float = 1.5

        # 注册默认恢复策略
        self._register_default_strategies()

    def _register_default_strategies(self):
        """注册默认恢复策略"""
        strategies = [
            # 工具执行失败 - 重试
            RecoveryStrategy(
                strategy_id="retry_tool",
                error_type=ErrorType.TOOL_EXECUTION,
                action=self._retry_with_backoff,
                preconditions=["retry_count < max_retries"]
            ),

            # 超时 - 调整超时参数
            RecoveryStrategy(
                strategy_id="adjust_timeout",
                error_type=ErrorType.TIMEOUT,
                action=self._increase_timeout,
                preconditions=["timeout_can_increase"]
            ),

            # 网络错误 - 代理切换
            RecoveryStrategy(
                strategy_id="network_failover",
                error_type=ErrorType.NETWORK,
                action=self._try_alternative_endpoint,
                preconditions=["has_backup_endpoint"]
            ),

            # 策略失败 - 回退到保守策略
            RecoveryStrategy(
                strategy_id="fallback_strategy",
                error_type=ErrorType.STRATEGY_FAILED,
                action=self._fallback_to_safe_strategy,
                preconditions=["safe_strategy_available"]
            ),

            # LLM错误 - 模型降级
            RecoveryStrategy(
                strategy_id="model_downgrade",
                error_type=ErrorType.LLM_ERROR,
                action=self._switch_to_backup_model,
                preconditions=["backup_model_configured"]
            ),

            # 目标不可达 - 等待重试
            RecoveryStrategy(
                strategy_id="wait_and_retry",
                error_type=ErrorType.TARGET_DOWN,
                action=self._wait_and_retry_target,
                preconditions=["target_may_recover"]
            ),
        ]

        for strategy in strategies:
            self.recovery_strategies[strategy.strategy_id] = strategy

    def record_error(
        self,
        error_type: ErrorType,
        severity: ErrorSeverity,
        message: str,
        context: Dict[str, Any],
        agent_type: str,
        node_name: str
    ) -> ErrorRecord:
        """记录错误"""
        error_id = self._generate_error_id(error_type, message, context)

        # 检查是否已存在相同错误（避免重复记录）
        existing = [e for e in self.error_history if e.error_id == error_id]
        if existing:
            # 增加重试计数
            record = existing[0]
            record.retry_count += 1
            return record

        record = ErrorRecord(
            error_id=error_id,
            error_type=error_type,
            severity=severity,
            message=message,
            context=context,
            timestamp=datetime.now(),
            agent_type=agent_type,
            node_name=node_name
        )

        self.error_history.append(record)
        return record

    def _generate_error_id(
        self,
        error_type: ErrorType,
        message: str,
        context: Dict[str, Any]
    ) -> str:
        """生成错误唯一ID"""
        # 使用错误类型+消息+关键上下文生成ID
        key_data = {
            "type": error_type.value,
            "message": message[:50],  # 只取前50字符
            "context_keys": sorted(context.keys())
        }
        return hashlib.md5(json.dumps(key_data).encode()).hexdigest()[:12]

    def can_recover(self, error_record: ErrorRecord) -> bool:
        """判断是否可以自动恢复"""
        # 严重性检查
        if error_record.severity == ErrorSeverity.CRITICAL:
            return False

        # 重试次数检查
        if error_record.retry_count >= error_record.max_retries:
            return False

        # 全局重试限制
        global_retries = sum(1 for e in self.error_history if not e.recovered)
        if global_retries >= self.max_global_retries:
            return False

        # 恢复策略可用性检查
        strategy = self._get_recovery_strategy(error_record.error_type)
        if strategy is None:
            return False

        # 检查前置条件
        for precondition in strategy.preconditions:
            if not self._check_precondition(precondition, error_record):
                return False

        return True

    def attempt_recovery(
        self,
        error_record: ErrorRecord,
        state: Dict[str, Any]
    ) -> Dict[str, Any]:
        """尝试恢复"""
        strategy = self._get_recovery_strategy(error_record.error_type)

        if strategy is None:
            return {
                "success": False,
                "message": "无可用恢复策略"
            }

        try:
            # 执行恢复动作
            result = strategy.action(error_record, state)

            # 更新成功率统计
            strategy.success_rate = (
                strategy.success_rate * 0.9 + 1.0 * 0.1
                if result["success"] else
                strategy.success_rate * 0.9
            )

            # 记录恢复结果
            error_record.recovered = result["success"]
            error_record.recovery_strategy = strategy.strategy_id

            # 如果恢复成功，记录教训
            if result["success"] and result.get("lesson"):
                self._record_lesson(error_record.error_id, result["lesson"])

            return result

        except Exception as e:
            return {
                "success": False,
                "message": f"恢复策略执行失败: {str(e)}"
            }

    def _get_recovery_strategy(
        self,
        error_type: ErrorType
    ) -> Optional[RecoveryStrategy]:
        """获取恢复策略"""
        for strategy in self.recovery_strategies.values():
            if strategy.error_type == error_type:
                return strategy
        return None

    def _check_precondition(
        self,
        precondition: str,
        error_record: ErrorRecord
    ) -> bool:
        """检查前置条件"""
        # 简化实现：解析条件字符串
        if precondition == "retry_count < max_retries":
            return error_record.retry_count < error_record.max_retries
        elif precondition == "timeout_can_increase":
            timeout = error_record.context.get("timeout", 300)
            return timeout < 600  # 最大10分钟
        elif precondition == "has_backup_endpoint":
            return len(error_record.context.get("endpoints", [])) > 1
        elif precondition == "safe_strategy_available":
            return error_record.context.get("safe_strategy") is not None
        elif precondition == "backup_model_configured":
            return True  # 默认配置备用模型
        elif precondition == "target_may_recover":
            return error_record.context.get("is_transient", True)

        return True  # 默认满足

    # === 具体恢复动作 ===

    def _retry_with_backoff(
        self,
        error_record: ErrorRecord,
        state: Dict[str, Any]
    ) -> Dict[str, Any]:
        """指数退避重试"""
        import time

        backoff_seconds = (
            self.backoff_factor ** error_record.retry_count
        )

        return {
            "success": True,
            "action": "wait",
            "wait_seconds": backoff_seconds,
            "lesson": "增加等待时间避免立即重试"
        }

    def _increase_timeout(
        self,
        error_record: ErrorRecord,
        state: Dict[str, Any]
    ) -> Dict[str, Any]:
        """增加超时时间"""
        old_timeout = error_record.context.get("timeout", 300)
        new_timeout = int(old_timeout * 1.5)

        return {
            "success": True,
            "action": "adjust_timeout",
            "old_timeout": old_timeout,
            "new_timeout": new_timeout,
            "lesson": "超时错误应增加等待时间"
        }

    def _try_alternative_endpoint(
        self,
        error_record: ErrorRecord,
        state: Dict[str, Any]
    ) -> Dict[str, Any]:
        """尝试备用端点"""
        endpoints = error_record.context.get("endpoints", [])
        current_index = error_record.context.get("endpoint_index", 0)

        if current_index + 1 < len(endpoints):
            return {
                "success": True,
                "action": "switch_endpoint",
                "new_endpoint": endpoints[current_index + 1],
                "lesson": "网络失败时切换备用端点"
            }

        return {
            "success": False,
            "message": "无可用备用端点"
        }

    def _fallback_to_safe_strategy(
        self,
        error_record: ErrorRecord,
        state: Dict[str, Any]
    ) -> Dict[str, Any]:
        """回退到安全策略"""
        safe_strategy = error_record.context.get("safe_strategy")

        if safe_strategy:
            return {
                "success": True,
                "action": "change_strategy",
                "new_strategy": safe_strategy,
                "lesson": "激进策略失败时回退保守方案"
            }

        return {
            "success": False,
            "message": "无安全策略可用"
        }

    def _switch_to_backup_model(
        self,
        error_record: ErrorRecord,
        state: Dict[str, Any]
    ) -> Dict[str, Any]:
        """切换备用模型"""
        return {
            "success": True,
            "action": "switch_model",
            "new_model": "glm-5",  # 默认备用模型
            "lesson": "LLM错误时切换备用模型"
        }

    def _wait_and_retry_target(
        self,
        error_record: ErrorRecord,
        state: Dict[str, Any]
    ) -> Dict[str, Any]:
        """等待目标恢复并重试"""
        return {
            "success": True,
            "action": "wait_retry",
            "wait_seconds": 30,
            "lesson": "目标不可达时等待恢复"
        }

    def _record_lesson(self, error_id: str, lesson: str):
        """记录教训"""
        if error_id not in self.error_knowledge:
            self.error_knowledge[error_id] = []
        self.error_knowledge[error_id].append(lesson)

    def get_error_stats(self) -> Dict[str, Any]:
        """获取错误统计"""
        total = len(self.error_history)
        recovered = sum(1 for e in self.error_history if e.recovered)

        by_type = {}
        for e in self.error_history:
            key = e.error_type.value
            by_type[key] = by_type.get(key, 0) + 1

        by_severity = {}
        for e in self.error_history:
            key = e.severity.value
            by_severity[key] = by_severity.get(key, 0) + 1

        return {
            "total_errors": total,
            "recovered": recovered,
            "recovery_rate": recovered / total if total > 0 else 0.0,
            "by_type": by_type,
            "by_severity": by_severity,
            "lessons_count": len(self.error_knowledge)
        }

    def export_state(self) -> Dict[str, Any]:
        """导出状态（用于恢复）"""
        return {
            "error_history": [
                {
                    "error_id": e.error_id,
                    "error_type": e.error_type.value,
                    "severity": e.severity.value,
                    "message": e.message,
                    "timestamp": e.timestamp.isoformat(),
                    "retry_count": e.retry_count,
                    "recovered": e.recovered,
                    "recovery_strategy": e.recovery_strategy
                }
                for e in self.error_history
            ],
            "error_knowledge": self.error_knowledge,
            "stats": self.get_error_stats()
        }


# 全局错误恢复引擎
_error_recovery: Optional[ErrorRecoveryEngine] = None


def get_error_recovery() -> ErrorRecoveryEngine:
    """获取全局错误恢复引擎"""
    global _error_recovery
    if _error_recovery is None:
        _error_recovery = ErrorRecoveryEngine()
    return _error_recovery


# 使用示例
if __name__ == "__main__":
    engine = get_error_recovery()

    # 模拟错误
    error = engine.record_error(
        error_type=ErrorType.TOOL_EXECUTION,
        severity=ErrorSeverity.MEDIUM,
        message="nmap扫描超时",
        context={"timeout": 300, "target": "192.168.1.1"},
        agent_type="explore",
        node_name="port_scan"
    )

    # 尝试恢复
    if engine.can_recover(error):
        result = engine.attempt_recovery(error, {})
        print(f"恢复结果: {result}")

    # 统计
    print("\n" + "=" * 60)
    stats = engine.get_error_stats()
    print(f"错误统计: {stats}")