"""
Token 统计持久化模块

提供:
- Token 使用统计
- 内存存储（后续可扩展为持久化存储）
- 多模型统计支持
"""
import threading
from typing import Dict, Optional
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict


@dataclass
class TokenUsage:
    """Token使用记录"""
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    request_count: int = 0
    last_request: Optional[datetime] = None


class TokenStatsManager:
    """
    Token统计管理器

    功能:
    - 多模型Token统计
    - 线程安全
    - 内存存储（可扩展为持久化）
    """

    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return

        self._initialized = True
        self._stats: Dict[str, TokenUsage] = defaultdict(TokenUsage)
        self._global_stats = TokenUsage()
        self._stats_lock = threading.Lock()

    def record_usage(
        self,
        model: str,
        prompt_tokens: int,
        completion_tokens: int
    ) -> None:
        """
        记录Token使用

        Args:
            model: 模型名称
            prompt_tokens: 提示Token数
            completion_tokens: 完成Token数
        """
        total = prompt_tokens + completion_tokens

        with self._stats_lock:
            # 更新模型统计
            model_stats = self._stats[model]
            model_stats.prompt_tokens += prompt_tokens
            model_stats.completion_tokens += completion_tokens
            model_stats.total_tokens += total
            model_stats.request_count += 1
            model_stats.last_request = datetime.now()

            # 更新全局统计
            self._global_stats.prompt_tokens += prompt_tokens
            self._global_stats.completion_tokens += completion_tokens
            self._global_stats.total_tokens += total
            self._global_stats.request_count += 1
            self._global_stats.last_request = datetime.now()

    def record_usage_simple(
        self,
        prompt_tokens: int,
        completion_tokens: int
    ) -> None:
        """
        简化的Token记录接口（不区分模型）

        Args:
            prompt_tokens: 提示Token数
            completion_tokens: 完成Token数
        """
        self.record_usage("default", prompt_tokens, completion_tokens)

    def get_stats(self) -> Dict:
        """获取统计摘要（简化接口）"""
        with self._stats_lock:
            return {
                "total_tokens": self._global_stats.total_tokens,
                "prompt_tokens": self._global_stats.prompt_tokens,
                "completion_tokens": self._global_stats.completion_tokens,
                "request_count": self._global_stats.request_count,
            }

    def get_model_stats(self, model: str) -> TokenUsage:
        """获取指定模型的统计"""
        with self._stats_lock:
            return self._stats.get(model, TokenUsage())

    def get_all_stats(self) -> Dict[str, TokenUsage]:
        """获取所有模型统计"""
        with self._stats_lock:
            return dict(self._stats)

    def get_global_stats(self) -> TokenUsage:
        """获取全局统计"""
        with self._stats_lock:
            return self._global_stats

    def reset_stats(self, model: Optional[str] = None) -> None:
        """
        重置统计

        Args:
            model: 指定模型，None表示重置所有
        """
        with self._stats_lock:
            if model:
                self._stats[model] = TokenUsage()
            else:
                self._stats.clear()
                self._global_stats = TokenUsage()

    def get_summary(self) -> str:
        """获取统计摘要"""
        stats = self.get_global_stats()
        return (
            f"Token统计: "
            f"总计={stats.total_tokens:,} "
            f"(提示={stats.prompt_tokens:,}, 完成={stats.completion_tokens:,}), "
            f"请求次数={stats.request_count}"
        )


# 单例实例
_manager: Optional[TokenStatsManager] = None


def get_token_stats_manager() -> TokenStatsManager:
    """获取Token统计管理器单例"""
    global _manager
    if _manager is None:
        _manager = TokenStatsManager()
    return _manager


__all__ = [
    "TokenStatsManager",
    "TokenUsage",
    "get_token_stats_manager",
]