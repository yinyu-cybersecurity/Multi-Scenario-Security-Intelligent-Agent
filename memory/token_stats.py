# memory/token_stats.py
"""
Token统计持久化模块

功能:
- 持久化存储LLM Token使用量
- 服务重启后恢复累计值
- 支持按日期统计
"""

import os
import json
import time
import threading
from typing import Dict, Any
from pathlib import Path
from datetime import datetime


class TokenStatsManager:
    """Token统计持久化管理器"""

    def __init__(self, stats_dir: str = None):
        if stats_dir is None:
            # 默认存储在data目录
            stats_dir = os.path.join(os.path.dirname(__file__), '..', 'data')

        self.stats_dir = Path(stats_dir)
        self.stats_file = self.stats_dir / "token_stats.json"
        self._lock = threading.Lock()

        # 确保目录存在
        self.stats_dir.mkdir(parents=True, exist_ok=True)

        # 加载历史数据
        self._data = self._load()

    def _load(self) -> Dict[str, Any]:
        """加载历史统计数据"""
        if not self.stats_file.exists():
            return {
                "total_tokens": 0,
                "prompt_tokens": 0,
                "completion_tokens": 0,
                "request_count": 0,
                "daily_stats": {},
                "last_updated": None
            }

        try:
            with open(self.stats_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"[TokenStats] 加载失败: {e}")
            return {
                "total_tokens": 0,
                "prompt_tokens": 0,
                "completion_tokens": 0,
                "request_count": 0,
                "daily_stats": {},
                "last_updated": None
            }

    def _save(self):
        """保存统计数据到文件"""
        try:
            self._data["last_updated"] = datetime.now().isoformat()
            with open(self.stats_file, 'w', encoding='utf-8') as f:
                json.dump(self._data, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print(f"[TokenStats] 保存失败: {e}")

    def record_usage(self, prompt_tokens: int, completion_tokens: int):
        """
        记录Token使用量

        Args:
            prompt_tokens: 输入token数
            completion_tokens: 输出token数
        """
        with self._lock:
            total = prompt_tokens + completion_tokens

            # 更新累计值
            self._data["total_tokens"] += total
            self._data["prompt_tokens"] += prompt_tokens
            self._data["completion_tokens"] += completion_tokens
            self._data["request_count"] += 1

            # 更新每日统计
            today = datetime.now().strftime("%Y-%m-%d")
            if today not in self._data["daily_stats"]:
                self._data["daily_stats"][today] = {
                    "total_tokens": 0,
                    "prompt_tokens": 0,
                    "completion_tokens": 0,
                    "request_count": 0
                }

            daily = self._data["daily_stats"][today]
            daily["total_tokens"] += total
            daily["prompt_tokens"] += prompt_tokens
            daily["completion_tokens"] += completion_tokens
            daily["request_count"] += 1

            # 异步保存（避免阻塞）
            self._save()

    def get_stats(self) -> Dict[str, Any]:
        """获取统计数据"""
        with self._lock:
            return {
                "total_tokens": self._data["total_tokens"],
                "prompt_tokens": self._data["prompt_tokens"],
                "completion_tokens": self._data["completion_tokens"],
                "request_count": self._data["request_count"],
                "last_updated": self._data.get("last_updated"),
                "today": self._get_today_stats()
            }

    def _get_today_stats(self) -> Dict[str, int]:
        """获取今日统计"""
        today = datetime.now().strftime("%Y-%m-%d")
        return self._data["daily_stats"].get(today, {
            "total_tokens": 0,
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "request_count": 0
        })

    def get_daily_stats(self, days: int = 7) -> Dict[str, Dict]:
        """获取最近N天的统计"""
        with self._lock:
            return dict(list(self._data["daily_stats"].items())[-days:])

    def reset(self):
        """重置统计数据"""
        with self._lock:
            self._data = {
                "total_tokens": 0,
                "prompt_tokens": 0,
                "completion_tokens": 0,
                "request_count": 0,
                "daily_stats": {},
                "last_updated": None
            }
            self._save()


# 全局单例
_token_stats_manager = None


def get_token_stats_manager() -> TokenStatsManager:
    """获取Token统计管理器单例"""
    global _token_stats_manager
    if _token_stats_manager is None:
        _token_stats_manager = TokenStatsManager()
    return _token_stats_manager