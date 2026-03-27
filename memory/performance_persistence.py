# memory/performance_persistence.py
"""
性能数据持久化模块

功能:
- 持久化存储性能统计数据
- 支持降采样策略（小时/日聚合）
- 服务重启后恢复历史数据
- 保存最近30天的历史趋势
"""

import os
import json
import time
import threading
from typing import Dict, Any, List, Optional
from pathlib import Path
from datetime import datetime, timedelta
from collections import defaultdict


class PerformancePersistence:
    """
    性能数据持久化管理器

    存储策略:
    - 原始统计: 实时保存（节流30秒）
    - 小时聚合: 每小时聚合一组数据，保留24小时
    - 日汇总: 每日汇总，保留30天
    """

    def __init__(self, data_dir: str = None):
        if data_dir is None:
            data_dir = os.path.join(os.path.dirname(__file__), '..', 'data')

        self.data_dir = Path(data_dir)
        self.stats_file = self.data_dir / "performance_stats.json"
        self.history_file = self.data_dir / "performance_history.json"
        self._lock = threading.Lock()

        # 确保目录存在
        self.data_dir.mkdir(parents=True, exist_ok=True)

        # 加载历史数据
        self._stats_data = self._load_stats()
        self._history_data = self._load_history()

    def _load_stats(self) -> Dict[str, Any]:
        """加载统计数据"""
        if not self.stats_file.exists():
            return {
                "nodes": {},
                "llm": {},
                "tools": {},
                "uptime_seconds": 0,
                "last_updated": None
            }

        try:
            with open(self.stats_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"[PerformancePersistence] 加载统计数据失败: {e}")
            return {"nodes": {}, "llm": {}, "tools": {}, "uptime_seconds": 0}

    def _load_history(self) -> Dict[str, Any]:
        """加载历史数据"""
        if not self.history_file.exists():
            return {
                "hourly": {},  # 小时聚合 {hour_key: stats}
                "daily": {}    # 日汇总 {date_key: stats}
            }

        try:
            with open(self.history_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"[PerformancePersistence] 加载历史数据失败: {e}")
            return {"hourly": {}, "daily": {}}

    def _save_stats(self):
        """保存统计数据"""
        try:
            self._stats_data["last_updated"] = datetime.now().isoformat()
            with open(self.stats_file, 'w', encoding='utf-8') as f:
                json.dump(self._stats_data, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print(f"[PerformancePersistence] 保存统计数据失败: {e}")

    def _save_history(self):
        """保存历史数据"""
        try:
            with open(self.history_file, 'w', encoding='utf-8') as f:
                json.dump(self._history_data, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print(f"[PerformancePersistence] 保存历史数据失败: {e}")

    def save(self, stats: Dict[str, Any]):
        """
        保存统计数据

        Args:
            stats: 包含 nodes, llm, tools 等的统计数据
        """
        with self._lock:
            # 更新统计数据
            self._stats_data["nodes"] = stats.get("nodes", {})
            self._stats_data["llm"] = stats.get("llm", {})
            self._stats_data["tools"] = stats.get("tools", {})
            self._stats_data["uptime_seconds"] = stats.get("uptime_seconds", 0)

            # 保存统计
            self._save_stats()

            # 更新小时聚合
            self._update_hourly_stats(stats)

    def _update_hourly_stats(self, stats: Dict[str, Any]):
        """更新小时聚合数据"""
        now = datetime.now()
        hour_key = now.strftime("%Y-%m-%dT%H")

        # 计算总数
        node_count = sum(v.get("count", 0) for v in stats.get("nodes", {}).values())
        llm_count = sum(v.get("count", 0) for v in stats.get("llm", {}).values())
        tool_count = sum(v.get("total_executions", 0) for v in stats.get("tools", {}).values())

        # 计算平均耗时
        total_ms = 0
        total_count = 0
        for v in stats.get("nodes", {}).values():
            total_ms += v.get("total_ms", 0)
            total_count += v.get("count", 0)
        for v in stats.get("tools", {}).values():
            total_ms += v.get("total_duration", 0) * 1000
            total_count += v.get("total_executions", 0)

        avg_duration = total_ms / max(total_count, 1)

        self._history_data["hourly"][hour_key] = {
            "node_count": node_count,
            "llm_count": llm_count,
            "tool_count": tool_count,
            "avg_duration_ms": round(avg_duration, 2),
            "timestamp": now.isoformat()
        }

        # 清理过期的小时数据（保留24小时）
        self._cleanup_hourly_stats()

        # 检查是否需要更新日汇总
        self._check_daily_update()

        # 保存历史
        self._save_history()

    def _cleanup_hourly_stats(self):
        """清理过期的小时数据"""
        cutoff = datetime.now() - timedelta(hours=24)
        cutoff_key = cutoff.strftime("%Y-%m-%dT%H")

        keys_to_remove = [k for k in self._history_data["hourly"] if k < cutoff_key]
        for k in keys_to_remove:
            del self._history_data["hourly"][k]

    def _check_daily_update(self):
        """检查并更新日汇总"""
        today = datetime.now().strftime("%Y-%m-%d")

        if today in self._history_data["daily"]:
            return  # 今日已存在

        # 计算昨日汇总
        yesterday = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d")

        # 从小时数据聚合昨日数据
        yesterday_hours = [
            v for k, v in self._history_data["hourly"].items()
            if k.startswith(yesterday)
        ]

        if yesterday_hours:
            total_executions = sum(
                h.get("node_count", 0) + h.get("tool_count", 0)
                for h in yesterday_hours
            )

            # 计算成功率（从当前统计数据推断）
            nodes = self._stats_data.get("nodes", {})
            tools = self._stats_data.get("tools", {})

            total_success = sum(v.get("count", 0) - v.get("errors", 0) for v in nodes.values())
            total_success += sum(
                v.get("successful_executions", 0)
                for v in tools.values()
            )
            total_count = sum(v.get("count", 0) for v in nodes.values())
            total_count += sum(v.get("total_executions", 0) for v in tools.values())

            success_rate = (total_success / max(total_count, 1)) * 100

            # 计算慢操作数
            slow_ops = sum(1 for v in tools.values() if v.get("max_duration", 0) > 5)

            self._history_data["daily"][yesterday] = {
                "total_executions": total_executions,
                "success_rate": round(success_rate, 1),
                "slow_ops": slow_ops
            }

        # 清理过期的日数据（保留30天）
        cutoff = datetime.now() - timedelta(days=30)
        cutoff_date = cutoff.strftime("%Y-%m-%d")

        keys_to_remove = [k for k in self._history_data["daily"] if k < cutoff_date]
        for k in keys_to_remove:
            del self._history_data["daily"][k]

    def load(self) -> Dict[str, Any]:
        """加载统计数据"""
        with self._lock:
            return {
                "nodes": self._stats_data.get("nodes", {}),
                "llm": self._stats_data.get("llm", {}),
                "tools": self._stats_data.get("tools", {})
            }

    def get_history(self, days: int = 7) -> Dict[str, Any]:
        """
        获取历史趋势数据

        Args:
            days: 获取最近N天的数据

        Returns:
            {
                "hourly": [...],  # 最近24小时
                "daily": [...]    # 最近N天
            }
        """
        with self._lock:
            # 获取小时数据（最近24小时）
            hourly = sorted(
                [{"hour": k, **v} for k, v in self._history_data["hourly"].items()],
                key=lambda x: x["hour"]
            )

            # 获取日数据
            daily = sorted(
                [{"date": k, **v} for k, v in self._history_data["daily"].items()],
                key=lambda x: x["date"]
            )[-days:]

            return {
                "hourly": hourly,
                "daily": daily
            }

    def clear(self):
        """清除所有数据"""
        with self._lock:
            self._stats_data = {
                "nodes": {},
                "llm": {},
                "tools": {},
                "uptime_seconds": 0,
                "last_updated": None
            }
            self._history_data = {
                "hourly": {},
                "daily": {}
            }
            self._save_stats()
            self._save_history()


# 全局单例
_performance_persistence = None


def get_performance_persistence() -> PerformancePersistence:
    """获取性能持久化管理器单例"""
    global _performance_persistence
    if _performance_persistence is None:
        _performance_persistence = PerformancePersistence()
    return _performance_persistence