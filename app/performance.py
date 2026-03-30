# performance.py
"""
性能优化与监控模块

提供:
- 节点执行耗时统计
- LLM调用耗时统计
- 工具执行耗时统计
- 并行工具执行
- 内存使用监控
- 实时性能数据
- 持久化存储（降采样策略）
"""

import time
import threading
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from collections import defaultdict
from datetime import datetime
from contextlib import contextmanager
import psutil
import os

from logger import get_logger

logger = get_logger("Performance")

# 尝试导入持久化模块
try:
    from memory.performance_persistence import get_performance_persistence
    PERSISTENCE_AVAILABLE = True
except ImportError:
    PERSISTENCE_AVAILABLE = False


@dataclass
class PerformanceMetrics:
    """性能指标"""
    total_executions: int = 0
    successful_executions: int = 0
    failed_executions: int = 0
    total_duration: float = 0.0
    avg_duration: float = 0.0
    max_duration: float = 0.0
    min_duration: float = float('inf')
    cache_hits: int = 0
    cache_misses: int = 0
    timeout_count: int = 0

    def update(self, duration: float, success: bool, cached: bool = False, timeout: bool = False):
        self.total_executions += 1
        if cached:
            self.cache_hits += 1
        else:
            self.cache_misses += 1
        if success:
            self.successful_executions += 1
        else:
            self.failed_executions += 1
        if timeout:
            self.timeout_count += 1
        self.total_duration += duration
        self.avg_duration = self.total_duration / self.total_executions
        self.max_duration = max(self.max_duration, duration)
        self.min_duration = min(self.min_duration, duration)


@dataclass
class ExecutionRecord:
    """执行记录"""
    name: str
    category: str  # node, llm, tool
    start_time: float
    end_time: float = 0
    duration_ms: float = 0
    success: bool = True
    error: str = ""


class PerformanceMonitor:
    """
    性能监控器

    监控工具执行性能，提供统计信息
    支持：节点、LLM调用、工具执行

    内存安全:
    - MAX_RECORDS: 最多保留500条原始记录
    - 自动清理旧记录

    持久化:
    - 统计数据自动保存
    - 服务重启后恢复历史数据
    """

    _instance = None
    _lock = threading.Lock()

    # 内存限制
    MAX_RECORDS = 500  # 最多保留500条原始记录
    SAVE_INTERVAL = 30  # 每30秒保存一次统计数据

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._metrics = defaultdict(PerformanceMetrics)
                    cls._instance._start_time = time.time()
                    cls._instance._records: List[ExecutionRecord] = []
                    cls._instance._node_stats = defaultdict(lambda: {"count": 0, "total_ms": 0, "max_ms": 0, "errors": 0})
                    cls._instance._llm_stats = defaultdict(lambda: {"count": 0, "total_ms": 0, "max_ms": 0, "errors": 0, "tokens": 0})
                    cls._instance._last_save_time = time.time()
                    # 加载历史数据
                    cls._instance._load_persistence()
        return cls._instance

    def _load_persistence(self):
        """从持久化存储加载历史数据"""
        if not PERSISTENCE_AVAILABLE:
            return

        try:
            persistence = get_performance_persistence()
            data = persistence.load()
            if data:
                # 恢复节点统计
                for name, stats in data.get("nodes", {}).items():
                    self._node_stats[name] = stats.copy()
                # 恢复LLM统计
                for name, stats in data.get("llm", {}).items():
                    self._llm_stats[name] = stats.copy()
                # 恢复工具统计
                for name, stats in data.get("tools", {}).items():
                    self._metrics[name] = PerformanceMetrics(
                        total_executions=stats.get("total_executions", 0),
                        successful_executions=stats.get("successful_executions", 0),
                        failed_executions=stats.get("failed_executions", 0),
                        total_duration=stats.get("total_duration", 0),
                        avg_duration=stats.get("avg_duration", 0),
                        max_duration=stats.get("max_duration", 0),
                        min_duration=stats.get("min_duration", float('inf')),
                        cache_hits=stats.get("cache_hits", 0),
                        cache_misses=stats.get("cache_misses", 0),
                        timeout_count=stats.get("timeout_count", 0)
                    )
                logger.info(f"已加载历史数据: {len(self._node_stats)} 节点, {len(self._llm_stats)} LLM, {len(self._metrics)} 工具")
        except Exception as e:
            logger.warning(f"加载历史数据失败: {e}")

    def _save_persistence(self):
        """保存统计数据到持久化存储"""
        if not PERSISTENCE_AVAILABLE:
            return

        # 节流：避免频繁保存
        if time.time() - self._last_save_time < self.SAVE_INTERVAL:
            return

        try:
            persistence = get_performance_persistence()
            persistence.save({
                "nodes": dict(self._node_stats),
                "llm": dict(self._llm_stats),
                "tools": {k: v.__dict__ for k, v in self._metrics.items()},
                "uptime_seconds": time.time() - self._start_time
            })
            self._last_save_time = time.time()
        except Exception as e:
            logger.warning(f"保存数据失败: {e}")

    def _trim_records(self):
        """清理旧记录，保持内存安全"""
        if len(self._records) > self.MAX_RECORDS:
            self._records = self._records[-self.MAX_RECORDS:]

    def record_execution(self, tool_name: str, duration: float,
                        success: bool, cached: bool = False, timeout: bool = False):
        """记录工具执行"""
        with self._lock:
            self._metrics[tool_name].update(duration, success, cached, timeout)
            # 添加记录
            self._records.append(ExecutionRecord(
                name=tool_name, category="tool", start_time=time.time(),
                end_time=time.time(), duration_ms=duration * 1000, success=success
            ))
            self._trim_records()
            # 保存到持久化
            self._save_persistence()

    @contextmanager
    def track_node(self, node_name: str):
        """跟踪节点执行"""
        start = time.time()
        error = ""
        success = True
        try:
            yield
        except Exception as e:
            error = str(e)
            success = False
            raise
        finally:
            duration_ms = (time.time() - start) * 1000
            with self._lock:
                self._records.append(ExecutionRecord(
                    name=node_name, category="node", start_time=start,
                    end_time=time.time(), duration_ms=duration_ms, success=success, error=error
                ))
                self._trim_records()
                stats = self._node_stats[node_name]
                stats["count"] += 1
                stats["total_ms"] += duration_ms
                stats["max_ms"] = max(stats["max_ms"], duration_ms)
                if not success:
                    stats["errors"] += 1
                self._save_persistence()

    @contextmanager
    def track_llm(self, model: str, tokens: int = 0):
        """跟踪LLM调用"""
        start = time.time()
        error = ""
        success = True
        try:
            yield
        except Exception as e:
            error = str(e)
            success = False
            raise
        finally:
            duration_ms = (time.time() - start) * 1000
            with self._lock:
                self._records.append(ExecutionRecord(
                    name=model, category="llm", start_time=start,
                    end_time=time.time(), duration_ms=duration_ms, success=success, error=error
                ))
                self._trim_records()
                stats = self._llm_stats[model]
                stats["count"] += 1
                stats["total_ms"] += duration_ms
                stats["max_ms"] = max(stats["max_ms"], duration_ms)
                stats["tokens"] += tokens
                if not success:
                    stats["errors"] += 1
                self._save_persistence()

    def record_llm_call(self, model: str, duration_ms: float, tokens: int = 0, success: bool = True):
        """记录LLM调用（手动方式）"""
        with self._lock:
            self._records.append(ExecutionRecord(
                name=model, category="llm", start_time=time.time(),
                end_time=time.time(), duration_ms=duration_ms, success=success
            ))
            self._trim_records()
            stats = self._llm_stats[model]
            stats["count"] += 1
            stats["total_ms"] += duration_ms
            stats["max_ms"] = max(stats["max_ms"], duration_ms)
            stats["tokens"] += tokens
            if not success:
                stats["errors"] += 1
            self._save_persistence()

    def get_metrics(self, tool_name: str = None) -> Dict:
        """获取性能指标"""
        with self._lock:
            if tool_name:
                return self._metrics.get(tool_name, PerformanceMetrics()).__dict__
            return {k: v.__dict__ for k, v in self._metrics.items()}

    def get_summary(self) -> Dict:
        """获取性能摘要"""
        with self._lock:
            total = PerformanceMetrics()
            for metrics in self._metrics.values():
                total.total_executions += metrics.total_executions
                total.successful_executions += metrics.successful_executions
                total.failed_executions += metrics.failed_executions
                total.cache_hits += metrics.cache_hits
                total.cache_misses += metrics.cache_misses
                total.timeout_count += metrics.timeout_count

            uptime = time.time() - self._start_time

            return {
                "uptime_seconds": uptime,
                "total_executions": total.total_executions,
                "success_rate": total.successful_executions / max(total.total_executions, 1) * 100,
                "cache_hit_rate": total.cache_hits / max(total.total_executions, 1) * 100,
                "timeout_rate": total.timeout_count / max(total.total_executions, 1) * 100,
                "executions_per_minute": total.total_executions / max(uptime / 60, 1)
            }

    def get_full_stats(self) -> Dict:
        """获取完整统计信息"""
        with self._lock:
            process = psutil.Process()
            memory_mb = process.memory_info().rss / 1024 / 1024
            uptime = time.time() - self._start_time

            return {
                "uptime_seconds": round(uptime, 1),
                "memory_mb": round(memory_mb, 1),
                "total_records": len(self._records),
                "nodes": {k: {
                    "count": v["count"],
                    "avg_ms": round(v["total_ms"] / max(v["count"], 1), 2),
                    "max_ms": round(v["max_ms"], 2),
                    "total_ms": round(v["total_ms"], 2),
                    "errors": v["errors"]
                } for k, v in self._node_stats.items()},
                "llm": {k: {
                    "count": v["count"],
                    "avg_ms": round(v["total_ms"] / max(v["count"], 1), 2),
                    "max_ms": round(v["max_ms"], 2),
                    "total_ms": round(v["total_ms"], 2),
                    "tokens": v["tokens"],
                    "errors": v["errors"]
                } for k, v in self._llm_stats.items()},
                "tools": {k: v.__dict__ for k, v in self._metrics.items()},
            }

    def get_recent_records(self, limit: int = 50) -> List[Dict]:
        """获取最近的执行记录"""
        with self._lock:
            recent = self._records[-limit:] if len(self._records) > limit else self._records
            return [
                {
                    "name": r.name,
                    "category": r.category,
                    "duration_ms": round(r.duration_ms, 2),
                    "success": r.success,
                    "error": r.error[:100] if r.error else "",
                    "time": datetime.fromtimestamp(r.start_time).strftime("%H:%M:%S"),
                }
                for r in recent
            ]

    def get_slow_operations(self, threshold_ms: float = 5000) -> List[Dict]:
        """获取慢操作列表"""
        with self._lock:
            slow = [
                {
                    "name": r.name,
                    "category": r.category,
                    "duration_ms": round(r.duration_ms, 2),
                    "time": datetime.fromtimestamp(r.start_time).strftime("%H:%M:%S"),
                }
                for r in self._records
                if r.duration_ms >= threshold_ms
            ]
            return sorted(slow, key=lambda x: x["duration_ms"], reverse=True)[:20]

    def reset(self):
        """重置监控器"""
        with self._lock:
            self._metrics.clear()
            self._records.clear()
            self._node_stats.clear()
            self._llm_stats.clear()
            self._start_time = time.time()
            self._last_save_time = time.time()
            # 清除持久化数据
            if PERSISTENCE_AVAILABLE:
                try:
                    persistence = get_performance_persistence()
                    persistence.clear()
                except Exception as e:
                    logger.warning(f"清除持久化数据失败: {e}")




class ResourceLimiter:
    """
    资源限制器

    监控和限制系统资源使用
    """

    def __init__(self, max_memory_mb: int = 4096, max_cpu_percent: float = 80):
        self.max_memory_mb = max_memory_mb
        self.max_cpu_percent = max_cpu_percent
        self._process = psutil.Process(os.getpid())

    def check_resources(self) -> Dict:
        """检查资源使用情况"""
        memory_info = self._process.memory_info()
        cpu_percent = self._process.cpu_percent(interval=0.1)

        return {
            "memory_mb": memory_info.rss / 1024 / 1024,
            "cpu_percent": cpu_percent,
            "memory_limit_mb": self.max_memory_mb,
            "cpu_limit_percent": self.max_cpu_percent,
            "memory_ok": memory_info.rss / 1024 / 1024 < self.max_memory_mb,
            "cpu_ok": cpu_percent < self.max_cpu_percent
        }

    def is_resource_available(self) -> bool:
        """检查资源是否可用"""
        resources = self.check_resources()
        return resources["memory_ok"] and resources["cpu_ok"]

    def wait_for_resources(self, timeout: float = 60) -> bool:
        """等待资源可用"""
        start_time = time.time()
        while time.time() - start_time < timeout:
            if self.is_resource_available():
                return True
            time.sleep(1)
        return False


class AdaptiveTimeout:
    """
    自适应超时管理

    根据历史执行时间自动调整超时值
    """

    def __init__(self, initial_timeout: float = 60, min_timeout: float = 10, max_timeout: float = 300):
        self.initial_timeout = initial_timeout
        self.min_timeout = min_timeout
        self.max_timeout = max_timeout
        self._execution_times = defaultdict(list)
        self._lock = threading.Lock()

    def record_execution_time(self, tool_name: str, duration: float):
        """记录执行时间"""
        with self._lock:
            self._execution_times[tool_name].append(duration)
            # 只保留最近20次
            if len(self._execution_times[tool_name]) > 20:
                self._execution_times[tool_name] = self._execution_times[tool_name][-20:]

    def get_timeout(self, tool_name: str) -> float:
        """获取建议的超时时间"""
        with self._lock:
            times = self._execution_times.get(tool_name, [])

            if not times:
                return self.initial_timeout

            # 使用P95作为超时基准
            sorted_times = sorted(times)
            p95_index = int(len(sorted_times) * 0.95)
            p95_time = sorted_times[p95_index]

            # 添加安全边际（1.5倍）
            suggested_timeout = p95_time * 1.5

            # 限制在范围内
            return max(self.min_timeout, min(suggested_timeout, self.max_timeout))


# 全局实例
performance_monitor = PerformanceMonitor()
adaptive_timeout = AdaptiveTimeout()


