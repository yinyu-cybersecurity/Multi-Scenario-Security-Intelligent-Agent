# performance.py
"""
性能优化模块

提供:
- 并行工具执行
- 性能监控
- 资源限制
- 自适应超时
"""

import time
import threading
import concurrent.futures
from typing import Dict, List, Any, Callable, Optional
from dataclasses import dataclass, field
from collections import defaultdict
import psutil
import os


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


class PerformanceMonitor:
    """
    性能监控器

    监控工具执行性能，提供统计信息
    """

    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._metrics = defaultdict(PerformanceMetrics)
                    cls._instance._start_time = time.time()
        return cls._instance

    def record_execution(self, tool_name: str, duration: float,
                        success: bool, cached: bool = False, timeout: bool = False):
        """记录工具执行"""
        with self._lock:
            self._metrics[tool_name].update(duration, success, cached, timeout)

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

    def reset(self):
        """重置监控器"""
        with self._lock:
            self._metrics.clear()
            self._start_time = time.time()


class ParallelExecutor:
    """
    并行执行器

    支持并行执行多个工具或攻击
    """

    def __init__(self, max_workers: int = 4):
        self.max_workers = max_workers
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=max_workers)
        self.monitor = PerformanceMonitor()

    def execute_parallel(self, tasks: List[Dict]) -> List[Dict]:
        """
        并行执行多个任务

        Args:
            tasks: 任务列表，每个任务包含:
                - name: 任务名称
                - func: 执行函数
                - args: 参数字典

        Returns:
            结果列表
        """
        futures = {}
        results = []

        for task in tasks:
            name = task.get("name", "unknown")
            func = task.get("func")
            args = task.get("args", {})

            if not func:
                continue

            future = self.executor.submit(self._execute_with_monitor, name, func, args)
            futures[future] = name

        # 收集结果
        for future in concurrent.futures.as_completed(futures):
            name = futures[future]
            try:
                result = future.result(timeout=300)  # 5分钟超时
                results.append({"name": name, "result": result, "success": True})
            except Exception as e:
                results.append({"name": name, "error": str(e), "success": False})

        return results

    def _execute_with_monitor(self, name: str, func: Callable, args: Dict) -> Any:
        """带监控的执行"""
        start_time = time.time()
        success = False
        timeout = False

        try:
            result = func(**args)
            success = True
            return result
        except TimeoutError:
            timeout = True
            raise
        finally:
            duration = time.time() - start_time
            self.monitor.record_execution(name, duration, success, timeout=timeout)

    def shutdown(self):
        """关闭执行器"""
        self.executor.shutdown(wait=True)


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


def get_system_status() -> Dict:
    """获取系统状态"""
    try:
        limiter = ResourceLimiter()
        resources = limiter.check_resources()
        monitor_summary = performance_monitor.get_summary()

        return {
            "resources": resources,
            "performance": monitor_summary,
            "status": "healthy" if resources["memory_ok"] and resources["cpu_ok"] else "warning"
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}