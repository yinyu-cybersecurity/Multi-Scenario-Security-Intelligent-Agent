# app/task_cancel_manager.py
"""
任务取消管理器 - 实现真正的任务中断

功能:
- 维护全局取消状态注册表
- 支持线程安全的取消检查
- 集成到工作流节点边界检查

使用方式:
    from task_cancel_manager import cancel_manager

    # 注册取消
    cancel_manager.request_cancel(task_id)

    # 检查是否取消
    if cancel_manager.is_cancelled(task_id):
        raise TaskCancelledError(task_id)
"""

import threading
from typing import Dict, Set, Optional
from logger import get_logger

logger = get_logger("TaskCancel")


class TaskCancelledError(Exception):
    """任务被取消的异常，用于中断工作流"""
    def __init__(self, task_id: str):
        self.task_id = task_id
        super().__init__(f"Task {task_id} was cancelled by user")


class TaskCancelManager:
    """
    任务取消管理器

    线程安全的单例模式，管理所有任务的取消状态
    """

    def __init__(self):
        self._cancelled: Set[str] = set()
        self._lock = threading.RLock()
        self._current_task: Optional[str] = None
        self._task_lock = threading.local()

    def request_cancel(self, task_id: str) -> bool:
        """
        请求取消任务

        Args:
            task_id: 任务ID

        Returns:
            是否成功标记取消
        """
        with self._lock:
            self._cancelled.add(task_id)
            logger.info(f"[CancelManager] 任务 {task_id} 已标记为取消")
            return True

    def is_cancelled(self, task_id: str) -> bool:
        """
        检查任务是否被取消

        Args:
            task_id: 任务ID

        Returns:
            是否被取消
        """
        with self._lock:
            return task_id in self._cancelled

    def clear_cancel(self, task_id: str) -> bool:
        """
        清除取消标记（用于任务完成后清理）

        Args:
            task_id: 任务ID

        Returns:
            是否成功清除
        """
        with self._lock:
            if task_id in self._cancelled:
                self._cancelled.remove(task_id)
                logger.debug(f"[CancelManager] 任务 {task_id} 取消标记已清除")
                return True
            return False

    def get_all_cancelled(self) -> Set[str]:
        """获取所有已取消的任务ID"""
        with self._lock:
            return self._cancelled.copy()

    def check_and_raise(self, task_id: str) -> None:
        """
        检查取消状态并在已取消时抛出异常

        用于节点边界检查，快速中断执行

        Args:
            task_id: 任务ID

        Raises:
            TaskCancelledError: 如果任务已被取消
        """
        if self.is_cancelled(task_id):
            logger.info(f"[CancelManager] 检测到取消信号，中断任务 {task_id}")
            raise TaskCancelledError(task_id)

    def set_current_task(self, task_id: Optional[str]) -> None:
        """
        设置当前线程正在执行的任务ID

        用于线程局部存储，确保多任务并发时的正确性

        Args:
            task_id: 任务ID或None（清除）
        """
        self._task_lock.task_id = task_id

    def get_current_task(self) -> Optional[str]:
        """
        获取当前线程正在执行的任务ID

        Returns:
            当前任务ID或None
        """
        return getattr(self._task_lock, 'task_id', None)

    def check_current_task(self) -> None:
        """
        检查当前线程的任务取消状态

        Raises:
            TaskCancelledError: 如果当前任务已被取消
        """
        task_id = self.get_current_task()
        if task_id:
            self.check_and_raise(task_id)


# 全局单例
cancel_manager = TaskCancelManager()