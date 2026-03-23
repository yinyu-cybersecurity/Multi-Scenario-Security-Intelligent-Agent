# memory/__init__.py
"""
Memory模块 - 三层记忆系统

提供:
- 工作记忆: 当前任务状态
- 文件记忆: 持久化存储
- RAG知识检索: 向量数据库检索
"""

from .memory_manager import MemoryManager

__all__ = ['MemoryManager']