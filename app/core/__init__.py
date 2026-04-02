"""
CTF-Agent核心模块

包含:
- query: Claude Code Query循环
- QueryConfig: 查询配置类
"""

from app.core.query import query, QueryConfig

__all__ = [
    "query",
    "QueryConfig",
]