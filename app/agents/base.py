# app/agents/base.py
"""Agent权限定义"""

from enum import Enum


class ToolPermission(Enum):
    """工具权限"""
    READ = "read"
    WRITE = "write"
    EXECUTE = "execute"
    NETWORK = "network"


__all__ = ["ToolPermission"]