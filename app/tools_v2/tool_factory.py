# app/tools_v2/tool_factory.py
"""工具参数定义 - 极简版"""

from dataclasses import dataclass
from typing import List, Any, Optional
from enum import Enum


class ParamType(Enum):
    STRING = "string"
    INTEGER = "integer"
    NUMBER = "number"
    BOOLEAN = "boolean"
    ARRAY = "array"
    OBJECT = "object"
    URI = "uri"
    PATH = "path"


@dataclass
class ParamSchema:
    """参数定义"""
    name: str
    type: ParamType
    required: bool = True
    description: str = ""
    default: Any = None


# 仅保留必要的导入支持
__all__ = ["ParamType", "ParamSchema"]