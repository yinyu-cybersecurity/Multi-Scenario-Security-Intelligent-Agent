# reverse/__init__.py
"""
逆向模块 - 二进制逆向分析支持

提供:
- 反汇编分析
- 反编译支持
- 调试辅助
- 字符串与数据提取
- 算法识别
- 关键函数定位

设计原则:
1. 独立于其他模块
2. 可选启用
3. 共享CTFState状态
"""

from .nodes import (
    reverse_analyst_node,
    reverse_decompiler_node
)
from .tools import (
    Disassembler,
    Decompiler,
    StringExtractor,
    FunctionAnalyzer,
    PatternMatcher
)

__all__ = [
    # 节点
    'reverse_analyst_node',
    'reverse_decompiler_node',
    # 工具类
    'Disassembler',
    'Decompiler',
    'StringExtractor',
    'FunctionAnalyzer',
    'PatternMatcher'
]