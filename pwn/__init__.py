# pwn/__init__.py
"""
Pwn模块 - 二进制漏洞利用支持

提供:
- 栈溢出检测与利用
- 堆利用（UAF, Double Free, Heap Overflow等）
- 格式化字符串漏洞
- ROP/ROPgadget链构建
- Shellcode生成
- 保护机制检测（ASLR, NX, PIE, Canary等）

设计原则:
1. 独立于其他模块
2. 可选启用
3. 共享CTFState状态
"""

from .nodes import (
    pwn_analyst_node,
    pwn_exploiter_node
)
from .tools import (
    BinaryAnalyzer,
    ProtectionChecker,
    ROPBuilder,
    ShellcodeGenerator,
    ExploitBuilder
)

__all__ = [
    # 节点
    'pwn_analyst_node',
    'pwn_exploiter_node',
    # 工具类
    'BinaryAnalyzer',
    'ProtectionChecker',
    'ROPBuilder',
    'ShellcodeGenerator',
    'ExploitBuilder'
]