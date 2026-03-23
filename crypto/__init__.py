# crypto/__init__.py
"""
Crypto模块 - CTF密码学方向支持

提供:
- 加密算法识别
- 常见编码解码 (Base64, Hex, URL, etc.)
- 古典密码破解 (Caesar, Vigenere, XOR, etc.)
- 现代密码分析 (RSA, AES, etc.)
- Hash识别与破解

设计原则:
1. 独立于Web CTF和内网渗透模块
2. 可选启用
3. 共享CTFState状态
"""

from .nodes import (
    crypto_analyst_node,
    crypto_solver_node
)
from .tools import (
    CryptoIdentifier,
    EncodingDecoder,
    ClassicalCipherSolver,
    ModernCryptoSolver,
    HashAnalyzer
)

__all__ = [
    # 节点
    'crypto_analyst_node',
    'crypto_solver_node',
    # 工具类
    'CryptoIdentifier',
    'EncodingDecoder',
    'ClassicalCipherSolver',
    'ModernCryptoSolver',
    'HashAnalyzer'
]