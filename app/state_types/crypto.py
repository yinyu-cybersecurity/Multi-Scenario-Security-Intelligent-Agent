# app/state_types/crypto.py
"""
密码学 CTF 状态定义

密码学场景专用字段。

设计原则:
- 继承 BaseCTFState 的通用字段
- 只添加密码学场景特有的字段
"""

from typing import Annotated, List, Dict, Literal, Any, Optional
from typing_extensions import TypedDict


class RSAParams(TypedDict):
    """RSA 参数结构"""
    n: int  # 模数
    e: int  # 公钥指数
    d: Optional[int]  # 私钥指数
    p: Optional[int]  # 质因数 p
    q: Optional[int]  # 质因数 q
    phi: Optional[int]  # 欧拉函数值


class CryptoCipher(TypedDict):
    """密码结构"""
    cipher_type: str  # 加密类型: rsa, aes, des, xor, etc.
    mode: str  # 加密模式: ecb, cbc, ctr, etc.
    key: Optional[str]  # 密钥
    iv: Optional[str]  # 初始向量
    plaintext: Optional[str]  # 明文
    ciphertext: str  # 密文


class CryptoCTFState(TypedDict):
    """
    密码学 CTF 状态

    包含:
    - 加密数据
    - 密码参数
    - 解密结果
    """

    # =========================================================================
    # 加密数据
    # =========================================================================

    # 加密数据列表
    cipher_data: List[CryptoCipher]

    # 当前分析的密码对象
    current_cipher: Optional[CryptoCipher]

    # =========================================================================
    # RSA 专用字段
    # =========================================================================

    # RSA 参数
    rsa_params: Optional[RSAParams]

    # 是否已分解 n
    n_factored: bool

    # =========================================================================
    # 密码分析结果
    # =========================================================================

    # 分析出的加密类型
    detected_cipher_type: str

    # 可能的攻击方法
    possible_attacks: List[str]

    # 已尝试的解密方法
    tried_methods: Annotated[List[str], lambda x, y: list(set(x + y))]

    # 解密结果
    decrypted_data: str

    # =========================================================================
    # 编码检测
    # =========================================================================

    # 检测到的编码类型
    detected_encoding: str  # base64, hex, ascii, etc.

    # 解码后的数据
    decoded_data: str

    # =========================================================================
    # 古典密码
    # =========================================================================

    # 古典密码类型
    classical_cipher: str  # caesar, vigenere, substitution, etc.

    # 密钥候选
    key_candidates: List[str]

    # 频率分析结果
    frequency_analysis: Dict[str, float]