# app/state_types/pwn.py
"""
Pwn CTF 状态定义

二进制漏洞利用场景专用字段。

设计原则:
- 继承 BaseCTFState 的通用字段
- 只添加 Pwn 场景特有的字段
"""

from typing import Annotated, List, Dict, Literal, Any, Optional
from typing_extensions import TypedDict


class BinaryInfo(TypedDict):
    """二进制文件信息"""
    path: str  # 文件路径
    arch: str  # 架构: x86, x64, arm, mips
    bits: int  # 位数: 32, 64
    endian: str  # 字节序: little, big
    protections: Dict[str, bool]  # 保护机制: nx, pie, canary, relro
    linked_libs: List[str]  # 链接库


class GadgetInfo(TypedDict):
    """ROP Gadget 信息"""
    address: int  # 地址
    instruction: str  # 指令
    category: str  # 分类: pop, mov, syscall, etc.


class ExploitScript(TypedDict):
    """漏洞利用脚本"""
    name: str  # 脚本名称
    language: str  # 语言: python, pwntools, etc.
    code: str  # 脚本代码
    target: str  # 目标地址
    port: int  # 目标端口


class PwnCTFState(TypedDict):
    """
    Pwn CTF 状态

    包含:
    - 二进制信息
    - 漏洞分析结果
    - 利用脚本
    """

    # =========================================================================
    # 二进制文件信息
    # =========================================================================

    # 二进制文件信息
    binary_info: Optional[BinaryInfo]

    # 文件是否已分析
    binary_analyzed: bool

    # =========================================================================
    # 漏洞分析
    # =========================================================================

    # 发现的漏洞类型
    vuln_types: Annotated[List[str], lambda x, y: list(set(x + y))]

    # 缓冲区溢出信息
    buffer_overflow: Optional[Dict[str, Any]]

    # 格式化字符串漏洞信息
    format_string: Optional[Dict[str, Any]]

    # 堆漏洞信息
    heap_vuln: Optional[Dict[str, Any]]

    # =========================================================================
    # 内存布局
    # =========================================================================

    # PIE 基址
    pie_base: Optional[int]

    # Libc 基址
    libc_base: Optional[int]

    # 栈地址
    stack_addr: Optional[int]

    # 堆地址
    heap_addr: Optional[int]

    # =========================================================================
    # ROP / Gadget
    # =========================================================================

    # 找到的 ROP gadgets
    gadgets: List[GadgetInfo]

    # ROP 链
    rop_chain: Optional[List[int]]

    # =========================================================================
    # 漏洞利用
    # =========================================================================

    # 利用脚本
    exploit_script: Optional[ExploitScript]

    # 利用是否成功
    exploit_success: bool

    # 获取的 shell 类型
    shell_type: str  # local, remote, none

    # =========================================================================
    # 目标信息
    # =========================================================================

    # 目标地址
    target_host: str

    # 目标端口
    target_port: int

    # 是否为本地利用
    is_local: bool