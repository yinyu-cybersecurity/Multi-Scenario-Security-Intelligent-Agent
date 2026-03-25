# app/state_types/reverse.py
"""
逆向 CTF 状态定义

逆向工程场景专用字段。

设计原则:
- 继承 BaseCTFState 的通用字段
- 只添加逆向场景特有的字段
"""

from typing import Annotated, List, Dict, Literal, Any, Optional
from typing_extensions import TypedDict


class FunctionInfo(TypedDict):
    """函数信息"""
    name: str  # 函数名
    address: int  # 地址
    size: int  # 大小
    called_by: List[str]  # 调用者
    calls: List[str]  # 被调用函数
    is_library: bool  # 是否为库函数


class StringInfo(TypedDict):
    """字符串信息"""
    value: str  # 字符串值
    address: int  # 地址
    xrefs: List[int]  # 引用地址
    is_unicode: bool  # 是否为 Unicode


class AntiDebugTechnique(TypedDict):
    """反调试技术"""
    name: str  # 名称
    address: int  # 地址
    technique_type: str  # 类型: int3, time_check, etc.
    bypass_method: str  # 绕过方法


class ReverseCTFState(TypedDict):
    """
    逆向 CTF 状态

    包含:
    - 二进制信息
    - 反编译结果
    - 反调试检测
    """

    # =========================================================================
    # 二进制文件信息
    # =========================================================================

    # 文件类型: pe, elf, apk, dex, etc.
    file_type: str

    # 编译器/打包器
    compiler: str

    # 是否加壳
    is_packed: bool

    # 加壳类型
    packer_type: str

    # 是否已脱壳
    unpacked: bool

    # =========================================================================
    # 反编译结果
    # =========================================================================

    # 反编译代码
    decompiled_code: str

    # 汇编代码
    disassembly: str

    # 函数列表
    functions: List[FunctionInfo]

    # 入口点
    entry_point: int

    # =========================================================================
    # 字符串信息
    # =========================================================================

    # 提取的字符串
    strings: List[StringInfo]

    # 有趣的字符串（可能包含 flag 或关键信息）
    interesting_strings: List[str]

    # =========================================================================
    # 反调试/混淆
    # =========================================================================

    # 检测到的反调试技术
    anti_debug: List[AntiDebugTechnique]

    # 是否存在混淆
    has_obfuscation: bool

    # 混淆类型
    obfuscation_types: List[str]

    # =========================================================================
    # 分析结果
    # =========================================================================

    # 关键函数（如验证函数）
    key_functions: List[str]

    # 算法识别结果
    detected_algorithms: List[str]

    # 分析摘要
    analysis_summary: str

    # =========================================================================
    # APK/DEX 专用（Android 逆向）
    # =========================================================================

    # 包名
    package_name: str

    # 主 Activity
    main_activity: str

    # 权限列表
    permissions: List[str]

    # Native 库
    native_libs: List[str]