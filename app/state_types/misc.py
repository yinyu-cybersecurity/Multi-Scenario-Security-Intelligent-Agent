# app/state_types/misc.py
"""
Misc CTF 状态定义

杂项场景专用字段。

设计原则:
- 继承 BaseCTFState 的通用字段
- 只添加 Misc 场景特有的字段
"""

from typing import Annotated, List, Dict, Literal, Any, Optional
from typing_extensions import TypedDict


class StegInfo(TypedDict):
    """隐写信息"""
    carrier_type: str  # 载体类型: png, jpg, bmp, wav, mp3
    method: str  # 隐写方法: lsb, dct, spread_spectrum
    extracted_data: bytes  # 提取的数据
    offset: int  # 偏移量


class MediaAnalysis(TypedDict):
    """媒体分析结果"""
    file_type: str  # 文件类型
    width: int  # 宽度（图片）
    height: int  # 高度（图片）
    bit_depth: int  # 位深
    channels: int  # 通道数
    metadata: Dict[str, str]  # 元数据
    has_alpha: bool  # 是否有透明通道


class ForensicInfo(TypedDict):
    """取证信息"""
    file_signature: str  # 文件签名
    magic_bytes: str  # 魔数
    embedded_files: List[str]  # 嵌入的文件
    deleted_data: bool  # 是否有已删除数据
    timeline: List[Dict[str, Any]]  # 时间线


class MiscCTFState(TypedDict):
    """
    Misc CTF 状态

    包含:
    - 文件分析结果
    - 隐写检测
    - 取证信息
    """

    # =========================================================================
    # 文件分析
    # =========================================================================

    # 分析的文件路径
    analyzed_file: str

    # 文件哈希
    file_hash: Dict[str, str]  # md5, sha1, sha256

    # 文件实际类型
    actual_file_type: str

    # 文件是否与扩展名匹配
    type_mismatch: bool

    # =========================================================================
    # 媒体分析
    # =========================================================================

    # 媒体分析结果
    media_info: Optional[MediaAnalysis]

    # 是否存在隐写
    has_steganography: bool

    # 隐写检测结果
    steg_results: List[StegInfo]

    # =========================================================================
    # 取证分析
    # =========================================================================

    # 取证信息
    forensic_info: Optional[ForensicInfo]

    # 提取的嵌入文件
    extracted_files: Annotated[List[str], lambda x, y: list(set(x + y))]

    # 数据恢复结果
    recovered_data: str

    # =========================================================================
    # 网络流量分析
    # =========================================================================

    # 流量分析结果
    traffic_analysis: Optional[Dict[str, Any]]

    # 提取的连接
    connections: List[Dict[str, Any]]

    # 提取的文件（从流量中）
    traffic_files: List[str]

    # =========================================================================
    # 编码/压缩
    # =========================================================================

    # 检测到的编码层
    encoding_layers: List[str]

    # 解码结果
    decoded_result: str

    # 压缩格式
    compression_format: str

    # =========================================================================
    # 其他杂项
    # =========================================================================

    # 特殊模式匹配结果
    pattern_matches: List[str]

    # 分析备注
    analysis_notes: str