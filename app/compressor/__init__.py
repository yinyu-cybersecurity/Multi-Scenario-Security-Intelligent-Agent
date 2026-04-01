# 压缩系统
#
# 借鉴Claude Code的Context Compression机制

from .smart_compressor import (
    SmartCompressor,
    CompressionStrategy,
    CompressionResult,
    get_compressor,
    compress_context,
)

__all__ = [
    "SmartCompressor",
    "CompressionStrategy",
    "CompressionResult",
    "get_compressor",
    "compress_context",
]