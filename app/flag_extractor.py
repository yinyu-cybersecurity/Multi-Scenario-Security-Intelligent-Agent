#!/usr/bin/env python
"""
Flag Extractor - 增强的Flag提取器
支持多种编码格式和CTF平台的Flag格式
"""

import re
import base64
import codecs
from typing import List, Optional, Tuple


class FlagExtractor:
    """增强的Flag提取器"""

    # Flag正则模式 (按优先级排序)
    FLAG_PATTERNS = [
        # 标准格式
        (r"flag\{[a-zA-Z0-9_\-]+\}", "standard"),
        (r"FLAG\{[a-zA-Z0-9_\-]+\}", "standard_upper"),
        (r"ctf\{[a-zA-Z0-9_\-]+\}", "ctf"),
        (r"CTF\{[a-zA-Z0-9_\-]+\}", "ctf_upper"),

        # 各平台格式
        (r"NSSCTF\{[a-zA-Z0-9_\-]+\}", "nssctf"),
        (r"actf\{[a-zA-Z0-9_\-]+\}", "actf"),
        (r"hctf\{[a-zA-Z0-9_\-]+\}", "hctf"),
        (r"sctf\{[a-zA-Z0-9_\-]+\}", "sctf"),
        (r"bytectf\{[a-zA-Z0-9_\-]+\}", "bytectf"),
        (r"xctf\{[a-zA-Z0-9_\-]+\}", "xctf"),
        (r"qwb\{[a-zA-Z0-9_\-]+\}", "qwb"),
        (r"GWHT\{[a-zA-Z0-9_\-]+\}", "gwht"),
        (r"xyctf\{[a-zA-Z0-9_\-]+\}", "xyctf"),
        (r"d3ctf\{[a-zA-Z0-9_\-]+\}", "d3ctf"),
        (r"dozer\{[a-zA-Z0-9_\-]+\}", "dozer"),

        # 特殊格式 (可能包含特殊字符)
        (r"flag\{[^\}]{5,50}\}", "standard_loose"),
        (r"FLAG\{[^\}]{5,50}\}", "standard_loose_upper"),

        # 无花括号格式
        (r"flag[:=]\s*[a-zA-Z0-9_\-]{10,}", "no_braces"),
        (r"FLAG[:=]\s*[a-zA-Z0-9_\-]{10,}", "no_braces_upper"),
    ]

    # 编码检测模式
    ENCODING_PATTERNS = [
        (r'[A-Za-z0-9+/]{20,}={0,2}', 'base64'),
        (r'%[0-9A-Fa-f]{2}', 'url'),
        (r'\\x[0-9A-Fa-f]{2}', 'hex_escape'),
        (r'[0-9A-Fa-f]{40,}', 'hex'),
        (r'&#\d+;', 'html_entity'),
        (r'&#x[0-9A-Fa-f]+;', 'html_entity_hex'),
        (r'\\u[0-9A-Fa-f]{4}', 'unicode_escape'),
    ]

    def __init__(self):
        self.compiled_patterns = [(re.compile(p, re.IGNORECASE), name)
                                   for p, name in self.FLAG_PATTERNS]
        self.compiled_encoding = [(re.compile(p), name)
                                   for p, name in self.ENCODING_PATTERNS]

    def extract(self, text: str, decode: bool = True) -> List[Tuple[str, str]]:
        """
        提取所有可能的Flag

        Args:
            text: 要搜索的文本
            decode: 是否尝试解码编码内容

        Returns:
            [(flag, source), ...] 列表
        """
        flags = []
        seen = set()

        # 1. 直接匹配
        for pattern, name in self.compiled_patterns:
            matches = pattern.findall(text)
            for match in matches:
                if match not in seen:
                    flags.append((match, f"direct:{name}"))
                    seen.add(match)

        # 2. 如果启了解码，尝试解码后匹配
        if decode:
            decoded_flags = self._extract_from_encoded(text)
            for flag, source in decoded_flags:
                if flag not in seen:
                    flags.append((flag, source))
                    seen.add(flag)

        return flags

    def _extract_from_encoded(self, text: str) -> List[Tuple[str, str]]:
        """从编码内容中提取Flag"""
        flags = []

        # Base64解码
        b64_flags = self._try_base64(text)
        flags.extend(b64_flags)

        # URL解码
        url_flags = self._try_url_decode(text)
        flags.extend(url_flags)

        # 十六进制解码
        hex_flags = self._try_hex_decode(text)
        flags.extend(hex_flags)

        # Unicode解码
        unicode_flags = self._try_unicode_decode(text)
        flags.extend(unicode_flags)

        return flags

    def _try_base64(self, text: str) -> List[Tuple[str, str]]:
        """尝试Base64解码"""
        flags = []
        pattern = re.compile(r'[A-Za-z0-9+/]{20,}={0,2}')

        for match in pattern.findall(text):
            try:
                # 补齐padding
                padding = 4 - len(match) % 4
                if padding != 4:
                    match += '=' * padding

                decoded = base64.b64decode(match).decode('utf-8', errors='ignore')

                # 在解码后的内容中找Flag
                for pattern, name in self.compiled_patterns:
                    found = pattern.findall(decoded)
                    for f in found:
                        flags.append((f, f"base64:{name}"))

            except Exception as e:
                pass  # base64解码失败，继续尝试其他解码

        return flags

    def _try_url_decode(self, text: str) -> List[Tuple[str, str]]:
        """尝试URL解码"""
        flags = []
        try:
            from urllib.parse import unquote
            decoded = unquote(text)

            for pattern, name in self.compiled_patterns:
                found = pattern.findall(decoded)
                for f in found:
                    flags.append((f, f"url_decode:{name}"))
        except Exception:
            pass

        return flags

    def _try_hex_decode(self, text: str) -> List[Tuple[str, str]]:
        """尝试十六进制解码"""
        flags = []
        pattern = re.compile(r'\b[0-9A-Fa-f]{40,}\b')

        for match in pattern.findall(text):
            try:
                decoded = bytes.fromhex(match).decode('utf-8', errors='ignore')

                for pattern, name in self.compiled_patterns:
                    found = pattern.findall(decoded)
                    for f in found:
                        flags.append((f, f"hex_decode:{name}"))
            except Exception as e:
                pass  # base64解码失败，继续尝试其他解码

        return flags

    def _try_unicode_decode(self, text: str) -> List[Tuple[str, str]]:
        """尝试Unicode解码"""
        flags = []
        try:
            # \uXXXX 格式
            decoded = text.encode('utf-8').decode('unicode_escape')

            for pattern, name in self.compiled_patterns:
                found = pattern.findall(decoded)
                for f in found:
                    flags.append((f, f"unicode_decode:{name}"))
        except Exception:
            pass

        return flags

    def extract_first(self, text: str, decode: bool = True) -> Optional[str]:
        """提取第一个找到的Flag"""
        flags = self.extract(text, decode)
        return flags[0][0] if flags else None

    def has_flag(self, text: str) -> bool:
        """检查是否包含Flag"""
        return len(self.extract(text, decode=False)) > 0

    def get_flag_info(self, text: str) -> dict:
        """获取Flag详细信息"""
        flags = self.extract(text)

        return {
            "found": len(flags) > 0,
            "count": len(flags),
            "flags": [f[0] for f in flags],
            "sources": [f[1] for f in flags],
            "first_flag": flags[0][0] if flags else None
        }


# 全局实例
flag_extractor = FlagExtractor()


def extract_flags(text: str, decode: bool = True) -> List[str]:
    """便捷函数：提取所有Flag"""
    return [f[0] for f in flag_extractor.extract(text, decode)]


def extract_first_flag(text: str) -> Optional[str]:
    """便捷函数：提取第一个Flag"""
    return flag_extractor.extract_first(text)


def check_for_flag(text: str) -> bool:
    """便捷函数：检查是否有Flag"""
    return flag_extractor.has_flag(text)