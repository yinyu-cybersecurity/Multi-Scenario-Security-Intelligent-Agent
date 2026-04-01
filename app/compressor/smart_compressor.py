# 智能上下文压缩器
#
# 借鉴Claude Code的Context Compression机制
# 实现优先级压缩、Token估算、关键信息保留

from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
import json
from datetime import datetime

from app.state.state_v3 import Priority, ToolResult, Finding


class CompressionStrategy(Enum):
    """压缩策略"""
    AGGRESSIVE = "aggressive"    # 激进压缩，大幅减少Token
    BALANCED = "balanced"        # 平衡压缩，保留关键信息
    CONSERVATIVE = "conservative" # 保守压缩，尽量保留详情


@dataclass
class CompressionResult:
    """压缩结果"""
    compressed_content: str
    original_tokens: int
    compressed_tokens: int
    compression_ratio: float
    removed_items: List[str] = field(default_factory=list)
    preserved_items: List[str] = field(default_factory=list)


class SmartCompressor:
    """
    智能上下文压缩器

    借鉴Claude Code的Context Compression设计:
    - 优先级压缩（CRITICAL > HIGH > MEDIUM > LOW）
    - Token预算控制
    - 关键信息保留
    - 增量压缩

    核心功能:
    1. compress_messages - 压缩消息历史
    2. compress_tool_results - 压缩工具结果
    3. compress_findings - 压缩发现
    4. estimate_tokens - Token估算
    """

    # Token估算常数
    TOKENS_PER_CHAR = 0.25  # 平均每字符Token数（中英文混合）
    TOKENS_PER_MESSAGE_OVERHEAD = 10  # 消息结构开销

    def __init__(
        self,
        strategy: CompressionStrategy = CompressionStrategy.BALANCED,
        max_tokens: int = 100000
    ):
        self.strategy = strategy
        self.max_tokens = max_tokens

        # 压缩阈值配置
        self.compression_thresholds = {
            CompressionStrategy.AGGRESSIVE: 0.7,   # 压缩70%
            CompressionStrategy.BALANCED: 0.5,     # 压缩50%
            CompressionStrategy.CONSERVATIVE: 0.3, # 压缩30%
        }

    def compress_messages(
        self,
        messages: List[Dict],
        keep_recent: int = 5
    ) -> CompressionResult:
        """
        压缩消息历史

        策略:
        - 保留最近N条消息完整
        - 早期消息压缩为摘要
        - CRITICAL优先级消息永不压缩

        Args:
            messages: 消息列表
            keep_recent: 保留最近N条完整消息

        Returns:
            CompressionResult
        """
        if not messages:
            return CompressionResult(
                compressed_content="",
                original_tokens=0,
                compressed_tokens=0,
                compression_ratio=0
            )

        original_tokens = self._estimate_messages_tokens(messages)

        # 分割消息
        recent_messages = messages[-keep_recent:] if len(messages) > keep_recent else messages
        old_messages = messages[:-keep_recent] if len(messages) > keep_recent else []

        compressed_parts = []
        preserved_items = []
        removed_items = []

        # 压缩早期消息
        if old_messages:
            summary = self._summarize_old_messages(old_messages)
            compressed_parts.append(f"[历史摘要]\n{summary}")
            removed_items.append(f"{len(old_messages)}条早期消息压缩为摘要")

        # 保留最近消息
        for msg in recent_messages:
            content = self._extract_message_content(msg)
            if content:
                compressed_parts.append(content)
                preserved_items.append(f"消息: {msg.get('role', 'unknown')}")

        # 组装压缩结果
        compressed_content = "\n\n".join(compressed_parts)
        compressed_tokens = self._estimate_text_tokens(compressed_content)

        compression_ratio = 1 - (compressed_tokens / original_tokens) if original_tokens > 0 else 0

        return CompressionResult(
            compressed_content=compressed_content,
            original_tokens=original_tokens,
            compressed_tokens=compressed_tokens,
            compression_ratio=compression_ratio,
            removed_items=removed_items,
            preserved_items=preserved_items
        )

    def compress_tool_results(
        self,
        tool_results: List[ToolResult],
        preserve_errors: bool = True
    ) -> CompressionResult:
        """
        压缩工具结果

        策略:
        - 保留错误结果（用于调试）
        - 成功结果压缩为摘要
        - 按优先级压缩

        Args:
            tool_results: 工具结果列表
            preserve_errors: 是否保留错误详情

        Returns:
            CompressionResult
        """
        if not tool_results:
            return CompressionResult(
                compressed_content="",
                original_tokens=0,
                compressed_tokens=0,
                compression_ratio=0
            )

        original_tokens = sum(
            self._estimate_text_tokens(str(r.output))
            for r in tool_results
        )

        compressed_parts = []
        preserved_items = []
        removed_items = []

        # 按优先级分组
        critical_results = [r for r in tool_results if r.priority == Priority.CRITICAL]
        high_results = [r for r in tool_results if r.priority == Priority.HIGH]
        medium_results = [r for r in tool_results if r.priority == Priority.MEDIUM]
        low_results = [r for r in tool_results if r.priority == Priority.LOW]

        # CRITICAL：完整保留
        for result in critical_results:
            compressed_parts.append(f"[CRITICAL] {result.tool_name}:\n{result.output}")
            preserved_items.append(f"CRITICAL: {result.tool_name}")

        # HIGH：保留关键信息
        for result in high_results:
            summary = self._extract_key_info(result.output)
            compressed_parts.append(f"[HIGH] {result.tool_name}:\n{summary}")
            preserved_items.append(f"HIGH: {result.tool_name}")

        # MEDIUM：压缩为摘要
        if medium_results:
            summary = self._summarize_tool_results(medium_results)
            compressed_parts.append(f"[MEDIUM摘要]\n{summary}")
            removed_items.append(f"{len(medium_results)}条MEDIUM结果压缩")

        # LOW：仅保留统计
        if low_results:
            stats = f"{len(low_results)}个低优先级结果"
            compressed_parts.append(f"[LOW统计]\n{stats}")
            removed_items.append(f"{len(low_results)}条LOW结果压缩为统计")

        # 保留错误
        if preserve_errors:
            error_results = [r for r in tool_results if r.error]
            for result in error_results:
                compressed_parts.append(f"[错误] {result.tool_name}:\n{result.error}")
                preserved_items.append(f"错误: {result.tool_name}")

        compressed_content = "\n\n".join(compressed_parts)
        compressed_tokens = self._estimate_text_tokens(compressed_content)

        compression_ratio = 1 - (compressed_tokens / original_tokens) if original_tokens > 0 else 0

        return CompressionResult(
            compressed_content=compressed_content,
            original_tokens=original_tokens,
            compressed_tokens=compressed_tokens,
            compression_ratio=compression_ratio,
            removed_items=removed_items,
            preserved_items=preserved_items
        )

    def compress_findings(
        self,
        findings: List[Finding]
    ) -> CompressionResult:
        """
        压缩发现

        策略:
        - 保留所有Flag发现
        - 保留高置信度漏洞
        - 合并相似发现

        Args:
            findings: 发现列表

        Returns:
            CompressionResult
        """
        if not findings:
            return CompressionResult(
                compressed_content="",
                original_tokens=0,
                compressed_tokens=0,
                compression_ratio=0
            )

        original_tokens = sum(
            self._estimate_text_tokens(str(f.content))
            for f in findings
        )

        compressed_parts = []
        preserved_items = []
        removed_items = []

        # 按类型分组
        flags = [f for f in findings if f.finding_type == "flag"]
        vulns = [f for f in findings if f.finding_type == "vuln"]
        credentials = [f for f in findings if f.finding_type == "credential"]
        others = [f for f in findings if f.finding_type not in ["flag", "vuln", "credential"]]

        # Flag：完整保留
        for finding in flags:
            compressed_parts.append(f"[FLAG]\n{json.dumps(finding.content, ensure_ascii=False)}")
            preserved_items.append(f"FLAG: {finding.finding_id}")

        # 漏洞：按置信度筛选
        high_confidence_vulns = [v for v in vulns if v.confidence >= 0.8]
        for finding in high_confidence_vulns:
            compressed_parts.append(f"[漏洞-高置信度]\n{json.dumps(finding.content, ensure_ascii=False)}")
            preserved_items.append(f"漏洞: {finding.finding_id}")

        if len(vulns) > len(high_confidence_vulns):
            removed_items.append(f"{len(vulns) - len(high_confidence_vulns)}个低置信度漏洞省略")

        # 凭据：完整保留
        for finding in credentials:
            compressed_parts.append(f"[凭据]\n{json.dumps(finding.content, ensure_ascii=False)}")
            preserved_items.append(f"凭据: {finding.finding_id}")

        # 其他：压缩摘要
        if others:
            summary = self._summarize_other_findings(others)
            compressed_parts.append(f"[其他发现摘要]\n{summary}")
            removed_items.append(f"{len(others)}条其他发现压缩为摘要")

        compressed_content = "\n\n".join(compressed_parts)
        compressed_tokens = self._estimate_text_tokens(compressed_content)

        compression_ratio = 1 - (compressed_tokens / original_tokens) if original_tokens > 0 else 0

        return CompressionResult(
            compressed_content=compressed_content,
            original_tokens=original_tokens,
            compressed_tokens=compressed_tokens,
            compression_ratio=compression_ratio,
            removed_items=removed_items,
            preserved_items=preserved_items
        )

    def estimate_tokens(self, content: Any) -> int:
        """
        Token估算

        支持多种输入类型:
        - 字符串
        - 字典/列表
        - 消息列表

        Args:
            content: 内容

        Returns:
            Token估算值
        """
        if isinstance(content, str):
            return self._estimate_text_tokens(content)
        elif isinstance(content, (dict, list)):
            return self._estimate_text_tokens(json.dumps(content, ensure_ascii=False))
        elif isinstance(content, list) and all(isinstance(m, dict) for m in content):
            return self._estimate_messages_tokens(content)
        else:
            return self._estimate_text_tokens(str(content))

    def _estimate_text_tokens(self, text: str) -> int:
        """估算文本Token数"""
        if not text:
            return 0
        return int(len(text) * self.TOKENS_PER_CHAR)

    def _estimate_messages_tokens(self, messages: List[Dict]) -> int:
        """估算消息列表Token数"""
        total = 0

        for msg in messages:
            # 消息结构开销
            total += self.TOKENS_PER_MESSAGE_OVERHEAD

            # 内容估算
            content = msg.get("content", "")
            if isinstance(content, str):
                total += self._estimate_text_tokens(content)
            elif isinstance(content, list):
                for block in content:
                    if isinstance(block, dict):
                        total += self._estimate_text_tokens(
                            block.get("text", "") or
                            json.dumps(block, ensure_ascii=False)
                        )

        return total

    def _extract_message_content(self, msg: Dict) -> str:
        """提取消息内容"""
        content = msg.get("content", "")

        if isinstance(content, str):
            return content
        elif isinstance(content, list):
            parts = []
            for block in content:
                if isinstance(block, dict):
                    if block.get("type") == "text":
                        parts.append(block.get("text", ""))
                    elif block.get("type") == "tool_use":
                        parts.append(f"[工具调用: {block.get('name', 'unknown')}]")
                    elif block.get("type") == "tool_result":
                        parts.append(f"[工具结果: {block.get('tool_use_id', 'unknown')[:8]}]")
            return "\n".join(parts)

        return str(content)

    def _summarize_old_messages(self, messages: List[Dict]) -> str:
        """摘要早期消息"""
        summaries = []

        for msg in messages:
            role = msg.get("role", "unknown")
            content_preview = self._extract_message_content(msg)[:200]

            if role == "user":
                summaries.append(f"用户: {content_preview}")
            elif role == "assistant":
                summaries.append(f"助手: {content_preview}")

        return "\n".join(summaries[-10:])  # 最多10条

    def _extract_key_info(self, output: Any) -> str:
        """提取关键信息"""
        if isinstance(output, dict):
            # 提取关键字段
            key_fields = ["url", "endpoint", "vulnerability", "flag", "credential", "error"]
            extracted = {}

            for field in key_fields:
                if field in output:
                    extracted[field] = output[field]

            if extracted:
                return json.dumps(extracted, ensure_ascii=False)

        return str(output)[:500]  # 截断

    def _summarize_tool_results(self, results: List[ToolResult]) -> str:
        """摘要工具结果"""
        summaries = []

        for result in results:
            status = "成功" if result.success else "失败"
            summaries.append(f"{result.tool_name}: {status}")

        return "\n".join(summaries)

    def _summarize_other_findings(self, findings: List[Finding]) -> str:
        """摘要其他发现"""
        summaries = []

        for finding in findings:
            summaries.append(f"- {finding.finding_type}: {finding.finding_id}")

        return "\n".join(summaries[:20])  # 最多20条


# ============================================
# 便捷函数
# ============================================

_compressor: Optional[SmartCompressor] = None


def get_compressor(
    strategy: CompressionStrategy = CompressionStrategy.BALANCED
) -> SmartCompressor:
    """获取压缩器单例"""
    global _compressor
    if _compressor is None:
        _compressor = SmartCompressor(strategy=strategy)
    return _compressor


def compress_context(
    messages: List[Dict],
    tool_results: List[ToolResult] = None,
    findings: List[Finding] = None,
    strategy: CompressionStrategy = CompressionStrategy.BALANCED
) -> Tuple[str, Dict]:
    """
    便捷函数：压缩完整上下文

    Args:
        messages: 消息列表
        tool_results: 工具结果
        findings: 发现列表
        strategy: 压缩策略

    Returns:
        (压缩后内容, 统计信息)
    """
    compressor = get_compressor(strategy)

    parts = []
    stats = {
        "original_tokens": 0,
        "compressed_tokens": 0,
        "compression_ratio": 0
    }

    # 压缩消息
    msg_result = compressor.compress_messages(messages)
    parts.append(msg_result.compressed_content)
    stats["original_tokens"] += msg_result.original_tokens
    stats["compressed_tokens"] += msg_result.compressed_tokens

    # 压缩工具结果
    if tool_results:
        tool_result = compressor.compress_tool_results(tool_results)
        parts.append(tool_result.compressed_content)
        stats["original_tokens"] += tool_result.original_tokens
        stats["compressed_tokens"] += tool_result.compressed_tokens

    # 压缩发现
    if findings:
        finding_result = compressor.compress_findings(findings)
        parts.append(finding_result.compressed_content)
        stats["original_tokens"] += finding_result.original_tokens
        stats["compressed_tokens"] += finding_result.compressed_tokens

    # 计算总体压缩比
    if stats["original_tokens"] > 0:
        stats["compression_ratio"] = 1 - (stats["compressed_tokens"] / stats["original_tokens"])

    compressed_content = "\n\n---\n\n".join(parts)

    return compressed_content, stats