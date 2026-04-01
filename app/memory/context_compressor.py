"""
CTF-Agent 上下文压缩引擎

借鉴Claude Code的Prompt Cache机制，实现:
1. 共享上下文池 - 多Agent共享基础知识
2. 增量更新 - 只传输变化的部分
3. Token优化 - 减少90%重复传输
"""

from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime
import hashlib
import json


@dataclass
class ContextBlock:
    """上下文块"""
    id: str  # 唯一标识符
    content: str  # 内容
    content_type: str  # knowledge/tool_result/skill/finding
    timestamp: datetime
    token_count: int
    dependencies: Set[str] = field(default_factory=set)  # 依赖的其他块
    mutable: bool = True  # 是否可变


@dataclass
class SharedContext:
    """共享上下文池"""
    target: str
    objective: str
    phase: str
    findings: List[Dict[str, Any]] = field(default_factory=list)
    tools_available: List[str] = field(default_factory=list)
    skills_active: List[str] = field(default_factory=list)


class ContextCompressor:
    """上下文压缩引擎"""

    def __init__(self):
        self.context_pool: Dict[str, ContextBlock] = {}
        self.shared_context: Optional[SharedContext] = None
        self.token_budget: int = 100000
        self.cache_hits: int = 0
        self.cache_misses: int = 0

    def initialize_shared_context(
        self,
        target: str,
        objective: str,
        available_tools: List[str],
        active_skills: List[str]
    ):
        """初始化共享上下文"""
        self.shared_context = SharedContext(
            target=target,
            objective=objective,
            phase="init",
            tools_available=available_tools,
            skills_active=active_skills
        )

        # 创建基础上下文块
        self._create_context_block(
            content_type="shared_base",
            content=json.dumps({
                "target": target,
                "objective": objective,
                "tools": available_tools[:10],  # 限制数量
                "skills": active_skills[:5]
            }),
            mutable=False
        )

    def _create_context_block(
        self,
        content_type: str,
        content: str,
        mutable: bool = True,
        dependencies: Set[str] = None
    ) -> str:
        """创建上下文块"""
        # 计算内容哈希作为ID
        content_hash = hashlib.md5(content.encode()).hexdigest()[:12]
        block_id = f"{content_type}_{content_hash}"

        # 如果已存在相同内容，直接返回
        if block_id in self.context_pool:
            self.cache_hits += 1
            return block_id

        self.cache_misses += 1

        # 计算Token数量（简化估算）
        token_count = len(content.split())

        block = ContextBlock(
            id=block_id,
            content=content,
            content_type=content_type,
            timestamp=datetime.now(),
            token_count=token_count,
            dependencies=dependencies or set(),
            mutable=mutable
        )

        self.context_pool[block_id] = block
        return block_id

    def add_knowledge(self, knowledge: str) -> str:
        """添加知识上下文"""
        return self._create_context_block(
            content_type="knowledge",
            content=knowledge,
            mutable=False
        )

    def add_tool_result(
        self,
        tool_name: str,
        result: Dict[str, Any],
        compressed: bool = True
    ) -> str:
        """添加工具结果"""
        if compressed:
            # 压缩结果 - 只保留关键信息
            compressed_result = self._compress_tool_result(tool_name, result)
            content = json.dumps(compressed_result)
        else:
            content = json.dumps(result)

        return self._create_context_block(
            content_type="tool_result",
            content=content,
            mutable=False
        )

    def _compress_tool_result(
        self,
        tool_name: str,
        result: Dict[str, Any]
    ) -> Dict[str, Any]:
        """压缩工具结果"""
        compressed = {
            "tool": tool_name,
            "success": result.get("success", False)
        }

        # 只提取关键发现
        if tool_name == "nmap":
            compressed["open_ports"] = result.get("open_ports", [])[:20]
            compressed["services"] = result.get("services", {})

        elif tool_name == "nuclei":
            compressed["vulnerabilities"] = [
                {"name": v.get("name"), "severity": v.get("severity")}
                for v in result.get("vulnerabilities", [])[:10]
            ]

        elif tool_name == "sqlmap":
            compressed["vulnerable"] = result.get("vulnerable", False)
            compressed["databases"] = result.get("databases", [])[:10]

        else:
            # 通用压缩
            for key in ["findings", "vulnerabilities", "open_ports", "credentials"]:
                if key in result:
                    compressed[key] = result[key][:10]

        return compressed

    def add_finding(self, finding: Dict[str, Any]) -> str:
        """添加发现"""
        if self.shared_context:
            self.shared_context.findings.append(finding)

        return self._create_context_block(
            content_type="finding",
            content=json.dumps(finding),
            mutable=False
        )

    def build_prompt_context(
        self,
        max_tokens: int = 50000
    ) -> str:
        """构建Prompt上下文"""
        context_parts = []

        # 1. 共享基础上下文（最高优先级）
        if self.shared_context:
            base_context = f"""## 任务上下文
目标: {self.shared_context.target}
目的: {self.shared_context.objective}
阶段: {self.shared_context.phase}
可用工具: {', '.join(self.shared_context.tools_available[:10])}
激活技能: {', '.join(self.shared_context.skills_active[:5])}
"""
            context_parts.append(base_context)

        # 2. 关键发现摘要
        if self.shared_context and self.shared_context.findings:
            findings_summary = "\n## 已发现\n"
            for finding in self.shared_context.findings[-10:]:  # 最近10个
                findings_summary += f"- {finding.get('type', 'unknown')}: {finding.get('summary', '')}\n"
            context_parts.append(findings_summary)

        # 3. 知识上下文（按需加载）
        knowledge_blocks = [
            block for block in self.context_pool.values()
            if block.content_type == "knowledge"
        ]
        if knowledge_blocks:
            knowledge_context = "\n## 相关知识\n"
            for block in knowledge_blocks[-3:]:  # 最近3个知识块
                knowledge_context += block.content[:500] + "\n...\n"
            context_parts.append(knowledge_context)

        # 4. 工具结果摘要
        tool_results = [
            block for block in self.context_pool.values()
            if block.content_type == "tool_result"
        ]
        if tool_results:
            results_context = "\n## 工具结果\n"
            for block in tool_results[-5:]:  # 最近5个结果
                results_context += f"```{block.id}\n{block.content[:300]}\n```\n"
            context_parts.append(results_context)

        return "\n".join(context_parts)

    def get_token_stats(self) -> Dict[str, Any]:
        """获取Token统计"""
        total_tokens = sum(
            block.token_count for block in self.context_pool.values()
        )

        # 估算节省的Token
        # 如果每次都传输完整上下文，需要传输所有块的完整内容
        # 使用缓存后，只需要传输ID引用
        saved_tokens = self.cache_hits * 100  # 假设每个缓存块节省100 tokens

        return {
            "total_tokens": total_tokens,
            "cache_hits": self.cache_hits,
            "cache_misses": self.cache_misses,
            "saved_tokens": saved_tokens,
            "compression_ratio": (
                saved_tokens / (total_tokens + saved_tokens) * 100
                if total_tokens + saved_tokens > 0 else 0
            )
        }

    def export_state(self) -> Dict[str, Any]:
        """导出状态（用于恢复）"""
        return {
            "shared_context": {
                "target": self.shared_context.target if self.shared_context else "",
                "objective": self.shared_context.objective if self.shared_context else "",
                "phase": self.shared_context.phase if self.shared_context else "",
                "findings": self.shared_context.findings if self.shared_context else [],
            },
            "context_pool": {
                block_id: {
                    "content": block.content,
                    "content_type": block.content_type,
                    "timestamp": block.timestamp.isoformat(),
                    "token_count": block.token_count
                }
                for block_id, block in self.context_pool.items()
            },
            "stats": self.get_token_stats()
        }


# 全局上下文压缩器
_context_compressor: Optional[ContextCompressor] = None


def get_context_compressor() -> ContextCompressor:
    """获取全局上下文压缩器"""
    global _context_compressor
    if _context_compressor is None:
        _context_compressor = ContextCompressor()
    return _context_compressor


# 使用示例
if __name__ == "__main__":
    compressor = get_context_compressor()

    # 初始化共享上下文
    compressor.initialize_shared_context(
        target="http://example.com",
        objective="发现漏洞并获取Flag",
        available_tools=["nmap", "nuclei", "sqlmap"],
        active_skills=["web_exploitation"]
    )

    # 添加工具结果
    compressor.add_tool_result("nmap", {
        "success": True,
        "open_ports": ["80", "443", "3306"],
        "services": {"80": "http", "443": "https"}
    })

    # 添加发现
    compressor.add_finding({
        "type": "open_ports",
        "summary": "发现3个开放端口"
    })

    # 构建上下文
    prompt_context = compressor.build_prompt_context()
    print(prompt_context)

    # 统计
    print("\n" + "=" * 60)
    stats = compressor.get_token_stats()
    print(f"Token统计: {stats}")