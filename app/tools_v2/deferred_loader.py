"""
工具延迟加载系统

借鉴Claude Code的工具延迟加载设计：
- 核心工具始终加载
- 专业工具按需加载
- ToolSearch搜索未加载工具

预期效果：Token消耗降低30%+
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Callable
from enum import Enum
import asyncio

from app.tools_v2.tools import list_tools, get_tool_schema


class LoadPriority(Enum):
    """加载优先级"""
    ALWAYS = "always"        # 始终加载
    DEFERRED = "deferred"    # 延迟加载
    ON_DEMAND = "on_demand"  # 按需加载


@dataclass
class ToolLoadConfig:
    """工具加载配置"""
    name: str
    priority: LoadPriority
    description: str = ""
    tags: List[str] = field(default_factory=list)
    load_condition: Optional[Callable[[Dict], bool]] = None

    def should_load(self, context: Dict) -> bool:
        """判断是否应该加载"""
        if self.priority == LoadPriority.ALWAYS:
            return True

        if self.load_condition:
            return self.load_condition(context)

        # 延迟加载工具默认不加载
        return False


# ============================================
# 工具加载配置表
# ============================================

TOOL_LOAD_CONFIGS: Dict[str, ToolLoadConfig] = {
    # === 始终加载的核心工具 ===
    "Read": ToolLoadConfig(
        name="Read",
        priority=LoadPriority.ALWAYS,
        description="文件读取",
        tags=["file", "read"]
    ),
    "Glob": ToolLoadConfig(
        name="Glob",
        priority=LoadPriority.ALWAYS,
        description="文件模式匹配",
        tags=["file", "search"]
    ),
    "Grep": ToolLoadConfig(
        name="Grep",
        priority=LoadPriority.ALWAYS,
        description="内容搜索",
        tags=["search", "code"]
    ),
    "Bash": ToolLoadConfig(
        name="Bash",
        priority=LoadPriority.ALWAYS,
        description="命令执行",
        tags=["execute", "shell"]
    ),
    "WebFetch": ToolLoadConfig(
        name="WebFetch",
        priority=LoadPriority.ALWAYS,
        description="网页获取",
        tags=["network", "http"]
    ),

    # === Web安全核心工具（优先加载）===
    "nmap": ToolLoadConfig(
        name="nmap",
        priority=LoadPriority.ALWAYS,
        description="端口扫描",
        tags=["network", "scan", "recon"]
    ),
    "httpx": ToolLoadConfig(
        name="httpx",
        priority=LoadPriority.ALWAYS,
        description="HTTP探测",
        tags=["http", "recon"]
    ),
    "nuclei": ToolLoadConfig(
        name="nuclei",
        priority=LoadPriority.ALWAYS,
        description="漏洞扫描",
        tags=["vuln", "scan"]
    ),
    "sqlmap": ToolLoadConfig(
        name="sqlmap",
        priority=LoadPriority.DEFERRED,
        description="SQL注入利用",
        tags=["sqli", "attack"],
        load_condition=lambda ctx: "sql" in str(ctx).lower() or "sqli" in str(ctx).lower()
    ),
    "ffuf": ToolLoadConfig(
        name="ffuf",
        priority=LoadPriority.DEFERRED,
        description="模糊测试",
        tags=["fuzz", "enumerate"],
        load_condition=lambda ctx: "fuzz" in str(ctx).lower() or "dir" in str(ctx).lower()
    ),
    "fscan": ToolLoadConfig(
        name="fscan",
        priority=LoadPriority.DEFERRED,
        description="内网综合扫描",
        tags=["intranet", "scan"],
        load_condition=lambda ctx: "内网" in str(ctx) or "intranet" in str(ctx).lower()
    ),

    # === 专业方向工具（按需加载）===
    "crypto_identifier": ToolLoadConfig(
        name="crypto_identifier",
        priority=LoadPriority.ON_DEMAND,
        description="密码学识别",
        tags=["crypto", "ctf"],
        load_condition=lambda ctx: "crypto" in str(ctx).lower() or "密码" in str(ctx)
    ),
    "rsa_attacker": ToolLoadConfig(
        name="rsa_attacker",
        priority=LoadPriority.ON_DEMAND,
        description="RSA攻击",
        tags=["crypto", "rsa"],
        load_condition=lambda ctx: "rsa" in str(ctx).lower()
    ),
    "binary_analyzer": ToolLoadConfig(
        name="binary_analyzer",
        priority=LoadPriority.ON_DEMAND,
        description="二进制分析",
        tags=["pwn", "binary"],
        load_condition=lambda ctx: "pwn" in str(ctx).lower() or "binary" in str(ctx).lower()
    ),
    "ai_attacker": ToolLoadConfig(
        name="ai_attacker",
        priority=LoadPriority.ON_DEMAND,
        description="AI安全攻击",
        tags=["ai", "llm"],
        load_condition=lambda ctx: "ai" in str(ctx).lower() or "llm" in str(ctx).lower()
    ),
    "oa_exploiter": ToolLoadConfig(
        name="oa_exploiter",
        priority=LoadPriority.ON_DEMAND,
        description="OA系统攻击",
        tags=["oa", "weaver", "seeyon"],
        load_condition=lambda ctx: any(oa in str(ctx).lower() for oa in ["oa", "weaver", "seeyon", "tongda", "landray"])
    ),
    "cloud_scanner": ToolLoadConfig(
        name="cloud_scanner",
        priority=LoadPriority.ON_DEMAND,
        description="云安全扫描",
        tags=["cloud", "aws", "azure"],
        load_condition=lambda ctx: any(c in str(ctx).lower() for c in ["cloud", "aws", "azure", "aliyun"])
    ),
}


class DeferredToolRegistry:
    """
    延迟加载工具注册表

    核心设计：
    1. 核心工具始终加载
    2. 专业工具按需加载
    3. 支持ToolSearch搜索
    """

    def __init__(self):
        self._loaded_tools: Dict[str, Any] = {}
        self._deferred_tools: Dict[str, ToolLoadConfig] = TOOL_LOAD_CONFIGS.copy()
        self._load_history: List[str] = []

    def get_tools_for_context(
        self,
        context: Dict[str, Any],
        include_deferred: bool = False
    ) -> List[str]:
        """
        根据上下文获取应加载的工具列表

        Args:
            context: 任务上下文
            include_deferred: 是否包含延迟加载的工具

        Returns:
            工具名称列表
        """
        tools = []

        for name, config in self._deferred_tools.items():
            if config.priority == LoadPriority.ALWAYS:
                tools.append(name)
            elif include_deferred or config.should_load(context):
                tools.append(name)

        return tools

    def get_tool_schemas_for_context(
        self,
        context: Dict[str, Any],
        include_deferred: bool = False
    ) -> List[Dict]:
        """
        获取工具Schema列表（用于构建Prompt）

        Args:
            context: 任务上下文
            include_deferred: 是否包含延迟加载的工具

        Returns:
            工具Schema列表
        """
        tool_names = self.get_tools_for_context(context, include_deferred)
        schemas = []

        for name in tool_names:
            schema = get_tool_schema(name)
            if schema:
                schemas.append(schema)

        return schemas

    def search_tools(self, query: str) -> List[Dict]:
        """
        搜索工具（包括延迟加载的）

        用于ToolSearch工具，让Agent发现未加载的工具

        Args:
            query: 搜索关键词

        Returns:
            匹配的工具列表
        """
        results = []
        query_lower = query.lower()

        for name, config in self._deferred_tools.items():
            # 名称匹配
            if query_lower in name.lower():
                results.append({
                    "name": name,
                    "description": config.description,
                    "tags": config.tags,
                    "priority": config.priority.value
                })
                continue

            # 标签匹配
            for tag in config.tags:
                if query_lower in tag.lower():
                    results.append({
                        "name": name,
                        "description": config.description,
                        "tags": config.tags,
                        "priority": config.priority.value
                    })
                    break

        return results

    def load_tool(self, name: str) -> Optional[Dict]:
        """
        显式加载工具

        Args:
            name: 工具名称

        Returns:
            工具Schema
        """
        if name in self._loaded_tools:
            return self._loaded_tools[name]

        schema = get_tool_schema(name)
        if schema:
            self._loaded_tools[name] = schema
            self._load_history.append(name)
            return schema

        return None

    def get_token_savings(self) -> Dict[str, Any]:
        """
        计算Token节省情况

        Returns:
            节省统计
        """
        total_tools = len(self._deferred_tools)
        loaded_tools = len(self._loaded_tools)
        always_tools = sum(
            1 for c in self._deferred_tools.values()
            if c.priority == LoadPriority.ALWAYS
        )

        # 估算每个工具Schema约200 tokens
        saved_tools = total_tools - loaded_tools
        estimated_tokens_saved = saved_tools * 200

        return {
            "total_tools": total_tools,
            "loaded_tools": loaded_tools,
            "always_load_tools": always_tools,
            "deferred_tools": saved_tools,
            "estimated_tokens_saved": estimated_tokens_saved,
            "savings_percentage": (saved_tools / total_tools * 100) if total_tools > 0 else 0
        }


# ============================================
# 全局实例
# ============================================

_registry: Optional[DeferredToolRegistry] = None


def get_deferred_tool_registry() -> DeferredToolRegistry:
    """获取延迟加载工具注册表"""
    global _registry
    if _registry is None:
        _registry = DeferredToolRegistry()
    return _registry


# ============================================
# ToolSearch工具实现
# ============================================

async def tool_search_handler(params: Dict, context: Dict) -> Dict:
    """
    ToolSearch工具处理器

    让Agent搜索未加载的工具
    """
    query = params.get("query", "")
    registry = get_deferred_tool_registry()

    results = registry.search_tools(query)

    return {
        "success": True,
        "query": query,
        "results": results,
        "count": len(results),
        "message": f"找到 {len(results)} 个匹配工具"
    }


# ToolSearch工具Schema
TOOL_SEARCH_SCHEMA = {
    "name": "ToolSearch",
    "description": "搜索可用的安全工具（包括延迟加载的工具）",
    "inputSchema": {
        "type": "object",
        "properties": {
            "query": {
                "type": "string",
                "description": "搜索关键词，如 'sql', 'xss', 'crypto'"
            }
        },
        "required": ["query"]
    }
}