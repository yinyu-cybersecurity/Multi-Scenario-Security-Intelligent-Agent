# Agent类型系统
#
# 借鉴Claude Code的分层Agent架构设计
# 实现 Explore/Plan/Attack/Verify/Coordinator 五类Agent

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Callable
from enum import Enum


class AgentType(Enum):
    """Agent类型枚举"""
    EXPLORE = "explore"
    PLAN = "plan"
    ATTACK = "attack"
    VERIFY = "verify"
    COORDINATOR = "coordinator"


class ToolPermission(Enum):
    """工具权限枚举"""
    READ = "read"
    WRITE = "write"
    EXECUTE = "execute"
    NETWORK = "network"


@dataclass
class AgentDefinition:
    """
    Agent定义 - 借鉴Claude Code BaseAgentDefinition

    核心设计原则:
    1. 权限分离 - 不同Agent有不同权限边界
    2. 工具池定制 - 可继承或自定义工具列表
    3. 模型选择 - 根据任务复杂度选择合适模型
    4. 超时控制 - 防止任务无限运行
    """

    # 基本信息
    agent_type: AgentType
    when_to_use: str  # 使用场景描述

    # 模型配置
    model: str = "glm-5"

    # 权限配置
    read_only: bool = True
    allowed_tools: List[str] = field(default_factory=list)
    disallowed_tools: List[str] = field(default_factory=list)
    required_permissions: List[ToolPermission] = field(default_factory=list)

    # 执行配置
    max_turns: int = 200
    timeout: int = 600  # 秒
    max_concurrent_tasks: int = 1

    # 记忆配置
    memory_scope: str = "task"  # task, session, global
    can_read_memory: bool = True
    can_write_memory: bool = False

    # 其他配置
    omit_context: bool = False  # 是否省略CLAUDE.md节省Token
    adversarial_mode: bool = False  # 对抗性验证模式
    inherit_tools: bool = True  # 是否继承父Agent工具池


# ============================================
# 五类Agent的具体定义
# ============================================

EXPLORE_AGENT = AgentDefinition(
    agent_type=AgentType.EXPLORE,
    when_to_use="""
快速代码库探索和信息收集。适用于：
- 目录扫描和路径发现
- 代码漏洞定位
- 内网资产探测
- Web应用信息收集
- CVE/漏洞模式搜索

指定彻底性级别：
- quick: 基础搜索
- medium: 中等深度探索
- very_thorough: 全面分析
""",
    model="glm-5",
    read_only=True,
    allowed_tools=[
        # 核心读取工具
        "Read", "Glob", "Grep", "LSP",

        # 网络获取
        "WebFetch", "WebSearch",

        # Serena LSP分析
        "mcp__plugin_serena_serena__list_dir",
        "mcp__plugin_serena_serena__find_file",
        "mcp__plugin_serena_serena__find_symbol",
        "mcp__plugin_serena_serena__get_symbols_overview",
        "mcp__plugin_serena_serena__search_for_pattern",

        # Memory读取
        "mcp__plugin_serena_serena__read_memory",
        "mcp__plugin_serena_serena__list_memories",

        # 代码扫描
        "mcp__plugin_semgrep-plugin_semgrep__semgrep_scan",

        # 文档查询
        "mcp__plugin_context7_context7__query-docs",
    ],
    disallowed_tools=[
        "Edit", "Write", "Bash",
        "mcp__plugin_serena_serena__write_memory",
    ],
    required_permissions=[ToolPermission.READ],
    max_turns=100,
    timeout=300,
    can_read_memory=True,
    can_write_memory=False,
    omit_context=True,  # 节省Token
)

PLAN_AGENT = AgentDefinition(
    agent_type=AgentType.PLAN,
    when_to_use="""
攻击策略规划Agent。适用于：
- 漏洞利用链设计
- 内网渗透路径规划
- 攻击方案制定
- 风险评估

输出:
- 步骤化实现计划
- 关键文件识别
- 架构权衡分析
""",
    model="glm-5",
    read_only=True,
    allowed_tools=[
        # 继承Explore的工具
        *EXPLORE_AGENT.allowed_tools,

        # 额外交互工具
        "AskUserQuestion",
        "EnterPlanMode", "ExitPlanMode",

        # Memory写入（写入攻击计划）
        "mcp__plugin_serena_serena__write_memory",
    ],
    disallowed_tools=[
        "Edit", "Write", "Bash",
    ],
    required_permissions=[ToolPermission.READ],
    max_turns=150,
    timeout=600,
    can_read_memory=True,
    can_write_memory=True,
    inherit_tools=True,
)

ATTACK_AGENT = AgentDefinition(
    agent_type=AgentType.ATTACK,
    when_to_use="""
攻击执行Agent。适用于：
- 漏洞利用执行
- 后渗透操作
- 工具调用
- Web攻击
- 内网横向移动
""",
    model="glm-5",
    read_only=False,
    allowed_tools=[
        # 读写执行
        "Read", "Write", "Edit", "Bash",

        # 网络工具
        "WebFetch",

        # Memory
        "mcp__plugin_serena_serena__read_memory",
        "mcp__plugin_serena_serena__write_memory",

        # 浏览器自动化
        "mcp__plugin_playwright_playwright__browser_navigate",
        "mcp__plugin_playwright_playwright__browser_snapshot",
        "mcp__plugin_playwright_playwright__browser_click",
        "mcp__plugin_playwright_playwright__browser_type",
        "mcp__plugin_playwright_playwright__browser_fill_form",
        "mcp__plugin_playwright_playwright__browser_evaluate",
        "mcp__plugin_playwright_playwright__browser_take_screenshot",

        # Chrome DevTools
        "mcp__plugin_chrome-devtools-mcp_chrome-devtools__take_snapshot",
        "mcp__plugin_chrome-devtools-mcp_chrome-devtools__navigate_page",
        "mcp__plugin_chrome-devtools-mcp_chrome-devtools__click",
        "mcp__plugin_chrome-devtools-mcp_chrome-devtools__fill",
        "mcp__plugin_chrome-devtools-mcp_chrome-devtools__evaluate_script",
        "mcp__plugin_chrome-devtools-mcp_chrome-devtools__list_network_requests",
        "mcp__plugin_chrome-devtools-mcp_chrome-devtools__get_network_request",

        # Semgrep
        "mcp__plugin_semgrep-plugin_semgrep__semgrep_scan",
    ],
    disallowed_tools=[
        # 安全边界：禁止的危险操作
        "Bash(rm -rf /*)",
        "Bash(rm -rf:*)",
        "Bash(sudo rm:*)",
        "Bash(format:*)",
        "Bash(shutdown:*)",
        "Bash(reboot:*)",
        "Bash(dd:*)",
    ],
    required_permissions=[
        ToolPermission.READ,
        ToolPermission.WRITE,
        ToolPermission.EXECUTE,
        ToolPermission.NETWORK,
    ],
    max_turns=200,
    timeout=1200,  # 攻击任务可能较长
    can_read_memory=True,
    can_write_memory=True,
)

VERIFY_AGENT = AgentDefinition(
    agent_type=AgentType.VERIFY,
    when_to_use="""
验证Agent。适用于：
- Flag有效性验证
- 漏洞可复现性检查
- 误报过滤
- 对抗性测试

验证原则:
- 证明代码工作，而非确认存在
- 独立测试，不走过场
- 怀疑一切看起来不对的情况
""",
    model="glm-5",
    read_only=False,
    allowed_tools=[
        "Read", "Bash", "Grep",

        # Memory读取
        "mcp__plugin_serena_serena__read_memory",

        # Semgrep验证
        "mcp__plugin_semgrep-plugin_semgrep__semgrep_scan",
        "mcp__plugin_semgrep-plugin_semgrep__semgrep_findings",
    ],
    disallowed_tools=[
        "Edit", "Write",
        "mcp__plugin_serena_serena__write_memory",  # 验证Agent不写Memory
    ],
    required_permissions=[
        ToolPermission.READ,
        ToolPermission.EXECUTE,
    ],
    max_turns=100,
    timeout=300,
    can_read_memory=True,
    can_write_memory=False,
    adversarial_mode=True,  # 对抗性验证
)

COORDINATOR_AGENT = AgentDefinition(
    agent_type=AgentType.COORDINATOR,
    when_to_use="""
多Agent协调调度。适用于：
- 并行扫描多目标
- 复杂任务分解
- 结果汇总
- Agent间通信协调

协调原则:
- 并行是超能力
- 独立任务同时派发
- 结果综合后汇报
""",
    model="glm-5",
    read_only=True,
    allowed_tools=[
        # Agent派发
        "Agent",

        # Memory系统
        "mcp__plugin_serena_serena__read_memory",
        "mcp__plugin_serena_serena__write_memory",
        "mcp__plugin_serena_serena__list_memories",

        # 用户交互
        "AskUserQuestion",
    ],
    disallowed_tools=[
        "Edit", "Write", "Bash",
    ],
    required_permissions=[ToolPermission.READ],
    max_turns=50,
    timeout=3600,  # 协调任务可能很长
    max_concurrent_tasks=8,  # 支持并行8个Agent
    can_read_memory=True,
    can_write_memory=True,
)


# ============================================
# Agent注册表
# ============================================

AGENT_REGISTRY: Dict[AgentType, AgentDefinition] = {
    AgentType.EXPLORE: EXPLORE_AGENT,
    AgentType.PLAN: PLAN_AGENT,
    AgentType.ATTACK: ATTACK_AGENT,
    AgentType.VERIFY: VERIFY_AGENT,
    AgentType.COORDINATOR: COORDINATOR_AGENT,
}


def get_agent_definition(agent_type: AgentType) -> Optional[AgentDefinition]:
    """获取Agent定义"""
    return AGENT_REGISTRY.get(agent_type)


def get_all_agent_types() -> List[AgentType]:
    """获取所有Agent类型"""
    return list(AGENT_REGISTRY.keys())


def get_agent_permissions(agent_type: AgentType) -> List[ToolPermission]:
    """获取Agent所需权限"""
    definition = get_agent_definition(agent_type)
    return definition.required_permissions if definition else []


def is_agent_read_only(agent_type: AgentType) -> bool:
    """检查Agent是否只读"""
    definition = get_agent_definition(agent_type)
    return definition.read_only if definition else True


def check_tool_allowed(agent_type: AgentType, tool_name: str) -> bool:
    """检查工具是否对该Agent可用"""
    definition = get_agent_definition(agent_type)
    if not definition:
        return False

    # 检查禁止列表
    for disallowed in definition.disallowed_tools:
        if disallowed.endswith("*"):
            if tool_name.startswith(disallowed[:-1]):
                return False
        elif tool_name == disallowed:
            return False

    # 检查允许列表
    if tool_name in definition.allowed_tools:
        return True

    # 通配符匹配
    for allowed in definition.allowed_tools:
        if allowed.endswith("*"):
            if tool_name.startswith(allowed[:-1]):
                return True

    return False