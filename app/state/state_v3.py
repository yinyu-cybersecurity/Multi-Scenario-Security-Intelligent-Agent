# State V3 - CTF状态定义
#
# 借鉴Claude Code的状态管理设计
# 实现分层状态结构和Selector订阅机制

from typing import Dict, Any, List, Optional, TypedDict, Annotated
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime

# 导入Agent类型
from app.agents.base import AgentType


class ChallengeType(Enum):
    """CTF挑战类型"""
    WEB = "web"
    PWN = "pwn"
    CRYPTO = "crypto"
    REVERSE = "reverse"
    MISC = "misc"
    NETWORK = "network"  # 内网渗透
    CLOUD = "cloud"      # 云安全
    AI = "ai"            # AI安全


class PhaseType(Enum):
    """执行阶段"""
    DETECTION = "detection"
    EXPLORE = "explore"
    PLAN = "plan"
    ATTACK = "attack"
    VERIFY = "verify"
    EVOLVE = "evolve"
    COMPLETE = "complete"


class Priority(Enum):
    """优先级（用于上下文压缩）"""
    CRITICAL = "critical"    # 核心信息，永不压缩
    HIGH = "high"            # 高优先级，尽量保留
    MEDIUM = "medium"        # 中等优先级，可压缩摘要
    LOW = "low"              # 低优先级，可大幅压缩


@dataclass
class ToolResult:
    """工具执行结果"""
    tool_name: str
    success: bool
    output: Any
    error: Optional[str] = None
    timestamp: float = field(default_factory=lambda: datetime.now().timestamp())
    priority: Priority = Priority.MEDIUM

    def to_dict(self) -> Dict:
        return {
            "tool_name": self.tool_name,
            "success": self.success,
            "output": self.output,
            "error": self.error,
            "timestamp": self.timestamp,
            "priority": self.priority.value
        }


@dataclass
class AgentSession:
    """Agent会话记录"""
    agent_type: AgentType
    session_id: str
    messages: List[Dict] = field(default_factory=list)
    tool_results: List[ToolResult] = field(default_factory=list)
    findings: List[Dict] = field(default_factory=list)
    status: str = "active"
    started_at: float = field(default_factory=lambda: datetime.now().timestamp())


@dataclass
class ChallengeInfo:
    """挑战信息"""
    challenge_id: str
    challenge_type: ChallengeType
    title: str
    description: str
    target_url: Optional[str] = None
    target_ip: Optional[str] = None
    target_port: Optional[int] = None
    attachments: List[str] = field(default_factory=list)
    hints: List[str] = field(default_factory=list)
    category: Optional[str] = None
    points: int = 0


@dataclass
class AttackPlan:
    """攻击计划"""
    plan_id: str
    target: str
    strategy: str
    steps: List[Dict]
    priority: Priority = Priority.HIGH
    created_by: AgentType = AgentType.PLAN
    status: str = "pending"
    estimated_success_rate: float = 0.0


@dataclass
class Finding:
    """发现记录"""
    finding_id: str
    finding_type: str  # endpoint, vuln, credential, flag, asset
    content: Dict
    source: AgentType
    confidence: float = 1.0
    verified: bool = False
    priority: Priority = Priority.HIGH


@dataclass
class FlagSubmission:
    """Flag提交记录"""
    flag: str
    challenge_id: str
    submitted_at: float
    success: bool
    response: Optional[str] = None


# ============================================
# 核心状态定义 - TypedDict for LangGraph
# ============================================

class CTFStateV3(TypedDict):
    """
    CTF状态V3 - 借鉴Claude Code分层状态设计

    分层结构:
    1. 挑战层 - ChallengeInfo
    2. 执行层 - PhaseType, AgentSession
    3. 知识层 - Findings, AttackPlans
    4. 结果层 - Flags, Results

    Selector订阅:
    - 状态分片订阅，减少无效渲染
    - 精确控制Agent需要的状态切片
    """

    # === 挑战层 ===
    challenge: ChallengeInfo
    challenge_type: ChallengeType

    # === 执行层 ===
    current_phase: PhaseType
    current_agent: AgentType
    active_sessions: Dict[str, AgentSession]  # session_id -> AgentSession

    # === 知识层 ===
    findings: List[Finding]
    attack_plans: Dict[str, AttackPlan]  # plan_id -> AttackPlan
    credentials: List[Dict]
    discovered_assets: List[Dict]

    # === 工具层 ===
    tool_history: List[ToolResult]
    pending_tools: List[Dict]

    # === 结果层 ===
    flags_found: List[str]
    flag_submissions: List[FlagSubmission]
    final_result: Optional[Dict]

    # === 控制层 ===
    iteration_count: int
    max_iterations: int
    should_continue: bool
    error_log: List[str]

    # === Memory层 ===
    memory_updates: List[Dict]  # 待写入Memory的更新
    subscribed_topics: List[str]  # Agent订阅的Memory主题

    # === Prompt Cache层 ===
    parent_messages: List[Dict]  # 父Agent消息（用于Fork）
    fork_tasks: List[Dict]  # Fork子Agent任务

    # === 元数据层 ===
    session_id: str
    start_time: float
    last_update_time: float
    metadata: Dict[str, Any]


# ============================================
# 状态切片定义（用于Selector）
# ============================================

class StateSlice:
    """
    状态切片 - 用于Selector精确订阅

    借鉴React Redux的selector概念
    不同Agent只订阅需要的状态切片
    """

    # Explore Agent订阅
    EXPLORE_SLICE = [
        "challenge",
        "challenge_type",
        "findings",
        "discovered_assets",
        "tool_history",
        "subscribed_topics",
    ]

    # Plan Agent订阅
    PLAN_SLICE = [
        "challenge",
        "findings",
        "discovered_assets",
        "credentials",
        "attack_plans",
        "memory_updates",
    ]

    # Attack Agent订阅
    ATTACK_SLICE = [
        "challenge",
        "attack_plans",
        "credentials",
        "findings",
        "tool_history",
        "pending_tools",
        "flags_found",
    ]

    # Verify Agent订阅
    VERIFY_SLICE = [
        "challenge",
        "flags_found",
        "findings",
        "flag_submissions",
        "final_result",
    ]

    # Coordinator Agent订阅（全量）
    COORDINATOR_SLICE = [
        # 订阅所有状态
        "*"
    ]


def get_state_slice_for_agent(agent_type: AgentType) -> List[str]:
    """获取Agent对应的状态切片"""
    slice_map = {
        AgentType.EXPLORE: StateSlice.EXPLORE_SLICE,
        AgentType.PLAN: StateSlice.PLAN_SLICE,
        AgentType.ATTACK: StateSlice.ATTACK_SLICE,
        AgentType.VERIFY: StateSlice.VERIFY_SLICE,
        AgentType.COORDINATOR: StateSlice.COORDINATOR_SLICE,
    }
    return slice_map.get(agent_type, [])


def create_initial_state(
    challenge: ChallengeInfo,
    session_id: str = None
) -> CTFStateV3:
    """创建初始状态"""
    import uuid

    return CTFStateV3(
        challenge=challenge,
        challenge_type=challenge.challenge_type,
        current_phase=PhaseType.DETECTION,
        current_agent=AgentType.EXPLORE,
        active_sessions={},
        findings=[],
        attack_plans={},
        credentials=[],
        discovered_assets=[],
        tool_history=[],
        pending_tools=[],
        flags_found=[],
        flag_submissions=[],
        final_result=None,
        iteration_count=0,
        max_iterations=10,
        should_continue=True,
        error_log=[],
        memory_updates=[],
        subscribed_topics=[],
        parent_messages=[],
        fork_tasks=[],
        session_id=session_id or str(uuid.uuid4()),
        start_time=datetime.now().timestamp(),
        last_update_time=datetime.now().timestamp(),
        metadata={}
    )


def reduce_messages_for_cache(
    messages: List[Dict],
    max_tokens: int = 10000
) -> List[Dict]:
    """
    压缩消息用于Prompt Cache

    保留:
    - 用户核心指令
    - 工具调用结构
    - 关键发现摘要
    """
    compressed = []

    # 简化实现：保留最后N条消息
    # TODO: 更智能的优先级压缩
    for msg in messages[-20:]:
        if msg.get("role") in ["user", "assistant"]:
            # 保留核心结构
            compressed.append({
                "role": msg["role"],
                "content": msg.get("content", [])[:3]  # 只保留前3个block
            })

    return compressed