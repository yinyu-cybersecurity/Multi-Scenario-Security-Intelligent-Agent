# app/staged_planner.py - 阶段性计划器
"""
阶段性计划器 - 针对CTF和内网渗透的分阶段攻击规划

设计要点:
1. 五个CTF阶段（针对30分钟熔断优化）
2. 五个内网渗透阶段（针对50分钟熔断优化）
3. 量化成功标准
4. 超时自动切换机制
5. 备选策略生成

使用方式:
    from app.staged_planner import StagedPlanner, get_ctf_planner, get_internal_planner

    planner = get_ctf_planner()
    current_stage = planner.get_current_stage(state)
    if planner.should_advance(state):
        planner.advance_stage()
"""

from typing import TypedDict, List, Dict, Any, Optional, Literal, Callable
from dataclasses import dataclass, field
import time
from enum import Enum

from logger import get_logger
from config import config
from state_types.strategic import ATTACK_PHASES

logger = get_logger("staged_planner")


# =============================================================================
# 阶段名称映射（兼容 ATTACK_PHASES）
# =============================================================================

# stage_type (英文ID) -> ATTACK_PHASES中文阶段名
STAGE_NAME_MAP = {
    # CTF阶段 (对应 ATTACK_PHASES["web"])
    "recon": "侦察",
    "discovery": "分析",
    "exploitation": "攻击",
    "post_exploit": "验证",
    "flag_capture": "FLAG",
    # 内网阶段 (对应 ATTACK_PHASES["internal"])
    "foothold": "立足点",
    "internal_recon": "侦察",
    "lateral_move": "横向移动",
    "privilege_escalation": "权限提升",
    "persistence_flag": "FLAG",
}


def get_stage_display_name(stage_type: str) -> str:
    """
    获取阶段的中文显示名（兼容 ATTACK_PHASES）

    Args:
        stage_type: 阶段类型（英文ID，如 "recon", "foothold"）

    Returns:
        对应的中文显示名，如 "侦察", "立足点" 等
    """
    return STAGE_NAME_MAP.get(stage_type, stage_type)


# =============================================================================
# 阶段类型枚举
# =============================================================================

class StageType(str, Enum):
    """阶段类型"""
    # CTF阶段（外网打点）
    CTF_RECON = "recon"                    # 信息收集
    CTF_DISCOVERY = "discovery"            # 漏洞发现
    CTF_EXPLOITATION = "exploitation"      # 漏洞利用
    CTF_POST_EXPLOIT = "post_exploit"      # 后渗透
    CTF_FLAG_CAPTURE = "flag_capture"      # FLAG获取

    # 内网渗透阶段
    INTERNAL_FOOTHOLD = "foothold"                  # 立足点
    INTERNAL_RECON = "internal_recon"               # 内网侦察
    INTERNAL_LATERAL = "lateral_move"               # 横向移动
    INTERNAL_PRIVILEGE = "privilege_escalation"     # 权限提升
    INTERNAL_PERSISTENCE = "persistence_flag"       # 持久化和FLAG


# =============================================================================
# 类型定义
# =============================================================================

class StageSuccessCriteria(TypedDict):
    """阶段成功标准"""
    # 条件类型
    condition_type: Literal["any", "all", "threshold"]  # any=任一满足, all=全部满足, threshold=达到阈值

    # 条件列表
    conditions: List[str]  # 条件描述

    # 阈值（当condition_type为threshold时使用）
    threshold: Optional[int]

    # 当前满足数量
    current_count: Optional[int]


class Stage(TypedDict, total=False):
    """单个阶段的定义"""
    # 阶段标识
    stage_id: str                    # 阶段ID
    stage_name: str                  # 阶段名称（中文）
    stage_type: str                  # 阶段类型（recon/discovery等）

    # 时间控制
    timeout_seconds: int             # 硬性超时（秒）
    soft_timeout_seconds: int        # 软超时（开始警告）
    start_time: Optional[float]      # 阶段开始时间戳

    # 成功标准
    success_criteria: StageSuccessCriteria

    # 攻击策略
    primary_strategy: str            # 主攻击策略描述
    fallback_strategies: List[str]   # 备选策略列表

    # 目标提示
    goals: List[str]                 # 阶段目标列表
    hints: List[str]                 # 阶段提示

    # 状态
    is_completed: bool               # 是否已完成
    is_skipped: bool                 # 是否被跳过
    completion_reason: str           # 完成原因


class StagePlan(TypedDict):
    """阶段性计划"""
    # 计划类型
    plan_type: Literal["ctf", "internal"]  # CTF或内网渗透

    # 阶段列表
    stages: List[Stage]

    # 当前阶段索引
    current_stage_index: int

    # 时间控制
    total_timeout: int               # 总超时时间
    start_time: float                # 计划开始时间

    # 统计信息
    completed_stages: int            # 已完成阶段数
    skipped_stages: int              # 跳过阶段数

    # 元数据
    metadata: Dict[str, Any]        # 额外元数据


# =============================================================================
# 阶段定义模板
# =============================================================================

# CTF阶段定义（30分钟熔断优化）
CTF_STAGES: List[Dict[str, Any]] = [
    {
        "stage_id": "ctf_recon",
        "stage_name": "信息收集",
        "stage_type": "recon",
        "timeout_seconds": 300,       # 5分钟
        "soft_timeout_seconds": 240,  # 4分钟开始警告
        "success_criteria": {
            "condition_type": "all",
            "conditions": [
                "tech_stack非空",
                "visited_urls >= 3",
            ],
            "threshold": None,
            "current_count": 0,
        },
        "primary_strategy": "端口扫描、目录枚举、技术栈识别、指纹收集",
        "fallback_strategies": [
            "使用更激进的扫描模式",
            "尝试常见路径字典",
            "分析响应头和错误页面",
        ],
        "goals": [
            "识别目标技术栈",
            "发现隐藏路径和入口点",
            "收集版本信息",
        ],
        "hints": [
            "关注响应头中的Server、X-Powered-By",
            "检查robots.txt和sitemap.xml",
            "观察错误页面的框架特征",
        ],
    },
    {
        "stage_id": "ctf_discovery",
        "stage_name": "漏洞发现",
        "stage_type": "discovery",
        "timeout_seconds": 480,       # 8分钟
        "soft_timeout_seconds": 360,  # 6分钟开始警告
        "success_criteria": {
            "condition_type": "any",
            "conditions": [
                "vuln_candidates非空",
                "发现可疑注入点",
                "检测到敏感文件",
            ],
            "threshold": None,
            "current_count": 0,
        },
        "primary_strategy": "漏洞扫描、参数测试、敏感路径探测",
        "fallback_strategies": [
            "使用模糊测试发现隐藏参数",
            "尝试各种注入类型",
            "检查文件上传点",
        ],
        "goals": [
            "发现至少一个潜在漏洞",
            "识别攻击面",
            "确定漏洞类型",
        ],
        "hints": [
            "优先测试已知漏洞类型",
            "关注异常响应和错误信息",
            "尝试绕过WAF的payload",
        ],
    },
    {
        "stage_id": "ctf_exploitation",
        "stage_name": "漏洞利用",
        "stage_type": "exploitation",
        "timeout_seconds": 600,       # 10分钟
        "soft_timeout_seconds": 480,  # 8分钟开始警告
        "success_criteria": {
            "condition_type": "any",
            "conditions": [
                "shell_session不为空",
                "found_flag为True",
                "获取有效凭据",
            ],
            "threshold": None,
            "current_count": 0,
        },
        "primary_strategy": "漏洞利用、payload构造、获取shell或flag",
        "fallback_strategies": [
            "尝试不同的payload编码",
            "利用链组合攻击",
            "尝试其他漏洞类型",
        ],
        "goals": [
            "成功利用漏洞",
            "获取目标访问权限",
            "执行任意代码或命令",
        ],
        "hints": [
            "根据漏洞类型选择payload",
            "注意特殊字符和编码",
            "尝试反向shell",
        ],
    },
    {
        "stage_id": "ctf_post_exploit",
        "stage_name": "后渗透",
        "stage_type": "post_exploit",
        "timeout_seconds": 300,       # 5分钟
        "soft_timeout_seconds": 240,  # 4分钟开始警告
        "success_criteria": {
            "condition_type": "any",
            "conditions": [
                "is_admin为True",
                "credentials数量增加",
                "发现敏感文件",
            ],
            "threshold": None,
            "current_count": 0,
        },
        "primary_strategy": "权限提升、凭据收集、横向探测",
        "fallback_strategies": [
            "尝试内核提权",
            "查找配置文件中的密码",
            "枚举系统信息",
        ],
        "goals": [
            "提升当前权限",
            "收集更多凭据",
            "发现其他攻击面",
        ],
        "hints": [
            "检查sudo权限和SUID文件",
            "查找历史文件和配置文件",
            "枚举用户和组",
        ],
    },
    {
        "stage_id": "ctf_flag_capture",
        "stage_name": "FLAG获取",
        "stage_type": "flag_capture",
        "timeout_seconds": 120,       # 2分钟
        "soft_timeout_seconds": 90,   # 1.5分钟开始警告
        "success_criteria": {
            "condition_type": "threshold",
            "conditions": [
                "found_flags数量增加",
            ],
            "threshold": 1,
            "current_count": 0,
        },
        "primary_strategy": "搜索FLAG、读取敏感文件、解码隐藏数据",
        "fallback_strategies": [
            "搜索更多路径",
            "尝试解码隐藏数据",
            "检查环境变量",
        ],
        "goals": [
            "找到并提交FLAG",
            "完成任务目标",
        ],
        "hints": [
            "FLAG通常在/root、/home、/var/www",
            "注意FLAG格式（flag{xxx}或类似）",
            "检查数据库和配置文件",
        ],
    },
]

# 内网渗透阶段定义（50分钟熔断优化）
INTERNAL_STAGES: List[Dict[str, Any]] = [
    {
        "stage_id": "internal_foothold",
        "stage_name": "立足点",
        "stage_type": "foothold",
        "timeout_seconds": 600,       # 10分钟
        "soft_timeout_seconds": 480,  # 8分钟开始警告
        "success_criteria": {
            "condition_type": "any",
            "conditions": [
                "shell_session不为空",
                "获取初始访问权限",
                "建立隧道连接",
            ],
            "threshold": None,
            "current_count": 0,
        },
        "primary_strategy": "外网打点、建立隧道、获取初始shell",
        "fallback_strategies": [
            "尝试其他入口点",
            "使用代理链",
            "尝试不同的利用方式",
        ],
        "goals": [
            "获取内网入口",
            "建立稳定的访问通道",
            "上传必要工具",
        ],
        "hints": [
            "优先选择稳定的反弹shell",
            "建立SOCKS5代理",
            "上传信息收集工具",
        ],
    },
    {
        "stage_id": "internal_recon",
        "stage_name": "内网侦察",
        "stage_type": "internal_recon",
        "timeout_seconds": 480,       # 8分钟
        "soft_timeout_seconds": 360,  # 6分钟开始警告
        "success_criteria": {
            "condition_type": "threshold",
            "conditions": [
                "internal_hosts数量 >= 3",
                "发现域控",
                "识别高价值目标",
            ],
            "threshold": 3,
            "current_count": 0,
        },
        "primary_strategy": "内网扫描、端口探测、域信息收集",
        "fallback_strategies": [
            "使用被动侦察",
            "查询域DNS记录",
            "分析网络流量",
        ],
        "goals": [
            "发现内网主机",
            "识别域环境",
            "枚举高价值目标",
        ],
        "hints": [
            "扫描内网网段",
            "识别域控制器",
            "枚举域用户和组",
        ],
    },
    {
        "stage_id": "internal_lateral",
        "stage_name": "横向移动",
        "stage_type": "lateral_move",
        "timeout_seconds": 900,       # 15分钟
        "soft_timeout_seconds": 720,  # 12分钟开始警告
        "success_criteria": {
            "condition_type": "any",
            "conditions": [
                "compromised_hosts数量增加",
                "获取域用户凭据",
                "访问域控",
            ],
            "threshold": None,
            "current_count": 0,
        },
        "primary_strategy": "凭据复用、票据攻击、横向渗透",
        "fallback_strategies": [
            "尝试其他协议（WinRM/WMI）",
            "利用零信任漏洞",
            "尝试票据传递攻击",
        ],
        "goals": [
            "获取更多主机权限",
            "收集域凭据",
            "接近域控",
        ],
        "hints": [
            "使用crackmapexec批量测试",
            "尝试哈希传递",
            "查找域管理员会话",
        ],
    },
    {
        "stage_id": "internal_privilege",
        "stage_name": "权限提升",
        "stage_type": "privilege_escalation",
        "timeout_seconds": 600,       # 10分钟
        "soft_timeout_seconds": 480,  # 8分钟开始警告
        "success_criteria": {
            "condition_type": "any",
            "conditions": [
                "获取域管理员权限",
                "获取域控权限",
                "获取系统权限",
            ],
            "threshold": None,
            "current_count": 0,
        },
        "primary_strategy": "域提权、获取域控、权限维持",
        "fallback_strategies": [
            "尝试域提权漏洞",
            "攻击域控服务",
            "利用信任关系",
        ],
        "goals": [
            "获取高权限账户",
            "控制域控",
            "建立持久化访问",
        ],
        "hints": [
            "查找域提权漏洞",
            "攻击Kerberos",
            "利用委派攻击",
        ],
    },
    {
        "stage_id": "internal_persistence",
        "stage_name": "持久化和FLAG",
        "stage_type": "persistence_flag",
        "timeout_seconds": 420,       # 7分钟
        "soft_timeout_seconds": 300,  # 5分钟开始警告
        "success_criteria": {
            "condition_type": "threshold",
            "conditions": [
                "found_flags数量 >= 1",
                "persistence_established为True",
            ],
            "threshold": 1,
            "current_count": 0,
        },
        "primary_strategy": "搜索FLAG、建立后门、清理痕迹",
        "fallback_strategies": [
            "搜索更多位置",
            "尝试不同用户账户",
            "检查域控数据库",
        ],
        "goals": [
            "找到所有FLAG",
            "建立持久化访问",
            "完成攻击目标",
        ],
        "hints": [
            "FLAG可能在域控、数据库、文件服务器",
            "建立多种持久化方式",
            "注意清除日志",
        ],
    },
]


# =============================================================================
# 成功标准评估函数
# =============================================================================

def evaluate_success_criteria(state: Dict[str, Any], criteria: StageSuccessCriteria) -> tuple[bool, int]:
    """
    评估阶段成功标准

    Args:
        state: 当前状态
        criteria: 成功标准

    Returns:
        (是否满足, 当前满足数量)
    """
    conditions_met = 0
    total_conditions = len(criteria.get("conditions", []))

    for condition in criteria.get("conditions", []):
        if _check_single_condition(state, condition):
            conditions_met += 1

    condition_type = criteria.get("condition_type", "any")

    if condition_type == "any":
        return conditions_met > 0, conditions_met
    elif condition_type == "all":
        return conditions_met == total_conditions, conditions_met
    elif condition_type == "threshold":
        threshold = criteria.get("threshold", 1)
        return conditions_met >= threshold, conditions_met

    return False, conditions_met


def _check_single_condition(state: Dict[str, Any], condition: str) -> bool:
    """
    检查单个条件

    支持的条件格式:
    - "field非空": 字段不为空
    - "field >= N": 字段值大于等于N
    - "field为True": 布尔字段为True
    - "field数量增加": 列表字段长度增加
    """
    try:
        # 处理 "field非空"
        if "非空" in condition:
            field = condition.split("非空")[0].strip()
            value = state.get(field)
            if value is None:
                return False
            if isinstance(value, (list, dict, str)):
                return len(value) > 0
            return bool(value)

        # 处理 "field >= N"
        if ">=" in condition:
            parts = condition.split(">=")
            field = parts[0].strip()
            threshold = int(parts[1].strip())
            value = state.get(field, [])
            if isinstance(value, list):
                return len(value) >= threshold
            return value >= threshold

        # 处理 "field为True"
        if "为True" in condition:
            field = condition.split("为True")[0].strip()
            return state.get(field, False) is True

        # 处理 "field不为空"
        if "不为空" in condition:
            field = condition.split("不为空")[0].strip()
            value = state.get(field)
            if value is None:
                return False
            if isinstance(value, (list, dict, str)):
                return len(value) > 0
            return bool(value)

        # 处理 "field数量增加" (需要与之前状态比较，暂不实现)
        if "数量增加" in condition:
            field = condition.split("数量增加")[0].strip()
            value = state.get(field, [])
            if isinstance(value, list):
                return len(value) > 0
            return False

        # 默认：检查字段是否存在且非空
        field = condition.split()[0] if " " in condition else condition
        value = state.get(field)
        if value is None:
            return False
        if isinstance(value, (list, dict, str)):
            return len(value) > 0
        return bool(value)

    except Exception as e:
        logger.warning(f"条件检查失败: {condition}, 错误: {e}")
        return False


# =============================================================================
# 主类：StagedPlanner
# =============================================================================

class StagedPlanner:
    """
    阶段性计划器

    负责管理CTF和内网渗透的分阶段攻击计划，包括：
    - 阶段进度跟踪
    - 超时管理
    - 成功标准评估
    - 备选策略生成
    """

    def __init__(
        self,
        plan_type: Literal["ctf", "internal"],
        stages: List[Dict[str, Any]],
        total_timeout: int,
    ):
        """
        初始化阶段计划器

        Args:
            plan_type: 计划类型（ctf/internal）
            stages: 阶段定义列表
            total_timeout: 总超时时间（秒）
        """
        self.plan_type = plan_type
        self.total_timeout = total_timeout
        self.start_time = time.time()

        # 初始化阶段
        self.stages: List[Stage] = []
        for stage_def in stages:
            stage: Stage = {
                "stage_id": stage_def["stage_id"],
                "stage_name": stage_def["stage_name"],
                "stage_type": stage_def["stage_type"],
                "timeout_seconds": stage_def["timeout_seconds"],
                "soft_timeout_seconds": stage_def.get("soft_timeout_seconds", stage_def["timeout_seconds"] - 60),
                "start_time": None,
                "success_criteria": stage_def["success_criteria"].copy(),
                "primary_strategy": stage_def["primary_strategy"],
                "fallback_strategies": stage_def.get("fallback_strategies", []),
                "goals": stage_def.get("goals", []),
                "hints": stage_def.get("hints", []),
                "is_completed": False,
                "is_skipped": False,
                "completion_reason": "",
            }
            self.stages.append(stage)

        self.current_stage_index = 0
        self.completed_stages = 0
        self.skipped_stages = 0
        self.metadata: Dict[str, Any] = {}

        logger.info(f"[{plan_type.upper()}] 阶段计划器初始化完成，共{len(self.stages)}个阶段，总超时{total_timeout}秒")

    def get_current_stage(self) -> Optional[Stage]:
        """获取当前阶段"""
        if self.current_stage_index >= len(self.stages):
            return None
        return self.stages[self.current_stage_index]

    def get_current_stage_index(self) -> int:
        """获取当前阶段索引"""
        return self.current_stage_index

    def get_stage_by_index(self, index: int) -> Optional[Stage]:
        """根据索引获取阶段"""
        if 0 <= index < len(self.stages):
            return self.stages[index]
        return None

    def start_stage(self, index: Optional[int] = None) -> Stage:
        """
        开始指定阶段

        Args:
            index: 阶段索引，None则开始当前阶段

        Returns:
            开始的阶段
        """
        if index is not None:
            self.current_stage_index = min(index, len(self.stages) - 1)

        stage = self.get_current_stage()
        if stage:
            stage["start_time"] = time.time()
            stage["is_completed"] = False
            stage["is_skipped"] = False
            stage["completion_reason"] = ""
            logger.info(f"[{self.plan_type.upper()}] 开始阶段 {self.current_stage_index + 1}/{len(self.stages)}: {stage['stage_name']}")

        return stage

    def should_advance(self, state: Dict[str, Any]) -> tuple[bool, str]:
        """
        检查是否应该进入下一阶段

        Args:
            state: 当前状态

        Returns:
            (是否应该前进, 原因)
        """
        stage = self.get_current_stage()
        if not stage:
            return True, "已完成所有阶段"

        # 检查阶段是否已完成
        if stage["is_completed"]:
            return True, "阶段已完成"

        # 检查成功标准
        success, count = evaluate_success_criteria(state, stage["success_criteria"])
        if success:
            return True, f"成功标准已满足 (满足条件数: {count})"

        # 检查超时
        if stage["start_time"]:
            elapsed = time.time() - stage["start_time"]
            if elapsed >= stage["timeout_seconds"]:
                return True, f"阶段超时 (已用时: {elapsed:.0f}秒/{stage['timeout_seconds']}秒)"

        # 检查总超时
        total_elapsed = time.time() - self.start_time
        if total_elapsed >= self.total_timeout:
            return True, f"总时间超时 (已用时: {total_elapsed:.0f}秒/{self.total_timeout}秒)"

        # 检查是否已找到flag
        if state.get("found_flag") or len(state.get("found_flags", [])) > 0:
            # 如果是最后一个阶段，不需要前进
            if self.current_stage_index == len(self.stages) - 1:
                return False, "已找到FLAG，继续当前阶段"
            return True, "已找到FLAG，跳转到FLAG获取阶段"

        return False, "继续当前阶段"

    def advance_stage(self, reason: str = "") -> Optional[Stage]:
        """
        前进到下一阶段

        Args:
            reason: 前进原因

        Returns:
            新的阶段，如果没有更多阶段则返回None
        """
        current = self.get_current_stage()
        if current:
            current["is_completed"] = True
            current["completion_reason"] = reason
            self.completed_stages += 1
            logger.info(f"[{self.plan_type.upper()}] 完成阶段 {self.current_stage_index + 1}: {current['stage_name']} - {reason}")

        self.current_stage_index += 1

        next_stage = self.get_current_stage()
        if next_stage:
            return self.start_stage()
        else:
            logger.info(f"[{self.plan_type.upper()}] 所有阶段已完成")
            return None

    def skip_stage(self, reason: str = "") -> Optional[Stage]:
        """
        跳过当前阶段

        Args:
            reason: 跳过原因

        Returns:
            新的阶段
        """
        current = self.get_current_stage()
        if current:
            current["is_skipped"] = True
            current["is_completed"] = True
            current["completion_reason"] = f"跳过: {reason}"
            self.skipped_stages += 1
            logger.warning(f"[{self.plan_type.upper()}] 跳过阶段 {self.current_stage_index + 1}: {current['stage_name']} - {reason}")

        self.current_stage_index += 1

        next_stage = self.get_current_stage()
        if next_stage:
            return self.start_stage()
        return None

    def get_fallback_strategies(self, state: Dict[str, Any]) -> List[str]:
        """
        获取当前阶段的备选策略

        Args:
            state: 当前状态

        Returns:
            备选策略列表
        """
        stage = self.get_current_stage()
        if not stage:
            return []

        strategies = stage.get("fallback_strategies", [])

        # 根据当前状态添加动态策略
        if self.plan_type == "ctf":
            # 根据失败次数添加策略
            failure_count = state.get("rule_miss_count", 0)
            if failure_count > 3:
                strategies.append("切换到探索模式，尝试更多攻击向量")
            if failure_count > 5:
                strategies.append("进入创新模式，尝试非常规方法")

        elif self.plan_type == "internal":
            # 内网渗透特定策略
            internal_hosts = state.get("internal_hosts", [])
            if len(internal_hosts) == 0:
                strategies.append("扩大扫描范围，使用更多端口")

            active_sessions = state.get("active_sessions", [])
            if not active_sessions:
                strategies.append("检查隧道状态，重新建立连接")

        return strategies

    def get_stage_progress(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """
        获取阶段进度信息

        Args:
            state: 当前状态

        Returns:
            进度信息字典
        """
        stage = self.get_current_stage()
        if not stage:
            return {
                "status": "completed",
                "message": "所有阶段已完成",
                "total_stages": len(self.stages),
                "completed_stages": self.completed_stages,
                "skipped_stages": self.skipped_stages,
            }

        # 计算时间
        stage_elapsed = 0
        if stage.get("start_time"):
            stage_elapsed = time.time() - stage["start_time"]

        total_elapsed = time.time() - self.start_time

        # 评估成功标准
        success, count = evaluate_success_criteria(state, stage["success_criteria"])

        return {
            "status": "in_progress",
            "plan_type": self.plan_type,
            "current_stage": {
                "index": self.current_stage_index + 1,
                "id": stage["stage_id"],
                "name": stage["stage_name"],
                "type": stage["stage_type"],
            },
            "timing": {
                "stage_elapsed": stage_elapsed,
                "stage_timeout": stage["timeout_seconds"],
                "total_elapsed": total_elapsed,
                "total_timeout": self.total_timeout,
                "stage_progress": min(stage_elapsed / stage["timeout_seconds"], 1.0),
                "total_progress": min(total_elapsed / self.total_timeout, 1.0),
            },
            "success_criteria": {
                "met": success,
                "current_count": count,
                "conditions": stage["success_criteria"]["conditions"],
            },
            "strategies": {
                "primary": stage["primary_strategy"],
                "fallbacks": stage.get("fallback_strategies", []),
            },
            "goals": stage.get("goals", []),
            "hints": stage.get("hints", []),
            "statistics": {
                "total_stages": len(self.stages),
                "completed_stages": self.completed_stages,
                "skipped_stages": self.skipped_stages,
            },
        }

    def get_time_warning(self, state: Dict[str, Any]) -> Optional[str]:
        """
        获取时间警告信息

        Args:
            state: 当前状态

        Returns:
            警告信息，如果无需警告则返回None
        """
        stage = self.get_current_stage()
        if not stage:
            return None

        if not stage.get("start_time"):
            return None

        elapsed = time.time() - stage["start_time"]
        soft_timeout = stage.get("soft_timeout_seconds", stage["timeout_seconds"] - 60)

        # 软超时警告
        if elapsed >= soft_timeout and elapsed < stage["timeout_seconds"]:
            remaining = stage["timeout_seconds"] - elapsed
            return f"阶段即将超时: {stage['stage_name']} 剩余 {remaining:.0f} 秒"

        # 总时间警告
        total_elapsed = time.time() - self.start_time
        total_soft = self.total_timeout * 0.8

        if total_elapsed >= total_soft and total_elapsed < self.total_timeout:
            remaining = self.total_timeout - total_elapsed
            return f"总时间即将耗尽: 剩余 {remaining:.0f} 秒"

        return None

    def should_skip_to_flag(self, state: Dict[str, Any]) -> bool:
        """
        检查是否应该跳转到FLAG获取阶段

        当已找到FLAG或时间紧迫时使用

        Args:
            state: 当前状态

        Returns:
            是否应该跳转
        """
        # 如果已找到flag
        if state.get("found_flag"):
            return True

        found_flags = state.get("found_flags", [])
        if len(found_flags) > 0:
            return True

        # 如果时间紧迫（剩余时间少于总时间的20%）
        total_elapsed = time.time() - self.start_time
        remaining = self.total_timeout - total_elapsed

        if remaining < self.total_timeout * 0.2:
            # 只在非最后阶段时跳转
            if self.current_stage_index < len(self.stages) - 1:
                return True

        return False

    def jump_to_stage(self, stage_type: str) -> Optional[Stage]:
        """
        跳转到指定类型的阶段

        Args:
            stage_type: 目标阶段类型

        Returns:
            目标阶段
        """
        for i, stage in enumerate(self.stages):
            if stage["stage_type"] == stage_type and not stage["is_completed"]:
                # 标记中间阶段为跳过
                for j in range(self.current_stage_index, i):
                    self.stages[j]["is_skipped"] = True
                    self.stages[j]["is_completed"] = True
                    self.stages[j]["completion_reason"] = "跳过（跳转到后续阶段）"
                    self.skipped_stages += 1

                self.current_stage_index = i
                logger.info(f"[{self.plan_type.upper()}] 跳转到阶段 {i + 1}: {stage['stage_name']}")
                return self.start_stage(i)

        return None

    def to_dict(self) -> StagePlan:
        """转换为字典"""
        return {
            "plan_type": self.plan_type,
            "stages": self.stages,
            "current_stage_index": self.current_stage_index,
            "total_timeout": self.total_timeout,
            "start_time": self.start_time,
            "completed_stages": self.completed_stages,
            "skipped_stages": self.skipped_stages,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: StagePlan) -> "StagedPlanner":
        """从字典恢复"""
        planner = cls(
            plan_type=data["plan_type"],
            stages=data["stages"],
            total_timeout=data["total_timeout"],
        )
        planner.stages = data["stages"]
        planner.current_stage_index = data["current_stage_index"]
        planner.start_time = data["start_time"]
        planner.completed_stages = data["completed_stages"]
        planner.skipped_stages = data["skipped_stages"]
        planner.metadata = data.get("metadata", {})
        return planner


# =============================================================================
# 工厂函数
# =============================================================================

def get_ctf_planner() -> StagedPlanner:
    """
    获取CTF阶段计划器（30分钟超时）

    Returns:
        配置好的StagedPlanner实例
    """
    return StagedPlanner(
        plan_type="ctf",
        stages=CTF_STAGES,
        total_timeout=config.TASK_TIMEOUT,  # 1800秒 (30分钟)
    )


def get_internal_planner() -> StagedPlanner:
    """
    获取内网渗透阶段计划器（50分钟超时）

    Returns:
        配置好的StagedPlanner实例
    """
    return StagedPlanner(
        plan_type="internal",
        stages=INTERNAL_STAGES,
        total_timeout=config.INTERNAL_TASK_TIMEOUT,  # 3000秒 (50分钟)
    )


def get_planner_by_mode(mode: str) -> StagedPlanner:
    """
    根据模式获取计划器

    Args:
        mode: 模式（ctf/internal/web/internal_network）

    Returns:
        配置好的StagedPlanner实例
    """
    if mode in ("internal", "internal_network", "内网"):
        return get_internal_planner()
    else:
        return get_ctf_planner()


# =============================================================================
# 阶段进度辅助函数
# =============================================================================

def get_stage_guidance(state: Dict[str, Any], planner: StagedPlanner) -> str:
    """
    生成阶段指导信息

    根据当前阶段和状态，生成指导性建议

    Args:
        state: 当前状态
        planner: 阶段计划器

    Returns:
        指导信息字符串
    """
    progress = planner.get_stage_progress(state)

    if progress["status"] == "completed":
        return "所有阶段已完成"

    stage = progress["current_stage"]
    timing = progress["timing"]
    criteria = progress["success_criteria"]

    guidance_parts = [
        f"当前阶段 [{stage['name']}] ({stage['index']}/{progress['statistics']['total_stages']})",
        f"主策略: {progress['strategies']['primary']}",
        f"阶段进度: {timing['stage_progress']*100:.0f}% ({timing['stage_elapsed']:.0f}s/{timing['stage_timeout']}s)",
        f"总进度: {timing['total_progress']*100:.0f}% ({timing['total_elapsed']:.0f}s/{timing['total_timeout']}s)",
    ]

    # 添加目标
    goals = progress.get("goals", [])
    if goals:
        guidance_parts.append(f"目标: {', '.join(goals[:3])}")

    # 添加成功标准状态
    guidance_parts.append(f"成功标准: {'已满足' if criteria['met'] else '未满足'} ({criteria['current_count']}个条件)")

    # 添加警告
    warning = planner.get_time_warning(state)
    if warning:
        guidance_parts.append(f"警告: {warning}")

    # 如果成功标准未满足，添加备选策略
    if not criteria["met"]:
        fallbacks = progress["strategies"]["fallbacks"]
        if fallbacks:
            guidance_parts.append(f"备选策略: {fallbacks[0]}")

    return "\n".join(guidance_parts)


def update_state_with_stage_info(state: Dict[str, Any], planner: StagedPlanner) -> Dict[str, Any]:
    """
    更新状态中的阶段信息

    Args:
        state: 当前状态
        planner: 阶段计划器

    Returns:
        更新后的状态
    """
    progress = planner.get_stage_progress(state)

    # 更新战略上下文
    strategic_context = state.get("strategic_context", {})

    stage = progress.get("current_stage", {})
    if stage:
        strategic_context["current_stage"] = {
            "id": stage.get("id", ""),
            "name": stage.get("name", ""),
            "type": stage.get("type", ""),
            "index": stage.get("index", 0),
        }

        # 更新攻击链
        attack_chain = []
        for i, s in enumerate(planner.stages):
            prefix = "[完成]" if s.get("is_completed") else "[当前]" if i == planner.current_stage_index else "[待定]"
            attack_chain.append(f"{prefix} {s['stage_name']}")

        strategic_context["attack_chain"] = attack_chain
        strategic_context["current_step"] = stage.get("index", 1)
        strategic_context["total_steps"] = len(planner.stages)

    state["strategic_context"] = strategic_context

    return state


# =============================================================================
# 导出
# =============================================================================

__all__ = [
    # 类型
    "StageType",
    "StageSuccessCriteria",
    "Stage",
    "StagePlan",
    # 阶段定义
    "CTF_STAGES",
    "INTERNAL_STAGES",
    # 阶段名称映射
    "STAGE_NAME_MAP",
    "get_stage_display_name",
    # 主类
    "StagedPlanner",
    # 函数
    "evaluate_success_criteria",
    "get_ctf_planner",
    "get_internal_planner",
    "get_planner_by_mode",
    "get_stage_guidance",
    "update_state_with_stage_info",
]