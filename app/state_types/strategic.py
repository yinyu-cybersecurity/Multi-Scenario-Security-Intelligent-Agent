# app/state_types/strategic.py - AI战略上下文类型定义
# 作用：定义AI思维框架的结构化字段

from typing import TypedDict, List, Dict, Any, Literal


class StrategicContext(TypedDict):
    """
    AI战略上下文 - 让AI像人一样思考和规划

    这个结构帮助AI建立"心理地图"，包含：
    1. 空间认知：知道自己在哪（web/internal/cloud/ai）
    2. 目标规划：知道要做什么，分几步
    3. 资源映射：知道有什么可用凭据
    4. 障碍感知：知道有什么阻碍
    5. 备选方案：知道失败后怎么做
    """

    # 空间认知
    position_type: str          # 当前位置类型: "web" / "internal" / "cloud" / "ai" / "crypto" / "pwn" / "reverse" / "misc"
    position_detail: str        # 详细位置: "scene=Spring" / "host=192.168.1.5" / "provider=aws"

    # 目标规划
    primary_goal: str           # 当前主要目标描述
    attack_chain: List[str]     # 攻击链步骤: ["信息收集", "漏洞确认", "利用执行", "后渗透", "FLAG获取"]
    current_step: int           # 当前处于第几步 (从1开始)
    total_steps: int            # 总步骤数

    # 资源映射
    credential_access: List[Dict[str, Any]]  # 可用凭据: [{"username": "admin", "password": "pass", "scope": "192.168.1.*"}]

    # 障碍与备选
    blockers: List[str]         # 当前障碍列表: ["WAF拦截", "认证失败", "端口未开放"]
    alternate_routes: List[str] # 备选路径: ["尝试其他参数", "切换攻击类型", "横向移动"]


def get_default_strategic_context() -> StrategicContext:
    """获取默认战略上下文"""
    return {
        "position_type": "web",
        "position_detail": "",
        "primary_goal": "获取FLAG",
        "attack_chain": ATTACK_PHASES["web"],
        "current_step": 1,
        "total_steps": len(ATTACK_PHASES["web"]),
        "credential_access": [],
        "blockers": [],
        "alternate_routes": [],
    }


def update_strategic_position(
    context: StrategicContext,
    position_type: str,
    position_detail: str
) -> StrategicContext:
    """更新空间认知"""
    context["position_type"] = position_type
    context["position_detail"] = position_detail
    return context


def update_attack_progress(
    context: StrategicContext,
    current_step: int,
    blockers: List[str] = None,
    alternate_routes: List[str] = None
) -> StrategicContext:
    """更新攻击进度"""
    context["current_step"] = current_step
    if blockers:
        context["blockers"] = blockers
    if alternate_routes:
        context["alternate_routes"] = alternate_routes
    return context


def add_credential(
    context: StrategicContext,
    credential: Dict[str, Any]
) -> StrategicContext:
    """添加可用凭据"""
    context["credential_access"].append(credential)
    return context


# 场景类型枚举
PositionType = Literal[
    "web",
    "internal",
    "cloud",
    "ai",
    "crypto",
    "pwn",
    "reverse",
    "misc",
]


# 攻击阶段映射
ATTACK_PHASES = {
    "web": ["侦察", "分析", "攻击", "验证", "FLAG"],
    "internal": ["立足点", "侦察", "横向移动", "权限提升", "FLAG"],
    "cloud": ["元数据泄露", "权限枚举", "利用", "提权", "FLAG"],
    "ai": ["检测", "探测", "注入", "泄露", "FLAG"],
    "crypto": ["密文分析", "算法识别", "密钥恢复", "解密", "FLAG"],
    "pwn": ["逆向分析", "漏洞识别", "利用开发", "获取Shell", "FLAG"],
    "reverse": ["静态分析", "动态调试", "算法还原", "密钥提取", "FLAG"],
    "misc": ["文件分析", "编码识别", "数据提取", "解密", "FLAG"],
}