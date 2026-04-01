"""
Skill系统

提供领域知识包：
- web_exploitation: Web渗透技能
- internal_network: 内网渗透技能
- ad_attack: 域渗透技能
- cloud_attack: 云安全技能
"""

from .registry import (
    SkillRegistry,
    Skill,
    Workflow,
    WorkflowStep,
    ToolPreference,
    Example,
    get_skill_registry,
)

__all__ = [
    "SkillRegistry",
    "Skill",
    "Workflow",
    "WorkflowStep",
    "ToolPreference",
    "Example",
    "get_skill_registry",
]