"""
Skill系统

提供领域知识包：
- web_exploitation: Web渗透技能
- internal_network: 内网渗透技能
- ad_attack: 域渗透技能
- cloud_attack: 云安全技能
"""

from pathlib import Path
from .registry import (
    SkillRegistry,
    Skill,
    Workflow,
    WorkflowStep,
    ToolPreference,
    Example,
    get_skill_registry,
)


def load_all_skills():
    """加载所有Skill定义"""
    registry = get_skill_registry()

    # 加载项目根目录的 skills/ 文件夹
    project_root = Path(__file__).parent.parent.parent
    skills_dir = project_root / "skills"

    if skills_dir.exists():
        count = registry.load_from_directory(str(skills_dir))
        print(f"[Skills] 成功加载 {count} 个Skills")
        return count
    else:
        print(f"[Skills] 警告: {skills_dir} 不存在")
        return 0


__all__ = [
    "SkillRegistry",
    "Skill",
    "Workflow",
    "WorkflowStep",
    "ToolPreference",
    "Example",
    "get_skill_registry",
    "load_all_skills",
]