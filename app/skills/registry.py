"""
Skill系统实现

借鉴Claude Code的Skill设计：
- 领域知识包，提供专业知识
- 工作流模板，指导Agent执行
- 工具偏好，优化工具选择
"""

import os
import yaml
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class WorkflowStep:
    """工作流步骤"""
    description: str
    suggested_tools: List[str] = field(default_factory=list)
    expected_output: str = ""


@dataclass
class Workflow:
    """工作流定义"""
    name: str
    description: str = ""
    steps: List[WorkflowStep] = field(default_factory=list)


@dataclass
class ToolPreference:
    """工具偏好"""
    tool_name: str
    score: float  # 0.0 - 1.0，越高越优先
    reason: str = ""


@dataclass
class Example:
    """示例场景"""
    scenario: str
    solution: str
    tools_used: List[str] = field(default_factory=list)


@dataclass
class Skill:
    """Skill定义"""
    name: str
    description: str
    domain: str

    # 知识内容
    knowledge: str = ""

    # 工作流模板
    workflows: List[Workflow] = field(default_factory=list)

    # 工具偏好
    tool_preferences: List[ToolPreference] = field(default_factory=list)

    # 示例
    examples: List[Example] = field(default_factory=list)

    # 元数据
    version: str = "1.0"
    tags: List[str] = field(default_factory=list)

    @classmethod
    def from_yaml(cls, yaml_path: str) -> "Skill":
        """从YAML文件加载Skill"""
        with open(yaml_path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)

        return cls._parse_dict(data)

    @classmethod
    def _parse_dict(cls, data: Dict) -> "Skill":
        """解析字典为Skill对象"""
        workflows = []
        for wf_data in data.get("workflows", []):
            steps = []
            for step_data in wf_data.get("steps", []):
                steps.append(WorkflowStep(
                    description=step_data.get("description", ""),
                    suggested_tools=step_data.get("suggested_tools", []),
                    expected_output=step_data.get("expected_output", "")
                ))
            workflows.append(Workflow(
                name=wf_data.get("name", ""),
                description=wf_data.get("description", ""),
                steps=steps
            ))

        tool_prefs = []
        for pref_data in data.get("tool_preferences", {}).items():
            if isinstance(pref_data[1], dict):
                tool_prefs.append(ToolPreference(
                    tool_name=pref_data[0],
                    score=pref_data[1].get("score", 0.5),
                    reason=pref_data[1].get("reason", "")
                ))
            else:
                tool_prefs.append(ToolPreference(
                    tool_name=pref_data[0],
                    score=float(pref_data[1]),
                    reason=""
                ))

        examples = []
        for ex_data in data.get("examples", []):
            examples.append(Example(
                scenario=ex_data.get("scenario", ""),
                solution=ex_data.get("solution", ""),
                tools_used=ex_data.get("tools_used", [])
            ))

        return cls(
            name=data.get("name", ""),
            description=data.get("description", ""),
            domain=data.get("domain", ""),
            knowledge=data.get("knowledge", ""),
            workflows=workflows,
            tool_preferences=tool_prefs,
            examples=examples,
            version=data.get("version", "1.0"),
            tags=data.get("tags", [])
        )


class SkillRegistry:
    """
    Skill注册表

    管理Skill的加载、匹配、推荐
    """

    def __init__(self):
        self._skills: Dict[str, Skill] = {}
        self._domain_index: Dict[str, List[str]] = {}
        self._tag_index: Dict[str, List[str]] = {}

    def register(self, skill: Skill) -> None:
        """注册Skill"""
        self._skills[skill.name] = skill

        # 建立域索引
        if skill.domain not in self._domain_index:
            self._domain_index[skill.domain] = []
        self._domain_index[skill.domain].append(skill.name)

        # 建立标签索引
        for tag in skill.tags:
            if tag not in self._tag_index:
                self._tag_index[tag] = []
            self._tag_index[tag].append(skill.name)

    def load_from_directory(self, directory: str) -> int:
        """
        从目录加载所有Skill

        Args:
            directory: Skill YAML文件目录

        Returns:
            加载的Skill数量
        """
        count = 0
        dir_path = Path(directory)

        if not dir_path.exists():
            return 0

        for yaml_file in dir_path.glob("*.yaml"):
            try:
                skill = Skill.from_yaml(str(yaml_file))
                # 使用文件名作为唯一标识，避免name字段重复导致覆盖
                skill_id = yaml_file.stem  # 文件名去掉.yaml后缀

                # 如果name为空或重复，使用文件名作为name
                if not skill.name or skill.name in self._skills:
                    # 保留原name作为显示名，但使用文件名作为注册ID
                    skill_display_name = skill.name or skill_id
                    skill.name = skill_id  # 注册用的唯一ID

                self.register(skill)
                count += 1
            except Exception as e:
                print(f"加载Skill失败 {yaml_file}: {e}")

        return count

    def get_skill(self, name: str) -> Optional[Skill]:
        """获取指定Skill"""
        return self._skills.get(name)

    def list_skills(self) -> List[str]:
        """列出所有Skill名称"""
        return list(self._skills.keys())

    def get_skills_by_domain(self, domain: str) -> List[Skill]:
        """按域获取Skills"""
        skill_names = self._domain_index.get(domain, [])
        return [self._skills[name] for name in skill_names]

    def get_skills_by_tag(self, tag: str) -> List[Skill]:
        """按标签获取Skills"""
        skill_names = self._tag_index.get(tag, [])
        return [self._skills[name] for name in skill_names]

    def find_matching_skills(
        self,
        context: Dict[str, Any]
    ) -> List[Skill]:
        """
        根据上下文匹配合适的Skills

        Args:
            context: 包含task, target, vulns等信息的上下文

        Returns:
            匹配的Skill列表，按相关性排序
        """
        matches = []
        task = context.get("task", "").lower()
        target = context.get("target", "")
        vulns = context.get("vulns", [])

        for skill in self._skills.values():
            score = self._calculate_relevance(skill, task, target, vulns)
            if score > 0:
                matches.append((skill, score))

        # 按相关性排序
        matches.sort(key=lambda x: x[1], reverse=True)
        return [skill for skill, _ in matches]

    def _calculate_relevance(
        self,
        skill: Skill,
        task: str,
        target: str,
        vulns: List
    ) -> float:
        """计算Skill与任务的相关性"""
        score = 0.0

        # 任务描述匹配
        if skill.domain.lower() in task:
            score += 0.5

        # 标签匹配
        for tag in skill.tags:
            if tag.lower() in task:
                score += 0.3

        # 知识内容匹配
        knowledge_lower = skill.knowledge.lower()
        task_words = task.split()
        for word in task_words:
            if len(word) > 3 and word in knowledge_lower:
                score += 0.1

        # 工作流匹配
        for workflow in skill.workflows:
            if any(word in workflow.name.lower() for word in task_words if len(word) > 3):
                score += 0.2

        return min(score, 1.0)

    def get_tool_recommendation(
        self,
        skill_name: str,
        task_type: str = ""
    ) -> List[ToolPreference]:
        """
        获取工具推荐

        Args:
            skill_name: Skill名称
            task_type: 任务类型（可选）

        Returns:
            工具偏好列表，按score排序
        """
        skill = self.get_skill(skill_name)
        if not skill:
            return []

        prefs = sorted(skill.tool_preferences, key=lambda x: x.score, reverse=True)
        return prefs


# 全局注册表实例
_registry: Optional[SkillRegistry] = None


def get_skill_registry() -> SkillRegistry:
    """获取全局Skill注册表"""
    global _registry
    if _registry is None:
        _registry = SkillRegistry()
    return _registry