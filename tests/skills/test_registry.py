"""
SkillRegistry单元测试
"""

import os
import pytest
import tempfile
import yaml

from app.skills.registry import (
    SkillRegistry,
    Skill,
    Workflow,
    WorkflowStep,
    ToolPreference,
    Example,
    get_skill_registry,
)


class TestSkillModels:
    """测试Skill数据模型"""

    def test_workflow_step_creation(self):
        """测试工作流步骤创建"""
        step = WorkflowStep(
            description="扫描目标",
            suggested_tools=["nmap"],
            expected_output="端口列表"
        )
        assert step.description == "扫描目标"
        assert "nmap" in step.suggested_tools

    def test_skill_creation(self):
        """测试Skill创建"""
        skill = Skill(
            name="test_skill",
            description="测试技能",
            domain="test"
        )
        assert skill.name == "test_skill"
        assert skill.domain == "test"


class TestSkillFromYaml:
    """测试从YAML加载Skill"""

    def test_load_from_yaml(self, tmp_path):
        """测试YAML加载"""
        yaml_content = """
name: test_skill
description: 测试技能
domain: web
version: "1.0"
tags:
  - web
  - test
knowledge: |
  这是测试知识
workflows:
  - name: test_workflow
    steps:
      - description: 步骤1
        suggested_tools: ["tool1"]
tool_preferences:
  tool1: 0.9
examples:
  - scenario: 场景1
    solution: 解决方案1
"""
        yaml_file = tmp_path / "test_skill.yaml"
        yaml_file.write_text(yaml_content, encoding='utf-8')

        skill = Skill.from_yaml(str(yaml_file))

        assert skill.name == "test_skill"
        assert skill.domain == "web"
        assert "web" in skill.tags
        assert len(skill.workflows) == 1
        assert len(skill.tool_preferences) == 1
        assert skill.tool_preferences[0].score == 0.9


class TestSkillRegistry:
    """测试SkillRegistry"""

    def test_register_skill(self):
        """测试注册Skill"""
        registry = SkillRegistry()
        skill = Skill(name="test", description="测试", domain="test")

        registry.register(skill)

        assert "test" in registry.list_skills()
        assert registry.get_skill("test") == skill

    def test_load_from_directory(self, tmp_path):
        """测试从目录加载"""
        # 创建YAML文件
        yaml_content = """
name: skill1
description: 技能1
domain: web
tags: [web]
knowledge: 知识
"""
        yaml_file = tmp_path / "skill1.yaml"
        yaml_file.write_text(yaml_content, encoding='utf-8')

        registry = SkillRegistry()
        count = registry.load_from_directory(str(tmp_path))

        assert count == 1
        assert "skill1" in registry.list_skills()

    def test_find_matching_skills(self):
        """测试匹配Skills"""
        registry = SkillRegistry()

        # 注册测试Skills
        registry.register(Skill(
            name="web_skill",
            description="Web技能",
            domain="web",
            tags=["http", "injection"],
            knowledge="SQL injection XSS vulnerability"
        ))
        registry.register(Skill(
            name="internal_skill",
            description="内网技能",
            domain="internal",
            tags=["smb", "lateral"],
            knowledge="lateral movement domain"
        ))

        # 测试匹配 - domain "web" 在 task 中
        matches = registry.find_matching_skills({
            "task": "web sql injection"
        })

        assert len(matches) > 0
        assert matches[0].name == "web_skill"

    def test_get_tool_recommendation(self):
        """测试工具推荐"""
        registry = SkillRegistry()

        skill = Skill(
            name="test",
            description="测试",
            domain="test",
            tool_preferences=[
                ToolPreference(tool_name="tool_a", score=0.9),
                ToolPreference(tool_name="tool_b", score=0.7),
            ]
        )
        registry.register(skill)

        recs = registry.get_tool_recommendation("test")

        assert len(recs) == 2
        assert recs[0].tool_name == "tool_a"
        assert recs[0].score > recs[1].score


class TestGlobalRegistry:
    """测试全局注册表"""

    def test_get_skill_registry(self):
        """测试获取全局注册表"""
        registry1 = get_skill_registry()
        registry2 = get_skill_registry()

        assert registry1 is registry2