# app/skills/skill_loader.py

"""
Skill延迟加载系统 - 参考Claude Code的Skill设计

设计原则:
1. Skills按需加载，不预加载所有
2. 根据上下文推荐相关Skills
3. Skill可以增强AI特定领域能力
4. 支持热插拔扩展
"""

from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from pathlib import Path
import os
import logging

logger = logging.getLogger(__name__)


@dataclass
class Skill:
    """Skill定义"""
    name: str
    description: str
    domain: str
    knowledge: str = ""
    tool_preferences: Dict[str, float] = field(default_factory=dict)
    is_loaded: bool = False
    file_path: Optional[str] = None

    def get_enhanced_prompt(self) -> str:
        """获取Skill增强的提示词"""
        if not self.knowledge:
            return ""
        return f"""
## Skill: {self.name}

{self.description}

### Domain Knowledge
{self.knowledge}

### Recommended Tools
{', '.join(self.tool_preferences.keys()) if self.tool_preferences else 'General tools'}
"""


class SkillLoader:
    """
    Skill延迟加载器

    参考Claude Code的Skill系统:
    - 初始只扫描Skill索引
    - 按需加载完整Skill内容
    - 根据上下文推荐相关Skills
    """

    def __init__(self, skills_dir: str = None):
        # 默认使用项目根目录的skills文件夹
        if skills_dir is None:
            from pathlib import Path
            project_root = Path(__file__).parent.parent.parent
            skills_dir = project_root / "skills"

        self.skills_dir = Path(skills_dir)
        self._skill_index: Dict[str, Dict] = {}
        self._loaded_skills: Dict[str, Skill] = {}
        self._build_index()

    def _build_index(self):
        """构建Skill索引 - 仅扫描元数据，不加载内容"""
        if not self.skills_dir.exists():
            logger.info(f"Skills directory not found: {self.skills_dir}")
            return

        # 扫描yaml/yml文件
        for yaml_file in self.skills_dir.glob("*.yaml"):
            self._index_yaml_file(yaml_file)
        for yaml_file in self.skills_dir.glob("*.yml"):
            self._index_yaml_file(yaml_file)

        logger.info(f"Indexed {len(self._skill_index)} skills")

    def _index_yaml_file(self, yaml_path: Path):
        """索引单个YAML文件"""
        try:
            # 只读取文件头部的元数据
            with open(yaml_path, 'r', encoding='utf-8') as f:
                content = f.read(2048)  # 只读前2KB获取元数据

            # 简单解析name和domain
            name = yaml_path.stem
            domain = "general"

            for line in content.split('\n')[:20]:
                if line.startswith('name:'):
                    name = line.split(':', 1)[1].strip().strip('"')
                elif line.startswith('domain:'):
                    domain = line.split(':', 1)[1].strip().strip('"')

            self._skill_index[name] = {
                "name": name,
                "domain": domain,
                "file_path": str(yaml_path),
            }

        except Exception as e:
            logger.warning(f"Failed to index skill {yaml_path}: {e}")

    def list_available_skills(self) -> List[str]:
        """列出所有可用的Skill名称"""
        return list(self._skill_index.keys())

    def recommend_skills(self, context: Dict) -> List[Dict]:
        """
        根据上下文推荐Skills

        Args:
            context: 包含task, target_type, keywords等信息的上下文

        Returns:
            推荐的Skill列表，按相关性排序
        """
        recommendations = []

        task = context.get("task", "").lower()
        target_type = context.get("target_type", "").lower()
        keywords = set(k.lower() for k in context.get("keywords", []))

        for skill_id, skill_info in self._skill_index.items():
            score = 0.0
            domain = skill_info.get("domain", "").lower()

            # 域匹配
            if domain in task or domain in target_type:
                score += 0.5

            # 名称匹配
            if skill_id.lower() in task:
                score += 0.3

            # 关键词匹配
            if keywords and skill_id.lower() in keywords:
                score += 0.2

            if score > 0:
                recommendations.append({
                    "id": skill_id,
                    "name": skill_info.get("name", skill_id),
                    "domain": domain,
                    "score": min(1.0, score),
                })

        # 按分数排序
        recommendations.sort(key=lambda x: x["score"], reverse=True)
        return recommendations[:5]

    def load_skill(self, skill_id: str) -> Optional[Skill]:
        """
        加载完整Skill内容

        Args:
            skill_id: Skill名称

        Returns:
            加载的Skill对象，如果失败返回None
        """
        if skill_id in self._loaded_skills:
            return self._loaded_skills[skill_id]

        if skill_id not in self._skill_index:
            logger.warning(f"Skill not found: {skill_id}")
            return None

        skill_info = self._skill_index[skill_id]
        file_path = skill_info.get("file_path")

        if not file_path or not Path(file_path).exists():
            logger.warning(f"Skill file not found: {file_path}")
            return None

        try:
            # 尝试使用yaml解析
            try:
                import yaml
                with open(file_path, 'r', encoding='utf-8') as f:
                    data = yaml.safe_load(f)
            except ImportError:
                # 如果没有yaml库，简单解析
                data = self._simple_parse(file_path)

            skill = Skill(
                name=data.get("name", skill_id),
                description=data.get("description", ""),
                domain=data.get("domain", "general"),
                knowledge=data.get("knowledge", ""),
                tool_preferences=data.get("tool_preferences", {}),
                is_loaded=True,
                file_path=file_path,
            )

            self._loaded_skills[skill_id] = skill
            logger.info(f"Loaded skill: {skill_id}")
            return skill

        except Exception as e:
            logger.error(f"Failed to load skill {skill_id}: {e}")
            return None

    def _simple_parse(self, file_path: str) -> Dict:
        """简单的YAML解析（不依赖yaml库）"""
        data = {}
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if ':' in line and not line.startswith('#'):
                        key, value = line.split(':', 1)
                        data[key.strip()] = value.strip().strip('"\'')
        except Exception:
            pass
        return data

    def activate_skill(self, skill_id: str) -> Optional[Skill]:
        """激活一个Skill（加载并返回）"""
        return self.load_skill(skill_id)

    def get_active_skills(self) -> List[Skill]:
        """获取所有已激活的Skills"""
        return list(self._loaded_skills.values())

    def get_skill_prompt(self, skill_ids: List[str]) -> str:
        """
        获取多个Skills组合的增强提示词

        Args:
            skill_ids: Skill ID列表

        Returns:
            组合后的提示词
        """
        prompts = []
        for skill_id in skill_ids:
            skill = self.load_skill(skill_id)
            if skill:
                prompt = skill.get_enhanced_prompt()
                if prompt:
                    prompts.append(prompt)
        return "\n".join(prompts)


# 全局加载器实例
_loader: Optional[SkillLoader] = None
_loader_lock = None

def _get_lock():
    """延迟初始化锁"""
    global _loader_lock
    if _loader_lock is None:
        import threading
        _loader_lock = threading.Lock()
    return _loader_lock


def get_skill_loader() -> SkillLoader:
    """获取全局Skill加载器"""
    global _loader
    with _get_lock():
        if _loader is None:
            _loader = SkillLoader()
    return _loader


def recommend_skills_for_task(task: str, target_type: str = "") -> List[Dict]:
    """
    便捷函数：为任务推荐Skills

    Args:
        task: 任务描述
        target_type: 目标类型

    Returns:
        推荐的Skill列表
    """
    loader = get_skill_loader()
    return loader.recommend_skills({
        "task": task,
        "target_type": target_type,
    })


__all__ = [
    "Skill",
    "SkillLoader",
    "get_skill_loader",
    "recommend_skills_for_task",
]