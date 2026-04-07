"""
OpenSpace Skill Engine 集成

将 CTF-Agent 的技能系统与 OpenSpace 集成，提供：
- 本地技能搜索（TF-IDF + 语义搜索）
- 云端技能共享（可选）
- 技能进化（自动修复/改进）
"""

import os
import sys
from pathlib import Path
from typing import Dict, List, Optional, Any

# 添加 OpenSpace 到路径
OPENSPACE_DIR = Path(__file__).parent.parent.parent / "OpenSpace-main"
if OPENSPACE_DIR.exists():
    sys.path.insert(0, str(OPENSPACE_DIR))

try:
    from openspace.skill_engine.registry import SkillRegistry
    from openspace.skill_engine.skill_utils import parse_frontmatter, strip_frontmatter
    OPENSACE_AVAILABLE = True
except ImportError:
    OPENSACE_AVAILABLE = False

from mcp.types import TextContent


class OpenSpaceSkillEngine:
    """
    OpenSpace 技能引擎封装

    提供：
    - 本地技能搜索（兼容 YAML 和 SKILL.md 格式）
    - 云端技能搜索（可选）
    - 技能进化支持
    """

    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return

        self._initialized = True
        self._registry: Optional[SkillRegistry] = None
        self._skills_dir: Optional[Path] = None
        self._yaml_skills: Dict[str, Dict] = {}  # 回退：YAML 技能缓存

    def initialize(self, skills_dir: Path):
        """初始化技能引擎"""
        self._skills_dir = skills_dir

        if OPENSACE_AVAILABLE:
            try:
                # 使用 OpenSpace 的 SkillRegistry
                self._registry = SkillRegistry()
                self._registry.register_skill_dir(str(skills_dir))
                print(f"[OpenSpace] Initialized with {len(self._registry._skills)} skills")
            except Exception as e:
                print(f"[OpenSpace] Failed to initialize: {e}")
                self._registry = None

        # 如果 OpenSpace 不可用，加载 YAML 技能作为回退
        if not self._registry:
            self._load_yaml_skills()

    def _load_yaml_skills(self):
        """加载 YAML 格式的技能（回退方案）"""
        if not self._skills_dir or not self._skills_dir.exists():
            return

        import yaml
        for yaml_file in self._skills_dir.glob("*.yaml"):
            try:
                with open(yaml_file, 'r', encoding='utf-8') as f:
                    data = yaml.safe_load(f)
                if data:
                    name = data.get('name', yaml_file.stem)
                    self._yaml_skills[name] = {
                        'path': yaml_file,
                        'data': data,
                    }
            except Exception:
                pass

        print(f"[SkillEngine] Loaded {len(self._yaml_skills)} YAML skills (fallback mode)")

    def search(self, query: str, top_k: int = 10) -> List[Dict]:
        """
        搜索技能

        Args:
            query: 搜索查询
            top_k: 返回数量

        Returns:
            技能列表，每个包含 name, description, score, path
        """
        if self._registry:
            # 使用 OpenSpace 搜索
            try:
                candidates = self._registry.match_skills(query, top_k=top_k)
                results = []
                for candidate in candidates:
                    results.append({
                        'name': candidate.skill_name,
                        'description': candidate.description,
                        'score': candidate.score,
                        'path': str(candidate.skill_dir) if hasattr(candidate, 'skill_dir') else '',
                    })
                return results
            except Exception as e:
                print(f"[OpenSpace] Search failed: {e}")

        # 回退：简单的关键词匹配
        return self._fallback_search(query, top_k)

    def _fallback_search(self, query: str, top_k: int) -> List[Dict]:
        """回退搜索：关键词匹配"""
        query_lower = query.lower()
        results = []

        for name, info in self._yaml_skills.items():
            data = info['data']
            # 简单的匹配分数
            score = 0
            name_lower = name.lower()
            desc = data.get('description', '').lower()
            knowledge = data.get('knowledge', '').lower()
            tags = ' '.join(data.get('tags', [])).lower()

            # 计算分数
            for term in query_lower.split():
                if term in name_lower:
                    score += 10
                if term in desc:
                    score += 5
                if term in tags:
                    score += 3
                if term in knowledge:
                    score += 1

            if score > 0:
                results.append({
                    'name': name,
                    'description': desc[:100],
                    'score': score,
                    'path': str(info['path']),
                })

        # 排序并返回 top_k
        results.sort(key=lambda x: x['score'], reverse=True)
        return results[:top_k]

    def read_skill(self, name: str) -> Optional[Dict]:
        """
        读取技能完整内容

        Args:
            name: 技能名称

        Returns:
            技能内容字典，包含 name, description, content
        """
        # 首先尝试从 YAML 技能读取
        if name in self._yaml_skills:
            data = self._yaml_skills[name]['data']
            return {
                'name': data.get('name', name),
                'description': data.get('description', ''),
                'content': data.get('knowledge', ''),
                'domain': data.get('domain', ''),
                'tags': data.get('tags', []),
                'path': str(self._yaml_skills[name]['path']),
            }

        # 尝试从 OpenSpace registry 读取
        if self._registry:
            try:
                skill_meta = self._registry.get_skill(name)
                if skill_meta:
                    content = skill_meta.skill_dir.joinpath('SKILL.md').read_text(encoding='utf-8')
                    body = strip_frontmatter(content)
                    fm = parse_frontmatter(content)
                    return {
                        'name': fm.get('name', name),
                        'description': fm.get('description', ''),
                        'content': body,
                        'path': str(skill_meta.skill_dir),
                    }
            except Exception:
                pass

        return None


# 全局实例
_engine: Optional[OpenSpaceSkillEngine] = None


def get_skill_engine() -> OpenSpaceSkillEngine:
    """获取技能引擎单例"""
    global _engine
    if _engine is None:
        _engine = OpenSpaceSkillEngine()
    return _engine


def initialize_skill_engine(skills_dir: Path):
    """初始化技能引擎"""
    engine = get_skill_engine()
    engine.initialize(skills_dir)
    return engine