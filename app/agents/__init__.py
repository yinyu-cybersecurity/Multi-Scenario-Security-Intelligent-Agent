# app/agents/__init__.py
"""
Agent 注册中心 - 动态提示词加载

设计原则：
- Agent 模板是 .md 文件，运行时加载
- 通过组合 base + agent-specific + shared_tools 形成完整提示词
- 支持比赛模式下按阶段自动选择 Agent
- 纯提示词层改动，不影响 Query Loop 管道
"""

from pathlib import Path
from typing import Optional


class AgentRegistry:
    """Agent 模板注册中心"""

    _templates_dir: Path = Path(__file__).parent / "templates"
    _templates: dict[str, str] = {}
    _shared_tools: str = ""

    @classmethod
    def load_all(cls):
        """加载所有 Agent 模板（启动时调用一次）"""
        cls._templates.clear()
        cls._shared_tools = ""

        if not cls._templates_dir.exists():
            print(f"[WARN] Agent templates dir not found: {cls._templates_dir}")
            return

        for md_file in cls._templates_dir.glob("*.md"):
            name = md_file.stem
            try:
                content = md_file.read_text(encoding="utf-8")
                if name == "shared_tools":
                    cls._shared_tools = content
                else:
                    cls._templates[name] = content
            except Exception as e:
                print(f"[WARN] Failed to load template {md_file}: {e}")

        print(f"[AgentRegistry] Loaded {len(cls._templates)} agent templates, "
              f"shared_tools: {len(cls._shared_tools)} chars")

        # 验证 base 模板存在
        if "base" not in cls._templates:
            print(f"[WARN] base.md template not found — Agent compose() will use fallback")

    @classmethod
    def get_template(cls, name: str) -> Optional[str]:
        """获取指定 Agent 模板内容"""
        return cls._templates.get(name)

    @classmethod
    def list_names(cls) -> list[str]:
        """列出所有可用 Agent 名称"""
        return list(cls._templates.keys())

    @classmethod
    def compose(cls, agent_name: str, extra_context: str = "") -> str:
        """
        组合完整提示词：base + agent-specific + shared_tools + extra

        Args:
            agent_name: Agent 模板名称（如 "vuln_discovery"）
            extra_context: 额外上下文（如目标信息、比赛阶段）

        Returns:
            组合后的系统提示词
        """
        parts = []

        # 1. 基础模板（始终包含）
        if "base" in cls._templates:
            parts.append(cls._templates["base"])

        # 2. Agent 专属模板
        agent_template = cls.get_template(agent_name)
        if agent_template:
            parts.append(agent_template)
        else:
            parts.append(f"## 角色：{agent_name}\n\n你是 CTF 渗透专家。")

        # 3. 共享工具知识（始终包含）
        if cls._shared_tools:
            parts.append(cls._shared_tools)

        # 4. 额外上下文
        if extra_context:
            parts.append(extra_context)

        return "\n\n".join(parts)

    @classmethod
    def auto_select(cls, phase_hint: str = "") -> str:
        """
        根据阶段提示自动选择 Agent

        Args:
            phase_hint: 阶段描述（如 "discovery", "exploit", "src", "cve", "multi_layer", "domain"）

        Returns:
            选中的 Agent 名称
        """
        phase_lower = phase_hint.lower()

        # 关键字匹配
        if any(k in phase_lower for k in ["src", "众测", "批量"]):
            return "src_agent"
        if any(k in phase_lower for k in ["cve", "云安全", "cloud", "ai 安全"]):
            return "cve_agent"
        if any(k in phase_lower for k in ["多层", "multi", "内网", "横向", "隧道"]):
            return "multi_layer"
        if any(k in phase_lower for k in ["域", "domain", "ad 域", "内网渗透"]):
            return "domain_pentest"
        if any(k in phase_lower for k in ["发现", "discovery", "侦察", "扫描", "信息收集"]):
            return "vuln_discovery"
        if any(k in phase_lower for k in ["利用", "exploit", "payload", "rce", "注入"]):
            return "vuln_exploit"

        # 默认：通用 Agent
        return "base"


__all__ = ["AgentRegistry"]
