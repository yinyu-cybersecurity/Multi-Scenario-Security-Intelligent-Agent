"""
CTF-Agent 配置管理模块

功能:
- YAML配置文件加载
- 多环境配置支持 (dev/staging/prod)
- 工具配置管理
- Agent参数配置
"""

import yaml
from typing import Dict, Any, Optional, List
from pathlib import Path
from dataclasses import dataclass, field
import os


@dataclass
class ToolConfig:
    """工具配置"""
    name: str
    enabled: bool = True
    timeout: int = 300
    max_retries: int = 3
    params: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AgentConfig:
    """Agent配置"""
    agent_type: str
    model: str = "glm-5"
    max_iterations: int = 20
    max_tokens: int = 100000
    temperature: float = 0.7
    permissions: List[str] = field(default_factory=list)


@dataclass
class SkillConfig:
    """技能配置"""
    name: str
    enabled: bool = True
    auto_trigger: bool = False
    priority: int = 5
    params: Dict[str, Any] = field(default_factory=dict)


class ConfigManager:
    """配置管理器"""

    def __init__(self, config_path: str = "config.yaml"):
        self.config_path = Path(config_path)
        self.config: Dict[str, Any] = {}
        self.tools: Dict[str, ToolConfig] = {}
        self.agents: Dict[str, AgentConfig] = {}
        self.skills: Dict[str, SkillConfig] = {}

        self._load_config()

    def _load_config(self):
        """加载配置文件"""
        if not self.config_path.exists():
            self._create_default_config()
            return

        with open(self.config_path, "r", encoding="utf-8") as f:
            self.config = yaml.safe_load(f) or {}

        self._parse_config()

    def _create_default_config(self):
        """创建默认配置"""
        default_config = {
            "version": "2.0",
            "environment": "development",

            "agents": {
                "explore": {
                    "model": "glm-5",
                    "max_iterations": 15,
                    "permissions": ["read", "glob", "grep"]
                },
                "plan": {
                    "model": "glm-5",
                    "max_iterations": 10,
                    "permissions": ["read", "ask_user"]
                },
                "attack": {
                    "model": "glm-5",
                    "max_iterations": 30,
                    "permissions": ["read", "write", "edit", "bash", "network"]
                },
                "verify": {
                    "model": "glm-5",
                    "max_iterations": 10,
                    "permissions": ["read", "bash"]
                }
            },

            "tools": {
                "nmap": {
                    "enabled": True,
                    "timeout": 300,
                    "params": {}
                },
                "nuclei": {
                    "enabled": True,
                    "timeout": 180,
                    "params": {
                        "severity": "high,critical"
                    }
                },
                "sqlmap": {
                    "enabled": True,
                    "timeout": 600,
                    "params": {
                        "level": 1
                    }
                }
            },

            "skills": {
                "web_exploitation": {
                    "enabled": True,
                    "auto_trigger": True,
                    "priority": 8
                },
                "internal_network": {
                    "enabled": True,
                    "auto_trigger": False,
                    "priority": 7
                }
            },

            "memory": {
                "enabled": True,
                "backend": "file",  # file/redis/mongodb
                "cache_size": 1000
            },

            "logging": {
                "level": "INFO",
                "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
                "file": "logs/ctf_agent.log"
            },

            "security": {
                "ssrf_protection": True,
                "command_injection_protection": True,
                "private_ip_only_tools": ["fscan", "crackmapexec"]
            }
        }

        self.config = default_config
        self._save_config()
        self._parse_config()

    def _save_config(self):
        """保存配置文件"""
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.config_path, "w", encoding="utf-8") as f:
            yaml.dump(self.config, f, allow_unicode=True, default_flow_style=False)

    def _parse_config(self):
        """解析配置"""
        # 解析工具配置
        for name, cfg in self.config.get("tools", {}).items():
            self.tools[name] = ToolConfig(
                name=name,
                enabled=cfg.get("enabled", True),
                timeout=cfg.get("timeout", 300),
                max_retries=cfg.get("max_retries", 3),
                params=cfg.get("params", {})
            )

        # 解析Agent配置
        for agent_type, cfg in self.config.get("agents", {}).items():
            self.agents[agent_type] = AgentConfig(
                agent_type=agent_type,
                model=cfg.get("model", "glm-5"),
                max_iterations=cfg.get("max_iterations", 20),
                max_tokens=cfg.get("max_tokens", 100000),
                temperature=cfg.get("temperature", 0.7),
                permissions=cfg.get("permissions", [])
            )

        # 解析技能配置
        for name, cfg in self.config.get("skills", {}).items():
            self.skills[name] = SkillConfig(
                name=name,
                enabled=cfg.get("enabled", True),
                auto_trigger=cfg.get("auto_trigger", False),
                priority=cfg.get("priority", 5),
                params=cfg.get("params", {})
            )

    def get_tool_config(self, tool_name: str) -> Optional[ToolConfig]:
        """获取工具配置"""
        return self.tools.get(tool_name)

    def get_agent_config(self, agent_type: str) -> Optional[AgentConfig]:
        """获取Agent配置"""
        return self.agents.get(agent_type)

    def get_skill_config(self, skill_name: str) -> Optional[SkillConfig]:
        """获取技能配置"""
        return self.skills.get(skill_name)

    def get(self, key: str, default: Any = None) -> Any:
        """获取配置值"""
        keys = key.split(".")
        value = self.config

        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default

        return value

    def set(self, key: str, value: Any):
        """设置配置值"""
        keys = key.split(".")
        config = self.config

        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]

        config[keys[-1]] = value
        self._save_config()

    def load_environment(self, env: str):
        """加载环境配置"""
        env_file = self.config_path.parent / f"config.{env}.yaml"
        if env_file.exists():
            with open(env_file, "r", encoding="utf-8") as f:
                env_config = yaml.safe_load(f) or {}
                # 合并配置
                self._merge_config(self.config, env_config)
                self._parse_config()

    def _merge_config(self, base: Dict, override: Dict):
        """合并配置"""
        for key, value in override.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._merge_config(base[key], value)
            else:
                base[key] = value

    def list_enabled_tools(self) -> List[str]:
        """列出所有启用的工具"""
        return [name for name, cfg in self.tools.items() if cfg.enabled]

    def list_enabled_skills(self) -> List[str]:
        """列出所有启用的技能"""
        return [name for name, cfg in self.skills.items() if cfg.enabled]

    def export_config(self) -> str:
        """导出配置为YAML字符串"""
        return yaml.dump(self.config, allow_unicode=True, default_flow_style=False)


# 全局配置实例
_config_manager: Optional[ConfigManager] = None


def get_config_manager(config_path: str = "config.yaml") -> ConfigManager:
    """获取全局配置管理器"""
    global _config_manager
    if _config_manager is None:
        _config_manager = ConfigManager(config_path)
    return _config_manager


# 使用示例
if __name__ == "__main__":
    config = get_config_manager()

    print("=" * 60)
    print("CTF-Agent 配置管理器")
    print("=" * 60)

    print("\n📦 启用的工具:")
    for tool in config.list_enabled_tools():
        cfg = config.get_tool_config(tool)
        print(f"  - {tool}: timeout={cfg.timeout}s, retries={cfg.max_retries}")

    print("\n🤖 Agent配置:")
    for agent_type, cfg in config.agents.items():
        print(f"  - {agent_type}: model={cfg.model}, iterations={cfg.max_iterations}")

    print("\n🎯 启用的技能:")
    for skill in config.list_enabled_skills():
        cfg = config.get_skill_config(skill)
        print(f"  - {skill}: priority={cfg.priority}, auto_trigger={cfg.auto_trigger}")

    print("\n⚙️ 安全配置:")
    print(f"  - SSRF防护: {config.get('security.ssrf_protection')}")
    print(f"  - 命令注入防护: {config.get('security.command_injection_protection')}")