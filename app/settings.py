# app/settings.py
"""配置加载 - 从 settings.json 读取"""

import json
from pathlib import Path
from dataclasses import dataclass, field


@dataclass
class Config:
    """配置"""
    LLM_MODEL: str = "qwen3.5-plus"
    LLM_BASE_URL: str = ""
    LLM_API_KEY: str = ""
    LLM_TIMEOUT: int = 120
    TASK_TIMEOUT: int = 1800
    TOOL_TIMEOUT: int = 300
    MCP_SERVERS: dict = field(default_factory=dict)


def load_settings() -> Config:
    """加载 settings.json"""
    config = Config()

    # 查找配置文件
    settings_path = Path(__file__).parent.parent / "settings.json"
    if not settings_path.exists():
        print(f"[WARN] settings.json not found at {settings_path}")
        return config

    with open(settings_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    # 模型配置
    if "model" in data:
        model = data["model"]
        config.LLM_MODEL = model.get("name", config.LLM_MODEL)
        config.LLM_BASE_URL = model.get("base_url", "")
        config.LLM_API_KEY = model.get("api_key", "")
        config.LLM_TIMEOUT = model.get("timeout", 120)

    # 超时配置
    if "timeouts" in data:
        timeouts = data["timeouts"]
        config.TASK_TIMEOUT = timeouts.get("task", 1800)
        config.TOOL_TIMEOUT = timeouts.get("tool_default", 300)

    # MCP服务器配置
    if "mcp_servers" in data:
        config.MCP_SERVERS = data["mcp_servers"]

    return config


# 全局配置
config = load_settings()