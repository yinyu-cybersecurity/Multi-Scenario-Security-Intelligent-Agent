# app/settings.py
"""
配置系统 - 企业级标准

设计原则（对齐 Claude Code）:
1. 环境变量优先于配置文件（12-factor app）
2. Pydantic 验证，启动时 fail-fast
3. 敏感信息禁止硬编码，必须走环境变量
4. 单一真相源：settings.json + env overlay
"""

import json
import os
from pathlib import Path
from typing import Dict, Optional
from dataclasses import dataclass, field


# ============================================================================
# 配置数据类
# ============================================================================

@dataclass
class ModelConfig:
    """模型配置"""
    name: str = "qwen3.5-plus"
    base_url: str = ""
    api_key: str = ""
    timeout: int = 120
    max_tokens: Optional[int] = None
    temperature: float = 0.1

    # Fallback 模型链（主模型失败时依次尝试）
    fallback_models: list = field(default_factory=list)


@dataclass
class TimeoutConfig:
    """超时配置"""
    task: int = 1800          # 单题默认30分钟
    tool_default: int = 300    # 工具默认5分钟
    llm_call: int = 120        # LLM单次调用2分钟
    mcp_connect: int = 30      # MCP连接超时30秒


@dataclass
class RetryConfig:
    """重试配置"""
    max_retries: int = 3
    base_delay: float = 1.0
    max_delay: float = 30.0
    exponential_base: float = 2.0


@dataclass
class CompetitionConfig:
    """比赛平台配置"""
    server_host: str = ""
    agent_token: str = ""
    mcp_url: str = ""          # 比赛MCP直连URL
    rate_limit: float = 0.35   # 请求间隔(秒)，确保不超过3次/秒
    max_concurrent_instances: int = 3
    hint_penalty: float = 0.1  # 提示扣分比例

    @property
    def is_enabled(self) -> bool:
        return bool(self.server_host) and bool(self.agent_token)

    @property
    def api_base_url(self) -> str:
        if not self.server_host:
            return ""
        host = self.server_host
        if not host.startswith("http"):
            host = f"http://{host}"
        return host


@dataclass
class MCPServerConfig:
    """单个MCP服务器配置"""
    command: str = ""
    args: list = field(default_factory=list)
    env: dict = field(default_factory=dict)


@dataclass
class QueryConfig:
    """Query Loop 配置"""
    max_turns: int = 500
    context_window_tokens: int = 262144  # 上下文窗口大小
    context_reserve_tokens: int = 8192   # 为响应预留的token
    message_truncate_threshold: int = 16000  # 单条消息截断阈值
    parallel_tool_calls: bool = True      # 是否并行执行工具


@dataclass
class AppConfig:
    """应用总配置"""
    model: ModelConfig = field(default_factory=ModelConfig)
    timeouts: TimeoutConfig = field(default_factory=TimeoutConfig)
    retry: RetryConfig = field(default_factory=RetryConfig)
    competition: CompetitionConfig = field(default_factory=CompetitionConfig)
    query: QueryConfig = field(default_factory=QueryConfig)
    mcp_servers: Dict[str, MCPServerConfig] = field(default_factory=dict)

    # 兼容旧接口的属性
    @property
    def LLM_MODEL(self) -> str:
        return self.model.name

    @property
    def LLM_BASE_URL(self) -> str:
        return self.model.base_url

    @property
    def LLM_API_KEY(self) -> str:
        return self.model.api_key

    @property
    def LLM_TIMEOUT(self) -> int:
        return self.model.timeout

    @property
    def TASK_TIMEOUT(self) -> int:
        return self.timeouts.task

    @property
    def TOOL_TIMEOUT(self) -> int:
        return self.timeouts.tool_default

    @property
    def MCP_SERVERS(self) -> dict:
        """兼容旧接口"""
        return {
            name: {
                "command": srv.command,
                "args": srv.args,
                "env": srv.env,
            }
            for name, srv in self.mcp_servers.items()
        }


# ============================================================================
# 配置加载器
# ============================================================================

def _find_settings_file() -> Optional[Path]:
    """查找 settings.json（支持多路径）"""
    candidates = [
        os.environ.get("CTF_SETTINGS_PATH", ""),
        Path(__file__).parent.parent / "settings.json",
        Path.cwd() / "settings.json",
    ]
    for p in candidates:
        if isinstance(p, str):
            if not p:  # 空字符串跳过
                continue
            p = Path(p)
        if p.exists() and p.is_file():  # 必须是文件
            return p
    return None


def _resolve_env_var(value: str) -> str:
    """解析环境变量引用: ${VAR_NAME} -> os.environ[VAR_NAME]"""
    if isinstance(value, str) and value.startswith("${") and value.endswith("}"):
        env_name = value[2:-1]
        return os.environ.get(env_name, "")
    return value


def load_config() -> AppConfig:
    """
    加载配置，优先级：环境变量 > settings.json > 默认值

    环境变量映射：
        LLM_API_KEY          -> model.api_key
        LLM_BASE_URL         -> model.base_url
        LLM_MODEL            -> model.name
        LLM_TIMEOUT          -> model.timeout
        TASK_TIMEOUT          -> timeouts.task
        COMPETITION_SERVER_HOST -> competition.server_host
        COMPETITION_AGENT_TOKEN -> competition.agent_token
        COMPETITION_MCP_URL   -> competition.mcp_url
    """
    cfg = AppConfig()

    # 1. 从 settings.json 加载
    settings_path = _find_settings_file()
    if settings_path:
        try:
            with open(settings_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            _apply_json_config(cfg, data)
        except Exception as e:
            print(f"[WARN] Failed to load {settings_path}: {e}")

    # 2. 环境变量覆盖（最高优先级）
    _apply_env_overrides(cfg)

    # 3. 验证配置
    _validate_config(cfg)

    return cfg


def _apply_json_config(cfg: AppConfig, data: dict):
    """从 JSON 数据填充配置"""
    # 模型配置
    if "model" in data:
        m = data["model"]
        cfg.model.name = m.get("name", cfg.model.name)
        cfg.model.base_url = m.get("base_url", cfg.model.base_url)
        # API key 从配置文件读取时解析环境变量引用
        raw_key = m.get("api_key", "")
        cfg.model.api_key = _resolve_env_var(raw_key)
        cfg.model.timeout = m.get("timeout", cfg.model.timeout)
        cfg.model.max_tokens = m.get("max_tokens", cfg.model.max_tokens)
        cfg.model.temperature = m.get("temperature", cfg.model.temperature)
        cfg.model.fallback_models = m.get("fallback_models", [])

    # 超时配置
    if "timeouts" in data:
        t = data["timeouts"]
        cfg.timeouts.task = t.get("task", cfg.timeouts.task)
        cfg.timeouts.tool_default = t.get("tool_default", cfg.timeouts.tool_default)
        cfg.timeouts.llm_call = t.get("llm_call", cfg.timeouts.llm_call)
        cfg.timeouts.mcp_connect = t.get("mcp_connect", cfg.timeouts.mcp_connect)

    # 重试配置
    if "retry" in data:
        r = data["retry"]
        cfg.retry.max_retries = r.get("max_retries", cfg.retry.max_retries)
        cfg.retry.base_delay = r.get("base_delay", cfg.retry.base_delay)
        cfg.retry.max_delay = r.get("max_delay", cfg.retry.max_delay)

    # 比赛配置
    if "competition" in data:
        c = data["competition"]
        cfg.competition.server_host = c.get("server_host", cfg.competition.server_host)
        cfg.competition.agent_token = _resolve_env_var(c.get("agent_token", ""))
        cfg.competition.mcp_url = c.get("mcp_url", cfg.competition.mcp_url)
        cfg.competition.rate_limit = c.get("rate_limit", cfg.competition.rate_limit)

    # Query 配置
    if "query" in data:
        q = data["query"]
        cfg.query.max_turns = q.get("max_turns", cfg.query.max_turns)
        cfg.query.context_window_tokens = q.get("context_window_tokens", cfg.query.context_window_tokens)
        cfg.query.parallel_tool_calls = q.get("parallel_tool_calls", cfg.query.parallel_tool_calls)

    # MCP 服务器配置
    if "mcp_servers" in data:
        for name, srv_data in data["mcp_servers"].items():
            env = {}
            for k, v in srv_data.get("env", {}).items():
                env[k] = _resolve_env_var(v)
            cfg.mcp_servers[name] = MCPServerConfig(
                command=srv_data.get("command", ""),
                args=srv_data.get("args", []),
                env=env,
            )


def _apply_env_overrides(cfg: AppConfig):
    """环境变量覆盖（最高优先级）"""
    # LLM
    if v := os.environ.get("LLM_API_KEY"):
        cfg.model.api_key = v
    if v := os.environ.get("LLM_BASE_URL"):
        cfg.model.base_url = v
    if v := os.environ.get("LLM_MODEL"):
        cfg.model.name = v
    if v := os.environ.get("LLM_TIMEOUT"):
        cfg.model.timeout = int(v)

    # Timeouts
    if v := os.environ.get("TASK_TIMEOUT"):
        cfg.timeouts.task = int(v)

    # Competition
    if v := os.environ.get("COMPETITION_SERVER_HOST"):
        cfg.competition.server_host = v
    if v := os.environ.get("COMPETITION_AGENT_TOKEN"):
        cfg.competition.agent_token = v
    if v := os.environ.get("COMPETITION_MCP_URL"):
        cfg.competition.mcp_url = v


def _validate_config(cfg: AppConfig):
    """配置验证 - fail fast"""
    errors = []

    if not cfg.model.api_key:
        errors.append("LLM API key not set. Use env var LLM_API_KEY or settings.json model.api_key=${LLM_API_KEY}")

    if not cfg.model.base_url:
        errors.append("LLM base URL not set. Use env var LLM_BASE_URL or settings.json model.base_url")

    if cfg.timeouts.task < 60:
        errors.append(f"Task timeout too short: {cfg.timeouts.task}s (min 60s)")

    if errors:
        print("\n[CONFIG ERRORS]")
        for e in errors:
            print(f"  - {e}")
        print()
        # 不立即退出，允许在某些场景下部分运行


# ============================================================================
# 全局配置单例
# ============================================================================

config = load_config()


__all__ = [
    "AppConfig",
    "ModelConfig",
    "TimeoutConfig",
    "RetryConfig",
    "CompetitionConfig",
    "MCPServerConfig",
    "QueryConfig",
    "config",
    "load_config",
]
