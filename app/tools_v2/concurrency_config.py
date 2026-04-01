"""
工具并发安全配置

借鉴Claude Code的isConcurrencySafe设计：
- 只读工具可并发执行
- 修改操作需串行
- 根据参数动态判断安全性

并发策略：
- 只读扫描（nmap -sV, whatweb）: 可并发
- 漏洞扫描（nuclei）: 需谨慎（可能触发WAF）
- 攻击工具（sqlmap, hydra）: 串行执行
"""

from dataclasses import dataclass
from typing import Dict, List, Optional, Callable, Any
from enum import Enum


class ConcurrencyLevel(Enum):
    """并发安全级别"""
    ALWAYS_SAFE = "always_safe"      # 始终可并发（只读操作）
    CONDITIONAL = "conditional"       # 条件性安全（需检查参数）
    NEVER_SAFE = "never_safe"         # 禁止并发（修改操作）


@dataclass
class ToolConcurrencyConfig:
    """工具并发配置"""
    name: str
    level: ConcurrencyLevel
    is_read_only: bool
    safe_conditions: Optional[Callable[[Dict], bool]] = None
    max_concurrent: int = 8  # 最大并发数


# 只读命令白名单（用于Bash工具）
READ_ONLY_COMMANDS = [
    # 文件操作
    "ls", "cat", "head", "tail", "find", "grep", "wc", "file",
    # Git只读
    "git status", "git log", "git diff", "git show", "git branch",
    # 网络探测
    "curl", "wget", "ping", "nc -z", "nmap -sV", "nmap -sT",
    "whatweb", "dig", "nslookup", "whois",
    # 信息收集
    "whoami", "id", "uname", "hostname", "env", "printenv"
]

# 危险命令黑名单（禁止并发）
DANGEROUS_COMMANDS = [
    "rm", "mv", "chmod", "chown",
    "iptables", "ufw",
    "mkfs", "dd",
    "shutdown", "reboot", "halt"
]


def is_read_only_command(command: str) -> bool:
    """
    判断命令是否只读

    Args:
        command: Bash命令字符串

    Returns:
        是否只读
    """
    cmd_lower = command.strip().lower()

    # 检查危险命令
    for dangerous in DANGEROUS_COMMANDS:
        if cmd_lower.startswith(dangerous):
            return False

    # 检查只读命令
    for safe in READ_ONLY_COMMANDS:
        if cmd_lower.startswith(safe.lower()):
            return True

    # 默认不安全
    return False


def check_nmap_safety(params: Dict) -> bool:
    """检查nmap参数是否安全"""
    scan_type = params.get("scan_type", "quick")
    # quick和service扫描通常是只读的
    # full扫描可能触发IDS
    return scan_type in ["quick", "service"]


def check_bash_safety(params: Dict) -> bool:
    """检查Bash命令是否安全"""
    command = params.get("command", "")
    return is_read_only_command(command)


def check_httpx_safety(params: Dict) -> bool:
    """httpx始终是只读探测"""
    return True


def check_nuclei_safety(params: Dict) -> bool:
    """nuclei可能触发WAF，需谨慎"""
    # 默认保守策略：nuclei不并发
    return False


# ============================================
# 工具并发配置表
# ============================================

TOOL_CONCURRENCY_CONFIGS: Dict[str, ToolConcurrencyConfig] = {
    # === 始终安全的只读工具 ===
    "nmap": ToolConcurrencyConfig(
        name="nmap",
        level=ConcurrencyLevel.CONDITIONAL,
        is_read_only=True,
        safe_conditions=check_nmap_safety
    ),
    "httpx": ToolConcurrencyConfig(
        name="httpx",
        level=ConcurrencyLevel.ALWAYS_SAFE,
        is_read_only=True,
        safe_conditions=check_httpx_safety
    ),
    "whatweb": ToolConcurrencyConfig(
        name="whatweb",
        level=ConcurrencyLevel.ALWAYS_SAFE,
        is_read_only=True
    ),
    "subfinder": ToolConcurrencyConfig(
        name="subfinder",
        level=ConcurrencyLevel.ALWAYS_SAFE,
        is_read_only=True
    ),

    # === 条件性安全工具 ===
    "Bash": ToolConcurrencyConfig(
        name="Bash",
        level=ConcurrencyLevel.CONDITIONAL,
        is_read_only=False,  # 需检查命令
        safe_conditions=check_bash_safety
    ),

    # === 需串行的工具 ===
    "nuclei": ToolConcurrencyConfig(
        name="nuclei",
        level=ConcurrencyLevel.NEVER_SAFE,
        is_read_only=True,
        safe_conditions=check_nuclei_safety
    ),
    "sqlmap": ToolConcurrencyConfig(
        name="sqlmap",
        level=ConcurrencyLevel.NEVER_SAFE,
        is_read_only=False,
        max_concurrent=1
    ),
    "hydra": ToolConcurrencyConfig(
        name="hydra",
        level=ConcurrencyLevel.NEVER_SAFE,
        is_read_only=False,
        max_concurrent=1
    ),
    "ffuf": ToolConcurrencyConfig(
        name="ffuf",
        level=ConcurrencyLevel.NEVER_SAFE,
        is_read_only=True,  # 只读但可能触发WAF
        max_concurrent=1
    ),
    "fscan": ToolConcurrencyConfig(
        name="fscan",
        level=ConcurrencyLevel.NEVER_SAFE,
        is_read_only=True,
        max_concurrent=1
    ),

    # === 攻击工具（始终串行）===
    "crackmapexec": ToolConcurrencyConfig(
        name="crackmapexec",
        level=ConcurrencyLevel.NEVER_SAFE,
        is_read_only=False,
        max_concurrent=1
    ),
    "impacket": ToolConcurrencyConfig(
        name="impacket",
        level=ConcurrencyLevel.NEVER_SAFE,
        is_read_only=False,
        max_concurrent=1
    ),
    "ysoserial": ToolConcurrencyConfig(
        name="ysoserial",
        level=ConcurrencyLevel.NEVER_SAFE,
        is_read_only=False,
        max_concurrent=1
    ),
}


def get_tool_concurrency_config(tool_name: str) -> ToolConcurrencyConfig:
    """获取工具并发配置"""
    return TOOL_CONCURRENCY_CONFIGS.get(
        tool_name,
        ToolConcurrencyConfig(
            name=tool_name,
            level=ConcurrencyLevel.NEVER_SAFE,  # 默认保守
            is_read_only=False
        )
    )


def is_concurrency_safe(tool_name: str, params: Dict) -> bool:
    """
    判断工具调用是否并发安全

    Args:
        tool_name: 工具名称
        params: 工具参数

    Returns:
        是否可安全并发执行
    """
    config = get_tool_concurrency_config(tool_name)

    if config.level == ConcurrencyLevel.ALWAYS_SAFE:
        return True

    if config.level == ConcurrencyLevel.NEVER_SAFE:
        return False

    # 条件性安全：检查条件函数
    if config.safe_conditions:
        return config.safe_conditions(params)

    # 默认不安全
    return False


def get_max_concurrent(tool_name: str) -> int:
    """获取工具最大并发数"""
    config = get_tool_concurrency_config(tool_name)
    return config.max_concurrent


def classify_tools_for_parallel(
    tool_calls: List[Dict[str, Any]]
) -> tuple[List[Dict], List[Dict]]:
    """
    将工具调用分类为可并行和需串行

    Args:
        tool_calls: 工具调用列表 [{"tool": "nmap", "params": {...}}, ...]

    Returns:
        (parallel_tools, serial_tools)
    """
    parallel = []
    serial = []

    for call in tool_calls:
        tool = call.get("tool", "")
        params = call.get("params", {})

        if is_concurrency_safe(tool, params):
            parallel.append(call)
        else:
            serial.append(call)

    return parallel, serial