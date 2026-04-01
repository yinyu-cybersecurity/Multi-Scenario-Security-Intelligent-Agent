"""
Docker工具镜像配置

定义工具到镜像的映射关系，以及容器池配置
"""

from typing import Dict, Any, Literal
from dataclasses import dataclass, field


@dataclass
class ToolImageConfig:
    """工具镜像配置"""
    image: str
    persistent: bool
    pool_name: str = ""
    timeout: int = 300


# 工具到镜像的映射
TOOL_IMAGE_MAPPING: Dict[str, ToolImageConfig] = {
    # === Web工具 - 高频持久容器 ===
    "nmap": ToolImageConfig(image="ctf-tools-web", persistent=True, pool_name="web"),
    "nuclei": ToolImageConfig(image="ctf-tools-web", persistent=True, pool_name="web", timeout=600),
    "httpx": ToolImageConfig(image="ctf-tools-web", persistent=True, pool_name="web"),
    "fscan": ToolImageConfig(image="ctf-tools-web", persistent=True, pool_name="web", timeout=600),
    "sqlmap": ToolImageConfig(image="ctf-tools-web", persistent=True, pool_name="web", timeout=600),
    "ffuf": ToolImageConfig(image="ctf-tools-web", persistent=True, pool_name="web"),
    "dirsearch": ToolImageConfig(image="ctf-tools-web", persistent=True, pool_name="web"),
    "xray": ToolImageConfig(image="ctf-tools-web", persistent=True, pool_name="web", timeout=600),
    "subfinder": ToolImageConfig(image="ctf-tools-web", persistent=True, pool_name="web"),
    "gobuster": ToolImageConfig(image="ctf-tools-web", persistent=True, pool_name="web"),
    "whatweb": ToolImageConfig(image="ctf-tools-web", persistent=True, pool_name="web"),
    "hydra": ToolImageConfig(image="ctf-tools-web", persistent=True, pool_name="web", timeout=600),
    "dalfox": ToolImageConfig(image="ctf-tools-web", persistent=True, pool_name="web"),
    "httprobe": ToolImageConfig(image="ctf-tools-web", persistent=True, pool_name="web"),

    # === Pwn工具 - 高频持久容器 ===
    "binary_analyzer": ToolImageConfig(image="ctf-tools-pwn", persistent=True, pool_name="pwn"),
    "rop_builder": ToolImageConfig(image="ctf-tools-pwn", persistent=True, pool_name="pwn"),
    "shellcode_generator": ToolImageConfig(image="ctf-tools-pwn", persistent=True, pool_name="pwn"),

    # === AD域工具 - 低频临时容器 ===
    "crackmapexec": ToolImageConfig(image="ctf-tools-ad", persistent=False, timeout=600),
    "impacket": ToolImageConfig(image="ctf-tools-ad", persistent=False),
    "bloodhound": ToolImageConfig(image="ctf-tools-ad", persistent=False),
    "certipy": ToolImageConfig(image="ctf-tools-ad", persistent=False),
    "ldapdomaindump": ToolImageConfig(image="ctf-tools-ad", persistent=False),
    "pywhisker": ToolImageConfig(image="ctf-tools-ad", persistent=False),
    "mimikatz": ToolImageConfig(image="ctf-tools-ad", persistent=False),

    # === 反序列化工具 - 低频临时容器 ===
    "ysoserial": ToolImageConfig(image="ctf-tools-deser", persistent=False),
    "marshalsec": ToolImageConfig(image="ctf-tools-deser", persistent=False),
    "jndiexploit": ToolImageConfig(image="ctf-tools-deser", persistent=False),
    "phpggc": ToolImageConfig(image="ctf-tools-deser", persistent=False),

    # === 杂项工具 - 低频临时容器 ===
    "jwt_tool": ToolImageConfig(image="ctf-tools-misc", persistent=False),
    "ssrfmap": ToolImageConfig(image="ctf-tools-misc", persistent=False),
    "gopherus": ToolImageConfig(image="ctf-tools-misc", persistent=False),
    "githacker": ToolImageConfig(image="ctf-tools-misc", persistent=False),
    "binwalk": ToolImageConfig(image="ctf-tools-misc", persistent=False),
    "foremost": ToolImageConfig(image="ctf-tools-misc", persistent=False),
    "stegsolve": ToolImageConfig(image="ctf-tools-misc", persistent=False),
}


# 容器池配置
CONTAINER_POOL_CONFIG: Dict[str, Dict[str, Any]] = {
    "web": {
        "count": 3,
        "image": "ctf-tools-web:latest",
        "memory": "1g",
        "cpu_period": 100000,
        "cpu_quota": 50000,  # 50% CPU
    },
    "pwn": {
        "count": 2,
        "image": "ctf-tools-pwn:latest",
        "memory": "512m",
        "cpu_period": 100000,
        "cpu_quota": 30000,  # 30% CPU
    },
}


# 镜像构建配置
IMAGE_BUILD_CONFIG: Dict[str, Dict[str, Any]] = {
    "ctf-tools-web": {
        "dockerfile": "docker/web-tools/Dockerfile",
        "context": ".",
        "tools": ["nmap", "nuclei", "httpx", "fscan", "sqlmap", "ffuf", "dirsearch",
                  "xray", "subfinder", "gobuster", "whatweb", "hydra", "dalfox", "httprobe"],
    },
    "ctf-tools-pwn": {
        "dockerfile": "docker/pwn-tools/Dockerfile",
        "context": ".",
        "tools": ["pwntools", "ROPgadget", "shellcode_generator"],
    },
    "ctf-tools-ad": {
        "dockerfile": "docker/ad-tools/Dockerfile",
        "context": ".",
        "tools": ["crackmapexec", "impacket", "bloodhound", "certipy", "mimikatz"],
    },
    "ctf-tools-deser": {
        "dockerfile": "docker/deser-tools/Dockerfile",
        "context": ".",
        "tools": ["ysoserial", "marshalsec", "JNDIExploit", "phpggc"],
    },
    "ctf-tools-misc": {
        "dockerfile": "docker/misc-tools/Dockerfile",
        "context": ".",
        "tools": ["jwt_tool", "ssrfmap", "gopherus", "githacker", "binwalk"],
    },
}


def get_tool_config(tool_name: str) -> ToolImageConfig | None:
    """获取工具配置"""
    return TOOL_IMAGE_MAPPING.get(tool_name)


def is_docker_tool(tool_name: str) -> bool:
    """检查工具是否应该用Docker执行"""
    return tool_name in TOOL_IMAGE_MAPPING


def get_pool_config(pool_name: str) -> Dict[str, Any] | None:
    """获取容器池配置"""
    return CONTAINER_POOL_CONFIG.get(pool_name)


def get_all_required_images() -> list[str]:
    """获取所有需要的镜像列表"""
    return list(set(config.image for config in TOOL_IMAGE_MAPPING.values()))