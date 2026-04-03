"""
工具路径配置 - thirdparty目录工具映射

根据thirdparty目录实际结构配置工具路径
"""

from pathlib import Path
from typing import Dict, Optional
import os

# 项目根目录
PROJECT_ROOT = Path(__file__).parent.parent.parent

# thirdparty目录
THIRDPARTY_DIR = PROJECT_ROOT / "thirdparty"

# 操作系统检测
IS_WINDOWS = os.name == 'nt'
EXE_SUFFIX = ".exe" if IS_WINDOWS else ""

# 工具路径映射 - 基于thirdparty实际目录结构
TOOL_PATHS: Dict[str, Path] = {
    # === Go工具 ===
    "nuclei": THIRDPARTY_DIR / "nuclei" / "nuclei",
    "httpx": THIRDPARTY_DIR / "httpx" / "httpx",
    "ffuf": THIRDPARTY_DIR / "ffuf" / "ffuf",
    "subfinder": THIRDPARTY_DIR / "subfinder" / "subfinder",
    "gobuster": THIRDPARTY_DIR / "gobuster" / "gobuster",
    "dalfox": THIRDPARTY_DIR / "dalfox" / f"dalfox-linux-amd64",
    "httprobe": THIRDPARTY_DIR / "httprobe" / "httprobe",

    # === 内网扫描 ===
    "fscan": THIRDPARTY_DIR / ("fscan_windows" if IS_WINDOWS else "fscan_linux") / f"fscan{EXE_SUFFIX}",

    # === Web扫描 ===
    "xray": THIRDPARTY_DIR / "xray" / f"xray_linux_amd64",

    # === Python工具 ===
    "sqlmap": THIRDPARTY_DIR / "sqlmap" / "sqlmap.py",
    "dirsearch": THIRDPARTY_DIR / "dirsearch",  # 目录

    # === 内网渗透 ===
    "crackmapexec": THIRDPARTY_DIR / "crackmapexec" / "cme",
    "impacket": THIRDPARTY_DIR / "impacket",  # 目录

    # === AD工具 ===
    "bloodhound": THIRDPARTY_DIR / "bloodhound",  # 目录
    "certipy": THIRDPARTY_DIR / "certipy" / f"Certipy{EXE_SUFFIX}",
    "pywhisker": THIRDPARTY_DIR / "pywhisker",  # 目录
    "mimikatz": THIRDPARTY_DIR / "mimikatz" / f"mimikatz_64{EXE_SUFFIX}",
    "rubeus": THIRDPARTY_DIR / "rubeus" / f"Rubeus{EXE_SUFFIX}",
    "petitpotam": THIRDPARTY_DIR / "petitpotam" / f"PetitPotam{EXE_SUFFIX}",

    # === Java工具 (jar文件) ===
    "ysoserial": THIRDPARTY_DIR / "ysoserial" / "ysoserial-all.jar",
    "marshalsec": THIRDPARTY_DIR / "marshalsec" / "marshalsec-0.0.3-SNAPSHOT-all.jar",
    "jndiexploit": THIRDPARTY_DIR / "jndiexploit" / "JNDIExploit-1.3-SNAPSHOT.jar",

    # === 专项工具 ===
    "jwt_tool": THIRDPARTY_DIR / "jwt_tool" / "jwt_tool.py",
    "ssrfmap": THIRDPARTY_DIR / "ssrfmap",  # 目录
    "githacker": THIRDPARTY_DIR / "githacker" / "GitHack.py",
    "gopherus": THIRDPARTY_DIR / "gopherus",  # 目录
    "phpggc": THIRDPARTY_DIR / "phpggc",  # 目录
    "ghostcat": THIRDPARTY_DIR / "ghostcat" / "ajpShooter.py",
    "xxeinjector": THIRDPARTY_DIR / "xxeinjector",  # 目录
    "jsfinder": THIRDPARTY_DIR / "jsfinder" / "JSFinder.py",
    "php_filter_chain_generator": THIRDPARTY_DIR / "php_filter_chain_generator" / "php_filter_chain_generator.py",

    # === 内网穿透 ===
    "frp": THIRDPARTY_DIR / "frp",  # 目录

    # === 工具集合 ===
    "crypto_tools": THIRDPARTY_DIR / "crypto_tools",  # 目录
    "binary_tools": THIRDPARTY_DIR / "binary_tools",  # 目录
    "cloud_tools": THIRDPARTY_DIR / "cloud_tools",  # 目录
    "oa_tools": THIRDPARTY_DIR / "oa_tools",  # 目录
}


def get_tool_path(tool_name: str) -> Optional[Path]:
    """
    获取工具路径

    Args:
        tool_name: 工具名称

    Returns:
        工具路径，不存在返回None
    """
    if tool_name not in TOOL_PATHS:
        return None

    path = TOOL_PATHS[tool_name]

    # 检查路径是否存在
    if path.exists():
        return path

    return None


def is_python_tool(tool_name: str) -> bool:
    """判断是否为Python脚本工具"""
    python_tools = {
        "sqlmap", "jwt_tool", "githacker", "ghostcat",
        "jsfinder", "php_filter_chain_generator"
    }
    return tool_name in python_tools


def is_java_tool(tool_name: str) -> bool:
    """判断是否为Java jar工具"""
    java_tools = {
        "ysoserial", "marshalsec", "jndiexploit"
    }
    return tool_name in java_tools


def is_directory_tool(tool_name: str) -> bool:
    """判断是否为目录型工具（需要进一步查找入口）"""
    dir_tools = {
        "dirsearch", "impacket", "bloodhound", "pywhisker",
        "ssrfmap", "gopherus", "phpggc", "xxeinjector",
        "frp", "crypto_tools", "binary_tools", "cloud_tools", "oa_tools"
    }
    return tool_name in dir_tools


__all__ = [
    "TOOL_PATHS",
    "THIRDPARTY_DIR",
    "get_tool_path",
    "is_python_tool",
    "is_java_tool",
    "is_directory_tool",
]