"""
专业安全工具定义

使用buildTool工厂创建标准化工具
"""

from .nmap import nmap_tool, register_nmap
from .nuclei import nuclei_tool, register_nuclei
from .httpx import httpx_tool, register_httpx
from .fscan import fscan_tool, register_fscan
from .sqlmap import sqlmap_tool, register_sqlmap

__all__ = [
    "nmap_tool", "register_nmap",
    "nuclei_tool", "register_nuclei",
    "httpx_tool", "register_httpx",
    "fscan_tool", "register_fscan",
    "sqlmap_tool", "register_sqlmap",
]


def register_all_tools():
    """注册所有工具"""
    register_nmap()
    register_nuclei()
    register_httpx()
    register_fscan()
    register_sqlmap()