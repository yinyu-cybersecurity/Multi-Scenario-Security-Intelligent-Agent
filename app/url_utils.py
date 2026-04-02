# app/url_utils.py
"""
URL和IP地址处理工具函数

包含:
- is_ip_target: 判断是否为IP目标
- extract_ip: 从URL或字符串中提取IP地址
"""

import re
import ipaddress
from typing import Optional
from urllib.parse import urlparse


def is_ip_target(target: str) -> bool:
    """
    判断目标是否为IP地址（而非域名或URL）

    Args:
        target: 目标地址字符串

    Returns:
        True表示是IP地址，False表示是域名或URL
    """
    if not target:
        return False

    # 如果是URL，提取主机名判断
    if target.startswith("http://") or target.startswith("https://"):
        try:
            parsed = urlparse(target)
            hostname = parsed.hostname
            if hostname:
                # 检查主机名是否为IP
                try:
                    ipaddress.ip_address(hostname)
                    return True
                except ValueError:
                    return False
        except Exception:
            return False

    # 检查是否为纯IP地址格式
    # IPv4格式: xxx.xxx.xxx.xxx
    ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(ipv4_pattern, target):
        try:
            ipaddress.ip_address(target)
            return True
        except ValueError:
            return False

    # IPv6格式检查（简化版）
    # 包含冒号可能是IPv6
    if ':' in target and not target.startswith('http'):
        try:
            ipaddress.ip_address(target)
            return True
        except ValueError:
            return False

    return False


def extract_ip(target: str) -> Optional[str]:
    """
    从URL或字符串中提取IP地址

    Args:
        target: 目标地址（URL/IP/域名）

    Returns:
        IP地址字符串，如果无法提取则返回None
    """
    if not target:
        return None

    # 如果是URL，提取主机名
    if target.startswith("http://") or target.startswith("https://"):
        try:
            parsed = urlparse(target)
            hostname = parsed.hostname
            if hostname:
                # 检查主机名是否为IP
                try:
                    ipaddress.ip_address(hostname)
                    return hostname
                except ValueError:
                    # 是域名，无法提取IP
                    return None
        except Exception:
            return None

    # 如果已经是IP格式，直接返回
    ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(ipv4_pattern, target):
        try:
            ipaddress.ip_address(target)
            return target
        except ValueError:
            return None

    # IPv6格式检查
    if ':' in target and not target.startswith('http'):
        try:
            ipaddress.ip_address(target)
            return target
        except ValueError:
            return None

    return None


def is_internal_ip(ip_str: str) -> bool:
    """
    判断IP是否为内网地址

    Args:
        ip_str: IP地址字符串

    Returns:
        True表示是内网地址
    """
    if not ip_str:
        return False

    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return False


def normalize_target(target: str) -> str:
    """
    标准化目标地址

    - 如果是IP，确保没有协议前缀
    - 如果是域名，确保有http://前缀

    Args:
        target: 目标地址

    Returns:
        标准化后的地址
    """
    if not target:
        return target

    # 移除多余空格
    target = target.strip()

    # 如果是IP地址，直接返回
    if is_ip_target(target):
        ip = extract_ip(target)
        return ip if ip else target

    # 如果是域名且没有协议，添加http://
    if not target.startswith("http://") and not target.startswith("https://"):
        # 简单域名检查
        if '.' in target and not target.startswith('/'):
            return f"http://{target}"

    return target