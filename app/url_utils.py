# app/url_utils.py
"""
URL处理工具集 - 统一URL规范化、解析、IP提取等功能

包含:
- normalize_target_url: 规范化目标URL（处理LLM产生的噪音）
- normalize_url: 标准化URL格式（添加协议头等）
- ensure_protocol_consistency: 确保协议一致性
- extract_target_info: 从URL提取任务信息
- is_ip_target: 判断是否为IP目标
- extract_ip: 从URL提取IP地址
"""

import re
from typing import Dict, Optional, Tuple
from urllib.parse import urlparse


def normalize_target_url(url_str: str) -> str:
    """
    [加固版] 极度鲁棒的 URL 清洗逻辑，专门对付 LLM 产生的各类噪音

    Args:
        url_str: 原始URL字符串，可能包含各种噪音

    Returns:
        清洗后的干净URL
    """
    if not url_str:
        return ""

    s = str(url_str).strip()

    # 1. 暴力移除所有已知的干扰字符
    for char in ["`", "\\", "\n", "\r", "\t"]:
        s = s.replace(char, "")

    # 2. 精准提取第一个 http(s) 链接
    # 只排除空白字符和换行符，其他字符都可能是URL的一部分
    # 例如: http://target/?url=system('ls') 这里的引号和括号都是payload的一部分
    match = re.search(r'(https?://[^\s]+)', s)
    if match:
        clean_url = match.group(1)
        # 3. 剥离末尾可能残留的标点符号（常见的结束标点）
        # 但保留括号、引号等可能是payload一部分的字符
        return clean_url.strip().rstrip(".").rstrip(",").rstrip(";")

    # 4. 如果没找到协议头，尝试二次清理后返回
    return s.strip("'").strip('"').strip()


def normalize_url(url: str) -> str:
    """
    标准化URL：添加协议头、处理常见格式问题

    Args:
        url: 原始URL字符串

    Returns:
        标准化后的URL
    """
    if not url:
        return ""

    url = url.strip()

    # 移除多余空白和特殊字符
    for char in ["`", "\\", "\n", "\r", "\t"]:
        url = url.replace(char, "")

    # 如果没有协议头，添加http://
    if not url.startswith(("http://", "https://")):
        # 检查是否是IP或域名格式
        if re.match(r'^[\w\.-]+(:\d+)?', url):
            url = "http://" + url

    # 移除末尾的标点符号
    url = url.rstrip(".").rstrip(",").rstrip("/")

    return url


def ensure_protocol_consistency(target_url: str, original_url: str) -> str:
    """
    确保目标URL与原始URL使用相同协议
    防止LLM将https改成http

    Args:
        target_url: 目标URL
        original_url: 原始URL（作为协议参考）

    Returns:
        协议修正后的目标URL
    """
    if not target_url or not original_url:
        return target_url

    original_is_https = original_url.lower().startswith("https://")

    if original_is_https and target_url.lower().startswith("http://"):
        # 将http改为https
        target_url = "https://" + target_url[7:]
    elif not original_is_https and target_url.lower().startswith("https://"):
        # 将https改为http
        target_url = "http://" + target_url[8:]

    return target_url


def extract_target_info(url: str) -> Tuple[str, str]:
    """
    从URL自动识别环境类型

    Args:
        url: 目标URL

    Returns:
        tuple: (task_name, task_description)

    环境类型:
        - CTF环境: 域名形式，CTF靶场题目
        - 内网渗透: 内网IP段 (10.x, 172.16-31.x, 192.168.x)
        - 外网打点: 公网IP形式，可访问
    """
    parsed = urlparse(url)
    hostname = parsed.hostname or parsed.netloc.split(':')[0]
    port = parsed.port or (443 if parsed.scheme == 'https' else 80)

    # 判断是否为IP地址
    is_ip = bool(re.match(r'^(\d{1,3}\.){3}\d{1,3}$', hostname))

    if is_ip:
        # 解析IP段
        ip_parts = [int(x) for x in hostname.split('.')]
        first_octet = ip_parts[0]
        second_octet = ip_parts[1]

        # 内网IP段判断
        # 10.0.0.0/8
        # 172.16.0.0/12 (172.16.x.x - 172.31.x.x)
        # 192.168.0.0/16
        is_internal = (
            first_octet == 10 or
            (first_octet == 172 and 16 <= second_octet <= 31) or
            (first_octet == 192 and second_octet == 168)
        )

        if is_internal:
            task_name = f"Internal-{hostname}:{port}"
            task_description = "内网渗透环境 - 内网IP目标"
        else:
            task_name = f"External-{hostname}:{port}"
            task_description = "外网打点环境 - 公网IP目标"
    else:
        # 域名形式，判定为CTF环境
        domain_parts = hostname.split('.')
        if len(domain_parts) >= 2:
            task_name = domain_parts[0]
        else:
            task_name = hostname
        task_description = "CTF靶场环境 - 域名目标"

    return task_name, task_description


def is_ip_target(url: str) -> bool:
    """
    检查目标是否是IP地址

    Args:
        url: 目标URL或IP字符串

    Returns:
        bool: 是否为IP地址格式
    """
    ip_pattern = r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(:\d+)?$'
    return bool(re.match(ip_pattern, url.split('/')[0].split('?')[0]))


def extract_ip(url: str) -> Optional[str]:
    """
    从URL中提取IP地址

    Args:
        url: 包含IP的URL字符串

    Returns:
        str: 提取到的IP地址，未找到返回None
    """
    ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', url)
    return ip_match.group(1) if ip_match else None