import os

# 设置 HuggingFace 缓存目录（使用预下载的模型）
os.environ['HF_HOME'] = os.environ.get('HF_HOME', '/app/.cache/huggingface')
os.environ['HF_ENDPOINT'] = os.environ.get('HF_ENDPOINT', 'https://hf-mirror.com')

import argparse
import re
import hashlib
import requests
import sys
import concurrent.futures
import traceback
import urllib3
from urllib.parse import urlparse

# 上下文压缩和链条记录
from context_compressor import get_chain_recorder, get_compressor

# Token压缩节点
try:
    from compressor_node import compressor_node
    COMPRESSOR_AVAILABLE = True
except ImportError:
    COMPRESSOR_AVAILABLE = False

# 统一日志系统
from logger import get_logger, node_log, log_node_start, log_node_result, log_attack, log_flag_found
logger = get_logger(__name__)

def log(msg: str, node: str = "main", level: str = "info"):
    """
    统一日志输出函数
    同时输出到控制台（带颜色/图标）和日志文件
    """
    node_log(node, msg, level)

# 节点日志快捷函数
def log_recon(msg: str): log(msg, node="recon")
def log_analyst(msg: str): log(msg, node="analyst")
def log_attacker(msg: str): log(msg, node="attacker")
def log_verifier(msg: str): log(msg, node="verifier")
def log_explorer(msg: str): log(msg, node="explorer")
def log_innovator(msg: str): log(msg, node="innovator")
def log_detector(msg: str): log(msg, node="challenge_type_detector")
def log_mode_manager(msg: str): log(msg, node="mode_manager")
def log_system(msg: str): log(msg, node="system")

# 抑制 SSL 安全警告 (CTF 环境中通常不需要)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 修复 ChromaDB 在 Linux/Docker 环境下的 SQLite3 版本兼容性问题
try:
    import pysqlite3
    sys.modules["sqlite3"] = sys.modules.pop("pysqlite3")
except ImportError:
    pass  # pysqlite3 未安装，使用系统 sqlite3

# [性能优化] 全局线程池 - 懒加载模式
from typing import Dict as TypingDict
import atexit

# URL处理工具集
from url_utils import normalize_target_url, normalize_url, ensure_protocol_consistency, extract_target_info

_executor = None
_running_tasks: TypingDict[str, concurrent.futures.Future] = {}

def get_executor():
    """获取全局线程池(懒加载)"""
    global _executor
    if _executor is None:
        # 线程数根据并发需求设定，8个足够处理并行扫描和攻击
        _executor = concurrent.futures.ThreadPoolExecutor(max_workers=8)
        atexit.register(_shutdown_executor)
    return _executor

def _shutdown_executor():
    """关闭线程池"""
    global _executor
    if _executor is not None:
        _executor.shutdown(wait=False, cancel_futures=False)
        _executor = None

# URL处理函数已移至 url_utils.py:
# - normalize_target_url
# - normalize_url
# - ensure_protocol_consistency
# - extract_target_info

# ctf_agent_graph.py
from config import config
from llm_client import llm_client
from analyst_prompt import get_analyst_prompt
from tools import load_minimal_tools, load_web_tools, load_internal_tools, load_tools_by_category
from verifier_prompt import get_verifier_prompt
from attacker_prompt import get_attacker_prompt
from topology import TopologyBuilder, TopologyAnalyzer, TopologyPruner
from tool_framework import ToolRegistry, CTFTool
from topology.page_diff import page_diff_manager
from scene_detector import SceneDetector

from evolution import evolution_node
from strategy_filter import strategy_filter_node
from innovator_agent import innovator_node
from router import (
    route_mode,
    route_verify,
    route_evolution,
    get_routing_stats,
    route_internal_mode,
    route_internal_to_web,
    get_internal_next_target,
    route_post_exploit,
    route_with_strategic_context,
    update_strategic_context_after_node
)
from state import CTFState, VulnerabilityCandidate, AttackAction, PageFeatures, Hint, ToolCall

# 使用模块注册机制替代重复的 try/except
from module_registry import ModuleRegistry

# 节点控制 - 支持运行时禁用节点
from node_control import node_control, create_disabled_wrapper

# 模块可用性标志（通过 ModuleRegistry 自动管理）
SELF_CORRECTION_AVAILABLE = ModuleRegistry.is_available('self_correction')
INTERNAL_NETWORK_AVAILABLE = ModuleRegistry.is_available('internal_network')
POST_EXPLOIT_AVAILABLE = ModuleRegistry.is_available('post_exploit')
CRYPTO_AVAILABLE = ModuleRegistry.is_available('crypto')
PWN_AVAILABLE = ModuleRegistry.is_available('pwn')
REVERSE_AVAILABLE = ModuleRegistry.is_available('reverse')
MISC_AVAILABLE = ModuleRegistry.is_available('misc')
PERFORMANCE_AVAILABLE = ModuleRegistry.is_available('performance')
CLOUD_SECURITY_AVAILABLE = ModuleRegistry.is_available('cloud_security')
AI_SECURITY_AVAILABLE = ModuleRegistry.is_available('ai_security')

# 导入可用模块的节点函数
if SELF_CORRECTION_AVAILABLE:
    self_correction_manager = ModuleRegistry.get_node('self_correction', 'self_correction_manager')
    ErrorSeverity = ModuleRegistry.get_node('self_correction', 'ErrorSeverity')

if INTERNAL_NETWORK_AVAILABLE:
    internal_recon_node = ModuleRegistry.get_node('internal_network', 'internal_recon')
    lateral_move_node = ModuleRegistry.get_node('internal_network', 'lateral_move')
    privilege_escalation_node = ModuleRegistry.get_node('internal_network', 'privilege_escalation')
    credential_gather_node = ModuleRegistry.get_node('internal_network', 'credential_gather')
    flag_search_node = ModuleRegistry.get_node('internal_network', 'flag_search')
    persistence_node = ModuleRegistry.get_node('internal_network', 'persistence')
    try:
        from internal_network.orchestrator import InternalNetworkOrchestrator
    except ImportError:
        InternalNetworkOrchestrator = None

if POST_EXPLOIT_AVAILABLE:
    post_exploit_node = ModuleRegistry.get_node('post_exploit', 'post_exploit')
    upload_tools_node = ModuleRegistry.get_node('post_exploit', 'upload_tools')
    setup_tunnel_node = ModuleRegistry.get_node('post_exploit', 'setup_tunnel')

if CRYPTO_AVAILABLE:
    crypto_analyst_node = ModuleRegistry.get_node('crypto', 'crypto_analyst')
    crypto_solver_node = ModuleRegistry.get_node('crypto', 'crypto_solver')

if PWN_AVAILABLE:
    pwn_analyst_node = ModuleRegistry.get_node('pwn', 'pwn_analyst')
    pwn_exploiter_node = ModuleRegistry.get_node('pwn', 'pwn_exploiter')

if REVERSE_AVAILABLE:
    reverse_analyst_node = ModuleRegistry.get_node('reverse', 'reverse_analyst')
    reverse_decompiler_node = ModuleRegistry.get_node('reverse', 'reverse_decompiler')

if MISC_AVAILABLE:
    misc_analyst_node = ModuleRegistry.get_node('misc', 'misc_analyst')
    misc_extractor_node = ModuleRegistry.get_node('misc', 'misc_extractor')

if CLOUD_SECURITY_AVAILABLE:
    cloud_recon_node = ModuleRegistry.get_node('cloud_security', 'cloud_recon')
    cloud_enum_node = ModuleRegistry.get_node('cloud_security', 'cloud_enum')
    cloud_exploit_node = ModuleRegistry.get_node('cloud_security', 'cloud_exploit')
    cloud_escalate_node = ModuleRegistry.get_node('cloud_security', 'cloud_escalate')

if AI_SECURITY_AVAILABLE:
    ai_detect_node = ModuleRegistry.get_node('ai_security', 'ai_detect')
    ai_probe_node = ModuleRegistry.get_node('ai_security', 'ai_probe')
    ai_exploit_node = ModuleRegistry.get_node('ai_security', 'ai_exploit')
    ai_exfiltrate_node = ModuleRegistry.get_node('ai_security', 'ai_exfiltrate')

if PERFORMANCE_AVAILABLE:
    performance_monitor = ModuleRegistry.get_node('performance', 'performance_monitor')
    get_system_status = ModuleRegistry.get_node('performance', 'get_system_status')
    ParallelExecutor = ModuleRegistry.get_node('performance', 'ParallelExecutor')
import networkx as nx
import json
import yaml
import os
import time
from typing import Annotated, List, Dict, Literal, Union, Any, Optional, Tuple, Callable
from typing_extensions import TypedDict
from langgraph.graph import StateGraph, END, START
from langgraph.checkpoint.memory import MemorySaver
from dataclasses import dataclass



# ==============================================================================
# 2. 工具集成框架 (Tool Integration Framework) - 可无限扩展
# ==============================================================================

# CTFTool and ToolRegistry are now imported from tool_framework.py
# Removed redundant initialization here as it's handled by the entry point or registry.

# ==============================================================================
# 3. 辅助函数 (Utils)
# ==============================================================================

def log_node_data(node_name: str, input_data: Any, output_data: Any):
    """最简单的日志记录：将节点输入输出写入 log 文件夹"""
    os.makedirs("log", exist_ok=True)
    log_file = os.path.join("log", f"{node_name}_{int(time.time())}.log")
    with open(log_file, "w", encoding="utf-8") as f:
        f.write(f"=== [{node_name}] INPUT ===\n")
        f.write(json.dumps(input_data, indent=2, ensure_ascii=False, default=str))
        f.write(f"\n\n=== [{node_name}] OUTPUT ===\n")
        f.write(json.dumps(output_data, indent=2, ensure_ascii=False, default=str))
    log(f"📝 [Log] {node_name} 数据已写入 {log_file}")

def calculate_dom_fingerprint(html_content: str) -> str:
    """计算DOM结构指纹"""
    if not html_content:
        return ""
    return hashlib.md5(html_content.encode('utf-8', errors='ignore')).hexdigest()


def extract_structured_html(html_content: str) -> Dict[str, Any]:
    """
    [P0 Critical] 在HTML截断之前提取结构化数据

    提取关键攻击面信息，防止因截断而丢失:
    - hidden_fields: 隐藏表单字段（可能用于SSRF等攻击）
    - form_endpoints: 表单端点和字段
    - script_endpoints: JavaScript中的URL/端点
    - comments: HTML注释（可能包含提示）
    - meta_tags: Meta标签内容
    - data_attributes: data-*属性
    - api_endpoints: API端点（fetch/ajax调用）

    Args:
        html_content: 完整的HTML内容（截断前）

    Returns:
        结构化提取的数据字典
    """
    if not html_content:
        return {
            "hidden_fields": {},
            "form_endpoints": [],
            "script_endpoints": [],
            "comments": [],
            "meta_tags": {},
            "data_attributes": {},
            "api_endpoints": []
        }

    result = {
        "hidden_fields": {},
        "form_endpoints": [],
        "script_endpoints": [],
        "comments": [],
        "meta_tags": {},
        "data_attributes": {},
        "api_endpoints": []
    }

    # 1. 提取隐藏字段 (input type=hidden)
    # 匹配各种格式的hidden input
    hidden_pattern = r'<input[^>]*type=["\']?hidden["\']?[^>]*>'
    for match in re.finditer(hidden_pattern, html_content, re.IGNORECASE):
        input_tag = match.group(0)
        # 提取name和value
        name_match = re.search(r'name=["\']?([^"\'>\s]+)["\']?', input_tag, re.IGNORECASE)
        value_match = re.search(r'value=["\']?([^"\'>]*)["\']?', input_tag, re.IGNORECASE)
        if name_match:
            name = name_match.group(1)
            value = value_match.group(1) if value_match else ""
            result["hidden_fields"][name] = value

    # 2. 提取表单端点和字段
    form_pattern = r'<form[^>]*>'
    for match in re.finditer(form_pattern, html_content, re.IGNORECASE):
        form_tag = match.group(0)
        # 提取action和method
        action_match = re.search(r'action=["\']?([^"\'>\s]+)["\']?', form_tag, re.IGNORECASE)
        method_match = re.search(r'method=["\']?([^"\'>\s]+)["\']?', form_tag, re.IGNORECASE)

        action = action_match.group(1) if action_match else ""
        method = method_match.group(1).upper() if method_match else "GET"

        # 提取表单内的所有字段
        form_end = html_content.find('</form>', match.end(), re.IGNORECASE)
        if form_end == -1:
            form_end = min(match.end() + 5000, len(html_content))
        form_content = html_content[match.end():form_end]

        fields = []
        # 提取所有input字段
        for input_match in re.finditer(r'<input[^>]*>', form_content, re.IGNORECASE):
            input_tag = input_match.group(0)
            input_name = re.search(r'name=["\']?([^"\'>\s]+)["\']?', input_tag, re.IGNORECASE)
            input_type = re.search(r'type=["\']?([^"\'>\s]+)["\']?', input_tag, re.IGNORECASE)
            if input_name:
                fields.append({
                    "name": input_name.group(1),
                    "type": input_type.group(1) if input_type else "text"
                })

        # 提取select和textarea
        for select_match in re.finditer(r'<select[^>]*name=["\']?([^"\'>\s]+)["\']?', form_content, re.IGNORECASE):
            fields.append({"name": select_match.group(1), "type": "select"})

        for textarea_match in re.finditer(r'<textarea[^>]*name=["\']?([^"\'>\s]+)["\']?', form_content, re.IGNORECASE):
            fields.append({"name": textarea_match.group(1), "type": "textarea"})

        result["form_endpoints"].append({
            "action": action,
            "method": method,
            "fields": fields
        })

    # 3. 提取JavaScript中的URL/端点
    # 匹配fetch, ajax, axios, XMLHttpRequest等
    js_url_patterns = [
        r'fetch\s*\(\s*["\']([^"\']+)["\']',  # fetch('url')
        r'\.ajax\s*\(\s*\{[^}]*url\s*:\s*["\']([^"\']+)["\']',  # $.ajax({url: 'url'})
        r'axios\.[get|post]+\s*\(\s*["\']([^"\']+)["\']',  # axios.get('url')
        r'XMLHttpRequest[^}]*open\s*\([^,]+,\s*["\']([^"\']+)["\']',  # xhr.open('GET', 'url')
        r'\.load\s*\(\s*["\']([^"\']+)["\']',  # $('#el').load('url')
        r'window\.location\s*=\s*["\']([^"\']+)["\']',  # window.location = 'url'
        r'location\.href\s*=\s*["\']([^"\']+)["\']',  # location.href = 'url'
        r'src\s*=\s*["\']([^"\']*(?:api|endpoint|ajax|fetch)[^"\']*)["\']',  # API-related src
        r'url\s*:\s*["\']([^"\']+(?:api|endpoint)[^"\']*)["\']',  # url: '/api/...'
    ]

    script_content = ""
    # 提取<script>标签内容
    for script_match in re.finditer(r'<script[^>]*>(.*?)</script>', html_content, re.IGNORECASE | re.DOTALL):
        script_content += script_match.group(1) + "\n"

    for pattern in js_url_patterns:
        for match in re.finditer(pattern, script_content, re.IGNORECASE):
            url = match.group(1)
            if url and len(url) < 500:  # 过滤掉超长字符串
                result["script_endpoints"].append(url)

    # 去重
    result["script_endpoints"] = list(set(result["script_endpoints"]))

    # 4. 提取HTML注释
    for match in re.finditer(r'<!--(.*?)-->', html_content, re.DOTALL):
        comment = match.group(1).strip()
        if comment and len(comment) < 1000:  # 过滤掉超长注释
            result["comments"].append(comment)

    # 5. 提取meta标签
    for match in re.finditer(r'<meta[^>]*>', html_content, re.IGNORECASE):
        meta_tag = match.group(0)
        # 提取name/property和content
        name_match = re.search(r'(?:name|property)=["\']?([^"\'>\s]+)["\']?', meta_tag, re.IGNORECASE)
        content_match = re.search(r'content=["\']([^"\']*)["\']', meta_tag, re.IGNORECASE)
        if name_match and content_match:
            result["meta_tags"][name_match.group(1)] = content_match.group(1)

    # 6. 提取data-*属性（可能包含重要信息）
    for match in re.finditer(r'data-([a-zA-Z0-9_-]+)=["\']([^"\']*)["\']', html_content, re.IGNORECASE):
        attr_name = f"data-{match.group(1)}"
        attr_value = match.group(2)
        if attr_value and len(attr_value) < 500:
            result["data_attributes"][attr_name] = attr_value

    # 7. 提取API端点（更全面的模式）
    api_patterns = [
        r'["\']/(api|v\d+)/[a-zA-Z0-9_/-]+["\']',  # '/api/...', '/v1/...'
        r'["\'][a-zA-Z0-9_/-]+\.(?:json|xml|php|asp|aspx)["\']',  # '*.json', '*.php'
        r'["\'][a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+(?:/[a-zA-Z0-9_-]+)*["\']',  # RESTful paths
    ]

    for pattern in api_patterns:
        for match in re.finditer(pattern, html_content):
            endpoint = match.group(0).strip('"\'')
            if endpoint and endpoint not in result["api_endpoints"] and len(endpoint) < 200:
                result["api_endpoints"].append(endpoint)

    # 去重api_endpoints
    result["api_endpoints"] = list(set(result["api_endpoints"]))

    return result




# ==============================================================================
# 4. 兵种节点定义 (Node Definitions)
# ==============================================================================

def challenge_type_detector_node(state: CTFState) -> Dict:
    """
    [CTF类型检测器] 多信号智能检测挑战类型

    检测策略（按优先级）：
    1. 附件文件类型检测（最可靠）
    2. HTTP服务可访问性检测
    3. LLM智能判断（兜底方案）

    检测类型:
        - Web: HTTP服务可访问
        - Pwn: ELF/PE二进制文件
        - Reverse: 需逆向分析的二进制
        - Crypto: 加密相关文件或描述
        - Misc: 图片/音频/pcap等杂项文件
        - Internal: 内网IP地址
    """
    log("[TypeDetector] Analyzing challenge type...")

    task_name = state.get("task_name", "")
    task_desc = state.get("task_description", "")
    target_url = state.get("target_url", "")
    attachments = state.get("attachments", [])

    result = {}

    # =========================================================================
    # 策略1: 附件文件类型检测（最可靠）
    # =========================================================================
    if attachments:
        for att in attachments:
            att_path = att.get("path", "")
            att_type = att.get("type", "").lower()
            att_name = att.get("name", "").lower()

            # 根据文件扩展名判断
            ext = att_name.split('.')[-1] if '.' in att_name else ''

            # 二进制文件类型
            if ext in ['elf', 'so', 'out'] or att_type in ['elf', 'binary']:
                # ELF文件 - 进一步判断是Pwn还是Reverse
                # 通过LLM分析任务描述来区分
                if _is_pwn_challenge(task_name, task_desc):
                    log(f"   [Signal:Attachment] Pwn challenge detected (ELF binary)")
                    result = {"pwn_mode": True, "binary_path": att_path}
                else:
                    log(f"   [Signal:Attachment] Reverse challenge detected (ELF binary)")
                    result = {"reverse_mode": True, "binary_path": att_path}
                break

            elif ext in ['exe', 'dll'] or att_type in ['pe', 'exe']:
                log(f"   [Signal:Attachment] Reverse/Pwn challenge (PE binary)")
                result = {"reverse_mode": True, "binary_path": att_path}
                break

            # Misc文件类型
            elif ext in ['png', 'jpg', 'jpeg', 'gif', 'bmp', 'wav', 'mp3', 'mp4', 'avi']:
                log(f"   [Signal:Attachment] Misc challenge (media file: {ext})")
                result = {"misc_mode": True, "misc_file": att_path}
                break

            elif ext in ['pcap', 'pcapng', 'cap']:
                log(f"   [Signal:Attachment] Misc challenge (traffic capture)")
                result = {"misc_mode": True, "misc_file": att_path}
                break

            elif ext in ['pdf', 'doc', 'docx', 'xls', 'xlsx']:
                log(f"   [Signal:Attachment] Misc challenge (document)")
                result = {"misc_mode": True, "misc_file": att_path}
                break

            elif ext in ['zip', 'rar', '7z', 'tar', 'gz']:
                log(f"   [Signal:Attachment] Misc challenge (archive)")
                result = {"misc_mode": True, "misc_file": att_path}
                break

            # Crypto文件类型
            elif ext in ['enc', 'key', 'pem', 'pub', 'priv']:
                log(f"   [Signal:Attachment] Crypto challenge (key file)")
                result = {"crypto_mode": True}
                break

    # =========================================================================
    # 策略2: HTTP服务可访问性检测 + 内网模式判断
    # =========================================================================
    if not result and target_url:
        # 检查云服务特征
        cloud_patterns = [".amazonaws.com", ".s3.amazonaws", ".cloudfront.net",
                          ".azurewebsites.net", ".blob.core.windows.net",
                          ".appspot.com", ".storage.googleapis.com",
                          ".aliyuncs.com", ".myqcloud.com"]
        if any(p in target_url.lower() for p in cloud_patterns):
            log(f"   [Signal:Cloud] 云服务特征检测")
            result = {"cloud_mode": True}

        # 检查AI服务特征
        ai_patterns = ["openai.com", "chatgpt", "anthropic.com", "claude",
                       "deepseek", "gemini", "bard", "llm-api"]
        task_desc = state.get("task_description", "") if isinstance(state, dict) else ""
        if any(p in target_url.lower() or p in task_desc.lower() for p in ai_patterns):
            log(f"   [Signal:AI] AI服务特征检测")
            result = {"ai_mode": True}

        # 检查是否是纯IP地址（可能是内网目标）
        ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', target_url)
        is_pure_ip = bool(re.match(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(:\d+)?$', target_url.strip()))

        # 构建测试URL
        test_url = target_url
        if is_pure_ip and not target_url.startswith('http'):
            test_url = f"http://{target_url}"

        if test_url.startswith('http://') or test_url.startswith('https://'):
            is_accessible, response_info = _check_http_accessible(test_url)
            if is_accessible:
                log(f"   [Signal:HTTP] Web challenge (service accessible)")
                # HTTP 可访问，检查是否有内网渗透特征
                # [修复] 移除对未定义变量 raw_html 的引用
                if response_info.get("server", "").lower().find("nginx") >= 0:
                    log(f"   [Signal:Web-Framework] 可能使用Nginx服务器")
                result = {}  # Web是默认模式
            else:
                # HTTP不可访问
                if ip_match:
                    log(f"   [Signal:IP-NoHTTP] IP地址无HTTP服务 -> 内网扫描模式")
                    result = {"internal_mode": True}
                else:
                    log(f"   [Signal:Unknown] HTTP not accessible, will use LLM analysis")
        elif target_url.startswith('file://') or os.path.exists(target_url):
            # 本地文件路径
            log(f"   [Signal:LocalFile] Processing local file")
            result = _detect_file_type(target_url)

    # =========================================================================
    # 策略3: LLM智能判断（兜底方案）
    # =========================================================================
    if not result:
        log("   [Signal:LLM] Using LLM for type detection...")
        llm_result = _llm_detect_challenge_type(task_name, task_desc, target_url, attachments)
        if llm_result:
            result = llm_result

    # 如果仍未确定，默认Web模式
    if not result:
        log("   [Default] Assuming Web challenge")
        result = {}

    # 根据检测到的类型设置内存模式并切换模块
    if result.get("internal_mode"):
        target_mode = "internal"
    elif result.get("cloud_mode") or result.get("ai_mode"):
        target_mode = "cloud"
    elif result.get("crypto_mode"):
        target_mode = "crypto"
    elif result.get("pwn_mode"):
        target_mode = "pwn"
    elif result.get("reverse_mode"):
        target_mode = "reverse"
    elif result.get("misc_mode"):
        target_mode = "misc"
    else:
        target_mode = "web"

    result["memory_mode"] = target_mode

    # 直接切换模块管理器模式
    try:
        from module_manager import module_manager
        if module_manager.memory_mode != target_mode:
            log(f"   [ModuleManager] 初始化模式: {target_mode}")
            module_manager.switch_mode(target_mode, result)
    except ImportError:
        pass

    result["execution_steps"] = state.get("execution_steps", 0) + 1
    return result


def _is_pwn_challenge(task_name: str, task_desc: str) -> bool:
    """通过关键词判断是否是Pwn挑战（vs Reverse）"""
    pwn_indicators = [
        'pwn', 'shell', 'exploit', 'overflow', 'rop', 'heap', 'stack',
        'canary', 'aslr', 'pie', 'nx', 'got', 'plt', 'libc', 'shellcode',
        'uaf', 'race condition', '漏洞利用'
    ]
    reverse_indicators = [
        'reverse', '逆向', 'crack', 'keygen', 'serial', 'license',
        '反编译', '注册机', '算法分析'
    ]

    text = f"{task_name} {task_desc}".lower()

    pwn_score = sum(1 for kw in pwn_indicators if kw in text)
    reverse_score = sum(1 for kw in reverse_indicators if kw in text)

    return pwn_score > reverse_score


def _check_http_accessible(url: str) -> tuple:
    """检查HTTP服务是否可访问"""
    try:
        import requests
        resp = requests.head(url, timeout=config.HTTP_HEAD_TIMEOUT, verify=False, allow_redirects=True)
        if resp.status_code < 500:
            return True, {
                "status_code": resp.status_code,
                "server": resp.headers.get("Server", ""),
                "content_type": resp.headers.get("Content-Type", "")
            }
    except requests.exceptions.Timeout:
        return False, {"error": "timeout"}
    except requests.exceptions.ConnectionError:
        return False, {"error": "connection_refused"}
    except Exception as e:
        return False, {"error": str(e)}

    return False, {"error": "unknown"}


def _detect_file_type(file_path: str) -> Dict:
    """检测本地文件类型"""
    import os
    if not os.path.exists(file_path):
        return {}

    ext = file_path.split('.')[-1].lower() if '.' in file_path else ''

    # 读取文件头判断真实类型
    try:
        with open(file_path, 'rb') as f:
            header = f.read(16)

        # ELF文件
        if header[:4] == b'\x7fELF':
            if _is_pwn_challenge("", ""):
                return {"pwn_mode": True, "binary_path": file_path}
            return {"reverse_mode": True, "binary_path": file_path}

        # PE文件
        if header[:2] == b'MZ':
            return {"reverse_mode": True, "binary_path": file_path}

        # PNG
        if header[:8] == b'\x89PNG\r\n\x1a\n':
            return {"misc_mode": True, "misc_file": file_path}

        # JPEG
        if header[:2] == b'\xff\xd8':
            return {"misc_mode": True, "misc_file": file_path}

        # PDF
        if header[:4] == b'%PDF':
            return {"misc_mode": True, "misc_file": file_path}

        # ZIP
        if header[:4] == b'PK\x03\x04':
            return {"misc_mode": True, "misc_file": file_path}

    except Exception as e:
        logger.debug(f"[ChallengeType] 文件头检测失败: {e}")
        # 继续按扩展名判断

    # 按扩展名判断
    if ext in ['elf', 'out', 'so']:
        return {"pwn_mode": True, "binary_path": file_path}
    elif ext in ['exe', 'dll']:
        return {"reverse_mode": True, "binary_path": file_path}
    elif ext in ['png', 'jpg', 'gif', 'wav', 'mp3', 'pcap']:
        return {"misc_mode": True, "misc_file": file_path}

    return {}


def _llm_detect_challenge_type(task_name: str, task_desc: str,
                                target_url: str, attachments: list) -> Dict:
    """使用LLM智能判断挑战类型"""

    prompt = f"""Analyze this CTF challenge and determine its type.

## Challenge Information
- Name: {task_name}
- Description: {task_desc}
- Target: {target_url}
- Attachments: {len(attachments)} files

## Challenge Types
1. **Web**: Web security (SQLi, XSS, SSRF, file upload, etc.)
2. **Pwn**: Binary exploitation (buffer overflow, ROP, heap, etc.)
3. **Reverse**: Reverse engineering (crackme, keygen, algorithm analysis)
4. **Crypto**: Cryptography (RSA, AES, hash cracking, encoding)
5. **Misc**: Steganography, forensics, traffic analysis, encoding
6. **Internal**: Internal network penetration (AD, lateral movement)
7. **Cloud**: Cloud security (AWS/Azure/GCP, Lambda, IAM, S3)
8. **AI**: AI security (LLM, prompt injection, jailbreak, model extraction)

## Output Format (JSON)
{{
  "type": "web/pwn/reverse/crypto/misc/internal",
  "confidence": 0.0-1.0,
  "reasoning": "brief explanation"
}}
"""

    try:
        response = llm_client.call_chat_completion(
            model=config.ANALYST_MODEL,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.1,
            json_mode=True,
            timeout=30  # 类型检测应快速完成
        )

        if "```json" in response:
            response = response.split("```json")[1].split("```")[0]

        result = json.loads(response.strip())
        detected_type = result.get("type", "web")
        confidence = result.get("confidence", 0.5)

        log(f"   [LLM Result] Type: {detected_type}, Confidence: {confidence:.2f}")
        log(f"   [LLM Reason] {result.get('reasoning', 'N/A')}")

        if detected_type == "pwn":
            return {"pwn_mode": True}
        elif detected_type == "reverse":
            return {"reverse_mode": True}
        elif detected_type == "crypto":
            return {"crypto_mode": True}
        elif detected_type == "misc":
            return {"misc_mode": True}
        elif detected_type == "internal":
            return {"internal_mode": True}
        elif detected_type == "cloud":
            return {"cloud_mode": True}
        elif detected_type == "ai":
            return {"ai_mode": True}
        else:
            return {}  # Web is default

    except Exception as e:
        log(f"   [LLM Error] {e}")
        return {}


def recon_node(state: CTFState) -> Dict:
    """
    [侦察兵] (LLM 驱动的特征提取 + 自动化扫描)

    职责:
        1. 获取原始页面内容 (HTTP)
        2. 对 IP 目标执行 fscan 快速扫描
        3. 执行 dirsearch 目录扫描
        4. 计算页面指纹用于去重
        5. 调用 LLM 进行深度特征提取
    """
    url = state.get('current_url', state['target_url'])
    task_name = state.get("task_name", "")
    task_desc = state.get("task_description", "")

    # 获取已扫描记录，防止重复扫描
    scanned_ips = state.get("scanned_ips", []) or []
    scanned_urls = state.get("scanned_urls", []) or []

    log(f"📡 [侦察] {url}")

    # =========================================================================
    # 新增: 检测是否是纯 IP 目标，执行 fscan 扫描
    # =========================================================================
    ip_match = re.match(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(:\d+)?$', url.split('/')[0].split('?')[0])
    if not ip_match:
        # 尝试从 URL 中提取 IP
        ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', url)

    fscan_findings = []
    if ip_match:
        target_ip = ip_match.group(1)
        if target_ip not in scanned_ips:
            log(f"   🔍 [fscan] 扫描目标 IP: {target_ip}")
            try:
                fscan_result = ToolRegistry.execute_cached("fscan", target_ip, {
                    "scan_type": "quick"
                })
                if fscan_result and fscan_result.get("result", {}).get("success"):
                    result_data = fscan_result.get("result", {})
                    # fscan 返回 hosts 和 vulnerabilities (由 AI 解析)
                    hosts = result_data.get("hosts", [])
                    vulns = result_data.get("vulnerabilities", [])
                    # 合并为findings格式
                    findings = []
                    for v in vulns:
                        # 兼容两种格式：AI解析返回 target，正则解析返回 ip
                        vuln_target = v.get("target") or v.get("ip", target_ip)
                        # 提取端口（可能是数字或 "ip:port" 格式）
                        vuln_port = v.get("port", "?")
                        if isinstance(vuln_target, str) and ":" in vuln_target:
                            parts = vuln_target.split(":")
                            vuln_target = parts[0]
                            vuln_port = parts[1] if len(parts) > 1 else vuln_port

                        findings.append({
                            "type": v.get("type", "vulnerability"),
                            "target": vuln_target,
                            "port": vuln_port,
                            "info": v.get("info", v.get("description", "")),
                            "severity": v.get("severity", "high"),
                            "poc": v.get("poc", ""),
                            "cve": v.get("cve", "")
                        })
                    for h in hosts:
                        for p in h.get("ports", []):
                            findings.append({
                                "type": "port",
                                "target": h.get("ip", "?"),
                                "port": p.get("port", "?"),
                                "info": f"{p.get('service', 'unknown')} {p.get('state', '')}"
                            })
                    fscan_findings = findings
                    if findings:
                        log(f"   🔥 fscan 发现 {len(findings)} 个潜在漏洞/服务")
                        for f in findings[:5]:
                            vuln_type = f.get("type", "unknown")
                            port = f.get("port", "?")
                            info = f.get("info", "")[:50]
                            log(f"      - [{vuln_type}] {target_ip}:{port} {info}")
            except Exception as e:
                log(f"   ⚠️ [fscan] 扫描失败: {e}")
            scanned_ips = scanned_ips + [target_ip]
        else:
            log(f"   ⏭️ [fscan] IP {target_ip} 已扫描过，跳过")

    # =========================================================================
    # dirsearch 由分析兵决策是否需要，不在此处自动执行
    # 分析兵可通过 structured_guidance.guidance_type="need_dirsearch" 请求扫描
    # =========================================================================
    dirsearch_paths = []
    # 记录扫描状态，避免重复
    scan_url = url.split('?')[0].split('#')[0]
    if scan_url not in scanned_urls and scan_url.startswith('http'):
        scanned_urls = scanned_urls + [scan_url]

    # =========================================================================
    # 1. 发起 HTTP 请求获取原始 HTML
    # =========================================================================
    # 如果是纯 IP 且没有 HTTP 前缀，尝试添加
    http_url = url
    if ip_match and not url.startswith('http'):
        http_url = f"http://{url}"

    try:
        import requests
        resp = requests.get(http_url, timeout=config.HTTP_GET_TIMEOUT, verify=False, allow_redirects=True)
        raw_html = resp.text

        # 记录重定向信息
        redirect_chain = []
        final_url = resp.url
        if resp.history:
            for r in resp.history:
                redirect_chain.append({
                    "status_code": r.status_code,
                    "url": r.url,
                    "location": r.headers.get('Location', '')
                })
            log(f"   🔀 重定向: {http_url} -> {final_url}")
            if "?" in final_url:
                log(f"   📌 发现参数: {final_url.split('?', 1)[1]}")

        # 记录基准响应信息
        baseline = {
            "status_code": resp.status_code,
            "content_length": len(raw_html),
            "response_time": resp.elapsed.total_seconds(),
            "final_url": final_url,
            "redirect_chain": redirect_chain,
            "server": resp.headers.get("Server", ""),
            "x_powered_by": resp.headers.get("X-Powered-By", "")
        }
        log(f"   状态码: {resp.status_code}, 长度: {len(raw_html)}")

        # 检测常见框架指纹 - 增强版
        server_header = resp.headers.get("Server", "").lower()
        x_powered_by = resp.headers.get("X-Powered-By", "").lower()
        html_lower = raw_html.lower()

        detected_frameworks = []

        # Tomcat检测
        if "tomcat" in server_header or "tomcat" in html_lower:
            version_match = re.search(r'tomcat[/\s]*(\d+\.\d+\.\d+)', server_header + raw_html, re.I)
            version = version_match.group(1) if version_match else "unknown"
            detected_frameworks.append({"name": "Tomcat", "version": version})
            log(f"   🔥 检测到 Apache Tomcat/{version}!")

        # Spring检测
        if "spring" in x_powered_by or "spring" in html_lower or "whitelabel error page" in html_lower:
            detected_frameworks.append({"name": "Spring"})
            log(f"   🔥 检测到 Spring 框架!")

        # ThinkPHP检测
        if "thinkphp" in html_lower or "thinkphp" in server_header or "thinkphp" in x_powered_by:
            detected_frameworks.append({"name": "ThinkPHP"})
            log(f"   🔥 检测到 ThinkPHP 框架!")

        # Laravel检测
        if "laravel" in html_lower or "laravel" in x_powered_by:
            detected_frameworks.append({"name": "Laravel"})
            log(f"   🔥 检测到 Laravel 框架!")

        # WebLogic检测
        if "weblogic" in server_header or "weblogic" in html_lower:
            detected_frameworks.append({"name": "WebLogic"})
            log(f"   🔥 检测到 WebLogic!")

        # Shiro检测 (rememberMe cookie)
        if "rememberme" in str(resp.cookies).lower() or "shiro" in html_lower:
            detected_frameworks.append({"name": "Shiro"})
            log(f"   🔥 检测到 Shiro 框架!")

        # 存储检测到的框架，供后续使用
        if detected_frameworks:
            baseline["detected_frameworks"] = detected_frameworks

    except Exception as e:
        log(f"   ❌ 请求失败: {e}")
        raw_html = "<html><body><!-- Connection Failed --></body></html>"
        baseline = {"status_code": 0, "content_length": 0, "response_time": 0}

    fingerprint = calculate_dom_fingerprint(raw_html)

    # =========================================================================
    # [P0 Critical] 结构化HTML提取 - 在截断之前进行
    # =========================================================================
    # 提取关键攻击面信息：隐藏字段、表单端点、JS端点、注释、meta标签
    # 这些信息可能因截断而丢失，必须先提取再存储
    html_extraction = extract_structured_html(raw_html)

    # 记录提取结果摘要
    extraction_summary = []
    if html_extraction["hidden_fields"]:
        extraction_summary.append(f"隐藏字段: {len(html_extraction['hidden_fields'])}个")
        for name, value in list(html_extraction["hidden_fields"].items())[:5]:
            log(f"      📋 hidden[{name}] = '{value[:50]}...'" if len(value) > 50 else f"      📋 hidden[{name}] = '{value}'")
    if html_extraction["form_endpoints"]:
        extraction_summary.append(f"表单: {len(html_extraction['form_endpoints'])}个")
        for form in html_extraction["form_endpoints"][:3]:
            log(f"      📝 form[{form.get('action', 'N/A')}] method={form.get('method', 'GET')} fields={len(form.get('fields', []))}")
    if html_extraction["script_endpoints"]:
        extraction_summary.append(f"JS端点: {len(html_extraction['script_endpoints'])}个")
    if html_extraction["comments"]:
        extraction_summary.append(f"注释: {len(html_extraction['comments'])}个")
        for comment in html_extraction["comments"][:3]:
            log(f"      💬 <!-- {comment[:100]}... -->" if len(comment) > 100 else f"      💬 <!-- {comment} -->")
    if html_extraction["api_endpoints"]:
        extraction_summary.append(f"API端点: {len(html_extraction['api_endpoints'])}个")

    if extraction_summary:
        log(f"   ✅ 结构化提取: {', '.join(extraction_summary)}")

    # 去重检查
    visited_fps = state.get("visited_fingerprints") or []
    if fingerprint in visited_fps:
        log(f"   ⏭️ 页面重复，跳过 LLM 分析")
        return {
            "visited_urls": [url],
            "scanned_ips": scanned_ips,
            "scanned_urls": scanned_urls
        }

    # =========================================================================
    # 2. 构建 LLM 提示，包含扫描结果
    # =========================================================================
    # 构建扫描结果摘要
    scan_summary = ""
    if fscan_findings:
        scan_summary += f"\n### fscan 扫描发现 ({len(fscan_findings)} 项)\n"
        for f in fscan_findings[:10]:
            scan_summary += f"- [{f.get('type', '?')}] {f.get('target', '?')}:{f.get('port', '?')} {f.get('info', '')[:100]}\n"

    if dirsearch_paths:
        scan_summary += f"\n### dirsearch 发现的路径 ({len(dirsearch_paths)} 条)\n"
        for p in dirsearch_paths[:15]:
            scan_summary += f"- {p}\n"

    # 构建响应头信息
    headers_info = ""
    if baseline.get("server"):
        headers_info += f"Server: {baseline['server']}\n"
    if baseline.get("x_powered_by"):
        headers_info += f"X-Powered-By: {baseline['x_powered_by']}\n"

    # 2. 调用 LLM 进行智能特征提取

    # 构建结构化提取摘要（用于LLM提示）
    extraction_info = ""
    if html_extraction["hidden_fields"]:
        extraction_info += f"\n### 预提取的隐藏字段 ({len(html_extraction['hidden_fields'])}个)\n"
        for name, value in html_extraction["hidden_fields"].items():
            extraction_info += f"- hidden[{name}] = \"{value[:100]}...\"\n" if len(value) > 100 else f"- hidden[{name}] = \"{value}\"\n"
    if html_extraction["form_endpoints"]:
        extraction_info += f"\n### 预提取的表单信息 ({len(html_extraction['form_endpoints'])}个)\n"
        for form in html_extraction["form_endpoints"]:
            fields_str = ", ".join([f"{f['name']}({f['type']})" for f in form.get("fields", [])])
            extraction_info += f"- form action=\"{form.get('action', '#')}\" method=\"{form.get('method', 'GET')}\" fields=[{fields_str}]\n"
    if html_extraction["script_endpoints"]:
        extraction_info += f"\n### 预提取的JS端点 ({len(html_extraction['script_endpoints'])}个)\n"
        for endpoint in html_extraction["script_endpoints"][:20]:
            extraction_info += f"- {endpoint}\n"
    if html_extraction["comments"]:
        extraction_info += f"\n### HTML注释 ({len(html_extraction['comments'])}个)\n"
        for comment in html_extraction["comments"][:10]:
            extraction_info += f"- <!-- {comment[:200]} -->\n" if len(comment) > 200 else f"- <!-- {comment} -->\n"
    if html_extraction["api_endpoints"]:
        extraction_info += f"\n### 预提取的API端点 ({len(html_extraction['api_endpoints'])}个)\n"
        for endpoint in html_extraction["api_endpoints"][:20]:
            extraction_info += f"- {endpoint}\n"
    if html_extraction["meta_tags"]:
        extraction_info += f"\n### Meta标签\n"
        for name, content in html_extraction["meta_tags"].items():
            extraction_info += f"- meta[{name}] = \"{content[:100]}\"\n" if len(content) > 100 else f"- meta[{name}] = \"{content}\"\n"

    recon_prompt = f"""
你是一个高级 Web 渗透测试侦察专家。你的任务是从 HTML 源码中提取攻击面。
特别注意：如果题目名称或描述中提到了特定的参数名，请务必将其包含在 input_vectors 中。

### 题目背景
- 名称: {task_name}
- 描述: {task_desc}

### 响应头信息
{headers_info if headers_info else "无特殊响应头"}
{scan_summary}
{extraction_info if extraction_info else ""}
### 待分析源码（已截断，请结合预提取信息）
```html
{raw_html[:config.HTML_MAX_LENGTH] if config.USE_LARGE_CONTEXT else raw_html[:config.HTML_TRUNCATE_LENGTH]}
```

### 输出要求 (JSON ONLY)
{{
  "tech_stack": ["识别到的技术框架"],
  "input_vectors": ["格式 type:name, 如 GET:id, POST:username，务必包含预提取的隐藏字段"],
  "sensitive_paths": ["发现的敏感路径，结合预提取的API端点"],
  "vuln_hints": ["可能的漏洞提示，结合扫描结果和预提取信息"],
  "framework": "识别到的主要框架，如 thinkphp, laravel, spring 等"
}}
"""

    try:
        response_text = llm_client.call_chat_completion(
            model=config.EXPLORER_MODEL,
            messages=[{"role": "user", "content": recon_prompt}],
            temperature=0.1,
            json_mode=True
        )

        if "```json" in response_text:
            response_text = response_text.split("```json")[1].split("```")[0]
        elif "```" in response_text:
            response_text = response_text.split("```")[1].split("```")[0]

        recon_data = json.loads(response_text)
    except Exception as e:
        log(f"❌ [Recon] LLM 提取失败: {e}")
        recon_data = {}

    # 合并 dirsearch 发现的敏感路径
    discovered_paths = recon_data.get("sensitive_paths", [])
    if dirsearch_paths:
        for p in dirsearch_paths:
            if p not in discovered_paths:
                discovered_paths.append(p)

    features: PageFeatures = {
        "tech_stack": recon_data.get("tech_stack", []),
        "input_vectors": recon_data.get("input_vectors", []),
        "sensitive_paths": discovered_paths[:20],  # 限制数量
        "dom_structure_hash": fingerprint,
        "form_structure": html_extraction["form_endpoints"],  # 使用结构化提取的表单数据
        "scripts": [],
        "cookies": {},
        "headers": {"server": baseline.get("server", ""), "x_powered_by": baseline.get("x_powered_by", "")},
        "html_extraction": html_extraction  # [P0] 存储完整的结构化提取数据
    }

    page_history = state.get("page_history", {})
    page_diff_manager.save_page(http_url, raw_html.encode('utf-8'), page_history)

    # 如果发现框架，记录到 analyst_intel 并自动触发CVE扫描
    framework = recon_data.get("framework", "")
    vuln_hints = recon_data.get("vuln_hints", [])
    analyst_intel_parts = []

    # 并行扫描发现的漏洞候选（用于传递给analyst）
    parallel_scan_vuln_candidates = []

    # 处理检测到的框架
    detected_frameworks = baseline.get("detected_frameworks", [])
    if detected_frameworks:
        for fw in detected_frameworks:
            fw_name = fw.get("name", "")
            fw_version = fw.get("version", "")
            analyst_intel_parts.append(f"[框架识别] {fw_name}" + (f"/{fw_version}" if fw_version else ""))

            # [已移除] 自动触发并行CVE扫描的硬编码逻辑
            # 改为通过知识库检索获取扫描策略
            # if fw_name in ["Tomcat", "Spring", "WebLogic", "Shiro", "ThinkPHP"]:
            #     ... 原硬编码扫描逻辑已删除 ...

    if framework and framework not in [fw.get("name") for fw in detected_frameworks]:
        analyst_intel_parts.append(f"[框架识别] {framework}")
    if fscan_findings:
        analyst_intel_parts.append(f"[fscan发现] {len(fscan_findings)} 个潜在漏洞点")
    if vuln_hints:
        analyst_intel_parts.append(f"[漏洞提示] {'; '.join(vuln_hints[:5])}")

    # 场景检测
    scene_detector = SceneDetector()
    detected_scenes = scene_detector.detect(features, baseline, raw_html)

    # 确定聚焦场景（优先级：检测到的框架 > LLM识别的框架 > None）
    focused_scene = None
    if detected_frameworks:
        # 取第一个检测到的框架作为聚焦场景
        fw = detected_frameworks[0]
        fw_name = fw.get("name", "")
        fw_version = fw.get("version", "")
        focused_scene = f"{fw_name}/{fw_version}" if fw_version else fw_name
    elif framework:
        focused_scene = framework

    # 如果识别到新场景，重置场景攻击计数
    prev_focused_scene = state.get("focused_scene", "")
    if focused_scene and focused_scene != prev_focused_scene:
        log(f"   🎯 新的聚焦场景: {focused_scene}")
        scene_attack_attempts = 0
        scene_exhausted = False
    else:
        scene_attack_attempts = state.get("scene_attack_attempts", 0)
        scene_exhausted = state.get("scene_exhausted", False)

    # 如果发生重定向，同时记录最终 URL
    visited_urls = [url]
    if baseline.get("final_url") and baseline["final_url"] != url:
        visited_urls.append(baseline["final_url"])
        page_diff_manager.save_page(baseline["final_url"], raw_html.encode('utf-8'), page_history)

    # 将 fscan 发现的漏洞转换为 vuln_candidates 格式
    fscan_vuln_candidates = []
    for f in fscan_findings:
        vuln_type = f.get("type", "unknown")
        target = f.get("target", "")
        port = f.get("port", "")
        info = f.get("info", "")

        # 根据漏洞类型确定置信度
        confidence = 0.7  # 默认置信度
        if vuln_type == "weak_password":
            confidence = 0.95  # 弱口令置信度很高
        elif vuln_type == "unauthorized":
            confidence = 0.9
        elif vuln_type == "vulnerability":
            confidence = 0.85
        elif vuln_type == "port":
            confidence = 0.5  # 仅端口开放，置信度较低

        # [核心修复] 确定 URL 绑定
        # Web 端口列表 - 使用配置
        web_ports = config.WEB_PORTS
        port_num = port if isinstance(port, int) else (int(port) if str(port).isdigit() else 0)

        if port_num in web_ports or vuln_type in config.WEB_VULN_TYPES:
            # Web 漏洞，绑定到 http_url
            vuln_url = http_url
        elif target:
            # 非 Web 漏洞，构造协议 URL
            if port_num == 22:
                vuln_url = f"ssh://{target}:{port}" if port else f"ssh://{target}"
            elif port_num in config.DATABASE_PORTS:
                vuln_url = f"db://{target}:{port}"
            elif port_num in config.MAIL_PORTS:
                vuln_url = f"tcp://{target}:{port}"
            else:
                vuln_url = f"http://{target}:{port}" if port else f"http://{target}"
        else:
            vuln_url = http_url

        fscan_vuln_candidates.append({
            "type": vuln_type,
            "location": f"{target}:{port}" if port else target,
            "description": info,
            "confidence": confidence,
            "source": "fscan",
            "evidence": info,
            "url": vuln_url
        })

    # [核心修复] 合并 fscan 发现和并行扫描发现的漏洞候选
    all_vuln_candidates = fscan_vuln_candidates + parallel_scan_vuln_candidates

    res = {
        "page_features": features,
        "raw_html_snippet": raw_html[:config.HTML_MAX_LENGTH] if config.USE_LARGE_CONTEXT else raw_html[:config.HTML_TRUNCATE_LENGTH],
        "baseline_response": baseline,
        "page_history": page_history,
        "visited_urls": visited_urls,
        "visited_fingerprints": [fingerprint],
        "scanned_ips": scanned_ips,
        "scanned_urls": scanned_urls,
        "execution_steps": state.get("execution_steps", 0) + 1,
        "analyst_intel": "\n".join(analyst_intel_parts) if analyst_intel_parts else None,
        "detected_scenes": detected_scenes,
        "focused_scene": focused_scene,
        "scene_attack_attempts": scene_attack_attempts,
        "scene_exhausted": scene_exhausted,
        "vuln_candidates": all_vuln_candidates,  # 合并所有漏洞候选
        # 拓扑初始化 - 添加入口URL（即使没有dirsearch路径也初始化入口节点）
        "site_topology": {http_url: dirsearch_paths[:20] if dirsearch_paths else []},
        "node_metadata": {
            http_url: {
                "status": baseline.get("status_code", 200),
                "title": recon_data.get("title", ""),
                "tech_stack": features.get("tech_stack", []),
                "last_seen": time.time()
            }
        }
    }

    # [关键修复] 如果发现了漏洞，直接添加攻击动作
    if all_vuln_candidates:
        log(f"   🎯 发现 {len(all_vuln_candidates)} 个漏洞候选，优先处理")
        # 高置信度漏洞已在 all_vuln_candidates 中，会被传递给 analyst_node

    log_node_data("recon", {"url": url}, res)
    return res


def _ai_analyze_exploit_chain(vuln_candidates: List[Dict], page_features: Dict) -> Optional[Dict]:
    """
    AI分析漏洞利用链

    识别多步漏洞利用场景，如:
    - SSRF → 文件读取 → RCE
    - SQL注入 → 文件写入 → Webshell
    - LFI → 日志注入 → RCE

    Args:
        vuln_candidates: 发现的漏洞候选列表
        page_features: 页面特征

    Returns:
        漏洞链分析结果，或None
    """
    if len(vuln_candidates) < 1:
        return None

    # 检查是否有多个不同类型的漏洞
    vuln_types = set(v.get("type", "").lower() for v in vuln_candidates)

    prompt = f"""分析这些漏洞是否可以组成利用链:

漏洞列表:
{json.dumps([{"type": v.get("type"), "location": v.get("location"), "confidence": v.get("confidence")} for v in vuln_candidates], ensure_ascii=False, indent=2)}

环境特征:
{json.dumps(page_features.get("tech_stack", []) + page_features.get("input_vectors", []), ensure_ascii=False)}

分析:
1. 这些漏洞能否组合利用？
2. 是否需要前置条件？
3. 最终能达到什么目标？

常见漏洞链示例:
- SSRF + 内网服务 = 内网渗透
- SQL注入 + 文件写入 = Webshell上传
- LFI + 日志注入 = RCE
- 反序列化 + gadget链 = RCE

输出JSON:
{{
    "type": "single/chain",
    "description": "漏洞链描述",
    "steps": [
        {{"step": 1, "vuln_type": "类型", "action": "利用动作", "expected": "预期结果"}}
    ],
    "final_goal": "最终目标(flag/shell等)"
}}"""

    try:
        response = llm_client.call_chat_completion(
            model=config.ANALYST_MODEL,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.2,
            json_mode=True
        )

        if response:
            if "```json" in response:
                response = response.split("```json")[1].split("```")[0]
            result = json.loads(response.strip())

            # 只返回链式利用
            if result.get("type") == "chain":
                return result

    except Exception as e:
        log(f"   [漏洞链分析] AI分析失败: {e}")

    return None


def analyst_node(state: CTFState) -> Dict:
    """
    分析兵 - 调用大模型进行深度漏洞分析

    内网模式增强:
    - 执行并行漏扫（nuclei + xray）
    - 输出 exploit_keywords 供攻击兵检索
    """
    log("🔍 [分析] 解析页面特征...")

    # 导入hybrid_detector用于置信度分级检测
    try:
        from hybrid_detector import hybrid_detector, quick_detect, full_detect
    except ImportError:
        hybrid_detector = None
        quick_detect = None
        full_detect = None

    # 检查是否为内网模式
    internal_mode = state.get("internal_mode", False)

    # 1. 准备输入数据
    page_features = state.get("page_features", {})
    raw_html = state.get("raw_html_snippet", "")
    task_name = state.get("task_name", "Unknown Task")
    task_description = state.get("task_description", "No description provided")
    baseline_response = state.get("baseline_response", {})  # 包含重定向信息

    # 规则引擎的初步结果（如果有）
    rule_candidates = state.get("vuln_candidates", [])

    # 获取场景信息
    detected_scenes = state.get("detected_scenes", {})

    # 获取场景聚焦信息
    focused_scene = state.get("focused_scene", "")
    scene_exhausted = state.get("scene_exhausted", False)

    # 获取拓扑信息
    critical_nodes = state.get("critical_nodes", [])
    topology_priority = state.get("topology_priority", [])
    current_url = state.get("current_url", "")

    # =====================================================
    # [内网模式增强] 简化漏扫（移除硬编码函数）
    # =====================================================
    scan_vulns = []
    exploit_keywords = {}

    if internal_mode and current_url:
        log("   🔬 [内网模式] 执行简化漏扫...")

        # 从配置获取扫描工具列表（移除硬编码）
        scan_tools = config.DEFAULT_SCAN_TOOLS
        executor = get_executor()
        scan_futures = []

        for tool_name in scan_tools:
            def run_scan(tool):
                try:
                    params = {"target": current_url}
                    if tool == "nuclei":
                        params["severity"] = "high,critical"
                    elif tool == "xray":
                        params["mode"] = "webscan"
                    result = ToolRegistry.execute_cached(tool, current_url, params)
                    if result and result.get("result", {}).get("vulnerable"):
                        return result["result"].get("vulnerabilities", [])
                except Exception as e:
                    log(f"   ⚠️ {tool}扫描异常: {e}")
                return []
            scan_futures.append((executor.submit(run_scan, tool_name), tool_name))

        # 收集结果
        for future, tool_name in scan_futures:
            try:
                vulns = future.result(timeout=120)
                for v in vulns:
                    v["source"] = tool_name
                    scan_vulns.append(v)
                    cve_id = v.get("cve") or v.get("cve_id") or v.get("template-id", "")
                    if cve_id:
                        log(f"   🎯 [{tool_name}] 发现: {cve_id}")
            except Exception as e:
                log(f"   ⚠️ {tool_name} 结果获取失败: {e}")

        if scan_vulns:
            log(f"   ✅ 漏扫发现 {len(scan_vulns)} 个漏洞")

        # 构建检索关键词
        try:
            from exploit_helper import build_exploit_keywords
            exploit_keywords = build_exploit_keywords(dict(state))
            # 补充扫描发现的CVE
            for v in scan_vulns:
                cve_id = v.get("cve") or v.get("cve_id", "")
                if cve_id and cve_id not in exploit_keywords.get("cve_ids", []):
                    exploit_keywords.setdefault("cve_ids", []).append(cve_id)
        except ImportError:
            exploit_keywords = {
                "cve_ids": [v.get("cve", "") for v in scan_vulns if v.get("cve")],
                "tags": []
            }

    # 构建拓扑提示
    topology_hint = None
    if critical_nodes or topology_priority:
        hint_parts = []
        if current_url in critical_nodes:
            hint_parts.append(f"当前URL是关键节点（PageRank Top {len(critical_nodes)}），请提升分析深度，优先挖掘漏洞。")
        elif critical_nodes:
            hint_parts.append(f"已知关键节点: {critical_nodes[:3]}")
        if topology_priority:
            top_targets = [url for url, score in topology_priority[:3]]
            hint_parts.append(f"拓扑优先目标: {top_targets}")
        topology_hint = "\n".join(hint_parts)

    # =====================================================
    # [置信度分级检测] hybrid_detector快速检测
    # =====================================================
    quick_results = []
    hybrid_candidates = []
    page_content = raw_html or page_features.get('text_content', '')

    if quick_detect and page_content:
        log("   🔬 [hybrid_detector] 执行快速正则检测...")
        detection = quick_detect(page_content)
        if detection.get('detected'):
            log(f"   ✅ [hybrid_detector] 检测到: {detection.get('detection_type')}, 置信度: {detection.get('confidence')}")
            quick_results.append({
                "type": detection.get("detection_type"),
                "confidence": detection.get("confidence"),
                "matched_text": detection.get("matched_text", "")[:200],
                "matches": detection.get("matches", []),
                "source": "hybrid_detector"
            })
            
            # 高置信度结果直接转换为漏洞候选
            if detection.get("confidence") == "high":
                for match in detection.get("matches", [])[:3]:  # 取前3个匹配
                    hybrid_candidates.append({
                        "type": match.get("type", "unknown"),
                        "location": current_url,
                        "confidence": 0.95,  # 高置信度
                        "context": {
                            "matched_text": match.get("matched_text", "")[:500],
                            "pattern_name": match.get("pattern_name", ""),
                            "source": "hybrid_detector"
                        },
                        "reason": f"hybrid_detector高置信度检测: {match.get('description', '检测到安全敏感信息')}",
                        "recommended_tools": [],
                        "url": current_url
                    })
                log(f"   🎯 [hybrid_detector] 高置信度候选: {len(hybrid_candidates)} 个")
    
    # 合并hybrid_detector候选到规则候选
    combined_candidates = rule_candidates + hybrid_candidates

    # 获取战略上下文和阶段信息
    strategic_context = state.get("strategic_context", {})

    # 构建阶段信息
    stage_info = None
    if strategic_context:
        current_step = strategic_context.get("current_step", 1)
        attack_chain = strategic_context.get("attack_chain", [])
        stage_info = {
            "stage_name": attack_chain[current_step - 1] if current_step <= len(attack_chain) else "未知",
            "goal": strategic_context.get("primary_goal", "获取FLAG"),
            "success_criteria": [],  # 可根据需要从staged_planner获取
            "timeout": 0  # 可根据需要从staged_planner获取
        }

    # 2. 构建 Prompt (将quick_results作为参考信息)
    prompt = get_analyst_prompt(
        page_features,
        raw_html,
        combined_candidates,  # 使用合并后的候选
        task_name=task_name,
        task_description=task_description,
        baseline_response=baseline_response,
        detected_scenes=detected_scenes,
        focused_scene=focused_scene,
        scene_tested=scene_exhausted,
        topology_hint=topology_hint,  # 拓扑提示
        hybrid_detection_results=quick_results,  # hybrid_detector检测结果
        stage_info=stage_info,
        strategic_context=strategic_context
    )
    
    # 3. 调用 LLM
    response_text = llm_client.call_chat_completion(
        model=config.ANALYST_MODEL,
        messages=[{"role": "user", "content": prompt}],
        temperature=0.1,
        json_mode=True
    )
    
    if not response_text:
        log("   ⚠️ LLM 无响应，使用规则引擎结果")
        log_node_data("analyst", {"prompt": prompt}, {"error": "LLM failed"})
        return {"vuln_candidates": rule_candidates} # 降级：使用规则引擎的结果

    # 4. 解析结果
    try:
        # 清理可能的 markdown 标记
        if "```json" in response_text:
            response_text = response_text.split("```json")[1].split("```")[0]
        elif "```" in response_text:
            response_text = response_text.split("```")[1].split("```")[0]
            
        result = json.loads(response_text)
        candidates = result.get("candidates", [])

        # [断点1修复] 提取结构化战术指导
        structured_guidance = result.get("structured_guidance", {})
        if structured_guidance:
            guidance_action = structured_guidance.get("action", "")
            guidance_type = structured_guidance.get("guidance_type", "continue")
            enforce_change = structured_guidance.get("enforce_change", False)
            guidance_target_url = structured_guidance.get("target_url", "")
            guidance_reason = structured_guidance.get("reason", "")
            guidance_params = structured_guidance.get("params", {})
            log(f"   📋 战术指导: {guidance_type}, 强制执行: {enforce_change}")
            if guidance_action:
                log(f"   🎯 建议动作: {guidance_action[:100]}")
            if guidance_target_url:
                log(f"   🔗 建议目标URL: {guidance_target_url}")

        # 提取分析兵的关键情报（源码、过滤规则等）
        key_intel_parts = []
        meta = result.get("meta_analysis", "")
        if meta:
            key_intel_parts.append(f"[总体分析] {meta}")
        key_intel_raw = result.get("key_intel", "")
        if key_intel_raw:
            key_intel_parts.append(f"[关键情报] {key_intel_raw}")

        # 统一格式化为 state.py 定义的 VulnerabilityCandidate
        current_url = state.get("current_url")
        formatted_candidates = []
        for cand in candidates:
            ctx = cand.get("context", {})
            # 将 key_code 也纳入 intel 汇总
            key_code = ctx.get("key_code", "")
            if key_code:
                key_intel_parts.append(f"[{cand.get('type','?')}@{cand.get('location','?')}] 关键代码:\n{key_code}")
            formatted_candidates.append({
                "type": cand.get("type", "unknown"),
                "location": cand.get("location", ""),
                "confidence": float(cand.get("confidence", 0.5)),
                "context": ctx,
                "reason": cand.get("reason", ""), # 保留分析理由
                "recommended_tools": cand.get("recommended_tools", ctx.get("recommended_tools", [])),
                "url": current_url # [核心修复] 绑定当前 URL
            })
            
        # [拓扑驱动] 按拓扑优先级排序漏洞候选
        priority_dict = {url: score for url, score in topology_priority}
        if formatted_candidates and priority_dict:
            formatted_candidates.sort(key=lambda c: (
                priority_dict.get(c.get("url", current_url), 0.5) * 0.5 + c.get("confidence", 0.5) * 0.5
            ), reverse=True)
            top_url = formatted_candidates[0].get("url", "")
            top_score = priority_dict.get(top_url, 0.5)
            log(f"   📊 拓扑驱动排序: 优先漏洞 @ {top_url} (优先级={top_score:.2f})")

        log(f"   ✅ 发现 {len(formatted_candidates)} 个潜在漏洞点")

        # [内网模式] 合并漏扫结果
        if scan_vulns:
            for v in scan_vulns:
                vtype = v.get("plugin") or v.get("name") or v.get("template-id", "unknown")
                formatted_candidates.append({
                    "type": vtype.lower(),
                    "location": v.get("url", current_url),
                    "confidence": 0.8,  # 工具验证的置信度
                    "context": {
                        "cve_id": v.get("cve") or v.get("cve_id"),
                        "severity": v.get("severity"),
                        "source": v.get("source"),
                        "curl_command": v.get("curl_command", "")
                    },
                    "recommended_tools": [],
                    "url": v.get("url", current_url),
                    "verified": True
                })
            log(f"   ✅ 合并漏扫结果后共 {len(formatted_candidates)} 个漏洞候选")

        # [AI漏洞链分析] 识别多步漏洞利用链
        if formatted_candidates:
            chain_analysis = _ai_analyze_exploit_chain(formatted_candidates, page_features)
            if chain_analysis and chain_analysis.get("type") == "chain":
                log(f"   🔗 检测到漏洞链: {chain_analysis.get('description', '')}")
                # 将链式利用信息添加到第一个高置信度漏洞
                for cand in formatted_candidates:
                    if cand.get("confidence", 0) > 0.6:
                        cand["exploit_chain"] = chain_analysis
                        break

        # 如果 formatted_candidates 为空，直接触发探索模式
        if not formatted_candidates:
            log("   ⚠️ 未识别到漏洞候选，触发探索模式")
            return {
                "vuln_candidates": [],
                "analyst_intel": "\n\n".join(key_intel_parts) if key_intel_parts else None,
                "failure_weighted_score": state.get("failure_weighted_score", 0) + 1.5,
                "exploit_keywords": exploit_keywords if exploit_keywords else {}
            }

        analyst_intel = "\n\n".join(key_intel_parts) if key_intel_parts else None
        res = {
            "vuln_candidates": formatted_candidates,
            "analyst_intel": analyst_intel,
            "exploit_keywords": exploit_keywords if exploit_keywords else {}
        }
        # [断点1修复] 将结构化战术指导传递给状态
        if structured_guidance:
            res["structured_guidance"] = structured_guidance
            res["latest_tactical_guidance"] = structured_guidance.get("action", "")
            res["guidance_type"] = structured_guidance.get("guidance_type", "continue")
            res["enforce_change"] = structured_guidance.get("enforce_change", False)
            if structured_guidance.get("target_url"):
                res["guidance_target_url"] = structured_guidance.get("target_url")
        log_node_data("analyst", {"prompt": prompt}, res)
        return res

    except json.JSONDecodeError:
        log(f"   ❌ JSON 解析失败，执行降级分析")
        log_node_data("analyst", {"prompt": prompt, "raw_response": response_text}, {"error": "JSON parse error"})

        # [断点3修复] JSON解析失败时生成默认漏洞候选，防止浪费一轮
        # 基于当前URL和页面特征生成基础探测候选
        default_candidates = []
        current_url = state.get("current_url", "")

        if current_url:
            # 生成基础URL探测候选
            default_candidates.append({
                "type": "info_disclosure",
                "location": current_url,
                "confidence": 0.3,
                "reason": "降级分析：JSON解析失败，执行基础信息收集",
                "recommended_tools": ["requests"],
                "context": {"fallback": True},
                "url": current_url
            })

            # 检查是否有参数，生成参数探测候选
            if "?" in current_url:
                params_part = current_url.split("?", 1)[1]
                param_names = [p.split("=")[0] for p in params_part.split("&") if "=" in p]
                for param in param_names[:3]:
                    default_candidates.append({
                        "type": "param_probe",
                        "location": f"{current_url} (参数: {param})",
                        "confidence": 0.25,
                        "reason": f"降级分析：探测参数 {param} 的潜在漏洞",
                        "recommended_tools": ["requests"],
                        "context": {"param": param, "fallback": True},
                        "url": current_url
                    })

        # 合并漏扫结果
        if scan_vulns:
            for v in scan_vulns:
                vtype = v.get("plugin") or v.get("name") or v.get("template-id", "unknown")
                default_candidates.append({
                    "type": vtype.lower(),
                    "location": v.get("url", current_url),
                    "confidence": 0.8,
                    "context": {
                        "cve_id": v.get("cve") or v.get("cve_id"),
                        "severity": v.get("severity"),
                        "source": v.get("source"),
                        "fallback": True
                    },
                    "recommended_tools": [],
                    "url": v.get("url", current_url),
                    "verified": True
                })

        log(f"   📋 降级生成 {len(default_candidates)} 个默认漏洞候选")
        return {
            "vuln_candidates": default_candidates,  # [断点3修复] 返回默认候选而非空
            "analyst_intel": "降级分析：JSON解析失败，已生成基础探测候选",
            "failure_weighted_score": state.get("failure_weighted_score", 0) + 0.5,  # 减少惩罚，因为有降级动作
            "exploit_keywords": exploit_keywords if exploit_keywords else {}
        }


def _ai_decide_mode_switch(state: Dict) -> Optional[Dict]:
    """
    AI决策模式切换

    综合考虑：失败分、探索进度、场景匹配度、剩余时间

    Returns:
        None: AI决策不可用或失败，使用硬编码规则
        Dict: AI决策结果，包含 current_mode 和决策理由
    """
    # 检查是否启用AI决策
    if not config.USE_AI_MODE_DECISION:
        return None

    # 检查决策间隔，避免频繁调用LLM
    last_ai_decision_time = state.get("last_ai_decision_time", 0)
    current_time = time.time()
    if current_time - last_ai_decision_time < config.AI_MODE_DECISION_INTERVAL:
        return None

    # 收集决策上下文
    score = state.get("failure_weighted_score", 0)
    steps = state.get("execution_steps", 0)
    current_mode = state.get("current_mode", "exploit")
    start_time = state.get("start_time", time.time())
    internal_mode = state.get("internal_mode", False)
    visited_urls = state.get("visited_urls", [])
    vuln_candidates = state.get("vuln_candidates", [])
    focused_scene = state.get("focused_scene", "")
    scene_attack_attempts = state.get("scene_attack_attempts", 0)
    explore_rounds = state.get("explore_rounds", 0)
    current_round = state.get("current_round", 0)
    flags_found = state.get("flags_found", [])

    # 计算剩余时间
    timeout = config.INTERNAL_TASK_TIMEOUT if internal_mode else config.TASK_TIMEOUT
    elapsed_time = current_time - start_time
    remaining_time = timeout - elapsed_time
    remaining_minutes = remaining_time / 60

    # 计算探索进度
    total_urls = len(visited_urls)
    high_value_urls = sum(1 for url in visited_urls if any(kw in url.lower() for kw in ["admin", "login", "api", "upload", "config", "backup", "debug"]))
    vuln_count = len(vuln_candidates)

    # 构建AI决策提示
    prompt = f"""你是一个CTF攻击模式决策专家。请根据当前状态决定下一步应该切换到什么模式。

## 当前状态
- 当前模式: {current_mode}
- 失败分数: {score:.1f} (越高表示攻击越不顺利)
- 执行步数: {steps}
- 当前轮次: {current_round}
- 剩余时间: {remaining_minutes:.1f} 分钟
- 环境类型: {'内网渗透' if internal_mode else 'Web CTF'}

## 探索进度
- 已访问URL数: {total_urls}
- 高价值URL数: {high_value_urls}
- 漏洞候选数: {vuln_count}
- 探索轮数: {explore_rounds}

## 场景聚焦
- 聚焦场景: {focused_scene or '无'}
- 场景攻击次数: {scene_attack_attempts}/{config.MAX_SCENE_ATTEMPTS}

## 已发现Flag
- Flag数量: {len(flags_found)}

## 可选模式
1. **exploit**: 继续攻击当前目标或漏洞候选
   - 适合：有明确的攻击目标、漏洞候选、或场景聚焦

2. **explore**: 探索新目标
   - 适合：当前目标无进展、需要发现新攻击面

3. **innovate**: 创新思维模式
   - 适合：常规方法失效、需要尝试非常规思路

4. **end**: 结束任务
   - 适合：时间耗尽、已获得Flag、或确实无解

## 决策原则
1. 内网渗透模式只按时间结束，不受失败分影响
2. 有聚焦场景时优先深度挖掘，直到场景穷尽
3. 失败分高时考虑切换模式，但不要过于激进
4. 时间不足时，优先快速验证高价值目标
5. 已发现Flag时，考虑是否需要继续寻找其他Flag

## 输出格式 (JSON)
{{
  "mode": "exploit/explore/innovate/end",
  "confidence": 0.0-1.0,
  "reasoning": "简要说明决策理由",
  "factors": {{
    "failure_score_weight": 0.0-1.0,
    "time_pressure": 0.0-1.0,
    "exploration_progress": 0.0-1.0,
    "vuln_potential": 0.0-1.0
  }}
}}
"""

    try:
        log_mode_manager("🤖 调用AI决策模式切换...")
        response = llm_client.call_chat_completion(
            model=config.ANALYST_MODEL,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.2,
            json_mode=True
        )

        if not response:
            log_mode_manager("   ⚠️ AI决策无响应")
            return None

        # 解析响应
        if "```json" in response:
            response = response.split("```json")[1].split("```")[0]

        result = json.loads(response.strip())
        mode = result.get("mode", "exploit")
        confidence = result.get("confidence", 0.5)
        reasoning = result.get("reasoning", "")

        # 验证模式有效性
        valid_modes = ["exploit", "explore", "innovate", "end"]
        if mode not in valid_modes:
            log_mode_manager(f"   ⚠️ AI返回无效模式: {mode}")
            return None

        # 置信度过低时使用硬编码规则
        if confidence < 0.4:
            log_mode_manager(f"   ⚠️ AI置信度过低: {confidence:.2f}，使用硬编码规则")
            return None

        log_mode_manager(f"   ✅ AI决策: {mode} (置信度: {confidence:.2f})")
        log_mode_manager(f"   📝 理由: {reasoning}")

        return {
            "current_mode": mode,
            "ai_decision_reasoning": reasoning,
            "ai_decision_confidence": confidence,
            "last_ai_decision_time": current_time,
            "ai_decision_factors": result.get("factors", {})
        }

    except json.JSONDecodeError as e:
        log_mode_manager(f"   ❌ AI决策JSON解析失败: {e}")
        return None
    except Exception as e:
        log_mode_manager(f"   ❌ AI决策异常: {e}")
        return None


def mode_manager_node(state: CTFState) -> Dict:
    """
    模式决策器 - 增强版（AI决策 + 硬编码规则降级）

    决策优先级：
    1. 预设模式（上游已决定）
    2. AI决策（如果启用）
    3. 硬编码规则（降级方案）

    结束条件：只有时间超时
    - 外网打点：30分钟 (TASK_TIMEOUT)
    - 内网渗透：50分钟 (INTERNAL_TASK_TIMEOUT)
    """
    score = state.get("failure_weighted_score", 0)
    steps = state.get("execution_steps", 0)
    current_url = state.get("current_url")
    node_status = state.get("node_attack_status", {})
    start_time = state.get("start_time", time.time())
    internal_mode = state.get("internal_mode", False)

    # 获取场景聚焦信息
    focused_scene = state.get("focused_scene", "")
    scene_attack_attempts = state.get("scene_attack_attempts", 0)
    scene_exhausted = state.get("scene_exhausted", False)

    # 0. 尊重上游设置的模式
    preset_mode = state.get("current_mode")
    if preset_mode == "end":
        log_mode_manager("保持预设模式: end")
        return {"current_mode": "end"}
    elif preset_mode == "explore":
        log_mode_manager("保持预设模式: explore")
        return {"current_mode": "explore"}
    elif preset_mode == "innovate":
        log_mode_manager("创新模式已执行，重置分数并切回攻击模式")
        return {
            "current_mode": "exploit",
            "failure_weighted_score": 0,
            "current_round": state.get("current_round", 0) + 1
        }

    # 1. [优先] AI决策模式切换
    if config.USE_AI_MODE_DECISION:
        ai_decision = _ai_decide_mode_switch(state)
        if ai_decision:
            # AI决策成功，检查是否需要进一步验证
            ai_mode = ai_decision.get("current_mode")
            ai_confidence = ai_decision.get("ai_decision_confidence", 0)

            # AI决策高置信度时直接采用
            if ai_confidence >= 0.7:
                log_mode_manager(f"AI高置信度决策: {ai_mode} (置信度: {ai_confidence:.2f})")
                return ai_decision

            # 中等置信度时，结合硬编码规则验证
            # 特别关注：时间超时检查不可跳过
            elapsed_time = time.time() - start_time
            timeout = config.INTERNAL_TASK_TIMEOUT if internal_mode else config.TASK_TIMEOUT

            if elapsed_time >= timeout:
                log_mode_manager(f"时间超时优先于AI决策: {elapsed_time/60:.1f}分钟 >= {timeout/60:.0f}分钟")
                return {"current_mode": "end"}

            # 中等置信度时采用AI建议，但记录降级情况
            log_mode_manager(f"AI中等置信度决策: {ai_mode} (置信度: {ai_confidence:.2f})")
            return ai_decision

    # 2. [降级] 硬编码规则决策
    log_mode_manager("使用硬编码规则决策")

    # 时间超时检查
    elapsed_time = time.time() - start_time
    timeout = config.INTERNAL_TASK_TIMEOUT if internal_mode else config.TASK_TIMEOUT

    if elapsed_time >= timeout:
        log_mode_manager(f"任务超时: {elapsed_time/60:.1f}分钟 >= {timeout/60:.0f}分钟")
        return {"current_mode": "end"}

    # 剩余时间提醒
    remaining = timeout - elapsed_time
    if remaining < 300:  # 剩余不足5分钟
        log_mode_manager(f"剩余时间: {remaining/60:.1f}分钟")

    # 场景聚焦判断
    MAX_SCENE_ATTEMPTS = config.MAX_SCENE_ATTEMPTS

    if focused_scene and not scene_exhausted:
        if scene_attack_attempts < MAX_SCENE_ATTEMPTS:
            log_mode_manager(f"聚焦场景 [{focused_scene}] 继续攻击 ({scene_attack_attempts}/{MAX_SCENE_ATTEMPTS})")
            return {"current_mode": "exploit"}
        else:
            log_mode_manager(f"场景 [{focused_scene}] 已穷尽 {scene_attack_attempts} 次攻击，切换探索模式")
            return {
                "current_mode": "explore",
                "scene_exhausted": True
            }

    # 创新模式检查 (仅Web CTF)
    if not internal_mode and (steps >= config.MAX_STEPS_BEFORE_INNOVATE or score >= config.FAILURE_SCORE_FOR_INNOVATE):
        log_mode_manager(f"自动进入创新模式 (步数:{steps}, 失败分:{score:.1f})")
        return {"current_mode": "innovate"}
    elif internal_mode:
        log_mode_manager(f"内网模式，继续渗透 (已运行:{elapsed_time/60:.1f}分钟, 失败分:{score:.1f})")

    # 节点状态管理 - 智能放弃判断
    # 不再仅凭 attempt_count 判断，而是看最近的攻击是否有进展
    # 如果最近有成功的攻击（状态码200且有输出变化），则不放弃
    if current_url and current_url in node_status:
        status = node_status[current_url]
        attempts = status.get("attempt_count", 0)
        recent_codes = status.get("last_status_codes", [])[-5:]

        # 检查最近是否有有效的攻击（非404/500的状态码占比超过50%）
        if attempts > 10 and recent_codes:
            success_rate = sum(1 for c in recent_codes if c not in [404, 500, 0]) / len(recent_codes)
            if success_rate < 0.3:  # 最近5次攻击中，成功率低于30%才放弃
                status["status"] = "abandoned"
                log_mode_manager(f"放弃节点（成功率低）: {current_url}")
            else:
                log_mode_manager(f"节点仍有进展（成功率 {success_rate*100:.0f}%），继续攻击")

    # 模式切换 - 简化阈值
    # [重要] 头脑风暴和探索模式只在Web CTF模式下触发
    # 内网渗透只按时间超时结束，不受失败分影响
    if score >= config.FAILURE_SCORE_FOR_INNOVATE and not internal_mode:
        log_mode_manager(f"创新模式 (失败分:{score:.1f})")
        return {"current_mode": "innovate"}
    elif score >= config.FAILURE_SCORE_FOR_EXPLORE and not internal_mode:
        log_mode_manager(f"探索模式 (失败分:{score:.1f})")
        return {"current_mode": "explore"}
    else:
        return {
            "current_mode": "exploit",
            "current_round": state.get("current_round", 0) + 1,
            "node_attack_status": node_status
        }


def execute_single_attack(action: Dict, current_url: str, page_history: Dict, timeout: int = None) -> Dict:
    """同步执行单个攻击动作并进行页面对比

    Args:
        action: 攻击动作配置
        current_url: 当前目标URL
        page_history: 页面历史记录
        timeout: 工具超时时间（秒），None时使用默认30秒
    """
    # [核心修复] 初始化默认返回值，确保即便发生异常，核心字段也不为空
    tool_name = "unknown"
    target = current_url
    payload = "N/A"
    request_timeout = timeout or 30  # 统一超时处理
    
    try:
        if not isinstance(action, dict):
            # 兼容性修复：如果 action 是字符串（LLM 可能直接输出 JSON 字符串），尝试解析
            try:
                action = json.loads(action)
            except (json.JSONDecodeError, TypeError) as e:
                raise ValueError(f"Invalid action format: {type(action)}: {e}")
            
        tool_name = action.get("tool", "unknown")
        params = action.get("params", {})

        # [核心修复] 使用最佳实践规范化 URL，彻底解决反引号、转义符和废话干扰
        if isinstance(params, dict) and "url" in params:
            target = normalize_target_url(params["url"])
            # [协议修正] 确保与原始URL协议一致
            target = ensure_protocol_consistency(target, current_url)
            params["url"] = target
        else:
            # 如果工具未提供 URL，使用当前上下文 URL
            target = current_url
            if isinstance(params, dict):
                params["url"] = target

        payload = json.dumps(params) if isinstance(params, dict) else str(params)
        
        if tool_name == "requests":
            start_time = time.time()
            method = params.get("method", "GET").upper()
            
            # [Requests 参数清洗] 确保 params, data, headers 格式正确
            req_params = params.get("params")
            if isinstance(req_params, str):
                try: req_params = json.loads(req_params)
                except (json.JSONDecodeError, ValueError): pass  # 解析失败，保留原样

            req_data = params.get("data")
            if isinstance(req_data, str):
                try: req_data = json.loads(req_data)
                except (json.JSONDecodeError, ValueError): pass  # POST data 可以是字符串

            req_headers = params.get("headers")
            if isinstance(req_headers, str):
                try: req_headers = json.loads(req_headers)
                except (json.JSONDecodeError, ValueError): req_headers = {}

            # 支持文件上传 (multipart/form-data)
            req_files = params.get("files")
            opened_files = []  # 追踪打开的文件句柄，确保关闭

            # 如果 files 是字典格式 {"field_name": file_spec}，转化为 requests 格式
            if isinstance(req_files, dict):
                formatted_files = {}
                for field, content in req_files.items():
                    if isinstance(content, str):
                        # 如果内容看起来像路径，尝试读取（CTF 常见场景）
                        if os.path.exists(content) and os.path.isfile(content):
                            f = open(content, 'rb')
                            opened_files.append(f)  # 追踪文件句柄
                            formatted_files[field] = (os.path.basename(content), f)
                        else:
                            # 否则视为纯文本内容上传
                            formatted_files[field] = (f"test_{field}.txt", content)
                    elif isinstance(content, (list, tuple)):
                        # [核心修复] 处理列表/元组格式: [filename, content, mime] 或 (filename, content, mime)
                        # JSON 序列化会将元组转为列表，所以需要兼容两种格式
                        if len(content) >= 2:
                            filename = content[0]
                            file_content = content[1]
                            mime_type = content[2] if len(content) >= 3 else "application/octet-stream"
                            formatted_files[field] = (filename, file_content, mime_type)
                        else:
                            formatted_files[field] = content  # 透传给 requests
                    else:
                        formatted_files[field] = content  # 其他格式直接透传
                req_files = formatted_files

            # [同步修复] 直接发起同步请求
            try:
                resp = requests.request(
                    method=method,
                    url=target,
                    params=req_params,
                    data=req_data,
                    headers=req_headers,
                    files=req_files, # 增加文件支持
                    timeout=request_timeout,  # 使用统一超时
                    verify=False
                )
            finally:
                # 确保关闭所有打开的文件句柄
                for f in opened_files:
                    try:
                        f.close()
                    except Exception as e:
                        log(f"[Warning] Failed to close file handle: {e}")
            duration = time.time() - start_time
            content = resp.content
            
            # [Optimization] Save large responses to file to avoid memory issues and consistent with other tools
            file_path = None
            if len(content) > 2000:
                os.makedirs("data/tool_outputs", exist_ok=True)
                file_path = f"data/tool_outputs/req_{int(time.time())}_{hash(str(params))%1000}.html"
                with open(file_path, "wb") as f:
                    f.write(content)

            # [优化] 构建简短的 output 供即时查看，完整内容在 file_path
            short_output = content[:1500].decode('utf-8', errors='replace')
            if len(content) > 1500:
                short_output += f"\n... (Total {len(content)} bytes, see file)"

            diff_analysis = page_diff_manager.compare_and_analyze(target, content, page_history)

            # [核心修复] 将 diff_analysis 中的 extracted_flag 提升到顶层 result
            result = {
                "action_id": f"req_{int(time.time())}_{hash(str(params))%1000}",
                "tool": "requests",
                "target": target,
                "payload": payload,
                "status": resp.status_code,
                "output": short_output,
                "file_path": file_path,
                "duration": duration,
                "diff_analysis": diff_analysis,
                "is_exploit": diff_analysis.get("changed", False)
            }
            # [核心修复] extracted_flag 需要提升到顶层，确保 verifier 能直接读取
            if diff_analysis.get("extracted_flag"):
                result["extracted_flag"] = diff_analysis["extracted_flag"]
            return result
            
        else:
            # [同步修复] 直接调用工具执行引擎
            exec_result = ToolRegistry.execute_cached(tool_name, target, params)
            
            if "error" in exec_result:
                return {
                    "action_id": f"{tool_name}_err_{int(time.time())}",
                    "tool": tool_name, 
                    "payload": payload,
                    "error": exec_result["error"], 
                    "status": 500,
                    "diff_analysis": {"changed": False}
                }
            
            tool_res = exec_result.get("result", {})

            # [核心修复] 适配新的结构化结果
            if "summary" in tool_res:
                display_output = f"Summary: {tool_res['summary']}\nFindings: {json.dumps(tool_res.get('findings', []), ensure_ascii=False)}"
            else:
                display_output = json.dumps(tool_res, ensure_ascii=False)

            # [核心修复] 兼容多种工具返回格式的漏洞判断
            vulnerable = tool_res.get("vulnerable", False)
            if not vulnerable:
                # fscan/nuclei 返回 vulnerabilities 列表
                if tool_res.get("vulnerabilities"):
                    vulnerable = len(tool_res["vulnerabilities"]) > 0
                # oa-exploiter 返回 vuln_confirmed
                elif tool_res.get("vuln_confirmed"):
                    vulnerable = True
                # 检查 findings 中是否有成功项 (oa-exploiter等)
                elif tool_res.get("findings"):
                    vulnerable = any(f.get("success") for f in tool_res["findings"] if isinstance(f, dict))
                # 检查 hosts 中是否有发现 (fscan)
                elif tool_res.get("hosts"):
                    vulnerable = len(tool_res["hosts"]) > 0
                # nuclei 返回 total_found
                elif tool_res.get("total_found", 0) > 0:
                    vulnerable = True

            # 提取flag（如果有）
            extracted_flag = tool_res.get("extracted_flag")
            if not extracted_flag and tool_res.get("findings"):
                for f in tool_res.get("findings", []):
                    if isinstance(f, dict) and f.get("flag"):
                        extracted_flag = f["flag"]
                        break

            result = {
                "action_id": f"{tool_name}_{int(time.time())}_{hash(str(params))%1000}",
                "tool": tool_name,
                "target": target,
                "payload": payload,
                "status": 200 if (tool_res.get("success") or vulnerable) else 500,
                "output": display_output, # 简短的结构化输出
                "file_path": tool_res.get("full_log_path"),
                "duration": exec_result.get("duration", 0),
                "is_exploit": vulnerable,
                "diff_analysis": {"changed": vulnerable, "reason": tool_res.get("summary", "Tool findings")},
                # 保留AI解析的结构化数据
                "vulnerabilities": tool_res.get("vulnerabilities", []),
                "hosts": tool_res.get("hosts", []),
                "credentials": tool_res.get("credentials", []),
                "attack_paths": tool_res.get("attack_paths", []),
                "domain_info": tool_res.get("domain_info", {}),
                "summary": tool_res.get("summary", "")
            }
            if extracted_flag:
                result["extracted_flag"] = extracted_flag
            return result
    except Exception as e:
        # [核心修复] 将详细报错信息放入 output，让核验兵能识别出具体错误
        error_msg = f"Execution Exception: {str(e)}\n{traceback.format_exc()}"
        log(f"❌ [Executor] 攻击动作执行失败: {tool_name}\n{error_msg}")
        
        return {
            "action_id": f"err_{tool_name}_{int(time.time())}_{hash(str(action))%1000}",
            "tool": tool_name,
            "target": target,
            "payload": payload,
            "status": 500,
            "error": str(e),
            "output": error_msg,
            "diff_analysis": {"changed": False}
        }

def attacker_node(state: CTFState) -> Dict:
    """
    [攻击兵] (同步并发执行优化版)

    攻击策略:
    1. 首先使用nuclei/xray等工具批量验证漏洞
    2. 然后使用手工payload进行攻击
    3. 综合两种方式的结果
    """
    # [智能流转] 导入AI流转控制器
    try:
        from ai_flow_controller import ai_flow_controller, FlowDecision
    except ImportError:
        ai_flow_controller = None
        FlowDecision = None

    current_url = state.get("current_url")
    target_url = state.get("target_url", current_url)  # 原始目标URL
    log(f"⚔️ [攻击] 目标: {current_url}")

    # 获取拓扑优先级
    topology_priority = state.get("topology_priority", [])
    priority_dict = {url: score for url, score in topology_priority}
    current_priority = priority_dict.get(current_url, 0.5)

    # [核心修复] 获取所有漏洞候选，不再仅限当前URL
    # 因为fscan扫描出的漏洞URL可能与current_url不同
    all_candidates = state.get("vuln_candidates", [])

    # 改进过滤逻辑：不遗漏无URL的候选（如非Web漏洞）
    candidates_for_current = [c for c in all_candidates if c.get("url") == current_url]
    # 无URL或非当前URL的候选（保留无URL候选，不遗漏）
    other_candidates = [c for c in all_candidates if c.get("url") != current_url]

    # 如果当前URL没有候选，但有其他候选，使用其他候选
    if not candidates_for_current and other_candidates:
        log(f"   📌 当前URL无候选，使用其他漏洞候选 ({len(other_candidates)}个)")
        candidates = other_candidates[:10]
    elif candidates_for_current:
        # 优先使用当前URL的候选，补充其他URL的高置信度候选
        high_conf_other = [c for c in other_candidates if c.get("confidence", 0) >= 0.7][:3]
        candidates = candidates_for_current + high_conf_other
    else:
        # 都没有，使用所有候选
        candidates = all_candidates

    # 按拓扑优先级 + 置信度排序
    if candidates and priority_dict:
        candidates.sort(key=lambda c: (
            c.get("confidence", 0) * 0.6 + priority_dict.get(c.get("url", ""), 0.5) * 0.4
        ), reverse=True)
        log(f"   📊 已按拓扑优先级排序候选漏洞")

    # [节点状态管理]
    node_status = state.get("node_attack_status", {})
    if current_url and current_url not in node_status:
        node_status[current_url] = {
            "status": "active",
            "start_time": time.time(),
            "last_decision_time": time.time(),
            "attempt_count": 0,
            "last_status_codes": [],
            "ai_decision_log": []
        }
    if current_url:
        node_status[current_url]["attempt_count"] += 1

    if not candidates:
        log(f"   ⚠️ 无匹配漏洞候选项，直接触发探索模式")
        # 直接设置模式为 explore，跳过 verifier
        return {
            "failure_weighted_score": state.get("failure_weighted_score", 0) + 2.0,  # 直接加2.0触发explore
            "current_mode": "explore",  # 直接设置模式
            "execution_steps": state.get("execution_steps", 0) + 1
        }

    # =====================================================
    # [内网模式增强] nuclei模板检索 + 智慧决策
    # =====================================================
    internal_mode = state.get("internal_mode", False)

    if internal_mode:
        log("   🔬 [内网模式] 检索nuclei模板...")

        try:
            from exploit_helper import (
                search_nuclei_templates,
                smart_attack_decision
            )

            # 获取检索关键词
            exploit_keywords = state.get("exploit_keywords", {})
            if not exploit_keywords:
                exploit_keywords = {
                    "cve_ids": [],
                    "framework": "",
                    "tags": [],
                    "vuln_types": list(set(c.get("type", "") for c in candidates if c.get("type")))
                }

            # 检索模板（用于日志展示）
            templates = search_nuclei_templates(exploit_keywords)
            if templates:
                log(f"   ✅ 找到 {len(templates)} 个相关模板")
                for t in templates[:3]:
                    log(f"      - {t.get('name', t.get('path'))} [{t.get('severity', 'unknown')}]")
        except ImportError as e:
            log(f"   ⚠️ exploit_helper未安装: {e}")
        except Exception as e:
            log(f"   ⚠️ 模板检索失败: {e}")

        # 智慧决策攻击方式
        if candidates:
            try:
                from exploit_helper import smart_attack_decision

                decision_context = {
                    "vuln_type": candidates[0].get("type", "unknown"),
                    "os_type": "unknown",
                    "has_shell": bool(state.get("shell_session")),
                    "target_url": current_url,
                    "attacker_ip": config.LOCAL_PUBLIC_IP or "127.0.0.1"
                }

                attack_decision = smart_attack_decision(decision_context)
                log(f"   🎯 智慧决策: {attack_decision.get('primary_method', 'unknown')}")
                log(f"      理由: {attack_decision.get('reason', '')}")

                # 将决策添加到第一个候选的context
                if candidates and attack_decision:
                    candidates[0].setdefault("context", {})["attack_decision"] = attack_decision
            except Exception as e:
                log(f"   ⚠️ 智慧决策失败: {e}")

    # [RAG优化] 已移除其他节点的RAG调用，RAG仅在innovator_node中调用
    # 如果有temp_rules（来自innovator_node的RAG检索），可以在攻击时参考
    temp_rules = state.get("temp_rules", [])
    if temp_rules:
        log(f"   💡 使用innovator生成的 {len(temp_rules)} 条临时规则")

    # =====================================================
    # [断点1修复] 处理结构化战术指导
    # =====================================================
    guidance_type = state.get("guidance_type", "continue")
    enforce_change = state.get("enforce_change", False)
    tactical_guidance = state.get("latest_tactical_guidance", "")

    # 如果有强制切换场景的指导，优先执行
    if guidance_type == "switch_scene" and enforce_change and tactical_guidance:
        # 从指导中提取目标URL（如果指导是结构化的dict）
        guidance_target = None
        if isinstance(tactical_guidance, dict):
            guidance_target = tactical_guidance.get("target_url", "")
        elif isinstance(tactical_guidance, str) and "http" in tactical_guidance:
            # 尝试从文本中提取URL
            import re
            url_match = re.search(r'https?://[^\s<>"]+', tactical_guidance)
            if url_match:
                guidance_target = url_match.group()

        if guidance_target:
            log(f"   🔄 [强制指导] 切换到新目标: {guidance_target}")
            # 直接生成访问新URL的攻击动作
            forced_attack = {
                "tool": "requests",
                "params": {
                    "method": "GET",
                    "url": guidance_target
                },
                "reasoning": f"强制执行战术指导: {tactical_guidance[:100]}"
            }
            # 返回强制攻击，绕过LLM生成
            return {
                "attack_batch": [forced_attack],
                "attack_results": [],
                "current_url": guidance_target,  # 更新当前URL
                "execution_steps": state.get("execution_steps", 0) + 1,
                "guidance_type": "",  # 清空指导，已执行
                "enforce_change": False
            }

    # =====================================================
    # LLM生成攻击Payload
    # =====================================================

    # 1. 扩容动作数量：实现饱和测试（高优先级目标增加动作数量）
    # 动态获取所有注册工具的详细定义（含参数规范）
    tools_info = ToolRegistry.get_all_tools_info()

    # 根据拓扑优先级动态调整攻击动作数量
    max_actions = 15 if current_priority > 0.7 else 10
    if current_priority > 0.7:
        log(f"   🎯 高优先级目标，增加攻击动作上限至 {max_actions}")

    # [优化] 获取最近的攻击历史，用于防止重复并引导进化
    history = state.get("attack_results", [])[-10:]

    # 获取题目背景信息
    task_info = {
        "name": state.get("task_name", "Unknown"),
        "description": state.get("task_description", "No description"),
        "target_url": state.get("target_url", ""),
        "current_url": current_url,
        "topology_priority": current_priority  # 新增：传递优先级信息
    }

    # 获取最新的人工提示
    human_hint = None
    hint_history = state.get("hint_history", [])
    if hint_history:
        latest_hint = hint_history[-1]
        if latest_hint.get("source") == "human":
            human_hint = latest_hint.get("content")

    # 获取战略上下文和阶段信息
    strategic_context = state.get("strategic_context", {})

    # 构建阶段信息
    stage_info = None
    if strategic_context:
        current_step = strategic_context.get("current_step", 1)
        attack_chain = strategic_context.get("attack_chain", [])
        stage_info = {
            "stage_name": attack_chain[current_step - 1] if current_step <= len(attack_chain) else "未知",
            "goal": strategic_context.get("primary_goal", "获取FLAG"),
            "success_criteria": [],
            "timeout": 0
        }

    prompt = get_attacker_prompt(
        candidates[:max_actions],  # 使用动态上限
        tools_info,
        history,
        task_info=task_info,
        tactical_guidance=state.get("latest_tactical_guidance"),
        analyst_intel=state.get("analyst_intel"),
        known_facts=state.get("known_facts", ""),
        failed_payloads=state.get("failed_payloads", []),
        human_hint=human_hint,
        stage_info=stage_info,
        strategic_context=strategic_context
    ) # 增加题目背景与战术指引

    try:
        response_text = llm_client.call_chat_completion(
            model=config.ATTACKER_MODEL if hasattr(config, 'ATTACKER_MODEL') else config.ANALYST_MODEL,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.3, # 略微提高随机性，增加 Payload 的多样性
            json_mode=True
        )
        if "```json" in response_text:
            response_text = response_text.split("```json")[1].split("```")[0]
        elif "```" in response_text:
            response_text = response_text.split("```")[1].split("```")[0]

        # [核心修复] 增强JSON解析容错能力
        response_text = response_text.strip()
        try:
            result = json.loads(response_text)
            # [兼容] 处理 LLM 返回 "actions" 而不是 "attack_actions" 的情况
            if "actions" in result and "attack_actions" not in result:
                result["attack_actions"] = result["actions"]
        except json.JSONDecodeError as json_err:
            # 尝试修复常见问题
            log(f"⚠️ [Attacker] JSON解析失败，尝试修复: {json_err}")
            # 1. 尝试截断到最后一个完整的 }
            if '"attack_actions"' in response_text or '"actions"' in response_text:
                # 提取 attack_actions 或 actions 数组
                import re
                # 尝试匹配 attack_actions 或 actions
                match = re.search(r'"(?:attack_actions|actions)"\s*:\s*\[', response_text)
                if match:
                    # 尝试找到数组结束位置
                    start = match.end() - 1
                    bracket_count = 0
                    for i, c in enumerate(response_text[start:], start):
                        if c == '[': bracket_count += 1
                        elif c == ']': bracket_count -= 1
                        if bracket_count == 0:
                            # 找到数组结束
                            actions_str = response_text[start:i+1]
                            try:
                                raw_actions = json.loads(actions_str)
                                result = {"attack_actions": raw_actions}
                                log(f"✅ [Attacker] JSON修复成功，提取到 {len(raw_actions)} 个动作")
                            except (json.JSONDecodeError, TypeError) as e:
                                log(f"[Warning] JSON parse failed in recovery: {e}")
                                result = {"attack_actions": []}
                            break
                    else:
                        result = {"attack_actions": []}
                else:
                    result = {"attack_actions": []}
            else:
                result = {"attack_actions": []}

        raw_actions = result.get("attack_actions", [])[:max_actions]

        # [断点2修复] 按 tool+params hash 去重，保留唯一攻击
        # 防止同工具不同参数的攻击被忽略
        import hashlib
        attack_actions = []
        seen_action_hashes = set()
        # [fallback修复] 收集fallback方案
        fallback_plans = []

        def _make_action_hash(action: dict) -> str:
            """生成动作唯一hash：tool + params组合"""
            tool = action.get("tool", "")
            params_str = json.dumps(action.get("params", {}), sort_keys=True, ensure_ascii=False)
            params_hash = hashlib.md5(params_str.encode()).hexdigest()[:8]
            return f"{tool}:{params_hash}"

        for idx, action in enumerate(raw_actions):
            if not isinstance(action, dict): continue
            tool = action.get("tool")
            if not tool: continue

            # 新策略：按 tool+params hash 去重
            action_hash = _make_action_hash(action)
            if action_hash in seen_action_hashes:
                log(f"⚠️ [Attacker] 忽略完全重复的攻击: {tool} (相同params)")
                continue

            attack_actions.append(action)
            seen_action_hashes.add(action_hash)

            # [fallback修复] 提取并存储fallback方案
            fallback = action.get("fallback", "")
            if fallback and isinstance(fallback, str) and fallback.strip():
                # 尝试将fallback转换为具体的攻击动作
                fallback_action = {
                    "tool": tool,  # 默认使用相同工具
                    "params": action.get("params", {}),
                    "reasoning": f"Fallback方案: {fallback}",
                    "source_action_id": f"fallback_{idx}_{tool}",
                    "fallback_description": fallback
                }
                # 如果fallback中包含工具切换提示，尝试解析
                if "时间盲注" in fallback or "sleep" in fallback.lower():
                    fallback_action["params"] = {
                        "method": "POST",
                        "url": action.get("params", {}).get("url", current_url),
                        "data": {"sleep": "5"}
                    }
                    fallback_action["reasoning"] = "Fallback: 切换到时间盲注"
                elif "union" in fallback.lower():
                    fallback_action["params"] = {
                        "method": "GET",
                        "url": action.get("params", {}).get("url", current_url),
                        "params": {"id": "1' UNION SELECT 1,2,3--"}
                    }
                    fallback_action["reasoning"] = "Fallback: 切换到UNION注入"
                elif "布尔盲注" in fallback or "boolean" in fallback.lower():
                    fallback_action["params"] = {
                        "method": "GET",
                        "url": action.get("params", {}).get("url", current_url),
                        "params": {"id": "1' AND 1=1--"}
                    }
                    fallback_action["reasoning"] = "Fallback: 切换到布尔盲注"
                elif "错误注入" in fallback or "error" in fallback.lower():
                    fallback_action["params"] = {
                        "method": "GET",
                        "url": action.get("params", {}).get("url", current_url),
                        "params": {"id": "1' AND extractvalue(1,concat(0x7e,version()))--"}
                    }
                    fallback_action["reasoning"] = "Fallback: 切换到错误注入"
                fallback_plans.append(fallback_action)
                log(f"   📋 收集Fallback方案: {fallback[:50]}")

        # [fallback修复] 记录收集到的fallback方案数量
        if fallback_plans:
            log(f"   ✅ 共收集 {len(fallback_plans)} 个Fallback方案")

    except Exception as e:
        log(f"   ❌ LLM 决策失败: {e}")
        log_node_data("attacker", {"prompt": prompt}, {"error": str(e)})
        attack_actions = []

    # [断点3修复] JSON解析失败或空动作时的降级逻辑
    # 生成默认探测攻击，防止无攻击执行
    if not attack_actions:
        log("   ⚠️ LLM 未生成有效攻击动作，执行降级探测")
        # 降级：生成默认探测攻击
        default_probe = {
            "tool": "requests",
            "params": {
                "method": "GET",
                "url": current_url
            },
            "reasoning": "降级探测：JSON解析失败或无有效动作，执行基础GET请求"
        }
        attack_actions = [default_probe]
        log(f"   📌 执行降级探测: GET {current_url}")

    # 2. 并发执行
    log(f"   执行 {len(attack_actions)} 个攻击动作...")

    # [同步修复] 使用线程池执行，并设置合理的单任务超时
    attack_results = []
    futures_map = {}

    for a in attack_actions:
        # 从配置获取慢速工具列表和超时值
        tool_name = a.get("tool", "unknown")
        task_timeout = config.TOOL_TIMEOUTS.get("slow", 180) if tool_name in config.SLOW_TOOLS else config.TOOL_TIMEOUTS.get("default", 60)

        future = get_executor().submit(execute_single_attack, a, current_url, state.get("page_history", {}), task_timeout)
        futures_map[future] = a

    try:
        # 使用 as_completed 允许部分完成的任务先进入下一步，或者在超时后统一处理
        from concurrent.futures import as_completed, wait, FIRST_EXCEPTION
        
        # 最多等待 300 秒，防止整个节点卡死（dirsearch/sqlmap 需要更长时间）
        done, not_done = wait(futures_map.keys(), timeout=300)
        
        for f in done:
            try:
                attack_results.append(f.result())
            except Exception as e:
                action = futures_map[f]
                log(f"❌ [Attacker] 任务执行崩溃: {action.get('tool')} - {e}")
                attack_results.append({
                    "tool": action.get("tool"),
                    "status": 500,
                    "output": f"Internal Error: {str(e)}",
                    "diff_analysis": {"changed": False}
                })
        
        # 处理超时的任务
        for f in not_done:
            action = futures_map[f]
            log(f"⚠️ [Attacker] 任务执行超时已取消: {action.get('tool')}")
            # 注意：concurrent.futures 无法强制杀掉正在运行的线程，但我们可以不再等待它
            attack_results.append({
                "tool": action.get("tool"),
                "status": 408,
                "output": "Task timed out and backgrounded.",
                "diff_analysis": {"changed": False}
            })

    except KeyboardInterrupt:
        log("\n🛑 [Attacker] 用户中断执行，正在尝试收尾...")
        raise # 重新抛出让主程序处理
    except Exception as e:
        log(f"❌ [Attacker] 并发管理异常: {e}")

    # 3. 检查是否有成功的动作 (Early Exit Sign)
    success_found = any(r.get("is_exploit") for r in attack_results)
    if success_found:
        log("   🔥 有动作命中目标！")

    # 4. 合并工具发现的结构化数据
    discovered_vulns = []
    discovered_creds = []
    discovered_hosts = []

    for r in attack_results:
        # 漏洞
        for v in r.get("vulnerabilities", []):
            # 去重
            if not any(dv.get("target") == v.get("target") and dv.get("type") == v.get("type")
                       for dv in discovered_vulns):
                discovered_vulns.append(v)

        # 凭据
        for c in r.get("credentials", []):
            if c not in discovered_creds:
                discovered_creds.append(c)

        # 主机
        for h in r.get("hosts", []):
            if not any(dh.get("ip") == h.get("ip") for dh in discovered_hosts):
                discovered_hosts.append(h)

    # 打印发现摘要
    if discovered_vulns:
        log(f"   📌 发现 {len(discovered_vulns)} 个新漏洞")
    if discovered_creds:
        log(f"   🔑 发现 {len(discovered_creds)} 个新凭据")
    if discovered_hosts:
        log(f"   🖥️ 发现 {len(discovered_hosts)} 个新主机")

    # 记录攻击链
    try:
        from context_compressor import record_node
        attack_summary = f"执行{len(attack_actions)}个攻击动作"
        changes = []
        if discovered_vulns:
            changes.append(f"发现{len(discovered_vulns)}个漏洞")
        if discovered_creds:
            changes.append(f"发现{len(discovered_creds)}个凭据")
        if discovered_hosts:
            changes.append(f"发现{len(discovered_hosts)}个主机")

        record_node(
            node="attacker",
            decision=f"攻击目标: {current_url}",
            result=attack_summary,
            changes=changes,
            success=len(discovered_vulns) > 0 or len(discovered_creds) > 0
        )
    except Exception as e:
        log(f"   ⚠️ 记录攻击链失败: {e}")

    # [断点4修复] 生成攻击历史摘要
    # 当attack_results达到上限时，生成摘要保留关键信息
    existing_results = state.get("attack_results", [])
    total_results = len(existing_results) + len(attack_results)
    new_attack_summary = ""
    if total_results > 40:  # 接近上限时生成摘要
        from state_types.reducers import generate_attack_summary
        all_results = existing_results + attack_results
        new_attack_summary = generate_attack_summary(all_results)
        log(f"   📝 生成攻击摘要: {new_attack_summary[:100]}")

    res = {
        "flow_decision": "",  # [关键] 重置流转标志，避免死循环
        "attack_batch": attack_actions,
        "attack_results": attack_results,
        # [断点4修复] 添加攻击摘要
        "attack_summary": new_attack_summary,
        "page_history": state.get("page_history", {}),
        "node_attack_status": node_status,
        "execution_steps": state.get("execution_steps", 0) + 1,
        # 新发现的结构化数据（会自动合并到状态）
        "vuln_candidates": discovered_vulns,
        "credentials": discovered_creds,
        "internal_hosts": discovered_hosts,
    }
    # [fallback修复] 将fallback方案存入状态
    if fallback_plans:
        res["fallback_plans"] = fallback_plans

    # =========================================================================
    # [智能流转] AI流转决策 - 根据攻击结果智能决定下一步流向
    # =========================================================================
    if ai_flow_controller and attack_results:
        try:
            # 综合所有攻击结果进行决策
            combined_result = {
                "attack_count": len(attack_results),
                "success_count": sum(1 for r in attack_results if r.get("is_exploit")),
                "vulns_found": len(discovered_vulns),
                "creds_found": len(discovered_creds),
                "hosts_found": len(discovered_hosts),
                "has_progress": len(discovered_vulns) > 0 or len(discovered_creds) > 0 or len(discovered_hosts) > 0
            }

            flow_decision, decision_reason = ai_flow_controller.decide(
                state=state,
                attack_result=combined_result,
                current_node="attacker"
            )

            log(f"   🧠 [智能流转] 决策: {flow_decision.value if hasattr(flow_decision, 'value') else flow_decision}")
            log(f"      理由: {decision_reason}")

            # 根据决策设置流转标志
            if flow_decision == FlowDecision.CONTINUE_ATTACK:
                # 有明显进展，可以绕过verifier直接继续
                res["skip_verifier"] = True
                res["flow_decision"] = "continue_attack"
                res["flow_reason"] = decision_reason
                log("      → 绕过verifier，直接继续攻击")

            elif flow_decision == FlowDecision.REPORT_FLAG:
                # 发现FLAG，直接报告
                res["skip_verifier"] = True
                res["flow_decision"] = "report_flag"
                res["flow_reason"] = decision_reason
                log("      → 发现FLAG，准备报告")

            elif flow_decision == FlowDecision.SWITCH_STRATEGY:
                # 需要切换策略
                res["flow_decision"] = "switch_strategy"
                res["flow_reason"] = decision_reason
                # 增加失败分触发策略切换
                res["failure_weighted_score"] = state.get("failure_weighted_score", 0) + 3.0
                log("      → 切换攻击策略")

            else:
                # GO_VERIFIER - 正常流转
                res["flow_decision"] = "go_verifier"
                res["flow_reason"] = decision_reason
                log("      → 正常流转到verifier")

        except Exception as e:
            log(f"   ⚠️ [智能流转] 决策异常: {e}")
            # 异常时保持默认流转（不设置skip_verifier）

    log_node_data("attacker", {"prompt": prompt, "actions": attack_actions}, res)
    return res


def _run_exploration_tool(tool_name: str, target: str, options: dict = None) -> dict:
    """
    执行单个探索工具并返回发现的URL列表
    """
    result = {"urls": [], "status_codes": {}, "error": None}
    options = options or {}

    try:
        tool_result = ToolRegistry.execute_cached(tool_name, target, options)
        if tool_result.get("cached", False):
            return result

        output = tool_result.get("result", {}).get("output", "")
        if not output and tool_result.get("result", {}).get("file_path"):
            try:
                with open(tool_result["result"]["file_path"], "r", encoding="utf-8") as f:
                    output = f.read()
            except (IOError, OSError, UnicodeDecodeError):
                pass

        if output:
            urls = re.findall(r'(http[s]?://[^\s<>"\']+)', output)
            static_exts = ('.css', '.ico', '.png', '.jpg', '.gif', '.svg', '.woff')
            for u in urls:
                if u != target and not any(u.endswith(ext) for ext in static_exts):
                    result["urls"].append(u)
                    result["status_codes"][u] = 200
    except Exception as e:
        result["error"] = str(e)

    return result


def _should_switch_to_innovate(exploration_rounds: int, found_count: int) -> tuple:
    """判断是否应该切换到创新模式"""
    min_rounds = getattr(config, 'EXPLORE_ROUNDS_FOR_INNOVATE', 8)
    if exploration_rounds < min_rounds:
        return False, f"轮次 {exploration_rounds}/{min_rounds}"
    if found_count > 0:
        return False, f"仍有发现({found_count})"
    return True, f"探索{exploration_rounds}轮后无新发现"


def explorer_node(state: CTFState) -> Dict:
    """
    [探索兵] (多工具组合扫描 + 图数据库更新)

    职责:
        1. 执行多工具组合扫描 (dirsearch + ffuf + nuclei)
        2. 发现新路径，更新拓扑图
        3. 图分析（关键节点、死循环检测）
        4. 自动剪枝无效路径

    探索策略:
        - 第一轮: dirsearch 目录扫描
        - 第二轮: ffuf 模糊测试
        - 第三轮+: nuclei 漏洞扫描
        - 达到 EXPLORE_ROUNDS_FOR_INNOVATE 后才允许切换创新模式
    """
    log("🗺️ [探索] 启动多工具组合扫描...")
    target_url = state.get("target_url")
    current_url = state.get("current_url")
    exploration_rounds = state.get("exploration_rounds", 0)
    visited_urls = state.get("visited_urls", [])

    scan_target = current_url if current_url else target_url

    # 检查是否已扫描过该目标
    if scan_target in visited_urls:
        log(f"   📦 已扫描过: {scan_target}")
        exploration_rounds += 1
        should_switch, reason = _should_switch_to_innovate(exploration_rounds, 0)
        if should_switch:
            log(f"   🔄 {reason}，切换创新模式")
            return {"exploration_rounds": exploration_rounds,
                    "failure_weighted_score": state.get("failure_weighted_score", 0) + 0.5,
                    "current_mode": "innovate"}
        log(f"   ⏭️ {reason}，跳过")

    new_paths = {}
    node_status = {}
    total_found = 0

    if scan_target:
        log(f"   扫描: {scan_target}")

        # 探索工具组合（按轮次递进）
        explore_tools = [
            {"name": "dirsearch", "condition": exploration_rounds < 3,
             "options": {"extensions": config.DEFAULT_SCAN_EXTENSIONS}},
            {"name": "ffuf", "condition": exploration_rounds >= 1, "options": {"mode": "dir"}},
            {"name": "nuclei", "condition": exploration_rounds >= 2,
             "options": {"severity": "medium,high,critical"}},
        ]

        for tool_info in explore_tools:
            tool_name = tool_info["name"]
            if not tool_info.get("condition", True):
                continue

            log(f"   🔧 执行 {tool_name}...")
            result = _run_exploration_tool(tool_name, scan_target, tool_info.get("options", {}))

            if result.get("error"):
                log(f"   ⚠️ {tool_name} 失败: {result['error']}")
                continue

            found_urls = result.get("urls", [])
            if found_urls:
                unique_urls = list(set(found_urls) - set(visited_urls))
                if unique_urls:
                    new_paths[f"{scan_target}_{tool_name}"] = unique_urls
                    node_status.update(result.get("status_codes", {}))
                    total_found += len(unique_urls)
                    log(f"   ✅ {tool_name} 发现 {len(unique_urls)} 个新路径")

        # 汇总路径
        all_found = list(set(sum(new_paths.values(), [])))
        if all_found:
            new_paths[scan_target] = all_found
            log(f"   📊 本轮共发现 {len(all_found)} 个新路径")
        else:
            log("   ⚠️ 本轮未发现新路径")

        # 延迟切换创新模式
        should_switch, reason = _should_switch_to_innovate(exploration_rounds + 1, total_found)
        if should_switch:
            log(f"   🔄 {reason}，切换创新模式")
            return {"exploration_rounds": exploration_rounds + 1,
                    "failure_weighted_score": state.get("failure_weighted_score", 0) + 0.3,
                    "current_mode": "innovate"}

    # 1. 初始化图构建器
    builder = TopologyBuilder()

    # 2. 更新拓扑图（合并新路径）
    topology_updates = builder.update_from_explorer(state, new_paths)

    # 3. 构建NetworkX图进行分析
    merged_topology = {**state.get("site_topology", {}), **topology_updates.get("site_topology", {})}
    G = builder.build_from_adjacency(merged_topology)

    # 4. 添加节点属性（状态码、技术栈等）
    for url, status in node_status.items():
        builder.add_node_attr(url, status_code=status)

    # 5. 图分析
    analyzer = TopologyAnalyzer(G)

    # 5.1 找出关键节点（PageRank高的节点）
    critical_nodes = analyzer.find_critical_nodes(top_k=5)
    log(f"  📊 关键节点: {critical_nodes}")

    # 5.2 检测循环路径
    cycles = analyzer.detect_cycles()
    if cycles:
        log(f"  ⚠️ 检测到 {len(cycles)} 个循环路径")

    # 5.3 找到从入口到敏感页面的最短攻击路径
    target_url = state.get("target_url")
    sensitive_paths = state.get("page_features", {}).get("sensitive_paths", [])
    if sensitive_paths and target_url:
        attack_path = analyzer.find_shortest_attack_path(target_url, sensitive_paths)
        if attack_path:
            log(f"  🎯 最短攻击路径: {' -> '.join(attack_path)}")

    # 5.4 计算拓扑优先级（核心对接点）
    visited_urls = state.get("visited_urls", [])
    topology_priority = analyzer.prioritize_attack_targets(visited_urls, top_k=10)
    if topology_priority:
        log(f"  🎯 拓扑优先目标: {[f'{url}({score:.2f})' for url, score in topology_priority[:3]]}")

    # 6. 剪枝（删除无效节点）
    pruner = TopologyPruner()

    # 准备剪枝元数据
    metadata = {
        "node_status": node_status,
        "root": state.get("target_url", "/"),
        "node_last_seen": {url: time.time() for url in G.nodes}
    }

    # 执行剪枝
    G_pruned = pruner.prune_all(G, metadata)

    # 7. 统计剪枝效果
    before_count = G.number_of_nodes()
    after_count = G_pruned.number_of_nodes()
    if before_count > after_count:
        log(f"  ✂️ 剪枝完成: 节点数 {before_count} → {after_count}")

    # 8. 可选：可视化（调试用）
    if state.get("debug_mode"):
        from topology import TopologyVisualizer
        viz = TopologyVisualizer(G_pruned)
        viz.export_to_html(f"topology_{int(time.time())}.html")

    # 9. 转回邻接表存回state
    new_topology = nx.to_dict_of_lists(G_pruned)

    return {
        "exploration_rounds": state.get("exploration_rounds", 0) + 1,
        "site_topology": new_topology,
        "critical_nodes": critical_nodes,
        "topology_priority": topology_priority,  # 新增：拓扑优先级列表
        "pruned_nodes": before_count - after_count
    }


def verifier_node(state: CTFState) -> Dict:
    """
    [核验兵] (AI 驱动验证) [P3合并版]

    职责:
        1. 验证攻击结果，识别各种变体形式的 Flag
        2. 分析失败原因，决定节点是否继续
        3. 提供战术指导

    合并了原verifier和reflector的职责，减少LLM调用次数
    """
    log("🔎 [核验] 分析攻击结果...")

    current_url = state.get("current_url")
    node_status = state.get("node_attack_status", {})
    updates = {}  # 用于收集更新数据

    # [P3合并] 超时检查 (原reflector功能)
    if current_url and current_url in node_status:
        status = node_status[current_url]
        now = time.time()

        # 硬熔断：节点超时
        if now - status.get("start_time", now) > config.NODE_TIMEOUT:
            log(f"   ⏰ 节点超时，放弃: {current_url}")
            status["status"] = "abandoned"
            # [补充修复] 早期返回分支也需要完整字段
            strategic_context = update_strategic_context_after_node(state, "verifier", {"error": "timeout"})

            # 记录战略决策
            try:
                from router import record_strategic_decision
                decision_updates = record_strategic_decision(
                    state,
                    {
                        "timestamp": time.time(),
                        "node": "verifier",
                        "decision_type": "validation",
                        "action": "abandon",
                        "reason": "节点超时",
                        "confidence": 1.0,
                        "outcome": "timeout"
                    }
                )
            except Exception as e:
                logger.warning(f"记录战略决策失败: {e}")
                decision_updates = {}

            return {
                "node_attack_status": node_status,
                "failure_weighted_score": state.get("failure_weighted_score", 0) + 0.5,
                "execution_steps": state.get("execution_steps", 0) + 1,
                "guidance_type": "continue",
                "enforce_change": False,
                "guidance_reason": "节点超时",
                "guidance_target_url": "",
                "strategic_context": strategic_context,
                **decision_updates
            }

    # 获取当前批次的攻击结果
    results = state.get("attack_results", [])
    attack_batch = state.get("attack_batch", [])

    # 如果无攻击动作，检查是否已触发模式切换
    current_mode = state.get("current_mode")
    if not attack_batch:
        if current_mode == "explore":
            # 已由 attacker 设置为 explore 模式，直接返回
            log("   ⏭️ 已触发探索模式，跳过核验")

            # 记录战略决策
            try:
                from router import record_strategic_decision
                decision_updates = record_strategic_decision(
                    state,
                    {
                        "timestamp": time.time(),
                        "node": "verifier",
                        "decision_type": "validation",
                        "action": "skip",
                        "reason": "探索模式已触发",
                        "confidence": 1.0,
                        "outcome": "skipped"
                    }
                )
            except Exception as e:
                logger.warning(f"记录战略决策失败: {e}")
                decision_updates = {}

            return {
                "guidance_type": "continue",
                "enforce_change": False,
                "guidance_reason": "探索模式已触发",
                "guidance_target_url": "",
                **decision_updates
            }
        log("   ⚠️ 本轮无攻击动作")

        # 记录战略决策
        try:
            from router import record_strategic_decision
            decision_updates = record_strategic_decision(
                state,
                {
                    "timestamp": time.time(),
                    "node": "verifier",
                    "decision_type": "validation",
                    "action": "skip",
                    "reason": "无攻击动作",
                    "confidence": 0.5,
                    "outcome": "skipped"
                }
            )
        except Exception as e:
            logger.warning(f"记录战略决策失败: {e}")
            decision_updates = {}

        return {
            "failure_weighted_score": state.get("failure_weighted_score", 0) + config.HARD_FAILURE_WEIGHT,
            "guidance_type": "continue",
            "enforce_change": False,
            "guidance_reason": "无攻击动作",
            "guidance_target_url": "",
            **decision_updates
        }

    recent_results = results[-len(attack_batch):]

    # 更新节点状态码
    if current_url and current_url in node_status:
        new_codes = [res.get("status", 0) for res in recent_results]
        node_status[current_url]["last_status_codes"].extend(new_codes)
        node_status[current_url]["last_status_codes"] = node_status[current_url]["last_status_codes"][-10:]
        node_status[current_url]["attempt_count"] = node_status[current_url].get("attempt_count", 0) + 1

    if not recent_results:
        log("   ⚠️ 无结果可核验")

        # 记录战略决策
        try:
            from router import record_strategic_decision
            decision_updates = record_strategic_decision(
                state,
                {
                    "timestamp": time.time(),
                    "node": "verifier",
                    "decision_type": "validation",
                    "action": "skip",
                    "reason": "无结果可核验",
                    "confidence": 0.5,
                    "outcome": "skipped"
                }
            )
        except Exception as e:
            logger.warning(f"记录战略决策失败: {e}")
            decision_updates = {}

        return {
            "failure_weighted_score": state.get("failure_weighted_score", 0) + config.HARD_FAILURE_WEIGHT,
            "guidance_type": "continue",
            "enforce_change": False,
            "guidance_reason": "无结果可核验",
            "guidance_target_url": "",
            **decision_updates
        }

    # [核心] Flag预捕获 - 使用统一的flag_extractor，支持多Flag
    pre_captured_flags: List[str] = []
    try:
        from flag_extractor import extract_flags
        for res in recent_results:
            if res.get("extracted_flag"):
                pre_captured_flags.append(res["extracted_flag"])
            diff = res.get("diff_analysis", {})
            if diff.get("extracted_flag"):
                pre_captured_flags.append(diff["extracted_flag"])
            output_text = res.get("output", "")
            if isinstance(output_text, str):
                found = extract_flags(output_text, decode=True)
                pre_captured_flags.extend(found)
        # 去重
        pre_captured_flags = list(set(pre_captured_flags))
    except ImportError:
        # 兜底：使用简化正则
        for res in recent_results:
            if res.get("extracted_flag"):
                pre_captured_flags.append(res["extracted_flag"])
            output_text = res.get("output", "")
            if isinstance(output_text, str):
                flag_m = re.search(r"[a-zA-Z0-9_]+\{[^\}]+\}", output_text, re.IGNORECASE)
                if flag_m:
                    pre_captured_flags.append(flag_m.group(0))
        pre_captured_flags = list(set(pre_captured_flags))

    # 取第一个作为预捕获flag（向后兼容）
    pre_captured_flag: Optional[str] = pre_captured_flags[0] if pre_captured_flags else None

    # 读取日志文件并附加差异分析（限制总大小避免prompt过大）
    total_log_size = 0
    MAX_TOTAL_LOG = 4000
    for res in recent_results:
        if res.get("file_path") and os.path.exists(res["file_path"]):
            try:
                read_size = min(2000, MAX_TOTAL_LOG - total_log_size)
                if read_size > 0:
                    with open(res["file_path"], 'rb') as f:
                        content = f.read(read_size).decode('utf-8', errors='ignore')
                        total_log_size += len(content)
                        if isinstance(res.get("output"), str) and res["output"].strip().startswith("{"):
                            res["output"] = f"Cleaned Info: {res['output'][:500]}\n\nRaw Logs:\n{content}"
                        else:
                            res["output"] = content
            except Exception as e:
                log(f"⚠️ [Verifier] 读取文件失败: {e}")

        diff = res.get("diff_analysis", {})
        res["diff_metrics"] = {
            "is_significant_change": diff.get("changed", False),
            "exploit_confidence": diff.get("confidence", 0.0),
            "change_reason": diff.get("reason", "")
        }

    # [P3合并] 构建节点信息供AI决策
    node_info = {}
    if current_url and current_url in node_status:
        status = node_status[current_url]
        node_info = {
            "attempt_count": status.get("attempt_count", 0),
            "duration_min": (time.time() - status.get("start_time", time.time())) / 60,
            "recent_codes": status.get("last_status_codes", [])[-5:]
        }

    # 获取最新的人工提示
    human_hint = None
    hint_history = state.get("hint_history", [])
    if hint_history:
        latest_hint = hint_history[-1]
        if latest_hint.get("source") == "human":
            human_hint = latest_hint.get("content")

    # 获取战略上下文和阶段信息
    strategic_context = state.get("strategic_context", {})

    # 构建阶段信息
    stage_info = None
    if strategic_context:
        current_step = strategic_context.get("current_step", 1)
        attack_chain = strategic_context.get("attack_chain", [])
        stage_info = {
            "stage_name": attack_chain[current_step - 1] if current_step <= len(attack_chain) else "未知",
            "goal": strategic_context.get("primary_goal", "获取FLAG"),
            "success_criteria": [],
            "timeout": 0
        }

    # 调用LLM
    prompt = get_verifier_prompt(
        attack_batch,
        recent_results,
        analyst_intel=state.get("analyst_intel"),
        node_info=node_info,
        known_facts=state.get("known_facts", ""),
        human_hint=human_hint,
        stage_info=stage_info,
        strategic_context=strategic_context
    )

    response_text = llm_client.call_chat_completion(
        model=config.VERIFIER_MODEL,
        messages=[{"role": "user", "content": prompt}],
        temperature=0.1,
        json_mode=True,
        timeout=60  # 核验应快速完成
    )

    candidates = state.get("vuln_candidates", [])

    # 容错
    if not response_text or not response_text.strip():
        log("   ⚠️ Verifier LLM 返回空响应")
        return {
            "failure_weighted_score": state.get("failure_weighted_score", 0) + 0.5,
            "execution_steps": state.get("execution_steps", 0) + 1,
            "node_attack_status": node_status,
            "vuln_candidates": candidates,
            "guidance_type": "continue",
            "enforce_change": False,
            "guidance_reason": "LLM返回空响应",
            "guidance_target_url": ""
        }

    # 解析结果
    try:
        if "```json" in response_text:
            response_text = response_text.split("```json")[1].split("```")[0]
        elif "```" in response_text:
            response_text = response_text.split("```")[1].split("```")[0]

        result = json.loads(response_text)

        found_flag = result.get("found_flag", False)
        potential_flag = result.get("potential_flag", "")
        evidence = result.get("exploit_evidence", "")
        failure_severity = result.get("failure_severity", 0.5)
        is_exploit_successful = result.get("is_exploit_successful", False)
        # [断点1修复] 处理结构化的tactical_guidance
        tactical_guidance_raw = result.get("tactical_guidance", "")
        if isinstance(tactical_guidance_raw, dict):
            # 新格式：结构化指导
            tactical_guidance = tactical_guidance_raw.get("action", "")
            guidance_type = tactical_guidance_raw.get("guidance_type", "continue")
            enforce_change = tactical_guidance_raw.get("enforce_change", False)
            guidance_reason = tactical_guidance_raw.get("reason", "")
            guidance_target_url = tactical_guidance_raw.get("target_url", "")
            log(f"   📋 战术指导类型: {guidance_type}, 强制执行: {enforce_change}")
            if guidance_target_url:
                log(f"   🎯 建议目标URL: {guidance_target_url}")
        else:
            # 兼容旧格式：纯文本
            tactical_guidance = tactical_guidance_raw if isinstance(tactical_guidance_raw, str) else str(tactical_guidance_raw)
            guidance_type = "continue"
            enforce_change = False
            guidance_reason = ""
            guidance_target_url = ""
        updated_known_facts = result.get("updated_known_facts", "")
        node_decision = result.get("node_decision", "continue")
        failure_analysis = result.get("failure_analysis", "")

        # 预捕获Flag优先
        if pre_captured_flag:
            potential_flag = pre_captured_flag
            found_flag = True
            log(f"   🔓 预捕获 Flag: {potential_flag}")

        # 找到FLAG
        if found_flag:
            log(f"\n   🎉 找到 FLAG: {potential_flag}")
            result = {
                "found_flag": True,
                "final_flag": potential_flag,
                "success_trace": recent_results[-1:],
                "failure_weighted_score": 0,
                "node_attack_status": node_status,
                "execution_steps": state.get("execution_steps", 0) + 1
            }
            # [战略上下文更新] 找到FLAG是成功案例
            updated_context = update_strategic_context_after_node(state, "verifier", result)
            if updated_context:
                result["strategic_context"] = updated_context

            # 记录战略决策
            try:
                from router import record_strategic_decision
                decision_updates = record_strategic_decision(
                    state,
                    {
                        "timestamp": time.time(),
                        "node": "verifier",
                        "decision_type": "validation",
                        "action": "flag_captured",
                        "reason": f"成功捕获FLAG: {potential_flag[:50]}...",
                        "confidence": 1.0,
                        "outcome": "success",
                        "target": current_url
                    }
                )
                result.update(decision_updates)
            except Exception as e:
                logger.warning(f"记录战略决策失败: {e}")

            return result

        # 攻击成功
        if is_exploit_successful:
            log(f"   [+] Attack effective: {evidence[:100] if evidence else 'N/A'}")

            # 检测并管理交互式会话 - 创建完整的ShellSession对象
            shell_session_info = None
            try:
                for res in recent_results:
                    output = res.get("output", "")
                    tool = res.get("tool", "")

                    # 检测 meterpreter 会话
                    if "meterpreter" in output.lower() or tool in ["metasploit", "msfvenom"]:
                        log(f"   [MSF] Detected Meterpreter session, connecting...")
                        try:
                            from tools.metasploit_manager import get_msf_manager
                            from remote_executor.session_manager import ShellSession, ShellType, get_session_manager

                            msf = get_msf_manager()
                            if msf.connect():
                                sessions = msf.list_sessions()
                                if sessions:
                                    latest_session = sessions[-1]
                                    log(f"   [MSF] Connected to session: {latest_session.id}")

                                    # 创建 ShellSession 对象并注册
                                    session_manager = get_session_manager()
                                    shell_session = ShellSession(
                                        id=str(latest_session.id),
                                        session_type=ShellType.METERPRETER,
                                        target=latest_session.target,
                                        os_type=latest_session.platform or "unknown",
                                        metadata={
                                            "rpc_host": msf.host,
                                            "rpc_port": msf.port,
                                            "rpc_password": msf.password,
                                            "via_exploit": latest_session.via_exploit
                                        }
                                    )
                                    # 注册到 session_manager
                                    session_manager.sessions[shell_session.id] = shell_session
                                    session_manager._save_sessions()

                                    # 返回给状态的信息
                                    shell_session_info = {
                                        "type": "meterpreter",
                                        "session_id": shell_session.id,
                                        "target": latest_session.target,
                                        "platform": latest_session.platform
                                    }
                                    log(f"   [MSF] Session registered: {shell_session.id}")

                                    # 获取系统信息
                                    sysinfo = msf.execute(latest_session.id, "sysinfo")
                                    if sysinfo.get("success"):
                                        log(f"   [MSF] System info: {sysinfo.get('output', '')[:100]}")
                        except Exception as msf_err:
                            log(f"   [!] MSF connection failed: {msf_err}")
                        break

                    # 检测其他 shell 类型
                    elif any(indicator in output.lower() for indicator in
                            ["shell>", "cmd>", "whoami", "uid=", "c:\\"]):
                        log(f"   [Shell] Detected shell session")
                        shell_session_info = {
                            "type": "shell",
                            "output_sample": output[:500]
                        }
                        break
            except Exception as e:
                log(f"   [!] Session detection failed: {e}")

            new_known_facts = ""
            if updated_known_facts:
                existing = state.get("known_facts", "")
                new_known_facts = f"{existing}; {updated_known_facts}" if existing else updated_known_facts

            if tactical_guidance and candidates:
                for cand in candidates:
                    if cand.get("url") == current_url:
                        cand.setdefault("context", {})["tactical_guidance"] = tactical_guidance

            # [核心修复] 只有当 failure_severity < 0.5 时才减少失败分
            # 如果 failure_severity >= 0.5，说明虽然有进展但仍有问题，保持或增加失败分
            if failure_severity < 0.5:
                new_score = max(0, state.get("failure_weighted_score", 0) - 0.3)
            else:
                # 有变化但无实质突破，仍然增加失败分（只是权重较低）
                new_score = state.get("failure_weighted_score", 0) + 0.2

            result_dict = {
                "failure_weighted_score": new_score,
                "latest_tactical_guidance": tactical_guidance,
                # [断点1修复] 添加结构化指导字段到成功分支
                "guidance_type": guidance_type,
                "enforce_change": enforce_change,
                "guidance_reason": guidance_reason,
                "guidance_target_url": guidance_target_url,
                "execution_steps": state.get("execution_steps", 0) + 1,
                "node_attack_status": node_status,
                "vuln_candidates": candidates
            }
            if new_known_facts:
                result_dict["known_facts"] = new_known_facts
            if shell_session_info:
                result_dict["shell_session"] = shell_session_info

            # [战略上下文更新] 攻击成功时更新战略上下文
            updated_context = update_strategic_context_after_node(state, "verifier", result_dict)
            if updated_context:
                result_dict["strategic_context"] = updated_context

            # 记录战略决策
            try:
                from router import record_strategic_decision
                decision_updates = record_strategic_decision(
                    state,
                    {
                        "timestamp": time.time(),
                        "node": "verifier",
                        "decision_type": "validation",
                        "action": node_decision if node_decision else "continue",
                        "reason": evidence[:100] if evidence else "攻击有效",
                        "confidence": 0.8,
                        "outcome": "success",
                        "target": current_url
                    }
                )
                result_dict.update(decision_updates)
            except Exception as e:
                logger.warning(f"记录战略决策失败: {e}")

            return result_dict

        # 攻击失败 - [P3合并] 处理节点决策
        log(f"   📉 攻击无效 (严重度: {failure_severity})")

        # 更新场景攻击计数
        scene_attack_attempts = state.get("scene_attack_attempts", 0) + 1
        focused_scene = state.get("focused_scene", "")

        # 记录失败的payload
        failed_payloads = []
        for action in attack_batch:
            payload_str = action.get("payload", "")
            if payload_str:
                failed_payloads.append(payload_str)

        # =====================================================
        # [fallback修复] 检查是否有备选方案可用
        # =====================================================
        fallback_plans = state.get("fallback_plans", [])
        fallback_action = None

        if fallback_plans:
            log(f"   🔄 检查Fallback方案... (共 {len(fallback_plans)} 个)")
            # 找到第一个未被尝试的fallback方案
            for fb in fallback_plans:
                fb_desc = fb.get("fallback_description", "")
                fb_tool = fb.get("tool", "")
                # 检查是否已被尝试（通过failed_payloads或历史记录）
                if fb_desc and fb_desc not in [p[:50] for p in failed_payloads]:
                    fallback_action = fb
                    log(f"   ✅ 找到可用Fallback: {fb_tool} - {fb_desc[:50]}")
                    break

        # 如果有fallback方案，生成fallback攻击动作
        if fallback_action:
            log(f"   🔀 执行Fallback方案切换")
            # 从fallback_plans中移除已使用的方案
            remaining_fallbacks = [fb for fb in fallback_plans if fb != fallback_action]

            # 构建fallback攻击动作
            fallback_attack = {
                "tool": fallback_action.get("tool", "requests"),
                "params": fallback_action.get("params", {}),
                "reasoning": fallback_action.get("reasoning", "Fallback方案执行")
            }

            # 更新战术指导，说明正在执行fallback
            tactical_guidance = f"原攻击失败，正在执行Fallback方案: {fallback_action.get('fallback_description', '未知')}"
            guidance_type = "continue"
            enforce_change = False

            result_dict = {
                "failure_weighted_score": max(0, state.get("failure_weighted_score", 0) - 0.3),  # 有fallback方案，减少失败惩罚
                "attack_batch": [fallback_attack],  # 直接生成fallback攻击
                "latest_tactical_guidance": tactical_guidance,
                "guidance_type": guidance_type,
                "enforce_change": enforce_change,
                "guidance_reason": "Fallback方案执行",
                "guidance_target_url": "",
                "execution_steps": state.get("execution_steps", 0) + 1,
                "node_attack_status": node_status,
                "vuln_candidates": candidates,
                "fallback_plans": remaining_fallbacks,  # 更新剩余fallback列表
                "scene_attack_attempts": scene_attack_attempts
            }
            if failed_payloads:
                result_dict["failed_payloads"] = failed_payloads

            # [战略上下文更新] Fallback方案执行时更新战略上下文
            updated_context = update_strategic_context_after_node(state, "verifier", result_dict)
            if updated_context:
                result_dict["strategic_context"] = updated_context

            # 记录战略决策
            try:
                from router import record_strategic_decision
                decision_updates = record_strategic_decision(
                    state,
                    {
                        "timestamp": time.time(),
                        "node": "verifier",
                        "decision_type": "validation",
                        "action": "fallback",
                        "reason": fallback_action.get("fallback_description", "执行Fallback方案"),
                        "confidence": 0.6,
                        "outcome": "pending",
                        "target": current_url
                    }
                )
                result_dict.update(decision_updates)
            except Exception as e:
                logger.warning(f"记录战略决策失败: {e}")

            log(f"   🎯 Fallback攻击动作: {fallback_attack.get('tool')}")
            return result_dict

        # =====================================================
        # [内网模式增强] Shell存活验证 + 继续攻击决策
        # =====================================================
        internal_mode = state.get("internal_mode", False)
        continue_attack = False
        remaining_payloads = []

        if internal_mode:
            # 检查是否有活跃的shell会话
            shell_session = state.get("shell_session")
            active_sessions = state.get("active_sessions", [])

            if shell_session:
                log(f"   ✅ [内网] 检测到活跃Shell会话")
                # 有shell会话，进入后渗透阶段
                result_dict = {
                    "failure_weighted_score": max(0, state.get("failure_weighted_score", 0) - 0.5),
                    "execution_steps": state.get("execution_steps", 0) + 1,
                    "node_attack_status": node_status,
                    "vuln_candidates": candidates,
                    "shell_session": shell_session,
                    # [断点1修复] 添加结构化指导字段
                    "guidance_type": guidance_type,
                    "enforce_change": enforce_change,
                    "guidance_reason": guidance_reason,
                    "guidance_target_url": guidance_target_url
                }

                # [战略上下文更新] 内网模式获取Shell时更新战略上下文
                updated_context = update_strategic_context_after_node(state, "verifier", result_dict)
                if updated_context:
                    result_dict["strategic_context"] = updated_context

                # 记录战略决策
                try:
                    from router import record_strategic_decision
                    decision_updates = record_strategic_decision(
                        state,
                        {
                            "timestamp": time.time(),
                            "node": "verifier",
                            "decision_type": "validation",
                            "action": "shell_obtained",
                            "reason": "内网模式检测到活跃Shell会话",
                            "confidence": 0.9,
                            "outcome": "success",
                            "target": current_url
                        }
                    )
                    result_dict.update(decision_updates)
                except Exception as e:
                    logger.warning(f"记录战略决策失败: {e}")

                return result_dict

            # 检查是否还有未尝试的payload
            exploit_keywords = state.get("exploit_keywords", {})
            if exploit_keywords and len(failed_payloads) < 3:
                # 还有尝试空间，标记继续攻击
                continue_attack = True
                log(f"   🔄 [内网] 标记继续攻击，尝试其他payload")

                # 从候选中提取可能的payload
                for cand in candidates[:3]:
                    if cand.get("context", {}).get("curl_command"):
                        remaining_payloads.append({
                            "type": cand.get("type"),
                            "payload": cand["context"]["curl_command"],
                            "source": "verified_vuln"
                        })

        if node_decision == "abandon" and current_url and current_url in node_status:
            log(f"   🛑 AI决策: 放弃节点 {current_url}")
            log(f"   💡 原因: {failure_analysis[:100] if failure_analysis else 'N/A'}")
            node_status[current_url]["status"] = "abandoned"
        elif tactical_guidance:
            log(f"   💡 分析: {failure_analysis[:100] if failure_analysis else 'N/A'}")
            log(f"   🎯 建议: {tactical_guidance[:100]}")

        # 如果有聚焦场景，显示进度
        if focused_scene:
            log(f"   📍 场景 [{focused_scene}] 攻击尝试: {scene_attack_attempts}")

        result_dict = {
            "failure_weighted_score": state.get("failure_weighted_score", 0) + failure_severity,
            "execution_steps": state.get("execution_steps", 0) + 1,
            "node_attack_status": node_status,
            "vuln_candidates": candidates,
            "latest_tactical_guidance": tactical_guidance,
            # [断点1修复] 添加结构化指导字段
            "guidance_type": guidance_type,
            "enforce_change": enforce_change,
            "guidance_reason": guidance_reason,
            "guidance_target_url": guidance_target_url,
            "scene_attack_attempts": scene_attack_attempts,
            "continue_attack": continue_attack,
            "remaining_payloads": remaining_payloads
        }
        if failed_payloads:
            result_dict["failed_payloads"] = failed_payloads

        # [战略上下文更新] 更新战略上下文
        updated_context = update_strategic_context_after_node(state, "verifier", result_dict)
        if updated_context:
            result_dict["strategic_context"] = updated_context

        # 记录战略决策
        try:
            from router import record_strategic_decision
            decision_updates = record_strategic_decision(
                state,
                {
                    "timestamp": time.time(),
                    "node": "verifier",
                    "decision_type": "validation",
                    "action": node_decision if node_decision else "continue",
                    "reason": failure_analysis[:100] if failure_analysis else "攻击无效",
                    "confidence": 1.0 - failure_severity,
                    "outcome": "failed",
                    "target": current_url
                }
            )
            result_dict.update(decision_updates)
        except Exception as e:
            logger.warning(f"记录战略决策失败: {e}")

        return result_dict

    except Exception as e:
        log(f"   ❌ 解析异常: {e}")
        result_dict = {
            "failure_weighted_score": state.get("failure_weighted_score", 0) + 0.8,
            "execution_steps": state.get("execution_steps", 0) + 1,
            "node_attack_status": node_status,
            "vuln_candidates": candidates,
            "guidance_type": "continue",
            "enforce_change": False,
            "guidance_reason": f"解析异常: {str(e)[:50]}",
            "guidance_target_url": ""
        }

        # [战略上下文更新] 异常时也更新战略上下文，记录失败
        updated_context = update_strategic_context_after_node(state, "verifier", result_dict)
        if updated_context:
            result_dict["strategic_context"] = updated_context

        # 记录战略决策
        try:
            from router import record_strategic_decision
            decision_updates = record_strategic_decision(
                state,
                {
                    "timestamp": time.time(),
                    "node": "verifier",
                    "decision_type": "validation",
                    "action": "error",
                    "reason": f"解析异常: {str(e)[:50]}",
                    "confidence": 0.0,
                    "outcome": "error",
                    "target": current_url
                }
            )
            result_dict.update(decision_updates)
        except Exception as ex:
            logger.warning(f"记录战略决策失败: {ex}")

        return result_dict





# ==============================================================================
# 6. 图编排 (Graph Orchestration)
# ==============================================================================

# 创建状态图
workflow = StateGraph(CTFState) # type: ignore

# 辅助函数：包装节点以支持禁用功能
def wrap_node(name: str, func: Callable) -> Callable:
    """包装节点函数，支持运行时禁用"""
    return create_disabled_wrapper(name, func)

# 添加所有兵种节点 [P3优化: 移除reflector]
# 注意：所有节点都通过 wrap_node 包装，支持运行时禁用
workflow.add_node("challenge_type_detector", wrap_node("challenge_type_detector", challenge_type_detector_node))  # type: ignore # CTF类型检测器
workflow.add_node("recon", wrap_node("recon", recon_node))  # type: ignore # 侦察兵
workflow.add_node("analyst", wrap_node("analyst", analyst_node))  # type: ignore # 分析兵
workflow.add_node("strategy_filter", wrap_node("strategy_filter", strategy_filter_node))  # type: ignore # 策略过滤器
workflow.add_node("mode_manager", wrap_node("mode_manager", mode_manager_node))  # type: ignore # 模式决策器
workflow.add_node("attacker", wrap_node("attacker", attacker_node))  # type: ignore # 攻击兵
workflow.add_node("explorer", wrap_node("explorer", explorer_node))  # type: ignore # 探索兵
workflow.add_node("innovator", wrap_node("innovator", innovator_node))  # type: ignore # 头脑风暴
workflow.add_node("verifier", wrap_node("verifier", verifier_node))  # type: ignore # 核验兵 [P3合并]
workflow.add_node("evolution", wrap_node("evolution", evolution_node))  # type: ignore # 进化闭环

# Token压缩节点 (可选启用)
if COMPRESSOR_AVAILABLE:
    workflow.add_node("compressor", compressor_node)  # type: ignore # Token压缩

# 内网渗透节点 (可选启用)
if INTERNAL_NETWORK_AVAILABLE:
    workflow.add_node("internal_recon", wrap_node("internal_recon", internal_recon_node))  # type: ignore # 内网侦察
    workflow.add_node("lateral_move", wrap_node("lateral_move", lateral_move_node))  # type: ignore # 横向移动
    workflow.add_node("privilege_escalation", wrap_node("privilege_escalation", privilege_escalation_node))  # type: ignore # 权限提升
    workflow.add_node("credential_gather", wrap_node("credential_gather", credential_gather_node))  # type: ignore # 凭据收集
    workflow.add_node("flag_search", wrap_node("flag_search", flag_search_node))  # type: ignore # Flag搜索节点
    workflow.add_node("persistence", wrap_node("persistence", persistence_node))  # type: ignore # 持久化节点
    workflow.add_node("post_exploit", wrap_node("post_exploit", post_exploit_node))  # type: ignore # 后渗透节点
    workflow.add_node("upload_tools", wrap_node("upload_tools", upload_tools_node))  # type: ignore # 工具上传节点
    workflow.add_node("setup_tunnel", wrap_node("setup_tunnel", setup_tunnel_node))  # type: ignore # 隧道搭建节点

# Crypto节点 (可选启用)
if CRYPTO_AVAILABLE:
    workflow.add_node("crypto_analyst", wrap_node("crypto_analyst", crypto_analyst_node))  # type: ignore # 加密分析
    workflow.add_node("crypto_solver", wrap_node("crypto_solver", crypto_solver_node))  # type: ignore # 密码破解

# Pwn节点 (可选启用)
if PWN_AVAILABLE:
    workflow.add_node("pwn_analyst", wrap_node("pwn_analyst", pwn_analyst_node))  # type: ignore # Pwn分析
    workflow.add_node("pwn_exploiter", wrap_node("pwn_exploiter", pwn_exploiter_node))  # type: ignore # Pwn利用

# Reverse节点 (可选启用)
if REVERSE_AVAILABLE:
    workflow.add_node("reverse_analyst", wrap_node("reverse_analyst", reverse_analyst_node))  # type: ignore # 逆向分析
    workflow.add_node("reverse_decompiler", wrap_node("reverse_decompiler", reverse_decompiler_node))  # type: ignore # 反编译

# Misc节点 (可选启用)
if MISC_AVAILABLE:
    workflow.add_node("misc_analyst", wrap_node("misc_analyst", misc_analyst_node))  # type: ignore # Misc分析
    workflow.add_node("misc_extractor", wrap_node("misc_extractor", misc_extractor_node))  # type: ignore # Misc提取

# Cloud Security节点 (可选启用)
if CLOUD_SECURITY_AVAILABLE:
    workflow.add_node("cloud_recon", wrap_node("cloud_recon", cloud_recon_node))  # type: ignore
    workflow.add_node("cloud_enum", wrap_node("cloud_enum", cloud_enum_node))  # type: ignore
    workflow.add_node("cloud_exploit", wrap_node("cloud_exploit", cloud_exploit_node))  # type: ignore
    workflow.add_node("cloud_escalate", wrap_node("cloud_escalate", cloud_escalate_node))  # type: ignore

# AI Security节点 (可选启用)
if AI_SECURITY_AVAILABLE:
    workflow.add_node("ai_detect", wrap_node("ai_detect", ai_detect_node))  # type: ignore
    workflow.add_node("ai_probe", wrap_node("ai_probe", ai_probe_node))  # type: ignore
    workflow.add_node("ai_exploit", wrap_node("ai_exploit", ai_exploit_node))  # type: ignore
    workflow.add_node("ai_exfiltrate", wrap_node("ai_exfiltrate", ai_exfiltrate_node))  # type: ignore

# 0. CTF类型检测路由
def _route_from_challenge_detector(state: CTFState) -> str:
    """根据检测到的CTF类型路由到对应的入口节点"""
    # 优先检查特定模式
    if state.get("internal_mode", False) and INTERNAL_NETWORK_AVAILABLE:
        return "internal_recon"
    if state.get("pwn_mode", False) and PWN_AVAILABLE:
        return "pwn_analyst"
    if state.get("reverse_mode", False) and REVERSE_AVAILABLE:
        return "reverse_analyst"
    if state.get("crypto_mode", False) and CRYPTO_AVAILABLE:
        return "crypto_analyst"
    if state.get("misc_mode", False) and MISC_AVAILABLE:
        return "misc_analyst"
    if state.get("cloud_mode", False) and CLOUD_SECURITY_AVAILABLE:
        return "cloud_recon"
    if state.get("ai_mode", False) and AI_SECURITY_AVAILABLE:
        return "ai_detect"
    # 默认走Web流程
    return "recon"

# 构建类型检测器的路由映射
_detector_routes = {
    "recon": "recon"  # Web模式默认走侦察
}

if INTERNAL_NETWORK_AVAILABLE:
    _detector_routes["internal_recon"] = "internal_recon"
if PWN_AVAILABLE:
    _detector_routes["pwn_analyst"] = "pwn_analyst"
if REVERSE_AVAILABLE:
    _detector_routes["reverse_analyst"] = "reverse_analyst"
if CRYPTO_AVAILABLE:
    _detector_routes["crypto_analyst"] = "crypto_analyst"
if MISC_AVAILABLE:
    _detector_routes["misc_analyst"] = "misc_analyst"
if CLOUD_SECURITY_AVAILABLE:
    _detector_routes["cloud_recon"] = "cloud_recon"
if AI_SECURITY_AVAILABLE:
    _detector_routes["ai_detect"] = "ai_detect"

workflow.add_edge(START, "challenge_type_detector")  # type: ignore
workflow.add_conditional_edges(
    "challenge_type_detector",
    _route_from_challenge_detector,
    _detector_routes
)

# 1. 线性分析流: 侦察 -> 分析 -> 过滤 -> 决策
workflow.add_edge("recon", "analyst")
workflow.add_edge("analyst", "strategy_filter")
workflow.add_edge("strategy_filter", "mode_manager")

# 2. 模式分流: 根据决策结果进入不同执行路径
# 统一处理所有模式切换
def _route_from_mode_manager(state: CTFState) -> str:
    """统一的mode_manager路由函数，处理所有CTF方向模式，集成战略上下文"""
    # 优先检查内网模式
    if state.get("internal_mode", False) and INTERNAL_NETWORK_AVAILABLE:
        return "internal_recon"
    # 检查Crypto模式
    if state.get("crypto_mode", False) and CRYPTO_AVAILABLE:
        return "crypto_analyst"
    # 检查Pwn模式
    if state.get("pwn_mode", False) and PWN_AVAILABLE:
        return "pwn_analyst"
    # 检查Reverse模式
    if state.get("reverse_mode", False) and REVERSE_AVAILABLE:
        return "reverse_analyst"
    # 检查Misc模式
    if state.get("misc_mode", False) and MISC_AVAILABLE:
        return "misc_analyst"
    # 检查Cloud模式
    if state.get("cloud_mode", False) and CLOUD_SECURITY_AVAILABLE:
        return "cloud_recon"
    # 检查AI模式
    if state.get("ai_mode", False) and AI_SECURITY_AVAILABLE:
        return "ai_detect"

    # Web模式：使用战略上下文路由
    strategic_result = route_with_strategic_context(state, "mode_manager")
    next_node = strategic_result.get("next_node", "exploit")

    # 记录战略路由决策日志
    strategic_context = strategic_result.get("strategic_context", {})
    if strategic_context:
        logger.info(f"[StrategicRoute] Web模式路由决策: {next_node}, 理由: {strategic_result.get('reasoning', 'N/A')}")

    return next_node

# 构建基础路由映射
_mode_manager_routes = {
    "exploit": "attacker",
    "explore": "explorer",
    "innovate": "innovator",
    "recon": "recon", # 支持跳转回侦察兵
    "end": END
}

# 条件添加内网模块路由
if INTERNAL_NETWORK_AVAILABLE:
    _mode_manager_routes["internal_recon"] = "internal_recon"

# 条件添加Crypto模块路由
if CRYPTO_AVAILABLE:
    _mode_manager_routes["crypto_analyst"] = "crypto_analyst"

# 条件添加Pwn模块路由
if PWN_AVAILABLE:
    _mode_manager_routes["pwn_analyst"] = "pwn_analyst"

# 条件添加Reverse模块路由
if REVERSE_AVAILABLE:
    _mode_manager_routes["reverse_analyst"] = "reverse_analyst"

# 条件添加Misc模块路由
if MISC_AVAILABLE:
    _mode_manager_routes["misc_analyst"] = "misc_analyst"

# Token压缩节点路由（可选启用）
if COMPRESSOR_AVAILABLE:
    # mode_manager后先压缩再路由
    workflow.add_edge("mode_manager", "compressor")
    # 构建压缩器路由映射（添加compressor）
    _compressor_routes = _mode_manager_routes.copy()
    _compressor_routes["compressor"] = "compressor"
    workflow.add_conditional_edges(
        "compressor",
        _route_from_mode_manager,
        _compressor_routes
    )
else:
    # 原有逻辑：直接从mode_manager路由
    workflow.add_conditional_edges(
        "mode_manager",
        _route_from_mode_manager,
        _mode_manager_routes
    )

# 3. 分支回归逻辑
workflow.add_edge("explorer", "mode_manager")  # 探索后重新决策
workflow.add_edge("innovator", "strategy_filter")  # 创新后注入规则到过滤器

# 3.5 [智能流转] attacker 条件路由 - 支持绕过 verifier
def _route_from_attacker(state: CTFState) -> str:
    """
    attacker 后智能路由

    根据 ai_flow_controller 的决策决定下一步：
    - flow_decision='continue_attack' -> 直接返回 attacker 继续攻击
    - flow_decision='report_flag' -> 进化流程
    - 默认 -> verifier 验证
    """
    # 检查 flow_decision（从state读取，attacker_node已设置）
    flow_decision = state.get("flow_decision", "")

    if flow_decision == "continue_attack":
        # 重置标志，避免重复路由
        logger.info("[智能流转] 绕过 verifier，直接继续攻击")
        # 返回attacker前重置flow_decision，避免死循环
        # 注意：这里返回的更新会在下一次attacker调用前合并
        return "attacker"

    if flow_decision == "report_flag":
        logger.info("[智能流转] 发现 FLAG，进入进化流程")
        return "evolution"

    # 默认进入 verifier
    return "verifier"

_attacker_routes = {
    "verifier": "verifier",
    "attacker": "attacker",  # 绕过 verifier 继续攻击
    "evolution": "evolution",  # 发现 FLAG 直接进化
}

workflow.add_conditional_edges(
    "attacker",
    _route_from_attacker,
    _attacker_routes
)

# 4. [P3优化] 验证后分流: 成功则进化，shell则后渗透，失败则回到mode_manager
_verifier_routes = {
    "evolution": "evolution",
    "mode_manager": "mode_manager",  # 直接回到决策
    "attacker": "attacker",  # [内网模式] 继续攻击
}

# 添加后渗透路由（如果内网模块可用）
if INTERNAL_NETWORK_AVAILABLE:
    _verifier_routes["post_exploit"] = "post_exploit"
    _verifier_routes["internal_recon"] = "internal_recon"

workflow.add_conditional_edges(
    "verifier",
    lambda state: route_verify(state, "verifier"),
    _verifier_routes
)

# 6. 进化结束
workflow.add_edge("evolution", END)

# 7. 内网渗透路由 (Internal Network Routing)
if INTERNAL_NETWORK_AVAILABLE:
    # 内网节点的统一路由映射（所有内网节点共享）
    _internal_route_map = {
        "internal_recon": "internal_recon",
        "credential_gather": "credential_gather",
        "lateral_move": "lateral_move",
        "privilege_escalation": "privilege_escalation",
        "flag_search": "flag_search",
        "persistence": "persistence",
        "upload_tools": "upload_tools",
        "setup_tunnel": "setup_tunnel",
        "mode_manager": "mode_manager"
    }

    # 内网侦察/凭据收集/横向移动/权限提升/Flag搜索/持久化 共用同一路由映射
    for _node_name in ["internal_recon", "credential_gather", "lateral_move",
                       "privilege_escalation", "flag_search", "persistence"]:
        workflow.add_conditional_edges(
            _node_name,
            lambda state, _n=_node_name: route_internal_mode(state, _n),
            _internal_route_map
        )

    # 后渗透节点路由
    workflow.add_conditional_edges(
        "post_exploit",
        lambda state: route_post_exploit(state, "post_exploit"),
        {
            "upload_tools": "upload_tools",
            "setup_tunnel": "setup_tunnel",
            "internal_recon": "internal_recon",
            "mode_manager": "mode_manager"
        }
    )

    # 工具上传后路由
    workflow.add_conditional_edges(
        "upload_tools",
        lambda state: route_post_exploit(state, "upload_tools"),
        {
            "upload_tools": "upload_tools",
            "setup_tunnel": "setup_tunnel",
            "internal_recon": "internal_recon",
            "mode_manager": "mode_manager"
        }
    )

    # 隧道搭建后路由
    workflow.add_conditional_edges(
        "setup_tunnel",
        lambda state: route_post_exploit(state, "setup_tunnel"),
        {
            "internal_recon": "internal_recon",
            "mode_manager": "mode_manager"
        }
    )

# 8. Crypto路由 (Crypto Routing)
if CRYPTO_AVAILABLE:
    # Crypto分析后路由
    def _route_crypto_analyst(state: CTFState) -> str:
        """Crypto分析师路由"""
        crypto_analysis = state.get("crypto_analysis", {})
        if crypto_analysis.get("status") == "analyzed":
            return "crypto_solver"
        return "mode_manager"

    workflow.add_conditional_edges(
        "crypto_analyst",
        _route_crypto_analyst,
        {
            "crypto_solver": "crypto_solver",
            "mode_manager": "mode_manager"
        }
    )

    # Crypto求解后路由
    def _route_crypto_solver(state: CTFState) -> str:
        """Crypto求解器路由"""
        potential_flags = state.get("potential_flags", [])
        if potential_flags:
            return "verifier"  # 有潜在flag，去验证
        return "mode_manager"

    workflow.add_conditional_edges(
        "crypto_solver",
        _route_crypto_solver,
        {
            "verifier": "verifier",
            "mode_manager": "mode_manager"
        }
    )

# 9. Pwn路由 (Pwn Routing)
if PWN_AVAILABLE:
    # Pwn分析后路由
    def _route_pwn_analyst(state: CTFState) -> str:
        """Pwn分析师路由"""
        pwn_analysis = state.get("pwn_analysis", {})
        if pwn_analysis.get("status") == "analyzed":
            return "pwn_exploiter"
        return "mode_manager"

    workflow.add_conditional_edges(
        "pwn_analyst",
        _route_pwn_analyst,
        {
            "pwn_exploiter": "pwn_exploiter",
            "mode_manager": "mode_manager"
        }
    )

    # Pwn利用后路由
    def _route_pwn_exploiter(state: CTFState) -> str:
        """Pwn利用器路由"""
        exploit_info = state.get("exploit_info", {})
        if exploit_info.get("status") == "ready":
            return "mode_manager"  # 继续执行
        return "mode_manager"

    workflow.add_conditional_edges(
        "pwn_exploiter",
        _route_pwn_exploiter,
        {
            "mode_manager": "mode_manager"
        }
    )

# 10. Reverse路由 (Reverse Routing)
if REVERSE_AVAILABLE:
    # Reverse分析后路由
    def _route_reverse_analyst(state: CTFState) -> str:
        """Reverse分析师路由"""
        reverse_info = state.get("reverse_info", {})
        if reverse_info.get("status") == "analyzed":
            return "reverse_decompiler"
        return "mode_manager"

    workflow.add_conditional_edges(
        "reverse_analyst",
        _route_reverse_analyst,
        {
            "reverse_decompiler": "reverse_decompiler",
            "mode_manager": "mode_manager"
        }
    )

    # Reverse反编译后路由
    def _route_reverse_decompiler(state: CTFState) -> str:
        """Reverse反编译器路由"""
        potential_flags = state.get("potential_flags", [])
        if potential_flags:
            return "verifier"
        return "mode_manager"

    workflow.add_conditional_edges(
        "reverse_decompiler",
        _route_reverse_decompiler,
        {
            "verifier": "verifier",
            "mode_manager": "mode_manager"
        }
    )

# 11. Misc路由 (Misc Routing)
if MISC_AVAILABLE:
    # Misc分析后路由
    def _route_misc_analyst(state: CTFState) -> str:
        """Misc分析师路由"""
        misc_analysis = state.get("misc_analysis", {})
        if misc_analysis.get("status") == "analyzed":
            return "misc_extractor"
        return "mode_manager"

    workflow.add_conditional_edges(
        "misc_analyst",
        _route_misc_analyst,
        {
            "misc_extractor": "misc_extractor",
            "mode_manager": "mode_manager"
        }
    )

    # Misc提取后路由
    def _route_misc_extractor(state: CTFState) -> str:
        """Misc提取器路由"""
        potential_flags = state.get("potential_flags", [])
        if potential_flags:
            return "verifier"
        return "mode_manager"

    workflow.add_conditional_edges(
        "misc_extractor",
        _route_misc_extractor,
        {
            "verifier": "verifier",
            "mode_manager": "mode_manager"
        }
    )

# Cloud Security路由
if CLOUD_SECURITY_AVAILABLE:
    def _route_cloud_recon(state: CTFState) -> str:
        if state.get("cloud_phase") == "enum":
            return "cloud_enum"
        return "mode_manager"

    workflow.add_conditional_edges("cloud_recon", _route_cloud_recon,
        {"cloud_enum": "cloud_enum", "mode_manager": "mode_manager"})

    def _route_cloud_enum(state: CTFState) -> str:
        if state.get("cloud_phase") == "exploit":
            return "cloud_exploit"
        return "mode_manager"

    workflow.add_conditional_edges("cloud_enum", _route_cloud_enum,
        {"cloud_exploit": "cloud_exploit", "mode_manager": "mode_manager"})

    def _route_cloud_exploit(state: CTFState) -> str:
        if state.get("cloud_phase") == "escalate":
            return "cloud_escalate"
        if state.get("potential_flags"):
            return "verifier"
        return "mode_manager"

    workflow.add_conditional_edges("cloud_exploit", _route_cloud_exploit,
        {"cloud_escalate": "cloud_escalate", "verifier": "verifier", "mode_manager": "mode_manager"})

    workflow.add_conditional_edges("cloud_escalate",
        lambda s: "verifier" if s.get("potential_flags") else "mode_manager",
        {"verifier": "verifier", "mode_manager": "mode_manager"})

# AI Security路由
if AI_SECURITY_AVAILABLE:
    def _route_ai_detect(state: CTFState) -> str:
        if state.get("ai_phase") == "probe":
            return "ai_probe"
        return "mode_manager"

    workflow.add_conditional_edges("ai_detect", _route_ai_detect,
        {"ai_probe": "ai_probe", "mode_manager": "mode_manager"})

    def _route_ai_probe(state: CTFState) -> str:
        if state.get("ai_phase") == "exploit":
            return "ai_exploit"
        return "mode_manager"

    workflow.add_conditional_edges("ai_probe", _route_ai_probe,
        {"ai_exploit": "ai_exploit", "mode_manager": "mode_manager"})

    def _route_ai_exploit(state: CTFState) -> str:
        if state.get("ai_phase") == "exfiltrate":
            return "ai_exfiltrate"
        if state.get("potential_flags"):
            return "verifier"
        return "mode_manager"

    workflow.add_conditional_edges("ai_exploit", _route_ai_exploit,
        {"ai_exfiltrate": "ai_exfiltrate", "verifier": "verifier", "mode_manager": "mode_manager"})

    workflow.add_conditional_edges("ai_exfiltrate",
        lambda s: "verifier" if s.get("potential_flags") else "mode_manager",
        {"verifier": "verifier", "mode_manager": "mode_manager"})

# 编译图 - 启用内存检查点用于状态持久化
checkpointer = MemorySaver()
app = workflow.compile(checkpointer=checkpointer)


# ==============================================================================
# 7. 主入口 (Main)
# ==============================================================================

def system_check():
    """系统功能自检 - 全量模型与工具链测试"""
    log("🔄 [System] 开始系统功能自检...")

    # 1. 检查所有节点使用的模型
    models_to_test = {
        "分析兵 (Analyst)": config.ANALYST_MODEL,
        "攻击兵 (Attacker)": config.ATTACKER_MODEL,
        "核验兵 (Verifier)": config.VERIFIER_MODEL,
        "探索兵 (Explorer)": config.EXPLORER_MODEL,
        "头脑风暴 (Innovator)": config.INNOVATOR_MODEL,
        "变化检测 (Detection)": config.CHANGE_DETECTION_MODEL
    }

    log("   -> 检查全量 LLM 模型连通性...")
    for role, model_name in models_to_test.items():
        try:
            # 使用极短的超时进行快速自检
            test_resp = llm_client.call_chat_completion(
                model=model_name,
                messages=[{"role": "user", "content": "ping"}],
                temperature=0.1,
                max_tokens=5
            )
            if test_resp:
                log(f"   ✅ {role} [{model_name}]: 响应正常")
            else:
                log(f"   ⚠️ {role} [{model_name}]: 无响应")
        except Exception as e:
            log(f"   ❌ {role} [{model_name}] 异常: {e}")

    # 2. 检查关键工具
    log("   -> 检查关键工具挂载...")
    tools_to_check = ["dirsearch", "sqlmap"]
    for t in tools_to_check:
        tool_instances = ToolRegistry.get_tools(t) # Try to match by name or vulnerability
        # Just check if registered
        is_registered = any(tool.name() == t for tool_list in ToolRegistry._tools.values() for tool in tool_list)
        if is_registered:
             log(f"   ✅ 工具 {t} 已注册")
        else:
             log(f"   ⚠️ 工具 {t} 未找到注册信息")

    # 3. 检查自我纠错模块
    if SELF_CORRECTION_AVAILABLE:
        log("   -> 检查自我纠错模块...")
        log(f"   ✅ 自我纠错模块已加载")
    else:
        log("   ⚠️ 自我纠错模块未加载")

    # 4. 检查内网渗透模块
    if INTERNAL_NETWORK_AVAILABLE:
        log("   -> 检查内网渗透模块...")
        log(f"   ✅ 内网渗透模块已加载")
    else:
        log("   ⚠️ 内网渗透模块未加载")

    # 5. 检查Crypto模块
    if CRYPTO_AVAILABLE:
        log("   -> 检查密码学模块...")
        log(f"   ✅ 密码学模块已加载")
    else:
        log("   ⚠️ 密码学模块未加载")

    # 6. 检查性能监控模块
    if PERFORMANCE_AVAILABLE:
        log("   -> 检查性能监控模块...")
        status = get_system_status()
        log(f"   ✅ 性能监控模块已加载 (状态: {status.get('status', 'unknown')})")
    else:
        log("   ⚠️ 性能监控模块未加载")

    log("[System] 自检完成。\n")

def _start_internal_network_services():
    """
    启动内网渗透基础设施

    启动服务:
    1. HTTP服务器 - 用于工具分发
    2. frps服务 - 用于接收反向隧道
    """
    log("[InternalNet] 启动内网渗透基础设施...")

    # 1. 检查并启动HTTP服务器
    if config.LOCAL_PUBLIC_IP:
        try:
            from remote_executor.http_server import start_http_server, check_tools_directory

            # 检查工具目录
            tools_status = check_tools_directory()
            log(f"   📁 工具目录状态: {sum(s.get('count', 0) for s in tools_status.values())} 个文件")

            # 启动HTTP服务器 (根目录为/opt，包含tools、frp、linux子目录)
            http_thread = start_http_server(
                port=config.HTTP_SERVER_PORT,
                directory="/opt",  # HTTP服务器根目录，提供tools/frp/linux访问
                daemon=True
            )

            if http_thread:
                log(f"   ✅ HTTP服务器已启动: {config.HTTP_SERVER}")
            else:
                log(f"   ⚠️ HTTP服务器启动失败或端口被占用")

        except ImportError:
            log("   ⚠️ HTTP服务器模块未加载")
        except Exception as e:
            log(f"   ⚠️ HTTP服务器启动异常: {e}")

        # 2. 检查并启动frps
        try:
            from remote_executor.tunnel_manager import start_local_frps, check_frps_status

            # 检查frps是否已运行
            if check_frps_status(config.FRP_SERVER_PORT):
                log(f"   ✅ frps已在运行: 端口 {config.FRP_SERVER_PORT}")
            else:
                # 启动frps
                frps_process = start_local_frps(
                    port=config.FRP_SERVER_PORT,
                    frp_dir=config.FRP_DIR
                )

                if frps_process:
                    log(f"   ✅ frps已启动: 端口 {config.FRP_SERVER_PORT}")
                else:
                    log(f"   ⚠️ frps启动失败，请检查 {config.FRP_DIR}")

        except ImportError:
            log("   ⚠️ 隧道管理模块未加载")
        except Exception as e:
            log(f"   ⚠️ frps启动异常: {e}")
    else:
        log("   ⚠️ LOCAL_PUBLIC_IP未配置，内网渗透功能受限")
        log("   💡 请在config.yaml中设置LOCAL_PUBLIC_IP以启用完整功能")

    log("[InternalNet] 基础设施启动完成")

def main():
    """主运行函数

    执行流程:
        1. 解析命令行参数
        2. 加载配置
        3. 初始化状态
        4. 运行工作流
        5. 输出结果
    """
    parser = argparse.ArgumentParser(description="CTF-Agent v2.5")
    parser.add_argument("--skip", action="store_true", help="跳过系统自检")
    args = parser.parse_args()

    log("\n🚀 CTF-Agent v2.5 启动")
    log("=" * 50)

    # 加载最小工具集（节省内存）
    # 工具会在实际使用时按场景动态加载
    load_minimal_tools(ToolRegistry())
    log("💡 工具将按需加载（内存优化模式）")

    # [清理] 启动时清理过期缓存
    page_diff_manager.cleanup_cache(max_age_seconds=86400) # 保留24小时

    # =========================================================================
    # [新增] 启动内网渗透基础设施
    # =========================================================================
    _start_internal_network_services()

    # 执行系统自检 (除非指定了 -skip)
    if args.skip:
        log("⏭️ [System] 跳过系统自检。")
    else:
        system_check()

    # 主循环：支持连续出题
    while True:
        try:
            # 获取用户输入 - 只需要URL
            log("\n📝 请输入目标 URL (输入 q 退出):")
            target_url = input("   URL: ").strip()

            # 退出检查
            if target_url.lower() == 'q':
                log("\n👋 感谢使用，再见！")
                return

            while not target_url:
                log("   ❌ URL 不能为空！")
                target_url = input("   URL (输入 q 退出): ").strip()
                if target_url.lower() == 'q':
                    log("\n👋 感谢使用，再见！")
                    return

            # 自动识别URL并标准化
            target_url = normalize_url(target_url)

            # 自动提取环境信息
            task_name, task_description = extract_target_info(target_url)

            log("\n" + "=" * 50)
            log(f"🎯 目标锁定: {task_name}")
            log(f"📝 识别描述: {task_description}")
            log(f"🔗 URL: {target_url}")
            log("=" * 50)

            # 运行任务
            result = run_single_task(task_name, task_description, target_url)

            # 输出结果
            log("\n" + "=" * 50)
            log("🏁 任务结束")
            if result.get('found_flag'):
                log(f"🎉 FLAG: {result.get('final_flag', result.get('found_flag'))}")
            else:
                log(f"📊 最终状态: {result.get('current_mode')}")
                log("❌ 未找到 Flag")

            # 询问是否继续
            log("\n" + "-" * 50)
            choice = input("继续下一题？(y/n): ").strip().lower()
            if choice != 'y':
                log("\n👋 感谢使用，再见！")
                return

        except KeyboardInterrupt:
            log("\n\n⏹️ 用户中断，正在退出...")
            log("👋 再见！")
            return
        except Exception as e:
            log(f"\n❌ 运行出错: {e}")
            choice = input("是否继续下一题？(y/n): ").strip().lower()
            if choice != 'y':
                return


def _load_tools_for_task(task_description: str, target_url: str):
    """
    根据任务类型动态加载工具（内存优化）

    只加载当前任务需要的工具，减少内存占用

    Args:
        task_description: 任务描述
        target_url: 目标URL
    """
    from tools import load_tools_by_category

    # 判断任务类型
    desc_lower = task_description.lower() if task_description else ""
    url_lower = target_url.lower() if target_url else ""

    # 内网渗透特征
    internal_keywords = ["内网", "internal", "ad域", "active directory", "域控",
                        "lateral", "privilege", "credential", "post-exploit"]
    is_internal = any(kw in desc_lower or kw in url_lower for kw in internal_keywords)

    # Web安全特征
    web_keywords = ["web", "http", "https", "sql", "xss", "ssti", "ssrf",
                   "injection", "upload", "rce", "漏洞"]
    is_web = any(kw in desc_lower or kw in url_lower for kw in web_keywords)

    # 云安全特征
    cloud_keywords = ["cloud", "aws", "azure", "gcp", "s3", "bucket", "kubernetes",
                     "容器", "docker", "云"]
    is_cloud = any(kw in desc_lower or kw in url_lower for kw in cloud_keywords)

    # AI安全特征
    ai_keywords = ["ai", "llm", "gpt", "chatbot", "prompt", "ai安全", "模型"]
    is_ai = any(kw in desc_lower or kw in url_lower for kw in ai_keywords)

    # 加载对应工具
    categories = ["core"]  # 始终加载核心工具

    if is_internal:
        categories.append("internal")
        log("📦 加载内网渗透工具集...")
    elif is_cloud or is_ai:
        categories.append("cloud_ai")
        log("📦 加载云/AI安全工具集...")
    else:
        # 默认加载Web工具
        categories.append("web")
        log("📦 加载Web渗透工具集...")

    loaded = load_tools_by_category(categories, ToolRegistry())
    log(f"✅ 已加载 {loaded} 个工具")


def run_single_task(task_name: str, task_description: str, target_url: str,
                    task_id: str = None, cancel_check: Callable = None) -> dict:
    """
    运行单个CTF任务

    Args:
        task_name: 任务名称
        task_description: 任务描述
        target_url: 目标URL
        task_id: 任务ID（用于取消检查）
        cancel_check: 取消检查函数（可选）

    Returns:
        任务结果字典
    """
    # 重置路由守卫，避免上一个任务的状态影响
    from router import reset_route_guard
    reset_route_guard()

    # 根据任务类型动态加载工具（内存优化）
    _load_tools_for_task(task_description, target_url)

    # 使用统一的默认状态生成器，确保字段同步
    from state_v2 import get_default_state
    initial_state: CTFState = get_default_state(task_name, task_description, target_url)

    # 设置当前任务ID（用于取消检查）
    if task_id:
        try:
            from task_cancel_manager import cancel_manager
            cancel_manager.set_current_task(task_id)
        except ImportError:
            pass

    # 运行工作流
    log("\n⏳ 开始攻击...")
    config_params = {
        "configurable": {"thread_id": f"ctf_task_{int(time.time())}"},
        "recursion_limit": 500
    }

    try:
        # 使用 stream() 替代 invoke() 以支持取消检查
        result = None
        accumulated_state = dict(initial_state)  # 维护完整状态
        for event in app.stream(initial_state, config=config_params):
            # 检查取消状态
            if cancel_check and cancel_check():
                log("⚠️ 任务被取消，停止执行")
                return {"current_mode": "end", "found_flag": False, "cancelled": True}

            if task_id:
                try:
                    from task_cancel_manager import cancel_manager, TaskCancelledError
                    cancel_manager.check_and_raise(task_id)
                except ImportError:
                    pass
                except TaskCancelledError as e:
                    log(f"⚠️ 任务被取消: {e}")
                    return {"current_mode": "end", "found_flag": False, "cancelled": True}

            # 处理事件
            if event:
                # 提取最新状态（LangGraph stream 返回的是节点输出）
                for node_name, node_output in event.items():
                    if isinstance(node_output, dict):
                        result = node_output
                        # 合并节点输出到完整状态
                        for key, value in node_output.items():
                            accumulated_state[key] = value

                        # 触发节点回调（如果有）- 传递完整状态
                        if hasattr(app, '_node_callbacks') and task_id in app._node_callbacks:
                            try:
                                app._node_callbacks[task_id](node_name, accumulated_state)
                            except Exception as cb_e:
                                log(f"回调错误: {cb_e}")

                # 检查终止状态 - 主动退出循环避免阻塞
                if accumulated_state.get("found_flag"):
                    log("✅ 已找到 FLAG，退出执行循环")
                    break
                if accumulated_state.get("current_mode") == "end":
                    log("📍 工作流已结束，退出执行循环")
                    break

        # 返回最终结果 - 使用累积状态而非最后一个节点输出
        # 这样可以包含所有节点的状态（如 site_topology）
        final_result = accumulated_state if accumulated_state else {"current_mode": "end", "found_flag": False}

        # 清理不需要返回的大字段
        for key in ["raw_html_snippet", "baseline_response", "page_history", "recon_data"]:
            final_result.pop(key, None)

        return final_result

    except Exception as e:
        import traceback

        # 检查是否是取消异常
        try:
            from task_cancel_manager import TaskCancelledError
            if isinstance(e, TaskCancelledError):
                log(f"⚠️ 任务被取消: {e}")
                return {"current_mode": "end", "found_flag": False, "cancelled": True}
        except ImportError:
            pass

        log(f"❌ 工作流执行异常: {e}")
        traceback.print_exc()
        return {"current_mode": "end", "found_flag": False}

    finally:
        # 清除当前任务ID
        if task_id:
            try:
                from task_cancel_manager import cancel_manager
                cancel_manager.set_current_task(None)
                cancel_manager.clear_cancel(task_id)
            except ImportError:
                pass


if __name__ == "__main__":
    main()