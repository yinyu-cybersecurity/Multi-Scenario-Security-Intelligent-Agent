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
def log_analyst(msg: str): log(msg, node="analyst")
def log_attacker(msg: str): log(msg, node="attacker")
def log_verifier(msg: str): log(msg, node="verifier")
def log_explorer(msg: str): log(msg, node="explorer")
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
    """精简日志记录：避免输出过大内容"""
    os.makedirs("log", exist_ok=True)
    log_file = os.path.join("log", f"{node_name}_{int(time.time())}.log")

    def _truncate_large(obj, max_str=500):
        """递归截断大字符串和列表"""
        if isinstance(obj, dict):
            return {k: _truncate_large(v, max_str) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [_truncate_large(item, max_str) for item in obj[:10]] + (["..."] if len(obj) > 10 else [])
        elif isinstance(obj, str) and len(obj) > max_str:
            return obj[:max_str] + f"...({len(obj)} chars)"
        return obj

    # 精简输入输出
    input_trimmed = _truncate_large(input_data)
    output_trimmed = _truncate_large(output_data)

    with open(log_file, "w", encoding="utf-8") as f:
        f.write(f"=== [{node_name}] INPUT ===\n")
        f.write(json.dumps(input_trimmed, indent=2, ensure_ascii=False, default=str))
        f.write(f"\n\n=== [{node_name}] OUTPUT ===\n")
        f.write(json.dumps(output_trimmed, indent=2, ensure_ascii=False, default=str))
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


# [已移除] recon_node - 功能已合并到 analyst_node 开头
# recon_node 原有的页面获取、框架检测、特征提取功能现在由 analyst_node 自动执行


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
        {{\"step\": 1, \"vuln_type\": \"类型\", \"action\": \"利用动作\", \"expected\": \"预期结果\"}}
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

    [简化] 合并原recon_node功能，首次访问时自动获取页面数据

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
    current_url = state.get("current_url", state.get("target_url", ""))

    # =====================================================
    # [合并recon] 检查并获取缺失的页面数据
    # =====================================================
    page_features = state.get("page_features") or {}  # [防御性修复] 处理 None 值
    raw_html = state.get("raw_html_snippet", "")
    baseline_response = state.get("baseline_response") or {}  # [防御性修复] 处理 None 值

    # [拓扑初始化] 提前定义，确保在所有代码路径中可用
    site_topology = state.get("site_topology") or {}

    if not page_features or not raw_html:
        log("   📡 首次访问，获取页面数据...")
        try:
            # 快速HTTP请求获取页面
            resp = requests.get(current_url, timeout=10, verify=False, headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            })
            raw_html = resp.text[:5000]  # 限制长度
            baseline_response = {
                "status_code": resp.status_code,
                "headers": dict(resp.headers),
                "final_url": resp.url
            }

            # 提取基本特征
            from scene_detector import SceneDetector
            detector = SceneDetector()
            # 先手动提取基础page_features
            basic_features = {
                "tech_stack": [],
                "input_vectors": [],
                "sensitive_paths": [],
                "text_content": resp.text[:2000]
            }
            # 然后使用detect方法提取场景信息
            page_features = detector.detect(basic_features, baseline_response, resp.text)
            log(f"   ✅ 页面数据获取完成 (状态码: {resp.status_code})")

            # [拓扑初始化] 首次访问时初始化拓扑数据
            if current_url and current_url not in site_topology:
                site_topology = {current_url: []}
                log(f"   📍 初始化拓扑: {current_url}")
        except Exception as e:
            log(f"   ⚠️ 页面获取失败: {e}")
            raw_html = ""
            page_features = {"tech_stack": [], "input_vectors": []}
            # 如果连目标URL都没有，用target_url初始化
            if not site_topology:
                target_url = state.get("target_url", "")
                if target_url:
                    site_topology = {target_url: []}

    # [关键修复] 确保 site_topology 始终被初始化
    # 如果上面没有进入初始化块（page_features 和 raw_html 已有值），需要在这里初始化
    if not site_topology:
        target_url = state.get("target_url", "")
        current_url_for_topo = state.get("current_url", target_url)
        if current_url_for_topo:
            site_topology = {current_url_for_topo: []}
            log(f"   📍 补充初始化拓扑: {current_url_for_topo}")

    # 1. 准备输入数据
    task_name = state.get("task_name", "Unknown Task")
    task_description = state.get("task_description", "No description provided")

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
        return {
            "vuln_candidates": rule_candidates,
            "exploit_keywords": exploit_keywords if exploit_keywords else {},
            "page_features": page_features,
            "raw_html_snippet": raw_html,
            "baseline_response": baseline_response,
            "detected_scenes": page_features,  # detected_scenes 使用 page_features
            "site_topology": site_topology  # 拓扑数据
        }

    # 4. 解析结果
    try:
        # 清理可能的 markdown 标记
        if "```json" in response_text:
            response_text = response_text.split("```json")[1].split("```")[0]
        elif "```" in response_text:
            response_text = response_text.split("```")[1].split("```")[0]
            
        result = json.loads(response_text)
        candidates = result.get("candidates", [])

        # [简化格式] 战术指导现在是字符串，guidance_type是单独字段
        tactical_guidance = result.get("tactical_guidance", "")
        guidance_type = result.get("guidance_type", "continue")
        guidance_target_url = result.get("target_url", "")
        log(f"   📋 战术指导: {guidance_type}")
        if tactical_guidance:
            log(f"   🎯 建议动作: {tactical_guidance}")  # 不截断，完整显示
        if guidance_target_url:
            log(f"   🔗 建议目标URL: {guidance_target_url}")

        # [简化] 将关键情报合并到第一个漏洞候选的reason字段
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
                key_intel_parts.append(f"[{cand.get('type','?')}@{cand.get('location','?')}] 关键代码:\n{key_code[:500]}")  # 限制长度
            formatted_candidates.append({
                "type": cand.get("type", "unknown"),
                "location": cand.get("location", ""),
                "confidence": float(cand.get("confidence", 0.5)),
                "context": ctx,
                "reason": cand.get("reason", ""),
                "recommended_tools": cand.get("recommended_tools", ctx.get("recommended_tools", [])),
                "url": current_url
            })

        # [核心改进] 将key_intel合并到第一个候选的reason字段，避免冗余
        if formatted_candidates and key_intel_parts:
            first_reason = formatted_candidates[0].get("reason", "")
            intel_str = "; ".join(key_intel_parts[:3])  # 限制情报数量
            formatted_candidates[0]["reason"] = f"{intel_str}\n{first_reason}" if first_reason else intel_str
            
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
                "failure_weighted_score": state.get("failure_weighted_score", 0) + 1.5,
                "exploit_keywords": exploit_keywords if exploit_keywords else {},
                "site_topology": site_topology
            }

        res = {
            "vuln_candidates": formatted_candidates,  # key_intel已合并到第一个候选的reason字段
            "exploit_keywords": exploit_keywords if exploit_keywords else {},
            "site_topology": site_topology
        }
        # [简化格式] 将战术指导传递给状态
        if tactical_guidance:
            res["latest_tactical_guidance"] = tactical_guidance
        if guidance_type:
            res["guidance_type"] = guidance_type
        if guidance_target_url:
            res["guidance_target_url"] = guidance_target_url
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
            "vuln_candidates": default_candidates,  # 降级信息已合并到reason字段
            "failure_weighted_score": state.get("failure_weighted_score", 0) + 0.5,
            "exploit_keywords": exploit_keywords if exploit_keywords else {},
            "site_topology": site_topology
        }


def mode_manager_node(state: CTFState) -> Dict:
    """
    模式决策器 - 极简版

    唯一规则：时间超时 → end，否则 → exploit
    - CTF模式: 30分钟超时
    - 内网模式: 1小时超时
    """
    start_time = state.get("start_time", time.time())
    internal_mode = state.get("internal_mode", False)

    # 尊重上游设置的end模式
    if state.get("current_mode") == "end":
        return {"current_mode": "end"}

    # 时间超时检查
    elapsed_time = time.time() - start_time
    timeout = config.INTERNAL_TASK_TIMEOUT if internal_mode else config.TASK_TIMEOUT

    if elapsed_time >= timeout:
        log_mode_manager(f"任务超时: {elapsed_time/60:.1f}分钟")
        return {"current_mode": "end"}

    return {"current_mode": "exploit"}


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

            # [修复] is_exploit 应该使用 diff_analysis 中的 is_exploit 字段，而不是 changed
            # changed 只表示内容是否变化，is_exploit 才表示是否成功利用
            result = {
                "tool": "requests",
                "status": resp.status_code,
                "output": short_output,
                "payload": payload[:500] if payload else "",
                "is_exploit": diff_analysis.get("is_exploit", diff_analysis.get("changed", False)),
                "diff_reason": diff_analysis.get("reason", "")
            }
            # extracted_flag和file_path仅在有值时添加
            if diff_analysis.get("extracted_flag"):
                result["extracted_flag"] = diff_analysis["extracted_flag"]
            if file_path:
                result["file_path"] = file_path
            return result
            
        else:
            # [同步修复] 直接调用工具执行引擎
            exec_result = ToolRegistry.execute_cached(tool_name, target, params)
            
            if "error" in exec_result:
                # [简化] 仅保留核心字段
                return {
                    "tool": tool_name,
                    "status": 500,
                    "output": f"Error: {exec_result['error']}",
                    "payload": payload[:500] if payload else "",
                    "is_exploit": False
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

            # [简化] 仅保留核心字段
            result = {
                "tool": tool_name,
                "status": 200 if (tool_res.get("success") or vulnerable) else 500,
                "output": display_output[:2000],  # 限制输出长度
                "payload": payload[:500] if payload else "",
                "is_exploit": vulnerable
            }
            # 仅在有值时添加可选字段
            if extracted_flag:
                result["extracted_flag"] = extracted_flag
            if tool_res.get("full_log_path"):
                result["file_path"] = tool_res["full_log_path"]
            return result
    except Exception as e:
        # [核心修复] 将详细报错信息放入 output，让核验兵能识别出具体错误
        error_msg = f"Execution Exception: {str(e)}\n{traceback.format_exc()}"
        log(f"❌ [Executor] 攻击动作执行失败: {tool_name}\n{error_msg}")
        
        # [简化] 仅保留核心字段
        return {
            "tool": tool_name,
            "status": 500,
            "output": f"Exception: {str(e)}",
            "payload": payload[:500] if payload else "",
            "is_exploit": False
        }

def attacker_node(state: CTFState) -> Dict:
    """
    [攻击兵] (同步并发执行优化版)

    攻击策略:
    1. 首先使用nuclei/xray等工具批量验证漏洞
    2. 然后使用手工payload进行攻击
    3. 综合两种方式的结果
    """
    # [简化] 移除智能流转，直接流转到verifier

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
                    "has_shell": bool(state.get("active_sessions")),
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
    guidance_target_url = state.get("guidance_target_url", "")  # [断点修复] 获取精确目标URL

    # 如果有强制切换场景的指导，优先执行
    if guidance_type == "switch_scene" and enforce_change:
        # [断点修复] 优先使用guidance_target_url字段，而不是从字符串提取
        guidance_target = guidance_target_url if guidance_target_url else None

        # 如果没有精确URL，尝试从tactical_guidance中提取
        if not guidance_target and tactical_guidance:
            if isinstance(tactical_guidance, dict):
                guidance_target = tactical_guidance.get("target_url", "")
            elif isinstance(tactical_guidance, str) and "http" in tactical_guidance:
                # 尝试从文本中提取URL
                url_match = re.search(r'https?://[^\s<>"]+', tactical_guidance)
                if url_match:
                    guidance_target = url_match.group()

        if guidance_target:
            log(f"   🔄 [强制指导] 使用精确URL: {guidance_target}")
            # 直接生成访问新URL的攻击动作
            forced_attack = {
                "tool": "requests",
                "params": {
                    "method": "GET",
                    "url": guidance_target
                },
                "reasoning": f"执行精确攻击URL: {guidance_target}"
            }
            # 返回强制攻击，绕过LLM生成
            return {
                "attack_batch": [forced_attack],
                "attack_results": [],
                "current_url": guidance_target if guidance_type == "switch_scene" else current_url,
                "execution_steps": state.get("execution_steps", 0) + 1,
                "guidance_type": "",  # 清空指导，已执行
                "enforce_change": False,
                "guidance_target_url": ""  # 清空，已使用
            }

    # =====================================================
    # LLM生成攻击Payload
    # =====================================================

    # 1. 获取推荐工具详情（按需），不再传递全部工具描述
    recommended_tools = set()
    for c in candidates[:5]:
        for t in c.get("recommended_tools", []):
            recommended_tools.add(t)
    # 确保requests始终可用
    recommended_tools.add("requests")
    tools_info = ToolRegistry.get_tool_detail(list(recommended_tools))
    if not tools_info:
        tools_info = ToolRegistry.get_tool_names()  # 降级为名称列表

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
        known_facts=state.get("known_facts", ""),
        failed_payloads=state.get("failed_payloads", []),
        stage_info=stage_info,
        strategic_context=strategic_context
    )

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

            # [fallback修复] 提取并存储fallback方案（AI驱动，不硬编码转换）
            fallback = action.get("fallback", "")
            if fallback and isinstance(fallback, str) and fallback.strip():
                fallback_plans.append({
                    "tool": tool,
                    "description": fallback,  # 保留AI的fallback描述
                    "context": {
                        "original_params": action.get("params", {}),
                        "target": action.get("params", {}).get("url", current_url)
                    }
                })
                log(f"   📋 收集Fallback方案: {fallback[:50]}")

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
                    "payload": str(action.get("params", ""))[:500],
                    "is_exploit": False
                })
        
        # 处理超时的任务
        for f in not_done:
            action = futures_map[f]
            log(f"⚠️ [Attacker] 任务执行超时已取消: {action.get('tool')}")
            # 注意：concurrent.futures 无法强制杀掉正在运行的线程，但我们可以不再等待它
            attack_results.append({
                    "tool": action.get("tool"),
                    "status": 408,
                    "output": "Task timed out",
                    "payload": str(action.get("params", ""))[:500],
                    "is_exploit": False
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

    # [简化] 移除智能流转，直接流转到verifier
    # verifier会判断攻击是否有效并给出下一步指导
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
        # 简化：不再切换innovate，直接返回explore继续
        return {"exploration_rounds": exploration_rounds,
                "failure_weighted_score": state.get("failure_weighted_score", 0) + 0.5,
                "current_mode": "explore"}
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

    # 简化：移除innovate模式切换，继续探索

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
    page_features = state.get("page_features") or {}  # [防御性修复] 处理 None 值
    sensitive_paths = page_features.get("sensitive_paths", [])
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

        # [简化] 直接使用is_exploit字段
        res["diff_metrics"] = {
            "is_significant_change": res.get("is_exploit", False),
            "exploit_confidence": "high" if res.get("is_exploit") else "unknown",
            "change_reason": ""
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
        node_info=node_info,
        known_facts=state.get("known_facts", ""),
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
        failure_level = result.get("failure_level", "minor")  # 改为定性描述
        is_exploit_successful = result.get("is_exploit_successful", False)

        # [修复] 将failure_level转换为failure_severity数值
        failure_severity_map = {
            "none": 0.0,
            "minor": 0.2,
            "moderate": 0.5,
            "major": 0.8,
            "critical": 1.0
        }
        failure_severity = failure_severity_map.get(failure_level, 0.2)

        # [简化格式处理] tactical_guidance现在是字符串，guidance_type是单独字段
        tactical_guidance = result.get("tactical_guidance", "")
        guidance_type = result.get("guidance_type", "continue")
        guidance_reason = result.get("guidance_reason", "")  # 添加guidance_reason
        guidance_target_url = result.get("target_url", "")
        enforce_change = guidance_type == "switch_scene"  # switch_scene时强制执行

        log(f"   📋 战术指导类型: {guidance_type}")
        if tactical_guidance:
            log(f"   💡 分析: {tactical_guidance[:200]}")  # 增加截断长度
        if guidance_target_url:
            log(f"   🎯 建议目标URL: {guidance_target_url}")

        updated_known_facts = result.get("updated_known_facts", "")
        node_decision = result.get("node_decision", "continue")
        failure_analysis = result.get("failure_analysis", "")
        new_discoveries = result.get("new_discoveries", [])

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
                # 添加到active_sessions而不是设置shell_session
                current_sessions = state.get("active_sessions", [])
                result_dict["active_sessions"] = current_sessions + [shell_session_info]

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

        # 记录失败的payload（累加模式）
        existing_failed = state.get("failed_payloads", [])
        failed_payloads = list(existing_failed)  # 复制已有记录
        for action in attack_batch:
            # 从 params 中提取 payload
            params = action.get("params", {})
            url = params.get("url", "")
            if url and url not in failed_payloads:
                failed_payloads.append(url)
        # 保留最近50条，避免过长
        failed_payloads = failed_payloads[-50:]

        # =====================================================
        # [fallback修复] 检查是否有备选方案可用
        # =====================================================
        fallback_plans = state.get("fallback_plans", [])
        fallback_action = None

        if fallback_plans:
            log(f"   🔄 检查Fallback方案... (共 {len(fallback_plans)} 个)")
            for fb in fallback_plans:
                fb_desc = fb.get("description", "")
                fb_tool = fb.get("tool", "")
                if fb_desc and fb_desc not in [p[:50] for p in failed_payloads]:
                    fallback_action = fb
                    log(f"   ✅ 找到可用Fallback: {fb_tool} - {fb_desc[:50]}")
                    break

        if fallback_action:
            log(f"   🔀 执行Fallback方案切换")
            remaining_fallbacks = [fb for fb in fallback_plans if fb != fallback_action]

            # 从fallback描述构建攻击动作
            fb_context = fallback_action.get("context", {})
            fallback_attack = {
                "tool": fallback_action.get("tool", "requests"),
                "params": fb_context.get("original_params", {"url": current_url}),
                "reasoning": f"Fallback: {fallback_action.get('description', '')}"
            }

            tactical_guidance = f"执行Fallback: {fallback_action.get('description', '未知')[:80]}"

            result_dict = {
                "continue_attack": True,  # [关键修复] 设置标志，路由直接去attacker
                "failure_weighted_score": max(0, state.get("failure_weighted_score", 0) - 0.3),
                "attack_batch": [fallback_attack],
                "latest_tactical_guidance": tactical_guidance,
                "guidance_type": "continue",
                "enforce_change": False,
                "guidance_reason": "Fallback方案执行",
                "guidance_target_url": "",
                "execution_steps": state.get("execution_steps", 0) + 1,
                "node_attack_status": node_status,
                "vuln_candidates": candidates,
                "fallback_plans": remaining_fallbacks,
                "scene_attack_attempts": scene_attack_attempts,
                "failed_payloads": failed_payloads  # 传递失败记录
            }

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
            active_sessions = state.get("active_sessions", [])

            if active_sessions:
                log(f"   ✅ [内网] 检测到活跃Shell会话 ({len(active_sessions)}个)")
                # 有shell会话，进入后渗透阶段
                result_dict = {
                    "failure_weighted_score": max(0, state.get("failure_weighted_score", 0) - 0.5),
                    "execution_steps": state.get("execution_steps", 0) + 1,
                    "node_attack_status": node_status,
                    "vuln_candidates": candidates,
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
            log(f"   💡 原因: {failure_analysis}")  # 不截断
            node_status[current_url]["status"] = "abandoned"
        elif tactical_guidance:
            log(f"   💡 分析: {failure_analysis}")  # 不截断
            log(f"   🎯 建议: {tactical_guidance}")  # 不截断

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
            "remaining_payloads": remaining_payloads,
            "failed_payloads": failed_payloads  # 始终返回，即使为空
        }

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

# 添加所有兵种节点 [P3优化: 移除reflector和recon]
# 注意：所有节点都通过 wrap_node 包装，支持运行时禁用
workflow.add_node("challenge_type_detector", wrap_node("challenge_type_detector", challenge_type_detector_node))  # type: ignore # CTF类型检测器
# [简化] recon功能已合并到analyst_node
workflow.add_node("analyst", wrap_node("analyst", analyst_node))  # type: ignore # 分析兵
workflow.add_node("strategy_filter", wrap_node("strategy_filter", strategy_filter_node))  # type: ignore # 策略过滤器
workflow.add_node("mode_manager", wrap_node("mode_manager", mode_manager_node))  # type: ignore # 模式决策器
workflow.add_node("attacker", wrap_node("attacker", attacker_node))  # type: ignore # 攻击兵
workflow.add_node("explorer", wrap_node("explorer", explorer_node))  # type: ignore # 探索兵
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
    return "analyst"

# 构建类型检测器的路由映射（移除recon）
_detector_routes = {
    "analyst": "analyst"  # Web模式直接走分析
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

# 1. 线性分析流: 分析 -> 过滤 -> 决策 (移除recon)
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

# 构建基础路由映射（移除innovate模式）
_mode_manager_routes = {
    "exploit": "attacker",
    "explore": "explorer",
    "recon": "analyst", # [简化] recon已合并到analyst
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

# 3.5 [简化] attacker 直接流转到 verifier
workflow.add_edge("attacker", "verifier")

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