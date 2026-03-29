"""
Web API 服务
提供前端接口：任务管理、状态查询、日志查看、实时状态
集成模块:
- 任务持久化 (TaskPersistenceManager)
- 自我纠错 (SelfCorrectionManager)
- 攻击策略评估 (AttackStrategyEvaluator)

安全配置:
- 访问路径: /fisher_ctf_agent/
- 端口: 54565
- 无默认首页
"""

import os
import sys
import json
import time
import threading
import subprocess
import logging
from datetime import datetime
from flask import Flask, Blueprint, render_template, jsonify, request, Response, abort
from flask_cors import CORS
import queue

# 添加app目录和deploy目录到路径（使用绝对路径确保在不同运行目录下都能正确工作）
_web_dir = os.path.dirname(os.path.abspath(__file__))
_deploy_dir = os.path.dirname(_web_dir)
_app_dir = os.path.join(_deploy_dir, 'app')

if _deploy_dir not in sys.path:
    sys.path.insert(0, _deploy_dir)
    print(f"[Web] Added to sys.path: {_deploy_dir}")
if _app_dir not in sys.path:
    sys.path.insert(0, _app_dir)
    print(f"[Web] Added to sys.path: {_app_dir}")

# 导入工具模块以触发工具注册（忽略错误）
try:
    import tools
except Exception as e:
    print(f"[Web] Warning: Failed to load tools: {e}")
    pass

# 导入节点控制模块
try:
    from node_control import node_control
except ImportError:
    node_control = None

# 导入任务取消管理器
try:
    from task_cancel_manager import cancel_manager, TaskCancelledError
except ImportError:
    cancel_manager = None
    TaskCancelledError = None

# =============================================================================
# Flask 应用配置
# =============================================================================

# URL 前缀 - 所有路由都带此前缀
URL_PREFIX = '/fisher_ctf_agent'

# 创建 Blueprint - 统一管理所有路由
bp = Blueprint('main', __name__, url_prefix=URL_PREFIX)

# 创建 Flask 应用
app = Flask(__name__,
            template_folder='templates',
            static_folder='static',
            static_url_path=URL_PREFIX + '/static')

CORS(app)

# 配置Jinja2不与Vue冲突 - 使用 [[ ]] 作为Jinja变量分隔符
app.jinja_env.variable_start_string = '[['
app.jinja_env.variable_end_string = ']]'

# Blueprint 在路由定义后注册（见文件末尾）

# 任务存储（内存缓存）
tasks = {}
task_logs = {}
task_queues = {}
task_states = {}
task_results = {}  # 存储任务详细结果
task_completion_times = {}  # 记录任务完成时间

# 内存清理配置
MAX_MEMORY_TASKS = 20  # 内存中最多保留20个任务的详细数据
CLEANUP_INTERVAL = 300  # 每5分钟检查一次

def cleanup_old_tasks():
    """清理内存中的旧任务数据"""
    global tasks, task_logs, task_queues, task_states, task_results, task_completion_times

    if len(tasks) <= MAX_MEMORY_TASKS:
        return

    # 按完成时间排序，保留最近的任务
    completed_tasks = [
        (tid, task_completion_times.get(tid, 0))
        for tid in tasks.keys()
        if tasks.get(tid, {}).get("status") in ["completed", "error", "cancelled"]
    ]
    completed_tasks.sort(key=lambda x: x[1])

    # 清理最旧的任务
    to_remove = completed_tasks[:len(tasks) - MAX_MEMORY_TASKS]
    for tid, _ in to_remove:
        task_logs.pop(tid, None)
        task_queues.pop(tid, None)
        task_states.pop(tid, None)
        task_results.pop(tid, None)
        task_completion_times.pop(tid, None)
        tasks.pop(tid, None)
        if task_persistence:
            try:
                task_persistence.delete_task(tid)
            except:
                pass

    if to_remove:
        print(f"[Cleanup] 已清理 {len(to_remove)} 个旧任务，当前保留 {len(tasks)} 个")

# 定时清理
import threading
_cleanup_timer = None

def start_cleanup_timer():
    """启动定时清理"""
    global _cleanup_timer
    def cleanup_loop():
        while True:
            time.sleep(CLEANUP_INTERVAL)
            try:
                cleanup_old_tasks()
            except Exception as e:
                print(f"[Cleanup] 清理出错: {e}")

    _cleanup_timer = threading.Thread(target=cleanup_loop, daemon=True)
    _cleanup_timer.start()

# 启动时自动开始清理
start_cleanup_timer()

# 初始化任务持久化管理器
task_persistence = None
try:
    from task_persistence import get_task_persistence
    task_persistence = get_task_persistence()
except ImportError:
    pass

# 初始化自我纠错管理器
self_correction_manager = None
ErrorSeverity = None
ErrorType = None
classify_error = None
enrich_error_context = None
try:
    from self_correction import (
        self_correction_manager as scm,
        ErrorSeverity,
        ErrorType,
        classify_error,
        enrich_error_context
    )
    self_correction_manager = scm
except ImportError:
    pass

# 初始化攻击策略评估器
strategy_evaluator = None
try:
    from attack_strategy_evaluator import get_evaluator
    strategy_evaluator = get_evaluator()
except ImportError:
    pass

# =============================================================================
# RAG 检索器预热 - 解决API超时问题
# =============================================================================
# 全局RAG检索器实例（预热后缓存）
_rag_retriever = None
_rag_status_cache = None  # 缓存状态避免重复查询
_rag_init_lock = threading.Lock()  # 防止并发初始化

def prewarm_rag_retriever():
    """
    预热RAG检索器 - 在Flask启动时加载模型

    解决问题：
    - API首次调用需要加载模型，耗时40秒+
    - 模型下载导致用户等待超时
    - 预热后API响应时间降至毫秒级
    """
    global _rag_retriever, _rag_status_cache

    # 使用锁防止并发初始化
    with _rag_init_lock:
        # 已经初始化完成，直接返回
        if _rag_retriever is not None:
            return True

        print("[RAG] Pre-warming retriever (loading model)...")
        try:
            from rag_builder.unified_vector_store import get_unified_retriever
            _rag_retriever = get_unified_retriever()

            # 缓存状态信息
            _rag_status_cache = {
                "writeups": _rag_retriever.writeups_collection.count() if _rag_retriever.writeups_collection else 0,
                "nuclei": _rag_retriever.nuclei_collection.count() if _rag_retriever.nuclei_collection else 0,
                "payloads": _rag_retriever.payloads_collection.count() if _rag_retriever.payloads_collection else 0,
                "security_resources": _rag_retriever.security_resources_collection.count() if _rag_retriever.security_resources_collection else 0,
                "available": True
            }
            _rag_status_cache["total"] = sum([
                _rag_status_cache["writeups"],
                _rag_status_cache["nuclei"],
                _rag_status_cache["payloads"],
                _rag_status_cache["security_resources"]
            ])

            print(f"[RAG] Pre-warming complete! Total records: {_rag_status_cache['total']}")
            print(f"       - Writeups: {_rag_status_cache['writeups']}")
            print(f"       - Nuclei: {_rag_status_cache['nuclei']}")
            print(f"       - Payloads: {_rag_status_cache['payloads']}")
            print(f"       - Security Resources: {_rag_status_cache['security_resources']}")

            return True
        except Exception as e:
            print(f"[RAG] Pre-warming failed: {e}")
            import traceback
            traceback.print_exc()
            _rag_status_cache = {
                "error": str(e),
                "available": False,
                "total": 0,
                "writeups": 0, "nuclei": 0, "payloads": 0, "security_resources": 0
            }
            return False

def get_cached_rag_retriever():
    """获取缓存中的RAG检索器，如果未预热则尝试初始化"""
    global _rag_retriever

    if _rag_retriever is not None:
        return _rag_retriever

    # 未预热，尝试初始化（可能耗时）
    # 注意：prewarm_rag_retriever会修改_rag_retriever全局变量
    prewarm_rag_retriever()
    return _rag_retriever  # 返回检索器对象，而不是布尔值

# Flask启动后自动预热（延迟执行，避免阻塞启动）
def schedule_rag_prewarm():
    """延迟预热RAG检索器"""
    def _prewarm():
        time.sleep(3)  # 等待Flask完全启动
        prewarm_rag_retriever()

    thread = threading.Thread(target=_prewarm, daemon=True)
    thread.start()
    return thread

# 启动时自动预热
schedule_rag_prewarm()

# 全局状态
system_status = {
    "llm_connected": False,
    "tools_loaded": 0,
    "active_sessions": 0,
    "start_time": datetime.now().isoformat()
}


# =============================================================================
# 统一错误处理机制
# =============================================================================

def handle_api_error(func):
    """
    API 错误处理装饰器

    功能:
    - 自动捕获异常
    - 记录错误到 self_correction_manager
    - 返回标准化错误响应
    - 支持错误分类和严重度评估
    """
    from functools import wraps

    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            # 获取函数名作为节点标识
            node_name = func.__name__

            # 分类错误
            error_type = "EXECUTION_ERROR"
            severity_name = "MEDIUM"

            if classify_error and ErrorSeverity:
                error_type, severity = classify_error(e, {})
                severity_name = severity.name
            else:
                # 简单分类
                error_msg = str(e).lower()
                if 'timeout' in error_msg:
                    error_type = "NETWORK_TIMEOUT"
                elif 'connection' in error_msg:
                    error_type = "CONNECTION_REFUSED"
                elif 'not found' in error_msg:
                    error_type = "RESOURCE_NOT_FOUND"

            # 记录错误
            if self_correction_manager and ErrorSeverity:
                try:
                    self_correction_manager.record_error(
                        node=node_name,
                        error_type=error_type,
                        error_message=str(e),
                        severity=ErrorSeverity.MEDIUM if ErrorSeverity else None
                    )
                except Exception:
                    pass  # 防止错误记录失败导致二次异常

            # 构建错误响应
            error_response = {
                "error": str(e),
                "error_type": error_type,
                "severity": severity_name,
                "node": node_name,
                "timestamp": datetime.now().isoformat()
            }

            # 根据错误类型选择 HTTP 状态码
            status_code = 500
            if 'not found' in str(e).lower() or error_type == "RESOURCE_NOT_FOUND":
                status_code = 404
            elif 'invalid' in str(e).lower() or 'required' in str(e).lower():
                status_code = 400

            return jsonify(error_response), status_code

    return wrapper


def record_task_error(task_id: str, node: str, error: Exception, state: dict = None) -> dict:
    """
    记录任务错误并尝试分析

    Args:
        task_id: 任务ID
        node: 发生错误的节点
        error: 异常对象
        state: 当前状态（用于 AI 分析）

    Returns:
        错误分析结果
    """
    result = {
        "error": str(error),
        "error_type": "EXECUTION_ERROR",
        "severity": "MEDIUM",
        "analysis": None,
        "recovery_attempted": False
    }

    # 分类错误
    if classify_error:
        try:
            error_type, severity = classify_error(error, {"task_id": task_id})
            result["error_type"] = error_type
            result["severity"] = severity.name
        except Exception:
            pass

    # 记录到 self_correction_manager
    if self_correction_manager:
        try:
            record = self_correction_manager.record_error(
                node=node,
                error_type=result["error_type"],
                error_message=str(error),
                severity=ErrorSeverity[result["severity"]] if ErrorSeverity else None
            )
            result["recorded"] = True
        except Exception as e:
            result["record_error"] = str(e)

    # AI 分析错误（如果可用）
    if self_correction_manager and state:
        try:
            analysis = self_correction_manager.analyze_failure_with_ai(
                error_record=record if 'record' in dir() else None,
                context={
                    "task_id": task_id,
                    "target_url": state.get("target_url", ""),
                    "recent_actions": state.get("attack_results", [])[-5:],
                    "attempts": state.get("execution_steps", 0)
                }
            )
            result["analysis"] = analysis
        except Exception as e:
            result["analysis_error"] = str(e)

    return result


def attempt_task_recovery(task_id: str, state: dict, analysis: dict) -> tuple:
    """
    尝试任务恢复

    Args:
        task_id: 任务ID
        state: 当前状态
        analysis: AI 分析结果

    Returns:
        (recovered: bool, updates: dict)
    """
    if not self_correction_manager:
        return False, {}

    try:
        updates, recovered = self_correction_manager.attempt_ai_recovery(state, analysis)
        return recovered, updates
    except Exception as e:
        return False, {"recovery_error": str(e)}


def get_graph_structure():
    """获取LangGraph图结构"""
    groups = {
        "entry": {"name": "入口", "color": "#409EFF"},
        "web": {"name": "Web攻击", "color": "#67C23A"},
        "decision": {"name": "决策", "color": "#E6A23C"},
        "internal": {"name": "内网渗透", "color": "#F56C6C"},
        "crypto": {"name": "密码学", "color": "#9C27B0"},
        "pwn": {"name": "二进制", "color": "#FF5722"},
        "reverse": {"name": "逆向", "color": "#00BCD4"},
        "misc": {"name": "杂项", "color": "#8BC34A"},
        "cloud": {"name": "云安全", "color": "#FF9800"},
        "ai": {"name": "AI安全", "color": "#E91E63"},
        "end": {"name": "结束", "color": "#95a5a6"}
    }

    # 节点按执行流程排序：入口 -> Web主流程 -> 内网 -> 其他分支 -> 结束
    nodes = [
        # 入口
        {"id": "challenge_type_detector", "name": "类型检测", "group": "entry", "description": "检测CTF题目类型", "order": 1},
        # Web攻击主流程
        {"id": "recon", "name": "侦察兵", "group": "web", "description": "HTTP请求、指纹识别", "order": 10},
        {"id": "analyst", "name": "分析兵", "group": "web", "description": "漏洞分析、策略生成", "order": 20},
        {"id": "strategy_filter", "name": "策略过滤", "group": "web", "description": "过滤无效策略", "order": 25},
        {"id": "mode_manager", "name": "模式决策", "group": "decision", "description": "决定攻击/探索模式", "order": 30},
        {"id": "attacker", "name": "攻击兵", "group": "web", "description": "执行攻击动作", "order": 40},
        {"id": "verifier", "name": "核验兵", "group": "web", "description": "验证攻击结果", "order": 50},
        {"id": "explorer", "name": "探索兵", "group": "web", "description": "目录扫描", "order": 60},
        {"id": "innovator", "name": "头脑风暴", "group": "web", "description": "生成新策略", "order": 70},
        # 内网渗透
        {"id": "post_exploit", "name": "后渗透", "group": "internal", "description": "Shell后处理", "order": 100},
        {"id": "upload_tools", "name": "工具上传", "group": "internal", "description": "上传渗透工具", "order": 110},
        {"id": "setup_tunnel", "name": "隧道搭建", "group": "internal", "description": "FRP代理搭建", "order": 120},
        {"id": "internal_recon", "name": "内网侦察", "group": "internal", "description": "fscan扫描", "order": 130},
        {"id": "lateral_move", "name": "横向移动", "group": "internal", "description": "impacket利用", "order": 140},
        {"id": "privilege_escalation", "name": "权限提升", "group": "internal", "description": "Potato提权", "order": 150},
        {"id": "persistence", "name": "持久化", "group": "internal", "description": "AI驱动持久化", "order": 155},
        {"id": "credential_gather", "name": "凭据收集", "group": "internal", "description": "mimikatz导出", "order": 160},
        # 其他分支
        {"id": "crypto_analyst", "name": "密码分析", "group": "crypto", "description": "加密类型识别", "order": 200},
        {"id": "crypto_solver", "name": "密码破解", "group": "crypto", "description": "尝试解密破解", "order": 210},
        {"id": "pwn_analyst", "name": "二进制分析", "group": "pwn", "description": "漏洞检测分析", "order": 220},
        {"id": "pwn_exploiter", "name": "漏洞利用", "group": "pwn", "description": "构建exploit", "order": 230},
        {"id": "reverse_analyst", "name": "逆向分析", "group": "reverse", "description": "二进制逆向", "order": 240},
        {"id": "reverse_decompiler", "name": "反编译", "group": "reverse", "description": "反编译分析", "order": 250},
        {"id": "misc_analyst", "name": "杂项分析", "group": "misc", "description": "文件分析隐写检测", "order": 260},
        {"id": "misc_extractor", "name": "数据提取", "group": "misc", "description": "提取隐藏数据", "order": 270},
        # 云安全分支
        {"id": "cloud_recon", "name": "云侦察", "group": "cloud", "description": "识别云服务商", "order": 280},
        {"id": "cloud_enum", "name": "云枚举", "group": "cloud", "description": "枚举云资源", "order": 281},
        {"id": "cloud_exploit", "name": "云攻击", "group": "cloud", "description": "攻击云资源", "order": 282},
        {"id": "cloud_escalate", "name": "云提权", "group": "cloud", "description": "权限提升分析", "order": 283},
        # AI安全分支
        {"id": "ai_detect", "name": "AI检测", "group": "ai", "description": "识别AI服务", "order": 290},
        {"id": "ai_probe", "name": "AI探测", "group": "ai", "description": "Prompt注入测试", "order": 291},
        {"id": "ai_exploit", "name": "AI攻击", "group": "ai", "description": "越狱攻击", "order": 292},
        {"id": "ai_exfiltrate", "name": "AI窃取", "group": "ai", "description": "数据窃取", "order": 293},
        # 结束
        {"id": "evolution", "name": "进化", "group": "end", "description": "学习总结", "order": 300},
    ]

    # 添加启用状态和分组名称
    for node in nodes:
        # 使用 node_control 获取启用状态
        if node_control:
            node["enabled"] = node_control.is_enabled(node["id"])
        else:
            node["enabled"] = node_enabled.get(node["id"], True)
        node["groupName"] = groups.get(node["group"], {}).get("name", node["group"])

    # 按执行流程排序
    nodes.sort(key=lambda n: n.get("order", 99))

    all_edges = [
        {"source": "challenge_type_detector", "target": "recon"},
        {"source": "recon", "target": "analyst"},
        {"source": "analyst", "target": "strategy_filter"},
        {"source": "strategy_filter", "target": "mode_manager"},
        {"source": "mode_manager", "target": "attacker", "label": "exploit"},
        {"source": "mode_manager", "target": "explorer", "label": "explore"},
        {"source": "mode_manager", "target": "innovator", "label": "innovate"},
        {"source": "attacker", "target": "verifier"},
        {"source": "explorer", "target": "analyst"},
        {"source": "innovator", "target": "attacker"},
        {"source": "verifier", "target": "evolution", "label": "success"},
        {"source": "verifier", "target": "post_exploit", "label": "shell"},
        {"source": "verifier", "target": "mode_manager", "label": "continue"},
        {"source": "post_exploit", "target": "upload_tools"},
        {"source": "upload_tools", "target": "setup_tunnel"},
        {"source": "setup_tunnel", "target": "internal_recon"},
        {"source": "internal_recon", "target": "credential_gather"},
        {"source": "internal_recon", "target": "lateral_move"},
        {"source": "lateral_move", "target": "privilege_escalation"},
        {"source": "privilege_escalation", "target": "persistence"},
        {"source": "persistence", "target": "credential_gather"},
        {"source": "challenge_type_detector", "target": "crypto_analyst", "label": "crypto"},
        {"source": "crypto_analyst", "target": "crypto_solver"},
        {"source": "crypto_solver", "target": "evolution"},
        {"source": "challenge_type_detector", "target": "pwn_analyst", "label": "pwn"},
        {"source": "pwn_analyst", "target": "pwn_exploiter"},
        {"source": "pwn_exploiter", "target": "evolution"},
        {"source": "challenge_type_detector", "target": "reverse_analyst", "label": "reverse"},
        {"source": "reverse_analyst", "target": "reverse_decompiler"},
        {"source": "reverse_decompiler", "target": "evolution"},
        {"source": "challenge_type_detector", "target": "misc_analyst", "label": "misc"},
        {"source": "misc_analyst", "target": "misc_extractor"},
        {"source": "misc_extractor", "target": "evolution"},
        # 云安全分支
        {"source": "challenge_type_detector", "target": "cloud_recon", "label": "cloud"},
        {"source": "cloud_recon", "target": "cloud_enum"},
        {"source": "cloud_enum", "target": "cloud_exploit"},
        {"source": "cloud_exploit", "target": "cloud_escalate"},
        {"source": "cloud_escalate", "target": "evolution"},
        # AI安全分支
        {"source": "challenge_type_detector", "target": "ai_detect", "label": "ai"},
        {"source": "ai_detect", "target": "ai_probe"},
        {"source": "ai_probe", "target": "ai_exploit"},
        {"source": "ai_exploit", "target": "ai_exfiltrate"},
        {"source": "ai_exfiltrate", "target": "evolution"},
    ]

    # 返回所有边，但标记禁用状态（前端负责淡化显示）
    edges = []
    for edge in all_edges:
        source_enabled = node_enabled.get(edge["source"], True)
        target_enabled = node_enabled.get(edge["target"], True)
        edge_copy = edge.copy()
        edge_copy["disabled"] = not (source_enabled and target_enabled)
        edges.append(edge_copy)

    return {
        "nodes": nodes,
        "edges": edges,
        "groups": {k: {"name": v["name"], "color": v["color"]} for k, v in groups.items()}
    }


# 线程局部存储，用于隔离不同任务的日志
_task_context = threading.local()


def get_current_task_id():
    """获取当前线程的任务ID"""
    return getattr(_task_context, 'task_id', None)


def set_current_task_id(task_id):
    """设置当前线程的任务ID"""
    _task_context.task_id = task_id


class ThreadSafeLogCapture:
    """
    线程安全的日志捕获器

    使用线程局部存储，避免多任务并发时stdout互相覆盖
    """
    def __init__(self):
        self.original_stdout = sys.stdout

    def write(self, message):
        # 写入原始stdout
        self.original_stdout.write(message)

        # 只捕获当前线程的日志
        task_id = get_current_task_id()
        if task_id and message.strip():
            log_callback(task_id, message.strip())

    def flush(self):
        self.original_stdout.flush()


# 全局日志捕获器实例（线程安全）
_log_capture_instance = None


class WebUILogHandler(logging.Handler):
    """
    自定义 logging Handler，将日志输出到 Web UI

    解决问题：logging.StreamHandler 在初始化时持有原始 sys.stdout 引用，
    之后替换 sys.stdout 不会影响已创建的 handler。
    """
    def __init__(self):
        super().__init__()
        self.setFormatter(logging.Formatter('%(message)s'))

    def emit(self, record):
        """发送日志记录到 Web UI"""
        try:
            task_id = get_current_task_id()
            if task_id:
                msg = self.format(record)
                # 处理 emoji 编码问题 - 替换无法编码的字符
                try:
                    msg.encode('utf-8')
                except UnicodeEncodeError:
                    # 移除或替换 emoji
                    msg = msg.encode('ascii', 'ignore').decode('ascii')

                if msg.strip():
                    log_callback(task_id, msg.strip())
        except Exception:
            # 静默处理异常，避免影响主流程
            pass

    def flush(self):
        pass


def init_log_capture():
    """初始化全局日志捕获器"""
    global _log_capture_instance, sys

    if _log_capture_instance is None:
        _log_capture_instance = ThreadSafeLogCapture()
        sys.stdout = _log_capture_instance

    # 每次都重新添加 WebUILogHandler（防止被其他模块清除）
    root_logger = logging.getLogger()

    # 检查是否已存在 WebUILogHandler
    has_web_handler = any(isinstance(h, WebUILogHandler) for h in root_logger.handlers)

    if not has_web_handler:
        web_handler = WebUILogHandler()
        web_handler.setLevel(logging.INFO)
        # 插入到第一个位置，确保最先处理
        root_logger.handlers.insert(0, web_handler)
        root_logger.setLevel(logging.DEBUG)


class LogCapture:
    """日志捕获器（向后兼容）"""
    def __init__(self, task_id):
        self.task_id = task_id
        self.original_stdout = sys.stdout

    def write(self, message):
        self.original_stdout.write(message)
        if message.strip():
            log_callback(self.task_id, message.strip())

    def flush(self):
        self.original_stdout.flush()


def log_callback(task_id, msg):
    """日志回调"""
    if task_id not in task_logs:
        task_logs[task_id] = []

    # 解析日志类型
    log_type = "info"
    if "[SUCCESS]" in msg or "FLAG" in msg or "[+]" in msg:
        log_type = "success"
    elif "[Error]" in msg or "[-]" in msg or "FAILED" in msg:
        log_type = "error"
    elif "[Warning]" in msg or "[!]" in msg:
        log_type = "warning"

    log_entry = {
        "time": datetime.now().strftime("%H:%M:%S"),
        "msg": msg,
        "type": log_type
    }
    task_logs[task_id].append(log_entry)

    # 通知队列
    if task_id in task_queues:
        task_queues[task_id].put(log_entry)


def run_task(task_id, target_url):
    """后台运行任务"""
    global tasks, task_logs, task_queues, task_states, task_results

    try:
        from ctf_agent_graph import run_single_task, normalize_url, extract_target_info, app as ctf_app

        target_url = normalize_url(target_url)
        task_name, task_description = extract_target_info(target_url)

        tasks[task_id]["target_url"] = target_url
        tasks[task_id]["task_name"] = task_name
        tasks[task_id]["task_description"] = task_description

        log_callback(task_id, f"[System] Task started: {task_name}")
        log_callback(task_id, f"[System] Target: {target_url}")
        log_callback(task_id, f"[System] Type: {task_description}")

        # 使用线程局部存储设置当前任务ID（线程安全）
        set_current_task_id(task_id)

        # 设置取消管理器的当前任务ID
        if cancel_manager:
            cancel_manager.set_current_task(task_id)

        # 初始化全局日志捕获器（如果还没初始化）
        init_log_capture()

        def node_callback(node_name, state=None):
            tasks[task_id]["current_node"] = node_name
            tasks[task_id]["visited_nodes"].append(node_name)
            task_states[task_id] = node_name

            # 更新详细状态
            if state:
                task_results[task_id] = {
                    "vuln_candidates": state.get("vuln_candidates", []),
                    "credentials": state.get("credentials", []),
                    "internal_hosts": state.get("internal_hosts", []),
                    "attack_results": state.get("attack_results", [])[-5:],
                    "found_flag": state.get("found_flag", False),
                    "final_flag": state.get("final_flag", ""),
                    "shell_session": state.get("shell_session", {}),
                    "current_mode": state.get("current_mode", "exploit"),
                    "failure_weighted_score": state.get("failure_weighted_score", 0),
                    "execution_steps": state.get("execution_steps", 0),
                    "site_topology": state.get("site_topology", {}),
                    "critical_nodes": state.get("critical_nodes", []),
                    "topology_priority": state.get("topology_priority", []),
                    # 节点状态信息（用于拓扑图显示）
                    "node_statuses": state.get("node_attack_status", {}),
                    # 已访问的URL列表（用于拓扑图显示）
                    "visited_urls": state.get("visited_urls", []),
                    # 云安全状态
                    "cloud_provider": state.get("cloud_provider", ""),
                    "cloud_phase": state.get("cloud_phase", ""),
                    "buckets_found": state.get("buckets_found", []),
                    # AI安全状态
                    "target_model": state.get("target_model", ""),
                    "ai_phase": state.get("ai_phase", ""),
                    "prompt_injection_success": state.get("prompt_injection_success", False),
                    "jailbreak_success": state.get("jailbreak_success", False),
                }

        if not hasattr(ctf_app, '_node_callbacks'):
            ctf_app._node_callbacks = {}
        ctf_app._node_callbacks[task_id] = node_callback

        # 取消检查函数
        def cancel_check():
            return cancel_manager and cancel_manager.is_cancelled(task_id)

        try:
            # 传入task_id和取消检查函数
            result = run_single_task(task_name, task_description, target_url,
                                     task_id=task_id, cancel_check=cancel_check)

            # 检查是否被取消
            if result.get('cancelled'):
                tasks[task_id]["status"] = "cancelled"
                log_callback(task_id, "[CANCELLED] Task stopped by user")
                task_completion_times[task_id] = time.time()
            elif result.get('found_flag'):
                tasks[task_id]["status"] = "completed"
                tasks[task_id]["found_flag"] = True
                tasks[task_id]["final_flag"] = result.get('final_flag', result.get('found_flag'))
                log_callback(task_id, f"[SUCCESS] FLAG: {tasks[task_id]['final_flag']}")
                task_completion_times[task_id] = time.time()
            else:
                tasks[task_id]["status"] = "completed"
                log_callback(task_id, "[END] Task completed, no FLAG found")
                task_completion_times[task_id] = time.time()

            tasks[task_id]["progress"] = 100
            task_results[task_id] = result

        except TaskCancelledError as e:
            # 处理取消异常
            tasks[task_id]["status"] = "cancelled"
            log_callback(task_id, f"[CANCELLED] Task stopped: {e}")
            task_completion_times[task_id] = time.time()

        finally:
            # 清除当前线程的任务ID
            set_current_task_id(None)
            if cancel_manager:
                cancel_manager.set_current_task(None)
                cancel_manager.clear_cancel(task_id)
            if hasattr(ctf_app, '_node_callbacks') and task_id in ctf_app._node_callbacks:
                del ctf_app._node_callbacks[task_id]

    except ImportError as e:
        log_callback(task_id, f"[Error] Import failed: {e}")
        log_callback(task_id, "[Info] Running in simulation mode...")
        run_simulated_task(task_id, target_url)
    except TaskCancelledError as e:
        # 处理取消异常（从run_single_task内部抛出）
        tasks[task_id]["status"] = "cancelled"
        log_callback(task_id, f"[CANCELLED] Task stopped by user")
        task_completion_times[task_id] = time.time()
    except Exception as e:
        import traceback
        log_callback(task_id, f"[Error] Task exception: {e}")
        log_callback(task_id, traceback.format_exc())

        # 检查是否是取消异常
        if TaskCancelledError and isinstance(e, TaskCancelledError):
            tasks[task_id]["status"] = "cancelled"
            log_callback(task_id, "[CANCELLED] Task stopped by user")
            task_completion_times[task_id] = time.time()
            return

        # 使用增强的错误处理机制
        error_result = record_task_error(
            task_id=task_id,
            node="run_task",
            error=e,
            state=task_results.get(task_id, {})
        )

        # 记录错误分析结果
        if error_result.get("analysis"):
            analysis = error_result["analysis"]
            log_callback(task_id, f"[AI Analysis] {analysis.get('root_cause', 'Unknown cause')}")

            # 如果 AI 建议恢复策略
            if analysis.get("is_recoverable") and analysis.get("recovery_strategies"):
                log_callback(task_id, f"[Recovery] Suggested: {analysis['recovery_strategies'][0].get('strategy', 'N/A')}")

        tasks[task_id]["status"] = "error"
        tasks[task_id]["error"] = str(e)
        tasks[task_id]["error_type"] = error_result.get("error_type", "EXECUTION_ERROR")
        tasks[task_id]["error_severity"] = error_result.get("severity", "MEDIUM")
        tasks[task_id]["error_analysis"] = error_result.get("analysis")
        task_completion_times[task_id] = time.time()


def run_simulated_task(task_id, target_url):
    """模拟运行任务"""
    nodes = ["challenge_type_detector", "recon", "analyst", "attacker", "verifier"]

    for node in nodes:
        # 检查取消状态
        if tasks[task_id]["status"] == "cancelled":
            break
        if cancel_manager and cancel_manager.is_cancelled(task_id):
            tasks[task_id]["status"] = "cancelled"
            log_callback(task_id, "[CANCELLED] Task stopped by user")
            break

        tasks[task_id]["current_node"] = node
        log_callback(task_id, f"[{node}] Executing...")

        time.sleep(2)

        tasks[task_id]["visited_nodes"].append(node)
        tasks[task_id]["progress"] = len(tasks[task_id]["visited_nodes"]) / len(nodes) * 100

        log_callback(task_id, f"[{node}] Completed")

    if tasks[task_id]["status"] != "cancelled":
        tasks[task_id]["status"] = "completed"
        tasks[task_id]["progress"] = 100
        log_callback(task_id, "[SUCCESS] Task completed!")


# =============================================================================
# API Routes
# =============================================================================

# 根路径处理 - 安全起见不提供默认首页
@app.route('/')
def root():
    """根路径 - 返回 404"""
    abort(404)


@bp.route('/')
def index():
    """前缀根路径 - 重定向到监控面板"""
    from flask import redirect, url_for
    return redirect(url_for('.monitor'))


@bp.route('/monitor')
def monitor():
    """监控面板"""
    return render_template('monitor.html')


@bp.route('/modules')
def modules():
    """模块管理"""
    return render_template('modules.html')


@bp.route('/topology')
def topology():
    """拓扑图可视化"""
    return render_template('topology.html')


@bp.route('/rag')
def rag_page():
    """RAG知识库检索页面"""
    return render_template('rag.html')


# =============================================================================
# RAG 知识库检索 API
# =============================================================================

@bp.route('/api/rag/status')
def api_rag_status():
    """获取RAG索引状态 - 使用预热缓存，毫秒级响应"""
    global _rag_status_cache

    # 如果已预热，直接返回缓存状态
    if _rag_status_cache:
        return jsonify(_rag_status_cache)

    # 未预热，尝试获取（可能超时）
    try:
        retriever = get_cached_rag_retriever()
        if retriever:
            status = {
                "writeups": retriever.writeups_collection.count() if retriever.writeups_collection else 0,
                "nuclei": retriever.nuclei_collection.count() if retriever.nuclei_collection else 0,
                "payloads": retriever.payloads_collection.count() if retriever.payloads_collection else 0,
                "security_resources": retriever.security_resources_collection.count() if retriever.security_resources_collection else 0,
                "available": True
            }
            status["total"] = sum([status["writeups"], status["nuclei"], status["payloads"], status["security_resources"]])
            return jsonify(status)
        else:
            return jsonify({"error": "Retriever not initialized", "available": False, "total": 0,
                            "writeups": 0, "nuclei": 0, "payloads": 0, "security_resources": 0})
    except Exception as e:
        return jsonify({"error": str(e), "available": False, "total": 0,
                        "writeups": 0, "nuclei": 0, "payloads": 0, "security_resources": 0})


@bp.route('/api/rag/search', methods=['POST'])
def api_rag_search():
    """搜索知识库 - 使用预热后的检索器，响应快速"""
    try:
        data = request.json or {}
        query = data.get('query', '')
        top_k = data.get('top_k', 5)
        sources = data.get('sources', ['writeups', 'nuclei', 'payloads', 'security_resources'])

        if not query:
            return jsonify({"error": "Query is required", "results": {}, "total": 0})

        # 使用缓存的检索器（预热后毫秒级响应）
        retriever = get_cached_rag_retriever()
        if not retriever:
            return jsonify({"error": "RAG retriever not initialized", "results": {}, "total": 0})

        results = retriever.search(query, top_k=top_k, sources=sources)

        return jsonify({"results": results, "total": results.get("total", 0)})
    except Exception as e:
        return jsonify({"error": str(e), "results": {}, "total": 0})


@bp.route('/api/rag/collections')
def api_rag_collections():
    """获取所有知识库集合信息 - 使用缓存"""
    global _rag_status_cache

    # 使用缓存状态构建集合信息
    if _rag_status_cache and _rag_status_cache.get("available"):
        collections = []
        collection_info = [
            ("writeups", "CTF Writeups", "CTF比赛题解和技术分析", "#1890ff"),
            ("nuclei", "Nuclei Templates", "Nuclei漏洞扫描模板", "#52c41a"),
            ("payloads", "Payloads", "各种攻击载荷和利用代码", "#faad14"),
            ("security_resources", "Security Resources", "安全资源和参考资料", "#eb2f96")
        ]

        for key, name, desc, color in collection_info:
            count = _rag_status_cache.get(key, 0)
            collections.append({
                "key": key,
                "name": name,
                "description": desc,
                "color": color,
                "count": count
            })

        return jsonify({"collections": collections})

    # 未预热，返回错误
    return jsonify({"error": _rag_status_cache.get("error", "RAG not initialized"), "collections": []})


@bp.route('/api/graph')
def api_graph():
    """获取图结构"""
    return jsonify(get_graph_structure())


@bp.route('/api/system/status')
def api_system_status():
    """获取系统状态"""
    try:
        from tool_framework import ToolRegistry
        from tools import _ensure_tools_loaded
        _ensure_tools_loaded()
        stats = ToolRegistry.get_statistics()
        tools_loaded = stats.get("total_tools", 0)
    except ImportError as e:
        print(f"[API] ToolRegistry not available: {e}")
        tools_loaded = 0
    except Exception as e:
        print(f"[API] Failed to get tool stats: {e}")
        tools_loaded = 0

    try:
        from remote_executor.session_manager import get_session_manager
        sm = get_session_manager()
        active_sessions = len(sm.sessions)
    except ImportError as e:
        print(f"[API] SessionManager not available: {e}")
        active_sessions = 0
    except Exception as e:
        print(f"[API] Failed to get session count: {e}")
        active_sessions = 0

    # 检测LLM连接状态
    llm_connected = False
    try:
        from llm_client import llm_client
        from config import config
        # 尝试简单的连接测试
        if hasattr(llm_client, 'test_connection'):
            llm_connected = llm_client.test_connection()
        elif hasattr(config, 'OPENAI_API_KEY') and config.OPENAI_API_KEY:
            llm_connected = True  # 有API key就认为连接可用
        else:
            llm_connected = bool(config.ANTHROPIC_API_KEY or config.OPENAI_API_KEY)
    except Exception as e:
        print(f"[API] LLM connection check failed: {e}")
        llm_connected = False

    return jsonify({
        "llm_connected": llm_connected,
        "tools_loaded": tools_loaded,
        "active_sessions": active_sessions,
        "start_time": system_status["start_time"],
        "tasks_total": len(tasks),
        "tasks_running": sum(1 for t in tasks.values() if t["status"] == "running"),
        "tasks_completed": sum(1 for t in tasks.values() if t["status"] == "completed")
    })


@bp.route('/api/tools')
def api_tools():
    """获取可用工具列表（分类显示）"""
    try:
        from tool_framework import ToolRegistry
        from tools import _ensure_tools_loaded
        _ensure_tools_loaded()

        # 定义工具分类 - 与实际注册的工具完全匹配
        categories = {
            "impacket": {
                "name": "Impacket工具集",
                "tools": [
                    # 远程执行 (5)
                    "psexec", "wmiexec", "smbexec", "atexec", "dcomexec",
                    # 凭据导出 (1)
                    "secretsdump",
                    # Kerberos攻击 (4)
                    "getnpusers", "getuserspns", "ticketer", "goldenpac",
                    # NTLM中继 (1)
                    "ntlmrelayx",
                    # AD域渗透 (3)
                    "dacledit", "getadusers", "raisechild",
                    # SMB工具 (3)
                    "smbclient", "lookupsid", "smbserver",
                    # MSSQL工具 (2)
                    "mssqlclient", "mssqlinstance",
                    # RPC工具 (2)
                    "rpcdump", "samrdump",
                    # 其他 (3)
                    "reg", "services", "getarch"
                ]
            },
            "web_attack": {
                "name": "Web攻击",
                "tools": [
                    "sqlmap", "ffuf", "dirsearch", "nuclei", "xray", "nmap",
                    "dalfox", "oa-exploiter", "httpx", "subfinder"
                ]
            },
            "java_deserialize": {
                "name": "Java反序列化",
                "tools": ["ysoserial", "jndi-exploit", "marshalsec"]
            },
            "ad_attack": {
                "name": "AD域攻击",
                "tools": ["petitpotam", "rubeus", "bloodhound", "crackmapexec", "mimikatz", "getnpusers", "getuserspns", "secretsdump"]
            },
            "privilege_escalation": {
                "name": "权限提升",
                "tools": ["potato", "privesc"]
            },
            "info_leak": {
                "name": "信息泄露",
                "tools": ["jsfinder", "git-hacker", "xxe-injector", "ajp-shooter"]
            },
            "session_attack": {
                "name": "会话攻击",
                "tools": ["flask-unsign", "jwt-tool"]
            },
            "crypto": {
                "name": "密码学",
                "tools": ["fenjing"]
            },
            "framework": {
                "name": "框架工具",
                "tools": ["fscan", "hydra", "msf"]
            },
            "deserialization": {
                "name": "反序列化",
                "tools": ["phpggc", "pickle-pwn", "phar-gen"]
            },
            "file_attack": {
                "name": "文件攻击",
                "tools": ["php-filter-chain", "file-creator"]
            },
            "scanner": {
                "name": "扫描器",
                "tools": ["cve-scanner", "ssrf-scanner", "cloud-scanner"]
            },
            "database": {
                "name": "数据库攻击",
                "tools": ["db-attacks"]
            },
            "utility": {
                "name": "实用工具",
                "tools": ["python-exec", "container-escape-checker", "frp-manager", "ai-attacker"]
            },
            "other": {
                "name": "其他工具",
                "tools": []  # 未分类的工具会放在这里
            }
        }

        # 收集所有工具
        all_tools = {}
        for tool in ToolRegistry.get_all_tools():
            tool_name = tool.name()
            all_tools[tool_name] = {
                "name": tool_name,
                "description": tool.description() if hasattr(tool, 'description') else "",
                "available": tool.check_available() if hasattr(tool, 'check_available') else True
            }

        # 按分类组织工具
        categorized_tools = {}
        used_tools = set()

        for cat_key, cat_info in categories.items():
            if cat_key == "other":
                continue
            cat_tools = []
            for tool_name in cat_info["tools"]:
                if tool_name in all_tools:
                    cat_tools.append(all_tools[tool_name])
                    used_tools.add(tool_name)

            if cat_tools:
                categorized_tools[cat_key] = {
                    "name": cat_info["name"],
                    "tools": cat_tools,
                    "available_count": sum(1 for t in cat_tools if t["available"]),
                    "total_count": len(cat_tools)
                }

        # 未分类的工具放入"其他"
        other_tools = [t for name, t in all_tools.items() if name not in used_tools]
        if other_tools:
            categorized_tools["other"] = {
                "name": "其他工具",
                "tools": other_tools,
                "available_count": sum(1 for t in other_tools if t["available"]),
                "total_count": len(other_tools)
            }

        return jsonify({
            "categories": categorized_tools,
            "total": len(all_tools),
            "available": sum(1 for t in all_tools.values() if t["available"])
        })
    except Exception as e:
        return jsonify({"categories": {}, "error": str(e)})


@bp.route('/api/sessions')
def api_sessions():
    """获取活跃会话"""
    try:
        from remote_executor.session_manager import get_session_manager
        sm = get_session_manager()
        sessions = []
        for sid, session in sm.sessions.items():
            sessions.append({
                "id": sid,
                "type": str(session.session_type),
                "target": session.target,
                "os_type": session.os_type,
                "created": session.created_at if hasattr(session, 'created_at') else ""
            })
        return jsonify({"sessions": sessions})
    except Exception as e:
        return jsonify({"sessions": [], "error": str(e)})


@bp.route('/api/task/start', methods=['POST'])
def api_task_start():
    """启动新任务"""
    data = request.json
    target_url = data.get('target_url', '')
    task_name = data.get('task_name', '')
    task_description = data.get('task_description', '')

    if not target_url:
        return jsonify({"error": "Target URL required"}), 400

    task_id = f"task_{int(time.time() * 1000)}"

    tasks[task_id] = {
        "id": task_id,
        "target_url": target_url,
        "status": "running",
        "current_node": "",
        "visited_nodes": [],
        "progress": 0,
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "task_name": task_name,
        "task_description": task_description,
        "found_flag": False,
        "final_flag": ""
    }
    task_logs[task_id] = []
    task_states[task_id] = ""
    task_results[task_id] = {}

    # 持久化任务创建
    if task_persistence:
        try:
            task_persistence.create_task(
                task_id=task_id,
                target=target_url,
                mode="web_ctf",
                metadata={"task_name": task_name, "task_description": task_description}
            )
        except Exception as e:
            print(f"[API] Failed to persist task: {e}")

    thread = threading.Thread(target=run_task, args=(task_id, target_url))
    thread.daemon = True
    thread.start()

    return jsonify({"task_id": task_id, "status": "started"})


@bp.route('/api/task/<task_id>')
def api_task_status(task_id):
    """获取任务状态"""
    if task_id not in tasks:
        return jsonify({"error": "Task not found"}), 404

    task = tasks[task_id]
    result = task_results.get(task_id, {})

    return jsonify({
        "id": task["id"],
        "target_url": task["target_url"],
        "status": task["status"],
        "current_node": task["current_node"],
        "visited_nodes": task["visited_nodes"],
        "progress": task["progress"],
        "created_at": task["created_at"],
        "error": task.get("error", ""),
        "task_name": task.get("task_name", ""),
        "task_description": task.get("task_description", ""),
        "found_flag": task.get("found_flag", False),
        "final_flag": task.get("final_flag", ""),
        "vuln_candidates": result.get("vuln_candidates", []),
        "credentials": result.get("credentials", []),
        "internal_hosts": result.get("internal_hosts", []),
        "current_mode": result.get("current_mode", ""),
        "execution_steps": result.get("execution_steps", 0),
        # 云安全状态
        "cloud_provider": result.get("cloud_provider", ""),
        "cloud_phase": result.get("cloud_phase", ""),
        "buckets_found": result.get("buckets_found", []),
        # AI安全状态
        "target_model": result.get("target_model", ""),
        "ai_phase": result.get("ai_phase", ""),
        "prompt_injection_success": result.get("prompt_injection_success", False),
        "jailbreak_success": result.get("jailbreak_success", False),
    })


@bp.route('/api/task/<task_id>/logs')
def api_task_logs(task_id):
    """获取任务日志"""
    if task_id not in task_logs:
        return jsonify({"logs": []})

    offset = request.args.get('offset', 0, type=int)
    logs = task_logs[task_id][offset:]

    return jsonify({
        "logs": logs,
        "total": len(task_logs[task_id])
    })


@bp.route('/api/task/<task_id>/cancel', methods=['POST'])
def api_task_cancel(task_id):
    """取消/终止任务 - 真正中断执行"""
    if task_id not in tasks:
        return jsonify({"error": "Task not found"}), 404

    task = tasks[task_id]
    if task["status"] == "running":
        # 使用取消管理器标记任务为取消
        if cancel_manager:
            cancel_manager.request_cancel(task_id)
            log_callback(task_id, "[System] Task cancelled by user - interrupting execution")
        else:
            # 降级处理：仅设置状态
            task["status"] = "cancelled"
            log_callback(task_id, "[System] Task cancelled by user")

        return jsonify({"status": "cancelled", "message": "Task cancellation requested"})
    else:
        return jsonify({"error": "Task is not running", "status": task["status"]}), 400


@bp.route('/api/task/<task_id>', methods=['DELETE'])
def api_task_delete(task_id):
    """删除任务记录"""
    global tasks, task_logs, task_queues, task_states, task_results

    if task_id not in tasks:
        return jsonify({"error": "Task not found"}), 404

    task = tasks[task_id]

    # 不允许删除正在运行的任务
    if task["status"] == "running":
        return jsonify({"error": "Cannot delete running task. Cancel it first."}), 400

    # 清理所有相关数据
    tasks.pop(task_id, None)
    task_logs.pop(task_id, None)
    task_queues.pop(task_id, None)
    task_states.pop(task_id, None)
    task_results.pop(task_id, None)
    task_completion_times.pop(task_id, None)

    return jsonify({"status": "deleted", "task_id": task_id})


@bp.route('/api/tasks/clear', methods=['POST'])
def api_tasks_clear():
    """清空所有已完成的任务"""
    global tasks, task_logs, task_queues, task_states, task_results

    cleared_count = 0
    task_ids_to_delete = []

    # 找出所有非运行状态的任务
    for task_id, task in list(tasks.items()):
        if task["status"] != "running":
            task_ids_to_delete.append(task_id)

    # 删除任务
    for task_id in task_ids_to_delete:
        tasks.pop(task_id, None)
        task_logs.pop(task_id, None)
        task_queues.pop(task_id, None)
        task_states.pop(task_id, None)
        task_results.pop(task_id, None)
        task_completion_times.pop(task_id, None)
        cleared_count += 1

    return jsonify({
        "status": "cleared",
        "cleared_count": cleared_count,
        "remaining_count": len(tasks)
    })


@bp.route('/api/task/<task_id>/restart', methods=['POST'])
def api_task_restart(task_id):
    """重启任务"""
    if task_id not in tasks:
        return jsonify({"error": "Task not found"}), 404

    old_task = tasks[task_id]
    target_url = old_task.get("target_url", "")

    if not target_url:
        return jsonify({"error": "No target URL found"}), 400

    # 创建新任务
    import uuid
    new_task_id = str(uuid.uuid4())[:8]

    tasks[new_task_id] = {
        "id": new_task_id,
        "target_url": target_url,
        "status": "pending",
        "current_node": "",
        "visited_nodes": [],
        "progress": 0,
        "created_at": time.time(),
        "task_name": old_task.get("task_name", ""),
        "task_description": old_task.get("task_description", "")
    }

    task_logs[new_task_id] = []
    task_queues[new_task_id] = queue.Queue()
    task_states[new_task_id] = ""
    task_results[new_task_id] = {}

    # 在后台启动任务
    thread = threading.Thread(target=run_task, args=(new_task_id, target_url))
    thread.daemon = True
    thread.start()

    return jsonify({
        "status": "restarted",
        "old_task_id": task_id,
        "new_task_id": new_task_id
    })


@bp.route('/api/task/<task_id>/result')
def api_task_result(task_id):
    """获取任务详细结果"""
    if task_id not in task_results:
        return jsonify({"error": "No results"}), 404

    return jsonify(task_results[task_id])


@bp.route('/api/tasks')
def api_tasks():
    """获取任务列表"""
    task_list = []
    for tid, task in tasks.items():
        task_list.append({
            "id": task["id"],
            "target_url": task["target_url"],
            "status": task["status"],
            "progress": task["progress"],
            "created_at": task["created_at"],
            "task_name": task.get("task_name", ""),
            "found_flag": task.get("found_flag", False)
        })

    # 按时间倒序
    task_list.sort(key=lambda x: x["created_at"], reverse=True)

    return jsonify({"tasks": task_list})


@bp.route('/api/task/<task_id>/stream')
def api_task_stream(task_id):
    """日志流（SSE）- 使用Queue阻塞等待"""
    # 确保队列存在
    if task_id not in task_queues:
        task_queues[task_id] = queue.Queue()

    task_queue = task_queues[task_id]

    def generate():
        while True:
            try:
                # 阻塞等待，最多等待30秒
                log_entry = task_queue.get(timeout=30)
                yield f"data: {json.dumps(log_entry)}\n\n"

                # 检查是否结束
                if log_entry.get("type") == "end":
                    break

            except queue.Empty:
                # 发送心跳包保持连接
                yield ": heartbeat\n\n"

                # 检查任务是否已结束
                if tasks.get(task_id, {}).get("status") in ["completed", "error", "cancelled"]:
                    yield f"data: {json.dumps({'type': 'end'})}\n\n"
                    break

    return Response(generate(), mimetype='text/event-stream')


@bp.route('/api/health')
def api_health():
    """健康检查"""
    return jsonify({"status": "ok", "timestamp": datetime.now().isoformat()})


# =============================================================================
# 任务持久化 API
# =============================================================================

@bp.route('/api/persistence/tasks')
def api_persistence_tasks():
    """获取持久化的任务列表"""
    if not task_persistence:
        return jsonify({"error": "Persistence module not available"}), 503

    status = request.args.get('status', '')
    limit = request.args.get('limit', 50, type=int)

    if status:
        records = task_persistence.get_tasks_by_status(status)
    else:
        # 获取所有任务（不只是活跃任务）
        try:
            records = task_persistence.get_all_tasks(limit=limit)
        except AttributeError:
            # 如果没有 get_all_tasks 方法，使用 get_active_tasks
            records = task_persistence.get_active_tasks()

    return jsonify({
        "tasks": [r.to_dict() if hasattr(r, 'to_dict') else r for r in records],
        "total": len(records)
    })


@bp.route('/api/persistence/task/<task_id>')
def api_persistence_task(task_id):
    """获取持久化的任务详情"""
    if not task_persistence:
        return jsonify({"error": "Persistence module not available"}), 503

    record = task_persistence.get_task(task_id)
    if not record:
        return jsonify({"error": "Task not found"}), 404

    # 获取执行历史
    history = task_persistence.get_execution_history(task_id)
    discoveries = task_persistence.get_discoveries(task_id)

    # 获取任务记录字典
    task_dict = record.to_dict() if hasattr(record, 'to_dict') else record

    # 合并到返回结果
    result = {
        "task_id": task_dict.get("task_id", task_id),
        "target": task_dict.get("target", ""),
        "status": task_dict.get("status", "unknown"),
        "created_at": task_dict.get("created_at", ""),
        "completed_at": task_dict.get("completed_at", ""),
        "found_flag": task_dict.get("found_flag", False),
        "final_flag": task_dict.get("final_flag", ""),
        "execution_history": history[:50] if history else [],
        "discoveries": discoveries if discoveries else []
    }

    return jsonify(result)


@bp.route('/api/persistence/statistics')
def api_persistence_statistics():
    """获取任务统计信息"""
    if not task_persistence:
        return jsonify({"error": "Persistence module not available"}), 503

    return jsonify(task_persistence.get_statistics())


@bp.route('/api/persistence/task/<task_id>', methods=['DELETE'])
def api_persistence_delete_task(task_id):
    """删除持久化任务"""
    if not task_persistence:
        return jsonify({"error": "Persistence module not available"}), 503

    success = task_persistence.delete_task(task_id)
    return jsonify({"success": success})


# =============================================================================
# 自我纠错状态 API
# =============================================================================

@bp.route('/api/system/recovery')
def api_system_recovery():
    """获取自我纠错状态"""
    if not self_correction_manager:
        return jsonify({"error": "Self-correction module not available"}), 503

    stats = self_correction_manager.get_recovery_stats()
    error_summary = self_correction_manager.get_error_summary()

    return jsonify({
        "recovery_stats": stats,
        "recent_errors": error_summary
    })


@bp.route('/api/system/recovery/history')
def api_recovery_history():
    """获取错误恢复历史"""
    if not self_correction_manager:
        return jsonify({"error": "Self-correction module not available"}), 503

    return jsonify({
        "errors": [
            {
                "timestamp": e.timestamp,
                "node": e.node,
                "error_type": e.error_type,
                "error_message": e.error_message[:200],
                "severity": e.severity.name,
                "recovered": e.recovered,
                "recovery_action": e.recovery_action
            }
            for e in self_correction_manager.error_history[-20:]
        ]
    })


@bp.route('/api/errors/statistics')
def api_error_statistics():
    """获取错误统计信息"""
    if not self_correction_manager:
        return jsonify({"error": "Self-correction module not available"}), 503

    # 按错误类型统计
    error_type_counts = {}
    for e in self_correction_manager.error_history:
        error_type_counts[e.error_type] = error_type_counts.get(e.error_type, 0) + 1

    # 按节点统计
    node_error_counts = {}
    for e in self_correction_manager.error_history:
        node_error_counts[e.node] = node_error_counts.get(e.node, 0) + 1

    # 按严重程度统计
    severity_counts = {}
    for e in self_correction_manager.error_history:
        severity_name = e.severity.name if hasattr(e.severity, 'name') else str(e.severity)
        severity_counts[severity_name] = severity_counts.get(severity_name, 0) + 1

    # 恢复率
    total_errors = len(self_correction_manager.error_history)
    recovered_count = sum(1 for e in self_correction_manager.error_history if e.recovered)

    return jsonify({
        "total_errors": total_errors,
        "recovered_count": recovered_count,
        "recovery_rate": recovered_count / total_errors if total_errors > 0 else 0,
        "by_type": error_type_counts,
        "by_node": node_error_counts,
        "by_severity": severity_counts,
        "is_healthy": self_correction_manager.health_status.is_healthy,
        "consecutive_failures": self_correction_manager.health_status.consecutive_failures
    })


@bp.route('/api/errors/recent')
def api_recent_errors():
    """获取最近错误列表（带分页）"""
    if not self_correction_manager:
        return jsonify({"error": "Self-correction module not available"}), 503

    limit = request.args.get('limit', 50, type=int)
    offset = request.args.get('offset', 0, type=int)
    error_type = request.args.get('type', '')
    severity = request.args.get('severity', '')

    # 过滤错误
    filtered = self_correction_manager.error_history
    if error_type:
        filtered = [e for e in filtered if e.error_type == error_type]
    if severity:
        filtered = [e for e in filtered if hasattr(e.severity, 'name') and e.severity.name == severity]

    # 分页
    total = len(filtered)
    paginated = filtered[offset:offset + limit]

    return jsonify({
        "total": total,
        "errors": [
            {
                "timestamp": e.timestamp,
                "datetime": datetime.fromtimestamp(e.timestamp).isoformat() if e.timestamp else None,
                "node": e.node,
                "error_type": e.error_type,
                "error_message": e.error_message,
                "severity": e.severity.name if hasattr(e.severity, 'name') else str(e.severity),
                "recovered": e.recovered,
                "recovery_action": e.recovery_action,
                "stack_trace": e.stack_trace[:500] if e.stack_trace else None
            }
            for e in paginated
        ]
    })


@bp.route('/api/errors/analyze', methods=['POST'])
def api_analyze_error():
    """AI 分析错误"""
    if not self_correction_manager:
        return jsonify({"error": "Self-correction module not available"}), 503

    data = request.json
    error_message = data.get('error_message', '')
    node = data.get('node', '')
    context = data.get('context', {})

    if not error_message:
        return jsonify({"error": "error_message required"}), 400

    # 创建临时错误记录
    from self_correction import ErrorRecord, ErrorSeverity

    temp_record = ErrorRecord(
        timestamp=time.time(),
        node=node or "unknown",
        error_type="MANUAL_ANALYSIS",
        error_message=error_message,
        severity=ErrorSeverity.MEDIUM
    )

    # AI 分析
    analysis = self_correction_manager.analyze_failure_with_ai(temp_record, context)

    return jsonify({
        "analysis": analysis
    })


# =============================================================================
# 攻击策略评估 API
# =============================================================================

@bp.route('/api/strategy/evaluate', methods=['POST'])
def api_strategy_evaluate():
    """评估攻击策略"""
    if not strategy_evaluator:
        return jsonify({"error": "Strategy evaluator not available"}), 503

    data = request.json
    tool = data.get('tool', '')
    target = data.get('target', '')
    vuln_type = data.get('vuln_type', '')
    context = data.get('context', {})

    if not tool or not target:
        return jsonify({"error": "tool and target required"}), 400

    from attack_strategy_evaluator import evaluate_attack_strategy
    result = evaluate_attack_strategy(tool, target, vuln_type, context)

    return jsonify({
        "score": result.score,
        "confidence": result.confidence,
        "reasoning": result.reasoning,
        "recommendations": result.recommendations,
        "alternatives": [
            {
                "tool": s.tool,
                "target": s.target,
                "vuln_type": s.vuln_type,
                "estimated_success_rate": s.estimated_success_rate
            }
            for s in result.alternative_strategies
        ]
    })


@bp.route('/api/strategy/analyze-path', methods=['POST'])
def api_strategy_analyze_path():
    """分析攻击路径"""
    if not strategy_evaluator:
        return jsonify({"error": "Strategy evaluator not available"}), 503

    data = request.json
    target = data.get('target', '')
    vulnerabilities = data.get('vulnerabilities', [])
    context = data.get('context', {})

    result = strategy_evaluator.analyze_attack_path(target, vulnerabilities, context)

    return jsonify(result)


@bp.route('/api/strategy/statistics')
def api_strategy_statistics():
    """获取策略评估统计"""
    if not strategy_evaluator:
        return jsonify({"error": "Strategy evaluator not available"}), 503

    return jsonify(strategy_evaluator.get_statistics())


# =============================================================================
# LLM 状态 API
# =============================================================================

@bp.route('/api/llm/status')
def api_llm_status():
    """获取 LLM 状态"""
    try:
        from llm_client import get_rate_limiter_status
        status = get_rate_limiter_status()
        return jsonify(status)
    except ImportError:
        return jsonify({"error": "LLM client not available"}), 503


# =============================================================================
# 性能监控 API
# =============================================================================

@bp.route('/api/performance/stats')
def api_performance_stats():
    """获取性能统计"""
    try:
        from performance import performance_monitor
        return jsonify(performance_monitor.get_full_stats())
    except ImportError:
        return jsonify({"error": "Performance monitor not available"}), 503


@bp.route('/api/performance/records')
def api_performance_records():
    """获取最近执行记录"""
    try:
        from performance import performance_monitor
        limit = request.args.get('limit', 50, type=int)
        return jsonify({"records": performance_monitor.get_recent_records(limit)})
    except ImportError:
        return jsonify({"error": "Performance monitor not available"}), 503


@bp.route('/api/performance/slow')
def api_performance_slow():
    """获取慢操作列表"""
    try:
        from performance import performance_monitor
        threshold = request.args.get('threshold', 5000, type=float)
        return jsonify({"slow_ops": performance_monitor.get_slow_operations(threshold)})
    except ImportError:
        return jsonify({"error": "Performance monitor not available"}), 503


@bp.route('/api/performance/reset', methods=['POST'])
def api_performance_reset():
    """重置性能统计"""
    try:
        from performance import performance_monitor
        performance_monitor.reset()
        return jsonify({"success": True})
    except ImportError:
        return jsonify({"error": "Performance monitor not available"}), 503


@bp.route('/api/performance/summary')
def api_performance_summary():
    """获取性能摘要（供监控面板使用）"""
    try:
        from performance import performance_monitor
        stats = performance_monitor.get_full_stats()

        # 计算摘要
        node_count = sum(v.get("count", 0) for v in stats.get("nodes", {}).values())
        tool_count = sum(v.get("total_executions", 0) for v in stats.get("tools", {}).values())
        llm_count = sum(v.get("count", 0) for v in stats.get("llm", {}).values())

        # 计算平均耗时
        total_ms = 0
        total_ops = 0
        for v in stats.get("nodes", {}).values():
            total_ms += v.get("total_ms", 0)
            total_ops += v.get("count", 0)
        for v in stats.get("tools", {}).values():
            total_ms += v.get("total_duration", 0) * 1000
            total_ops += v.get("total_executions", 0)

        avg_duration = total_ms / max(total_ops, 1)

        # 获取慢操作数
        slow_ops = performance_monitor.get_slow_operations(5000)

        return jsonify({
            "total_operations": node_count + tool_count + llm_count,
            "node_count": node_count,
            "tool_count": tool_count,
            "llm_count": llm_count,
            "avg_duration_ms": round(avg_duration, 2),
            "slow_ops_count": len(slow_ops),
            "uptime_seconds": stats.get("uptime_seconds", 0)
        })
    except ImportError:
        return jsonify({"error": "Performance monitor not available"}), 503


@bp.route('/api/performance/history')
def api_performance_history():
    """获取性能历史趋势数据"""
    try:
        from memory.performance_persistence import get_performance_persistence
        persistence = get_performance_persistence()
        days = request.args.get('days', 7, type=int)
        history = persistence.get_history(days)
        return jsonify(history)
    except ImportError:
        return jsonify({"error": "Performance persistence not available"}), 503


# =============================================================================
# 上下文压缩状态 API
# =============================================================================

@bp.route('/api/compression/status')
def api_compression_status():
    """获取压缩状态"""
    try:
        from context_compressor import get_compressor
        compressor = get_compressor()
        stats = compressor.get_compression_stats()
        return jsonify(stats)
    except ImportError:
        return jsonify({"error": "Compressor not available"}), 503


# =============================================================================
# 系统资源监控 API
# =============================================================================

# 系统监控历史数据存储
_system_monitor_history = {
    "cpu": [],
    "memory": [],
    "network": [],
    "timestamps": [],
    "max_points": 60  # 保留最近60个数据点
}
_monitor_lock = threading.Lock()

def _collect_system_metrics():
    """收集系统指标"""
    try:
        import psutil

        # CPU使用率
        cpu_percent = psutil.cpu_percent(interval=0.1)

        # 内存使用
        memory = psutil.virtual_memory()
        memory_percent = memory.percent
        memory_used = memory.used
        memory_total = memory.total

        # 网络流量
        net = psutil.net_io_counters()
        bytes_sent = net.bytes_sent
        bytes_recv = net.bytes_recv

        # 磁盘使用
        disk = psutil.disk_usage('/')
        disk_percent = disk.percent
        disk_used = disk.used
        disk_total = disk.total

        return {
            "cpu_percent": cpu_percent,
            "memory": {
                "percent": memory_percent,
                "used": memory_used,
                "total": memory_total
            },
            "network": {
                "bytes_sent": bytes_sent,
                "bytes_recv": bytes_recv
            },
            "disk": {
                "percent": disk_percent,
                "used": disk_used,
                "total": disk_total
            }
        }
    except ImportError:
        # psutil不可用，返回模拟数据
        return {
            "cpu_percent": 0,
            "memory": {"percent": 0, "used": 0, "total": 0},
            "network": {"bytes_sent": 0, "bytes_recv": 0},
            "disk": {"percent": 0, "used": 0, "total": 0}
        }

def _update_monitor_history():
    """更新监控历史"""
    metrics = _collect_system_metrics()
    timestamp = time.time()

    with _monitor_lock:
        _system_monitor_history["cpu"].append(metrics["cpu_percent"])
        _system_monitor_history["memory"].append(metrics["memory"]["percent"])
        _system_monitor_history["network"].append({
            "sent": metrics["network"]["bytes_sent"],
            "recv": metrics["network"]["bytes_recv"]
        })
        _system_monitor_history["timestamps"].append(timestamp)

        # 限制数据点数量
        max_pts = _system_monitor_history["max_points"]
        for key in ["cpu", "memory", "network", "timestamps"]:
            if len(_system_monitor_history[key]) > max_pts:
                _system_monitor_history[key] = _system_monitor_history[key][-max_pts:]

    return metrics


@bp.route('/api/system/metrics')
def api_system_metrics():
    """获取系统资源指标"""
    metrics = _update_monitor_history()
    return jsonify(metrics)


@bp.route('/api/system/metrics/history')
def api_system_metrics_history():
    """获取系统资源历史数据"""
    with _monitor_lock:
        # 计算网络流量变化率
        network_data = _system_monitor_history["network"]
        timestamps = _system_monitor_history["timestamps"]

        # 计算每秒传输速率
        net_rates = []
        for i in range(1, len(network_data)):
            if i > 0:
                time_diff = timestamps[i] - timestamps[i-1]
                if time_diff > 0:
                    sent_rate = (network_data[i]["sent"] - network_data[i-1]["sent"]) / time_diff
                    recv_rate = (network_data[i]["recv"] - network_data[i-1]["recv"]) / time_diff
                    net_rates.append({"sent_rate": sent_rate, "recv_rate": recv_rate})

        return jsonify({
            "cpu": _system_monitor_history["cpu"],
            "memory": _system_monitor_history["memory"],
            "network_rates": net_rates,
            "timestamps": timestamps,
            "current": {
                "cpu": _system_monitor_history["cpu"][-1] if _system_monitor_history["cpu"] else 0,
                "memory": _system_monitor_history["memory"][-1] if _system_monitor_history["memory"] else 0
            }
        })

@bp.route('/api/modules')
def api_modules():
    """获取所有模块状态"""
    try:
        from module_registry import ModuleRegistry
        report = ModuleRegistry.get_status_report()
        return jsonify(report)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@bp.route('/api/modules/<module_name>')
def api_module_detail(module_name):
    """获取单个模块详情"""
    try:
        from module_registry import ModuleRegistry
        info = ModuleRegistry.get_module_info(module_name)
        if info:
            return jsonify({
                "name": info.name,
                "available": info.available,
                "nodes": list(info.nodes.keys()) if info.available else [],
                "error": info.error
            })
        return jsonify({"error": "Module not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@bp.route('/api/modules/<module_name>/nodes')
def api_module_nodes(module_name):
    """获取模块中的节点列表"""
    try:
        from module_registry import ModuleRegistry
        info = ModuleRegistry.get_module_info(module_name)
        if info and info.available:
            nodes = []
            for node_name, node_func in info.nodes.items():
                nodes.append({
                    "name": node_name,
                    "available": node_func is not None
                })
            return jsonify({"nodes": nodes})
        return jsonify({"error": "Module not available"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# =============================================================================
# 拓扑图 API
# =============================================================================

@bp.route('/api/topology/<task_id>')
def api_topology(task_id):
    """获取任务的拓扑图数据"""
    if task_id not in task_results:
        return jsonify({"error": "Task not found"}), 404

    result = task_results.get(task_id, {})
    topology = result.get("site_topology", {})

    if not topology:
        return jsonify({"nodes": [], "edges": [], "message": "No topology data available"})

    # 转换为 D3.js 格式
    nodes = []
    edges = []
    seen_nodes = set()

    for source, targets in topology.items():
        if source not in seen_nodes:
            nodes.append({"id": source, "name": source.split("/")[-1] or "/"})
            seen_nodes.add(source)
        for target in targets:
            if target not in seen_nodes:
                nodes.append({"id": target, "name": target.split("/")[-1] or "/"})
                seen_nodes.add(target)
            edges.append({"source": source, "target": target})

    return jsonify({
        "nodes": nodes,
        "edges": edges,
        "stats": {
            "total_nodes": len(nodes),
            "total_edges": len(edges)
        }
    })


@bp.route('/api/topology/<task_id>/critical')
def api_topology_critical(task_id):
    """获取关键节点"""
    if task_id not in task_results:
        return jsonify({"error": "Task not found"}), 404

    result = task_results.get(task_id, {})
    critical_nodes = result.get("critical_nodes", [])

    return jsonify({"critical_nodes": critical_nodes})


@bp.route('/api/topology/<task_id>/statuses')
def api_topology_statuses(task_id):
    """获取节点状态信息"""
    if task_id not in task_results:
        return jsonify({"error": "Task not found"}), 404

    result = task_results.get(task_id, {})

    # 获取拓扑数据
    topology = result.get("site_topology", {})
    node_attack_status = result.get("node_statuses", {})
    visited_urls = result.get("visited_urls", [])

    # 构建节点状态信息
    # 将 node_attack_status 的格式转换为前端期望的格式
    node_statuses = {}
    all_nodes = set(topology.keys())
    for targets in topology.values():
        all_nodes.update(targets)

    for node in all_nodes:
        # 检查节点是否有攻击状态
        attack_status = node_attack_status.get(node, {})

        # 转换状态值
        raw_status = attack_status.get("status", "")
        if raw_status == "success":
            status = "success"
        elif raw_status == "abandoned":
            status = "failed"
        elif raw_status == "active":
            status = "visited"
        elif node in visited_urls:
            status = "visited"
        else:
            status = "pending"

        node_statuses[node] = {
            "status": status,
            "attempts": attack_status.get("attempt_count", 0),
            "priority": 0.5,
            "last_result": "",
            "metadata": {}
        }

    return jsonify({
        "statuses": node_statuses,
        "stats": {
            "total": len(node_statuses),
            "success": sum(1 for s in node_statuses.values() if s.get("status") == "success"),
            "failed": sum(1 for s in node_statuses.values() if s.get("status") == "failed"),
            "deprioritized": sum(1 for s in node_statuses.values() if s.get("status") == "deprioritized"),
            "pending": sum(1 for s in node_statuses.values() if s.get("status") == "pending"),
            "visited": sum(1 for s in node_statuses.values() if s.get("status") == "visited")
        }
    })


# =============================================================================
# 系统控制 API
# =============================================================================

# 模块启用状态存储 - 默认全部启用
DEFAULT_MODULES = [
    'internal_network', 'post_exploit',
    'crypto', 'pwn', 'reverse', 'misc',
    'performance', 'self_correction',
    'web', 'decision', 'entry', 'end'
]
module_enabled = {name: True for name in DEFAULT_MODULES}
tool_enabled = {}

# 节点启用状态存储 - 默认全部启用
DEFAULT_NODES = [
    'challenge_type_detector', 'recon', 'analyst', 'strategy_filter',
    'mode_manager', 'attacker', 'verifier', 'explorer', 'innovator', 'evolution',
    'post_exploit', 'upload_tools', 'setup_tunnel', 'internal_recon',
    'lateral_move', 'privilege_escalation', 'persistence', 'credential_gather',
    'crypto_analyst', 'crypto_solver',
    'pwn_analyst', 'pwn_exploiter',
    'reverse_analyst', 'reverse_decompiler',
    'misc_analyst', 'misc_extractor'
]
node_enabled = {name: True for name in DEFAULT_NODES}

@bp.route('/api/system/config', methods=['GET'])
def api_get_config():
    """获取当前配置"""
    try:
        from config import config
        return jsonify({
            "LLM_BASE_URL": config.LLM_BASE_URL,
            "LLM_API_KEY": "***" + config.LLM_API_KEY[-6:] if config.LLM_API_KEY else "",
            "ANALYST_MODEL": config.ANALYST_MODEL,
            "ATTACKER_MODEL": config.ATTACKER_MODEL,
            "MAX_TOTAL_ROUNDS": config.MAX_TOTAL_ROUNDS,
            "LOCAL_PUBLIC_IP": config.LOCAL_PUBLIC_IP,
            "HTTP_SERVER_PORT": config.HTTP_SERVER_PORT,
            "FRP_SERVER_PORT": config.FRP_SERVER_PORT,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@bp.route('/api/system/config', methods=['POST'])
def api_update_config():
    """更新配置（运行时）"""
    global system_status
    try:
        data = request.json
        from config import config

        # 更新允许的配置项
        if 'LLM_BASE_URL' in data:
            config.LLM_BASE_URL = data['LLM_BASE_URL']
        if 'LLM_API_KEY' in data:
            # 空字符串表示清除
            if data['LLM_API_KEY'] == '':
                config.LLM_API_KEY = ''
            else:
                config.LLM_API_KEY = data['LLM_API_KEY']
        if 'ANALYST_MODEL' in data:
            config.ANALYST_MODEL = data['ANALYST_MODEL']
        if 'LOCAL_PUBLIC_IP' in data:
            config.LOCAL_PUBLIC_IP = data['LOCAL_PUBLIC_IP']

        return jsonify({"success": True, "message": "配置已更新"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@bp.route('/api/modules/<module_name>/toggle', methods=['POST'])
def api_toggle_module(module_name):
    """切换模块启用状态"""
    global module_enabled
    try:
        data = request.json or {}
        enabled = data.get('enabled', True)
        module_enabled[module_name] = enabled
        return jsonify({
            "success": True,
            "module": module_name,
            "enabled": enabled
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@bp.route('/api/modules/status')
def api_modules_status():
    """获取所有模块启用状态"""
    try:
        from module_registry import ModuleRegistry
        report = ModuleRegistry.get_status_report()
        modules = report.get("modules", {})

        result = {}
        for name, info in modules.items():
            result[name] = {
                "available": info.get("available", False),
                "enabled": module_enabled.get(name, True),
                "nodes": info.get("nodes", []),
                "error": info.get("error", "")
            }
        return jsonify({"modules": result})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@bp.route('/api/tools/status')
def api_tools_status():
    """获取所有工具启用状态"""
    try:
        from tool_framework import ToolRegistry
        from tools import _ensure_tools_loaded
        _ensure_tools_loaded()
        tools = []
        for tool in ToolRegistry.get_all_tools():
            tool_name = tool.name()
            tools.append({
                "name": tool_name,
                "available": tool.check_available() if hasattr(tool, 'check_available') else True,
                "enabled": ToolRegistry.is_tool_enabled(tool_name),
                "description": tool.description() if hasattr(tool, 'description') else ""
            })
        return jsonify({"tools": tools, "total": len(tools)})
    except Exception as e:
        return jsonify({"tools": [], "error": str(e)})


@bp.route('/api/tools/<tool_name>/toggle', methods=['POST'])
def api_toggle_tool(tool_name):
    """切换工具启用状态"""
    try:
        from tool_framework import ToolRegistry
        from tools import _ensure_tools_loaded
        _ensure_tools_loaded()
        data = request.json or {}
        enabled = data.get('enabled', True)
        success = ToolRegistry.set_tool_enabled(tool_name, enabled)
        return jsonify({
            "success": success,
            "tool": tool_name,
            "enabled": enabled
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@bp.route('/api/nodes/<node_id>/toggle', methods=['POST'])
def api_toggle_node(node_id):
    """切换节点启用状态"""
    global node_enabled
    try:
        data = request.json or {}
        enabled = data.get('enabled', True)

        # 更新本地状态（兼容旧代码）
        node_enabled[node_id] = enabled

        # 更新 node_control（真正控制节点执行）
        if node_control:
            node_control.set_enabled(node_id, enabled)

        # 获取禁用节点数量
        disabled_count = node_control.get_disabled_count() if node_control else 0

        return jsonify({
            "success": True,
            "node": node_id,
            "enabled": enabled,
            "disabled_count": disabled_count,
            "graph": get_graph_structure()
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@bp.route('/api/nodes/status')
def api_nodes_status():
    """获取所有节点启用状态"""
    try:
        if node_control:
            status = node_control.get_all_status()
            disabled_count = node_control.get_disabled_count()
            disabled = node_control.get_disabled_nodes()
            return jsonify({
                "nodes": status,
                "disabled_count": disabled_count,
                "disabled_nodes": disabled
            })
        return jsonify({"nodes": node_enabled})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@bp.route('/api/graph/nodes')
def api_graph_nodes():
    """获取图节点详情"""
    try:
        graph = get_graph_structure()
        groups = graph.get("groups", {})
        nodes = []
        for node in graph["nodes"]:
            group_info = groups.get(node["group"], {})
            nodes.append({
                "id": node["id"],
                "name": node["name"],
                "group": node["group"],
                "groupName": group_info.get("name", node["group"]),
                "description": node["description"],
                "enabled": node["enabled"]
            })
        return jsonify({"nodes": nodes})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@bp.route('/api/nodes/groups/toggle', methods=['POST'])
def api_toggle_node_group():
    """批量切换节点组启用状态"""
    try:
        data = request.json or {}
        group_name = data.get('group', '')
        enabled = data.get('enabled', True)

        if not node_control:
            return jsonify({"error": "node_control not available"}), 500

        if enabled:
            count = node_control.enable_group(group_name)
        else:
            count = node_control.disable_group(group_name)

        disabled_count = node_control.get_disabled_count()

        return jsonify({
            "success": True,
            "group": group_name,
            "enabled": enabled,
            "affected_nodes": count,
            "disabled_count": disabled_count
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@bp.route('/api/nodes/groups')
def api_get_node_groups():
    """获取节点分组信息"""
    try:
        if not node_control:
            return jsonify({"error": "node_control not available"}), 500

        groups = {}
        for group_name, nodes in node_control.NODE_GROUPS.items():
            group_status = {
                "name": group_name,
                "nodes": nodes,
                "enabled_count": sum(1 for n in nodes if node_control.is_enabled(n)),
                "total_count": len(nodes),
                "disabled_count": sum(1 for n in nodes if not node_control.is_enabled(n))
            }
            groups[group_name] = group_status

        return jsonify({
            "groups": groups,
            "total_disabled_count": node_control.get_disabled_count()
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# =============================================================================
# 日志查看 API
# =============================================================================

@bp.route('/api/logs')
def api_logs_list():
    """获取所有任务的日志列表"""
    try:
        from logger import list_task_logs
        logs = list_task_logs()
        return jsonify({"logs": logs})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@bp.route('/api/logs/<task_id>')
def api_logs_task(task_id):
    """获取指定任务的日志信息"""
    try:
        from logger import get_task_logs
        info = get_task_logs(task_id)
        return jsonify(info)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@bp.route('/api/logs/<task_id>/<node_name>')
def api_logs_node(task_id, node_name):
    """获取指定任务指定节点的日志内容"""
    try:
        from logger import get_task_logs
        info = get_task_logs(task_id)

        if node_name not in info.get("logs", {}):
            return jsonify({"error": f"Node {node_name} not found"}), 404

        log_path = info["logs"][node_name]["path"]
        with open(log_path, 'r', encoding='utf-8') as f:
            content = f.read()

        return jsonify({
            "task_id": task_id,
            "node": node_name,
            "content": content,
            "lines": info["logs"][node_name]["lines"]
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    # 注册 Blueprint（确保所有路由已定义）
    app.register_blueprint(bp)

    # 配置
    HOST = '0.0.0.0'
    PORT = 54565
    DEBUG = False  # 生产环境关闭 debug

    print("=" * 60)
    print("CTF-Agent Web Service")
    print("=" * 60)
    print(f"Access URL: http://<SERVER_IP>:{PORT}{URL_PREFIX}/monitor")
    print(f"Modules:    http://<SERVER_IP>:{PORT}{URL_PREFIX}/modules")
    print(f"Topology:   http://<SERVER_IP>:{PORT}{URL_PREFIX}/topology")
    print("=" * 60)
    print("[Security] No default index page. Use full URL path.")
    print("=" * 60)

    app.run(host=HOST, port=PORT, debug=DEBUG, threaded=True)