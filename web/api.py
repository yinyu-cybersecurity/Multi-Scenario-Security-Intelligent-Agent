"""
Web API 服务
提供前端接口：任务管理、状态查询、日志查看、实时状态
集成模块:
- 任务持久化 (TaskPersistenceManager)
- 自我纠错 (SelfCorrectionManager)
- 攻击策略评估 (AttackStrategyEvaluator)
"""

import os
import sys
import json
import time
import threading
import subprocess
from datetime import datetime
from flask import Flask, render_template, jsonify, request, Response
from flask_cors import CORS
import queue

# 添加app目录和deploy目录到路径
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'app'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

# 导入工具模块以触发工具注册
try:
    import tools
except ImportError:
    pass

app = Flask(__name__,
            template_folder='templates',
            static_folder='static')
CORS(app)

# 配置Jinja2不与Vue冲突 - 使用 [[ ]] 作为Jinja变量分隔符
app.jinja_env.variable_start_string = '[['
app.jinja_env.variable_end_string = ']]'

# 任务存储（内存缓存）
tasks = {}
task_logs = {}
task_queues = {}
task_states = {}
task_results = {}  # 存储任务详细结果

# 初始化任务持久化管理器
task_persistence = None
try:
    from task_persistence import get_task_persistence
    task_persistence = get_task_persistence()
except ImportError:
    pass

# 初始化自我纠错管理器
self_correction_manager = None
try:
    from self_correction import self_correction_manager as scm
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

# 全局状态
system_status = {
    "llm_connected": False,
    "tools_loaded": 0,
    "active_sessions": 0,
    "start_time": datetime.now().isoformat()
}


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
        # 结束
        {"id": "evolution", "name": "进化", "group": "end", "description": "学习总结", "order": 300},
    ]

    # 添加启用状态和分组名称
    for node in nodes:
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


def init_log_capture():
    """初始化全局日志捕获器"""
    global _log_capture_instance, sys

    if _log_capture_instance is None:
        _log_capture_instance = ThreadSafeLogCapture()
        sys.stdout = _log_capture_instance


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
                    "execution_steps": state.get("execution_steps", 0)
                }

        if not hasattr(ctf_app, '_node_callbacks'):
            ctf_app._node_callbacks = {}
        ctf_app._node_callbacks[task_id] = node_callback

        try:
            result = run_single_task(task_name, task_description, target_url)

            if result.get('found_flag'):
                tasks[task_id]["status"] = "completed"
                tasks[task_id]["found_flag"] = True
                tasks[task_id]["final_flag"] = result.get('final_flag', result.get('found_flag'))
                log_callback(task_id, f"[SUCCESS] FLAG: {tasks[task_id]['final_flag']}")
            else:
                tasks[task_id]["status"] = "completed"
                log_callback(task_id, "[END] Task completed, no FLAG found")

            tasks[task_id]["progress"] = 100
            task_results[task_id] = result

        finally:
            # 清除当前线程的任务ID
            set_current_task_id(None)
            if hasattr(ctf_app, '_node_callbacks') and task_id in ctf_app._node_callbacks:
                del ctf_app._node_callbacks[task_id]

    except ImportError as e:
        log_callback(task_id, f"[Error] Import failed: {e}")
        log_callback(task_id, "[Info] Running in simulation mode...")
        run_simulated_task(task_id, target_url)
    except Exception as e:
        import traceback
        log_callback(task_id, f"[Error] Task exception: {e}")
        log_callback(task_id, traceback.format_exc())
        tasks[task_id]["status"] = "error"
        tasks[task_id]["error"] = str(e)


def run_simulated_task(task_id, target_url):
    """模拟运行任务"""
    nodes = ["challenge_type_detector", "recon", "analyst", "attacker", "verifier"]

    for node in nodes:
        if tasks[task_id]["status"] == "cancelled":
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

@app.route('/')
def index():
    """主页"""
    return render_template('index.html')


@app.route('/monitor')
def monitor():
    """监控面板"""
    return render_template('monitor.html')


@app.route('/modules')
def modules():
    """模块管理"""
    return render_template('modules.html')


@app.route('/topology')
def topology():
    """拓扑图可视化"""
    return render_template('topology.html')


@app.route('/api/graph')
def api_graph():
    """获取图结构"""
    return jsonify(get_graph_structure())


@app.route('/api/system/status')
def api_system_status():
    """获取系统状态"""
    try:
        from tool_framework import ToolRegistry
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

    return jsonify({
        "llm_connected": True,  # TODO: 实际检测
        "tools_loaded": tools_loaded,
        "active_sessions": active_sessions,
        "start_time": system_status["start_time"],
        "tasks_total": len(tasks),
        "tasks_running": sum(1 for t in tasks.values() if t["status"] == "running"),
        "tasks_completed": sum(1 for t in tasks.values() if t["status"] == "completed")
    })


@app.route('/api/tools')
def api_tools():
    """获取可用工具列表（分类显示）"""
    try:
        from tool_framework import ToolRegistry

        # 定义工具分类
        categories = {
            "impacket": {
                "name": "Impacket工具集",
                "tools": [
                    # 远程执行
                    "psexec", "wmiexec", "smbexec", "atexec", "dcomexec",
                    # 凭据导出
                    "secretsdump",
                    # Kerberos攻击
                    "getnpusers", "getuserspns", "ticketer", "goldenpac",
                    # NTLM中继
                    "ntlmrelayx",
                    # AD域渗透
                    "dacledit", "getadusers", "raisechild",
                    # SMB工具
                    "smbclient", "lookupsid", "smbserver",
                    # MSSQL工具
                    "mssqlclient", "mssqlinstance",
                    # RPC工具
                    "rpcdump", "samrdump",
                    # 其他
                    "reg", "services", "getarch"
                ]
            },
            "web_attack": {
                "name": "Web攻击",
                "tools": ["sqlmap", "ffuf", "dirsearch", "nuclei", "xray", "nmap", "httpx", "subfinder", "httprobe"]
            },
            "java_deserialize": {
                "name": "Java反序列化",
                "tools": ["ysoserial", "jndi-exploit", "marshalsec", "jdbc-exploit"]
            },
            "ad_attack": {
                "name": "AD域攻击",
                "tools": ["petitpotam", "rubeus", "bloodhound", "crackmapexec", "mimikatz"]
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
                "tools": ["metasploit", "metasploit-manager", "fscan", "hydra"]
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


@app.route('/api/sessions')
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


@app.route('/api/task/start', methods=['POST'])
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


@app.route('/api/task/<task_id>')
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
        "execution_steps": result.get("execution_steps", 0)
    })


@app.route('/api/task/<task_id>/logs')
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


@app.route('/api/task/<task_id>/cancel', methods=['POST'])
def api_task_cancel(task_id):
    """取消任务"""
    if task_id not in tasks:
        return jsonify({"error": "Task not found"}), 404

    tasks[task_id]["status"] = "cancelled"
    log_callback(task_id, "[System] Task cancelled by user")

    return jsonify({"status": "cancelled"})


@app.route('/api/task/<task_id>/result')
def api_task_result(task_id):
    """获取任务详细结果"""
    if task_id not in task_results:
        return jsonify({"error": "No results"}), 404

    return jsonify(task_results[task_id])


@app.route('/api/tasks')
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


@app.route('/api/task/<task_id>/stream')
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


@app.route('/api/health')
def api_health():
    """健康检查"""
    return jsonify({"status": "ok", "timestamp": datetime.now().isoformat()})


# =============================================================================
# 任务持久化 API
# =============================================================================

@app.route('/api/persistence/tasks')
def api_persistence_tasks():
    """获取持久化的任务列表"""
    if not task_persistence:
        return jsonify({"error": "Persistence module not available"}), 503

    status = request.args.get('status', '')
    if status:
        records = task_persistence.get_tasks_by_status(status)
    else:
        records = task_persistence.get_active_tasks()

    return jsonify({
        "tasks": [r.to_dict() for r in records],
        "total": len(records)
    })


@app.route('/api/persistence/task/<task_id>')
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

    return jsonify({
        "task": record.to_dict(),
        "execution_history": history[:50],
        "discoveries": discoveries
    })


@app.route('/api/persistence/statistics')
def api_persistence_statistics():
    """获取任务统计信息"""
    if not task_persistence:
        return jsonify({"error": "Persistence module not available"}), 503

    return jsonify(task_persistence.get_statistics())


@app.route('/api/persistence/task/<task_id>', methods=['DELETE'])
def api_persistence_delete_task(task_id):
    """删除持久化任务"""
    if not task_persistence:
        return jsonify({"error": "Persistence module not available"}), 503

    success = task_persistence.delete_task(task_id)
    return jsonify({"success": success})


# =============================================================================
# 自我纠错状态 API
# =============================================================================

@app.route('/api/system/recovery')
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


@app.route('/api/system/recovery/history')
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


# =============================================================================
# 攻击策略评估 API
# =============================================================================

@app.route('/api/strategy/evaluate', methods=['POST'])
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


@app.route('/api/strategy/analyze-path', methods=['POST'])
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


@app.route('/api/strategy/statistics')
def api_strategy_statistics():
    """获取策略评估统计"""
    if not strategy_evaluator:
        return jsonify({"error": "Strategy evaluator not available"}), 503

    return jsonify(strategy_evaluator.get_statistics())


# =============================================================================
# LLM 状态 API
# =============================================================================

@app.route('/api/llm/status')
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

@app.route('/api/performance/stats')
def api_performance_stats():
    """获取性能统计"""
    try:
        from performance import performance_monitor
        return jsonify(performance_monitor.get_full_stats())
    except ImportError:
        return jsonify({"error": "Performance monitor not available"}), 503


@app.route('/api/performance/records')
def api_performance_records():
    """获取最近执行记录"""
    try:
        from performance import performance_monitor
        limit = request.args.get('limit', 50, type=int)
        return jsonify({"records": performance_monitor.get_recent_records(limit)})
    except ImportError:
        return jsonify({"error": "Performance monitor not available"}), 503


@app.route('/api/performance/slow')
def api_performance_slow():
    """获取慢操作列表"""
    try:
        from performance import performance_monitor
        threshold = request.args.get('threshold', 5000, type=float)
        return jsonify({"slow_ops": performance_monitor.get_slow_operations(threshold)})
    except ImportError:
        return jsonify({"error": "Performance monitor not available"}), 503


@app.route('/api/performance/reset', methods=['POST'])
def api_performance_reset():
    """重置性能统计"""
    try:
        from performance import performance_monitor
        performance_monitor.reset()
        return jsonify({"success": True})
    except ImportError:
        return jsonify({"error": "Performance monitor not available"}), 503


# =============================================================================
# 上下文压缩状态 API
# =============================================================================

@app.route('/api/compression/status')
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
# 模块管理 API
# =============================================================================

@app.route('/api/modules')
def api_modules():
    """获取所有模块状态"""
    try:
        from module_registry import ModuleRegistry
        report = ModuleRegistry.get_status_report()
        return jsonify(report)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/modules/<module_name>')
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


@app.route('/api/modules/<module_name>/nodes')
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

@app.route('/api/topology/<task_id>')
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


@app.route('/api/topology/<task_id>/critical')
def api_topology_critical(task_id):
    """获取关键节点"""
    if task_id not in task_results:
        return jsonify({"error": "Task not found"}), 404

    result = task_results.get(task_id, {})
    critical_nodes = result.get("critical_nodes", [])

    return jsonify({"critical_nodes": critical_nodes})


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

@app.route('/api/system/config', methods=['GET'])
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


@app.route('/api/system/config', methods=['POST'])
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
            config.LLM_API_KEY = data['LLM_API_KEY']
        if 'ANALYST_MODEL' in data:
            config.ANALYST_MODEL = data['ANALYST_MODEL']
        if 'LOCAL_PUBLIC_IP' in data:
            config.LOCAL_PUBLIC_IP = data['LOCAL_PUBLIC_IP']

        return jsonify({"success": True, "message": "配置已更新"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/modules/<module_name>/toggle', methods=['POST'])
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


@app.route('/api/modules/status')
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


@app.route('/api/tools/status')
def api_tools_status():
    """获取所有工具启用状态"""
    try:
        from tool_framework import ToolRegistry
        tools = []
        for tool in ToolRegistry.get_all_tools():
            tool_name = tool.name()
            tools.append({
                "name": tool_name,
                "available": tool.check_available() if hasattr(tool, 'check_available') else True,
                "enabled": tool_enabled.get(tool_name, True),
                "description": tool.description() if hasattr(tool, 'description') else ""
            })
        return jsonify({"tools": tools, "total": len(tools)})
    except Exception as e:
        return jsonify({"tools": [], "error": str(e)})


@app.route('/api/tools/<tool_name>/toggle', methods=['POST'])
def api_toggle_tool(tool_name):
    """切换工具启用状态"""
    global tool_enabled
    try:
        data = request.json or {}
        enabled = data.get('enabled', True)
        tool_enabled[tool_name] = enabled
        return jsonify({
            "success": True,
            "tool": tool_name,
            "enabled": enabled
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/nodes/<node_id>/toggle', methods=['POST'])
def api_toggle_node(node_id):
    """切换节点启用状态"""
    global node_enabled
    try:
        data = request.json or {}
        enabled = data.get('enabled', True)
        node_enabled[node_id] = enabled
        return jsonify({
            "success": True,
            "node": node_id,
            "enabled": enabled,
            "graph": get_graph_structure()
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/nodes/status')
def api_nodes_status():
    """获取所有节点启用状态"""
    try:
        return jsonify({"nodes": node_enabled})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/graph/nodes')
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


# =============================================================================
# 日志查看 API
# =============================================================================

@app.route('/api/logs')
def api_logs_list():
    """获取所有任务的日志列表"""
    try:
        from logger import list_task_logs
        logs = list_task_logs()
        return jsonify({"logs": logs})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/logs/<task_id>')
def api_logs_task(task_id):
    """获取指定任务的日志信息"""
    try:
        from logger import get_task_logs
        info = get_task_logs(task_id)
        return jsonify(info)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/logs/<task_id>/<node_name>')
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
    print("=" * 50)
    print("CTF-Agent Web UI")
    print("=" * 50)
    print(f"URL: http://localhost:5000")
    print("=" * 50)
    app.run(host='0.0.0.0', port=5000, debug=True, threaded=True)