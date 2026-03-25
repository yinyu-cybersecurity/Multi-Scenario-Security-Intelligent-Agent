"""
Web API 服务 - 增强版
提供前端接口：任务管理、状态查询、日志查看、实时状态

[任务3.1/3.2/4.1] 集成新模块:
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

# 添加app目录到路径
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'app'))

app = Flask(__name__,
            template_folder='templates',
            static_folder='static')
CORS(app)

# 任务存储（内存缓存）
tasks = {}
task_logs = {}
task_queues = {}
task_states = {}
task_results = {}  # 存储任务详细结果

# [任务3.1] 初始化任务持久化管理器
task_persistence = None
try:
    from task_persistence import get_task_persistence
    task_persistence = get_task_persistence()
except ImportError:
    pass

# [任务2.3] 初始化自我纠错管理器
self_correction_manager = None
try:
    from self_correction import self_correction_manager as scm
    self_correction_manager = scm
except ImportError:
    pass

# [任务4.1] 初始化攻击策略评估器
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
    return {
        "nodes": [
            {"id": "challenge_type_detector", "name": "类型检测", "group": "entry", "description": "检测CTF题目类型"},
            {"id": "recon", "name": "侦察兵", "group": "web", "description": "HTTP请求、指纹识别"},
            {"id": "analyst", "name": "分析兵", "group": "web", "description": "漏洞分析、策略生成"},
            {"id": "strategy_filter", "name": "策略过滤", "group": "web", "description": "过滤无效策略"},
            {"id": "mode_manager", "name": "模式决策", "group": "decision", "description": "决定攻击/探索模式"},
            {"id": "attacker", "name": "攻击兵", "group": "web", "description": "执行攻击动作"},
            {"id": "verifier", "name": "核验兵", "group": "web", "description": "验证攻击结果"},
            {"id": "explorer", "name": "探索兵", "group": "web", "description": "目录扫描"},
            {"id": "innovator", "name": "头脑风暴", "group": "web", "description": "生成新策略"},
            {"id": "evolution", "name": "进化", "group": "end", "description": "学习总结"},
            {"id": "post_exploit", "name": "后渗透", "group": "internal", "description": "Shell后处理"},
            {"id": "upload_tools", "name": "工具上传", "group": "internal", "description": "上传渗透工具"},
            {"id": "setup_tunnel", "name": "隧道搭建", "group": "internal", "description": "FRP代理搭建"},
            {"id": "internal_recon", "name": "内网侦察", "group": "internal", "description": "fscan扫描"},
            {"id": "lateral_move", "name": "横向移动", "group": "internal", "description": "impacket利用"},
            {"id": "privilege_escalation", "name": "权限提升", "group": "internal", "description": "Potato提权"},
            {"id": "credential_gather", "name": "凭据收集", "group": "internal", "description": "mimikatz导出"},
        ],
        "edges": [
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
            {"source": "privilege_escalation", "target": "credential_gather"},
        ],
        "groups": {
            "entry": {"name": "入口", "color": "#409EFF"},
            "web": {"name": "Web攻击", "color": "#67C23A"},
            "decision": {"name": "决策", "color": "#E6A23C"},
            "internal": {"name": "内网渗透", "color": "#F56C6C"},
            "end": {"name": "结束", "color": "#95a5a6"}
        }
    }


class LogCapture:
    """日志捕获器，重定向print输出"""
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

        log_capture = LogCapture(task_id)
        old_stdout = sys.stdout
        sys.stdout = log_capture

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
            sys.stdout = old_stdout
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


@app.route('/api/graph')
def api_graph():
    """获取图结构"""
    return jsonify(get_graph_structure())


@app.route('/api/system/status')
def api_system_status():
    """获取系统状态"""
    try:
        from tool_framework import ToolRegistry
        tools_loaded = len(ToolRegistry._tools)
    except:
        tools_loaded = 0

    try:
        from remote_executor.session_manager import get_session_manager
        sm = get_session_manager()
        active_sessions = len(sm.sessions)
    except:
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
    """获取可用工具列表"""
    try:
        from tool_framework import ToolRegistry
        tools = []
        for name, tool in ToolRegistry._tools.items():
            tools.append({
                "name": name,
                "description": tool.description() if hasattr(tool, 'description') else "",
                "available": tool.check_available() if hasattr(tool, 'check_available') else True
            })
        return jsonify({"tools": tools})
    except Exception as e:
        return jsonify({"tools": [], "error": str(e)})


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

    # [任务3.1] 持久化任务创建
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
    """日志流（SSE）"""
    def generate():
        offset = 0
        while True:
            if task_id in task_logs:
                logs = task_logs[task_id]
                new_logs = logs[offset:]
                for log in new_logs:
                    yield f"data: {json.dumps(log)}\n\n"
                offset = len(logs)

                if tasks.get(task_id, {}).get("status") in ["completed", "error", "cancelled"]:
                    yield f"data: {json.dumps({'type': 'end'})}\n\n"
                    break
            time.sleep(0.5)

    return Response(generate(), mimetype='text/event-stream')


@app.route('/api/health')
def api_health():
    """健康检查"""
    return jsonify({"status": "ok", "timestamp": datetime.now().isoformat()})


# =============================================================================
# [任务3.1] 任务持久化 API
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
# [任务2.3] 自我纠错状态 API
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
# [任务4.1] 攻击策略评估 API
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
# [任务2.1] LLM 状态 API
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
# [任务2.2] 上下文压缩状态 API
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


if __name__ == '__main__':
    print("=" * 50)
    print("CTF-Agent Web UI")
    print("=" * 50)
    print(f"URL: http://localhost:5000")
    print("=" * 50)
    app.run(host='0.0.0.0', port=5000, debug=True, threaded=True)