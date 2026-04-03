# CTF-Agent Backend Server
# FastAPI + WebSocket 实时通信
# 架构: Claude Code Query Loop

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import asyncio
import json
import os
import uuid
import re
import ipaddress
from datetime import datetime
from pathlib import Path
import logging

# 配置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("CTF-Agent-Server")

# 导入新架构组件
from app.core.query import query, QueryConfig
from app.core.time_manager import TimeManager, TaskType
from app.state.store import get_app_state_store
from app.prompts.ctf_system_prompt import get_target_specific_prompt
from app.settings import config
from app.tools_v2.ctf_tools import get_tools_for_api, register_ctf_tools
from app.skills import load_all_skills

# 初始化Skill系统
load_all_skills()

# ============================================
# FastAPI 应用
# ============================================

app = FastAPI(
    title="CTF-Agent 2.0",
    description="AI-Powered CTF Automation Framework - Claude Code Architecture",
    version="2.0.0"
)

# CORS配置 - 根据环境变量配置允许的来源
# 开发环境: 默认允许 localhost
# 生产环境: ALLOWED_ORIGINS="https://your-domain.com,https://app.your-domain.com"
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "")
if ALLOWED_ORIGINS:
    # 显式配置的来源
    allow_origins_list = [origin.strip() for origin in ALLOWED_ORIGINS.split(",")]
else:
    # 开发环境默认只允许 localhost
    allow_origins_list = [
        "http://localhost:5173",
        "http://localhost:3000",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:3000",
    ]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allow_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# WebSocket连接管理
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except:
                pass

    async def send_personal(self, websocket: WebSocket, message: dict):
        try:
            await websocket.send_json(message)
        except:
            pass

manager = ConnectionManager()

# 注意：工具注册由query.py的ensure_tools_registered()自动处理
# 避免重复注册

# ============================================
# 数据模型
# ============================================

class TaskRequest(BaseModel):
    target: str
    description: Optional[str] = ""
    challenge_type: Optional[str] = None
    max_iterations: Optional[int] = 50
    timeout_minutes: Optional[int] = None

class MessageRequest(BaseModel):
    message: str
    attachments: List[Dict[str, Any]] = []

# ============================================
# 全局状态
# ============================================

execution_lock = asyncio.Lock()
time_manager = TimeManager()

current_task = None
is_executing = False
iteration_count = 0
findings: List[Dict] = []
flags: List[Dict] = []
tool_executions: List[Dict] = []
log_entries: List[Dict] = []

# ============================================
# API 路由
# ============================================

@app.get("/")
async def root():
    return {"message": "CTF-Agent 2.0 API", "status": "running", "arch": "Claude Code Query Loop"}

@app.get("/api/status")
async def get_status():
    return {
        "is_executing": is_executing,
        "iteration_count": iteration_count,
        "findings_count": len(findings),
        "flags_count": len(flags),
        "tools_count": len(tool_executions),
    }

@app.get("/api/config")
async def get_config():
    """获取当前配置"""
    return {
        "model": getattr(config, 'LLM_MODEL', 'glm-5'),
        "base_url": getattr(config, 'LLM_BASE_URL', ''),
        "timeout": getattr(config, 'LLM_TIMEOUT', 120),
    }

@app.get("/api/skills/list")
async def list_skills():
    """列出可用的Skills"""
    try:
        from app.skills.skill_loader import get_skill_loader
        loader = get_skill_loader()
        skills = loader.list_available_skills()
        return {"skills": [{"name": s} for s in skills]}
    except Exception as e:
        return {"skills": [], "error": str(e)}

@app.get("/api/skills/count")
async def get_skills_count():
    """获取Skills数量"""
    try:
        from app.skills.skill_loader import get_skill_loader
        loader = get_skill_loader()
        skills = loader.list_available_skills()
        return {"count": len(skills), "skills": skills}
    except Exception as e:
        return {"count": 0, "skills": [], "error": str(e)}

@app.get("/api/test/agent")
async def test_agent_import():
    """测试Agent导入"""
    try:
        from app.main import run_ctf_agent
        return {"status": "ok", "message": "run_ctf_agent导入成功"}
    except ImportError as e:
        return {"status": "error", "message": f"导入失败: {str(e)}"}

@app.post("/api/task/start")
async def start_task(request: TaskRequest):
    global current_task, is_executing, iteration_count, findings, flags, tool_executions, log_entries

    if is_executing:
        raise HTTPException(status_code=400, detail="Task already executing")

    # 重置状态
    iteration_count = 0
    findings = []
    flags = []
    tool_executions = []
    log_entries = []
    is_executing = True

    # 广播任务开始
    await manager.broadcast({
        "type": "task_start",
        "data": {
            "target": request.target,
            "description": request.description,
            "timestamp": datetime.now().isoformat()
        }
    })

    return {"status": "started", "target": request.target}

@app.post("/api/task/stop")
async def stop_task():
    global is_executing
    is_executing = False
    await manager.broadcast({
        "type": "interrupt",
        "data": {"reason": "user_cancel", "timestamp": datetime.now().isoformat()}
    })
    return {"status": "stopped"}

@app.post("/api/upload")
async def upload_file(file: UploadFile = File(...)):
    upload_dir = Path("uploads")
    upload_dir.mkdir(exist_ok=True)

    file_path = upload_dir / f"{uuid.uuid4()}_{file.filename}"

    with open(file_path, "wb") as f:
        content = await file.read()
        f.write(content)

    await manager.broadcast({
        "type": "file_uploaded",
        "data": {
            "filename": file.filename,
            "size": len(content),
            "path": str(file_path),
            "timestamp": datetime.now().isoformat()
        }
    })

    return {"filename": file.filename, "size": len(content), "path": str(file_path)}

# ============================================
# WebSocket 路由
# ============================================

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    manager.active_connections.append(websocket)

    global is_executing, iteration_count, findings, flags, tool_executions, log_entries

    try:
        await websocket.send_json({
            "type": "connection_established",
            "data": {
                "message": "Connected to CTF-Agent 2.0 (Claude Code Architecture)",
                "timestamp": datetime.now().isoformat()
            }
        })

        while True:
            data = await websocket.receive_text()

            try:
                message = json.loads(data)
            except json.JSONDecodeError:
                await websocket.send_json({
                    "type": "error",
                    "data": {"message": "Invalid JSON format"}
                })
                continue

            msg_type = message.get("type")
            msg_data = message.get("data", {})

            if msg_type == "user_input":
                user_message = msg_data.get("message", "")
                attachments = msg_data.get("attachments", [])

                log_entry = {
                    "id": f"log-{uuid.uuid4()}",
                    "timestamp": datetime.now().isoformat(),
                    "type": "user",
                    "message": user_message,
                    "iteration": iteration_count
                }
                log_entries.append(log_entry)

                await manager.broadcast({"type": "log", "data": log_entry})

                if not is_executing:
                    try:
                        target = extract_target_from_message(user_message)

                        if target:
                            async with execution_lock:
                                if not is_executing:
                                    is_executing = True
                                    task = asyncio.create_task(execute_query_loop(
                                        target=target,
                                        description=user_message,
                                        websocket=websocket,
                                        session_id=str(uuid.uuid4())
                                    ))
                                    task.add_done_callback(lambda t: t.exception() if not t.cancelled() else None)
                        else:
                            await websocket.send_json({
                                "type": "system",
                                "data": {
                                    "message": "未检测到有效的目标URL或IP地址",
                                    "timestamp": datetime.now().isoformat()
                                }
                            })
                    except Exception as e:
                        logger.error(f"user_input处理错误: {e}")
                        await websocket.send_json({
                            "type": "error",
                            "data": {"message": f"处理输入时出错: {str(e)}"}
                        })
                else:
                    await websocket.send_json({
                        "type": "system",
                        "data": {"message": "已有任务正在执行中"}
                    })

            elif msg_type == "interrupt":
                is_executing = False
                await manager.broadcast({
                    "type": "interrupt",
                    "data": {"reason": "user_cancel", "timestamp": datetime.now().isoformat()}
                })

            elif msg_type == "ping":
                await websocket.send_json({
                    "type": "pong",
                    "data": {"timestamp": datetime.now().isoformat()}
                })

    except WebSocketDisconnect:
        if websocket in manager.active_connections:
            manager.active_connections.remove(websocket)
    except Exception as e:
        logger.error(f"WebSocket错误: {e}")
        if websocket in manager.active_connections:
            manager.active_connections.remove(websocket)

# ============================================
# Agent执行函数
# ============================================

def extract_target_from_message(message: str) -> str:
    """从用户消息中提取目标URL/IP"""
    url_pattern = r'(https?://[^\s]+)'
    url_match = re.search(url_pattern, message)

    if url_match:
        url = url_match.group(1)
        if len(url) > 2083:
            return ""
        return url

    ip_pattern = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::(\d+))?'
    ip_match = re.search(ip_pattern, message)

    if ip_match:
        ip_str = ip_match.group(1)
        port = ip_match.group(2)

        try:
            ipaddress.ip_address(ip_str)
            result = ip_str
            if port:
                result += f":{port}"
            return result
        except ValueError:
            return ""

    return ""


async def execute_query_loop(
    target: str,
    description: str,
    websocket: WebSocket,
    session_id: str
):
    """使用Claude Code Query循环执行任务 - 完整消息类型"""
    global is_executing, iteration_count, flags

    logger.info(f"[Query Loop] 开始执行 - 目标: {target}")

    # 初始化
    store = get_app_state_store()
    budget = time_manager.create_budget(session_id, TaskType.CTF_SINGLE_FLAG)

    # 获取模型配置
    model = getattr(config, 'LLM_MODEL', 'glm-5')

    # 构建System Prompt
    system_prompt = get_target_specific_prompt("web", target)
    system_prompt += f"\n\n**Time Budget**: {budget.total_seconds / 60:.0f} minutes."

    # 配置Query - 使用延迟加载
    query_config = QueryConfig(
        model=model,
        max_turns=200,
        system_prompt=system_prompt,
        tools=[],  # 空列表 - 启用延迟加载
    )

    # 初始消息
    messages = [{
        "role": "user",
        "content": f"""CTF Challenge Target: {target}

Description: {description or 'No description provided'}

Your task:
1. Analyze the target and identify potential vulnerabilities
2. Exploit any vulnerabilities found
3. Extract the flag (format: flag{{...}} or FLAG{{...}})

Time budget: {budget.total_seconds / 60:.0f} minutes.

Begin your analysis now."""
    }]

    flags_found = []
    current_iteration = 0

    try:
        async for event in query(messages, query_config):
            # 检查超时
            if time_manager.should_stop(session_id):
                await websocket.send_json({
                    "type": "system",
                    "data": {"message": "Timeout reached, task ended"}
                })
                break

            # 处理事件
            event_type = event.get("type")
            turn = event.get("turn", 0)

            # 检测新迭代开始
            if turn > current_iteration:
                # 结束上一个迭代
                if current_iteration > 0:
                    await websocket.send_json({
                        "type": "iteration_end",
                        "data": {
                            "iteration": current_iteration,
                            "timestamp": datetime.now().isoformat()
                        }
                    })

                current_iteration = turn
                iteration_count = turn

                # 发送迭代开始事件
                await websocket.send_json({
                    "type": "iteration_start",
                    "data": {
                        "iteration": turn,
                        "timestamp": datetime.now().isoformat()
                    }
                })

            if event_type == "message":
                content = event.get("message", {}).get("content", "")

                # 发送节点开始事件 (Think节点)
                await websocket.send_json({
                    "type": "node_start",
                    "data": {
                        "node": "think",
                        "iteration": turn,
                        "timestamp": datetime.now().isoformat()
                    }
                })

                # 广播AI响应
                await websocket.send_json({
                    "type": "log",
                    "data": {
                        "id": f"ai-{uuid.uuid4()}",
                        "timestamp": datetime.now().isoformat(),
                        "type": "assistant",
                        "message": content[:500],
                        "iteration": turn,
                        "node": "think"
                    }
                })

                # 发送节点结束事件
                await websocket.send_json({
                    "type": "node_end",
                    "data": {
                        "node": "think",
                        "iteration": turn,
                        "result": "AI thinking completed",
                        "timestamp": datetime.now().isoformat()
                    }
                })

                # 检查Flag
                flag_match = re.search(r'flag\{[^}]+\}', content, re.IGNORECASE)
                if flag_match:
                    flag = flag_match.group(0)
                    if flag not in flags_found:
                        flags_found.append(flag)
                        flags.append({"flag": flag, "timestamp": datetime.now().isoformat()})

                        # 发送发现事件
                        await websocket.send_json({
                            "type": "finding",
                            "data": {
                                "id": f"finding-{uuid.uuid4()}",
                                "type": "flag",
                                "content": flag,
                                "iteration": turn,
                                "timestamp": datetime.now().isoformat()
                            }
                        })

                        await websocket.send_json({
                            "type": "flag",
                            "data": {
                                "flag": flag,
                                "iteration": turn,
                                "timestamp": datetime.now().isoformat()
                            }
                        })

            elif event_type == "tool_call_request":
                tool_call = event.get("tool_call", {})
                tool_name = tool_call.tool_name if hasattr(tool_call, 'tool_name') else tool_call.get("tool_name", "unknown")
                tool_id = tool_call.tool_id if hasattr(tool_call, 'tool_id') else tool_call.get("tool_id", f"tool-{uuid.uuid4()}")
                tool_args = tool_call.arguments if hasattr(tool_call, 'arguments') else tool_call.get("arguments", {})

                # 构建命令字符串
                command_str = ""
                if tool_name == "Bash":
                    command_str = tool_args.get("command", "")
                elif tool_args:
                    # 其他工具显示参数
                    command_str = json.dumps(tool_args, ensure_ascii=False)[:200]

                # 发送节点开始事件 (Act节点)
                await websocket.send_json({
                    "type": "node_start",
                    "data": {
                        "node": "act",
                        "iteration": turn,
                        "timestamp": datetime.now().isoformat()
                    }
                })

                # 发送工具开始事件
                await websocket.send_json({
                    "type": "tool_start",
                    "data": {
                        "id": tool_id,
                        "tool": tool_name,
                        "command": command_str,
                        "iteration": turn,
                        "startTime": datetime.now().isoformat()
                    }
                })

            elif event_type == "tool_result":
                tool_result = event.get("result", {})
                tool_id = event.get("tool_id", f"tool-{uuid.uuid4()}")
                duration = event.get("duration", 0)

                # 发送工具完成事件
                await websocket.send_json({
                    "type": "tool_complete",
                    "data": {
                        "id": tool_id,
                        "result": tool_result,
                        "duration": duration,
                        "timestamp": datetime.now().isoformat()
                    }
                })

                # 发送节点结束事件 (Act节点)
                await websocket.send_json({
                    "type": "node_end",
                    "data": {
                        "node": "act",
                        "iteration": turn,
                        "result": "Tool execution completed",
                        "timestamp": datetime.now().isoformat()
                    }
                })

                # 发送节点开始事件 (Reflect节点)
                await websocket.send_json({
                    "type": "node_start",
                    "data": {
                        "node": "reflect",
                        "iteration": turn,
                        "timestamp": datetime.now().isoformat()
                    }
                })

                # 分析工具结果
                result_str = json.dumps(tool_result, ensure_ascii=False) if isinstance(tool_result, dict) else str(tool_result)

                # 发送日志
                await websocket.send_json({
                    "type": "log",
                    "data": {
                        "id": f"reflect-{uuid.uuid4()}",
                        "timestamp": datetime.now().isoformat(),
                        "type": "info",
                        "message": f"Tool result: {result_str[:200]}",
                        "iteration": turn,
                        "node": "reflect"
                    }
                })

                # 发送节点结束事件 (Reflect节点)
                await websocket.send_json({
                    "type": "node_end",
                    "data": {
                        "node": "reflect",
                        "iteration": turn,
                        "result": "Reflection completed",
                        "timestamp": datetime.now().isoformat()
                    }
                })

            elif event_type == "complete":
                reason = event.get("reason", "unknown")

                # 发送最终迭代结束
                if current_iteration > 0:
                    await websocket.send_json({
                        "type": "iteration_end",
                        "data": {
                            "iteration": current_iteration,
                            "timestamp": datetime.now().isoformat()
                        }
                    })

                await websocket.send_json({
                    "type": "task_complete",
                    "data": {
                        "success": len(flags_found) > 0,
                        "flags": flags_found,
                        "iterations": turn,
                        "reason": reason,
                        "timestamp": datetime.now().isoformat()
                    }
                })
                break

            elif event_type == "error":
                error = event.get("error", "Unknown error")
                await websocket.send_json({
                    "type": "error",
                    "data": {
                        "message": error,
                        "iteration": turn,
                        "timestamp": datetime.now().isoformat()
                    }
                })

    except Exception as e:
        logger.error(f"Query循环错误: {e}")
        try:
            await websocket.send_json({
                "type": "error",
                "data": {"message": f"Execution error: {str(e)}"}
            })
        except Exception:
            pass
    finally:
        is_executing = False
        logger.info(f"[Query Loop] 任务结束 - Flags: {len(flags_found)}")

# ============================================
# 静态文件服务
# ============================================

dist_path = Path(__file__).parent.parent / "frontend" / "dist"
if dist_path.exists():
    app.mount("/", StaticFiles(directory=str(dist_path), html=True), name="static")

# ============================================
# 启动入口
# ============================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.server:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )