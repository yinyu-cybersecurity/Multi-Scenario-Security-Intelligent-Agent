# CTF-Agent Backend Server
# FastAPI + WebSocket 实时通信

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

# 导入核心组件
from app.graph.ctf_graph import build_ctf_graph
from app.state.state_v3 import create_initial_state, ChallengeInfo, ChallengeType
from app.coordinator.dispatcher import get_coordinator_dispatcher
from app.memory import get_agent_memory
from app.settings import config

# 启动时加载Skills
from app.skills import load_all_skills
load_all_skills()

# ============================================
# FastAPI 应用
# ============================================

app = FastAPI(
    title="CTF-Agent 2.0",
    description="AI-Powered CTF Automation Framework",
    version="2.0.0"
)

# CORS配置
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # 开发环境允许所有来源
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# WebSocket连接管理
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        # 注意：FastAPI WebSocket路由已经自动accept，这里只添加到连接列表
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

# 全局状态锁（防止并发状态竞争）
execution_lock = asyncio.Lock()

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
    return {"message": "CTF-Agent 2.0 API", "status": "running"}

@app.get("/api/status")
async def get_status():
    return {
        "is_executing": is_executing,
        "iteration_count": iteration_count,
        "findings_count": len(findings),
        "flags_count": len(flags),
        "tools_count": len(tool_executions),
    }

@app.get("/api/skills/count")
async def get_skills_count():
    from app.skills import get_skill_registry
    registry = get_skill_registry()
    return {
        "count": len(registry.list_skills()),
        "skills": registry.list_skills()
    }

@app.get("/api/skills/list")
async def list_skills():
    from app.skills import get_skill_registry
    registry = get_skill_registry()
    skills = []
    for name in registry.list_skills():
        skill = registry.get_skill(name)
        if skill:
            skills.append({
                "name": skill.name,
                "domain": skill.domain,
                "description": skill.description,
                "tags": skill.tags
            })
    return {"skills": skills}

@app.get("/api/test/agent")
async def test_agent_import():
    """测试Agent导入和执行准备"""
    try:
        from app.main import run_agent
        return {
            "status": "ok",
            "message": "run_agent导入成功",
            "is_coroutine": True
        }
    except ImportError as e:
        return {
            "status": "error",
            "message": f"导入失败: {str(e)}"
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"未知错误: {str(e)}"
        }

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
    # 保存上传的文件
    upload_dir = Path("uploads")
    upload_dir.mkdir(exist_ok=True)

    file_path = upload_dir / f"{uuid.uuid4()}_{file.filename}"

    with open(file_path, "wb") as f:
        content = await file.read()
        f.write(content)

    # 广播文件上传事件
    await manager.broadcast({
        "type": "file_uploaded",
        "data": {
            "filename": file.filename,
            "size": len(content),
            "path": str(file_path),
            "timestamp": datetime.now().isoformat()
        }
    })

    return {
        "filename": file.filename,
        "size": len(content),
        "path": str(file_path)
    }

# ============================================
# WebSocket 路由
# ============================================

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    # 先accept连接
    await websocket.accept()
    manager.active_connections.append(websocket)

    global is_executing, iteration_count, findings, flags, tool_executions, log_entries

    try:
        # 发送初始状态
        await websocket.send_json({
            "type": "connection_established",
            "data": {
                "message": "Connected to CTF-Agent 2.0",
                "timestamp": datetime.now().isoformat()
            }
        })

        while True:
            # 接收消息
            data = await websocket.receive_text()

            try:
                message = json.loads(data)
            except json.JSONDecodeError:
                await websocket.send_json({
                    "type": "error",
                    "data": {"message": "Invalid JSON format"}
                })
                continue

            # 处理不同类型的消息
            msg_type = message.get("type")
            msg_data = message.get("data", {})

            if msg_type == "user_input":
                # 用户输入
                user_message = msg_data.get("message", "")
                attachments = msg_data.get("attachments", [])

                # 添加日志
                log_entry = {
                    "id": f"log-{uuid.uuid4()}",
                    "timestamp": datetime.now().isoformat(),
                    "type": "user",
                    "message": user_message,
                    "iteration": iteration_count
                }
                log_entries.append(log_entry)

                # 广播用户消息
                await manager.broadcast({
                    "type": "log",
                    "data": log_entry
                })

                # 触发真实Agent执行（使用锁防止并发竞争）
                if not is_executing:
                    try:
                        target = extract_target_from_message(user_message)

                        if target:
                            async with execution_lock:
                                if not is_executing:  # 双重检查
                                    is_executing = True
                                    # 创建任务并添加完成回调处理异常
                                    task = asyncio.create_task(execute_agent_task(
                                        target=target,
                                        description=user_message,
                                        websocket=websocket,
                                        session_id=str(uuid.uuid4())
                                    ))
                                    task.add_done_callback(lambda t: t.exception() if not t.cancelled() else None)
                        else:
                            # 未检测到有效目标，提示用户
                            await websocket.send_json({
                                "type": "system",
                                "data": {
                                    "message": "未检测到有效的目标URL或IP地址，请输入类似 http://example.com 或 192.168.1.1 格式的目标",
                                    "timestamp": datetime.now().isoformat()
                                }
                            })
                    except Exception as e:
                        # 捕获并报告错误，避免连接关闭
                        print(f"[WebSocket] user_input处理错误: {e}")
                        await websocket.send_json({
                            "type": "error",
                            "data": {"message": f"处理输入时出错: {str(e)}", "timestamp": datetime.now().isoformat()}
                        })
                else:
                    # 正在执行中，提示用户
                    await websocket.send_json({
                        "type": "system",
                        "data": {"message": "已有任务正在执行中，请等待完成或发送interrupt中断", "timestamp": datetime.now().isoformat()}
                    })

            elif msg_type == "interrupt":
                # 用户打断
                is_executing = False

                await manager.broadcast({
                    "type": "interrupt",
                    "data": {"reason": "user_cancel", "timestamp": datetime.now().isoformat()}
                })

            elif msg_type == "ping":
                # 心跳
                await websocket.send_json({
                    "type": "pong",
                    "data": {"timestamp": datetime.now().isoformat()}
                })

    except WebSocketDisconnect:
        if websocket in manager.active_connections:
            manager.active_connections.remove(websocket)
        await manager.broadcast({
            "type": "system",
            "data": {"message": "Client disconnected", "timestamp": datetime.now().isoformat()}
        })
    except Exception as e:
        if websocket in manager.active_connections:
            manager.active_connections.remove(websocket)
        await manager.broadcast({
            "type": "error",
            "data": {"message": str(e), "timestamp": datetime.now().isoformat()}
        })

# ============================================
# Agent执行函数
# ============================================

def extract_target_from_message(message: str) -> str:
    """从用户消息中提取并验证目标URL/IP"""

    # 匹配URL模式
    url_pattern = r'(https?://[^\s]+)'
    url_match = re.search(url_pattern, message)

    if url_match:
        url = url_match.group(1)
        # 基本URL验证 - 防止SSRF风险
        if len(url) > 2083:  # URL长度限制
            return ""
        return url

    # 匹配IP:端口模式
    ip_pattern = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::(\d+))?'
    ip_match = re.search(ip_pattern, message)

    if ip_match:
        ip_str = ip_match.group(1)
        port = ip_match.group(2)

        # 验证IP合法性
        try:
            ip = ipaddress.ip_address(ip_str)
            # 构造返回结果
            result = ip_str
            if port:
                result += f":{port}"
            return result
        except ValueError:
            # IP地址不合法，返回空字符串
            return ""

    return ""


async def execute_agent_task(
    target: str,
    description: str,
    websocket: WebSocket,
    session_id: str
):
    """真实Agent执行流程"""
    global is_executing

    print(f"[Agent] 开始执行任务 - 目标: {target}")

    try:
        from app.main import run_agent  # 延迟导入避免循环依赖
    except ImportError as e:
        print(f"[Agent] 导入run_agent失败: {e}")
        await websocket.send_json({
            "type": "error",
            "data": {"message": f"Agent模块导入失败: {str(e)}"}
        })
        is_executing = False
        return

    try:
        print(f"[Agent] 调用run_agent...")
        # 调用真实Agent执行（添加超时控制：5分钟）
        result = await asyncio.wait_for(
            run_agent(
                target=target,
                description=description,
                max_iterations=50
            ),
            timeout=300  # 5分钟超时
        )
        print(f"[Agent] run_agent完成 - 成功: {result.get('success')}")

        # 流式发送结果（使用.get()确保健壮性）
        await websocket.send_json({
            "type": "task_complete",
            "data": {
                "success": result.get("success", False),
                "flags": result.get("flags", []),
                "iterations": result.get("iterations", 0),
                "session_id": result.get("session_id"),
                "error": result.get("error")
            }
        })
    except asyncio.TimeoutError:
        print(f"[Agent] 执行超时")
        await websocket.send_json({
            "type": "error",
            "data": {"message": "Agent execution timeout (5 minutes)"}
        })
    except Exception as e:
        print(f"[Agent] 执行错误: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        await websocket.send_json({
            "type": "error",
            "data": {"message": f"Agent执行错误: {str(e)}"}
        })
    finally:
        is_executing = False
        print(f"[Agent] 任务结束 - is_executing: {is_executing}")

# ============================================
# 静态文件服务（生产环境）
# ============================================

# 如果dist目录存在，服务前端静态文件
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