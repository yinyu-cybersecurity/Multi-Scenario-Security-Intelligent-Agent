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
from datetime import datetime
from pathlib import Path

# 导入核心组件
from app.graph.ctf_graph import build_ctf_graph
from app.state.state_v3 import create_initial_state, ChallengeInfo, ChallengeType
from app.coordinator.dispatcher import get_coordinator_dispatcher
from app.memory import get_agent_memory
from app.settings import config

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
        await websocket.accept()
        self.active_connections.append(websocket)
        await self.broadcast({
            "type": "system",
            "data": {"message": "Client connected", "timestamp": datetime.now().isoformat()}
        })

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
    await manager.connect(websocket)

    try:
        # 发送初始状态
        await manager.send_personal(websocket, {
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
                await manager.send_personal(websocket, {
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

                # TODO: 调用Agent处理
                # 模拟Agent响应
                await manager.broadcast({
                    "type": "log",
                    "data": {
                        "id": f"log-{uuid.uuid4()}",
                        "timestamp": datetime.now().isoformat(),
                        "type": "assistant",
                        "message": f"收到任务: {user_message}",
                        "iteration": iteration_count
                    }
                })

            elif msg_type == "interrupt":
                # 用户打断
                global is_executing
                is_executing = False

                await manager.broadcast({
                    "type": "interrupt",
                    "data": {"reason": "user_cancel", "timestamp": datetime.now().isoformat()}
                })

            elif msg_type == "ping":
                # 心跳
                await manager.send_personal(websocket, {
                    "type": "pong",
                    "data": {"timestamp": datetime.now().isoformat()}
                })

    except WebSocketDisconnect:
        manager.disconnect(websocket)
        await manager.broadcast({
            "type": "system",
            "data": {"message": "Client disconnected", "timestamp": datetime.now().isoformat()}
        })
    except Exception as e:
        manager.disconnect(websocket)
        await manager.broadcast({
            "type": "error",
            "data": {"message": str(e), "timestamp": datetime.now().isoformat()}
        })

# ============================================
# 模拟数据生成（用于测试）
# ============================================

async def simulate_agent_execution():
    """模拟Agent执行过程（测试用）"""
    global iteration_count, is_executing

    for i in range(1, 6):
        if not is_executing:
            break

        iteration_count = i

        # 迭代开始
        await manager.broadcast({
            "type": "iteration_start",
            "data": {
                "iteration": i,
                "timestamp": datetime.now().isoformat()
            }
        })

        # 模拟节点执行
        for node in ["think", "act", "reflect", "decide"]:
            await manager.broadcast({
                "type": "node_start",
                "data": {
                    "node": node,
                    "iteration": i,
                    "timestamp": datetime.now().isoformat()
                }
            })

            await asyncio.sleep(1)

            await manager.broadcast({
                "type": "node_end",
                "data": {
                    "node": node,
                    "iteration": i,
                    "result": f"{node} completed",
                    "timestamp": datetime.now().isoformat()
                }
            })

        # 迭代结束
        await manager.broadcast({
            "type": "iteration_end",
            "data": {
                "iteration": i,
                "timestamp": datetime.now().isoformat()
            }
        })

        await asyncio.sleep(2)

    # 任务完成
    await manager.broadcast({
        "type": "task_complete",
        "data": {
            "success": True,
            "flags": flags,
            "timestamp": datetime.now().isoformat()
        }
    })

    is_executing = False

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
        "server:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )