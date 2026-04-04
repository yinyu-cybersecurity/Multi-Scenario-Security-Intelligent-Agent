#!/usr/bin/env python3
"""Web服务器 - 提供WebSocket接口供前端监控"""

import asyncio
import json
from typing import Set
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import uvicorn

from app.core.query import query, QueryConfig
from app.prompts.ctf_system_prompt import build_system_prompt
from app.tools_v2.ctf_tools import register_ctf_tools
from app.logger import get_logger

logger = get_logger("WebServer")

app = FastAPI(title="CTF-Agent Web Interface")

# 连接管理
class ConnectionManager:
    def __init__(self):
        self.active_connections: Set[WebSocket] = set()

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.add(websocket)
        logger.info(f"Client connected. Total: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        self.active_connections.discard(websocket)
        logger.info(f"Client disconnected. Total: {len(self.active_connections)}")

    async def broadcast(self, message: dict):
        """广播消息给所有连接"""
        data = json.dumps(message, ensure_ascii=False)
        for connection in self.active_connections:
            try:
                await connection.send_text(data)
            except:
                pass

manager = ConnectionManager()


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket接口"""
    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            try:
                request = json.loads(data)
                command = request.get("command")

                if command == "start":
                    # 启动任务
                    target = request.get("target", "")
                    if target:
                        asyncio.create_task(run_agent(target, websocket))
                        await websocket.send_text(json.dumps({
                            "type": "status",
                            "status": "started",
                            "target": target
                        }))

                elif command == "stop":
                    # 停止任务
                    await websocket.send_text(json.dumps({
                        "type": "status",
                        "status": "stopped"
                    }))

            except json.JSONDecodeError:
                await websocket.send_text(json.dumps({
                    "type": "error",
                    "message": "Invalid JSON"
                }))

    except WebSocketDisconnect:
        manager.disconnect(websocket)


async def run_agent(target: str, websocket: WebSocket):
    """运行Agent任务"""
    # 注册工具
    register_ctf_tools()

    # 配置
    config = QueryConfig(
        model="qwen3.5-plus",
        max_turns=200,
        timeout_seconds=1800,
        system_prompt=build_system_prompt(target, 1800),
    )

    messages = [{
        "role": "user",
        "content": f"Target: {target}\n\nFind the FLAG."
    }]

    turn = 0
    async for event in query(messages, config):
        turn += 1

        # 发送事件到前端
        event_data = {"type": event["type"], "turn": turn}

        if event["type"] == "assistant_message":
            event_data["content"] = event.get("content", "")
            event_data["turn"] = event.get("turn", turn)

        elif event["type"] == "tool_result":
            event_data["tool_name"] = event.get("tool_name", "")

        elif event["type"] == "complete":
            event_data["reason"] = event.get("reason", "")

        elif event["type"] == "loop_detected":
            event_data["tool"] = event.get("tool", "")

        # 发送给当前客户端
        try:
            await websocket.send_text(json.dumps(event_data, ensure_ascii=False))
        except:
            break

        # 广播给所有客户端
        await manager.broadcast(event_data)


# 静态文件服务（前端）
@app.get("/")
async def root():
    return FileResponse("frontend/index.html")


@app.get("/{path:path}")
async def serve_frontend(path: str):
    """服务前端静态文件"""
    import os
    file_path = f"frontend/{path}"
    if os.path.exists(file_path) and os.path.isfile(file_path):
        return FileResponse(file_path)
    return FileResponse("frontend/index.html")


if __name__ == "__main__":
    print("=" * 60)
    print("CTF-Agent Web Interface")
    print("=" * 60)
    print("Frontend: http://localhost:8000")
    print("WebSocket: ws://localhost:8000/ws")
    print("=" * 60)

    uvicorn.run(app, host="0.0.0.0", port=8000)