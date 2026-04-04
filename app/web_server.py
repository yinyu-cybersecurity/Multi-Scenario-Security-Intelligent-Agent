#!/usr/bin/env python3
"""Web服务器 - 提供WebSocket接口供前端监控"""

import asyncio
import json
from typing import Set, Optional
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import uvicorn

from app.core.query import query, QueryConfig
from app.prompts.ctf_system_prompt import build_system_prompt
from app.logger import get_logger

logger = get_logger("WebServer")

app = FastAPI(title="CTF-Agent Web Interface")

# 全局停止标志
_stop_flag = False
_current_task: Optional[asyncio.Task] = None


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
    global _stop_flag, _current_task

    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            try:
                request = json.loads(data)
                command = request.get("command")
                msg_type = request.get("type")

                # 新格式：command=start
                if command == "start":
                    target = request.get("target", "")
                    if target:
                        _stop_flag = False
                        _current_task = asyncio.create_task(run_agent(target, websocket))
                        await websocket.send_text(json.dumps({
                            "type": "status",
                            "status": "started",
                            "target": target
                        }))

                # 旧格式：type=user_input
                elif msg_type == "user_input":
                    message = request.get("data", {}).get("message", "")
                    # 处理用户输入

                elif msg_type == "interrupt":
                    _stop_flag = True
                    if _current_task:
                        _current_task.cancel()
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
    global _stop_flag

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
    try:
        async for event in query(messages, config):
            if _stop_flag:
                await websocket.send_text(json.dumps({
                    "type": "status",
                    "status": "interrupted"
                }))
                break

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
    except asyncio.CancelledError:
        await websocket.send_text(json.dumps({
            "type": "status",
            "status": "stopped"
        }))


# 静态文件服务（前端）
@app.get("/")
async def root():
    return FileResponse("frontend/dist/index.html")


@app.get("/api")
async def api_info():
    return {"message": "CTF-Agent 2.0 API", "status": "running", "arch": "Claude Code Query Loop"}


@app.get("/assets/{path:path}")
async def serve_assets(path: str):
    """服务前端资源文件"""
    import os
    file_path = f"frontend/dist/assets/{path}"
    if os.path.exists(file_path):
        return FileResponse(file_path)
    return {"error": "Not found"}, 404


@app.get("/{path:path}")
async def serve_frontend(path: str):
    """服务前端静态文件"""
    import os
    # 先检查dist目录
    file_path = f"frontend/dist/{path}"
    if os.path.exists(file_path) and os.path.isfile(file_path):
        return FileResponse(file_path)
    # 再检查frontend目录
    file_path = f"frontend/{path}"
    if os.path.exists(file_path) and os.path.isfile(file_path):
        return FileResponse(file_path)
    return FileResponse("frontend/dist/index.html")


if __name__ == "__main__":
    print("=" * 60)
    print("CTF-Agent Web Interface")
    print("=" * 60)
    print("Frontend: http://localhost:8000")
    print("WebSocket: ws://localhost:8000/ws")
    print("=" * 60)

    uvicorn.run(app, host="0.0.0.0", port=8000)