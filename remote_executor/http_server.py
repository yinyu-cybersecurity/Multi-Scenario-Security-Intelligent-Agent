# remote_executor/http_server.py
"""
HTTP服务器模块

提供简单的HTTP服务器用于工具分发

框架运行在VPS上，本模块启动HTTP服务器
供目标机器下载工具

使用方式:
    from remote_executor.http_server import start_http_server
    start_http_server(port=8000, directory="data/tools")
"""

import os
import threading
import http.server
import socketserver
from typing import Optional


class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    """多线程HTTP服务器"""
    pass


def start_http_server(
    port: int = 8000,
    directory: str = "data/tools",
    daemon: bool = True
) -> Optional[threading.Thread]:
    """
    启动HTTP服务器

    Args:
        port: 监听端口
        directory: 服务目录
        daemon: 是否作为守护线程运行

    Returns:
        服务器线程对象
    """
    if not os.path.exists(directory):
        os.makedirs(directory, exist_ok=True)

    os.chdir(directory)

    handler = http.server.SimpleHTTPRequestHandler

    try:
        server = ThreadedHTTPServer(("0.0.0.0", port), handler)
        server_thread = threading.Thread(target=server.serve_forever)
        server_thread.daemon = daemon
        server_thread.start()

        print(f"[HTTPServer] 启动成功: http://0.0.0.0:{port}")
        print(f"[HTTPServer] 服务目录: {os.path.abspath(directory)}")

        return server_thread

    except OSError as e:
        if "Address already in use" in str(e) or e.errno == 98:
            print(f"[HTTPServer] 端口 {port} 已被占用")
        else:
            print(f"[HTTPServer] 启动失败: {e}")
        return None
    except Exception as e:
        print(f"[HTTPServer] 启动失败: {e}")
        return None


def check_tools_directory() -> dict:
    """
    检查工具目录

    Returns:
        各目录的工具列表
    """
    dirs = {
        "tools": "data/tools",
        "potato": "data/tools/potato",
        "ad": "data/tools/ad",
        "linux": "data/tools/linux",
        "frp": "data/frp"
    }

    result = {}
    for name, path in dirs.items():
        if os.path.exists(path):
            files = os.listdir(path)
            result[name] = {
                "path": os.path.abspath(path),
                "files": files,
                "count": len(files)
            }
        else:
            result[name] = {
                "path": path,
                "files": [],
                "count": 0,
                "exists": False
            }

    return result


def ensure_tools_directories():
    """确保工具目录存在"""
    dirs = [
        "data/tools",
        "data/tools/potato",
        "data/tools/ad",
        "data/tools/linux",
        "data/frp"
    ]

    for d in dirs:
        os.makedirs(d, exist_ok=True)

    print(f"[HTTPServer] 创建工具目录: {len(dirs)} 个")
    return dirs