# remote_executor/http_server.py
"""
HTTP服务器模块

提供简单的HTTP服务器用于工具分发

框架运行在VPS上，本模块启动HTTP服务器
供目标机器下载工具

使用方式:
    from remote_executor.http_server import start_http_server
    start_http_server(port=8000, directory="/opt/tools")
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
    directory: str = "/opt/tools",
    daemon: bool = True
) -> Optional[threading.Thread]:
    """
    启动HTTP服务器

    Args:
        port: 监听端口
        directory: 服务目录 (默认使用镜像内置的工具目录)
        daemon: 是否作为守护线程运行

    Returns:
        服务器线程对象
    """
    if not os.path.exists(directory):
        print(f"[HTTPServer] 警告: 目录不存在 {directory}")
        os.makedirs(directory, exist_ok=True)

    # 保存当前目录
    original_dir = os.getcwd()
    os.chdir(directory)

    handler = http.server.SimpleHTTPRequestHandler

    try:
        server = ThreadedHTTPServer(("0.0.0.0", port), handler)
        server_thread = threading.Thread(target=server.serve_forever)
        server_thread.daemon = daemon
        server_thread.start()

        # 恢复原目录
        os.chdir(original_dir)

        print(f"[HTTPServer] 启动成功: http://0.0.0.0:{port}")
        print(f"[HTTPServer] 服务目录: {directory}")

        return server_thread

    except OSError as e:
        os.chdir(original_dir)
        if "Address already in use" in str(e) or e.errno == 98:
            print(f"[HTTPServer] 端口 {port} 已被占用")
        else:
            print(f"[HTTPServer] 启动失败: {e}")
        return None
    except Exception as e:
        os.chdir(original_dir)
        print(f"[HTTPServer] 启动失败: {e}")
        return None


def check_tools_directory() -> dict:
    """
    检查工具目录 (镜像内置路径)

    Returns:
        各目录的工具列表
    """
    dirs = {
        "tools": "/opt/tools",
        "potato": "/opt/tools/potato",
        "ad": "/opt/tools/ad",
        "linux": "/opt/tools/linux",
        "windows": "/opt/tools/windows",
        "frp": "/opt/frp"
    }

    result = {}
    for name, path in dirs.items():
        if os.path.exists(path):
            files = os.listdir(path)
            result[name] = {
                "path": path,
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
    """确保工具目录存在 (仅在本地开发时使用)"""
    # 生产环境中，工具目录由Dockerfile创建
    # 此函数仅用于本地开发或调试
    dirs = [
        "/opt/tools",
        "/opt/tools/potato",
        "/opt/tools/ad",
        "/opt/tools/linux",
        "/opt/tools/windows",
        "/opt/frp"
    ]

    for d in dirs:
        os.makedirs(d, exist_ok=True)

    print(f"[HTTPServer] 确保工具目录存在: {len(dirs)} 个")
    return dirs