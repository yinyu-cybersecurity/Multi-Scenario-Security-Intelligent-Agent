# tools/phpggc_tool.py
# PHPGGC - PHP 反序列化 Payload 生成器
import os
import sys
import json
import subprocess
from typing import Dict, Any
from tool_framework import CommandLineTool


class PhpggcTool(CommandLineTool):
    """
    PHPGGC 封装 - PHP 反序列化 Gadget 链生成器
    支持 Laravel、Symfony、WordPress 等多种框架
    """

    def __init__(self):
        cmd = "php" if os.path.exists("/.dockerenv") else "php"
        super().__init__(cmd)

        docker_path = "/app/thirdparty/phpggc/phpggc"
        local_path = os.path.join(os.getcwd(), "thirdparty", "phpggc", "phpggc")
        self.script_path = docker_path if os.path.exists(docker_path) else local_path
        self.timeout = 60

    def name(self) -> str:
        return "phpggc"

    def description(self) -> str:
        return "PHP 反序列化 Payload 生成器，支持 Laravel、Symfony、WordPress 等框架的 Gadget 链"

    def supported_vulns(self) -> list:
        return ["PHP Deserialization", "Insecure Deserialization", "Object Injection", "RCE"]

    def check_available(self) -> bool:
        import shutil
        php_exists = shutil.which("php") is not None
        script_exists = self.script_path is not None and os.path.exists(self.script_path)
        return php_exists and script_exists

    def expected_params(self) -> Dict[str, Dict[str, Any]]:
        return {
            "gadget": {
                "type": "str",
                "description": "Gadget 链名称，如 Laravel/RCE1, Symfony/RCE1, WordPress/PHPMailer",
                "required": True
            },
            "parameters": {
                "type": "str",
                "description": "Gadget 参数，如命令或回调函数",
                "required": False,
                "default": "id"
            },
            "encode": {
                "type": "str",
                "description": "编码格式: base64, url, raw (默认 raw)",
                "required": False,
                "default": "raw"
            }
        }

    def execute(self, target: str, params: Dict) -> Dict:
        gadget = params.get("gadget")
        parameters = params.get("parameters", "id")

        if not gadget:
            raise ValueError("必须提供 gadget 参数")

        cmd = [self.cmd_path, self.script_path, gadget]

        # 添加参数
        if parameters:
            cmd.append(parameters)

        # 编码
        encode = params.get("encode", "raw")
        if encode == "base64":
            cmd.append("-b")
        elif encode == "url":
            cmd.append("-u")

        try:
            raw_result = self._run_command(cmd, timeout=self.timeout, stream_output=True)
            stdout = raw_result.get("stdout", "")
            stderr = raw_result.get("stderr", "")

            payload_generated = len(stdout) > 0 and "error" not in stderr.lower()

            result = {
                "success": payload_generated,
                "vulnerable": payload_generated,
                "gadget": gadget,
                "parameters": parameters,
                "encoding": encode,
                "payload_length": len(stdout),
                "payload_preview": stdout[:1000] if stdout else "",
                "summary": f"生成 {gadget} 链 payload {'成功' if payload_generated else '失败'}"
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