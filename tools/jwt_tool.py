# tools/jwt_tool.py
# JWT Tool - JWT 安全测试工具
import os
import json
import subprocess
from typing import Dict, Any
from tool_framework import CommandLineTool


class JwtTool(CommandLineTool):
    """
    JWT Tool 封装 - JWT 安全测试工具
    支持 JWT 伪造、破解、算法混淆等攻击
    """

    def __init__(self):
        cmd = "python3" if os.path.exists("/.dockerenv") else "python"
        super().__init__(cmd)

        docker_path = "/app/thirdparty/jwt_tool/jwt_tool.py"
        local_path = os.path.join(os.getcwd(), "thirdparty", "jwt_tool", "jwt_tool.py")
        self.script_path = docker_path if os.path.exists(docker_path) else local_path
        self.timeout = 60

    def name(self) -> str:
        return "jwt-tool"

    def description(self) -> str:
        return "JWT 安全测试工具，支持令牌伪造、密钥破解、算法混淆攻击"

    def supported_vulns(self) -> list:
        return ["JWT Forgery", "Algorithm Confusion", "None Algorithm", "Weak Secret", "Token Tampering"]

    def check_available(self) -> bool:
        return os.path.exists(self.script_path)

    def expected_params(self) -> Dict[str, Dict[str, Any]]:
        return {
            "jwt": {
                "type": "str",
                "description": "JWT token 值",
                "required": True
            },
            "action": {
                "type": "str",
                "description": "操作类型: decode (解码), crack (破解密钥), forge (伪造), none (None算法)",
                "required": True
            },
            "payload": {
                "type": "dict",
                "description": "要注入的 payload 数据 (forge 时需要)",
                "required": False
            },
            "secret": {
                "type": "str",
                "description": "签名密钥 (forge/verify 时需要)",
                "required": False
            },
            "wordlist": {
                "type": "str",
                "description": "密钥字典文件路径 (crack 时需要)",
                "required": False
            }
        }

    def execute(self, target: str, params: Dict) -> Dict:
        jwt_token = params.get("jwt")
        action = params.get("action", "decode")

        if not jwt_token:
            raise ValueError("必须提供 jwt 参数")

        try:
            # 简单解码 JWT (不验证签名)
            if action == "decode":
                parts = jwt_token.split('.')
                if len(parts) != 3:
                    raise ValueError("无效的 JWT 格式")

                import base64
                header = base64.urlsafe_b64decode(parts[0] + '==').decode('utf-8', errors='ignore')
                payload = base64.urlsafe_b64decode(parts[1] + '==').decode('utf-8', errors='ignore')

                return {
                    "success": True,
                    "action": "decode",
                    "jwt": jwt_token,
                    "header": json.loads(header) if header else {},
                    "payload": json.loads(payload) if payload else {},
                    "summary": "JWT 解码成功"
                }

            # 使用 jwt_tool 进行更复杂的操作
            cmd = [self.cmd_path, self.script_path, jwt_token]

            if action == "crack":
                wordlist = params.get("wordlist", "/usr/share/wordlists/rockyou.txt")
                cmd.extend(["-C", "-d", wordlist])
            elif action == "forge":
                secret = params.get("secret", "")
                payload_data = params.get("payload", {})
                # jwt_tool 伪造需要更复杂的参数处理
                # 这里简化处理，返回指导信息
                return {
                    "success": True,
                    "action": "forge",
                    "jwt": jwt_token,
                    "new_payload": payload_data,
                    "secret": secret,
                    "usage": "使用 jwt_tool.py <token> -S <secret> -I -pc <claim> -pv <value>",
                    "summary": "请使用命令行工具进行精确伪造"
                }
            elif action == "none":
                cmd.extend(["-X", "n"])  # None algorithm attack

            raw_result = self._run_command(cmd, timeout=self.timeout, stream_output=True)
            stdout = raw_result.get("stdout", "")
            stderr = raw_result.get("stderr", "")

            result = {
                "success": True,
                "action": action,
                "jwt": jwt_token,
                "output": stdout[:2000] if stdout else "",
                "summary": f"JWT {action} 操作完成"
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