# tools/flask_unsign_tool.py
# Flask-Unsign - Flask Session 签名工具
import os
import json
import subprocess
from typing import Dict, Any
from tool_framework import CommandLineTool


class FlaskUnsignTool(CommandLineTool):
    """
    Flask-Unsign 封装 - Flask Session Cookie 签名/解签工具
    用于伪造 Flask session cookie
    """

    def __init__(self):
        import sys
        cmd = "python3" if os.path.exists("/.dockerenv") else sys.executable
        super().__init__(cmd)
        self.timeout = 30

    def name(self) -> str:
        return "flask-unsign"

    def description(self) -> str:
        return "Flask Session Cookie 签名/解签工具，用于伪造和破解 Flask session"

    def supported_vulns(self) -> list:
        return ["Session Tampering", "Flask Session Forgery", "Cookie Manipulation", "Insecure Session"]

    def check_available(self) -> bool:
        try:
            import flask_unsign
            return True
        except ImportError:
            return False

    def expected_params(self) -> Dict[str, Dict[str, Any]]:
        return {
            "action": {
                "type": "str",
                "description": "操作类型: sign (签名), unsign (解签), crack (破解密钥)",
                "required": True
            },
            "cookie": {
                "type": "str",
                "description": "Flask session cookie 值 (unsign/crack 时需要)",
                "required": False
            },
            "secret": {
                "type": "str",
                "description": "签名密钥 (sign/unsign 时需要)",
                "required": False
            },
            "data": {
                "type": "dict",
                "description": "要签名的数据，如 {'user': 'admin'} (sign 时需要)",
                "required": False
            },
            "wordlist": {
                "type": "str",
                "description": "密钥字典文件路径 (crack 时需要)",
                "required": False
            }
        }

    def execute(self, target: str, params: Dict) -> Dict:
        action = params.get("action", "unsign")
        cookie = params.get("cookie")
        secret = params.get("secret")
        data = params.get("data")
        wordlist = params.get("wordlist")

        try:
            from flask_unsign.sign import sign
            from flask_unsign.verify import verify, InvalidSignature
            import json as json_module

            result = {"success": True}

            if action == "sign":
                if not secret or not data:
                    raise ValueError("sign 操作需要 secret 和 data 参数")
                signed_cookie = sign(data, secret)
                result.update({
                    "action": "sign",
                    "secret": secret,
                    "data": data,
                    "cookie": signed_cookie,
                    "summary": f"成功生成签名 Cookie: {signed_cookie[:50]}..."
                })

            elif action == "unsign":
                if not cookie or not secret:
                    raise ValueError("unsign 操作需要 cookie 和 secret 参数")
                try:
                    decoded = verify(cookie, secret)
                    result.update({
                        "action": "unsign",
                        "cookie": cookie,
                        "secret": secret,
                        "data": decoded,
                        "valid": True,
                        "summary": f"Cookie 解签成功: {decoded}"
                    })
                except InvalidSignature:
                    result.update({
                        "action": "unsign",
                        "cookie": cookie,
                        "secret": secret,
                        "valid": False,
                        "summary": "密钥错误或签名无效"
                    })

            elif action == "crack":
                if not cookie:
                    raise ValueError("crack 操作需要 cookie 参数")

                # 尝试常见密钥
                common_secrets = [
                    "secret", "password", "admin", "flask", "secret_key",
                    "SECRET_KEY", "development", "production", "changeme"
                ]

                if wordlist and os.path.exists(wordlist):
                    with open(wordlist, 'r') as f:
                        common_secrets = [line.strip() for line in f if line.strip()]

                found_secret = None
                for s in common_secrets:
                    try:
                        verify(cookie, s)
                        found_secret = s
                        break
                    except InvalidSignature:
                        continue

                if found_secret:
                    result.update({
                        "action": "crack",
                        "cookie": cookie,
                        "found_secret": found_secret,
                        "success": True,
                        "summary": f"成功破解密钥: {found_secret}"
                    })
                else:
                    result.update({
                        "action": "crack",
                        "cookie": cookie,
                        "success": False,
                        "summary": "未能破解密钥"
                    })

            else:
                raise ValueError(f"未知操作: {action}")

            return result

        except ImportError:
            return {
                "success": False,
                "error": "flask-unsign 未安装，请运行: pip install flask-unsign",
                "vulnerable": False,
                "summary": "工具不可用"
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "vulnerable": False,
                "summary": f"执行失败: {str(e)}"
            }