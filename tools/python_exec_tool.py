# tools/python_exec_tool.py
# Python 脚本执行工具 - 让 AI 用代码精确处理任务
import os
import sys
import json
import base64
import subprocess
import tempfile
from typing import Dict, Any
from tool_framework import CTFTool


class PythonExecTool(CTFTool):
    """
    Python 脚本执行工具

    适用场景：
    1. 编码/解码（base64、URL、十六进制、Unicode等）
    2. 加密/解密（MD5、SHA、AES、RSA等）
    3. 数据处理和转换
    4. 正则匹配和文本提取
    5. 数学计算
    6. 任何需要精确执行的任务

    AI 自己写脚本，确保准确性！
    """

    OUTPUT_DIR = os.path.join("data", "tool_outputs")

    def __init__(self):
        os.makedirs(self.OUTPUT_DIR, exist_ok=True)

    def name(self) -> str:
        return "python-exec"

    def description(self) -> str:
        return ("Python 脚本执行工具。当需要精确处理编码、解码、加密、解密、数据处理、"
                "正则提取、数学计算等任务时，编写 Python 代码执行。比 AI 直接输出更准确！")

    def supported_vulns(self) -> list:
        return ["Data Processing", "Encoding", "Decoding", "Cryptography", "Calculation"]

    def check_available(self) -> bool:
        return True  # Python 总是可用

    def expected_params(self) -> Dict[str, Dict[str, Any]]:
        return {
            "code": {
                "type": "str",
                "description": "要执行的 Python 代码。可以 import 标准库。结果通过 print() 输出或设置 result 变量。",
                "required": True
            },
            "description": {
                "type": "str",
                "description": "代码功能描述（如：base64解码、提取URL等）",
                "required": False,
                "default": ""
            }
        }

    def execute(self, target: str, params: Dict) -> Dict:
        code = params.get("code", "")
        description = params.get("description", "Python execution")

        if not code:
            return {
                "success": False,
                "error": "必须提供 code 参数",
                "summary": "执行失败：缺少代码"
            }

        # 创建临时脚本
        try:
            with tempfile.NamedTemporaryFile(
                mode='w',
                suffix='.py',
                delete=False,
                encoding='utf-8'
            ) as f:
                # 包装代码，捕获输出和 result 变量
                wrapped_code = f'''
import sys
import json
import base64
import hashlib
import re
import urllib.parse
import binascii
import struct
import zlib
import gzip
from io import BytesIO

# 用户代码
{code}

# 输出 result 变量（如果存在）
if 'result' in dir():
    try:
        if isinstance(result, (dict, list)):
            print("=== RESULT_JSON ===")
            print(json.dumps(result, ensure_ascii=False, indent=2))
        else:
            print("=== RESULT ===")
            print(result)
    except Exception as e:
        print("=== RESULT ===")
        print(result)
'''
                f.write(wrapped_code)
                script_path = f.name

            # 执行脚本
            result = subprocess.run(
                [sys.executable, script_path],
                capture_output=True,
                text=True,
                timeout=30,
                cwd=self.OUTPUT_DIR
            )

            # 清理临时文件
            os.unlink(script_path)

            stdout = result.stdout
            stderr = result.stderr
            return_code = result.returncode

            # 解析结果
            output_data = None
            if "=== RESULT_JSON ===" in stdout:
                parts = stdout.split("=== RESULT_JSON ===")
                json_str = parts[-1].strip().split("=== RESULT ===")[0].strip()
                try:
                    output_data = json.loads(json_str)
                except:
                    output_data = json_str
            elif "=== RESULT ===" in stdout:
                output_data = stdout.split("=== RESULT ===")[-1].strip()
            else:
                # 捕获所有 print 输出作为结果
                output_data = stdout.strip() if stdout.strip() else None

            success = return_code == 0

            summary = f"Python 执行{'成功' if success else '失败'}"
            if output_data and success:
                summary += f": {str(output_data)[:200]}"

            return {
                "success": success,
                "output": stdout,
                "output_data": output_data,
                "stderr": stderr if stderr else None,
                "return_code": return_code,
                "description": description,
                "summary": summary
            }

        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "error": "执行超时（30秒）",
                "summary": "执行失败：超时"
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "summary": f"执行失败: {str(e)}"
            }