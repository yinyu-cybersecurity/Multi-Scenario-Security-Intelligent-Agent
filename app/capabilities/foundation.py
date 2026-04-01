"""
基础能力实现

借鉴Claude Code的Foundation工具设计：
- Read/Write/Edit/Bash/Glob/Grep作为Agent默认能力
- Schema驱动，LLM自动构造调用
- 支持本地文件和远程URL

安全特性:
- 路径遍历防护 - 所有文件操作验证路径在workspace内
- 命令注入防护 - Bash使用参数化执行
- 危险命令黑名单
"""

import os
import re
import fnmatch
import asyncio
import aiofiles
import glob as glob_module
import shlex
import ipaddress
from urllib.parse import urlparse
from enum import Enum
from typing import Dict, Any, List, Optional
from dataclasses import dataclass


class FoundationTool(Enum):
    """基础工具枚举"""
    READ = "Read"          # 读取文件/URL/输出
    WRITE = "Write"        # 创建文件
    EDIT = "Edit"          # 编辑文件
    BASH = "Bash"          # 执行命令
    GLOB = "Glob"          # 文件搜索
    GREP = "Grep"          # 内容搜索


@dataclass
class ToolSchema:
    """工具Schema定义"""
    name: str
    description: str
    parameters: Dict[str, Any]
    returns: str

    def to_api_format(self) -> Dict:
        """转换为API格式供LLM调用"""
        return {
            "name": self.name,
            "description": self.description,
            "parameters": self.parameters
        }


# 基础工具Schema定义
FOUNDATION_SCHEMAS = {
    FoundationTool.READ: ToolSchema(
        name="Read",
        description="""读取文件、URL或命令输出。

用途:
- 读取本地文件内容
- 获取远程URL响应
- 查看目录结构

支持:
- 本地文件路径（绝对或相对）
- HTTP/HTTPS URL
- 目录列表（路径以/结尾）
""",
        parameters={
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "文件路径或URL"
                },
                "offset": {
                    "type": "integer",
                    "description": "起始行号（可选，从0开始）"
                },
                "limit": {
                    "type": "integer",
                    "description": "读取行数（可选）"
                }
            },
            "required": ["file_path"]
        },
        returns="文件内容或URL响应，包含success字段"
    ),

    FoundationTool.WRITE: ToolSchema(
        name="Write",
        description="""创建新文件或覆盖现有文件。

用途:
- 创建配置文件
- 生成脚本文件
- 保存输出结果

注意:
- 会覆盖已存在的文件
- 自动创建父目录
""",
        parameters={
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "文件路径（推荐绝对路径）"
                },
                "content": {
                    "type": "string",
                    "description": "文件内容"
                }
            },
            "required": ["file_path", "content"]
        },
        returns="写入结果，包含success和path字段"
    ),

    FoundationTool.EDIT: ToolSchema(
        name="Edit",
        description="""编辑现有文件，进行精确字符串替换。

用途:
- 修改配置文件
- 更新代码
- 调整脚本

要求:
- old_string必须在文件中唯一存在
- 不会执行不明确的替换
""",
        parameters={
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "文件路径"
                },
                "old_string": {
                    "type": "string",
                    "description": "要替换的内容（必须唯一匹配）"
                },
                "new_string": {
                    "type": "string",
                    "description": "替换后的内容"
                }
            },
            "required": ["file_path", "old_string", "new_string"]
        },
        returns="编辑结果，包含success字段"
    ),

    FoundationTool.BASH: ToolSchema(
        name="Bash",
        description="""执行Shell命令。

用途:
- 运行扫描工具
- 执行脚本
- 系统操作

安全:
- 不执行危险命令（rm -rf /*等）
- 支持超时控制
""",
        parameters={
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "description": "要执行的Shell命令"
                },
                "timeout": {
                    "type": "integer",
                    "description": "超时时间（毫秒），默认60000"
                },
                "background": {
                    "type": "boolean",
                    "description": "是否后台运行，默认false"
                }
            },
            "required": ["command"]
        },
        returns="命令执行结果，包含stdout/stderr/returncode"
    ),

    FoundationTool.GLOB: ToolSchema(
        name="Glob",
        description="""文件模式匹配搜索。

用途:
- 查找特定类型文件
- 搜索配置文件
- 发现敏感文件

模式:
- * 匹配任意字符
- ** 递归匹配目录
- ? 匹配单个字符
""",
        parameters={
            "type": "object",
            "properties": {
                "pattern": {
                    "type": "string",
                    "description": "glob模式，如 **/*.py"
                },
                "path": {
                    "type": "string",
                    "description": "搜索路径，默认当前工作目录"
                }
            },
            "required": ["pattern"]
        },
        returns="匹配的文件路径列表"
    ),

    FoundationTool.GREP: ToolSchema(
        name="Grep",
        description="""文件内容正则搜索。

用途:
- 搜索敏感信息
- 查找配置项
- 发现凭据泄露

支持:
- 正则表达式
- 文件过滤
- 多行匹配
""",
        parameters={
            "type": "object",
            "properties": {
                "pattern": {
                    "type": "string",
                    "description": "正则表达式"
                },
                "path": {
                    "type": "string",
                    "description": "搜索路径"
                },
                "glob": {
                    "type": "string",
                    "description": "文件模式过滤，如 *.py"
                }
            },
            "required": ["pattern"]
        },
        returns="匹配结果列表，包含file/line/content"
    )
}


def validate_path(path: str, workspace: str) -> tuple[bool, str, str]:
    """
    验证路径安全性，防止路径遍历攻击

    Args:
        path: 待验证的路径
        workspace: 工作目录边界

    Returns:
        (is_valid, resolved_path, error_message)
    """
    try:
        # 解析为绝对路径
        resolved = os.path.abspath(path) if os.path.isabs(path) else os.path.abspath(os.path.join(workspace, path))

        # 规范化路径（解析 .. 等）
        resolved = os.path.normpath(resolved)
        workspace_norm = os.path.normpath(workspace)

        # 检查是否在workspace内
        if not resolved.startswith(workspace_norm + os.sep) and resolved != workspace_norm:
            return False, "", f"路径遍历攻击被阻止: {path}"

        return True, resolved, ""
    except Exception as e:
        return False, "", f"路径验证错误: {str(e)}"


def validate_url_for_ssrf(url: str, allow_private: bool = False) -> tuple[bool, str]:
    """
    验证URL防止SSRF攻击

    Args:
        url: 待验证的URL
        allow_private: 是否允许私有IP（内网场景）

    Returns:
        (is_valid, error_message)
    """
    try:
        parsed = urlparse(url)

        # 检查协议
        if parsed.scheme not in ['http', 'https']:
            return False, f"不支持的协议: {parsed.scheme}"

        # 获取主机名
        hostname = parsed.hostname
        if not hostname:
            return False, "无效的URL：缺少主机名"

        # 解析IP
        try:
            ip = ipaddress.ip_address(hostname)

            # 检查是否为私有IP
            if not allow_private and ip.is_private:
                return False, f"SSRF防护：禁止访问私有IP {hostname}"

            # 检查回环地址
            if ip.is_loopback and not allow_private:
                return False, f"SSRF防护：禁止访问回环地址"

        except ValueError:
            # 不是IP地址，可能是域名
            pass

        return True, ""
    except Exception as e:
        return False, f"URL验证错误: {str(e)}"


def ensure_result_format(result: Dict) -> Dict:
    """
    确保结果格式规范

    所有工具返回统一格式
    """
    return {
        "success": result.get("success", False),
        "data": result.get("data"),
        "error": result.get("error"),
        "metadata": result.get("metadata", {})
    }


class FoundationCapability:
    """
    基础能力实现

    所有Agent默认具备的基础能力：
    - Read: 读取文件/URL
    - Write: 创建文件
    - Edit: 编辑文件
    - Bash: 执行命令
    - Glob: 文件搜索
    - Grep: 内容搜索

    特点:
    - Schema驱动，LLM自动构造调用
    - 支持本地文件和远程URL
    - 统一的结果格式
    """

    def __init__(self, workspace: str = "."):
        """
        初始化基础能力

        Args:
            workspace: 工作目录，相对路径基于此解析
        """
        self.workspace = os.path.abspath(workspace)
        self._dangerous_commands = [
            "rm -rf /*",
            "rm -rf /",
            "mkfs",
            "dd if=",
            "> /dev/sd",
            "chmod -R 777 /",
        ]

    def get_schema(self, tool: FoundationTool) -> ToolSchema:
        """获取工具Schema"""
        return FOUNDATION_SCHEMAS[tool]

    def get_all_schemas(self) -> List[Dict]:
        """获取所有工具Schema（API格式）"""
        return [
            schema.to_api_format()
            for schema in FOUNDATION_SCHEMAS.values()
        ]

    async def execute(
        self,
        tool: FoundationTool,
        params: Dict[str, Any],
        context: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """
        执行基础工具

        Args:
            tool: 工具类型
            params: 工具参数
            context: 执行上下文（可选）

        Returns:
            执行结果字典，包含success字段
        """
        context = context or {}

        handlers = {
            FoundationTool.READ: self._read,
            FoundationTool.WRITE: self._write,
            FoundationTool.EDIT: self._edit,
            FoundationTool.BASH: self._bash,
            FoundationTool.GLOB: self._glob,
            FoundationTool.GREP: self._grep,
        }

        handler = handlers.get(tool)
        if not handler:
            return ensure_result_format({
                "success": False,
                "error": f"Unknown tool: {tool}"
            })

        try:
            result = await handler(params, context)
            return ensure_result_format(result)
        except Exception as e:
            return ensure_result_format({
                "success": False,
                "error": str(e)
            })

    # ==================== Read 实现 ====================

    async def _read(self, params: Dict, context: Dict) -> Dict:
        """
        读取实现

        支持:
        - 本地文件
        - HTTP/HTTPS URL
        - 目录列表
        """
        file_path = params["file_path"]
        offset = params.get("offset", 0)
        limit = params.get("limit", None)

        # 支持URL
        if file_path.startswith(("http://", "https://")):
            # SSRF防护
            is_valid, error = validate_url_for_ssrf(file_path)
            if not is_valid:
                return {"success": False, "error": error}
            return await self._read_url(file_path)

        # 路径遍历防护
        is_valid, resolved_path, error = validate_path(file_path, self.workspace)
        if not is_valid:
            return {"success": False, "error": error}

        # 检查是否存在
        if not os.path.exists(resolved_path):
            return {
                "success": False,
                "error": f"文件不存在: {resolved_path}"
            }

        # 目录列表
        if os.path.isdir(resolved_path):
            return await self._list_directory(resolved_path)

        # 读取文件
        return await self._read_file(resolved_path, offset, limit)

    async def _read_file(
        self,
        file_path: str,
        offset: int,
        limit: Optional[int]
    ) -> Dict:
        """读取文件内容"""
        try:
            async with aiofiles.open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                if offset > 0:
                    # 跳过前offset行
                    for _ in range(offset):
                        await f.readline()

                if limit is not None:
                    lines = []
                    for _ in range(limit):
                        line = await f.readline()
                        if not line:
                            break
                        lines.append(line)
                    content = ''.join(lines)
                else:
                    content = await f.read()

            return {
                "success": True,
                "data": {
                    "content": content,
                    "path": file_path,
                    "offset": offset,
                    "limit": limit
                }
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"读取文件错误: {str(e)}"
            }

    async def _read_url(self, url: str) -> Dict:
        """读取URL内容"""
        try:
            import aiohttp

            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                    if resp.status != 200:
                        return {
                            "success": False,
                            "error": f"HTTP {resp.status}: {url}"
                        }
                    content = await resp.text()

            return {
                "success": True,
                "data": {
                    "content": content,
                    "url": url,
                    "status": resp.status
                }
            }
        except asyncio.TimeoutError:
            return {
                "success": False,
                "error": f"URL超时: {url}"
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"URL获取错误: {str(e)}"
            }

    async def _list_directory(self, dir_path: str) -> Dict:
        """列出目录内容"""
        try:
            entries = []
            for entry in os.listdir(dir_path):
                full_path = os.path.join(dir_path, entry)
                entries.append({
                    "name": entry,
                    "type": "directory" if os.path.isdir(full_path) else "file",
                    "path": full_path
                })

            return {
                "success": True,
                "data": {
                    "path": dir_path,
                    "entries": entries,
                    "count": len(entries)
                }
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"列出目录错误: {str(e)}"
            }

    # ==================== Write 实现 ====================

    async def _write(self, params: Dict, context: Dict) -> Dict:
        """
        写入实现

        创建新文件或覆盖现有文件
        自动创建父目录
        """
        file_path = params["file_path"]
        content = params["content"]

        # 路径遍历防护
        is_valid, resolved_path, error = validate_path(file_path, self.workspace)
        if not is_valid:
            return {"success": False, "error": error}

        try:
            # 创建父目录
            parent_dir = os.path.dirname(resolved_path)
            if parent_dir and not os.path.exists(parent_dir):
                os.makedirs(parent_dir, exist_ok=True)

            # 写入文件
            async with aiofiles.open(resolved_path, 'w', encoding='utf-8') as f:
                await f.write(content)

            return {
                "success": True,
                "data": {
                    "path": resolved_path,
                    "size": len(content),
                    "lines": content.count('\n') + 1
                }
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"写入错误: {str(e)}"
            }

    # ==================== Edit 实现 ====================

    async def _edit(self, params: Dict, context: Dict) -> Dict:
        """
        编辑实现

        精确字符串替换，要求old_string唯一匹配
        """
        file_path = params["file_path"]
        old_string = params["old_string"]
        new_string = params["new_string"]

        # 路径遍历防护
        is_valid, resolved_path, error = validate_path(file_path, self.workspace)
        if not is_valid:
            return {"success": False, "error": error}

        # 检查文件存在
        if not os.path.exists(resolved_path):
            return {
                "success": False,
                "error": f"文件不存在: {resolved_path}"
            }

        try:
            # 读取现有内容
            async with aiofiles.open(resolved_path, 'r', encoding='utf-8') as f:
                content = await f.read()

            # 检查匹配
            count = content.count(old_string)

            if count == 0:
                return {
                    "success": False,
                    "error": f"字符串在文件中未找到"
                }

            if count > 1:
                return {
                    "success": False,
                    "error": f"发现{count}个匹配，期望1个（匹配不唯一）"
                }

            # 执行替换
            new_content = content.replace(old_string, new_string)

            # 写回文件
            async with aiofiles.open(resolved_path, 'w', encoding='utf-8') as f:
                await f.write(new_content)

            return {
                "success": True,
                "data": {
                    "path": resolved_path,
                    "old_length": len(old_string),
                    "new_length": len(new_string)
                }
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"编辑错误: {str(e)}"
            }

    # ==================== Bash 实现 ====================

    async def _bash(self, params: Dict, context: Dict) -> Dict:
        """
        Bash命令执行

        支持:
        - 同步执行（默认）
        - 后台执行
        - 超时控制

        安全:
        - 使用create_subprocess_exec参数化执行，防止命令注入
        - 危险命令黑名单
        """
        command = params["command"]
        timeout = params.get("timeout", 60000)  # 默认60秒
        background = params.get("background", False)

        # 安全检查：危险命令黑名单
        for dangerous in self._dangerous_commands:
            if dangerous in command:
                return {
                    "success": False,
                    "error": f"危险命令被阻止: {dangerous}"
                }

        try:
            # 使用shlex.split进行安全的参数解析
            # 这正确处理引号包裹的参数，防止注入
            try:
                cmd_args = shlex.split(command)
            except ValueError as e:
                return {
                    "success": False,
                    "error": f"命令解析错误: {str(e)}"
                }

            if not cmd_args:
                return {
                    "success": False,
                    "error": "空命令"
                }

            if background:
                # 后台执行 - 使用exec避免shell注入
                proc = await asyncio.create_subprocess_exec(
                    *cmd_args,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd=self.workspace
                )
                return {
                    "success": True,
                    "data": {
                        "pid": proc.pid,
                        "background": True,
                        "command": command
                    }
                }
            else:
                # 同步执行 - 使用exec避免shell注入
                proc = await asyncio.create_subprocess_exec(
                    *cmd_args,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd=self.workspace
                )

                try:
                    stdout, stderr = await asyncio.wait_for(
                        proc.communicate(),
                        timeout=timeout / 1000
                    )
                except asyncio.TimeoutError:
                    proc.kill()
                    return {
                        "success": False,
                        "error": f"命令超时 ({timeout}ms)",
                        "data": {"command": command}
                    }

                return {
                    "success": proc.returncode == 0,
                    "data": {
                        "stdout": stdout.decode('utf-8', errors='replace'),
                        "stderr": stderr.decode('utf-8', errors='replace'),
                        "returncode": proc.returncode,
                        "command": command
                    }
                }

        except FileNotFoundError:
            return {
                "success": False,
                "error": f"命令未找到: {cmd_args[0] if 'cmd_args' in dir() else 'unknown'}"
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"Bash错误: {str(e)}"
            }

    # ==================== Glob 实现 ====================

    async def _glob(self, params: Dict, context: Dict) -> Dict:
        """
        Glob文件搜索

        支持:
        - 标准glob模式
        - ** 递归匹配
        """
        pattern = params["pattern"]
        path = params.get("path", self.workspace)

        # 路径遍历防护
        is_valid, resolved_path, error = validate_path(path, self.workspace)
        if not is_valid:
            return {"success": False, "error": error}

        try:
            # 执行glob搜索
            full_pattern = os.path.join(resolved_path, pattern)
            matches = glob_module.glob(full_pattern, recursive=True)

            # 转换为相对路径并验证每个匹配
            relative_matches = []
            for match in matches:
                # 验证匹配结果也在workspace内
                is_valid, _, _ = validate_path(match, self.workspace)
                if is_valid:
                    try:
                        rel_path = os.path.relpath(match, self.workspace)
                        relative_matches.append(rel_path)
                    except ValueError:
                        relative_matches.append(match)

            return {
                "success": True,
                "data": {
                    "files": relative_matches,
                    "count": len(relative_matches),
                    "pattern": pattern,
                    "path": resolved_path
                }
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"Glob错误: {str(e)}"
            }

    # ==================== Grep 实现 ====================

    async def _grep(self, params: Dict, context: Dict) -> Dict:
        """
        Grep内容搜索

        支持:
        - 正则表达式
        - 文件过滤
        - 递归搜索
        """
        pattern = params["pattern"]
        path = params.get("path", self.workspace)
        glob_pattern = params.get("glob", "*")

        # 路径遍历防护
        is_valid, resolved_path, error = validate_path(path, self.workspace)
        if not is_valid:
            return {"success": False, "error": error}

        try:
            # 编译正则
            regex = re.compile(pattern, re.MULTILINE | re.IGNORECASE)

            results = []

            # 遍历目录
            for root, dirs, files in os.walk(resolved_path):
                for file in files:
                    # 文件过滤
                    if not fnmatch.fnmatch(file, glob_pattern):
                        continue

                    file_path = os.path.join(root, file)

                    # 验证文件路径
                    is_valid_file, _, _ = validate_path(file_path, self.workspace)
                    if not is_valid_file:
                        continue

                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            for line_num, line in enumerate(f, 1):
                                if regex.search(line):
                                    # 转换为相对路径
                                    try:
                                        rel_path = os.path.relpath(file_path, self.workspace)
                                    except ValueError:
                                        rel_path = file_path

                                    results.append({
                                        "file": rel_path,
                                        "line": line_num,
                                        "content": line.rstrip('\n\r')
                                    })
                    except Exception:
                        # 跳过无法读取的文件
                        pass

            return {
                "success": True,
                "data": {
                    "matches": results,
                    "count": len(results),
                    "pattern": pattern,
                    "glob": glob_pattern
                }
            }
        except re.error as e:
            return {
                "success": False,
                "error": f"无效正则表达式: {str(e)}"
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"Grep错误: {str(e)}"
            }