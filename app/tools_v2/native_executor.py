"""
原生工具执行器 - Claude Code最佳实践

核心设计:
1. 工具路径由tool_paths.py配置，支持thirdparty目录
2. 工具通过subprocess直接调用
3. 权限检查与执行分离
4. 错误直接返回AI，让其自我纠错

参考: Claude Code工具系统深度技术文档
"""

import asyncio
import subprocess
import shutil
import os
import logging
from typing import Dict, Any, List, Optional
from pathlib import Path
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# 导入工具路径配置
from app.tools_v2.tool_paths import (
    get_tool_path,
    is_python_tool,
    is_java_tool,
    is_directory_tool,
    THIRDPARTY_DIR,
)


# ============================================
# 工具执行结果
# ============================================

@dataclass
class ToolResult:
    """工具执行结果"""
    success: bool
    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0
    error: Optional[str] = None
    tool: str = ""
    hint: Optional[str] = None


# ============================================
# 工具权限检查
# ============================================

class PermissionResult:
    """权限检查结果"""
    ALLOW = "allow"
    DENY = "deny"
    ASK = "ask"


async def check_tool_permissions(
    tool_name: str,
    args: List[str],
    context: Dict[str, Any]
) -> str:
    """
    检查工具执行权限

    Claude Code模式:
    - 返回 allow/deny/ask
    - 独立于执行逻辑

    Args:
        tool_name: 工具名称
        args: 参数列表
        context: 执行上下文

    Returns:
        PermissionResult.ALLOW/DENY/ASK
    """
    # 危险命令检查
    dangerous_patterns = [
        "rm -rf",
        "mkfs",
        "dd if=",
        "> /dev/sd",
        "chmod 777",
        "curl | bash",
        "wget | bash",
    ]

    cmd_str = " ".join(args)
    for pattern in dangerous_patterns:
        if pattern in cmd_str:
            logger.warning(f"Dangerous pattern detected: {pattern}")
            return PermissionResult.ASK

    # 默认允许（Claude Code模式）
    return PermissionResult.ALLOW


# ============================================
# 工具执行函数
# ============================================

async def execute_tool(
    tool_name: str,
    args: List[str],
    timeout: int = 120000,
    env: Optional[Dict[str, str]] = None,
    cwd: Optional[str] = None,
    context: Optional[Dict[str, Any]] = None,
) -> ToolResult:
    """
    执行工具 - Claude Code最佳实践

    核心模式:
    1. 工具通过subprocess直接调用
    2. 系统PATH自动解析工具位置
    3. 无硬编码路径映射

    Args:
        tool_name: 工具名称（如"sqlmap", "nuclei"）
        args: 参数列表
        timeout: 超时时间（毫秒）
        env: 额外环境变量
        cwd: 工作目录
        context: 执行上下文

    Returns:
        ToolResult
    """
    # 1. 权限检查
    permission = await check_tool_permissions(
        tool_name,
        args,
        context or {}
    )

    if permission == PermissionResult.DENY:
        return ToolResult(
            success=False,
            error="Permission denied",
            tool=tool_name,
            hint="This tool execution is not allowed"
        )

    # 2. 检查工具是否可用
    tool_path = get_tool_path(tool_name)

    if not tool_path:
        # 尝试从系统PATH查找
        tool_path = shutil.which(tool_name)

        if not tool_path:
            return ToolResult(
                success=False,
                error=f"Tool '{tool_name}' not found",
                tool=tool_name,
                hint=get_install_hint(tool_name)
            )

    # 3. 构建命令
    cmd = _build_command(tool_name, str(tool_path), args)

    # 4. 准备环境变量
    exec_env = os.environ.copy()
    if env:
        exec_env.update(env)

    logger.info(f"Executing: {tool_name} {' '.join(args[:5])}...")

    try:
        # 5. 异步subprocess调用
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=exec_env,
            cwd=cwd,
        )

        # 6. 等待执行完成（带超时）
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(),
            timeout=timeout / 1000,
        )

        stdout_str = stdout.decode("utf-8", errors="replace")
        stderr_str = stderr.decode("utf-8", errors="replace")

        # 7. 返回结果
        result = ToolResult(
            success=proc.returncode == 0,
            stdout=stdout_str,
            stderr=stderr_str,
            exit_code=proc.returncode,
            tool=tool_name,
        )

        if proc.returncode == 0:
            logger.info(f"Tool {tool_name} executed successfully")
        else:
            logger.warning(
                f"Tool {tool_name} failed with exit code {proc.returncode}"
            )

        return result

    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        logger.error(f"Tool {tool_name} timeout after {timeout}ms")

        return ToolResult(
            success=False,
            error=f"Timeout after {timeout}ms",
            tool=tool_name,
            hint="Consider increasing timeout or optimizing parameters"
        )

    except FileNotFoundError as e:
        logger.error(f"Tool {tool_name} not found: {e}")

        return ToolResult(
            success=False,
            error=f"Tool executable not found: {e}",
            tool=tool_name,
            hint=get_install_hint(tool_name)
        )

    except PermissionError as e:
        logger.error(f"Permission denied for {tool_name}: {e}")

        return ToolResult(
            success=False,
            error=f"Permission denied: {e}",
            tool=tool_name,
            hint="Check file permissions or run with appropriate privileges"
        )

    except Exception as e:
        logger.error(f"Unexpected error executing {tool_name}: {e}")

        return ToolResult(
            success=False,
            error=str(e),
            tool=tool_name
        )


# ============================================
# 辅助函数
# ============================================

def _build_command(tool_name: str, tool_path: str, args: List[str]) -> List[str]:
    """
    根据工具类型构建执行命令

    Args:
        tool_name: 工具名称
        tool_path: 工具路径
        args: 参数列表

    Returns:
        完整命令列表
    """
    # Python脚本工具
    if is_python_tool(tool_name):
        return ["python", tool_path] + args

    # Java jar工具
    if is_java_tool(tool_name):
        return ["java", "-jar", tool_path] + args

    # 目录型工具（需要进一步处理）
    if is_directory_tool(tool_name):
        # 返回目录路径，让具体工具handler处理
        return [tool_path] + args

    # 可执行文件直接执行
    return [tool_path] + args


def get_install_hint(tool_name: str) -> str:
    """
    获取工具安装提示

    Args:
        tool_name: 工具名称

    Returns:
        安装提示
    """
    hints = {
        "sqlmap": "pip install sqlmap",
        "nuclei": "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        "httpx": "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
        "ffuf": "go install -v github.com/ffuf/ffuf/v2@latest",
        "subfinder": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        "gobuster": "go install github.com/OJ/gobuster/v3@latest",
        "dalfox": "go install github.com/hahwul/dalfox/v2@latest",
        "hashcat": "apt install hashcat (Linux) or download from hashcat.net",
        "john": "apt install john (Linux)",
        "gdb": "apt install gdb (Linux)",
    }

    return hints.get(
        tool_name,
        f"Install {tool_name} using your system package manager"
    )


# ============================================
# 批量执行
# ============================================

async def execute_batch(
    commands: List[Dict[str, Any]],
    max_concurrent: int = 3,
) -> List[ToolResult]:
    """
    批量执行多个工具命令

    Args:
        commands: 命令列表 [{"tool": str, "args": list, "timeout": int}, ...]
        max_concurrent: 最大并发数

    Returns:
        结果列表
    """
    semaphore = asyncio.Semaphore(max_concurrent)

    async def execute_with_semaphore(cmd: Dict[str, Any]) -> ToolResult:
        async with semaphore:
            return await execute_tool(
                tool_name=cmd.get("tool"),
                args=cmd.get("args", []),
                timeout=cmd.get("timeout", 120000),
                env=cmd.get("env"),
                cwd=cmd.get("cwd"),
                context=cmd.get("context"),
            )

    tasks = [execute_with_semaphore(cmd) for cmd in commands]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    # 处理异常结果
    processed_results = []
    for i, result in enumerate(results):
        if isinstance(result, Exception):
            processed_results.append(
                ToolResult(
                    success=False,
                    error=str(result),
                    tool=commands[i].get("tool"),
                )
            )
        else:
            processed_results.append(result)

    return processed_results


# ============================================
# 兼容层
# ============================================

class NativeExecutor:
    """
    兼容层：为旧代码提供API

    内部直接调用execute_tool函数
    """

    def __init__(self):
        pass

    async def check_available(self, tool_name: str) -> Dict[str, Any]:
        """检查工具是否可用"""
        tool_path = shutil.which(tool_name)

        if tool_path:
            return {
                "name": tool_name,
                "is_available": True,
                "path": tool_path,
            }
        else:
            return {
                "name": tool_name,
                "is_available": False,
                "error": f"Tool not found in PATH",
            }

    async def execute(
        self,
        tool_name: str,
        args: List[str],
        timeout: int = 120000,
        env: Optional[Dict[str, str]] = None,
        cwd: Optional[str] = None,
    ) -> Dict[str, Any]:
        """执行工具"""
        result = await execute_tool(
            tool_name=tool_name,
            args=args,
            timeout=timeout,
            env=env,
            cwd=cwd,
        )

        return {
            "success": result.success,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "exit_code": result.exit_code,
            "error": result.error,
            "tool": result.tool,
            "hint": result.hint,
        }

    async def execute_batch(
        self,
        commands: List[Dict[str, Any]],
        max_concurrent: int = 3,
    ) -> List[Dict[str, Any]]:
        """批量执行"""
        results = await execute_batch(commands, max_concurrent)

        return [
            {
                "success": r.success,
                "stdout": r.stdout,
                "stderr": r.stderr,
                "exit_code": r.exit_code,
                "error": r.error,
                "tool": r.tool,
            }
            for r in results
        ]

    def clear_cache(self):
        """兼容方法"""
        pass


# 全局实例
_executor: Optional[NativeExecutor] = None


def get_native_executor() -> NativeExecutor:
    """获取全局执行器实例"""
    global _executor
    if _executor is None:
        _executor = NativeExecutor()
    return _executor


# 快捷函数
async def check_tool_available(tool_name: str) -> Dict[str, Any]:
    """快捷函数：检查工具是否可用"""
    executor = get_native_executor()
    return await executor.check_available(tool_name)


async def run_tool(
    tool_name: str,
    args: List[str],
    timeout: int = 120000,
    **kwargs
) -> Dict[str, Any]:
    """快捷函数：执行工具"""
    return await execute_tool(tool_name, args, timeout, **kwargs)


__all__ = [
    "execute_tool",
    "execute_batch",
    "check_tool_permissions",
    "ToolResult",
    "PermissionResult",
    "NativeExecutor",
    "get_native_executor",
    "check_tool_available",
    "run_tool",
]