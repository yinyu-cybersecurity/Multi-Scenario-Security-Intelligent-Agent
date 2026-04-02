"""
原生工具执行器 - 直接调用系统工具

设计原则:
1. 直接执行系统命令，无Docker开销
2. 通过虚拟环境隔离Python工具
3. 安全检查仅针对极危险操作
4. 错误直接返回给AI，让其自我纠错
"""

import asyncio
import subprocess
import shutil
import os
import logging
from typing import Dict, Any, Optional, List
from pathlib import Path
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class ToolAvailability:
    """工具可用性检查结果"""
    name: str
    is_available: bool
    version: Optional[str] = None
    path: Optional[str] = None
    error: Optional[str] = None


class NativeExecutor:
    """
    原生工具执行器

    直接调用系统工具，无需Docker容器
    """

    # Python工具的虚拟环境路径
    VENV_PATH = Path.home() / ".ctf_agent" / "venv"

    # 工具路径映射
    TOOL_PATHS: Dict[str, Any] = {}

    def __init__(self):
        self._availability_cache: Dict[str, ToolAvailability] = {}
        self._setup_tool_paths()

    def _setup_tool_paths(self):
        """设置工具路径"""
        venv = self.VENV_PATH
        self.TOOL_PATHS = {
            # Python工具
            "sqlmap": venv / "bin" / "sqlmap",
            "nuclei": venv / "bin" / "nuclei",
            "ffuf": venv / "bin" / "ffuf",
            "httpx": venv / "bin" / "httpx",

            # 系统工具
            "nmap": "nmap",
            "gdb": "gdb",
            "hashcat": "hashcat",
            "john": "john",
        }

    async def check_available(self, tool_name: str) -> ToolAvailability:
        """检查工具是否可用 - 真实检查"""
        if tool_name in self._availability_cache:
            return self._availability_cache[tool_name]

        # 真实的文件系统检查
        if tool_name in self.TOOL_PATHS:
            tool_path = self.TOOL_PATHS[tool_name]
            if isinstance(tool_path, Path):
                if tool_path.exists():
                    # 尝试获取版本信息
                    version = await self._get_tool_version(str(tool_path))
                    result = ToolAvailability(
                        name=tool_name,
                        is_available=True,
                        path=str(tool_path),
                        version=version,
                    )
                else:
                    result = ToolAvailability(
                        name=tool_name,
                        is_available=False,
                        error=f"Tool not found at {tool_path}",
                    )
            else:
                # 真实的PATH检查
                full_path = shutil.which(tool_path)
                if full_path:
                    version = await self._get_tool_version(full_path)
                    result = ToolAvailability(
                        name=tool_name,
                        is_available=True,
                        path=full_path,
                        version=version,
                    )
                else:
                    result = ToolAvailability(
                        name=tool_name,
                        is_available=False,
                        error=f"Tool not found in PATH",
                    )
        else:
            # 真实的系统PATH检查
            full_path = shutil.which(tool_name)
            if full_path:
                version = await self._get_tool_version(full_path)
                result = ToolAvailability(
                    name=tool_name,
                    is_available=True,
                    path=full_path,
                    version=version,
                )
            else:
                result = ToolAvailability(
                    name=tool_name,
                    is_available=False,
                    error="Tool not found",
                )

        self._availability_cache[tool_name] = result
        return result

    async def _get_tool_version(self, tool_path: str) -> Optional[str]:
        """获取工具版本信息"""
        try:
            # 尝试常见的版本参数
            for version_flag in ["--version", "-V", "version", "-version"]:
                proc = await asyncio.create_subprocess_exec(
                    tool_path,
                    version_flag,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=5.0,
                )
                if proc.returncode == 0:
                    output = stdout.decode("utf-8", errors="replace").strip()
                    if output:
                        # 提取版本号（取第一行）
                        return output.split("\n")[0][:100]
        except Exception:
            pass
        return None

    async def execute(
        self,
        tool_name: str,
        args: List[str],
        timeout: int = 120000,
        env: Optional[Dict[str, str]] = None,
        cwd: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        原生执行工具 - 真实的subprocess调用

        Args:
            tool_name: 工具名称
            args: 参数列表
            timeout: 超时时间（毫秒）
            env: 额外环境变量
            cwd: 工作目录
        """
        # 真实的可用性检查
        availability = await self.check_available(tool_name)
        if not availability.is_available:
            return {
                "success": False,
                "error": f"Tool '{tool_name}' is not available: {availability.error}",
                "hint": self._get_install_hint(tool_name),
            }

        tool_path = availability.path

        # 构建命令
        cmd = [tool_path] + args

        # 真实的环境变量
        exec_env = os.environ.copy()
        if env:
            exec_env.update(env)

        logger.info(f"Executing: {tool_name} with args: {args[:5]}...")

        try:
            # 真实的异步subprocess调用
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=exec_env,
                cwd=cwd,
            )

            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=timeout / 1000,
            )

            stdout_str = stdout.decode("utf-8", errors="replace")
            stderr_str = stderr.decode("utf-8", errors="replace")

            result = {
                "success": proc.returncode == 0,
                "stdout": stdout_str,
                "stderr": stderr_str,
                "exit_code": proc.returncode,
                "tool": tool_name,
                "path": tool_path,
            }

            # 添加版本信息（如果有的话）
            if availability.version:
                result["version"] = availability.version

            # 记录执行结果
            if proc.returncode == 0:
                logger.info(f"Tool {tool_name} executed successfully")
            else:
                logger.warning(f"Tool {tool_name} failed with exit code {proc.returncode}")

            return result

        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            logger.error(f"Tool {tool_name} timeout after {timeout}ms")
            return {
                "success": False,
                "error": f"Timeout after {timeout}ms",
                "tool": tool_name,
                "hint": "Consider increasing timeout or optimizing command parameters",
            }
        except FileNotFoundError as e:
            logger.error(f"Tool {tool_name} not found: {e}")
            return {
                "success": False,
                "error": f"Tool executable not found: {e}",
                "tool": tool_name,
            }
        except PermissionError as e:
            logger.error(f"Permission denied for {tool_name}: {e}")
            return {
                "success": False,
                "error": f"Permission denied: {e}",
                "tool": tool_name,
                "hint": "Check file permissions or run with appropriate privileges",
            }
        except Exception as e:
            logger.error(f"Unexpected error executing {tool_name}: {e}")
            return {
                "success": False,
                "error": str(e),
                "tool": tool_name,
            }

    def _get_install_hint(self, tool_name: str) -> str:
        """获取工具安装提示"""
        hints = {
            "sqlmap": "pip install sqlmap",
            "nuclei": "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
            "ffuf": "go install -v github.com/ffuf/ffuf/v2@latest",
            "httpx": "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
            "nmap": "apt install nmap (Linux) or download from nmap.org (Windows)",
            "gdb": "apt install gdb (Linux)",
            "hashcat": "apt install hashcat (Linux) or download from hashcat.net",
            "john": "apt install john (Linux)",
        }
        return hints.get(tool_name, f"Install {tool_name} using your system package manager")

    async def execute_batch(
        self,
        commands: List[Dict[str, Any]],
        max_concurrent: int = 3,
    ) -> List[Dict[str, Any]]:
        """
        批量执行多个工具命令

        Args:
            commands: 命令列表 [{"tool": str, "args": list, "timeout": int}, ...]
            max_concurrent: 最大并发数

        Returns:
            结果列表
        """
        semaphore = asyncio.Semaphore(max_concurrent)

        async def execute_with_semaphore(cmd: Dict[str, Any]) -> Dict[str, Any]:
            async with semaphore:
                return await self.execute(
                    tool_name=cmd.get("tool"),
                    args=cmd.get("args", []),
                    timeout=cmd.get("timeout", 120000),
                    env=cmd.get("env"),
                    cwd=cmd.get("cwd"),
                )

        tasks = [execute_with_semaphore(cmd) for cmd in commands]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # 处理异常结果
        processed_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                processed_results.append({
                    "success": False,
                    "error": str(result),
                    "tool": commands[i].get("tool"),
                })
            else:
                processed_results.append(result)

        return processed_results

    def clear_cache(self):
        """清除可用性缓存"""
        self._availability_cache.clear()

    def list_available_tools(self) -> List[str]:
        """列出所有已配置且可用的工具"""
        available = []
        for tool_name in self.TOOL_PATHS.keys():
            availability = self._availability_cache.get(tool_name)
            if availability and availability.is_available:
                available.append(tool_name)
        return available


# 全局执行器实例
_executor: Optional[NativeExecutor] = None


def get_native_executor() -> NativeExecutor:
    """获取全局执行器实例"""
    global _executor
    if _executor is None:
        _executor = NativeExecutor()
    return _executor


async def check_tool_available(tool_name: str) -> ToolAvailability:
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
    executor = get_native_executor()
    return await executor.execute(tool_name, args, timeout, **kwargs)


__all__ = [
    "NativeExecutor",
    "ToolAvailability",
    "get_native_executor",
    "check_tool_available",
    "run_tool",
]