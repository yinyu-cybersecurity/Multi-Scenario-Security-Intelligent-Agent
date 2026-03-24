# remote_executor/__init__.py
"""
远程执行器模块

提供远程命令执行、文件传输、隧道管理能力

支持会话类型:
- webshell: HTTP WebShell
- reverse_shell: 反弹Shell
- ssh: SSH连接
- impacket: psexec/wmiexec
- meterpreter: MSF会话
"""

from .session_manager import ShellSessionManager, ShellSession, ShellType
from .executors import (
    WebShellExecutor,
    SSHExecutor,
    ImpacketExecutor,
    ProxyExecutor
)
from .file_transfer import FileTransfer
from .tunnel_manager import (
    TunnelManager,
    TunnelConfig,
    TunnelStatus,
    start_local_frps,
    check_frps_status
)
from .http_server import start_http_server, check_tools_directory, ensure_tools_directories

__all__ = [
    'ShellSessionManager',
    'ShellSession',
    'ShellType',
    'WebShellExecutor',
    'SSHExecutor',
    'ImpacketExecutor',
    'ProxyExecutor',
    'FileTransfer',
    'TunnelManager',
    'TunnelConfig',
    'TunnelStatus',
    'start_local_frps',
    'check_frps_status',
    'start_http_server',
    'check_tools_directory',
    'ensure_tools_directories'
]