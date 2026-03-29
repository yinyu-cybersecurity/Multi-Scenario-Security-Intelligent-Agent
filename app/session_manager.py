# app/session_manager.py
"""
会话管理器应用层接口

这是一个薄包装器，将 remote_executor/session_manager.py 暴露给应用层使用。

解决：
- 会话检测不统一问题
- 提供统一的会话访问接口

使用:
    from app.session_manager import get_session_manager, ShellType, ShellSession
"""

# 从remote_executor导入所有内容
from remote_executor.session_manager import (
    ShellSessionManager,
    ShellSession,
    ShellType,
    SessionStatus,
    MSFRPCClient,
    get_session_manager,
    get_msf_rpc_client,
)

# 重新导出，方便app层使用
__all__ = [
    # 核心类
    'ShellSessionManager',
    'ShellSession',
    'ShellType',
    'SessionStatus',
    'MSFRPCClient',
    # 单例获取函数
    'get_session_manager',
    'get_msf_rpc_client',
]


# ==================== 便捷函数 ====================

def has_active_session() -> bool:
    """检查是否有活跃会话"""
    manager = get_session_manager()
    return len(manager.get_active_sessions()) > 0


def get_best_session_for_os(os_type: str = "linux", require_admin: bool = False) -> ShellSession:
    """获取指定操作系统的最佳会话"""
    manager = get_session_manager()
    return manager.get_best_session(os_type=os_type, require_admin=require_admin)


def execute_in_session(session_id: str, command: str, timeout: float = 30) -> dict:
    """在指定会话中执行命令"""
    manager = get_session_manager()
    return manager.execute_command(session_id, command, timeout)


def get_session_summary() -> str:
    """获取会话摘要，供AI决策使用"""
    manager = get_session_manager()
    return manager.get_session_info_for_ai()


def create_ssh_session(host: str, username: str, password: str = "",
                       private_key: str = "", port: int = 22) -> ShellSession:
    """创建SSH会话的便捷函数"""
    manager = get_session_manager()
    return manager.create_ssh_session(host, username, password, private_key, port)


def create_webshell_session(url: str, password: str = "",
                            shell_type: str = "custom", os_type: str = "linux") -> ShellSession:
    """创建WebShell会话的便捷函数"""
    manager = get_session_manager()
    return manager.create_webshell_session(url, password, shell_type, os_type)