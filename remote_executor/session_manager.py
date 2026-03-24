# remote_executor/session_manager.py
"""
Shell会话管理器

管理所有远程会话，支持多种会话类型:
- webshell: HTTP WebShell
- reverse_shell: 反弹Shell
- ssh: SSH连接
- impacket: psexec/wmiexec
- meterpreter: MSF会话

设计理念:
- 统一的会话接口
- 支持会话持久化
- 自动重连机制
"""
import os
import json
import time
import uuid
import socket
import subprocess
import requests
from enum import Enum
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, field, asdict
from threading import Lock


class ShellType(Enum):
    """Shell会话类型"""
    WEBSHELL = "webshell"
    REVERSE_SHELL = "reverse_shell"
    SSH = "ssh"
    IMPACKET = "impacket"
    METERPRETER = "meterpreter"
    CS_BEACON = "cs_beacon"


@dataclass
class ShellSession:
    """
    Shell会话定义

    Attributes:
        id: 会话唯一标识
        session_type: 会话类型
        target: 目标主机
        os_type: 操作系统类型 (windows/linux)
        created_at: 创建时间
        last_active: 最后活跃时间
        is_admin: 是否有管理员权限
        is_system: 是否有SYSTEM/ROOT权限
        internal_ips: 发现的内网IP
        metadata: 额外元数据
    """
    id: str
    session_type: ShellType
    target: str
    os_type: str = "linux"
    created_at: float = field(default_factory=time.time)
    last_active: float = field(default_factory=time.time)
    is_admin: bool = False
    is_system: bool = False
    internal_ips: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    # 连接信息 (根据类型不同)
    url: str = ""  # webshell URL
    password: str = ""  # webshell密码
    username: str = ""  # SSH/Windows用户名
    host: str = ""  # 目标主机
    port: int = 22  # 端口
    private_key: str = ""  # SSH私钥

    def to_dict(self) -> Dict:
        """转换为字典"""
        data = asdict(self)
        data['session_type'] = self.session_type.value
        return data

    @classmethod
    def from_dict(cls, data: Dict) -> 'ShellSession':
        """从字典创建"""
        data['session_type'] = ShellType(data['session_type'])
        return cls(**data)


class ShellSessionManager:
    """
    Shell会话管理器

    功能:
    - 创建和管理多种类型的会话
    - 会话持久化
    - 自动检测会话状态
    """

    def __init__(self):
        self.sessions: Dict[str, ShellSession] = {}
        self.lock = Lock()
        self.session_file = "data/sessions.json"
        self._load_sessions()

    def _load_sessions(self):
        """从文件加载会话"""
        if os.path.exists(self.session_file):
            try:
                with open(self.session_file, 'r') as f:
                    data = json.load(f)
                    for sid, sdata in data.items():
                        self.sessions[sid] = ShellSession.from_dict(sdata)
            except Exception as e:
                print(f"[SessionManager] 加载会话失败: {e}")

    def _save_sessions(self):
        """保存会话到文件"""
        os.makedirs(os.path.dirname(self.session_file), exist_ok=True)
        try:
            with open(self.session_file, 'w') as f:
                json.dump({sid: s.to_dict() for sid, s in self.sessions.items()}, f)
        except Exception as e:
            print(f"[SessionManager] 保存会话失败: {e}")

    def create_webshell_session(
        self,
        url: str,
        password: str = "",
        shell_type: str = "custom",
        os_type: str = "linux"
    ) -> ShellSession:
        """
        创建WebShell会话

        Args:
            url: WebShell URL
            password: 密码 (如冰蝎、哥斯拉需要)
            shell_type: 类型 (behinder, godzilla, custom)
            os_type: 操作系统类型

        Returns:
            ShellSession
        """
        session_id = str(uuid.uuid4())[:8]

        # 探测目标系统
        detected_os = self._detect_os_from_webshell(url, password) or os_type

        session = ShellSession(
            id=session_id,
            session_type=ShellType.WEBSHELL,
            target=url,
            os_type=detected_os,
            url=url,
            password=password,
            metadata={"shell_type": shell_type}
        )

        with self.lock:
            self.sessions[session_id] = session
            self._save_sessions()

        print(f"[SessionManager] 创建WebShell会话: {session_id} -> {url}")
        return session

    def create_ssh_session(
        self,
        host: str,
        username: str,
        password: str = "",
        private_key: str = "",
        port: int = 22
    ) -> Optional[ShellSession]:
        """
        创建SSH会话

        Args:
            host: 目标主机
            username: 用户名
            password: 密码
            private_key: 私钥路径或内容
            port: SSH端口

        Returns:
            ShellSession 或 None
        """
        # 测试连接
        if not self._test_ssh_connection(host, username, password, private_key, port):
            print(f"[SessionManager] SSH连接失败: {username}@{host}:{port}")
            return None

        session_id = str(uuid.uuid4())[:8]

        # 检测权限
        is_root = False
        internal_ips = []
        if password or private_key:
            # 执行命令检测
            result = self._execute_ssh_command(
                host, username, password, private_key, port, "id; hostname -I"
            )
            if result:
                is_root = "uid=0" in result or "root" in result
                # 提取内网IP
                import re
                ips = re.findall(r'\d+\.\d+\.\d+\.\d+', result)
                internal_ips = [ip for ip in ips if not ip.startswith('127.')]

        session = ShellSession(
            id=session_id,
            session_type=ShellType.SSH,
            target=host,
            os_type="linux",
            host=host,
            port=port,
            username=username,
            password=password,
            private_key=private_key,
            is_admin=is_root,
            is_system=is_root,
            internal_ips=internal_ips
        )

        with self.lock:
            self.sessions[session_id] = session
            self._save_sessions()

        print(f"[SessionManager] 创建SSH会话: {session_id} -> {username}@{host}:{port}")
        return session

    def create_impacket_session(
        self,
        host: str,
        username: str,
        password: str = "",
        hash_: str = "",
        domain: str = "",
        method: str = "psexec"
    ) -> Optional[ShellSession]:
        """
        创建Impacket会话 (psexec/wmiexec)

        Args:
            host: 目标主机
            username: 用户名
            password: 密码
            hash_: NTLM哈希
            domain: 域名
            method: 方法 (psexec, wmiexec, smbexec)

        Returns:
            ShellSession 或 None
        """
        session_id = str(uuid.uuid4())[:8]

        # 检测是否是管理员
        is_admin = self._check_impacket_admin(host, username, password, hash_, domain)

        session = ShellSession(
            id=session_id,
            session_type=ShellType.IMPACKET,
            target=host,
            os_type="windows",
            host=host,
            username=username,
            password=password,
            metadata={
                "hash": hash_,
                "domain": domain,
                "method": method
            },
            is_admin=is_admin
        )

        with self.lock:
            self.sessions[session_id] = session
            self._save_sessions()

        print(f"[SessionManager] 创建Impacket会话: {session_id} -> {username}@{host} ({method})")
        return session

    def get_session(self, session_id: str) -> Optional[ShellSession]:
        """获取会话"""
        return self.sessions.get(session_id)

    def list_sessions(self) -> List[ShellSession]:
        """列出所有会话"""
        return list(self.sessions.values())

    def remove_session(self, session_id: str):
        """移除会话"""
        with self.lock:
            if session_id in self.sessions:
                del self.sessions[session_id]
                self._save_sessions()

    def update_session(self, session_id: str, **kwargs):
        """更新会话属性"""
        with self.lock:
            if session_id in self.sessions:
                session = self.sessions[session_id]
                for key, value in kwargs.items():
                    if hasattr(session, key):
                        setattr(session, key, value)
                session.last_active = time.time()
                self._save_sessions()

    # ==================== 辅助方法 ====================

    def _detect_os_from_webshell(self, url: str, password: str) -> Optional[str]:
        """通过WebShell检测操作系统"""
        try:
            # 尝试执行简单的探测命令
            test_commands = [
                ("whoami", "windows"),
                ("id", "linux"),
                ("ver", "windows"),
                ("uname", "linux")
            ]

            for cmd, os_type in test_commands:
                # 这里需要实际的webshell执行器
                pass

            return None
        except Exception:
            return None

    def _test_ssh_connection(
        self, host: str, username: str, password: str, private_key: str, port: int
    ) -> bool:
        """测试SSH连接"""
        try:
            import paramiko
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            if private_key:
                if os.path.exists(private_key):
                    key = paramiko.RSAKey.from_private_key_file(private_key)
                else:
                    import io
                    key = paramiko.RSAKey.from_private_key(io.StringIO(private_key))
                client.connect(host, port, username, pkey=key, timeout=10)
            else:
                client.connect(host, port, username, password, timeout=10)

            client.close()
            return True
        except Exception as e:
            print(f"[SessionManager] SSH测试失败: {e}")
            return False

    def _execute_ssh_command(
        self, host: str, username: str, password: str, private_key: str, port: int, command: str
    ) -> Optional[str]:
        """通过SSH执行命令"""
        try:
            import paramiko
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            if private_key:
                if os.path.exists(private_key):
                    key = paramiko.RSAKey.from_private_key_file(private_key)
                else:
                    import io
                    key = paramiko.RSAKey.from_private_key(io.StringIO(private_key))
                client.connect(host, port, username, pkey=key, timeout=10)
            else:
                client.connect(host, port, username, password, timeout=10)

            stdin, stdout, stderr = client.exec_command(command)
            result = stdout.read().decode('utf-8', errors='ignore')
            client.close()
            return result
        except Exception:
            return None

    def _check_impacket_admin(
        self, host: str, username: str, password: str, hash_: str, domain: str
    ) -> bool:
        """检查Impacket会话是否有管理员权限"""
        # 通过crackmapexec检查
        try:
            cmd = ["crackmapexec", "smb", host, "-u", username]
            if password:
                cmd.extend(["-p", password])
            if hash_:
                cmd.extend(["-H", hash_])
            if domain:
                cmd.extend(["-d", domain])

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            return "Pwn3d!" in result.stdout or "(admin)" in result.stdout.lower()
        except Exception:
            return False


# 全局会话管理器实例
_session_manager = None

def get_session_manager() -> ShellSessionManager:
    """获取全局会话管理器"""
    global _session_manager
    if _session_manager is None:
        _session_manager = ShellSessionManager()
    return _session_manager