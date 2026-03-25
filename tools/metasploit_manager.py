# tools/metasploit_manager.py
"""
Metasploit RPC 管理器

通过 MSFRPC (Metasploit RPC) 实现与会话的交互
支持：
- 会话管理
- Shell/Meterpreter 命令执行
- 后渗透模块运行
- 智能交互

启动方式：
    msfrpcd -P password123 -S -f

API文档：
    https://docs.metasploit.com/docs/using-metasploit/interfacing-with-msf/msfrpcd-api-reference.html
"""

import os
import json
import time
import subprocess
import requests
from typing import Dict, List, Optional, Any
from dataclasses import dataclass


@dataclass
class MSFSession:
    """MSF会话信息"""
    id: int
    type: str  # shell, meterpreter
    target: str
    platform: str
    via_exploit: str
    created_at: float = time.time()

    @classmethod
    def from_dict(cls, data: Dict) -> 'MSFSession':
        return cls(
            id=data.get("id", 0),
            type=data.get("type", "unknown"),
            target=data.get("session_host", data.get("target", "")),
            platform=data.get("platform", ""),
            via_exploit=data.get("via_exploit", "")
        )


class MetasploitManager:
    """
    Metasploit RPC 管理器

    使用方式:
        msf = MetasploitManager()
        msf.connect()

        # 列出会话
        sessions = msf.list_sessions()

        # 执行命令
        result = msf.execute_shell(session_id, "whoami")

        # 智能交互
        result = msf.smart_interact(session_id, "获取系统信息")
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 55553,
                 password: str = "msfpassword"):
        self.host = host
        self.port = port
        self.password = password
        self.token: Optional[str] = None
        self.base_url = f"http://{host}:{port}/api"
        self._msfrpcd_process = None

    # =========================================================================
    # 连接管理
    # =========================================================================

    def connect(self) -> bool:
        """连接到 msfrpcd 服务"""
        # 尝试直接连接
        if self._try_connect():
            return True

        # 连接失败，尝试启动 msfrpcd
        print("[MSF] msfrpcd 未运行，尝试启动...")
        if self._start_msfrpcd():
            time.sleep(3)  # 等待服务启动
            return self._try_connect()

        return False

    def _try_connect(self) -> bool:
        """尝试连接"""
        try:
            resp = requests.post(
                f"{self.base_url}/login",
                json={"username": "msf", "password": self.password},
                timeout=5
            )
            if resp.status_code == 200:
                data = resp.json()
                self.token = data.get("token")
                if self.token:
                    print(f"[MSF] 已连接到 msfrpcd")
                    return True
        except requests.exceptions.ConnectionError:
            pass
        except Exception as e:
            print(f"[MSF] 连接失败: {e}")
        return False

    def _start_msfrpcd(self) -> bool:
        """启动 msfrpcd 服务"""
        try:
            # 检查 msfrpcd 是否存在
            msfrpcd = self._find_msfrpcd()
            if not msfrpcd:
                print("[MSF] 未找到 msfrpcd")
                return False

            # 启动服务 (-S 禁用SSL, -f 后台运行)
            cmd = [msfrpcd, "-P", self.password, "-S"]
            self._msfrpcd_process = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            print(f"[MSF] msfrpcd 已启动 (PID: {self._msfrpcd_process.pid})")
            return True
        except Exception as e:
            print(f"[MSF] 启动 msfrpcd 失败: {e}")
            return False

    def _find_msfrpcd(self) -> Optional[str]:
        """查找 msfrpcd 路径"""
        import shutil

        # 直接查找
        path = shutil.which("msfrpcd")
        if path:
            return path

        # 常见路径
        common_paths = [
            "/usr/bin/msfrpcd",
            "/usr/local/bin/msfrpcd",
            "/opt/metasploit-framework/msfrpcd",
        ]
        for p in common_paths:
            if os.path.exists(p):
                return p

        return None

    def disconnect(self):
        """断开连接"""
        if self._msfrpcd_process:
            self._msfrpcd_process.terminate()
            self._msfrpcd_process = None
        self.token = None

    def _request(self, method: str, endpoint: str, data: Dict = None) -> Dict:
        """发送API请求"""
        if not self.token:
            return {"error": "未连接到 msfrpcd"}

        headers = {"Authorization": f"Bearer {self.token}"}
        url = f"{self.base_url}{endpoint}"

        try:
            if method == "GET":
                resp = requests.get(url, headers=headers, timeout=30)
            else:
                resp = requests.post(url, headers=headers, json=data or {}, timeout=30)

            if resp.status_code == 200:
                return resp.json()
            return {"error": f"HTTP {resp.status_code}", "detail": resp.text}

        except requests.exceptions.Timeout:
            return {"error": "请求超时"}
        except Exception as e:
            return {"error": str(e)}

    # =========================================================================
    # 会话管理
    # =========================================================================

    def list_sessions(self) -> List[MSFSession]:
        """获取所有会话列表"""
        result = self._request("GET", "/sessions")

        if "error" in result:
            print(f"[MSF] 获取会话列表失败: {result['error']}")
            return []

        sessions = []
        for sid, data in result.get("sessions", {}).items():
            try:
                session = MSFSession.from_dict({"id": int(sid), **data})
                sessions.append(session)
            except Exception:
                pass

        return sessions

    def get_session(self, session_id: int) -> Optional[MSFSession]:
        """获取单个会话详情"""
        sessions = self.list_sessions()
        for s in sessions:
            if s.id == session_id:
                return s
        return None

    def kill_session(self, session_id: int) -> bool:
        """终止会话"""
        result = self._request("POST", f"/sessions/{session_id}/kill")
        return "error" not in result

    # =========================================================================
    # 命令执行
    # =========================================================================

    def execute_shell(self, session_id: int, command: str,
                      timeout: float = 30) -> Dict:
        """
        在 Shell 会话中执行命令

        Args:
            session_id: 会话ID
            command: 要执行的命令
            timeout: 超时时间（秒）

        Returns:
            {"success": bool, "output": str, "error": str}
        """
        result = self._request("POST", f"/sessions/{session_id}/shell", {
            "command": command,
            "timeout": timeout
        })

        if "error" in result:
            return {"success": False, "output": "", "error": result["error"]}

        return {
            "success": True,
            "output": result.get("output", result.get("data", "")),
            "error": ""
        }

    def execute_meterpreter(self, session_id: int, command: str) -> Dict:
        """
        在 Meterpreter 会话中执行命令

        Args:
            session_id: 会话ID
            command: Meterpreter命令

        Returns:
            {"success": bool, "output": str, "error": str}
        """
        result = self._request("POST", f"/sessions/{session_id}/meterpreter", {
            "command": command
        })

        if "error" in result:
            return {"success": False, "output": "", "error": result["error"]}

        return {
            "success": True,
            "output": result.get("output", result.get("result", "")),
            "error": ""
        }

    def execute(self, session_id: int, command: str) -> Dict:
        """
        自动选择执行方式（Shell或Meterpreter）

        根据会话类型自动选择 execute_shell 或 execute_meterpreter
        """
        session = self.get_session(session_id)
        if not session:
            return {"success": False, "output": "", "error": "会话不存在"}

        if session.type == "meterpreter":
            return self.execute_meterpreter(session_id, command)
        else:
            return self.execute_shell(session_id, command)

    # =========================================================================
    # 后渗透模块
    # =========================================================================

    def run_post_module(self, session_id: int, module: str,
                        options: Dict = None) -> Dict:
        """
        运行后渗透模块

        常用模块:
        - post/multi/gather/env: 环境变量
        - post/windows/gather/enum_system: 系统信息枚举
        - post/windows/gather/credentials/credential_collector: 凭据收集
        - post/windows/escalate/getsystem: 提权尝试
        - post/linux/gather/enum_system: Linux系统信息

        Args:
            session_id: 会话ID
            module: 模块路径
            options: 模块选项

        Returns:
            {"success": bool, "output": str, "results": dict}
        """
        options = options or {}
        options["SESSION"] = session_id

        result = self._request("POST", f"/modules/post/{module.replace('/', '.')}", {
            "options": options
        })

        if "error" in result:
            return {"success": False, "output": "", "results": {}, "error": result["error"]}

        return {
            "success": True,
            "output": result.get("output", ""),
            "results": result.get("results", {})
        }

    # =========================================================================
    # 智能交互
    # =========================================================================

    def smart_interact(self, session_id: int, goal: str) -> Dict:
        """
        智能交互 - 根据目标自动决定操作

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
        session = self.get_session(session_id)
        if not session:
            return {"success": False, "result": "会话不存在", "output": ""}

        # 获取当前环境信息
        env_info = self._get_env_info(session_id, session.type)
        if not env_info.get("success"):
            env_info["output"] = "无法获取环境信息"

        # AI决策
        decision = self._ai_decide_action(goal, env_info, session)

        if not decision.get("command"):
            return {
                "success": False,
                "result": "AI决策失败",
                "output": str(decision)
            }

        # 执行决策
        print(f"[MSF] 执行: {decision['command']}")
        result = self.execute(session_id, decision["command"])

        # 解析结果
        return {
            "success": result.get("success", False),
            "result": decision.get("description", ""),
            "output": result.get("output", ""),
            "next_steps": decision.get("next_steps", [])
        }

    def _get_env_info(self, session_id: int, session_type: str) -> Dict:
        """获取环境信息"""
        if session_type == "meterpreter":
            # Meterpreter: 使用 sysinfo 和 getuid
            sysinfo = self.execute_meterpreter(session_id, "sysinfo")
            getuid = self.execute_meterpreter(session_id, "getuid")
            return {
                "success": True,
                "sysinfo": sysinfo.get("output", ""),
                "user": getuid.get("output", "")
            }
        else:
            # Shell: 使用 whoami 和系统命令
            whoami = self.execute_shell(session_id, "whoami")
            hostname = self.execute_shell(session_id, "hostname")
            return {
                "success": True,
                "user": whoami.get("output", "").strip(),
                "hostname": hostname.get("output", "").strip()
            }

    def _ai_decide_action(self, goal: str, env_info: Dict, session: MSFSession) -> Dict:
        """AI决策要执行的操作"""
        from llm_client import llm_client
        from config import config

        # 预定义的快捷命令
        quick_commands = {
            "获取系统信息": {
                "shell": "whoami && hostname && systeminfo",
                "meterpreter": "sysinfo && getuid"
            },
            "提权": {
                "shell": "whoami /priv",
                "meterpreter": "getsystem"
            },
            "导出凭据": {
                "shell": "type C:\\Users\\*\\Desktop\\*",
                "meterpreter": "run post/windows/gather/credentials/credential_collector"
            },
            "发现内网": {
                "shell": "ipconfig /all && arp -a",
                "meterpreter": "run post/multi/gather/enum_network"
            }
        }

        # 检查是否是预定义目标
        if goal in quick_commands:
            cmd = quick_commands[goal].get(session.type, quick_commands[goal].get("shell", ""))
            return {
                "command": cmd,
                "description": goal,
                "next_steps": []
            }

        # AI决策
        prompt = f"""根据目标和环境，决定要执行的命令。

## 目标
{goal}

## 当前环境
- 会话类型: {session.type}
- 目标: {session.target}
- 平台: {session.platform}
- 环境信息: {json.dumps(env_info, ensure_ascii=False)}

## 输出格式 (JSON)
{{
  "command": "要执行的命令",
  "description": "命令说明",
  "expected_output": "预期输出",
  "next_steps": ["成功后的下一步建议"]
}}
"""
        try:
            response = llm_client.call_chat_completion(
                model=config.ANALYST_MODEL,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.1,
                json_mode=True
            )

            if "```json" in response:
                response = response.split("```json")[1].split("```")[0]

            return json.loads(response.strip())

        except Exception as e:
            return {"command": "", "error": str(e)}

    # =========================================================================
    # 常用操作快捷方法
    # =========================================================================

    def get_system_info(self, session_id: int) -> Dict:
        """获取系统信息"""
        return self.smart_interact(session_id, "获取系统信息")

    def try_privesc(self, session_id: int) -> Dict:
        """尝试提权"""
        return self.smart_interact(session_id, "提权")

    def dump_credentials(self, session_id: int) -> Dict:
        """导出凭据"""
        return self.smart_interact(session_id, "导出凭据")

    def discover_network(self, session_id: int) -> Dict:
        """发现内网"""
        return self.smart_interact(session_id, "发现内网")


# =============================================================================
# 全局实例
# =============================================================================

_msf_manager: Optional[MetasploitManager] = None


def get_msf_manager() -> MetasploitManager:
    """获取全局MSF管理器实例"""
    global _msf_manager
    if _msf_manager is None:
        _msf_manager = MetasploitManager()
    return _msf_manager