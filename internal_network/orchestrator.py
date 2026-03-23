# internal_network/orchestrator.py
"""
内网渗透编排器

负责协调内网渗透的各个阶段:
1. 初始访问
2. 内网侦察
3. 凭据获取
4. 横向移动
5. 权限提升
"""

import json
from typing import Dict, List, Optional, Any
from enum import Enum
from dataclasses import dataclass

from .nodes import internal_recon_node, lateral_move_node


class InternalPhase(Enum):
    """内网渗透阶段"""
    INITIAL_ACCESS = "initial_access"
    RECONNAISSANCE = "reconnaissance"
    CREDENTIAL_GATHERING = "credential_gathering"
    LATERAL_MOVEMENT = "lateral_movement"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    COMPLETE = "complete"


@dataclass
class InternalNetworkContext:
    """内网渗透上下文"""
    phase: InternalPhase
    current_target: str
    credentials_count: int
    hosts_count: int
    sessions_count: int


class InternalNetworkOrchestrator:
    """
    内网渗透编排器

    设计:
    - 独立于Web CTF流程
    - 可嵌入现有节点或独立运行
    - 支持从任意阶段恢复
    """

    def __init__(self):
        self.phase = InternalPhase.INITIAL_ACCESS
        self.history: List[Dict] = []

    def run_phase(self, state: Dict, phase: InternalPhase = None) -> Dict:
        """
        执行指定阶段

        Args:
            state: 当前CTFState
            phase: 要执行的阶段，默认为当前阶段

        Returns:
            状态更新字典
        """
        if phase:
            self.phase = phase

        phase_handlers = {
            InternalPhase.RECONNAISSANCE: self._run_reconnaissance,
            InternalPhase.CREDENTIAL_GATHERING: self._run_credential_gathering,
            InternalPhase.LATERAL_MOVEMENT: self._run_lateral_movement,
            InternalPhase.PRIVILEGE_ESCALATION: self._run_privilege_escalation,
        }

        handler = phase_handlers.get(self.phase)
        if handler:
            result = handler(state)
            self.history.append({
                "phase": self.phase.value,
                "result": result
            })
            return result

        return {"error": f"未知阶段: {self.phase}"}

    def _run_reconnaissance(self, state: Dict) -> Dict:
        """执行内网侦察"""
        result = internal_recon_node(state)

        if result.get("internal_hosts"):
            self.phase = InternalPhase.CREDENTIAL_GATHERING

        return result

    def _run_credential_gathering(self, state: Dict) -> Dict:
        """收集凭据"""
        from tool_framework import ToolRegistry

        # 尝试从当前目标获取凭据
        target = state.get("current_internal_target", "")

        # 使用crackmapexec测试凭据
        result = ToolRegistry.execute_cached(
            "crackmapexec",
            target,
            {
                "protocol": "smb",
                "target": target,
                "action": "enum"
            }
        )

        # 如果发现新凭据
        if result.get("result", {}).get("results"):
            credentials = []
            for r in result["result"]["results"]:
                if r.get("status") == "success":
                    credentials.append({
                        "host": target,
                        "username": r.get("username", ""),
                        "password": r.get("password", ""),
                        "domain": r.get("domain", ""),
                        "cred_type": "plaintext"
                    })

            if credentials:
                self.phase = InternalPhase.LATERAL_MOVEMENT
                return {"credentials": credentials}

        return {"error": "未获取到凭据"}

    def _run_lateral_movement(self, state: Dict) -> Dict:
        """执行横向移动"""
        result = lateral_move_node(state)

        if result.get("active_sessions"):
            self.phase = InternalPhase.PRIVILEGE_ESCALATION

        return result

    def _run_privilege_escalation(self, state: Dict) -> Dict:
        """权限提升"""
        # TODO: 实现权限提升逻辑
        self.phase = InternalPhase.COMPLETE
        return {"message": "权限提升阶段待实现"}

    def get_context(self, state: Dict) -> InternalNetworkContext:
        """获取当前上下文"""
        return InternalNetworkContext(
            phase=self.phase,
            current_target=state.get("current_internal_target", ""),
            credentials_count=len(state.get("credentials", [])),
            hosts_count=len(state.get("internal_hosts", [])),
            sessions_count=len(state.get("active_sessions", []))
        )

    def suggest_next_action(self, state: Dict) -> Dict:
        """AI建议下一步行动"""
        context = self.get_context(state)

        prompt = f"""
基于当前内网渗透状态，建议下一步行动。

## 当前状态
- 阶段: {context.phase.value}
- 当前目标: {context.current_target}
- 已获取凭据: {context.credentials_count}
- 发现主机: {context.hosts_count}
- 活跃会话: {context.sessions_count}

## 建议
返回JSON格式:
{{
    "next_phase": "阶段名称",
    "reason": "原因",
    "specific_action": "具体建议"
}}
"""

        from llm_client import llm_client
        from config import config

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
        except Exception:
            return {
                "next_phase": self.phase.value,
                "reason": "继续当前阶段",
                "specific_action": "继续执行"
            }