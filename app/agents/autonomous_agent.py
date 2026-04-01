"""
自主Agent实现

借鉴Claude Code的AgenticLoop设计：
思考 → 选择工具 → 执行 → 反思 → 继续/结束

集成系统:
- Skill系统: 提供领域知识和工具推荐
- Memory系统: 记录发现，Agent间通信
- 权限检查: 确保操作符合Agent权限
"""

import asyncio
from enum import Enum
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from datetime import datetime

from app.capabilities.foundation import FoundationCapability, FoundationTool
from app.tools_v2.tools import execute_tool, list_tools, get_tool_schema
from app.tools_v2.deferred_loader import get_deferred_tool_registry
from app.skills import get_skill_registry
from app.memory import get_agent_memory
from app.agents.base import AgentType


class AgentPhase(Enum):
    """Agent执行阶段"""
    INIT = "init"
    EXPLORING = "exploring"
    PLANNING = "planning"
    ATTACKING = "attacking"
    VERIFYING = "verifying"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class AgentState:
    """Agent状态"""
    phase: AgentPhase = AgentPhase.INIT
    target: str = ""
    objective: str = ""
    current_iteration: int = 0
    max_iterations: int = 50
    findings: List[Dict] = field(default_factory=list)
    tool_calls: List[Dict] = field(default_factory=list)
    flag_found: bool = False
    flag: str = ""


class AutonomousAgent:
    """
    自主Agent

    核心能力：
    - 完全自主执行任务
    - 动态选择工具和技能
    - 记录发现到Memory
    - 循环执行直到完成或失败

    集成系统:
    - Skill系统: _think()中使用skill_registry获取相关知识
    - Memory系统: _reflect()中写入发现
    - 权限检查: _execute_action中验证权限
    """

    # Agent类型权限映射
    AGENT_PERMISSIONS = {
        AgentType.EXPLORE: ["read", "glob", "grep", "network_scan"],
        AgentType.PLAN: ["read", "glob", "grep", "ask"],
        AgentType.ATTACK: ["read", "write", "edit", "bash", "network_attack"],
        AgentType.VERIFY: ["read", "bash", "scan"],
        AgentType.COORDINATOR: ["read", "write", "bash", "dispatch"],
    }

    def __init__(
        self,
        target: str,
        objective: str = "",
        workspace: str = ".",
        max_iterations: int = 50,
        agent_type: AgentType = AgentType.COORDINATOR
    ):
        self.target = target
        self.objective = objective or f"攻击目标 {target}，获取flag"
        self.workspace = workspace
        self.agent_type = agent_type

        # 状态
        self.state = AgentState(
            target=target,
            objective=self.objective,
            max_iterations=max_iterations
        )

        # 能力
        self.foundation = FoundationCapability(workspace=workspace)
        self.memory = get_agent_memory()
        self.skill_registry = get_skill_registry()
        self.deferred_registry = get_deferred_tool_registry()

    async def run(self) -> Dict[str, Any]:
        """
        执行主循环

        Returns:
            执行结果
        """
        print(f"🎯 开始攻击目标: {self.target}")
        print(f"📋 目标: {self.objective}")

        while not self._should_stop():
            self.state.current_iteration += 1

            # 执行一步
            result = await self._step()

            if result.get("completed"):
                break

            # 避免无限循环
            await asyncio.sleep(0.1)

        return self._build_result()

    def _should_stop(self) -> bool:
        """判断是否应该停止"""
        if self.state.phase in [AgentPhase.COMPLETED, AgentPhase.FAILED]:
            return True
        if self.state.current_iteration >= self.state.max_iterations:
            return True
        if self.state.flag_found:
            return True
        return False

    async def _step(self) -> Dict[str, Any]:
        """
        执行一步

        AgenticLoop: 思考 → 选择工具 → 执行 → 反思
        """
        iteration = self.state.current_iteration
        print(f"\n📍 第 {iteration} 步 [{self.state.phase.value}]")

        # 1. 思考：决定下一步行动
        action = await self._think()

        # 2. 执行行动
        result = await self._execute_action(action)

        # 3. 反思：更新状态
        await self._reflect(result)

        return result

    async def _think(self) -> Dict[str, Any]:
        """
        思考：决定下一步行动

        基于当前阶段和发现决定行动
        集成Skill系统获取专业知识推荐
        """
        phase = self.state.phase

        # 尝试从Skill系统获取建议
        skill_suggestion = await self._get_skill_suggestion()
        if skill_suggestion:
            return skill_suggestion

        # 检查工具是否在延迟加载列表中，需要时显式加载
        context = {
            "phase": phase.value,
            "target": self.target,
            "findings": self.state.findings[-3:] if self.state.findings else []
        }

        # 获取当前应加载的工具列表
        available_tools = self.deferred_registry.get_tools_for_context(context)

        # 默认逻辑
        if phase == AgentPhase.INIT:
            # 初始阶段：信息收集
            return {
                "type": "scan",
                "tool": "nmap",
                "params": {"target": self.target, "scan_type": "quick"}
            }

        elif phase == AgentPhase.EXPLORING:
            # 探索阶段：发现服务后深入
            if self._has_web_service():
                return {
                    "type": "vuln_scan",
                    "tool": "nuclei",
                    "params": {"target": self._get_web_url()}
                }
            else:
                # 继续探索
                return {
                    "type": "scan",
                    "tool": "nmap",
                    "params": {"target": self.target, "scan_type": "service"}
                }

        elif phase == AgentPhase.ATTACKING:
            # 攻击阶段：利用发现的漏洞
            vuln = self._get_next_vuln()
            if vuln:
                return self._plan_exploit(vuln)
            else:
                self.state.phase = AgentPhase.EXPLORING
                return {"type": "explore", "tool": "nmap"}

        elif phase == AgentPhase.VERIFYING:
            # 验证阶段：检查flag
            return {
                "type": "verify",
                "tool": "foundation",
                "params": {"action": "check_flag"}
            }

        return {"type": "wait", "tool": None}

    async def _get_skill_suggestion(self) -> Optional[Dict[str, Any]]:
        """
        从Skill系统获取行动建议

        Returns:
            行动建议，如果无相关Skill则返回None
        """
        try:
            # 构建上下文
            context = {
                "phase": self.state.phase.value,
                "target": self.target,
                "objective": self.objective,
                "findings": self.state.findings[-5:] if self.state.findings else [],  # 最近5个发现
            }

            # 查找匹配的Skill
            matching_skills = self.skill_registry.find_matching_skills(context)

            if not matching_skills:
                return None

            # 使用最佳匹配的Skill
            best_skill = matching_skills[0]

            # 获取推荐的工具
            tool_prefs = best_skill.tool_preferences
            if tool_prefs:
                # 按分数排序，选择最高分的工具
                sorted_prefs = sorted(tool_prefs, key=lambda x: x.score, reverse=True)
                recommended_tool = sorted_prefs[0].tool_name

                # 检查工具是否可用
                available_tools = list_tools()
                if recommended_tool in available_tools:
                    print(f"  📚 Skill推荐: {best_skill.name} → {recommended_tool}")

                    # 构建参数
                    params = self._build_tool_params(recommended_tool)
                    return {
                        "type": "skill_recommended",
                        "tool": recommended_tool,
                        "params": params,
                        "skill": best_skill.name
                    }

            # 尝试使用工作流
            if best_skill.workflows:
                workflow = best_skill.workflows[0]
                if workflow.steps:
                    # 找到当前阶段对应的步骤
                    for step in workflow.steps:
                        if step.suggested_tools:
                            return {
                                "type": "workflow_step",
                                "tool": step.suggested_tools[0],
                                "params": self._build_tool_params(step.suggested_tools[0]),
                                "description": step.description
                            }

            return None

        except Exception as e:
            print(f"  ⚠️ Skill查询失败: {e}")
            return None

    def _build_tool_params(self, tool_name: str) -> Dict[str, Any]:
        """根据工具名称构建默认参数"""
        if tool_name == "nmap":
            return {"target": self.target, "scan_type": "quick"}
        elif tool_name == "nuclei":
            return {"target": self._get_web_url() if self._has_web_service() else self.target}
        elif tool_name == "sqlmap":
            vuln = self._get_next_vuln()
            url = vuln.get("url", self._get_web_url()) if vuln else self._get_web_url()
            return {"target_url": url, "action": "detect"}
        elif tool_name in ["httpx", "fscan"]:
            return {"target": self.target}
        return {}

    def _search_deferred_tool(self, query: str) -> Optional[Dict[str, Any]]:
        """搜索延迟加载的工具"""
        results = self.deferred_registry.search_tools(query)
        if results:
            best_match = results[0]
            # 加载工具Schema
            schema = self.deferred_registry.load_tool(best_match["name"])
            if schema:
                print(f"  🔍 发现工具: {best_match['name']} - {best_match['description']}")
                return {
                    "tool": best_match["name"],
                    "params": self._build_tool_params(best_match["name"]),
                    "tags": best_match.get("tags", [])
                }
        return None

    async def _execute_action(self, action: Dict) -> Dict[str, Any]:
        """执行行动"""
        tool = action.get("tool")
        if not tool:
            return {"completed": False, "message": "无工具可执行"}

        params = action.get("params", {})
        action_type = action.get("type", "unknown")

        # 权限检查
        if not self._check_permission(tool, action_type):
            return {
                "completed": False,
                "success": False,
                "error": f"权限不足: {self.agent_type.value} 无权执行 {tool}"
            }

        print(f"  🔧 执行: {tool} ({action_type})")

        # 记录工具调用
        self.state.tool_calls.append({
            "step": self.state.current_iteration,
            "tool": tool,
            "params": params,
            "timestamp": datetime.now().isoformat()
        })

        try:
            if tool == "foundation":
                # 使用基础能力
                result = await self._use_foundation(params)
            else:
                # 使用专业工具
                result = await execute_tool(tool, params)

            return {
                "completed": False,
                "success": result.get("success", False),
                "data": result
            }

        except Exception as e:
            return {
                "completed": False,
                "success": False,
                "error": str(e)
            }

    def _check_permission(self, tool: str, action_type: str) -> bool:
        """
        检查Agent是否有权限执行该工具

        Args:
            tool: 工具名称
            action_type: 行动类型

        Returns:
            是否有权限
        """
        permissions = self.AGENT_PERMISSIONS.get(self.agent_type, [])

        # Foundation工具权限映射
        foundation_permissions = {
            "read": ["Read"],
            "write": ["Write"],
            "edit": ["Edit"],
            "bash": ["Bash"],
            "glob": ["Glob"],
            "grep": ["Grep"],
        }

        # 专业工具权限映射
        tool_permission_map = {
            "nmap": "network_scan",
            "nuclei": "network_scan",
            "httpx": "network_scan",
            "fscan": "network_scan",
            "sqlmap": "network_attack",
            "ffuf": "network_attack",
            "dirsearch": "network_scan",
        }

        # 检查Foundation工具
        if tool in ["Read", "Write", "Edit", "Bash", "Glob", "Grep"]:
            for perm_type, tools in foundation_permissions.items():
                if tool in tools and perm_type in permissions:
                    return True
            return False

        # 检查专业工具
        required_perm = tool_permission_map.get(tool)
        if required_perm:
            return required_perm in permissions

        # 默认允许（未知工具）
        return True

    async def _use_foundation(self, params: Dict) -> Dict:
        """使用基础能力"""
        action = params.get("action", "read")

        if action == "check_flag":
            # 检查是否找到flag
            flag = await self._search_flag()
            if flag:
                self.state.flag_found = True
                self.state.flag = flag
                self.state.phase = AgentPhase.COMPLETED
                return {"success": True, "flag": flag}

        return {"success": False, "message": "未找到flag"}

    async def _reflect(self, result: Dict):
        """
        反思：更新状态和发现

        分析执行结果，决定下一步
        将发现写入Memory系统，实现Agent间通信
        """
        if not result.get("success"):
            return

        data = result.get("data", {})

        # 分析扫描结果
        if "open_ports" in data:
            self._process_scan_result(data)

        if "vulnerabilities" in data:
            self._process_vuln_result(data)

        if "flag" in data:
            print(f"  🏆 发现FLAG: {data['flag']}")

        # 写入Memory系统，实现Agent间通信
        await self._write_to_memory(result)

    async def _write_to_memory(self, result: Dict):
        """
        将发现写入Memory系统

        实现Agent间通信，共享发现
        """
        try:
            data = result.get("data", {})

            # 写入端口发现
            if "open_ports" in data:
                await self.memory.write_finding(
                    agent_type=self.agent_type,
                    target=self.target,
                    topic="endpoints",
                    data={
                        "type": "open_ports",
                        "ports": data["open_ports"],
                        "target": self.target,
                        "timestamp": datetime.now().isoformat()
                    }
                )
                print(f"  📝 Memory: 记录端口发现")

            # 写入漏洞发现
            if "vulnerabilities" in data:
                await self.memory.write_finding(
                    agent_type=self.agent_type,
                    target=self.target,
                    topic="vulns",
                    data={
                        "type": "vulnerabilities",
                        "vulns": data["vulnerabilities"],
                        "target": self.target,
                        "timestamp": datetime.now().isoformat()
                    }
                )
                print(f"  📝 Memory: 记录漏洞发现")

            # 写入凭据发现
            if "credentials" in data:
                await self.memory.write_finding(
                    agent_type=self.agent_type,
                    target=self.target,
                    topic="credentials",
                    data={
                        "type": "credentials",
                        "creds": data["credentials"],
                        "target": self.target,
                        "timestamp": datetime.now().isoformat()
                    }
                )
                print(f"  📝 Memory: 记录凭据发现")

            # 写入Flag
            if "flag" in data or self.state.flag_found:
                await self.memory.write_finding(
                    agent_type=self.agent_type,
                    target=self.target,
                    topic="flags",
                    data={
                        "type": "flag",
                        "flag": self.state.flag or data.get("flag"),
                        "target": self.target,
                        "timestamp": datetime.now().isoformat()
                    }
                )
                print(f"  📝 Memory: 记录Flag")

        except Exception as e:
            print(f"  ⚠️ Memory写入失败: {e}")

    def _process_scan_result(self, data: Dict):
        """处理扫描结果"""
        open_ports = data.get("open_ports", [])

        if open_ports:
            print(f"  📊 发现开放端口: {open_ports}")

            # 记录发现
            self.state.findings.append({
                "type": "open_ports",
                "ports": open_ports,
                "target": self.target
            })

            # 更新阶段
            if self.state.phase == AgentPhase.INIT:
                self.state.phase = AgentPhase.EXPLORING

    def _process_vuln_result(self, data: Dict):
        """处理漏洞扫描结果"""
        vulns = data.get("vulnerabilities", [])

        if vulns:
            print(f"  🔴 发现漏洞: {len(vulns)} 个")

            self.state.findings.append({
                "type": "vulnerabilities",
                "vulns": vulns,
                "target": self.target
            })

            # 更新阶段
            self.state.phase = AgentPhase.ATTACKING

    async def _search_flag(self) -> Optional[str]:
        """搜索flag"""
        # 在发现中搜索flag格式
        import re
        flag_patterns = [
            r"flag\{[^}]+\}",
            r"FLAG\{[^}]+\}",
            r"ctf\{[^}]+\}",
            r"CTF\{[^}]+\}"
        ]

        for finding in self.state.findings:
            finding_str = str(finding)
            for pattern in flag_patterns:
                match = re.search(pattern, finding_str, re.IGNORECASE)
                if match:
                    return match.group(0)

        return None

    def _has_web_service(self) -> bool:
        """检查是否有Web服务"""
        for finding in self.state.findings:
            if finding.get("type") == "open_ports":
                ports = finding.get("ports", [])
                web_ports = ["80", "443", "8080", "8443", "3000", "5000"]
                return any(p in web_ports for p in ports)
        return False

    def _get_web_url(self) -> str:
        """获取Web URL"""
        for finding in self.state.findings:
            if finding.get("type") == "open_ports":
                ports = finding.get("ports", [])
                if "443" in ports:
                    return f"https://{self.target}"
                elif "80" in ports:
                    return f"http://{self.target}"
        return f"http://{self.target}"

    def _get_next_vuln(self) -> Optional[Dict]:
        """获取下一个待利用的漏洞"""
        for finding in self.state.findings:
            if finding.get("type") == "vulnerabilities":
                vulns = finding.get("vulns", [])
                if vulns:
                    return vulns[0]
        return None

    def _plan_exploit(self, vuln: Dict) -> Dict:
        """规划漏洞利用"""
        vuln_name = vuln.get("name", "").lower()
        url = vuln.get("url", self._get_web_url())

        # SQL注入
        if "sql" in vuln_name or "sqli" in vuln_name:
            return {
                "type": "exploit",
                "tool": "sqlmap",
                "params": {"target_url": url, "action": "detect"}
            }

        # 默认：使用nuclei深入扫描
        return {
            "type": "vuln_scan",
            "tool": "nuclei",
            "params": {"target": url}
        }

    def _build_result(self) -> Dict[str, Any]:
        """构建最终结果"""
        if self.state.flag_found:
            self.state.phase = AgentPhase.COMPLETED
        elif self.state.current_iteration >= self.state.max_iterations:
            self.state.phase = AgentPhase.FAILED

        return {
            "success": self.state.flag_found,
            "phase": self.state.phase.value,
            "flag": self.state.flag,
            "iterations": self.state.current_iteration,
            "findings": self.state.findings,
            "tool_calls": self.state.tool_calls
        }


# ============================================
# 便捷函数
# ============================================

async def run_autonomous_attack(
    target: str,
    objective: str = "",
    max_iterations: int = 50
) -> Dict[str, Any]:
    """
    执行自主攻击

    Args:
        target: 目标地址
        objective: 攻击目标描述
        max_iterations: 最大迭代次数

    Returns:
        攻击结果
    """
    agent = AutonomousAgent(
        target=target,
        objective=objective,
        max_iterations=max_iterations
    )
    return await agent.run()