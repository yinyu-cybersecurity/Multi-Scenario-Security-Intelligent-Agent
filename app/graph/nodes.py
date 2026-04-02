# app/graph/nodes.py
"""
AgenticLoop节点实现

借鉴Claude Code的AgenticLoop设计：
Think → Act → Reflect → Decide

核心原则:
1. Think节点：LLM决策，集成工具推荐、Skill推荐、Memory读取
2. Act节点：执行行动，支持工具调用、子Agent派发、阶段切换
3. Reflect节点：学习反思，提取发现、更新Memory、压缩上下文
"""

import json
import re
import shlex
from enum import Enum
from typing import Dict, Any, List, Optional, Literal, Set
from datetime import datetime

from app.state.state_v3 import CTFStateV3, PhaseType, ChallengeType
from app.agents.base import AgentType


# ============================================
# 安全配置
# ============================================

# 允许执行的工具白名单（从tools_v2动态获取）
ALLOWED_TOOLS: Set[str] = {
    # Web安全工具
    "nmap", "nuclei", "httpx", "fscan", "sqlmap", "ffuf", "dirsearch",
    "gobuster", "whatweb", "subfinder", "hydra", "xray", "dalfox",
    "httprobe", "jsfinder", "gopherus", "ssrfmap", "jwt_tool",

    # Pwn工具
    "binary_analyzer", "rop_builder", "shellcode_generator",

    # Crypto工具
    "crypto_identifier", "rsa_attacker", "hash_analyzer",
    "classical_cipher_solver", "encoding_decoder",

    # Reverse工具
    "disassembler", "decompiler", "string_extractor", "apk_analyzer",

    # Misc工具
    "steganography_detector", "forensics_analyzer", "traffic_analyzer",
    "qr_decoder", "encoding_converter",

    # AI安全工具
    "ai_attacker", "prompt_injector", "model_extractor",

    # 云安全工具
    "cloud_scanner", "container_escape", "kube_attacker",

    # 内网渗透工具
    "privesc_scanner", "potato_attack", "ldap_domaindump",
    "crackmapexec", "impacket", "bloodhound",

    # OA攻击工具
    "oa_exploiter", "ysoserial", "marshalsec", "jndiexploit",

    # 其他
    "Read", "Glob", "Grep", "Bash", "WebFetch", "LSP"
}

# 最大参数值长度（防止超长输入）
MAX_PARAM_LENGTH = 10000


class ActionType(Enum):
    """Agent可选择的行动类型"""
    DIRECT_TOOL = "direct_tool"
    DISPATCH_SUBAGENT = "dispatch_subagent"
    SWITCH_PHASE = "switch_phase"
    COMPLETE = "complete"


def validate_tool_name(tool_name: str) -> bool:
    """
    验证工具名称是否在白名单中

    Args:
        tool_name: 工具名称

    Returns:
        是否允许执行
    """
    if not tool_name or not isinstance(tool_name, str):
        return False

    # 检查是否在白名单中
    return tool_name in ALLOWED_TOOLS


def validate_tool_params(params: Dict[str, Any], tool_name: str) -> tuple[bool, str]:
    """
    验证工具参数，检查是否安全

    Args:
        params: 工具参数
        tool_name: 工具名称

    Returns:
        (是否安全, 错误信息)
    """
    if not isinstance(params, dict):
        return True, ""

    for key, value in params.items():
        # 检查参数值长度
        if isinstance(value, str) and len(value) > MAX_PARAM_LENGTH:
            return False, f"Parameter '{key}' exceeds max length {MAX_PARAM_LENGTH}"

        # 检查参数名是否合法
        if not isinstance(key, str) or not key.replace("_", "").replace("-", "").isalnum():
            return False, f"Invalid parameter name: {key}"

    return True, ""


async def think_node(state: CTFStateV3) -> CTFStateV3:
    """
    思考节点：分析状态，LLM决策下一步行动

    集成:
    - deferred_loader: 延迟加载工具推荐
    - skill_registry: Skill知识推荐
    - agent_memory: 历史发现读取
    - llm_client: LLM决策调用
    - dispatcher: 超时检查
    """
    from app.tools_v2.deferred_loader import get_deferred_tool_registry
    from app.skills import get_skill_registry
    from app.memory import get_agent_memory
    from app.llm_client import llm_client
    from app.coordinator.dispatcher import get_coordinator_dispatcher

    dispatcher = get_coordinator_dispatcher()
    deferred_registry = get_deferred_tool_registry()
    skill_registry = get_skill_registry()
    memory = get_agent_memory()

    # =========================================
    # 1. 检查超时（唯一硬性停止条件）
    # =========================================
    if dispatcher.should_stop(state["session_id"]):
        state["next_action"] = {
            "type": ActionType.COMPLETE.value,
            "reason": "timeout"
        }
        return state

    # =========================================
    # 2. 构建思考上下文
    # =========================================
    target = _get_target(state)
    context = {
        "phase": state["current_phase"].value,
        "target": target,
        "findings": state["findings"][-5:] if state["findings"] else []
    }

    # =========================================
    # 3. 获取延迟加载工具（根据上下文）
    # =========================================
    available_tools = deferred_registry.get_tools_for_context(context)
    tools_desc = "\n".join([
        f"- {name}"
        for name in available_tools[:15]  # 限制数量节省Token
    ])

    # =========================================
    # 4. 获取Skill推荐
    # =========================================
    skill_suggestions = await _get_skill_recommendations(skill_registry, state, context)
    skills_desc = ""
    if skill_suggestions:
        skills_desc = "\n## Skill推荐\n" + "\n".join([
            f"- {s['name']}: {s['reason']}"
            for s in skill_suggestions[:3]
        ])

    # =========================================
    # 5. 读取Memory历史发现
    # =========================================
    relevant_memories = []
    try:
        # 读取最近的endpoints和vulns
        for topic in ["endpoints", "vulns", "credentials"]:
            findings = memory.read_finding(state["session_id"], topic)
            if findings:
                relevant_memories.extend(findings[:3])
    except Exception:
        pass

    memories_desc = ""
    if relevant_memories:
        memories_desc = "\n## 历史发现\n" + "\n".join([
            f"- [{m.get('topic', 'unknown')}] {str(m.get('data', ''))[:100]}"
            for m in relevant_memories[:5]
        ])

    # =========================================
    # 6. 构建决策Prompt
    # =========================================
    prompt = _build_decision_prompt(
        state=state,
        tools_desc=tools_desc,
        skills_desc=skills_desc,
        memories_desc=memories_desc,
        target=target
    )

    # =========================================
    # 7. LLM决策
    # =========================================
    try:
        response = llm_client.call_chat_completion(
            model="deepseek-chat",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.3,
            max_tokens=800,
            json_mode=True
        )

        # 解析决策
        action = _parse_action_response(response, available_tools)
        state["next_action"] = action

    except Exception as e:
        # LLM调用失败，使用默认行动
        state["next_action"] = {
            "type": ActionType.SWITCH_PHASE.value,
            "new_phase": PhaseType.EXPLORE.value,
            "reasoning": f"LLM调用失败: {str(e)}"
        }

    return state


def _get_target(state: CTFStateV3) -> str:
    """获取当前目标地址"""
    challenge = state.get("challenge")
    if challenge:
        return challenge.target_url or challenge.target_ip or "unknown"
    return "unknown"


async def _get_skill_recommendations(
    skill_registry,
    state: CTFStateV3,
    context: Dict
) -> List[Dict]:
    """从Skill系统获取推荐"""
    try:
        matching_skills = skill_registry.find_matching_skills(context)
        recommendations = []

        for skill in matching_skills[:3]:
            if hasattr(skill, 'tool_preferences') and skill.tool_preferences:
                top_tool = max(skill.tool_preferences, key=lambda x: x.score)
                recommendations.append({
                    "name": skill.name,
                    "tool": top_tool.tool_name,
                    "reason": f"匹配Skill: {skill.name}"
                })

        return recommendations
    except Exception:
        return []


def _build_decision_prompt(
    state: CTFStateV3,
    tools_desc: str,
    skills_desc: str,
    memories_desc: str,
    target: str
) -> str:
    """构建决策Prompt"""
    return f"""你是一个渗透测试专家。分析当前状态并决定下一步行动。

## 当前状态
- 阶段: {state['current_phase'].value}
- 迭代: {state['iteration_count']}/{state['max_iterations']}
- 已发现: {len(state['findings'])} 个发现
- 已找到Flag: {bool(state.get('flags_found'))}
- 目标: {target}

{skills_desc}
{memories_desc}

## 可用工具
{tools_desc}

## 行动选项
1. direct_tool - 调用工具
2. dispatch_subagent - 派发子Agent并行处理
3. switch_phase - 切换到下一阶段
4. complete - 任务完成

## 返回格式
请返回JSON格式的行动决策:
{{
  "type": "direct_tool",
  "tool": "nmap",
  "params": {{"target": "{target}"}},
  "reasoning": "原因说明"
}}

或:
{{
  "type": "dispatch_subagent",
  "agent_type": "explore",
  "targets": ["{target}"],
  "reasoning": "原因说明"
}}

或:
{{
  "type": "switch_phase",
  "new_phase": "attack",
  "reasoning": "原因说明"
}}

或:
{{
  "type": "complete",
  "reason": "flag_found",
  "reasoning": "原因说明"
}}
"""


def _parse_action_response(response: str, available_tools: List[str]) -> Dict:
    """解析LLM响应为行动决策"""
    try:
        # 提取JSON
        json_match = re.search(r'\{[\s\S]*\}', response)
        if json_match:
            action = json.loads(json_match.group())

            # 验证type字段
            if "type" not in action:
                action["type"] = ActionType.SWITCH_PHASE.value

            # 验证工具是否存在
            if action.get("type") == ActionType.DIRECT_TOOL.value:
                if action.get("tool") not in available_tools:
                    # 工具不存在，切换到探索阶段
                    action = {
                        "type": ActionType.SWITCH_PHASE.value,
                        "new_phase": PhaseType.EXPLORE.value,
                        "reasoning": f"工具 {action.get('tool')} 不可用"
                    }

            return action
    except Exception:
        pass

    # 解析失败，默认探索
    return {
        "type": ActionType.SWITCH_PHASE.value,
        "new_phase": PhaseType.EXPLORE.value,
        "reasoning": "LLM响应解析失败"
    }


async def act_node(state: CTFStateV3) -> CTFStateV3:
    """
    执行节点：执行Think决策的行动

    支持行动类型:
    1. DIRECT_TOOL - 直接工具调用
    2. DISPATCH_SUBAGENT - 派发子Agent
    3. SWITCH_PHASE - 阶段切换
    4. COMPLETE - 任务完成
    """
    from app.tools_v2.tools import execute_tool
    from app.coordinator.dispatcher import get_coordinator_dispatcher
    from app.tools_v2 import get_max_concurrent

    action = state.get("next_action", {})
    action_type = action.get("type", ActionType.SWITCH_PHASE.value)

    # =========================================
    # 行动类型1：直接工具调用
    # =========================================
    if action_type == ActionType.DIRECT_TOOL.value:
        tool_name = action.get("tool")
        params = action.get("params", {})

        # =====================================
        # 安全验证：工具白名单检查
        # =====================================
        if not validate_tool_name(tool_name):
            state["last_tool_result"] = {
                "success": False,
                "error": f"Tool '{tool_name}' is not allowed or does not exist"
            }
            state["tool_history"].append({
                "tool": tool_name,
                "params": params,
                "success": False,
                "error": "Tool not in whitelist",
                "timestamp": datetime.now().isoformat()
            })
            return state

        # =====================================
        # 安全验证：参数基本检查
        # =====================================
        is_valid, error_msg = validate_tool_params(params, tool_name)
        if not is_valid:
            state["last_tool_result"] = {
                "success": False,
                "error": f"Invalid parameters: {error_msg}"
            }
            state["tool_history"].append({
                "tool": tool_name,
                "params": params,
                "success": False,
                "error": error_msg,
                "timestamp": datetime.now().isoformat()
            })
            return state

        try:
            # execute_tool内部已集成Docker执行
            result = await execute_tool(tool_name, params)
            state["last_tool_result"] = result

            # 记录工具历史
            state["tool_history"].append({
                "tool": tool_name,
                "params": params,
                "success": result.get("success", False),
                "timestamp": datetime.now().isoformat()
            })
        except Exception as e:
            state["last_tool_result"] = {
                "success": False,
                "error": str(e)
            }

    # =========================================
    # 行动类型2：派发子Agent
    # =========================================
    elif action_type == ActionType.DISPATCH_SUBAGENT.value:
        result = await _dispatch_subagent_integrated(state, action)
        state["last_subagent_result"] = result

    # =========================================
    # 行动类型3：阶段切换
    # =========================================
    elif action_type == ActionType.SWITCH_PHASE.value:
        new_phase_str = action.get("new_phase", PhaseType.EXPLORE.value)
        # 转换为PhaseType枚举
        try:
            new_phase = PhaseType(new_phase_str)
        except ValueError:
            new_phase = PhaseType.EXPLORE
        state["current_phase"] = new_phase
        state["last_phase_switch"] = {
            "to": new_phase.value,
            "reason": action.get("reasoning", "")
        }

    # =========================================
    # 行动类型4：任务完成
    # =========================================
    elif action_type == ActionType.COMPLETE.value:
        state["current_phase"] = PhaseType.COMPLETE
        state["final_result"] = {
            "success": bool(state.get("flags_found")),
            "reason": action.get("reason", "completed")
        }

    # 更新迭代计数
    state["iteration_count"] += 1
    state["last_update_time"] = datetime.now().timestamp()

    return state


async def _dispatch_subagent_integrated(
    state: CTFStateV3,
    action: Dict
) -> Dict:
    """
    派发子Agent - 深度集成版

    复用CoordinatorDispatcher的并行派发能力
    """
    from app.coordinator.dispatcher import get_coordinator_dispatcher
    from app.tools_v2 import get_max_concurrent
    from app.memory.prompt_cache import PromptCacheManager

    dispatcher = get_coordinator_dispatcher()
    cache_manager = PromptCacheManager()

    target = _get_target(state)
    targets = action.get("targets", [target])
    agent_type_str = action.get("agent_type", "explore")
    task_template = action.get("task_template", "分析目标 {target}")

    # 转换agent_type
    try:
        agent_type = AgentType(agent_type_str)
    except ValueError:
        agent_type = AgentType.EXPLORE

    # 获取并发限制
    max_concurrent = get_max_concurrent(agent_type.value)

    try:
        # =========================================
        # 1. 派发并行任务
        # =========================================
        tasks = await dispatcher.dispatch_parallel_agents(
            session_id=state["session_id"],
            targets=targets[:max_concurrent],
            task_template=task_template,
            agent_type=agent_type
        )

        # =========================================
        # 2. 执行并聚合
        # =========================================
        # 注意：这里需要提供一个执行handler
        # 由于子Agent也是AgenticLoop，我们创建一个简化的执行器
        results = await dispatcher.execute_all_fork_tasks(
            session_id=state["session_id"],
            execute_handler=_create_subagent_handler(state, agent_type),
            max_concurrent=max_concurrent
        )

        return results

    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "findings": []
        }


def _create_subagent_handler(parent_state: CTFStateV3, agent_type: AgentType):
    """创建子Agent执行handler"""
    async def handler(agent_type: AgentType, messages: list, target: str) -> dict:
        """
        子Agent执行函数

        简化实现：使用AutonomousAgent执行子任务
        """
        from app.agents.autonomous_agent import AutonomousAgent

        try:
            # 创建子Agent
            sub_agent = AutonomousAgent(
                target=target,
                objective=f"分析目标 {target}",
                max_iterations=10,  # 子Agent限制迭代次数
                agent_type=agent_type
            )

            # 执行
            result = await sub_agent.run()

            return {
                "success": result.get("success", False),
                "findings": result.get("findings", []),
                "target": target
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "findings": [],
                "target": target
            }

    return handler


async def reflect_node(state: CTFStateV3) -> CTFStateV3:
    """
    反思节点：分析结果，学习反思，更新知识库

    集成:
    - agent_memory: 写入发现
    - flag_extractor_v2: Flag提取
    - context_compressor: 上下文压缩
    """
    from app.memory import get_agent_memory
    from app.flag_extractor_v2 import extract_flags
    from app.memory.context_compressor import get_context_compressor

    memory = get_agent_memory()
    compressor = get_context_compressor()
    target = _get_target(state)

    # =========================================
    # 1. 分析工具结果
    # =========================================
    if tool_result := state.get("last_tool_result"):
        # 提取发现
        findings = _extract_findings_from_result(tool_result)

        for finding in findings:
            # 写入状态
            state["findings"].append(finding)

            # 写入Memory
            try:
                await memory.write_finding(
                    agent_type=AgentType.COORDINATOR,
                    target=target,
                    topic=finding.get("type", "general"),
                    data=finding
                )
            except Exception:
                pass

        # Flag提取
        try:
            flags = extract_flags(str(tool_result))
            if flags:
                for flag in flags:
                    if flag not in state.get("flags_found", []):
                        state["flags_found"].append(flag)
        except Exception:
            pass

    # =========================================
    # 2. 分析子Agent结果
    # =========================================
    if subagent_result := state.get("last_subagent_result"):
        sub_findings = subagent_result.get("findings", [])
        state["findings"].extend(sub_findings)

        # 同步到Memory
        for finding in sub_findings:
            try:
                await memory.write_finding(
                    agent_type=AgentType.COORDINATOR,
                    target=target,
                    topic=finding.get("type", "general"),
                    data=finding
                )
            except Exception:
                pass

    # =========================================
    # 3. 上下文压缩（避免Token爆炸）
    # =========================================
    if len(state["findings"]) > 20:
        try:
            # 使用context_compressor压缩
            compressed = compressor.build_prompt_context(max_tokens=5000)
            # 保留关键发现
            state["findings"] = state["findings"][-15:]
        except Exception:
            # 压缩失败，简单截断
            state["findings"] = state["findings"][-15:]

    # =========================================
    # 4. 更新发现资产
    # =========================================
    state["discovered_assets"] = _extract_assets(state["findings"])

    return state


def _extract_findings_from_result(result: Dict) -> List[Dict]:
    """
    从工具结果提取发现

    复用现有的结果解析逻辑
    """
    findings = []

    if not isinstance(result, dict):
        return findings

    # 端口发现
    if "open_ports" in result:
        findings.append({
            "type": "endpoint",
            "topic": "endpoints",
            "content": {"ports": result["open_ports"]},
            "confidence": 1.0,
            "timestamp": datetime.now().isoformat()
        })

    # 漏洞发现
    if "vulnerabilities" in result:
        for vuln in result.get("vulnerabilities", []):
            findings.append({
                "type": "vuln",
                "topic": "vulns",
                "content": vuln,
                "confidence": vuln.get("confidence", 0.8),
                "timestamp": datetime.now().isoformat()
            })

    # 凭据发现
    if "credentials" in result:
        for cred in result.get("credentials", []):
            findings.append({
                "type": "credential",
                "topic": "credentials",
                "content": cred,
                "confidence": 0.9,
                "timestamp": datetime.now().isoformat()
            })

    # 通用数据发现
    if "data" in result and isinstance(result["data"], dict):
        data = result["data"]
        if "endpoints" in data:
            findings.append({
                "type": "endpoint",
                "topic": "endpoints",
                "content": {"endpoints": data["endpoints"]},
                "confidence": 0.8,
                "timestamp": datetime.now().isoformat()
            })

    return findings


def _extract_assets(findings: List[Dict]) -> List[Dict]:
    """从发现中提取资产列表"""
    assets = []
    seen = set()

    for finding in findings:
        content = finding.get("content", {})

        # 提取端口资产
        if finding.get("type") == "endpoint":
            ports = content.get("ports", [])
            for port in ports:
                key = f"port:{port}"
                if key not in seen:
                    seen.add(key)
                    assets.append({"type": "port", "value": port})

        # 提取URL资产
        if "url" in content:
            url = content["url"]
            if url not in seen:
                seen.add(url)
                assets.append({"type": "url", "value": url})

    return assets