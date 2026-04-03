"""
Claude Code Query循环 - Python移植版

完全复制Claude Code的query.ts设计：
- 消息循环
- 工具调用处理
- AI自主决策
- 无预制流程

核心设计原则：
1. AI完全自主决策下一步行动
2. 没有预制的"先探索后攻击"流程
3. 每一轮都由AI根据当前状态决定做什么
4. 工具调用由AI主动发起，不是被动分配

集成系统:
- Memory系统: 记录发现和状态
- Skill系统: 提供领域知识建议
- 时间管理: 超时控制
"""

from typing import AsyncGenerator, Dict, Any, List, Optional
from dataclasses import dataclass, field
import asyncio
import json
import re

from app.llm_client import llm_client, LLMResult, LLMErrorType
from app.logger import get_logger
from app.tools_v2.tool_factory import get_tool_registry_v2
from app.tools_v2.ctf_tools import register_ctf_tools
from app.tools_v2.deferred_loader import get_deferred_tool_registry
from app.memory import get_agent_memory
from app.agents.base import AgentType
from app.skills import get_skill_registry

logger = get_logger("Query")

# 确保工具已注册
_tools_registered = False


def ensure_tools_registered():
    """确保工具已注册"""
    global _tools_registered
    if not _tools_registered:
        register_ctf_tools()
        _tools_registered = True


@dataclass
class QueryConfig:
    """查询配置"""
    model: str
    max_turns: int = 200
    system_prompt: str = ""
    tools: List[Dict] = field(default_factory=list)
    permission_mode: str = "default"  # default, auto, interactive


@dataclass
class ToolCallRequest:
    """工具调用请求"""
    tool_name: str
    tool_id: str
    arguments: Dict[str, Any]


@dataclass
class ToolCallResult:
    """工具调用结果"""
    tool_id: str
    tool_name: str
    result: Any
    success: bool
    error: Optional[str] = None


async def query(
    messages: List[Dict],
    config_obj: QueryConfig,
) -> AsyncGenerator[Dict, None]:
    """
    Claude Code核心查询循环

    完全复制Claude Code的query.ts逻辑:
    1. 调用LLM API（真实调用）
    2. 处理响应内容
    3. 检查是否有工具调用请求
    4. 如果有工具调用，通过ToolRegistry执行
    5. 将工具结果返回给LLM
    6. 循环直到无工具调用或达到max_turns

    Args:
        messages: 消息列表
        config_obj: 查询配置

    Yields:
        事件字典，包含类型和相关信息
    """
    # 确保工具已注册
    ensure_tools_registered()

    turn_count = 0

    # 初始化Memory系统
    memory = get_agent_memory()

    # 构建系统提示（如果有）
    if config_obj.system_prompt:
        # 确保系统消息在开头
        if not messages or messages[0].get("role") != "system":
            messages.insert(0, {
                "role": "system",
                "content": config_obj.system_prompt
            })

    # 获取工具注册表
    registry = get_tool_registry_v2()

    # 提取目标信息用于Memory记录
    target = None
    for msg in messages:
        if msg.get("role") == "user":
            content = msg.get("content", "")
            # 尝试提取URL或IP
            url_match = re.search(r'https?://[^\s]+', content)
            ip_match = re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', content)
            if url_match:
                target = url_match.group(0)
            elif ip_match:
                target = ip_match.group(0)
            if target:
                break

    while turn_count < config_obj.max_turns:
        turn_count += 1

        logger.info(f"[Query] Turn {turn_count}/{config_obj.max_turns}")

        # 动态获取当前上下文应该加载的工具（延迟加载）
        context = {
            "turn": turn_count,
            "messages": messages[-5:],  # 最近5条消息
            "system_prompt": config_obj.system_prompt,
        }

        # 获取延迟加载注册表
        deferred_registry = get_deferred_tool_registry()

        # 根据上下文获取应加载的工具Schema
        dynamic_tool_schemas = deferred_registry.get_tool_schemas_for_context(
            context,
            include_deferred=False  # 只加载当前应该加载的
        )

        # 如果配置中没有指定工具，使用动态工具
        tools_to_use = config_obj.tools if config_obj.tools else dynamic_tool_schemas

        logger.info(f"[Query] Active tools: {len(tools_to_use)} schemas")

        # Skill推荐集成 - 获取领域知识建议
        skill_suggestions = await _get_skill_suggestions(context, target, turn_count)
        if skill_suggestions:
            # 将Skill建议注入到当前轮次的消息中
            logger.info(f"[Query] Skill建议: {skill_suggestions.get('skill_name', 'unknown')}")

        # 1. 原生异步LLM API调用
        try:
            response = await llm_client.call_with_details(
                model=config_obj.model,
                messages=messages,
                temperature=0.1,
                timeout=120,  # 单次调用超时
                tools=tools_to_use,  # 使用动态工具列表
                tool_choice="auto",
            )
        except Exception as e:
            logger.error(f"[Query] LLM调用异常: {e}")
            yield {
                "type": "error",
                "error": str(e),
                "error_type": "llm_exception",
                "turn": turn_count,
            }
            return

        # 2. 处理响应
        if not response.success:
            logger.error(f"[Query] LLM调用失败: {response.error_type} - {response.error_message}")
            yield {
                "type": "error",
                "error": response.error_message,
                "error_type": response.error_type.value,
                "turn": turn_count,
            }
            return

        content = response.content
        tool_calls = response.tool_calls

        # 构建助手消息（包含tool_calls）
        assistant_message = {
            "role": "assistant",
            "content": content,
        }

        # 如果有工具调用，添加到消息中
        if tool_calls:
            assistant_message["tool_calls"] = tool_calls

        messages.append(assistant_message)

        # Yield消息给外部观察者
        yield {
            "type": "message",
            "message": assistant_message,
            "turn": turn_count,
            "duration": response.duration,
        }

        # 3. 检查完成信号（AI自主决策完成）
        if _detect_completion(content):
            logger.info(f"[Query] AI报告任务完成 (Turn {turn_count})")
            yield {
                "type": "complete",
                "reason": "task_done",
                "turn": turn_count,
            }
            return

        # 4. 检查是否有flag（CTF场景）
        flag = _extract_flag(content)
        if flag:
            logger.info(f"[Query] 发现FLAG: {flag}")
            yield {
                "type": "flag_found",
                "flag": flag,
                "turn": turn_count,
            }

            # 记录到Memory系统
            if target:
                try:
                    await memory.write_finding(
                        agent_type=AgentType.COORDINATOR,
                        target=target,
                        topic="flags",
                        data={
                            "flag": flag,
                            "turn": turn_count,
                            "context": content[:200]
                        }
                    )
                    logger.info(f"[Query] Flag已记录到Memory")
                except Exception as e:
                    logger.warning(f"[Query] Memory写入失败: {e}")

            # 找到flag后继续，可能还有更多flag

        # 5. 检查是否有工具调用请求（使用ToolRegistry模式）
        if tool_calls:
            tool_results = []

            for tool_call in tool_calls:
                # 解析工具调用
                tool_id = tool_call.get("id", f"call_{turn_count}")
                function = tool_call.get("function", {})
                tool_name = function.get("name", "")

                try:
                    arguments = json.loads(function.get("arguments", "{}"))
                except json.JSONDecodeError:
                    arguments = {}

                tool_call_request = ToolCallRequest(
                    tool_name=tool_name,
                    tool_id=tool_id,
                    arguments=arguments,
                )

                yield {
                    "type": "tool_call_request",
                    "tool_call": tool_call_request,
                    "turn": turn_count,
                }

                # 通过ToolRegistry执行工具（Claude Code模式）
                result = await execute_tool_via_registry(
                    tool_name=tool_name,
                    tool_input=arguments,
                    tool_id=tool_id,
                    registry=registry,
                )

                tool_results.append(result)

                yield {
                    "type": "tool_result",
                    "tool_name": tool_name,
                    "tool_id": tool_id,
                    "result": result,
                    "turn": turn_count,
                }

                # 记录重要发现到Memory系统
                if target and result.get("success"):
                    await _record_tool_result_to_memory(
                        memory=memory,
                        tool_name=tool_name,
                        result=result,
                        target=target,
                        turn=turn_count
                    )

            # 将工具结果添加到消息（使用智谱API格式）
            for result in tool_results:
                messages.append({
                    "role": "tool",
                    "tool_call_id": result["tool_use_id"],
                    "content": json.dumps(result["content"], ensure_ascii=False),
                })

            # 继续下一轮循环处理工具结果
            continue

        # 5.5. 如果API没有返回tool_calls，尝试从文本中解析工具调用
        # 这是为了兼容不支持function calling的模型（如GLM-5）
        text_tool_calls = _extract_tool_calls_from_text(content)
        if text_tool_calls:
            logger.info(f"[Query] 从文本中解析到 {len(text_tool_calls)} 个工具调用")
            tool_results = []

            for tool_call_req in text_tool_calls:
                yield {
                    "type": "tool_call_request",
                    "tool_call": tool_call_req,
                    "turn": turn_count,
                }

                # 执行工具
                result = await execute_tool_via_registry(
                    tool_name=tool_call_req.tool_name,
                    tool_input=tool_call_req.arguments,
                    tool_id=tool_call_req.tool_id,
                    registry=registry,
                )

                tool_results.append(result)

                yield {
                    "type": "tool_result",
                    "tool_name": tool_call_req.tool_name,
                    "tool_id": tool_call_req.tool_id,
                    "result": result,
                    "turn": turn_count,
                }

            # 将工具结果添加到消息（使用user角色，因为不是标准function calling）
            for result in tool_results:
                result_text = json.dumps(result["content"], ensure_ascii=False, indent=2)
                messages.append({
                    "role": "user",
                    "content": f"Tool '{result.get('tool_name', 'unknown')}' execution result:\n```\n{result_text}\n```",
                })

            # 继续下一轮
            continue

        # 6. 检查是否需要等待用户输入
        if _detect_user_input_needed(content):
            yield {
                "type": "waiting_for_user",
                "prompt": _extract_user_prompt(content),
                "turn": turn_count,
            }
            # 等待外部提供用户输入后继续

        # 7. 没有工具调用，继续下一轮
        yield {
            "type": "turn_complete",
            "turn": turn_count,
        }

        # 如果没有工具调用且没有明确完成信号，继续循环
        # AI会在下一轮自行决定做什么

    # 达到最大轮数
    logger.warning(f"[Query] 达到最大轮数 {config_obj.max_turns}")
    yield {
        "type": "complete",
        "reason": "max_turns_reached",
        "turn": turn_count,
    }


async def execute_tool_via_registry(
    tool_name: str,
    tool_input: Dict,
    tool_id: str,
    registry: Any,
) -> Dict:
    """
    通过ToolRegistry执行工具

    遵循Claude Code模式:
    - 从Registry获取工具
    - 执行工具
    - 错误直接返回给AI
    - 返回标准格式结果

    Args:
        tool_name: 工具名称
        tool_input: 工具输入参数
        tool_id: 工具调用ID
        registry: ToolRegistry实例

    Returns:
        标准格式的工具结果
    """
    # 从Registry获取工具
    tool = registry.get_tool(tool_name)

    if not tool:
        # 工具不存在 - 返回错误给AI
        logger.warning(f"[Query] Tool '{tool_name}' not found in registry")
        return {
            "tool_use_id": tool_id,
            "content": {"error": f"Tool '{tool_name}' not found. Available tools: {registry.list_tools()}"},
            "is_error": True,
        }

    try:
        # 执行工具 - 简化参数，只传必要参数
        logger.info(f"[Query] Executing tool: {tool_name} with input: {tool_input}")

        # 调用工具的execute方法
        # 注意: 这里不再传递context和agent_type，让工具内部决定
        result = await tool.execute(
            params=tool_input,
            context={},  # 空context，工具可以自行填充
            agent_type=None,  # 不限制权限
        )

        # 转换结果格式
        if result.success:
            return {
                "tool_use_id": tool_id,
                "content": result.output if isinstance(result.output, dict) else {"result": result.output},
                "is_error": False,
            }
        else:
            # 执行失败 - 直接返回错误给AI（无降级）
            return {
                "tool_use_id": tool_id,
                "content": {"error": result.error or "Unknown error"},
                "is_error": True,
            }

    except Exception as e:
        # 执行异常 - 直接返回错误给AI（让其自我纠错）
        logger.error(f"[Query] Tool execution error: {tool_name} - {e}")
        return {
            "tool_use_id": tool_id,
            "content": {"error": f"Execution error: {str(e)}"},
            "is_error": True,
        }


def _extract_tool_calls_from_text(response: str) -> List[ToolCallRequest]:
    """
    从文本响应中提取工具调用请求

    用于兼容不支持function calling的模型（如GLM-5）

    支持多种格式:
    1. JSON格式: {"tool": "name", "args": {...}}
    2. 函数调用格式: tool_name(arg1=val1, arg2=val2)
    """
    tool_calls = []

    # 1. JSON格式检测
    json_pattern = r'\{[^{}]*"tool"\s*:\s*"([^"]+)"[^{}]*"args"\s*:\s*\{[^{}]*\}[^{}]*\}'
    json_matches = re.findall(json_pattern, response)

    for tool_name in json_matches:
        try:
            # 找到完整的JSON对象
            full_json_pattern = r'\{[^{}]*"tool"\s*:\s*"' + tool_name + r'"[^{}]*\}'
            full_match = re.search(full_json_pattern, response)
            if full_match:
                data = json.loads(full_match.group(0))
                tool_calls.append(ToolCallRequest(
                    tool_name=data.get("tool"),
                    tool_id=f"call_{len(tool_calls)}",
                    arguments=data.get("args", {}),
                ))
        except:
            pass

    # 2. 函数调用格式检测
    func_pattern = r'(\w+)\s*\(\s*([^)]*)\s*\)'
    func_matches = re.findall(func_pattern, response)

    for tool_name, args_str in func_matches:
        # 排除常见的非工具调用
        if tool_name.lower() in ['print', 'log', 'if', 'for', 'while', 'def', 'class', 'function']:
            continue

        # 解析参数
        args = {}
        if args_str:
            # 尝试解析 key=value 格式
            arg_pairs = re.findall(r'(\w+)\s*=\s*([^,)]+)', args_str)
            for key, val in arg_pairs:
                # 清理值
                val = val.strip().strip('"').strip("'")
                args[key] = val

        if tool_name not in [tc.tool_name for tc in tool_calls]:
            tool_calls.append(ToolCallRequest(
                tool_name=tool_name,
                tool_id=f"call_{len(tool_calls)}",
                arguments=args,
            ))

    return tool_calls


def _detect_completion(response: str) -> bool:
    """
    检测AI是否认为任务完成

    Claude Code模式:
    - AI通过System Prompt指导使用特定标记表达完成
    - 系统只检测AI主动发出的完成信号
    - 不通过语义分析猜测AI意图

    System Prompt应指导AI:
    - 完成时输出[TASK_COMPLETE]标记
    - 或在tool_call中使用complete动作
    """
    if not response:
        return False

    # 只检测AI主动发出的明确完成信号
    # 这些标记由System Prompt指导AI使用
    completion_markers = [
        "[TASK_COMPLETE]",
        "[MISSION_ACCOMPLISHED]",
        "[TASK_DONE]",
    ]

    for marker in completion_markers:
        if marker in response:
            return True

    return False


def _extract_flag(response: str) -> Optional[str]:
    """
    从响应中提取flag

    Claude Code模式:
    - AI通过report_flag工具主动报告flag
    - 此函数只作为辅助验证和日志记录
    - 不强制匹配任何格式

    AI主导流程:
    1. AI识别flag后调用report_flag工具
    2. 工具执行结果返回给AI确认
    3. 此函数辅助提取用于日志和验证
    """
    # Claude Code模式: AI通过工具报告flag
    # 此函数仅作为辅助，不主动提取
    # 如果AI在响应中明确展示了flag，可以辅助提取用于验证

    # 仅在AI明确标记flag时提取
    # 例如: AI说 "找到flag: flag{xxx}" 时辅助提取
    flagged_pattern = r"(?:found|captured|obtained|flag)\s*[:：]\s*(flag\{[^}]+\}|FLAG\{[^}]+\})"
    match = re.search(flagged_pattern, response, re.IGNORECASE)

    if match:
        return match.group(1)

    return None


def _detect_user_input_needed(response: str) -> bool:
    """
    检测是否需要用户输入

    Claude Code模式:
    - AI通过System Prompt指导使用明确标记
    - 不使用过于宽泛的检测（如"?"）
    - AI主动表达需要输入的意图
    """
    if not response:
        return False

    # 明确的输入请求标记（AI主动表达）
    explicit_markers = [
        "[NEED_INPUT]",
        "[WAITING_FOR_INPUT]",
        "[USER_INPUT_REQUIRED]",
    ]

    for marker in explicit_markers:
        if marker in response:
            return True

    # 辅助检测：明确的请求语句
    request_phrases = [
        "Please provide",
        "Please enter",
        "I need input",
        "Waiting for input",
        "请提供",
        "请输入",
        "需要输入",
    ]

    response_lower = response.lower()
    for phrase in request_phrases:
        if phrase.lower() in response_lower:
            return True

    return False


def _extract_user_prompt(response: str) -> str:
    """提取需要用户输入的提示"""
    # 尝试明确的问题
    question_pattern = r'([^.!?]*\?)'
    match = re.search(question_pattern, response)
    if match:
        return match.group(1).strip()

    # 尝试请求输入的句子
    request_patterns = [
        r'Please provide[^.]*',
        r'Please enter[^.]*',
        r'请提供[^.]*',
        r'请输入[^.]*',
    ]

    for pattern in request_patterns:
        match = re.search(pattern, response)
        if match:
            return match.group(0).strip()

    return "请提供输入"


async def _get_skill_suggestions(
    context: Dict,
    target: Optional[str],
    turn: int
) -> Optional[Dict[str, Any]]:
    """
    获取Skill系统推荐

    Claude Code模式:
    - Skill提供领域知识和工具推荐
    - 根据当前上下文智能匹配
    - 不硬编码决策，只提供建议

    Args:
        context: 当前上下文
        target: 目标标识
        turn: 当前轮次

    Returns:
        Skill建议字典，如果没有匹配则返回None
    """
    try:
        skill_registry = get_skill_registry()

        # 扩展上下文用于Skill匹配
        skill_context = {
            **context,
            "target": target,
            "turn": turn,
        }

        # 查找匹配的Skills
        matching_skills = skill_registry.find_matching_skills(skill_context)

        if not matching_skills:
            return None

        # 使用最佳匹配的Skill
        best_skill = matching_skills[0]

        # 提取工具推荐
        tool_prefs = best_skill.tool_preferences
        recommended_tools = []
        if tool_prefs:
            sorted_prefs = sorted(tool_prefs, key=lambda x: x.score, reverse=True)
            recommended_tools = [pref.tool_name for pref in sorted_prefs[:3]]

        # 提取工作流建议
        workflow_hints = []
        if best_skill.workflows:
            for workflow in best_skill.workflows[:1]:
                if workflow.steps:
                    workflow_hints = [step.description for step in workflow.steps[:3]]

        return {
            "skill_name": best_skill.name,
            "description": best_skill.description,
            "recommended_tools": recommended_tools,
            "workflow_hints": workflow_hints,
            "knowledge": best_skill.knowledge[:500] if best_skill.knowledge else None,
        }

    except Exception as e:
        logger.warning(f"[Skill] 获取建议失败: {e}")
        return None


async def _record_tool_result_to_memory(
    memory,
    tool_name: str,
    result: Dict,
    target: str,
    turn: int
):
    """
    将工具结果中的重要发现记录到Memory系统

    Claude Code模式:
    - 自动记录重要发现供后续使用
    - 支持跨Agent通信
    - 知识积累

    Args:
        memory: Memory系统实例
        tool_name: 工具名称
        result: 工具执行结果
        target: 目标标识
        turn: 当前轮次
    """
    try:
        content = result.get("content", {})
        if isinstance(content, str):
            # 尝试解析JSON
            try:
                content = json.loads(content)
            except:
                content = {"raw": content}

        # 扫描工具结果处理
        if tool_name in ["nmap", "nuclei", "httpx", "fscan"]:
            # 端口发现
            if isinstance(content, dict):
                open_ports = content.get("open_ports", [])
                if open_ports:
                    await memory.write_finding(
                        agent_type=AgentType.EXPLORE,
                        target=target,
                        topic="endpoints",
                        data={
                            "type": "open_ports",
                            "ports": open_ports,
                            "source_tool": tool_name,
                            "turn": turn
                        }
                    )
                    logger.info(f"[Memory] 记录端口发现: {len(open_ports)} 个")

                # 漏洞发现
                vulnerabilities = content.get("vulnerabilities", [])
                if vulnerabilities:
                    await memory.write_finding(
                        agent_type=AgentType.EXPLORE,
                        target=target,
                        topic="vulns",
                        data={
                            "type": "vulnerabilities",
                            "vulns": vulnerabilities,
                            "source_tool": tool_name,
                            "turn": turn
                        }
                    )
                    logger.info(f"[Memory] 记录漏洞发现: {len(vulnerabilities)} 个")

        # 攻击工具结果处理
        elif tool_name in ["sqlmap", "ffuf", "dirsearch"]:
            if isinstance(content, dict):
                # 凭据发现
                credentials = content.get("credentials", [])
                if credentials:
                    await memory.write_finding(
                        agent_type=AgentType.ATTACK,
                        target=target,
                        topic="credentials",
                        data={
                            "type": "credentials",
                            "creds": credentials,
                            "source_tool": tool_name,
                            "turn": turn
                        }
                    )
                    logger.info(f"[Memory] 记录凭据发现: {len(credentials)} 个")

                # 数据提取
                data_extracted = content.get("data", [])
                if data_extracted:
                    await memory.write_finding(
                        agent_type=AgentType.ATTACK,
                        target=target,
                        topic="extracted_data",
                        data={
                            "type": "extracted_data",
                            "data": data_extracted,
                            "source_tool": tool_name,
                            "turn": turn
                        }
                    )

    except Exception as e:
        logger.warning(f"[Memory] 记录工具结果失败: {e}")


# 同步版本（用于简单场景）
def query_sync(
    messages: List[Dict],
    config_obj: QueryConfig,
) -> List[Dict]:
    """
    同步版本的Query循环

    返回所有事件列表
    """
    events = []

    async def run():
        async for event in query(messages, config_obj):
            events.append(event)

    asyncio.run(run())

    return events


__all__ = [
    "query",
    "query_sync",
    "QueryConfig",
    "ToolCallRequest",
    "ToolCallResult",
    "execute_tool_via_registry",
]