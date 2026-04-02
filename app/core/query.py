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
"""

from typing import AsyncGenerator, Dict, Any, List, Optional
from dataclasses import dataclass, field
import asyncio
import re

from app.llm_client import llm_client, LLMResult, LLMErrorType
from app.logger import get_logger

logger = get_logger("Query")


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
    tool_executor: Optional[Any] = None,
) -> AsyncGenerator[Dict, None]:
    """
    Claude Code核心查询循环

    完全复制Claude Code的query.ts逻辑:
    1. 调用LLM API（真实调用）
    2. 处理响应内容
    3. 检查是否有工具调用请求
    4. 如果有工具调用，执行工具（需要tool_executor）
    5. 将工具结果返回给LLM
    6. 循环直到无工具调用或达到max_turns

    Args:
        messages: 消息列表
        config_obj: 查询配置
        tool_executor: 工具执行器（可选，用于处理工具调用）

    Yields:
        事件字典，包含类型和相关信息
    """
    turn_count = 0

    # 构建系统提示（如果有）
    if config_obj.system_prompt:
        # 确保系统消息在开头
        if not messages or messages[0].get("role") != "system":
            messages.insert(0, {
                "role": "system",
                "content": config_obj.system_prompt
            })

    while turn_count < config_obj.max_turns:
        turn_count += 1

        logger.info(f"[Query] Turn {turn_count}/{config_obj.max_turns}")

        # 1. 真实调用LLM API
        try:
            # 使用同步的llm_client，需要在async中执行
            response = await asyncio.to_thread(
                llm_client.call_with_details,
                model=config_obj.model,
                messages=messages,
                temperature=0.1,
                timeout=120,  # 单次调用超时
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

        # 构建助手消息
        assistant_message = {
            "role": "assistant",
            "content": content,
        }
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
            # 找到flag后继续，可能还有更多flag

        # 5. 检查是否有工具调用请求
        tool_calls = _extract_tool_calls(content)

        if tool_calls and tool_executor:
            # 处理每个工具调用
            for tool_call in tool_calls:
                yield {
                    "type": "tool_call_request",
                    "tool_call": tool_call,
                    "turn": turn_count,
                }

                # 执行工具（真实执行）
                try:
                    tool_result = await asyncio.to_thread(
                        tool_executor.execute,
                        tool_call.tool_name,
                        tool_call.arguments,
                    )

                    yield {
                        "type": "tool_call_result",
                        "tool_result": tool_result,
                        "turn": turn_count,
                    }

                    # 将工具结果添加到消息
                    messages.append({
                        "role": "user",
                        "content": _format_tool_result_message(tool_call, tool_result),
                    })

                except Exception as e:
                    logger.error(f"[Query] 工具执行异常: {tool_call.tool_name} - {e}")
                    error_result = ToolCallResult(
                        tool_id=tool_call.tool_id,
                        tool_name=tool_call.tool_name,
                        result=None,
                        success=False,
                        error=str(e),
                    )

                    yield {
                        "type": "tool_call_result",
                        "tool_result": error_result,
                        "turn": turn_count,
                    }

                    # 将错误信息返回给AI
                    messages.append({
                        "role": "user",
                        "content": f"Tool '{tool_call.tool_name}' execution failed: {str(e)}",
                    })

            # 继续下一轮循环处理工具结果
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


def _detect_completion(response: str) -> bool:
    """检测AI是否认为任务完成"""
    completion_markers = [
        "TASK_COMPLETE",
        "TASK_DONE",
        "MISSION_COMPLETE",
        "All objectives achieved",
        "Challenge solved",
        "FLAG successfully extracted",
        "任务完成",
        "已完成所有目标",
    ]

    response_lower = response.lower()
    for marker in completion_markers:
        if marker.lower() in response_lower:
            # 确保不是仅仅提到这些词，而是确实完成
            # 检查是否有明确的完成声明
            if "i have completed" in response_lower or "completed" in response_lower:
                return True
            if "任务已完成" in response or "已完成" in response:
                return True

    return False


def _extract_flag(response: str) -> Optional[str]:
    """从响应中提取flag"""
    patterns = [
        r'flag\{[^}]+\}',
        r'FLAG\{[^}]+\}',
        r'ctf\{[^}]+\}',
        r'CTF\{[^}]+\}',
        r'hctf\{[^}]+\}',
        r'HCTF\{[^}]+\}',
        r'actf\{[^}]+\}',
        r'ACTF\{[^}]+\}',
    ]

    for pattern in patterns:
        match = re.search(pattern, response, re.IGNORECASE)
        if match:
            return match.group(0)

    return None


def _extract_tool_calls(response: str) -> List[ToolCallRequest]:
    """
    从响应中提取工具调用请求

    支持多种格式:
    1. JSON格式: {"tool": "name", "args": {...}}
    2. 函数调用格式: tool_name(arg1=val1, arg2=val2)
    3. Markdown代码块格式
    """
    tool_calls = []

    # 1. JSON格式检测
    json_pattern = r'\{[^{}]*"tool"\s*:\s*"([^"]+)"[^{}]*"args"\s*:\s*\{[^{}]*\}[^{}]*\}'
    json_matches = re.findall(json_pattern, response)

    for tool_name in json_matches:
        # 尝试解析完整的JSON
        try:
            # 找到完整的JSON对象
            full_json_pattern = r'\{[^{}]*"tool"\s*:\s*"' + tool_name + r'"[^{}]*\}'
            full_match = re.search(full_json_pattern, response)
            if full_match:
                import json
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


def _detect_user_input_needed(response: str) -> bool:
    """检测是否需要用户输入"""
    markers = [
        "Please provide",
        "Please enter",
        "Waiting for input",
        "请提供",
        "请输入",
        "?",  # 问题标记
    ]

    for marker in markers:
        if marker in response:
            return True

    return False


def _extract_user_prompt(response: str) -> str:
    """提取需要用户输入的提示"""
    # 尝找明确的问题
    question_pattern = r'([^.!?]*\?)'
    match = re.search(question_pattern, response)
    if match:
        return match.group(1).strip()

    # 尝找请求输入的句子
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


def _format_tool_result_message(tool_call: ToolCallRequest, result: ToolCallResult) -> str:
    """格式化工具结果消息"""
    if result.success:
        return f"Tool '{tool_call.tool_name}' executed successfully. Result: {result.result}"
    else:
        return f"Tool '{tool_call.tool_name}' execution failed: {result.error}"


class SimpleToolExecutor:
    """简单的工具执行器示例"""

    def __init__(self, tools: Dict[str, Any]):
        """
        Args:
            tools: 工具名称到工具函数的映射
        """
        self.tools = tools

    def execute(self, tool_name: str, arguments: Dict[str, Any]) -> ToolCallResult:
        """执行工具"""
        if tool_name not in self.tools:
            return ToolCallResult(
                tool_id=f"call_{tool_name}",
                tool_name=tool_name,
                result=None,
                success=False,
                error=f"Tool '{tool_name}' not found",
            )

        try:
            tool_func = self.tools[tool_name]
            result = tool_func(**arguments)

            return ToolCallResult(
                tool_id=f"call_{tool_name}",
                tool_name=tool_name,
                result=result,
                success=True,
            )
        except Exception as e:
            return ToolCallResult(
                tool_id=f"call_{tool_name}",
                tool_name=tool_name,
                result=None,
                success=False,
                error=str(e),
            )


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
    "SimpleToolExecutor",
]