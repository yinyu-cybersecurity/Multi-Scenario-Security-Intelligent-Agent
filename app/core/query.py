# app/core/query.py

"""
极简Query循环 - 框架只做管道，智能全在AI端

核心原则：
1. 框架做得越少越好，AI做得越多越好
2. 循环本身是无状态的管道，所有智能都在AI端
3. 框架仅干预2件事：超时熔断、循环检测
"""

from typing import AsyncGenerator, Dict, List
from dataclasses import dataclass
import hashlib
import json

from app.llm_client import llm_client
from app.logger import get_logger
from app.tools_v2.mcp.client import get_mcp_client
from app.core.loop_detector import LoopDetector
from app.core.time_manager import TimeBudget

logger = get_logger("Query")


@dataclass
class QueryConfig:
    """查询配置"""
    model: str
    max_turns: int = 50
    timeout_seconds: int = 1800
    system_prompt: str = ""


async def query(
    messages: List[Dict],
    config: QueryConfig,
) -> AsyncGenerator[Dict, None]:
    """极简Query循环。框架只做消息传递+超时熔断+循环检测。"""

    # === 初始化MCP工具 ===
    from app.tools_v2.mcp.client import ensure_mcp_tools_registered
    await ensure_mcp_tools_registered()

    # 获取工具schemas（从MCP客户端获取）
    client = get_mcp_client()
    tool_schemas = client.get_all_tool_schemas()
    time_budget = TimeBudget(config.timeout_seconds)
    loop_detector = LoopDetector()

    for turn in range(1, config.max_turns + 1):
        # === 超时检查（唯一强制熔断） ===
        if time_budget.is_timeout:
            messages.append({"role": "system", "content": "[TIMEOUT] 时间耗尽。立即输出当前最佳结果。"})
            response = await llm_client.call_with_details(
                model=config.model,
                messages=messages,
                tools=tool_schemas,
                temperature=0.1,
            )
            yield {"type": "assistant_message", "content": response.content}
            yield {"type": "complete", "reason": "timeout"}
            return

        # === 时间警告（非阻塞） ===
        if time_budget.remaining_ratio < 0.2:
            messages.append({"role": "system", "content": f"[TIME_WARNING] 剩余时间: {int(time_budget.remaining_seconds)}s。立即收敛。"})

        # === LLM调用 ===
        response = await llm_client.call_with_details(
            model=config.model,
            messages=messages,
            tools=tool_schemas,
            temperature=0.1,
        )

        content = response.content or ""
        tool_calls = response.tool_calls or []

        # 构建消息（不包含空的tool_calls字段）
        msg = {"role": "assistant", "content": content}
        if tool_calls:
            msg["tool_calls"] = tool_calls
        messages.append(msg)
        yield {"type": "assistant_message", "content": content, "turn": turn, "tool_calls": tool_calls}

        # === 执行工具（如果有）===
        for tc in tool_calls:
            tool_id = tc.get("id", f"call_{turn}")
            function = tc.get("function", {})
            tool_name = function.get("name", "")

            try:
                arguments = json.loads(function.get("arguments", "{}"))
            except json.JSONDecodeError:
                arguments = {}

            # 循环检测
            args_hash = hashlib.md5(json.dumps(arguments, sort_keys=True).encode()).hexdigest()[:8]
            if loop_detector.record(tool_name, args_hash):
                messages.append({"role": "tool", "tool_call_id": tool_id, "content": loop_detector.get_warning()})
                yield {"type": "loop_detected", "tool": tool_name}
                continue

            # 执行工具（通过MCP）
            try:
                result = await client.call_tool(tool_name, arguments)
                result_str = str(result)
            except Exception as e:
                result_str = json.dumps({"status": "error", "error": str(e)})

            logger.info(f"[Query] Tool result for {tool_name}: {result_str[:500]}...")
            messages.append({"role": "tool", "tool_call_id": tool_id, "content": result_str})
            yield {"type": "tool_result", "tool_name": tool_name}

    yield {"type": "complete", "reason": "max_turns"}


__all__ = ["query", "QueryConfig"]