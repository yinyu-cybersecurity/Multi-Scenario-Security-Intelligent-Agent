# app/core/query.py

"""
核心 Query 循环 - 对齐 Claude Code 架构

核心原则：
1. 框架做得越少越好，AI做得越多越好
2. 循环只是消息管道 + 工具执行器
3. 框架仅干预：超时熔断、循环检测、上下文窗口管理
4. AI完全自主决策攻击策略、工具选择、任务切换

企业级改进：
- 上下文窗口管理（消息截断，防止 context_length 错误）
- 并行工具执行
- 优雅错误恢复（LLM 错误不中断循环）
- 结构化事件流
- 比赛全自主模式支持
"""

from typing import AsyncGenerator, Dict, List, Optional
from dataclasses import dataclass
import asyncio
import hashlib
import json
import re
import time

from app.llm_client import llm_client, LLMErrorType
from app.logger import get_logger
from app.tools_v2.mcp.client import get_mcp_client
from app.core.loop_detector import LoopDetector
from app.core.time_manager import TimeBudget
from app.memory.token_stats import get_token_stats_manager

logger = get_logger("Query")


# ============================================================================
# Flag 自动检测
# ============================================================================

# 常见 CTF flag 格式（覆盖主流平台）
FLAG_PATTERNS = [
    re.compile(r'flag\{[^}]+\}', re.IGNORECASE),
    re.compile(r'FLAG\{[^}]+\}'),
    re.compile(r'ctf\{[^}]+\}', re.IGNORECASE),
    re.compile(r'key\{[^}]+\}', re.IGNORECASE),
    re.compile(r'NSSCTF\{[^}]+\}', re.IGNORECASE),      # NSSCTF 平台
    re.compile(r'ACTF\{[^}]+\}', re.IGNORECASE),        # ACTF 平台
    re.compile(r'SCTF\{[^}]+\}', re.IGNORECASE),        # SCTF 平台
    re.compile(r'[A-Z]+CTF\{[^}]+\}', re.IGNORECASE),   # 通配: XXCTF{...}
    re.compile(r'hgame\{[^}]+\}', re.IGNORECASE),       # HGAME 平台
    re.compile(r'syc\{[^}]+\}', re.IGNORECASE),         # SYC 平台
]


def _scan_for_flags(text: str) -> list:
    """扫描文本中的疑似 flag，返回去重列表"""
    if not text:
        return []
    flags = []
    seen = set()
    for pattern in FLAG_PATTERNS:
        for match in pattern.findall(text):
            if match not in seen:
                seen.add(match)
                flags.append(match)
    return flags


# ============================================================================
# 切题上下文清理
# ============================================================================

def _is_challenge_switch(tool_calls: list) -> Optional[str]:
    """检测是否正在切换题目（调用了 start_challenge），返回 challenge code"""
    for tc in tool_calls:
        func = tc.get("function", {})
        name = func.get("name", "")
        if name.endswith("start_challenge"):
            try:
                args = json.loads(func.get("arguments", "{}"))
                return args.get("code", "")
            except Exception:
                return ""
    return None


def reset_context_for_new_challenge(
    messages: List[Dict],
    challenge_code: str,
) -> List[Dict]:
    """
    切题时重置上下文 — 保留 system prompt + 最近 5 条消息

    注入提示让 AI 用 recall 恢复记忆
    """
    if len(messages) <= 6:
        return messages  # 消息太少，不需要清理

    system_prompt = messages[0]  # 始终保留
    recent = messages[-5:]        # 保留最近 5 条（包含 start_challenge 的调用和结果）

    # 构建切题通知
    switch_notice = {
        "role": "system",
        "content": (
            f"[CHALLENGE_SWITCH] Switched to challenge: {challenge_code}\n"
            f"Previous context has been cleared to save tokens.\n"
            f"Use recall(query=\"{challenge_code}\") to retrieve any previous progress on this challenge.\n"
            f"Use recall(query=\"progress\") to review overall competition status."
        ),
    }

    logger.info(f"[Query] Context reset for challenge switch: {challenge_code}, kept {len(recent)} recent messages")
    return [system_prompt, switch_notice] + recent


# ============================================================================
# 配置
# ============================================================================

@dataclass
class QueryConfig:
    """Query 循环配置"""
    model: str = ""
    max_turns: int = 200
    timeout_seconds: int = 1800
    system_prompt: str = ""
    # 上下文管理
    context_window_tokens: int = 120000
    context_reserve_tokens: int = 4000
    message_truncate_threshold: int = 8000
    # 并行工具
    parallel_tool_calls: bool = True
    # 模式控制
    auto_continue: bool = True  # 无工具调用时是否自动注入提示继续


# ============================================================================
# 上下文窗口管理
# ============================================================================

def _estimate_tokens(text: str) -> int:
    """粗略估算 token 数（中文约 1.5 char/token，英文约 4 char/token）"""
    if not text:
        return 0
    cn_chars = sum(1 for c in text if '\u4e00' <= c <= '\u9fff')
    en_chars = len(text) - cn_chars
    return int(cn_chars * 0.7 + en_chars * 0.25)


def _estimate_messages_tokens(messages: List[Dict]) -> int:
    """估算消息列表总 token 数"""
    total = 0
    for msg in messages:
        content = msg.get("content", "")
        if isinstance(content, str):
            total += _estimate_tokens(content)
        # tool_calls 也占 token
        if "tool_calls" in msg:
            total += _estimate_tokens(json.dumps(msg["tool_calls"], ensure_ascii=False))
    return total


def _truncate_message_content(content: str, max_chars: int = 8000) -> str:
    """截断单条消息内容，保留头尾"""
    if len(content) <= max_chars:
        return content
    keep = max_chars // 2
    return (
        content[:keep]
        + f"\n\n... [TRUNCATED {len(content) - max_chars} chars] ...\n\n"
        + content[-keep:]
    )


def manage_context_window(
    messages: List[Dict],
    max_tokens: int = 120000,
    reserve_tokens: int = 4000,
    truncate_threshold: int = 8000,
) -> List[Dict]:
    """
    管理上下文窗口，防止超长

    策略（对齐 Claude Code）：
    1. 保护 system prompt（第一条消息）
    2. 保护最近的消息（最新 20 条）
    3. 中间消息按时间从旧到新截断
    4. 单条过长消息截断
    """
    if not messages:
        return messages

    target_tokens = max_tokens - reserve_tokens

    # 先截断单条过长消息（tool 结果可能很长）
    for i, msg in enumerate(messages):
        content = msg.get("content", "")
        if isinstance(content, str) and len(content) > truncate_threshold:
            messages[i] = {**msg, "content": _truncate_message_content(content, truncate_threshold)}

    # 估算当前 token 数
    current_tokens = _estimate_messages_tokens(messages)
    if current_tokens <= target_tokens:
        return messages

    # 需要裁剪 - 保护首尾
    protected_head = 1  # system prompt
    protected_tail = min(20, len(messages) // 2)  # 最近的消息

    if len(messages) <= protected_head + protected_tail:
        return messages  # 消息太少，不裁剪

    # 从中间开始移除
    head = messages[:protected_head]
    tail = messages[-protected_tail:]
    middle = messages[protected_head:-protected_tail]

    # 从最旧的开始移除中间消息
    removed = 0
    while middle and _estimate_messages_tokens(head + middle + tail) > target_tokens:
        middle.pop(0)
        removed += 1

    if removed > 0:
        # 插入裁剪提示
        trim_notice = {
            "role": "system",
            "content": f"[CONTEXT_TRIMMED] 已移除 {removed} 条历史消息以适应上下文窗口。最近的对话已保留。",
        }
        result = head + [trim_notice] + middle + tail
        logger.info(f"[Query] Context trimmed: removed {removed} messages")
        return result

    return head + middle + tail


# ============================================================================
# 核心 Query 循环
# ============================================================================

async def query(
    messages: List[Dict],
    config: QueryConfig,
) -> AsyncGenerator[Dict, None]:
    """
    极简 Query 循环 - AI 完全自主

    框架职责（仅此 3 项）：
    1. 消息传递管道（LLM <-> Tools）
    2. 超时熔断 + 循环检测
    3. 上下文窗口管理

    事件类型：
    - assistant_message: AI 输出
    - tool_result: 工具执行结果
    - tool_error: 工具执行错误
    - loop_detected: 检测到循环调用
    - context_trimmed: 上下文被裁剪
    - task_complete: AI 自主结束（找到 FLAG）
    - complete: 循环结束（timeout / max_turns / error）
    """

    # === 初始化 ===
    from app.tools_v2.mcp.client import ensure_mcp_tools_registered
    mcp_ok = await ensure_mcp_tools_registered()
    if not mcp_ok:
        yield {"type": "complete", "reason": "mcp_connection_failed"}
        return

    client = get_mcp_client()
    tool_schemas = client.get_all_tool_schemas()
    time_budget = TimeBudget(config.timeout_seconds)
    loop_detector = LoopDetector()
    token_manager = get_token_stats_manager()

    # 从 settings 获取模型名
    if not config.model:
        from app.settings import config as app_config
        config.model = app_config.model.name

    consecutive_errors = 0
    max_consecutive_errors = 5

    for turn in range(1, config.max_turns + 1):

        # === 上下文窗口管理 ===
        old_len = len(messages)
        messages = manage_context_window(
            messages,
            max_tokens=config.context_window_tokens,
            reserve_tokens=config.context_reserve_tokens,
            truncate_threshold=config.message_truncate_threshold,
        )
        if len(messages) < old_len:
            yield {"type": "context_trimmed", "removed": old_len - len(messages)}

        # === 超时检查（唯一强制熔断）===
        if time_budget.is_timeout:
            messages.append({
                "role": "system",
                "content": (
                    "[TIMEOUT] 时间耗尽。立即输出当前最佳结果。"
                    "如果已找到FLAG，输出 [TASK_COMPLETE] FLAG: flag{xxx}"
                ),
            })
            response = await llm_client.call_with_details(
                model=config.model,
                messages=messages,
                tools=tool_schemas,
                temperature=0.1,
            )
            if response.success:
                yield {"type": "assistant_message", "content": response.content, "turn": turn}
                # 检查是否在超时时刻输出了 FLAG
                flags = _scan_for_flags(response.content or "")
                if flags:
                    yield {"type": "task_complete", "flags": flags, "reason": "timeout_with_flag"}
                    return
            yield {"type": "complete", "reason": "timeout"}
            return

        # === 时间警告（非阻塞）===
        remaining = time_budget.remaining_seconds
        ratio = time_budget.remaining_ratio
        if ratio < 0.1:
            messages.append({
                "role": "system",
                "content": f"[CRITICAL] 仅剩 {int(remaining)}s！必须立即收敛到最有可能的攻击路径。",
            })
        elif ratio < 0.2:
            messages.append({
                "role": "system",
                "content": f"[TIME_WARNING] 剩余 {int(remaining)}s。优先完成当前最有可能成功的攻击。",
            })

        # === Token 统计（每 15 轮提示一次）===
        if turn % 15 == 0:
            stats = token_manager.get_global_stats()
            messages.append({
                "role": "system",
                "content": f"[INFO] Turn {turn}/{config.max_turns} | Token: {stats.total_tokens:,} | Time: {int(remaining)}s remaining",
            })

        # === LLM 调用 ===
        response = await llm_client.call_with_details(
            model=config.model,
            messages=messages,
            tools=tool_schemas,
            temperature=0.1,
            timeout=120,
        )

        # 处理 LLM 错误
        if not response.success:
            consecutive_errors += 1

            if response.error_type == LLMErrorType.CONTEXT_LENGTH:
                # 上下文超长 -> 强制裁剪 50% 并重试
                logger.warning("[Query] Context length exceeded, force trimming...")
                half = len(messages) // 2
                messages = messages[:1] + messages[half:]
                messages.insert(1, {
                    "role": "system",
                    "content": "[CONTEXT_RESET] 上下文已大幅裁剪。请基于记忆（recall）恢复之前的进度。",
                })
                yield {"type": "context_trimmed", "removed": half, "reason": "context_length_error"}
                continue

            if consecutive_errors >= max_consecutive_errors:
                yield {"type": "complete", "reason": f"consecutive_errors_{consecutive_errors}"}
                return

            logger.warning(
                f"[Query] LLM error (attempt {consecutive_errors}): "
                f"{response.error_type.value} - {response.error_message}"
            )
            yield {"type": "llm_error", "error": response.error_message, "turn": turn}
            # LLM 客户端已有重试，这里额外等一下
            await asyncio.sleep(2)
            continue

        consecutive_errors = 0  # 重置连续错误计数

        content = response.content or ""
        tool_calls = response.tool_calls or []

        # 构建 assistant 消息
        msg = {"role": "assistant", "content": content}
        if tool_calls:
            msg["tool_calls"] = tool_calls
        messages.append(msg)

        yield {
            "type": "assistant_message",
            "content": content,
            "turn": turn,
            "tool_calls": tool_calls,
            "time_remaining": int(remaining),
        }

        # === AI 自主结束检测 ===
        if "[TASK_COMPLETE]" in content:
            flags = _scan_for_flags(content)
            yield {"type": "task_complete", "flags": flags, "reason": "ai_terminated"}
            return

        # === 无工具调用 = AI 认为任务结束 ===
        if not tool_calls:
            # 再检查一次是否有 flag 格式的内容
            flags = _scan_for_flags(content)
            if flags:
                yield {"type": "task_complete", "flags": flags, "reason": "flag_in_response"}
                return
            # REPL 模式：不自动继续，等待用户输入
            if not config.auto_continue:
                yield {"type": "complete", "reason": "awaiting_user_input"}
                return
            # 自动攻击模式：注入提示让 AI 继续
            messages.append({
                "role": "user",
                "content": "继续攻击。如果已完成，输出 [TASK_COMPLETE] FLAG: flag{xxx}。如果卡住了，换一种方法。",
            })
            continue

        # === 执行工具 ===
        # 检测切题 — 在执行前记录
        switch_code = _is_challenge_switch(tool_calls)

        if config.parallel_tool_calls and len(tool_calls) > 1:
            # 并行执行多个工具调用
            await _execute_tools_parallel(
                tool_calls, client, loop_detector, messages, turn,
            )
            for tc in tool_calls:
                yield {"type": "tool_result", "tool_name": tc.get("function", {}).get("name", "")}
        else:
            # 顺序执行
            for tc in tool_calls:
                tool_id = tc.get("id", f"call_{turn}")
                function = tc.get("function", {})
                tool_name = function.get("name", "")

                result_str = await _execute_single_tool(
                    tc, client, loop_detector, messages, turn,
                )

                if result_str == "__LOOP__":
                    yield {"type": "loop_detected", "tool": tool_name}
                else:
                    yield {"type": "tool_result", "tool_name": tool_name}

        # === 切题上下文清理（工具执行后）===
        if switch_code:
            old_len = len(messages)
            messages[:] = reset_context_for_new_challenge(messages, switch_code)
            loop_detector.reset()  # 重置循环检测
            yield {"type": "context_trimmed", "removed": old_len - len(messages), "reason": "challenge_switch"}

    yield {"type": "complete", "reason": "max_turns"}


# ============================================================================
# 工具执行
# ============================================================================

async def _execute_single_tool(
    tc: Dict,
    client,
    loop_detector: LoopDetector,
    messages: List[Dict],
    turn: int,
) -> str:
    """执行单个工具调用，返回结果字符串"""
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
        warning = loop_detector.get_warning()
        messages.append({"role": "tool", "tool_call_id": tool_id, "content": warning})
        return "__LOOP__"

    # 执行工具（通过 MCP）
    try:
        if "__" not in tool_name:
            raise ValueError(f"Invalid tool name: {tool_name}. Expected format: server__tool")

        server, tool = tool_name.split("__", 1)
        result = await client.call_tool(server, tool, arguments)
        result_str = str(result)
    except Exception as e:
        result_str = json.dumps({"status": "error", "error": str(e)}, ensure_ascii=False)

    # === Flag 自动检测：扫描工具输出 ===
    flags_found = _scan_for_flags(result_str)
    if flags_found:
        flag_notice = (
            f"\n\n[FLAG_DETECTED] Found potential flag(s) in output: {', '.join(flags_found)}\n"
            f"SUBMIT IMMEDIATELY if in competition mode: submit_flag(code=..., flag=\"{flags_found[0]}\")"
        )
        result_str += flag_notice

    messages.append({"role": "tool", "tool_call_id": tool_id, "content": result_str})
    return result_str


async def _execute_tools_parallel(
    tool_calls: List[Dict],
    client,
    loop_detector: LoopDetector,
    messages: List[Dict],
    turn: int,
):
    """并行执行多个工具调用"""

    async def _exec_one(tc: Dict, index: int):
        tool_id = tc.get("id", f"call_{turn}_{index}")
        function = tc.get("function", {})
        tool_name = function.get("name", "")

        try:
            arguments = json.loads(function.get("arguments", "{}"))
        except json.JSONDecodeError:
            arguments = {}

        # 循环检测
        args_hash = hashlib.md5(json.dumps(arguments, sort_keys=True).encode()).hexdigest()[:8]
        if loop_detector.record(tool_name, args_hash):
            return tool_id, loop_detector.get_warning()

        try:
            if "__" not in tool_name:
                raise ValueError(f"Invalid tool name: {tool_name}")
            server, tool = tool_name.split("__", 1)
            result = await client.call_tool(server, tool, arguments)
            result_str = str(result)
            # Flag 自动检测
            flags_found = _scan_for_flags(result_str)
            if flags_found:
                result_str += (
                    f"\n\n[FLAG_DETECTED] Found potential flag(s): {', '.join(flags_found)}\n"
                    f"SUBMIT IMMEDIATELY: submit_flag(code=..., flag=\"{flags_found[0]}\")"
                )
            return tool_id, result_str
        except Exception as e:
            return tool_id, json.dumps({"status": "error", "error": str(e)}, ensure_ascii=False)

    # 并行执行
    tasks = [_exec_one(tc, i) for i, tc in enumerate(tool_calls)]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    # 按顺序添加结果到消息
    for i, result in enumerate(results):
        if isinstance(result, Exception):
            tool_id = tool_calls[i].get("id", f"call_{turn}_{i}")
            messages.append({
                "role": "tool",
                "tool_call_id": tool_id,
                "content": json.dumps({"status": "error", "error": str(result)}, ensure_ascii=False),
            })
        else:
            tool_id, content = result
            messages.append({"role": "tool", "tool_call_id": tool_id, "content": content})


__all__ = ["query", "QueryConfig"]
