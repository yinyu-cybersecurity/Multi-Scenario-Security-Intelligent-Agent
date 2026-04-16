# app/core/query.py

"""
核心 Query 循环 - 对齐 Claude Code 架构

核心原则：
1. 框架做得越少越好，AI做得越多越好
2. 循环只是消息管道 + 工具执行器
3. 框架仅干预：超时熔断、循环检测
4. AI完全自主决策攻击策略、工具选择、任务切换

特性：
- Advisor 语义压缩（防止 token 溢出）
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

from app.llm_client import llm_client, LLMErrorType
from app.logger import get_logger
from app.tools_v2.mcp.client import get_mcp_client
from app.core.loop_detector import LoopDetector
from app.core.time_manager import TimeBudget
from app.settings import config as app_config

logger = get_logger("Query")


# ============================================================================
# Token 估算（tiktoken 真实计数 + 缓存）
# ============================================================================

# 尝试加载 tiktoken，使用 cl100k_base 作为 Qwen BPE 的近似
_tiktoken_encoder = None
try:
    import tiktoken as _tiktoken
    _tiktoken_encoder = _tiktoken.get_encoding("cl100k_base")
    _USE_TIKTOKEN = True
except Exception:
    _USE_TIKTOKEN = False

# Qwen3.6 的 token 通常比 OpenAI cl100k_base 略少，乘以校正系数
_QWEN_TOKEN_CORRECTION = 0.85

# 消息 token 缓存：用消息内容的 hash 映射到 token 数，避免重复计算
_message_token_cache: Dict[str, int] = {}


def _estimate_tokens(text: str) -> int:
    """
    使用真实 tokenizer 估算 token 数。

    优先使用 tiktoken（cl100k_base）+ 0.85 校正系数。
    如果 tiktoken 不可用，回退到字符数加权估算。
    """
    if not text:
        return 0

    if _USE_TIKTOKEN:
        try:
            raw_tokens = len(_tiktoken_encoder.encode(text))
            return int(raw_tokens * _QWEN_TOKEN_CORRECTION)
        except Exception:
            pass  # 编码失败时回退到字符估算

    # Fallback: 字符数加权估算（中文 ~0.7 char/token，英文 ~0.25 char/token）
    cn_chars = sum(1 for c in text if '\u4e00' <= c <= '\u9fff')
    en_chars = len(text) - cn_chars
    return int(cn_chars * 0.7 + en_chars * 0.25)


def _compute_message_token(msg: Dict) -> int:
    """计算单条消息的 token 数，带缓存。"""
    # 构建缓存 key：用内容 hash 避免大字符串做 key
    content = msg.get("content", "")
    content_hash = hashlib.md5(content.encode("utf-8", errors="replace")).hexdigest()

    if content_hash in _message_token_cache:
        return _message_token_cache[content_hash]

    tokens = _estimate_tokens(content) if isinstance(content, str) else 0

    # tool_calls 也占 token
    if "tool_calls" in msg:
        tokens += _estimate_tokens(json.dumps(msg["tool_calls"], ensure_ascii=False))

    _message_token_cache[content_hash] = tokens
    return tokens


def _estimate_messages_tokens(messages: List[Dict]) -> int:
    """估算消息列表总 token 数（带缓存）。"""
    return sum(_compute_message_token(msg) for msg in messages)


# ============================================================================
# 思考提取
# ============================================================================

def _extract_thinking(content: str) -> str:
    """从 assistant message 中提取思考内容（用于 advisor 评估）"""
    if not content:
        return ""
    # 匹配 【标题】+ 后续内容（支持多行，直到下一个【或末尾）
    thinking_blocks = re.findall(r'【[^】]+】[\s\S]*?(?=【|$)', content)
    if thinking_blocks:
        return "\n".join(b.strip() for b in thinking_blocks)
    # 如果没有标记的思考，返回前 500 字符
    return content[:500]


def _extract_recent_tool_results(messages: list, max_results: int = 5) -> str:
    """从消息列表中提取最近的工具执行结果（用于 advisor 评估）

    返回最近 N 条 tool 消息的精简预览，不区分成功/失败。
    每条截取前 300 字符，确保 Advisor 能看到关键信息。
    """
    results = []
    for msg in reversed(messages[-30:]):  # 只看最近 30 条消息
        if msg.get("role") == "tool":
            content = msg.get("content", "")
            # 每条工具结果取前 300 字符预览
            preview = content[:300] if len(content) > 300 else content
            # 提取工具名（从 tool_call_id 推断）
            tool_id = msg.get("tool_call_id", "")
            results.append(f"[{tool_id}] {preview}")
            if len(results) >= max_results:
                break
    if not results:
        return "无"
    return "\n---\n".join(reversed(results))  # 保持时间顺序


# ============================================================================
# 比赛实例跟踪（模块级状态）
# ============================================================================

class ChallengeInstanceTracker:
    """跟踪当前活跃的 challenge 实例，提供信息给 AI 决策（软限制，不强制）"""

    def __init__(self, max_instances: int = 3):
        self.max_instances = max_instances
        self.active: set = set()

    @property
    def count(self) -> int:
        return len(self.active)

    @property
    def slots_available(self) -> int:
        return max(0, self.max_instances - self.count)

    def start(self, code: str):
        self.active.add(code)

    def stop(self, code: str):
        self.active.discard(code)

    def format_status(self) -> str:
        if not self.active:
            return "Active instances: 0/3 (all slots available)"
        return f"Active instances: {self.count}/{self.max_instances} [{', '.join(sorted(self.active))}]"


# 模块级实例跟踪器（D4: 使用 max_concurrent_instances 配置）
_instance_tracker = ChallengeInstanceTracker(
    max_instances=app_config.competition.max_concurrent_instances
    if app_config.competition.max_concurrent_instances > 0
    else 3
)

# 当前正在攻击的 challenge code（用于 Flag 自动提交和实例跟踪）
_current_challenge_code: Optional[str] = None

# 已提交的 flag 集合（防止并行检测导致重复提交）
_submitted_flags: set = set()

# ============================================================================
# 挑战顺序维护（做过的排最后，避免重复开题）
# ============================================================================

class ChallengeOrder:
    """维护挑战尝试顺序的有序列表。
    最近被 start/stop 过的挑战排到队尾，避免 AI 反复启动同一道题。
    """

    def __init__(self):
        self._order: List[str] = []

    def mark_attempt(self, code: str):
        """start_challenge 时调用，将题目移到队尾"""
        if code in self._order:
            self._order.remove(code)
        self._order.append(code)

    def mark_abandon(self, code: str):
        """stop_challenge 时调用，将题目移到队尾（和 mark_attempt 效果一样）"""
        self.mark_attempt(code)

    def mark_solved(self, code: str):
        """找到 flag 时调用，从列表中移除"""
        if code in self._order:
            self._order.remove(code)

    def format_hint(self) -> str:
        """生成提示：最近尝试过的排在后面"""
        if not self._order:
            return ""
        # 最后几个是最近尝试过的
        recent = self._order[-3:] if len(self._order) > 3 else self._order
        rest = self._order[:-3] if len(self._order) > 3 else []
        parts = []
        if rest:
            parts.append(f"Not attempted: {', '.join(rest)}")
        parts.append(f"Recently tried (avoid repeating): {', '.join(recent)}")
        return "[CHALLENGE_ORDER]\n" + " | ".join(parts)

    def reset(self):
        self._order.clear()


# 模块级挑战顺序
_challenge_order = ChallengeOrder()


# ============================================================================
# Flag 自动检测
# ============================================================================

# 常见 CTF flag 格式（覆盖主流平台）
# 比赛 flag 格式：flag{...}（唯一精确匹配）
# 避免使用 key{...} 等宽泛正则导致误报配置文本
FLAG_PATTERN = re.compile(r'flag\{[^}]+\}', re.IGNORECASE)


def _scan_for_flags(text: str) -> list:
    """扫描文本中的 flag，返回去重列表"""
    if not text:
        return []
    return list(set(FLAG_PATTERN.findall(text)))


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


def _check_start_challenge_success(messages: List[Dict]) -> bool:
    """检查 start_challenge 工具调用是否成功

    解析 JSON 响应判断 status 字段，避免误判。

    Returns:
        True: 实例启动成功，应该 tracker.start()
        False: 实例启动失败，不应 tracker.start()
    """
    for msg in reversed(messages):
        if msg.get("role") != "tool":
            continue
        content = msg.get("content", "")
        if "start_challenge" not in content and "start_challenge" not in str(msg.get("tool_call_id", "")):
            continue

        # 尝试解析 JSON，判断 status 字段
        try:
            data = json.loads(content)
            status = data.get("status", "")
            # status 为 error / failed / failure → 失败
            if status.lower() in ("error", "failed", "failure"):
                logger.warning(f"[Query] start_challenge failed: {content[:200]}")
                return False
            # status 为 success / ok / running → 成功
            if status.lower() in ("success", "ok", "running"):
                return True
            # 包含 entry/url/address 等成功标记
            content_str = json.dumps(data, ensure_ascii=False)
            if any(key in content_str for key in ["entry", "url", "address", "http://", "https://", "port"]):
                return True
            # 无法判断，默认成功（保守策略）
            return True
        except json.JSONDecodeError:
            # 非 JSON 响应，按文本判断
            content_lower = content.lower()
            if "error" in content_lower or "failed" in content_lower or "failure" in content_lower:
                logger.warning(f"[Query] start_challenge failed: {content[:200]}")
                return False
            return True

    logger.warning("[Query] start_challenge result not found in messages, skipping tracker.start()")
    return False


def reset_context_for_new_challenge(
    messages: List[Dict],
    challenge_code: str,
    track_instance: bool = True,
) -> List[Dict]:
    """
    切题时重置上下文 — 保留 system prompt + 最近 5 条消息

    Args:
        messages: 当前消息列表
        challenge_code: 新题目代码
        track_instance: 是否更新实例跟踪（默认是；仅在确认 start_challenge 成功后调用时为 True）
    """
    global _current_challenge_code

    if len(messages) <= 6:
        return messages  # 消息太少，不需要清理

    system_prompt = messages[0]  # 始终保留
    recent = messages[-5:]        # 保留最近 5 条（包含 start_challenge 的调用和结果）

    # D1: 记录旧实例切换（不自动 stop，AI 自主管理）
    old_code = _current_challenge_code
    if old_code and old_code != challenge_code:
        logger.info(f"[Query] Challenge switch: {old_code} → {challenge_code} "
                    f"(instances: {_instance_tracker.format_status()})")

    # D2: 更新跟踪状态（仅当调用方确认实例启动成功）
    if track_instance:
        _instance_tracker.start(challenge_code)
    _current_challenge_code = challenge_code

    # 构建切题通知（包含实例状态 — D4 软限制）
    per_challenge_seconds = 600  # 每题建议 10 分钟
    switch_notice = {
        "role": "system",
        "content": (
            f"[CHALLENGE_SWITCH] Switched to: {challenge_code}\n"
            f"Context cleared to save tokens.\n"
            f"recall(query=\"{challenge_code}\") for previous progress.\n"
            f"recall(query=\"progress\") for competition status.\n"
            f"[INSTANCES] {_instance_tracker.format_status()}\n"
            f"[TIME_BUDGET] ~{per_challenge_seconds}s per challenge. "
            f"If stuck 2-3 approaches, move on."
        ),
    }

    logger.info(f"[Query] Context reset: {challenge_code}, kept {len(recent)} recent messages")
    return [system_prompt, switch_notice] + recent


# ============================================================================
# 配置
# ============================================================================

@dataclass
class QueryConfig:
    """Query 循环配置"""
    model: str = ""
    timeout_seconds: int = 1800
    system_prompt: str = ""
    # 并行工具
    parallel_tool_calls: bool = True
    # 模式控制
    auto_continue: bool = True  # 无工具调用时是否自动注入提示继续
    competition_mode: bool = False  # 比赛模式（禁用超时熔断）


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
    3. Advisor 语义压缩

    注意：此函数会原地修改传入的 messages 列表。
    如果需要保留原始消息，调用者应在传入前复制。

    事件类型：
    - assistant_message: AI 输出
    - tool_result: 工具执行结果
    - tool_error: 工具执行错误
    - loop_detected: 检测到循环调用
    - context_compressed: Advisor 语义压缩
    - task_complete: AI 自主结束（找到 FLAG）
    - complete: 循环结束（timeout / error）
    """

    # === 初始化 ===
    from app.tools_v2.mcp.client import ensure_mcp_tools_registered
    mcp_ok = await ensure_mcp_tools_registered()
    if not mcp_ok:
        yield {"type": "complete", "reason": "mcp_connection_failed"}
        return

    # 重置模块级全局状态，防止跨 query() 调用泄漏（REPL 模式关键）
    global _current_challenge_code
    _current_challenge_code = None
    _instance_tracker.active.clear()
    _challenge_order.reset()
    _submitted_flags.clear()
    if len(_message_token_cache) > 5000:
        _message_token_cache.clear()

    client = get_mcp_client()
    tool_schemas = client.get_all_tool_schemas()
    time_budget = TimeBudget(config.timeout_seconds)
    loop_detector = LoopDetector()

    # 从 settings 获取模型名
    if not config.model:
        from app.settings import config as _settings_config
        config.model = _settings_config.model.name

    consecutive_errors = 0
    max_consecutive_errors = 10

    # === 指导 Agent 初始化 ===
    advisor = None
    advisor_evaluate_interval = 3
    try:
        if hasattr(app_config, 'advisor') and app_config.advisor.enabled:
            from app.advisors import CTFAdvisor
            advisor = CTFAdvisor(model=config.model, llm_client=llm_client)
            advisor_evaluate_interval = app_config.advisor.evaluate_interval
            logger.info(f"[Query] Advisor enabled (eval={advisor_evaluate_interval})")
    except Exception as e:
        logger.warning(f"[Query] Advisor init failed: {e}")
        advisor = None

    # advisor 状态追踪
    evaluate_counter = 0
    _last_progress_summary = ""
    _advisor_intervention_history: List[Dict] = []
    _unaddressed_guidance: List[str] = []
    _turns_since_advisor_intervention = 0

    # 启动 Advisor 后台侦察循环
    if advisor:
        mcp_client_for_advisor = get_mcp_client()
        advisor.start_background_loop(messages, mcp_client_for_advisor)
        advisor.set_current_challenge("_init_")

    def _stop_advisor():
        """统一停止 Advisor 后台循环"""
        if advisor:
            advisor.stop_background_loop()

    turn = 0
    while True:
        turn += 1

        # === 超时检查（比赛模式禁用，由比赛服务器控制时限）===
        if not config.competition_mode and time_budget.is_timeout:
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
                flags = _scan_for_flags(response.content or "")
                if flags:
                    yield {"type": "task_complete", "flags": flags, "reason": "timeout_with_flag"}
                    _stop_advisor()
                    return
            yield {"type": "complete", "reason": "timeout"}
            _stop_advisor()
            return

        remaining = time_budget.remaining_seconds  # 用于日志

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
                consecutive_errors = 0
                half = len(messages) // 2
                trimmed = messages[:1] + messages[half:]
                trimmed.insert(1, {
                    "role": "system",
                    "content": "[CONTEXT_RESET] 上下文已大幅裁剪。请基于记忆（recall）恢复之前的进度。",
                })
                messages[:] = trimmed
                yield {"type": "context_trimmed", "removed": half, "reason": "context_length_error"}
                continue

            if consecutive_errors >= max_consecutive_errors:
                yield {"type": "complete", "reason": f"consecutive_errors_{consecutive_errors}"}
                _stop_advisor()
                return

            logger.warning(
                f"[Query] LLM error (attempt {consecutive_errors}): "
                f"{response.error_type.value} - {response.error_message}"
            )
            yield {"type": "llm_error", "error": response.error_message, "turn": turn}
            await asyncio.sleep(2)
            continue

        consecutive_errors = 0

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

        # === 指导 Agent 评估（每 N 轮，仅在有 tool_calls 时）===
        if advisor and tool_calls:
            current_thinking = _extract_thinking(content)
            advisor.append_to_thinking(f"\n[Turn {turn}] {current_thinking}")

            evaluate_counter += 1
            if evaluate_counter >= advisor_evaluate_interval:
                evaluate_counter = 0
                try:
                    recent_results_text = _extract_recent_tool_results(messages)

                    loop_info = None
                    if loop_detector.loop_count > 0:
                        loop_info = {
                            "total_loops": loop_detector.loop_count,
                            "recent_pattern": loop_detector.get_recent_pattern(),
                        }

                    recent_tool_names = []
                    for tc in tool_calls:
                        func = tc.get("function", {})
                        recent_tool_names.append(func.get("name", ""))

                    intervention, new_unaddressed, suggest_switch = await advisor.evaluate(
                        thinking_history=advisor.get_current_thinking(),
                        recent_actions=tool_calls,
                        progress_summary=_last_progress_summary,
                        recent_results=recent_results_text,
                        loop_detected=loop_info,
                        previous_guidance=_unaddressed_guidance,
                        turns_since_last_intervention=_turns_since_advisor_intervention,
                        recent_tools=recent_tool_names,
                    )

                    if suggest_switch and _current_challenge_code:
                        _challenge_order.mark_abandon(_current_challenge_code)
                        messages.append({
                            "role": "system",
                            "content": f"[ADVISOR_SUGGEST_SWITCH] Advisor 建议放弃当前题目 {_current_challenge_code}，选择其他题目。",
                        })
                        logger.info(f"[Query] Advisor suggests switching challenge: {_current_challenge_code}")

                    if intervention:
                        if loop_detector.loop_count >= 5:
                            intervention += (
                                "\n\n[ESCALATED] 已检测到 5+ 次循环，这是强制约束：\n"
                                "1. 你**必须**立即停止当前的攻击方法\n"
                                "2. 你**必须**先调用 recall(query=\"progress\") 查看已知信息\n"
                                "3. 你**必须**选择一个完全不同的攻击向量\n"
                                "4. 如果仍然卡住，调用 view_hint 查看提示"
                            )

                        _advisor_intervention_history.append({"turn": turn, "guidance": intervention})
                        if len(_advisor_intervention_history) > 5:
                            _advisor_intervention_history = _advisor_intervention_history[-5:]

                        messages.append({"role": "system", "content": f"[GUIDANCE] {intervention}"})
                        messages.append({
                            "role": "user",
                            "content": (
                                "⚠️ 你刚刚收到了一条 Advisor 指导消息（见上方 [GUIDANCE]）。"
                                "在下一轮回复中，你必须：\n"
                                "1. **首先在回复开头回应这条 GUIDANCE** — 说明你打算采纳还是拒绝，给出理由\n"
                                "2. 回应完毕后再执行你的正常行动（输出思维链、调用工具等）\n"
                                "不要忽略这条指导消息。Advisor 是基于对你的行为分析和工具侦察给出的精准建议。"
                            ),
                        })
                        yield {"type": "advisor_intervention", "guidance": intervention}

                        _turns_since_advisor_intervention = 0
                        if new_unaddressed:
                            _unaddressed_guidance[:] = new_unaddressed[:5]
                        else:
                            _unaddressed_guidance.clear()
                    else:
                        _turns_since_advisor_intervention += advisor_evaluate_interval
                except Exception as e:
                    logger.debug(f"[Query] Advisor evaluate failed: {e}")
                    _turns_since_advisor_intervention += advisor_evaluate_interval

        # === AI 自主结束检测 ===
        if "[TASK_COMPLETE]" in content:
            flags = _scan_for_flags(content)
            yield {"type": "task_complete", "flags": flags, "reason": "ai_terminated"}
            _stop_advisor()
            return

        # === 无工具调用 = AI 认为任务结束 ===
        if not tool_calls:
            flags = _scan_for_flags(content)
            if flags:
                yield {"type": "task_complete", "flags": flags, "reason": "flag_in_response"}
                _stop_advisor()
                return

            # REPL 模式：不自动继续，等待用户输入
            if not config.auto_continue:
                yield {"type": "complete", "reason": "awaiting_user_input"}
                _stop_advisor()
                return
            # 自动攻击模式：注入提示让 AI 继续
            messages.append({
                "role": "user",
                "content": "继续攻击。如果已完成，输出 [TASK_COMPLETE] FLAG: flag{xxx}。如果卡住了，换一种方法。",
            })
            continue

        # === 执行工具 ===
        switch_code = _is_challenge_switch(tool_calls)
        if switch_code:
            _challenge_order.mark_attempt(switch_code)

        # 检测 stop_challenge 调用
        stop_codes = []
        for tc in tool_calls:
            func = tc.get("function", {})
            if func.get("name", "").endswith("stop_challenge"):
                try:
                    args = json.loads(func.get("arguments", "{}"))
                    stop_codes.append(args.get("code", ""))
                except Exception:
                    pass

        if config.parallel_tool_calls and len(tool_calls) > 1:
            async for event in _execute_tools_parallel(tool_calls, client, loop_detector, messages, turn):
                yield event
        else:
            for tc in tool_calls:
                function = tc.get("function", {})
                tool_name = function.get("name", "")
                result_info = await _execute_single_tool(tc, client, loop_detector, messages, turn)
                if result_info.get("is_loop"):
                    yield {"type": "loop_detected", "tool": tool_name}
                else:
                    yield {"type": "tool_result", "tool_name": tool_name, **result_info}

        # 更新实例跟踪 + 挑战顺序
        for code in stop_codes:
            if code:
                if advisor and _last_progress_summary:
                    advisor.save_challenge_progress(code, _last_progress_summary)
                elif advisor:
                    advisor.save_challenge_progress(code, f"Challenge {code} was stopped. No summary available.")
                _instance_tracker.stop(code)
                _challenge_order.mark_abandon(code)
                logger.info(f"[Query] Instance stopped: {code} ({_instance_tracker.format_status()})")

        # === 切题上下文清理 ===
        if switch_code:
            # 保存旧题进度（如果 AI 没有调 stop_challenge）
            old_code = _current_challenge_code
            if advisor and old_code and old_code != switch_code and _last_progress_summary:
                advisor.save_challenge_progress(old_code, _last_progress_summary)
                logger.info(f"[Query] Saved progress for abandoned challenge: {old_code}")

            track_ok = _check_start_challenge_success(messages)
            old_len = len(messages)
            messages[:] = reset_context_for_new_challenge(messages, switch_code, track_instance=track_ok)
            loop_detector.reset()
            evaluate_counter = 0
            _last_progress_summary = ""
            _advisor_intervention_history = []
            _unaddressed_guidance = []
            _turns_since_advisor_intervention = 0
            if advisor:
                if advisor._recon_task and not advisor._recon_task.done():
                    advisor._recon_task.cancel()
                    try:
                        await advisor._recon_task
                    except asyncio.CancelledError:
                        pass
                advisor.set_current_challenge(switch_code)
                advisor._predicted_stage = None
                advisor._last_messages_len = len(messages)

            order_hint = _challenge_order.format_hint()
            if order_hint:
                messages.append({"role": "system", "content": order_hint})

            if advisor:
                prev_progress = advisor.get_challenge_progress(switch_code)
                if prev_progress:
                    messages.append({
                        "role": "system",
                        "content": f"[PREVIOUS_PROGRESS] 这道题之前尝试过但放弃了。以下是上次保存的进度摘要：\n{prev_progress}\n\n请参考这些信息，避免重复已失败的尝试。",
                    })
                    logger.info(f"[Query] Injected previous progress for challenge {switch_code}")

            yield {"type": "context_trimmed", "removed": old_len - len(messages), "reason": "challenge_switch"}

        # === 语义压缩（每轮检查，token 阈值触发）===
        if advisor:
            current_tokens = _estimate_messages_tokens(messages)
            if current_tokens > 40000:
                try:
                    summary = await advisor.compress_conversation(messages)
                    if summary:
                        _last_progress_summary = summary

                        # 删除旧的摘要，用新的替换
                        messages_without_old_summaries = [
                            msg for msg in messages
                            if not (msg.get("role") == "system" and
                                    ("[PROGRESS_SUMMARY]" in msg.get("content", "") or
                                     "[ADVISOR_HISTORY]" in msg.get("content", "")))
                        ]

                        preserved_head = messages_without_old_summaries[:1]

                        summary_msg = {"role": "system", "content": f"[PROGRESS_SUMMARY]\n{summary}"}

                        context_parts = [summary_msg]
                        if _advisor_intervention_history:
                            history_lines = []
                            for item in _advisor_intervention_history:
                                history_lines.append(f"  T{item['turn']}: {item['guidance']}")
                            advisor_context_msg = {
                                "role": "system",
                                "content": f"[ADVISOR_HISTORY]\n最近 Advisor 干预记录：\n" + "\n".join(history_lines),
                            }
                            context_parts.append(advisor_context_msg)

                        # 动态计算尾部保留轮数：确保压缩后 < 20K tokens
                        head_tokens = _estimate_messages_tokens(preserved_head + context_parts)
                        target_tail_tokens = max(0, 20000 - head_tokens)

                        if target_tail_tokens <= 0:
                            logger.warning(f"[Query] Compression: head+context already {head_tokens:,} tokens (>20K), keeping minimal tail")
                            tail_messages = []
                        else:
                            tail_messages = []
                            tail_accu_tokens = 0
                            for msg in reversed(messages_without_old_summaries[1:]):
                                msg_tokens = _estimate_messages_tokens([msg])
                                if tail_accu_tokens + msg_tokens > target_tail_tokens:
                                    break
                                tail_accu_tokens += msg_tokens
                                tail_messages.insert(0, msg)

                        removed = len(messages_without_old_summaries) - len(preserved_head) - len(context_parts) - len(tail_messages)
                        messages[:] = preserved_head + context_parts + tail_messages

                        _unaddressed_guidance.clear()
                        if advisor:
                            advisor.reset_thinking_buffer()
                            advisor._last_messages_len = 0

                        post_tokens = _estimate_messages_tokens(messages)
                        if post_tokens > 20000:
                            logger.warning(f"[Query] Post-compression tokens ({post_tokens:,}) still exceeds 20K target")
                        loop_detector.reset()
                        yield {"type": "context_compressed", "summary": summary, "removed": removed,
                               "pre_tokens": current_tokens, "post_tokens": post_tokens}
                        logger.info(f"[Query] Context compressed: {current_tokens:,} → {post_tokens:,} tokens, removed {removed} messages")
                except Exception as e:
                    logger.warning(f"[Query] Context compression failed: {e}")

    # 停止 Advisor 后台循环
    _stop_advisor()


# ============================================================================
# 工具执行
# ============================================================================

async def _execute_single_tool(
    tc: Dict,
    client,
    loop_detector: LoopDetector,
    messages: List[Dict],
    turn: int,
) -> Dict:
    """执行单个工具调用，返回结果信息字典"""
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
        return {"is_loop": True}

    # 执行工具
    try:
        if "__" not in tool_name:
            raise ValueError(f"Invalid tool name: {tool_name}. Expected format: server__tool")

        server, tool = tool_name.split("__", 1)

        call_timeout = arguments.get("timeout", 600)
        call_timeout = min(call_timeout, 1800)

        try:
            result = await asyncio.wait_for(
                client.call_tool(server, tool, arguments),
                timeout=call_timeout,
            )
            result_str = str(result)
        except asyncio.TimeoutError:
            result_str = json.dumps({
                "status": "error",
                "error": f"Command timed out after {call_timeout}s",
                "hint": "Reduce command scope or increase timeout parameter",
            }, ensure_ascii=False)
    except Exception as e:
        result_str = json.dumps({"status": "error", "error": str(e)}, ensure_ascii=False)

    # === Flag 自动检测 ===
    flags_found = _scan_for_flags(result_str)
    if flags_found:
        result_str += (
            f"\n\n[FLAG_DETECTED] Found potential flag(s): {', '.join(flags_found)}\n"
            f"SUBMIT IMMEDIATELY: submit_flag(code=..., flag=\"{flags_found[0]}\")"
        )
        if _current_challenge_code:
            code = _current_challenge_code
            flag = flags_found[0]
            if flag not in _submitted_flags:
                _submitted_flags.add(flag)
                logger.info(f"[Query] Auto-submitting flag for {code}: {flag[:20]}...")
                try:
                    submit_result = await client.call_tool(
                        "competition", "submit_flag",
                        {"code": code, "flag": flag},
                    )
                    result_str += f"\n[AUTO_SUBMIT] submit_flag({code}): {str(submit_result)[:200]}"
                    _challenge_order.mark_solved(code)
                except Exception as e:
                    result_str += f"\n[AUTO_SUBMIT_FAILED] {e}"

    messages.append({"role": "tool", "tool_call_id": tool_id, "content": result_str})

    # 记录工具执行结果日志（前 300 字符）
    result_preview = result_str[:300].replace('\n', ' ')
    if len(result_str) > 300:
        result_preview += '...'
    logger.debug(f"[Query] Tool result: {tool_name} → {result_preview}")

    return {
        "is_loop": False,
        "arguments": arguments,
        "result_preview": result_str[:500] if len(result_str) > 500 else result_str,
        "result_length": len(result_str),
        "has_error": "error" in result_str.lower()[:100],
    }


async def _execute_tools_parallel(
    tool_calls: List[Dict],
    client,
    loop_detector: LoopDetector,
    messages: List[Dict],
    turn: int,
) -> AsyncGenerator[Dict, None]:
    """并行执行多个工具调用"""

    tasks = {}
    final_results = {}

    for i, tc in enumerate(tool_calls):
        tool_id = tc.get("id", f"call_{turn}_{i}")
        tool_name = tc.get("function", {}).get("name", "")
        yield {"type": "tool_start", "tool_id": tool_id, "tool_name": tool_name, "turn": turn}
        tasks[tool_id] = asyncio.create_task(
            _exec_one(tc, i, client, loop_detector, messages, turn)
        )

    # 等待所有任务完成
    for tool_id, task in tasks.items():
        result = await task
        final_results[tool_id] = result
        yield {
            "type": "tool_complete",
            "tool_id": tool_id,
            "tool_name": result.get("tool_name", ""),
            "has_error": result.get("has_error", False),
            "result_length": result.get("result_length", 0),
        }

    yield {
        "type": "tool_execution_summary",
        "total": len(tool_calls),
        "errors": sum(1 for r in final_results.values() if r.get("has_error")),
    }


async def _exec_one(tc: Dict, index: int, client, loop_detector, messages, turn: int):
    """执行单个工具调用"""
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
        content = loop_detector.get_warning()
        messages.append({"role": "tool", "tool_call_id": tool_id, "content": content})
        return {"is_loop": True, "arguments": arguments, "tool_name": tool_name,
                "has_error": True, "result_length": len(content), "error_detail": "loop detected"}

    try:
        if "__" not in tool_name:
            raise ValueError(f"Invalid tool name: {tool_name}")
        server, tool = tool_name.split("__", 1)

        call_timeout = arguments.get("timeout", 600)
        call_timeout = min(call_timeout, 1800)

        try:
            result = await asyncio.wait_for(
                client.call_tool(server, tool, arguments),
                timeout=call_timeout,
            )
            result_str = str(result)
        except asyncio.TimeoutError:
            result_str = json.dumps({
                "status": "error",
                "error": f"Command timed out after {call_timeout}s",
                "hint": "Reduce command scope or increase timeout parameter",
            }, ensure_ascii=False)
    except Exception as e:
        result_str = json.dumps({"status": "error", "error": str(e)}, ensure_ascii=False)

    # Flag 自动检测
    flags_found = _scan_for_flags(result_str)
    if flags_found:
        result_str += (
            f"\n\n[FLAG_DETECTED] Found potential flag(s): {', '.join(flags_found)}\n"
            f"SUBMIT IMMEDIATELY: submit_flag(code=..., flag=\"{flags_found[0]}\")"
        )
        if _current_challenge_code:
            code = _current_challenge_code
            flag = flags_found[0]
            if flag not in _submitted_flags:
                _submitted_flags.add(flag)
                logger.info(f"[Query] Auto-submit flag (parallel) for {code}: {flag[:20]}...")
                try:
                    submit_result = await client.call_tool(
                        "competition", "submit_flag",
                        {"code": code, "flag": flag},
                    )
                    result_str += f"\n[AUTO_SUBMIT] submit_flag({code}): {str(submit_result)[:200]}"
                    _challenge_order.mark_solved(code)
                except Exception as e:
                    result_str += f"\n[AUTO_SUBMIT_FAILED] {e}"

    messages.append({"role": "tool", "tool_call_id": tool_id, "content": result_str})

    error_detail = ""
    if "error" in result_str.lower()[:200]:
        try:
            d = json.loads(result_str)
            error_detail = d.get("error", str(result_str[:200]))
        except Exception:
            error_detail = str(result_str[:200])

    return {
        "is_loop": False,
        "arguments": arguments,
        "result_preview": result_str[:500] if len(result_str) > 500 else result_str,
        "result_length": len(result_str),
        "has_error": "error" in result_str.lower()[:100],
        "tool_name": tool_name,
        "error_detail": error_detail,
    }


__all__ = ["query", "QueryConfig"]
