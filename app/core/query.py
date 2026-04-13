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
from collections import Counter
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

# 连续 bash 空输出计数（模块级状态，但在每个 turn 开始时重置为 0，避免跨 turn 累积）
_turn_empty_bash_count = 0
_empty_count_lock = asyncio.Lock()  # 保护并行 bash 工具的竞态条件

# 工具执行状态追踪（用于看门狗和状态注入）
_tool_execution_state: Dict[str, Dict] = {}  # tool_id -> {status, start_time, tool_name, args_preview}


def _inject_status(messages: List[Dict], content: str):
    """注入系统状态消息到 messages（Agent 和 Advisor 共享）"""
    messages.append({"role": "system", "content": content})


def _get_instance_tracker() -> ChallengeInstanceTracker:
    """获取实例跟踪器（允许外部访问）"""
    return _instance_tracker


def _get_current_challenge_code() -> Optional[str]:
    """获取当前 challenge code（允许外部访问）"""
    return _current_challenge_code


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


def reset_context_for_new_challenge(
    messages: List[Dict],
    challenge_code: str,
) -> List[Dict]:
    """
    切题时重置上下文 — 保留 system prompt + 最近 5 条消息

    D1+D2 修复:
    - 更新实例跟踪状态（start 新实例）
    - 切题通知中注入实例槽位使用情况
    - 如果之前有旧实例，记录日志（不自动 stop，AI 自主管理）
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

    # D2: 更新跟踪状态
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
    max_turns: int = 200
    timeout_seconds: int = 1800
    system_prompt: str = ""
    # 上下文管理（适配 Qwen3.6 1M 上下文）
    context_window_tokens: int = 1048576  # 1M tokens
    context_reserve_tokens: int = 32768   # 32K 为响应预留
    message_truncate_threshold: int = 16000
    # 并行工具
    parallel_tool_calls: bool = True
    # 模式控制
    auto_continue: bool = True  # 无工具调用时是否自动注入提示继续
    competition_mode: bool = False  # 比赛模式（禁用超时熔断）


# ============================================================================
# 上下文窗口管理
# ============================================================================

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
    max_tokens: int = 1048576,
    reserve_tokens: int = 32768,
    truncate_threshold: int = 16000,
) -> List[Dict]:
    """
    管理上下文窗口，智能压缩（适配 Qwen3.6 1M 上下文，真实 token 计数）

    策略（动态分级截断，基于真实 tiktoken 计数）：
    1. 使用量 < 200K tokens：不截断，自由增长
    2. 使用量 200K-500K tokens：正常裁剪（移除最旧非保护消息）
    3. 使用量 > 500K tokens：渐进式截断
    4. 使用量 > 800K tokens：强制截断，保留 system + 关键系统消息 + 最近 50 轮

    保护优先级：
    1. system prompt（第一条）
    2. 带 tool_calls 的消息（AI 决策点）
    3. 最近的 50 轮对话
    4. 包含 FLAG 的通知消息

    截断优先级：
    1. 早期的纯文本 tool 结果
    2. 早期的 assistant 普通输出
    3. 系统通知消息
    """
    if not messages:
        return messages

    target_tokens = max_tokens - reserve_tokens

    # 估算当前 token 数
    current_tokens = _estimate_messages_tokens(messages)

    # 使用量 < 200K，不截断
    if current_tokens < 200000:
        return messages

    # 先截断单条过长消息（tool 结果可能很长）
    for i, msg in enumerate(messages):
        content = msg.get("content", "")
        if isinstance(content, str) and len(content) > truncate_threshold:
            messages[i] = {**msg, "content": _truncate_message_content(content, truncate_threshold)}

    # 重新估算
    current_tokens = _estimate_messages_tokens(messages)
    if current_tokens <= target_tokens:
        return messages

    # === 分级保护策略 ===

    # 识别需要保护的"关键系统消息"
    # [PROGRESS_SUMMARY] 和 [ADVISOR_HISTORY] 是压缩后注入的关键信息
    def _is_protected_system_message(msg: Dict) -> bool:
        content = msg.get("content", "")
        return msg.get("role") == "system" and (
            "[PROGRESS_SUMMARY]" in content or
            "[ADVISOR_HISTORY]" in content or
            "[CHALLENGE_SWITCH]" in content or
            "[GUIDANCE]" in content
        )

    # 使用量 > 800K：强制截断，只保留 system + 关键系统消息 + 最近 50 轮
    if current_tokens > 800000:
        protected_tail = 50
        if len(messages) <= 1 + protected_tail:
            return messages

        head = [messages[0]]  # system prompt

        # 保护 [PROGRESS_SUMMARY] 和 [ADVISOR_HISTORY]
        protected_messages = []
        for msg in messages[1:min(len(messages), 20)]:  # 只在前面几条中找
            if _is_protected_system_message(msg):
                protected_messages.append(msg)
            else:
                break  # 遇到非保护的，停止

        tail = messages[-protected_tail:]

        removed = len(messages) - len(head) - len(protected_messages) - len(tail)
        messages[:] = head + protected_messages + tail

        if not any("[CONTEXT_TRUNCATED]" in m.get("content", "") for m in protected_messages):
            trim_notice = {
                "role": "system",
                "content": f"[CONTEXT_TRUNCATED] 上下文已超过 800K tokens，已移除 {removed} 条早期消息。最近 50 轮对话已保留。进度摘要仍在上方。",
            }
            messages.insert(1, trim_notice)
        logger.warning(f"[Query] Context forced truncate: removed {removed} messages, {len(messages)} remaining")
        return messages

    # 使用量 > 500K：渐进式截断
    protected_head = 1  # system prompt
    protected_tail = min(50, len(messages) // 3)  # 最近的消息，至少 1/3

    if len(messages) <= protected_head + protected_tail:
        return messages

    head = messages[:protected_head]
    tail = messages[-protected_tail:]
    # 中间消息：排除关键系统消息
    middle = messages[protected_head:-protected_tail]

    # 从中间消息中识别并保护 [PROGRESS_SUMMARY] / [ADVISOR_HISTORY]
    protected_in_middle = []
    filtered_middle = []
    for msg in middle:
        if _is_protected_system_message(msg):
            protected_in_middle.append(msg)
        else:
            filtered_middle.append(msg)

    # 从过滤后的中间消息中移除最旧的
    removed = 0
    while filtered_middle and _estimate_messages_tokens(head + protected_in_middle + filtered_middle + tail) > target_tokens:
        filtered_middle.pop(0)
        removed += 1

    if removed > 0:
        trim_notice = {
            "role": "system",
            "content": f"[CONTEXT_TRUNCATED] 已移除 {removed} 条早期消息。最近对话和进度摘要已保留。",
        }
        result = head + [trim_notice] + protected_in_middle + filtered_middle + tail
        logger.info(f"[Query] Context trimmed: removed {removed} messages, {len(protected_in_middle)} key messages protected")
        return result

    return head + protected_in_middle + tail


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

    注意：此函数会原地修改传入的 messages 列表。
    如果需要保留原始消息，调用者应在传入前复制。

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

    # 重置模块级全局状态，防止跨 query() 调用泄漏（REPL 模式关键）
    global _current_challenge_code
    _current_challenge_code = None
    _instance_tracker.active.clear()
    if len(_message_token_cache) > 5000:
        _message_token_cache.clear()

    client = get_mcp_client()
    tool_schemas = client.get_all_tool_schemas()
    time_budget = TimeBudget(config.timeout_seconds)
    loop_detector = LoopDetector()
    token_manager = get_token_stats_manager()

    # 从 settings 获取模型名
    if not config.model:
        from app.settings import config as _settings_config
        config.model = _settings_config.model.name

    consecutive_errors = 0
    max_consecutive_errors = 10  # 在容错和及时止损之间平衡

    # === 卡住恢复机制（无限恢复，不终止）===
    consecutive_empty_responses = 0

    # === 指导 Agent 初始化 ===
    advisor = None
    advisor_evaluate_interval = 3
    advisor_compress_interval = 15
    try:
        if hasattr(app_config, 'advisor') and app_config.advisor.enabled:
            from app.advisors import CTFAdvisor
            advisor = CTFAdvisor(model=config.model, llm_client=llm_client)
            advisor_evaluate_interval = app_config.advisor.evaluate_interval
            advisor_compress_interval = app_config.advisor.compress_interval
            logger.info(f"[Query] Advisor enabled (eval={advisor_evaluate_interval}, compress={advisor_compress_interval})")
    except Exception as e:
        logger.warning(f"[Query] Advisor init failed: {e}")
        advisor = None

    # advisor 状态追踪
    evaluate_counter = 0
    compress_counter = 0
    _last_progress_summary = ""
    _advisor_intervention_history: List[Dict] = []  # 记录干预历史 [(guidance_text, turn), ...]
    _unaddressed_guidance: List[str] = []  # 未被采纳的历史建议
    _turns_since_advisor_intervention = 0  # 上次 advisor 干预到现在经过的轮数

    # 启动 Advisor 后台侦察循环
    if advisor:
        mcp_client_for_advisor = get_mcp_client()
        advisor.start_background_loop(messages, mcp_client_for_advisor)
        # 初始化默认 thinking buffer key
        advisor.set_current_challenge("_init_")

    # === 时间盒反思机制 ===
    start_time = time.time()
    last_reflection = start_time
    reflection_interval = 900  # 15分钟

    # 时间警告标记：确保每种警告只注入一次（P2 修复）
    time_warning_issued = {"warning": False, "critical": False}

    def _stop_advisor():
        """统一停止 Advisor 后台循环"""
        if advisor:
            advisor.stop_background_loop()

    for turn in range(1, config.max_turns + 1):

        # === Turn 级计数器重置 ===
        global _turn_empty_bash_count
        _turn_empty_bash_count = 0  # 每个 turn 独立计数

        # === 上下文窗口管理 ===
        old_len = len(messages)
        new_messages = manage_context_window(
            messages,
            max_tokens=config.context_window_tokens,
            reserve_tokens=config.context_reserve_tokens,
            truncate_threshold=config.message_truncate_threshold,
        )
        # 原地更新，保持引用一致性
        if new_messages is not messages:
            messages[:] = new_messages
        if len(messages) < old_len:
            yield {"type": "context_trimmed", "removed": old_len - len(messages)}

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
                # 检查是否在超时时刻输出了 FLAG
                flags = _scan_for_flags(response.content or "")
                if flags:
                    yield {"type": "task_complete", "flags": flags, "reason": "timeout_with_flag"}
                    _stop_advisor()
                    return
            yield {"type": "complete", "reason": "timeout"}
            _stop_advisor()
            return

        # === 时间警告（比赛模式禁用）===
        if not config.competition_mode:
            remaining = time_budget.remaining_seconds
            ratio = time_budget.remaining_ratio
            if ratio < 0.1 and not time_warning_issued["critical"]:
                messages.append({
                    "role": "system",
                    "content": f"[CRITICAL] 仅剩 {int(remaining)}s！必须立即收敛到最有可能的攻击路径。",
                })
                time_warning_issued["critical"] = True
            elif ratio < 0.2 and not time_warning_issued["warning"]:
                messages.append({
                    "role": "system",
                    "content": f"[TIME_WARNING] 剩余 {int(remaining)}s。优先完成当前最有可能成功的攻击。",
                })
                time_warning_issued["warning"] = True
        else:
            remaining = time_budget.remaining_seconds  # 比赛模式也需要用于日志

        # === Token 统计（每 15 轮注入精简消息）===
        if turn % 15 == 0:
            stats = token_manager.get_global_stats()
            total_k = stats.total_tokens // 1000
            messages.append({
                "role": "system",
                "content": f"[TOKEN] {total_k}K used",
            })
            logger.info(f"[Query] Turn {turn}/{config.max_turns} | Token: {stats.total_tokens:,} | Time: {int(remaining)}s remaining")

        # === 记忆提醒（每 8 轮注入，提醒 Operator 记录关键信息）===
        # 检查上一轮是否有 tool_calls（从最近 assistant message 判断）
        has_recent_tool_calls = any("tool_calls" in m for m in reversed(messages) if m.get("role") == "assistant")
        if turn % 8 == 0 and has_recent_tool_calls:
            messages.append({
                "role": "system",
                "content": "[MEMORY_REMINDER] 检查是否有新发现的关键信息（凭据、端点、漏洞、sudo 权限等），如有请立即调用 remember 记录。压缩后未记录的信息将永久丢失。",
            })

        # === 时间盒反思（每 15 分钟）===
        elapsed_since_reflection = time.time() - last_reflection
        if elapsed_since_reflection >= reflection_interval:
            reflection_prompt = {
                "role": "user",
                "content": f"""[REFLECTION] 已运行 {int((time.time() - start_time) // 60)} 分钟，请评估当前进度：

1. **已尝试的攻击路径**：简要列出已测试的方法
2. **成功/失败分析**：为什么成功或失败？
3. **最有希望的方向**：下一步该做什么？
4. **是否需要切换策略**：如果当前路径不工作，是否应该换方向？

如果已找到FLAG，立即输出 [TASK_COMPLETE] FLAG: flag{{xxx}}"""
            }
            messages.append(reflection_prompt)
            last_reflection = time.time()
            yield {"type": "reflection_prompted", "elapsed_minutes": int((time.time() - start_time) // 60)}

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
                consecutive_errors = 0  # 裁剪是受控操作，不计入连续错误
                half = len(messages) // 2
                # 原地更新，保持引用一致性
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

        # === 工具调用去重（在 flag 检测之后、执行之前，所有路径都执行）===
        if len(tool_calls) > 1:
            tc_signatures = []
            for tc in tool_calls:
                func = tc.get("function", {})
                name = func.get("name", "")
                args = func.get("arguments", "{}")
                sig = f"{name}:{args}"
                tc_signatures.append(sig)

            sig_counts = Counter(tc_signatures)
            most_common_sig, most_common_count = sig_counts.most_common(1)[0]

            if most_common_count >= 2:
                # 去重：只保留第一个相同的调用
                seen_sigs = set()
                unique_tool_calls = []
                for tc in tool_calls:
                    func = tc.get("function", {})
                    sig = f"{func.get('name', '')}:{func.get('arguments', '{}')}"
                    if sig not in seen_sigs:
                        seen_sigs.add(sig)
                        unique_tool_calls.append(tc)
                tool_calls = unique_tool_calls
                msg["tool_calls"] = tool_calls

                # 通知 LLM 重复率
                total_original = len(tc_signatures)
                repeat_ratio = most_common_count / total_original
                if repeat_ratio > 0.5:
                    dedup_hint = (
                        f"[DUPLICATE_DETECTED] You generated {most_common_count} identical calls "
                        f"out of {total_original} total (>{most_common_count * 100 // total_original}% duplicate). "
                        f"Duplicates removed. Change your strategy — repeating the same call won't help. "
                        f"Try search_skills or a different approach."
                    )
                else:
                    dedup_hint = (
                        f"[DUPLICATE_DETECTED] You generated {most_common_count} identical tool calls. "
                        f"Duplicates removed. Same input always gives same output."
                    )
                messages.append({"role": "system", "content": dedup_hint})
                yield {"type": "duplicate_calls_removed", "count": most_common_count, "tool": most_common_sig.split(":")[0]}

        yield {
            "type": "assistant_message",
            "content": content,
            "turn": turn,
            "tool_calls": tool_calls,
            "time_remaining": int(remaining),
        }

        # === 指导 Agent 评估（每 N 轮，仅在有 tool_calls 时）===
        if advisor and tool_calls:
            # 累积最近思考（通过 Advisor 按 challenge 隔离管理）
            current_thinking = _extract_thinking(content)
            advisor.append_to_thinking(f"\n[Turn {turn}] {current_thinking}")

            evaluate_counter += 1
            if evaluate_counter >= advisor_evaluate_interval:
                evaluate_counter = 0
                try:
                    # 提取最近工具执行结果（最近 5 条 tool message）
                    recent_results_text = _extract_recent_tool_results(messages)

                    # Loop Detector 状态
                    loop_info = None
                    if loop_detector.loop_count > 0:
                        loop_info = {
                            "total_loops": loop_detector.loop_count,
                            "recent_pattern": loop_detector.get_recent_pattern(),
                        }

                    # 最近执行的工具名称（供 Advisor 判断建议是否被采纳）
                    recent_tool_names = []
                    for tc in tool_calls:
                        func = tc.get("function", {})
                        recent_tool_names.append(func.get("name", ""))

                    intervention, new_unaddressed = await advisor.evaluate(
                        thinking_history=advisor.get_current_thinking(),
                        recent_actions=tool_calls,
                        progress_summary=_last_progress_summary,
                        recent_results=recent_results_text,
                        loop_detected=loop_info,
                        previous_guidance=_unaddressed_guidance,
                        turns_since_last_intervention=_turns_since_advisor_intervention,
                        recent_tools=recent_tool_names,
                    )
                    if intervention:
                        _advisor_intervention_history.append({
                            "turn": turn,
                            "guidance": intervention,
                        })
                        # 只保留最近 5 条干预历史
                        if len(_advisor_intervention_history) > 5:
                            _advisor_intervention_history = _advisor_intervention_history[-5:]

                        messages.append({
                            "role": "system",
                            "content": f"[GUIDANCE] {intervention}",
                        })
                        yield {"type": "advisor_intervention", "guidance": intervention}

                        # 追踪：干预已发生，重置计数器
                        _turns_since_advisor_intervention = 0

                        # 更新未采纳建议列表：完全由 Advisor 自行判断和维护
                        # Advisor 返回的 unaddressed_guidance 是更新后的列表
                        if new_unaddressed:
                            _unaddressed_guidance[:] = new_unaddressed[:5]  # 最多保留 5 条
                        else:
                            # Advisor 认为所有建议都已解决或被忽略太久，清空
                            _unaddressed_guidance.clear()
                    else:
                        # 没有干预，增加计数器
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
            # 再检查一次是否有 flag 格式的内容
            flags = _scan_for_flags(content)
            if flags:
                yield {"type": "task_complete", "flags": flags, "reason": "flag_in_response"}
                _stop_advisor()
                return

            # 空响应检测 - 恢复机制而非终止
            if not content.strip():
                consecutive_empty_responses += 1
                if consecutive_empty_responses >= 3:
                    # 注入强制恢复提示
                    messages.append({
                        "role": "system",
                        "content": (
                            "[STUCK_RECOVERY] You've provided empty responses 3 times in a row. "
                            "This indicates you're stuck. RECOVERY ACTIONS:\n"
                            "1. Use recall(query=\"progress\") to check what you've tried\n"
                            "2. Use list_challenges to see current status\n"
                            "3. Pick a different challenge or attack method\n"
                            "4. Use search_skills to find new techniques\n"
                            "DO NOT stay silent. Choose an action NOW."
                        ),
                    })
                    consecutive_empty_responses = 0  # 重置，给AI新机会
                    yield {"type": "recovery_triggered", "reason": "empty_responses"}
                else:
                    # 轻度警告
                    messages.append({
                        "role": "user",
                        "content": "[PROMPT] Please respond with your next action or current progress.",
                    })
                continue
            else:
                consecutive_empty_responses = 0  # 有内容则重置

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
        # 检测切题 — 在执行前记录
        switch_code = _is_challenge_switch(tool_calls)

        # 检测 stop_challenge 调用（用于更新实例跟踪）
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
            # 并行执行多个工具调用（AsyncGenerator，实时注入状态）
            async for event in _execute_tools_parallel(
                tool_calls, client, loop_detector, messages, turn,
            ):
                yield event
        else:
            # 顺序执行
            for tc in tool_calls:
                tool_id = tc.get("id", f"call_{turn}")
                function = tc.get("function", {})
                tool_name = function.get("name", "")

                result_info = await _execute_single_tool(
                    tc, client, loop_detector, messages, turn,
                )

                if result_info.get("is_loop"):
                    yield {"type": "loop_detected", "tool": tool_name}
                else:
                    yield {"type": "tool_result", "tool_name": tool_name, **result_info}

        # 更新实例跟踪：stop_challenge 成功后移除跟踪
        for code in stop_codes:
            if code:
                _instance_tracker.stop(code)
                logger.info(f"[Query] Instance stopped: {code} ({_instance_tracker.format_status()})")

        # === 切题上下文清理（工具执行后）===
        if switch_code:
            old_len = len(messages)
            messages[:] = reset_context_for_new_challenge(messages, switch_code)
            loop_detector.reset()  # 重置循环检测
            evaluate_counter = 0  # 重置 advisor 计数器
            compress_counter = 0
            _last_progress_summary = ""
            _advisor_intervention_history = []  # 重置干预历史
            _unaddressed_guidance = []  # 重置未确认建议
            _turns_since_advisor_intervention = 0
            _turn_empty_bash_count = 0  # 切题重置空输出计数
            # 切换 Advisor 到新的挑战（保留历史挑战的缓存，不清空）
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
            yield {"type": "context_trimmed", "removed": old_len - len(messages), "reason": "challenge_switch"}

        # === 语义压缩上下文（token 阈值 + 定时触发）===
        if advisor and tool_calls:
            compress_counter += 1

            # 检查是否需要压缩：300K tokens 触发 或 达到定时间隔
            current_tokens = _estimate_messages_tokens(messages)
            token_triggered = current_tokens > 300000
            time_triggered = compress_counter >= advisor_compress_interval

            # 如果上下文本身很小（<50K tokens），跳过压缩——注入摘要反而会增加 token
            if current_tokens < 50000:
                compress_counter = 0
                continue

            if token_triggered or time_triggered:
                compress_counter = 0
                reason = "token_threshold" if token_triggered else "scheduled"
                if token_triggered:
                    logger.info(f"[Query] Compression triggered: context at {current_tokens:,} tokens (>300K)")

                try:
                    summary = await advisor.compress_conversation(messages)
                    if summary:
                        _last_progress_summary = summary

                        # 构建压缩后的上下文
                        # 主动删除旧的 [PROGRESS_SUMMARY] 和 [ADVISOR_HISTORY]，用新的替换
                        messages_without_old_summaries = [
                            msg for msg in messages
                            if not (msg.get("role") == "system" and
                                    ("[PROGRESS_SUMMARY]" in msg.get("content", "") or
                                     "[ADVISOR_HISTORY]" in msg.get("content", "")))
                        ]

                        preserved_head = messages_without_old_summaries[:1]  # system

                        summary_msg = {
                            "role": "system",
                            "content": f"[PROGRESS_SUMMARY]\n{summary}",
                        }

                        # 注入 Advisor 干预历史（压缩后存活）
                        context_parts = [summary_msg]
                        if _advisor_intervention_history:
                            history_lines = []
                            for item in _advisor_intervention_history:
                                history_lines.append(
                                    f"  T{item['turn']}: {item['guidance']}"
                                )
                            advisor_context_msg = {
                                "role": "system",
                                "content": f"[ADVISOR_HISTORY]\n最近 Advisor 干预记录：\n" + "\n".join(history_lines),
                            }
                            context_parts.append(advisor_context_msg)

                        # 动态计算尾部保留轮数：确保压缩后 < 50K tokens
                        head_tokens = _estimate_messages_tokens(preserved_head + context_parts)
                        target_tail_tokens = max(0, 50000 - head_tokens)

                        if target_tail_tokens <= 0:
                            # 头部+上下文已超过 50K tokens，警告但继续
                            logger.warning(f"[Query] Compression: head+context already {head_tokens:,} tokens (>50K), keeping minimal tail")
                            tail_messages = []
                        else:
                            # 从尾部向前累积，确保 assistant tool_calls 和 tool results 的连续性
                            # 消息追加顺序保证：assistant_msg → tool_result_1 → tool_result_2 → ... → 系统消息
                            # 所以从后往前遍历时，tool results 总是先于对应的 assistant 被包含
                            tail_messages = []
                            tail_accu_tokens = 0
                            for msg in reversed(messages_without_old_summaries[1:]):  # 从尾部向前（跳过 system）
                                msg_tokens = _estimate_messages_tokens([msg])
                                if tail_accu_tokens + msg_tokens > target_tail_tokens:
                                    break
                                tail_accu_tokens += msg_tokens
                                tail_messages.insert(0, msg)

                        removed = len(messages_without_old_summaries) - len(preserved_head) - len(context_parts) - len(tail_messages)
                        messages[:] = preserved_head + context_parts + tail_messages

                        # 压缩后重置 Advisor 状态（已被移除的消息不应再被引用）
                        _unaddressed_guidance.clear()  # 历史建议已写入摘要，不再单独引用
                        if advisor:
                            advisor.reset_thinking_buffer()  # 仅重置 thinking buffer，保留 recon 缓存

                        # 验证压缩结果
                        post_tokens = _estimate_messages_tokens(messages)
                        if post_tokens > 50000:
                            logger.warning(f"[Query] Post-compression tokens ({post_tokens:,}) still exceeds 50K target")
                        loop_detector.reset()  # 上下文重置后循环检测也重置
                        yield {"type": "context_compressed", "summary": summary, "removed": removed,
                               "pre_tokens": current_tokens, "post_tokens": post_tokens}
                        logger.info(f"[Query] Context compressed ({reason}): {current_tokens:,} → {post_tokens:,} tokens, removed {removed} messages")
                except Exception as e:
                    logger.warning(f"[Query] Context compression failed: {e}")
                    compress_counter = 0  # 重置计数器，下轮立即尝试

    # 停止 Advisor 后台循环
    _stop_advisor()
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

    # 执行工具（通过 MCP）— 带 per-tool timeout + 状态注入
    try:
        if "__" not in tool_name:
            raise ValueError(f"Invalid tool name: {tool_name}. Expected format: server__tool")

        server, tool = tool_name.split("__", 1)

        # 注入 [TOOL_STARTED]
        args_preview = function.get("arguments", "{}")[:150]
        _inject_status(messages, f"[TOOL_STARTED] {tool_name}({args_preview})")

        # 提取 timeout 参数
        call_timeout = arguments.get("timeout", 600)
        call_timeout = min(call_timeout, 1800)

        # 带超时的工具调用
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
            _inject_status(messages,
                f"[TOOL_TIMEOUT] {tool_name} — timed out after {call_timeout}s"
            )
    except Exception as e:
        result_str = json.dumps({"status": "error", "error": str(e)}, ensure_ascii=False)
        _inject_status(messages,
            f"[TOOL_FAILED] {tool_name} — error: {str(e)[:200]}"
        )

    # === 空输出智能检测（bash 命令）=== Sequential path
    global _turn_empty_bash_count
    if "bash" in tool_name.lower():
        try:
            result_data = json.loads(result_str)
            stdout_val = result_data.get("stdout", "")
        except (json.JSONDecodeError, AttributeError):
            stdout_val = ""
        if stdout_val is None:
            stdout_val = ""
        if not stdout_val.strip():
            async with _empty_count_lock:
                _turn_empty_bash_count += 1
                current_count = _turn_empty_bash_count
            empty_hint = "\n\n[EMPTY_OUTPUT] 命令执行成功但无输出。可能原因：(1)权限不足 (2)命令不存在 (3)输出被过滤。请检查命令是否适合当前环境。"
            result_str += empty_hint
            if current_count >= 3:
                strategy_hint = f"\n[STRATEGY_HINT] 连续{current_count}次命令无输出。建议：换一种方法，或使用 search_skills 寻找新思路。"
                result_str += strategy_hint
        else:
            async with _empty_count_lock:
                _turn_empty_bash_count = 0
    else:
        async with _empty_count_lock:
            _turn_empty_bash_count = 0

    # === Flag 自动检测：扫描工具输出 ===
    flags_found = _scan_for_flags(result_str)
    if flags_found:
        flag_notice = (
            f"\n\n[FLAG_DETECTED] Found potential flag(s): {', '.join(flags_found)}\n"
            f"SUBMIT IMMEDIATELY: submit_flag(code=..., flag=\"{flags_found[0]}\")"
        )
        result_str += flag_notice

        # D3: 半自动提交 — 如果已知当前 challenge code，同时尝试自动提交
        if _current_challenge_code:
            code = _current_challenge_code
            flag = flags_found[0]
            logger.info(f"[Query] Auto-submitting flag for {code}: {flag[:20]}...")
            try:
                submit_result = await client.call_tool(
                    "competition", "submit_flag",
                    {"code": code, "flag": flag},
                )
                submit_str = str(submit_result)
                result_str += f"\n[AUTO_SUBMIT] submit_flag({code}): {submit_str[:200]}"
            except Exception as e:
                result_str += f"\n[AUTO_SUBMIT_FAILED] {e}"

    # 注入 [TOOL_COMPLETED]（顺序路径）
    _inject_status(messages,
        f"[TOOL_COMPLETED] {tool_name} — {len(result_str)} chars output"
    )

    messages.append({"role": "tool", "tool_call_id": tool_id, "content": result_str})
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
    """并行执行多个工具调用，实时注入状态到 messages"""

    status_queue: asyncio.Queue = asyncio.Queue()
    running_tasks: Dict[str, asyncio.Task] = {}
    final_results: Dict[str, Dict] = {}

    # 1. 为每个工具注册状态 + 启动任务 + 注入 [TOOL_STARTED]
    for i, tc in enumerate(tool_calls):
        tool_id = tc.get("id", f"call_{turn}_{i}")
        tool_name = tc.get("function", {}).get("name", "")
        args = tc.get("function", {}).get("arguments", "{}")
        args_preview = args[:150] if len(args) > 150 else args

        _tool_execution_state[tool_id] = {
            "status": "running",
            "start_time": time.time(),
            "tool_name": tool_name,
            "args_preview": args_preview,
        }

        # 注入启动状态 — Agent 和 Advisor 都能看到
        _inject_status(messages,
            f"[TOOL_STARTED] {tool_name}({args_preview})"
        )

        yield {"type": "tool_start", "tool_id": tool_id, "tool_name": tool_name, "turn": turn}
        running_tasks[tool_id] = asyncio.create_task(
            _exec_one(tc, i, client, loop_detector, messages, turn)
        )

    # 2. 启动后台看门狗（注入 [TOOL_RUNNING]）
    watchdog_task = asyncio.create_task(
        _watchdog_loop(running_tasks, turn, status_queue, messages)
    )

    # 3. 主循环：等待任务完成 + 排水状态队列
    pending_ids = set(running_tasks.keys())
    while pending_ids:
        done_ids = [tid for tid in pending_ids if running_tasks[tid].done()]
        for tid in done_ids:
            pending_ids.discard(tid)
            result = running_tasks[tid].result()
            elapsed = time.time() - _tool_execution_state[tid]["start_time"]

            # 注入完成状态
            tool_name = result.get("tool_name", _tool_execution_state[tid]["tool_name"])
            if result.get("has_error"):
                _inject_status(messages,
                    f"[TOOL_FAILED] {tool_name} — {elapsed:.1f}s — {result.get('error_detail', 'unknown error')}"
                )
            else:
                _inject_status(messages,
                    f"[TOOL_COMPLETED] {tool_name} — {elapsed:.1f}s — {result.get('result_length', 0)} chars output"
                )

            yield {
                "type": "tool_complete",
                "tool_id": tid,
                "tool_name": tool_name,
                "duration": round(elapsed, 2),
                "has_error": result.get("has_error", False),
                "result_length": result.get("result_length", 0),
            }
            final_results[tid] = result
            _tool_execution_state.pop(tid, None)

        # 排水状态队列（看门狗可能又产出了新状态）
        while not status_queue.empty():
            yield await status_queue.get()

        if pending_ids:
            await asyncio.sleep(0.5)

    # 4. 取消看门狗
    watchdog_task.cancel()
    try:
        await watchdog_task
    except asyncio.CancelledError:
        pass

    # 5. 产出执行摘要
    yield {
        "type": "tool_execution_summary",
        "total": len(tool_calls),
        "errors": sum(1 for r in final_results.values() if r.get("has_error")),
    }


async def _watchdog_loop(
    tasks: Dict[str, asyncio.Task],
    turn: int,
    status_queue: asyncio.Queue,
    messages: List[Dict],
    interval: float = 15.0,
):
    """后台看门狗：每 15 秒注入 [TOOL_RUNNING] 状态到 messages"""
    last_injected = {}  # tool_id -> last injection time
    try:
        while True:
            await asyncio.sleep(interval)
            now = time.time()
            for tool_id, task in tasks.items():
                if task.done():
                    continue
                state = _tool_execution_state.get(tool_id, {})
                elapsed = now - state.get("start_time", now)
                tool_name = state.get("tool_name", "unknown")

                # 避免频繁注入：至少间隔 15 秒
                if tool_id in last_injected and now - last_injected[tool_id] < 15:
                    continue

                last_injected[tool_id] = now

                # 注入运行状态 — Agent 和 Advisor 都能看到
                _inject_status(messages,
                    f"[TOOL_RUNNING] {tool_name} — executing for {elapsed:.0f}s (still in progress, do not re-invoke)"
                )

                # 也推送到状态队列供 CLI 显示
                await status_queue.put({
                    "type": "tool_running",
                    "tool_id": tool_id,
                    "tool_name": tool_name,
                    "elapsed_seconds": round(elapsed, 1),
                    "turn": turn,
                })
    except asyncio.CancelledError:
        pass


async def _exec_one(tc: Dict, index: int, client, loop_detector, messages, turn: int):
    """执行单个工具调用，带 per-tool timeout 和状态注入"""
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

        # 提取 timeout 参数
        call_timeout = arguments.get("timeout", 600)
        call_timeout = min(call_timeout, 1800)

        # 带超时的工具调用
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
            # 注入超时状态
            _inject_status(messages,
                f"[TOOL_TIMEOUT] {tool_name} — timed out after {call_timeout}s"
            )

        # Flag 自动检测
        flags_found = _scan_for_flags(result_str)
        if flags_found:
            result_str += (
                f"\n\n[FLAG_DETECTED] Found potential flag(s): {', '.join(flags_found)}\n"
                f"SUBMIT IMMEDIATELY: submit_flag(code=..., flag=\"{flags_found[0]}\")"
            )
            # D3: 半自动提交
            if _current_challenge_code:
                code = _current_challenge_code
                flag = flags_found[0]
                logger.info(f"[Query] Auto-submit flag (parallel) for {code}: {flag[:20]}...")
                try:
                    submit_result = await client.call_tool(
                        "competition", "submit_flag",
                        {"code": code, "flag": flag},
                    )
                    result_str += f"\n[AUTO_SUBMIT] submit_flag({code}): {str(submit_result)[:200]}"
                except Exception as e:
                    result_str += f"\n[AUTO_SUBMIT_FAILED] {e}"

    except Exception as e:
        result_str = json.dumps({"status": "error", "error": str(e)}, ensure_ascii=False)
        # 注入失败状态
        _inject_status(messages,
            f"[TOOL_FAILED] {tool_name} — error: {str(e)[:200]}"
        )

    # === 空输出智能检测（bash 命令）=== Parallel path (_exec_one)
    global _turn_empty_bash_count
    if "bash" in tool_name.lower():
        try:
            result_data = json.loads(result_str)
            stdout_val = result_data.get("stdout", "")
        except (json.JSONDecodeError, AttributeError):
            stdout_val = ""
        if stdout_val is None:
            stdout_val = ""
        if not stdout_val.strip():
            async with _empty_count_lock:
                _turn_empty_bash_count += 1
                current_count = _turn_empty_bash_count
            empty_hint = "\n\n[EMPTY_OUTPUT] 命令执行成功但无输出。可能原因：(1)权限不足 (2)命令不存在 (3)输出被过滤。请检查命令是否适合当前环境。"
            result_str += empty_hint
            if current_count >= 3:
                strategy_hint = f"\n[STRATEGY_HINT] 连续{current_count}次命令无输出。建议：换一种方法，或使用 search_skills 寻找新思路。"
                result_str += strategy_hint
        else:
            async with _empty_count_lock:
                _turn_empty_bash_count = 0
    else:
        async with _empty_count_lock:
            _turn_empty_bash_count = 0

    messages.append({"role": "tool", "tool_call_id": tool_id, "content": result_str})

    # 提取 error_detail
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
