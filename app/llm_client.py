"""
LLM 客户端 - 企业级标准

对齐 Claude Code 模式:
- 原生异步 HTTP（httpx 连接池复用）
- 指数退避重试（rate limit / 5xx / timeout）
- 多模型 fallback chain
- 结构化错误分类
- Token 统计集成
"""

import asyncio
import httpx
import time
import os
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from enum import Enum

from app.logger import get_logger

logger = get_logger("LLM")


# ============================================================================
# 错误类型
# ============================================================================

class LLMErrorType(Enum):
    """LLM错误分类"""
    SUCCESS = "success"
    TIMEOUT = "timeout"
    AUTH_ERROR = "auth_error"
    RATE_LIMIT = "rate_limit"
    NETWORK_ERROR = "network_error"
    INVALID_RESPONSE = "invalid_response"
    CONTEXT_LENGTH = "context_length"
    UNKNOWN = "unknown"


# ============================================================================
# 结果数据类
# ============================================================================

@dataclass
class LLMResult:
    """LLM调用结果"""
    content: str
    error_type: LLMErrorType
    error_message: str = ""
    retry_count: int = 0
    duration: float = 0.0
    tool_calls: Optional[List[Dict]] = None
    raw_response: Optional[Dict] = None
    model_used: str = ""

    @property
    def success(self) -> bool:
        return self.error_type == LLMErrorType.SUCCESS

    @property
    def retryable(self) -> bool:
        return self.error_type in (
            LLMErrorType.RATE_LIMIT,
            LLMErrorType.NETWORK_ERROR,
            LLMErrorType.TIMEOUT,
        )


# ============================================================================
# 重试策略
# ============================================================================

class RetryPolicy:
    """指数退避重试策略"""

    def __init__(
        self,
        max_retries: int = 3,
        base_delay: float = 1.0,
        max_delay: float = 30.0,
        exponential_base: float = 2.0,
    ):
        self.max_retries = max_retries
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.exponential_base = exponential_base

    def get_delay(self, attempt: int) -> float:
        """计算第 N 次重试的等待时间"""
        delay = self.base_delay * (self.exponential_base ** attempt)
        return min(delay, self.max_delay)

    def should_retry(self, result: LLMResult, attempt: int) -> bool:
        """判断是否应该重试"""
        if attempt >= self.max_retries:
            return False
        return result.retryable


# ============================================================================
# LLM 客户端
# ============================================================================

class LLMClient:
    """
    LLM API 客户端 - 企业级

    特性:
    - httpx 连接池复用（避免每次请求创建新连接）
    - 指数退避重试
    - 多模型 fallback
    - 结构化错误处理
    """

    def __init__(self):
        self._http_client: Optional[httpx.AsyncClient] = None
        self._retry_policy: Optional[RetryPolicy] = None

    def _get_http_client(self, timeout: int = 120) -> httpx.AsyncClient:
        """获取或创建连接池复用的 HTTP 客户端"""
        if self._http_client is None or self._http_client.is_closed:
            self._http_client = httpx.AsyncClient(
                timeout=httpx.Timeout(timeout, connect=10.0),
                limits=httpx.Limits(max_connections=10, max_keepalive_connections=5),
                follow_redirects=True,
            )
        return self._http_client

    def _get_retry_policy(self) -> RetryPolicy:
        """获取重试策略（延迟加载配置）"""
        if self._retry_policy is None:
            from app.settings import config
            self._retry_policy = RetryPolicy(
                max_retries=config.retry.max_retries,
                base_delay=config.retry.base_delay,
                max_delay=config.retry.max_delay,
                exponential_base=config.retry.exponential_base,
            )
        return self._retry_policy

    def _get_config(self) -> Dict[str, Any]:
        """动态获取当前配置"""
        from app.settings import config
        return {
            "api_key": config.model.api_key,
            "base_url": config.model.base_url,
            "model": config.model.name,
            "timeout": config.model.timeout,
            "temperature": config.model.temperature,
            "fallback_models": config.model.fallback_models,
        }

    async def close(self):
        """关闭连接池"""
        if self._http_client and not self._http_client.is_closed:
            await self._http_client.aclose()
            self._http_client = None

    # ----------------------------------------------------------------
    # 核心调用方法
    # ----------------------------------------------------------------

    async def call_chat_completion(
        self,
        model: str,
        messages: List[Dict],
        temperature: float = 0.1,
        max_tokens: Optional[int] = None,
        json_mode: bool = False,
        timeout: int = 120,
        tools: Optional[List[Dict]] = None,
        tool_choice: str = "auto",
    ) -> str:
        """简化接口 - 返回内容字符串"""
        result = await self.call_with_details(
            model=model,
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
            json_mode=json_mode,
            timeout=timeout,
            tools=tools,
            tool_choice=tool_choice,
        )
        return result.content

    async def call_with_details(
        self,
        model: str,
        messages: List[Dict],
        temperature: float = 0.1,
        max_tokens: Optional[int] = None,
        json_mode: bool = False,
        timeout: int = 120,
        tools: Optional[List[Dict]] = None,
        tool_choice: str = "auto",
    ) -> LLMResult:
        """
        带重试和 fallback 的完整调用

        流程:
        1. 尝试主模型，失败则重试（指数退避）
        2. 主模型全部重试失败，尝试 fallback 模型
        3. 返回结构化结果
        """
        cfg = self._get_config()
        retry_policy = self._get_retry_policy()

        # 构建模型列表: 主模型 + fallback
        models_to_try = [model or cfg["model"]]
        for fb in cfg.get("fallback_models", []):
            if fb not in models_to_try:
                models_to_try.append(fb)

        last_result = None
        primary_model_error = None  # 保存主模型的原始错误

        for model_name in models_to_try:
            for attempt in range(retry_policy.max_retries + 1):
                result = await self._single_call(
                    model=model_name,
                    messages=messages,
                    temperature=temperature,
                    max_tokens=max_tokens,
                    json_mode=json_mode,
                    timeout=timeout,
                    tools=tools,
                    tool_choice=tool_choice,
                    api_key=cfg["api_key"],
                    base_url=cfg["base_url"],
                )
                result.retry_count = attempt
                result.model_used = model_name

                if result.success:
                    return result

                last_result = result

                # 保存主模型的原始错误（用于调试）
                if model_name == models_to_try[0] and primary_model_error is None:
                    primary_model_error = result

                # 上下文超长 -> 不重试，需要调用者截断
                if result.error_type == LLMErrorType.CONTEXT_LENGTH:
                    return result

                # 认证错误 -> 不重试
                if result.error_type == LLMErrorType.AUTH_ERROR:
                    return result

                # 判断是否重试
                if not retry_policy.should_retry(result, attempt):
                    break

                delay = retry_policy.get_delay(attempt)
                logger.warning(
                    f"[LLM] {model_name} attempt {attempt + 1} failed: "
                    f"{result.error_type.value} - {result.error_message}. "
                    f"Retrying in {delay:.1f}s..."
                )
                await asyncio.sleep(delay)

            # 当前模型全部重试失败，尝试下一个 fallback
            if len(models_to_try) > 1:
                logger.warning(f"[LLM] {model_name} exhausted, trying next fallback...")

        # 如果最终失败且主模型有错误信息，附加到返回结果
        if last_result and primary_model_error and last_result.model_used != models_to_try[0]:
            logger.info(f"[LLM] Primary model error was: {primary_model_error.error_type.value} - {primary_model_error.error_message[:200]}")

        return last_result or LLMResult(
            content="",
            error_type=LLMErrorType.UNKNOWN,
            error_message="No models available",
        )

    async def _single_call(
        self,
        model: str,
        messages: List[Dict],
        temperature: float,
        max_tokens: Optional[int],
        json_mode: bool,
        timeout: int,
        tools: Optional[List[Dict]],
        tool_choice: str,
        api_key: str,
        base_url: str,
    ) -> LLMResult:
        """单次 API 调用（无重试）"""
        start_time = time.time()
        url = f"{base_url}/chat/completions"
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }

        payload: Dict[str, Any] = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
            "top_p": 0.8,  # Qwen3.6 推荐值
        }

        if max_tokens:
            payload["max_tokens"] = max_tokens

        if json_mode:
            payload["response_format"] = {"type": "json_object"}

        if tools:
            wrapped_tools = []
            for tool in tools:
                if tool.get("type") == "function":
                    wrapped_tools.append(tool)
                else:
                    wrapped_tools.append({"type": "function", "function": tool})
            payload["tools"] = wrapped_tools
            payload["tool_choice"] = tool_choice

        try:
            client = self._get_http_client(timeout)
            response = await client.post(url, headers=headers, json=payload)
            duration = time.time() - start_time

            # 分类 HTTP 状态码
            if response.status_code == 400:
                error_text = response.text
                # 检测上下文超长错误
                if any(kw in error_text.lower() for kw in [
                    "context_length", "max_tokens", "too long", "token limit",
                    "maximum context", "context window",
                ]):
                    return LLMResult("", LLMErrorType.CONTEXT_LENGTH,
                                     f"Context too long: {error_text[:200]}", duration=duration)
                return LLMResult("", LLMErrorType.INVALID_RESPONSE,
                                 f"Bad request: {error_text[:200]}", duration=duration)

            if response.status_code == 401:
                return LLMResult("", LLMErrorType.AUTH_ERROR,
                                 "API key invalid or expired", duration=duration)

            if response.status_code == 429:
                return LLMResult("", LLMErrorType.RATE_LIMIT,
                                 "Rate limit exceeded", duration=duration)

            if response.status_code >= 500:
                return LLMResult("", LLMErrorType.NETWORK_ERROR,
                                 f"Server error: {response.status_code}", duration=duration)

            response.raise_for_status()
            result = response.json()

            # 解析响应
            if "choices" not in result or len(result["choices"]) == 0:
                return LLMResult("", LLMErrorType.INVALID_RESPONSE,
                                 f"No choices in response", duration=duration, raw_response=result)

            choice = result["choices"][0]
            message = choice.get("message", {})
            content = message.get("content", "") or ""
            tool_calls = message.get("tool_calls")

            # 记录 Token 使用
            usage = result.get("usage", {})
            if usage:
                try:
                    from app.memory.token_stats import get_token_stats_manager
                    token_mgr = get_token_stats_manager()
                    token_mgr.record_usage(
                        model=model,
                        prompt_tokens=usage.get("prompt_tokens", 0),
                        completion_tokens=usage.get("completion_tokens", 0),
                    )
                except Exception:
                    pass

            logger.info(f"[LLM] {model} | {duration:.1f}s | "
                        f"content={len(content)}c | tools={len(tool_calls) if tool_calls else 0}")

            return LLMResult(
                content=content,
                error_type=LLMErrorType.SUCCESS,
                duration=duration,
                tool_calls=tool_calls,
                raw_response=result,
            )

        except httpx.TimeoutException:
            return LLMResult("", LLMErrorType.TIMEOUT,
                             f"Timed out after {timeout}s",
                             duration=time.time() - start_time)

        except httpx.RequestError as e:
            return LLMResult("", LLMErrorType.NETWORK_ERROR,
                             f"Network error: {e}",
                             duration=time.time() - start_time)

        except Exception as e:
            return LLMResult("", LLMErrorType.UNKNOWN,
                             str(e),
                             duration=time.time() - start_time)


# ============================================================================
# 全局单例
# ============================================================================

llm_client = LLMClient()

__all__ = ["LLMClient", "LLMResult", "LLMErrorType", "RetryPolicy", "llm_client"]
