"""
LLM 客户端模块

提供:
- LLMClient: LLM API 客户端
- LLMResult: 调用结果数据类
- LLMErrorType: 错误类型枚举
- 并发控制与智能重试
- Token统计持久化
"""
import json
import requests
import time
import threading
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, as_completed
from config import config
from logger import get_logger

logger = get_logger("LLM")

# 导入Token统计持久化模块
try:
    from memory.token_stats import get_token_stats_manager
    TOKEN_PERSISTENCE_AVAILABLE = True
except ImportError:
    TOKEN_PERSISTENCE_AVAILABLE = False
    logger.info("Token持久化模块不可用，使用内存存储")


class LLMErrorType(Enum):
    """LLM错误类型"""
    SUCCESS = "success"
    TIMEOUT = "timeout"
    AUTH_ERROR = "auth_error"
    RATE_LIMIT = "rate_limit"
    NETWORK_ERROR = "network_error"
    INVALID_RESPONSE = "invalid_response"
    UNKNOWN = "unknown"


@dataclass
class LLMResult:
    """LLM调用结果"""
    content: str
    error_type: LLMErrorType
    error_message: str = ""
    retry_count: int = 0
    duration: float = 0.0  # 执行耗时

    @property
    def success(self) -> bool:
        return self.error_type == LLMErrorType.SUCCESS


class LLMRateLimiter:
    """
    LLM 并发控制器

    限制并发请求数，防止 API 限流
    """
    def __init__(self, max_concurrent: int = 5):
        self.max_concurrent = max_concurrent
        self._semaphore = threading.Semaphore(max_concurrent)
        self._active_count = 0
        self._lock = threading.Lock()
        # Token使用统计
        self._total_tokens = 0
        self._prompt_tokens = 0
        self._completion_tokens = 0
        self._request_count = 0

    def acquire(self, timeout: float = 30.0) -> bool:
        """获取执行槽位"""
        acquired = self._semaphore.acquire(timeout=timeout)
        if acquired:
            with self._lock:
                self._active_count += 1
        return acquired

    def release(self):
        """释放执行槽位"""
        with self._lock:
            self._active_count -= 1
        self._semaphore.release()

    def record_usage(self, prompt_tokens: int, completion_tokens: int):
        """记录token使用量（同步持久化）"""
        with self._lock:
            self._total_tokens += prompt_tokens + completion_tokens
            self._prompt_tokens += prompt_tokens
            self._completion_tokens += completion_tokens
            self._request_count += 1

        # 持久化存储
        if TOKEN_PERSISTENCE_AVAILABLE:
            try:
                stats_manager = get_token_stats_manager()
                stats_manager.record_usage(prompt_tokens, completion_tokens)
            except Exception as e:
                logger.warning(f"Token持久化失败: {e}")

    def get_status(self) -> Dict:
        """获取当前状态"""
        with self._lock:
            status = {
                "active_requests": self._active_count,
                "max_concurrent": self.max_concurrent,
                "available_slots": self.max_concurrent - self._active_count,
                "total_tokens": self._total_tokens,
                "prompt_tokens": self._prompt_tokens,
                "completion_tokens": self._completion_tokens,
                "request_count": self._request_count
            }

        # 添加今日统计
        if TOKEN_PERSISTENCE_AVAILABLE:
            try:
                stats_manager = get_token_stats_manager()
                persistent_stats = stats_manager.get_stats()
                status["persistent_total_tokens"] = persistent_stats["total_tokens"]
                status["today_tokens"] = persistent_stats["today"]["total_tokens"]
                status["today_requests"] = persistent_stats["today"]["request_count"]
            except Exception as e:
                logger.warning(f"获取持久化统计失败: {e}")

        return status


# 全局限流器
_rate_limiter = LLMRateLimiter(max_concurrent=5)

# 启动时加载历史Token数据
if TOKEN_PERSISTENCE_AVAILABLE:
    try:
        stats_manager = get_token_stats_manager()
        stats = stats_manager.get_stats()
        # 恢复累计值
        _rate_limiter._total_tokens = stats["total_tokens"]
        _rate_limiter._prompt_tokens = stats["prompt_tokens"]
        _rate_limiter._completion_tokens = stats["completion_tokens"]
        _rate_limiter._request_count = stats["request_count"]
        logger.info(f"已恢复历史Token统计: {stats['total_tokens']} tokens, {stats['request_count']} requests")
    except Exception as e:
        logger.warning(f"加载历史Token统计失败: {e}")


class LLMClient:
    """LLM API 客户端 - 增强版"""

    def __init__(self):
        self.api_key = config.LLM_API_KEY
        self.base_url = config.LLM_BASE_URL
        self.headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        self.rate_limiter = _rate_limiter

    def call_chat_completion(
        self,
        model: str,
        messages: List[Dict[str, str]],
        temperature: float = 0.1,
        max_tokens: Optional[int] = None,
        json_mode: bool = False,
        retry_count: int = 3,
        timeout: Optional[int] = None
    ) -> str:
        """
        调用 Chat Completion API (增加重试机制和超时控制)

        Args:
            model: 模型名称
            messages: 消息列表
            temperature: 温度参数
            max_tokens: 最大token数
            json_mode: 是否JSON模式
            retry_count: 重试次数
            timeout: 超时秒数 (可选，默认使用config.LLM_TIMEOUT)

        Returns:
            AI响应字符串
        """
        result = self.call_with_details(model, messages, temperature, max_tokens, json_mode, retry_count, timeout)
        return result.content

    def call_with_details(
        self,
        model: str,
        messages: List[Dict[str, str]],
        temperature: float = 0.1,
        max_tokens: Optional[int] = None,
        json_mode: bool = False,
        retry_count: int = 3,
        timeout: Optional[int] = None
    ) -> LLMResult:
        """
        调用 Chat Completion API，返回详细结果

        增强功能:
        - 并发控制
        - 智能重试（根据错误类型调整策略）
        - 性能监控
        - 可配置超时

        Args:
            model: 模型名称
            messages: 消息列表
            temperature: 温度参数
            max_tokens: 最大token数
            json_mode: 是否JSON模式
            retry_count: 重试次数
            timeout: 超时秒数 (可选，默认使用config.LLM_TIMEOUT)

        Returns:
            LLMResult 详细结果对象
        """
        start_time = time.time()
        tokens_used = 0

        # 并发控制
        if not self.rate_limiter.acquire(timeout=60):
            return LLMResult(
                "",
                LLMErrorType.RATE_LIMIT,
                "并发请求过多，等待超时",
                0,
                time.time() - start_time
            )

        try:
            result = self._call_with_retry(
                model, messages, temperature, max_tokens, json_mode, retry_count, timeout
            )
            result.duration = time.time() - start_time

            # 记录到性能监控
            try:
                from performance import performance_monitor
                # 从结果中提取token使用量
                performance_monitor.record_llm_call(
                    model,
                    result.duration * 1000,  # 转换为毫秒
                    tokens=0,  # token统计由rate_limiter处理
                    success=result.success
                )
            except ImportError:
                pass

            return result
        finally:
            self.rate_limiter.release()

    def _call_with_retry(
        self,
        model: str,
        messages: List[Dict[str, str]],
        temperature: float,
        max_tokens: Optional[int],
        json_mode: bool,
        retry_count: int,
        timeout: Optional[int] = None
    ) -> LLMResult:
        """
        内部重试逻辑 - 根据错误类型智能调整

        Args:
            timeout: 超时秒数 (可选，默认使用config.LLM_TIMEOUT)
        """
        url = f"{self.base_url}/chat/completions"
        request_timeout = timeout if timeout is not None else config.LLM_TIMEOUT

        payload = {
            "model": model,
            "messages": messages,
            "temperature": temperature
        }

        if max_tokens:
            payload["max_tokens"] = max_tokens

        if json_mode:
            payload["response_format"] = {"type": "json_object"}

        last_error_type = LLMErrorType.UNKNOWN
        last_error_msg = ""

        for attempt in range(retry_count):
            try:
                response = requests.post(url, headers=self.headers, json=payload, timeout=request_timeout)

                # 检查HTTP状态码
                if response.status_code == 401:
                    # 认证错误不重试
                    return LLMResult("", LLMErrorType.AUTH_ERROR, "API key invalid or expired", attempt)

                elif response.status_code == 429:
                    # 限流：指数退避
                    last_error_type = LLMErrorType.RATE_LIMIT
                    last_error_msg = "Rate limit exceeded"
                    if attempt < retry_count - 1:
                        wait_time = min(2 ** (attempt + 1), 60)  # 最大60秒
                        logger.info(f"Rate limited, waiting {wait_time}s (attempt {attempt+1}/{retry_count})...")
                        time.sleep(wait_time)
                    continue

                elif response.status_code >= 500:
                    # 服务器错误：线性退避
                    last_error_type = LLMErrorType.NETWORK_ERROR
                    last_error_msg = f"Server error: {response.status_code}"
                    if attempt < retry_count - 1:
                        time.sleep(2 + attempt)
                    continue

                response.raise_for_status()

                result = response.json()

                # 记录token使用量
                if "usage" in result:
                    usage = result["usage"]
                    _rate_limiter.record_usage(
                        usage.get("prompt_tokens", 0),
                        usage.get("completion_tokens", 0)
                    )

                if "choices" in result and len(result["choices"]) > 0:
                    content = result["choices"][0]["message"]["content"]
                    return LLMResult(content, LLMErrorType.SUCCESS, "", attempt)
                else:
                    last_error_type = LLMErrorType.INVALID_RESPONSE
                    last_error_msg = f"Invalid response format: {result}"
                    if attempt < retry_count - 1:
                        time.sleep(1)

            except requests.exceptions.Timeout:
                last_error_type = LLMErrorType.TIMEOUT
                last_error_msg = "Request timed out"
                if attempt < retry_count - 1:
                    logger.info(f"Timeout, retry {attempt+1}/{retry_count}...")
                    time.sleep(2)

            except requests.exceptions.RequestException as e:
                last_error_type = LLMErrorType.NETWORK_ERROR
                last_error_msg = str(e)
                if attempt < retry_count - 1:
                    time.sleep(2)

            except Exception as e:
                last_error_type = LLMErrorType.UNKNOWN
                last_error_msg = str(e)
                break

        # 所有重试失败
        logger.warning(f"All retries failed: {last_error_type.value} - {last_error_msg}")
        return LLMResult("", last_error_type, last_error_msg, retry_count)

    def call_batch(
        self,
        requests_list: List[Dict],
        max_concurrent: int = 3
    ) -> List[LLMResult]:
        """
        批量并发调用 LLM

        Args:
            requests_list: 请求列表，每个元素包含 model, messages, temperature 等
            max_concurrent: 最大并发数

        Returns:
            结果列表，顺序与输入对应
        """
        results = [None] * len(requests_list)

        def call_single(index: int, req: Dict) -> Tuple[int, LLMResult]:
            result = self.call_with_details(
                model=req.get('model', config.ANALYST_MODEL),
                messages=req['messages'],
                temperature=req.get('temperature', 0.1),
                json_mode=req.get('json_mode', False)
            )
            return (index, result)

        with ThreadPoolExecutor(max_workers=max_concurrent) as executor:
            futures = {
                executor.submit(call_single, i, req): i
                for i, req in enumerate(requests_list)
            }

            for future in as_completed(futures):
                try:
                    index, result = future.result(timeout=180)
                    results[index] = result
                except Exception as e:
                    index = futures[future]
                    results[index] = LLMResult("", LLMErrorType.UNKNOWN, str(e))

        return results


# 全局客户端实例
llm_client = LLMClient()


def get_rate_limiter_status() -> Dict:
    """获取限流器状态（用于监控）"""
    return _rate_limiter.get_status()


def safe_call_chat_completion(
    model: str,
    messages: List[Dict[str, str]],
    timeout: int = 30,
    **kwargs
) -> Optional[str]:
    """
    安全的AI调用（带超时和错误处理）

    Args:
        model: 模型名称
        messages: 消息列表
        timeout: 超时秒数
        **kwargs: 其他参数 (temperature, json_mode, max_tokens, retry_count)

    Returns:
        AI响应或None（失败时返回None）
    """
    try:
        response = llm_client.call_chat_completion(
            model=model,
            messages=messages,
            timeout=timeout,
            **kwargs
        )
        return response
    except Exception as e:
        logger.warning(f"[LLM] AI调用失败: {e}")
        return None


def call_with_retry(
    call_func,
    max_retries: int = 3,
    base_delay: float = 1.0,
    **kwargs
) -> Optional[str]:
    """
    带指数退避重试的AI调用

    Args:
        call_func: 调用函数 (如 safe_call_chat_completion)
        max_retries: 最大重试次数
        base_delay: 基础延迟秒数
        **kwargs: 传递给调用函数的参数

    Returns:
        AI响应或None（所有重试失败后返回None）
    """
    for attempt in range(max_retries):
        try:
            result = call_func(**kwargs)
            if result:
                return result
        except Exception as e:
            delay = base_delay * (2 ** attempt)
            logger.warning(f"[LLM] 调用失败，{delay}秒后重试 ({attempt+1}/{max_retries}): {e}")
            time.sleep(delay)

    logger.error(f"[LLM] 所有重试失败 ({max_retries}次)")
    return None


def safe_call_with_details(
    model: str,
    messages: List[Dict[str, str]],
    timeout: int = 30,
    **kwargs
) -> Optional[LLMResult]:
    """
    安全的AI调用（返回详细结果，带超时和错误处理）

    Args:
        model: 模型名称
        messages: 消息列表
        timeout: 超时秒数
        **kwargs: 其他参数

    Returns:
        LLMResult或None（失败时返回None）
    """
    try:
        result = llm_client.call_with_details(
            model=model,
            messages=messages,
            timeout=timeout,
            **kwargs
        )
        return result
    except Exception as e:
        logger.warning(f"[LLM] AI调用失败: {e}")
        return None
