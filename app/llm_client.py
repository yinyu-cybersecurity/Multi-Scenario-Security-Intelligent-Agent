"""
LLM 客户端模块

提供:
- LLMClient: LLM API 客户端
- LLMResult: 调用结果数据类
- LLMErrorType: 错误类型枚举
- 并发控制与智能重试
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

    def get_status(self) -> Dict:
        """获取当前状态"""
        with self._lock:
            return {
                "active_requests": self._active_count,
                "max_concurrent": self.max_concurrent,
                "available_slots": self.max_concurrent - self._active_count
            }


# 全局限流器
_rate_limiter = LLMRateLimiter(max_concurrent=5)


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
        retry_count: int = 3
    ) -> str:
        """
        调用 Chat Completion API (增加重试机制)
        返回字符串以保持向后兼容
        """
        result = self.call_with_details(model, messages, temperature, max_tokens, json_mode, retry_count)
        return result.content

    def call_with_details(
        self,
        model: str,
        messages: List[Dict[str, str]],
        temperature: float = 0.1,
        max_tokens: Optional[int] = None,
        json_mode: bool = False,
        retry_count: int = 3
    ) -> LLMResult:
        """
        调用 Chat Completion API，返回详细结果

        增强功能:
        - 并发控制
        - 智能重试（根据错误类型调整策略）
        """
        start_time = time.time()

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
                model, messages, temperature, max_tokens, json_mode, retry_count
            )
            result.duration = time.time() - start_time
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
        retry_count: int
    ) -> LLMResult:
        """
        内部重试逻辑 - 根据错误类型智能调整
        """
        url = f"{self.base_url}/chat/completions"

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
                response = requests.post(url, headers=self.headers, json=payload, timeout=config.LLM_TIMEOUT)

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
                        print(f"[LLM] Rate limited, waiting {wait_time}s (attempt {attempt+1}/{retry_count})...")
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
                    print(f"[LLM] Timeout, retry {attempt+1}/{retry_count}...")
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
        print(f"[LLM] All retries failed: {last_error_type.value} - {last_error_msg}")
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
