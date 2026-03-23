import json
import requests
import time
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
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

    @property
    def success(self) -> bool:
        return self.error_type == LLMErrorType.SUCCESS


class LLMClient:
    """LLM API 客户端"""

    def __init__(self):
        self.api_key = config.LLM_API_KEY
        self.base_url = config.LLM_BASE_URL
        self.headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }

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

        for i in range(retry_count):
            try:
                response = requests.post(url, headers=self.headers, json=payload, timeout=120)

                # 检查HTTP状态码
                if response.status_code == 401:
                    return LLMResult("", LLMErrorType.AUTH_ERROR, "API key invalid or expired", i)
                elif response.status_code == 429:
                    last_error_type = LLMErrorType.RATE_LIMIT
                    last_error_msg = "Rate limit exceeded"
                    if i < retry_count - 1:
                        wait_time = 2 ** (i + 1)  # 指数退避
                        print(f"[LLM] Rate limited, waiting {wait_time}s...")
                        time.sleep(wait_time)
                    continue
                elif response.status_code >= 500:
                    last_error_type = LLMErrorType.NETWORK_ERROR
                    last_error_msg = f"Server error: {response.status_code}"
                    if i < retry_count - 1:
                        time.sleep(2)
                    continue

                response.raise_for_status()

                result = response.json()
                if "choices" in result and len(result["choices"]) > 0:
                    content = result["choices"][0]["message"]["content"]
                    return LLMResult(content, LLMErrorType.SUCCESS, "", i)
                else:
                    last_error_type = LLMErrorType.INVALID_RESPONSE
                    last_error_msg = f"Invalid response format: {result}"
                    if i < retry_count - 1:
                        time.sleep(1)

            except requests.exceptions.Timeout:
                last_error_type = LLMErrorType.TIMEOUT
                last_error_msg = "Request timed out"
                if i < retry_count - 1:
                    print(f"[LLM] Timeout, retry {i+1}/{retry_count}...")
                    time.sleep(2)

            except requests.exceptions.RequestException as e:
                last_error_type = LLMErrorType.NETWORK_ERROR
                last_error_msg = str(e)
                if i < retry_count - 1:
                    time.sleep(2)

            except Exception as e:
                last_error_type = LLMErrorType.UNKNOWN
                last_error_msg = str(e)
                break

        # 所有重试失败
        print(f"[LLM] All retries failed: {last_error_type.value} - {last_error_msg}")
        return LLMResult("", last_error_type, last_error_msg, retry_count)
# 全局客户端实例
llm_client = LLMClient()
