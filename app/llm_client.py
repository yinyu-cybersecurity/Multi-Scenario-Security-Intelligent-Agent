"""
LLM 客户端模块 - 异步原生设计

遵循Claude Code模式:
- 原生异步HTTP调用（httpx）
- 无同步包装
- 错误直接返回给调用者
- 无复杂重试逻辑（由调用者决定）
"""
import httpx
import time
import os
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from enum import Enum

from app.settings import config
from app.logger import get_logger

logger = get_logger("LLM")


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
    duration: float = 0.0
    tool_calls: Optional[List[Dict]] = None
    raw_response: Optional[Dict] = None  # 原始响应，供调试

    @property
    def success(self) -> bool:
        return self.error_type == LLMErrorType.SUCCESS


class LLMClient:
    """
    LLM API 客户端 - 异步原生设计

    遵循Claude Code模式:
    - 原生异步HTTP（httpx）
    - 无同步包装
    - 错误直接返回
    - 无复杂重试（由调用者决定）
    """

    def __init__(self):
        # 动态配置，每次调用时读取
        pass

    def _get_config(self) -> Dict[str, str]:
        """动态获取当前配置"""
        return {
            "api_key": config.LLM_API_KEY,
            "base_url": config.LLM_BASE_URL
        }

    def _get_headers(self, api_key: str) -> Dict[str, str]:
        """构建请求头"""
        return {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }

    async def call_chat_completion(
        self,
        model: str,
        messages: List[Dict[str, str]],
        temperature: float = 0.1,
        max_tokens: Optional[int] = None,
        json_mode: bool = False,
        timeout: int = 120,
        tools: Optional[List[Dict]] = None,
        tool_choice: str = "auto"
    ) -> str:
        """
        异步调用 Chat Completion API

        Args:
            model: 模型名称
            messages: 消息列表
            temperature: 温度参数
            max_tokens: 最大token数
            json_mode: 是否JSON模式
            timeout: 超时秒数
            tools: 工具schema列表
            tool_choice: 工具选择策略

        Returns:
            AI响应字符串
        """
        result = await self.call_with_details(
            model, messages, temperature, max_tokens, json_mode,
            timeout, tools, tool_choice
        )
        return result.content

    async def call_with_details(
        self,
        model: str,
        messages: List[Dict[str, str]],
        temperature: float = 0.1,
        max_tokens: Optional[int] = None,
        json_mode: bool = False,
        timeout: int = 120,
        tools: Optional[List[Dict]] = None,
        tool_choice: str = "auto"
    ) -> LLMResult:
        """
        异步调用 Chat Completion API - 返回详细结果

        遵循Claude Code模式:
        - 单次调用，无内置重试
        - 错误直接返回给调用者
        - 原生异步HTTP

        Args:
            model: 模型名称
            messages: 消息列表
            temperature: 温度参数
            max_tokens: 最大token数
            json_mode: 是否JSON模式
            timeout: 超时秒数
            tools: 工具schema列表
            tool_choice: 工具选择策略

        Returns:
            LLMResult 详细结果对象
        """
        start_time = time.time()

        # 动态获取当前配置
        cfg = self._get_config()
        url = f"{cfg['base_url']}/chat/completions"
        headers = self._get_headers(cfg['api_key'])

        payload = {
            "model": model,
            "messages": messages,
            "temperature": temperature
        }

        if max_tokens:
            payload["max_tokens"] = max_tokens

        if json_mode:
            payload["response_format"] = {"type": "json_object"}

        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = tool_choice

        try:
            # 原生异步HTTP调用
            async with httpx.AsyncClient(timeout=timeout) as client:
                response = await client.post(
                    url,
                    headers=headers,
                    json=payload
                )

                # 检查HTTP状态码
                if response.status_code == 401:
                    return LLMResult(
                        "",
                        LLMErrorType.AUTH_ERROR,
                        "API key invalid or expired",
                        0,
                        time.time() - start_time
                    )

                elif response.status_code == 429:
                    return LLMResult(
                        "",
                        LLMErrorType.RATE_LIMIT,
                        "Rate limit exceeded",
                        0,
                        time.time() - start_time
                    )

                elif response.status_code >= 500:
                    return LLMResult(
                        "",
                        LLMErrorType.NETWORK_ERROR,
                        f"Server error: {response.status_code}",
                        0,
                        time.time() - start_time
                    )

                response.raise_for_status()

                result = response.json()

                # 解析响应
                if "choices" in result and len(result["choices"]) > 0:
                    choice = result["choices"][0]
                    message = choice["message"]
                    content = message.get("content", "")
                    tool_calls = message.get("tool_calls")

                    return LLMResult(
                        content or "",
                        LLMErrorType.SUCCESS,
                        "",
                        0,
                        time.time() - start_time,
                        tool_calls=tool_calls,
                        raw_response=result
                    )
                else:
                    return LLMResult(
                        "",
                        LLMErrorType.INVALID_RESPONSE,
                        f"Invalid response format: {result}",
                        0,
                        time.time() - start_time
                    )

        except httpx.TimeoutException:
            return LLMResult(
                "",
                LLMErrorType.TIMEOUT,
                f"Request timed out after {timeout}s",
                0,
                time.time() - start_time
            )

        except httpx.RequestError as e:
            return LLMResult(
                "",
                LLMErrorType.NETWORK_ERROR,
                f"Network error: {str(e)}",
                0,
                time.time() - start_time
            )

        except Exception as e:
            return LLMResult(
                "",
                LLMErrorType.UNKNOWN,
                str(e),
                0,
                time.time() - start_time
            )


# 全局客户端实例
llm_client = LLMClient()


# 注意: 不提供safe_开头的包装函数
# 遵循Claude Code模式: 错误直接返回给调用者，由调用者决定如何处理
# 调用者应该检查LLMResult.success字段，而不是期望None作为失败标志
