#!/usr/bin/env python3
# app/main.py

"""
CTF-Agent 主入口 - 极简版本

MCP架构：所有工具通过MCP服务器注册
"""

import asyncio
import sys

from app.core.query import query, QueryConfig
from app.prompts.ctf_system_prompt import build_system_prompt
from app.logger import get_logger

logger = get_logger("CTF-Agent")


async def main(target: str):
    """主入口 - 启动Query循环"""

    # 构建配置
    config = QueryConfig(
        model="qwen3.5-plus",
        max_turns=200,
        timeout_seconds=1800,
        system_prompt=build_system_prompt(target, 1800),
    )

    # 初始消息
    messages = [{
        "role": "user",
        "content": f"Target: {target}\n\nFind the FLAG."
    }]

    # 启动Query循环
    logger.info(f"Target: {target}")
    logger.info(f"Model: {config.model}")
    logger.info(f"Timeout: {config.timeout_seconds}s")

    async for event in query(messages, config):
        if event["type"] == "assistant_message":
            content = event.get("content", "")
            tool_calls = event.get("tool_calls", [])
            logger.info(f"AI Content: {content}")
            logger.info(f"AI Tool Calls: {tool_calls}")
        elif event["type"] == "tool_result":
            logger.info(f"Tool: {event['tool_name']}")
        elif event["type"] == "complete":
            logger.info(f"Complete: {event['reason']}")
            break
        elif event["type"] == "loop_detected":
            logger.warning(f"Loop detected: {event['tool']}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python -m app.main <target_url>")
        sys.exit(1)

    target = sys.argv[1]
    asyncio.run(main(target))