#!/usr/bin/env python3
"""
CTF-Agent CLI - 极简单命令行界面
"""

import asyncio
import sys
from app.core.query import query, QueryConfig
from app.prompts.ctf_system_prompt import build_system_prompt
from app.settings import config as app_config


async def main():
    if len(sys.argv) < 2:
        print("Usage: python -m app.cli <target>")
        sys.exit(1)

    target = sys.argv[1]

    # 从配置文件读取模型和超时
    model = app_config.LLM_MODEL
    timeout = app_config.TASK_TIMEOUT

    query_config = QueryConfig(
        model=model,
        max_turns=200,
        timeout_seconds=timeout,
        system_prompt=build_system_prompt(target, timeout),
    )

    messages = []

    # 注入系统提示词
    if query_config.system_prompt:
        messages.append({"role": "system", "content": query_config.system_prompt})

    messages.append({"role": "user", "content": f"Target: {target}\n\nFind the FLAG."})

    async for event in query(messages, query_config):
        if event["type"] == "assistant_message":
            content = event.get("content", "")
            if content:
                print(f"\n[AI] {content}")
        elif event["type"] == "tool_result":
            print(f"[Tool] {event.get('tool_name')}")
        elif event["type"] == "task_complete":
            print(f"\n[Complete] {event.get('reason')}")
            break
        elif event["type"] == "complete":
            print(f"\n[Done] {event.get('reason')}")
            break


if __name__ == "__main__":
    asyncio.run(main())