#!/usr/bin/env python3
"""
CTF-Agent CLI - 极简单命令行界面
"""

import asyncio
import os
import sys
from app.core.query import query, QueryConfig
from app.prompts.ctf_system_prompt import build_system_prompt
from app.settings import config as app_config


async def main():
    if len(sys.argv) < 2:
        print("Usage: python -m app.cli <target> [competition_host] [competition_token]")
        print("")
        print("Examples:")
        print("  python -m app.cli http://target.com")
        print("  python -m app.cli http://target.com competition.host.com your-token")
        sys.exit(1)

    target = sys.argv[1]

    # 支持命令行参数设置比赛平台
    if len(sys.argv) >= 4:
        os.environ["COMPETITION_SERVER_HOST"] = sys.argv[2]
        os.environ["COMPETITION_AGENT_TOKEN"] = sys.argv[3]

    # 检测比赛模式
    competition_host = os.environ.get("COMPETITION_SERVER_HOST", "")
    competition_token = os.environ.get("COMPETITION_AGENT_TOKEN", "")
    is_competition = bool(competition_host) and bool(competition_token)

    # 从配置文件读取模型和超时
    model = app_config.LLM_MODEL
    timeout = app_config.TASK_TIMEOUT

    query_config = QueryConfig(
        model=model,
        max_turns=200,
        timeout_seconds=timeout,
        system_prompt=build_system_prompt(target, timeout, competition_mode=is_competition),
    )

    messages = []

    # 注入系统提示词
    if query_config.system_prompt:
        messages.append({"role": "system", "content": query_config.system_prompt})

    # 根据模式设置初始消息
    if is_competition:
        messages.append({"role": "user", "content": f"比赛模式已启用。请先获取题目列表，选择一个题目开始攻击。"})
    else:
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