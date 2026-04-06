#!/usr/bin/env python3
"""
CTF-Agent CLI - 支持单题模式 + 比赛自动模式

用法:
  # 单题攻击
  python -m app.cli http://target.com

  # 比赛自动模式（AI全自主）
  python -m app.cli --competition

  # 比赛模式（指定平台）
  python -m app.cli --competition --host competition.host.com --token your-token

  # 交互模式
  python -m app.cli --interactive
"""

import asyncio
import os
import sys
import time
from datetime import datetime

from app.core.query import query, QueryConfig
from app.prompts.ctf_system_prompt import build_system_prompt
from app.settings import config as app_config
from app.logger import get_logger, set_task

logger = get_logger("CLI")


def parse_args():
    """解析命令行参数"""
    args = {
        "target": "",
        "competition": False,
        "interactive": False,
        "host": "",
        "token": "",
        "timeout": 0,
        "auto_solve": True,  # 比赛模式默认全自动
    }

    i = 1
    while i < len(sys.argv):
        arg = sys.argv[i]
        if arg == "--competition" or arg == "-c":
            args["competition"] = True
        elif arg == "--interactive" or arg == "-i":
            args["interactive"] = True
        elif arg == "--host":
            i += 1
            args["host"] = sys.argv[i] if i < len(sys.argv) else ""
        elif arg == "--token":
            i += 1
            args["token"] = sys.argv[i] if i < len(sys.argv) else ""
        elif arg == "--timeout":
            i += 1
            args["timeout"] = int(sys.argv[i]) if i < len(sys.argv) else 0
        elif not arg.startswith("-"):
            args["target"] = arg
        i += 1

    return args


async def run_single_target(target: str, timeout: int = 0):
    """单题攻击模式"""
    timeout = timeout or app_config.TASK_TIMEOUT
    model = app_config.LLM_MODEL

    # 设置任务日志
    task_id = f"single_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    set_task(task_id)

    print(f"\n{'='*60}")
    print(f"  CTF-Agent | Single Target Mode")
    print(f"  Target : {target}")
    print(f"  Model  : {model}")
    print(f"  Timeout: {timeout}s ({timeout//60}min)")
    print(f"{'='*60}\n")

    qconfig = QueryConfig(
        model=model,
        max_turns=app_config.query.max_turns,
        timeout_seconds=timeout,
        system_prompt=build_system_prompt(target, timeout, competition_mode=False),
        context_window_tokens=app_config.query.context_window_tokens,
        parallel_tool_calls=app_config.query.parallel_tool_calls,
    )

    messages = [
        {"role": "system", "content": qconfig.system_prompt},
        {"role": "user", "content": f"Target: {target}\n\nFind the FLAG."},
    ]

    flags_found = []
    start_time = time.time()

    async for event in query(messages, qconfig):
        _handle_event(event, flags_found)
        if event["type"] in ("task_complete", "complete"):
            break

    elapsed = time.time() - start_time
    _print_summary(flags_found, elapsed)


async def run_competition(timeout: int = 0):
    """
    比赛自动模式 - AI 全自主

    AI 自己负责:
    - 获取题目列表
    - 选择攻击顺序
    - 启动/停止实例
    - 攻击并提交 FLAG
    - 切换到下一题
    """
    timeout = timeout or app_config.TASK_TIMEOUT * 10  # 比赛模式给更长时间
    model = app_config.LLM_MODEL

    task_id = f"competition_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    set_task(task_id)

    print(f"\n{'='*60}")
    print(f"  CTF-Agent | Competition Auto-Solve Mode")
    print(f"  Model  : {model}")
    print(f"  Timeout: {timeout}s ({timeout//60}min)")
    print(f"  Mode   : AI Full Autonomous")
    print(f"{'='*60}\n")

    qconfig = QueryConfig(
        model=model,
        max_turns=app_config.query.max_turns,
        timeout_seconds=timeout,
        system_prompt=build_system_prompt("competition", timeout, competition_mode=True),
        context_window_tokens=app_config.query.context_window_tokens,
        parallel_tool_calls=app_config.query.parallel_tool_calls,
    )

    messages = [
        {"role": "system", "content": qconfig.system_prompt},
        {"role": "user", "content": (
            "Competition mode activated. You are fully autonomous.\n\n"
            "Start by calling list_challenges to see available challenges, "
            "then solve as many as possible for maximum score.\n\n"
            "You decide everything: which challenge to attempt, attack strategy, "
            "when to move on, resource management. Go."
        )},
    ]

    flags_found = []
    start_time = time.time()

    async for event in query(messages, qconfig):
        _handle_event(event, flags_found)
        if event["type"] in ("task_complete", "complete"):
            break

    elapsed = time.time() - start_time
    _print_summary(flags_found, elapsed)


def _handle_event(event: dict, flags_found: list):
    """处理 Query 事件流"""
    etype = event.get("type", "")

    if etype == "assistant_message":
        content = event.get("content", "")
        turn = event.get("turn", 0)
        remaining = event.get("time_remaining", 0)
        tool_calls = event.get("tool_calls", [])

        if content:
            # 控制台输出 AI 思考内容
            display = content if len(content) <= 500 else content[:500] + "..."
            print(f"\n[AI|T{turn}|{remaining}s] {display}")

        if tool_calls:
            tools_str = ", ".join(
                tc.get("function", {}).get("name", "?") for tc in tool_calls
            )
            print(f"  -> Calling: {tools_str}")

    elif etype == "tool_result":
        tool_name = event.get("tool_name", "")
        print(f"  <- {tool_name}")

    elif etype == "loop_detected":
        print(f"  [!] Loop detected: {event.get('tool', '')}")

    elif etype == "context_trimmed":
        removed = event.get("removed", 0)
        print(f"  [~] Context trimmed: {removed} messages removed")

    elif etype == "llm_error":
        print(f"  [!] LLM error: {event.get('error', '')}")

    elif etype == "task_complete":
        flags = event.get("flags", [])
        reason = event.get("reason", "")
        flags_found.extend(flags)
        print(f"\n[COMPLETE] {reason}")
        if flags:
            for f in flags:
                print(f"  FLAG: {f}")

    elif etype == "complete":
        reason = event.get("reason", "")
        print(f"\n[DONE] {reason}")


def _print_summary(flags_found: list, elapsed: float):
    """打印执行摘要"""
    print(f"\n{'='*60}")
    print(f"  Execution Summary")
    print(f"  Time   : {elapsed:.0f}s ({elapsed/60:.1f}min)")
    print(f"  Flags  : {len(flags_found)}")
    if flags_found:
        for f in flags_found:
            print(f"    {f}")
    print(f"{'='*60}\n")


async def main():
    args = parse_args()

    # 应用命令行参数到环境变量
    if args["host"]:
        os.environ["COMPETITION_SERVER_HOST"] = args["host"]
    if args["token"]:
        os.environ["COMPETITION_AGENT_TOKEN"] = args["token"]

    # 无参数时显示用法
    if not args["target"] and not args["competition"] and not args["interactive"]:
        # 检查环境变量是否已设置比赛模式
        if os.environ.get("COMPETITION_SERVER_HOST") and os.environ.get("COMPETITION_AGENT_TOKEN"):
            args["competition"] = True
        else:
            print("CTF-Agent - AI Autonomous Penetration Testing")
            print()
            print("Usage:")
            print("  python -m app.cli <target_url>              Single target attack")
            print("  python -m app.cli --competition              Competition auto-solve")
            print("  python -m app.cli --competition --host H --token T")
            print("  python -m app.cli --interactive              Interactive mode")
            print()
            print("Environment Variables:")
            print("  LLM_API_KEY                 LLM API key (required)")
            print("  COMPETITION_SERVER_HOST     Competition server host")
            print("  COMPETITION_AGENT_TOKEN     Competition agent token")
            sys.exit(1)

    if args["interactive"]:
        from app.interactive import main as interactive_main
        interactive_main()
    elif args["competition"]:
        await run_competition(args["timeout"])
    else:
        await run_single_target(args["target"], args["timeout"])


if __name__ == "__main__":
    asyncio.run(main())
