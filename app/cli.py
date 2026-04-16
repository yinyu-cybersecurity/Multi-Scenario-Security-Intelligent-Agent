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
import json
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
        "repl": False,  # 新增智能 REPL 模式
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
        elif arg == "--repl" or arg == "-r":
            args["repl"] = True
        elif arg == "--host":
            i += 1
            args["host"] = sys.argv[i] if i < len(sys.argv) else ""
        elif arg == "--token":
            i += 1
            args["token"] = sys.argv[i] if i < len(sys.argv) else ""
        elif arg == "--timeout":
            i += 1
            try:
                args["timeout"] = int(sys.argv[i]) if i < len(sys.argv) else 0
            except (ValueError, IndexError):
                args["timeout"] = 0
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

    print(f"\n{'─'*60}")
    print(f"  🎯 CTF-Agent | Single Target Mode")
    print(f"{'─'*60}")
    print(f"  📍 Target : {target}")
    print(f"  🤖 Model  : {model}")
    print(f"  ⏱  Timeout: {timeout}s ({timeout//60}min)")
    print(f"{'─'*60}\n")

    qconfig = QueryConfig(
        model=model,
        timeout_seconds=timeout,
        system_prompt=build_system_prompt(target, timeout, competition_mode=False),
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

    print(f"\n{'─'*60}")
    print(f"  🏆 CTF-Agent | Competition Auto-Solve Mode")
    print(f"{'─'*60}")
    print(f"  🤖 Model  : {model}")
    print(f"  ⏱  Timeout: {timeout}s ({timeout//60}min)")
    print(f"  🎮 Mode   : AI Full Autonomous")
    print(f"{'─'*60}\n")

    qconfig = QueryConfig(
        model=model,
        timeout_seconds=0,  # 比赛模式不禁用超时，由比赛服务器控制
        system_prompt=build_system_prompt("competition", timeout, competition_mode=True),
        parallel_tool_calls=app_config.query.parallel_tool_calls,
        competition_mode=True,
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
    """处理 Query 事件流 - 复刻 Claude Code CLI 显示风格"""
    etype = event.get("type", "")

    if etype == "assistant_message":
        content = event.get("content", "")
        turn = event.get("turn", 0)
        remaining = event.get("time_remaining", 0)
        tool_calls = event.get("tool_calls", [])

        # 显示 AI 思考内容
        if content:
            display = content if len(content) <= 500 else content[:500] + "..."
            print(f"\n[AI|T{turn}|{remaining}s] {display}")

        # 显示工具调用详情
        if tool_calls:
            for tc in tool_calls:
                func = tc.get("function", {})
                tool_name = func.get("name", "?")
                args_str = func.get("arguments", "{}")

                # 解析参数
                try:
                    args = json.loads(args_str)
                except json.JSONDecodeError:
                    args = {}

                # 提取服务器和工具名
                if "__" in tool_name:
                    server, tool = tool_name.split("__", 1)
                    display_name = f"{tool}"
                else:
                    display_name = tool_name

                # 特殊处理 bash 命令显示
                if tool == "bash" and "command" in args:
                    cmd = args["command"]
                    # 截断长命令
                    cmd_display = cmd if len(cmd) <= 80 else cmd[:77] + "..."
                    print(f"  → {display_name}({cmd_display})")
                elif tool == "http" and "url" in args:
                    url = args["url"]
                    method = args.get("method", "GET")
                    parts = [f"{method} {url[:50]}"]
                    # 显示关键参数
                    if "body" in args:
                        body = str(args["body"])[:50]
                        parts.append(f"body='{body}'")
                    if "data" in args:
                        data = str(args["data"])[:50]
                        parts.append(f"data='{data}'")
                    if "json" in args:
                        j = str(args["json"])[:50]
                        parts.append(f"json={j}")
                    if "headers" in args and args["headers"]:
                        h = str(args["headers"])[:40]
                        parts.append(f"headers={h}")
                    print(f"  → {display_name}({', '.join(parts)})")
                elif tool == "remember":
                    key = args.get("key", "")
                    print(f"  → {display_name}(key=\"{key}\")")
                elif tool == "recall":
                    query = args.get("query", "")
                    print(f"  → {display_name}(query=\"{query}\")")
                else:
                    # 通用显示：显示关键参数
                    key_args = []
                    for k, v in args.items():
                        if k in ("command", "url", "path", "query", "key", "value", "code", "flag"):
                            val_str = str(v)[:40]
                            key_args.append(f"{k}={val_str!r}")
                    if key_args:
                        print(f"  → {display_name}({', '.join(key_args)})")
                    else:
                        print(f"  → {display_name}()")

    elif etype == "tool_result":
        tool_name = event.get("tool_name", "")
        result_preview = event.get("result_preview", "")
        result_length = event.get("result_length", 0)
        has_error = event.get("has_error", False)
        is_loop = event.get("is_loop", False)

        # 提取工具名
        if "__" in tool_name:
            server, tool = tool_name.split("__", 1)
            display_name = tool
        else:
            display_name = tool_name

        if is_loop:
            print(f"  ← {display_name}: [LOOP DETECTED] 跳过重复调用")
        elif has_error:
            # 显示错误信息
            error_preview = result_preview[:100] if result_preview else "error"
            print(f"  ← {display_name}: ❌ {error_preview}")
        else:
            # 显示结果摘要
            if result_length > 200:
                print(f"  ← {display_name}: ✓ ({result_length} chars)")
            elif result_preview:
                # 显示简短结果
                preview = result_preview[:100].replace("\n", " ")
                print(f"  ← {display_name}: {preview}")
            else:
                print(f"  ← {display_name}: ✓")

    elif etype == "loop_detected":
        tool = event.get("tool", "")
        print(f"  [!] Loop detected: {tool}")

    elif etype == "context_trimmed":
        removed = event.get("removed", 0)
        reason = event.get("reason", "")
        if reason:
            print(f"  [~] Context trimmed: {removed} messages ({reason})")
        else:
            print(f"  [~] Context trimmed: {removed} messages removed")

    elif etype == "llm_error":
        print(f"  [!] LLM error: {event.get('error', '')}")

    elif etype == "reflection_prompted":
        elapsed = event.get("elapsed_minutes", 0)
        print(f"  [↩] Reflection triggered ({elapsed} min elapsed)")

    elif etype == "duplicate_calls_recovered":
        count = event.get("count", 0)
        tool = event.get("tool", "")
        print(f"  [↩] Duplicate calls recovered: {count}x {tool} → deduplicated")

    elif etype == "recovery_triggered":
        reason = event.get("reason", "")
        print(f"  [↩] Stuck recovery triggered: {reason}")

    elif etype == "task_complete":
        flags = event.get("flags", [])
        reason = event.get("reason", "")
        flags_found.extend(flags)
        print(f"\n✅ [COMPLETE] {reason}")
        if flags:
            for f in flags:
                print(f"  🚩 FLAG: {f}")

    elif etype == "complete":
        reason = event.get("reason", "")
        print(f"\n⏹ [DONE] {reason}")


def _print_summary(flags_found: list, elapsed: float):
    """打印执行摘要"""
    print(f"\n{'─'*60}")
    print(f"  📊 Execution Summary")
    print(f"{'─'*60}")
    print(f"  ⏱  Time   : {elapsed:.0f}s ({elapsed/60:.1f}min)")
    print(f"  🚩 Flags  : {len(flags_found)}")
    if flags_found:
        for f in flags_found:
            print(f"       • {f}")
    print(f"{'─'*60}\n")


def _run():
    """入口 - 根据模式决定是否使用 asyncio"""
    args = parse_args()

    # 应用命令行参数到环境变量
    if args["host"]:
        os.environ["COMPETITION_SERVER_HOST"] = args["host"]
    if args["token"]:
        os.environ["COMPETITION_AGENT_TOKEN"] = args["token"]

    # 无参数时显示用法
    if not args["target"] and not args["competition"] and not args["interactive"] and not args["repl"]:
        if os.environ.get("COMPETITION_SERVER_HOST") and os.environ.get("COMPETITION_AGENT_TOKEN"):
            args["competition"] = True
        else:
            print("CTF-Agent - AI Autonomous Penetration Testing")
            print()
            print("Usage:")
            print("  python -m app.cli <target_url>              Single target attack")
            print("  python -m app.cli --repl                     Smart interactive REPL")
            print("  python -m app.cli --competition              Competition auto-solve")
            print("  python -m app.cli --competition --host H --token T")
            print("  python -m app.cli --interactive              Legacy interactive mode")
            print()
            print("Environment Variables:")
            print("  LLM_API_KEY                 LLM API key (required)")
            print("  COMPETITION_SERVER_HOST     Competition server host")
            print("  COMPETITION_AGENT_TOKEN     Competition agent token")
            sys.exit(1)

    # REPL 和 interactive 模式有自己的事件循环
    if args["repl"]:
        from app.repl import main as repl_main
        repl_main()
    elif args["interactive"]:
        from app.interactive import main as interactive_main
        interactive_main()
    else:
        # 异步模式：competition 或 single target
        asyncio.run(main_async(args))


async def main_async(args: dict):
    """异步主函数"""
    if args["competition"]:
        await run_competition(args["timeout"])
    else:
        await run_single_target(args["target"], args["timeout"])


if __name__ == "__main__":
    _run()
