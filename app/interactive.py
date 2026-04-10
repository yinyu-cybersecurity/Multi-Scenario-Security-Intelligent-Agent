#!/usr/bin/env python3
"""
CTF-Agent 交互式模式

支持:
- 实时输出 AI 决策过程
- 输入反馈引导 AI 策略
- Stop/Pause 控制
- 比赛模式 + 单题模式
"""

import asyncio
import sys
import signal
import os
from typing import Optional
from datetime import datetime

from app.core.query import query, QueryConfig
from app.prompts.ctf_system_prompt import build_system_prompt
from app.settings import config as app_config
from app.logger import get_logger, set_task

logger = get_logger("Interactive")


class InteractiveSession:
    """交互式会话"""

    def __init__(self):
        self.running = False
        self.paused = False
        self.messages = []
        self.flags_found = []

    async def run(self, target: str, timeout: int = 1800, competition: bool = False):
        """运行攻击"""
        self.running = True
        self.flags_found = []

        model = app_config.LLM_MODEL
        task_id = f"interactive_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        set_task(task_id)

        qconfig = QueryConfig(
            model=model,
            max_turns=app_config.query.max_turns,
            timeout_seconds=timeout,
            system_prompt=build_system_prompt(target, timeout, competition_mode=competition),
            context_window_tokens=app_config.query.context_window_tokens,
            parallel_tool_calls=app_config.query.parallel_tool_calls,
        )

        self.messages = [{"role": "system", "content": qconfig.system_prompt}]

        if competition:
            self.messages.append({
                "role": "user",
                "content": "Competition mode. Start by listing challenges, then solve them autonomously.",
            })
        else:
            self.messages.append({
                "role": "user",
                "content": f"Target: {target}\n\nFind the FLAG.",
            })

        print(f"\n{'='*60}")
        print(f"  Target : {target}")
        print(f"  Model  : {model}")
        print(f"  Timeout: {timeout}s")
        print(f"{'='*60}\n")

        try:
            async for event in query(self.messages, qconfig):
                if not self.running:
                    print("\n[INTERRUPTED]")
                    break

                while self.paused:
                    await asyncio.sleep(0.5)

                etype = event.get("type", "")

                if etype == "assistant_message":
                    content = event.get("content", "")
                    if content:
                        display = content if len(content) <= 600 else content[:600] + "..."
                        print(f"\n[AI] {display}")
                    tool_calls = event.get("tool_calls", [])
                    if tool_calls:
                        names = [tc.get("function", {}).get("name", "?") for tc in tool_calls]
                        print(f"  -> {', '.join(names)}")

                elif etype == "tool_result":
                    print(f"  <- {event.get('tool_name', '')}")

                elif etype == "loop_detected":
                    print(f"  [!] Loop: {event.get('tool', '')}")

                elif etype == "task_complete":
                    flags = event.get("flags", [])
                    self.flags_found.extend(flags)
                    print(f"\n[COMPLETE] Flags: {flags}")
                    break

                elif etype == "complete":
                    print(f"\n[DONE] {event.get('reason', '')}")
                    break

        except asyncio.CancelledError:
            print("\n[CANCELLED]")

        self.running = False

    def stop(self):
        self.running = False

    def pause(self):
        self.paused = not self.paused
        return self.paused

    def inject_feedback(self, feedback: str):
        """注入用户反馈到消息上下文"""
        if self.running and feedback.strip():
            self.messages.append({"role": "user", "content": feedback})
            return True
        return False


async def interactive_mode():
    """交互式主循环"""
    session = InteractiveSession()
    _active_tasks: set = set()  # 跟踪活动任务，防止垃圾回收和丢失异常

    print("""
+----------------------------------------------------------+
|              CTF-Agent Interactive Mode                   |
+----------------------------------------------------------+
| Commands:                                                |
|   target <url>     Start attacking a target              |
|   competition      Start competition auto-solve          |
|   stop             Stop current task                     |
|   pause            Pause/resume                          |
|   status           Show status                           |
|   quit             Exit                                  |
|                                                          |
| During execution, type text to guide AI strategy         |
+----------------------------------------------------------+
""")

    def signal_handler(sig, frame):
        if session.running:
            print("\n[Signal] Stopping...")
            session.stop()
        else:
            print("\nGoodbye!")
            sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    loop = asyncio.get_event_loop()

    while True:
        try:
            prompt = "[You] " if not session.running else "[You] (running) "
            user_input = await loop.run_in_executor(None, input, prompt)
            cmd = user_input.strip()

            if not cmd:
                continue

            cmd_lower = cmd.lower()

            if cmd_lower.startswith("target "):
                target = cmd[7:].strip()
                if target:
                    task = asyncio.create_task(session.run(target))
                    _active_tasks.add(task)
                    task.add_done_callback(_active_tasks.discard)

            elif cmd_lower == "competition":
                task = asyncio.create_task(session.run("competition", timeout=18000, competition=True))
                _active_tasks.add(task)
                task.add_done_callback(_active_tasks.discard)

            elif cmd_lower == "stop":
                session.stop()
                print("[Stopped]")

            elif cmd_lower == "pause":
                paused = session.pause()
                print(f"[{'Paused' if paused else 'Resumed'}]")

            elif cmd_lower == "status":
                print(f"Running: {session.running} | Paused: {session.paused} | Flags: {len(session.flags_found)}")

            elif cmd_lower in ("quit", "exit"):
                session.stop()
                print("Goodbye!")
                break

            elif session.running:
                if session.inject_feedback(cmd):
                    print("[Feedback added]")

            await asyncio.sleep(0.1)

        except EOFError:
            break
        except Exception as e:
            print(f"[Error] {e}")


def main():
    try:
        asyncio.run(interactive_mode())
    except KeyboardInterrupt:
        print("\nGoodbye!")


if __name__ == "__main__":
    main()
