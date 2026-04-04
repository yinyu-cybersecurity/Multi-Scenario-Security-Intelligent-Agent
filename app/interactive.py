#!/usr/bin/env python3
"""
CTF-Agent 交互式对话框模式
支持：实时输出、打断、用户输入
"""

import asyncio
import sys
import signal
from typing import Optional

from app.core.query import query, QueryConfig
from app.prompts.ctf_system_prompt import build_system_prompt
from app.logger import get_logger

logger = get_logger("Interactive")


class InteractiveSession:
    """交互式会话管理器"""

    def __init__(self):
        self.running = False
        self.paused = False
        self.current_task: Optional[asyncio.Task] = None
        self.messages = []
        self.findings = []

    async def run_agent(self, target: str, timeout: int = 1800):
        """运行Agent"""
        self.running = True

        # 配置
        config = QueryConfig(
            model="qwen3.5-plus",
            max_turns=200,
            timeout_seconds=timeout,
            system_prompt=build_system_prompt(target, timeout),
        )

        self.messages = [{
            "role": "user",
            "content": f"Target: {target}\n\nFind the FLAG."
        }]

        print("\n" + "=" * 60)
        print(f"Target: {target}")
        print(f"Timeout: {timeout}s")
        print("=" * 60 + "\n")

        try:
            async for event in query(self.messages, config):
                if not self.running:
                    print("\n[INTERRUPTED] Task stopped by user")
                    break

                while self.paused:
                    await asyncio.sleep(0.5)

                # 处理事件
                if event["type"] == "assistant_message":
                    content = event.get("content", "")
                    if content:
                        print(f"\n[AI] {content[:500]}...")

                elif event["type"] == "tool_result":
                    tool_name = event.get("tool_name", "")
                    print(f"[Tool] {tool_name}")

                elif event["type"] == "complete":
                    reason = event.get("reason", "")
                    print(f"\n[Complete] {reason}")
                    break

                elif event["type"] == "loop_detected":
                    tool = event.get("tool", "")
                    print(f"\n[Warning] Loop detected: {tool}")

        except asyncio.CancelledError:
            print("\n[INTERRUPTED] Task cancelled")

        self.running = False

    def stop(self):
        """停止运行"""
        self.running = False

    def pause(self):
        """暂停/继续"""
        self.paused = not self.paused
        return self.paused


async def interactive_mode():
    """交互式主循环"""
    session = InteractiveSession()

    print("""
╔════════════════════════════════════════════════════════════╗
║              CTF-Agent Interactive Mode                     ║
╠════════════════════════════════════════════════════════════╣
║  Commands:                                                  ║
║    target <url>   - 设置目标并开始                          ║
║    stop           - 停止当前任务                            ║
║    pause          - 暂停/继续                               ║
║    status         - 查看状态                                ║
║    help           - 显示帮助                                ║
║    quit           - 退出                                    ║
╚════════════════════════════════════════════════════════════╝
""")

    # 信号处理
    def signal_handler(sig, frame):
        if session.running:
            print("\n[Signal] Stopping current task...")
            session.stop()
        else:
            print("\n[Exit] Goodbye!")
            sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    loop = asyncio.get_event_loop()

    while True:
        try:
            # 读取用户输入
            user_input = await loop.run_in_executor(
                None,
                input,
                "\n[You] " if not session.running else "[You] (running, 'stop' to interrupt) "
            )

            cmd = user_input.strip().lower()

            if cmd.startswith("target "):
                target = user_input[7:].strip()
                if target:
                    # 异步启动任务
                    asyncio.create_task(session.run_agent(target))

            elif cmd == "stop":
                if session.running:
                    session.stop()
                    print("[System] Task stopped")
                else:
                    print("[System] No running task")

            elif cmd == "pause":
                paused = session.pause()
                print(f"[System] {'Paused' if paused else 'Resumed'}")

            elif cmd == "status":
                print(f"[Status] Running: {session.running}, Paused: {session.paused}")

            elif cmd == "help":
                print("""
Commands:
  target <url>   - Set target and start (e.g., target http://example.com)
  stop           - Stop current task
  pause          - Pause/resume
  status         - Show status
  help           - Show this help
  quit           - Exit

Tips:
  - Press Ctrl+C to interrupt current task
  - Provide feedback during execution to guide AI
""")

            elif cmd == "quit":
                if session.running:
                    session.stop()
                print("[Exit] Goodbye!")
                break

            elif cmd and session.running:
                # 用户在任务运行时提供输入
                session.messages.append({
                    "role": "user",
                    "content": user_input
                })
                print("[System] Feedback added to context")

            await asyncio.sleep(0.1)

        except EOFError:
            break
        except Exception as e:
            print(f"[Error] {e}")


def main():
    """主入口"""
    try:
        asyncio.run(interactive_mode())
    except KeyboardInterrupt:
        print("\n[Exit] Goodbye!")


if __name__ == "__main__":
    main()