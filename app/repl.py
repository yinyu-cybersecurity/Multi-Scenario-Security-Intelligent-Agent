#!/usr/bin/env python3
"""
CTF-Agent 智能 REPL - 类似 Claude Code CLI

特性:
- 启动时自动检测环境（MCP连接、工具列表）
- 自由对话，AI 可自主调用工具
- 支持检查、探索、攻击等多种模式
- 实时流式输出
"""

import asyncio
import sys
import os
import signal
from datetime import datetime

from app.core.query import query, QueryConfig
from app.prompts.ctf_system_prompt import build_system_prompt
from app.settings import config as app_config
from app.logger import get_logger, set_task
from app.tools_v2.mcp.client import get_mcp_client, ensure_mcp_tools_registered

logger = get_logger("REPL")


class SmartREPL:
    """智能 REPL 会话"""

    def __init__(self):
        self.messages = []
        self.mcp_client = None
        self.connected = False
        self.target = None
        self.flags_found = []

    async def initialize(self):
        """初始化环境"""
        print("\n[Setup] Connecting to MCP servers...")

        try:
            self.mcp_client = get_mcp_client()
            await ensure_mcp_tools_registered()

            servers = self.mcp_client.get_connected_servers()
            self.connected = len(servers) > 0

            if self.connected:
                print(f"[Setup] Connected: {', '.join(servers)}")

                # 获取工具列表
                tools = self.mcp_client.get_all_tool_schemas()
                tool_names = [t["name"] for t in tools]
                print(f"[Setup] {len(tools)} tools available")
            else:
                print("[Setup] No MCP servers connected")

        except Exception as e:
            print(f"[Setup] Error: {e}")
            self.connected = False

        # 初始化消息 - 使用统一的系统提示词
        system_prompt = build_system_prompt("interactive", 3600, competition_mode=False)
        self.messages = [
            {"role": "system", "content": system_prompt}
        ]

    async def chat(self, user_input: str):
        """处理用户输入，返回事件流"""
        self.messages.append({"role": "user", "content": user_input})

        # 从已初始化的messages中获取系统提示词
        system_prompt = self.messages[0]["content"] if self.messages else ""

        qconfig = QueryConfig(
            model=app_config.LLM_MODEL,
            max_turns=app_config.query.max_turns,
            timeout_seconds=300,  # 5分钟超时
            system_prompt=system_prompt,
            context_window_tokens=app_config.query.context_window_tokens,
            parallel_tool_calls=app_config.query.parallel_tool_calls,
            auto_continue=False,  # REPL 模式：不自动继续
        )

        # query 会直接修改 self.messages
        async for event in query(self.messages, qconfig):
            yield event

    def get_tool_list(self) -> str:
        """获取工具列表字符串"""
        if not self.connected:
            return "MCP not connected"

        tools = self.mcp_client.get_all_tool_schemas()
        lines = [f"  {t['name']}: {t['description'][:60]}..." for t in tools[:20]]
        if len(tools) > 20:
            lines.append(f"  ... and {len(tools) - 20} more")
        return "\n".join(lines)


async def print_stream(repl: SmartREPL, user_input: str):
    """流式打印 AI 响应"""
    print()  # 空行分隔

    try:
        async for event in repl.chat(user_input):
            etype = event.get("type", "")

            if etype == "assistant_message":
                content = event.get("content", "")
                tool_calls = event.get("tool_calls", [])

                if content:
                    print(content, end="", flush=True)

                if tool_calls:
                    names = [tc.get("function", {}).get("name", "?") for tc in tool_calls]
                    print(f"\n  → Using: {', '.join(names)}", flush=True)

            elif etype == "tool_result":
                tool_name = event.get("tool_name", "")
                for msg in reversed(repl.messages):
                    if msg.get("role") == "tool":
                        result = msg.get("content", "")
                        if len(result) > 300:
                            preview = result[:150] + "\n...[truncated]...\n" + result[-100:]
                        else:
                            preview = result
                        print(f"  ← {tool_name}:\n{preview}", flush=True)
                        break
                else:
                    print(f"  ← {tool_name}: [done]", flush=True)

            elif etype == "loop_detected":
                print(f"  ⚠ Loop detected: {event.get('tool', '')}", flush=True)

            elif etype == "context_trimmed":
                print(f"  ℹ Context trimmed: {event.get('removed', 0)} messages", flush=True)

            elif etype == "llm_error":
                print(f"\n[Error] {event.get('error', '')}", flush=True)

            elif etype in ("task_complete", "complete"):
                reason = event.get("reason", "")
                if reason:
                    print(f"\n[Done: {reason}]", flush=True)
                break

        print()

    except asyncio.CancelledError:
        print("\n[Cancelled]", flush=True)
        # 清理可能不完整的消息
        if len(repl.messages) > 1 and repl.messages[-1].get("role") == "user":
            repl.messages.pop()
        # 不重新抛出，让 REPL 继续运行
    except Exception as e:
        print(f"\n[Error] {e}", flush=True)
        logger.error(f"print_stream error: {e}")
        if len(repl.messages) > 1 and repl.messages[-1].get("role") == "user":
            repl.messages.pop()


async def repl_main():
    """REPL 主循环"""
    repl = SmartREPL()
    await repl.initialize()

    print(f"""
╔══════════════════════════════════════════════════════════╗
║           CTF-Agent Interactive REPL                      ║
║           Model: {app_config.LLM_MODEL:<42} ║
╠══════════════════════════════════════════════════════════╣
║  chat naturally, or use commands:                         ║
║  help     - show help                                     ║
║  tools    - list MCP tools                                ║
║  check    - self-check environment                        ║
║  target   - set target URL                                ║
║  quit     - exit                                          ║
╚══════════════════════════════════════════════════════════╝
""")

    loop = asyncio.get_running_loop()

    # 信号处理状态
    interrupt_count = [0]  # 使用列表来在闭包中修改

    def handle_sigint():
        """处理 Ctrl+C 信号"""
        interrupt_count[0] += 1
        if interrupt_count[0] >= 2:
            # 第二次 Ctrl+C：强制退出
            print("\n[Force quit]", flush=True)
            raise KeyboardInterrupt()
        else:
            # 第一次 Ctrl+C：打印提示
            print("\n[Interrupted] Press Ctrl+C again to quit, or continue chatting.", flush=True)

    # 设置信号处理器 - 在事件循环内部
    try:
        loop.add_signal_handler(signal.SIGINT, handle_sigint)
    except (NotImplementedError, OSError):
        # Windows 或其他不支持的平台
        pass

    try:
        while True:
            try:
                # 重置中断计数
                interrupt_count[0] = 0

                # 异步获取输入
                user_input = await loop.run_in_executor(None, input, "\nYou: ")
                cmd = user_input.strip()

                if not cmd:
                    continue

                cmd_lower = cmd.lower()

                # 内置命令
                if cmd_lower in ("quit", "exit", "q"):
                    print("\nGoodbye!")
                    break

                elif cmd_lower == "help":
                    print("""
Commands:
  help          Show this help
  tools         List available MCP tools
  check         Self-check environment and tools
  target <url>  Set target and start reconnaissance
  clear         Clear conversation history
  quit          Exit REPL
""")

                elif cmd_lower == "tools":
                    print(f"\nAvailable Tools:\n{repl.get_tool_list()}")

                elif cmd_lower == "check":
                    await print_stream(repl, "Please check the environment: verify MCP connection, list available Kali tools, and test a simple bash command.")

                elif cmd_lower == "clear":
                    system_prompt = build_system_prompt("interactive", 3600, competition_mode=False)
                    repl.messages = [{"role": "system", "content": system_prompt}]
                    print("[Conversation cleared]")

                elif cmd_lower.startswith("target "):
                    url = cmd[7:].strip()
                    repl.target = url
                    await print_stream(repl, f"Target set to: {url}\nPlease start reconnaissance.")

                elif cmd.startswith("http://") or cmd.startswith("https://"):
                    repl.target = cmd
                    await print_stream(repl, f"Target detected: {cmd}\nStarting reconnaissance.")

                else:
                    await print_stream(repl, cmd)

            except EOFError:
                print("\nGoodbye!")
                break

    except KeyboardInterrupt:
        # 由信号处理器抛出的强制退出
        print("\nGoodbye!")
    finally:
        # 清理信号处理器
        try:
            loop.remove_signal_handler(signal.SIGINT)
        except (NotImplementedError, ValueError, OSError):
            pass


def main():
    """入口"""
    task_id = f"repl_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    set_task(task_id)
    asyncio.run(repl_main())


if __name__ == "__main__":
    main()