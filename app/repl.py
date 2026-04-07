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


# 系统提示词 - REPL 模式
REPL_SYSTEM_PROMPT = """You are CTF-Agent, an AI penetration testing assistant.

**Your Capabilities**:
- Access to Kali Linux tools via MCP (nmap, sqlmap, burpsuite, etc.)
- HTTP client for web testing
- File system access for scripts and tools
- Structured memory system

**Operating Modes**:
1. **Chat/Help**: Answer questions, explain concepts, guide users
2. **Recon**: Explore targets, gather information
3. **Attack**: Active exploitation, capture flags
4. **Analysis**: Analyze results, suggest strategies

**Guidelines**:
- Be proactive: suggest next steps, tools, or approaches
- Explain your reasoning when making decisions
- Use tools autonomously when needed (e.g., self-check, environment inspection)
- When user says "check environment", inspect MCP tools and Kali availability
- When given a target URL, start recon automatically
- Always ask before destructive actions (rm, drop, etc.)

**Available Commands** (tell user when they ask):
- `help` - Show this help
- `tools` - List available MCP tools
- `check` - Self-check environment
- `target <url>` - Set target and start recon
- `attack` - Start active exploitation
- `clear` - Clear conversation
- `quit` - Exit

Respond naturally. Use tools when appropriate. Be helpful and educational.
"""


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

        # 初始化消息
        self.messages = [
            {"role": "system", "content": REPL_SYSTEM_PROMPT}
        ]

    async def chat(self, user_input: str):
        """处理用户输入，返回事件流"""
        self.messages.append({"role": "user", "content": user_input})

        qconfig = QueryConfig(
            model=app_config.LLM_MODEL,
            max_turns=app_config.query.max_turns,
            timeout_seconds=300,  # 5分钟超时
            system_prompt=REPL_SYSTEM_PROMPT,
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

    except (KeyboardInterrupt, asyncio.CancelledError):
        print("\n[Cancelled]", flush=True)
        # 清理可能不完整的消息
        if len(repl.messages) > 1 and repl.messages[-1].get("role") == "user":
            repl.messages.pop()
    except Exception as e:
        # 捕获所有其他异常（包括 MCP 重连错误）
        print(f"\n[Error] {e}", flush=True)
        logger.error(f"print_stream error: {e}")
        # 清理不完整的消息
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

    loop = asyncio.get_event_loop()

    while True:
        try:
            # 异步获取输入
            user_input = await loop.run_in_executor(None, input, "\nYou: ")
            cmd = user_input.strip()

            if not cmd:
                continue

            cmd_lower = cmd.lower()

            # 内置命令
            if cmd_lower in ("quit", "exit", "q"):
                print("\nGoodbye! 👋")
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

Tips:
  - Just chat naturally, AI will understand
  - Say "check environment" to inspect tools
  - Paste a URL to start recon automatically
  - Ask about any tool or technique
""")
                continue

            elif cmd_lower == "tools":
                print(f"\nAvailable Tools:\n{repl.get_tool_list()}")
                continue

            elif cmd_lower == "check":
                await print_stream(repl, "Please check the environment: verify MCP connection, list available Kali tools, and test a simple bash command like 'whoami'.")
                continue

            elif cmd_lower == "clear":
                repl.messages = [{"role": "system", "content": REPL_SYSTEM_PROMPT}]
                print("[Conversation cleared]")
                continue

            elif cmd_lower.startswith("target "):
                url = cmd[7:].strip()
                repl.target = url
                await print_stream(repl, f"Target set to: {url}\nPlease start reconnaissance. Use nmap to scan ports, then explore the web service if HTTP is open.")
                continue

            # 检测 URL 自动开始 recon
            elif cmd.startswith("http://") or cmd.startswith("https://"):
                repl.target = cmd
                await print_stream(repl, f"Target detected: {cmd}\nStarting reconnaissance. First, I'll check what services are running.")
                continue

            # 普通对话
            else:
                await print_stream(repl, cmd)

        except EOFError:
            print("\nGoodbye!")
            break
        except (KeyboardInterrupt, asyncio.CancelledError):
            # Ctrl+C 中断 - 打印提示并继续循环
            print("\n[Interrupted] Type 'quit' to exit or continue chatting.")
            # 清理可能不完整的最后一条消息
            if len(repl.messages) > 1 and repl.messages[-1].get("role") == "user":
                repl.messages.pop()
        except Exception as e:
            print(f"\n[Error] {e}")
            logger.error(f"REPL error: {e}")


def main():
    """入口"""
    task_id = f"repl_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    set_task(task_id)
    asyncio.run(repl_main())


if __name__ == "__main__":
    main()