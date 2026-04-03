# app/main.py

"""
CTF-Agent 主入口 - 使用Claude Code Query循环模式

设计原则:
1. Query循环替代LangGraph状态机
2. AI完全自主决策下一步行动
3. 超时是唯一熔断条件
4. 动态AppState，无预置字段
"""

import asyncio
import sys
import re
import ipaddress
import logging
from typing import Optional
from datetime import datetime

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("CTF-Agent")

# 导入新架构组件
from app.core.query import query, QueryConfig
from app.core.time_manager import TimeManager, TaskType
from app.state.store import get_app_state_store
from app.prompts.ctf_system_prompt import get_target_specific_prompt
from app.settings import config


# ============================================
# 安全验证函数
# ============================================

def validate_target(target: str, allow_internal: bool = False) -> tuple:
    """
    验证目标地址是否合法

    Args:
        target: 目标地址（URL/IP/域名）
        allow_internal: 是否允许内网地址

    Returns:
        (是否合法, 错误信息)
    """
    if not target or not isinstance(target, str):
        return False, "Target is empty or invalid"

    # 长度限制
    if len(target) > 255:
        return False, "Target exceeds max length 255"

    # 检查危险协议
    dangerous_protocols = ["file://", "ftp://", "gopher://", "dict://"]
    for proto in dangerous_protocols:
        if target.lower().startswith(proto):
            return False, f"Protocol '{proto}' is not allowed"

    # 如果允许内网地址，直接返回True
    if allow_internal:
        return True, ""

    # 检查是否为内网IP地址
    if not target.startswith("http"):
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if re.match(ip_pattern, target):
            try:
                ip = ipaddress.ip_address(target)
                if ip.is_private:
                    return False, f"Private IP address not allowed: {target}"
                if ip.is_loopback:
                    return False, f"Loopback address not allowed: {target}"
                if ip.is_link_local:
                    return False, f"Link-local address not allowed: {target}"
            except ValueError:
                pass

    # 检查URL中的主机名
    if target.startswith("http"):
        from urllib.parse import urlparse
        try:
            parsed = urlparse(target)
            hostname = parsed.hostname
            if hostname:
                try:
                    ip = ipaddress.ip_address(hostname)
                    if ip.is_private or ip.is_loopback or ip.is_link_local:
                        return False, f"Internal IP in URL not allowed: {hostname}"
                except ValueError:
                    if hostname.lower() in ["localhost", "127.0.0.1", "0.0.0.0"]:
                        return False, f"Localhost not allowed: {hostname}"
        except Exception as e:
            return False, f"Invalid URL: {str(e)}"

    return True, ""


def detect_challenge_type(target: str, description: str = "") -> str:
    """简单规则检测挑战类型"""
    target_lower = target.lower()
    desc_lower = description.lower()

    # Web检测
    if target.startswith("http") or any(kw in target_lower for kw in [".php", ".asp", "web"]):
        return "web"

    # Pwn检测
    if any(kw in desc_lower for kw in ["pwn", "binary", "buffer", "overflow", "漏洞利用"]):
        return "pwn"

    # Crypto检测
    if any(kw in desc_lower for kw in ["crypto", "rsa", "aes", "encrypt", "decrypt", "密码"]):
        return "crypto"

    # Reverse检测
    if any(kw in desc_lower for kw in ["reverse", "逆向", "decompile", "反编译"]):
        return "reverse"

    # 内网渗透
    if any(kw in desc_lower for kw in ["内网", "internal", "域控", "ad ", "active directory"]):
        return "network"

    # 默认Web
    return "web"


def map_challenge_to_task_type(challenge_type: str) -> TaskType:
    """映射挑战类型到任务类型"""
    mapping = {
        "web": TaskType.CTF_SINGLE_FLAG,
        "pwn": TaskType.CTF_SINGLE_FLAG,
        "crypto": TaskType.CTF_SINGLE_FLAG,
        "reverse": TaskType.CTF_SINGLE_FLAG,
        "misc": TaskType.CTF_SINGLE_FLAG,
        "network": TaskType.INTERNAL_PENETRATION,
        "cloud": TaskType.FULL_PENETRATION,
        "ai": TaskType.RESEARCH,
    }
    return mapping.get(challenge_type, TaskType.CTF_SINGLE_FLAG)


async def run_ctf_agent(
    target: str,
    description: str = "",
    challenge_type: Optional[str] = None,
    timeout_minutes: Optional[int] = None,
) -> dict:
    """
    运行CTF Agent - 使用Query循环

    Args:
        target: 目标URL或描述
        description: 任务描述
        challenge_type: 挑战类型 (web/pwn/crypto/reverse/misc/network/cloud/ai)
        timeout_minutes: 超时时间（分钟）

    Returns:
        执行结果
    """
    start_time = datetime.now()

    # 检测挑战类型
    if not challenge_type:
        challenge_type = detect_challenge_type(target, description)

    # 确定是否允许内网地址
    allow_internal = challenge_type == "network"

    # 安全验证
    is_valid, error_msg = validate_target(target, allow_internal)
    if not is_valid:
        return {
            "success": False,
            "error": f"Invalid target: {error_msg}",
            "flags": [],
            "duration_seconds": 0,
        }

    # 初始化
    store = get_app_state_store()
    time_manager = TimeManager()
    session_id = f"session-{datetime.now().strftime('%Y%m%d%H%M%S')}"

    # 确定任务类型和超时
    task_type = map_challenge_to_task_type(challenge_type)

    # 创建时间预算
    budget = time_manager.create_budget(session_id, task_type)

    # 获取模型配置
    model = getattr(config, 'LLM_MODEL', 'glm-5')

    # 构建System Prompt
    system_prompt = get_target_specific_prompt(challenge_type, target)

    # 添加时间预算信息
    time_prompt = f"\n\n**Time Budget**: {budget.total_seconds / 60:.0f} minutes for this task."
    system_prompt += time_prompt

    # 配置Query
    # 不传递静态工具列表，让query.py使用延迟加载
    query_config = QueryConfig(
        model=model,
        max_turns=200,
        system_prompt=system_prompt,
        tools=[],  # 空列表 - 启用延迟加载
    )

    # 初始消息
    messages = [{
        "role": "user",
        "content": f"""CTF Challenge Target: {target}

Description: {description or 'No description provided'}

Your task:
1. Analyze the target and identify potential vulnerabilities
2. Exploit any vulnerabilities found
3. Extract the flag (format: flag{{...}} or FLAG{{...}})

Time budget: {budget.total_seconds / 60:.0f} minutes.

Begin your analysis and exploitation now."""
    }]

    # 运行Query循环
    final_result = {
        "success": False,
        "flags": [],
        "iterations": 0,
        "findings": [],
        "duration_seconds": 0,
        "session_id": session_id,
    }

    flags_found = []

    print(f"\n{'='*60}")
    print(f"[CTF-Agent] Starting with Claude Code Query Loop")
    print(f"{'='*60}")
    print(f"Target: {target}")
    print(f"Type: {challenge_type}")
    print(f"Model: {model}")
    print(f"Time budget: {budget.total_seconds / 60:.0f} minutes")
    print(f"{'='*60}\n")

    try:
        async for event in query(messages, query_config):
            # 检查超时
            if time_manager.should_stop(session_id):
                print("\n⏰ **TIMEOUT** - Time budget exhausted!")
                final_result["timeout"] = True
                break

            # 处理事件
            event_type = event.get("type")
            turn = event.get("turn", 0)

            if event_type == "message":
                content = event.get("message", {}).get("content", "")
                print(f"\n[Turn {turn}] AI Response:")
                print(content[:500] + "..." if len(content) > 500 else content)

                # 检查是否找到Flag
                flag_match = re.search(r'flag\{[^}]+\}', content, re.IGNORECASE)
                if flag_match:
                    flag = flag_match.group(0)
                    if flag not in flags_found:
                        flags_found.append(flag)
                        print(f"\n🎉 **FLAG FOUND**: {flag}")

                final_result["iterations"] = turn

            elif event_type == "flag_found":
                flag = event.get("flag")
                if flag and flag not in flags_found:
                    flags_found.append(flag)

            elif event_type == "complete":
                reason = event.get("reason", "unknown")
                print(f"\n✅ Task completed: {reason}")
                break

            elif event_type == "error":
                error = event.get("error", "Unknown error")
                print(f"\n❌ Error: {error}")
                final_result["error"] = error

            elif event_type == "turn_complete":
                # 显示时间状态
                remaining = budget.remaining_seconds
                if remaining > 0:
                    elapsed_pct = budget.progress_ratio * 100
                    if elapsed_pct >= 80:
                        print(f"\n⏰ Time warning: {remaining/60:.0f} min remaining ({elapsed_pct:.0f}% used)")

    except Exception as e:
        logger.error(f"Query loop error: {e}")
        final_result["error"] = str(e)

    # 构建最终结果
    end_time = datetime.now()
    final_result["flags"] = flags_found
    final_result["success"] = len(flags_found) > 0
    final_result["duration_seconds"] = (end_time - start_time).total_seconds()

    return final_result


def main():
    """命令行入口"""
    import argparse

    parser = argparse.ArgumentParser(description="CTF-Agent - Claude Code Query Loop Architecture")
    parser.add_argument("target", help="目标地址（URL/IP/域名）")
    parser.add_argument("-d", "--description", default="", help="任务描述")
    parser.add_argument("-t", "--type",
                        choices=["web", "pwn", "crypto", "reverse", "misc", "network", "cloud", "ai"],
                        help="挑战类型（默认自动检测）")
    parser.add_argument("--timeout", type=int, help="超时时间（分钟）")
    parser.add_argument("-v", "--verbose", action="store_true", help="详细输出")

    args = parser.parse_args()

    # 执行
    result = asyncio.run(run_ctf_agent(
        target=args.target,
        description=args.description,
        challenge_type=args.type,
        timeout_minutes=args.timeout,
    ))

    # 输出结果
    print(f"\n{'='*60}")
    print("[Result] Execution completed")
    print(f"{'='*60}")
    print(f"Success: {'YES' if result['success'] else 'NO'}")

    if result.get("flags"):
        print(f"\n🎉 Flags Found: {len(result['flags'])}")
        for i, flag in enumerate(result["flags"], 1):
            print(f"  {i}. {flag}")

    print(f"\nIterations: {result.get('iterations', 0)}")
    print(f"Duration: {result.get('duration_seconds', 0):.1f} seconds")

    if result.get("error"):
        print(f"Error: {result['error']}")

    print(f"{'='*60}\n")

    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())