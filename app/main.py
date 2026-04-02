# app/main.py
"""
CTF-Agent 2.0 统一入口

设计原则:
1. 单一入口 - 所有任务从此进入
2. 智能分类 - LLM自动识别任务类型
3. 状态持久化 - 支持断点续传
4. 优雅退出 - 超时熔断
"""

import asyncio
import sys
import ipaddress
import re
from typing import Optional
from datetime import datetime

from app.graph.ctf_graph import build_ctf_graph
from app.state.state_v3 import (
    CTFStateV3,
    ChallengeInfo,
    ChallengeType,
    create_initial_state
)
from app.coordinator.dispatcher import (
    get_coordinator_dispatcher,
    TaskType
)
from app.memory import get_agent_memory


# ============================================
# 安全验证函数
# ============================================

def validate_target(target: str, allow_internal: bool = False) -> tuple[bool, str]:
    """
    验证目标地址是否合法

    Args:
        target: 目标地址（URL/IP/域名）
        allow_internal: 是否允许内网地址（内网渗透场景）

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

    # 如果允许内网地址，直接返回True（内网渗透场景）
    if allow_internal:
        return True, ""

    # 检查是否为内网IP地址
    # 提取IP地址（如果不是URL）
    if not target.startswith("http"):
        # 可能是IP或域名
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if re.match(ip_pattern, target):
            try:
                ip = ipaddress.ip_address(target)

                # 禁止私有IP、环回地址、链路本地地址
                if ip.is_private:
                    return False, f"Private IP address not allowed: {target}"
                if ip.is_loopback:
                    return False, f"Loopback address not allowed: {target}"
                if ip.is_link_local:
                    return False, f"Link-local address not allowed: {target}"
                if ip.is_multicast:
                    return False, f"Multicast address not allowed: {target}"
            except ValueError:
                # 不是有效IP，可能是域名
                pass

    # 检查URL中的主机名
    if target.startswith("http"):
        # 提取主机名
        from urllib.parse import urlparse
        try:
            parsed = urlparse(target)
            hostname = parsed.hostname

            if hostname:
                # 检查是否为IP
                try:
                    ip = ipaddress.ip_address(hostname)
                    if ip.is_private or ip.is_loopback or ip.is_link_local:
                        return False, f"Internal IP in URL not allowed: {hostname}"
                except ValueError:
                    # 是域名，检查是否为localhost等
                    if hostname.lower() in ["localhost", "127.0.0.1", "0.0.0.0"]:
                        return False, f"Localhost not allowed: {hostname}"
        except Exception as e:
            return False, f"Invalid URL: {str(e)}"

    return True, ""


async def run_agent(
    target: str,
    description: str = "",
    challenge_type: Optional[ChallengeType] = None,
    max_iterations: int = 50,
    timeout_minutes: Optional[int] = None
) -> dict:
    """
    执行CTF-Agent主入口

    Args:
        target: 目标地址（URL/IP/域名）
        description: 任务描述（用于LLM分类）
        challenge_type: 挑战类型（可选，默认自动识别）
        max_iterations: 最大迭代次数
        timeout_minutes: 超时时间（分钟）

    Returns:
        执行结果
    """
    # =========================================
    # 安全验证：检查target是否合法
    # =========================================
    # 内网渗透类型允许内网地址
    allow_internal = (challenge_type == ChallengeType.NETWORK) if challenge_type else False
    is_valid, error_msg = validate_target(target, allow_internal)

    if not is_valid:
        return {
            "success": False,
            "error": f"Invalid target: {error_msg}",
            "session_id": None
        }

    # =========================================
    # 1. 初始化组件
    # =========================================
    coordinator = get_coordinator_dispatcher()
    memory = get_agent_memory()

    # =========================================
    # 2. 智能分类挑战类型（如未指定）
    # =========================================
    if not challenge_type:
        challenge_type = await _classify_challenge_type(target, description)

    # =========================================
    # 3. 构建挑战信息
    # =========================================
    challenge = ChallengeInfo(
        challenge_id=f"task_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
        challenge_type=challenge_type,
        title=f"Attack: {target}",
        description=description or f"攻击目标 {target}",
        target_url=target if target.startswith("http") else None,
        target_ip=target if not target.startswith("http") else None
    )

    # =========================================
    # 4. 创建初始状态
    # =========================================
    initial_state = create_initial_state(challenge)
    initial_state["max_iterations"] = max_iterations

    # =========================================
    # 5. 创建Coordinator会话（启动超时）
    # =========================================
    task_description = description or f"攻击目标 {target}"

    # 确定任务类型和超时
    task_type = _map_challenge_to_task_type(challenge_type)
    timeout_seconds = timeout_minutes * 60 if timeout_minutes else None

    session_id = await coordinator.create_session(
        parent_messages=[],
        task_description=task_description,
        task_type=task_type,
        timeout_override=timeout_seconds
    )

    initial_state["session_id"] = session_id

    # =========================================
    # 6. 构建并执行图
    # =========================================
    print(f"\n{'='*60}")
    print(f"🎯 CTF-Agent 2.0 启动")
    print(f"{'='*60}")
    print(f"目标: {target}")
    print(f"类型: {challenge_type.value}")
    print(f"描述: {task_description[:50]}...")
    remaining = coordinator.get_remaining_time(session_id)
    print(f"超时: {remaining:.0f} 秒")
    print(f"{'='*60}\n")

    try:
        # 构建图
        graph = build_ctf_graph()

        # 执行
        final_state = await graph.ainvoke(initial_state)

        # =========================================
        # 7. 构建结果
        # =========================================
        result = _build_final_result(final_state, session_id, coordinator)

        return result

    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "session_id": session_id
        }
    finally:
        # 清理会话
        coordinator.cleanup_session(session_id)


async def _classify_challenge_type(target: str, description: str) -> ChallengeType:
    """智能分类挑战类型"""
    from app.llm_client import llm_client

    # 简单规则优先
    if target.startswith("http"):
        return ChallengeType.WEB

    # LLM分类
    prompt = f"""分析目标并分类挑战类型。

目标: {target}
描述: {description}

类型选项:
- web: Web应用
- pwn: 二进制漏洞
- crypto: 密码学
- reverse: 逆向工程
- misc: 杂项
- network: 内网渗透
- cloud: 云安全
- ai: AI安全

只返回类型名称，不要解释。"""

    try:
        response = llm_client.call_chat_completion(
            model="deepseek-chat",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=20
        )
        type_str = response.strip().lower()

        type_map = {
            "web": ChallengeType.WEB,
            "pwn": ChallengeType.PWN,
            "crypto": ChallengeType.CRYPTO,
            "reverse": ChallengeType.REVERSE,
            "misc": ChallengeType.MISC,
            "network": ChallengeType.NETWORK,
            "cloud": ChallengeType.CLOUD,
            "ai": ChallengeType.AI,
        }

        return type_map.get(type_str, ChallengeType.WEB)
    except Exception:
        return ChallengeType.WEB


def _map_challenge_to_task_type(challenge_type: ChallengeType) -> TaskType:
    """映射挑战类型到任务类型"""
    from app.coordinator.dispatcher import TaskType

    mapping = {
        ChallengeType.WEB: TaskType.CTF_CHALLENGE,
        ChallengeType.PWN: TaskType.CTF_CHALLENGE,
        ChallengeType.CRYPTO: TaskType.CTF_CHALLENGE,
        ChallengeType.REVERSE: TaskType.CTF_CHALLENGE,
        ChallengeType.MISC: TaskType.CTF_CHALLENGE,
        ChallengeType.NETWORK: TaskType.PENETRATION_INTERNAL,
        ChallengeType.CLOUD: TaskType.PENETRATION_FULL,
        ChallengeType.AI: TaskType.RESEARCH,
    }
    return mapping.get(challenge_type, TaskType.CTF_CHALLENGE)


def _build_final_result(
    state: CTFStateV3,
    session_id: str,
    coordinator
) -> dict:
    """构建最终结果"""
    timeout_status = coordinator.get_timeout_status(session_id)

    phase = state.get("current_phase")
    phase_value = phase.value if hasattr(phase, 'value') else "unknown"

    return {
        "success": bool(state.get("flags_found")),
        "flags": state.get("flags_found", []),
        "phase": phase_value,
        "iterations": state.get("iteration_count", 0),
        "findings_count": len(state.get("findings", [])),
        "tool_calls_count": len(state.get("tool_history", [])),
        "findings": state.get("findings", [])[-10:],
        "timeout": timeout_status,
        "session_id": session_id,
        "duration_seconds": timeout_status.get("elapsed_seconds", 0)
    }


def main():
    """命令行入口"""
    import argparse

    parser = argparse.ArgumentParser(description="CTF-Agent 2.0 - 智能渗透测试Agent")
    parser.add_argument("target", help="目标地址（URL/IP/域名）")
    parser.add_argument("-d", "--description", default="", help="任务描述")
    parser.add_argument("-t", "--type",
                        choices=["web", "pwn", "crypto", "reverse", "misc", "network", "cloud", "ai"],
                        help="挑战类型（默认自动识别）")
    parser.add_argument("-i", "--max-iterations", type=int, default=50, help="最大迭代次数")
    parser.add_argument("--timeout", type=int, help="超时时间（分钟）")
    parser.add_argument("-v", "--verbose", action="store_true", help="详细输出")

    args = parser.parse_args()

    # 类型映射
    type_map = {
        "web": ChallengeType.WEB,
        "pwn": ChallengeType.PWN,
        "crypto": ChallengeType.CRYPTO,
        "reverse": ChallengeType.REVERSE,
        "misc": ChallengeType.MISC,
        "network": ChallengeType.NETWORK,
        "cloud": ChallengeType.CLOUD,
        "ai": ChallengeType.AI,
    }

    challenge_type = type_map.get(args.type) if args.type else None

    # 执行
    result = asyncio.run(run_agent(
        target=args.target,
        description=args.description,
        challenge_type=challenge_type,
        max_iterations=args.max_iterations,
        timeout_minutes=args.timeout
    ))

    # 输出结果
    print(f"\n{'='*60}")
    print("📊 执行结果")
    print(f"{'='*60}")
    print(f"成功: {'✅' if result['success'] else '❌'}")
    if result.get("flags"):
        print(f"Flags: {result['flags']}")
    print(f"迭代: {result['iterations']}")
    print(f"发现: {result['findings_count']}")
    print(f"耗时: {result['duration_seconds']:.1f}秒")
    print(f"{'='*60}\n")

    # 详细输出
    if args.verbose and result.get("findings"):
        print("\n📝 发现详情:")
        for i, finding in enumerate(result["findings"], 1):
            content = finding.get("content", str(finding))
            print(f"{i}. [{finding.get('type', 'unknown')}] {str(content)[:100]}")

    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())