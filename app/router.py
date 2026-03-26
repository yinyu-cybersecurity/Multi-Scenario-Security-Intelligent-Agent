# router.py - 系统的"导航"
# 作用：定义节点间的跳转逻辑，防止死循环，处理多路径汇合

from state import CTFState
from config import config
from typing import Dict, List, Tuple
import time
import json
from langgraph.graph import END
from llm_client import llm_client
from logger import get_logger

logger = get_logger(__name__)

class RouteGuard:
    """路由守卫 - 防止死循环和异常跳转"""

    def __init__(self):
        self.path_history: List[Tuple[str, str]] = []  # 记录走过的路径 (当前节点, 下一节点)
        self.last_transition_time: float = time.time()
        self.loop_count: Dict[str, int] = {}  # 记录每个节点的累计访问次数

    def check_dead_loop(self, current_node: str, next_node: str) -> bool:
        """
        检测死循环

        检测模式：
        1. A -> B -> A -> B 的来回循环
        2. 同一节点总计访问超过10次（非连续）
        3. 10步内出现重复路径模式

        Args:
            current_node: 当前节点名
            next_node: 下一节点名

        Returns:
            True: 检测到死循环，需要干预
            False: 正常
        """
        # 记录当前跳转
        self.path_history.append((current_node, next_node))

        # 保留最近30步（上调自20）
        if len(self.path_history) > 30:
            self.path_history = self.path_history[-30:]

        # 记录节点累计访问次数
        self.loop_count[next_node] = self.loop_count.get(next_node, 0) + 1

        # ---------- 死循环检测规则 ----------

        # 规则1: 同一节点总计访问超过10次
        if self.loop_count.get(next_node, 0) > 10:
            logger.warning(f"节点 {next_node} 总计访问超过10次")
            return True

        # 规则2: 检测 A->B->A 来回循环 (需要6次以上才触发)
        if len(self.path_history) >= 6:
            last6 = self.path_history[-6:]
            # 模式: A->B, B->A, A->B, B->A, A->B, B->A (连续3次来回)
            if (last6[0][1] == last6[2][0] and
                    last6[1][1] == last6[3][0] and
                    last6[2][1] == last6[4][0] and
                    last6[3][1] == last6[5][0] and
                    last6[0][0] == last6[2][0] and
                    last6[1][0] == last6[3][0]):
                logger.warning(f"检测到持续来回循环: {last6}")
                return True

        # 规则3: 长时间没有进展（超过600秒，10分钟）
        current_time = time.time()
        if current_time - self.last_transition_time > 600:
            logger.warning("600秒无进展，可能卡死")
            self.last_transition_time = current_time
            return True

        # 更新最后跳转时间
        self.last_transition_time = current_time

        return False

    def reset_loop_count(self, node: str):
        """重置特定节点的循环计数"""
        self.loop_count[node] = 0

    def get_stats(self) -> Dict:
        """获取路由统计信息"""
        return {
            "path_history": self.path_history[-10:],  # 最近10步
            "loop_count": dict(self.loop_count),
            "last_transition": self.last_transition_time
        }


# 全局路由守卫实例（单例）
_route_guard = RouteGuard()


def reset_route_guard():
    """重置路由守卫（新任务开始时调用）"""
    global _route_guard
    _route_guard = RouteGuard()


def route_mode(state: CTFState, current_node: str) -> str:
    """
    模式路由 - 根据current_mode决定下一节点

    处理流程：
        1. 从状态获取目标模式
        2. 上下文压缩检查
        3. 死循环检测
        4. 异常情况处理
        5. 返回下一节点

    Args:
        state: 当前状态
        current_node: 当前节点名（用于死循环检测）

    Returns:
        目标节点名称: 'attacker'/'explorer'/'innovator'/END
    """
    next_node = state.get("current_mode", "exploit")

    # [核心修复] 检查当前 URL 是否已经过侦察
    current_url = state.get("current_url")
    visited_urls = state.get("visited_urls", [])

    # 如果当前 URL 没在访问列表中，且当前不是在进行探索或创新模式，强制先去侦察
    if current_url and current_url not in visited_urls and next_node not in ["explore", "innovate"]:
        logger.info(f"检测到新 URL: {current_url}，强制切换至侦察模式")
        return "recon"

    # 1. 死循环检测
    if _route_guard.check_dead_loop(current_node, next_node):
        logger.warning("检测到死循环，尝试自动恢复")
        # 重置循环计数，避免日志刷屏
        _route_guard.reset_loop_count(next_node)

        # 策略修正：如果卡在探索或创新模式，强制切回攻击模式尝试突破
        if next_node in ["explore", "innovate"]:
             return "exploit"
        # 如果卡在攻击模式，保持现状或让 ModeManager 决定（通常会因为失败分增加而自然切换）
        return next_node

    # 2. 移除错误的 temp_rules 检查
    # temp_rules 是 innovator_node 执行后生成的，不应在进入前检查
    # 如果 innovator 执行后没有生成有效规则，会在 strategy_filter 中处理

    # 3. 安全检查：探索模式但已经探索很多轮，考虑切回
    if next_node == "explore" and state.get("exploration_rounds", 0) > config.EXPLORE_ROUNDS_FOR_INNOVATE:
        if not state.get("site_topology"):  # 没有发现新路径
            logger.info("探索多轮无发现，尝试攻击模式")
            return "exploit"

    return next_node


def route_verify(state: CTFState, current_node: str) -> str:
    """
    验证后路由 [P3优化版] - 成功则进化，失败则回到决策

    新目标: 找到flag后继续内网渗透，攻陷所有主机

    优先级：
        1. 获取shell -> post_exploit（后渗透处理）
        2. 找到flag -> 继续内网渗透（不再结束）
        3. continue_attack -> attacker（继续攻击）
        4. 失败分过高 -> mode_manager (自动进入创新模式)
        5. 正常情况 -> mode_manager

    Args:
        state: 当前状态
        current_node: 当前节点名

    Returns:
        "evolution" / "post_exploit" / "attacker" / "mode_manager"
    """
    # 1. 检查是否获取了shell且需要后渗透处理
    shell_session = state.get("shell_session")
    post_exploit_status = state.get("post_exploit_status", "")

    # 如果有shell会话且还没执行过后渗透处理，进入post_exploit
    if shell_session and not post_exploit_status:
        logger.info("检测到shell会话，进入后渗透处理")
        return "post_exploit"

    # 2. 检查是否找到flag
    found_flags = state.get("found_flags") or []
    if state.get("found_flag") or found_flags:
        # 如果是Web CTF模式，找到flag后结束
        if not state.get("internal_mode"):
            logger.info("Web CTF模式下找到flag，进入进化流程")
            _route_guard.reset_loop_count("verifier")
            return "evolution"
        # 如果是内网渗透模式，继续攻陷其他主机
        else:
            logger.info(f"内网渗透模式下找到{len(found_flags)}个flag，继续攻陷其他主机")
            return "mode_manager"

    # 3. [内网模式增强] 检查是否需要继续攻击
    if state.get("internal_mode") and state.get("continue_attack"):
        remaining = state.get("remaining_payloads", [])
        if remaining:
            logger.info(f"内网模式：继续攻击，剩余 {len(remaining)} 个payload")
            return "attacker"

    # 4. 正常回到mode_manager
    return "mode_manager"


def route_evolution(state: CTFState, current_node: str) -> str:
    """
    进化后路由 - 进化完成直接结束

    Args:
        state: 当前状态
        current_node: 当前节点名

    Returns:
        END
    """
    logger.info("进化完成，结束流程")
    return END


def get_routing_stats() -> Dict:
    """获取路由统计信息（用于调试）"""
    return _route_guard.get_stats()


# ==============================================================================
# 内网渗透路由扩展 (Internal Network Routing Extension)
# 添加时间：2026-03-22
# ==============================================================================

def route_internal_mode(state: CTFState, current_node: str) -> str:
    """
    内网模式路由决策 - AI驱动

    AI分析当前态势，决定最优下一步:
    1. internal_recon: 内网侦察
    2. upload_tools: 工具上传
    3. setup_tunnel: 隧道搭建
    4. credential_gather: 凭据收集
    5. lateral_move: 横向移动
    6. privilege_escalation: 权限提升
    7. persistence: 持久化访问

    Args:
        state: 当前状态
        current_node: 当前节点名

    Returns:
        下一节点名称
    """
    # 检查是否处于内网模式
    if not state.get("internal_mode", False):
        return "mode_manager"  # 返回Web模式

    # 收集关键状态信息 (压缩上下文)
    context = {
        "internal_hosts_count": len(state.get("internal_hosts") or []),
        "credentials_count": len(state.get("credentials") or []),
        "active_sessions_count": len(state.get("active_sessions") or []),
        "upload_status": state.get("upload_status", ""),
        "tunnel_status": state.get("tunnel_status", ""),
        "current_target": state.get("current_internal_target", ""),
        "pivot_host": state.get("pivot_host", ""),
        "shell_session": bool(state.get("shell_session")),
        "proxy_info": bool(state.get("proxy_info")),
        "persistence_established": state.get("persistence_established", False),
    }

    # 死循环检测
    if _route_guard.check_dead_loop(current_node, "internal_recon"):
        logger.warning(f"[InternalRoute] 检测到潜在死循环，重置计数")
        _route_guard.reset_loop_count("internal_recon")

    # AI决策路由
    decision = _ai_route_internal_decision(context, state)
    return decision


def _ai_route_internal_decision(context: Dict, state: CTFState) -> str:
    """
    AI决策内网路由

    根据当前态势选择最优节点
    """
    # 获取当前攻击阶段
    current_phase = state.get("current_compromise_phase", "")

    # 规则优先 (快速响应常见情况)
    # 规则1: 如果还没有侦察过，先侦察
    if context["internal_hosts_count"] == 0:
        logger.info(f"[InternalRoute] 侦察阶段")
        return "internal_recon"

    # 规则2: 如果有shell但没有上传工具
    if context["shell_session"] and context["upload_status"] not in ["completed", "commands_generated"]:
        logger.info(f"[InternalRoute] 工具上传阶段")
        return "upload_tools"

    # 规则3: 如果工具已上传但隧道未搭建
    if context["upload_status"] == "completed" and context["tunnel_status"] not in ["configured"]:
        logger.info(f"[InternalRoute] 隧道搭建阶段")
        return "setup_tunnel"

    # 规则4: 根据当前阶段决定下一步
    if current_phase == "flag_search":
        logger.info(f"[InternalRoute] Flag搜索阶段")
        return "flag_search"

    if current_phase == "complete":
        logger.info(f"[InternalRoute] 内网渗透完成")
        return "mode_manager"

    # 规则5: 如果有活跃会话但还没建立持久化
    active_sessions = state.get("active_sessions") or []
    if active_sessions and not context["persistence_established"]:
        logger.info(f"[InternalRoute] 有活跃会话，先建立持久化")
        return "persistence"

    # 规则6: 如果有活跃会话但还没搜索flag
    compromised_hosts = state.get("compromised_hosts") or []
    found_flags = state.get("found_flags") or []

    if active_sessions and len(found_flags) == 0:
        # 刚获取shell，先搜索flag
        logger.info(f"[InternalRoute] 有活跃会话，先搜索Flag")
        return "flag_search"

    # 规则6: 检查是否所有主机都已攻陷
    internal_hosts = state.get("internal_hosts") or []
    session_hosts = [s.get("host") for s in active_sessions if s.get("host")]
    all_compromised = set(compromised_hosts + session_hosts)

    unexplored_count = sum(1 for h in internal_hosts
                          if isinstance(h, dict) and h.get("ip") and h.get("ip") not in all_compromised)

    if unexplored_count > 0 and context["credentials_count"] > 0:
        logger.info(f"[InternalRoute] 还有{unexplored_count}台主机未攻陷，继续横向移动")
        return "lateral_move"

    # 复杂情况交给AI决策
    prompt = f"""
分析内网渗透态势，决定下一步行动。

## 当前状态
- 发现主机: {context['internal_hosts_count']} 台
- 已获取凭据: {context['credentials_count']} 组
- 活跃会话: {context['active_sessions_count']} 个
- 已发现Flag: {len(found_flags)} 个
- 已攻陷主机: {len(all_compromised)} 台
- 未攻陷主机: {unexplored_count} 台
- 工具上传: {context['upload_status']}
- 隧道状态: {context['tunnel_status']}
- 当前目标: {context['current_target'] or '未确定'}

## 可选节点
- internal_recon: 继续扫描发现更多主机
- credential_gather: 收集凭据
- lateral_move: 横向移动到其他主机
- privilege_escalation: 提升当前会话权限
- persistence: 建立持久化访问，确保会话不丢失
- flag_search: 在已攻陷主机上搜索Flag

## 目标
1. 首先搜索Flag
2. 然后攻陷所有内网主机
3. 在每台主机的管理员文件夹中寻找Flag

## 要求
1. 选择最优下一步
2. 输出节点名称和理由

## 输出格式 (JSON)
{{
    "next_node": "节点名称",
    "reason": "选择理由"
}}
"""

    try:
        response = llm_client.call_chat_completion(
            model=config.ANALYST_MODEL,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.1,
            json_mode=True
        )

        if "```json" in response:
            response = response.split("```json")[1].split("```")[0]

        result = json.loads(response.strip())
        next_node = result.get("next_node", "flag_search")
        logger.info(f"[InternalRoute] AI决策: {next_node} - {result.get('reason', '')}")

        # 验证节点名称
        valid_nodes = ["internal_recon", "credential_gather", "lateral_move", "privilege_escalation", "upload_tools", "setup_tunnel", "flag_search"]
        if next_node in valid_nodes:
            return next_node

    except Exception as e:
        logger.info(f"[InternalRoute] AI决策失败: {e}")

    # 降级: 基于规则的决策
    if context["credentials_count"] < 2 and context["current_target"]:
        return "credential_gather"

    if context["credentials_count"] > 0 and unexplored_count > 0:
        return "lateral_move"

    if context["active_sessions_count"] > 0:
        return "flag_search"

    return "internal_recon"


def route_internal_to_web(state: CTFState) -> str:
    """
    内网到Web模式的切换判断

    新目标: 攻陷所有内网主机，在每台主机上搜索Flag
    结束条件: 50分钟超时 或 所有主机已攻陷

    Args:
        state: 当前状态

    Returns:
        "internal" 或 "web"
    """
    # 如果内网模式已关闭
    if not state.get("internal_mode", False):
        return "web"

    # 检查当前阶段
    current_phase = state.get("current_compromise_phase", "")
    if current_phase == "complete":
        logger.info(f"[InternalRoute] 内网渗透已完成")
        return "web"

    # 检查是否所有主机都已攻陷
    internal_hosts = state.get("internal_hosts") or []
    compromised_hosts = state.get("compromised_hosts") or []
    active_sessions = state.get("active_sessions") or []

    session_hosts = [s.get("host") for s in active_sessions if s.get("host")]
    all_compromised = set(compromised_hosts + session_hosts)

    unexplored = [h for h in internal_hosts
                  if isinstance(h, dict) and h.get("ip") and h.get("ip") not in all_compromised]

    if not unexplored and internal_hosts:
        logger.info(f"[InternalRoute] 所有主机已攻陷，内网渗透完成")
        return "web"

    # 内网渗透只按时间超时结束，不受步数限制
    # 移除了 MAX_TOTAL_ROUNDS 检查，因为内网渗透有自己的 INTERNAL_TASK_TIMEOUT

    return "internal"


def get_internal_next_target(state: CTFState) -> str:
    """
    选择下一个内网目标

    优先级:
    1. 域控制器
    2. 高价值服务器（数据库、文件服务器）
    3. 普通工作站

    Args:
        state: 当前状态

    Returns:
        目标IP
    """
    # 安全获取列表，处理None值
    internal_hosts = state.get("internal_hosts") or []
    active_sessions = state.get("active_sessions") or []
    compromised = [s.get("host") for s in active_sessions if s.get("host")]

    # 优先级排序
    for host in internal_hosts:
        if not isinstance(host, dict):
            continue
        ip = host.get("ip", "")
        if not ip or ip in compromised:
            continue

        ports = host.get("ports") or []
        port_numbers = [p.get("port") for p in ports if isinstance(p, dict) and p.get("port")]

        # 域控制器特征
        if any(p in port_numbers for p in [88, 389, 636, 3268]):
            return ip

        # 高价值服务器
        if any(p in port_numbers for p in [1433, 3306, 5432, 445]):
            return ip

    # 返回第一个未攻陷的主机
    for host in internal_hosts:
        if not isinstance(host, dict):
            continue
        ip = host.get("ip", "")
        if ip and ip not in compromised:
            return ip

    return ""


def route_post_exploit(state: CTFState, current_node: str) -> str:
    """
    后渗透路由 - AI驱动 + 自动化流程

    流程:
        1. 检测到内网环境 -> upload_tools (先上传工具)
        2. 工具上传完成 -> setup_tunnel (搭建隧道)
        3. 隧道搭建完成 -> internal_recon (开始内网侦察)
        4. 无内网环境 -> mode_manager (继续Web攻击)

    Args:
        state: 当前状态
        current_node: 当前节点名

    Returns:
        下一节点名称
    """
    post_exploit_status = state.get("post_exploit_status", "")
    upload_status = state.get("upload_status", "")
    tunnel_status = state.get("tunnel_status", "")
    internal_range = state.get("internal_network_range", "")

    # 如果发现内网环境，进入内网渗透流程
    if post_exploit_status == "ready_for_internal" and internal_range:
        # 步骤1: 上传工具
        if upload_status not in ["completed", "commands_generated"]:
            logger.info(f"[PostExploitRoute] 发现内网，准备上传工具")
            return "upload_tools"

        # 步骤2: 搭建隧道
        if tunnel_status != "configured":
            logger.info(f"[PostExploitRoute] 工具就绪，准备搭建隧道")
            return "setup_tunnel"

        # 步骤3: 开始内网侦察
        logger.info(f"[PostExploitRoute] 隧道就绪，进入内网侦察")
        return "internal_recon"

    # 如果只是Web shell，继续Web攻击流程
    if post_exploit_status == "web_only":
        logger.info(f"📌 [PostExploitRoute] 无内网环境，继续Web攻击")
        return "mode_manager"

    # 如果无结果或失败，回到决策
    return "mode_manager"