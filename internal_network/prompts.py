# internal_network/prompts.py
"""
内网渗透提示词模块

提供内网渗透场景下的分析和攻击提示词
"""

from typing import Dict, List, Any, Optional


def _build_stage_section(stage_info: Dict = None) -> str:
    """
    构建阶段信息部分

    Args:
        stage_info: 阶段信息字典

    Returns:
        格式化的阶段信息字符串
    """
    if not stage_info:
        return ""

    return f"""
## 当前阶段: {stage_info.get('stage_name', '')}
- 目标: {stage_info.get('goal', '')}
- 成功标准: {', '.join(stage_info.get('success_criteria', [])) or '无'}
"""


def _build_strategic_section(strategic_context: Dict = None) -> str:
    """
    构建战略上下文部分

    Args:
        strategic_context: 战略上下文字典

    Returns:
        格式化的战略上下文字符串
    """
    if not strategic_context:
        return ""

    return f"""
## 战略上下文
- 攻击链进度: 第{strategic_context.get('current_step', 1)}步/共{strategic_context.get('total_steps', 5)}步
- 已知障碍: {', '.join(strategic_context.get('blockers', [])) or '无'}
- 备选路径: {', '.join(strategic_context.get('alternate_routes', [])) or '无'}
"""


def get_internal_recon_prompt(
    network_range: str,
    discovered_hosts: List[Dict],
    pivot_host: str,
    stage_info: Dict = None,
    strategic_context: Dict = None
) -> str:
    """
    内网侦察分析提示词

    Args:
        network_range: 内网网段
        discovered_hosts: 已发现的主机列表
        pivot_host: 跳板机IP
        stage_info: 阶段信息
        strategic_context: 战略上下文

    Returns:
        分析提示词
    """
    hosts_summary = []
    for host in discovered_hosts[:20]:
        ports_str = ", ".join([f"{p.get('port')}/{p.get('service', '?')}" for p in host.get("ports", [])[:5]])
        hosts_summary.append(f"  - {host.get('ip')}: [{ports_str}] OS: {host.get('os', 'unknown')}")

    hosts_text = "\n".join(hosts_summary) if hosts_summary else "暂无发现"

    stage_section = _build_stage_section(stage_info)
    strategic_section = _build_strategic_section(strategic_context)

    return f"""
# 内网侦察分析报告

## 当前状态
- 内网网段: {network_range}
- 跳板机: {pivot_host}
- 发现主机数: {len(discovered_hosts)}
{stage_section}{strategic_section}
## 发现的主机
{hosts_text}

## 分析任务

### 1. 高价值目标识别
识别可能存在高价值数据或漏洞的主机:
- 域控制器 (开放 88/389/636/3268 端口)
- 文件服务器 (开放 445/139 端口)
- 数据库服务器 (开放 1433/3306/5432 端口)
- Web服务器 (开放 80/443/8080 端口)

### 2. 攻击路径规划
基于发现的端口和服务，规划潜在攻击路径:
- SMB利用 (445端口)
- RDP爆破 (3389端口)
- SSH爆破 (22端口)
- Web应用攻击 (80/443/8080端口)

### 3. 下一步建议

## 输出格式 (JSON) - 简化版
{{
  "high_value_targets": [
    {{
      "ip": "目标IP",
      "reason": "原因",
      "recommended_action": "建议动作"
    }}
  ],
  "attack_paths": [
    {{
      "source": "跳板机",
      "target": "目标IP",
      "method": "攻击方法"
    }}
  ],
  "next_steps": ["下一步操作列表"],
  "priority_order": ["按优先级排序的IP列表"]
}}
"""


def get_credential_analysis_prompt(
    credentials: List[Dict],
    target_host: str,
    target_ports: List[Dict],
    stage_info: Dict = None,
    strategic_context: Dict = None
) -> str:
    """
    凭据分析提示词

    Args:
        credentials: 已获取的凭据列表
        target_host: 目标主机
        target_ports: 目标主机开放的端口
        stage_info: 阶段信息
        strategic_context: 战略上下文

    Returns:
        凭据分析提示词
    """
    creds_summary = []
    for cred in credentials:
        cred_type = cred.get("cred_type", "unknown")
        username = cred.get("username", "?")
        domain = cred.get("domain", "WORKGROUP")
        creds_summary.append(f"  - {domain}\\{username} ({cred_type})")

    creds_text = "\n".join(creds_summary) if creds_summary else "暂无凭据"
    ports_text = ", ".join([f"{p.get('port')}/{p.get('service', '?')}" for p in target_ports])

    stage_section = _build_stage_section(stage_info)
    strategic_section = _build_strategic_section(strategic_context)

    return f"""
# 凭据利用分析

## 已获取凭据
{creds_text}

## 目标主机
- IP: {target_host}
- 开放端口: {ports_text}
{stage_section}{strategic_section}
## 分析任务

### 1. 凭据复用检测
检查获取的凭据是否可用于目标主机:
- 相同用户名/密码组合
- 哈希传递 (Pass-the-Hash)
- 票据传递 (Pass-the-Ticket)

### 2. 横向移动方法选择
基于目标端口选择最佳横向移动方法:
- 445端口: PsExec, SMBExec, WMIExec
- 135/5985端口: WMI, WinRM
- 22端口: SSH
- 3389端口: RDP

### 3. 成功概率评估
评估凭据利用的成功概率

## 输出格式 (JSON) - 简化版
{{
  "usable_credentials": [
    {{
      "credential": "username@domain",
      "can_use": true,
      "method": "psexec"
    }}
  ],
  "recommended_method": "psexec/wmiexec/ssh/rdp",
  "alternative_methods": ["备选方法"],
  "potential_issues": ["可能遇到的问题"]
}}
"""


def get_lateral_move_prompt(
    source_host: str,
    target_host: str,
    method: str,
    credential: Dict,
    target_info: Dict,
    stage_info: Dict = None,
    strategic_context: Dict = None
) -> str:
    """
    横向移动执行提示词

    Args:
        source_host: 源主机
        target_host: 目标主机
        method: 移动方法
        credential: 使用的凭据
        target_info: 目标主机信息
        stage_info: 阶段信息
        strategic_context: 战略上下文

    Returns:
        横向移动提示词
    """
    stage_section = _build_stage_section(stage_info)
    strategic_section = _build_strategic_section(strategic_context)

    return f"""
# 横向移动执行计划

## 移动信息
- 源主机: {source_host}
- 目标主机: {target_host}
- 方法: {method}
- 凭据: {credential.get('username')}@{credential.get('domain', 'WORKGROUP')}

## 目标主机信息
- OS: {target_info.get('os', 'unknown')}
- 开放端口: {target_info.get('ports', [])}
- 域: {target_info.get('domain', 'unknown')}
{stage_section}{strategic_section}
## 执行步骤

### PsExec方式
```bash
impacket-psexec {credential.get('domain', 'WORKGROUP')}/{credential.get('username')}:{credential.get('password', '')}@{target_host}
```

### WMIExec方式
```bash
impacket-wmiexec {credential.get('domain', 'WORKGROUP')}/{credential.get('username')}:{credential.get('password', '')}@{target_host}
```

### WinRM方式
```bash
evil-winrm -i {target_host} -u {credential.get('username')} -p '{credential.get('password', '')}'
```

## 输出格式 (JSON)
{{
  "command": "完整命令",
  "expected_output": "预期输出特征",
  "success_indicators": ["成功指标"],
  "failure_indicators": ["失败指标"],
  "post_exploitation": ["获取shell后的操作"]
}}
"""


def get_ad_analysis_prompt(
    ad_domain: str,
    ad_users: List[str],
    ad_groups: List[str],
    ad_computers: List[str],
    domain_controller: str,
    stage_info: Dict = None,
    strategic_context: Dict = None
) -> str:
    """
    AD域分析提示词

    Args:
        ad_domain: AD域名
        ad_users: 域用户列表
        ad_groups: 域组列表
        ad_computers: 域计算机列表
        domain_controller: 域控IP
        stage_info: 阶段信息
        strategic_context: 战略上下文

    Returns:
        AD分析提示词
    """
    users_text = "\n".join([f"  - {u}" for u in ad_users[:20]]) if ad_users else "  暂无"
    groups_text = "\n".join([f"  - {g}" for g in ad_groups[:15]]) if ad_groups else "  暂无"
    computers_text = "\n".join([f"  - {c}" for c in ad_computers[:15]]) if ad_computers else "  暂无"

    stage_section = _build_stage_section(stage_info)
    strategic_section = _build_strategic_section(strategic_context)

    return f"""
# Active Directory 分析报告

## 域信息
- 域名: {ad_domain}
- 域控制器: {domain_controller}

## 域用户 ({len(ad_users)} 个)
{users_text}

## 域组 ({len(ad_groups)} 个)
{groups_text}

## 域计算机 ({len(ad_computers)} 台)
{computers_text}
{stage_section}{strategic_section}
## 分析任务

### 1. 高权限账户识别
查找可能具有高权限的账户:
- Domain Admins组成员
- Enterprise Admins组成员
- 账户操作员
- 备份操作员

### 2. 攻击路径分析
识别潜在的攻击路径:
- Kerberoasting攻击目标 (SPN账户)
- AS-REP Roasting目标 (禁用预认证的账户)
- 委派攻击 (约束/非约束委派)
- DCSync攻击可能性

### 3. 横向移动建议
基于AD信息建议横向移动策略

## 输出格式 (JSON) - 简化版
{{
  "high_privilege_accounts": [
    {{
      "username": "用户名",
      "groups": ["所属组"]
    }}
  ],
  "roastable_targets": [
    {{
      "account": "账户",
      "type": "kerberoast/asrep"
    }}
  ],
  "delegation_attacks": [
    {{
      "account": "账户",
      "type": "委托类型",
      "target": "可访问的资源"
    }}
  ],
  "priority_order": ["优先攻击目标"]
}}
"""


def get_privilege_escalation_prompt(
    current_user: str,
    current_privileges: List[str],
    system_info: Dict,
    available_tools: List[str],
    stage_info: Dict = None,
    strategic_context: Dict = None
) -> str:
    """
    权限提升分析提示词

    Args:
        current_user: 当前用户
        current_privileges: 当前权限
        system_info: 系统信息
        available_tools: 可用工具列表
        stage_info: 阶段信息
        strategic_context: 战略上下文

    Returns:
        权限提升提示词
    """
    stage_section = _build_stage_section(stage_info)
    strategic_section = _build_strategic_section(strategic_context)

    return f"""
# 权限提升分析

## 当前状态
- 当前用户: {current_user}
- 当前权限: {current_privileges}

## 系统信息
- OS: {system_info.get('os', 'unknown')}
- 架构: {system_info.get('arch', 'unknown')}
- 补丁级别: {system_info.get('patches', 'unknown')}

## 可用工具
{available_tools}
{stage_section}{strategic_section}
## 分析任务

### 1. 本地提权漏洞
检查已知的本地提权漏洞:
- Potato系列 (PrintSpoofer, JuicyPotato, RoguePotato)
- CVE漏洞 (根据补丁级别)
- 服务配置错误
- 不安全的服务权限

### 2. 凭据窃取
检查可窃取的凭据:
- 内存中的凭据 (Mimikatz)
- 注册表中的凭据
- 配置文件中的凭据
- 计划任务中的凭据

### 3. UAC绕过
检查UAC绕过可能性

## 输出格式 (JSON) - 简化版
{{
  "privilege_escalation_paths": [
    {{
      "method": "提权方法",
      "command": "具体命令",
      "requirements": ["所需条件"]
    }}
  ],
  "credential_harvesting": [
    {{
      "location": "凭据位置",
      "tool": "使用工具",
      "command": "命令"
    }}
  ],
  "recommended_order": ["按优先级排序的提权方法"]
}}
"""


def get_internal_mode_router_prompt(
    state: Dict,
    stage_info: Dict = None,
    strategic_context: Dict = None
) -> str:
    """
    内网模式路由决策提示词

    Args:
        state: 当前状态
        stage_info: 阶段信息
        strategic_context: 战略上下文

    Returns:
        路由决策提示词
    """
    internal_hosts = state.get("internal_hosts", [])
    credentials = state.get("credentials", [])
    active_sessions = state.get("active_sessions", [])
    current_target = state.get("current_internal_target", "")
    pivot_host = state.get("pivot_host", "")

    stage_section = _build_stage_section(stage_info)
    strategic_section = _build_strategic_section(strategic_context)

    return f"""
# 内网渗透模式决策

## 当前状态
- 发现主机: {len(internal_hosts)} 台
- 已获取凭据: {len(credentials)} 组
- 活跃会话: {len(active_sessions)} 个
- 当前目标: {current_target}
- 跳板机: {pivot_host}
{stage_section}{strategic_section}
## 决策选项

### recon_mode (侦察模式)
条件: 未发现足够多的主机
动作: 继续扫描内网

### credential_mode (凭据获取模式)
条件: 发现主机但凭据不足
动作: 尝试从当前目标获取凭据

### lateral_mode (横向移动模式)
条件: 有凭据且有新目标
动作: 尝试横向移动到新主机

### privilege_mode (权限提升模式)
条件: 已获得shell但权限不足
动作: 尝试提权

### persistence_mode (持久化模式)
条件: 获得足够权限
动作: 建立持久化访问

## 输出格式 (JSON)
{{
  "current_phase": "当前阶段名称",
  "recommended_mode": "建议的模式",
  "reason": "原因",
  "target_host": "目标主机IP",
  "action": "具体动作"
}}
"""


def get_flag_search_prompt(
    current_host: str,
    user_context: str,
    search_paths: List[str],
    stage_info: Dict = None,
    strategic_context: Dict = None
) -> str:
    """
    Flag搜索提示词

    Args:
        current_host: 当前主机
        user_context: 用户上下文
        search_paths: 搜索路径列表
        stage_info: 阶段信息
        strategic_context: 战略上下文

    Returns:
        Flag搜索提示词
    """
    stage_section = _build_stage_section(stage_info)
    strategic_section = _build_strategic_section(strategic_context)
    paths_text = "\n".join([f"  - {p}" for p in search_paths]) if search_paths else "  默认路径"

    return f"""
# Flag搜索任务

## 当前环境
- 主机: {current_host}
- 用户上下文: {user_context}
{stage_section}{strategic_section}
## 搜索路径
{paths_text}

## 搜索策略

### 1. 文件系统搜索
搜索常见的flag存放位置:
- 桌面目录
- 用户文档目录
- Web目录
- 数据库文件

### 2. 数据库搜索
检查数据库中的flag:
- MySQL: information_schema, 用户数据库
- MSSQL: master, 用户数据库
- PostgreSQL: postgres, 用户数据库

### 3. 内存搜索
从进程内存中提取flag

## 输出格式 (JSON)
{{
  "search_commands": [
    {{
      "path": "搜索路径",
      "command": "搜索命令",
      "expected_pattern": "flag格式模式"
    }}
  ],
  "priority_order": ["按优先级排序的搜索位置"],
  "estimated_time": "预计耗时"
}}
"""


def get_persistence_prompt(
    target_host: str,
    user_context: str,
    system_info: Dict,
    stage_info: Dict = None,
    strategic_context: Dict = None
) -> str:
    """
    持久化提示词

    Args:
        target_host: 目标主机
        user_context: 用户上下文
        system_info: 系统信息
        stage_info: 阶段信息
        strategic_context: 战略上下文

    Returns:
        持久化提示词
    """
    stage_section = _build_stage_section(stage_info)
    strategic_section = _build_strategic_section(strategic_context)

    return f"""
# 持久化方案

## 目标环境
- 主机: {target_host}
- 用户: {user_context}
- OS: {system_info.get('os', 'unknown')}
- 架构: {system_info.get('arch', 'unknown')}
{stage_section}{strategic_section}
## 持久化方法

### 1. 计划任务 (Windows)
使用schtasks创建持久化任务

### 2. 注册表 (Windows)
通过注册表启动项实现持久化

### 3. 服务 (Windows/Linux)
创建恶意服务实现持久化

### 4. Cron (Linux)
通过cron任务实现持久化

### 5. SSH密钥 (Linux)
植入SSH公钥实现持久化

## 输出格式 (JSON) - 简化版
{{
  "persistence_methods": [
    {{
      "method": "方法名称",
      "command": "执行命令",
      "cleanup_command": "清理命令"
    }}
  ],
  "recommended_order": ["按优先级排序的方法"]
}}
"""


def get_credential_gather_prompt(
    target_host: str,
    target_info: Dict,
    available_methods: List[str],
    stage_info: Dict = None,
    strategic_context: Dict = None
) -> str:
    """
    凭据收集提示词

    Args:
        target_host: 目标主机
        target_info: 目标主机信息
        available_methods: 可用的凭据收集方法
        stage_info: 阶段信息
        strategic_context: 战略上下文

    Returns:
        凭据收集提示词
    """
    stage_section = _build_stage_section(stage_info)
    strategic_section = _build_strategic_section(strategic_context)
    methods_text = ", ".join(available_methods) if available_methods else "默认方法"

    return f"""
# 凭据收集任务

## 目标信息
- 主机: {target_host}
- OS: {target_info.get('os', 'unknown')}
- 域: {target_info.get('domain', 'unknown')}
- 开放端口: {target_info.get('ports', [])}
{stage_section}{strategic_section}
## 可用方法
{methods_text}

## 收集策略

### 1. 内存凭据 (LSASS)
- Mimikatz sekurlsa::logonpasswords
- Procdump + Mimikatz离线分析

### 2. 本地账户
- SAM数据库导出
- 本地管理员密码重置

### 3. 域凭据
- NTDS.dit导出
- DCSync攻击
- Kerberoasting

### 4. 配置文件
- Web配置文件
- 数据库连接字符串
- 应用程序配置

## 输出格式 (JSON) - 简化版
{{
  "collection_methods": [
    {{
      "method": "方法名称",
      "command": "执行命令",
      "privilege_required": "所需权限"
    }}
  ],
  "priority_order": ["按优先级排序的方法"]
}}
"""