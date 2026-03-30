# pwn/prompts.py
"""
Pwn模块提示词

提供LLM分析用的提示词模板
"""

from typing import Dict, List, Optional, Any


def _format_stage_section(stage_info: Optional[Dict[str, Any]] = None) -> str:
    """
    格式化阶段信息部分

    Args:
        stage_info: 阶段信息字典

    Returns:
        格式化后的阶段信息字符串
    """
    if not stage_info:
        return ""

    stage_name = stage_info.get('stage_name', '')
    stage_type = stage_info.get('stage_type', '')
    goal = stage_info.get('goal', '')
    success_criteria = stage_info.get('success_criteria', [])
    timeout = stage_info.get('timeout', 0)
    hints = stage_info.get('hints', [])
    primary_strategy = stage_info.get('primary_strategy', '')

    lines = ["## 当前阶段指引"]
    if stage_name:
        lines.append(f"- 阶段名称: {stage_name}")
    if stage_type:
        lines.append(f"- 阶段类型: {stage_type}")
    if goal:
        lines.append(f"- 阶段目标: {goal}")
    if primary_strategy:
        lines.append(f"- 主策略: {primary_strategy}")
    if success_criteria:
        criteria_str = ', '.join(success_criteria) if isinstance(success_criteria, list) else str(success_criteria)
        lines.append(f"- 成功标准: {criteria_str}")
    if timeout:
        lines.append(f"- 超时限制: {timeout}秒")
    if hints:
        hints_str = '; '.join(hints[:3]) if isinstance(hints, list) else str(hints)
        lines.append(f"- 阶段提示: {hints_str}")

    return '\n'.join(lines) + '\n'


def _format_strategic_section(strategic_context: Optional[Dict[str, Any]] = None) -> str:
    """
    格式化战略上下文部分

    Args:
        strategic_context: 战略上下文字典

    Returns:
        格式化后的战略上下文字符串
    """
    if not strategic_context:
        return ""

    position_type = strategic_context.get('position_type', 'pwn')
    position_detail = strategic_context.get('position_detail', '')
    primary_goal = strategic_context.get('primary_goal', '获取FLAG')
    attack_chain = strategic_context.get('attack_chain', [])
    current_step = strategic_context.get('current_step', 1)
    total_steps = strategic_context.get('total_steps', len(attack_chain))
    blockers = strategic_context.get('blockers', [])
    alternate_routes = strategic_context.get('alternate_routes', [])
    credential_access = strategic_context.get('credential_access', [])

    # 获取当前阶段名称
    current_stage_name = attack_chain[current_step - 1] if current_step <= len(attack_chain) else '未知'

    lines = ["## 战略上下文"]
    lines.append(f"- 当前位置类型: {position_type}")
    if position_detail:
        lines.append(f"- 详细位置: {position_detail}")
    lines.append(f"- 攻击链进度: 第{current_step}步/共{total_steps}步")
    lines.append(f"- 当前阶段: {current_stage_name}")
    lines.append(f"- 主要目标: {primary_goal}")

    if blockers:
        blockers_str = ', '.join(blockers)
        lines.append(f"- 已知障碍: {blockers_str}")

    if alternate_routes:
        routes_str = ', '.join(alternate_routes)
        lines.append(f"- 备选路径: {routes_str}")

    if credential_access:
        lines.append(f"- 可用凭据: {len(credential_access)}组")

    return '\n'.join(lines) + '\n'


def _format_pwn_stage_context(
    stage_info: Optional[Dict[str, Any]] = None,
    strategic_context: Optional[Dict[str, Any]] = None
) -> str:
    """
    格式化Pwn场景的阶段和战略上下文

    Args:
        stage_info: 阶段信息
        strategic_context: 战略上下文

    Returns:
        格式化后的上下文字符串
    """
    sections = []

    stage_section = _format_stage_section(stage_info)
    if stage_section:
        sections.append(stage_section)

    strategic_section = _format_strategic_section(strategic_context)
    if strategic_section:
        sections.append(strategic_section)

    return '\n'.join(sections)


def get_pwn_analysis_prompt(
    binary_info: Dict,
    protections: Dict,
    stage_info: Optional[Dict[str, Any]] = None,
    strategic_context: Optional[Dict[str, Any]] = None
) -> str:
    """
    获取Pwn分析提示词

    Args:
        binary_info: 二进制信息
        protections: 保护机制状态
        stage_info: 阶段信息
        strategic_context: 战略上下文

    Returns:
        分析提示词
    """
    context_section = _format_pwn_stage_context(stage_info, strategic_context)

    return f"""
你是一个二进制安全专家，分析以下二进制文件的安全状况。

## 二进制信息
- 架构: {binary_info.get('arch', 'unknown')}
- 位数: {binary_info.get('bits', 'unknown')}
- 危险函数: {binary_info.get('dangerous_functions', [])}

## 保护机制
{protections}

{context_section}
## 分析任务
1. 评估各保护机制对利用的影响
2. 识别可能的绕过方法
3. 推荐最佳利用策略

## 输出格式 (JSON)
{{
  "protection_analysis": {{
    "nx_impact": "NX保护的影响分析",
    "canary_bypass": "可能的Canary绕过方法",
    "pie_impact": "PIE对地址计算的影响"
  }},
  "exploit_strategy": "推荐的利用策略",
  "difficulty": "easy/medium/hard",
  "key_points": ["关键点列表"]
}}
"""


def get_buffer_overflow_prompt(
    vuln_info: Dict,
    protections: Dict,
    stage_info: Optional[Dict[str, Any]] = None,
    strategic_context: Optional[Dict[str, Any]] = None
) -> str:
    """
    获取缓冲区溢出利用提示词

    Args:
        vuln_info: 漏洞信息
        protections: 保护机制
        stage_info: 阶段信息
        strategic_context: 战略上下文

    Returns:
        利用提示词
    """
    context_section = _format_pwn_stage_context(stage_info, strategic_context)

    return f"""
分析缓冲区溢出漏洞的利用方法。

## 漏洞信息
- 位置: {vuln_info.get('location', 'unknown')}
- 严重性: {vuln_info.get('severity', 'unknown')}

## 保护状态
- NX: {protections.get('NX', True)}
- Canary: {protections.get('Canary', False)}
- PIE: {protections.get('PIE', False)}

{context_section}
## 利用策略选择
1. 如果NX关闭: 注入shellcode
2. 如果NX开启: ROP链或ret2libc
3. 如果Canary开启: 需要先泄露canary

## 输出格式 (JSON)
{{
  "exploit_type": "shellcode/rop/ret2libc",
  "steps": ["利用步骤"],
  "required_values": ["需要计算的值"],
  "payload_structure": "payload结构说明"
}}
"""


def get_rop_chain_prompt(
    gadgets: List[str],
    target: str,
    stage_info: Optional[Dict[str, Any]] = None,
    strategic_context: Optional[Dict[str, Any]] = None
) -> str:
    """
    获取ROP链构建提示词

    Args:
        gadgets: 可用gadget列表
        target: 目标函数
        stage_info: 阶段信息
        strategic_context: 战略上下文

    Returns:
        ROP链构建提示词
    """
    context_section = _format_pwn_stage_context(stage_info, strategic_context)

    return f"""
构建ROP链执行目标函数。

## 可用Gadgets
{gadgets[:50]}

## 目标
{target}

{context_section}
## 构建要求
1. 选择合适的gadgets
2. 设置正确的参数
3. 考虑对齐问题

## 输出格式 (JSON)
{{
  "chain": [
    {{"gadget": "名称", "value": "参数值", "purpose": "作用"}}
  ],
  "total_length": 链的总长度,
  "notes": "注意事项"
}}
"""


def get_format_string_prompt(
    offset: int,
    target_addr: str,
    stage_info: Optional[Dict[str, Any]] = None,
    strategic_context: Optional[Dict[str, Any]] = None
) -> str:
    """
    获取格式化字符串利用提示词

    Args:
        offset: 格式化字符串偏移
        target_addr: 目标地址
        stage_info: 阶段信息
        strategic_context: 战略上下文

    Returns:
        格式化字符串利用提示词
    """
    context_section = _format_pwn_stage_context(stage_info, strategic_context)

    return f"""
构建格式化字符串利用payload。

## 参数
- 格式化字符串偏移: {offset}
- 目标地址: {target_addr}

{context_section}
## 利用方法
1. 泄露栈数据确定偏移
2. 使用%n写入目标地址
3. 考虑字节写入顺序

## 输出格式 (JSON)
{{
  "payload": "格式化字符串payload",
  "write_value": 要写入的值,
  "explanation": "payload解释"
}}
"""


def get_heap_exploit_prompt(
    heap_info: Dict,
    stage_info: Optional[Dict[str, Any]] = None,
    strategic_context: Optional[Dict[str, Any]] = None
) -> str:
    """
    获取堆利用提示词

    Args:
        heap_info: 堆信息
        stage_info: 阶段信息
        strategic_context: 战略上下文

    Returns:
        堆利用提示词
    """
    context_section = _format_pwn_stage_context(stage_info, strategic_context)

    return f"""
分析堆漏洞利用方法。

## 堆信息
{heap_info}

{context_section}
## 常见堆利用技术
1. Fastbin Attack: 伪造fastbin chunk
2. Tcache Poisoning: 污染tcache
3. Unsorted Bin Attack: 利用unsorted bin
4. House of 系列技术

## 输出格式 (JSON)
{{
  "recommended_technique": "推荐的利用技术",
  "chunk_layout": ["chunk布局规划"],
  "target_hook": "目标hook地址",
  "steps": ["利用步骤"]
}}
"""


def get_pwn_mode_router_prompt(
    state: Dict,
    stage_info: Optional[Dict[str, Any]] = None,
    strategic_context: Optional[Dict[str, Any]] = None
) -> str:
    """
    获取Pwn模式路由提示词

    Args:
        state: 当前状态
        stage_info: 阶段信息
        strategic_context: 战略上下文

    Returns:
        路由决策提示词
    """
    context_section = _format_pwn_stage_context(stage_info, strategic_context)

    return f"""
判断是否需要启用Pwn模式进行二进制分析。

## 已知事实
{state.get("known_facts", "")}

## 文件信息
{state.get("attachments", [])}

{context_section}
## 判断标准
1. 是否有ELF/PE二进制文件
2. 是否提到栈溢出、堆漏洞、格式化字符串
3. 是否有nc连接端口提示
4. 是否需要pwn工具

## 输出格式 (JSON)
{{
  "need_pwn_mode": true/false,
  "reason": "判断理由",
  "binary_type": "ELF32/ELF64/PE/unknown",
  "expected_vulnerability": "预期的漏洞类型"
}}
"""


def get_shellcode_prompt(
    arch: str,
    constraints: Dict[str, Any],
    stage_info: Optional[Dict[str, Any]] = None,
    strategic_context: Optional[Dict[str, Any]] = None
) -> str:
    """
    获取Shellcode生成提示词

    Args:
        arch: 目标架构
        constraints: 约束条件（如禁用字符）
        stage_info: 阶段信息
        strategic_context: 战略上下文

    Returns:
        Shellcode生成提示词
    """
    context_section = _format_pwn_stage_context(stage_info, strategic_context)

    bad_chars = constraints.get('bad_chars', [])
    max_length = constraints.get('max_length', 'unlimited')

    return f"""
生成适用于指定架构的Shellcode。

## 架构信息
- 目标架构: {arch}

## 约束条件
- 禁用字符: {bad_chars if bad_chars else '无'}
- 最大长度: {max_length}

{context_section}
## 生成要求
1. 避免使用禁用字符
2. 尽量缩短长度
3. 确保可执行

## 输出格式 (JSON)
{{
  "shellcode": "shellcode十六进制字符串",
  "length": 实际长度,
  "description": "功能描述",
  "notes": "注意事项"
}}
"""


def get_ret2libc_prompt(
    libc_info: Dict[str, Any],
    protections: Dict,
    stage_info: Optional[Dict[str, Any]] = None,
    strategic_context: Optional[Dict[str, Any]] = None
) -> str:
    """
    获取ret2libc利用提示词

    Args:
        libc_info: Libc信息
        protections: 保护机制
        stage_info: 阶段信息
        strategic_context: 战略上下文

    Returns:
        ret2libc利用提示词
    """
    context_section = _format_pwn_stage_context(stage_info, strategic_context)

    return f"""
分析ret2libc利用方法。

## Libc信息
- 版本: {libc_info.get('version', 'unknown')}
- 基地址: {libc_info.get('base_addr', 'unknown')}
- 关键函数偏移: {libc_info.get('offsets', {})}

## 保护状态
- ASLR: {protections.get('ASLR', True)}
- PIE: {protections.get('PIE', False)}

{context_section}
## 利用策略
1. 泄露Libc地址
2. 计算基地址
3. 构造ROP链调用system

## 输出格式 (JSON)
{{
  "leak_method": "地址泄露方法",
  "rop_chain": ["ROP链步骤"],
  "required_gadgets": ["需要的gadgets"],
  "payload_structure": "payload结构说明"
}}
"""


def get_pwn_summary_prompt(
    analysis_results: Dict[str, Any],
    stage_info: Optional[Dict[str, Any]] = None,
    strategic_context: Optional[Dict[str, Any]] = None
) -> str:
    """
    获取Pwn分析总结提示词

    Args:
        analysis_results: 分析结果
        stage_info: 阶段信息
        strategic_context: 战略上下文

    Returns:
        总结提示词
    """
    context_section = _format_pwn_stage_context(stage_info, strategic_context)

    return f"""
总结Pwn题目分析结果。

## 分析结果
{analysis_results}

{context_section}
## 总结要求
1. 整理所有发现的漏洞点
2. 评估利用可行性
3. 给出最佳利用路径
4. 标注关键偏移和地址

## 输出格式 (JSON)
{{
  "vulnerabilities": [
    {{
      "type": "漏洞类型",
      "location": "位置",
      "severity": "严重程度",
      "exploitable": true/false
    }}
  ],
  "best_exploit": {{
    "type": "推荐利用方式",
    "difficulty": "难度评估",
    "steps": ["利用步骤"]
  }},
  "key_addresses": {{
    "function_name": "地址"
  }},
  "final_payload": "最终payload结构"
}}
"""