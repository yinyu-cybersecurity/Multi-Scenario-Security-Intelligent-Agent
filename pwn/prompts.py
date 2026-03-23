# pwn/prompts.py
"""
Pwn模块提示词

提供LLM分析用的提示词模板
"""

from typing import Dict, List, Optional


def get_pwn_analysis_prompt(binary_info: Dict, protections: Dict) -> str:
    """
    获取Pwn分析提示词

    Args:
        binary_info: 二进制信息
        protections: 保护机制状态

    Returns:
        分析提示词
    """
    return f"""
你是一个二进制安全专家，分析以下二进制文件的安全状况。

## 二进制信息
- 架构: {binary_info.get('arch', 'unknown')}
- 位数: {binary_info.get('bits', 'unknown')}
- 危险函数: {binary_info.get('dangerous_functions', [])}

## 保护机制
{protections}

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


def get_buffer_overflow_prompt(vuln_info: Dict, protections: Dict) -> str:
    """
    获取缓冲区溢出利用提示词

    Args:
        vuln_info: 漏洞信息
        protections: 保护机制

    Returns:
        利用提示词
    """
    return f"""
分析缓冲区溢出漏洞的利用方法。

## 漏洞信息
- 位置: {vuln_info.get('location', 'unknown')}
- 严重性: {vuln_info.get('severity', 'unknown')}

## 保护状态
- NX: {protections.get('NX', True)}
- Canary: {protections.get('Canary', False)}
- PIE: {protections.get('PIE', False)}

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


def get_rop_chain_prompt(gadgets: List[str], target: str) -> str:
    """
    获取ROP链构建提示词

    Args:
        gadgets: 可用gadget列表
        target: 目标函数

    Returns:
        ROP链构建提示词
    """
    return f"""
构建ROP链执行目标函数。

## 可用Gadgets
{gadgets[:50]}

## 目标
{target}

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


def get_format_string_prompt(offset: int, target_addr: str) -> str:
    """
    获取格式化字符串利用提示词

    Args:
        offset: 格式化字符串偏移
        target_addr: 目标地址

    Returns:
        格式化字符串利用提示词
    """
    return f"""
构建格式化字符串利用payload。

## 参数
- 格式化字符串偏移: {offset}
- 目标地址: {target_addr}

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


def get_heap_exploit_prompt(heap_info: Dict) -> str:
    """
    获取堆利用提示词

    Args:
        heap_info: 堆信息

    Returns:
        堆利用提示词
    """
    return f"""
分析堆漏洞利用方法。

## 堆信息
{heap_info}

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


def get_pwn_mode_router_prompt(state: Dict) -> str:
    """
    获取Pwn模式路由提示词

    Args:
        state: 当前状态

    Returns:
        路由决策提示词
    """
    return f"""
判断是否需要启用Pwn模式进行二进制分析。

## 已知事实
{state.get("known_facts", "")}

## 文件信息
{state.get("attachments", [])}

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