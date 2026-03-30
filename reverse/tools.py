# reverse/tools.py
"""
逆向工具集

提供反汇编、反编译、分析等功能
"""

import re
import os
import subprocess
import struct
import json
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from enum import Enum
from app.flag_extractor_v2 import extract_flags

# 延迟导入避免循环依赖
def _get_llm_client():
    """获取LLM客户端实例"""
    try:
        from llm_client import llm_client
        return llm_client
    except ImportError:
        return None

def _get_config():
    """获取配置"""
    try:
        from config import config
        return config
    except ImportError:
        return None


class BinaryType(Enum):
    """二进制类型"""
    ELF32 = "ELF32"
    ELF64 = "ELF64"
    PE32 = "PE32"
    PE64 = "PE64"
    MACHO = "MACHO"
    UNKNOWN = "UNKNOWN"


@dataclass
class FunctionInfo:
    """函数信息"""
    name: str
    address: int
    size: int
    instructions: List[str]
    calls: List[str]
    strings: List[str]
    is_library: bool


@dataclass
class DisassemblyResult:
    """反汇编结果"""
    address: int
    bytes: bytes
    mnemonic: str
    operands: str
    comments: str


class Disassembler:
    """
    反汇编器

    支持多种架构的反汇编
    """

    @classmethod
    def disassemble(cls, binary_path: str,
                   start_addr: int = None,
                   end_addr: int = None) -> List[DisassemblyResult]:
        """
        反汇编二进制文件

        Args:
            binary_path: 二进制文件路径
            start_addr: 起始地址
            end_addr: 结束地址

        Returns:
            反汇编结果列表
        """
        results = []

        try:
            # 使用objdump反汇编
            cmd = ['objdump', '-d', '-M', 'intel', binary_path]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

            current_addr = None
            for line in result.stdout.split('\n'):
                # 解析反汇编行
                match = re.match(r'^\s*([0-9a-fA-F]+):\s+([0-9a-fA-F ]+)\s+(\w+)\s*(.*)$', line)
                if match:
                    addr = int(match.group(1), 16)
                    bytes_hex = match.group(2).strip()
                    mnemonic = match.group(3)
                    operands = match.group(4).strip()

                    # 地址过滤
                    if start_addr and addr < start_addr:
                        continue
                    if end_addr and addr > end_addr:
                        continue

                    results.append(DisassemblyResult(
                        address=addr,
                        bytes=bytes.fromhex(bytes_hex.replace(' ', '')),
                        mnemonic=mnemonic,
                        operands=operands,
                        comments=''
                    ))

        except FileNotFoundError:
            print("[Disassembler] objdump not found, trying alternative...")
            return cls._disassemble_with_capstone(binary_path, start_addr, end_addr)
        except Exception as e:
            print(f"[Disassembler] Error: {e}")

        return results

    @classmethod
    def _disassemble_with_capstone(cls, binary_path: str,
                                   start_addr: int = None,
                                   end_addr: int = None) -> List[DisassemblyResult]:
        """使用Capstone反汇编"""
        results = []

        try:
            from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64

            # 读取二进制
            with open(binary_path, 'rb') as f:
                data = f.read()

            # 确定架构
            arch = cls._detect_arch(binary_path)
            mode = CS_MODE_64 if '64' in arch else CS_MODE_32

            md = Cs(CS_ARCH_X86, mode)

            for insn in md.disasm(data, 0x1000):
                results.append(DisassemblyResult(
                    address=insn.address,
                    bytes=insn.bytes,
                    mnemonic=insn.mnemonic,
                    operands=insn.op_str,
                    comments=''
                ))

        except ImportError:
            print("[Disassembler] Capstone not available")
        except Exception as e:
            print(f"[Disassembler] Capstone error: {e}")

        return results

    @classmethod
    def _detect_arch(cls, binary_path: str) -> str:
        """检测二进制架构"""
        try:
            result = subprocess.run(['file', binary_path],
                                    capture_output=True, text=True)
            output = result.stdout.lower()

            if 'x86-64' in output:
                return 'x64'
            elif '80386' in output:
                return 'x86'
            elif 'aarch64' in output:
                return 'arm64'
            else:
                return 'unknown'
        except Exception:
            return 'unknown'

    @classmethod
    def disassemble_function(cls, binary_path: str,
                            func_name: str) -> List[DisassemblyResult]:
        """
        反汇编指定函数

        Args:
            binary_path: 二进制文件路径
            func_name: 函数名

        Returns:
            函数的反汇编结果
        """
        # 首先获取函数地址
        func_addr = cls._get_function_address(binary_path, func_name)
        if not func_addr:
            return []

        # 反汇编该函数
        return cls.disassemble(binary_path, func_addr, func_addr + 0x1000)[:100]

    @classmethod
    def _get_function_address(cls, binary_path: str, func_name: str) -> Optional[int]:
        """获取函数地址"""
        try:
            result = subprocess.run(
                ['nm', binary_path],
                capture_output=True, text=True
            )

            for line in result.stdout.split('\n'):
                if func_name in line:
                    parts = line.split()
                    if parts:
                        return int(parts[0], 16)
        except Exception:
            pass

        return None


class Decompiler:
    """
    反编译器

    将汇编代码转换为高级语言伪代码
    """

    @classmethod
    def decompile(cls, binary_path: str,
                 func_name: str = None,
                 addr: int = None) -> str:
        """
        反编译二进制代码

        Args:
            binary_path: 二进制文件路径
            func_name: 函数名
            addr: 地址

        Returns:
            伪代码
        """
        try:
            # 尝试使用Ghidra (如果安装)
            return cls._decompile_with_ghidra(binary_path, func_name, addr)
        except Exception:
            pass

        try:
            # 尝试使用radare2
            return cls._decompile_with_r2(binary_path, func_name, addr)
        except Exception:
            pass

        # 回退到简单的模式匹配分析
        return cls._pseudo_decompile(binary_path, func_name, addr)

    @classmethod
    def _decompile_with_ghidra(cls, binary_path: str,
                               func_name: str, addr: int) -> str:
        """使用Ghidra反编译"""
        # Ghidra headless模式
        # 实际实现需要Ghidra安装
        raise NotImplementedError("Ghidra integration not implemented")

    @classmethod
    def _decompile_with_r2(cls, binary_path: str,
                          func_name: str, addr: int) -> str:
        """使用radare2反编译"""
        try:
            # 使用r2的pdc命令
            cmd = ['r2', '-q', '-c', f'pdc @ {func_name or hex(addr)}', binary_path]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            return result.stdout
        except FileNotFoundError:
            raise Exception("radare2 not found")
        except Exception as e:
            raise e

    @classmethod
    def _pseudo_decompile(cls, binary_path: str,
                         func_name: str, addr: int) -> str:
        """
        简单的伪反编译

        基于模式匹配生成伪代码
        """
        disasm = Disassembler.disassemble_function(binary_path, func_name) if func_name \
                 else Disassembler.disassemble(binary_path, addr, addr + 0x200 if addr else None)

        pseudo = []
        indent = 0

        for insn in disasm[:50]:  # 限制数量
            mnemonic = insn.mnemonic.lower()
            operands = insn.operands

            if mnemonic in ['push', 'pop']:
                continue  # 跳过栈操作

            elif mnemonic in ['mov', 'lea']:
                pseudo.append(f"{'  ' * indent}{operands.split(',')[0].strip()} = {operands.split(',')[1].strip() if ',' in operands else '0'};")

            elif mnemonic in ['add', 'sub', 'xor', 'and', 'or']:
                op_map = {'add': '+', 'sub': '-', 'xor': '^', 'and': '&', 'or': '|'}
                parts = operands.split(',')
                if len(parts) == 2:
                    pseudo.append(f"{'  ' * indent}{parts[0].strip()} {op_map[mnemonic]}= {parts[1].strip()};")

            elif mnemonic == 'call':
                pseudo.append(f"{'  ' * indent}{operands}();")

            elif mnemonic in ['jz', 'je', 'jnz', 'jne']:
                pseudo.append(f"{'  ' * indent}if (condition) goto {operands};")

            elif mnemonic in ['jmp']:
                pseudo.append(f"{'  ' * indent}goto {operands};")

            elif mnemonic == 'ret':
                pseudo.append(f"{'  ' * indent}return;")

            elif mnemonic == 'cmp':
                pseudo.append(f"{'  ' * indent}// compare: {operands}")

        return '\n'.join(pseudo)


class StringExtractor:
    """
    字符串提取器

    从二进制中提取字符串
    """

    # 常见编码标记
    ENCODING_PATTERNS = {
        'base64': r'[A-Za-z0-9+/]{20,}={0,2}',
        'hex': r'[0-9a-fA-F]{32,}',
        'url': r'(?:%[0-9a-fA-F]{2})+'
    }

    @classmethod
    def extract(cls, binary_path: str,
               min_length: int = 4) -> List[str]:
        """
        提取所有字符串

        Args:
            binary_path: 二进制文件路径
            min_length: 最小长度

        Returns:
            字符串列表
        """
        strings = []

        try:
            result = subprocess.run(
                ['strings', '-n', str(min_length), binary_path],
                capture_output=True, text=True, timeout=60
            )
            strings = [s.strip() for s in result.stdout.split('\n') if s.strip()]

        except FileNotFoundError:
            # strings命令不存在，手动提取
            strings = cls._extract_manually(binary_path, min_length)
        except Exception as e:
            print(f"[StringExtractor] Error: {e}")

        return strings

    @classmethod
    def _extract_manually(cls, binary_path: str, min_length: int) -> List[str]:
        """手动提取字符串"""
        strings = []

        try:
            with open(binary_path, 'rb') as f:
                data = f.read()

            current_string = []
            for byte in data:
                if 32 <= byte <= 126:  # 可打印ASCII
                    current_string.append(chr(byte))
                else:
                    if len(current_string) >= min_length:
                        strings.append(''.join(current_string))
                    current_string = []

            # 最后的字符串
            if len(current_string) >= min_length:
                strings.append(''.join(current_string))

        except Exception as e:
            print(f"[StringExtractor] Manual extraction error: {e}")

        return strings

    @classmethod
    def find_flag_patterns(cls, strings: List[str]) -> List[str]:
        """查找可能的flag模式"""
        # 合并所有字符串并使用统一的提取函数
        combined_text = ' '.join(strings)
        return extract_flags(combined_text)

    @classmethod
    def find_encoded_strings(cls, strings: List[str]) -> Dict[str, List[str]]:
        """查找编码的字符串"""
        encoded = {}

        for enc_type, pattern in cls.ENCODING_PATTERNS.items():
            for s in strings:
                matches = re.findall(pattern, s)
                if matches:
                    if enc_type not in encoded:
                        encoded[enc_type] = []
                    encoded[enc_type].extend(matches)

        return encoded


class FunctionAnalyzer:
    """
    函数分析器

    分析函数行为和特征
    """

    # 算法特征模式
    ALGORITHM_PATTERNS = {
        'xor_cipher': ['xor', 'xmm', 'pxor'],
        'base64': ['ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'],
        'aes': ['aes', 'sbox', 'mixcolumns', 'aesenc'],
        'des': ['des', 'feistel', 'sbox'],
        'rc4': ['rc4', 'ksa', 'prga'],
        'tea': ['tea', 'delta'],
        'md5': ['md5', 'k', 's'],
        'sha': ['sha', 'k', 'w']
    }

    @classmethod
    def analyze_function(cls, disasm: List) -> Dict:
        """
        分析函数行为

        Args:
            disasm: 反汇编结果

        Returns:
            函数分析结果
        """
        analysis = {
            'instructions_count': len(disasm),
            'has_loops': False,
            'has_syscalls': False,
            'has_crypto': False,
            'crypto_type': None,
            'calls': [],
            'interesting_operations': []
        }

        mnemonics = [d.mnemonic.lower() for d in disasm]
        operands = ' '.join([d.operands for d in disasm])

        # 检测循环
        if mnemonics.count('jmp') > 0 or mnemonics.count('loop') > 0:
            # 简单的循环检测
            jumps = [i for i, m in enumerate(mnemonics) if m in ['jmp', 'jne', 'jnz', 'je', 'jz']]
            if len(jumps) > 1:
                analysis['has_loops'] = True

        # 检测系统调用
        if 'syscall' in mnemonics or 'int 0x80' in operands:
            analysis['has_syscalls'] = True

        # 检测加密算法
        for algo, patterns in cls.ALGORITHM_PATTERNS.items():
            for pattern in patterns:
                if pattern.lower() in operands.lower():
                    analysis['has_crypto'] = True
                    analysis['crypto_type'] = algo
                    break
            if analysis['crypto_type']:
                break

        # 提取call指令
        for d in disasm:
            if d.mnemonic.lower() == 'call':
                analysis['calls'].append(d.operands)

        return analysis

    @classmethod
    def find_main_function(cls, binary_path: str) -> Optional[int]:
        """查找main函数地址"""
        # 首先尝试直接找main
        try:
            result = subprocess.run(
                ['nm', binary_path],
                capture_output=True, text=True
            )

            for line in result.stdout.split('\n'):
                if ' T main' in line or ' t main' in line:
                    return int(line.split()[0], 16)
        except Exception:
            pass

        # 在_start中找main调用
        try:
            disasm = Disassembler.disassemble_function(binary_path, '_start')
            for d in disasm[:20]:
                if d.mnemonic.lower() == 'call':
                    # 提取目标地址
                    match = re.search(r'([0-9a-fA-F]+)', d.operands)
                    if match:
                        return int(match.group(1), 16)
        except Exception:
            pass

        return None


class PatternMatcher:
    """
    模式匹配器

    识别代码模式和行为
    """

    # 常见CTF算法模式
    CTF_PATTERNS = {
        'xor_loop': {
            'pattern': ['xor', 'inc', 'cmp', 'jl/jne'],
            'description': 'XOR解密循环'
        },
        'reverse_string': {
            'pattern': ['swap', 'dec/inc', 'loop'],
            'description': '字符串反转'
        },
        'caesar_cipher': {
            'pattern': ['add/sub', 'mod', 'cmp'],
            'description': '凯撒密码'
        },
        'base64_decode': {
            'pattern': ['lookup', 'shift', 'or'],
            'description': 'Base64解码'
        },
        'flag_check': {
            'pattern': ['cmp', 'jne', 'success'],
            'description': 'Flag校验'
        }
    }

    @classmethod
    def match_patterns(cls, disasm: List) -> List[Dict]:
        """
        匹配已知模式

        Args:
            disasm: 反汇编结果

        Returns:
            匹配的模式列表
        """
        matches = []
        mnemonics = [d.mnemonic.lower() for d in disasm]

        # 简单的模式匹配
        mnemonic_str = ' '.join(mnemonics)

        for pattern_name, pattern_info in cls.CTF_PATTERNS.items():
            # 检查模式元素是否存在
            pattern_elements = pattern_info['pattern']

            # 简化检查
            if 'xor' in pattern_name and mnemonic_str.count('xor') > 5:
                matches.append({
                    'pattern': pattern_name,
                    'description': pattern_info['description'],
                    'confidence': 0.7
                })

            elif 'cmp' in pattern_name and mnemonic_str.count('cmp') > 10:
                matches.append({
                    'pattern': 'flag_check',
                    'description': '可能的Flag校验',
                    'confidence': 0.5
                })

        return matches

    @classmethod
    def find_constant_values(cls, disasm: List) -> List[Dict]:
        """查找常量值"""
        constants = []

        for d in disasm:
            # 查找mov指令中的立即数
            if d.mnemonic.lower() == 'mov':
                # 提取立即数
                match = re.search(r'0x([0-9a-fA-F]+)', d.operands)
                if match:
                    value = int(match.group(1), 16)
                    if 0x20 < value < 0x100000:  # 合理范围
                        constants.append({
                            'address': d.address,
                            'value': hex(value),
                            'instruction': f"{d.mnemonic} {d.operands}"
                        })

        return constants[:50]  # 限制数量

    @classmethod
    def identify_algorithm(cls, analysis: Dict, disasm: List = None, decompiled: str = None) -> str:
        """
        识别算法类型

        Args:
            analysis: 函数分析结果
            disasm: 反汇编结果（可选，用于AI分析）
            decompiled: 反编译代码（可选，用于AI分析）

        Returns:
            算法类型
        """
        # 首先尝试规则匹配
        rule_based_result = cls._rule_based_identify(analysis)

        # 如果规则匹配置信度较高，直接返回
        if analysis.get('crypto_type') and analysis.get('confidence', 0) > 0.8:
            return rule_based_result

        # 尝试AI动态识别
        if disasm or decompiled:
            ai_result = cls._ai_identify_algorithm(analysis, disasm, decompiled)
            if ai_result and ai_result.get('confidence', 0) > 0.6:
                return f"{ai_result.get('algorithm', 'Unknown')} (AI identified, confidence: {ai_result.get('confidence', 0):.2f})"

        return rule_based_result

    @classmethod
    def _rule_based_identify(cls, analysis: Dict) -> str:
        """基于规则的算法识别"""
        if analysis.get('crypto_type'):
            return f"Detected: {analysis['crypto_type']}"

        if analysis.get('has_loops') and analysis.get('instructions_count', 0) > 50:
            return "Possible custom algorithm"

        return "Standard code"

    @classmethod
    def _ai_identify_algorithm(cls, analysis: Dict, disasm: List = None, decompiled: str = None) -> Optional[Dict]:
        """
        使用AI动态识别算法

        根据代码结构、指令模式、数据流等特征让AI进行算法识别，
        而非依赖硬编码的模式匹配。

        Args:
            analysis: 函数分析结果
            disasm: 反汇编结果列表
            decompiled: 反编译代码字符串

        Returns:
            识别结果字典，包含algorithm、confidence、description等字段
        """
        llm_client = _get_llm_client()
        config = _get_config()

        if not llm_client or not config:
            return None

        # 构建代码上下文
        code_context = ""

        # 反编译代码（最易读）
        if decompiled:
            code_context += f"## Decompiled Code\n```\n{decompiled[:1500]}\n```\n\n"

        # 反汇编指令摘要
        if disasm:
            # 提取关键指令序列（限制数量）
            instructions = []
            for i, insn in enumerate(disasm[:100]):
                instructions.append(f"{insn.mnemonic} {insn.operands}")
            code_context += f"## Instruction Sequence (first 100)\n```\n" + "\n".join(instructions) + "\n```\n\n"

        # 函数分析特征
        code_context += f"""## Function Analysis Features
- Total Instructions: {analysis.get('instructions_count', 0)}
- Has Loops: {analysis.get('has_loops', False)}
- Has Crypto Indicators: {analysis.get('has_crypto', False)}
- Crypto Type Hint: {analysis.get('crypto_type', 'None')}
- Function Calls: {', '.join(analysis.get('calls', [])[:10]) or 'None'}
"""

        prompt = f"""
You are a reverse engineering expert analyzing binary code to identify algorithms.

{code_context}

## Task
Analyze the code structure and identify the algorithm being used. Consider:
1. Instruction patterns and their sequences
2. Data transformation operations (XOR, shifts, rotations, etc.)
3. Loop structures and iteration patterns
4. Constant values and their significance
5. Library function calls (crypto libraries, etc.)

## Common CTF Algorithms to Consider
- XOR cipher (single-byte, multi-byte, rolling key)
- Base64 encoding/decoding
- AES encryption/decryption
- DES/3DES
- RC4 stream cipher
- TEA/XTEA
- MD5/SHA hash functions
- RSA operations
- Custom substitution ciphers
- Bit manipulation puzzles
- Anti-debugging tricks

## Output Format (JSON)
{{
  "algorithm": "algorithm name or 'Unknown'",
  "confidence": 0.0-1.0,
  "description": "brief description of the algorithm behavior",
  "key_indicators": ["list of features that led to this conclusion"],
  "suggested_approach": "how to verify or exploit this algorithm",
  "potential_keys": ["any hardcoded keys or constants found"]
}}

Only output valid JSON. Be honest about confidence levels.
"""

        try:
            response = llm_client.call_chat_completion(
                model=config.ANALYST_MODEL,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.1,
                json_mode=True
            )

            # 解析JSON响应
            if "```json" in response:
                response = response.split("```json")[1].split("```")[0]

            result = json.loads(response.strip())
            return result

        except json.JSONDecodeError as e:
            print(f"[PatternMatcher] AI identification JSON parse error: {e}")
            return None
        except Exception as e:
            print(f"[PatternMatcher] AI identification error: {e}")
            return None