# crypto/tools.py
"""
Crypto工具集

提供加密识别、编码解码、密码破解等功能
"""

import re
import base64
import hashlib
import string
from typing import Dict, List, Optional, Tuple, Any
from collections import Counter
from itertools import product


class CryptoIdentifier:
    """
    加密算法识别器

    自动识别密文的加密类型
    """

    # 编码特征模式
    PATTERNS = {
        # Base64: 字母数字+/和=
        'base64': {
            'pattern': r'^[A-Za-z0-9+/]+=*$',
            'min_length': 4,
            'length_mod': 4,  # 长度是4的倍数
            'description': 'Base64编码'
        },
        # Base32: 大写字母和数字2-7，末尾可能有=
        'base32': {
            'pattern': r'^[A-Z2-7]+=*$',
            'min_length': 8,
            'description': 'Base32编码'
        },
        # Hex: 十六进制字符
        'hex': {
            'pattern': r'^[0-9a-fA-F]+$',
            'min_length': 2,
            'length_mod': 2,  # 长度是偶数
            'description': '十六进制编码'
        },
        # URL编码
        'url': {
            'pattern': r'(?:%[0-9a-fA-F]{2})+',
            'description': 'URL编码'
        },
        # Brainfuck
        'brainfuck': {
            'pattern': r'^[><+\-\[\],\.]+$',
            'description': 'Brainfuck代码'
        },
        # Morse电码
        'morse': {
            'pattern': r'^[\.\-\/\s]+$',
            'description': 'Morse电码'
        },
        # Binary
        'binary': {
            'pattern': r'^[01\s]+$',
            'description': '二进制编码'
        },
        # ROT13 (只有字母)
        'rot13': {
            'pattern': r'^[A-Za-z]+$',
            'check_func': '_check_rot13',
            'description': 'ROT13编码'
        }
    }

    # Hash特征
    HASH_PATTERNS = {
        'md5': {'length': 32, 'pattern': r'^[a-f0-9]{32}$'},
        'sha1': {'length': 40, 'pattern': r'^[a-f0-9]{40}$'},
        'sha256': {'length': 64, 'pattern': r'^[a-f0-9]{64}$'},
        'sha512': {'length': 128, 'pattern': r'^[a-f0-9]{128}$'},
        'ntlm': {'length': 32, 'pattern': r'^[a-f0-9]{32}$'},
        'mysql5': {'length': 41, 'pattern': r'^\*[A-F0-9]{40}$'},
    }

    @classmethod
    def identify(cls, ciphertext: str) -> List[Dict]:
        """
        识别密文的可能编码/加密类型

        Args:
            ciphertext: 待识别的密文

        Returns:
            可能的编码类型列表，按置信度排序
        """
        results = []
        text = ciphertext.strip()

        if not text:
            return results

        # 检查编码类型
        for enc_type, config in cls.PATTERNS.items():
            score = 0
            matched = False

            # 正则匹配
            if re.match(config['pattern'], text):
                matched = True
                score += 50

                # 长度检查
                if 'length_mod' in config:
                    if len(text) % config['length_mod'] == 0:
                        score += 20

                # 最小长度检查
                if 'min_length' in config and len(text) >= config['min_length']:
                    score += 10

            if matched:
                results.append({
                    'type': enc_type,
                    'confidence': min(score, 100),
                    'description': config['description']
                })

        # 检查Hash类型
        hash_result = cls._identify_hash(text)
        if hash_result:
            results.append(hash_result)

        # 按置信度排序
        results.sort(key=lambda x: x['confidence'], reverse=True)
        return results

    @classmethod
    def _identify_hash(cls, text: str) -> Optional[Dict]:
        """识别Hash类型"""
        text_lower = text.lower()

        for hash_type, config in cls.HASH_PATTERNS.items():
            if len(text) == config['length'] and re.match(config['pattern'], text_lower):
                return {
                    'type': f'hash_{hash_type}',
                    'confidence': 85,
                    'description': f'{hash_type.upper()}哈希'
                }
        return None

    @classmethod
    def _check_rot13(cls, text: str) -> bool:
        """检查是否可能是ROT13"""
        # ROT13特征：解码后可能有可读单词
        decoded = cls._rot13(text)
        common_words = ['the', 'and', 'is', 'flag', 'ctf', 'key', 'secret']
        return any(word in decoded.lower() for word in common_words)

    @staticmethod
    def _rot13(text: str) -> str:
        """ROT13解码"""
        result = []
        for char in text:
            if 'a' <= char <= 'z':
                result.append(chr((ord(char) - ord('a') + 13) % 26 + ord('a')))
            elif 'A' <= char <= 'Z':
                result.append(chr((ord(char) - ord('A') + 13) % 26 + ord('A')))
            else:
                result.append(char)
        return ''.join(result)


class EncodingDecoder:
    """
    编码解码器

    处理各种常见编码
    """

    @classmethod
    def decode(cls, text: str, encoding_type: str) -> Dict:
        """
        解码文本

        Args:
            text: 待解码文本
            encoding_type: 编码类型

        Returns:
            解码结果
        """
        decoders = {
            'base64': cls._decode_base64,
            'base32': cls._decode_base32,
            'hex': cls._decode_hex,
            'url': cls._decode_url,
            'binary': cls._decode_binary,
            'morse': cls._decode_morse,
            'rot13': cls._decode_rot13,
            'ascii': cls._decode_ascii,
        }

        decoder = decoders.get(encoding_type)
        if not decoder:
            return {'success': False, 'error': f'Unknown encoding: {encoding_type}'}

        try:
            result = decoder(text)
            return {'success': True, 'result': result, 'encoding': encoding_type}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    @staticmethod
    def _decode_base64(text: str) -> str:
        """Base64解码"""
        # 处理可能的padding问题
        padding = 4 - len(text) % 4
        if padding != 4:
            text += '=' * padding
        return base64.b64decode(text).decode('utf-8', errors='replace')

    @staticmethod
    def _decode_base32(text: str) -> str:
        """Base32解码"""
        padding = 8 - len(text) % 8
        if padding != 8:
            text += '=' * padding
        return base64.b32decode(text).decode('utf-8', errors='replace')

    @staticmethod
    def _decode_hex(text: str) -> str:
        """Hex解码"""
        return bytes.fromhex(text).decode('utf-8', errors='replace')

    @staticmethod
    def _decode_url(text: str) -> str:
        """URL解码"""
        from urllib.parse import unquote
        return unquote(text)

    @staticmethod
    def _decode_binary(text: str) -> str:
        """二进制解码"""
        # 移除空格
        binary = text.replace(' ', '')
        # 每8位转换为字符
        chars = [chr(int(binary[i:i+8], 2)) for i in range(0, len(binary), 8)]
        return ''.join(chars)

    @staticmethod
    def _decode_morse(text: str) -> str:
        """Morse电码解码"""
        MORSE_CODE = {
            '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E',
            '..-.': 'F', '--.': 'G', '....': 'H', '..': 'I', '.---': 'J',
            '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N', '---': 'O',
            '.--.': 'P', '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T',
            '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X', '-.--': 'Y',
            '--..': 'Z', '-----': '0', '.----': '1', '..---': '2',
            '...--': '3', '....-': '4', '.....': '5', '-....': '6',
            '--...': '7', '---..': '8', '----.': '9', '/': ' '
        }

        words = text.split(' / ')
        result = []
        for word in words:
            chars = word.split(' ')
            decoded_word = ''.join(MORSE_CODE.get(c, c) for c in chars)
            result.append(decoded_word)
        return ' '.join(result)

    @staticmethod
    def _decode_rot13(text: str) -> str:
        """ROT13解码"""
        result = []
        for char in text:
            if 'a' <= char <= 'z':
                result.append(chr((ord(char) - ord('a') + 13) % 26 + ord('a')))
            elif 'A' <= char <= 'Z':
                result.append(chr((ord(char) - ord('A') + 13) % 26 + ord('A')))
            else:
                result.append(char)
        return ''.join(result)

    @staticmethod
    def _decode_ascii(text: str) -> str:
        """ASCII码解码（支持数字形式）"""
        # 尝试识别数字分隔
        if ',' in text:
            nums = [int(n.strip()) for n in text.split(',')]
        elif ' ' in text:
            nums = [int(n.strip()) for n in text.split()]
        else:
            # 尝试按固定宽度分割
            nums = [int(text[i:i+2]) for i in range(0, len(text), 2)]

        return ''.join(chr(n) if 32 <= n <= 126 else '?' for n in nums)


class ClassicalCipherSolver:
    """
    古典密码破解器

    支持凯撒密码、栅栏密码、培根密码、Vigenere等
    """

    @classmethod
    def caesar_bruteforce(cls, ciphertext: str) -> List[Dict]:
        """
        凯撒密码暴力破解

        Returns:
            所有25种移位的结果
        """
        results = []
        for shift in range(1, 26):
            decrypted = cls._caesar_decrypt(ciphertext, shift)
            score = cls._score_text(decrypted)
            results.append({
                'shift': shift,
                'plaintext': decrypted,
                'score': score,
                'likely': score > 50
            })

        # 按分数排序
        results.sort(key=lambda x: x['score'], reverse=True)
        return results

    @staticmethod
    def _caesar_decrypt(text: str, shift: int) -> str:
        """凯撒解密"""
        result = []
        for char in text:
            if char.isalpha():
                base = ord('a') if char.islower() else ord('A')
                result.append(chr((ord(char) - base - shift) % 26 + base))
            else:
                result.append(char)
        return ''.join(result)

    @classmethod
    def _score_text(cls, text: str) -> int:
        """评估文本可读性"""
        # 常见英语单词
        common_words = ['the', 'and', 'is', 'in', 'to', 'of', 'a', 'for',
                        'flag', 'ctf', 'key', 'secret', 'password', 'admin']

        text_lower = text.lower()
        score = 0

        # 统计常见单词出现次数
        for word in common_words:
            if word in text_lower:
                score += 20

        # 字母频率分析
        freq = Counter(c.lower() for c in text if c.isalpha())
        if freq:
            # 英语常见字母: e, t, a, o, i, n
            top_letters = [c for c, _ in freq.most_common(6)]
            common_english = set('etaoin')
            overlap = len(set(top_letters) & common_english)
            score += overlap * 10

        return min(score, 100)

    @classmethod
    def rail_fence_decrypt(cls, ciphertext: str, rails: int) -> str:
        """
        栅栏密码解密

        Args:
            ciphertext: 密文
            rails: 栏数

        Returns:
            明文
        """
        if rails >= len(ciphertext) or rails < 2:
            return ciphertext

        # 创建栅栏矩阵
        matrix = [['' for _ in range(len(ciphertext))] for _ in range(rails)]

        # 标记Z字形路径
        row, direction = 0, 1
        for col in range(len(ciphertext)):
            matrix[row][col] = '*'
            row += direction
            if row == rails - 1 or row == 0:
                direction = -direction

        # 填充密文
        idx = 0
        for r in range(rails):
            for c in range(len(ciphertext)):
                if matrix[r][c] == '*' and idx < len(ciphertext):
                    matrix[r][c] = ciphertext[idx]
                    idx += 1

        # 读取明文
        result = []
        row, direction = 0, 1
        for col in range(len(ciphertext)):
            result.append(matrix[row][col])
            row += direction
            if row == rails - 1 or row == 0:
                direction = -direction

        return ''.join(result)

    @classmethod
    def vigenere_decrypt(cls, ciphertext: str, key: str) -> str:
        """
        Vigenere密码解密

        Args:
            ciphertext: 密文
            key: 密钥

        Returns:
            明文
        """
        result = []
        key_idx = 0
        key = key.upper()

        for char in ciphertext:
            if char.isalpha():
                shift = ord(key[key_idx % len(key)]) - ord('A')
                base = ord('a') if char.islower() else ord('A')
                result.append(chr((ord(char) - base - shift) % 26 + base))
                key_idx += 1
            else:
                result.append(char)

        return ''.join(result)

    @classmethod
    def xor_bruteforce(cls, ciphertext: str, key_length: int = 1) -> List[Dict]:
        """
        XOR暴力破解

        Args:
            ciphertext: 密文（hex格式）
            key_length: 密钥长度

        Returns:
            可能的解密结果
        """
        results = []

        try:
            data = bytes.fromhex(ciphertext)
        except ValueError:
            # 如果不是hex，尝试作为字符串处理
            data = ciphertext.encode()

        if key_length == 1:
            # 单字节XOR
            for key in range(256):
                decrypted = bytes(b ^ key for b in data)
                try:
                    text = decrypted.decode('utf-8')
                    if text.isprintable():
                        score = cls._score_text(text)
                        results.append({
                            'key': hex(key),
                            'key_int': key,
                            'plaintext': text,
                            'score': score
                        })
                except:
                    pass
        else:
            # 多字节XOR - 使用频率分析
            for key_bytes in product(range(256), repeat=key_length):
                key = bytes(key_bytes)
                decrypted = bytes(b ^ key[i % len(key)] for i, b in enumerate(data))
                try:
                    text = decrypted.decode('utf-8')
                    if text.isprintable():
                        score = cls._score_text(text)
                        if score > 30:  # 只保留高分结果
                            results.append({
                                'key': key.hex(),
                                'plaintext': text,
                                'score': score
                            })
                except:
                    pass

        results.sort(key=lambda x: x['score'], reverse=True)
        return results[:10]  # 返回前10个结果


class ModernCryptoSolver:
    """
    现代密码分析

    支持RSA、AES等现代加密算法的分析
    """

    @classmethod
    def analyze_rsa(cls, n: int = None, e: int = None, c: int = None,
                    p: int = None, q: int = None, **kwargs) -> Dict:
        """
        RSA分析

        支持场景:
        1. 已知p, q, e, c 求m
        2. 小指数攻击 (e=3)
        3. 共模攻击
        4. Wiener攻击 (小d)
        """
        results = {
            'vulnerabilities': [],
            'solutions': []
        }

        # 检查小指数攻击
        if e and e == 3:
            results['vulnerabilities'].append({
                'type': 'small_exponent',
                'description': 'e=3 可能存在小指数攻击',
                'severity': 'high'
            })

        # 检查n是否可分解
        if n:
            # 尝试Fermat分解（对于接近的p和q）
            if p and q:
                results['solutions'].append({
                    'method': 'known_factors',
                    'description': '已知因子，可直接计算私钥'
                })
            else:
                # 检查n是否过小
                if n.bit_length() < 512:
                    results['vulnerabilities'].append({
                        'type': 'weak_n',
                        'description': f'N位数过小({n.bit_length()}bit)，可被分解',
                        'severity': 'critical'
                    })

        # 检查Wiener条件
        if e and n:
            if e > 0 and n > 0:
                from math import isqrt
                # 简化检查：如果e很大，可能存在小d
                if e > n ** 0.25:
                    results['vulnerabilities'].append({
                        'type': 'potential_wiener',
                        'description': 'e较大，可能存在Wiener攻击漏洞',
                        'severity': 'medium'
                    })

        return results

    @classmethod
    def rsa_decrypt(cls, c: int, d: int, n: int) -> int:
        """
        RSA解密

        Args:
            c: 密文
            d: 私钥指数
            n: 模数

        Returns:
            明文（整数）
        """
        return pow(c, d, n)

    @classmethod
    def int_to_bytes(cls, n: int) -> bytes:
        """整数转字节"""
        byte_length = (n.bit_length() + 7) // 8
        return n.to_bytes(byte_length, 'big')


class HashAnalyzer:
    """
    Hash分析器

    识别和破解哈希值
    """

    # 扩展的常见CTF密码字典（100+常见密码）
    COMMON_PASSWORDS = [
        # 基础弱密码
        'password', '123456', 'admin', 'root', 'test', 'guest',
        'flag', 'ctf', 'secret', 'key', 'pass', 'qwerty',
        'letmein', 'welcome', 'monkey', 'dragon', 'master',
        # CTF常见密码
        'flag{', 'ctf2024', 'ctf2023', 'ctf2025', 'hacker', 'pwn', 'web', 'crypto',
        'misc', 'reverse', 'forensic', 'stego', 'pwnable', 'exploit', 'shell',
        'overflow', 'buffer', 'injection', 'xss', 'sqli', 'rce', 'lfi', 'rfi',
        # 数字密码
        '12345678', '123456789', '1234567890', '111111', '000000', '666666',
        '88888888', '123123', '12341234', '12345', '1234567', '111',
        # 常见单词密码
        'hello', 'world', 'love', 'god', 'sex', 'money', 'angel', 'devil',
        'shadow', 'sunshine', 'princess', 'football', 'baseball', 'soccer',
        # 安全相关词汇
        'security', 'secure', 'access', 'login', 'user', 'passwd', 'authenticate',
        'encrypted', 'decrypt', 'cipher', 'hash', 'md5', 'sha1', 'sha256',
        # Linux/系统相关
        'linux', 'ubuntu', 'centos', 'debian', 'redhat', 'unix', 'bash', 'shell',
        'nobody', 'apache', 'nginx', 'mysql', 'postgres', 'redis', 'mongodb',
        # 默认密码
        'default', 'changeme', 'administrator', 'sysadmin', 'operator',
        'manager', 'supervisor', 'support', 'service', 'backup', 'oracle',
        # 动物和常见词
        'abc123', 'qazwsx', 'asdfgh', 'zxcvbn', 'password1', 'password123',
        'admin123', 'root123', 'test123', 'guest123', 'user123', 'login123',
        # 技术相关
        'python', 'java', 'javascript', 'php', 'ruby', 'golang', 'rust',
        'docker', 'kubernetes', 'aws', 'azure', 'cloud', 'server', 'network',
        # CTF平台常见词
        'ctftime', 'ctfhub', 'bugku', 'buuctf', 'hwb', 'actf', 'suctf', 'qwb',
        'xctf', 'hgame', 'nss', 'ciscn', 'awd', 'awdp', 'joy', 'easy', 'hard',
        # 题目提示词
        'baby', 'easy', 'simple', 'basic', 'classic', 'crypto', 'modern',
        'ancient', 'caesar', 'vigenere', 'rsa', 'aes', 'des', 'xor', 'rot13',
        # 节日日期
        'spring', 'summer', 'autumn', 'winter', 'christmas', 'halloween',
        'newyear', 'holiday', '2024', '2025', '2026',
        # 其他常见弱密码
        'qwertyuiop', 'asdfghjkl', 'zxcvbnm', '1qaz2wsx', 'qazwsxedc',
        'password!', 'admin!', 'p@ssw0rd', 'p@ssword', 'pa$$word',
    ]

    @classmethod
    def _ai_generate_passwords(cls, context: Dict = None, challenge_title: str = None,
                               challenge_description: str = None) -> List[str]:
        """
        根据题目上下文动态生成针对性密码

        Args:
            context: 题目上下文信息字典
            challenge_title: 题目标题
            challenge_description: 题目描述

        Returns:
            生成的针对性密码列表
        """
        generated = []

        # 合并上下文信息
        text = ''
        if context:
            text += str(context.get('title', '')) + ' '
            text += str(context.get('description', '')) + ' '
            text += str(context.get('hint', '')) + ' '
        if challenge_title:
            text += challenge_title + ' '
        if challenge_description:
            text += challenge_description + ' '

        text = text.lower()

        # 根据关键词生成针对性密码
        keyword_patterns = {
            # RSA相关
            'rsa': ['rsa', 'n', 'e', 'd', 'p', 'q', 'phi', 'modular', 'exponent',
                    'wiener', 'fermat', 'common_modulus', 'small_e', 'small_d',
                    'rsa2024', 'rsa2025', 'rsa_key', 'private_key', 'public_key'],
            # 凯撒密码相关
            'caesar': ['caesar', 'shift', 'rotate', 'rot', 'julius', 'caesar_cipher',
                       'rot13', 'rot47', 'shift13', 'shift5', 'shift3'],
            # XOR相关
            'xor': ['xor', 'exclusive', 'xor_key', 'xorcipher', 'xor_decrypt',
                    'xork', 'xorcrack', 'repeated_xor', 'single_byte_xor'],
            # Base编码相关
            'base': ['base64', 'base32', 'base16', 'base58', 'base85', 'b64', 'b32'],
            # 古典密码
            'classical': ['vigenere', 'rail_fence', 'railfence', 'fence', 'bacon',
                         'polybius', 'playfair', 'affine', 'atbash', 'substitution'],
            # 现代加密
            'modern': ['aes', 'des', '3des', 'rc4', 'blowfish', 'twofish',
                      'serpent', 'chacha20', 'salsa20'],
            # 哈希相关
            'hash': ['md5', 'sha1', 'sha256', 'sha512', 'md4', 'ntlm',
                    'bcrypt', 'scrypt', 'pbkdf2', 'hmac'],
            # 编码相关
            'encoding': ['hex', 'binary', 'octal', 'ascii', 'unicode', 'utf',
                        'morse', 'brainfuck', 'ook', 'aaencode'],
            # Web安全
            'web': ['sql', 'xss', 'csrf', 'ssrf', 'rce', 'lfi', 'rfi', 'sqli',
                   'xss_attack', 'webshell', 'backdoor', 'eval', 'system'],
            # 逆向相关
            'reverse': ['elf', 'pe', 'exe', 'binary', 'assembly', 'gdb', 'ida',
                       'ghidra', 'debug', 'breakpoint', 'register'],
            # PWN相关
            'pwn': ['shell', 'overflow', 'buffer', 'stack', 'heap', 'rop', 'ret',
                   'libc', 'gadget', 'canary', 'nx', 'aslr', 'pie'],
            # 隐写相关
            'stego': ['steghide', 'stegsolve', 'lsb', 'png', 'jpg', 'gif',
                     'exif', 'metadata', 'binwalk', 'foremost', 'wav'],
            # 取证相关
            'forensic': ['wireshark', 'pcap', 'network', 'traffic', 'packet',
                        'memory', 'disk', 'volatility', 'registry', 'timeline'],
            # 中文相关
            'chinese': ['flag', 'miyao', 'mima', 'key', 'secret', 'password',
                       'mima123', 'key123', 'admin', 'root', 'test'],
            # 数学相关
            'math': ['prime', 'factor', 'mod', 'gcd', 'lcm', 'euler', 'phi',
                    'carmichael', 'fermat', 'pollard', 'rho'],
        }

        # 根据匹配的关键词生成密码
        for category, passwords in keyword_patterns.items():
            if category in text:
                generated.extend(passwords)

        # 从题目中提取可能的密码关键词
        import re
        # 提取引号内的内容作为可能的密码
        quoted = re.findall(r'["\']([^"\']{3,20})["\']', text)
        generated.extend(quoted)

        # 提取可能的密码提示词
        hints = re.findall(r'(?:password|pwd|pass|key|flag)[:\s=]+(\S+)', text, re.IGNORECASE)
        generated.extend(hints)

        # 提取题目名称可能的变体
        if challenge_title:
            title_lower = challenge_title.lower().replace(' ', '_')
            generated.append(title_lower)
            generated.append(title_lower.replace('_', ''))
            generated.append(title_lower + '_flag')
            generated.append(title_lower + '_key')
            generated.append(title_lower + '_password')
            # 提取题目名称中的关键单词
            title_words = re.findall(r'[a-zA-Z]{3,}', challenge_title)
            generated.extend([w.lower() for w in title_words])

        # 根据数字生成变体
        numbers = re.findall(r'\d{4}', text)  # 年份
        for num in numbers:
            generated.extend([
                'password' + num,
                'admin' + num,
                'key' + num,
                'flag' + num,
                'ctf' + num,
            ])

        # 去重并保持顺序
        seen = set()
        unique_generated = []
        for pwd in generated:
            if pwd and pwd not in seen and len(pwd) >= 1:
                seen.add(pwd)
                unique_generated.append(pwd)

        return unique_generated

    @classmethod
    def identify_hash(cls, hash_value: str) -> Dict:
        """
        识别Hash类型

        Returns:
            可能的Hash类型信息
        """
        hash_lower = hash_value.lower().strip()
        length = len(hash_lower)

        hash_types = {
            32: ['md5', 'ntlm', 'md4'],
            40: ['sha1', 'mysql5_password'],
            64: ['sha256'],
            96: ['sha384'],
            128: ['sha512']
        }

        possible_types = hash_types.get(length, [])

        # 特殊格式检查
        if hash_value.startswith('$1$'):
            return {'type': 'md5_crypt', 'format': 'Unix MD5'}
        elif hash_value.startswith('$5$'):
            return {'type': 'sha256_crypt', 'format': 'Unix SHA256'}
        elif hash_value.startswith('$6$'):
            return {'type': 'sha512_crypt', 'format': 'Unix SHA512'}
        elif hash_value.startswith('$2y$') or hash_value.startswith('$2a$'):
            return {'type': 'bcrypt', 'format': 'bcrypt'}
        elif hash_value.startswith('*') and length == 41:
            return {'type': 'mysql5', 'format': 'MySQL5+ password'}

        return {
            'type': possible_types[0] if possible_types else 'unknown',
            'possible_types': possible_types,
            'length': length
        }

    @classmethod
    def crack_hash(cls, hash_value: str, hash_type: str = None,
                   wordlist: List[str] = None, context: Dict = None,
                   challenge_title: str = None, challenge_description: str = None,
                   use_ai_passwords: bool = True) -> Dict:
        """
        尝试破解Hash

        Args:
            hash_value: 哈希值
            hash_type: 哈希类型（可选）
            wordlist: 密码字典（可选）
            context: 题目上下文信息字典（用于AI生成针对性密码）
            challenge_title: 题目标题（用于AI生成针对性密码）
            challenge_description: 题目描述（用于AI生成针对性密码）
            use_ai_passwords: 是否使用AI生成的针对性密码（默认True）

        Returns:
            破解结果
        """
        if not hash_type:
            hash_type = cls.identify_hash(hash_value)['type']

        hash_funcs = {
            'md5': hashlib.md5,
            'sha1': hashlib.sha1,
            'sha256': hashlib.sha256,
            'sha512': hashlib.sha512
        }

        hash_func = hash_funcs.get(hash_type.lower())
        if not hash_func:
            return {'success': False, 'error': f'Unsupported hash type: {hash_type}'}

        hash_lower = hash_value.lower()

        # 构建密码尝试列表，优先级：用户字典 > AI生成 > 默认字典
        passwords_to_try = []

        if wordlist:
            # 用户提供的字典优先级最高
            passwords_to_try.extend(wordlist)

        if use_ai_passwords and (context or challenge_title or challenge_description):
            # AI生成的针对性密码优先于默认字典
            ai_passwords = cls._ai_generate_passwords(
                context=context,
                challenge_title=challenge_title,
                challenge_description=challenge_description
            )
            passwords_to_try.extend(ai_passwords)

        # 添加默认字典（去重）
        seen = set(passwords_to_try)
        for pwd in cls.COMMON_PASSWORDS:
            if pwd not in seen:
                passwords_to_try.append(pwd)
                seen.add(pwd)

        # 尝试破解
        for password in passwords_to_try:
            computed = hash_func(password.encode()).hexdigest()
            if computed == hash_lower:
                return {
                    'success': True,
                    'plaintext': password,
                    'hash_type': hash_type
                }

        return {
            'success': False,
            'error': 'Hash not cracked with provided wordlist'
        }

    @classmethod
    def generate_rainbow_table(cls, hash_type: str,
                               passwords: List[str] = None) -> Dict[str, str]:
        """
        生成彩虹表

        Args:
            hash_type: 哈希类型
            passwords: 密码列表

        Returns:
            密码->哈希 的映射表
        """
        hash_funcs = {
            'md5': hashlib.md5,
            'sha1': hashlib.sha1,
            'sha256': hashlib.sha256
        }

        hash_func = hash_funcs.get(hash_type.lower())
        if not hash_func:
            return {}

        passwords = passwords or cls.COMMON_PASSWORDS

        return {
            pwd: hash_func(pwd.encode()).hexdigest()
            for pwd in passwords
        }