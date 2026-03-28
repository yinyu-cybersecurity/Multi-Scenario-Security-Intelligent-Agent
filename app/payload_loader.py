# app/payload_loader.py
"""
Payload 加载器 - 从本地资源库加载 Payload

资源库位置从配置读取，默认:
- PayloadsAllTheThings - 各类漏洞 Payload
- SecLists - 字典、密码、Shell等
"""

import os
import json
import random
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from logger import get_logger

logger = get_logger("PayloadLoader")


def _get_resource_paths() -> Tuple[str, str]:
    """获取资源库路径（从配置或环境变量）"""
    # 尝试从配置读取
    try:
        from config import config
        payloads_path = getattr(config, 'PAYLOADS_PATH', '/app/data/security_resources/PayloadsAllTheThings-4.2')
        seclists_path = getattr(config, 'SECLISTS_PATH', '/app/data/security_resources/SecLists-master')
        return payloads_path, seclists_path
    except ImportError:
        pass

    # 环境变量
    payloads_path = os.environ.get('PAYLOADS_PATH', '/app/data/security_resources/PayloadsAllTheThings-4.2')
    seclists_path = os.environ.get('SECLISTS_PATH', '/app/data/security_resources/SecLists-master')

    return payloads_path, seclists_path


@dataclass
class PayloadSource:
    """Payload 来源"""
    name: str
    path: str
    category: str
    description: str


class PayloadLoader:
    """Payload 加载器"""

    # 漏洞类型到 Payload 目录的映射
    VULN_TO_DIR = {
        "sql_injection": "SQL Injection",
        "sqli": "SQL Injection",
        "sql": "SQL Injection",
        "xss": "XSS Injection",
        "ssti": "Server Side Template Injection",
        "template_injection": "Server Side Template Injection",
        "xxe": "XXE Injection",
        "ssrf": "Server-Side Request Forgery",
        "lfi": "Directory Traversal",
        "path_traversal": "Directory Traversal",
        "rce": "Remote Code Execution",
        "command_injection": "Command Injection",
        "deserialization": "Deserialization",
        "csrf": "CSRF Injection",
        "jwt": "JWT",
        "file_upload": "File Upload",
    }

    # SecLists 字典路径映射
    WORDLIST_MAP = {
        "web_common": "Discovery/Web-Content/common.txt",
        "web_medium": "Discovery/Web-Content/directory-list-2.3-medium.txt",
        "passwords": "Passwords/Common-Credentials/top-passwords-100.txt",
        "usernames": "Usernames/Names/names.txt",
        "sql_bypass": "Fuzzing/SQLi/Generic-SQLi.txt",
        "xss_bypass": "Fuzzing/XSS/XSS-Bypass-List.txt",
        "lfi_linux": "Fuzzing/LFI/LFI-Jhaddix.txt",
        "traversal": "Fuzzing/Traversal/Traversal.txt",
    }

    def __init__(self, payloads_path: str = None, seclists_path: str = None):
        """初始化，支持自定义路径"""
        if payloads_path and seclists_path:
            self.PAYLOADS_PATH = payloads_path
            self.SECLISTS_PATH = seclists_path
        else:
            self.PAYLOADS_PATH, self.SECLISTS_PATH = _get_resource_paths()

        self._cache: Dict[str, List[str]] = {}

    def is_available(self) -> bool:
        """检查资源库是否可用"""
        return os.path.exists(self.PAYLOADS_PATH) or os.path.exists(self.SECLISTS_PATH)

    def load_payloads(self, vuln_type: str, limit: int = 50) -> List[str]:
        """
        加载指定漏洞类型的 Payload

        Args:
            vuln_type: 漏洞类型 (sql_injection, xss, ssti, etc.)
            limit: 最大返回数量

        Returns:
            Payload 列表
        """
        cache_key = f"payloads_{vuln_type}"
        if cache_key in self._cache:
            return self._cache[cache_key][:limit]

        payloads = []
        vuln_type_lower = vuln_type.lower().replace("-", "_").replace(" ", "_")

        # 查找对应目录
        dir_name = self.VULN_TO_DIR.get(vuln_type_lower)
        if not dir_name:
            # 尝试模糊匹配
            for key, val in self.VULN_TO_DIR.items():
                if key in vuln_type_lower or vuln_type_lower in key:
                    dir_name = val
                    break

        if dir_name:
            payload_dir = os.path.join(self.PAYLOADS_PATH, dir_name)
            payloads = self._load_from_directory(payload_dir)

        self._cache[cache_key] = payloads
        return payloads[:limit]

    def load_wordlist(self, wordlist_type: str) -> List[str]:
        """
        加载 SecLists 字典

        Args:
            wordlist_type: 字典类型 (web_common, passwords, etc.)

        Returns:
            字典内容列表
        """
        cache_key = f"wordlist_{wordlist_type}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        wordlist_path = self.WORDLIST_MAP.get(wordlist_type)
        if not wordlist_path:
            return []

        full_path = os.path.join(self.SECLISTS_PATH, wordlist_path)
        words = []

        try:
            if os.path.exists(full_path):
                with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                    words = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except Exception as e:
            logger.warning(f"加载字典失败 {wordlist_type}: {e}")

        self._cache[cache_key] = words
        return words

    def get_sqli_payloads(self) -> List[str]:
        """获取 SQL 注入 Payload"""
        return self.load_payloads("sql_injection")

    def get_xss_payloads(self) -> List[str]:
        """获取 XSS Payload"""
        return self.load_payloads("xss")

    def get_ssti_payloads(self) -> List[str]:
        """获取 SSTI Payload"""
        return self.load_payloads("ssti")

    def get_lfi_payloads(self) -> List[str]:
        """获取 LFI Payload"""
        # 优先从 SecLists 加载
        lfi_list = self.load_wordlist("lfi_linux")
        if lfi_list:
            return lfi_list
        return self.load_payloads("lfi")

    def get_traversal_payloads(self) -> List[str]:
        """获取路径穿越 Payload"""
        traversal = self.load_wordlist("traversal")
        if traversal:
            return traversal
        return self.load_payloads("path_traversal")

    def get_common_passwords(self, limit: int = 20) -> List[str]:
        """获取常见密码列表"""
        return self.load_wordlist("passwords")[:limit]

    def get_common_usernames(self, limit: int = 20) -> List[str]:
        """获取常见用户名列表"""
        return self.load_wordlist("usernames")[:limit]

    def get_web_wordlist(self, wordlist_type: str = "web_common") -> List[str]:
        """获取 Web 目录字典"""
        return self.load_wordlist(wordlist_type)

    def get_random_payload(self, vuln_type: str) -> Optional[str]:
        """获取随机 Payload"""
        payloads = self.load_payloads(vuln_type)
        if payloads:
            return random.choice(payloads)
        return None

    def search_payloads(self, keyword: str, limit: int = 20) -> List[Tuple[str, str]]:
        """
        搜索 Payload

        Args:
            keyword: 搜索关键词

        Returns:
            [(文件名, 匹配内容)]
        """
        results = []

        if not os.path.exists(self.PAYLOADS_PATH):
            return results

        keyword_lower = keyword.lower()

        for root, dirs, files in os.walk(self.PAYLOADS_PATH):
            # 跳过隐藏目录
            dirs[:] = [d for d in dirs if not d.startswith('.')]

            for file in files:
                if file.endswith(('.md', '.txt', '.py')):
                    filepath = os.path.join(root, file)
                    try:
                        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            if keyword_lower in content.lower():
                                # 提取匹配行
                                lines = content.split('\n')
                                for line in lines:
                                    if keyword_lower in line.lower():
                                        results.append((file, line.strip()[:200]))
                                        if len(results) >= limit:
                                            return results
                    except Exception:
                        pass

        return results

    def _load_from_directory(self, directory: str) -> List[str]:
        """从目录加载 Payload"""
        payloads = []

        if not os.path.exists(directory):
            return payloads

        for root, dirs, files in os.walk(directory):
            for file in files:
                if file.endswith(('.md', '.txt')):
                    filepath = os.path.join(root, file)
                    try:
                        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            # 提取代码块中的 payload
                            import re
                            # 匹配代码块
                            code_blocks = re.findall(r'```(?:\w*)\n([\s\S]*?)```', content)
                            for block in code_blocks:
                                for line in block.strip().split('\n'):
                                    line = line.strip()
                                    if line and len(line) > 3 and len(line) < 500:
                                        # 过滤掉纯注释
                                        if not line.startswith(('#', '//', '/*', '*')):
                                            payloads.append(line)

                            # 也提取单独的行（非代码块中的 payload）
                            for line in content.split('\n'):
                                line = line.strip()
                                # 检测可能的 payload 特征
                                if any(marker in line for marker in ["'", '"', '<', '>', '{{', '${', '#{', '<!', '--', ';', '|']):
                                    if len(line) > 3 and len(line) < 500 and line not in payloads:
                                        payloads.append(line)

                    except Exception as e:
                        logger.warning(f"读取文件失败 {filepath}: {e}")

        # 去重
        return list(dict.fromkeys(payloads))

    def get_resource_info(self) -> Dict:
        """获取资源库信息"""
        info = {
            "payloads_available": os.path.exists(self.PAYLOADS_PATH),
            "seclists_available": os.path.exists(self.SECLISTS_PATH),
            "payload_categories": [],
            "wordlist_types": list(self.WORDLIST_MAP.keys()),
        }

        if os.path.exists(self.PAYLOADS_PATH):
            try:
                info["payload_categories"] = os.listdir(self.PAYLOADS_PATH)
            except Exception:
                pass

        return info


# 全局实例
payload_loader = PayloadLoader()


def get_payload_loader() -> PayloadLoader:
    """获取全局 Payload 加载器实例"""
    return payload_loader


# 便捷函数
def load_sqli_payloads(limit: int = 30) -> List[str]:
    """加载 SQL 注入 Payload"""
    return payload_loader.get_sqli_payloads()[:limit]


def load_xss_payloads(limit: int = 30) -> List[str]:
    """加载 XSS Payload"""
    return payload_loader.get_xss_payloads()[:limit]


def load_ssti_payloads(limit: int = 30) -> List[str]:
    """加载 SSTI Payload"""
    return payload_loader.get_ssti_payloads()[:limit]


def load_wordlist(wordlist_type: str) -> List[str]:
    """加载字典"""
    return payload_loader.load_wordlist(wordlist_type)