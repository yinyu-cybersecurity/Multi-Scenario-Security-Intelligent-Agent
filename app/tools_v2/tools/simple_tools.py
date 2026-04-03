"""
CTF安全工具定义 - 简化版

设计原则：
1. 工具路径由tool_paths.py管理
2. 工具执行由native_executor处理
3. 工具用法由skill文档说明
4. 此文件仅保留工具Schema定义和安全验证函数

AI通过skill文档了解工具用法，直接调用Bash工具执行
"""

import re
import ipaddress
from urllib.parse import urlparse
from typing import Dict, Tuple


# ============================================
# 安全验证函数
# ============================================

def validate_target(target: str) -> Tuple[bool, str]:
    """
    验证目标地址格式

    Args:
        target: 目标地址（IP、域名或URL）

    Returns:
        (is_valid, error_message)
    """
    if not target or not isinstance(target, str):
        return False, "目标地址不能为空"

    # 基本长度限制
    if len(target) > 253:
        return False, "目标地址过长"

    # URL格式验证（http/https）
    if target.startswith(('http://', 'https://')):
        try:
            parsed = urlparse(target)
            if parsed.hostname:
                return True, ""
            return False, "URL格式无效"
        except Exception:
            return False, "URL解析失败"

    # IP地址验证
    try:
        ipaddress.ip_address(target)
        return True, ""
    except ValueError:
        pass

    # CIDR验证
    try:
        ipaddress.ip_network(target, strict=False)
        return True, ""
    except ValueError:
        pass

    # 域名验证（简单正则）
    domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
    if re.match(domain_pattern, target):
        return True, ""

    return False, f"无效的目标地址格式: {target}"


def validate_url_for_ssrf(url: str, allow_private: bool = False) -> Tuple[bool, str]:
    """
    验证URL防止SSRF攻击

    Args:
        url: 待验证的URL
        allow_private: 是否允许私有IP（内网扫描场景）

    Returns:
        (is_valid, error_message)
    """
    try:
        parsed = urlparse(url)

        # 检查协议
        if parsed.scheme not in ['http', 'https']:
            return False, f"不支持的协议: {parsed.scheme}"

        # 获取主机名
        hostname = parsed.hostname
        if not hostname:
            return False, "无效的URL：缺少主机名"

        # 解析IP
        try:
            ip = ipaddress.ip_address(hostname)

            # 检查是否为私有IP
            if not allow_private and ip.is_private:
                return False, f"SSRF防护：禁止访问私有IP {hostname}。如需内网扫描，请使用allow_private=True"

            # 检查回环地址
            if ip.is_loopback and not allow_private:
                return False, f"SSRF防护：禁止访问回环地址"

            # 检查链路本地地址
            if ip.is_link_local and not allow_private:
                return False, f"SSRF防护：禁止访问链路本地地址"

        except ValueError:
            # 不是IP地址，可能是域名
            pass

        return True, ""
    except Exception as e:
        return False, f"URL验证错误: {str(e)}"


def validate_ports(ports: str) -> Tuple[bool, str]:
    """
    验证端口范围格式

    Args:
        ports: 端口范围字符串

    Returns:
        (is_valid, error_message)
    """
    if not ports:
        return True, ""  # 允许空，使用默认值

    # 单个端口
    if ports.isdigit():
        port = int(ports)
        if 1 <= port <= 65535:
            return True, ""
        return False, f"端口号超出范围: {port}"

    # 端口范围 (如 1-1000)
    if '-' in ports:
        parts = ports.split('-')
        if len(parts) == 2:
            try:
                start, end = int(parts[0]), int(parts[1])
                if 1 <= start <= end <= 65535:
                    return True, ""
                return False, f"端口范围无效: {ports}"
            except ValueError:
                return False, f"端口范围格式错误: {ports}"

    # 端口列表 (如 80,443,8080)
    if ',' in ports:
        try:
            for p in ports.split(','):
                port = int(p.strip())
                if not 1 <= port <= 65535:
                    return False, f"端口号超出范围: {port}"
            return True, ""
        except ValueError:
            return False, f"端口列表格式错误: {ports}"

    return False, f"无法识别的端口格式: {ports}"


# ============================================
# 工具Schema定义 - 仅元数据，无handler
# ============================================

TOOL_SCHEMAS = {
    # P0级核心工具
    "nuclei": {
        "name": "nuclei",
        "description": "漏洞扫描工具，使用模板检测CVE",
        "category": "web",
        "examples": ["nuclei -u http://target.com -severity critical,high"]
    },
    "httpx": {
        "name": "httpx",
        "description": "HTTP探测工具，快速发现Web服务",
        "category": "web",
        "examples": ["httpx -u target.com -silent -json"]
    },
    "fscan": {
        "name": "fscan",
        "description": "内网综合扫描工具",
        "category": "intranet",
        "examples": ["fscan -h 192.168.1.0/24"]
    },
    "sqlmap": {
        "name": "sqlmap",
        "description": "SQL注入自动化利用工具",
        "category": "web",
        "examples": ["sqlmap -u 'http://target.com?id=1' --dbs --batch"]
    },
    "ffuf": {
        "name": "ffuf",
        "description": "快速Web模糊测试工具",
        "category": "web",
        "examples": ["ffuf -u http://target.com/FUZZ -w wordlist.txt"]
    },
    "gobuster": {
        "name": "gobuster",
        "description": "多协议爆破工具",
        "category": "web",
        "examples": ["gobuster dir -u http://target.com -w wordlist.txt"]
    },
    "subfinder": {
        "name": "subfinder",
        "description": "子域名发现工具",
        "category": "recon",
        "examples": ["subfinder -d target.com -silent"]
    },
    "xray": {
        "name": "xray",
        "description": "被动/主动扫描工具",
        "category": "web",
        "examples": ["xray webscan --basic-crawler http://target.com"]
    },

    # P1级工具
    "crackmapexec": {
        "name": "crackmapexec",
        "description": "内网渗透工具",
        "category": "intranet",
        "examples": ["crackmapexec smb 192.168.1.0/24 -u admin -p password"]
    },
    "impacket": {
        "name": "impacket",
        "description": "网络协议工具包",
        "category": "intranet",
        "examples": ["impacket-psexec domain/user:pass@target"]
    },
    "bloodhound": {
        "name": "bloodhound",
        "description": "AD攻击路径分析工具",
        "category": "intranet",
        "examples": ["bloodhound-python -d domain.local -u user -p pass"]
    },

    # Java反序列化
    "ysoserial": {
        "name": "ysoserial",
        "description": "Java反序列化payload生成",
        "category": "deserialization",
        "examples": ["ysoserial CommonsCollections1 'touch /tmp/pwned'"]
    },
    "marshalsec": {
        "name": "marshalsec",
        "description": "Java反序列化利用",
        "category": "deserialization",
        "examples": ["java -cp marshalsec.jar marshalsec.JRMPListener 9999 CommonsCollections1"]
    },
    "jndiexploit": {
        "name": "jndiexploit",
        "description": "JNDI注入利用工具",
        "category": "deserialization",
        "examples": ["java -jar JNDIExploit.jar -i 192.168.1.100"]
    },

    # 专项工具
    "jwt_tool": {
        "name": "jwt_tool",
        "description": "JWT漏洞利用工具",
        "category": "web",
        "examples": ["python jwt_tool.py <token> -d"]
    },
    "githacker": {
        "name": "githacker",
        "description": "Git泄露利用工具",
        "category": "web",
        "examples": ["python GitHack.py --url http://target.com/.git/"]
    },
    "gopherus": {
        "name": "gopherus",
        "description": "Gopher协议利用工具",
        "category": "web",
        "examples": ["python gopherus.py --exploit mysql"]
    },
    "phpggc": {
        "name": "phpggc",
        "description": "PHP反序列化payload生成",
        "category": "deserialization",
        "examples": ["./phpggc Laravel/RCE1 whoami"]
    },

    # AD工具
    "certipy": {
        "name": "certipy",
        "description": "AD CS攻击工具",
        "category": "intranet",
        "examples": ["certipy find -u user@domain.local -p password"]
    },
    "mimikatz": {
        "name": "mimikatz",
        "description": "Windows凭据提取工具",
        "category": "intranet",
        "examples": ["mimikatz.exe sekurlsa::logonpasswords"]
    },
    "rubeus": {
        "name": "rubeus",
        "description": "Kerberos攻击工具",
        "category": "intranet",
        "examples": ["Rubeus.exe asktgt /user:admin /password:pass"]
    },

    # 内网穿透
    "frp": {
        "name": "frp",
        "description": "内网穿透工具",
        "category": "tunnel",
        "examples": ["frpc -c frpc.ini"]
    },
}


# ============================================
# 工具注册表 - 无handler版本
# ============================================

HANDLERS = {}  # 空字典，所有工具通过Bash直接调用


def get_tool_schema(name: str) -> dict:
    """获取工具Schema - 返回OpenAI Function Calling格式"""
    tool = TOOL_SCHEMAS.get(name)
    if not tool:
        return None

    # 转换为OpenAI function calling格式
    return {
        "name": tool.get("name", name),
        "description": tool.get("description", ""),
        "parameters": {
            "type": "object",
            "properties": {
                "args": {
                    "type": "string",
                    "description": f"工具命令参数，示例: {', '.join(tool.get('examples', []))}"
                }
            },
            "required": []
        }
    }


def list_tools() -> list:
    """列出所有工具"""
    return list(TOOL_SCHEMAS.keys())


def get_all_schemas() -> list:
    """获取所有工具Schema - 返回OpenAI Function Calling格式"""
    schemas = []
    for name in TOOL_SCHEMAS.keys():
        schema = get_tool_schema(name)
        if schema:
            schemas.append(schema)
    return schemas


# 导入专业方向工具Schema（如果有）
try:
    from .specialized_schemas import ALL_SPECIALIZED_SCHEMAS
    TOOL_SCHEMAS.update(ALL_SPECIALIZED_SCHEMAS)
except ImportError:
    pass


__all__ = [
    "validate_target",
    "validate_url_for_ssrf",
    "validate_ports",
    "TOOL_SCHEMAS",
    "HANDLERS",
    "get_tool_schema",
    "list_tools",
    "get_all_schemas",
]