#!/usr/bin/env python
"""
Tool Selector - 智能工具选择器
根据漏洞类型、上下文、历史记录智能选择最优工具组合
"""

from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
from logger import get_logger

logger = get_logger("ToolSelector")


class VulnCategory(Enum):
    """漏洞类型分类"""
    SQL_INJECTION = "sql_injection"
    SSTI = "ssti"
    XSS = "xss"
    XXE = "xxe"
    SSRF = "ssrf"
    LFI = "lfi"
    RFI = "rfi"
    FILE_UPLOAD = "file_upload"
    DESERIALIZATION = "deserialization"
    RCE = "rce"
    AUTH_BYPASS = "auth_bypass"
    JWT = "jwt"
    CSRF = "csrf"
    UNKNOWN = "unknown"


@dataclass
class ToolRecommendation:
    """工具推荐"""
    tool_name: str
    priority: int  # 1-10, 10最高
    reason: str
    params_suggestion: Dict
    alternative_tools: List[str]


class ToolSelector:
    """智能工具选择器"""

    # 侦察兵节点调用的工具 - 自动化扫描，无需复杂决策
    RECON_TOOLS = [
        "fscan",       # 内网综合扫描
        "nmap",        # 端口扫描
        "dirsearch",   # 目录扫描
        "nuclei",      # CVE模板扫描
        "xray",        # 漏洞扫描
        "httpx",       # HTTP探测
        "subfinder",   # 子域名发现
        "ffuf",        # 模糊测试
    ]

    # 攻击兵节点调用的工具 - 执行实际攻击
    ATTACKER_TOOLS = [
        "sqlmap", "msf", "impacket", "crackmapexec",
        "ysoserial", "phpggc", "marshalsec", "jndi-exploit",
        "jwt-tool", "flask-unsign", "fenjing", "dalfox",
        "xxe-injector", "hydra", "git-hacker", "ssrf-scanner",
        "cloud-scanner", "oa-exploiter", "db-attacks", "privesc",
        "ajp-shooter", "php-filter-chain", "pickle-pwn",
        "potato", "mimikatz", "rubeus",
    ]

    # 内网渗透工具 - 需要凭据或shell会话
    INTERNAL_TOOLS = [
        "bloodhound",   # 域分析（需要域凭据）
        "secretsdump",  # 凭据导出（需要管理员权限）
        "psexec",       # 远程执行（需要凭据）
        "wmiexec",      # WMI执行（需要凭据）
        "smbexec",      # SMB执行（需要凭据）
        "atexec",       # 计划任务（需要凭据）
        "dcomexec",     # DCOM执行（需要凭据）
        "getnpusers",   # AS-REP Roasting（需要域信息）
        "getuserspns",  # Kerberoasting（需要域凭据）
        "ticketer",     # 票据伪造（需要krbtgt哈希）
        "goldenpac",    # 黄金票据（需要krbtgt哈希）
        "ntlmrelayx",   # NTLM中继
        "dacledit",     # ACL编辑
        "getadusers",   # 域用户枚举
        "raisechild",   # 子域提权
        "smbclient",    # SMB客户端
        "lookupsid",    # SID枚举
        "mssqlclient",  # MSSQL客户端
    ]

    def __init__(self):
        # 简单的历史记录（不用于训练，仅用于当前会话优化）
        self.successful_tools = {}
        self.failed_tools = {}
        self.attack_history = []

    def get_recommended_tools(self, vuln_type: str, context: str = "") -> List[str]:
        """
        简化的工具推荐接口 - 返回可用工具列表

        Args:
            vuln_type: 漏洞类型（如 "sql注入", "SSTI", "反序列化"）
            context: 上下文信息（如 "MySQL", "Jinja2", "Java"）

        Returns:
            可用工具名称列表
        """
        # 默认返回通用工具列表
        return ["requests", "python-exec", "nuclei"]

    def classify_vuln(self, vuln_info: Dict) -> VulnCategory:
        """根据漏洞信息分类"""
        vuln_type = vuln_info.get("type", "").lower()
        context = vuln_info.get("context", {})

        # 直接匹配
        type_mapping = {
            "sql": VulnCategory.SQL_INJECTION,
            "sqli": VulnCategory.SQL_INJECTION,
            "ssti": VulnCategory.SSTI,
            "template": VulnCategory.SSTI,
            "xss": VulnCategory.XSS,
            "xxe": VulnCategory.XXE,
            "ssrf": VulnCategory.SSRF,
            "lfi": VulnCategory.LFI,
            "rfi": VulnCategory.RFI,
            "upload": VulnCategory.FILE_UPLOAD,
            "deserial": VulnCategory.DESERIALIZATION,
            "rce": VulnCategory.RCE,
            "auth": VulnCategory.AUTH_BYPASS,
            "jwt": VulnCategory.JWT,
        }

        for keyword, category in type_mapping.items():
            if keyword in vuln_type:
                return category

        return VulnCategory.UNKNOWN

    def select_tools(self, vuln_info: Dict, context: Dict = None) -> List[ToolRecommendation]:
        """
        选择可用工具列表

        Args:
            vuln_info: 漏洞信息 {"type": "sql", "location": "...", ...}
            context: 上下文信息 {"tech_stack": ["php"], "db_type": "mysql", ...}

        Returns:
            工具推荐列表
        """
        category = self.classify_vuln(vuln_info)
        recommendations = []

        # 获取可用工具列表（按类别）
        available_tools = []
        if category != VulnCategory.UNKNOWN:
            # 根据历史记录筛选可用工具
            for tool in self.successful_tools:
                if self.failed_tools.get(tool, 0) < 3:  # 失败次数少于3次
                    available_tools.append(tool)

        # 如果没有历史记录，返回通用工具
        if not available_tools:
            available_tools = ["requests", "python-exec", "nuclei"]

        for tool in available_tools:
            recommendations.append(ToolRecommendation(
                tool_name=tool,
                priority=5,  # 统一优先级
                reason="可用工具",
                params_suggestion=self._get_param_suggestions(tool, vuln_info, context),
                alternative_tools=[]
            ))

        return recommendations

    def _get_param_suggestions(self, tool: str, vuln_info: Dict, context: Dict) -> Dict:
        """获取工具参数建议"""
        suggestions = {}

        if tool == "sqlmap":
            suggestions = {
                "level": 3,
                "risk": 2,
                "technique": "BEUSTQ",  # 所有技术
            }
            # 如果有WAF特征
            if context and context.get("waf_detected"):
                suggestions["tamper"] = "space2comment,between"

        elif tool == "fenjing":
            suggestions = {
                "mode": "auto",
            }

        elif tool == "nuclei":
            suggestions = {
                "severity": "critical,high",
                "tags": vuln_info.get("type", ""),
            }

        elif tool == "requests":
            # 根据漏洞类型生成Payload建议
            vuln_type = vuln_info.get("type", "").lower()
            if "sql" in vuln_type:
                suggestions["payloads"] = [
                    "' OR '1'='1",
                    "' UNION SELECT 1,2,3--",
                    "1' AND SLEEP(5)--",
                ]
            elif "ssti" in vuln_type:
                suggestions["payloads"] = [
                    "{{7*7}}",
                    "${7*7}",
                    "#{7*7}",
                ]
            elif "xxe" in vuln_type:
                suggestions["payloads"] = [
                    '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>',
                ]

        return suggestions

    def record_result(self, tool: str, success: bool, vuln_type: str = ""):
        """记录工具执行结果，用于后续优化选择"""
        if success:
            self.successful_tools[tool] = self.successful_tools.get(tool, 0) + 1
        else:
            self.failed_tools[tool] = self.failed_tools.get(tool, 0) + 1

        self.attack_history.append({
            "tool": tool,
            "success": success,
            "vuln_type": vuln_type,
            "timestamp": __import__('time').time()
        })

    def get_best_tool_for_vuln(self, vuln_type: str) -> Optional[str]:
        """根据历史记录获取针对特定漏洞的最佳工具"""
        best_tool = None
        best_success_rate = 0

        for tool, success_count in self.successful_tools.items():
            total = success_count + self.failed_tools.get(tool, 0)
            if total > 0:
                success_rate = success_count / total
                if success_rate > best_success_rate:
                    best_success_rate = success_rate
                    best_tool = tool

        return best_tool

    def get_tool_combination(self, vuln_info: Dict, context: Dict = None) -> List[str]:
        """获取工具组合（主工具 + 辅助工具）"""
        recommendations = self.select_tools(vuln_info, context)

        if not recommendations:
            return ["requests", "python-exec"]  # 默认回退

        # 主工具
        primary = recommendations[0].tool_name

        # 如果主工具是自动化工具，添加requests作为辅助
        if primary in ["sqlmap", "nuclei", "fenjing"]:
            return [primary, "requests"]

        return [primary]


# 全局实例
tool_selector = ToolSelector()


def get_tool_selector() -> ToolSelector:
    """获取全局工具选择器实例"""
    return tool_selector


# ============================================================================
# 并行漏洞扫描工具组合
# ============================================================================


def get_parallel_scanners(scene: str = "cve_full") -> List[str]:
    """
    获取并行扫描工具组合

    Args:
        scene: 场景名称（保留参数兼容性）

    Returns:
        可用的扫描工具列表
    """
    from tool_framework import ToolRegistry

    # 默认扫描工具
    default_tools = ["nuclei", "xray", "fscan"]

    # 过滤出实际可用的工具
    available_tools = []
    for tool_name in default_tools:
        # 检查工具是否注册且可用
        for vuln_type, tool_list in ToolRegistry._tools.items():
            for tool in tool_list:
                if tool.name() == tool_name and tool.check_available():
                    if tool_name not in available_tools:
                        available_tools.append(tool_name)
                    break

    return available_tools if available_tools else ["nuclei"]


def run_parallel_vuln_scan(target: str, tools: List[str] = None,
                           params: Dict = None) -> Dict[str, Dict]:
    """
    并行执行多个漏洞扫描工具

    Args:
        target: 目标URL
        tools: 工具列表，默认使用 nuclei + xray
        params: 每个工具的参数（可选）

    Returns:
        {tool_name: scan_result}
    """
    import concurrent.futures
    from tool_framework import ToolRegistry

    if tools is None:
        tools = ["nuclei", "xray"]

    if params is None:
        params = {}

    results = {}

    def scan_with_tool(tool_name: str) -> tuple:
        """单个工具扫描"""
        tool_params = params.get(tool_name, {})
        result = ToolRegistry.execute_cached(tool_name, target, tool_params)
        return tool_name, result

    # 并行执行
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
        futures = {executor.submit(scan_with_tool, t): t for t in tools}

        for future in concurrent.futures.as_completed(futures, timeout=600):
            try:
                tool_name, result = future.result(timeout=300)
                results[tool_name] = result
            except Exception as e:
                tool_name = futures[future]
                results[tool_name] = {"error": str(e), "success": False}

    return results


def aggregate_scan_results(results: Dict[str, Dict]) -> Dict:
    """
    聚合多个扫描工具的结果

    Args:
        results: {tool_name: scan_result}

    Returns:
        聚合后的结果，包含发现的漏洞总数和详情
    """
    all_vulns = []
    successful_tools = []
    failed_tools = []

    for tool_name, result in results.items():
        if result.get("error") or not result.get("result", {}).get("success"):
            failed_tools.append(tool_name)
            continue

        successful_tools.append(tool_name)
        tool_result = result.get("result", {})

        # 提取漏洞
        vulns = tool_result.get("vulnerabilities", [])
        for vuln in vulns:
            vuln["detected_by"] = tool_name
            all_vulns.append(vuln)

    return {
        "total_vulns": len(all_vulns),
        "vulnerabilities": all_vulns,
        "successful_tools": successful_tools,
        "failed_tools": failed_tools,
        "vulnerable": len(all_vulns) > 0
    }


# ============================================================================
# 工具前置条件检查
# ============================================================================

# 需要凭据的工具（用户名/密码或哈希）
TOOLS_REQUIRING_CREDENTIALS = {
    "bloodhound": ["domain", "username", "password_or_hash"],
    "secretsdump": ["username", "password_or_hash"],
    "psexec": ["username", "password_or_hash"],
    "wmiexec": ["username", "password_or_hash"],
    "smbexec": ["username", "password_or_hash"],
    "atexec": ["username", "password_or_hash"],
    "dcomexec": ["username", "password_or_hash"],
    "getnpusers": ["domain"],
    "getuserspns": ["domain", "username", "password"],
    "crackmapexec": ["username", "password_or_hash"],  # 可选但通常需要
    "smbclient": ["username", "password"],
    "mssqlclient": ["username", "password"],
}

# 需要shell会话的工具（必须在已有shell的环境中执行）
TOOLS_REQUIRING_SHELL_SESSION = {
    "mimikatz": "Windows内存凭据提取，需要Windows shell或已有会话",
    "rubeus": "Kerberos攻击工具，需要在Windows域环境执行",
    "potato": "Windows提权工具，需要Windows shell",
    "printspoofer": "Windows提权工具，需要Windows shell",
    "godpotato": "Windows提权工具，需要Windows shell",
}

# 需要特定条件的工具
TOOLS_REQUIRING_CONDITIONS = {
    "bloodhound": "需要域环境和有效的域凭据",
    "mimikatz": "需要Windows环境和管理员权限",
    "rubeus": "需要Windows域环境",
    "ntlmrelayx": "需要能够监听和中继流量",
    "ticketer": "需要krbtgt哈希",
    "goldenpac": "需要krbtgt哈希",
}


def check_tool_prerequisites(tool_name: str, state: Dict) -> Dict:
    """
    检查工具执行的前置条件

    Args:
        tool_name: 工具名称
        state: 当前状态，包含凭据、会话等信息
            - credentials: {"username": "", "password": "", "hash": "", "domain": ""}
            - shell_sessions: {"session_id": {"os": "windows/linux", ...}}
            - internal_access: bool (是否已进入内网)

    Returns:
        {
            "can_execute": bool,
            "missing": List[str],  # 缺失的前置条件
            "hint": str,  # 提示信息
            "tool_category": str  # recon/attacker/internal
        }
    """
    missing = []
    hints = []

    # 确定工具类别
    if tool_name.lower() in [t.lower() for t in RECON_TOOLS]:
        tool_category = "recon"
    elif tool_name.lower() in [t.lower() for t in INTERNAL_TOOLS]:
        tool_category = "internal"
    else:
        tool_category = "attacker"

    # 检查是否需要凭据
    if tool_name.lower() in TOOLS_REQUIRING_CREDENTIALS:
        required_fields = TOOLS_REQUIRING_CREDENTIALS[tool_name.lower()]
        credentials = state.get("credentials", {})

        for field in required_fields:
            if field == "password_or_hash":
                if not credentials.get("password") and not credentials.get("hash"):
                    missing.append("password或hash")
                    hints.append(f"{tool_name}需要密码或NTLM哈希")
            elif field == "domain":
                if not credentials.get("domain"):
                    missing.append("domain")
                    hints.append(f"{tool_name}需要域名信息")
            elif not credentials.get(field):
                missing.append(field)
                hints.append(f"{tool_name}需要{field}")

    # 检查是否需要shell会话
    if tool_name.lower() in TOOLS_REQUIRING_SHELL_SESSION:
        shell_sessions = state.get("shell_sessions", {})
        if not shell_sessions:
            missing.append("shell_session")
            hints.append(TOOLS_REQUIRING_SHELL_SESSION[tool_name.lower()])
        else:
            # 检查是否有合适类型的会话
            tool_requires = TOOLS_REQUIRING_SHELL_SESSION[tool_name.lower()]
            valid_session = False
            for session_id, session_info in shell_sessions.items():
                if "Windows" in tool_requires and session_info.get("os", "").lower() == "windows":
                    valid_session = True
                    break
                elif "Windows" not in tool_requires:
                    valid_session = True
                    break

            if not valid_session and "Windows" in tool_requires:
                missing.append("windows_shell_session")
                hints.append(f"{tool_name}需要在Windows环境的shell会话")

    # 检查特殊条件
    if tool_name.lower() in TOOLS_REQUIRING_CONDITIONS:
        # 这些是提示性信息，不阻止执行但提醒用户
        pass

    can_execute = len(missing) == 0

    return {
        "can_execute": can_execute,
        "missing": missing,
        "hint": "; ".join(hints) if hints else "",
        "tool_category": tool_category,
        "requires_credentials": tool_name.lower() in TOOLS_REQUIRING_CREDENTIALS,
        "requires_session": tool_name.lower() in TOOLS_REQUIRING_SHELL_SESSION,
    }


def get_tools_by_category(category: str) -> List[str]:
    """
    按类别获取工具列表

    Args:
        category: "recon", "attacker", "internal"

    Returns:
        该类别的工具列表
    """
    if category == "recon":
        return RECON_TOOLS.copy()
    elif category == "internal":
        return INTERNAL_TOOLS.copy()
    elif category == "attacker":
        return ATTACKER_TOOLS.copy()
    return []


def filter_tools_by_prerequisites(tools: List[str], state: Dict) -> Dict[str, Dict]:
    """
    批量检查多个工具的前置条件

    Args:
        tools: 工具名称列表
        state: 当前状态

    Returns:
        {tool_name: check_result}
    """
    results = {}
    for tool in tools:
        results[tool] = check_tool_prerequisites(tool, state)
    return results


def get_executable_tools(tools: List[str], state: Dict) -> List[str]:
    """
    从工具列表中筛选出可以执行的工具

    Args:
        tools: 工具名称列表
        state: 当前状态

    Returns:
        可以执行的工具列表
    """
    executable = []
    for tool in tools:
        check = check_tool_prerequisites(tool, state)
        if check["can_execute"]:
            executable.append(tool)
    return executable


# ============================================================================
# AI驱动的智能工具选择
# ============================================================================

def ai_select_tools(vuln_info: Dict, context: Dict = None,
                    attack_history: List[Dict] = None) -> List[str]:
    """
    AI驱动的工具选择 - 根据漏洞特征和上下文动态选择最优工具

    Args:
        vuln_info: 漏洞信息 {"type": "sql", "location": "...", ...}
        context: 上下文信息 {"tech_stack": ["php"], "db_type": "mysql", ...}
        attack_history: 历史攻击记录

    Returns:
        推荐工具列表
    """
    try:
        from llm_client import llm_client
        from config import config
        import json

        # 构建压缩的上下文
        history_summary = ""
        if attack_history:
            failed_tools = [h.get("tool") for h in attack_history[-10:] if not h.get("success")]
            success_tools = [h.get("tool") for h in attack_history[-10:] if h.get("success")]
            if failed_tools or success_tools:
                history_summary = f"历史: 成功={set(success_tools)}, 失败={set(failed_tools)}"

        prompt = f"""
分析漏洞特征，选择最优攻击工具。

## 漏洞信息
{json.dumps(vuln_info, ensure_ascii=False, indent=2)[:500]}

## 环境
{json.dumps(context, ensure_ascii=False)[:300] if context else '未知'}

{history_summary}

## 可用工具
- sqlmap: SQL注入自动化
- fenjing: Jinja2 SSTI专用
- nuclei: CVE模板扫描
- xray: 被动漏洞扫描
- fscan: 内网综合扫描
- ysoserial: Java反序列化
- phpggc: PHP反序列化
- jwt-tool: JWT攻击
- requests: 手动HTTP请求
- python-exec: 自定义脚本执行

## 要求
1. 选择2-3个最合适的工具（按优先级排序）
2. 考虑历史成功/失败记录
3. 避免选择已失败多次的工具

## 输出格式 (JSON)
{{
    "tools": ["工具1", "工具2"],
    "reasoning": "选择理由",
    "params_suggestion": {{"工具名": {{"param": "value"}}}}
}}
"""
        response = llm_client.call_chat_completion(
            model=config.ANALYST_MODEL,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.1,
            json_mode=True
        )

        if "```json" in response:
            response = response.split("```json")[1].split("```")[0]

        result = json.loads(response.strip())
        tools = result.get("tools", ["requests", "python-exec"])
        logger.info(f"[AI工具选择] 选择: {tools} - {result.get('reasoning', '')}")
        return tools

    except Exception as e:
        logger.info(f"[AI工具选择] 降级到规则选择: {e}")
        # 降级到规则选择
        return tool_selector.get_recommended_tools(
            vuln_info.get("type", ""),
            str(context) if context else ""
        )


def ai_generate_exploit_strategy(vuln_info: Dict, binary_info: Dict = None) -> Dict:
    """
    AI生成exploit策略 - 用于Pwn模块

    Args:
        vuln_info: 漏洞信息
        binary_info: 二进制信息（Pwn场景）

    Returns:
        exploit策略和命令
    """
    try:
        from llm_client import llm_client
        from config import config
        import json

        prompt = f"""
分析漏洞，生成exploit攻击策略。

## 漏洞信息
{json.dumps(vuln_info, ensure_ascii=False, indent=2)}

## 二进制信息
{json.dumps(binary_info, ensure_ascii=False, indent=2)[:500] if binary_info else '无'}

## 要求
1. 分析漏洞利用条件
2. 生成具体的exploit命令或payload
3. 考虑保护机制的绕过

## 输出格式 (JSON)
{{
    "exploit_method": "方法名",
    "commands": ["执行的命令列表"],
    "payload": "payload内容",
    "notes": "注意事项"
}}
"""
        response = llm_client.call_chat_completion(
            model=config.ANALYST_MODEL,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.1,
            json_mode=True
        )

        if "```json" in response:
            response = response.split("```json")[1].split("```")[0]

        return json.loads(response.strip())

    except Exception as e:
        logger.warning(f"[AI Exploit生成] 失败: {e}")
        return {"exploit_method": "manual", "commands": [], "error": str(e)}


def ai_decide_decryption(ciphertext: str, analysis: Dict) -> Dict:
    """
    AI决策解密策略 - 用于Crypto模块

    Args:
        ciphertext: 密文
        analysis: 初步分析结果

    Returns:
        解密策略
    """
    try:
        from llm_client import llm_client
        from config import config
        import json

        prompt = f"""
分析密文，决策解密策略。

## 密文
{ciphertext[:200]}

## 初步分析
{json.dumps(analysis, ensure_ascii=False)}

## 要求
1. 判断最可能的加密/编码类型
2. 给出解密命令或方法
3. 如果需要密钥，说明可能的密钥来源

## 输出格式 (JSON)
{{
    "encryption_type": "类型",
    "decryption_method": "方法",
    "commands": ["python代码或命令"],
    "key_hint": "密钥提示"
}}
"""
        response = llm_client.call_chat_completion(
            model=config.ANALYST_MODEL,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.1,
            json_mode=True
        )

        if "```json" in response:
            response = response.split("```json")[1].split("```")[0]

        return json.loads(response.strip())

    except Exception as e:
        return {"decryption_method": "auto", "error": str(e)}