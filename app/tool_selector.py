#!/usr/bin/env python
"""
Tool Selector - 智能工具选择器
根据漏洞类型、上下文、历史记录智能选择最优工具组合
"""

from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum


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

    # 漏洞类型到工具的映射 (按优先级排序)
    TOOL_MAPPING = {
        VulnCategory.SQL_INJECTION: [
            ("sqlmap", 10, "最成熟的SQL注入自动化工具"),
            ("requests", 7, "手动构造注入Payload"),
            ("python-exec", 5, "自定义注入脚本"),
        ],
        VulnCategory.SSTI: [
            ("fenjing", 10, "专门针对Jinja2 SSTI的工具"),
            ("requests", 8, "手动构造模板注入Payload"),
            ("python-exec", 6, "自定义模板注入脚本"),
        ],
        VulnCategory.XSS: [
            ("dalfox", 10, "XSS自动化扫描工具"),
            ("requests", 7, "手动构造XSS Payload"),
        ],
        VulnCategory.XXE: [
            ("xxe-injector", 10, "XXE专用利用工具"),
            ("nuclei", 8, "包含XXE检测模板"),
            ("requests", 6, "手动构造XXE Payload"),
        ],
        VulnCategory.SSRF: [
            ("ssrf-scanner", 10, "SSRF专用扫描工具"),
            ("cloud-scanner", 9, "云元数据获取"),
            ("requests", 7, "手动构造SSRF请求"),
        ],
        VulnCategory.LFI: [
            ("php-filter-chain", 9, "PHP LFI利用"),
            ("ffuf", 8, "路径模糊测试"),
            ("dirsearch", 7, "目录扫描发现敏感文件"),
            ("requests", 6, "手动构造LFI Payload"),
        ],
        VulnCategory.FILE_UPLOAD: [
            ("file-creator", 9, "生成恶意上传文件"),
            ("requests", 8, "手动构造上传请求"),
        ],
        VulnCategory.DESERIALIZATION: [
            ("ysoserial", 10, "Java反序列化利用"),
            ("phpggc", 10, "PHP反序列化利用"),
            ("pickle-pwn", 10, "Python反序列化利用"),
            ("marshalsec", 9, "Java JNDI注入"),
            ("phar-gen", 8, "Phar文件生成"),
        ],
        VulnCategory.RCE: [
            ("nuclei", 10, "CVE模板扫描"),
            ("jndi-exploit", 9, "JNDI注入RCE"),
            ("python-exec", 7, "自定义RCE脚本"),
        ],
        VulnCategory.AUTH_BYPASS: [
            ("jwt-tool", 10, "JWT攻击"),
            ("flask-unsign", 10, "Flask Session伪造"),
            ("requests", 7, "手动构造认证绕过"),
        ],
        VulnCategory.JWT: [
            ("jwt-tool", 10, "JWT专用工具"),
        ],
    }

    # 技术栈到漏洞类型的映射
    TECH_TO_VULN = {
        "php": [VulnCategory.LFI, VulnCategory.DESERIALIZATION],
        "java": [VulnCategory.DESERIALIZATION, VulnCategory.XXE],
        "python": [VulnCategory.SSTI, VulnCategory.DESERIALIZATION],
        "nodejs": [VulnCategory.SSTI, VulnCategory.XXE],
        "asp": [VulnCategory.SQL_INJECTION, VulnCategory.LFI],
        "jsp": [VulnCategory.SQL_INJECTION, VulnCategory.DESERIALIZATION],
    }

    # 数据库类型到攻击方式的映射
    DB_TO_ATTACK = {
        "mysql": ["sqlmap", "db-attacks"],
        "mssql": ["sqlmap", "db-attacks"],
        "postgresql": ["sqlmap", "db-attacks"],
        "oracle": ["sqlmap", "db-attacks"],
        "redis": ["db-attacks", "ssrf-scanner"],
        "mongodb": ["db-attacks", "nosql-map"],
    }

    def __init__(self):
        # 简单的历史记录（不用于训练，仅用于当前会话优化）
        self.successful_tools = {}
        self.failed_tools = {}
        self.attack_history = []

    def get_recommended_tools(self, vuln_type: str, context: str = "") -> List[str]:
        """
        简化的工具推荐接口 - AI驱动增强版

        Args:
            vuln_type: 漏洞类型（如 "sql注入", "SSTI", "反序列化"）
            context: 上下文信息（如 "MySQL", "Jinja2", "Java"）

        Returns:
            推荐工具名称列表
        """
        # 标准化漏洞类型
        vuln_type_lower = vuln_type.lower()

        # 漏洞类型到工具的直接映射
        direct_mapping = {
            # Web漏洞
            "sql注入": ["sqlmap", "db-attacks", "requests"],
            "sql": ["sqlmap", "db-attacks", "requests"],
            "sqli": ["sqlmap", "db-attacks", "requests"],
            "ssti": ["fenjing", "requests", "python-exec"],
            "模板注入": ["fenjing", "requests", "python-exec"],
            "xss": ["dalfox", "requests"],
            "xxe": ["xxe-injector", "nuclei", "requests"],
            "ssrf": ["ssrf-scanner", "cloud-scanner", "requests"],
            "lfi": ["php-filter-chain", "ffuf", "dirsearch", "requests"],
            "rfi": ["requests", "python-exec"],
            "文件上传": ["file-creator", "requests"],

            # 反序列化
            "反序列化": ["ysoserial", "phpggc", "pickle-pwn", "marshalsec"],
            "java反序列化": ["ysoserial", "marshalsec", "jndi-exploit"],
            "php反序列化": ["phpggc", "phar-gen"],

            # CVE - 并行扫描
            "cve": ["nuclei", "xray", "fscan"],  # 多工具并行
            "log4j": ["jndi-exploit", "nuclei", "xray"],
            "log4shell": ["jndi-exploit", "nuclei", "xray"],
            "spring": ["nuclei", "xray", "cve-scanner"],
            "shiro": ["nuclei", "ysoserial", "xray"],
            "weblogic": ["nuclei", "ysoserial", "marshalsec", "xray"],
            "fastjson": ["jndi-exploit", "nuclei", "xray"],
            "tomcat": ["ajp-shooter", "nuclei", "xray", "fscan"],  # 并行扫描
            "ghostcat": ["ajp-shooter", "nuclei"],

            # 综合漏洞扫描
            "漏洞扫描": ["nuclei", "xray", "fscan"],
            "安全评估": ["nuclei", "xray"],
            "渗透测试": ["nuclei", "xray", "fscan"],

            # 云服务
            "云元数据": ["cloud-scanner", "ssrf-scanner"],
            "aws": ["cloud-scanner", "ssrf-scanner"],
            "azure": ["cloud-scanner", "ssrf-scanner"],
            "gcp": ["cloud-scanner", "ssrf-scanner"],

            # AI安全
            "prompt注入": ["ai-attacker", "requests"],
            "ai攻击": ["ai-attacker", "requests"],
            "越狱": ["ai-attacker", "requests"],

            # OA系统
            "oa漏洞": ["oa-exploiter", "nuclei", "requests"],
            "泛微": ["oa-exploiter", "nuclei"],
            "致远": ["oa-exploiter", "nuclei"],
            "通达": ["oa-exploiter", "nuclei"],
            "蓝凌": ["oa-exploiter", "nuclei"],

            # 内网渗透
            "端口扫描": ["nmap", "masscan"],
            "smb枚举": ["crackmapexec", "impacket", "nmap"],
            "横向移动": ["impacket", "crackmapexec"],
            "psexec": ["impacket", "crackmapexec"],
            "wmi": ["impacket", "crackmapexec"],
            "代理": ["frp-manager"],
            "socks5": ["frp-manager"],

            # 域渗透
            "kerberos": ["impacket", "bloodhound"],
            "as-rep roasting": ["impacket", "crackmapexec"],
            "kerberoasting": ["impacket", "crackmapexec"],
            "dcsync": ["impacket", "crackmapexec"],
            "域渗透": ["impacket", "bloodhound", "crackmapexec"],
            "票据": ["impacket", "mimikatz"],

            # 认证绕过
            "jwt": ["jwt-tool", "requests"],
            "认证绕过": ["jwt-tool", "flask-unsign", "requests"],
        }

        # 查找匹配的工具
        for key, tools in direct_mapping.items():
            if key in vuln_type_lower:
                return tools

        # 根据上下文进一步筛选
        if context:
            context_lower = context.lower()
            if "mysql" in context_lower or "mssql" in context_lower or "postgres" in context_lower:
                if "sql" in vuln_type_lower:
                    return ["sqlmap", "db-attacks"]
            if "jinja2" in context_lower or "flask" in context_lower:
                if "ssti" in vuln_type_lower or "模板" in vuln_type:
                    return ["fenjing", "requests"]
            if "java" in context_lower:
                if "反序列化" in vuln_type:
                    return ["ysoserial", "marshalsec", "jndi-exploit"]
            if "php" in context_lower:
                if "反序列化" in vuln_type:
                    return ["phpggc", "phar-gen"]

        # 默认返回通用工具
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
        智能选择工具

        Args:
            vuln_info: 漏洞信息 {"type": "sql", "location": "...", ...}
            context: 上下文信息 {"tech_stack": ["php"], "db_type": "mysql", ...}

        Returns:
            工具推荐列表
        """
        category = self.classify_vuln(vuln_info)
        recommendations = []

        # 获取基础工具列表
        base_tools = self.TOOL_MAPPING.get(category, [])

        # 根据上下文调整优先级
        if context:
            tech_stack = context.get("tech_stack", [])
            db_type = context.get("db_type", "")

            # 根据技术栈调整
            for tech in tech_stack:
                if tech.lower() in self.TECH_TO_VULN:
                    if category in self.TECH_TO_VULN[tech.lower()]:
                        # 相关技术栈，提高优先级
                        for tool, priority, reason in base_tools:
                            if tool == "requests":
                                priority += 2  # 手动构造更可控

            # 根据数据库类型调整
            if db_type and category == VulnCategory.SQL_INJECTION:
                db_tools = self.DB_TO_ATTACK.get(db_type.lower(), [])
                for tool, priority, reason in base_tools:
                    if tool in db_tools:
                        priority += 1

        # 根据历史记录调整
        for tool, priority, reason in base_tools:
            # 如果之前成功过，提高优先级
            if tool in self.successful_tools:
                priority += 2

            # 如果之前失败过，降低优先级
            if tool in self.failed_tools:
                priority -= 2
                # 如果失败次数过多，跳过
                if self.failed_tools[tool] >= 3:
                    continue

            recommendations.append(ToolRecommendation(
                tool_name=tool,
                priority=min(10, max(1, priority)),
                reason=reason,
                params_suggestion=self._get_param_suggestions(tool, vuln_info, context),
                alternative_tools=[t[0] for t in base_tools if t[0] != tool][:2]
            ))

        # 按优先级排序
        recommendations.sort(key=lambda x: x.priority, reverse=True)

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

# 漏洞扫描工具组（按场景分类，用于并行调用）
VULN_SCANNER_GROUPS = {
    # 综合CVE扫描 - 三个工具并行
    "cve_full": ["nuclei", "xray", "fscan"],

    # 快速扫描 - 两个工具
    "cve_quick": ["nuclei", "fscan"],

    # Java/中间件漏洞
    "java_middleware": ["nuclei", "xray"],

    # Tomcat专项
    "tomcat": ["nuclei", "xray", "fscan", "ajp-shooter"],

    # OA系统
    "oa": ["nuclei", "xray", "oa-exploiter"],

    # 内网资产发现
    "internal_scan": ["fscan", "nmap"],

    # Web应用深度扫描
    "web_deep": ["nuclei", "xray"],
}


def get_parallel_scanners(scene: str = "cve_full") -> List[str]:
    """
    获取并行扫描工具组合

    Args:
        scene: 场景名称，如 "cve_full", "tomcat", "web_deep"

    Returns:
        可用的扫描工具列表
    """
    from tool_framework import ToolRegistry

    tools = VULN_SCANNER_GROUPS.get(scene, VULN_SCANNER_GROUPS["cve_full"])

    # 过滤出实际可用的工具
    available_tools = []
    for tool_name in tools:
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
        print(f"[AI工具选择] 选择: {tools} - {result.get('reasoning', '')}")
        return tools

    except Exception as e:
        print(f"[AI工具选择] 降级到规则选择: {e}")
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
        print(f"[AI Exploit生成] 失败: {e}")
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