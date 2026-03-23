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
            ("xsser", 9, "XSS自动化扫描工具"),
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
            ("nuclei", 9, "CVE模板扫描"),
            ("metasploit", 9, "渗透框架"),
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
        pass  # 不需要历史记录，直接规则匹配

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