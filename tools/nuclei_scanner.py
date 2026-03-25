# tools/nuclei_scanner.py
"""
Nuclei漏洞扫描器集成

Nuclei是一个快速的漏洞扫描器，支持：
- 5000+ CVE模板
- 自定义POC模板
- JSON输出格式
- 多种协议支持
"""

import os
import json
import shutil
import subprocess
from typing import Dict, List, Any, Optional
from tool_framework import CommandLineTool


class NucleiScanner(CommandLineTool):
    """
    Nuclei漏洞扫描器封装

    功能：
    - 批量CVE扫描
    - 指定CVE检测
    - OA漏洞扫描
    - 自定义模板扫描
    """

    def __init__(self):
        self.executable = self._find_nuclei()
        super().__init__(self.executable or "nuclei")
        self.timeout = 300  # 5分钟超时
        self.templates_updated = False

    def _find_nuclei(self) -> Optional[str]:
        """查找nuclei可执行文件"""
        # 检查PATH
        nuclei = shutil.which("nuclei")
        if nuclei:
            return nuclei

        # 检查常见路径
        common_paths = [
            "/usr/local/bin/nuclei",
            "/usr/bin/nuclei",
            "/root/go/bin/nuclei",
            "/home/user/go/bin/nuclei",
        ]
        for path in common_paths:
            if os.path.exists(path):
                return path

        return None

    def name(self) -> str:
        return "nuclei"

    def description(self) -> str:
        return "Nuclei快速漏洞扫描器，支持5000+ CVE模板，覆盖Log4Shell、Spring、Shiro、OA系统等。"

    def supported_vulns(self) -> list:
        return [
            "CVE Scan", "Log4Shell", "Spring4Shell", "Shiro-550",
            "WebLogic RCE", "Tomcat Ghostcat", "OA Vulnerabilities"
        ]

    def capability_statement(self) -> str:
        return "CVE漏洞扫描器。输入URL，自动扫描5000+已知漏洞模板。适合：已识别框架/中间件、疑似CVE目标、批量安全评估。可指定tags过滤扫描范围。"

    def check_available(self) -> bool:
        """检查nuclei是否可用"""
        if not self.executable:
            return False
        try:
            result = subprocess.run(
                [self.executable, "-version"],
                capture_output=True,
                timeout=10
            )
            return result.returncode == 0
        except Exception:
            return False

    def expected_params(self) -> Dict[str, Dict[str, Any]]:
        return {
            "target": {
                "type": "str",
                "description": "目标URL或IP",
                "required": True
            },
            "severity": {
                "type": "str",
                "description": "最低严重级别: info/low/medium/high/critical",
                "required": False,
                "default": "high"
            },
            "cve_id": {
                "type": "str",
                "description": "指定CVE编号扫描，如CVE-2021-44228",
                "required": False
            },
            "tags": {
                "type": "str",
                "description": "模板标签，如log4j,spring,oa",
                "required": False
            },
            "templates": {
                "type": "str",
                "description": "自定义模板路径",
                "required": False
            },
            "update_templates": {
                "type": "bool",
                "description": "是否更新模板库",
                "required": False,
                "default": False
            }
        }

    def execute(self, target: str, params: Dict) -> Dict:
        """执行Nuclei扫描"""
        target = params.get("target") or target
        if not target:
            return {"error": "必须提供目标", "success": False}

        # 检查nuclei是否可用
        if not self.check_available():
            return {
                "error": "Nuclei未安装。安装方法：go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
                "success": False
            }

        # 更新模板（如果需要）
        if params.get("update_templates", False) or not self.templates_updated:
            self._update_templates()
            self.templates_updated = True

        # 构建命令
        cmd = [self.executable, "-u", target, "-json", "-silent"]

        # 严重级别过滤
        severity = params.get("severity", "high")
        if severity:
            cmd.extend(["-severity", severity])

        # 指定CVE
        cve_id = params.get("cve_id")
        if cve_id:
            # 查找CVE模板
            template_path = self._find_cve_template(cve_id)
            if template_path:
                cmd.extend(["-t", template_path])
            else:
                # 尝试直接使用标签
                cmd.extend(["-tags", cve_id.lower()])

        # 标签过滤
        tags = params.get("tags")
        if tags:
            cmd.extend(["-tags", tags])

        # 自定义模板
        templates = params.get("templates")
        if templates:
            cmd.extend(["-t", templates])

        # 执行扫描 - 使用基类的流式输出方法
        try:
            raw_result = self._run_command(cmd, timeout=self.timeout, stream_output=True)
            stdout = raw_result.get("stdout", "")
            stderr = raw_result.get("stderr", "")

            if not raw_result.get("success") and "error" in raw_result:
                return {
                    "success": False,
                    "error": raw_result.get("error"),
                    "target": target,
                    "command": ' '.join(cmd)
                }

            # 解析结果
            vulnerabilities = []
            for line in stdout.strip().split("\n"):
                if line:
                    try:
                        vuln = json.loads(line)
                        vulnerabilities.append(self._parse_result(vuln))
                    except json.JSONDecodeError:
                        continue

            # [修复] 添加 vulnerable 字段到顶层
            has_vulns = len(vulnerabilities) > 0

            return {
                "success": True,
                "vulnerable": has_vulns,
                "target": target,
                "command": raw_result.get('command', ''),
                "vulnerabilities": vulnerabilities,
                "total_found": len(vulnerabilities),
                "stdout": stdout,  # 保留原始输出用于日志
                "stderr": stderr
            }

        except Exception as e:
            return {
                "error": str(e),
                "success": False,
                "target": target
            }

    def _update_templates(self) -> bool:
        """更新Nuclei模板库"""
        try:
            result = subprocess.run(
                [self.executable, "-update-templates"],
                capture_output=True,
                timeout=120
            )
            return result.returncode == 0
        except Exception:
            return False

    def _find_cve_template(self, cve_id: str) -> Optional[str]:
        """查找CVE模板路径"""
        # Nuclei模板目录
        template_dirs = [
            os.path.expanduser("~/nuclei-templates"),
            "/root/nuclei-templates",
            "/home/user/nuclei-templates",
        ]

        cve_lower = cve_id.lower()
        cve_year = cve_lower.split("-")[1] if "-" in cve_lower else ""

        for template_dir in template_dirs:
            if not os.path.exists(template_dir):
                continue

            # 尝试多种路径格式
            possible_paths = [
                os.path.join(template_dir, "cves", cve_year, f"{cve_lower}.yaml"),
                os.path.join(template_dir, "cves", f"{cve_lower}.yaml"),
                os.path.join(template_dir, f"{cve_lower}.yaml"),
            ]

            for path in possible_paths:
                if os.path.exists(path):
                    return path

        return None

    def _parse_result(self, raw_result: Dict) -> Dict:
        """解析Nuclei输出结果"""
        return {
            "template_id": raw_result.get("template-id", ""),
            "name": raw_result.get("info", {}).get("name", ""),
            "severity": raw_result.get("info", {}).get("severity", ""),
            "cve_id": self._extract_cve(raw_result),
            "matched_at": raw_result.get("matched-at", raw_result.get("host", "")),
            "description": raw_result.get("info", {}).get("description", ""),
            "reference": raw_result.get("info", {}).get("reference", []),
            "timestamp": raw_result.get("timestamp", ""),
            "curl_command": raw_result.get("curl-command", ""),
        }

    def _extract_cve(self, result: Dict) -> str:
        """从结果中提取CVE编号"""
        # 从模板ID提取
        template_id = result.get("template-id", "")
        if template_id.startswith("CVE-") or template_id.startswith("cve-"):
            return template_id.upper()

        # 从标签提取
        tags = result.get("info", {}).get("tags", [])
        for tag in tags:
            if tag.upper().startswith("CVE-"):
                return tag.upper()

        # 从引用提取
        references = result.get("info", {}).get("reference", [])
        for ref in references:
            if "nvd.nist.gov/vuln/detail/CVE-" in ref:
                cve = ref.split("CVE-")[-1].split("/")[0]
                return f"CVE-{cve}"

        return ""

    # ==================== 快捷方法 ====================

    def scan_cve(self, target: str, severity: str = "critical") -> Dict:
        """快速CVE扫描"""
        return self.execute(target, {"severity": severity})

    def scan_log4j(self, target: str) -> Dict:
        """Log4Shell专项扫描"""
        return self.execute(target, {"tags": "log4j"})

    def scan_spring(self, target: str) -> Dict:
        """Spring漏洞专项扫描"""
        return self.execute(target, {"tags": "spring"})

    def scan_shiro(self, target: str) -> Dict:
        """Shiro漏洞专项扫描"""
        return self.execute(target, {"tags": "shiro"})

    def scan_oa(self, target: str) -> Dict:
        """OA系统漏洞扫描"""
        return self.execute(target, {"tags": "oa"})

    def scan_specific_cve(self, target: str, cve_id: str) -> Dict:
        """扫描指定CVE"""
        return self.execute(target, {"cve_id": cve_id})


# 常用CVE扫描预设
CVE_PRESETS = {
    "log4shell": {
        "cve_ids": ["CVE-2021-44228", "CVE-2021-45046"],
        "tags": ["log4j"],
        "description": "Log4j RCE漏洞"
    },
    "spring4shell": {
        "cve_ids": ["CVE-2022-22965"],
        "tags": ["spring", "spring4shell"],
        "description": "Spring Framework RCE"
    },
    "shiro": {
        "cve_ids": ["CVE-2016-4437", "CVE-2019-12422"],
        "tags": ["shiro"],
        "description": "Apache Shiro反序列化"
    },
    "weblogic": {
        "cve_ids": ["CVE-2020-14882", "CVE-2020-14883"],
        "tags": ["weblogic"],
        "description": "Oracle WebLogic RCE"
    },
    "tomcat": {
        "cve_ids": ["CVE-2020-1938"],
        "tags": ["tomcat", "ghostcat"],
        "description": "Apache Tomcat AJP文件读取"
    },
    "jenkins": {
        "cve_ids": ["CVE-2024-23897"],
        "tags": ["jenkins"],
        "description": "Jenkins CLI任意文件读取"
    },
    "confluence": {
        "cve_ids": ["CVE-2023-22515", "CVE-2023-22527"],
        "tags": ["confluence", "atlassian"],
        "description": "Confluence RCE"
    },
}


def quick_scan(target: str, preset: str = "all") -> Dict:
    """
    快速扫描快捷函数

    Args:
        target: 目标URL
        preset: 预设名称，可选 log4shell/spring4shell/shiro/weblogic/tomcat/jenkins/confluence/all

    Returns:
        扫描结果
    """
    scanner = NucleiScanner()

    if preset == "all":
        return scanner.scan_cve(target, severity="critical")

    if preset in CVE_PRESETS:
        return scanner.execute(target, {"tags": ",".join(CVE_PRESETS[preset]["tags"])})

    return {"error": f"未知预设: {preset}", "success": False}


def register():
    """注册Nuclei扫描器"""
    from tool_framework import ToolRegistry
    scanner = NucleiScanner()
    ToolRegistry.register(scanner)