# tools/fscan_tool.py
"""
Fscan Tool - 内网综合扫描工具

功能:
- 端口扫描
- 服务识别
- 漏洞扫描（弱口令、未授权访问等）
- 资产发现

特点:
- 比nmap更快
- 自动识别常见漏洞
- 支持多种协议爆破

CTF优化:
- 简化参数，直接一次性扫描完成
- 不分服务扫描和漏洞扫描
"""
import re
import json
import shutil
import subprocess
from typing import Dict, Any, List, Tuple
from tool_framework import NetworkScanTool
from llm_client import llm_client
from config import config


class FscanTool(NetworkScanTool):
    """
    Fscan 内网综合扫描工具封装

    简化使用：fscan -h target，一次完成所有扫描
    """

    def __init__(self):
        # 检测 fscan 是否可用
        self.executable = None
        possible_paths = [
            "/usr/local/bin/fscan",
            "/usr/bin/fscan",
            "./fscan",
            "./tools/fscan",
            "fscan"
        ]

        for path in possible_paths:
            if shutil.which(path):
                self.executable = path
                break

        # 尝试直接运行检查
        if not self.executable:
            try:
                result = subprocess.run(["fscan"], capture_output=True, timeout=5)
                output = result.stdout.decode('utf-8', errors='ignore') + result.stderr.decode('utf-8', errors='ignore')
                if "fscan" in output.lower() or result.returncode in [0, 1]:
                    self.executable = "fscan"
            except Exception:
                pass

        super().__init__(self.executable or "fscan")
        self.timeout = 600  # 10分钟超时

    def name(self) -> str:
        return "fscan"

    def description(self) -> str:
        return "内网综合扫描工具，一次扫描完成端口发现、服务识别、弱口令爆破、漏洞检测。"

    def supported_vulns(self) -> list:
        return [
            "Port Scan",
            "Service Detection",
            "Weak Password",
            "Unauthorized Access",
            "Network Reconnaissance",
            "Vulnerability Scan"
        ]

    def capability_statement(self) -> str:
        return "内网综合扫描工具。输入IP或网段，一次性完成端口扫描+服务识别+弱口令爆破+漏洞检测。适合：内网渗透、资产发现、横向移动。"

    def check_available(self) -> bool:
        """检查 fscan 是否可用"""
        if self.executable:
            return True
        try:
            result = subprocess.run(
                ["fscan"],
                capture_output=True,
                timeout=10
            )
            output = result.stdout.decode('utf-8', errors='ignore') + result.stderr.decode('utf-8', errors='ignore')
            if "fscan" in output.lower() or "usage" in output.lower() or result.returncode in [0, 1]:
                self.executable = "fscan"
                return True
            return False
        except FileNotFoundError:
            print("[Warning] fscan not found. Install: go install github.com/shadow1ng/fscan@latest")
            return False
        except Exception:
            return True

    def expected_params(self) -> Dict[str, Dict[str, Any]]:
        return {
            "target": {
                "type": "str",
                "description": "目标IP、CIDR网段或URL (如 192.168.1.1, 10.10.10.0/24, http://example.com)",
                "required": True
            },
            "no_ping": {
                "type": "bool",
                "description": "跳过存活检测，直接扫描（适用于禁ping环境）",
                "required": False,
                "default": True
            }
        }

    def execute(self, target: str, params: Dict) -> Dict:
        """
        执行 fscan 扫描 - 简化版，一次完成所有扫描
        输出完全交给 AI 解析，不做正则硬编码
        """
        target = params.get("target") or target
        if not target:
            return {"error": "必须提供目标", "success": False}

        # 构建命令 - 最简化
        cmd = [self.executable or "fscan"]

        # 检测是否是URL格式
        is_url = target.startswith("http://") or target.startswith("https://")

        if is_url:
            # URL扫描模式
            cmd.extend(["-u", target])
        else:
            # IP/网段扫描模式
            is_valid, error_msg = self.validate_target(target)
            if not is_valid:
                return {"error": f"目标验证失败: {error_msg}", "success": False}
            cmd.extend(["-h", target])

        # 跳过存活检测（CTF场景通常需要，因为很多目标禁ping）
        if params.get("no_ping", True):
            cmd.append("-np")

        print(f"[Fscan] Executing: {' '.join(cmd)}")

        try:
            # 使用流输出模式执行
            raw_result = self._run_command(cmd, timeout=self.timeout, stream_output=True)
            stdout = raw_result.get("stdout", "")
            stderr = raw_result.get("stderr", "")

            if not raw_result.get("success") and "error" in raw_result:
                return {
                    "success": False,
                    "error": raw_result.get("error"),
                    "command": ' '.join(cmd)
                }

            # 不做正则解析，直接返回原始输出，交给 AI 解析
            full_output = stdout + "\n" + stderr

            return {
                "success": True,
                "target": target,
                "command": raw_result.get('command', ''),
                "stdout": full_output  # 原始输出交给 AI 解析
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "target": target
            }

    def _parse_output(self, output: str) -> Tuple[List[Dict], List[Dict]]:
        """解析fscan输出"""
        hosts = {}
        vulnerabilities = []

        for line in output.split('\n'):
            line = line.strip()
            if not line:
                continue

            # 端口开放: [*] 端口开放 192.168.1.1:22
            port_match = re.match(r'\[.*?\]\s*\[?\*?\]?\s*端口开放\s+(\d+\.\d+\.\d+\.\d+):(\d+)', line)
            if port_match:
                ip = port_match.group(1)
                port = int(port_match.group(2))
                if ip not in hosts:
                    hosts[ip] = {"ip": ip, "ports": []}
                hosts[ip]["ports"].append({"port": port, "service": "unknown"})
                continue

            # 服务识别: [+] 192.168.1.1:22 SSH
            service_match = re.match(r'\[.*?\]\s*\[\+\]\s*(\d+\.\d+\.\d+\.\d+):(\d+)\s+(\w+)', line)
            if service_match:
                ip = service_match.group(1)
                port = int(service_match.group(2))
                service = service_match.group(3)
                if ip not in hosts:
                    hosts[ip] = {"ip": ip, "ports": []}
                # 更新服务名
                for p in hosts[ip]["ports"]:
                    if p["port"] == port:
                        p["service"] = service
                        break
                continue

            # 弱口令/漏洞: [+] 192.168.1.1:22 ssh admin admin123
            vuln_match = re.match(r'\[.*?\]\s*\[\+\]\s*(\d+\.\d+\.\d+\.\d+):(\d+)\s+(\w+)\s+(.+)', line)
            if vuln_match:
                ip = vuln_match.group(1)
                port = int(vuln_match.group(2))
                service = vuln_match.group(3)
                info = vuln_match.group(4).strip()

                # 检查是否是弱口令
                if ' ' in info:
                    parts = info.split()
                    if len(parts) >= 2:
                        vulnerabilities.append({
                            "type": "weak_password",
                            "ip": ip,
                            "port": port,
                            "service": service,
                            "username": parts[0],
                            "password": ' '.join(parts[1:]),
                            "severity": "high",
                            "info": f"{service} 弱口令: {parts[0]}/{' '.join(parts[1:])}"
                        })
                    else:
                        vulnerabilities.append({
                            "type": "vulnerability",
                            "ip": ip,
                            "port": port,
                            "service": service,
                            "severity": "high",
                            "info": info
                        })
                else:
                    vulnerabilities.append({
                        "type": "vulnerability",
                        "ip": ip,
                        "port": port,
                        "service": service,
                        "severity": "medium",
                        "info": info
                    })
                continue

            # 未授权访问等
            unauth_match = re.match(r'\[.*?\]\s*\[\+\]\s*(\d+\.\d+\.\d+\.\d+):(\d+)\s*(.+)', line)
            if unauth_match and '端口开放' not in line:
                ip = unauth_match.group(1)
                port = int(unauth_match.group(2))
                info = unauth_match.group(3).strip()
                if info and info not in ['Open', 'open']:
                    vulnerabilities.append({
                        "type": "unauthorized_access",
                        "ip": ip,
                        "port": port,
                        "severity": "high",
                        "info": info
                    })

        return list(hosts.values()), vulnerabilities

    def _parse_web_output(self, output: str) -> List[Dict]:
        """解析fscan Web扫描输出"""
        vulnerabilities = []

        for line in output.split('\n'):
            line = line.strip()
            if not line:
                continue

            # Web标题识别: 网站标题 https://example.com 状态码:200 标题:Apache Tomcat/9.0.97
            title_match = re.search(r'网站标题\s+(\S+)\s+状态码:(\d+).*?标题:(.+)', line)
            if title_match:
                url = title_match.group(1)
                title = title_match.group(3).strip()

                # 检查版本信息
                version_match = re.search(r'(\w+)/([\d.]+)', title)
                if version_match:
                    vulnerabilities.append({
                        "url": url,
                        "type": "fingerprint",
                        "name": version_match.group(1),
                        "version": version_match.group(2),
                        "severity": "info",
                        "info": f"检测到 {title}"
                    })
                continue

            # 漏洞发现
            if '[+]' in line and 'http' in line.lower():
                vuln_info = line.split('[+]')[-1].strip()
                vulnerabilities.append({
                    "url": vuln_info.split()[0] if ' ' in vuln_info else vuln_info,
                    "type": "vulnerability",
                    "severity": "high",
                    "info": vuln_info
                })

        return vulnerabilities