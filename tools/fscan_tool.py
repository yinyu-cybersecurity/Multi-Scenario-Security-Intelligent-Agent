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

使用 NetworkScanTool 基类，复用验证逻辑
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

    继承 NetworkScanTool 基类，复用：
    - validate_target: 目标验证
    - validate_ports: 端口验证
    - ai_analyze_results: AI 分析框架

    CTF场景特点:
    - 快速端口发现
    - 自动漏洞识别
    - 弱口令爆破
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
        self.timeout = 600  # 10分钟超时，网段扫描较慢

    def name(self) -> str:
        return "fscan"

    def description(self) -> str:
        return "内网综合扫描工具，支持端口扫描、服务识别、弱口令爆破、漏洞检测。比nmap更快更全面。"

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
        return "内网综合扫描工具。输入IP或网段，快速发现端口、服务、弱口令、未授权访问。适合：内网渗透、资产发现、权限维持后的横向移动。"

    def check_available(self) -> bool:
        """检查 fscan 是否可用"""
        if self.executable:
            return True
        try:
            # fscan 不带参数会显示帮助
            result = subprocess.run(
                ["fscan"],
                capture_output=True,
                timeout=10
            )
            # fscan 显示帮助时返回码可能是1，但有输出就说明工具存在
            output = result.stdout.decode('utf-8', errors='ignore') + result.stderr.decode('utf-8', errors='ignore')
            if "fscan" in output.lower() or "usage" in output.lower() or result.returncode in [0, 1]:
                self.executable = "fscan"
                return True
            return False
        except FileNotFoundError:
            print("[Warning] fscan not found. Install: go install github.com/shadow1ng/fscan@latest")
            return False
        except Exception:
            return True  # 超时等错误，但工具可能存在

    def expected_params(self) -> Dict[str, Dict[str, Any]]:
        return {
            "target": {
                "type": "str",
                "description": "目标IP、CIDR网段 (如 192.168.1.1, 10.10.10.0/24)",
                "required": True
            },
            "ports": {
                "type": "str",
                "description": "端口范围，如 '21,22,80,443,3306,3389' 或 '1-65535'，默认常用端口",
                "required": False,
                "default": "21,22,23,25,80,81,88,110,135,139,443,445,1433,1521,3306,3389,5432,6379,7001,8000,8080,8443,8888,9000,9090,27017"
            },
            "scan_type": {
                "type": "str",
                "description": "扫描类型: 'quick'(快速常用端口), 'full'(全端口), 'web'(Web端口)",
                "required": False,
                "default": "quick"
            },
            "mode": {
                "type": "str",
                "description": "扫描模式: 'web'(Web扫描-URL模式), 'network'(网络扫描-IP模式)",
                "required": False,
                "default": "network"
            },
            "brute": {
                "type": "bool",
                "description": "是否启用弱口令爆破",
                "required": False,
                "default": True
            },
            "no_ping": {
                "type": "bool",
                "description": "跳过存活检测，直接扫描",
                "required": False,
                "default": False
            }
        }

    def execute(self, target: str, params: Dict) -> Dict:
        """
        执行 fscan 扫描
        """
        target = params.get("target") or target
        if not target:
            return {"error": "必须提供目标", "success": False}

        # 构建命令
        cmd = [self.executable or "fscan"]

        # 检测是否是URL格式
        is_url = target.startswith("http://") or target.startswith("https://")

        if is_url:
            # URL扫描模式
            cmd.extend(["-u", target])
        else:
            # IP/网段扫描模式
            # 验证目标格式
            is_valid, error_msg = self.validate_target(target)
            if not is_valid:
                return {"error": f"目标验证失败: {error_msg}", "success": False}
            cmd.extend(["-h", target])

        # 端口
        scan_type = params.get("scan_type", "quick")
        ports = params.get("ports")

        if ports:
            # 验证端口参数
            is_valid_ports, ports_error = self.validate_ports(ports)
            if not is_valid_ports:
                return {"success": False, "error": f"端口参数验证失败: {ports_error}"}
            cmd.extend(["-p", ports])
        elif scan_type == "full":
            cmd.extend(["-p", "1-65535"])
        elif scan_type == "web":
            cmd.extend(["-p", "80,81,88,443,8000,8080,8443,8888,9000,9090,3000,5000"])
        # quick 使用默认端口

        # 跳过存活检测（CTF场景通常需要）
        if params.get("no_ping", False):
            cmd.append("-np")

        # 弱口令爆破
        if params.get("brute", True):
            # fscan 默认开启爆破，这里不需要额外参数
            pass

        print(f"[Fscan] Executing: {' '.join(cmd)}")

        try:
            raw_result = self._run_command(cmd, timeout=self.timeout)
            stdout = raw_result.get("stdout", "")
            stderr = raw_result.get("stderr", "")

            if not stdout and "error" in raw_result:
                return {
                    "success": False,
                    "error": raw_result.get("error"),
                    "command": ' '.join(cmd)
                }

            # 根据扫描模式解析结果
            if is_url:
                # Web扫描模式 - 解析Web扫描结果
                vulns = self._parse_web_output(stdout + "\n" + stderr)
                return {
                    "success": True,
                    "vulnerable": len(vulns) > 0,
                    "target": target,
                    "command": raw_result.get('command', ''),
                    "vulnerabilities": vulns,
                    "total_found": len(vulns),
                    "raw_output": stdout[:5000] if len(stdout) > 5000 else stdout
                }
            else:
                # 网络扫描模式
                hosts, parsed_vulns = self._parse_output(stdout + "\n" + stderr)
                analysis = self._analyze_results(hosts, target, parsed_vulns)

                has_vulnerabilities = len(parsed_vulns) > 0 or len(analysis.get("vulnerabilities", [])) > 0
                has_hosts = len(hosts) > 0

                return {
                    "success": True,
                    "vulnerable": has_vulnerabilities or has_hosts,
                    "target": target,
                    "command": raw_result.get('command', ''),
                    "hosts": hosts,
                    "summary": analysis.get("summary", ""),
                    "vulnerabilities": parsed_vulns + analysis.get("vulnerabilities", []),
                    "recommendations": analysis.get("recommendations", []),
                    "raw_output": stdout[:5000] if len(stdout) > 5000 else stdout
                }

        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "target": target
            }

    def _parse_output(self, output: str) -> Tuple[List[Dict], List[Dict]]:
        """使用AI解析fscan输出"""
        from tool_output_parser import parse_output

        result = parse_output("fscan", output, "")

        hosts = result.get("hosts", [])
        vulnerabilities = result.get("vulnerabilities", [])

        return hosts, vulnerabilities

    def _parse_web_output(self, output: str) -> List[Dict]:
        """解析fscan Web扫描输出"""
        vulnerabilities = []
        lines = output.split('\n')

        # Web扫描输出格式:
        # [900ms] [*] 网站标题 https://example.com 状态码:200 长度:1234 标题:Apache Tomcat/9.0.97
        # [+] https://example.com 存在漏洞

        title_pattern = re.compile(r'网站标题\s+(\S+)\s+状态码:(\d+).*?标题:(.+)')
        vuln_pattern = re.compile(r'\[\+\]\s*(.+)')

        for line in lines:
            line = line.strip()
            if not line:
                continue

            # 解析标题信息（指纹识别）
            title_match = title_pattern.search(line)
            if title_match:
                url = title_match.group(1)
                status = title_match.group(2)
                title = title_match.group(3).strip()

                # 检查标题中是否包含版本信息
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

            # 解析漏洞信息
            vuln_match = vuln_pattern.match(line)
            if vuln_match:
                vuln_info = vuln_match.group(1).strip()
                vulnerabilities.append({
                    "url": vuln_info.split()[0] if ' ' in vuln_info else vuln_info,
                    "type": "vulnerability",
                    "severity": "high",
                    "info": vuln_info
                })

        return vulnerabilities

    def _analyze_results(self, hosts: List[Dict], target: str, parsed_vulns: List[Dict] = None) -> Dict:
        """AI分析扫描结果"""
        parsed_vulns = parsed_vulns or []

        if not hosts and not parsed_vulns:
            return {
                "summary": "未发现存活主机或漏洞",
                "vulnerabilities": [],
                "recommendations": []
            }

        # 如果已经有解析出的漏洞，直接返回
        if parsed_vulns:
            summary = f"发现 {len(parsed_vulns)} 个漏洞"
            return {
                "summary": summary,
                "vulnerabilities": [],  # 漏洞已在 parsed_vulns 中
                "recommendations": []
            }

        if not hosts:
            return {
                "summary": "未发现存活主机",
                "vulnerabilities": [],
                "recommendations": []
            }

        # 统计信息
        total_ports = sum(len(h.get("ports", [])) for h in hosts)

        # 构建摘要
        summary_lines = []
        for host in hosts[:10]:
            ports_str = ", ".join([f"{p['port']}/{p.get('service', '?')}" for p in host.get("ports", [])[:10]])
            summary_lines.append(f"{host['ip']}: [{ports_str}]")

        prompt = f"""
分析内网扫描结果，识别攻击路径和漏洞利用点。

## 扫描目标
{target}

## 发现的主机 ({len(hosts)}台，{total_ports}个开放端口)
{chr(10).join(summary_lines)}

## 分析要求
1. 识别高价值目标（域控、数据库、文件服务器）
2. 发现可能的漏洞入口
3. 推荐攻击路径

## 输出格式 (JSON)
{{
  "summary": "一句话总结",
  "high_value_targets": ["IP列表"],
  "vulnerabilities": [
    {{"ip": "IP", "port": 端口, "type": "漏洞类型", "severity": "高/中/低"}}
  ],
  "recommendations": [
    {{"target": "IP:端口", "method": "攻击方法", "reason": "原因"}}
  ]
}}
"""

        try:
            analysis = llm_client.call_chat_completion(
                model=config.ANALYST_MODEL,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.1,
                json_mode=True
            )

            if "```json" in analysis:
                analysis = analysis.split("```json")[1].split("```")[0]

            return json.loads(analysis.strip())

        except Exception:
            return {
                "summary": f"发现 {len(hosts)} 台主机，{total_ports} 个开放端口",
                "vulnerabilities": [],
                "recommendations": []
            }