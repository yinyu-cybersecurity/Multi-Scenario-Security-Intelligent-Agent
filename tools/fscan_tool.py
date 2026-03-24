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
"""
import re
import json
import shutil
import subprocess
from typing import Dict, Any, List
from tool_framework import CommandLineTool
from llm_client import llm_client
from config import config


class FscanTool(CommandLineTool):
    """
    Fscan 内网综合扫描工具封装

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
                "default": True
            }
        }

    def execute(self, target: str, params: Dict) -> Dict:
        """
        执行 fscan 扫描
        """
        target = params.get("target") or target
        if not target:
            return {"error": "必须提供目标", "success": False}

        # 验证目标格式
        is_valid, error_msg = self._validate_target(target)
        if not is_valid:
            return {"error": f"目标验证失败: {error_msg}", "success": False}

        # 构建命令
        cmd = [self.executable or "fscan"]

        # 目标
        cmd.extend(["-h", target])

        # 端口
        scan_type = params.get("scan_type", "quick")
        ports = params.get("ports")

        if ports:
            cmd.extend(["-p", ports])
        elif scan_type == "full":
            cmd.extend(["-p", "1-65535"])
        elif scan_type == "web":
            cmd.extend(["-p", "80,81,88,443,8000,8080,8443,8888,9000,9090,3000,5000"])
        # quick 使用默认端口

        # 跳过存活检测（CTF场景通常需要）
        if params.get("no_ping", True):
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

            # 解析结果
            hosts = self._parse_output(stdout + "\n" + stderr)

            # AI分析
            analysis = self._analyze_results(hosts, target)

            # [修复] 添加 vulnerable 字段到顶层
            has_vulnerabilities = len(analysis.get("vulnerabilities", [])) > 0
            has_hosts = len(hosts) > 0

            return {
                "success": True,
                "vulnerable": has_vulnerabilities or has_hosts,  # 发现漏洞或主机即视为有发现
                "target": target,
                "command": raw_result.get('command', ''),
                "hosts": hosts,
                "summary": analysis.get("summary", ""),
                "vulnerabilities": analysis.get("vulnerabilities", []),
                "recommendations": analysis.get("recommendations", []),
                "raw_output": stdout[:5000] if len(stdout) > 5000 else stdout
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "target": target
            }

    def _validate_target(self, target: str) -> tuple:
        """验证目标格式"""
        if not target or not isinstance(target, str):
            return False, "目标不能为空"

        target = target.strip()

        if len(target) > 256:
            return False, "目标长度超过限制"

        # 检查危险字符
        dangerous_chars = [';', '|', '&', '$', '`', '(', ')', '{', '}', '<', '>', '\n', '\r']
        for char in dangerous_chars:
            if char in target:
                return False, f"目标包含非法字符: {char}"

        # IP或CIDR验证
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$'
        if re.match(ip_pattern, target):
            return True, ""

        return True, ""  # 允许其他格式

    def _parse_output(self, output: str) -> List[Dict]:
        """解析fscan输出"""
        hosts = {}
        vulnerabilities = []

        lines = output.split('\n')

        # fscan 实际输出格式:
        # 39.98.115.11:22 open
        # [*] 39.98.115.11:22 SSH-2.0-OpenSSH_8.9p1
        # [*] [mysql] 39.98.115.11:3306 mysql weak password: root/
        # [+] 192.168.1.1:3306 mysql unauthorized

        # 端口开放: IP:port open
        port_pattern = re.compile(r'^(\d+\.\d+\.\d+\.\d+):(\d+)\s+open')
        # 服务信息: [*] IP:port service_info
        service_pattern = re.compile(r'\[\*\]\s*(\d+\.\d+\.\d+\.\d+):(\d+)\s+(.+)')
        # 漏洞发现: [*] [service] IP:port ... 或 [+] IP:port ...
        vuln_pattern = re.compile(r'\[\+\]|\[\*\]\s*\[\w+\]', re.IGNORECASE)
        weak_pwd_pattern = re.compile(r'weak\s*password[:\s]*(\S+?)/(\S*)', re.IGNORECASE)

        for line in lines:
            line = line.strip()
            if not line:
                continue

            # 1. 解析开放端口
            port_match = port_pattern.match(line)
            if port_match:
                ip = port_match.group(1)
                port = int(port_match.group(2))

                if ip not in hosts:
                    hosts[ip] = {"ip": ip, "ports": []}

                hosts[ip]["ports"].append({
                    "port": port,
                    "state": "open",
                    "service": ""
                })
                continue

            # 2. 解析服务信息
            service_match = service_pattern.match(line)
            if service_match:
                ip = service_match.group(1)
                port = int(service_match.group(2))
                info = service_match.group(3).strip()

                if ip not in hosts:
                    hosts[ip] = {"ip": ip, "ports": []}

                # 更新端口的服务信息
                port_entry = next((p for p in hosts[ip]["ports"] if p["port"] == port), None)
                if port_entry:
                    # 提取服务名
                    service_name = info.split()[0] if info else ""
                    if service_name.startswith("["):
                        # 格式: [mysql] ... 提取方括号内容
                        service_name = re.search(r'\[(\w+)\]', info)
                        service_name = service_name.group(1) if service_name else ""
                    port_entry["service"] = service_name.lower()
                else:
                    hosts[ip]["ports"].append({
                        "port": port,
                        "state": "open",
                        "service": info.split()[0].lower() if info else ""
                    })

                # 3. 检查是否包含漏洞信息
                if "weak password" in line.lower() or "weak_password" in line.lower():
                    weak_match = weak_pwd_pattern.search(line)
                    username = weak_match.group(1) if weak_match else "unknown"
                    password = weak_match.group(2).strip() if weak_match and weak_match.group(2) else ""
                    vulnerabilities.append({
                        "ip": ip,
                        "port": port,
                        "type": "weak_password",
                        "info": f"弱口令: {username}/{password}"
                    })
                elif "unauthorized" in line.lower():
                    vulnerabilities.append({
                        "ip": ip,
                        "port": port,
                        "type": "unauthorized",
                        "info": info
                    })
                elif "rce" in line.lower() or "vuln" in line.lower():
                    vulnerabilities.append({
                        "ip": ip,
                        "port": port,
                        "type": "vulnerability",
                        "info": info
                    })

        return list(hosts.values())

    def _analyze_results(self, hosts: List[Dict], target: str) -> Dict:
        """AI分析扫描结果"""
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