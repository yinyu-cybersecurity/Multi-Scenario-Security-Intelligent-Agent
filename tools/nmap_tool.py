# tools/nmap_tool.py
"""
Nmap Tool - 网络扫描工具适配
适配自 Zen-Ai-Pentest 的 nmap_integration.py

功能:
- 端口扫描
- 服务识别
- OS检测
- NSE脚本扫描

CTF场景优化:
- 快速扫描模式
- 常用端口预设
- 自动解析输出

使用 NetworkScanTool 基类，复用验证逻辑
"""
import re
import json
import shutil
import xml.etree.ElementTree as ET
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from tool_framework import NetworkScanTool
from llm_client import llm_client
from config import config


@dataclass
class NmapPort:
    """端口扫描结果"""
    port: int
    protocol: str
    state: str
    service: str = ""
    version: str = ""
    banner: str = ""
    scripts: Dict[str, Any] = field(default_factory=dict)


@dataclass
class NmapHost:
    """主机扫描结果"""
    ip: str
    hostname: str = ""
    status: str = ""
    os_match: str = ""
    os_accuracy: int = 0
    ports: List[NmapPort] = field(default_factory=list)


class NmapTool(NetworkScanTool):
    """
    Nmap 网络扫描工具封装

    继承 NetworkScanTool 基类，复用：
    - validate_target: 目标验证
    - validate_ports: 端口验证
    - ai_analyze_results: AI 分析框架

    CTF场景特点:
    - 快速扫描优先
    - 常用端口预设
    - 自动服务识别
    - 漏洞脚本扫描
    """

    # 常用端口预设
    PORT_PRESETS = {
        "quick": "22,80,443,21,25,53,110,143,3306,3389,8080,8443",
        "web": "80,443,8080,8443,3000,5000,8000,8888,9000",
        "db": "1433,1521,3306,5432,6379,27017,9200,11211",
        "ad": "88,135,139,389,445,464,593,636,3268,3269,3389",
        "full": "1-65535",
        "top100": "22,80,443,21,25,53,110,143,993,995,135,139,445,23,161,162,389,636,989,990,1433,1521,1723,3306,3389,5432,5900,5901,5902,8080,8443,8888,9000,9999,10000,27017,28017"
    }

    def __init__(self):
        # 检测 nmap 是否可用
        self.executable = shutil.which("nmap")

        if self.executable:
            self.cmd_path = self.executable
        else:
            # 尝试常见路径
            common_paths = [
                "/usr/bin/nmap",
                "/usr/local/bin/nmap",
                "C:\\Program Files (x86)\\Nmap\\nmap.exe",
                "nmap"
            ]
            for path in common_paths:
                if shutil.which(path):
                    self.executable = path
                    self.cmd_path = path
                    break
            else:
                self.cmd_path = "nmap"  # 默认，可能在PATH中

        super().__init__(self.cmd_path)
        self.timeout = 300  # 5分钟超时

    def name(self) -> str:
        return "nmap"

    def description(self) -> str:
        return "网络端口扫描和服务识别工具，支持服务检测、OS识别和NSE脚本。"

    def supported_vulns(self) -> list:
        return [
            "Port Scan",
            "Service Detection",
            "OS Detection",
            "Network Reconnaissance",
            "Vulnerability Scan"
        ]

    def check_available(self) -> bool:
        """检查 nmap 是否可用"""
        if self.executable:
            return True
        # 尝试运行 nmap --version
        try:
            result = subprocess.run(
                ["nmap", "--version"],
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
                "description": "目标IP、主机名或CIDR网络 (如 192.168.1.1, scanme.nmap.org, 10.10.10.0/24)",
                "required": True
            },
            "ports": {
                "type": "str",
                "description": "端口规范: 'quick'(快速), 'web'(Web端口), 'db'(数据库), 'ad'(AD域), 'full'(全端口), 或自定义如 '80,443,8080'",
                "required": False,
                "default": "quick"
            },
            "scan_type": {
                "type": "str",
                "description": "扫描类型: 'syn'(TCP SYN,需root), 'connect'(TCP连接), 'udp', 'fast'(快速扫描)",
                "required": False,
                "default": "connect"
            },
            "service_detection": {
                "type": "bool",
                "description": "是否启用服务版本检测 (-sV)",
                "required": False,
                "default": True
            },
            "os_detection": {
                "type": "bool",
                "description": "是否启用OS识别 (-O, 需要root权限)",
                "required": False,
                "default": False
            },
            "script_scan": {
                "type": "str",
                "description": "NSE脚本扫描: 'default'(默认脚本), 'vuln'(漏洞脚本), 'safe'(安全脚本), 或自定义如 'http-title,smb-os-discovery'",
                "required": False,
                "default": None
            },
            "no_ping": {
                "type": "bool",
                "description": "跳过主机发现 (-Pn), 适用于被ICMP过滤的主机",
                "required": False,
                "default": True
            },
            "timing": {
                "type": "str",
                "description": "时序模板: 'paranoid'(T0), 'sneaky'(T1), 'polite'(T2), 'normal'(T3), 'aggressive'(T4), 'insane'(T5)",
                "required": False,
                "default": "aggressive"
            }
        }

    def execute(self, target: str, params: Dict) -> Dict:
        """
        执行 nmap 扫描
        """
        # 获取参数
        target = params.get("target") or target
        if not target:
            return {"error": "必须提供目标", "success": False}

        # [安全修复] 验证目标参数，防止命令注入
        is_valid, error_msg = self.validate_target(target)
        if not is_valid:
            return {"error": f"目标验证失败: {error_msg}", "success": False}

        ports = params.get("ports", "quick")
        scan_type = params.get("scan_type", "connect")
        service_detection = params.get("service_detection", True)
        os_detection = params.get("os_detection", False)
        script_scan = params.get("script_scan")
        no_ping = params.get("no_ping", True)
        timing = params.get("timing", "aggressive")

        # 构建命令
        cmd = [self.cmd_path]

        # 扫描类型
        if scan_type == "syn":
            cmd.append("-sS")
        elif scan_type == "connect":
            cmd.append("-sT")
        elif scan_type == "udp":
            cmd.append("-sU")
        elif scan_type == "fast":
            cmd.append("-F")  # 快速扫描，只扫常用端口
        else:
            cmd.append("-sT")  # 默认TCP连接扫描

        # 时序模板
        timing_map = {
            "paranoid": "-T0", "sneaky": "-T1", "polite": "-T2",
            "normal": "-T3", "aggressive": "-T4", "insane": "-T5"
        }
        cmd.append(timing_map.get(timing, "-T4"))

        # 跳过主机发现 (CTF场景中通常需要)
        if no_ping:
            cmd.append("-Pn")

        # 端口规范
        if ports in self.PORT_PRESETS:
            if ports == "full":
                cmd.extend(["-p", "-"])
            else:
                cmd.extend(["-p", self.PORT_PRESETS[ports]])
        else:
            # 验证自定义端口参数
            is_valid_ports, ports_error = self.validate_ports(ports)
            if not is_valid_ports:
                return {"success": False, "error": f"端口参数验证失败: {ports_error}"}
            cmd.extend(["-p", ports])

        # 服务检测
        if service_detection:
            cmd.append("-sV")

        # OS检测
        if os_detection:
            cmd.append("-O")

        # NSE脚本
        if script_scan:
            if script_scan == "default":
                cmd.append("-sC")
            elif script_scan == "vuln":
                cmd.extend(["--script", "vuln"])
            elif script_scan == "safe":
                cmd.extend(["--script", "safe"])
            else:
                cmd.extend(["--script", script_scan])

        # XML输出 (用于解析)
        cmd.extend(["-oX", "-"])

        # 添加目标
        cmd.append(target)

        try:
            # 执行扫描
            raw_result = self._run_command(cmd, timeout=self.timeout)
            stdout = raw_result.get("stdout", "")
            stderr = raw_result.get("stderr", "")

            if not stdout and "error" in raw_result:
                return {
                    "success": False,
                    "error": raw_result.get("error"),
                    "command": ' '.join(cmd)
                }

            # 解析XML输出
            hosts = self._parse_xml_output(stdout)

            # 生成摘要
            open_ports = []
            for host in hosts:
                for port in host.ports:
                    if port.state == "open":
                        open_ports.append({
                            "host": host.ip,
                            "port": port.port,
                            "protocol": port.protocol,
                            "service": port.service,
                            "version": port.version,
                            "scripts": port.scripts
                        })

            # 使用AI分析结果（对于复杂扫描）
            if len(open_ports) > 0 and (script_scan or service_detection):
                analysis = self._ai_analysis(target, hosts, open_ports, raw_result.get('command', ''))
            else:
                analysis = {
                    "summary": f"发现 {len(open_ports)} 个开放端口",
                    "recommendations": []
                }

            return {
                "success": True,
                "target": target,
                "command": raw_result.get('command', ''),
                "hosts": [{
                    "ip": h.ip,
                    "hostname": h.hostname,
                    "status": h.status,
                    "os_match": h.os_match,
                    "ports": [{
                        "port": p.port,
                        "protocol": p.protocol,
                        "state": p.state,
                        "service": p.service,
                        "version": p.version,
                        "scripts": p.scripts
                    } for p in h.ports]
                } for h in hosts],
                "open_ports": open_ports,
                "summary": analysis.get("summary", ""),
                "recommendations": analysis.get("recommendations", []),
                "stdout": stdout,  # 保留原始输出用于日志
                "stderr": stderr
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "target": target
            }

    def _parse_xml_output(self, xml_string: str) -> List[NmapHost]:
        """解析 nmap XML 输出"""
        hosts = []

        if not xml_string:
            return hosts

        try:
            root = ET.fromstring(xml_string)

            for host_elem in root.findall(".//host"):
                host = self._parse_host(host_elem)
                if host:
                    hosts.append(host)

        except ET.ParseError as e:
            # XML解析失败，尝试正则提取
            hosts = self._fallback_parse(xml_string)

        return hosts

    def _parse_host(self, host_elem: ET.Element) -> Optional[NmapHost]:
        """解析单个主机元素"""
        try:
            # 获取IP地址
            ip = ""
            for addr in host_elem.findall("address"):
                if addr.get("addrtype") == "ipv4":
                    ip = addr.get("addr", "")
                    break

            if not ip:
                return None

            host = NmapHost(ip=ip)

            # 获取主机名
            hostnames_elem = host_elem.find("hostnames")
            if hostnames_elem is not None:
                hostname = hostnames_elem.find("hostname")
                if hostname is not None:
                    host.hostname = hostname.get("name", "")

            # 获取状态
            status = host_elem.find("status")
            if status is not None:
                host.status = status.get("state", "")

            # 获取端口
            ports_elem = host_elem.find("ports")
            if ports_elem is not None:
                for port_elem in ports_elem.findall("port"):
                    port = self._parse_port(port_elem)
                    if port:
                        host.ports.append(port)

            # 获取OS信息
            os_elem = host_elem.find("os")
            if os_elem is not None:
                osmatch = os_elem.find("osmatch")
                if osmatch is not None:
                    host.os_match = osmatch.get("name", "")
                    host.os_accuracy = int(osmatch.get("accuracy", 0))

            return host

        except Exception:
            return None

    def _parse_port(self, port_elem: ET.Element) -> Optional[NmapPort]:
        """解析单个端口元素"""
        try:
            port_id = int(port_elem.get("portid", 0))
            protocol = port_elem.get("protocol", "tcp")

            state_elem = port_elem.find("state")
            state = state_elem.get("state", "") if state_elem is not None else "unknown"

            port = NmapPort(port=port_id, protocol=protocol, state=state)

            # 获取服务信息
            service = port_elem.find("service")
            if service is not None:
                port.service = service.get("name", "")
                port.version = service.get("version", "")
                if service.get("product"):
                    if port.version:
                        port.version = f"{service.get('product')} {port.version}"
                    else:
                        port.version = service.get("product", "")

            # 获取脚本结果
            for script in port_elem.findall("script"):
                script_id = script.get("id", "")
                script_output = script.get("output", "")
                port.scripts[script_id] = script_output

            return port

        except Exception:
            return None

    def _fallback_parse(self, xml_string: str) -> List[NmapHost]:
        """正则备用解析"""
        hosts = []

        # 提取开放端口
        port_pattern = re.compile(r'(\d+)/(tcp|udp)\s+open\s+(\S+)')
        ip_pattern = re.compile(r'Nmap scan report for ([^\s]+)')

        lines = xml_string.split('\n')
        current_ip = ""
        current_host = None

        for line in lines:
            # 提取IP
            ip_match = ip_pattern.search(line)
            if ip_match:
                if current_host and current_host.ports:
                    hosts.append(current_host)
                current_ip = ip_match.group(1)
                current_host = NmapHost(ip=current_ip, status="up")
                continue

            # 提取端口
            port_match = port_pattern.search(line)
            if port_match and current_host:
                port = NmapPort(
                    port=int(port_match.group(1)),
                    protocol=port_match.group(2),
                    state="open",
                    service=port_match.group(3)
                )
                current_host.ports.append(port)

        if current_host and current_host.ports:
            hosts.append(current_host)

        return hosts

    def _ai_analysis(self, target: str, hosts: List[NmapHost], open_ports: List[Dict], command: str) -> Dict:
        """使用AI分析扫描结果"""

        # 构建端口摘要
        port_summary = "\n".join([
            f"  - {p['port']}/{p['protocol']}: {p['service']} {p.get('version', '')}"
            for p in open_ports[:20]  # 限制数量
        ])

        # 构建脚本发现
        script_findings = []
        for p in open_ports:
            for script_id, output in p.get("scripts", {}).items():
                if output:
                    script_findings.append(f"  - Port {p['port']}: [{script_id}] {output[:200]}")

        prompt = f"""
分析 nmap 扫描结果，提取安全相关发现并给出下一步建议。

## 扫描目标
{target}

## 开放端口
{port_summary}

## NSE脚本发现
{chr(10).join(script_findings[:10]) if script_findings else '无脚本扫描结果'}

## 分析要求
1. 识别可能存在漏洞的服务版本
2. 推荐下一步渗透测试动作
3. 识别可能的攻击面

## 输出格式 (JSON)
{{
  "summary": "一句话总结扫描发现",
  "vulnerable_services": ["可疑服务列表"],
  "recommendations": [
    {{"tool": "推荐工具", "reason": "原因", "target_port": 端口号}},
    ...
  ],
  "attack_surface": ["攻击面分析"]
}}
"""

        try:
            analysis_text = llm_client.call_chat_completion(
                model=config.ANALYST_MODEL,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.1,
                json_mode=True
            )

            # 清理Markdown标记
            if "```json" in analysis_text:
                analysis_text = analysis_text.split("```json")[1].split("```")[0]
            elif "```" in analysis_text:
                analysis_text = analysis_text.split("```")[1].split("```")[0]

            return json.loads(analysis_text.strip())

        except Exception:
            return {
                "summary": f"发现 {len(open_ports)} 个开放端口",
                "recommendations": []
            }