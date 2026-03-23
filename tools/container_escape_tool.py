# tools/container_escape_tool.py
# Container Escape Checker - 容器逃逸检测工具
import os
import json
import subprocess
from typing import Dict, Any
from tool_framework import CommandLineTool


class ContainerEscapeTool(CommandLineTool):
    """
    Container Escape Checker 封装
    检测 Docker 容器逃逸风险
    """

    def __init__(self):
        cmd = "python3" if os.path.exists("/.dockerenv") else "python"
        super().__init__(cmd)
        self.timeout = 60

    def name(self) -> str:
        return "container-escape-checker"

    def description(self) -> str:
        return "容器逃逸检测工具，检测 Docker 容器配置错误和逃逸风险"

    def supported_vulns(self) -> list:
        return ["Container Escape", "Docker Breakout", "Privilege Escalation", "Container Security"]

    def check_available(self) -> bool:
        # 在容器内或主机上都可以运行
        return True

    def expected_params(self) -> Dict[str, Dict[str, Any]]:
        return {
            "check_type": {
                "type": "str",
                "description": "检查类型: all (全部), capabilities (能力), mounts (挂载), devices (设备), network (网络)",
                "required": False,
                "default": "all"
            },
            "detailed": {
                "type": "bool",
                "description": "是否输出详细信息",
                "required": False,
                "default": False
            }
        }

    def execute(self, target: str, params: Dict) -> Dict:
        check_type = params.get("check_type", "all")
        detailed = params.get("detailed", False)

        results = {
            "success": True,
            "vulnerable": False,
            "check_type": check_type,
            "findings": [],
            "summary": "容器逃逸检测完成"
        }

        try:
            # 检查是否在容器中
            in_container = os.path.exists("/.dockerenv")

            if not in_container:
                results["findings"].append({
                    "type": "info",
                    "message": "不在容器环境中运行"
                })
                return results

            results["in_container"] = True

            # 1. 检查特权模式
            if check_type in ["all", "capabilities"]:
                try:
                    with open("/proc/self/status", "r") as f:
                        status = f.read()
                        if "CapEff:" in status:
                            cap_line = [l for l in status.split("\n") if l.startswith("CapEff:")][0]
                            caps = cap_line.split(":")[1].strip()
                            # 检查是否有过多权限
                            if caps != "0000000000000000":
                                results["findings"].append({
                                    "type": "warning",
                                    "message": f"容器具有额外能力: {caps}",
                                    "risk": "medium"
                                })
                                results["vulnerable"] = True
                except Exception:
                    pass

            # 2. 检查挂载点
            if check_type in ["all", "mounts"]:
                try:
                    with open("/proc/mounts", "r") as f:
                        mounts = f.read()
                        dangerous_mounts = [
                            ("/var/run/docker.sock", "Docker socket 挂载 - 可能导致宿主机控制"),
                            ("/etc/passwd", "passwd 文件挂载 - 可能导致用户操作"),
                            ("/etc/shadow", "shadow 文件挂载 - 可能导致密码获取"),
                            ("/root", "root 目录挂载 - 高风险"),
                            ("/var/lib/docker", "Docker 数据目录挂载"),
                            ("/", "宿主机根目录挂载 - 极高风险")
                        ]
                        for mount_path, risk_msg in dangerous_mounts:
                            if mount_path in mounts:
                                results["findings"].append({
                                    "type": "critical",
                                    "message": risk_msg,
                                    "mount": mount_path,
                                    "risk": "high"
                                })
                                results["vulnerable"] = True
                except Exception:
                    pass

            # 3. 检查设备
            if check_type in ["all", "devices"]:
                try:
                    with open("/proc/self/mountinfo", "r") as f:
                        mountinfo = f.read()
                        if "/dev" in mountinfo:
                            results["findings"].append({
                                "type": "warning",
                                "message": "设备目录挂载 - 可能访问敏感设备",
                                "risk": "medium"
                            })
                except Exception:
                    pass

            # 4. 检查网络模式
            if check_type in ["all", "network"]:
                try:
                    # 检查是否使用 host 网络
                    with open("/proc/net/dev", "r") as f:
                        net_devs = f.read()
                        if "docker0" not in net_devs and "eth0" in net_devs:
                            # 可能是 host 网络模式
                            results["findings"].append({
                                "type": "warning",
                                "message": "可能使用 host 网络模式",
                                "risk": "medium"
                            })
                except Exception:
                    pass

            # 5. 检查敏感环境变量
            try:
                with open("/proc/self/environ", "r") as f:
                    env = f.read()
                    sensitive_keywords = ["AWS", "SECRET", "PASSWORD", "TOKEN", "KEY", "API"]
                    for kw in sensitive_keywords:
                        if kw in env.upper():
                            results["findings"].append({
                                "type": "info",
                                "message": f"发现可能敏感的环境变量包含: {kw}",
                                "risk": "low"
                            })
            except Exception:
                pass

            # 汇总风险等级
            risk_counts = {"high": 0, "medium": 0, "low": 0}
            for f in results["findings"]:
                risk = f.get("risk", "low")
                risk_counts[risk] = risk_counts.get(risk, 0) + 1

            results["risk_summary"] = risk_counts
            results["summary"] = f"发现 {risk_counts['high']} 个高危、{risk_counts['medium']} 个中危、{risk_counts['low']} 个低危问题"

            return results

        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "vulnerable": False,
                "summary": f"检测失败: {str(e)}"
            }