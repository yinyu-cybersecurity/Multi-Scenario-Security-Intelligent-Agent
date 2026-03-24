# tools/bloodhound_tool.py
"""
BloodHound Tool - AD域分析工具适配
适配自 Zen-Ai-Pentest 的 bloodhound_integration.py

功能:
- AD域信息收集
- 攻击路径分析
- 权限关系可视化

CTF场景优化:
- 快速数据采集
- 自动化分析
"""
import re
import sys
import json
import shutil
import subprocess
from typing import Dict, Any, Optional, List
from tool_framework import CommandLineTool
from llm_client import llm_client
from config import config


class BloodHoundTool(CommandLineTool):
    """
    BloodHound AD域分析工具封装
    """

    def __init__(self):
        # 检测 bloodhound-python 是否可用
        self.executable = shutil.which("bloodhound-python")

        if self.executable:
            self.cmd_path = self.executable
        else:
            self.cmd_path = "bloodhound-python"

        super().__init__(self.cmd_path)
        self.timeout = 600

    def name(self) -> str:
        return "bloodhound"

    def description(self) -> str:
        return "AD域攻击路径分析工具，发现权限提升路径。"

    def supported_vulns(self) -> list:
        return [
            "AD Enumeration",
            "Kerberos Attack",
            "Privilege Escalation",
            "Lateral Movement",
            "Domain Trust"
        ]

    def check_available(self) -> bool:
        if self.executable:
            return True
        try:
            result = subprocess.run(
                ["bloodhound-python", "--help"],
                capture_output=True,
                timeout=10
            )
            return result.returncode == 0
        except:
            return False

    def expected_params(self) -> Dict[str, Dict[str, Any]]:
        return {
            "domain": {
                "type": "str",
                "description": "目标域名 (如 corp.local)",
                "required": True
            },
            "dc": {
                "type": "str",
                "description": "域控制器IP",
                "required": True
            },
            "username": {
                "type": "str",
                "description": "用户名",
                "required": True
            },
            "password": {
                "type": "str",
                "description": "密码",
                "required": False,
                "default": None
            },
            "hash": {
                "type": "str",
                "description": "NTLM哈希",
                "required": False,
                "default": None
            },
            "collection": {
                "type": "str",
                "description": "收集方法: 'all', 'group', 'localadmin', 'session', 'trust', 'acl', 'container'",
                "required": False,
                "default": "all"
            },
            "output_dir": {
                "type": "str",
                "description": "输出目录",
                "required": False,
                "default": "data/bloodhound"
            }
        }

    def execute(self, target: str, params: Dict) -> Dict:
        domain = params.get("domain")
        dc = params.get("dc") or target
        username = params.get("username")
        password = params.get("password")
        hash_val = params.get("hash")
        collection = params.get("collection", "all")
        output_dir = params.get("output_dir", "data/bloodhound")

        if not all([domain, dc, username]):
            return {"error": "必须提供 domain, dc, username", "success": False}

        if not password and not hash_val:
            return {"error": "必须提供 password 或 hash", "success": False}

        cmd = [
            self.cmd_path,
            "-d", domain,
            "-dc", dc,
            "-u", username,
            "-c", collection,
            "--outputfolder", output_dir
        ]

        if password:
            cmd.extend(["-p", password])
        elif hash_val:
            cmd.extend(["--hash", hash_val])

        try:
            result = self._run_command(cmd, timeout=self.timeout)
            stdout = result.get("stdout", "")
            stderr = result.get("stderr", "")

            # 检查是否成功采集数据
            success = result.get("success", False)

            # 检查输出文件是否存在
            import os
            json_files = []
            if os.path.exists(output_dir):
                json_files = [f for f in os.listdir(output_dir) if f.endswith('.json')]

            # 判断是否有发现（有输出文件表示成功）
            vulnerable = success and len(json_files) > 0

            # AI分析结果
            analysis_result = {}
            if success and stdout:
                analysis_result = self._analyze_bloodhound_output(stdout + "\n" + stderr, domain, json_files)

            return {
                "success": success,
                "vulnerable": vulnerable,
                "domain": domain,
                "output_dir": output_dir,
                "json_files": json_files,
                "summary": analysis_result.get("summary", f"BloodHound采集完成，生成 {len(json_files)} 个JSON文件"),
                "attack_paths": analysis_result.get("attack_paths", []),
                "high_value_targets": analysis_result.get("high_value_targets", []),
                "recommendations": analysis_result.get("recommendations", []),
                "stdout": stdout,
                "stderr": stderr
            }
        except Exception as e:
            return {"success": False, "vulnerable": False, "error": str(e)}

    def _analyze_bloodhound_output(self, output: str, domain: str, json_files: List[str]) -> Dict:
        """AI分析BloodHound输出"""
        if not output.strip():
            return {"summary": "无输出"}

        prompt = f"""
分析BloodHound AD域信息采集结果。

## 目标域
{domain}

## 采集结果
生成了 {len(json_files)} 个JSON文件: {', '.join(json_files[:10])}

## 输出日志
{output[:3000]}

## 分析要求
1. 识别域控和高价值目标
2. 发现可能的攻击路径
3. 推荐下一步行动

## 输出格式 (JSON)
{{
  "summary": "一句话总结",
  "attack_paths": [
    {{"from": "用户", "to": "目标", "type": "攻击类型", "edge": "关系"}}
  ],
  "high_value_targets": ["高价值目标列表"],
  "recommendations": [
    {{"target": "目标", "method": "方法", "reason": "原因"}}
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
            return {"summary": f"BloodHound采集完成，生成 {len(json_files)} 个JSON文件"}