# app/tool_output_parser.py
"""
工具输出AI解析器
- 所有工具输出直接交给AI解析
- DeepSeek API 128k上下文足够大
- 统一输出格式，方便后续处理
"""

import json
import re
from typing import Dict, List, Optional
from llm_client import llm_client
from config import config


class ToolOutputParser:
    """AI驱动的工具输出解析器"""

    # 漏洞类型映射
    VULN_TYPES = [
        "rce", "sqli", "xss", "lfi", "rfi", "ssrf", "xxe",
        "weak_password", "unauthorized", "deserialization",
        "ssti", "csrf", "ssrf", "file_upload", "command_injection"
    ]

    # 严重程度
    SEVERITY_LEVELS = ["critical", "high", "medium", "low", "info"]

    def parse(self, tool_name: str, output: str, target: str = "") -> dict:
        """
        解析工具输出 - 完全交给AI

        Args:
            tool_name: 工具名称
            output: 原始输出（不截断）
            target: 目标地址

        Returns:
            标准化结果
        """
        if not output or len(output.strip()) < 10:
            return self._empty_result(tool_name, "输出为空")

        prompt = f"""分析以下安全工具输出，提取所有关键信息。

## 工具
{tool_name}

## 目标
{target}

## 输出
```
{output}
```

## 提取内容
1. 所有主机：IP、端口、服务、操作系统、主机名、是否域控
2. 所有漏洞：类型、目标、端口、严重程度、详细信息、POC名称、CVE编号
3. 所有凭据：用户名、密码/哈希、服务类型
4. 域信息：域名、域控IP
5. 攻击建议：优先级排序的攻击路径

## JSON输出
{{
  "success": true,
  "summary": "关键发现的一句话总结",
  "hosts": [
    {{"ip": "x.x.x.x", "hostname": "", "os": "", "is_dc": false, "domain": "", "ports": [{{"port": 80, "service": "http", "state": "open"}}]}}
  ],
  "vulnerabilities": [
    {{"type": "rce", "target": "x.x.x.x", "port": 80, "severity": "high", "info": "详情", "poc": "poc名称", "cve": ""}}
  ],
  "credentials": [
    {{"username": "admin", "password": "123456", "hash": "", "service": "ssh", "target": "x.x.x.x"}}
  ],
  "domain_info": {{"domain": "", "dc_ip": ""}},
  "attack_paths": [
    {{"target": "x.x.x.x:80", "method": "利用方法", "priority": 1, "reason": "原因"}}
  ]
}}

只输出JSON。"""

        try:
            response = llm_client.call_chat_completion(
                model=config.ANALYST_MODEL,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.1,
                json_mode=True
            )

            # 提取JSON
            if "```json" in response:
                response = response.split("```json")[1].split("```")[0]
            elif "```" in response:
                response = response.split("```")[1].split("```")[0]

            data = json.loads(response.strip())

            return {
                "success": data.get("success", True),
                "tool": tool_name,
                "target": target,
                "summary": data.get("summary", ""),
                "hosts": data.get("hosts", []),
                "vulnerabilities": data.get("vulnerabilities", []),
                "credentials": data.get("credentials", []),
                "domain_info": data.get("domain_info", {}),
                "attack_paths": data.get("attack_paths", []),
                "raw_output": output[:2000] if len(output) > 2000 else output
            }

        except Exception as e:
            return {
                "success": False,
                "tool": tool_name,
                "target": target,
                "summary": f"解析失败: {str(e)}",
                "hosts": [],
                "vulnerabilities": [],
                "credentials": [],
                "domain_info": {},
                "attack_paths": [],
                "raw_output": output[:2000] if len(output) > 2000 else output,
                "error": str(e)
            }

    def _empty_result(self, tool_name: str, reason: str) -> dict:
        return {
            "success": False,
            "tool": tool_name,
            "target": "",
            "summary": reason,
            "hosts": [],
            "vulnerabilities": [],
            "credentials": [],
            "domain_info": {},
            "attack_paths": [],
            "error": reason
        }


# 全局实例
_parser = None

def parse_output(tool_name: str, output: str, target: str = "") -> dict:
    """解析工具输出"""
    global _parser
    if _parser is None:
        _parser = ToolOutputParser()
    return _parser.parse(tool_name, output, target)


def wrap_tool_result(tool_name: str, target: str, raw_result: dict) -> dict:
    """
    包装工具执行结果，自动AI解析

    用法：
        raw_result = tool.execute(target, params)
        return wrap_tool_result("fscan", target, raw_result)

    Args:
        tool_name: 工具名称
        target: 目标
        raw_result: 工具原始返回结果

    Returns:
        AI解析后的标准化结果
    """
    # 如果已经有结构化结果，直接返回
    if raw_result.get("vulnerabilities") or raw_result.get("hosts"):
        return raw_result

    # 提取原始输出
    output = raw_result.get("raw_output", "") or raw_result.get("output", "") or str(raw_result)

    # AI解析
    parsed = parse_output(tool_name, output, target)

    # 合并原始结果中的成功状态
    if raw_result.get("success"):
        parsed["success"] = True

    return parsed