# -*- coding: utf-8 -*-
from typing import List, Dict
import json


def smart_truncate_output(output: str, max_length: int = 300) -> str:
    """
    智能截断输出，保留关键信息

    优先保留:
    1. 错误信息
    2. flag相关内容
    3. 前部和后部内容
    """
    if not output or len(output) <= max_length:
        return output

    output_lower = output.lower()

    # 检查是否包含错误
    if "error" in output_lower or "fail" in output_lower:
        # 保留错误部分
        return "... " + output[-max_length+20:]

    # 检查是否包含flag
    if "flag" in output_lower:
        flag_pos = output_lower.find("flag")
        start = max(0, flag_pos - 50)
        end = min(len(output), flag_pos + max_length - 50)
        return "... " + output[start:end] + " ..."

    # 默认保留前部和后部
    half = max_length // 2
    return output[:half] + " ... " + output[-half:]


def get_relevant_payloads(vuln_candidates: List[Dict], limit: int = 5) -> str:
    """
    根据漏洞类型获取相关 Payload 参考

    Args:
        vuln_candidates: 漏洞候选列表
        limit: 每种漏洞类型的 Payload 数量限制

    Returns:
        格式化的 Payload 参考字符串
    """
    try:
        from payload_loader import payload_loader

        if not payload_loader.is_available():
            return ""

        payload_sections = []
        seen_types = set()

        for vuln in vuln_candidates[:5]:  # 最多处理5个候选
            vuln_type = vuln.get("type", "").lower()

            # 标准化漏洞类型
            type_mapping = {
                "sql": "sql_injection",
                "sqli": "sql_injection",
                "xss": "xss",
                "ssti": "ssti",
                "template": "ssti",
                "xxe": "xxe",
                "ssrf": "ssrf",
                "lfi": "lfi",
                "traversal": "path_traversal",
                "rce": "rce",
                "deserialization": "deserialization",
            }

            std_type = None
            for key, val in type_mapping.items():
                if key in vuln_type:
                    std_type = val
                    break

            if std_type and std_type not in seen_types:
                seen_types.add(std_type)
                payloads = payload_loader.load_payloads(std_type, limit=limit)
                if payloads:
                    payload_str = "\n".join([f"  - {p[:100]}" for p in payloads[:limit]])
                    payload_sections.append(f"**{vuln_type.upper()} Payload 参考**:\n{payload_str}")

        if payload_sections:
            return "\n\n".join(payload_sections)
        return ""

    except Exception as e:
        return ""


def get_attacker_prompt(vuln_candidates: List[Dict], tool_definitions: str,
                        attack_history: List[Dict] = None,
                        task_info: Dict = None,
                        tactical_guidance: str = None,
                        analyst_intel: str = None,
                        known_facts: str = None,
                        failed_payloads: List[str] = None,
                        human_hint: str = None,
                        include_payloads: bool = True) -> str:
    """
    [P3优化版] 生成攻击兵提示词
    移除了 reflector_guidance，由 verifier 统一输出 tactical_guidance
    增加了 Payload 参考支持
    """
    # 历史攻击记录
    history_desc = "无"
    if attack_history:
        lines = []
        for h in attack_history[-5:]:
            tool = h.get("tool", "?")
            status = h.get("status", "?")
            output = smart_truncate_output(str(h.get("output", "")), max_length=300)
            lines.append(f"- {tool}: status={status}, output={output}")
        history_desc = "\n".join(lines)

    # 题目背景
    task_desc = ""
    if task_info:
        task_desc = f"题目: {task_info.get('name', 'Unknown')}\n目标: {task_info.get('current_url', 'N/A')}"

    # 已知事实
    facts_desc = ""
    if known_facts:
        facts_desc = f"\n已知事实: {known_facts}"

    # 战术指引
    guidance_desc = ""
    if tactical_guidance:
        guidance_desc = f"\n战术建议: {tactical_guidance}"

    # 人工提示
    hint_desc = ""
    if human_hint:
        hint_desc = f"""

## ⚠️ 人工指导（必须遵循）
{human_hint}
请严格按照以上人工指导生成攻击动作！
"""

    # 失败payload列表 - 必须避免重复
    failed_desc = ""
    if failed_payloads:
        failed_items = "\n".join([f"- {p[:100]}" for p in failed_payloads[-20:]])
        failed_desc = f"""
## ⛔ 已失败的Payload（严禁重复）
以下payload已被证明无效，请勿再次尝试：
{failed_items}
"""

    # 获取相关 Payload 参考
    payload_ref = ""
    if include_payloads and vuln_candidates:
        payload_ref = get_relevant_payloads(vuln_candidates)

    return f"""# CTF 攻击手

## 目标
获取 FLAG

## 任务
{task_desc}
{guidance_desc}
{hint_desc}

## 分析情报
{analyst_intel if analyst_intel else "无"}
{facts_desc}

## 攻击目标
{json.dumps(vuln_candidates, ensure_ascii=False, indent=2)}

**关键：优先使用每个候选点的recommended_tools！** 不要随意换工具。
- 如果recommended_tools=["sqlmap"]，就用sqlmap
- 如果recommended_tools=["requests"]，就用requests直接访问
- 只有推荐工具失败时，才考虑替代方案

## 历史攻击
{history_desc}
{failed_desc}

## 可用工具
{tool_definitions}

{payload_ref}



涉及精确计算的场景必须使用 `python-exec` 工具写脚本执行，不要自己猜测：

1. **编码解码**: base64、URL编码、十六进制、Unicode、ROT13等
   ```json
   {{"tool": "python-exec", "params": {{"code": "import base64; result = base64.b64decode('XXXXX').decode()", "description": "base64解码"}}}}
   ```

2. **加密解密**: MD5、SHA、AES等哈希或加密操作


**错误示例** ❌: 看到 base64 就直接脑补解码结果
**正确示例** ✅: 用 python-exec 写脚本精确解码

## ⚠️ 关键提示：发现新路径立即访问！

当解码或分析结果中**发现新的文件路径**时（如 `/test2222222222222222.php`）：
1. **立即用 requests 工具直接访问该URL**
2. URL格式: `http://目标域名/新路径`
3. **不要继续证明漏洞存在**，去新路径寻找FLAG！

示例：
```json
{{"tool": "requests", "params": {{"method": "GET", "url": "http://node7.anna.nssctf.cn:22856/test2222222222222222.php"}}, "reasoning": "访问新发现的路径"}}
```

## 输出要求
返回 JSON，包含 attack_actions 数组，每个动作包含 tool、params、reasoning 字段。

示例:
{{"attack_actions": [{{"tool": "requests", "params": {{"method": "POST", "url": "..."}}, "reasoning": "原因"}}]}}

**重要**: attack_actions 不能为空，必须根据漏洞候选生成攻击动作。
"""