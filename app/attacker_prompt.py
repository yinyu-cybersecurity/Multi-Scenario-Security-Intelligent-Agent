# -*- coding: utf-8 -*-
from typing import List, Dict
import json


def get_attacker_prompt(vuln_candidates: List[Dict], tool_definitions: str,
                        attack_history: List[Dict] = None,
                        task_info: Dict = None,
                        tactical_guidance: str = None,
                        analyst_intel: str = None,
                        known_facts: str = None,
                        failed_payloads: List[str] = None,
                        human_hint: str = None) -> str:
    """
    [P3优化版] 生成攻击兵提示词
    移除了 reflector_guidance，由 verifier 统一输出 tactical_guidance
    """
    # 历史攻击记录
    history_desc = "无"
    if attack_history:
        lines = []
        for h in attack_history[-5:]:
            tool = h.get("tool", "?")
            status = h.get("status", "?")
            output = str(h.get("output", ""))[:100]
            lines.append(f"- {tool}: status={status}, output={output}...")
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

## 历史攻击
{history_desc}
{failed_desc}

## 可用工具
{tool_definitions}



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