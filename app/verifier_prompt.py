# verifier_prompt.py - 核验兵提示词模板 [P3合并版]
import json
import re
from prompts.scene_framework import (
    get_encoding_tips,
    get_new_path_discovery_tips,
    get_success_criteria
)

# Base64 正则匹配
BASE64_PATTERN = re.compile(r'[A-Za-z0-9+/]{20,}={0,2}')

def get_verifier_prompt(attack_batch: list, results: list,
                        node_info: dict = None, known_facts: str = None,
                        stage_info: dict = None,
                        strategic_context: dict = None) -> str:
    """
    构建核验兵的 Prompt [简化版]
    """
    formatted_results = []
    for i, res in enumerate(results):
        raw_output = res.get("output") or res.get("result", {}).get("output", "N/A")
        content = raw_output

        # 尝试提取关键信息
        if isinstance(raw_output, str) and raw_output.startswith("{"):
            try:
                data = json.loads(raw_output)
                if "summary" in data:
                    content = data["summary"]
                elif "vulnerable" in data:
                    content = f"Vulnerable: {data.get('vulnerable')}\nSummary: {data.get('summary', '')}"
            except (json.JSONDecodeError, KeyError):
                pass  # JSON解析失败，使用原始输出

        # 检测并标注编码内容
        encoding_hints = []
        if isinstance(raw_output, str):
            # 检测 base64
            b64_matches = BASE64_PATTERN.findall(raw_output)
            if b64_matches:
                encoding_hints.append(f"🔍 发现可能的Base64编码: {b64_matches[0][:50]}...")
            # 检测 URL 编码
            if '%' in raw_output and re.search(r'%[0-9A-Fa-f]{2}', raw_output):
                encoding_hints.append("🔍 发现URL编码内容")
            # 检测十六进制
            if re.search(r'\b[0-9A-Fa-f]{20,}\b', raw_output):
                encoding_hints.append("🔍 发现可能的十六进制编码")

        if encoding_hints:
            content = content + "\n\n" + "\n".join(encoding_hints)

        formatted_results.append({
            "tool": res.get("tool", "unknown"),
            "payload": res.get("payload", "N/A"),  # 不截断，完整显示payload
            "status_code": res.get("status", "?"),
            "is_exploit": res.get("is_exploit", False),
            "diff_reason": res.get("diff_reason", ""),  # 新增：变化原因
            "response": str(content)[:2000]  # 增加响应长度
        })

    # 节点信息
    node_context = ""
    if node_info:
        node_context = f"""
## 节点状态
- 已尝试次数: {node_info.get('attempt_count', 0)}
- 持续时间: {node_info.get('duration_min', 0):.1f} 分钟
- 最近状态码: {node_info.get('recent_codes', [])}
"""

    # 已知事实
    facts_context = ""
    if known_facts:
        facts_context = f"""
## 已知事实
{known_facts}
"""

    # 阶段成功标准检查
    success_criteria_section = ""
    if stage_info and stage_info.get('success_criteria'):
        criteria_list = stage_info.get('success_criteria', [])
        criteria_text = '\n'.join(f'- {c}' for c in criteria_list) if isinstance(criteria_list, list) else f'- {criteria_list}'
        success_criteria_section = f"""
## 阶段成功标准
检查以下条件是否满足：
{criteria_text}

如果所有条件满足，应建议进入下一阶段。
"""

    # 战略上下文注入
    strategic_section = ""
    if strategic_context:
        attack_chain = strategic_context.get('attack_chain', [])
        current_step = strategic_context.get('current_step', 1)
        total_steps = strategic_context.get('total_steps', len(attack_chain))
        current_stage_name = attack_chain[current_step-1] if current_step <= len(attack_chain) else '未知'
        blockers = strategic_context.get('blockers', [])
        alternate_routes = strategic_context.get('alternate_routes', [])
        strategic_section = f"""
## 战略上下文
- 当前位置: {strategic_context.get('position_type', 'web')}
- 攻击链进度: 第{current_step}步/共{total_steps}步
- 当前阶段: {current_stage_name}
- 主要目标: {strategic_context.get('primary_goal', '获取FLAG')}
- 已知障碍: {', '.join(blockers) if blockers else '无'}
- 备选路径: {', '.join(alternate_routes) if alternate_routes else '无'}
"""

    # 获取共享的提示模块
    success_criteria = get_success_criteria()

    return f"""# CTF 核验官

## 任务
分析攻击结果，判断成功程度，决定后续策略。

## 已知事实
{facts_context}
{node_context}
{success_criteria_section}{strategic_section}
## 攻击结果
{json.dumps(formatted_results, indent=2, ensure_ascii=False)}

## 重要提示：精确处理

当响应中包含以下内容时，**必须**建议使用 `python-exec` 工具进行精确处理：
- Base64/URL编码/十六进制等编码内容 → 解码
- 需要精确计算（如字符数、哈希值）→ 计算
- 需要正则提取复杂内容 → 提取
- 任何容易出错的操作 → 写脚本执行

不要自己猜测解码结果，让 python-exec 工具执行！

## ⚠️ 关键：发现新路径必须访问！

当攻击结果中**发现新的文件路径或URL**时（如解码后得到 `/test2222222222222222.php`）：
1. **立即建议直接访问该URL**，如 `http://目标域名/test2222222222222222.php`
2. **不要继续证明漏洞存在**，应该去新路径寻找FLAG
3. 在 `tactical_guidance` 中明确写出完整的访问URL

错误示例: 继续用文件包含证明漏洞存在
正确示例: 直接访问 `http://node7.anna.nssctf.cn:22856/test2222222222222222.php`

## 评判标准

{success_criteria}

## 战略评估

### 1. 进度评估
分析当前攻击相对于目标的位置：
- 距离FLAG：[更近 / 不变 / 更远]
- 新获得了什么信息？
- 剩余障碍是什么？

### 2. 策略调整
- 当前策略是否有效？
- 是否需要换方向？
- 有没有遗漏的攻击面？

### 3. 资源优化
- 是否有更高效的攻击路径？
- 当前工具是否最适合？

### 节点决策 (node_decision)
- **continue**: 有明确进展，值得继续尝试新方法
- **abandon**: 连续多次无实质进展、重复相同失败模式、触发热熔断

## 输出 JSON（简化版，使用定性描述）
{{
    "found_flag": true/false,
    "potential_flag": "FLAG或空",
    "is_exploit_successful": true/false,
    "exploit_evidence": "成功证据简述",
    "failure_level": "critical/major/minor",
    "node_decision": "continue或abandon",
    "failure_analysis": "失败原因分析（如有失败）",
    "new_discoveries": ["发现1", "发现2"],
    "tactical_guidance": "攻击参数建议，如 ?url=system('ls')",
    "guidance_type": "switch_scene/continue/deepen/abort",
    "target_url": "目标页面URL（switch_scene时填写新路径，否则留空）",
    "updated_known_facts": "发现的关键信息"
}}
"""