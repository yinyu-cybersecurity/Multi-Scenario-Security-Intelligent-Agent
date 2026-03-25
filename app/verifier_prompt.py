# verifier_prompt.py - 核验兵提示词模板 [P3合并版]
import json
import re

# Base64 正则匹配
BASE64_PATTERN = re.compile(r'[A-Za-z0-9+/]{20,}={0,2}')

def get_verifier_prompt(attack_batch: list, results: list, analyst_intel: str = None,
                        node_info: dict = None, known_facts: str = None,
                        human_hint: str = None) -> str:
    """
    构建核验兵的 Prompt [P3合并版]
    合并了原verifier和reflector的职责，一次LLM调用完成所有判断
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
            "action_id": res.get("action_id", f"action_{i}"),
            "tool": res.get("tool", "unknown"),
            "payload": res.get("payload", "N/A"),
            "status_code": res.get("status", "?"),
            "response": str(content)[:6000]  # 缩短以腾出空间给更多上下文
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

    # 人工提示
    hint_context = ""
    if human_hint:
        hint_context = f"""
## ⚠️ 人工指导（必须遵循）
{human_hint}
请根据以上人工指导调整战术建议和攻击方向。
"""

    return f"""# CTF 核验官

## 任务
分析攻击结果，判断成功程度，决定后续策略。

## 分析情报
{analyst_intel if analyst_intel else "无"}
{facts_context}
{hint_context}
{node_context}

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

错误示例 ❌: 继续用文件包含证明漏洞存在
正确示例 ✅: 直接访问 `http://node7.anna.nssctf.cn:22856/test2222222222222222.php`

## 评判标准

### 成功程度 (failure_severity)
- **0.0**: 找到FLAG或明确成功（如完整读取到/etc/passwd内容、执行命令返回完整结果）
- **0.3**: 有明显实质进展（上传成功、发现新文件路径、绕过过滤成功且获得有效输出）
- **0.5**: 有变化但无实质价值（响应变化但只是错误信息、被过滤的回显）
- **0.8**: 完全失败（403/404/500/被过滤/无变化）

### ⚠️ 重要：is_exploit_successful 判断标准
**只有满足以下条件之一才能设为true：**
1. 找到FLAG
2. 成功读取到敏感文件内容（如flag.php源码、/etc/passwd完整内容）
3. 命令执行返回完整、有用的输出（不只是"Array"或截断内容）
4. 发现并成功访问新路径，且新路径有可利用内容

**以下情况必须设为false：**
- 响应只是"Array"或截断输出
- 只显示"有变化"但没有获取到实际内容
- 被过滤系统拦截（如"fxck your symbol"）
- 重复使用相同绕过技术

### 节点决策 (node_decision)
- **continue**: 有明确进展，值得继续尝试新方法
- **abandon**: 连续多次无实质进展、重复相同失败模式、触发热熔断

## 输出 JSON
{{
    "found_flag": true/false,
    "potential_flag": "FLAG或空",
    "is_exploit_successful": true/false,
    "exploit_evidence": "成功证据简述",
    "failure_severity": 0.0-1.0,
    "node_decision": "continue或abandon",
    "failure_analysis": "失败原因分析（如有失败）",
    "tactical_guidance": "下一步方向性建议。如果发现新路径必须写出完整的访问URL，如：访问 http://目标/test2222222222222222.php",
    "updated_known_facts": "发现的关键信息（如果成功）"
}}
"""