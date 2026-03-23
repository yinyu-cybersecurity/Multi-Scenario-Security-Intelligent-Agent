import json

def get_analyst_prompt(page_features: dict, raw_html: str, rule_candidates: list, task_name: str = "Unknown", task_description: str = "None", baseline_response: dict = None) -> str:
    """
    生成分析兵的情报统筹提示词。
    """

    # 构建重定向信息部分
    redirect_info = ""
    if baseline_response:
        final_url = baseline_response.get("final_url", "")
        redirect_chain = baseline_response.get("redirect_chain", [])
        if redirect_chain or (final_url and "?" in final_url):
            redirect_info = f"""
### 🔀 重定向信息
- **最终URL**: {final_url}
- **重定向链**: {json.dumps(redirect_chain, indent=2, ensure_ascii=False) if redirect_chain else "无重定向"}
"""
            # 提取参数信息
            if "?" in final_url:
                params_part = final_url.split("?", 1)[1]
                redirect_info += f"- **发现参数**: `{params_part}`\n"

    return f"""
# CTF 分析兵

## 任务
分析侦察数据，识别漏洞候选点或攻击方向。

## 题目信息
- 名称: {task_name}
- 描述: {task_description}

## 输入数据
### 页面特征
{json.dumps(page_features, indent=2, ensure_ascii=False)}
{redirect_info}
### 源码片段
{raw_html[:3000]}

### 规则引擎预警
{json.dumps(rule_candidates, indent=2, ensure_ascii=False)}

## 分析要点

1. **题目暗示**: 分析题目名称和描述中的关键词
2. **隐藏内容**: 检查HTML注释、隐藏元素、特殊编码
3. **输入点**: 表单、URL参数、Cookie、HTTP头
4. **敏感路径**: /admin, /.git, /flag, /config 等
5. **重定向参数**: 特别注意重定向后URL中的参数名（如 ?wllm= 说明参数名是 wllm）

## 输出要求
返回 JSON 格式：

```json
{{
  "candidates": [
    {{
      "type": "漏洞类型",
      "location": "攻击位置",
      "confidence": 0.0-1.0,
      "reason": "分析依据",
      "context": {{}},
      "url": "目标URL"
    }}
  ],
  "key_intel": "关键情报总结"
}}
```

**重要**: candidates 列表不能为空！根据题目描述给出至少一个攻击方向。
"""