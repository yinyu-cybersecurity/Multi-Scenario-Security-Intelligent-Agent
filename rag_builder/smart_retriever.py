# rag_builder/smart_retriever.py - RAG数据源描述
# 用于在AI prompt中说明可用的数据源

from typing import List, Dict


# 数据源配置 - 用于AI prompt
SOURCE_PROFILES = {
    "writeups": {
        "description": "CTF历史题解库，包含解题思路和技巧",
        "best_for": ["寻找类似题目解法", "了解攻击思路", "学习解题技巧"],
        "query_style": "技术栈+漏洞类型，如'spring ssti'",
        "examples": ["spring ssti", "jwt bypass", "file upload", "sql injection"]
    },
    "nuclei": {
        "description": "Nuclei漏洞扫描模板库",
        "best_for": ["CVE漏洞利用", "获取扫描模板", "了解漏洞参数"],
        "query_style": "CVE编号或漏洞名，如'CVE-2023-44487'",
        "examples": ["CVE-2023-44487", "log4j", "spring actuator"]
    },
    "payloads": {
        "description": "Payload知识库，包含各类漏洞攻击载荷",
        "best_for": ["获取具体payload", "绕过WAF", "payload变体"],
        "query_style": "漏洞类型，如'ssti'、'xss'、'sqli'",
        "examples": ["ssti jinja", "xss dom", "sqli union", "deserialization java"]
    },
    "security_resources": {
        "description": "安全资源库(PayloadsAllTheThings等)",
        "best_for": ["学习攻击技术", "了解绕过方法", "深入理解漏洞"],
        "query_style": "漏洞类型或攻击技术名称",
        "examples": ["ssti", "deserialization", "ssrf internal", "file inclusion"]
    }
}


def get_source_descriptions() -> str:
    """
    获取数据源描述，供AI prompt使用

    Returns:
        格式化的数据源描述字符串
    """
    lines = ["可用数据源："]
    for name, profile in SOURCE_PROFILES.items():
        lines.append(f"\n**{name}**")
        lines.append(f"- 描述: {profile['description']}")
        lines.append(f"- 适用: {', '.join(profile['best_for'])}")
        lines.append(f"- 查询示例: {', '.join(profile['examples'][:3])}")
    return "\n".join(lines)


# 用于AI prompt的数据源描述
RETRIEVAL_PROMPT_SECTION = f"""
## 知识库检索

你可以请求从知识库检索信息辅助攻击。

### 可用数据源

| 数据源 | 描述 | 适用场景 |
|--------|------|---------|
| writeups | CTF历史题解库 | 寻找类似题目解法，学习思路 |
| nuclei | CVE漏洞模板库 | 已知CVE编号，获取扫描模板 |
| payloads | 攻击载荷库 | 需要具体payload，绕过WAF |
| security_resources | 安全技术文档 | 深入理解漏洞，学习绕过技术 |

### 在输出中请求检索

在candidates同级添加retrieval_requests字段：

```json
{{
  "candidates": [...],
  "retrieval_requests": [
    {{
      "query": "spring ssti jinja",
      "source": "payloads",
      "reason": "需要Spring SSTI的具体payload"
    }}
  ]
}}
```

### 何时请求检索

- 发现漏洞但不确定如何利用
- 需要绕过特定防护（WAF、过滤）
- 攻击多次失败需要新思路
- 遇到不熟悉的漏洞类型
- 需要特定CVE的利用模板
"""