#!/usr/bin/env python3
"""
将 skill-play-main 中的知识文档转换为 Skill YAML 格式
"""

import os
import re
from pathlib import Path
from typing import Dict, List, Optional

# 源目录和目标目录
SOURCE_DIR = Path("skill-play-main/skill-play-main/security-testing/data")
TARGET_DIR = Path("skills")

# Skill 元数据映射
SKILL_METADATA = {
    # Web 类别
    "sqli": {
        "name": "SQL注入攻击",
        "domain": "web",
        "description": "MySQL、MSSQL、Oracle、PostgreSQL等数据库的SQL注入技术",
        "tags": ["web", "sqli", "injection", "database"]
    },
    "xss": {
        "name": "跨站脚本攻击",
        "domain": "web",
        "description": "反射型、存储型、DOM型XSS攻击技术",
        "tags": ["web", "xss", "javascript"]
    },
    "ssrf": {
        "name": "服务端请求伪造",
        "domain": "web",
        "description": "SSRF漏洞利用和内网探测技术",
        "tags": ["web", "ssrf", "internal"]
    },
    "ssti": {
        "name": "服务端模板注入",
        "domain": "web",
        "description": "Jinja2、Twig、Smarty等模板引擎注入技术",
        "tags": ["web", "ssti", "template"]
    },
    "rce": {
        "name": "远程代码执行",
        "domain": "web",
        "description": "命令注入、代码执行漏洞利用技术",
        "tags": ["web", "rce", "command-injection"]
    },
    "lfi": {
        "name": "本地文件包含",
        "domain": "web",
        "description": "LFI漏洞利用和文件读取技术",
        "tags": ["web", "lfi", "file-inclusion"]
    },
    "xxe": {
        "name": "XML外部实体注入",
        "domain": "web",
        "description": "XXE漏洞利用和文件读取技术",
        "tags": ["web", "xxe", "xml"]
    },
    "jwt": {
        "name": "JWT安全测试",
        "domain": "web",
        "description": "JWT令牌伪造、弱密钥检测技术",
        "tags": ["web", "jwt", "authentication"]
    },
    "auth": {
        "name": "认证漏洞测试",
        "domain": "web",
        "description": "认证绕过、会话管理漏洞测试",
        "tags": ["web", "auth", "authentication"]
    },
    "api": {
        "name": "API安全测试",
        "domain": "web",
        "description": "REST API、GraphQL安全测试技术",
        "tags": ["web", "api", "rest", "graphql"]
    },
    "biz-logic": {
        "name": "业务逻辑漏洞",
        "domain": "web",
        "description": "业务逻辑缺陷检测和利用",
        "tags": ["web", "logic", "business"]
    },
    "cache-cdn": {
        "name": "缓存投毒攻击",
        "domain": "web",
        "description": "Web缓存投毒和CDN利用技术",
        "tags": ["web", "cache", "cdn"]
    },
    "clickjacking": {
        "name": "点击劫持攻击",
        "domain": "web",
        "description": "点击劫持漏洞检测和利用",
        "tags": ["web", "clickjacking", "ui"]
    },
    "cloud": {
        "name": "云安全测试",
        "domain": "cloud",
        "description": "AWS、Azure、GCP云环境安全测试",
        "tags": ["cloud", "aws", "azure", "gcp"]
    },
    "framework": {
        "name": "框架安全测试",
        "domain": "web",
        "description": "Spring、Django、Flask等框架安全测试",
        "tags": ["web", "framework", "spring", "django"]
    },
    # Intranet 类别
    "ad-attack": {
        "name": "AD域攻击",
        "domain": "intranet",
        "description": "Active Directory域环境攻击技术",
        "tags": ["intranet", "ad", "windows", "domain"]
    },
    "lateral": {
        "name": "横向移动",
        "domain": "intranet",
        "description": "内网横向移动和权限扩展技术",
        "tags": ["intranet", "lateral", "movement"]
    },
    "privesc": {
        "name": "权限提升",
        "domain": "intranet",
        "description": "Linux/Windows权限提升技术",
        "tags": ["intranet", "privesc", "privilege"]
    },
    "recon": {
        "name": "内网信息收集",
        "domain": "intranet",
        "description": "内网资产发现和信息收集技术",
        "tags": ["intranet", "recon", "discovery"]
    },
    "tunnel": {
        "name": "隧道技术",
        "domain": "intranet",
        "description": "内网隧道和代理技术",
        "tags": ["intranet", "tunnel", "proxy"]
    },
    "evasion": {
        "name": "规避技术",
        "domain": "intranet",
        "description": "杀软规避和免杀技术",
        "tags": ["intranet", "evasion", "bypass"]
    },
    "persistence": {
        "name": "权限维持",
        "domain": "intranet",
        "description": "后门植入和权限维持技术",
        "tags": ["intranet", "persistence", "backdoor"]
    },
    "exchange-attack": {
        "name": "Exchange攻击",
        "domain": "intranet",
        "description": "Microsoft Exchange服务器攻击技术",
        "tags": ["intranet", "exchange", "email"]
    },
    "sharepoint-attack": {
        "name": "SharePoint攻击",
        "domain": "intranet",
        "description": "Microsoft SharePoint服务器攻击技术",
        "tags": ["intranet", "sharepoint", "microsoft"]
    },
    "cred theft": {
        "name": "凭证窃取",
        "domain": "intranet",
        "description": "密码哈希和凭证窃取技术",
        "tags": ["intranet", "credential", "theft"]
    }
}


def read_markdown_files(category_path: Path) -> Dict[str, str]:
    """读取目录下所有markdown文件"""
    content = {}
    for md_file in category_path.glob("*.md"):
        with open(md_file, "r", encoding="utf-8") as f:
            content[md_file.name] = f.read()
    return content


def combine_knowledge(files_content: Dict[str, str]) -> str:
    """合并多个markdown文件的知识内容"""
    combined = []
    for filename, content in sorted(files_content.items()):
        # 移除文件扩展名作为子标题
        title = filename.replace(".md", "").replace("-", " ").replace("_", " ")
        combined.append(f"\n### {title}\n\n{content}")
    return "\n".join(combined)


def create_skill_yaml(category_name: str, knowledge: str, metadata: Dict) -> str:
    """生成Skill YAML文件内容"""
    yaml_content = f"""name: "{metadata.get('name', category_name)}"
description: "{metadata.get('description', '')}"
domain: "{metadata.get('domain', 'web')}"
version: "1.0"
tags:
"""
    for tag in metadata.get("tags", []):
        yaml_content += f"  - {tag}\n"

    yaml_content += f"""
knowledge: |
{indent_text(knowledge, 2)}

workflows:
  - name: "自动检测和利用"
    description: "自动检测漏洞并尝试利用"
    steps:
      - description: "信息收集和漏洞探测"
        expected_output: "发现潜在漏洞点"
      - description: "漏洞验证"
        expected_output: "确认漏洞存在"
      - description: "漏洞利用"
        expected_output: "成功利用漏洞"

tool_preferences:
  nmap:
    score: 0.8
    reason: "端口和服务扫描"
  nuclei:
    score: 0.9
    reason: "漏洞扫描"

examples:
  - scenario: "发现漏洞并获取敏感信息"
    solution: "使用工具探测 -> 验证漏洞 -> 获取数据"
    tools_used: ["nmap", "nuclei"]
"""
    return yaml_content


def indent_text(text: str, spaces: int) -> str:
    """缩进文本"""
    indent = " " * spaces
    return "\n".join(indent + line for line in text.split("\n"))


def convert_all_skills():
    """转换所有技能 - 每个markdown文件一个Skill"""
    converted = 0

    # 遍历 web 和 intranet 目录
    for main_category in ["web", "intranet"]:
        main_path = SOURCE_DIR / main_category
        if not main_path.exists():
            continue

        # 首先处理主目录下的单独文件（如 web/sqli.md）
        for md_file in main_path.glob("*.md"):
            category_name = md_file.stem
            convert_single_skill(md_file, category_name, main_category)
            converted += 1

        # 然后处理子目录
        for category_path in main_path.iterdir():
            if not category_path.is_dir():
                continue

            category_name = category_path.name

            # 为每个markdown文件创建单独的Skill
            for md_file in category_path.glob("*.md"):
                skill_name = f"{category_name}_{md_file.stem}"
                convert_single_skill(md_file, skill_name, main_category, category_name)
                converted += 1

    print(f"\n总计转换 {converted} 个Skills")
    return converted


def convert_single_skill(md_file: Path, skill_name: str, main_category: str, sub_category: str = None):
    """转换单个markdown文件为Skill"""
    with open(md_file, "r", encoding="utf-8") as f:
        content = f.read()

    # 从文件名生成元数据
    base_name = sub_category or skill_name
    metadata = SKILL_METADATA.get(base_name, {
        "name": skill_name.replace("_", " ").replace("-", " "),
        "domain": main_category,
        "description": f"{skill_name} 攻击技术和利用方法",
        "tags": [main_category, skill_name]
    })

    # 生成YAML
    yaml_content = create_skill_yaml(skill_name, content, metadata)

    # 写入文件
    output_file = TARGET_DIR / f"{skill_name}.yaml"
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(yaml_content)

    print(f"转换完成: {skill_name}")


if __name__ == "__main__":
    convert_all_skills()