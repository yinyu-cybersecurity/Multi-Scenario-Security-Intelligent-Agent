#!/usr/bin/env python3
"""
YAML Skills → SKILL.md 格式转换脚本

将 CTF-Agent 的 YAML 技能文件转换为 OpenSpace 标准的 SKILL.md 格式。

YAML 格式:
  name: 技能名称
  description: 描述
  domain: 领域
  version: 版本
  tags: [标签]
  knowledge: |
    知识内容

SKILL.md 格式:
  ---
  name: skill-name
  description: Use when [触发条件]
  ---

  # 技能名称

  知识内容...
"""

import os
import re
import yaml
from pathlib import Path
from typing import Dict, Any, List


def sanitize_name(name: str) -> str:
    """转换为有效的 skill name（小写 kebab-case）"""
    # 中文保持原样，英文转小写
    name = name.strip()
    # 替换空格和特殊字符为连字符
    name = re.sub(r'[\s_]+', '-', name)
    name = re.sub(r'[^a-zA-Z0-9\u4e00-\u9fff\-]', '', name)
    return name.lower()


def extract_triggers(description: str, knowledge: str) -> str:
    """
    从描述和知识内容中提取触发条件
    生成 "Use when..." 格式的描述
    """
    # 提取关键领域词汇
    domain_keywords = {
        'web': ['注入', 'XSS', 'CSRF', 'SSRF', 'RCE', 'LFI', '文件上传', '反序列化'],
        'intranet': ['内网', '横向', '提权', '域', 'AD', 'Kerberos', '隧道'],
        'crypto': ['加密', '解密', 'RSA', 'AES', '哈希', '密码'],
        'pwn': ['溢出', 'ROP', '栈', '堆', 'shellcode'],
        'reverse': ['逆向', '反编译', '调试', '脱壳'],
    }

    # 简化描述为触发条件格式
    if description:
        # 如果已经是触发格式，直接使用
        if description.lower().startswith('use when'):
            return description

        # 否则转换为触发格式
        return f"Use when encountering {description.lower()}"

    return "Use when relevant attack scenario is identified"


def convert_yaml_to_skill_md(yaml_path: Path, output_dir: Path) -> Dict[str, Any]:
    """
    转换单个 YAML 文件为 SKILL.md

    返回转换统计信息
    """
    try:
        with open(yaml_path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
    except Exception as e:
        return {'error': str(e), 'file': str(yaml_path)}

    if not data:
        return {'error': 'Empty YAML', 'file': str(yaml_path)}

    name = data.get('name', yaml_path.stem)
    description = data.get('description', '')
    knowledge = data.get('knowledge', '')
    domain = data.get('domain', '')
    tags = data.get('tags', [])
    version = data.get('version', '1.0')

    # 使用原始文件名作为目录名（保证唯一性）
    skill_dir_name = sanitize_name(yaml_path.stem)
    if not skill_dir_name:
        skill_dir_name = sanitize_name(name)

    # 创建输出目录
    skill_dir = output_dir / skill_dir_name
    skill_dir.mkdir(parents=True, exist_ok=True)

    # 转换描述为触发格式
    trigger_description = extract_triggers(description, knowledge)

    # 构建 SKILL.md 内容
    frontmatter = f"""---
name: {skill_dir_name}
description: {trigger_description}
---"""

    # 构建正文
    body_lines = [f"# {name}", ""]

    # 添加元信息区域
    if domain or tags:
        body_lines.append("## Info")
        body_lines.append("")
        if domain:
            body_lines.append(f"- **Domain**: {domain}")
        if tags:
            body_lines.append(f"- **Tags**: {', '.join(tags)}")
        body_lines.append("")

    # 添加知识内容
    if knowledge:
        # 清理知识内容（移除开头的标题如果重复）
        knowledge_content = knowledge.strip()
        # 如果知识内容开头已经是标题，跳过
        if knowledge_content.startswith('# '):
            body_lines.append(knowledge_content[len(f'# {name}'):].strip() if knowledge_content.startswith(f'# {name}') else knowledge_content)
        else:
            body_lines.append(knowledge_content)

    # 写入文件
    skill_md_path = skill_dir / 'SKILL.md'
    content = frontmatter + "\n\n" + "\n".join(body_lines)

    with open(skill_md_path, 'w', encoding='utf-8') as f:
        f.write(content)

    return {
        'success': True,
        'source': str(yaml_path),
        'output': str(skill_md_path),
        'name': skill_dir_name,
    }


def batch_convert(source_dir: Path, output_dir: Path) -> List[Dict]:
    """批量转换所有 YAML 技能文件"""
    results = []

    # 查找所有 YAML 文件
    yaml_files = list(source_dir.glob('*.yaml')) + list(source_dir.glob('*.yml'))

    print(f"Found {len(yaml_files)} YAML files in {source_dir}")

    for yaml_path in sorted(yaml_files):
        result = convert_yaml_to_skill_md(yaml_path, output_dir)
        results.append(result)

        if result.get('success'):
            print(f"  [OK] {result['name']}")
        else:
            print(f"  [ERR] {yaml_path.name}: {result.get('error', 'Unknown error')}")

    return results


def main():
    """主函数"""
    import argparse

    parser = argparse.ArgumentParser(description='Convert YAML skills to SKILL.md format')
    parser.add_argument('--source', type=str, default='skills', help='Source directory with YAML files')
    parser.add_argument('--output', type=str, default='skills_md', help='Output directory for SKILL.md files')
    parser.add_argument('--single', type=str, help='Convert single file')
    args = parser.parse_args()

    source_dir = Path(args.source)
    output_dir = Path(args.output)

    if not source_dir.exists():
        print(f"Error: Source directory {source_dir} does not exist")
        return

    output_dir.mkdir(parents=True, exist_ok=True)

    if args.single:
        # 单文件转换
        result = convert_yaml_to_skill_md(Path(args.single), output_dir)
        print(result)
    else:
        # 批量转换
        results = batch_convert(source_dir, output_dir)

        # 统计
        success_count = sum(1 for r in results if r.get('success'))
        error_count = len(results) - success_count

        print(f"\n{'='*50}")
        print(f"Conversion complete: {success_count} success, {error_count} errors")
        print(f"Output directory: {output_dir.absolute()}")


if __name__ == '__main__':
    main()