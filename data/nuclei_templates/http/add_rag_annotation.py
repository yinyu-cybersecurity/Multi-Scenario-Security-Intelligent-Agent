#!/usr/bin/env python3
"""批量添加RAG Annotation到YAML文件"""
import os
import re
import sys

BASE_DIR = "D:/LangGraph2.0/langGraph/deploy/thirdparty/nuclei-templates-10.4.0/http"

def extract_info(file_path):
    """从YAML文件提取info部分的关键信息"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
    except:
        try:
            with open(file_path, 'r', encoding='latin-1') as f:
                content = f.read()
        except:
            return None

    # 提取name
    name_match = re.search(r'name:\s*(.+?)(?:\n|$)', content)
    name = name_match.group(1).strip().strip('"').strip("'") if name_match else "Unknown"

    # 提取description (截取前100字符)
    desc_match = re.search(r'description:\s*(.+?)(?:\n\s*[a-z]+:|\n\n|\n$|$)', content, re.DOTALL)
    if desc_match:
        desc = desc_match.group(1).strip().strip('"').strip("'")
        # 处理多行描述
        desc = desc.replace('\n', ' ').strip()
        desc = desc[:100] + "..." if len(desc) > 100 else desc
    else:
        desc = "No description available"

    # 提取severity
    severity_match = re.search(r'severity:\s*(\w+)', content)
    severity = severity_match.group(1).strip() if severity_match else "unknown"

    # 提取tags作为vuln_type
    tags_match = re.search(r'tags:\s*(.+?)(?:\n|$)', content)
    if tags_match:
        tags = tags_match.group(1).strip()
        # 取第一个tag作为vuln_type
        vuln_type = tags.split(',')[0].strip() if ',' in tags else tags.strip()
    else:
        vuln_type = "unknown"

    # 从文件名提取CVE编号
    filename = os.path.basename(file_path)
    cve_match = re.search(r'CVE-\d{4}-\d+', filename)
    cve_id = cve_match.group(0) if cve_match else ""

    return {
        'name': name,
        'description': desc,
        'vuln_type': vuln_type,
        'severity': severity,
        'cve_id': cve_id
    }

def add_rag_annotation(file_path, info):
    """添加RAG Annotation到文件开头"""
    # 构建annotation
    annotation = "# RAG Annotation:\n"
    annotation += f"# name: {info['name']}\n"
    annotation += f"# description: {info['description']}\n"
    annotation += f"# vuln_type: {info['vuln_type']}\n"
    annotation += f"# severity: {info['severity']}\n"
    annotation += f"# cve_id: {info['cve_id']}\n"

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
    except:
        with open(file_path, 'r', encoding='latin-1') as f:
            content = f.read()

    # 检查是否已有annotation
    if content.startswith("# RAG Annotation:"):
        return False

    # 添加annotation
    new_content = annotation + content

    try:
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(new_content)
    except:
        with open(file_path, 'w', encoding='latin-1') as f:
            f.write(new_content)

    return True

def main():
    # 文件列表
    files = [
        "./cves/2026/CVE-2026-0829.yaml",
        "./cves/2026/CVE-2026-1207.yaml",
        "./cves/2026/CVE-2026-1357.yaml",
        "./cves/2026/CVE-2026-1492.yaml",
        "./cves/2026/CVE-2026-1603.yaml",
        "./cves/2026/CVE-2026-21858.yaml",
        "./cves/2026/CVE-2026-21859.yaml",
        "./cves/2026/CVE-2026-21877.yaml",
        "./cves/2026/CVE-2026-21891.yaml",
        "./cves/2026/CVE-2026-22200.yaml",
        "./cves/2026/CVE-2026-22812.yaml",
        "./cves/2026/CVE-2026-23550.yaml",
        "./cves/2026/CVE-2026-23744.yaml",
        "./cves/2026/CVE-2026-23760.yaml",
        "./cves/2026/CVE-2026-23829.yaml",
        "./cves/2026/CVE-2026-24128.yaml",
        "./cves/2026/CVE-2026-2413.yaml",
        "./cves/2026/CVE-2026-25512.yaml",
        "./cves/2026/CVE-2026-25892.yaml",
        "./cves/2026/CVE-2026-27645.yaml",
        "./cves/2026/CVE-2026-27944.yaml",
        "./cves/2026/CVE-2026-27971.yaml",
    ]

    count = 0
    for rel_path in files:
        file_path = os.path.join(BASE_DIR, rel_path.lstrip('./'))
        info = extract_info(file_path)
        if info:
            if add_rag_annotation(file_path, info):
                count += 1
                print(f"[{count}] Processed: {rel_path}")

    print(f"\nTotal processed: {count} files")

if __name__ == "__main__":
    main()