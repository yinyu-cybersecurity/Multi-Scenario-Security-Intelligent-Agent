#!/usr/bin/env python3
"""
批量清理 skill YAML 文件 — 删除从未被代码消费的字段

删除字段: workflows, tool_preferences, examples
保留字段: name, description, domain, version, tags, knowledge, triggers
"""

import yaml
import sys
from pathlib import Path


FIELDS_TO_REMOVE = {"workflows", "tool_preferences", "examples"}
FIELDS_TO_KEEP = {"name", "description", "domain", "version", "tags", "knowledge", "triggers"}


def clean_skill(filepath: Path) -> bool:
    """清理单个 skill 文件，返回是否有修改"""
    try:
        content = filepath.read_text(encoding="utf-8")
        data = yaml.safe_load(content)

        if not isinstance(data, dict):
            return False

        # 检查是否有需要删除的字段
        to_remove = [k for k in data.keys() if k in FIELDS_TO_REMOVE]
        if not to_remove:
            return False

        # 删除字段
        for key in to_remove:
            del data[key]

        # 重新写入（保持中文和格式）
        output = yaml.dump(
            data,
            allow_unicode=True,
            default_flow_style=False,
            sort_keys=False,
            width=120,
        )

        filepath.write_text(output, encoding="utf-8")
        return True

    except Exception as e:
        print(f"  ERROR: {filepath.name}: {e}")
        return False


def main():
    skills_dir = Path(__file__).parent.parent / "skills"
    if not skills_dir.exists():
        print(f"Skills directory not found: {skills_dir}")
        sys.exit(1)

    yaml_files = list(skills_dir.glob("*.yaml")) + list(skills_dir.glob("*.yml"))
    print(f"Found {len(yaml_files)} skill files")

    modified = 0
    skipped = 0
    errors = 0

    for f in sorted(yaml_files):
        result = clean_skill(f)
        if result:
            modified += 1
            print(f"  CLEANED: {f.name}")
        elif result is False:
            skipped += 1

    print(f"\nDone: {modified} cleaned, {skipped} already clean/skipped")


if __name__ == "__main__":
    main()
