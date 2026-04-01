"""
CTF-Agent 报告生成器

功能:
- 生成Markdown格式渗透测试报告
- 支持HTML/PDF导出
- 攻击路径时间线
- 漏洞详情记录
- Flag提交历史
"""

from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
import json
import os


@dataclass
class Vulnerability:
    """漏洞记录"""
    name: str
    severity: str  # Critical/High/Medium/Low/Info
    url: str
    description: str
    evidence: str = ""
    remediation: str = ""
    cvss_score: float = 0.0
    tags: List[str] = field(default_factory=list)


@dataclass
class AttackStep:
    """攻击步骤"""
    timestamp: str
    phase: str  # scan/exploit/post-exploit
    action: str
    tool: str
    success: bool
    output: str = ""
    duration: float = 0.0


@dataclass
class FlagRecord:
    """Flag记录"""
    flag: str
    found_at: str
    source: str  # 哪个漏洞/步骤发现的
    points: int = 0


class ReportGenerator:
    """渗透测试报告生成器"""

    def __init__(self, target: str, project_name: str = "CTF-Agent Assessment"):
        self.target = target
        self.project_name = project_name
        self.start_time = datetime.now()
        self.end_time: Optional[datetime] = None

        # 数据存储
        self.vulnerabilities: List[Vulnerability] = []
        self.attack_timeline: List[AttackStep] = []
        self.flags: List[FlagRecord] = []
        self.tools_used: Dict[str, int] = {}  # 工具调用次数
        self.findings: Dict[str, Any] = {}

    def add_vulnerability(self, vuln: Vulnerability):
        """添加漏洞"""
        self.vulnerabilities.append(vuln)

    def add_attack_step(self, step: AttackStep):
        """添加攻击步骤"""
        self.attack_timeline.append(step)

    def add_flag(self, flag: FlagRecord):
        """添加Flag"""
        self.flags.append(flag)

    def record_tool_usage(self, tool_name: str):
        """记录工具使用"""
        self.tools_used[tool_name] = self.tools_used.get(tool_name, 0) + 1

    def generate_markdown(self) -> str:
        """生成Markdown报告"""
        self.end_time = datetime.now()
        duration = (self.end_time - self.start_time).total_seconds()

        report = []
        report.append(f"# {self.project_name}\n")
        report.append(f"**目标**: {self.target}\n")
        report.append(f"**时间**: {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        report.append(f"**持续时间**: {duration:.2f}秒\n")
        report.append("---\n")

        # 执行摘要
        report.append("## 执行摘要\n")
        report.append(f"- 发现漏洞: **{len(self.vulnerabilities)}** 个\n")
        report.append(f"- 获取Flag: **{len(self.flags)}** 个\n")
        report.append(f"- 工具调用: **{sum(self.tools_used.values())}** 次\n")

        # 漏洞统计
        severity_counts = {}
        for v in self.vulnerabilities:
            severity_counts[v.severity] = severity_counts.get(v.severity, 0) + 1

        report.append("\n### 漏洞分布\n")
        report.append("| 严重性 | 数量 |\n")
        report.append("|--------|------|\n")
        for sev in ["Critical", "High", "Medium", "Low", "Info"]:
            count = severity_counts.get(sev, 0)
            if count > 0:
                report.append(f"| {sev} | {count} |\n")

        # 攻击时间线
        report.append("\n## 攻击时间线\n")
        report.append("| 时间 | 阶段 | 动作 | 工具 | 状态 | 耗时 |\n")
        report.append("|------|------|------|------|------|------|\n")
        for step in self.attack_timeline:
            status = "✅" if step.success else "❌"
            report.append(
                f"| {step.timestamp} | {step.phase} | {step.action} | "
                f"{step.tool} | {status} | {step.duration:.2f}s |\n"
            )

        # 漏洞详情
        if self.vulnerabilities:
            report.append("\n## 漏洞详情\n")
            for i, vuln in enumerate(self.vulnerabilities, 1):
                report.append(f"\n### {i}. {vuln.name}\n")
                report.append(f"**严重性**: {vuln.severity}\n")
                report.append(f"**URL**: `{vuln.url}`\n")
                report.append(f"\n**描述**: {vuln.description}\n")
                if vuln.evidence:
                    report.append(f"\n**证据**:\n```\n{vuln.evidence}\n```\n")
                if vuln.remediation:
                    report.append(f"\n**修复建议**: {vuln.remediation}\n")

        # Flags
        if self.flags:
            report.append("\n## Flags\n")
            for flag in self.flags:
                report.append(f"- `{flag.flag}` (来源: {flag.source})\n")

        # 工具使用统计
        report.append("\n## 工具使用统计\n")
        report.append("| 工具 | 调用次数 |\n")
        report.append("|------|----------|\n")
        for tool, count in sorted(
            self.tools_used.items(), key=lambda x: x[1], reverse=True
        ):
            report.append(f"| {tool} | {count} |\n")

        return "".join(report)

    def save_report(self, output_path: str, format: str = "markdown"):
        """保存报告"""
        if format == "markdown":
            content = self.generate_markdown()
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(content)
        elif format == "json":
            data = {
                "target": self.target,
                "project_name": self.project_name,
                "start_time": self.start_time.isoformat(),
                "end_time": self.end_time.isoformat() if self.end_time else None,
                "vulnerabilities": [v.__dict__ for v in self.vulnerabilities],
                "attack_timeline": [s.__dict__ for s in self.attack_timeline],
                "flags": [f.__dict__ for f in self.flags],
                "tools_used": self.tools_used,
            }
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)

    def to_html(self) -> str:
        """转换为HTML格式"""
        md_content = self.generate_markdown()
        # 简单的Markdown转HTML
        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>{self.project_name}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }}
        h1 {{ color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }}
        h2 {{ color: #34495e; margin-top: 30px; }}
        h3 {{ color: #7f8c8d; }}
        table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
        th, td {{ border: 1px solid #bdc3c7; padding: 8px; text-align: left; }}
        th {{ background-color: #3498db; color: white; }}
        code {{ background-color: #ecf0f1; padding: 2px 6px; border-radius: 3px; }}
        pre {{ background-color: #2c3e50; color: #ecf0f1; padding: 15px; border-radius: 5px; overflow-x: auto; }}
    </style>
</head>
<body>
{self._markdown_to_html(md_content)}
</body>
</html>"""
        return html

    def _markdown_to_html(self, md: str) -> str:
        """简单Markdown转HTML"""
        lines = md.split("\n")
        html_lines = []
        in_code_block = False

        for line in lines:
            # 代码块
            if line.startswith("```"):
                if in_code_block:
                    html_lines.append("</code></pre>")
                    in_code_block = False
                else:
                    html_lines.append("<pre><code>")
                    in_code_block = True
                continue

            if in_code_block:
                html_lines.append(line)
                continue

            # 标题
            if line.startswith("# "):
                html_lines.append(f"<h1>{line[2:]}</h1>")
            elif line.startswith("## "):
                html_lines.append(f"<h2>{line[3:]}</h2>")
            elif line.startswith("### "):
                html_lines.append(f"<h3>{line[4:]}</h3>")
            # 表格
            elif line.startswith("|"):
                if "---" in line:
                    continue
                cells = [c.strip() for c in line.split("|")[1:-1]]
                if cells:
                    row = "".join(f"<td>{c}</td>" for c in cells)
                    html_lines.append(f"<tr>{row}</tr>")
            # 段落
            elif line.strip():
                # 行内代码
                line = line.replace("`", "<code>", 1).replace("`", "</code>", 1)
                html_lines.append(f"<p>{line}</p>")
            else:
                html_lines.append("")

        return "\n".join(html_lines)


def generate_attack_tree_report(
    target: str, attack_paths: List[Dict]
) -> str:
    """生成攻击树状图报告（Mermaid格式）"""
    mermaid = ["```mermaid", "graph TD"]

    # 根节点
    mermaid.append(f'    Root["{target}"]')

    for i, path in enumerate(attack_paths):
        node_id = f"P{i}"
        label = path.get("name", "Attack Path")
        mermaid.append(f'    {node_id}["{label}"]')
        mermaid.append(f"    Root --> {node_id}")

        # 子节点
        steps = path.get("steps", [])
        for j, step in enumerate(steps):
            step_id = f"{node_id}_S{j}"
            step_label = step.get("action", "Step")
            mermaid.append(f'    {step_id}["{step_label}"]')
            if j == 0:
                mermaid.append(f"    {node_id} --> {step_id}")
            else:
                prev_id = f"{node_id}_S{j-1}"
                mermaid.append(f"    {prev_id} --> {step_id}")

    mermaid.append("```")
    return "\n".join(mermaid)


# 使用示例
if __name__ == "__main__":
    # 创建报告
    report = ReportGenerator(
        target="http://example.com",
        project_name="Web Application Penetration Test"
    )

    # 添加漏洞
    report.add_vulnerability(
        Vulnerability(
            name="SQL Injection",
            severity="Critical",
            url="http://example.com/users?id=1",
            description="存在SQL注入漏洞，可获取数据库敏感信息",
            evidence="Error: You have an error in your SQL syntax",
            remediation="使用参数化查询，过滤用户输入"
        )
    )

    # 添加攻击步骤
    report.add_attack_step(
        AttackStep(
            timestamp="09:45:12",
            phase="scan",
            action="端口扫描",
            tool="nmap",
            success=True,
            duration=15.3
        )
    )

    # 添加Flag
    report.add_flag(
        FlagRecord(
            flag="flag{sql_injection_success}",
            found_at="09:50:23",
            source="SQL Injection漏洞利用"
        )
    )

    # 生成报告
    print(report.generate_markdown())