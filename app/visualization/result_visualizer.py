"""
CTF-Agent 结果可视化模块

功能:
- 攻击树状图生成
- 网络拓扑可视化
- Token消耗统计
- 工具调用热力图
"""

from typing import Dict, List, Any
from dataclasses import dataclass
from datetime import datetime
import json


@dataclass
class NetworkNode:
    """网络节点"""
    id: str
    ip: str
    hostname: str = ""
    os: str = ""
    open_ports: List[int] = None
    services: Dict[int, str] = None
    status: str = "unknown"  # discovered/exploited/owned


@dataclass
class AttackPath:
    """攻击路径"""
    id: str
    source: str
    target: str
    technique: str
    success: bool
    timestamp: str


class VisualizationEngine:
    """可视化引擎"""

    def __init__(self):
        self.nodes: List[NetworkNode] = []
        self.paths: List[AttackPath] = []
        self.token_stats: Dict[str, int] = {}
        self.tool_calls: Dict[str, List[datetime]] = {}

    def add_node(self, node: NetworkNode):
        """添加网络节点"""
        self.nodes.append(node)

    def add_attack_path(self, path: AttackPath):
        """添加攻击路径"""
        self.paths.append(path)

    def record_token_usage(self, model: str, tokens: int):
        """记录Token使用"""
        self.token_stats[model] = self.token_stats.get(model, 0) + tokens

    def record_tool_call(self, tool: str, timestamp: datetime):
        """记录工具调用"""
        if tool not in self.tool_calls:
            self.tool_calls[tool] = []
        self.tool_calls[tool].append(timestamp)

    def generate_attack_tree(self) -> str:
        """生成攻击树状图（Mermaid格式）"""
        lines = ["```mermaid", "graph TD"]

        # 根节点
        lines.append('    Root["🎯 攻击目标"]')

        # 按阶段分组
        phases = {
            "recon": "信息收集",
            "exploit": "漏洞利用",
            "post": "后渗透"
        }

        current_phase = None
        for i, node in enumerate(self.nodes):
            node_id = f"N{i}"

            # 节点状态图标
            status_icon = {
                "discovered": "🔍",
                "exploited": "💀",
                "owned": "🏆"
            }.get(node.status, "❓")

            # 节点标签
            label = f"{status_icon} {node.ip}"
            if node.hostname:
                label += f"\\n{node.hostname}"

            # 节点样式
            node_style = ""
            if node.status == "owned":
                node_style = ":::owned"
            elif node.status == "exploited":
                node_style = ":::exploited"

            lines.append(f'    {node_id}["{label}"]{node_style}')

            # 连接到根节点
            lines.append(f"    Root --> {node_id}")

            # 显示开放端口
            if node.open_ports:
                ports_str = ", ".join(map(str, node.open_ports[:5]))
                if len(node.open_ports) > 5:
                    ports_str += f" +{len(node.open_ports)-5}"
                lines.append(f'    {node_id}_ports["📡 {ports_str}"]')
                lines.append(f"    {node_id} --> {node_id}_ports")

        # 攻击路径
        for path in self.paths:
            style = "==>|" if path.success else "-..->|"
            result = "✅" if path.success else "❌"
            lines.append(
                f'    {path.source} {style} "{path.technique} {result}"| {path.target}'
            )

        # 样式定义
        lines.extend([
            "",
            "    classDef owned fill:#e74c3c,color:#fff",
            "    classDef exploited fill:#e67e22,color:#fff",
            "    classDef discovered fill:#3498db,color:#fff",
            "```"
        ])

        return "\n".join(lines)

    def generate_network_topology(self) -> str:
        """生成网络拓扑图（Mermaid格式）"""
        lines = ["```mermaid", "graph LR"]

        # 按网段分组
        subnets: Dict[str, List[NetworkNode]] = {}
        for node in self.nodes:
            # 提取网段
            ip_parts = node.ip.split(".")
            if len(ip_parts) == 4:
                subnet = ".".join(ip_parts[:3]) + ".0/24"
                if subnet not in subnets:
                    subnets[subnet] = []
                subnets[subnet].append(node)

        # 创建子网
        for subnet, nodes in subnets.items():
            subnet_id = subnet.replace(".", "_").replace("/", "_")
            lines.append(f'    subgraph {subnet_id}["{subnet}"]')

            for node in nodes:
                node_id = node.ip.replace(".", "_")
                status_icon = {
                    "owned": "🏆",
                    "exploited": "💀",
                    "discovered": "🔍"
                }.get(node.status, "❓")

                label = f"{status_icon} {node.ip}"
                lines.append(f'        {node_id}["{label}"]')

            lines.append("    end")

        lines.append("```")
        return "\n".join(lines)

    def generate_token_statistics(self) -> Dict[str, Any]:
        """生成Token消耗统计"""
        total_tokens = sum(self.token_stats.values())

        stats = {
            "total_tokens": total_tokens,
            "by_model": self.token_stats,
            "estimated_cost": self._estimate_cost(),
            "chart_data": self._generate_pie_chart_data()
        }

        return stats

    def _estimate_cost(self) -> float:
        """估算成本（美元）"""
        # 简化估算，实际价格可能不同
        pricing = {
            "claude-3-opus": {"input": 0.015, "output": 0.075},
            "claude-3-sonnet": {"input": 0.003, "output": 0.015},
            "claude-3-haiku": {"input": 0.00025, "output": 0.00125},
            "gpt-4": {"input": 0.03, "output": 0.06},
            "gpt-3.5-turbo": {"input": 0.0015, "output": 0.002},
        }

        total_cost = 0.0
        for model, tokens in self.token_stats.items():
            # 假设输入输出各占一半
            input_tokens = tokens // 2
            output_tokens = tokens // 2

            if model in pricing:
                cost = (
                    input_tokens * pricing[model]["input"] / 1000 +
                    output_tokens * pricing[model]["output"] / 1000
                )
                total_cost += cost

        return round(total_cost, 4)

    def _generate_pie_chart_data(self) -> Dict[str, Any]:
        """生成饼图数据"""
        return {
            "type": "pie",
            "data": {
                "labels": list(self.token_stats.keys()),
                "datasets": [{
                    "data": list(self.token_stats.values())
                }]
            }
        }

    def generate_tool_heatmap(self) -> str:
        """生成工具调用热力图"""
        lines = ["```mermaid", "gantt", "    title 工具调用时间线", "    dateFormat HH:mm:ss"]

        # 按工具分组
        for tool, timestamps in sorted(self.tool_calls.items()):
            if not timestamps:
                continue

            # 按时间排序
            sorted_times = sorted(timestamps)

            # 创建任务条
            for i, ts in enumerate(sorted_times):
                start = ts.strftime("%H:%M:%S")
                # 假设每次调用持续5秒
                end_ts = datetime.fromtimestamp(ts.timestamp() + 5)
                end = end_ts.strftime("%H:%M:%S")

                tool_safe = tool.replace(" ", "_").replace("-", "_")
                lines.append(f'    {tool_safe}_{i} : {tool}_{i}, {start}, {end}')

        lines.append("```")
        return "\n".join(lines)

    def generate_summary_dashboard(self) -> str:
        """生成汇总仪表板（ASCII Art）"""
        dashboard = f"""
╔════════════════════════════════════════════════════════════╗
║            CTF-Agent 攻击成果仪表板                          ║
╠════════════════════════════════════════════════════════════╣
║                                                            ║
║  📊 统计数据                                                ║
║  ┌────────────────────────────────────────────┐           ║
║  │ 发现主机: {len(self.nodes):>4} 台                          │           ║
║  │ 攻击路径: {len(self.paths):>4} 条                          │           ║
║  │ 工具调用: {sum(len(v) for v in self.tool_calls.values()):>4} 次                          │           ║
║  │ Token消耗: {sum(self.token_stats.values()):>8} 个                        │           ║
║  └────────────────────────────────────────────┘           ║
║                                                            ║
║  🎯 主机状态                                                ║
║  ┌────────────────────────────────────────────┐           ║
"""

        # 统计各状态主机数
        status_counts = {}
        for node in self.nodes:
            status_counts[node.status] = status_counts.get(node.status, 0) + 1

        for status, count in status_counts.items():
            icon = {
                "owned": "🏆",
                "exploited": "💀",
                "discovered": "🔍"
            }.get(status, "❓")
            dashboard += f"║  │ {icon} {status:12} : {count:>4} 台                  │           ║\n"

        dashboard += """║  └────────────────────────────────────────────┘           ║
║                                                            ║
║  💰 成本估算                                                ║
║  ┌────────────────────────────────────────────┐           ║
"""
        dashboard += f"║  │ 预估成本: ${self._estimate_cost():.4f}                        │           ║\n"
        dashboard += """║  └────────────────────────────────────────────┘           ║
║                                                            ║
╚════════════════════════════════════════════════════════════╝
"""
        return dashboard

    def export_json(self) -> str:
        """导出JSON格式数据"""
        data = {
            "nodes": [
                {
                    "id": n.id,
                    "ip": n.ip,
                    "hostname": n.hostname,
                    "os": n.os,
                    "open_ports": n.open_ports,
                    "services": n.services,
                    "status": n.status
                }
                for n in self.nodes
            ],
            "paths": [
                {
                    "id": p.id,
                    "source": p.source,
                    "target": p.target,
                    "technique": p.technique,
                    "success": p.success,
                    "timestamp": p.timestamp
                }
                for p in self.paths
            ],
            "token_stats": self.token_stats,
            "tool_calls": {
                k: [ts.isoformat() for ts in v]
                for k, v in self.tool_calls.items()
            }
        }
        return json.dumps(data, indent=2, ensure_ascii=False)


# 使用示例
if __name__ == "__main__":
    viz = VisualizationEngine()

    # 添加节点
    viz.add_node(NetworkNode(
        id="target1",
        ip="192.168.1.100",
        hostname="web-server",
        os="Linux",
        open_ports=[22, 80, 443],
        status="exploited"
    ))

    viz.add_node(NetworkNode(
        id="target2",
        ip="192.168.1.200",
        hostname="db-server",
        os="Windows",
        open_ports=[1433, 3389],
        status="owned"
    ))

    # 添加攻击路径
    viz.add_attack_path(AttackPath(
        id="path1",
        source="target1",
        target="target2",
        technique="Pass-the-Hash",
        success=True,
        timestamp="2024-01-01 10:30:00"
    ))

    # 记录Token使用
    viz.record_token_usage("claude-3-opus", 50000)
    viz.record_token_usage("claude-3-sonnet", 120000)

    # 生成可视化
    print(viz.generate_attack_tree())
    print(viz.generate_summary_dashboard())