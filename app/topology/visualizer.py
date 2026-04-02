# topology/visualizer.py - 可视化工具


import networkx as nx
import matplotlib.pyplot as plt
from typing import Optional
import tempfile
from app.logger import get_logger

logger = get_logger("Visualizer")



class TopologyVisualizer:
    """拓扑图可视化（用于调试）"""

    def __init__(self, graph: nx.DiGraph):
        self.graph = graph

    def draw(self, output_file: Optional[str] = None):
        """绘制图形"""
        plt.figure(figsize=(12, 8))

        # 布局
        pos = nx.spring_layout(self.graph, k=3, iterations=50)

        # 绘制节点
        nx.draw_networkx_nodes(self.graph, pos, node_color='lightblue',
                               node_size=500, alpha=0.8)

        # 绘制边
        nx.draw_networkx_edges(self.graph, pos, edge_color='gray',
                               arrows=True, arrowsize=20)

        # 绘制标签
        nx.draw_networkx_labels(self.graph, pos, font_size=8)

        plt.title("Site Topology Graph")
        plt.axis('off')

        if output_file:
            plt.savefig(output_file, dpi=150, bbox_inches='tight')
            logger.info(f"📊 拓扑图已保存至 {output_file}")
        else:
            # 默认保存到临时文件，防止阻塞
            tmp = tempfile.mktemp(suffix='.png')
            plt.savefig(tmp, dpi=150, bbox_inches='tight')
            logger.info(f"📊 拓扑图已保存至临时文件: {tmp}")
        
        plt.close() # 释放内存

    def export_to_html(self, output_file: str = "topology.html"):
        """导出为交互式HTML"""
        try:
            import pyvis
            net = pyvis.Network(height="750px", width="100%", directed=True)

            for node in self.graph.nodes:
                net.add_node(node, label=node)

            for edge in self.graph.edges:
                net.add_edge(edge[0], edge[1])

            net.show(output_file)
            logger.info(f"📊 交互式拓扑图已保存至 {output_file}")
        except ImportError:
            logger.warning("⚠️ 需要安装pyvis: pip install pyvis")