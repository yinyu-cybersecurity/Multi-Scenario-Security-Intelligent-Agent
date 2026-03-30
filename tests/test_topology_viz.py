# test_topology_viz.py - 可视化工具测试


import networkx as nx
import sys
import os

# 添加项目路径
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

# 导入可视化模块
from app.topology.visualizer import TopologyVisualizer


def create_sample_graph():
    """创建一个示例图用于测试"""
    G = nx.DiGraph()

    # 添加节点和边（模拟一个网站结构）
    edges = [
        ("/", "/login"),
        ("/", "/admin"),
        ("/", "/about"),
        ("/login", "/dashboard"),
        ("/admin", "/admin/config"),
        ("/admin", "/admin/users"),
        ("/admin/config", "/admin/config/db"),
        ("/dashboard", "/profile"),
        ("/profile", "/settings"),
    ]

    G.add_edges_from(edges)
    return G


def test_png_output():
    """测试1：生成PNG图片"""
    print("\n📸 测试1: 生成PNG图片")
    print("-" * 40)

    G = create_sample_graph()
    viz = TopologyVisualizer(G)

    # 生成PNG文件
    output_file = "topology_test.png"
    viz.draw(output_file=output_file)

    # 检查文件是否生成
    if os.path.exists(output_file):
        print(f"✅ PNG文件已生成: {output_file}")
        print(f"   文件大小: {os.path.getsize(output_file)} 字节")
    else:
        print("❌ PNG文件生成失败")


def test_temp_file():
    """测试2：不指定文件名，使用临时文件"""
    print("\n📸 测试2: 自动生成临时文件")
    print("-" * 40)

    G = create_sample_graph()
    viz = TopologyVisualizer(G)

    # 不指定output_file，会自动保存到临时文件
    viz.draw()

    print("✅ 临时文件已生成（见上面的路径）")


def test_html_output():
    """测试3：生成交互式HTML（需要pyvis）"""
    print("\n🌐 测试3: 生成HTML交互图")
    print("-" * 40)

    G = create_sample_graph()
    viz = TopologyVisualizer(G)

    output_file = "topology.html"
    viz.export_to_html(output_file)

    if os.path.exists(output_file):
        print(f"✅ HTML文件已生成: {output_file}")
        print(f"   用浏览器打开即可查看交互图")
    else:
        print("❌ HTML文件生成失败")


def test_real_data():
    """测试4：模拟真实扫描数据"""
    print("\n🔬 测试4: 模拟真实扫描数据")
    print("-" * 40)

    # 模拟一个真实的网站拓扑
    G = nx.DiGraph()

    # 首页
    G.add_node("/", status=200, type="index")

    # 常见目录
    dirs = ["/admin", "/login", "/backup", "/api", "/static", "/uploads"]
    for d in dirs:
        G.add_node(d, status=200 if d != "/backup" else 403)
        G.add_edge("/", d)

    # 后台页面
    admin_pages = ["/admin/config", "/admin/users", "/admin/logs"]
    for p in admin_pages:
        G.add_node(p, status=200)
        G.add_edge("/admin", p)

    # API接口
    api_endpoints = ["/api/user", "/api/data", "/api/auth"]
    for a in api_endpoints:
        G.add_node(a, status=200)
        G.add_edge("/api", a)

    print(f"图构建完成: {G.number_of_nodes()} 节点, {G.number_of_edges()} 条边")

    # 生成可视化
    viz = TopologyVisualizer(G)
    viz.draw("real_topology.png")
    viz.export_to_html("real_topology.html")

    print("✅ 真实数据可视化完成")


def test_with_attributes():
    """测试5：带节点属性的图"""
    print("\n🎨 测试5: 带节点属性的图")
    print("-" * 40)

    G = nx.DiGraph()

    # 添加带属性的节点
    nodes = [
        ("/", {"status": 200, "type": "index", "depth": 0}),
        ("/login", {"status": 200, "type": "form", "depth": 1}),
        ("/admin", {"status": 403, "type": "restricted", "depth": 1}),
        ("/backup", {"status": 404, "type": "gone", "depth": 1}),
        ("/api", {"status": 200, "type": "api", "depth": 1}),
    ]

    for node, attrs in nodes:
        G.add_node(node, **attrs)

    # 添加边
    G.add_edge("/", "/login")
    G.add_edge("/", "/admin")
    G.add_edge("/", "/backup")
    G.add_edge("/", "/api")

    print("节点属性:")
    for node in G.nodes:
        print(f"  {node}: {G.nodes[node]}")

    # 生成可视化
    viz = TopologyVisualizer(G)
    viz.draw("attr_topology.png")

    print("✅ 属性图可视化完成")


if __name__ == "__main__":
    print("=" * 60)
    print("🔍 拓扑可视化工具测试")
    print("=" * 60)

    # 运行所有测试
    test_png_output()
    test_temp_file()
    test_html_output()
    test_real_data()
    test_with_attributes()

    print("\n" + "=" * 60)
    print("✅ 所有测试完成！")
    print("📁 生成的文件：")
    print("   - topology_test.png")
    print("   - topology.html")
    print("   - real_topology.png")
    print("   - real_topology.html")
    print("   - attr_topology.png")
    print("=" * 60)