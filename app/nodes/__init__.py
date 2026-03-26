# nodes/__init__.py
"""
节点模块 - 从ctf_agent_graph.py拆分的独立节点

节点列表:
- challenge_type_detector: 挑战类型检测
- recon: 侦察节点
- analyst: 分析节点
- mode_manager: 模式管理
- attacker: 攻击节点
- explorer: 探索节点
- verifier: 验证节点

设计原则:
- 每个节点独立文件，便于维护和测试
- 共享工具函数放在 helpers.py
- 统一导入接口
"""

# 节点将在后续逐步迁移到这里
# 目前保持从ctf_agent_graph.py导入

__all__ = [
    'challenge_type_detector_node',
    'recon_node',
    'analyst_node',
    'mode_manager_node',
    'attacker_node',
    'explorer_node',
    'verifier_node',
]