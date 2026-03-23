# topology/__init__.py
from .builder import TopologyBuilder
from .analyzer import TopologyAnalyzer
from .pruner import TopologyPruner
from .models import PageNode, PageEdge, AttackPath

# Optional: visualizer requires matplotlib
try:
    from .visualizer import TopologyVisualizer
    TOPOLOGY_VISUALIZER_AVAILABLE = True
except ImportError:
    TopologyVisualizer = None
    TOPOLOGY_VISUALIZER_AVAILABLE = False

__all__ = [
    'TopologyBuilder',
    'TopologyAnalyzer',
    'TopologyPruner',
    'TopologyVisualizer',
    'PageNode',
    'PageEdge',
    'AttackPath',
    'TOPOLOGY_VISUALIZER_AVAILABLE'
]