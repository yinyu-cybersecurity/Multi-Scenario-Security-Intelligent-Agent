# app/module_registry.py
"""
模块注册机制

功能:
- 统一管理可选模块的导入
- 消除重复的 try/except 导入代码
- 提供模块可用性检查接口

设计原则:
- 延迟导入：只在需要时导入
- 错误隔离：模块导入失败不影响其他模块
- 统一接口：所有模块通过统一方式访问
"""

from typing import Callable, Dict, Any, Optional, List
from dataclasses import dataclass, field
import importlib


@dataclass
class ModuleInfo:
    """模块信息"""
    name: str
    available: bool = False
    nodes: Dict[str, Callable] = field(default_factory=dict)
    error: str = ""


class ModuleRegistry:
    """
    模块注册中心

    使用方式:
        # 注册模块
        ModuleRegistry.register('internal_network', lambda: {
            'internal_recon': internal_recon_node,
            'lateral_move': lateral_move_node,
        })

        # 检查可用性
        if ModuleRegistry.is_available('internal_network'):
            node = ModuleRegistry.get_node('internal_network', 'internal_recon')

        # 获取所有可用模块
        available = ModuleRegistry.get_available_modules()
    """

    _modules: Dict[str, ModuleInfo] = {}
    _initialized: bool = False

    @classmethod
    def _ensure_initialized(cls):
        """确保模块已初始化"""
        if not cls._initialized:
            cls._auto_register()
            cls._initialized = True

    @classmethod
    def _auto_register(cls):
        """自动注册已知模块"""
        # 内网渗透模块
        cls.register('internal_network', lambda: {
            'internal_recon': cls._import_node('internal_network.nodes', 'internal_recon_node'),
            'lateral_move': cls._import_node('internal_network.nodes', 'lateral_move_node'),
            'privilege_escalation': cls._import_node('internal_network.nodes', 'privilege_escalation_node'),
            'credential_gather': cls._import_node('internal_network.nodes', 'credential_gather_node'),
        })

        # 后渗透模块
        cls.register('post_exploit', lambda: {
            'post_exploit': cls._import_node('internal_network.post_exploit', 'post_exploit_node'),
            'upload_tools': cls._import_node('internal_network.post_exploit', 'upload_tools_node'),
            'setup_tunnel': cls._import_node('internal_network.post_exploit', 'setup_tunnel_node'),
        })

        # Crypto 模块
        cls.register('crypto', lambda: {
            'crypto_analyst': cls._import_node('crypto.nodes', 'crypto_analyst_node'),
            'crypto_solver': cls._import_node('crypto.nodes', 'crypto_solver_node'),
        })

        # Pwn 模块
        cls.register('pwn', lambda: {
            'pwn_analyst': cls._import_node('pwn.nodes', 'pwn_analyst_node'),
            'pwn_exploiter': cls._import_node('pwn.nodes', 'pwn_exploiter_node'),
        })

        # Reverse 模块
        cls.register('reverse', lambda: {
            'reverse_analyst': cls._import_node('reverse.nodes', 'reverse_analyst_node'),
            'reverse_decompiler': cls._import_node('reverse.nodes', 'reverse_decompiler_node'),
        })

        # Misc 模块
        cls.register('misc', lambda: {
            'misc_analyst': cls._import_node('misc.nodes', 'misc_analyst_node'),
            'misc_extractor': cls._import_node('misc.nodes', 'misc_extractor_node'),
        })

        # 性能监控模块 (在app目录下)
        cls.register('performance', lambda: {
            'performance_monitor': cls._import_attr('app.performance', 'performance_monitor'),
            'get_system_status': cls._import_attr('app.performance', 'get_system_status'),
            'ParallelExecutor': cls._import_attr('app.performance', 'ParallelExecutor'),
        })

        # 自我纠错模块 (在app目录下)
        cls.register('self_correction', lambda: {
            'self_correction_manager': cls._import_attr('app.self_correction', 'self_correction_manager'),
            'ErrorSeverity': cls._import_attr('app.self_correction', 'ErrorSeverity'),
        })

    @classmethod
    def _import_node(cls, module_path: str, node_name: str) -> Optional[Callable]:
        """导入节点函数"""
        try:
            module = importlib.import_module(module_path)
            return getattr(module, node_name, None)
        except ImportError:
            return None

    @classmethod
    def _import_attr(cls, module_path: str, attr_name: str) -> Optional[Any]:
        """导入模块属性"""
        try:
            module = importlib.import_module(module_path)
            return getattr(module, attr_name, None)
        except ImportError:
            return None

    @classmethod
    def register(cls, name: str, import_func: Callable[[], Dict[str, Optional[Callable]]]) -> bool:
        """
        注册模块

        Args:
            name: 模块名称
            import_func: 返回节点字典的函数

        Returns:
            是否注册成功（模块可用）
        """
        try:
            nodes = import_func()
            # 过滤掉 None 值
            valid_nodes = {k: v for k, v in nodes.items() if v is not None}

            if valid_nodes:
                cls._modules[name] = ModuleInfo(
                    name=name,
                    available=True,
                    nodes=valid_nodes
                )
                return True
            else:
                cls._modules[name] = ModuleInfo(
                    name=name,
                    available=False,
                    error="No valid nodes imported"
                )
                return False

        except ImportError as e:
            cls._modules[name] = ModuleInfo(
                name=name,
                available=False,
                error=str(e)
            )
            return False
        except Exception as e:
            cls._modules[name] = ModuleInfo(
                name=name,
                available=False,
                error=f"Unexpected error: {str(e)}"
            )
            return False

    @classmethod
    def is_available(cls, name: str) -> bool:
        """
        检查模块是否可用

        Args:
            name: 模块名称

        Returns:
            模块是否可用
        """
        cls._ensure_initialized()
        return cls._modules.get(name, ModuleInfo(name)).available

    @classmethod
    def get_node(cls, module: str, node_name: str) -> Optional[Callable]:
        """
        获取模块中的节点函数

        Args:
            module: 模块名称
            node_name: 节点名称

        Returns:
            节点函数，如果不存在则返回 None
        """
        cls._ensure_initialized()
        info = cls._modules.get(module)
        if info and info.available:
            return info.nodes.get(node_name)
        return None

    @classmethod
    def get_module_info(cls, name: str) -> Optional[ModuleInfo]:
        """
        获取模块信息

        Args:
            name: 模块名称

        Returns:
            模块信息
        """
        cls._ensure_initialized()
        return cls._modules.get(name)

    @classmethod
    def get_available_modules(cls) -> List[str]:
        """
        获取所有可用模块名称

        Returns:
            可用模块名称列表
        """
        cls._ensure_initialized()
        return [name for name, info in cls._modules.items() if info.available]

    @classmethod
    def get_all_modules(cls) -> Dict[str, ModuleInfo]:
        """
        获取所有模块信息

        Returns:
            模块名称到信息的映射
        """
        cls._ensure_initialized()
        return cls._modules.copy()

    @classmethod
    def get_status_report(cls) -> Dict[str, Any]:
        """
        获取状态报告

        Returns:
            包含所有模块状态的报告
        """
        cls._ensure_initialized()
        return {
            "total_modules": len(cls._modules),
            "available_modules": len([m for m in cls._modules.values() if m.available]),
            "modules": {
                name: {
                    "available": info.available,
                    "nodes": list(info.nodes.keys()) if info.available else [],
                    "error": info.error if not info.available else None
                }
                for name, info in cls._modules.items()
            }
        }


# 便捷函数
def get_module_node(module: str, node_name: str) -> Optional[Callable]:
    """获取模块节点"""
    return ModuleRegistry.get_node(module, node_name)


def is_module_available(name: str) -> bool:
    """检查模块是否可用"""
    return ModuleRegistry.is_available(name)


def get_available_modules() -> List[str]:
    """获取可用模块列表"""
    return ModuleRegistry.get_available_modules()