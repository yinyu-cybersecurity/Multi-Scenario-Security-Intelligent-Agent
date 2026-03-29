# app/module_manager.py - 模块智慧管理器
# 作用：根据CTF场景动态加载模块，优化内存占用

from typing import Dict, List, Set, Any
import sys
import gc
import threading
import importlib
from pathlib import Path

# 集成现有日志模块
try:
    from app.logger import get_logger
except ImportError:
    get_logger = lambda name: type('Logger', (), {'info': print, 'warning': print, 'error': print})()

class ModuleCategory:
    """模块分类"""

    # 模块名别名映射（兼容简写名）
    MODULE_ALIAS: Dict[str, str] = {
        "tools.sqlmap": "tools.sqlmap_tool",
        "tools.nmap": "tools.nmap_tool",
        "tools.nuclei": "tools.nuclei_tool",
        "tools.dirsearch": "tools.dirsearch_tool",
        "tools.ffuf": "tools.ffuf_tool",
        "tools.xray": "tools.xray_tool",
        "tools.dalfox": "tools.dalfox_tool",
        "tools.mimikatz": "tools.mimikatz_tool",
        "tools.bloodhound": "tools.bloodhound_tool",
        "tools.impacket": "tools.impacket_tools",
        "tools.crackmapexec": "tools.crackmapexec_tool",
    }

    # 核心模块（必须常驻）
    CORE: List[str] = [
        "app.llm_client",
        "app.logger",
        "app.config",
        "app.self_correction",
        # 注意: tools.requests 不存在，已移除
        "rag_builder.retriever",
    ]

    # Web模块（第一赛区）
    WEB: List[str] = [
        "tools.sqlmap_tool",
        "tools.nmap_tool",
        "tools.nuclei_tool",
        "tools.dirsearch_tool",
        "tools.ffuf_tool",
        "tools.xray_tool",
        "tools.dalfox_tool",
    ]

    # 内网模块（第三/四赛区）
    INTERNAL: List[str] = [
        "tools.mimikatz_tool",
        "tools.bloodhound_tool",
        "tools.impacket_tools",  # 注意: 实际文件名是 impacket_tools.py (带s)
        "tools.crackmapexec_tool",
        "internal_network.nodes",
        "internal_network.orchestrator",
        "internal_network.credential_manager",
        "internal_network.advanced_operations",
    ]

    # 云/AI模块（第二赛区）
    CLOUD_AI: List[str] = [
        "cloud_security.nodes",
        "ai_security.nodes",
        "tools.cloud_scanner",
        "tools.ai_attacker",
    ]

    # 专项模块（按需）
    SPECIALIZED: Dict[str, List[str]] = {
        "crypto": ["crypto.nodes", "crypto.tools"],
        "pwn": ["pwn.nodes", "pwn.tools"],
        "reverse": ["reverse.nodes", "reverse.tools"],
        "misc": ["misc.nodes", "misc.tools"],
    }


class ModuleManager:
    """模块智慧管理器"""

    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._initialized = True

        # 初始化时解析核心模块名（使用别名映射）
        resolved_core = set()
        for module in ModuleCategory.CORE:
            resolved_core.add(self._resolve_module_name(module))
        self.loaded_modules: Set[str] = resolved_core
        self.memory_mode: str = "minimal"
        self.logger = get_logger("ModuleManager")

        self.logger.info(f"ModuleManager初始化，核心模块: {len(self.loaded_modules)}")

    def _resolve_module_name(self, name: str) -> str:
        """解析模块名，支持别名映射"""
        return ModuleCategory.MODULE_ALIAS.get(name, name)

    def get_required_modules(self, mode: str) -> Set[str]:
        """获取指定模式需要的模块"""
        required = set(ModuleCategory.CORE)

        if mode == "web":
            required.update(ModuleCategory.WEB)
        elif mode == "internal":
            required.update(ModuleCategory.INTERNAL)
        elif mode in ["cloud", "ai"]:
            required.update(ModuleCategory.CLOUD_AI)
        elif mode in ModuleCategory.SPECIALIZED:
            required.update(ModuleCategory.SPECIALIZED[mode])

        return required

    def switch_mode(self, mode: str, state: Dict = None) -> Dict[str, Any]:
        """
        切换内存模式

        Args:
            mode: "web" / "internal" / "cloud" / "ai" / "crypto" / "pwn" / "reverse" / "misc"
            state: 当前状态（可选）

        Returns:
            更新后的状态字典
        """
        if mode == self.memory_mode:
            return {"active_modules": list(self.loaded_modules), "memory_mode": mode}

        self.logger.info(f"切换内存模式: {self.memory_mode} -> {mode}")

        # 获取新模式需要的模块
        required = self.get_required_modules(mode)

        # 加载新模块
        newly_loaded = []
        for module in required:
            resolved_name = self._resolve_module_name(module)
            if resolved_name not in self.loaded_modules:
                try:
                    # 使用 importlib.import_module 正确导入子模块
                    importlib.import_module(resolved_name)
                    self.loaded_modules.add(resolved_name)
                    newly_loaded.append(resolved_name)
                except ImportError as e:
                    self.logger.warning(f"模块加载失败: {module} ({resolved_name}) - {e}")

        # 清理不需要的模块缓存（Python不能真正卸载，但可清理引用）
        to_clean = []
        for module_name in list(sys.modules.keys()):
            if module_name.startswith(("tools.", "internal_network.", "cloud_security.", "ai_security.", "crypto.", "pwn.", "reverse.", "misc.")):
                if module_name not in required and module_name not in self.loaded_modules:
                    to_clean.append(module_name)

        for mod_name in to_clean:
            try:
                del sys.modules[mod_name]
            except:
                pass

        if to_clean:
            gc.collect()
            self.logger.info(f"清理了 {len(to_clean)} 个非活跃模块")

        self.memory_mode = mode

        updates = {
            "active_modules": list(self.loaded_modules),
            "memory_mode": mode,
        }

        self.logger.info(f"模式切换完成: {mode}，已加载模块数: {len(self.loaded_modules)}")

        return updates

    def get_status(self) -> Dict[str, Any]:
        """获取当前状态"""
        return {
            "memory_mode": self.memory_mode,
            "loaded_modules": list(self.loaded_modules),
            "loaded_count": len(self.loaded_modules),
        }

    def is_module_loaded(self, module_name: str) -> bool:
        """检查模块是否已加载"""
        return module_name in self.loaded_modules


# 全局单例
module_manager = ModuleManager()


def get_module_manager() -> ModuleManager:
    """获取模块管理器单例"""
    return module_manager