# tools/__init__.py
"""
工具动态加载模块

延迟加载机制：不在导入时立即加载工具，而是在首次使用时加载
支持按场景加载，优化内存占用
"""
import os
import importlib
import inspect
import threading

# 延迟加载标志
_tools_loaded = False
_partial_loaded = False

# 工具分类（按场景）
TOOL_CATEGORIES = {
    "core": [
        "python_exec_tool",
        "file_creator_tool",
        "payload_mutator",
    ],
    "web": [
        "sqlmap_tool",
        "nmap_tool",
        "nuclei_tool",
        "xray_tool",
        "ffuf_tool",
        "dirsearch_tool",
        "dalfox_tool",
        "fenjing_tool",
        "httpx_tool",
        "subfinder_tool",
        "jsfinder_tool",
        "git_hacker_tool",
        "jwt_tool",
        "flask_unsign_tool",
        "ssrf_scanner",
        "ssrfmap_tool",
        "gopherus_tool",
        "xxe_injector_tool",
        "phar_gen_tool",
        "php_filter_chain_tool",
        "phpggc_tool",
        "pickle_pwn_tool",
        "marshalsec_tool",
        "ysoserial_tool",
        "jndi_exploit_tool",
        "oa_exploiter",
        "ajpshooter_tool",
        "cve_scanner",
        "db_attacks",
    ],
    "internal": [
        "mimikatz_tool",
        "bloodhound_tool",
        "impacket_tools",
        "crackmapexec_tool",
        "msf_tool",
        "fscan_tool",
        "petitpotam_tool",
        "rubeus_tool",
        "adcs_abuse_tool",
        "ad_tools",
        "shadow_credentials_tool",
        "potato_tool",
        "privesc_tool",
        "hydra_tool",
        "frp_manager",
        "container_escape_tool",
    ],
    "cloud_ai": [
        "cloud_scanner",
        "ai_attacker",
        "kube_attacker",
    ],
    # 专项工具（低优先级，按需加载）
    "specialized": [
        "tool_scenarios",
    ],
}

# 反向映射：工具名 -> 类别名
_TOOL_TO_CATEGORY = {}
for cat, tools in TOOL_CATEGORIES.items():
    for tool in tools:
        _TOOL_TO_CATEGORY[tool] = cat


def _load_tool_by_name(tool_name: str, registry):
    """加载单个工具"""
    try:
        module_name = f"tools.{tool_name}"
        module = importlib.import_module(module_name)

        from tool_framework import CTFTool

        for name, obj in inspect.getmembers(module, inspect.isclass):
            if (issubclass(obj, CTFTool) and
                    obj.__module__ == module_name and
                    not inspect.isabstract(obj)):
                try:
                    registry.register(obj())
                    return True
                except Exception as e:
                    print(f"[Warning] Failed to register {name}: {e}")
        return False
    except ImportError as e:
        print(f"[Warning] Failed to import {tool_name}: {e}")
        return False


def load_tools_by_category(categories: list, registry=None):
    """
    按类别加载工具

    Args:
        categories: 类别列表，如 ["core", "web"] 或 ["core", "internal"]
        registry: 工具注册表，如果为None则自动获取
    """
    if registry is None:
        from tool_framework import ToolRegistry
        registry = ToolRegistry()

    loaded = 0
    for cat in categories:
        if cat not in TOOL_CATEGORIES:
            continue
        for tool_name in TOOL_CATEGORIES[cat]:
            if _load_tool_by_name(tool_name, registry):
                loaded += 1

    return loaded


def _ensure_tools_loaded():
    """确保工具已加载（延迟加载）"""
    global _tools_loaded

    if _tools_loaded:
        return

    _tools_loaded = True

    # 延迟导入，使用与工具文件相同的导入路径
    from tool_framework import CTFTool, ToolRegistry

    tools_dir = os.path.dirname(__file__)

    for filename in os.listdir(tools_dir):
        if filename.endswith(".py") and filename != "__init__.py":
            module_name = f"tools.{filename[:-3]}"

            try:
                module = importlib.import_module(module_name)
            except ImportError as e:
                print(f"[Warning] Skip {filename}: {e}")
                continue

            for name, obj in inspect.getmembers(module, inspect.isclass):
                if (issubclass(obj, CTFTool) and
                        obj.__module__ == module_name and
                        not inspect.isabstract(obj)):
                    try:
                        registry = ToolRegistry()
                        registry.register(obj())
                    except Exception as e:
                        print(f"[Warning] Failed to register {name}: {e}")


def load_all_tools(registry=None):
    """
    加载所有工具（兼容旧接口）

    注意：建议使用 load_tools_by_category 按需加载以节省内存
    """
    if registry is None:
        from tool_framework import ToolRegistry
        registry = ToolRegistry()

    _ensure_tools_loaded()
    return registry


def load_minimal_tools(registry=None):
    """
    加载最小工具集（仅核心工具）

    用于启动时减少内存占用
    """
    global _partial_loaded

    if registry is None:
        from tool_framework import ToolRegistry
        registry = ToolRegistry()

    # 只加载核心工具
    loaded = load_tools_by_category(["core"], registry)
    _partial_loaded = True

    print(f"[Tools] 已加载 {loaded} 个核心工具（最小模式）")
    return registry


def load_web_tools(registry=None):
    """加载Web渗透工具集"""
    if registry is None:
        from tool_framework import ToolRegistry
        registry = ToolRegistry()

    loaded = load_tools_by_category(["core", "web"], registry)
    print(f"[Tools] 已加载 {loaded} 个Web工具")
    return registry


def load_internal_tools(registry=None):
    """加载内网渗透工具集"""
    if registry is None:
        from tool_framework import ToolRegistry
        registry = ToolRegistry()

    loaded = load_tools_by_category(["core", "internal"], registry)
    print(f"[Tools] 已加载 {loaded} 个内网工具")
    return registry


def get_tool_registry():
    """获取工具注册表（触发延迟加载）"""
    _ensure_tools_loaded()
    from tool_framework import ToolRegistry
    return ToolRegistry()


def get_tool_count():
    """获取已加载工具数量"""
    from tool_framework import ToolRegistry
    registry = ToolRegistry()
    return len(registry._tools) if hasattr(registry, '_tools') else 0