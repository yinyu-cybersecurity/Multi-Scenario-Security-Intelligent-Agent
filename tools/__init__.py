# tools/__init__.py
"""
工具动态加载模块

延迟加载机制：不在导入时立即加载工具，而是在首次使用时加载
"""
import os
import importlib
import inspect

# 延迟加载标志
_tools_loaded = False

def _ensure_tools_loaded():
    """确保工具已加载（延迟加载）"""
    global _tools_loaded
    if _tools_loaded:
        return

    _tools_loaded = True

    # 延迟导入，使用与工具文件相同的导入路径
    # 工具文件使用 `from tool_framework import ...`，这里也必须使用相同的路径
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


def get_tool_registry():
    """获取工具注册表（触发延迟加载）"""
    _ensure_tools_loaded()
    from tool_framework import ToolRegistry
    return ToolRegistry()


# 不在导入时自动加载，改为按需加载
# load_all_tools(ToolRegistry)  # 移除此行