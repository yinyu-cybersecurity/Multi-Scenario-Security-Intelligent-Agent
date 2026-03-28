# tools/__init__.py
import os
import importlib
import inspect
import sys

# 确保父目录在路径中
_parent_dir = os.path.dirname(os.path.dirname(__file__))
if _parent_dir not in sys.path:
    sys.path.insert(0, _parent_dir)

from app.tool_framework import CTFTool, ToolRegistry


def load_all_tools(registry: ToolRegistry):
    """
    动态扫描 tools 目录下的所有文件，自动注册所有合法的 CTFTool 具体子类
    """
    tools_dir = os.path.dirname(__file__)

    # 遍历当前目录下的所有文件
    for filename in os.listdir(tools_dir):
        # 忽略非 Python 文件和 __init__.py 本身
        if filename.endswith(".py") and filename != "__init__.py":
            module_name = f"tools.{filename[:-3]}"

            try:
                # 动态导入模块
                module = importlib.import_module(module_name)
            except ImportError as e:
                # 跳过缺少依赖的模块
                print(f"[Warning] Skip {filename}: {e}")
                continue

            # 找出模块中所有的类
            for name, obj in inspect.getmembers(module, inspect.isclass):
                # 条件：
                # 1. 必须是 CTFTool 的子类
                # 2. 必须是当前模块定义的类（防止重复加载导入的类）
                # 3. 关键修复：不能是抽象类（跳过 MCPClientTool, CommandLineTool 等基类）
                if (issubclass(obj, CTFTool) and
                        obj.__module__ == module_name and
                        not inspect.isabstract(obj)):
                    # 实例化并注册
                    registry.register(obj())


# 自动加载所有工具
load_all_tools(ToolRegistry)