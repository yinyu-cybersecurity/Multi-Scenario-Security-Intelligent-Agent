# nodes/helpers.py
"""
节点共享工具函数

包含:
- 日志输出
- 节点数据记录
- 常用检查函数
"""

from typing import Dict, Any, Optional
import time
from app.logger import get_logger

# URL处理函数已移至 url_utils.py
from app.url_utils import is_ip_target, extract_ip

logger = get_logger(__name__)


def log(message: str):
    """统一日志输出"""
    logger.info(message)


def log_node_data(node_name: str, input_data: Dict, output_data: Dict):
    """记录节点输入输出数据（用于调试）"""
    logger.debug(f"[{node_name}] Input: {input_data}")
    logger.debug(f"[{node_name}] Output: {output_data}")


def check_timeout(start_time: float, timeout: int) -> bool:
    """检查是否超时"""
    return time.time() - start_time >= timeout


def get_elapsed_time(start_time: float) -> float:
    """获取已用时间（秒）"""
    return time.time() - start_time


def format_duration(seconds: float) -> str:
    """格式化时间显示"""
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes = seconds / 60
    if minutes < 60:
        return f"{minutes:.1f}m"
    hours = minutes / 60
    return f"{hours:.1f}h"

# IP相关函数已移至 url_utils.py:
# - is_ip_target
# - extract_ip


def safe_get(state: Dict, key: str, default: Any = None) -> Any:
    """安全获取状态值"""
    return state.get(key, default) or default