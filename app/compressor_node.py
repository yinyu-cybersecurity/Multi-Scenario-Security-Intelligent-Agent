# compressor_node.py - 独立的上下文压缩节点
# 作用：检测状态大小，执行压缩，防止内存溢出
# 调用位置：在路由之前或作为中间件

from typing import Dict
from state import CTFState
from logger import get_logger

logger = get_logger(__name__)


def compressor_node(state: CTFState) -> Dict:
    """
    独立的上下文压缩节点

    职责:
    1. 检测状态大小
    2. 执行压缩策略
    3. 返回需要更新的压缩后字段

    Args:
        state: 当前状态

    Returns:
        需要更新的字段字典，空字典表示无需压缩
    """
    state_size = len(str(state))
    threshold = 50000  # 50KB

    if state_size < threshold:
        return {}  # 无需压缩

    logger.info(f"[Compressor] 状态过大 ({state_size} bytes)，执行压缩...")

    try:
        from context_compressor import get_compressor, get_chain_recorder

        # 获取攻击链摘要
        chain_recorder = get_chain_recorder()
        chain_summary_text = chain_recorder.get_chain_summary()

        # 执行压缩
        compressor = get_compressor()
        compressed = compressor.compress(dict(state))

        if not compressed:
            return {}

        # 只压缩列表类型的字段
        updates = {}
        for key in ["attack_results", "page_history", "visited_urls"]:
            if key in compressed and len(str(state.get(key, ""))) > 5000:
                updates[key] = compressed.get(key, state.get(key, []))

        if updates:
            logger.info(f"[Compressor] 压缩完成，更新 {len(updates)} 个字段")

        return updates

    except ImportError:
        logger.debug("[Compressor] context_compressor 模块不可用")
        return {}
    except Exception as e:
        logger.warning(f"[Compressor] 压缩失败: {e}")
        return {}


def should_compress(state: CTFState) -> bool:
    """
    判断是否需要压缩

    Args:
        state: 当前状态

    Returns:
        是否需要压缩
    """
    state_size = len(str(state))
    return state_size > 50000