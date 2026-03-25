# app/state_types/reducers.py
"""
状态规约器

所有状态列表字段的合并策略。

设计原则:
- 统一管理所有 reducer
- 可配置上限
- 支持去重
"""

from typing import List, Dict, Any, TypeVar, Callable

T = TypeVar('T')


def cap_list_reducer(x: List[T], y: List[T], cap: int = 20) -> List[T]:
    """
    带上限的列表追加规约器

    Args:
        x: 现有状态列表
        y: 新增数据列表
        cap: 允许保留的最大条目数

    Returns:
        合并后的列表（不超过 cap 条）

    Example:
        >>> cap_list_reducer([1, 2], [3, 4], cap=5)
        [1, 2, 3, 4]
        >>> cap_list_reducer(list(range(10)), [11, 12], cap=10)
        [3, 4, 5, 6, 7, 8, 9, 10, 11, 12]
    """
    if x is None:
        x = []
    if y is None:
        y = []
    if not y:
        return x

    new_list = x + y
    if len(new_list) > cap:
        return new_list[-cap:]
    return new_list


def cap_results_reducer(x: List[Dict], y: List[Dict], cap: int = 20) -> List[Dict]:
    """
    攻击结果规约器

    保留最近的攻击结果记录

    Args:
        x: 现有结果
        y: 新结果
        cap: 最大保留数量

    Returns:
        合并后的结果列表
    """
    return cap_list_reducer(x, y, cap=cap)


def cap_candidates_reducer(
    x: List[Dict],
    y: List[Dict],
    cap: int = 10
) -> List[Dict]:
    """
    漏洞候选项规约器

    智能去重：使用 location + type 作为唯一键
    如果已存在，则更新（保留最新的 context）

    Args:
        x: 现有候选项
        y: 新候选项
        cap: 最大保留数量

    Returns:
        去重后的候选项列表
    """
    if x is None:
        x = []
    if y is None:
        y = []
    if not y:
        return x

    # 使用 location + type 作为唯一键进行去重
    existing_map = {f"{c.get('location', '')}_{c.get('type', '')}": c for c in x}

    for new_cand in y:
        key = f"{new_cand.get('location', '')}_{new_cand.get('type', '')}"
        if key in existing_map:
            # 更新已存在的条目
            existing_map[key].update(new_cand)
        else:
            existing_map[key] = new_cand

    new_list = list(existing_map.values())
    return new_list[-cap:] if len(new_list) > cap else new_list


def dedupe_list_reducer(x: List[str], y: List[str]) -> List[str]:
    """
    去重列表规约器

    用于需要去重但不需要上限的场景

    Args:
        x: 现有列表
        y: 新列表

    Returns:
        去重后的列表
    """
    if x is None:
        x = []
    if y is None:
        y = []
    return list(set(x + y))


def merge_dict_reducer(x: Dict, y: Dict) -> Dict:
    """
    字典合并规约器

    用于需要合并字典的场景（如 site_topology）

    Args:
        x: 现有字典
        y: 新字典

    Returns:
        合并后的字典
    """
    if x is None:
        x = {}
    if y is None:
        y = {}
    return {**x, **y}


# 预定义的规约器实例（用于 Annotated 类型）
visited_urls_reducer = lambda x, y: cap_list_reducer(x, y, cap=100)
visited_fingerprints_reducer = lambda x, y: cap_list_reducer(x, y, cap=100)
attack_results_reducer = lambda x, y: cap_list_reducer(x, y, cap=20)
tool_calls_reducer = lambda x, y: cap_list_reducer(x, y, cap=100)
failed_payloads_reducer = lambda x, y: cap_list_reducer(x, y, cap=50)
credentials_reducer = lambda x, y: cap_list_reducer(x, y, cap=30)
internal_hosts_reducer = lambda x, y: cap_list_reducer(x, y, cap=50)