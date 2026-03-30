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

# 从 config 导入统一上限配置（必须在函数定义之前）
from config import config

T = TypeVar('T')


def cap_list_reducer(x: List[T], y: List[T], cap: int = 20) -> List[T]:
    """
    带上限的列表追加规约器

    Args:
        x: 现有状态列表
        y: 新增数据列表
        cap: 上限值，默认20

    Returns:
        合并后的列表（不超过 cap 条）

    Example:
        >>> cap_list_reducer([1, 2], [3, 4])
        [1, 2, 3, 4]
        >>> cap_list_reducer(list(range(15)), [15, 16], cap=10)
        [7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
        >>> cap_list_reducer([1, 2], [3, 4], cap=100)
        [1, 2, 3, 4]
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


def cap_results_reducer(x: List[Dict], y: List[Dict]) -> List[Dict]:
    """
    攻击结果规约器

    保留最近的攻击结果记录

    Args:
        x: 现有结果
        y: 新结果

    Returns:
        合并后的结果列表（最多20条）
    """
    return cap_list_reducer(x, y)


def cap_candidates_reducer(x: List[Dict], y: List[Dict]) -> List[Dict]:
    """
    漏洞候选项规约器

    智能去重：使用 location + type 作为唯一键
    如果已存在，则更新（保留最新的 context）
    当 location 为空时，使用 fallback key: type + param + evidence[:20]

    Args:
        x: 现有候选项
        y: 新候选项

    Returns:
        去重后的候选项列表（使用config配置上限）
    """
    CAP_LIMIT = config.MAX_VULN_CANDIDATES

    if x is None:
        x = []
    if y is None:
        y = []
    if not y:
        return x

    def _make_dedup_key(cand: Dict) -> str:
        """生成去重键，处理 location 为空的情况"""
        location = cand.get('location', '')
        vuln_type = cand.get('type', '')
        if location:
            return f"{location}_{vuln_type}"
        # Fallback: 使用 type + param + evidence前20字符
        param = cand.get('param', '')
        evidence = cand.get('evidence', '') or ''
        return f"{vuln_type}_{param}_{evidence[:20]}"

    # 使用去重键进行去重
    existing_map = {_make_dedup_key(c): c for c in x}

    for new_cand in y:
        key = _make_dedup_key(new_cand)
        if key in existing_map:
            # 更新已存在的条目
            existing_map[key].update(new_cand)
        else:
            existing_map[key] = new_cand

    new_list = list(existing_map.values())
    return new_list[-CAP_LIMIT:] if len(new_list) > CAP_LIMIT else new_list


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
# LangGraph 要求 reducer 签名为 (x, y) -> result，不能有额外参数
# 所以我们使用闭包创建符合签名的 reducer

def _make_cap_reducer(cap: int):
    """创建带固定上限的 reducer"""
    def reducer(x, y):
        if x is None: x = []
        if y is None: y = []
        if not y: return x
        new_list = x + y
        return new_list[-cap:] if len(new_list) > cap else new_list
    return reducer

def _make_dedupe_cap_reducer(cap: int, dedupe_key_fn=None):
    """创建带去重和上限的 reducer - 超限时生成摘要保留关键信息"""
    def reducer(x, y):
        if x is None: x = []
        if y is None: y = []
        if not y: return x

        # 去重合并
        merged = list(x)
        seen = set()

        # 使用自定义去重键或默认值
        if dedupe_key_fn:
            seen = set(dedupe_key_fn(item) for item in merged)
            for item in y:
                key = dedupe_key_fn(item)
                if key not in seen:
                    merged.append(item)
                    seen.add(key)
        else:
            seen = set(merged)
            for item in y:
                if item not in seen:
                    merged.append(item)
                    seen.add(item)

        # 超限时压缩摘要而非直接删除
        if len(merged) > cap:
            # 保留最后cap-1条完整记录
            recent = merged[-(cap-1):]
            older = merged[:-(cap-1)]

            # 生成关键信息摘要
            summary = {
                "_summary": True,
                "count": len(older),
                "types": list(set(
                    item.get("type", "unknown") if isinstance(item, dict) else "unknown"
                    for item in older
                )),
                "first_ts": older[0].get("timestamp") if older and isinstance(older[0], dict) else None,
                "last_ts": older[-1].get("timestamp") if older and isinstance(older[-1], dict) else None,
            }
            return [summary] + recent

        return merged[-cap:] if len(merged) > cap else merged
    return reducer

def _make_candidates_reducer(cap: int):
    """创建带去重功能的候选项 reducer"""
    def _make_dedup_key(cand: Dict) -> str:
        """生成去重键，处理 location 为空的情况"""
        location = cand.get('location', '')
        vuln_type = cand.get('type', '')
        if location:
            return f"{location}_{vuln_type}"
        # Fallback: 使用 type + param + evidence前20字符
        param = cand.get('param', '')
        evidence = cand.get('evidence', '') or ''
        return f"{vuln_type}_{param}_{evidence[:20]}"

    def reducer(x, y):
        if x is None: x = []
        if y is None: y = []
        if not y: return x
        existing_map = {_make_dedup_key(c): c for c in x}
        for new_cand in y:
            key = _make_dedup_key(new_cand)
            if key in existing_map:
                existing_map[key].update(new_cand)
            else:
                existing_map[key] = new_cand
        new_list = list(existing_map.values())
        return new_list[-cap:] if len(new_list) > cap else new_list
    return reducer

# [断点4修复] 攻击结果摘要生成器
def generate_attack_summary(results: List[Dict]) -> str:
    """
    从攻击结果中提取关键信息生成摘要
    当attack_results达到上限时，压缩历史信息

    Args:
        results: 攻击结果列表

    Returns:
        关键发现摘要字符串
    """
    summary_parts = []

    # 提取成功的攻击
    successful = [r for r in results if r.get("is_exploit") or r.get("status") == 200]
    if successful:
        tools_used = set(r.get("tool", "unknown") for r in successful)
        summary_parts.append(f"成功工具: {', '.join(tools_used)}")

    # 提取发现的漏洞
    vulns_found = []
    for r in results:
        for v in r.get("vulnerabilities", []):
            vulns_found.append(f"{v.get('type', 'unknown')}@{v.get('target', 'unknown')}")
    if vulns_found:
        summary_parts.append(f"发现漏洞: {', '.join(vulns_found[:5])}")

    # 提取发现的凭据
    creds = []
    for r in results:
        for c in r.get("credentials", []):
            creds.append(f"{c.get('type', 'unknown')}")
    if creds:
        summary_parts.append(f"发现凭据: {len(creds)}个")

    # 提取发现的主机
    hosts = []
    for r in results:
        for h in r.get("hosts", []):
            hosts.append(h.get("ip", "unknown"))
    if hosts:
        summary_parts.append(f"发现主机: {', '.join(hosts[:5])}")

    # 提取有价值的响应特征
    interesting_responses = []
    for r in results:
        output = str(r.get("output", ""))
        if "flag" in output.lower() or "admin" in output.lower() or "secret" in output.lower():
            interesting_responses.append(r.get("tool", "unknown"))
    if interesting_responses:
        summary_parts.append(f"潜在flag响应: {', '.join(set(interesting_responses))}")

    if not summary_parts:
        return f"历史攻击{len(results)}次，无关键发现"

    return "; ".join(summary_parts)

# [断点4修复] 增强版攻击结果reducer（使用config配置上限）
def _attack_results_reducer_with_summary(x: List[Dict], y: List[Dict]) -> List[Dict]:
    """
    攻击结果规约器（带摘要生成）

    当达到上限时，生成摘要保留关键信息
    摘要需要通过其他机制更新到state.attack_summary
    """
    if x is None: x = []
    if y is None: y = []
    if not y: return x

    CAP = config.MAX_ATTACK_RESULTS

    new_list = x + y
    if len(new_list) > CAP:
        # 生成摘要（调用者需要在返回前更新state.attack_summary）
        # 这里只做截断，摘要生成由调用方处理
        return new_list[-CAP:]
    return new_list

# 导出的 reducer 实例（使用config统一配置）
visited_urls_reducer = _make_dedupe_cap_reducer(config.MAX_VISITED_URLS)
visited_fingerprints_reducer = _make_dedupe_cap_reducer(config.MAX_VISITED_PAGES)
attack_results_reducer = _attack_results_reducer_with_summary  # [断点4修复] 使用增强版
tool_calls_reducer = _make_cap_reducer(config.MAX_TOOL_CALLS)
failed_payloads_reducer = _make_dedupe_cap_reducer(config.MAX_FAILED_PAYLOADS)
credentials_reducer = _make_cap_reducer(config.MAX_CREDENTIALS)
internal_hosts_reducer = _make_cap_reducer(config.MAX_INTERNAL_HOSTS)

# 通用列表字段 reducer（用于无上限但有潜在增长风险的字段）
# 使用较大的上限防止意外无限增长
generic_list_reducer_20 = _make_cap_reducer(20)
generic_list_reducer_50 = _make_cap_reducer(50)
generic_list_reducer_100 = _make_cap_reducer(100)


def should_update_attack_summary(results: List[Dict], current_summary: str) -> str:
    """
    检查是否需要更新 attack_summary 并返回新摘要

    当满足以下条件时生成新摘要：
    1. results 数量达到上限的80%
    2. current_summary 为空
    3. 有新的成功攻击记录

    Args:
        results: 当前攻击结果列表
        current_summary: 当前摘要字符串

    Returns:
        新摘要（如果需要更新）或原摘要（如果不需要）
    """
    if not results:
        return current_summary

    # 条件1: 达到上限的80%
    threshold = int(config.MAX_ATTACK_RESULTS * 0.8)
    if len(results) < threshold:
        return current_summary

    # 条件2: 摘要为空
    if not current_summary:
        return generate_attack_summary(results)

    # 条件3: 有新的成功攻击（与上次摘要对比）
    # 检查是否有"成功"字样但摘要中未记录的工具
    successful_tools = set(
        r.get("tool", "unknown") for r in results
        if r.get("is_exploit") or r.get("status") == 200
    )
    if successful_tools and "成功工具:" in current_summary:
        existing_tools = set(
            t.strip() for t in current_summary.split("成功工具:")[1].split(";")[0].split(",")
        )
        new_tools = successful_tools - existing_tools
        if new_tools:
            return generate_attack_summary(results)

    return current_summary