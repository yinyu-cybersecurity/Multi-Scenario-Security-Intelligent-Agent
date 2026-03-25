# app/context_compressor.py
"""
智能上下文压缩器

目标：
1. 防止上下文无限膨胀
2. 保留关键攻击信息
3. AI智能压缩冗余数据

设计理念：
- CRITICAL: 凭据、FLAG、Shell会话 → 完整保留
- HIGH: 漏洞、攻击链、内网资产 → 保留结构
- MEDIUM: 扫描结果、页面特征 → 去重摘要
- LOW: 攻击结果、工具调用 → 只保留成功+统计
"""

import json
import time
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from llm_client import llm_client
from config import config


# =============================================================================
# 信息优先级定义
# =============================================================================

class Priority:
    """信息优先级"""
    CRITICAL = "critical"  # 必须完整保留
    HIGH = "high"          # 保留结构，可丢弃详情
    MEDIUM = "medium"      # 去重+摘要
    LOW = "low"            # 只保留统计


# 字段优先级映射
FIELD_PRIORITY = {
    # CRITICAL - 核心资产，永不压缩
    "credentials": Priority.CRITICAL,
    "found_flag": Priority.CRITICAL,
    "final_flag": Priority.CRITICAL,
    "shell_session": Priority.CRITICAL,
    "active_sessions": Priority.CRITICAL,

    # HIGH - 重要发现，保留结构
    "vuln_candidates": Priority.HIGH,
    "internal_hosts": Priority.HIGH,
    "domain_info": Priority.HIGH,
    "attack_chain": Priority.HIGH,
    "successful_exploits": Priority.HIGH,

    # MEDIUM - 有价值但可压缩
    "scanned_ips": Priority.MEDIUM,
    "scanned_urls": Priority.MEDIUM,
    "page_features": Priority.MEDIUM,
    "baseline_response": Priority.MEDIUM,
    "detected_scenes": Priority.MEDIUM,

    # LOW - 可大幅压缩
    "attack_results": Priority.LOW,
    "attack_batch": Priority.LOW,
    "tool_calls": Priority.LOW,
    "page_history": Priority.LOW,
    "failed_payloads": Priority.LOW,
    "raw_html_snippet": Priority.LOW,
}


# =============================================================================
# 攻击链条记录
# =============================================================================

@dataclass
class AttackChainEntry:
    """攻击链条条目"""
    step: int
    node: str
    timestamp: float
    decision: str  # 该节点做什么决策
    result: str    # 结果摘要
    changes: List[str] = field(default_factory=list)  # 状态变化
    success: bool = False

    def to_dict(self) -> Dict:
        return {
            "step": self.step,
            "node": self.node,
            "timestamp": self.timestamp,
            "decision": self.decision,
            "result": self.result,
            "changes": self.changes,
            "success": self.success
        }


class AttackChainRecorder:
    """攻击链条记录器"""

    def __init__(self):
        self.chain: List[AttackChainEntry] = []
        self.current_step = 0

    def record(self, node: str, decision: str, result: str,
               changes: List[str] = None, success: bool = False) -> AttackChainEntry:
        """记录一个节点的执行"""
        self.current_step += 1
        entry = AttackChainEntry(
            step=self.current_step,
            node=node,
            timestamp=time.time(),
            decision=decision[:200] if decision else "",  # 限制长度
            result=result[:200] if result else "",
            changes=changes or [],
            success=success
        )
        self.chain.append(entry)
        return entry

    def get_chain_summary(self) -> str:
        """获取链条摘要"""
        if not self.chain:
            return "Attack chain is empty"

        lines = ["Attack chain summary:"]
        for entry in self.chain[-10:]:  # 最近10步
            status = "[OK]" if entry.success else "[..]"
            lines.append(f"  {status} [{entry.node}] {entry.decision[:50]}")

        return "\n".join(lines)

    def to_list(self) -> List[Dict]:
        return [e.to_dict() for e in self.chain]

    def from_list(self, data: List[Dict]):
        self.chain = [AttackChainEntry(**d) for d in data]
        self.current_step = len(self.chain)


# =============================================================================
# 上下文压缩器
# =============================================================================

class ContextCompressor:
    """
    智能上下文压缩器

    增强功能:
    - Token 估算（基于字符数，不依赖 tiktoken）
    - 按需压缩触发
    - 压缩效果统计
    """

    # 压缩阈值
    MAX_ATTACK_RESULTS = 20      # 最多保留20条攻击结果
    MAX_TOOL_CALLS = 50          # 最多保留50条工具调用
    MAX_FAILED_PAYLOADS = 30     # 最多保留30条失败payload
    MAX_PAGE_HISTORY = 10        # 最多保留10个页面历史

    # Token 估算参数
    # 中文约 1.5 字符/token，英文约 4 字符/token，代码约 2-3 字符/token
    # 取保守值 2.5 字符/token
    CHARS_PER_TOKEN = 2.5
    MAX_TOKENS = 30000           # 触发压缩的 Token 阈值

    def __init__(self):
        self.chain_recorder = AttackChainRecorder()
        self._compression_stats = {
            "total_compressions": 0,
            "tokens_saved": 0,
            "last_compression_ratio": 0.0
        }

    def estimate_tokens(self, text: str) -> int:
        """
        估算文本的 Token 数量

        基于字符数的快速估算，不依赖外部库
        """
        if not text:
            return 0
        return int(len(text) / self.CHARS_PER_TOKEN)

    def estimate_state_tokens(self, state: Dict) -> int:
        """估算整个状态的 Token 数量"""
        try:
            state_str = json.dumps(state, ensure_ascii=False, default=str)
            return self.estimate_tokens(state_str)
        except Exception:
            # 如果序列化失败，使用近似估算
            total = 0
            for key, value in state.items():
                try:
                    total += self.estimate_tokens(str(key) + str(value))
                except Exception:
                    pass
            return total

    def should_compress(self, state: Dict) -> bool:
        """判断是否需要压缩"""
        return self.estimate_state_tokens(state) > self.MAX_TOKENS

    def get_compression_stats(self) -> Dict:
        """获取压缩统计信息"""
        return self._compression_stats.copy()

    def compress(self, state: Dict) -> Dict:
        """
        压缩状态，返回压缩后的状态

        策略:
        1. CRITICAL字段: 完整保留
        2. HIGH字段: 保留结构，丢弃冗余
        3. MEDIUM字段: 去重+截断
        4. LOW字段: 只保留成功+统计摘要
        """
        # 记录压缩前 Token 数
        before_tokens = self.estimate_state_tokens(state)

        compressed = {}

        for key, value in state.items():
            priority = FIELD_PRIORITY.get(key, Priority.MEDIUM)

            if priority == Priority.CRITICAL:
                # 完整保留
                compressed[key] = value

            elif priority == Priority.HIGH:
                # 保留结构，限制数量
                compressed[key] = self._compress_high(key, value)

            elif priority == Priority.MEDIUM:
                # 去重+截断
                compressed[key] = self._compress_medium(key, value)

            elif priority == Priority.LOW:
                # 大幅压缩
                compressed[key] = self._compress_low(key, value)
            else:
                compressed[key] = value

        # 记录压缩后 Token 数和统计
        after_tokens = self.estimate_state_tokens(compressed)
        tokens_saved = before_tokens - after_tokens
        compression_ratio = (tokens_saved / before_tokens * 100) if before_tokens > 0 else 0

        self._compression_stats["total_compressions"] += 1
        self._compression_stats["tokens_saved"] += tokens_saved
        self._compression_stats["last_compression_ratio"] = compression_ratio

        # 添加压缩元数据
        compressed["_compression_meta"] = {
            "compressed_at": time.time(),
            "attack_chain_length": len(self.chain_recorder.chain),
            "compression_version": "2.0",
            "before_tokens": before_tokens,
            "after_tokens": after_tokens,
            "tokens_saved": tokens_saved,
            "compression_ratio": round(compression_ratio, 1)
        }

        return compressed

    def compress_if_needed(self, state: Dict) -> Tuple[Dict, bool]:
        """
        按需压缩

        Args:
            state: 当前状态

        Returns:
            (compressed_state, was_compressed): 压缩后的状态和是否执行了压缩
        """
        if not self.should_compress(state):
            return state, False

        before_tokens = self.estimate_state_tokens(state)
        print(f"[Compressor] 状态过大 ({before_tokens} tokens)，执行压缩...")

        compressed = self.compress(state)

        after_tokens = self.estimate_state_tokens(compressed)
        ratio = self._compression_stats.get("last_compression_ratio", 0)

        print(f"[Compressor] 压缩完成: {before_tokens} -> {after_tokens} tokens (节省 {ratio:.1f}%)")

        return compressed, True

    def _compress_high(self, key: str, value: Any) -> Any:
        """压缩HIGH优先级字段"""
        if not isinstance(value, list):
            return value

        # 去重
        if key == "vuln_candidates":
            return self._dedupe_vuln_candidates(value)
        elif key == "internal_hosts":
            return self._dedupe_hosts(value)

        # 限制数量
        return value[:100] if len(value) > 100 else value

    def _compress_medium(self, key: str, value: Any) -> Any:
        """压缩MEDIUM优先级字段"""
        if key in ["scanned_ips", "scanned_urls"]:
            # 去重
            if isinstance(value, list):
                return list(set(value))
            return value

        if key == "page_features":
            # 只保留关键字段
            if isinstance(value, dict):
                return {
                    "tech_stack": value.get("tech_stack", [])[:10],
                    "input_vectors": value.get("input_vectors", [])[:10],
                    "sensitive_paths": value.get("sensitive_paths", [])[:10]
                }
            return value

        # 截断
        if isinstance(value, list) and len(value) > 50:
            return value[:50]

        return value

    def _compress_low(self, key: str, value: Any) -> Any:
        """压缩LOW优先级字段"""
        if key == "attack_results":
            return self._compress_attack_results(value)

        if key == "tool_calls":
            return self._compress_tool_calls(value)

        if key == "page_history":
            # 只保留URL列表
            if isinstance(value, dict):
                return {"urls": list(value.keys())[-self.MAX_PAGE_HISTORY:]}
            return value

        if key == "failed_payloads":
            # 只保留统计
            if isinstance(value, list):
                return value[-self.MAX_FAILED_PAYLOADS:]
            return value

        if key == "raw_html_snippet":
            # 删除，存文件
            return ""

        # 默认：限制数量
        if isinstance(value, list) and len(value) > self.MAX_ATTACK_RESULTS:
            return value[-self.MAX_ATTACK_RESULTS:]

        return value

    def _compress_attack_results(self, results: List[Dict]) -> List[Dict]:
        """
        压缩攻击结果

        保留:
        1. 所有成功的攻击
        2. 最近的失败攻击（有限数量）
        """
        if not isinstance(results, list) or len(results) <= self.MAX_ATTACK_RESULTS:
            return results

        successful = [r for r in results if r.get("is_exploit") or r.get("status") == 200]
        failed = [r for r in results if not (r.get("is_exploit") or r.get("status") == 200)]

        # 成功的全部保留
        # 失败的只保留最近的
        compressed = successful + failed[-(self.MAX_ATTACK_RESULTS - len(successful)):]

        return compressed

    def _compress_tool_calls(self, calls: List[Dict]) -> List[Dict]:
        """压缩工具调用记录"""
        if not isinstance(calls, list) or len(calls) <= self.MAX_TOOL_CALLS:
            return calls

        # 保留成功的调用
        successful = [c for c in calls if c.get("success")]
        recent = calls[-self.MAX_TOOL_CALLS:]

        # 合并去重
        seen = set()
        result = []
        for c in successful + recent:
            key = c.get("tool", "") + str(c.get("target", ""))
            if key not in seen:
                seen.add(key)
                result.append(c)

        return result[:self.MAX_TOOL_CALLS]

    def _dedupe_vuln_candidates(self, candidates: List[Dict]) -> List[Dict]:
        """漏洞候选去重"""
        if not isinstance(candidates, list):
            return candidates

        seen = set()
        result = []
        for c in candidates:
            key = f"{c.get('type', '')}:{c.get('location', c.get('target', ''))}"
            if key not in seen:
                seen.add(key)
                result.append(c)

        return result

    def _dedupe_hosts(self, hosts: List[Dict]) -> List[Dict]:
        """主机去重"""
        if not isinstance(hosts, list):
            return hosts

        seen = set()
        result = []
        for h in hosts:
            ip = h.get("ip", "")
            if ip and ip not in seen:
                seen.add(ip)
                result.append(h)

        return result

    # =========================================================================
    # AI智能压缩
    # =========================================================================

    def ai_compress_failures(self, failures: List[Dict]) -> Dict:
        """
        AI总结失败攻击

        当失败攻击太多时，用AI总结共同原因
        """
        if not failures:
            return {"total": 0, "reasons": [], "suggestion": ""}

        # 构建摘要
        failure_summary = []
        for f in failures[:20]:  # 最多分析20条
            failure_summary.append({
                "tool": f.get("tool", "unknown"),
                "target": f.get("target", ""),
                "error": f.get("error", f.get("output", ""))[:100]
            })

        prompt = f"""分析以下失败的攻击尝试，总结失败原因和下一步建议。

## 失败记录
{json.dumps(failure_summary, ensure_ascii=False, indent=2)}

## 输出格式 (JSON)
{{
  "total": 失败总数,
  "main_reasons": ["主要原因1", "主要原因2"],
  "tools_tried": ["尝试的工具列表"],
  "suggestion": "下一步建议"
}}
"""
        try:
            response = llm_client.call_chat_completion(
                model=config.ANALYST_MODEL,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.1,
                json_mode=True
            )

            if "```json" in response:
                response = response.split("```json")[1].split("```")[0]

            result = json.loads(response.strip())
            result["total"] = len(failures)
            return result

        except Exception as e:
            return {
                "total": len(failures),
                "reasons": ["分析失败"],
                "suggestion": "检查网络连接和目标可达性"
            }

    # =========================================================================
    # 状态变化检测
    # =========================================================================

    def detect_changes(self, before: Dict, after: Dict) -> List[str]:
        """
        检测状态变化

        用于记录攻击链条中的changes字段
        """
        changes = []

        # 检测新凭据
        before_creds = set(str(c) for c in (before.get("credentials") or []))
        after_creds = set(str(c) for c in (after.get("credentials") or []))
        new_creds = after_creds - before_creds
        if new_creds:
            changes.append(f"获取{len(new_creds)}个新凭据")

        # 检测新漏洞
        before_vulns = len(before.get("vuln_candidates") or [])
        after_vulns = len(after.get("vuln_candidates") or [])
        if after_vulns > before_vulns:
            changes.append(f"发现{after_vulns - before_vulns}个新漏洞")

        # 检测FLAG
        if after.get("found_flag") and not before.get("found_flag"):
            changes.append("发现FLAG!")

        # 检测Shell
        if after.get("shell_session") and not before.get("shell_session"):
            changes.append("获取Shell会话")

        # 检测新主机
        before_hosts = set(h.get("ip") for h in (before.get("internal_hosts") or []))
        after_hosts = set(h.get("ip") for h in (after.get("internal_hosts") or []))
        new_hosts = after_hosts - before_hosts
        if new_hosts:
            changes.append(f"发现{len(new_hosts)}个新主机")

        return changes


# =============================================================================
# 全局实例
# =============================================================================

_compressor: Optional[ContextCompressor] = None
_chain_recorder: Optional[AttackChainRecorder] = None


def get_compressor() -> ContextCompressor:
    """获取全局压缩器实例"""
    global _compressor
    if _compressor is None:
        _compressor = ContextCompressor()
    return _compressor


def get_chain_recorder() -> AttackChainRecorder:
    """获取全局链条记录器"""
    global _chain_recorder
    if _chain_recorder is None:
        _chain_recorder = AttackChainRecorder()
    return _chain_recorder


def compress_state(state: Dict) -> Dict:
    """便捷函数：压缩状态"""
    return get_compressor().compress(state)


def record_node(node: str, decision: str, result: str,
                changes: List[str] = None, success: bool = False) -> Dict:
    """便捷函数：记录节点执行"""
    entry = get_chain_recorder().record(node, decision, result, changes, success)
    return entry.to_dict()